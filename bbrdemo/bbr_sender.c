#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "minmax.h"
#include "utils/queue.h"

void do_bbr_init(struct sock *sk);
void do_bbr_dump(struct sock *sk);
void do_bbr_main(struct sock *sk, const struct rate_sample *rs);

#define SEQ_LT(a, b) ((int)((int)(a) - (int)(b)) < 0)
#define SEQ_GEQ(a, b) ((int)((int)(a) - (int)(b)) >= 0)
#define MIN(a, b) (SEQ_LT(a, b)? (a): (b))
#define MAX(a, b) (SEQ_LT(a, b)? (b): (a))

typedef unsigned int tcp_seq;

struct bbr_info {
    tcp_seq trackid;
    tcp_seq seq_pkt;
    tcp_seq seq_ack;
    tcp_seq ts_val;
    tcp_seq ts_ecr;
    tcp_seq counter;
    int nsack;
};

struct sack_score {
    tcp_seq start;
    tcp_seq end;
};

struct bbr_tcpcb {
    int update;
    int ticks;

    struct rate_sample rs;
    struct sock sock;

    tcp_seq trackid;
    tcp_seq ts_echo;
    tcp_seq ts_recent;

    tcp_seq snd_nxt;
    tcp_seq snd_una;

    uint64_t min_rtt_us;             /* min RTT in min_rtt_win_sec window */
    uint64_t min_rtt_stamp;          /* timestamp of min_rtt_us */

    tcp_seq last_ack;
    tcp_seq last_ack_seq;

    tcp_seq prior_out;
    tcp_seq prior_delivered;

    uint64_t first_tx_mstamp;

    tcp_seq app_limited_seq;
    uint64_t app_limited_mstamp;

    uint64_t lost;

    uint64_t pacing_leach_mstamp;

    struct {
	uint64_t rexmt_out;
	uint64_t delivered_rate;
	uint64_t delivered_interval;
	uint64_t xmit_counter;
 	uint64_t exceed_cwnd;
	uint64_t minmax;
    } debug;
};

static unsigned char TUNNEL_PADDIND_DNS[] = {
    0x20, 0x88, 0x81, 0x80
};

#define LEN_PADDING_DNS sizeof(TUNNEL_PADDIND_DNS)

struct tx_skb {
    int sacked;

#define TCPCB_SACKED_ACKED	0x01	/* SKB ACK'd by a SACK block	*/
#define TCPCB_SACKED_RETRANS	0x02	/* SKB retransmitted		*/
#define TCPCB_LOST		0x04	/* SKB is lost			*/
#define TCPCB_TAGBITS		0x07	/* All tag bits			*/
#define TCPCB_REPAIRED		0x10	/* SKB repaired (no skb_mstamp_ns)	*/
#define TCPCB_EVER_RETRANS	0x80	/* Ever retransmitted frame	*/
#define TCPCB_RETRANS		(TCPCB_SACKED_RETRANS|TCPCB_EVER_RETRANS| \
				TCPCB_REPAIRED)

    struct {
	tcp_seq delivered;
	uint64_t delivered_mstamp;
	uint64_t first_tx_mstamp;
    } tx;

    tcp_seq pkt_seq;
    tcp_seq skb_tx_seq;
    uint64_t skb_mstamp;
    TAILQ_ENTRY(tx_skb) skb_next;
};

TAILQ_HEAD(tx_skb_head, tx_skb);
struct tx_skb_head _skb_rexmt_queue = TAILQ_HEAD_INITIALIZER(_skb_rexmt_queue);
struct tx_skb_head _skb_delivery_queue = TAILQ_HEAD_INITIALIZER(_skb_delivery_queue);

#define MAX_SND_CWND 40960
static struct tx_skb tx_bitmap[MAX_SND_CWND] = {};

static uint64_t tcp_mstamp()
{
    int error;
    struct timespec mstamp;

    error = clock_gettime(CLOCK_MONOTONIC, &mstamp);
    assert (error == 0);

    return (uint64_t)(mstamp.tv_sec * 1000000ll + mstamp.tv_nsec / 1000ll);
}

#define US_IN_SEC  (1000ll * 1000ll)
#define US_TO_TS(us)   (uint32_t)((us)/1000ll)

static void bbr_update_model(struct bbr_tcpcb *cb)
{
    if (cb->update > 0) {
	do_bbr_main(&cb->sock, &cb->rs);
	cb->update = 0;
	cb->ticks++;
    }

    cb->rs.interval_us = 0;
    cb->rs.delivered = 0;
    return ;
}

static void bbr_show_status(struct bbr_tcpcb *cb)
{
    static time_t last_show_stamp = 0;
    struct tcp_sock *tp = tcp_sk(&cb->sock);

    if (time(NULL) == last_show_stamp)
	return;

    fprintf(stderr, "%d snd_una %d min_rtt %lld delivered %d inflight %lld loss %lld rate %lld, rexmt %lld rate {%lld,%ld} counter %lld/%lld\n",
	    cb->ticks, cb->snd_una, cb->min_rtt_us, tp->delivered, tp->packets_out, cb->lost, cb->sock.sk_pacing_rate,
	    cb->debug.rexmt_out, cb->debug.delivered_rate, cb->debug.delivered_interval, cb->debug.xmit_counter, cb->debug.exceed_cwnd);
    do_bbr_dump(&cb->sock);

    last_show_stamp  = time(NULL);
    return;
}

static int bbr_check_pacing_reached(struct bbr_tcpcb *cb, struct timeval *timevalp)
{
    uint64_t now = tcp_mstamp();
    static uint64_t _save_last_mstamp = 0;

    if (now >= cb->pacing_leach_mstamp) {
	if (_save_last_mstamp > cb->pacing_leach_mstamp + 1000ll)
            cb->pacing_leach_mstamp = _save_last_mstamp;
	_save_last_mstamp = now;
	return 0;
    }

    if (timevalp != NULL) {
	timevalp->tv_sec = 0;
	timevalp->tv_usec = (cb->pacing_leach_mstamp - now);
	assert(timevalp->tv_usec < 1000000);
    }

    return 1;
}

static int tcpup_output(struct bbr_tcpcb *cb, int sockfd, const struct sockaddr *from, socklen_t size)
{
    int error;
    tcp_seq seq_rexmt;
    char buffer[1300];
    struct tx_skb *skb, *hold;
    struct bbr_info *pbbr = NULL;
    struct tcp_sock *tp = tcp_sk(&cb->sock);

    seq_rexmt = cb->snd_nxt;
    TAILQ_FOREACH_SAFE(skb, &_skb_rexmt_queue, skb_next, hold) {
	if (SEQ_LT(skb->pkt_seq, seq_rexmt)) {
	    assert(skb->sacked & TCPCB_LOST);
	    seq_rexmt = skb->pkt_seq;
	}
    }

    skb = &tx_bitmap[seq_rexmt % MAX_SND_CWND];
    if (seq_rexmt != cb->snd_nxt) {
        TAILQ_REMOVE(&_skb_rexmt_queue, skb, skb_next);
	assert(skb->sacked & TCPCB_LOST);

	skb->tx.delivered = tp->delivered;
	skb->tx.delivered_mstamp = tp->delivered_mstamp;

	skb->skb_mstamp = tp->tcp_mstamp;
	skb->tx.first_tx_mstamp = cb->first_tx_mstamp;
	if (skb->sacked & TCPCB_SACKED_RETRANS)
	    skb->sacked |= TCPCB_EVER_RETRANS;
	skb->sacked |= TCPCB_SACKED_RETRANS;
	skb->sacked &= ~TCPCB_LOST;

	cb->debug.rexmt_out++;
	goto start_xmit;
    }

    if (tp->packets_out == 0) {
	cb->app_limited_seq = cb->snd_nxt + 1;
	cb->app_limited_mstamp = tp->tcp_mstamp;
	cb->first_tx_mstamp = tp->tcp_mstamp;
    }

    if (cb->min_rtt_us > 0 && tp->tcp_mstamp - tp->delivered_mstamp > 500000 + (cb->min_rtt_us << 1)) {
	fprintf(stderr, "could not got acked for long time %d\n", tp->tcp_mstamp - tp->delivered_mstamp);
	exit(0);
    }

    assert(SEQ_GEQ(cb->snd_nxt, cb->snd_una));
    if (SEQ_LT(cb->snd_una + tp->snd_cwnd, cb->snd_nxt + 1) &&
	    tp->packets_out > 2 /* && tp->delivered_mstamp + (cb->min_rtt_us >> 1) < tp->tcp_mstamp */ ) {
	assert(cb->min_rtt_us > 16 || cb->min_rtt_us == 0);
        cb->pacing_leach_mstamp += (US_IN_SEC * 1300 / cb->sock.sk_pacing_rate);
	cb->pacing_leach_mstamp += (cb->min_rtt_us / 4);
	cb->debug.exceed_cwnd ++;
	return 0;
    }

    skb = &tx_bitmap[cb->snd_nxt % MAX_SND_CWND];
    if (skb->sacked != 0) {
	fprintf(stderr, "sacked %x snd_nxt %x %x\n", skb->sacked, cb->snd_nxt, cb->snd_una);
    }
    assert(skb->sacked == 0);
    skb->sacked = 0;
    skb->pkt_seq = cb->snd_nxt++;
    skb->tx.delivered = tp->delivered;
    skb->tx.first_tx_mstamp = cb->first_tx_mstamp;
    skb->tx.delivered_mstamp = tp->delivered_mstamp;
    skb->skb_mstamp = tp->tcp_mstamp;

start_xmit:
    tp->packets_out++;
    TAILQ_INSERT_TAIL(&_skb_delivery_queue, skb, skb_next);

    pbbr = (struct bbr_info *)(buffer + LEN_PADDING_DNS);

    pbbr->trackid = cb->trackid;
    pbbr->seq_pkt = ntohl(skb->pkt_seq);
    pbbr->seq_ack = ntohl(0);
    pbbr->ts_val  = ntohl(US_TO_TS(tp->tcp_mstamp));
    pbbr->ts_ecr  = ntohl(cb->ts_recent);
    pbbr->counter = ntohl(0);

    error = sendto(sockfd, buffer, sizeof(buffer), 0, from, size);
    assert (error > 0);

    cb->pacing_leach_mstamp += (US_IN_SEC * tp->mss_cache / cb->sock.sk_pacing_rate);
    cb->debug.xmit_counter++;
    return 0;
}

static void failure(void)
{
    abort();
}

static int tcpup_acked(struct bbr_tcpcb *cb, int sockfd)
{
    int i;
    int error;
    char buffer[1300];

    uint32_t lost = cb->lost; 
    tcp_seq start, end;
    tcp_seq prior_snd_una = cb->snd_una;
    struct tcp_sock *tp = tcp_sk(&cb->sock);
    tcp_seq delivered = tp->delivered;

    int flags = 0;
    uint64_t last_rtt_mstamp = 0ull;
    uint64_t last_sack_rtt_mstamp = 0ull;

    struct tx_skb *skb, *skb_acked = NULL;
    struct bbr_info *pbbr = NULL;
    struct bbr_info bbrinfo = {};
    struct sockaddr_in client = {};
    struct sack_score * sacks = NULL;
    struct rate_sample rs = {};

    socklen_t addr_len = sizeof(client);
    int nbytes = recvfrom(sockfd, buffer, sizeof(buffer),
	    MSG_DONTWAIT, (struct sockaddr *)&client, &addr_len);

    if (nbytes == -1 || nbytes < sizeof(bbrinfo) + LEN_PADDING_DNS) {
	return (nbytes != -1);
    }
	
    rs.prior_in_flight = tp->packets_out;
    pbbr = (struct bbr_info *)(buffer + LEN_PADDING_DNS);
    bbrinfo.seq_pkt = ntohl(pbbr->seq_pkt);
    bbrinfo.seq_ack = ntohl(pbbr->seq_ack);
    bbrinfo.ts_val = ntohl(pbbr->ts_val);
    bbrinfo.ts_ecr = ntohl(pbbr->ts_ecr);
    bbrinfo.counter = ntohl(pbbr->counter);
    bbrinfo.nsack = ntohl(pbbr->nsack);

    sacks = (struct sack_score *)(pbbr + 1);

    if (SEQ_LT(cb->snd_una, bbrinfo.seq_ack)) {
	skb_acked = &tx_bitmap[cb->snd_una % MAX_SND_CWND];
	cb->snd_una = bbrinfo.seq_ack;
	/* update snd_una */
    } else if (bbrinfo.nsack > 0 && cb->snd_una == bbrinfo.seq_ack) {
	start = htonl(sacks[0].start);
	skb_acked = &tx_bitmap[start % MAX_SND_CWND];
	if (SEQ_LT(start, bbrinfo.seq_ack)) {
	    assert(skb_acked->sacked & TCPCB_SACKED_RETRANS);
	    tp->delivered ++;
	}
	/* update skb_acked */
    } else {
#if 0
	printf("old ack nsack=%d, snd_una %x seq_ack %x\n",
		bbrinfo.nsack, prior_snd_una, bbrinfo.seq_ack);
	printf("old ack tsecr=%d, tsval %u, mstamp %u seq_ack %x\n",
		bbrinfo.ts_ecr, bbrinfo.ts_val, US_TO_TS(tp->delivered_mstamp), cb->ts_recent);
#endif
	assert(SEQ_LT(bbrinfo.ts_ecr, US_TO_TS(tp->delivered_mstamp)));

	if (SEQ_LT(cb->ts_recent, bbrinfo.ts_val)) {
	    cb->ts_recent = bbrinfo.ts_val;
	    cb->ts_echo = bbrinfo.ts_ecr;
	    tp->delivered++;
	} else {
	    /* skip */
	    assert(SEQ_GEQ(prior_snd_una, bbrinfo.seq_ack));
	}

	cb->update = 1;
	cb->rs = rs;
	return 1;
    }

    if (SEQ_LT(cb->ts_recent, bbrinfo.ts_val) ||
		    SEQ_LT(cb->ts_echo, bbrinfo.ts_ecr)) {
	assert(SEQ_GEQ(bbrinfo.ts_val, cb->ts_recent));
	assert(SEQ_GEQ(bbrinfo.ts_ecr, cb->ts_echo));

	cb->ts_recent = bbrinfo.ts_val;
	cb->ts_echo = bbrinfo.ts_ecr;
    }

    struct sack_score scores[5];

    for (i = 0; i < bbrinfo.nsack; i++) {
	scores[i].start = htonl(sacks[i].start);
	scores[i].end = htonl(sacks[i].end);
    }

    for (i = bbrinfo.nsack - 1; i > 0; i--) {
	for (int j = 0; j < i; j++) {
	    if (after(scores[j].start, scores[j + 1].start)) {
		struct sack_score save = scores[j];
		scores[j] = scores[j + 1];
		scores[j + 1] = save;
	    }
	}
    }

    for (i = 0; i < bbrinfo.nsack; i++) {
	start = scores[i].start;
	end = scores[i].end;

	if (SEQ_LT(start, prior_snd_una)) {
	    start = prior_snd_una;
	}

	while (SEQ_LT(start, end)) {
	    skb = &tx_bitmap[start++ % MAX_SND_CWND];

	    if (~skb->sacked & TCPCB_SACKED_ACKED) {
	        skb->sacked |= TCPCB_SACKED_ACKED;
		if (~skb->sacked & TCPCB_SACKED_RETRANS)
			last_sack_rtt_mstamp = skb->skb_mstamp;
		tp->delivered ++;
	    }

	    if (skb->sacked & TCPCB_LOST) {
		TAILQ_REMOVE(&_skb_rexmt_queue, skb, skb_next);
		skb->sacked &= ~TCPCB_LOST;
		TAILQ_INSERT_TAIL(&_skb_delivery_queue, skb, skb_next);
	    }

	    if (!rs.prior_delivered ||
		    (skb->skb_mstamp > cb->first_tx_mstamp) ||
		    (skb->skb_mstamp == cb->first_tx_mstamp &&
		     SEQ_LT(rs.last_end_seq, skb->pkt_seq))) {
		rs.prior_delivered = skb->tx.delivered;
		rs.prior_mstamp    = skb->tx.delivered_mstamp;
		rs.last_end_seq    = skb->pkt_seq;
		rs.interval_us     = (skb->skb_mstamp - skb->tx.first_tx_mstamp);

                assert(rs.prior_delivered > 0);
		cb->first_tx_mstamp = skb->skb_mstamp;
	    }
	}
    }

    start = prior_snd_una;
    end = cb->snd_una;

    while (SEQ_LT(start, end)) {
	skb = &tx_bitmap[start++ % MAX_SND_CWND];

	if (~skb->sacked & TCPCB_SACKED_ACKED) {
	    skb->sacked |= TCPCB_SACKED_ACKED;
	    if (skb->sacked & TCPCB_SACKED_RETRANS)
		flags |= TCPCB_SACKED_RETRANS;
	    else
		last_rtt_mstamp = skb->skb_mstamp;
	    tp->delivered ++;
	}

	if (!rs.prior_delivered ||
		(skb->skb_mstamp > cb->first_tx_mstamp) ||
		(skb->skb_mstamp == cb->first_tx_mstamp &&
		 SEQ_LT(rs.last_end_seq, skb->pkt_seq))) {
	    rs.prior_delivered = skb->tx.delivered;
	    rs.prior_mstamp    = skb->tx.delivered_mstamp;
	    rs.last_end_seq    = skb->pkt_seq;
	    rs.interval_us      = (skb->skb_mstamp - skb->tx.first_tx_mstamp);
            
            assert(rs.prior_delivered > 0);
	    cb->first_tx_mstamp = skb->skb_mstamp;
	}

	if (skb->sacked & TCPCB_LOST) {
	    TAILQ_REMOVE(&_skb_rexmt_queue, skb, skb_next);
	    // TAILQ_INSERT_TAIL(&_skb_delivery_queue, skb, skb_next);
	} else {
	    TAILQ_REMOVE(&_skb_delivery_queue, skb, skb_next);
	}

	skb->sacked = 0;
    }

    struct tx_skb * hold = NULL;
    tcp_seq ts_recent = cb->ts_echo;
    uint64_t reord_wnd = (cb->min_rtt_us >> 3);

    reord_wnd = (reord_wnd < 1000? 1000: reord_wnd);
    TAILQ_FOREACH_SAFE(skb, &_skb_delivery_queue, skb_next, hold) {
	if (SEQ_LT(skb->pkt_seq, cb->snd_una)) {
	    TAILQ_REMOVE(&_skb_delivery_queue, skb, skb_next);
	    skb->sacked = 0;
	    continue;
	}

	if ((~skb->sacked & TCPCB_SACKED_ACKED) &&
		SEQ_LT(US_TO_TS(skb->skb_mstamp + reord_wnd), ts_recent)) {
	    TAILQ_REMOVE(&_skb_delivery_queue, skb, skb_next);
	    cb->lost++;
	    tp->packets_out--;
            skb->sacked |= TCPCB_LOST;
	    TAILQ_INSERT_TAIL(&_skb_rexmt_queue, skb, skb_next);
	}
    }

    if (tp->delivered != delivered) {
	tp->delivered_mstamp = tp->tcp_mstamp;
	tp->packets_out -= (tp->delivered - delivered);
    }

    if (tp->delivered < bbrinfo.counter) {
	fprintf(stderr, "cb->delivered %d, counter %d\n", tp->delivered, bbrinfo.counter);
	// assert(cb->delivered >= bbrinfo.counter);
	tp->delivered = bbrinfo.counter;
    }

    rs.rtt_us = -1;
    if (last_sack_rtt_mstamp)
	rs.rtt_us = tp->tcp_mstamp - last_sack_rtt_mstamp;
    else if (!flags && last_rtt_mstamp)
	rs.rtt_us = tp->tcp_mstamp - last_rtt_mstamp;
    rs.losses = cb->lost - lost;

    // rs.is_app_limited = !(rs.losses > 0);
    if (rs.prior_delivered )
	rs.delivered = tp->delivered - rs.prior_delivered;

    cb->rs = rs;
    if (rs.prior_delivered == 0) {
	assert(0);
	return;
    }
    cb->update = 1;

#if 0
    fprintf(stderr, "last_sack_rtt_mstamp %ld last_rtt_mstamp %ld mstamp %ld\n",
		    last_sack_rtt_mstamp, last_rtt_mstamp, cb->tcp_mstamp);
#endif
    if (rs.rtt_us != -1 && rs.rtt_us > 0) {
	tcp_seq mstamp = US_TO_TS(tp->tcp_mstamp - rs.rtt_us);
	if (mstamp != bbrinfo.ts_ecr)
	    fprintf(stderr, "mstamp %d tsecr %d\n", mstamp, bbrinfo.ts_ecr);
	assert(SEQ_GEQ(bbrinfo.ts_ecr, mstamp));

	if (cb->min_rtt_us == 0 || cb->min_rtt_us >= rs.rtt_us) {
	    cb->min_rtt_stamp = tp->tcp_mstamp;
	    cb->min_rtt_us = rs.rtt_us;
	}

	if (cb->min_rtt_stamp + 10000000 < tp->tcp_mstamp && bbrinfo.ts_ecr == mstamp) {
	    cb->min_rtt_us = rs.rtt_us;
            /* min rtt is too old */
	}
    }

    if (rs.delivered > 0 && rs.interval_us > 0) {
#if 0
	uint64_t snd_us = (skb_acked->skb_mstamp - skb_acked->tx.first_tx_mstamp);
	uint64_t ack_us = (cb->tcp_mstamp - skb_acked->tx.delivered_mstamp);
	uint64_t interval_us = MAX(ack_us, snd_us);
#endif

	cb->debug.delivered_rate = rs.delivered * 1328 * 1000000ull / rs.interval_us;
	cb->debug.delivered_interval = rs.interval_us;
    }

    return 1;
}

enum Action {
    Action_Listen, Action_Connect
};

uint32_t tcp_jiffies32 = 0;

int main(int argc, char *argv[])
{ 
    int action = 0, error = 0;
    struct sockaddr_in serv;
    struct sockaddr_in client;
    struct bbr_tcpcb cb = {};
    static char buff[1024] = {};
    struct tcp_sock *tp = tcp_sk(&cb.sock);

    bzero(&serv, sizeof(serv));
    if (strcmp(argv[1], "-l") == 0) {
	serv.sin_family = AF_INET;
	serv.sin_port = htons(atoi(argv[3]));
	serv.sin_addr.s_addr = inet_addr(argv[2]);
	action = Action_Listen;
    } else if (strcmp(argv[1], "-c") == 0) {
	client.sin_family = AF_INET;
	client.sin_port = htons(atoi(argv[3]));
	client.sin_addr.s_addr = inet_addr(argv[2]);
	action = Action_Connect;
    } else if (strcmp(argv[1], "-h") == 0) {
	fprintf(stderr, "-h\n");
	fprintf(stderr, "-l <address> <port> \n");
	fprintf(stderr, "-c <address> <port> \n");
	exit(-1);
    } else {
	fprintf(stderr, "-h\n");
	fprintf(stderr, "-l <address> <port> \n");
	fprintf(stderr, "-c <address> <port> \n");
	exit(-1);
    }

    int nselect;
    int got_acked = 0;
    socklen_t addr_len = sizeof(client);

    fd_set readfds;
    struct timeval timeout;

    int upfd = socket(AF_INET, SOCK_DGRAM, 0);
    assert (upfd != -1);

    switch (action) {
	case Action_Listen:
	    error = bind(upfd, (struct sockaddr *)&serv, sizeof(serv));
	    assert (error == 0);
	    error = recvfrom(upfd, buff, sizeof(buff), 0, (struct sockaddr *)&client, &addr_len);
	    assert (error != -1);
	    break;

	case Action_Connect:
	    memcpy(buff, TUNNEL_PADDIND_DNS, LEN_PADDING_DNS);
	    error = sendto(upfd, buff, LEN_PADDING_DNS + 1, 0, (struct sockaddr *)&client, sizeof(client));
	    assert (error != -1);
	    break;

	default:
	    fprintf(stderr, "unkown action\n");
            exit(0);
	    break;
    }

    tp->delivered = 1;
    tp->delivered_mstamp = tcp_mstamp();
    cb.ts_echo = US_TO_TS(tcp_mstamp());
    cb.ts_recent = 0;

    tp->mss_cache = 1328;
    tp->snd_cwnd = 655360;
    tp->snd_cwnd_clamp = 655360;
    cb.sock.sk_pacing_rate = 102400;
    cb.sock.sk_pacing_status = SK_PACING_NONE;
    cb.sock.sk_max_pacing_rate = 1024 * 1024 * 10;

    tcp_jiffies32 = US_TO_TS(tcp_mstamp())/10;
    do_bbr_init(&cb.sock);

    for ( ; ; ) {
	tcp_jiffies32 = US_TO_TS(tcp_mstamp())/10;
	bbr_update_model(&cb);

	if (got_acked == 1) {
            tp->tcp_mstamp = tcp_mstamp();
            got_acked = tcpup_acked(&cb, upfd);
	}

	if (!bbr_check_pacing_reached(&cb, NULL)) {
            tp->tcp_mstamp = tcp_mstamp();
	    tcpup_output(&cb, upfd, (struct sockaddr *)&client, sizeof(client));
	}

	if (got_acked == 1 ||
		!bbr_check_pacing_reached(&cb, &timeout)) {
	    continue;
	}

	FD_ZERO(&readfds);
	FD_SET(upfd, &readfds);

	nselect = select(upfd + 1, &readfds, NULL, NULL, &timeout);
	got_acked = (nselect > 0 && FD_ISSET(upfd, &readfds));
	assert(nselect != -1);

	bbr_show_status(&cb);
    }

    close(upfd);

    return 0;
}
