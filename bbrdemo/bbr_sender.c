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

#include "utils/queue.h"

enum bbr_mode {
    BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
    BBR_DRAIN,	/* drain any queue created during startup */
    BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
    BBR_PROBE_RTT,	/* cut inflight to min to probe min_rtt */
};

#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */
#define BBR_SCALE       8

/* Window length of bw filter (in rounds): */
static const int bbr_bw_rtts = CYCLE_LEN + 2;

struct minmax_sample {
    uint32_t t;	/* time measurement was taken */
    uint32_t v;	/* value measured */
};

struct minmax {
    struct minmax_sample s[3];
};

static inline uint32_t minmax_get(const struct minmax *m)
{
    return m->s[0].v;
}

static inline uint32_t minmax_reset(struct minmax *m, uint32_t t, uint32_t meas)
{
    struct minmax_sample val = { .t = t, .v = meas };

    m->s[2] = m->s[1] = m->s[0] = val;
    return m->s[0].v;
}

static uint32_t minmax_subwin_update(struct minmax *m, uint32_t win,
	const struct minmax_sample *val)
{
    uint32_t dt = val->t - m->s[0].t;

    if (dt > win) {
	m->s[1] = m->s[2];
	m->s[2] = *val;
	if (val->t - m->s[0].t > win) {
	    m->s[0] = m->s[1];
	    m->s[1] = m->s[2];
	    m->s[2] = *val;
	}
    } else if (m->s[1].t == m->s[0].t && dt > win/4) {
	m->s[2] = m->s[1] = *val;
    } else if (m->s[2].t == m->s[1].t && dt > win/2) {
	m->s[2] = *val;
    }
    return m->s[0].v;
}

uint32_t minmax_running_max(struct minmax *m, uint32_t win, uint32_t t, uint32_t meas)
{
    struct minmax_sample val = { .t = t, .v = meas };

    if ((val.v >= m->s[0].v) ||
	    (val.t - m->s[2].t > win)) {
	m->s[2] = m->s[1] = m->s[0] = val;
	return m->s[0].v;
    }

    if (val.v >= m->s[1].v)
	m->s[2] = m->s[1] = val;
    else if (val.v >= m->s[2].v)
	m->s[2] = val;

    return minmax_subwin_update(m, win, &val);
}

#define SEQ_LT(a, b) ((int)((int)(a) - (int)(b)) < 0)
#define SEQ_GEQ(a, b) ((int)((int)(a) - (int)(b)) >= 0)
#define MIN(a, b) (SEQ_LT(a, b)? (a): (b))
#define MAX(a, b) (SEQ_LT(a, b)? (b): (a))

typedef unsigned int tcp_seq;

static uint64_t _ts_recent = 0;
static tcp_seq _seq_snd_nxt = 0;
static tcp_seq _seq_snd_max = 0;
static tcp_seq _seq_snd_una = 0;

static tcp_seq _track_id = 0;
static tcp_seq _stat_delivery = 0;
static uint64_t _stat_delivery_mstamp = 0;
static tcp_seq _skb_tx_max_seq = 0;

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
    int mode;

    struct {
	int round_start;

	int rtt_cnt;
        tcp_seq next_rtt_delivered;
	struct minmax bw;

	int lt_bw;
	int lt_use_bw;
	int lt_rtt_cnt;
	int lt_last_lost;
	int lt_last_delivered;
        int lt_is_sampling;
	uint64_t lt_last_stamp;

	int cycle_idx;
	uint64_t cycle_mstamp;
	
	float pacing_gain;
    } bbr;

    struct {
	int delivered;
	int losses;
	int is_app_limited;
	uint64_t interval_us;
	tcp_seq prior_delivered;
    } rs;

    tcp_seq trackid;
    tcp_seq ts_echo;
    tcp_seq ts_recent;

    tcp_seq snd_nxt;
    tcp_seq snd_una;
    tcp_seq snd_cwnd;

    uint64_t min_rtt_us;             /* min RTT in min_rtt_win_sec window */
    uint64_t min_rtt_stamp;          /* timestamp of min_rtt_us */

    tcp_seq last_ack;
    tcp_seq last_ack_seq;

    tcp_seq prior_out;
    tcp_seq prior_delivered;
    uint64_t tcp_mstamp;

    tcp_seq delivered;
    uint64_t delivered_mstamp;

    uint64_t first_tx_mstamp;

    tcp_seq app_limited_seq;
    uint64_t app_limited_mstamp;

    uint64_t lost;
    uint64_t packets_out;

    uint64_t pacing_rate;
    uint64_t pacing_leach_mstamp;

    struct {
	uint64_t rexmt_out;
	uint64_t delivered_rate;
	uint64_t delivered_interval;
	uint64_t xmit_counter;
 	uint64_t exceed_cwnd;
    } debug;
};

static unsigned char TUNNEL_PADDIND_DNS[] = {
    0x20, 0x88, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x77, 0x77, 0x77,
    0x77, 0x00, 0x00, 0x01, 0x00, 0x01
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

#define MAX_SND_CWND 409600
static struct tx_skb tx_bitmap[MAX_SND_CWND] = {};
static const uint32_t bbr_lt_bw_max_rtts = 48;
static const uint32_t bbr_lt_intvl_min_rtts = 4;
static const uint32_t bbr_lt_loss_thresh = 50;
static const uint32_t bbr_lt_bw_ratio = 8;

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

/* Start a new long-term sampling interval. */
static void bbr_reset_lt_bw_sampling_interval(struct bbr_tcpcb *tp)
{
	tp->bbr.lt_last_stamp = tp->delivered_mstamp/1000;
	tp->bbr.lt_last_delivered = tp->delivered;
	tp->bbr.lt_last_lost = tp->lost;
	tp->bbr.lt_rtt_cnt = 0;
}

/* Completely reset long-term bandwidth sampling. */
static void bbr_reset_lt_bw_sampling(struct bbr_tcpcb *tp)
{
	tp->bbr.lt_bw = 0;
	tp->bbr.lt_use_bw = 0;
	tp->bbr.lt_is_sampling = 0;
	bbr_reset_lt_bw_sampling_interval(tp);
}

static void bbr_lt_bw_interval_done(struct bbr_tcpcb *tp, uint32_t bw)
{
	uint32_t diff;

	if (tp->bbr.lt_bw) {  /* do we have bw from a previous interval? */
		/* Is new bw close to the lt_bw from the previous interval? */
		diff = abs(bw - tp->bbr.lt_bw);
		if ((diff * bbr_lt_bw_ratio <= tp->bbr.lt_bw) || (diff < 2)) {
			tp->bbr.lt_bw = (bw + tp->bbr.lt_bw) >> 1;  /* avg 2 intvls */
			tp->bbr.lt_use_bw = 1;
			tp->bbr.pacing_gain = 1.0;  /* try to avoid drops */
			tp->bbr.lt_rtt_cnt = 0;
			return;
		}
	}
	tp->bbr.lt_bw = bw;
	bbr_reset_lt_bw_sampling_interval(tp);
}

static void bbr_advance_cycle_phase(struct bbr_tcpcb *tp);

static void bbr_reset_probe_bw_mode(struct bbr_tcpcb *tp)
{
    tp->mode = BBR_PROBE_BW;
    tp->bbr.cycle_idx = CYCLE_LEN - 1;
    bbr_advance_cycle_phase(tp);
}

static void bbr_lt_bw_sampling(struct bbr_tcpcb *tp)
{
	uint32_t lost, delivered;
	uint64_t bw;
	uint32_t t;

	if (tp->bbr.lt_use_bw) {
		if (tp->mode == BBR_PROBE_BW && tp->bbr.round_start &&
		    ++tp->bbr.lt_rtt_cnt >= bbr_lt_bw_max_rtts) {
			bbr_reset_lt_bw_sampling(tp);    /* stop using lt_bw */
			bbr_reset_probe_bw_mode(tp);  /* restart gain cycling */
		}
		return;
	}

	if (!tp->bbr.lt_is_sampling) {
		if (!tp->rs.losses)
			return;
		bbr_reset_lt_bw_sampling_interval(tp);
		tp->bbr.lt_is_sampling = 1;
	}

	if (tp->rs.is_app_limited) {
		bbr_reset_lt_bw_sampling(tp);
		return;
	}

	if (tp->bbr.round_start)
		tp->bbr.lt_rtt_cnt++;
	if (tp->bbr.lt_rtt_cnt < bbr_lt_intvl_min_rtts)
		return;
	if (tp->bbr.lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
		bbr_reset_lt_bw_sampling(tp);
		return;
	}

	if (!tp->rs.losses)
		return;

	lost = tp->lost - tp->bbr.lt_last_lost;
	delivered = tp->delivered - tp->bbr.lt_last_delivered;
	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
		return;

	/* Find average delivery rate in this sampling interval. */
	t = (tp->delivered_mstamp / 1000) - tp->bbr.lt_last_stamp;
	if ((int32_t)t < 1)
		return;		/* interval is less than one ms, so wait */
	/* Check if can multiply without overflow */
	if (t >= ~0U / 1000) {
		bbr_reset_lt_bw_sampling(tp);  /* interval too long; reset */
		return;
	}
	bw = (uint64_t)delivered * 1000 / t;
	bbr_lt_bw_interval_done(tp, bw);
}

static void bbr_update_bw(struct bbr_tcpcb *cb)
{
    uint64_t bw;

    cb->bbr.round_start = 0;
    if (cb->rs.delivered < 0 || cb->rs.interval_us <= 0)
	return;

    if (SEQ_GEQ(cb->rs.prior_delivered, cb->bbr.next_rtt_delivered)) {
	cb->bbr.next_rtt_delivered = cb->delivered;
	cb->bbr.rtt_cnt++;
	cb->bbr.round_start = 1;
#if 0
	cb->bbr.packet_conservation = 0;
#endif
    }

    bbr_lt_bw_sampling(cb);

    bw = (uint64_t)cb->rs.delivered * 1000000ull / cb->rs.interval_us;

    if (!cb->rs.is_app_limited || bw >= minmax_get(&cb->bbr.bw)) {
	minmax_running_max(&cb->bbr.bw, bbr_bw_rtts, cb->bbr.rtt_cnt, bw);
    }

    return;
}

static uint32_t bbr_inflight(struct bbr_tcpcb *tp, uint32_t bw, float gain)
{
    return tp->min_rtt_us * bw * gain / 1000000ull;
}

static int bbr_is_next_cycle_phase(struct bbr_tcpcb *tp)
{
    int is_full_length = (tp->delivered_mstamp - tp->bbr.cycle_mstamp) > tp->min_rtt_us;
    uint32_t inflight, bw;

    if (tp->bbr.pacing_gain == 1.0)
	return is_full_length;          /* just use wall clock time */

    inflight = tp->packets_out; // bbr_packets_in_net_at_edt(sk, rs->prior_in_flight);
    bw = minmax_get(&tp->bbr.bw);

    if (tp->bbr.pacing_gain > 1.0)
	return is_full_length &&
	    (tp->rs.losses ||
	     inflight >= bbr_inflight(tp, bw, tp->bbr.pacing_gain));

    return is_full_length ||
	inflight <= bbr_inflight(tp, bw, 1.0);
}

static void bbr_advance_cycle_phase(struct bbr_tcpcb *tp)
{
    float pacing_gain[] = {1.25, 0.75, 1, 1, 1, 1, 1, 1};
    tp->bbr.cycle_idx = (tp->bbr.cycle_idx + 1) & (CYCLE_LEN - 1);
    tp->bbr.cycle_mstamp = tp->delivered_mstamp;
    tp->bbr.pacing_gain = pacing_gain[tp->bbr.cycle_idx];
}

static void bbr_update_cycle_phase(struct bbr_tcpcb *cb)
{
    if (cb->mode == BBR_PROBE_BW && bbr_is_next_cycle_phase(cb))
	bbr_advance_cycle_phase(cb);
    return;
}

static void bbr_update_model(struct bbr_tcpcb *cb)
{

    bbr_update_bw(cb);
    bbr_update_cycle_phase(cb);

    uint32_t bw = minmax_get(&cb->bbr.bw);
    if (cb->bbr.lt_use_bw) {
	cb->pacing_rate = cb->bbr.lt_bw;
    } else if (cb->bbr.rtt_cnt > 4 && bw * cb->bbr.pacing_gain > 128) {
	cb->pacing_rate = bw * cb->bbr.pacing_gain;
    }

    if (cb->min_rtt_us > 0) {
	cb->snd_cwnd  = (cb->pacing_rate * (cb->min_rtt_us << 1)) / 1000000ll;
	cb->snd_cwnd += (cb->pacing_rate * (cb->min_rtt_us >> 1)) / 1000000ll;
        cb->snd_cwnd += 3;
    } else {
	cb->snd_cwnd  = cb->pacing_rate;
        cb->snd_cwnd += 3;
    }

    cb->rs.interval_us = 0;
    cb->rs.delivered = 0;
    return ;
}

static void bbr_show_status(struct bbr_tcpcb *cb)
{
    uint32_t bw;
    static time_t last_show_stamp = 0;

    if (time(NULL) == last_show_stamp)
	return;

    bw = minmax_get(&cb->bbr.bw);
    fprintf(stderr, "snd_una %d min_rtt %lld delivered %d inflight %lld loss %lld lt {%d/%d}, rexmt %lld rate {%lld,%ld} counter %lld/%lld bw %d\n",
	    cb->snd_una, cb->min_rtt_us, cb->delivered, cb->packets_out, cb->lost, cb->bbr.lt_use_bw, cb->bbr.lt_bw,
	    cb->debug.rexmt_out, cb->debug.delivered_rate, cb->debug.delivered_interval, cb->debug.xmit_counter, cb->debug.exceed_cwnd, bw);

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
    char buffer[1300];
    struct tx_skb *skb;
    struct bbr_info *pbbr = NULL;

    skb = TAILQ_FIRST(&_skb_rexmt_queue);
    if (skb != NULL) {
        TAILQ_REMOVE(&_skb_rexmt_queue, skb, skb_next);
	assert(skb->sacked & TCPCB_LOST);

	skb->tx.delivered = cb->delivered;
	skb->tx.delivered_mstamp = cb->delivered_mstamp;

	skb->skb_mstamp = cb->tcp_mstamp;
	skb->tx.first_tx_mstamp = cb->first_tx_mstamp;
	if (skb->sacked & TCPCB_SACKED_RETRANS)
	    skb->sacked |= TCPCB_EVER_RETRANS;
	skb->sacked |= TCPCB_SACKED_RETRANS;
	skb->sacked &= ~TCPCB_LOST;

	cb->debug.rexmt_out++;
	goto start_xmit;
    }

    if (cb->packets_out == 0) {
	cb->app_limited_seq = cb->snd_nxt + 1;
	cb->app_limited_mstamp = cb->tcp_mstamp;
	cb->first_tx_mstamp = cb->tcp_mstamp;
    }

    if (cb->min_rtt_us > 0 && cb->tcp_mstamp - cb->delivered_mstamp > 500000 + (cb->min_rtt_us << 1)) {
	fprintf(stderr, "could not got acked for long time %d\n", cb->tcp_mstamp - cb->delivered_mstamp);
	exit(0);
    }

    assert(SEQ_GEQ(cb->snd_nxt, cb->snd_una));
    if (SEQ_LT(cb->snd_una + cb->snd_cwnd, cb->snd_nxt + 1) &&
	    cb->packets_out > 3 && cb->delivered_mstamp + (cb->min_rtt_us >> 2) < cb->tcp_mstamp) {
	assert(cb->min_rtt_us > 16);
        cb->pacing_leach_mstamp += (US_IN_SEC / cb->pacing_rate);
	cb->pacing_leach_mstamp += (cb->min_rtt_us / 16);
	cb->debug.exceed_cwnd ++;
	return 0;
    }

    skb = &tx_bitmap[cb->snd_nxt % MAX_SND_CWND];
    assert(skb->sacked == 0);
    skb->sacked = 0;
    skb->pkt_seq = cb->snd_nxt++;
    skb->tx.delivered = cb->delivered;
    skb->tx.first_tx_mstamp = cb->first_tx_mstamp;
    skb->tx.delivered_mstamp = cb->delivered_mstamp;
    skb->skb_mstamp = cb->tcp_mstamp;

start_xmit:
    cb->packets_out++;
    TAILQ_INSERT_TAIL(&_skb_delivery_queue, skb, skb_next);

    pbbr = (struct bbr_info *)(buffer + LEN_PADDING_DNS);

    pbbr->trackid = cb->trackid;
    pbbr->seq_pkt = ntohl(skb->pkt_seq);
    pbbr->seq_ack = ntohl(0);
    pbbr->ts_val  = ntohl(US_TO_TS(cb->tcp_mstamp));
    pbbr->ts_ecr  = ntohl(cb->ts_recent);
    pbbr->counter = ntohl(0);

    error = sendto(sockfd, buffer, sizeof(buffer), 0, from, size);
    assert (error > 0);

    assert (cb->pacing_rate >= 128);
    cb->pacing_leach_mstamp += (US_IN_SEC / cb->pacing_rate);
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
    tcp_seq snd_una = cb->snd_una;
    tcp_seq delivered = cb->delivered;
    uint64_t recent_skb_mstamp = 0ull;

    struct tx_skb *skb, *skb_acked = NULL;
    struct bbr_info *pbbr = NULL;
    struct bbr_info bbrinfo = {};
    struct sockaddr_in client = {};
    struct sack_score * sacks = NULL;

    socklen_t addr_len = sizeof(client);
    int nbytes = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&client, &addr_len);

    if (nbytes == -1 || nbytes < sizeof(bbrinfo) + LEN_PADDING_DNS) {
	return (nbytes != -1);
    }
	
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
	    assert(skb_acked->sacked & TCPCB_RETRANS);
	    cb->delivered ++;
	}
	/* update skb_acked */
    } else {
	printf("old ack nsack=%d, snd_una %x seq_ack %x\n",
		bbrinfo.nsack, snd_una, bbrinfo.seq_ack);
	printf("old ack tsecr=%d, tsval %u, mstamp %u seq_ack %x\n",
		bbrinfo.ts_ecr, bbrinfo.ts_val, US_TO_TS(cb->delivered_mstamp), cb->ts_recent);
	assert(SEQ_LT(bbrinfo.ts_ecr, US_TO_TS(cb->delivered_mstamp)));
	assert(SEQ_LT(bbrinfo.ts_val, cb->ts_recent));

	if (!SEQ_LT(bbrinfo.seq_ack, snd_una)) {
		failure();
	}

	assert(SEQ_LT(bbrinfo.seq_ack, snd_una));
	return 1;
    }

    if (SEQ_LT(cb->ts_recent, bbrinfo.ts_val) ||
		    SEQ_LT(cb->ts_echo, bbrinfo.ts_ecr)) {
	assert(SEQ_GEQ(bbrinfo.ts_val, cb->ts_recent));
	assert(SEQ_GEQ(bbrinfo.ts_ecr, cb->ts_echo));

	cb->ts_recent = bbrinfo.ts_val;
	cb->ts_echo = bbrinfo.ts_ecr;
    }

    start = snd_una;
    end = bbrinfo.seq_ack;
    while (SEQ_LT(start, end)) {
	skb = &tx_bitmap[start++ % MAX_SND_CWND];
	if (skb->sacked & TCPCB_SACKED_ACKED) 
	    continue;
	if ((~skb->sacked & TCPCB_RETRANS)
		&& skb->skb_mstamp > recent_skb_mstamp) {
	    if (SEQ_LT(cb->prior_delivered, skb->tx.delivered)
		    && cb->first_tx_mstamp < skb->skb_mstamp) {
		cb->first_tx_mstamp = skb->skb_mstamp;
		cb->prior_delivered = skb->tx.delivered;
	    }
	    recent_skb_mstamp = skb->skb_mstamp;
	}

	assert(~skb->sacked & TCPCB_LOST);
	skb->sacked |= TCPCB_SACKED_ACKED;
	cb->delivered ++;
    }

    for (i = 0; i < bbrinfo.nsack; i++) {
	start = htonl(sacks[i].start);
	end = htonl(sacks[i].end);

	if (SEQ_LT(start, cb->snd_una)) {
	    start = cb->snd_una;
	}

	while (SEQ_LT(start, end)) {
	    skb = &tx_bitmap[start++ % MAX_SND_CWND];
	    if (skb->sacked & TCPCB_SACKED_ACKED) 
		continue;
	    if ((~skb->sacked & TCPCB_RETRANS)
		    && skb->skb_mstamp > recent_skb_mstamp) {
		if (SEQ_LT(cb->prior_delivered, skb->tx.delivered)
			&& cb->first_tx_mstamp < skb->skb_mstamp) {
		    cb->first_tx_mstamp = skb->skb_mstamp;
		    cb->prior_delivered = skb->tx.delivered;
		}
		recent_skb_mstamp = skb->skb_mstamp;
	    }
	    assert(~skb->sacked & TCPCB_LOST);
	    skb->sacked |= TCPCB_SACKED_ACKED;
	    cb->delivered ++;
	}
    }

    if (cb->delivered != delivered) {
	cb->delivered_mstamp = cb->tcp_mstamp;
	cb->packets_out -= (cb->delivered - delivered);
    }

    assert(cb->delivered >= bbrinfo.counter);

    if (recent_skb_mstamp != 0) {
	uint64_t rtt_us = cb->tcp_mstamp - recent_skb_mstamp;

	assert(rtt_us > 1000);
	assert(cb->delivered != delivered);
        if (US_TO_TS(recent_skb_mstamp) != bbrinfo.ts_ecr)
	    fprintf(stderr, "recent_skb_mstamp %d tsecr %d\n", US_TO_TS(recent_skb_mstamp), bbrinfo.ts_ecr);
        assert(US_TO_TS(recent_skb_mstamp) == bbrinfo.ts_ecr);

	if (cb->min_rtt_us > rtt_us
		|| cb->min_rtt_stamp + 10000000 < cb->tcp_mstamp) {
            if (cb->min_rtt_us > rtt_us)
		cb->min_rtt_stamp = cb->tcp_mstamp;
	    cb->min_rtt_us = rtt_us;
	}
    }

    struct tx_skb * hold = NULL;
    tcp_seq ts_recent = cb->ts_echo;

    if (recent_skb_mstamp > 0) {
	assert(ts_recent == US_TO_TS(recent_skb_mstamp));
	ts_recent = US_TO_TS(recent_skb_mstamp);
    }

    uint64_t reord_wnd = (cb->min_rtt_us >> 3);

    reord_wnd = (reord_wnd < 1000? 1000: reord_wnd);
    TAILQ_FOREACH_SAFE(skb, &_skb_delivery_queue, skb_next, hold) {
	if (SEQ_LT(skb->pkt_seq, cb->snd_una)) {
	    TAILQ_REMOVE(&_skb_delivery_queue, skb, skb_next);
	    skb->sacked = 0;
	    continue;
	}

	if (skb->sacked & TCPCB_SACKED_ACKED) {
	    continue;
	}
	
	if (SEQ_LT(US_TO_TS(skb->skb_mstamp + reord_wnd), ts_recent)) {
	    TAILQ_REMOVE(&_skb_delivery_queue, skb, skb_next);
	    cb->lost++;
	    cb->packets_out--;
            skb->sacked |= TCPCB_LOST;
	    TAILQ_INSERT_TAIL(&_skb_rexmt_queue, skb, skb_next);
	}
    }

    cb->rs.losses = cb->lost - lost;
    cb->rs.delivered = 0;
    cb->rs.prior_delivered = 0;

    if ((skb_acked != NULL) && (cb->delivered != skb_acked->tx.delivered)) {
	uint64_t snd_us = (skb_acked->skb_mstamp - skb_acked->tx.first_tx_mstamp);
	uint64_t ack_us = (cb->tcp_mstamp - skb_acked->tx.delivered_mstamp);
	uint64_t interval_us = MAX(ack_us, snd_us);

#if 0
	fprintf(stderr, "%ld %ld %ld %ld\n", skb_acked->skb_mstamp,
		skb_acked->tx.first_tx_mstamp, skb_acked->tx.delivered_mstamp, cb->tcp_mstamp);
#endif

	if (interval_us >= cb->min_rtt_us) {
	    cb->debug.delivered_rate = (cb->delivered - skb_acked->tx.delivered) * 1328 * 1000000ull / interval_us;
	    cb->debug.delivered_interval = interval_us;

            cb->rs.interval_us = interval_us;
            cb->rs.delivered = cb->delivered - skb_acked->tx.delivered;
            cb->rs.prior_delivered = skb_acked->tx.delivered;
	}
    }

    return 1;
}

enum Action {
    Action_Listen, Action_Connect
};

int main(int argc, char *argv[])
{ 
    int action = 0, error = 0;
    struct sockaddr_in serv;
    struct sockaddr_in client;
    struct bbr_tcpcb cb = {};
    static char buff[1024] = {};

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

    minmax_reset(&cb.bbr.bw, cb.bbr.rtt_cnt, 0);
    cb.pacing_rate = 128;
    cb.delivered_mstamp = tcp_mstamp();
    cb.ts_echo = US_TO_TS(tcp_mstamp());
    cb.ts_recent = 0;
    cb.bbr.pacing_gain = 1.0;

    for ( ; ; ) {
	bbr_update_model(&cb);

	if (got_acked == 1) {
            cb.tcp_mstamp = tcp_mstamp();
            got_acked = tcpup_acked(&cb, upfd);
	}

	if (!bbr_check_pacing_reached(&cb, NULL)) {
            cb.tcp_mstamp = tcp_mstamp();
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

