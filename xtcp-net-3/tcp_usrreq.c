#include <stdio.h>
#include <assert.h>
#include <winsock2.h>

#include "tcp.h"
#include "rgnbuf.h"
#include "tcp_var.h"
#include "tcp_timer.h"

#define tcp_rcvseqinit(tp) \
	(tp)->rcv_adv = (tp)->rcv_nxt = (tp)->iss + 1;

#define tcp_sendseqinit(tp) \
	(tp)->snd_una = (tp)->snd_nxt = (tp)->snd_max = (tp)->snd_recover = (tp)->iss;

int tcp_rexmit_min = TCPTV_MIN;
struct tcpcb * tcp_last_tcpcb = 0;
extern u_short tcp_port;
extern u_long  tcp_addr;

struct tcpcb * tcp_create(int if_fd)
{
	struct tcpcb * tp;
	tp = (struct tcpcb *) malloc(sizeof(*tp));
	memset(tp, 0, sizeof(*tp));

	tp->if_dev = if_fd;
	tp->ts_port = tcp_port++;
	tp->ts_addr = tcp_addr;
	tp->t_state = TCPS_CLOSED;
	tp->t_srtt  = TCPTV_SRTTBASE;
	tp->t_rxtcur = TCPTV_RTOBASE;
	tp->t_rttvar = ((TCPTV_RTOBASE - TCPTV_SRTTBASE) << TCP_RTTVAR_SHIFT) / 4;
	tp->snd_ssthresh = 65535;
	tp->t_maxseg = TCP_MSS;
	tp->rgn_snd = rgn_create(128 * 1024);
	tp->rgn_rcv = rgn_create(512 * 1024);
	tp->snd_cwnd = rgn_size(tp->rgn_snd);
	tp->t_rcvtime = ticks;
	tp->t_rttmin  = tcp_rexmit_min;
	tp->ts_recent = 0;
	tp->ts_recent_age = 0;

	return tp;
}

int tcp_empty(void)
{
	if (tcp_last_tcpcb)
		return 0;

	return 1;
}

int tcp_attach(struct tcpcb * tp)
{
	assert(tcp_last_tcpcb == 0);
	tcp_last_tcpcb = tp;
	return 0;
}

int tcp_destroy(struct tcpcb * tp)
{
	rgn_destroy(tp->rgn_snd);
	rgn_destroy(tp->rgn_rcv);
	free(tp);

	return 0;
}

int tcp_detach(struct tcpcb * tp)
{
	if (tcp_last_tcpcb == tp) {
		tp->t_flags |= TF_DETACH;
		if (tp->t_state == TCPS_CLOSED) {
			tcp_last_tcpcb = NULL;
			tcp_destroy(tp);
		}
	}

#define XX(field) printf("%s: %d\n", #field, tcpstat.field)
	XX(tcps_sndprobe);
	XX(tcps_sndrexmitpack);
	XX(tcps_sndrexmitbyte);
	XX(tcps_sndpack);
	XX(tcps_sndbyte);
	XX(tcps_sndacks);
	XX(tcps_sndctrl);
	XX(tcps_sndwinup);
	XX(tcps_segstimed);
	XX(tcps_sndtotal);
	XX(tcps_accepts);
	XX(tcps_connects);
	XX(tcps_pawsdrop);
	XX(tcps_predack);
	XX(tcps_preddat);
	XX(tcps_rcvackbyte);
	XX(tcps_rcvackpack);
	XX(tcps_rcvacktoomuch);
	XX(tcps_rcvafterclose);
	XX(tcps_rcvbyte);
	XX(tcps_rcvbyteafterwin);
	XX(tcps_rcvdupbyte);
	XX(tcps_rcvduppack);
	XX(tcps_rcvpack);
	XX(tcps_rcvpackafterwin);
	XX(tcps_rcvpartdupbyte);
	XX(tcps_rcvpartduppack);
	XX(tcps_rcvtotal);
	XX(tcps_rcvwinprobe);
	XX(tcps_rcvwinupd);
	XX(tcps_delack);
	XX(tcps_timeoutdrop);
	XX(tcps_rexmttimeo);
	XX(tcps_persisttimeo);
	XX(tcps_keeptimeo);
	XX(tcps_keepprobe);
	XX(tcps_keepdrops);
	XX(tcps_rttupdated);
	XX(tcps_sndrexmitbad);
#undef XX
	return 0;
}

int tcp_readable(struct tcpcb * tp)
{
	if (rgn_len(tp->rgn_rcv) > 0)
		return 1;

	if (TCPS_HAVERCVDFIN(tp->t_state))
		return 1;

	if (tp->t_state == TCPS_CLOSED)
		return 1;

	return 0;
}

int tcp_read(struct tcpcb * tp, void * buf, size_t count)
{
	int min_len = min((int)count, rgn_len(tp->rgn_rcv));
	rgn_get(tp->rgn_rcv, buf, min_len);
	tcp_output(tp);
	return min_len;
}

int tcp_write(struct tcpcb * tp, const void * buf, size_t count)
{
	int min_len = min((int)count, rgn_rest(tp->rgn_snd));
	switch (tp->t_state) {
		case TCPS_ESTABLISHED:
		case TCPS_CLOSE_WAIT:
			rgn_put(tp->rgn_snd, buf, min_len);
			tcp_output(tp);
			break;

		default:
			return -1;
	}

	return min_len;
}

int tcp_shutdown(struct tcpcb * tp)
{
	switch (tp->t_state) {
		case TCPS_ESTABLISHED:
			tp->t_state = TCPS_FIN_WAIT_1;
			fprintf(stderr, "TCPS_ESTABLISHED -> TCPS_FIN_WAIT_1\n");
			(void)tcp_output(tp);
			break;

		case TCPS_CLOSE_WAIT:
			fprintf(stderr, "TCPS_CLOSE_WAIT -> TCPS_LAST_ACK\n");
			tp->t_state = TCPS_LAST_ACK;
			(void)tcp_output(tp);
			break;
	}

	return 0;
}

int tcp_writable(struct tcpcb * tp)
{
	if (rgn_rest(tp->rgn_snd) == 0) {
		/* fprintf(stderr,
		 * "send buffer is full: %d!\n",
		 * rgn_len(tp->rgn_snd)); */
		return 0;
	}

	switch (tp->t_state) {
		case TCPS_SYN_SENT:
		case TCPS_SYN_RECEIVED:
			return 0;

		default:
			return 1;
	}

	return 0;
}

int tcp_connect(struct tcpcb * tp,
		const struct sockaddr_in * dst_addr, size_t dst_len)
{
	if (tp->t_state == TCPS_CLOSED) {
		fprintf(stderr, "TCPS_CLOSED -> TCPS_SYN_SENT\n");
		tp->iss = tcp_iss;
		tp->t_state = TCPS_SYN_SENT;
		tcp_sendseqinit(tp);
		fprintf(stderr, "tcpiss: %d\n", tcp_iss);
		assert(dst_len == sizeof(tp->dst_addr));
		memcpy(&tp->dst_addr, dst_addr, dst_len);
		(void)tcp_output(tp);
		return 1;
	}

	return -1;
}

int tcp_connected(struct tcpcb * tp)
{
	if (tp->t_state >= TCPS_ESTABLISHED) {
		return 0;
	}

	fprintf(stderr, "tcp_connected: %d\n", tp->t_state);
	return 1;
}

int tcp_listen(struct tcpcb * tp)
{
	if (tp->t_state == TCPS_CLOSED) {
		tp->t_state = TCPS_LISTEN;
		fprintf(stderr, "TCPS_CLOSED -> TCPS_LISTEN\n");
		return 1;
	}

	return -1;
}

int tcp_packet(int dst, const char * buf, size_t len,
		int * flags, const struct sockaddr_in * src_addr, size_t src_len)
{
	struct tcpcb * tp =  tcp_last_tcpcb;
	if (tp != NULL) {
		tcp_input(tp, dst, buf, len, flags, src_addr);
	}
	return 0;
}

