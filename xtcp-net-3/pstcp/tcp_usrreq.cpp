#include <stdio.h>
#include <assert.h>
#include <winsock2.h>

#include "tcp.h"
#include "event.h"
#include "timer.h"
#include "tcpusr.h"
#include "rgnbuf.h"
#include "tcp_var.h"
#include "tcp_timer.h"

#define LF_QUEUED 1

#define tcp_rcvseqinit(tp) \
	(tp)->rcv_adv = (tp)->rcv_nxt = (tp)->iss + 1;

#define tcp_sendseqinit(tp) \
	(tp)->snd_una = (tp)->snd_nxt = (tp)->snd_max = (tp)->snd_recover = (tp)->iss;

int tcp_rexmit_min = TCPTV_MIN;
struct tcpcb * tcp_last_tcpcb = 0;
static event_t * _accept_evt_list = 0;

int tcp_connected(struct tcpcb * tp)
{
	if ((tp->t_flags & TF_NOFDREF) &&
			_accept_evt_list != NULL)
		event_wakeup(&_accept_evt_list);
	return 0;
}

void tcp_rwakeup(struct tcpcb * tp)
{
	event_wakeup(&tp->r_event);
	return;
}

void tcp_wwakeup(struct tcpcb * tp)
{
	event_wakeup(&tp->w_event);
	return;
}

static int tcp_stat(void)
{
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

struct tcpcb * tcp_newtcpcb(int if_fd)
{
	struct tcpcb * tp;
	tp = (struct tcpcb *) malloc(sizeof(*tp));
	memset(tp, 0, sizeof(*tp));

	tp->if_dev = if_fd;
	tp->ts_port = u_short((u_long)tp & 0xFFFF);
	tp->ts_addr = if_fd;
	tp->t_state = TCPS_CLOSED;
	tp->t_srtt  = TCPTV_SRTTBASE;
	tp->t_rxtcur = TCPTV_RTOBASE;
	tp->t_rttvar = ((TCPTV_RTOBASE - TCPTV_SRTTBASE) << TCP_RTTVAR_SHIFT) / 4;
	tp->snd_ssthresh = 65535;
	tp->t_flags = TF_NOFDREF;
	tp->t_maxseg = TCP_MSS;
	tp->rgn_snd = rgn_create(128 * 1024);
	tp->rgn_rcv = rgn_create(512 * 1024);
	tp->snd_cwnd = rgn_size(tp->rgn_snd);
	tp->t_rcvtime = ticks;
	tp->t_rttmin  = tcp_rexmit_min;
	tp->ts_recent = 0;
	tp->ts_recent_age = 0;
	tp->w_event = 0;
	tp->r_event = 0;
	tcp_setuptimers(tp);

	tp->tle_flags = 0;
	tp->tle_next = NULL;
	tp->tle_prev = &tp->tle_next;

	return tp;
}

struct tcpcb * tcp_accept(struct sockaddr_in * name, size_t * namlen)
{
	struct tcpcb * tp;
	struct tcpcb * newtp;

	newtp = NULL;
	for (tp = tcp_last_tcpcb; tp != NULL; tp = tp->tle_next) {
		if ((tp->t_flags & TF_NOFDREF) &&
			   	(tp->t_state == TCPS_ESTABLISHED ||
				 tp->t_state == TCPS_CLOSE_WAIT)) {
			tp->t_flags &= ~TF_NOFDREF;
			newtp = tp;
			break;
		}
	}

	return newtp;
}

int tcp_attach(struct tcpcb * tp)
{
	assert((tp->tle_flags & LF_QUEUED) == 0);
	tp->tle_flags |= LF_QUEUED;
	tp->tle_next = tcp_last_tcpcb;
	tp->tle_prev = &tcp_last_tcpcb;
	if (tcp_last_tcpcb != NULL)
		tcp_last_tcpcb->tle_prev = &tp->tle_next;
	tcp_last_tcpcb = tp;

	return 0;
}

static int tcp_detach(struct tcpcb * tp)
{
	assert(tp->tle_flags & LF_QUEUED);
	*tp->tle_prev = tp->tle_next;
	if (tp->tle_next != NULL)
		tp->tle_next->tle_prev = tp->tle_prev;
	tp->tle_prev = &tp->tle_next;
	tp->tle_flags &= ~LF_QUEUED;

	return 0;
}

int tcp_free(struct tcpcb * tp)
{
	if ((tp->t_flags & TF_NOFDREF) == 0 ||
			(tp->t_flags & TF_PROTOREF) == TF_PROTOREF)
		return -1;

	assert(tp->r_event == NULL);
	assert(tp->w_event == NULL);
	
	rgn_destroy(tp->rgn_snd);
	rgn_destroy(tp->rgn_rcv);
	tcp_cleantimers(tp);
	tcp_detach(tp);
	tcp_stat();
	free(tp);

	return 0;
}

int tcp_disconnect(struct tcpcb * tp)
{
	if (tp->t_state == TCPS_CLOSED) {
		if (tp->t_flags & TF_PROTOREF)
			tp->t_flags &= ~TF_PROTOREF;
	   	tcp_free(tp);
		return 0;
	}

	tcp_shutdown(tp);
	return 0;
}

int tcp_read(struct tcpcb * tp, void * buf, size_t count)
{
	int min_len = min((int)count, rgn_len(tp->rgn_rcv));
	if (rgn_len(tp->rgn_rcv) == 0) {
		switch (tp->t_state) {
			case TCPS_CLOSING:
			case TCPS_TIME_WAIT:
			case TCPS_CLOSE_WAIT:
			case TCPS_LAST_ACK:
				break;

			default:
				tp->t_error = WSAEWOULDBLOCK;
				return -1;
		}

		return 0;
	}

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
			tp->t_error = WSAEINVAL;
			return -1;
	}

	if (min_len == 0) {
		tp->t_error = WSAEWOULDBLOCK;
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

int tcp_poll(struct tcpcb * tp, int typ, event_t * evt)
{
	int error = -1;

   	switch (typ) {
		case TCP_READ:
			drop_event(evt);

			if (rgn_len(tp->rgn_rcv) > 0) {
			   	event_insert_tailer(evt);
				error = 0;
				break;
		   	}

			if ( TCPS_HAVERCVDFIN(tp->t_state) ) {
			   	event_insert_tailer(evt);
				error = 0;
				break;
		   	}

			if (tp->t_state == TCPS_CLOSED) {
			   	event_insert_tailer(evt);
				error = 0;
				break;
		   	}

		   	event_insert_header(&tp->r_event, evt);
			error = 1;
			break;

		case TCP_WRITE:
		   	drop_event(evt);

		   	if (rgn_rest(tp->rgn_snd) == 0 ||
				   	tp->t_state == TCPS_SYN_SENT ||
				   	tp->t_state == TCPS_SYN_RECEIVED) {
			   	event_insert_header(&tp->w_event, evt);
				error = 0;
				break;
		   	} 

			event_insert_tailer(evt);
			error = 1;
			break;

		case TCP_ACCEPT:
			drop_event(evt);

		   	for (tp = tcp_last_tcpcb; tp != NULL; tp = tp->tle_next) {
			   	if ((tp->t_flags & TF_NOFDREF) &&
					   	(tp->t_state == TCPS_ESTABLISHED ||
						 tp->t_state == TCPS_CLOSE_WAIT)) {
				   	event_insert_tailer(evt);
					return 1;
			   	}
		   	}

			event_insert_header(&_accept_evt_list, evt);
			break;

		default:
			fprintf(stderr, "tcp poll error\n");
			break;
	}

	return error;
}

int tcp_connect(struct tcpcb * tp,
		const struct sockaddr_in * name, size_t namlen)
{
	if (tp->t_state == TCPS_CLOSED) {
		fprintf(stderr, "TCPS_CLOSED -> TCPS_SYN_SENT: %x\n", tcp_iss);
		tp->iss = tcp_iss;
		tcp_sendseqinit(tp);
		tp->t_state = TCPS_SYN_SENT;
		assert(namlen == sizeof(tp->dst_addr));
		memcpy(&tp->dst_addr, name, namlen);
		(void)tcp_output(tp);
		return 1;
	}

	tp->t_error = WSAEINVAL;
	return -1;
}

int tcp_listen(struct tcpcb * tp)
{
	if (tp->t_state == TCPS_CLOSED) {
		tp->t_state = TCPS_LISTEN;
		fprintf(stderr, "TCPS_CLOSED -> TCPS_LISTEN\n");
		return 1;
	}

	tp->t_error = WSAEINVAL;
	return -1;
}

int tcp_close(struct tcpcb * tp)
{
	tcp_disconnect(tp);
	if (tp->t_state != TCPS_CLOSED)
		tp->t_flags |= TF_PROTOREF;
	tp->t_flags |= TF_NOFDREF;
	tcp_free(tp);
	return 0;
}

int tcp_packet(int dst, const char * buf, size_t len,
	   	const struct sockaddr_in * src_addr, size_t src_len)
{
	int handled = 0;
	struct tcpcb * tp;
	struct tcphdr * ti;
	if (len < sizeof(*ti))
		return -1;

	ti = (struct tcphdr *)buf;
	if (ti->ti_flags & (TH_ACK|TH_RST)) {
	   	for (tp = tcp_last_tcpcb; tp != NULL; tp = tp->tle_next) {
			if (tp->ts_port == ti->ti_dst) {
			   	if ((ti->ti_flags & (TH_SYN|TH_RST)) ||
					   (tp->td_port == ti->ti_src &&
					   	tp->td_addr == ti->ti_srcc))
				   	tcp_input(tp, dst, buf, len, src_addr);
				handled = 1;
				break;
			}
	   	}
	} else if (ti->ti_flags & TH_ACK) {
	   	for (tp = tcp_last_tcpcb; tp != NULL; tp = tp->tle_next) {
		   	if (tp->td_port == ti->ti_src &&
				   	tp->td_addr == ti->ti_srcc) {
			   	tcp_input(tp, dst, buf, len, src_addr);
				handled = 1;
			   	break;
		   	}
	   	}
	}

#define TH_CONNECT (TH_SYN | TH_ACK | TH_RST)
	if (handled == 0 && (ti->ti_flags & TH_CONNECT) == TH_SYN) {
		tp = tcp_newtcpcb(dst);
		if (tp != NULL) {
			tcp_attach(tp);
			tp->t_state = TCPS_LISTEN;
			tcp_input(tp, dst, buf, len, src_addr);
		}
	} else if (handled == 0 && (ti->ti_flags & TH_CONNECT) == TH_ACK) {
		if (ti->ti_magic == MAGIC_UDP_TCP) {
			struct tcpcb tcb;
			tcb.if_dev = dst;
			tcb.dst_addr = *src_addr;
			ti->ti_seq = ntohl(ti->ti_seq);
			ti->ti_ack = ntohl(ti->ti_ack);
			ti->ti_tsval = ntohl(ti->ti_tsval);
			ti->ti_tsecr = ntohl(ti->ti_tsecr);
			tcp_respond(&tcb, ti, len - sizeof(*ti), TH_RST);
		}
	}

	return 0;
}

