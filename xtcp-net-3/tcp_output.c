#include <stdio.h>
#include <assert.h>
#include <winsock2.h>

#include "tcp.h"
#include "rgnbuf.h"
#include "tcp_var.h"

#define TCP_MAXRXTSHIFT 12
#define TCPTV_PERSMIN (5 * 1000)
#define TCPTV_PERSMAX (60 * 1000)
#define TCPT_RANGESET(tv, value, tvmin, tvmax) \
	do { \
		(tv) = (value); \
		if ((tv) < (tvmin)) { \
			(tv) = (tvmin); \
		} else if ((tv) > (tvmax)) { \
			(tv) = (tvmax); \
		} \
	} while ( 0 );

struct tcp_stat tcpstat;
int tcp_backoff[TCP_MAXRXTSHIFT + 1] = {
	1, 2, 4, 8, 16, 32, 64, 64, 64, 64, 64, 64, 64
};

int tcp_setpersist(struct tcpcb * tp)
{
	int persist_time = 0;
	register int t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1;
	assert(tp->t_timer[TCPT_REXMT] == 0);

	TCPT_RANGESET(persist_time,
			t * tcp_backoff[tp->t_rxtshift],
			TCPTV_PERSMIN, TCPTV_PERSMAX);
	tp->t_timer[TCPT_PERSIST] = (persist_time + ticks);

	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
	return 0;
}

int tcp_output(struct tcpcb * tp)
{
	int error;
	long len, win;
	int off, flags;
	int idle, sendalot;
	char buf[2048];
	int this_sent = 0;
	struct tcphdr * ti = (struct tcphdr *)buf;

	idle = (tp->t_flags & TF_LASTIDLE) || (tp->snd_max == tp->snd_una);
	if (idle && ticks - tp->t_rcvtime >= tp->t_rxtcur) {
		int rw = min(4 * tp->t_maxseg, max(2 * tp->t_maxseg, 4380));
		tp->snd_cwnd = min(rw, (int)tp->snd_cwnd);
		fprintf(stderr, "reset idle snd_cwnd: %d\n", tp->snd_cwnd);
	}

	tp->t_flags &= ~TF_LASTIDLE;
	if (idle) {
		if (tp->t_flags & TF_MORETOCOME) {
			tp->t_flags |= TF_LASTIDLE;
			idle = 0;
		}
	}

again:
	sendalot = 0;
	off = tp->snd_nxt - tp->snd_una;
	win = min(tp->snd_wnd, tp->snd_cwnd);
	flags = tcp_outflags[tp->t_state];

	if (tp->t_force) {
		if (win == 0) {
			if (off < rgn_len(tp->rgn_snd))
				flags &= ~TH_FIN;
			win = 1;
		} else {
			tp->t_timer[TCPT_PERSIST] = 0;
			tp->t_rxtshift = 0;
		}
	}

	len = min(rgn_len(tp->rgn_snd), win) - off;

	if (len < 0) {
		len = 0;
		if (win == 0) {
			tp->t_timer[TCPT_REXMT] = 0;
			tp->snd_nxt = tp->snd_una;
			tp->t_rxtshift = 0;
			if (tp->t_timer[TCPT_PERSIST] == 0)
				tcp_setpersist(tp);
		}
	}

	if (len > tp->t_maxseg) {
		len = tp->t_maxseg;
		sendalot = 1;
	}

	if (SEQ_LT(tp->snd_nxt + len, tp->snd_una + rgn_len(tp->rgn_snd)))
		flags &= ~TH_FIN;

	win = rgn_rest(tp->rgn_rcv);

	if (len) {
		if (len == tp->t_maxseg)
			goto sendit;

		if (idle && len + off >= rgn_len(tp->rgn_snd))
			goto sendit;

		if (tp->t_force)
			goto sendit;

		if ((u_long)len >= tp->max_sndwnd / 2 &&
				tp->max_sndwnd > 0)
			goto sendit;

		if (SEQ_LT(tp->snd_nxt, tp->snd_max))
			goto sendit;
	}

	if (win > 0 && !TCPS_HAVERCVDFIN(tp->t_state)) {
		long adv = min(win, (long) TCP_MAXWIN) -
			(tp->rcv_adv - tp->rcv_nxt);

		if (adv >= (long) (2 * tp->t_maxseg))
			goto sendit;

		if (2 * adv >= (long) rgn_size(tp->rgn_rcv))
			goto sendit;
	}

	if (tp->t_flags & TF_ACKNOW)
		goto sendit;

	if (flags & (TH_SYN | TH_RST))
		goto sendit;

	if (flags & TH_FIN &&
			((tp->t_flags & TF_SENTFIN) == 0 || tp->snd_nxt == tp->snd_una))
		goto sendit;

	if (rgn_len(tp->rgn_snd) && tp->t_timer[TCPT_REXMT] == 0 &&
			tp->t_timer[TCPT_PERSIST] == 0) {
		tp->t_rxtshift = 0;
		tcp_setpersist(tp);
	}

	return 0;

sendit:
	if (flags & TH_SYN) {
		tp->snd_nxt = tp->iss;
	}

	if (len) {
		if (tp->t_force && len == 1)
			tcpstat.tcps_sndprobe++;
		else if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
			tcpstat.tcps_sndrexmitpack++;
			tcpstat.tcps_sndrexmitbyte += len;
		} else {
			tcpstat.tcps_sndpack++;
			tcpstat.tcps_sndbyte += len;
		}
		rgn_peek(tp->rgn_snd, buf + sizeof(*ti), len, off);
		if (off + len == rgn_len(tp->rgn_snd))
			flags |= TH_PUSH;
	} else {
		if (tp->t_flags & TF_ACKNOW)
			tcpstat.tcps_sndacks++;
		else if (flags & (TH_SYN | TH_FIN | TH_RST))
			tcpstat.tcps_sndctrl++;
		else
			tcpstat.tcps_sndwinup++;
	}

	if (flags & TH_FIN && tp->t_flags & TF_SENTFIN &&
			tp->snd_nxt == tp->snd_max)
		tp->snd_nxt--;

	if (len || (flags & (TH_SYN | TH_FIN)) || tp->t_timer[TCPT_PERSIST])
		ti->ti_seq = htonl(tp->snd_nxt);
	else
		ti->ti_seq = htonl(tp->snd_max);

	ti->ti_res = 0x5a;
	ti->ti_ack = htonl(tp->rcv_nxt);
	ti->ti_tsval = htonl(ticks);
	ti->ti_tsecr = htonl(tp->ts_recent);
	ti->ti_flags = flags;
	ti->ti_len   = (u_short)len;

	if (win < (long) rgn_size(tp->rgn_rcv) / 4 && win < (long) tp->t_maxseg)
		win = 0;
	if (win > (long)TCP_MAXWIN)
		win = (long)TCP_MAXWIN;
	if (win < (long) (tp->rcv_adv - tp->rcv_nxt))
		win = (long) (tp->rcv_adv - tp->rcv_nxt);
	ti->ti_win = htons((u_short)win);

	if (tp->t_force == 0 || tp->t_timer[TCPT_PERSIST] == 0) {
		tcp_seq startseq = tp->snd_nxt;

		if (flags & (TH_SYN | TH_FIN)) {
			if (flags & TH_SYN)
				tp->snd_nxt++;
			if (flags & TH_FIN) {
				tp->snd_nxt++;
				tp->t_flags |= TF_SENTFIN;
			}
		}

		tp->snd_nxt += len;
		if (SEQ_GT(tp->snd_nxt, tp->snd_max)) {
			tp->snd_max = tp->snd_nxt;
			if (tp->t_rtttime == 0) {
				tp->t_rtttime = ticks;
				tp->t_rtseq = startseq;
				tcpstat.tcps_segstimed++;
			}
		}

		if (tp->t_timer[TCPT_REXMT] == 0 &&
				tp->snd_nxt != tp->snd_una) {
			tp->t_timer[TCPT_REXMT] = (ticks + tp->t_rxtcur);
			if (tp->t_timer[TCPT_PERSIST]) {
				tp->t_timer[TCPT_PERSIST] = 0;
				tp->t_rxtshift = 0;
			}
		}
	} else {
		int xlen = len;
		if (flags & TH_SYN)
			++xlen;
		if (flags & TH_FIN) {
			tp->t_flags |= TF_SENTFIN;
			++xlen;
		}
		if (SEQ_GT(tp->snd_nxt + xlen, tp->snd_max))
			tp->snd_max = tp->snd_nxt + len;
	}

	if (ti->ti_flags & TH_FIN)
		fprintf(stderr, "FIN: %x\n", ti->ti_flags & TH_FIN);

	error = sendto(tp->if_dev, buf, ti->ti_len + sizeof(*ti),
		   	0, (struct sockaddr *)&tp->dst_addr, sizeof(tp->dst_addr));
   	if (error == -1) {
		assert(WSAGetLastError() != 10035);
		tp->snd_nxt -= ti->ti_len;
		assert(tp->snd_nxt >= tp->snd_una);
	   	return -1;
   	}

	this_sent += ti->ti_len;
	tcpstat.tcps_sndtotal++;
	if (win > 0 && SEQ_GT(tp->rcv_nxt + win, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + win;
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~(TF_ACKNOW | TF_DELACK);

	if (sendalot && this_sent < 8192)
		goto again;

	return 0;
}

int tcp_respond(struct tcpcb * tp, struct tcphdr * orig, int flags)
{
	int error;
	char buf[2048];
	struct tcphdr * ti = (struct tcphdr *)buf;

	
	ti->ti_res = 0x5a;
	ti->ti_ack = htonl(orig->ti_seq + orig->ti_len);
	ti->ti_seq = htonl(orig->ti_ack);
	ti->ti_flags = flags;
	ti->ti_len   = (u_short)0;

	error = sendto(tp->if_dev, buf, sizeof(*ti),
		   	0, (struct sockaddr *)&tp->dst_addr, sizeof(tp->dst_addr));
	return error;
}
