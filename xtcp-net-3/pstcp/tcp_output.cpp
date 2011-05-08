#include <stdio.h>
#include <assert.h>
#include <winsock2.h>

#include "tcp.h"
#include "event.h"
#include "timer.h"
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
	assert( evt_inactive(&tp->t_timer_rexmt) );

	TCPT_RANGESET(persist_time,
			t * tcp_backoff[tp->t_rxtshift],
			TCPTV_PERSMIN, TCPTV_PERSMAX);
	callout_reset(&tp->t_timer_persist, persist_time);

	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
	return 0;
}

int tcp_output(struct tcpcb * tp)
{
	int error;
	int tilen = 0;
	long len, win;
	int off, flags;
	int idle, sendalot;
	char buf[2048];
	int optlen = 0;
	int this_sent = 0;
	tcp_seq this_snd_nxt = 0;
	struct tcphdr * ti = (struct tcphdr *)buf;

#if 0
	if ( tcp_busying() ) {
		tcp_devbusy(tp);
		return -1;
	}
#endif

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
	optlen = 0;
	sendalot = 0;
	this_snd_nxt = tp->snd_nxt;
	off = tp->snd_nxt - tp->snd_una;
	win = min(tp->snd_wnd, tp->snd_cwnd);
	flags = tcp_outflags[tp->t_state];

	if (tp->t_force) {
		if (win == 0) {
			if (off < rgn_len(tp->rgn_snd))
				flags &= ~TH_FIN;
			win = 1;
		} else {
			drop_event(&tp->t_timer_persist);
			tp->t_rxtshift = 0;
		}
	}

	len = min(rgn_len(tp->rgn_snd), win) - off;

	if (len < 0) {
		len = 0;
		if (win == 0) {
			drop_event(&tp->t_timer_rexmt);
			tp->snd_nxt = tp->snd_una;
			tp->t_rxtshift = 0;
			if ( evt_inactive(&tp->t_timer_persist) )
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

	if (rgn_len(tp->rgn_snd) &&
		   evt_inactive(&tp->t_timer_rexmt) &&
		   evt_inactive(&tp->t_timer_persist)) {
		tp->t_rxtshift = 0;
		tcp_setpersist(tp);
	}

	drop_event(&tp->t_event_devbusy);
	tp->t_flags &= ~TF_DEVBUSY;
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
		rgn_peek(tp->rgn_snd, buf + sizeof(*ti) + optlen, len, off);
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

	if (len || (flags & (TH_SYN | TH_FIN)) || 
			!evt_inactive(&tp->t_timer_persist))
		ti->ti_seq = htonl(tp->snd_nxt);
	else
		ti->ti_seq = htonl(tp->snd_max);

	ti->ti_magic = MAGIC_UDP_TCP;
	ti->ti_ack = htonl(tp->rcv_nxt);
	ti->ti_tsval = htonl(ticks);
	ti->ti_tsecr = htonl(tp->ts_recent);
	ti->ti_flags = flags;
	ti->ti_dst   = tp->td_port;
	ti->ti_src   = tp->ts_port;
	ti->ti_srcc  = tp->ts_addr;
	tilen   = (u_short)len;

	if (win < (long) rgn_size(tp->rgn_rcv) / 4 && win < (long) tp->t_maxseg)
		win = 0;
	if (win > (long)TCP_MAXWIN)
		win = (long)TCP_MAXWIN;
	if (win < (long) (tp->rcv_adv - tp->rcv_nxt))
		win = (long) (tp->rcv_adv - tp->rcv_nxt);
	ti->ti_win = htons((u_short)win);

	if (tp->t_force == 0 || evt_inactive(&tp->t_timer_persist)) {
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

		if (evt_inactive(&tp->t_timer_rexmt) &&
				tp->snd_nxt != tp->snd_una) {
			callout_reset(&tp->t_timer_rexmt, tp->t_rxtcur);
			if ( !evt_inactive(&tp->t_timer_persist) ) {
				drop_event(&tp->t_timer_persist);
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

	error = sendto(tp->if_dev, buf, tilen + sizeof(*ti),
		   	0, (struct sockaddr *)&tp->dst_addr, sizeof(tp->dst_addr));
   	if (error == -1) {
		tp->snd_nxt -= tilen;
		assert(tp->snd_nxt >= tp->snd_una);
		tcp_devbusy(tp);
	   	return -1;
   	}

	this_sent += tilen;
	tcpstat.tcps_sndtotal++;
	if (win > 0 && SEQ_GT(tp->rcv_nxt + win, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + win;
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~(TF_ACKNOW | TF_DELACK | TF_PREDELACKED);
	drop_event(&tp->t_event_delack);

	if (sendalot && this_sent < TCP_MSS * 2)
		goto again;

#if 0
	if (sendalot) {
		tcp_devbusy(tp);
		return -1;
	}
#endif

	drop_event(&tp->t_event_devbusy);
	tp->t_flags &= ~TF_DEVBUSY;
	return 0;
}

int tcp_respond(struct tcpcb * tp, struct tcphdr * orig, int tilen, int flags)
{
	int error;
	char buf[2048];
	struct tcphdr * ti = (struct tcphdr *)buf;

	
	ti->ti_magic = MAGIC_UDP_TCP;
	ti->ti_ack = htonl(orig->ti_seq + tilen);
	ti->ti_seq = htonl(orig->ti_ack);
	ti->ti_src = orig->ti_dst;
	ti->ti_srcc = tp->ts_addr;
	ti->ti_dst  = orig->ti_src;
	ti->ti_flags = flags;
	ti->ti_win   = 0;
	ti->ti_tsecr = htonl(orig->ti_tsval);
	ti->ti_tsval = htonl(orig->ti_tsecr);

	error = sendto(tp->if_dev, buf, sizeof(*ti),
		   	0, (struct sockaddr *)&tp->dst_addr, sizeof(tp->dst_addr));
	return error;
}

