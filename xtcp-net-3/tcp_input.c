#include <stdio.h>
#include <assert.h>
#include <winsock2.h>

#include "tcp.h"
#include "rgnbuf.h"
#include "tcp_var.h"
#include "tcp_timer.h"

#define tcp_rcvseqinit(tp) \
	(tp)->rcv_adv = (tp)->rcv_nxt = (tp)->irs + 1;

#define tcp_sendseqinit(tp) \
	(tp)->snd_una = (tp)->snd_nxt = (tp)->snd_max = (tp)->iss;

int tcp_iss = 0;

static int tcprexmtthresh = 3;
static int TCP_PAWS_IDLE = 24 * 24 * 60 * 60 * T_HZ;
static void tcp_xmit_timer(struct tcpcb * tp, int rtt);
static void tcp_newreno_partial_ack(struct tcpcb * tp, struct tcphdr * ti);

void tcp_input(struct tcpcb * tp, int dst, const char * buf,
		size_t len, int * flags, const struct sockaddr_in * src_addr)
{
	int tiflags;
	int todrop, acked;
	int needoutput = 0;
	int ourfinisacked = 0;
	struct tcphdr * ti;
	const char * dat = buf + sizeof(*ti);
	u_long ts_val, ts_ecr, tiwin;

	ti = (struct tcphdr *)buf;
	assert(len >= sizeof(*ti));
	assert(len >= sizeof(*ti) + ti->ti_len && len < 2048);
	tcpstat.tcps_rcvtotal++;

	if ((ti->ti_flags & TH_SYN) == 0) {
		ts_val = ntohl((u_long) ti->ti_tsval);
		ts_ecr = ntohl((u_long) ti->ti_tsecr);
	}

	tiflags = ti->ti_flags;

	ti->ti_seq = ntohl(ti->ti_seq);
	ti->ti_ack = ntohl(ti->ti_ack);
	ti->ti_win = ntohs(ti->ti_win);

	if (tiflags & TH_FIN) {
		int i = 0;
		i++;
	}

	tiwin = ti->ti_win;

	tp->t_rcvtime = ticks;
	tp->t_timer[TCPT_KEEP] = (ticks + tcp_keepidle);

	if (tiflags & TH_SYN) {
		ts_val = ntohl((u_long) ti->ti_tsval);
		ts_ecr = ntohl((u_long) ti->ti_tsecr);
		tp->ts_recent = ts_val;
		tp->ts_recent_age = ticks;
	}

	if (tp->t_state == TCPS_ESTABLISHED &&
			(tiflags & (TH_SYN | TH_FIN | TH_RST | TH_ACK)) == TH_ACK &&
			TSTMP_GEQ(ts_val, tp->ts_recent) &&
			ti->ti_seq == tp->rcv_nxt &&
			rgn_frgcnt(tp->rgn_rcv) == 0 &&
			tiwin && tiwin == tp->snd_wnd &&
			tp->snd_nxt == tp->snd_max) {

		if (SEQ_LEQ(ti->ti_seq, tp->last_ack_sent) &&
				SEQ_LT(tp->last_ack_sent, ti->ti_seq + ti->ti_len)) {
			tp->ts_recent_age = ticks;
			tp->ts_recent = ts_val;
		}

		if (ti->ti_len == 0) {
			if (SEQ_GT(ti->ti_ack, tp->snd_una) &&
					SEQ_LEQ(ti->ti_ack, tp->snd_max) &&
					tp->snd_cwnd >= tp->snd_wnd &&
					((tp->t_flags & TF_FASTRECOVERY) == 0)) {
				++tcpstat.tcps_predack;
				tcp_xmit_timer(tp, (ticks - ts_ecr + 1)); 
				acked = ti->ti_ack - tp->snd_una;
				tcpstat.tcps_rcvackpack++;
				tcpstat.tcps_rcvackbyte += acked;

				if (tp->t_rxtshift == 1 &&
						(int)(ticks - tp->t_badrxtwin) < 0) {
					tcpstat.tcps_sndrexmitbad++;
					tp->snd_cwnd = tp->snd_cwnd_prev;
					tp->snd_ssthresh = tp->snd_ssthresh_prev;
					tp->snd_recover = tp->snd_recover_prev;
					if (tp->t_flags & TF_WASFRECOVERY) {
						tp->t_flags |= TF_FASTRECOVERY;
					}
					tp->snd_nxt = tp->snd_max;
					tp->t_badrxtwin = 0;
				}

				rgn_drop(tp->rgn_snd, acked);
				if (SEQ_GT(tp->snd_una, tp->snd_recover) &&
						SEQ_LEQ(ti->ti_ack, tp->snd_recover))
					tp->snd_recover = ti->ti_ack - 1;
				tp->snd_una = ti->ti_ack;

				if (SEQ_GT(tp->snd_una, tp->snd_recover))
					tp->snd_recover = tp->snd_una;

				tp->snd_wl2 = ti->ti_ack;
				tp->t_dupacks = 0;

				if (tp->snd_una == tp->snd_max)
					tp->t_timer[TCPT_REXMT] = 0;
				else if (tp->t_timer[TCPT_PERSIST] == 0)
					tp->t_timer[TCPT_REXMT] = (ticks + tp->t_rxtcur);

				*flags |= XF_WRITE;
				if (rgn_len(tp->rgn_snd)) {
					(void) tcp_output(tp);
				}
				return;
			}
		} else if (ti->ti_ack == tp->snd_una &&
				ti->ti_len <= rgn_rest(tp->rgn_rcv)) {
			++tcpstat.tcps_preddat;
			tp->rcv_nxt += ti->ti_len;
			tcpstat.tcps_rcvpack++;
			tcpstat.tcps_rcvbyte += ti->ti_len;
			rgn_put(tp->rgn_rcv, dat, ti->ti_len);
			*flags |= XF_READ;
			if (tp->t_flags & TF_DELACK) {
				*flags |= XF_ACKNOW;
			} else {
				tp->t_flags |= TF_DELACK;
			}
			tp->snd_wl1 = ti->ti_seq;
			return;
		}
	}

	do {
		int win;

		win = rgn_rest(tp->rgn_rcv);
		if (win < 0)
			win = 0;
		tp->rcv_wnd = max(win, (int) (tp->rcv_adv - tp->rcv_nxt));
	} while ( 0 );

	switch (tp->t_state) {
		case TCPS_LISTEN:
			if (tiflags & TH_RST)
				goto dropit;

			if (tiflags & TH_ACK)
				goto dropitwithreset;

			if ((tiflags & TH_SYN) == 0)
				goto dropit;

			tp->iss = tcp_iss;
			tcp_iss += TCP_ISSINCR / 2;
			tp->irs = ti->ti_seq;
			tp->t_flags |= TF_ACKNOW;
			tp->t_state = TCPS_SYN_RECEIVED;
			tp->t_timer[TCPT_KEEP] = (ticks + TCPTV_KEEP_INIT);
			tcp_rcvseqinit(tp);
			tcp_sendseqinit(tp);
			memcpy(&tp->dst_addr, src_addr, sizeof(tp->dst_addr));
			tcpstat.tcps_accepts++;
			fprintf(stderr, "TCPS_LISTEN -> TCPS_SYN_RECEIVED\n");
			goto trimthenstep6;

		case TCPS_SYN_SENT:
			if ((tiflags & TH_ACK) &&
					(SEQ_LEQ(ti->ti_ack, tp->iss) ||
					 SEQ_GT(ti->ti_ack, tp->snd_max))) {
				fprintf(stderr, "connect error!\n");
				goto dropitwithreset;
			}

			if ((tiflags & (TH_RST| TH_ACK)) == (TH_RST| TH_ACK)) {
				*flags |= (XF_READ| XF_WRITE);
				tp->t_state = TCPS_CLOSED;
			}

			if (tiflags & TH_RST) {
				goto dropit;
			}
			
			if ((tiflags & TH_SYN) == 0)
				goto dropit;

			if (tiflags & TH_ACK) {
				tp->snd_una = ti->ti_ack;
				if (SEQ_GT(tp->snd_una, tp->snd_recover))
					tp->snd_recover = tp->snd_una;

				if (SEQ_LT(tp->snd_nxt, tp->snd_una))
					tp->snd_nxt = tp->snd_una;
			}

			tp->t_timer[TCPT_REXMT] = 0;
			tp->irs = ti->ti_seq;
			tcp_rcvseqinit(tp);
			tp->t_flags |= TF_ACKNOW;
			if (tiflags & TH_ACK) {
				tcpstat.tcps_connects++;
				tp->t_state = TCPS_ESTABLISHED;
				fprintf(stderr, "TCPS_SYN_SENT -> TCPS_ESTABLISHED\n");
				if (tp->t_rtttime)
					tcp_xmit_timer(tp, (ticks - tp->t_rtttime));
				*flags |= XF_WRITE;
			} else {
				tp->t_state = TCPS_SYN_RECEIVED;
				fprintf(stderr, "TCPS_SYN_SENT -> TCPS_SYN_RECEIVED\n");
			}
trimthenstep6:
			ti->ti_seq++;
			if (ti->ti_len > tp->rcv_wnd) {
				todrop = ti->ti_len - tp->rcv_wnd;
				ti->ti_len = (short)tp->rcv_wnd;
				tiflags &= ~TH_FIN;
				tcpstat.tcps_rcvpackafterwin++;
				tcpstat.tcps_rcvbyteafterwin += todrop;
			}
			tp->snd_wl1 = ti->ti_seq  - 1;
			goto step6;
	}

	if ((tiflags & TH_RST) == 0 && tp->ts_recent &&
			TSTMP_LT(ts_val, tp->ts_recent)) {
		if ((int)(ticks - tp->ts_recent_age) > TCP_PAWS_IDLE) {
			tp->ts_recent = 0;
		} else {
			tcpstat.tcps_rcvduppack++;
			tcpstat.tcps_rcvdupbyte += ti->ti_len;
			tcpstat.tcps_pawsdrop++;
			fprintf(stderr, "drop for time stamp\n");
			goto dropitafterack;
		}
	}

	todrop = tp->rcv_nxt - ti->ti_seq;
	if (todrop > 0) {
		if (tiflags & TH_SYN &&
			   	ti->ti_seq == tp->irs) {
			tiflags &= ~TH_SYN;
			ti->ti_seq++;
			todrop--;
		}

		if (todrop > ti->ti_len ||
				todrop == ti->ti_len && (tiflags & TH_FIN) == 0) {
			tiflags &= ~TH_FIN;
			tp->t_flags |= TF_ACKNOW;
			todrop = ti->ti_len;

			tcpstat.tcps_rcvduppack++;
			tcpstat.tcps_rcvdupbyte += todrop;
		} else {
			tcpstat.tcps_rcvpartduppack++;
			tcpstat.tcps_rcvpartdupbyte += todrop;
		}

		ti->ti_seq += todrop;
		ti->ti_len -= todrop;
		dat += todrop;
	}

	/* Do not support half open connect. */
	if (tp->t_state > TCPS_CLOSE_WAIT &&
			ti->ti_len) {
		tcpstat.tcps_rcvafterclose++;
		goto dropitwithreset;
	}

	todrop = (ti->ti_seq + ti->ti_len) - (tp->rcv_nxt + tp->rcv_wnd);
	if (todrop > 0) {
		tcpstat.tcps_rcvpackafterwin++;
		if (todrop >= ti->ti_len) {
			tcpstat.tcps_rcvbyteafterwin += ti->ti_len;
			if (tiflags & TH_SYN && 
					tp->t_state == TCPS_TIME_WAIT &&
					SEQ_GT(ti->ti_seq, tp->rcv_nxt)) {
				int iss = tp->rcv_nxt + TCP_ISSINCR;
				fprintf(stderr, "receive SYN on TCPS_TIME_WAIT\n");
				goto dropit;
			}

			if (tp->rcv_wnd == 0 && ti->ti_seq == tp->rcv_nxt) {
				tp->t_flags |= TF_ACKNOW;
				tcpstat.tcps_rcvwinprobe++;
			} else {
				fprintf(stderr, "drop for out of win\n");
				goto dropitafterack;
			}
		} else
			tcpstat.tcps_rcvbyteafterwin += todrop;
		ti->ti_len -= todrop;
		tiflags &= ~(TH_PUSH | TH_FIN);
	}

	if (TSTMP_GEQ(ts_val, tp->ts_recent) &&
			SEQ_LEQ(ti->ti_seq, tp->last_ack_sent)) {
		tp->ts_recent_age = ticks;
		tp->ts_recent = ts_val;
	}

	if (tiflags & TH_RST) {
		*flags |= (XF_READ| XF_WRITE);
		tp->t_state = TCPS_CLOSED;
		goto dropit;
	}

	if (tiflags & TH_SYN) {
		fprintf(stderr, "bad SYN: %d\n", tp->t_state);
		*flags |= (XF_READ| XF_WRITE);
		tp->t_state = TCPS_CLOSED;
		goto dropit;
	}

	if ((tiflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_ACKNOW)
			goto dropitafterack;
		goto dropit;
	}

	switch(tp->t_state) {
		case TCPS_SYN_RECEIVED:
			if (SEQ_GT(tp->snd_una, ti->ti_ack) ||
					SEQ_GT(ti->ti_ack, tp->snd_max))
				goto dropitwithreset;
			tcpstat.tcps_connects++;
			tp->t_state = TCPS_ESTABLISHED;
			fprintf(stderr, "TCPS_SYN_RECEIVED -> TCPS_ESTABLISHED\n");
			tp->t_timer[TCPT_KEEP] = (ticks + tcp_keepidle);
			tp->snd_wl1 = ti->ti_seq - 1;
			*flags |= XF_WRITE;
		case TCPS_ESTABLISHED:
		case TCPS_FIN_WAIT_1:
		case TCPS_FIN_WAIT_2:
		case TCPS_CLOSE_WAIT:
		case TCPS_CLOSING:
		case TCPS_LAST_ACK:
		case TCPS_TIME_WAIT:
			if (SEQ_LEQ(ti->ti_ack, tp->snd_una)) {
				if (ti->ti_len == 0 && tiwin == tp->snd_wnd) {
					tcpstat.tcps_rcvduppack++;
					if (tp->t_timer[TCPT_REXMT] == 0 ||
							ti->ti_ack != tp->snd_una)
						tp->t_dupacks = 0;
					else if (++tp->t_dupacks > tcprexmtthresh ||
							(tp->t_flags & TF_FASTRECOVERY)) {
						tp->snd_cwnd += tp->t_maxseg;
						(void)tcp_output(tp);
					} else if (tp->t_dupacks == tcprexmtthresh) {
						u_int win;
						tcp_seq onxt = tp->snd_nxt;

						if (SEQ_LEQ(ti->ti_ack, tp->snd_recover)) {
							tp->t_dupacks = 0;
							break;
						}

						win = umin(tp->snd_wnd, tp->snd_cwnd) /
						   	2 / tp->t_maxseg;
						if (win < 2)
							win = 2;
						tp->t_flags |= TF_FASTRECOVERY;
						tp->snd_recover = tp->snd_max;
						tp->snd_ssthresh = win * tp->t_maxseg;
						tp->t_timer[TCPT_REXMT] = 0;
						tp->t_rtttime = 0;
						tp->snd_nxt = ti->ti_ack;
						tp->snd_cwnd = tp->t_maxseg;
						(void)tcp_output(tp);
						tp->snd_cwnd = tp->snd_ssthresh +
							tp->t_maxseg * (tp->t_dupacks - tp->snd_limited);
						if (SEQ_GT(onxt, tp->snd_nxt))
							tp->snd_nxt = onxt;
#if 0
						fprintf(stderr, "fast rexmit snd_cwnd: %d\n",
							   	tp->snd_cwnd);
#endif
						goto dropit;
					} else {
						u_int sent;
						u_long oldcwnd = tp->snd_cwnd;
						tcp_seq oldsndmax = tp->snd_max;

						assert(tp->t_dupacks == 1 ||
							   	tp->t_dupacks == 2);
						if (tp->t_dupacks == 1)
							tp->snd_limited = 0;

						tp->snd_cwnd = 
							(tp->snd_nxt - tp->snd_una) +
							(tp->t_dupacks - tp->snd_limited) * tp->t_maxseg;
						(void)tcp_output(tp);
						sent = tp->snd_max - oldsndmax;
						if (sent > tp->t_maxseg) {
							tp->snd_limited = 2;
						} else if (sent > 0)
							++tp->snd_limited;
						tp->snd_cwnd = oldcwnd;
						goto dropit;
					}
				} else 
					tp->t_dupacks = 0;
				break;
			}

			if (tp->t_flags & TF_FASTRECOVERY) {
				if (SEQ_LT(ti->ti_ack, tp->snd_recover)) {
					tcp_newreno_partial_ack(tp, ti);
				} else {
				   	if (SEQ_GT(ti->ti_ack + tp->snd_ssthresh,
							   	tp->snd_max))
					   	tp->snd_cwnd = tp->snd_max -
						   	ti->ti_ack + tp->t_maxseg;
				   	else
					   	tp->snd_cwnd = tp->snd_ssthresh;
				}
			}

			tp->t_dupacks = 0;

			if (SEQ_GT(ti->ti_ack, tp->snd_max)) {
				tcpstat.tcps_rcvacktoomuch++;
				assert(0);
				goto dropitafterack;
			}

			acked = ti->ti_ack - tp->snd_una;
			tcpstat.tcps_rcvackpack++;
			tcpstat.tcps_rcvackbyte += acked;

			if (tp->t_rxtshift == 1 &&
					(int)(ticks - tp->t_badrxtwin) < 0) {
				tcpstat.tcps_sndrexmitbad++;
				tp->snd_cwnd = tp->snd_cwnd_prev;
				tp->snd_recover = tp->snd_recover_prev;
				tp->snd_ssthresh = tp->snd_ssthresh_prev;
				if (tp->t_flags & TF_WASFRECOVERY)
					tp->t_flags |= TF_FASTRECOVERY;
				tp->snd_nxt = tp->snd_max;
				tp->t_badrxtwin = 0;
			}

			tcp_xmit_timer(tp, (ticks - ts_ecr + 1));

			if (ti->ti_ack == tp->snd_max) {
				tp->t_timer[TCPT_REXMT] = 0;
				needoutput = 1;
			} else if (tp->t_timer[TCPT_PERSIST] == 0)
				tp->t_timer[TCPT_REXMT] = (ticks + tp->t_rxtcur);

			if (acked == 0)
				goto step6;

			if ((tp->t_flags & TF_FASTRECOVERY) == 0) {
				u_int cw = tp->snd_cwnd;
				u_int incr = tp->t_maxseg;

				if (cw > tp->snd_ssthresh) {
					tp->t_bytes_acked += acked;
					if (tp->t_bytes_acked >= tp->snd_cwnd)
						tp->t_bytes_acked -= cw;
					else
						incr = 0;
				} else if (tp->snd_nxt == tp->snd_max) {
					incr = min(acked, tp->t_maxseg * 1);
				}

				if (incr == 0 &&
						SEQ_GT(ti->ti_ack, tp->t_rtseq))
					incr = 1;
				if (incr > 0) {
					tp->snd_cwnd = cw + incr;
				}
			}
skip_upwin:

			if (acked > rgn_len(tp->rgn_snd)) {
				tp->snd_wnd -= rgn_len(tp->rgn_snd);
				rgn_clear(tp->rgn_snd);
				ourfinisacked = 1;
			} else {
				rgn_drop(tp->rgn_snd, acked);
				tp->snd_wnd -= acked;
				ourfinisacked = 0;
				needoutput = 1;
			}
			*flags |= XF_WRITE;

			if (((tp->t_flags & TF_FASTRECOVERY) == 0) &&
					SEQ_GT(tp->snd_una, tp->snd_recover) &&
					SEQ_LEQ(ti->ti_ack, tp->snd_recover))
				tp->snd_recover = ti->ti_ack - 1;

			if ((tp->t_flags & TF_FASTRECOVERY) &&
					SEQ_GEQ(ti->ti_ack, tp->snd_recover)) {
				tp->t_flags &= ~TF_FASTRECOVERY;
				tp->t_bytes_acked = 0;
			}

			tp->snd_una = ti->ti_ack;
			if (SEQ_LT(tp->snd_nxt, tp->snd_una))
				tp->snd_nxt = tp->snd_una;

			switch (tp->t_state) {
				case TCPS_FIN_WAIT_1:
					if (ourfinisacked) {
						tp->t_timer[TCPT_2MSL] = (ticks + tcp_maxidle);
						tp->t_state = TCPS_FIN_WAIT_2;
						fprintf(stderr, "TCPS_FIN_WAIT_1 -> TCPS_FIN_WAIT_2\n");
					}
					break;

				case TCPS_CLOSING:
					if (ourfinisacked) {
						tp->t_state = TCPS_TIME_WAIT;
						fprintf(stderr, "TCPS_CLOSING -> TCPS_TIME_WAIT\n");
						tcp_canceltimers(tp);
						tp->t_timer[TCPT_2MSL] = (ticks + 2 * TCPTV_MSL);
					}
					break;

				case TCPS_LAST_ACK:
					if (ourfinisacked) {
						fprintf(stderr, "TCPS_LAST_ACK -> TCPS_CLOSED\n");
						tp->t_state = TCPS_CLOSED;
						if (tp->t_flags & TF_DETACH) {
							tcp_detach(tp);
						}
						goto dropit;
					}
					break;

				case TCPS_TIME_WAIT:
					tp->t_timer[TCPT_2MSL] = (ticks + 2 * TCPTV_MSL);
					goto dropitafterack;
					break;
			}

		default:
			break;
	}

step6:
	if ((tiflags & TH_ACK) &&
			(SEQ_LT(tp->snd_wl1, ti->ti_seq) ||
			 tp->snd_wl1 == ti->ti_seq &&
			 (SEQ_LT(tp->snd_wl2, ti->ti_ack) || 
			  tp->snd_wl2 == ti->ti_ack && tiwin > tp->snd_wnd))) {

		if (ti->ti_len == 0 &&
				tp->snd_wl2 == ti->ti_ack && tiwin > tp->snd_wnd)
			tcpstat.tcps_rcvwinupd++;

		tp->snd_wnd = tiwin;
		tp->snd_wl1 = ti->ti_seq;
		tp->snd_wl2 = ti->ti_ack;
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
		needoutput = 1;
	}

	goto dodata;

dodata:
	if ((ti->ti_len || (tiflags & TH_FIN)) &&
			TCPS_HAVERCVDFIN(tp->t_state) == 0) {
		if (ti->ti_seq == tp->rcv_nxt &&
				rgn_frgcnt(tp->rgn_rcv) == 0 &&
				tp->t_state >= TCPS_ESTABLISHED) {
			if (tp->t_flags & TF_DELACK) {
				*flags |= XF_ACKNOW;
			} else {
				tp->t_flags |= TF_DELACK;
			}
			rgn_put(tp->rgn_rcv, dat, ti->ti_len);
			tp->rcv_nxt += ti->ti_len;
			tiflags = (ti->ti_flags & TH_FIN);
			tcpstat.tcps_rcvpack ++;
			tcpstat.tcps_rcvbyte += ti->ti_len;
			*flags |= XF_READ;
		} else if (ti->ti_len) {
			if (SEQ_GT(ti->ti_seq, tp->rcv_nxt)) {
				int off = (ti->ti_seq - tp->rcv_nxt);
				rgn_fragment(tp->rgn_rcv, dat, ti->ti_len, off);
				tiflags = 0;
			} else {
				rgn_put(tp->rgn_rcv, dat, ti->ti_len);
				tp->rcv_nxt += rgn_reass(tp->rgn_rcv);
				tp->rcv_nxt += ti->ti_len;
				*flags |= XF_READ;
			}
			tiflags = rgn_frgcnt(tp->rgn_rcv)? 0: tiflags;
			tp->t_flags |= TF_ACKNOW;
		}
	} else {
		tiflags &= ~TH_FIN;
	}

	if (tiflags & TH_FIN) {
		if (TCPS_HAVERCVDFIN(tp->t_state) == 0) {
			tp->t_flags |= TF_ACKNOW;
			tp->rcv_nxt++;
		}

		switch(tp->t_state) {
			case TCPS_SYN_RECEIVED:
			case TCPS_ESTABLISHED:
				fprintf(stderr, "TCPS_ESTABLISHED -> TCPS_CLOSE_WAIT\n");
				tp->t_state = TCPS_CLOSE_WAIT;
				*flags |= XF_READ;
				break;

			case TCPS_FIN_WAIT_1:
				fprintf(stderr, "TCPS_FIN_WAIT_1 -> TCPS_CLOSING\n");
				tp->t_state = TCPS_CLOSING;
				*flags |= XF_READ;
				break;

			case TCPS_FIN_WAIT_2:
				fprintf(stderr, "TCPS_FIN_WAIT_2 -> TCPS_TIME_WAIT\n");
				tp->t_state = TCPS_TIME_WAIT;
				tcp_canceltimers(tp); 
				tp->t_timer[TCPT_2MSL] = (ticks + 2 * TCPTV_MSL);
				*flags |= XF_READ;
				break;

			case TCPS_TIME_WAIT:
				tp->t_timer[TCPT_2MSL] = (ticks + 2 * TCPTV_MSL);
				break;
		}
	}

	if (needoutput || (tp->t_flags & TF_ACKNOW))
		(void)tcp_output(tp);
	return;

dropitafterack:
	if (tiflags & TH_RST)
		goto dropit;

	tp->t_flags |= TF_ACKNOW;
	(void) tcp_output(tp);
	return;

dropitwithreset:
	if (tiflags & TH_RST)
		goto dropit;

	if (tiflags & TH_ACK)
		tcp_respond(tp, ti, TH_RST);
	else {
		if (tiflags & TH_SYN)
			ti->ti_len++;
		tcp_respond(tp, ti, TH_RST| TH_ACK);
	}
	return;

dropit:
	return;
}

static void tcp_newreno_partial_ack(struct tcpcb * tp, struct tcphdr * ti)
{ 
	tcp_seq onxt = tp->snd_nxt;
	u_long ocwnd = tp->snd_cwnd;

	tp->t_timer[TCPT_REXMT] = 0;
	tp->t_rtttime = 0;
	tp->snd_nxt = ti->ti_ack;

	tp->snd_cwnd = tp->t_maxseg + (ti->ti_ack - tp->snd_una);
	tp->t_flags |= TF_ACKNOW;
	(void)tcp_output(tp);
	tp->snd_cwnd = ocwnd;
	if (SEQ_GT(onxt, tp->snd_nxt))
		tp->snd_nxt = onxt;

	if (tp->snd_cwnd > ti->ti_ack - tp->snd_una)
		tp->snd_cwnd -= (ti->ti_ack - tp->snd_una);
	else
		tp->snd_cwnd = 0;

	tp->snd_cwnd += tp->t_maxseg;
}

static void tcp_xmit_timer(struct tcpcb * tp, int rtt)
{
	int delta;

	tcpstat.tcps_rttupdated++;
	if (tp->t_srtt != 0) {
		delta = ((rtt - 1) << TCP_DELTA_SHIFT) 
			- (tp->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT));

		if ((tp->t_srtt += delta) <= 0)
			tp->t_srtt = 1;

		if (delta < 0)
			delta = -delta;

		delta -= tp->t_rttvar >> (TCP_RTTVAR_SHIFT - TCP_DELTA_SHIFT);
		if ((tp->t_rttvar += delta) <= 0)
			tp->t_rttvar = 1;

	} else {
		tp->t_srtt = rtt << TCP_RTT_SHIFT;
		tp->t_rttvar = rtt << (TCP_RTTVAR_SHIFT - 1);
	}

	tp->t_rtttime = 0;
	tp->t_rxtshift = 0;
	TCPT_RANGESET(tp->t_rxtcur, TCP_REXMTVAL(tp),
			max(tp->t_rttmin, rtt + 2), TCPTV_REXMTMAX);
	return;
}

