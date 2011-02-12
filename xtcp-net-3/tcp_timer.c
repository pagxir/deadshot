#include <stdio.h>
#include <assert.h>
#include <winsock2.h>

#include "tcp.h"
#include "tcp_var.h"
#include "tcp_timer.h"

int tcp_keepidle = TCPTV_KEEP_IDLE;
int tcp_keepintvl = TCPTV_KEEPINTVL;
int tcp_rexmit_slop = TCPTV_CPU_VAR;

int tcp_keepcnt = TCPTV_KEEPCNT;
int tcp_maxidle = TCPTV_KEEPINTVL * TCPTV_KEEPCNT;

int tcp_fasttimeo(int * flags)
{
	struct tcpcb * tp;
	tp = tcp_last_tcpcb;
	if (tp != NULL &&
			(tp->t_flags & TF_DELACK)) {
		tp->t_flags |= TF_ACKNOW;
		tp->t_flags &= ~TF_DELACK;
		tcpstat.tcps_delack++;
		(void)tcp_output(tp);
	}

	return 0;
}

int tcp_slowtimeo(int * flags)
{
	int i;
	u_long rexmt, t_ticks;
	struct tcpcb * tp;
	tp = tcp_last_tcpcb;

	if (tp != NULL) {
		for (i = 0; i < TCPT_NTIMERS; i++) {
			if (tp->t_timer[i] && (u_long)ticks >= tp->t_timer[i]) {
				t_ticks = tp->t_timer[i];
				tp->t_timer[i] = 0;
				switch (i) {
					case TCPT_2MSL:
						if (tp->t_state != TCPS_TIME_WAIT &&
								ticks - (int)tp->t_rcvtime <= tcp_maxidle) {
							tp->t_timer[TCPT_2MSL] = (ticks + tcp_keepintvl);
						} else {
							tp->t_state = TCPS_CLOSED;
							fprintf(stderr, "tcps_time_wait -> tcps_closed: %d %d %d\n",
									ticks, t_ticks, ticks - t_ticks);
							if (tp->t_flags & TF_DETACH) {
								tcp_last_tcpcb = NULL;
								tcp_destroy(tp);
							}
						}
						break;

					case TCPT_REXMT:
						if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
							tp->t_rxtshift = TCP_MAXRXTSHIFT;
							tp->t_state = TCPS_CLOSED;
							tcpstat.tcps_timeoutdrop++;
							if (tp->t_flags & TF_DETACH) {
								tcp_last_tcpcb = NULL;
								tcp_destroy(tp);
							}
							*flags |= (XF_READ| XF_WRITE);
							break;
						}

						if (tp->t_rxtshift == 1) {
							tp->snd_cwnd_prev = tp->snd_cwnd;
							tp->snd_recover_prev = tp->snd_recover;
							tp->snd_ssthresh_prev = tp->snd_ssthresh;
							if (tp->t_flags & TF_FASTRECOVERY)
								tp->t_flags |= TF_WASFRECOVERY;
							else
								tp->t_flags &= ~TF_WASFRECOVERY;
							tp->t_badrxtwin = ticks + (tp->t_srtt >> (TCP_RTT_SHIFT + 1));
						}

						fprintf(stderr, "rexmt timeout: %d, seq %x shift %d!\n", tp->t_rxtcur, tp->snd_una, tp->t_rxtshift);
						fprintf(stderr, "reset snd_cwnd for timeout: %d, %d, %d\n",
								tp->snd_cwnd, tp->snd_wnd, tp->snd_ssthresh);
						tcpstat.tcps_rexmttimeo++;
						rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];
						TCPT_RANGESET(tp->t_rxtcur, rexmt, 
								(u_long)tp->t_rttmin, TCPTV_REXMTMAX);
						tp->t_timer[TCPT_REXMT] = (ticks + tp->t_rxtcur);

						if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {
							tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
							tp->t_srtt = 0;
						}
						tp->snd_nxt = tp->snd_una;
						tp->snd_recover = tp->snd_max;
						tp->t_flags |= TF_ACKNOW;
						tp->t_rtttime = 0;
						{
							u_int win = min(tp->snd_wnd, tp->snd_cwnd) /
								2 / tp->t_maxseg;
							if (win < 2)
								win = 2;
							tp->snd_cwnd = tp->t_maxseg;
							tp->snd_ssthresh = win * tp->t_maxseg;
							tp->t_dupacks = 0;
						}
						tp->t_flags &= ~TF_FASTRECOVERY;
						tp->t_bytes_acked = 0;
						(void)tcp_output(tp);
						break;

					case TCPT_PERSIST:
						tcpstat.tcps_persisttimeo++;
						tcp_setpersist(tp);
						tp->t_force = 1;
						(void)tcp_output(tp);
						tp->t_force = 0;
						break;

					case TCPT_KEEP:
						tcpstat.tcps_keeptimeo++;
						if (tp->t_state < TCPS_ESTABLISHED)
							goto dropit;
						if (tp->t_state <= TCPS_CLOSE_WAIT) {
							if (ticks - (int)tp->t_rcvtime >= tcp_keepintvl + tcp_maxidle)
								goto dropit;
							tcpstat.tcps_keepprobe++;
							/* tcp_respond */
							tp->t_timer[TCPT_KEEP] = (ticks + tcp_keepintvl);
						} else
							tp->t_timer[TCPT_KEEP] = (ticks + tcp_keepidle);
						break;
dropit:
						tcpstat.tcps_keepdrops++;
						tp->t_state = TCPS_CLOSED;
						if (tp->t_flags & TF_DETACH) {
						}
						break;

					default:
						assert(0);
						break;
				}
			}
		}

		tcp_iss += TCP_ISSINCR / 2;
	}

	return 0;
}

void tcp_canceltimers(struct tcpcb * tp)
{
	int i;
	for (i = 0; i < TCPT_NTIMERS; i++) {
		tp->t_timer[i] = 0;
	}
}

