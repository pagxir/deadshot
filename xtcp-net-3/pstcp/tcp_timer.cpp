#include <stdio.h>
#include <assert.h>
#include <winsock2.h>

#include "tcp.h"
#include "event.h"
#include "timer.h"
#include "modules.h"
#include "tcp_var.h"
#include "tcp_timer.h"

int tcp_keepidle = TCPTV_KEEP_IDLE;
int tcp_keepintvl = TCPTV_KEEPINTVL;
int tcp_rexmit_slop = TCPTV_CPU_VAR;

int tcp_keepcnt = TCPTV_KEEPCNT;
int tcp_maxidle = TCPTV_KEEPINTVL * TCPTV_KEEPCNT;

void tcp_canceltimers(struct tcpcb * tp)
{
	drop_event(&tp->t_timer_persist);
	drop_event(&tp->t_timer_rexmt);
	drop_event(&tp->t_timer_keep);
	drop_event(&tp->t_timer_2msl);
}

static void tcp_2msl_timo(void * up)
{ 
   	struct tcpcb * tp;

	tp = (struct tcpcb *)up;
   	if (tp->t_state != TCPS_TIME_WAIT &&
		   	ticks - (int)tp->t_rcvtime <= tcp_maxidle) {
		callout_reset(&tp->t_timer_2msl, tcp_keepintvl);
   	} else {
	   	tp->t_state = TCPS_CLOSED;
	   	tcp_disconnect(tp);
   	}

	return;
}

static void tcp_persist_timo(void * up)
{
   	struct tcpcb * tp;

	tp = (struct tcpcb *)up;
   	tcpstat.tcps_persisttimeo++;
   	tcp_setpersist(tp);
   	tp->t_force = 1;
   	(void)tcp_output(tp);
   	tp->t_force = 0;

	return;
}

static void tcp_rexmt_timo(void * up)
{
	u_long rexmt;
   	struct tcpcb * tp;

	fprintf(stderr, "tcp rexmt time out\n");

	tp = (struct tcpcb *)up;
   	if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
	   	tp->t_rxtshift = TCP_MAXRXTSHIFT;
	   	tp->t_state = TCPS_CLOSED;
	   	tcpstat.tcps_timeoutdrop++;
	   	tcp_rwakeup(tp);
	   	tcp_wwakeup(tp);
	   	tcp_disconnect(tp);
		return;
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
   
	tcpstat.tcps_rexmttimeo++;
   	rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];
   	TCPT_RANGESET(tp->t_rxtcur, rexmt, 
			(u_long)tp->t_rttmin, TCPTV_REXMTMAX);
	callout_reset(&tp->t_timer_rexmt, tp->t_rxtcur);

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

	return;
}

static void tcp_keep_timo(void * up)
{
   	struct tcpcb * tp;

	tp = (struct tcpcb *)up;
   	tcpstat.tcps_keeptimeo++;
   	if (tp->t_state < TCPS_ESTABLISHED)
	   	goto dropit;
   	if (tp->t_state <= TCPS_CLOSE_WAIT) {
	   	if (ticks - (int)tp->t_rcvtime >= tcp_keepintvl + tcp_maxidle)
		   	goto dropit;
	   	tcpstat.tcps_keepprobe++;
	   	/* tcp_respond */
		callout_reset(&tp->t_timer_keep, tcp_keepintvl);
   	} else
		callout_reset(&tp->t_timer_keep, tcp_keepidle);
	return;

dropit:
   	tcpstat.tcps_keepdrops++;
   	tp->t_state = TCPS_CLOSED;
	tcp_disconnect(tp);

	return;
}

static void tcp_do_delack(void * uup)
{
	struct tcpcb * tp;

	tp = (struct tcpcb *)uup;
	tp->t_flags &= ~TF_PREDELACKED;

	if (tp->t_flags & TF_DELACK) {
		tp->t_flags |= TF_ACKNOW;
		tp->t_flags &= ~TF_DELACK;
		tcpstat.tcps_delack++;
		(void)tcp_output(tp);
	}

	return;
}

static void tcp_output_wrap(void * uup)
{
	struct tcpcb * tp;
	tp = (struct tcpcb *)uup;
	(void)tcp_output(tp);
	return;
}

void tcp_setuptimers(struct tcpcb * tp)
{
	event_init(&tp->t_timer_2msl, tcp_2msl_timo, tp);
	event_init(&tp->t_timer_keep, tcp_keep_timo, tp);
	event_init(&tp->t_timer_rexmt, tcp_rexmt_timo, tp);
	event_init(&tp->t_event_delack, tcp_do_delack, tp);
	event_init(&tp->t_timer_persist, tcp_persist_timo, tp);
	event_init(&tp->t_event_devbusy, tcp_output_wrap, tp);
}

void tcp_cleantimers(struct tcpcb * tp)
{
	event_clean(&tp->t_timer_2msl);
	event_clean(&tp->t_timer_keep);
	event_clean(&tp->t_timer_rexmt);
	event_clean(&tp->t_event_delack);
	event_clean(&tp->t_timer_persist);
	event_clean(&tp->t_event_devbusy);
}

static event_t _iss_timer;
static event_t _delack_timer;
static event_t * _delack_queue;

void tcp_prepare_acknow(struct tcpcb * tp)
{
	if (tp->t_flags & TF_PREDELACKED) {
		drop_event(&tp->t_event_delack);
		tp->t_flags &= ~TF_PREDELACKED;
	}

	if ( evt_inactive(&tp->t_event_delack) )
	   	event_insert_tailer(&tp->t_event_delack);

	return;
}

void tcp_prepare_delack(struct tcpcb * tp)
{
	if (tp->t_flags & TF_PREDELACKED)
		return;
	drop_event(&tp->t_event_delack);
	event_insert_header(&_delack_queue, &tp->t_event_delack);
	return;
}

static void inc_iss(void * up)
{
	int * p_iss;

	p_iss = (int *)up;
	(*p_iss)++;

	callout_reset(&_iss_timer, 500);
}

static void flush_delack(void * up)
{
   	event_t * evt;
	event_t ** pp_evt;

	pp_evt = (event_t **)up;
	while (*pp_evt) {
		evt = *pp_evt;
		drop_event(evt);
		event_insert_tailer(evt);
	}

	callout_reset(&_delack_timer, 200);
}

static void module_init(void)
{
	event_init(&_iss_timer, inc_iss, &tcp_iss);
	event_init(&_delack_timer, flush_delack, &_delack_queue);

	reset_event(&_iss_timer, -1, EV_RUNSTART);
	reset_event(&_delack_timer, -1, EV_RUNSTART);
}

static void module_clean(void)
{
	event_clean(&_iss_timer);
	event_clean(&_delack_timer);
}

modules_t tcp_timer_mod = {
	module_init, module_clean
};
