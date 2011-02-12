#ifndef _TCP_TIMER_H_
#define _TCP_TIMER_H_

#define TCPTV_MSL		(30 * T_HZ)
#define TCPTV_SRTTBASE	0

#define TCPTV_RTOBASE	( 3 * T_HZ)
#define TCPTV_SRTTDFLT	( 3 * T_HZ)

#define TCPTV_PERSMIN	( 5 * T_HZ)
#define TCPTV_PERSMAX	(60 * T_HZ)

#define TCPTV_KEEP_INIT	(75 * T_HZ)
#define TCPTV_KEEP_IDLE (120 * 60 * T_HZ)
#define TCPTV_KEEPINTVL	(75 * T_HZ)
#define TCPTV_KEEPCNT	8

#define TCPTV_FINWAIT2_TIMEOUT	(60 * T_HZ)

#define TCPTV_MIN		(T_HZ / 33)
#define TCPTV_CPU_VAR	(T_HZ / 5 )
#define TCPTV_REXMTMAX	(64 * T_HZ)

#define TCPTV_TWTRUNC	8

#define TCP_LINGERTIME	120

#define TCP_MAXRXTSHIFT	12

#define TCPTV_DELACK	(T_HZ / 10)

#define TCPT_RANGESET(tv, value, tvmin, tvmax) \
	do { \
		(tv) = (value) + tcp_rexmit_slop; \
		if ((u_long)(tv) < (u_long)(tvmin)) { \
			(tv) = (tvmin); \
		} else if ((u_long) (tv) > (u_long)(tvmax)) { \
			(tv) = (tvmax); \
		} \
	} while ( 0 );

extern int tcp_keepinit;
extern int tcp_keepidle;
extern int tcp_keepintvl;
extern int tcp_maxidle;
extern int tcp_delacktime;
extern int tcp_maxpersistidle;
extern int tcp_rexmit_min;
extern int tcp_rexmit_slop;
extern int tcp_msl;
extern int tcp_ttl;
extern int tcp_backoff[];

extern int tcp_finwait2_timeout;
extern int tcp_fast_finwait2_recycle;

void tcp_canceltimers(struct tcpcb * tp);

#endif
