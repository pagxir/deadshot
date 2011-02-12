#ifndef _TCP_H_
#define _TCP_H_

#include "dtype.h"

#define TCP_NSTATES     11
#define TCPS_CLOSED             0 
#define TCPS_LISTEN             1
#define TCPS_SYN_SENT           2   
#define TCPS_SYN_RECEIVED       3  
#define TCPS_ESTABLISHED        4 
#define TCPS_CLOSE_WAIT         5
#define TCPS_FIN_WAIT_1         6 
#define TCPS_CLOSING            7
#define TCPS_LAST_ACK           8
#define TCPS_FIN_WAIT_2         9 
#define TCPS_TIME_WAIT          10 

#define SEQ_LEQ(a, b) ((int)((a) - (b)) <= 0)
#define SEQ_LT(a, b) ((int)((a) - (b)) < 0)
#define SEQ_GEQ(a, b) ((int)((a) - (b)) >= 0)
#define SEQ_GT(a, b) ((int)((a) - (b)) > 0)
#define TSTMP_GEQ(a, b) SEQ_GEQ(a, b)
#define TSTMP_LT(a, b) SEQ_LT(a, b)
#define TCPS_HAVERCVDFIN(s) \
	(((s) >= TCPS_CLOSE_WAIT) && ((s) != TCPS_FIN_WAIT_2))


#define TH_ACK    (1 << 0)
#define TH_RST    (1 << 1)
#define TH_FIN    (1 << 2)
#define TH_SYN    (1 << 3)
#define TH_PUSH   (1 << 4)

#define TCP_MAXWIN 65535
#define TCP_ISSINCR  0x01000000
#define TF_ACKNOW    (1 << 0)
#define TF_DELACK    (1 << 1)
#define TF_SENTFIN   (1 << 2)
#define TF_DETACH    (1 << 3)
#define TF_MORETOCOME    (1 << 4)
#define TF_LASTIDLE      (1 << 5)
#define TF_FASTRECOVERY  (1 << 6)
#define TF_WASFRECOVERY  (1 << 7)
#define TF_RTSEQ1        (1 << 8)

#define XF_READ      (1 << 0)
#define XF_WRITE     (1 << 1)
#define XF_ACKNOW    (1 << 2)

#define T_HZ (1000)

enum {TCPT_REXMT, TCPT_PERSIST, TCPT_KEEP, TCPT_2MSL, TCPT_NTIMERS};

struct rgn;
struct tcphdr {
	u_char ti_res;
	u_char ti_flags;
	u_short ti_win;
	u_short ti_len;
	u_short ti_dst;
	tcp_seq ti_seq;
	tcp_seq ti_ack;
	tcp_seq ti_tsecr;
	tcp_seq ti_tsval;
};

struct tcpcb {
	short t_state;
	short t_rxtshift;
	u_long t_rxtcur;
	u_long t_timer[TCPT_NTIMERS];
	short t_dupacks;
	u_short t_maxseg;
	char t_force;
	u_short t_flags;

	tcp_seq snd_una;
	tcp_seq snd_nxt;
	tcp_seq snd_wl1;
	tcp_seq snd_wl2;
	tcp_seq snd_recover;
	tcp_seq snd_recover_prev;
	tcp_seq iss;
	u_long  snd_wnd;
	u_long  rcv_wnd;
	tcp_seq rcv_nxt;
	tcp_seq irs;

	tcp_seq rcv_adv;
	tcp_seq snd_max;
	tcp_seq t_rtseq1;

	u_long  snd_cwnd;
	u_long  snd_cwnd_prev;
	u_long  snd_ssthresh;
	u_long  snd_ssthresh_prev;
	u_long  snd_limited;
	u_long  t_bytes_acked;

	tcp_seq t_rtseq;
	long    t_srtt;
	long    t_rttvar;
	long    t_rttmin;
	u_long  t_rcvtime;
	u_long  t_badrxtwin;
	u_long  t_rtttime;
	u_long  ts_recent;
	u_long  ts_recent_age;
	u_long  max_sndwnd;
	tcp_seq last_ack_sent;

	struct rgnbuf * rgn_rcv;
	struct rgnbuf * rgn_snd;

	int if_dev;
	struct sockaddr_in dst_addr;
};

static u_char   tcp_outflags[TCP_NSTATES] = {
	TH_RST|TH_ACK,          /* 0, CLOSED */
	0,                      /* 1, LISTEN */
	TH_SYN,                 /* 2, SYN_SENT */
	TH_SYN|TH_ACK,          /* 3, SYN_RECEIVED */
	TH_ACK,                 /* 4, ESTABLISHED */
	TH_ACK,                 /* 5, CLOSE_WAIT */
	TH_FIN|TH_ACK,          /* 6, FIN_WAIT_1 */
	TH_FIN|TH_ACK,          /* 7, CLOSING */
	TH_FIN|TH_ACK,          /* 8, LAST_ACK */
	TH_ACK,                 /* 9, FIN_WAIT_2 */
	TH_ACK,                 /* 10, TIME_WAIT */
};

extern int tcp_rexmit_slop;
extern struct tcp_stat tcpstat;
struct tcpcb * tcp_create(int if_fd);

int tcp_empty(void);
int tcp_fasttimeo(int * flags);
int tcp_slowtimeo(int * flags);
int tcp_packet(int, const char *, size_t, int *, const struct sockaddr_in *, size_t);

int tcp_listen(struct tcpcb * tp);
int tcp_shutdown(struct tcpcb * tp);
int tcp_connected(struct tcpcb * tp);
int tcp_connect(struct tcpcb * , const struct sockaddr_in * , size_t);

int tcp_writable(struct tcpcb * tp);
int tcp_write(struct tcpcb * tp, const void * buf, size_t count);

int tcp_readable(struct tcpcb * tp);
int tcp_read(struct tcpcb * tp, void * buf, size_t count);
int tcp_respond(struct tcpcb * tp, struct tcphdr * hdr, int flags);

int tcp_attach(struct tcpcb * tp);
int tcp_detach(struct tcpcb * tp);
int tcp_destroy(struct tcpcb * tp);
int tcp_setpersist(struct tcpcb * tp);

extern int tcp_maxidle;
extern int tcp_iss, ticks;
extern int tcp_backoff[] ;

int tcp_output(struct tcpcb * tp);
void tcp_input(struct tcpcb *, int, const char *,
		size_t, int *, const struct sockaddr_in *);

extern struct tcpcb * tcp_last_tcpcb;
#endif

