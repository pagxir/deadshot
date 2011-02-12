#ifndef _TCP_VAR_H_
#define _TCP_VAR_H_

#define TCP_MSS 1440

#define TCP_RTT_SCALE		32
#define TCP_RTT_SHIFT		5
#define TCP_RTTVAR_SCALE	16
#define TCP_RTTVAR_SHIFT	4
#define TCP_DELTA_SHIFT		2

struct tcp_stat {
	u_long tcps_sndprobe;
	u_long tcps_sndrexmitpack;
	u_long tcps_sndrexmitbyte;
	u_long tcps_sndpack;
	u_long tcps_sndbyte;
	u_long tcps_sndacks;
	u_long tcps_sndctrl;
	u_long tcps_sndwinup;
	u_long tcps_segstimed;
	u_long tcps_sndtotal;
	u_long tcps_accepts;
	u_long tcps_connects;
	u_long tcps_pawsdrop;
	u_long tcps_predack;
	u_long tcps_preddat;
	u_long tcps_rcvackbyte;
	u_long tcps_rcvackpack;
	u_long tcps_rcvacktoomuch;
	u_long tcps_rcvafterclose;
	u_long tcps_rcvbyte;
	u_long tcps_rcvbyteafterwin;
	u_long tcps_rcvdupbyte;
	u_long tcps_rcvduppack;
	u_long tcps_rcvpack;
	u_long tcps_rcvpackafterwin;
	u_long tcps_rcvpartdupbyte;
	u_long tcps_rcvpartduppack;
	u_long tcps_rcvtotal;
	u_long tcps_rcvwinprobe;
	u_long tcps_rcvwinupd;
	u_long tcps_delack;
	u_long tcps_timeoutdrop;
	u_long tcps_rexmttimeo;
	u_long tcps_persisttimeo;
	u_long tcps_keeptimeo;
	u_long tcps_keepprobe;
	u_long tcps_keepdrops;
	u_long tcps_rttupdated;
	u_long tcps_sndrexmitbad;
};

#define TCP_REXMTVAL(tp) \
	max((tp)->t_rttmin, (((tp)->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT)) \
				+ (tp)->t_rttvar) >> TCP_DELTA_SHIFT)
#endif

