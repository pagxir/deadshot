[peer-A]         [STUN]          [ID-server]         [peer-B]
    (id-A,id-lock)------------------->|<------------(id-B,id-lock)
    ------MAP---->|<------------------MAP--------------
    "SESSION ss FROM idA TO idB EXCHANGE xxx.x.xx.x:aa" -> [ID-server] ->|
     <--------------------------------------------"SESSION xx FROM idB SYN"(try 3 times until receive ACK)
     <------[ID-server]-- "SESSION ss FROM idB TO idA EXCHANGE yyy.y.yy.y:bb"
     "SESSION ss FROM idA SYN?ACK"--------------------------->| (try 3 times until receive ACK)
     <--------------------------------------------"SESSION xx FROM idB SYN|ACK"

#if 0
        // receive REQUEST via helper server
			session: xxxx
			src: dupit8@gmail.com
			dst: pagxir@gmail.com
			via: 103.119.224.18:51901
			seq: I

        // send ACCEPT via helper server
			session: xxxx
			src: pagxir@gmail.com
			dst: dupit8@gmail.com
			via: GATEWAY
			seq: 9
			ack: J

		// send NOOP via direct with short ttl=3
			session: xxxx
			src: pagxir@gmail.com
			dst: dupit8@gmail.com
			seq: 9
			ack: J

		// receive NOOP via direct with short ttl=3
			session: xxxx
			src: dupit8@gmail.com
			dst: pagxir@gmail.com
			seq: J
			ack: 9

        // receive NOOP CONTINUE  via help server
			session: xxxx
			src: dupit8@gmail.com
			dst: pagxir@gmail.com
			via: $GATEWAY
			seq: J
			ack: 10

		// send PING via direct
			session: xxxx
			src: pagxir@gmail.com
			dst: dupit8@gmail.com
			seq: 10
			ack: J

		// receive NOOP PONG via direct
			session: xxxx
			src: dupit8@gmail.com
			dst: pagxir@gmail.com
			seq: J
			ack: 11

		// receive PING via other direct
			session: xxxx
			src: dupit8@gmail.com
			dst: pagxir@gmail.com
			seq: K
			ack: 10

		// receive PING via direct
			session: xxxx
			src: dupit8@gmail.com
			dst: pagxir@gmail.com
			seq: K
			ack: 11

		// receive SELECT via direct
			session: xxxx
			src: dupit8@gmail.com
			dst: pagxir@gmail.com
			seq: L
			ack: 11

		// send  REJECT via direct
			session: xxxx
			src: pagxir@gmail.com
			dst: dupit8@gmail.com
			seq: 11
			ack: M

		// send SELECT via other direct
			session: xxxx
			src: pagxir@gmail.com
			dst: dupit8@gmail.com
			seq: 11
			ack: M

		// send NOOP SELECTED via direct
			session: xxxx
			src: pagxir@gmail.com
			dst: dupit8@gmail.com
			seq: 11
			ack: M
#endif
        // receive REQUEST via helper server
        // send ACCEPT via helper server
		// send NOOP via direct with short ttl=3
		// receive NOOP via direct with short ttl=3
        // receive NOOP:CONTINUE  via help server
		// send PING via direct
		// receive NOOP:PONG via direct
		// receive PING via other direct
		// receive PING via direct
		// receive SELECT via direct
		// send REJECT via direct
		// send SELECT via other direct
		// send NOOP:SELECTED via direct

