[peer-A]         [STUN]          [ID-server]         [peer-B]
    (id-A,id-lock)------------------->|<------------(id-B,id-lock)
    ------MAP---->|<------------------MAP--------------
    "SESSION ss FROM idA TO idB EXCHANGE xxx.x.xx.x:aa" -> [ID-server] ->|
     <--------------------------------------------"SESSION xx FROM idB SYN"(try 3 times until receive ACK)
     <------[ID-server]-- "SESSION ss FROM idB TO idA EXCHANGE yyy.y.yy.y:bb"
     "SESSION ss FROM idA SYN?ACK"--------------------------->| (try 3 times until receive ACK)
     <--------------------------------------------"SESSION xx FROM idB SYN|ACK"
