self=172.31.1.30
left=58.33.42.122
REMOTE=23.105.198.189
server=66.220.18.42

# ip xfrm policy add src 58.33.42.122/32 dst $REMOTE/32 proto ipv6 dir out priority 0 tmpl src 172.31.1.30 dst $REMOTE proto esp reqid 0 mode tunnel
#  ip xfrm policy add dst $left/32 src $server/32 proto ipv6 dir out priority 0 tmpl dst $left src $REMOTE proto esp reqid 10 mode tunnel
#  ip xfrm policy add src 172.31.1.30/32 dst $server/32 proto ipv6 dir fwd priority 0 tmpl src $left dst $REMOTE proto esp reqid 10 mode tunnel
# ip xfrm policy add src $REMOTE/32 dst 172.31.1.30/32 proto ipv6 dir in priority 0 tmpl src $REMOTE dst 172.31.1.30 proto esp reqid 0 mode tunnel

right=$REMOTE
leftport=8844
rightport=8844
ip xfrm state add src $left dst $right \
        proto esp spi 0x7df4365d reqid 10 mode tunnel \
        enc 'cbc(aes)' 0x9b0b49337696fc1cee8967b597bc4393d2ac330a285b87029400ea9cca4eb754 \
        encap espinudp $leftport $rightport 0.0.0.0 \
        sel src $self dst $server

ip xfrm state add src $right dst $left \
        proto esp spi 0xb06b39d9 reqid 10 mode tunnel \
        enc 'cbc(aes)' 0x7d1462555cc20fa55f6fd0af4191baa65169a588f5dddfb29d6c8ea3d28d3ba6 \
        encap espinudp $rightport $leftport 0.0.0.0 \
        sel src $right dst $left

# ip tunnel add ipv6 mode sit local 172.31.1.30 ttl 64 remote 66.220.18.42
# ip -6 a a 2001:470:c:ff9::2/64 dev ipv6
# ip link set ipv6 up

sysctl net.ipv6.conf.all.forwarding=1
sysctl net.ipv6.conf.6to4.forwarding=1
sysctl net.ipv6.conf.nat64.forwarding=1
eval $(ip r g 192.88.99.1|sed 's/ \([a-z][a-z]*\) / \1=/g;s/^[^= ]* //')
myip=$(echo $src|sed 's/\./ /g'|xargs printf "2002:%02x%02x:%02x%02x::1")
ip tunnel add 6to4 mode sit ttl 64 remote any local $src
ip link set dev 6to4 up 

ip -6 addr add ${myip}/48 dev 6to4
ip -6 route add 2002::/16 via ::192.88.99.1 dev 6to4 metric 10
ip -6 route add default via ::192.88.99.1 dev 6to4 table 20
ip -6 rule add from $myip lookup 20


echo 2001:470:f1d4::1

# Generated by iptables-save v1.8.7 on Wed Nov  8 22:52:36 2023
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -s 58.33.42.122/32 -d 23.105.198.189/32 -p ipv6 -j DNAT --to-destination 66.220.18.42
-A POSTROUTING -j SNAT --to-source 23.105.198.189
COMMIT
# Completed on Wed Nov  8 22:52:36 2023

level@ServerA:~$ sudo ip xfrm policy
src 23.105.198.189/32 dst 58.33.42.122/32 proto ipv6 
	dir out priority 0 
	tmpl src 23.105.198.189 dst 58.33.42.122
		proto esp reqid 10 mode transport
src 58.33.42.122/32 dst 23.105.198.189/32 proto ipv6 
	dir in priority 0 
	tmpl src 58.33.42.122 dst 23.105.198.189
		proto esp reqid 10 mode transport

level@ServerA:~$ sudo ip xfrm state
src 23.105.198.189 dst 58.33.42.122
	proto esp spi 0xb06b39d9 reqid 10 mode transport
	replay-window 0 
	enc cbc(aes) 0x7d1462555cc20fa55f6fd0af4191baa65169a588f5dddfb29d6c8ea3d28d3ba6
	encap type espinudp sport 8844 dport 8844 addr 0.0.0.0
	anti-replay context: seq 0x0, oseq 0xa002, bitmap 0x00000000
	sel src 23.105.198.189/32 dst 58.33.42.122/32 
src 58.33.42.122 dst 23.105.198.189
	proto esp spi 0x7df4365d reqid 10 mode transport
	replay-window 0 
	enc cbc(aes) 0x9b0b49337696fc1cee8967b597bc4393d2ac330a285b87029400ea9cca4eb754
	encap type espinudp sport 8844 dport 8844 addr 0.0.0.0
	anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
	sel src 58.33.42.122/32 dst 23.105.198.189/32
OUTGOING=::ffff:127.0.0.53 INCOMING=::ffff:104.194.75.121 ./dns_echo

eval $(ip r g 192.88.99.1|sed 's/ \([a-z][a-z]*\) / \1=/g;s/^[^= ]* //')
myip=$(echo $src|sed 's/\./ /g'|xargs printf "2002:%02x%02x:%02x%02x::1")
ip tunnel add 6to4 mode sit ttl 64 remote any local $src
ip link set dev 6to4 up 

ip -6 addr add ${myip}/48 dev 6to4
ip -6 route add 2002::/16 via ::192.88.99.1 dev 6to4 metric 10
ip -6 route add default via ::192.88.99.1 dev 6to4 table 20
ip -6 route add default via ::192.88.99.1 dev 6to4
ip -6 rule add from $myip lookup 20

kcptun-server -l :5228 -t mtalk.google.com:5228 --key hello --tcp
./sniproxy -l 4430 -p 443 -s -d cmcc.cootail.com
resolvectl
OUTGOING=::ffff:127.0.0.53 INCOMING=::ffff:23.105.198.189 ./dns_echo
NAMESERVER=2001:470:66:22a::2 ROOTSERVER=::ffff:192.31.80.30 LOCALADDR6=::ffff:127.0.0.11 ./dns_mod_gfw
./sniproxy -l 4430 -p 443 -d cmcc.cootail.com -s
kcptun-server -l :5228 -t mtalk.google.com:5228 --key hello --tcp
 perl test.pl 8844
  BINDTO=::ffff:23.105.198.189 ./ech_sni_proxy -e -l 443 -p 443 -d www.baidu.com
  BINDLOCAL=::ffff:127.9.9.9 NAT64_PREFIX=64:ff9b:: REMOTESERVER=::ffff:1.0.0.1 NAMESERVER=::ffff:223.5.5.5 ~/dns_resolver_ng
modprobe ipv6
ip tunnel delete he-ipv6
ip tunnel add he-ipv6 mode ipip6 remote 192.88.99.1 local 104.194.75.121 ttl 255
ip link set he-ipv6 up
ip addr add 2002:68c2:4b79::2/64 dev he-ipv6
ip route add default via ::192.88.99.1 dev he-ipv6
ip -f inet6 addr
ip xfrm policy flush
ip xfrm state flush

REMOTE=23.105.198.189
server=66.220.18.42
server=23.105.198.189

# ip xfrm policy add src 58.33.42.122/32 dst $REMOTE/32 proto ipv6 dir out priority 0 tmpl src 172.31.1.30 dst $REMOTE proto esp reqid 0 mode tunnel
ip xfrm policy add src 58.33.42.122/32 dst $server/32 proto ipv6 dir in priority 0 tmpl src 58.33.42.122 dst $REMOTE proto esp reqid 10 mode transport
ip xfrm policy add src $server/32 dst 58.33.42.122/32 proto ipv6 dir out priority 0 tmpl src $REMOTE dst 58.33.42.122 proto esp reqid 10 mode transport
# ip xfrm policy add src $REMOTE/32 dst 172.31.1.30/32 proto ipv6 dir in priority 0 tmpl src $REMOTE dst 172.31.1.30 proto esp reqid 0 mode tunnel


left=58.33.42.122
right=$REMOTE
leftport=8844
rightport=8844
ip xfrm state add src $left dst $right \
        proto esp spi 0x7df4365d reqid 10 mode transport \
        enc 'cbc(aes)' 0x9b0b49337696fc1cee8967b597bc4393d2ac330a285b87029400ea9cca4eb754 \
        encap espinudp $leftport $rightport 0.0.0.0 \
        sel src $left dst $server

ip xfrm state add src $right dst $left \
        proto esp spi 0xb06b39d9 reqid 10 mode transport \
        enc 'cbc(aes)' 0x7d1462555cc20fa55f6fd0af4191baa65169a588f5dddfb29d6c8ea3d28d3ba6 \
        encap espinudp $rightport $leftport 0.0.0.0 \
        sel src $server dst $left

ip tunnel add ipv6 mode sit remote $left ttl 64 local $server
ip -6 a a 2001:470:c:ff9::1/64 dev ipv6
ip link set ipv6 up
