left=2001:470:23:678:ffff::1
left_subnet=2001:470:23:678:ffff::1/128
right=2407:cdc0:8204::abfd:ab6b
right=64:ff9b::1.1.1.1
right_subnet=64:ff9b::1.1.1.1/128

right_to_left_dir=in
left_to_right_dir=out

if ip r get $left|grep local > /dev/null; then
  right_to_left_dir=in
  left_to_right_dir=out
fi

if ip r get $right|grep local > /dev/null; then
   right_to_left_dir=out
   left_to_right_dir=in
fi

cat << EOF
ip -6 xfrm state flush
ip -6 xfrm state add src $left dst $right \
        proto esp spi 0xd74f63d5 reqid 0 mode transport \
        enc 'cbc(aes)' 0x9b0b49337696fc1cee8967b597bc4393d2ac330a285b87029400ea9cca4eb754
		echo sel src ${left_subnet} dst ${right_subnet} proto udp \

echo ip -6 xfrm state add dst $left src $right \
        proto esp spi 0x0bb6939d reqid 0 mode transport \
		sel dst ${left_subnet} src ${right_subnet} proto udp \
        enc 'cbc(aes)' 0x7d1462555cc20fa55f6fd0af4191baa65169a588f5dddfb29d6c8ea3d28d3ba6

ip -6 xfrm policy flush
# ip -6 xfrm policy add src ${right_subnet} dst ${left_subnet} proto udp dir ${right_to_left_dir} ptype main tmpl src $right dst $left proto esp reqid 0 mode transport
# ip -6 xfrm policy add src ${left_subnet} dst ${right_subnet} proto udp dir ${left_to_right_dir} ptype main tmpl dst $right src $left proto esp reqid 0 mode transport
ip -6 xfrm policy add src ${left_subnet} dst ${right_subnet} proto udp dport 53 dir ${left_to_right_dir} ptype main tmpl dst $right src $left proto esp reqid 0 mode tunnel

EOF


cat << EOF
ip xfrm state
src 1.1.1.1 dst 192.168.0.145
       proto esp spi 0xb2b7c283 reqid 16385 mode transport
       replay-window 32 
       auth-trunc hmac(sha1) 0x35... 96
       enc cbc(des3_ede) 0x20...
       encap type espinudp sport 4500 dport 4500 addr 0.0.0.0
       sel src 10.200.101.15/32 dst 192.168.0.145/32 proto udp dport 1701

src 192.168.0.145 dst 1.1.1.1
       proto esp spi 0xccc4890a reqid 16385 mode transport
       replay-window 32 
       auth-trunc hmac(sha1) 0x71... 96
       enc cbc(des3_ede) 0xc4...
       encap type espinudp sport 4500 dport 4500 addr 0.0.0.0
       sel src 192.168.0.145/32 dst 10.200.101.15/32 proto udp sport 1701

ip xfrm policy
src 192.168.0.145/32 dst 1.1.1.1/32 proto udp sport 1701 
       dir out priority 2080 
       tmpl src 0.0.0.0 dst 0.0.0.0
               proto esp reqid 16385 mode transport

src 10.200.101.15/32 dst 192.168.0.145/32 proto udp dport 1701 
       dir in priority 2080 
       tmpl src 0.0.0.0 dst 0.0.0.0
               proto esp reqid 16385 mode transport
EOF

cat << EOF
ip xfrm state add src 10.141.252.30 dst 10.141.252.252 proto esp spi 2172667646 mode transport enc cipher_null "" auth "hmac(md5)" 0x9059300b7a2f9a4025a0950d05adaf85 sel src 10.141.252.30 dst 10.141.252.252 proto ip sport 8000 dport 5061
ip xfrm policy add src 10.141.252.30 dst 10.141.252.252 proto ip sport 8000 dport 5061 dir out tmpl src 10.141.252.30 dst 10.141.252.252 proto esp mode transport
ip xfrm state add src 10.141.252.252 dst 10.141.252.30 proto esp spi 1556005832 mode transport enc cipher_null "" auth "hmac(md5)" 0x9059300b7a2f9a4025a0950d05adaf85 sel src 10.141.252.252 dst 10.141.252.30 proto ip sport 5062 dport 8001
ip xfrm policy add src 10.141.252.252 dst 10.141.252.30 proto ip sport 5062 dport 8001 dir in tmpl src 10.141.252.252 dst 10.141.252.30 proto esp mode transport
ip xfrm state add src 10.141.252.252 dst 10.141.252.30 proto esp spi 1556005831 mode transport enc cipher_null "" auth "hmac(md5)" 0x9059300b7a2f9a4025a0950d05adaf85 sel src 10.141.252.252 dst 10.141.252.30 proto ip sport 5061 dport 8000
ip xfrm policy add src 10.141.252.252 dst 10.141.252.30 proto ip sport 5061 dport 8000 dir in tmpl src 10.141.252.252 dst 10.141.252.30 proto esp mode transport
ip xfrm state add src 10.141.252.30 dst 10.141.252.252 proto esp spi 3725141580 mode transport enc cipher_null "" auth "hmac(md5)" 0x9059300b7a2f9a4025a0950d05adaf85 sel src 10.141.252.30 dst 10.141.252.252 proto ip sport 8001 dport 5062
ip xfrm policy add src 10.141.252.30 dst 10.141.252.252 proto ip sport 8001 dport 5062 dir out tmpl src 10.141.252.30 dst 10.141.252.252 proto esp mode transport
EOF

