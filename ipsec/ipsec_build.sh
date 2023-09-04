#!/bin/bash

leftid=$1
rightid=$2

left=$(echo $leftid|sed 's/:.*//')
right=$(echo $rightid|sed 's/:.*//')

right_to_left=in
left_to_right=out
leftport=$(echo $leftid|sed 's/.*://')
rightport=$(echo $rightid|sed 's/.*://')


[[ $left = 0.0.0.0 ]] && eval $(ip route get $right|sed 's/ \([a-z][a-z]*\) / \1=/g;s/ [^=]* //g;s/^[^=]* //'|head -n 1; echo -n left='$src')
[[ $right = 0.0.0.0 ]] && eval $(ip route get $left|sed 's/ \([a-z][a-z]*\) / \1=/g;s/ [^=]* //g;s/^[^=]* //'|head -n 1; echo -n right='$src')

if ip r get $left|grep local; then
  right_to_left=in
  left_to_right=out
  myport=$leftport
fi

if ip r get $right|grep local; then
   right_to_left=out
   left_to_right=in
   myport=$rightport
fi

cat << EOF|tee /tmp/build.log|bash
echo echo leftid $leftid rightid $rightid left $left

ip xfrm state flush
ip xfrm state add src $left dst $right \
        proto esp spi 0xd74f63d5 reqid 0 mode tunnel \
        replay-window 0 \
        enc 'cbc(aes)' 0x9b0b49337696fc1cee8967b597bc4393d2ac330a285b87029400ea9cca4eb754 \
        encap espinudp $leftport $rightport 0.0.0.0 \
        sel src 0.0.0.0/0 dst 0.0.0.0/0 

ip xfrm state add src $right dst $left \
        proto esp spi 0x0bb6939d reqid 0 mode tunnel \
        replay-window 0 \
        enc 'cbc(aes)' 0x7d1462555cc20fa55f6fd0af4191baa65169a588f5dddfb29d6c8ea3d28d3ba6 \
        encap espinudp $rightport $leftport 0.0.0.0 \
        sel src 0.0.0.0/0 dst 0.0.0.0/0 

ip xfrm policy flush
ip xfrm policy add dst 192.168.32.0/24 src 10.0.3.0/24 dir ${left_to_right} ptype main tmpl src $left dst $right proto esp reqid 0 mode tunnel
ip xfrm policy add src 192.168.32.0/24 dst 10.0.3.0/24 dir ${right_to_left} ptype main tmpl src $right dst $left proto esp reqid 0 mode tunnel

EOF

exeute_path=$(cd `dirname $0` && pwd)
exec $exeute_path/ipsec_udpinesp.pl $myport
