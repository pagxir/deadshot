left=89.117.113.248
left_subnet=192.168.1.0/24

right=114.92.113.240
right_subnet=192.168.111.0/24

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

leftport=4500
rightport=4500

cat << EOF
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
ip xfrm policy add src ${right_subnet} dst ${left_subnet} dir ${right_to_left_dir} ptype main tmpl src $right dst $left proto esp reqid 0 mode tunnel
ip xfrm policy add dst ${right_subnet} src ${left_subnet} dir ${left_to_right_dir} ptype main tmpl dst $right src $left proto esp reqid 0 mode tunnel

EOF
