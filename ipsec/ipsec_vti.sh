VTI_KEY=0x12345678
LOCAL_IPv4_ADDR=10.0.4.11
REMOTE_IPv4_ADDR=137.175.53.113

cat << EOF
ip link add name vti1 type vti key $VTI_KEY local $LOCAL_IPv4_ADDR remote $REMOTE_IPv4_ADDR

ifconfig vti1 111.111.111.20/24 up

ip xfrm state add src $REMOTE_IPv4_ADDR dst $LOCAL_IPv4_ADDR spi 0xbd270b9c proto esp aead 'rfc4106(gcm(aes))' 0x07ecd44d5425d4c8e81fee093086a38d9c83a44c0d27251fea49b30ed1cad4c1effa0801 128 mode tunnel
ip xfrm state add dst $REMOTE_IPv4_ADDR src $LOCAL_IPv4_ADDR spi 0xbd270b9c proto esp aead 'rfc4106(gcm(aes))' 0x07ecd44d5425d4c8e81fee093086a38d9c83a44c0d27251fea49b30ed1cad4c1effa0801 128 mode tunnel

ip xfrm policy add dir in tmpl src $REMOTE_IPv4_ADDR dst $LOCAL_IPv4_ADDR proto esp mode tunnel mark $VTI_KEY
ip xfrm policy add dir out tmpl src $LOCAL_IPv4_ADDR dst $REMOTE_IPv4_ADDR proto esp mode tunnel mark $VTI_KEY


# encap type espinudp sport 4500 dport 4500 addr 0.0.0.0
EOF
