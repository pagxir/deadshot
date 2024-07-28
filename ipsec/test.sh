cat << EOF
LOCAL=2001:470:23:678:ffff::1
REMOTE=64:ff9b::/96

ip -6 xfrm state flush
# ip -6 xfrm state add src $LOCAL dst $REMOTE proto esp spi 2172667646 mode transport enc cipher_null "" auth "hmac(md5)" 0x9059300b7a2f9a4025a0950d05adaf85 sel src $LOCAL dst $REMOTE proto ip sport 8000 dport 53
# ip -6 xfrm state add src $LOCAL dst $REMOTE proto esp spi 2172667646 mode transport enc cipher_null "" auth "hmac(md5)" 0x9059300b7a2f9a4025a0950d05adaf85 sel src $LOCAL dst $REMOTE proto ip dport 53
ip -6 xfrm state add src $LOCAL dst $REMOTE proto esp spi 2172667646 mode transport enc cipher_null "" auth "hmac(md5)" 0x9059300b7a2f9a4025a0950d05adaf85 sel src $LOCAL dst $REMOTE proto udp dport 53

ip -6 xfrm policy flush
# ip -6 xfrm policy add src $LOCAL dst $REMOTE proto ip sport 8000 dport 53 dir out tmpl src $LOCAL dst $REMOTE proto esp mode transport
# ip -6 xfrm policy add src $LOCAL dst $REMOTE proto ip dport 53 dir out tmpl src $LOCAL dst $REMOTE proto esp mode transport
ip -6 xfrm policy add src $LOCAL dst $REMOTE proto udp dport 53 dir out tmpl src $LOCAL dst $REMOTE proto esp mode transport
EOF

LOCAL=10.0.4.11
REMOTE=45.137.181.106

ip xfrm state flush
ip xfrm state add src $LOCAL dst $REMOTE proto esp spi 2172667646 mode transport enc blowfish 0xc0de0102 sel src $LOCAL dst $REMOTE proto 41

ip xfrm policy flush
ip xfrm policy add src $LOCAL dst $REMOTE proto 41 dir out tmpl src $LOCAL dst $REMOTE proto esp mode transport


LOCAL=10.0.4.11
REMOTE=45.137.181.106

ip xfrm state flush
ip xfrm state add src $LOCAL dst $REMOTE proto esp spi 2172667646 mode transport enc blowfish 0xc0de0102 sel src $LOCAL dst $REMOTE proto 41
ip xfrm state add src $REMOTE dst $LOCAL proto esp spi 2172667647 mode transport enc blowfish 0xc0ed0012 sel src $REMOTE dst $LOCAL proto 41

ip xfrm policy flush
ip xfrm policy add src $LOCAL dst $REMOTE proto 41 dir out tmpl src $LOCAL dst $REMOTE proto esp mode transport
ip xfrm policy add src $REMOTE dst $LOCAL proto 41 dir in tmpl src $LOCAL dst $REMOTE proto esp mode transport
