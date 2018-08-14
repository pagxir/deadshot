#!/bin/sh

# grep -v -e "RSSI" -e "HCSQ" -e SIMST -e SRVST -e XLEMA -e "^[^A-Z]*$" /dev/cdc-wdm0
# ^NDISSTAT:1,,,"IPV4"
# ^NDISSTAT:0,50,,"IPV6"
#
# echo -e "AT^NDISSTATQRY?\r" > /dev/cdc-wdm0
# echo -e "AT+CGDCONT?\r" > /dev/cdc-wdm0
#
# AT+CGDCONT=1,"IPV4V6","3gnet"
# AT^NDISDUP=1,1

dial() {
    test -c /dev/cdc-wdm0 || echo device not found 1>& 2;
    test -c /dev/cdc-wdm0 || return;

    rm /tmp/ndisstat.txt
    echo -e "AT^NDISSTATQRY?\r" > /dev/cdc-wdm0
    sleep 1;

    test -f /tmp/ndisstat.txt || return;
    STAT=$(sed 's/[^0-9]*\([0-9]\).*/\1/' /tmp/ndisstat.txt)

    [ "$STAT" -eq 1 ] && echo -e "AT^NDISDUP=1,0\r" > /dev/cdc-wdm0;

    echo $(date) do dial up link 1>& 2;
}

isconnected() {
    ping -c 3 -q -I wwan0 114.114.114.114  > /dev/null;
}

markstall() {
    while sleep 10; do
        isconnected || dial;
        isconnected || udhcpc -n -q -i wwan0 2> /dev/null;
    done;
}

statmachine() {

while read line; do
    case $line in
    ^RSSI*)
        echo $(date) $line > /tmp/at-cdc-wdm0-rssi.txt;
        ;;
    ^HCSQ*)
        echo $(date) $line > /tmp/at-cdc-wdm0-hcsq.txt;
        ;;
    ^NDISSTAT:*)
        echo $(date) $line
	if echo $line|grep ":0,[0-9][0-9]*,.*IPV4" > /dev/null; then
            echo -e "AT^NDISDUP=1,1\r" > /dev/cdc-wdm0;
        fi;
	if echo $line|grep ":1,[0-9]*,.*IPV4" > /dev/null; then
            udhcpc -n -q -i wwan0 2> /dev/null && dig @8.8.8.8 www.baidu.com > /dev/null;
        fi;
        ;;
    ^NDISSTATQRY:*|+CGDCONT*)
        echo $(date) $line;
        echo $line > /tmp/ndisstat.txt;
        ;;
    ^SIMST*|^SRVST*|^XLEMA*)
        echo $(date): $line >> /tmp/at-cdc-wdm0-log.txt;
        ;;

    ^*)
        echo $(date): $line >> /tmp/at-cdc-wdm0-log.txt;
        ;;
    [A-Z]*)
        echo $(date): $line >> /tmp/at-cdc-wdm0-log.txt;
        ;;
    *)
        ;;
    esac
done < /dev/cdc-wdm0 

}

                                                                                   
markstall |  statmachine
