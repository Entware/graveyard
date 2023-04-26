#!/bin/sh

. /opt/etc/bypass.conf

[ "$type" == "ip6tables" ] && exit
[ "$table" != "mangle" ] && exit
[ -z "$(ip link list | grep $VPN_NAME)" ] && exit
[ -z "$(ipset --quiet list bypass)" ] && exit

if [ -z "$(iptables-save | grep bypass)" ]; then
     iptables -w -t mangle -A PREROUTING ! -s $VPN_SUBNET -m conntrack --ctstate NEW -m set --match-set bypass dst -j CONNMARK --set-mark 1001
     iptables -w -t mangle -A PREROUTING ! -s $VPN_SUBNET -m set --match-set bypass dst -j CONNMARK --restore-mark
fi
