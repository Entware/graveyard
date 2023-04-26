#!/bin/sh

. /opt/etc/bypass.conf

[ "$1" == "hook" ] || exit 0
[ "$system_name" == "$VPN_NAME" ] || exit 0
[ ! -z "$(ipset --quiet list bypass)" ] || exit 0
[ "${change}-${connected}-${link}-${up}" == "link-yes-up-up" ] || exit 0

if [ -z "$(ip route list table 1001)" ]; then
    ip route add default dev $system_name table 1001
fi
