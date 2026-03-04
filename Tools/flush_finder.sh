#!/usr/bin/env bash

grep -rEl "iptables -F" /etc /usr/lib /usr/local /var/log /home /root /tmp /opt /usr/sbin/ /usr/bin/ 2>/dev/null
grep -rEl "nft flush" /etc /usr/lib /usr/local /var/log /home /root /tmp /opt /usr/sbin/ /usr/bin/ 2>/dev/null
