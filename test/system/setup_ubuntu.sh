#!/bin/bash -l

sed -i.orig '/options/ r /root/test/system/named_policy.conf' /etc/bind/named.conf.options
cat test/system/named_zone_ubuntu.conf >> /etc/bind/named.conf.local
named-checkconf
