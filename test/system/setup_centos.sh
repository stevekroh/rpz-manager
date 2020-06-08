#!/bin/sh -l

sed -i.orig '/options/ r /root/test/system/named_policy.conf' /etc/named.conf
cat test/system/named_zone_centos.conf >> /etc/named.conf
named-checkconf
