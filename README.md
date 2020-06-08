# rpz-manager
Block ads and malicious domains with response policy zones.

From [Wikipedia](https://en.wikipedia.org/wiki/Response_policy_zone):

> A response policy zone (RPZ) is a mechanism to introduce a customized 
> policy in Domain Name System servers, so that recursive resolvers 
> return possibly modified results. By modifying a result, access to the 
> corresponding host can be blocked. 

This program allows you to build and maintain RPZ zones from domain 
blocklist feeds. The resulting zones can be used with 
[ISC bind](https://en.wikipedia.org/wiki/BIND) (and other compatible
DNS servers).

rpz-manager is easy to deploy. Just copy it to your PATH. Optionally
use the config file, set up logging, or run a cron job to keep your
block lists up to date.

## Before you Start
Make sure to understand DNS RPZ before using this tool. These sites
provide great documentation:
 - https://www.dnsrpz.info
 - [Configuring a DNS firewall with RPZ](https://www.zytrax.com/books/dns/ch9/rpz.html)
 - [Response Policy Zone Configuration](https://www.zytrax.com/books/dns/ch7/rpz.html)
 
At minimum, you must create a [new zone clause](test/system/named_zone_centos.conf) 
for RPZ and mention that zone in a [response-policy statement](test/system/named_policy.conf).
 
## Quick Start with Ansible
TODO

## Quick Start for Manual Installation
TODO
