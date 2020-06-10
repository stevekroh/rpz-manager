# rpz-manager
Block ads and malicious domains with response policy zones.

![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/stevekroh/rpz-manager?sort=semver)
![PyPI](https://img.shields.io/pypi/v/rpz-manager)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/rpz-manager)
![GitHub commit activity](https://img.shields.io/github/commit-activity/y/stevekroh/rpz-manager)
![GitHub commits since latest release (by SemVer)](https://img.shields.io/github/commits-since/stevekroh/rpz-manager/latest/master?sort=semver)
![GitHub Workflow Status (branch)](https://img.shields.io/github/workflow/status/stevekroh/rpz-manager/CI/master)

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
write a config file, set up logging, or use a cron job to keep your
zone fresh.

## Before you Start
Make sure to understand DNS RPZ before using this tool. These sites
provide great documentation:
 - https://www.dnsrpz.info
 - [Configuring a DNS firewall with RPZ](https://www.zytrax.com/books/dns/ch9/rpz.html)
 - [Response Policy Zone Configuration](https://www.zytrax.com/books/dns/ch7/rpz.html)
 
At minimum, you must create a [new zone clause](https://raw.githubusercontent.com/stevekroh/rpz-manager/version-0.x/test/system/named_zone_centos.conf) 
for RPZ and mention that zone in a [response-policy statement](https://raw.githubusercontent.com/stevekroh/rpz-manager/version-0.x/test/system/named_policy.conf).
 
## How to Install
Run the following as root.
```shell script
# Download rpz-manager
curl -Ss https://raw.githubusercontent.com/stevekroh/rpz-manager/version-0.x/rpz_manager.py \
  -o /usr/local/bin/rpz-manager

# Set the executable bit
chmod 755 /usr/local/bin/rpz-manager
```
Alternatively, create a virtualenv and run pip install rpz-manager.

## Quick Start
```shell script
# View the help screen
rpz-manager --help

# Write, then review /etc/rpz-manager.ini
rpz-manager --init

# Optionally set up logging
curl -Ss https://raw.githubusercontent.com/stevekroh/rpz-manager/version-0.x/config/rpz-loggers.ini \
  -o /etc/rpz-loggers.ini

# Download block lists then write an RPZ zone file
rpz-manager
```
 
## Automate with Ansible
Add the following to your role or playbook.

```yaml
# Customize rpz-manager.ini and save it under files
- name: upload rpz-manager.ini
  copy:
    src: files/rpz-manager.ini
    dest: /etc/rpz-manager.ini
    owner: root
    group: root
    mode: 'u=rw,g=r,o=r'

# Customize rpz-loggers.ini and save it under files
- name: upload rpz-loggers.ini
  copy:
    src: files/rpz-loggers.ini
    dest: /etc/rpz-loggers.ini
    owner: root
    group: root
    mode: 'u=rw,g=r,o=r'

# rpz-manager will be updated to the latest version when force=yes
- name: download rpz-manager
  get_url:
    url: https://raw.githubusercontent.com/stevekroh/rpz-manager/version-0.x/rpz_manager.py
    dest: /usr/local/bin/rpz-manager
    force: yes
    owner: root
    group: root
    mode: 'u=rwx,g=rx,o=rx'

# Use a cron job to keep your zone fresh
- name: run rpz-manager daily
  cron:
    name: rpz-manager
    special_time: daily
    job: /usr/local/bin/rpz-manager
    user: root
```

## Run Without Root
It is possible to run rpz-manager without root permissions, though you must
be sure to update all relevant settings pertaining to the user.

For example:
```shell script
# Create an administrator belonging to the named group
useradd -m -G named admin

# Create the user cache directory
mkdir -p /home/admin/.cache

# Run rpz-manager
rpz-manager -o rpz.example.com. -z /var/named/rpz.example.com.zone \
  -u admin -g named -d /home/admin/.cache
```

Inspired by [Trellmor/bind-adblock](https://github.com/Trellmor/bind-adblock).
