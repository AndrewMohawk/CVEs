# Negative: current root Python and D-Bus service pass

Date: 2026-05-17
Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS
Result: no validated uid1001-to-root LPE.

## Scope

This pass rechecked the live default root Python/scripted service surface after the earlier broad audit: `netplan-dbus`, `software-properties-dbus`, Ubuntu Pro/UA timers and services, `unattended-upgrade-shutdown`, and update-notifier/MOTD jobs.

## Default proof

The target was healthy and fully updated:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend | wc -l -> 0
apt-get -s upgrade -> 0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Relevant package versions:

```text
netplan.io 1.1.2-8ubuntu1~24.04.2
software-properties-common 0.99.49.4
ubuntu-pro-client 37.2ubuntu~24.04
unattended-upgrades 2.9.1+nmu4ubuntu1
update-notifier-common 3.192.68.2
systemd 255.4-1ubuntu8.15
```

## Findings

`netplan-dbus` is default activatable as root:

```text
/usr/share/dbus-1/system-services/io.netplan.Netplan.service:
Name=io.netplan.Netplan
Exec=/usr/libexec/netplan/netplan-dbus
User=root
```

The system bus policy allows sends, but live uid1001 calls to `Info`, `Config`, `Generate`, and `Apply` all returned `Call failed: Access denied`. `/etc/netplan` is `0755 root:root`, and uid1001 cannot plant config.

`software-properties-dbus` is also root activatable:

```text
/usr/share/dbus-1/system-services/com.ubuntu.SoftwareProperties.service:
Exec=/usr/lib/software-properties/software-properties-dbus
User=root
```

The only unprotected method observed was `Reload`, which reparses root-owned apt sources. Mutators such as `AddSourceFromLine`, `AddKeyFromData`, `UpdateKeys`, and source enable/disable call `_check_policykit_privilege()` in `/usr/lib/python3/dist-packages/softwareproperties/dbus/SoftwarePropertiesDBus.py:101-327`; uid1001 received `com.ubuntu.softwareproperties.applychanges`.

Ubuntu Pro root units are installed but not attacker-influenced in default state:

```text
ubuntu-advantage.service enabled, condition-gated by cloud/auto-attach state
ua-timer.timer enabled, ConditionPathExists=/var/lib/ubuntu-advantage/private/machine-token.json
apt-news.service and esm-cache.service static root one-shots
```

`pro config set apt_news_url=...`, `pro config set apt_news=false`, and `pro refresh` as uid1001 all returned `This command must be run as root`. `/etc/ubuntu-advantage` and `/var/lib/ubuntu-advantage` are `0755 root:root`.

`unattended-upgrade-shutdown` runs as root under `unattended-upgrades.service`, but uid1001 cannot signal it or write its root-owned config/lock inputs. The live service uses fixed paths under `/run` and `/etc/apt/apt.conf.d`; attacker writes to those paths were denied.

`update-notifier-common` timers and MOTD jobs are default root triggers, but their hook/config roots are not writable:

```text
/usr/share/package-data-downloads root-owned and empty
/var/lib/update-notifier root:root
/etc/default/motd-news root:root
/var/cache/motd-news root:root
```

## Root proof

No root marker or root-context `id` was produced. The only root D-Bus method reachable without admin auth was `SoftwareProperties.Reload`, and that had no attacker-controlled file/code input in the stock state.

## Why scanners miss it

This lane looks promising because multiple root Python services are D-Bus activatable and several root timer jobs import Python modules or run shell helpers. Exploitability depends on D-Bus method-level authorization, systemd activation environment isolation, root-owned import paths, and unit conditions. Those semantics blocked all tested paths before attacker-controlled code or config reached root.
