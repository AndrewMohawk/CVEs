# Negative: default firewall and network boot helpers

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Attacker identity was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no validated uid1001 -> root LPE in this slice. No root proof exists.

## Default package and service state

Installed and in scope:

```text
ufw                 0.36.2-6
iptables            1.8.10-3ubuntu2
nftables            1.0.9-1ubuntu0.1
systemd             255.4-1ubuntu8.15
procps              2:4.0.4-4ubuntu3.2
kmod                31+20240202-2ubuntu7.2
ubuntu-server       1.539.2
ubuntu-standard     1.539.2
```

Not installed by default in this target: `iptables-persistent`, `netfilter-persistent`.

Relevant unit state:

```text
ufw.service                    loaded/enabled, active/exited, ExecStart=/usr/lib/ufw/ufw-init start quiet
nftables.service               loaded/disabled, inactive/dead, ExecStart=/usr/sbin/nft -f /etc/nftables.conf
netfilter-persistent.service   not-found
iptables.service               not-found
ip6tables.service              not-found
systemd-sysctl.service         loaded/static, active/exited, ExecStart=/usr/lib/systemd/systemd-sysctl
systemd-modules-load.service   loaded/static, active/exited, ExecStart=/usr/lib/systemd/systemd-modules-load
```

`ufw.service` is enabled/reachable at boot, but stock `/etc/ufw/ufw.conf` has `ENABLED=no`, and `ufw status verbose` reports `Status: inactive`. The unit still exits successfully because `/usr/lib/ufw/ufw-init start quiet` exits early when `ENABLED=no`.

## Trust boundary checks

`ufw-init` sources `/etc/ufw/ufw.conf`, then `/lib/ufw/ufw-init-functions`; the function file sources `/etc/default/ufw` and `/etc/ufw/ufw.conf`. If UFW is enabled, root would trust `IPT_MODULES`, `IPT_SYSCTL`, `/etc/ufw/{before,after,user}{,6}.rules`, and executable `/etc/ufw/{before,after}.init`. In this default target those paths are root-owned and not writable by uid1001. `before.init` and `after.init` are `0640`, so they are not executable hooks by default.

`nftables.service` is disabled and reads only root-owned `/etc/nftables.conf`. Direct uid1001 `nft -f /etc/nftables.conf` reaches the parser but fails netfilter changes with `Operation not permitted`.

`systemd-sysctl.service` imports `sysctl.*` credentials and reads sysctl config from root-owned `/usr/lib/sysctl.d`, `/etc/sysctl.d`, `/etc/sysctl.conf`, and absent `/run/sysctl.d`. `/run/credentials` is root-owned `0755`, and uid1001 cannot create `/run/credentials/systemd-sysctl.service/sysctl.firewall`.

`systemd-modules-load.service` reads module-load config from root-owned `/usr/lib/modules-load.d`, `/etc/modules-load.d`, `/etc/modules`, and absent `/run/modules-load.d`; modprobe policy paths are root-owned under `/usr/lib/modprobe.d` and `/etc/modprobe.d`, with absent `/run/modprobe.d`. uid1001 cannot plant module-load or modprobe config.

Package hooks did not add an attacker-writable root re-entry path. `ufw.postinst` copies templates into `/etc/ufw`, chmods rule/init files `0640`, enables `ufw.service`, and its only trigger is `interest-noawait /etc/ufw/applications.d`; that directory is root-owned and uid1001 cannot write it. `nftables.postinst` only manages `nftables.service` state.

## Attacker trigger results

uid1001 write attempts failed for all tested root trust paths:

```text
/etc/ufw/ufw.conf
/etc/default/ufw
/etc/ufw/before.rules
/etc/ufw/after.rules
/etc/ufw/user.rules
/etc/ufw/before.init
/etc/ufw/after.init
/etc/ufw/applications.d/firewall-boot-helpers
/run/ufw.lock
/lib/ufw/ufw.lock
/usr/lib/ufw/ufw-init-functions
/etc/nftables.conf
/etc/default/nftables
/etc/iptables/rules.v4
/var/lib/iptables/rules-save
/etc/sysctl.conf
/etc/sysctl.d/99-firewall-boot-helpers.conf
/usr/lib/sysctl.d/99-firewall-boot-helpers.conf
/run/sysctl.d/99-firewall-boot-helpers.conf
/run/credentials/systemd-sysctl.service/sysctl.firewall
/etc/modules
/etc/modules-load.d/firewall-boot-helpers.conf
/usr/lib/modules-load.d/firewall-boot-helpers.conf
/run/modules-load.d/firewall-boot-helpers.conf
/etc/modprobe.d/firewall-boot-helpers.conf
/usr/lib/modprobe.d/firewall-boot-helpers.conf
/run/modprobe.d/firewall-boot-helpers.conf
/etc/systemd/system/ufw.service.d/firewall.conf
/run/systemd/system/ufw.service.d/firewall.conf
```

uid1001 `systemctl start|restart|reload|stop` attempts for `ufw.service`, `nftables.service`, `systemd-sysctl.service`, `systemd-modules-load.service`, and `netfilter-persistent.service` all failed with `Interactive authentication required`.

Direct uid1001 `/usr/sbin/ufw` refused with `ERROR: You need to be root to run this script`. Direct uid1001 `/usr/lib/ufw/ufw-init status` returned `Firewall is not running`; a hostile `PATH` did not intercept `iptables` because `ufw-init-functions` resets `PATH=/sbin:/bin:/usr/sbin:/usr/bin`. A fake `--rootdir` test executed attacker-controlled functions only as uid1001, proving that path is a direct-call test mode, not a privileged service input.

## Conclusion

No root-owned attacker-controlled file, root command execution, symlink race, writable include/import path, or unprivileged boot/timer re-entry was validated. The exploitable-looking script trust points are guarded by root-owned configuration and systemd authorization in the default install. Root proof: none.

Rerun probe: `pocs/firewall_boot_helpers_probe.sh > logs/firewall-boot-helpers.out 2>&1`.
