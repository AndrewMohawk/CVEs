# Negative: default network and cloud hook trust boundaries

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Attacker identity was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no validated uid1001 -> root LPE in this slice. No root proof exists.

## Default package and service reachability

Installed and in scope:

```text
dhcpcd-base                         1:10.0.6-1ubuntu3.2
cloud-guest-utils                   0.33-1
cloud-initramfs-copymods            0.49~24.04.1
cloud-initramfs-dyn-netconf         0.49~24.04.1
landscape-common                    24.02-0ubuntu5.7
netplan.io                          1.1.2-8ubuntu1~24.04.2
networkd-dispatcher                 2.2.4-1
pollinate                           4.33-3.1ubuntu1.3
python3-netplan                     1.1.2-8ubuntu1~24.04.2
systemd                             255.4-1ubuntu8.15
systemd-resolved                    255.4-1ubuntu8.15
ubuntu-pro-client                   37.2ubuntu~24.04
```

Not installed by default in this target: `cloud-init`, `dhcpcd5`, `resolvconf`, `openresolv`, `ubuntu-advantage-tools`.

Relevant unit state:

```text
dhcpcd.service                      not-found
cloud-init-local.service            not-found
cloud-init.service                  not-found
cloud-config.service                not-found
cloud-final.service                 not-found
resolvconf.service                  not-found
pollinate.service                   loaded/enabled, inactive, ConditionResult=no
ubuntu-advantage.service            loaded/enabled, inactive, ConditionResult=no
ua-timer.service                    loaded/static, inactive, ConditionResult=no
ua-timer.timer                      loaded/enabled, inactive, ConditionResult=no
networkd-dispatcher.service         loaded/enabled, inactive, ConditionResult=no
netplan-ovs-cleanup.service         loaded/enabled-runtime, inactive, ConditionResult=no
systemd-resolved.service            loaded/enabled, active as User=systemd-resolve
```

## Trust boundary checks

`dhcpcd-base` installs `/usr/sbin/dhcpcd` and `/usr/lib/dhcpcd/dhcpcd-run-hooks`, but no default `dhcpcd.service` unit is present. The hook loader sources only `/etc/dhcpcd.enter-hook`, `/usr/lib/dhcpcd/dhcpcd-hooks/*`, and `/etc/dhcpcd.exit-hook`; all present hook directories/files are root-owned and non-writable by uid1001. Direct attacker execution of `dhcpcd-run-hooks` is not privileged.

`cloud-init` root/local modules are absent: no `/usr/bin/cloud-init`, no cloud-init systemd units, no cloud-init generator, no `/etc/cloud/cloud.cfg`, no `/etc/cloud/cloud.cfg.d`, no `/var/lib/cloud`, and no `/run/cloud-init`. The installed cloud-initramfs packages only add initramfs hooks/scripts under `/usr/share/initramfs-tools`, which are root-owned and not attacker-reachable as a live root service in this Docker target.

`netplan` is installed with root-owned `/etc/netplan`, `/usr/libexec/netplan/generate`, and `/usr/libexec/netplan/netplan-dbus`. uid1001 cannot write `/etc/netplan` or `/run/netplan`. uid1001 `netplan generate` and `netplan apply` fail on root-owned `/run/systemd/system/netplan-ovs-cleanup.service` creation and daemon-reload permissions. D-Bus calls to `io.netplan.Netplan.{Config,Generate,Apply}` all return `Access denied`.

`networkd-dispatcher` is installed but skipped by default: its unit requires at least one hook file under `/etc/networkd-dispatcher/*/*` or `/usr/lib/networkd-dispatcher/*/*`. Both trees contain only root-owned state directories and no hook files. uid1001 cannot plant hooks and cannot start the service.

`pollinate` is installed but Docker-gated by `ConditionVirtualization=!container` and runs as `User=pollinate`, not root. `/etc/default/pollinate` is root-owned and `/var/cache/pollinate` is `pollinate:daemon 0750`; uid1001 cannot alter either. Direct uid1001 `pollinate --print-user-agent` is unprivileged/read-only.

`ubuntu-pro-client` root services are condition-gated by absent cloud markers or an absent private machine token. `/etc/ubuntu-advantage` and `/var/lib/ubuntu-advantage` are root-owned, and uid1001 cannot start `ubuntu-advantage.service`, `ua-timer.service`, or `ua-timer.timer`.

`landscape-common` exposes the MOTD/sysinfo wrapper and writable service-owned state, but the attacker is not in group `landscape`. `/etc/landscape` is `root:landscape 0775`, `/var/lib/landscape` and `/var/log/landscape` are `landscape:landscape 0755`, and uid1001 cannot write the cache or config. Direct wrapper execution runs as uid1001 and only produces uid1001-owned `/tmp` output during probing.

`resolvconf`/`openresolv` are absent. `/etc/resolv.conf` is root-owned `0644`; there is no `/etc/resolvconf` or `/run/resolvconf` hook tree to plant into.

## Attacker trigger results

uid1001 write attempts failed for all relevant hook/config/state paths:

```text
/etc/dhcpcd.enter-hook
/usr/lib/dhcpcd/dhcpcd-hooks/99-attacker
/var/lib/dhcpcd/attacker
/etc/cloud/cloud.cfg.d/99-attacker.cfg
/var/lib/cloud/scripts/per-boot/99-attacker
/etc/netplan/99-attacker.yaml
/run/netplan/99-attacker.yaml
/etc/networkd-dispatcher/routable.d/99-attacker
/usr/lib/networkd-dispatcher/routable.d/99-attacker
/etc/default/pollinate
/var/cache/pollinate/attacker
/var/lib/ubuntu-advantage/status.json
/etc/landscape/client.conf
/var/lib/landscape/attacker
/var/log/landscape/attacker
/etc/resolvconf/update.d/99-attacker
```

uid1001 `systemctl start` attempts for `pollinate.service`, `ubuntu-advantage.service`, `ua-timer.service`, `ua-timer.timer`, `networkd-dispatcher.service`, and `netplan-ovs-cleanup.service` all failed with `Interactive authentication required`.

## Conclusion

This pass did not produce a root-owned attacker-controlled file, root command execution, or an exploitable default hook transition. The only active in-scope network service was `systemd-resolved`, which is not a network/cloud hook execution boundary. Root proof: none.

Rerun probe: `pocs/network_cloud_hooks_probe.sh`.
