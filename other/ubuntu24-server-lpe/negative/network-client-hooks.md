# network-client-hooks: no LPE

Verdict: no uid1001 -> root LPE was found in the stock Ubuntu 24.04 Server default network client hook surface tested here.

Evidence artifacts:

- Probe: `pocs/network_client_hooks_probe.sh`
- Log: `logs/network-client-hooks.out`
- Validation: `bash -n pocs/network_client_hooks_probe.sh` passed, and `./pocs/network_client_hooks_probe.sh ubuntu24-server-lpe-target` exited 0.

Default package and service proof from the target:

- `dhcpcd-base 1:10.0.6-1ubuntu3.2`, `ethtool 1:6.7-1build1`, `netplan.io 1.1.2-8ubuntu1~24.04.2`, `python3-netplan 1.1.2-8ubuntu1~24.04.2`, `networkd-dispatcher 2.2.4-1`, `pollinate 4.33-3.1ubuntu1.3`, `rsync 3.2.7-1ubuntu1.2`, `systemd 255.4-1ubuntu8.15`, and `systemd-resolved 255.4-1ubuntu8.15` are installed.
- `ifupdown`, `resolvconf`, `openresolv`, `ifupdown-ng`, and `isc-dhcp-client` are not installed.
- `systemd-resolved.service` is enabled and active as `systemd-resolve`.
- `pollinate.service` is enabled but condition-gated in Docker and runs as `User=pollinate`, not root.
- `rsync.service` is disabled and condition-gated by missing `/etc/rsyncd.conf`.
- `networkd-dispatcher.service`, `systemd-networkd.service`, `systemd-networkd.socket`, and `systemd-network-generator.service` are inactive; `systemd-networkd*` are disabled.
- No `dhcpcd.service` or `dhcpcd@eth0.service` unit exists.

Inspected code/config boundaries:

- `/usr/lib/dhcpcd/dhcpcd-run-hooks:11,336-353` fixes `state_dir=/run/dhcpcd/hook-state` and sources `/etc/dhcpcd.enter-hook`, `/usr/lib/dhcpcd/dhcpcd-hooks/*`, and `/etc/dhcpcd.exit-hook`.
- `/usr/lib/dhcpcd/dhcpcd-hooks/20-resolv.conf:13-18,173-184` uses `resolvconf` if present, otherwise writes under `/run/dhcpcd/hook-state` and `/etc/resolv.conf`.
- `/usr/lib/dhcpcd/dhcpcd-hooks/50-timesyncd.conf:1-4,24,41-43` writes `/run/systemd/timesyncd.conf.d/dhcpcd-$ifname.conf` and runs `systemctl try-reload-or-restart`.
- `/etc/network/if-pre-up.d/ethtool:3-14` and `/etc/network/if-up.d/ethtool:3-55` use absolute `/usr/sbin/ethtool`; `ifup`/`ifdown` are absent.
- `/usr/lib/systemd/system/pollinate.service` has `ConditionVirtualization=!container`, `User=pollinate`, and `CacheDirectoryMode=0750`; `/usr/bin/pollinate:256-257,319-350` sources only `/etc/default/pollinate` and requires writable `/var/cache/pollinate` for non-testing mode.
- `/usr/lib/systemd/system/rsync.service` has `ConditionPathExists=/etc/rsyncd.conf`, `ProtectSystem=full`, `PrivateDevices=on`, and `NoNewPrivileges=on`.
- `systemd-resolved` exposes `/run/systemd/resolve/io.systemd.Resolve` but mutating resolver methods are covered by `org.freedesktop.resolve1.*` polkit actions.

Trigger attempts as uid1001:

```sh
./pocs/network_client_hooks_probe.sh ubuntu24-server-lpe-target
```

The probe attempted attacker writes to all root hook/config locations, including `/etc/dhcpcd.enter-hook`, `/usr/lib/dhcpcd/dhcpcd-hooks/99-attacker`, `/etc/network/if-up.d/99-attacker`, `/etc/network/if-pre-up.d/99-attacker`, `/etc/netplan/99-attacker.yaml`, `/run/netplan/99-attacker.yaml`, `/etc/default/pollinate`, `/etc/pollinate/add-user-agent`, `/var/cache/pollinate/attacker`, `/etc/rsyncd.conf`, `/etc/default/rsync`, `/etc/resolv.conf`, and `/run/systemd/timesyncd.conf.d/attacker.conf`. All failed with permission denied or missing root-owned parent.

The probe also attempted:

- `systemctl start` as attacker for `dhcpcd.service`, `dhcpcd@eth0.service`, `systemd-networkd.service`, `systemd-networkd.socket`, `systemd-network-generator.service`, `networkd-dispatcher.service`, `netplan-ovs-cleanup.service`, `pollinate.service`, `rsync.service`, and `systemd-resolved.service`; all required interactive authentication.
- `netplan get`, `netplan generate`, `netplan apply`, and `io.netplan.Netplan.Config`; writes failed on `/run/systemd/system/netplan-ovs-cleanup.service`, daemon reload required authentication, and D-Bus `Config` returned `Access denied`.
- `resolvectl flush-caches`, `reset-statistics`, `dns eth0 127.0.0.1`, `domain eth0 attacker.example`, and `revert eth0`; mutating calls required authentication or hit the monitor-socket permission boundary.
- Direct hostile `dhcpcd-run-hooks` execution with fake `resolvconf` and fake `systemctl`; both fake helpers ran only as `uid=1001(attacker)`, and writes under `/run/dhcpcd` and `/run/systemd/timesyncd.conf.d` failed.
- Direct `if-up.d`/`if-pre-up.d` ethtool hook execution with shell metacharacters in `IF_*`; no shell execution occurred, `ifup`/`ifdown` were absent, and `ethtool` rejected invalid argument values.
- Direct `pollinate` non-testing and testing modes; non-testing could not run as attacker, while testing ignored the root device and fake `curl` ran only as uid1001.
- `rsync rsync://127.0.0.1/`; connection refused because no default daemon/socket is reachable.
- Unprivileged `unshare -Urn` net namespace device creation with names such as `nch0`, `nch;touch`, and `nch.dot`; devices were created only inside the private namespace and did not appear in root netns, root udev monitor output, or root journal hooks.

Root trigger check:

After planting attacker-owned fake helpers and symlinks under `/tmp/network-client-hooks`, root-started condition-gated default units were tested: `pollinate.service`, `rsync.service`, `networkd-dispatcher.service`, `netplan-ovs-cleanup.service`, and `systemd-network-generator.service`. No planted state was consumed and the log reports `NO_ROOT_PAYLOAD_MARKER`.

Cleanup:

The probe removes `/tmp/network-client-hooks`, `/root/network-client-hooks-root-marker`, and `/tmp/network-client-hooks-root-marker`, stops `systemd-network-generator.service`, and resets failed state for the tested units. Post-run verification showed `systemctl is-system-running` as `running`, zero failed units, and no probe leftovers.

Why this is a dead end:

The interesting primitives are real only as unprivileged self-execution or root-owned configuration hooks. A normal non-sudo user cannot install hook files, cannot start the root services, cannot feed initial-namespace root network hooks from an unprivileged net namespace, and cannot make active resolver/netplan mutations without polkit authorization. No root-owned file write, service-account pivot, or root command execution was produced.
