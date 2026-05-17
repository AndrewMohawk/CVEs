# Current focused local socket/timer recheck: no uid1001 -> root LPE

Date: 2026-05-17
Target: `ubuntu24-server-lpe-target`
Image: `ubuntu24-server-default-lpe:20260516-standard`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`
Result: negative. No root proof or working LPE PoC was produced.

## Default proof

The live target was healthy and current for the Docker image:

```text
ubuntu24-server-lpe-target Up ubuntu24-server-default-lpe:20260516-standard
systemctl is-system-running -> running
apt-get -s upgrade -> 0 upgraded, 0 newly installed, 0 to remove
```

Package versions checked in this pass:

```text
bolt                         0.9.7-1
lxd-installer                4ubuntu0.1
packagekit                   1.2.8-2ubuntu1.5
sysstat                      12.6.1-2
systemd                      255.4-1ubuntu8.15
udisks2                      2.10.1-6ubuntu1.3
update-notifier-common       3.192.68.2
```

Active/default root surfaces rechecked:

```text
lxd-installer.socket         active listening /run/lxd-installer.socket
systemd-sysext.socket        active listening /run/systemd/io.systemd.sysext
dm-event.socket              active listening /run/dmeventd-{client,server}
lvm2-lvmpolld.socket         active listening /run/lvm/lvmpolld.socket
systemd-initctl.socket       active listening /run/initctl
systemd-ask-password paths   active waiting /run/systemd/ask-password
sysstat timers               enabled/active root sa1/sa2 services
update-notifier timers       enabled/active root package-data/release MOTD services
```

## Findings

`lxd-installer.socket` is present and enabled, and its accepted service runs a fixed root shell script:

```text
/usr/lib/systemd/system/lxd-installer.socket:5  ListenStream=/run/lxd-installer.socket
/usr/lib/systemd/system/lxd-installer.socket:7  SocketGroup=lxd
/usr/lib/systemd/system/lxd-installer.socket:8  SocketMode=0660
/usr/lib/systemd/system/lxd-installer@.service:5 ExecStart=/bin/sh -eux /usr/share/lxd-installer/lxd-installer-service
/usr/share/lxd-installer/lxd-installer-service:27 snap install lxd --channel="$(lxd_channel)"
```

The normal attacker cannot reach it:

```text
/run/lxd-installer.socket -> srw-rw---- root:lxd
id attacker -> groups=1001(attacker)
/sbin/lxc version -> "Please make sure you're a member of the 'lxd' system group."
raw AF_UNIX connect -> Permission denied
systemctl start lxd-installer@attacker.service -> Interactive authentication required
snap install lxd --channel=5.21/stable/ubuntu-24.04 -> access denied
```

`systemd-sysext`, `dm-event`, `lvmpolld`, `initctl`, and ask-password root parser/control surfaces are default-present, but DAC stops uid1001 before parser reachability:

```text
/run/systemd/io.systemd.sysext       srw------- root:root
/run/dmeventd-client                 prw------- root:root
/run/dmeventd-server                 prw------- root:root
/run/lvm                             drwx------ root:root
/run/lvm/lvmpolld.socket             srw------- root:root
/run/initctl                         prw------- root:root
/dev/initctl                         -> /run/initctl
/run/systemd/ask-password            drwxr-xr-x root:root
```

Representative unit/code anchors:

```text
/usr/lib/systemd/system/systemd-sysext.socket:18-22  ListenStream, SocketMode=0600, Accept=yes
/usr/lib/systemd/system/dm-event.socket:7-10         FIFOs with SocketMode=0600
/usr/lib/systemd/system/lvm2-lvmpolld.socket:8-10    /run/lvm/lvmpolld.socket SocketMode=0600
/usr/lib/systemd/system/systemd-initctl.socket:16-19 /run/initctl, /dev/initctl, SocketMode=0600
/usr/lib/systemd/system/systemd-ask-password-wall.path:21-23 DirectoryNotEmpty=/run/systemd/ask-password
/usr/lib/systemd/system/systemd-ask-password-console.path:24-26 DirectoryNotEmpty=/run/systemd/ask-password
```

Uid1001 probes returned:

```text
varlinkctl info /run/systemd/io.systemd.sysext -> Permission denied
open /run/dmeventd-client or server -> Permission denied
connect /run/lvm/lvmpolld.socket -> Permission denied
printf x > /run/initctl -> Permission denied
telinit 3 -> Failed to open /run/initctl: Permission denied
touch /run/systemd/ask-password/ask.lpe -> Permission denied
```

`sysstat` and `update-notifier` root timers/scripts did not expose a writable input:

```text
/usr/lib/systemd/system/sysstat-collect.service: ExecStart=/usr/lib/sysstat/sa1 1 1
/usr/lib/systemd/system/sysstat-summary.service: ExecStart=/usr/lib/sysstat/sa2 -A
/etc/sysstat/sysstat                              root-owned
/var/log/sysstat                                  root-owned

/usr/lib/update-notifier/package-data-downloader  root service script
/usr/share/package-data-downloads                 root-owned and empty
/var/lib/update-notifier/package-data-downloads   root-owned
/var/lib/update-notifier/package-data-downloads/partial _apt:root 0700
```

`update-notifier-motd` writes only root-owned release-upgrader state:

```text
/usr/lib/ubuntu-release-upgrader/release-upgrade-motd:23 stamp=/var/lib/ubuntu-release-upgrader/release-upgrade-available
/var/lib/ubuntu-release-upgrader                  root:root 0755
/var/lib/ubuntu-release-upgrader/release-upgrade-available root:root 0644
```

This pass did not rely on the broad polkit map for its conclusion. A later corrected
XML sweep, run with `docker exec -i` so stdin was actually delivered to Python, showed
that active-user `yes` actions do exist on the target. They are concentrated in
UDisks2, ModemManager, fwupd trusted updates, logind session/self operations,
PackageKit refresh/proxy/offline helpers, and update-notifier's
`package-system-locked` action. Those active surfaces are tracked separately; they do
not change the socket/timer blockers above.

## Cleanup

No persistent test files or root markers were created by this recheck. The target remained `systemctl is-system-running -> running`.

## Why scanners may miss it

Static listings make these look like promising root parsers and root package/timer helpers: socket activation into root services, a root LXD snap installer, sysext merge semantics, LVM polling command execution, binary initctl runlevel parsing, and root cron-like timer scripts. The exploitable boundary only resolves after checking the exact default socket modes, group membership, active polkit result, and whether the root timer inputs are writable by a normal non-sudo user.

## Suggested fixes

No Ubuntu Security fix is proposed because no LPE was proven. Defense-in-depth hardening would be to keep these root sockets explicitly `0600`, keep `lxd-installer.socket` restricted to the `lxd` group, and document that update-notifier package-data hooks must remain root-owned and non-writable.
