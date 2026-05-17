# Negative: remaining setuid/setgid/cap helper deep audit

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS on `aarch64`.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`. No `sudo`, `docker`, `lxd`, `adm`, `shadow`, `_ssh`, `utmp`, or `messagebus` membership.

Result: no stock default `uid1001 -> root` local privilege escalation was validated in this lane. No `notes/<finding>.md` or `pocs/<finding>.*` was produced because there was no root proof.

## Default install and reachability proof

The target baseline package inventory contains the owning packages by default:

```text
baseline/docker-live-20260516/packages.txt:73   fuse3 3.14.0-5build1
baseline/docker-live-20260516/packages.txt:42   dbus 1.14.10-4ubuntu4.1
baseline/docker-live-20260516/packages.txt:407  openssh-client 1:9.6p1-3ubuntu13.16
baseline/docker-live-20260516/packages.txt:351  libutempter0:arm64 1.2.1-3build1
baseline/docker-live-20260516/packages.txt:520  sudo 1.9.15p5-3ubuntu5.24.04.2
baseline/docker-live-20260516/packages.txt:391  mtr-tiny 0.95-1.1ubuntu0.1
baseline/docker-live-20260516/packages.txt:111  iputils-ping 3:20240117-1ubuntu0.1
```

Live `dpkg-query`, mode, and capability proof:

```text
fuse3              3.14.0-5build1              /usr/bin/fusermount3                              4755 root:root
dbus               1.14.10-4ubuntu4.1          /usr/lib/dbus-1.0/dbus-daemon-launch-helper       4754 root:messagebus
openssh-client     1:9.6p1-3ubuntu13.16        /usr/lib/openssh/ssh-keysign                      4755 root:root
libutempter0       1.2.1-3build1               /usr/lib/aarch64-linux-gnu/utempter/utempter      2755 root:utmp
openssh-client     1:9.6p1-3ubuntu13.16        /usr/bin/ssh-agent                                2755 root:_ssh
sudo               1.9.15p5-3ubuntu5.24.04.2   /usr/bin/sudo                                     4755 root:root
mtr-tiny           0.95-1.1ubuntu0.1           /usr/bin/mtr-packet                               0755 root:root cap_net_raw=ep
iputils-ping       3:20240117-1ubuntu0.1       /usr/bin/ping                                     0755 root:root cap_net_raw=ep
```

Attacker reachability:

```text
/usr/bin/fusermount3                         executable; version 3.14.0
/usr/lib/dbus-1.0/dbus-daemon-launch-helper  direct exec denied by mode; indirectly reachable through system bus activation
/usr/lib/openssh/ssh-keysign                 executable; returns "ssh-keysign not enabled in /etc/ssh/ssh_config"
/usr/lib/aarch64-linux-gnu/utempter/utempter executable
/usr/bin/ssh-agent                           executable
/usr/bin/sudo                                executable; non-sudo user gets "a password is required" / auth failure
/usr/bin/mtr-packet                          executable; ICMP probe to 127.0.0.1 returns a reply
/usr/bin/ping                                executable; `ping -c1 127.0.0.1` succeeds
```

Source review used exact Ubuntu source package versions downloaded into `/tmp/helper-src`, Debian/Ubuntu patches applied, then removed after the report was written.

## fusermount3

Default config is restrictive: `/etc/fuse.conf:10` has `#user_allow_other`, and `/etc/fuse.conf:17` has `#mount_max = 1000`. `/etc/mtab` is a symlink to `../proc/self/mounts`, so the old mtab lock/update path is not a normal root-writable file target.

Relevant source boundaries:

```text
fuse-3.14.0/util/fusermount.c:80-93    drops/restores fsuid/fsgid around untrusted filesystem checks
fuse-3.14.0/util/fusermount.c:107-111  avoids mtab lock creation when /etc/mtab is a symlink
fuse-3.14.0/util/fusermount.c:513-519  parses only user_allow_other and mount_max from /etc/fuse.conf
fuse-3.14.0/util/fusermount.c:796-800  rejects allow_other/allow_root unless user_allow_other is set
fuse-3.14.0/util/fusermount.c:830-831  forces user_id/getuid and group_id/getgid into mount options
fuse-3.14.0/util/fusermount.c:907-943  lstat/chdir/lstat/access checks for directory mountpoints
fuse-3.14.0/util/fusermount.c:949-970  regular-file mountpoints are pinned through /proc/self/fd
fuse-3.14.0/util/fusermount.c:1099-1114 opens /dev/fuse, drops for config/check_perm, restores only for mount()
fuse-3.14.0/util/fusermount.c:1328-1358 resolves unmount path while dropped; mount requires _FUSE_COMMFD
```

Live FUSE harness using the real `_FUSE_COMMFD` socket path:

```text
allow_other:
  rc=1, got_fd=False
  /usr/bin/fusermount3: option allow_other only allowed if 'user_allow_other' is set in /etc/fuse.conf

normal mount on attacker-owned /tmp/fuse-deep/normal:
  rc=0, got_fd=True
  mountinfo: /tmp/fuse-deep/normal rw,nosuid,nodev,relatime - fuse /dev/fuse rw,user_id=1001,group_id=1001
  attacker unmount rc=0

symlink /tmp/fuse-deep/rootlink -> /:
  rc=1, got_fd=False
  mountpoint /tmp/fuse-deep/rootlink is not a directory or a regular file

root-owned directory /tmp/fuse-deep/rootmnt:
  rc=1, got_fd=False
  user has no write access to mountpoint /tmp/fuse-deep/rootmnt

unmount symlink-to-root:
  rc=1
  entry for /tmp/fuse-deep/rootlink not found in /etc/mtab
```

Hardlink probes against `/etc/passwd`, `/etc/sudoers`, and a root-owned D-Bus service file all failed with `Operation not permitted`; `fs.protected_hardlinks=1` and `fs.protected_symlinks=1`.

Conclusion: unprivileged FUSE mounting is real in this Docker target because `/dev/fuse` is present, but the mount is tagged to uid/gid 1001, `allow_other` is disabled, root-owned/symlink mountpoints are rejected, and no `/etc/mtab` root-file write or root execution primitive was exposed.

## dbus-daemon-launch-helper

Direct attacker execution is blocked by mode `4754 root:messagebus`:

```text
sh: 1: /usr/lib/dbus-1.0/dbus-daemon-launch-helper: Permission denied
```

It is still indirectly reachable through the system bus. `/usr/share/dbus-1/system.conf:18` runs the bus as `messagebus`, `:24` enables standard system service dirs, `:27` names the helper, `:42` listens on `/run/dbus/system_bus_socket`, and `:45-46` allow all local users to connect. The default service files under `/usr/share/dbus-1/system-services` are `root:root 0644`; attacker write checks for system service dirs were negative.

Runtime activation proof:

```text
attacker XDG_DATA_HOME=/home/attacker/dbus-deep with com.attacker.Deep.service:
  Error org.freedesktop.DBus.Error.ServiceUnknown: The name com.attacker.Deep was not provided by any .service files
  marker_absent

attacker dbus-send --system --dest=org.freedesktop.hostname1 ... Peer.Ping:
  method return ... sender=:1.1662 -> destination=:1.1661
  busctl then showed org.freedesktop.hostname1 owned by systemd-hostnamed running as root
```

Relevant source boundaries:

```text
dbus-1.14.10/bus/activation-helper.c:146-164 clears environment and hardcodes DBUS_STARTER_* to the system bus
dbus-1.14.10/bus/activation-helper.c:180-201 requires real uid == configured dbus user and euid == root
dbus-1.14.10/bus/activation-helper.c:210-232 requires service Name to match the requested bus name
dbus-1.14.10/bus/activation-helper.c:257-286 requires Exec and User from the service file
dbus-1.14.10/bus/activation-helper.c:294-331 initgroups/setgid/setuid to the service User
dbus-1.14.10/bus/activation-helper.c:336-363 parses Exec after switch_user and execv()s argv[0]
dbus-1.14.10/bus/config-parser.c:930-955 expands standard_system_servicedirs
dbus-1.14.10/bus/config-parser.c:3954-3957 standard system service dirs are /usr/local/share, /usr/share, DBUS_DATADIR, /lib
```

Conclusion: the helper is default and activatable, but the attacker cannot provide a system service file or inherit an attacker environment into the root service launch. Existing services remain bounded by their own D-Bus and polkit policy.

## ssh-keysign

Default `/etc/ssh/ssh_config:19` includes only root-owned `/etc/ssh/ssh_config.d/*.conf`; `/etc/ssh/ssh_config:26` leaves `HostbasedAuthentication` commented. No `/etc/ssh/ssh_host_*` private keys exist in this Docker target.

Live checks:

```text
HOME=/home/attacker/keysign-deep LD_PRELOAD=/home/attacker/nope.so PATH=/home/attacker/... /usr/lib/openssh/ssh-keysign
  ssh-keysign not enabled in /etc/ssh/ssh_config

strace as uid1001:
  openat("/etc/ssh/ssh_host_dsa_key", O_RDONLY) = ENOENT
  openat("/etc/ssh/ssh_host_ecdsa_key", O_RDONLY) = ENOENT
  openat("/etc/ssh/ssh_host_ed25519_key", O_RDONLY) = ENOENT
  openat("/etc/ssh/ssh_host_xmss_key", O_RDONLY) = ENOENT
  openat("/etc/ssh/ssh_host_rsa_key", O_RDONLY) = ENOENT
  openat("/etc/ssh/ssh_config", O_RDONLY) = 3
  openat("/etc/ssh/ssh_config.d/", O_DIRECTORY) = 4
```

A hostile user config with `EnableSSHKeysign yes`, `HostbasedAuthentication yes`, `Match exec "id > /tmp/keysign-match-exec-id"`, and `ProxyCommand /home/attacker/.../proxy` only executed those commands as the ssh client:

```text
match_marker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
proxy_marker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Relevant source boundaries:

```text
openssh-9.6p1/ssh-keysign.c:200-204 opens fixed host key paths
openssh-9.6p1/ssh-keysign.c:206-210 gets caller passwd entry then permanently_set_uid(pw)
openssh-9.6p1/ssh-keysign.c:218-225 reads _PATH_HOST_CONFIG_FILE only and fails unless enable_ssh_keysign == 1
openssh-9.6p1/readconf.c:1861-1863 parses EnableSSHKeysign into options
openssh-9.6p1/readconf.c:2816-2817 defaults EnableSSHKeysign to 0
```

Conclusion: user SSH config/environment did not reach root helper execution. The helper is disabled by global config and lacks host keys in this default Docker target.

## utempter

Only group-owned writable files for the `utmp` helper group are fixed accounting files:

```text
/run/utmp      0664 root:utmp
/var/log/wtmp  0664 root:utmp
/var/log/btmp  0660 root:utmp
/var/log/lastlog 0664 root:utmp
```

Invalid direct path/fd attempts did not open utmp/wtmp. A real PTY through `libutempter.so.0` added only a login accounting row and then removed the active utmp record:

```text
uidgid 1001 1001 [1001]
pty_slave /dev/pts/0
who_after_add: attacker pts/0 ... (utempter-deep-host)
who_after_remove: no active utempter-deep-host row
```

The probe immediately restored `/run/utmp` and `/var/log/wtmp` from pre-test copies; hashes after restore matched pre-test hashes.

Relevant source boundaries:

```text
libutempter-1.2.1/utempter.c:51-64 requires /dev/* slave device, O_RDWR stdin fd, and device owner == getuid()
libutempter-1.2.1/utempter.c:68-75 rejects non-printable hostname characters
libutempter-1.2.1/utempter.c:91-120 writes structured utmp/wtmp records with pututline() and updwtmp(_PATH_WTMP)
libutempter-1.2.1/utempter.c:141-153 accepts only add/del verbs
libutempter-1.2.1/utempter.c:161-173 derives user from getuid() and device from ptsname(STDIN_FILENO)
libutempter-1.2.1/iface.c:121-145 library add/remove invokes the fixed helper path with add/del
```

Conclusion: this is a bounded `utmp`/`wtmp` accounting mutation surface, not root execution or attacker-selected file write.

## ssh-agent setgid _ssh

The only file on the root filesystem with group `_ssh` is `/usr/bin/ssh-agent` itself. No group-writable `_ssh` target exists.

Runtime checks:

```text
ssh-agent command identity:
  uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
  Uid: 1001 1001 1001 1001
  Gid: 1001 1001 1001 1001
  CapEff: 0000000000000000

ssh-agent -D daemon:
  Uid: 1001 1001 1001 1001
  Gid: 1001 1001 106 1001
  Groups: 1001
  srw------- 1 1001 1001 /tmp/agent-deep/sock

SSH_PKCS11_HELPER=/home/attacker/... ssh-add -s ...
  helper marker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)

ssh-agent -a /tmp/agent-deep-link where link -> /root/agent-deep-target:
  unix_listener: cannot bind to path /tmp/agent-deep-link: Address already in use
  no_root_socket_target
```

Relevant source boundaries:

```text
openssh-9.6p1/ssh-agent.c:2220-2225 sanitises stdio and drops egid/gid to getgid()
openssh-9.6p1/ssh-pkcs11-client.c:559-566 honors SSH_PKCS11_HELPER, but this runs after agent's gid drop in this target
```

Conclusion: the saved setgid `_ssh` bit is observable in the daemon status, but effective/filesystem credentials and helper execution stay at uid/gid 1001. No `_ssh` group-write or root-write primitive was found.

## sudo as a non-sudo user

Default sudoers grants root and group-based access only: `/etc/sudoers:47` for root, `:53` for `%sudo`, and `:57` includes root-owned `/etc/sudoers.d`. Defaults include `env_reset`, `secure_path`, and `use_pty` at `/etc/sudoers:9-15`. Attacker is not in `%sudo`.

Live checks:

```text
sudo -n id:
  sudo: a password is required

SUDO_ASKPASS=/home/attacker/sudo-deep/askpass sudo -A id:
  Sorry, try again.
  sudo: 3 incorrect password attempts
  askpass marker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)

EDITOR=/home/attacker/sudo-deep/editor sudo -A -e /etc/hosts:
  auth failure
  editor marker: absent
  /root/sudo-deep-root: absent
```

Root-side strace of `sudo -A id` showed fixed config/plugin paths and unprivileged askpass execution:

```text
openat("/etc/sudo.conf", O_RDONLY|O_NONBLOCK)
openat("/usr/libexec/sudo/sudoers.so", O_RDONLY|O_CLOEXEC)
openat("/etc/sudoers", O_RDONLY|O_NONBLOCK)
openat("/etc/sudoers.d", O_RDONLY|O_DIRECTORY)
openat("/run/sudo/ts", O_RDONLY|O_NONBLOCK)
child: setuid(0); setgid(1001); setuid(1001); execve("/home/attacker/sudo-trace/askpass", ...)
```

`/run/sudo/ts/1001` existed before this lane and remained a fixed `root:attacker 0600` timestamp file afterward; I did not remove that pre-existing state.

Relevant source boundaries:

```text
sudo-1.9.15p5/src/sudo.c:176-196 reads sudo.conf, checks setuid root, then reads remaining sudo.conf
sudo-1.9.15p5/src/load_plugins.c:41-68 resolves plugins relative to sudo_conf plugin_dir, not attacker PATH
sudo-1.9.15p5/src/load_plugins.c:433-444 falls back to the default sudoers plugin when sudo.conf has no Plugin lines
sudo-1.9.15p5/src/tgetpass.c:126-153 selects SUDO_ASKPASS only for password collection
sudo-1.9.15p5/src/tgetpass.c:318-341 askpass child resets to caller gid/groups/uid before execl()
sudo-1.9.15p5/src/sudo_edit.c:735-741 runs the editor with user_cred after policy/auth has produced command_details
```

Conclusion: attacker-controlled askpass ran, but only after sudo reset the child to uid/gid 1001. `EDITOR`/sudoedit did not execute before authorization, and no sudoers/plugin/env path was attacker-controlled as root.

## mtr-packet and ping

These are file-capability helpers, not setuid root helpers:

```text
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping       cap_net_raw=ep
```

Runtime checks as attacker:

```text
mtr-packet one-shot:
  4 reply ip-4 127.0.0.1 round-trip-time 20

mtr-packet while alive:
  Uid: 1001 1001 1001 1001
  Gid: 1001 1001 1001 1001
  Groups: 1001
  CapEff: 0000000000000000

ping while alive:
  Uid: 1001 1001 1001 1001
  Gid: 1001 1001 1001 1001
  Groups: 1001
  CapEff: 0000000000000000
  3 packets transmitted, 3 received, 0% packet loss
```

Relevant source boundaries:

```text
mtr-0.95/packet/packet.c:84-91 opens network state for raw sockets, then drops elevated permissions
mtr-0.95/packet/packet.c:47-71 setgid(getgid), setuid(getuid), then cap_clear/cap_set_proc
mtr-0.95/packet/probe_unix.c:243-266 raw socket opens are the privileged operation
iputils-20240117/ping/ping_common.c:100-130 keeps only permitted CAP_NET_RAW/CAP_NET_ADMIN then setuid(getuid)
iputils-20240117/ping/ping.c:586-616 enables CAP_NET_RAW only around socket creation, then disables it
iputils-20240117/ping/ping.c:1033 drops all capabilities before the main receive/send loop
```

Conclusion: both helpers cross only the packet-socket capability boundary. They did not cross into root uid/gid, a privileged service, helper exec, or a filesystem write primitive.

## Why scanners might flag or miss this

Scanners will flag this surface because it contains classic high-risk metadata: setuid root (`fusermount3`, `ssh-keysign`, `sudo`), setuid root but group-gated (`dbus-daemon-launch-helper`), setgid privileged groups (`utempter`, `ssh-agent`), and file capabilities (`ping`, `mtr-packet`).

The important negative details are easy to miss:

```text
fusermount3 mounts are forced to user_id=1001/group_id=1001; allow_other is off; /etc/mtab is a symlink.
dbus-daemon-launch-helper is not directly executable by attacker and only consumes root-owned system service files.
ssh-keysign reads only global ssh_config for EnableSSHKeysign and defaults it off.
utempter writes only structured utmp/wtmp records derived from the caller's PTY.
ssh-agent carries only a saved _ssh gid and drops effective/filesystem gid before command/helper execution.
sudo askpass can be attacker-controlled but is executed after dropping to the original user.
ping/mtr-packet expose CAP_NET_RAW only and drop it after socket setup.
```

## Cleanup

Removed probe paths under `/tmp` and `/home/attacker`, unmounted the temporary FUSE mount, verified no `fuse-deep` mountinfo remained, verified no root markers existed under `/root` or `/tmp`, restored `/run/utmp` and `/var/log/wtmp` after the utempter PTY test, and verified no active `who` row for `utempter-deep-host`.

The temporary source-review trees `/tmp/helper-src` and `/tmp/helper-apt` were removed after extracting the line references above.

## Conclusion

No valid stock Ubuntu 24.04 Server default Docker local root privilege escalation was found in `/usr/bin/fusermount3`, `/usr/lib/dbus-1.0/dbus-daemon-launch-helper`, `/usr/lib/openssh/ssh-keysign`, `/usr/lib/aarch64-linux-gnu/utempter/utempter`, `/usr/bin/ssh-agent`, `/usr/bin/sudo` as a non-sudo user, `/usr/bin/mtr-packet`, or `/usr/bin/ping`.
