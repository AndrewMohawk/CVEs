# Negative triage: default setuid/setgid/file-capability helpers

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS, systemd PID 1. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no validated root LPE in this helper lane. The assigned helpers are default-installed and attacker-reachable where their file modes allow it, but targeted tests did not find root execution, privileged environment propagation, writable config pivots, or group-write-to-root escalation.

## Default install proof

The target baseline has the Ubuntu Server metapackages installed:

```text
baseline/live-target-standard/packages.txt:541 ubuntu-minimal 1.539.2
baseline/live-target-standard/packages.txt:545 ubuntu-server 1.539.2
baseline/live-target-standard/packages.txt:546 ubuntu-standard 1.539.2
```

Relevant package versions from `baseline/live-target-standard/packages.txt`:

```text
cron 3.0pl1-184ubuntu2
dbus 1.14.10-4ubuntu4.1
fuse3 3.14.0-5build1
iputils-ping 3:20240117-1ubuntu0.1
libcap2-bin 1:2.66-5ubuntu2.4
libgstreamer1.0-0:arm64 1.24.2-1ubuntu0.1
libutempter0:arm64 1.2.1-3build1
login 1:4.13+dfsg1-4ubuntu3.2
mtr-tiny 0.95-1.1ubuntu0.1
openssh-client 1:9.6p1-3ubuntu13.16
passwd 1:4.13+dfsg1-4ubuntu3.2
polkitd 124-2ubuntu1.24.04.3
sudo 1.9.15p5-3ubuntu5.24.04.2
util-linux 2.39.3-9ubuntu6.5
```

Setuid/setgid inventory from `baseline/live-target-standard/setuid-setgid.txt`:

```text
2  /usr/bin/chage root:shadow mode 2755
5  /usr/bin/crontab root:crontab mode 2755
6  /usr/bin/expiry root:shadow mode 2755
7  /usr/bin/fusermount3 root:root mode 4755
9  /usr/bin/mount root:root mode 4755
12 /usr/bin/ssh-agent root:_ssh mode 2755
14 /usr/bin/sudo root:root mode 4755
15 /usr/bin/umount root:root mode 4755
16 /usr/lib/aarch64-linux-gnu/utempter/utempter root:utmp mode 2755
17 /usr/lib/dbus-1.0/dbus-daemon-launch-helper root:messagebus mode 4754
18 /usr/lib/openssh/ssh-keysign root:root mode 4755
19 /usr/lib/polkit-1/polkit-agent-helper-1 root:root mode 4755
20 /usr/sbin/pam_extrausers_chkpwd root:shadow mode 2755
21 /usr/sbin/unix_chkpwd root:shadow mode 2755
```

File capabilities from `baseline/live-target-standard/capabilities.txt`:

```text
2 /usr/bin/mtr-packet cap_net_raw=ep
3 /usr/bin/ping cap_net_raw=ep
4 /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
```

Group proof from `baseline/live-target-standard/users-groups.txt`: `attacker` is only in group `attacker`; `sudo` contains only `ubuntu`; `crontab`, `shadow`, `_ssh`, `utmp`, and `messagebus` have no attacker membership.

## Sudo

Config paths:

```text
/etc/sudoers:9  Defaults env_reset
/etc/sudoers:11 Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
/etc/sudoers:15 Defaults use_pty
/etc/sudoers:47 root ALL=(ALL:ALL) ALL
/etc/sudoers:53 %sudo ALL=(ALL:ALL) ALL
/etc/sudoers:57 @includedir /etc/sudoers.d
```

Mode/ownership:

```text
-rwsr-xr-x root root /usr/bin/sudo
-r--r----- root root /etc/sudoers
drwxr-xr-x root root /etc/sudoers.d
```

Attacker proof:

```sh
sudo -U attacker -ll
# User attacker is not allowed to run sudo on fd448ecbc136.

printf 'attacker\n' | sudo -S id
# attacker is not in the sudoers file.

printf 'attacker\n' | sudo -S -R /tmp/sudo-root id
# sudo: you are not permitted to use the -R option with id
```

Conclusion: default sudo is reachable, but the normal non-sudo attacker has no sudoers policy entry. Environment and chroot-option probes do not reach root command execution.

## Crontab and cron spool

Default cron is enabled/running:

```text
baseline/live-target-standard/systemctl-active.txt:7 cron.service loaded active running
```

Config/modes:

```text
/etc/crontab root:root 0644
/etc/cron.d root:root 0755
/var/spool/cron/crontabs root:crontab 1730
/usr/bin/crontab root:crontab 2755
```

The crontab editor path was tested because it is the most plausible env/group propagation bug. The attacker-controlled editor ran without the `crontab` group and could not create in the spool:

```text
EDITOR=/tmp/crontab_editor_probe VISUAL=/tmp/crontab_editor_probe crontab -e
editor_id=uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
spool=drwx-wx--T root crontab /var/spool/cron/crontabs
spool_touch=fail:touch: cannot touch '/var/spool/cron/crontabs/setuid_probe_editor': Permission denied
```

Conclusion: `crontab` drops to the attacker UID/GID before spawning the editor. No spool write, symlink, or root cron pivot was validated.

## Shadow helpers

Paths/modes:

```text
/etc/shadow root:shadow 0640
/etc/gshadow root:shadow 0640
/usr/bin/chage root:shadow 2755
/usr/bin/expiry root:shadow 2755
/usr/sbin/unix_chkpwd root:shadow 2755
/usr/sbin/pam_extrausers_chkpwd root:shadow 2755
```

Attacker probes:

```text
chage -l attacker => rc=0, own aging data only
chage -l root => rc=1, "chage: Permission denied."
chage -E 2030-01-01 attacker => rc=1, "chage: Permission denied."
expiry -c => rc=0
expiry -f => rc=0, no change to attacker aging fields
/usr/sbin/unix_chkpwd attacker nullok </dev/null => rc=7
/usr/sbin/unix_chkpwd root nullok </dev/null => rc=7
```

Conclusion: the helpers grant read access needed for account/password checks, not write access to shadow state. No write primitive or root execution path was found.

## mount, umount, fusermount3

Config/modes:

```text
/etc/fstab:1 # UNCONFIGURED FSTAB FOR BASE SYSTEM
/etc/fuse.conf:10 #user_allow_other
/usr/bin/mount root:root 4755
/usr/bin/umount root:root 4755
/usr/bin/fusermount3 root:root 4755
/dev/fuse root:root 0666
```

Attacker probes:

```text
mount -o bind /tmp/setuid-src /tmp/setuid-mnt
# mount: /tmp/setuid-mnt: must be superuser to use mount. rc=32

mount -t tmpfs tmpfs /tmp/setuid-mnt
# mount: /tmp/setuid-mnt: must be superuser to use mount. rc=32

mount /tmp/setuid-mnt
# mount: /tmp/setuid-mnt: can't find in /etc/fstab. rc=1

fusermount3 -o allow_other /tmp/setuid-mnt
# fusermount3: old style mounting not supported. rc=1
```

Helper execution edge: `mount -t probe` did not search attacker `PATH`, but `mount -t fuse.probe` did reach the FUSE subtype helper path. The important boundary held: the attacker-controlled `probe` executable ran as UID/GID 1001 with no capabilities:

```text
PATH=/tmp:... mount -t fuse.probe none /tmp/setuid-mnt
helper_id=uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
Uid: 1001 1001 1001 1001
Gid: 1001 1001 1001 1001
CapEff: 0000000000000000
args=none /tmp/setuid-mnt -o rw,dev,suid
```

Conclusion: the promising FUSE helper-execution path drops privileges before executing attacker code. No root LPE.

## dbus-daemon-launch-helper

Default D-Bus is active:

```text
baseline/live-target-standard/systemctl-active.txt:8 dbus.service loaded active running
baseline/live-target-standard/systemctl-sockets.txt:4 dbus.socket loaded active running
```

Modes:

```text
/usr/lib/dbus-1.0/dbus-daemon-launch-helper root:messagebus 4754
/usr/share/dbus-1/system-services root:root 0755
/etc/dbus-1/system.d root:root 0755
/run/dbus/system_bus_socket root:root 0666
```

Attacker direct execution is blocked by mode:

```text
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
# sh: Permission denied. rc=126
```

System-bus activation uses root-owned service files only; attacker could list activatable names but could not plant or select an arbitrary service file.

Conclusion: reachable through D-Bus activation only, with root-owned activation metadata. No attacker-controlled root helper execution was found.

## ssh-keysign and ssh-agent

Config/modes:

```text
/etc/ssh/ssh_config:19 Include /etc/ssh/ssh_config.d/*.conf
/etc/ssh/ssh_config:21 Host *
/etc/ssh/ssh_config:26 #   HostbasedAuthentication no
/usr/lib/openssh/ssh-keysign root:root 4755
/usr/bin/ssh-agent root:_ssh 2755
```

Attacker probes:

```text
/usr/lib/openssh/ssh-keysign
# ssh-keysign not enabled in /etc/ssh/ssh_config. rc=255

ssh-agent sh -c 'id; stat "$SSH_AUTH_SOCK"'
# uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
# srw------- attacker attacker /tmp/ssh-.../agent...
```

The `ssh-agent` daemon has saved gid `_ssh` but effective gid remains attacker:

```text
Name: ssh-agent
Uid: 1001 1001 1001 1001
Gid: 1001 1001 106 1001
Groups: 1001
CapEff: 0000000000000000
```

PKCS#11 provider loading was checked with an attacker-controlled `.so`; default provider restrictions and explicit `-P /tmp/*` tests did not load the library:

```text
ssh-add -s /tmp/libpreload_probe.so
# Could not add card "/tmp/libpreload_probe.so": agent refused operation
# no /tmp/preload_marker created
```

Conclusion: hostbased signing is disabled in global config; ssh-agent does not expose root or useful group-write impact.

## utempter

Modes:

```text
/usr/lib/aarch64-linux-gnu/utempter/utempter root:utmp 2755
/run/utmp root:utmp 0664
/var/log/wtmp root:utmp 0664
/var/log/btmp root:utmp 0660
```

Attacker probes:

```text
/usr/lib/aarch64-linux-gnu/utempter/utempter => rc=1
/usr/lib/aarch64-linux-gnu/utempter/utempter add /tmp/attacker-pty testhost => rc=1
```

Conclusion: impact is constrained to utmp/wtmp/btmp update semantics; no root execution or root-owned file write outside the utmp group files was found.

## ping, mtr-packet, gst-ptp-helper

Capabilities:

```text
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
```

Attacker reachability:

```text
ping -c 1 -W 1 127.0.0.1 => rc=0
mtr-packet --help => rc=0
gst-ptp-helper </dev/null => binds interface then exits after stdin EOF
```

`LD_PRELOAD` was tested with a valid attacker-controlled aarch64 shared object. It loaded into `/bin/true`, but not into `ping`, `mtr-packet`, or direct `gst-ptp-helper`, so the file-capability helpers are in secure execution for this vector:

```text
LD_PRELOAD=/tmp/libpreload_probe.so /bin/true
# loaded uid=1001 euid=1001 gid=1001 egid=1001
# CapEff: 0000000000000000

LD_PRELOAD=/tmp/libpreload_probe.so /usr/bin/ping -c1 -W1 127.0.0.1
# no /tmp/preload_marker created

LD_PRELOAD=/tmp/libpreload_probe.so /usr/bin/mtr-packet </dev/null
# no /tmp/preload_marker created

LD_PRELOAD=/tmp/libpreload_probe.so gst-ptp-helper </dev/null
# no /tmp/preload_marker created
```

`gst-ptp-helper` is still the broadest capability surface in this lane. Runtime debug strings show the relevant source modules:

```text
../libs/gst/helpers/ptp/args.rs
../libs/gst/helpers/ptp/net.rs
../libs/gst/helpers/ptp/main.rs
```

Conclusion: no arbitrary code execution through environment propagation. `ping`/`mtr-packet` only expose their intended raw-socket functionality. `gst-ptp-helper` exposes a privileged network helper protocol, but this pass found no root primitive.

## Group-write pivot check

Only these assigned-helper groups have writable paths:

```text
crontab: /var/spool/cron/crontabs mode 1730 root:crontab
utmp: /var/log/btmp mode 0660 root:utmp
utmp: /var/log/lastlog mode 0664 root:utmp
utmp: /var/log/wtmp mode 0664 root:utmp
```

The tested helpers either deny direct access (`dbus-daemon-launch-helper`), drop to attacker before child execution (`crontab`, `mount.fuse3`, `ssh-agent` command mode), or expose only their intended log/network operation (`utempter`, `ping`, `mtr-packet`, `gst-ptp-helper`). No group-write path became root code execution.

Kernel hardlink/symlink protections are enabled:

```text
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
```

## Cleanup performed / needed

Temporary target files used during probing:

```text
/tmp/crontab_editor_probe
/tmp/libpreload_probe.so
/tmp/mount_fuse_helper_ran
/tmp/preload_marker
/tmp/probe
/tmp/setuid-mnt
/tmp/setuid-src
/tmp/sudo-root
```

These were removed after the pass. I temporarily set an attacker password to exercise sudo post-auth behavior while keeping attacker out of all privileged groups, then restored the account to locked state:

```text
passwd -S attacker
# attacker L 2026-05-16 0 99999 7 -1
```

## Promising unresolved edge

`gst-ptp-helper` remains the most interesting non-root edge because it is default-installed with `cap_net_admin` and parses a binary stdin protocol. This pass ruled out direct environment-based code execution and did not find a root escalation path, but a source-level protocol audit would be the next focused step if this lane is revisited.
