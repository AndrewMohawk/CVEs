# FUSE/tmpfiles probe notes

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 Server Docker/systemd target.

Attacker:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Probe harness: `ubuntu24-server-lpe/pocs/fuse_tmpfiles_probe.sh`. I built the embedded libfuse3 test filesystem in a disposable Ubuntu 24.04 build container with `gcc pkg-config libfuse3-dev`, copied only the resulting binary and script to `/tmp` in the live target, ran the mount as `attacker`, then removed those target-side files during cleanup.

The harness exposes old regular files, symlinks to `/root/fuse_tmpfiles_root_marker` and `/etc/shadow`, fake root-owned setuid metadata, FIFO metadata, and a subdirectory. It logs every FUSE callback with the caller uid/gid/pid.

## uid1001 mount works

```text
TARGET                   SOURCE              FSTYPE OPTIONS
/tmp/fuse-tmpfiles-probe fuse_tmpfiles_probe fuse   rw,nosuid,nodev,relatime,user_id=1001,group_id=1001,default_permissions
```

Attacker-visible metadata from the mounted filesystem:

```text
drwxrwxrwx 3 attacker attacker    0 Jan  1  1970 .
-rw-rw-rw- 1 attacker attacker   33 Jan  1  1970 cron_payload
prw-rw-rw- 1 attacker attacker    0 Jan  1  1970 fake_fifo
-rwsrwxrwx 2 root     root       33 Jan  1  1970 fake_root_suid
lrwxrwxrwx 1 attacker attacker   32 Jan  1  1970 symlink_to_root_marker -> /root/fuse_tmpfiles_root_marker
lrwxrwxrwx 1 attacker attacker   32 Jan  1  1970 symlink_to_shadow -> /etc/shadow
```

## Root cannot cross default attacker FUSE mounts

Without `allow_other`/`allow_root`, root in this target cannot stat the attacker FUSE mount:

```text
ls: cannot access '/tmp/fuse-tmpfiles-probe': Permission denied
stat: cannot statx '/tmp/fuse-tmpfiles-probe/fake_root_suid': Permission denied
```

Attacker cannot enable `allow_other` or `allow_root` because `/etc/fuse.conf` leaves `user_allow_other` commented:

```text
fusermount3: option allow_other only allowed if 'user_allow_other' is set in /etc/fuse.conf
```

`systemd-tmpfiles --clean --prefix=/tmp` hit the same gate and did not invoke any FUSE callbacks:

```text
Running clean action for entry D /tmp
Cleanup threshold for directory "/tmp" is Thu 2026-04-16 11:52:53.472412 UTC; age-by: abcmABM
statx(/tmp/fuse-tmpfiles-probe) failed: Permission denied
```

No root target was created or modified:

```text
ls: cannot access '/root/fuse_tmpfiles_root_marker': No such file or directory
ls: cannot access '/tmp/fuse-root-proof': No such file or directory
```

Starting the real unit also produced no FUSE callbacks:

```text
systemd-tmpfiles-clean.service: Deactivated successfully.
Finished systemd-tmpfiles-clean.service - Cleanup of Temporary Directories.
```

## /run/screen placement

`/run/screen` is attacker-writable, so I mounted a second FUSE instance at `/run/screen/fuse-tmpfiles-screen`.

```text
TARGET                           SOURCE              FSTYPE OPTIONS
/run/screen/fuse-tmpfiles-screen fuse_tmpfiles_probe fuse   rw,nosuid,nodev,relatime,user_id=1001,group_id=1001,default_permissions
ls: cannot access '/run/screen/fuse-tmpfiles-screen': Permission denied
```

`systemd-tmpfiles --create --clean --prefix=/run/screen` only handled the configured directory itself and did not traverse the attacker mount:

```text
Entry "/run/screen" matches include prefix "/run/screen".
Running clean action for entry d /run/screen
Running create action for entry d /run/screen
Found existing directory "/run/screen".
```

The FUSE callback log stayed empty.

## logrotate and man-db

Attacker cannot create FUSE mountpoints under the root-traversed trees for these services:

```text
/var/log/fuse_probe mkdir_by_attacker=NO mkdir: cannot create directory '/var/log/fuse_probe': Permission denied
/var/cache/man/fuse_probe mkdir_by_attacker=NO mkdir: cannot create directory '/var/cache/man/fuse_probe': Permission denied
/usr/share/man/fuse_probe mkdir_by_attacker=NO mkdir: cannot create directory '/usr/share/man/fuse_probe': Permission denied
/usr/local/share/man/fuse_probe mkdir_by_attacker=NO mkdir: cannot create directory '/usr/local/share/man/fuse_probe': Permission denied
```

With the `/tmp` FUSE mount still active, both default services completed without touching it:

```text
logrotate_rc=0
mandb_rc=0
logrotate.service: Deactivated successfully.
man-db.service: Deactivated successfully.
```

The FUSE callback log stayed empty.

## Link and protected regular checks

Kernel defaults:

```text
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
```

Hardlinking to a root-owned file failed as uid1001:

```text
ln: failed to create hard link '/tmp/fuse_hardlink_shadow' => '/etc/shadow': Operation not permitted
```

Root opening an attacker-owned regular file in sticky `/tmp` for truncation was blocked:

```text
sh: 1: cannot create /tmp/fuse_attacker_regular: Permission denied
```

An attacker symlink to a root file under `/tmp` did not lead to target modification during tmpfiles cleanup; the root target remained:

```text
-rw-r--r-- 1 root root 4 May 16 11:53 /root/fuse_symlink_target
target_content=keep
```

## Cleanup

Unmounted both FUSE mounts as `attacker`, removed `/tmp/fuse_tmpfiles_probe_bin`, `/tmp/fuse_tmpfiles_probe.sh`, FUSE logs, root marker files, and temporary link/protected-regular artifacts. `findmnt` had no remaining `fuse-tmpfiles` or `fuse_allow` entries.
