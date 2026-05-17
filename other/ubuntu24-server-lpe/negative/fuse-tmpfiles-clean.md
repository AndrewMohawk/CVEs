# Negative: FUSE/fusermount3 with default root cleanup timers

Status: no valid `uid=1001(attacker)` to root LPE was found in this slice.

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 Server Docker/systemd target.

## Default proof

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
Linux fd448ecbc136 6.10.14-linuxkit ... aarch64 GNU/Linux
Ubuntu 24.04.4 LTS (Noble Numbat)

fuse3 3.14.0-5build1 ii
libfuse3-3 3.14.0-5build1 ii
logrotate 3.21.0-2build1 ii
man-db 2.12.0-4build2 ii
systemd 255.4-1ubuntu8.15 ii
ubuntu-minimal 1.539.2 ii
ubuntu-server 1.539.2 ii
ubuntu-standard 1.539.2 ii

crw-rw-rw- 1 root root 10, 229 /dev/fuse
-rwsr-xr-x 1 root root 67744 /usr/bin/fusermount3
```

Relevant timers:

```text
logrotate.timer active/waiting -> logrotate.service
man-db.timer active/waiting -> man-db.service
systemd-tmpfiles-clean.timer active/waiting -> systemd-tmpfiles-clean.service
```

Relevant units:

```text
systemd-tmpfiles-clean.service ExecStart=systemd-tmpfiles --clean
logrotate.service ExecStart=/usr/sbin/logrotate /etc/logrotate.conf
man-db.service ExecStart=+/usr/bin/install -d -o man -g man -m 0755 /var/cache/man
man-db.service ExecStart=/usr/bin/mandb --quiet
man-db.service User=man
```

FUSE policy and kernel link protections:

```text
/etc/fuse.conf: #user_allow_other
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
```

## FUSE mount result

`attacker` can mount and interact with a FUSE filesystem through setuid `fusermount3`:

```text
TARGET                   SOURCE              FSTYPE OPTIONS
/tmp/fuse-tmpfiles-probe fuse_tmpfiles_probe fuse   rw,nosuid,nodev,relatime,user_id=1001,group_id=1001,default_permissions
```

The mounted filesystem exposed attacker-controlled symlinks and fake root-owned metadata:

```text
-rwsrwxrwx 2 root     root       33 Jan  1  1970 fake_root_suid
lrwxrwxrwx 1 attacker attacker   32 Jan  1  1970 symlink_to_root_marker -> /root/fuse_tmpfiles_root_marker
lrwxrwxrwx 1 attacker attacker   32 Jan  1  1970 symlink_to_shadow -> /etc/shadow
```

But default unprivileged FUSE mounts are not accessible to root in this target:

```text
ls: cannot access '/tmp/fuse-tmpfiles-probe': Permission denied
stat: cannot statx '/tmp/fuse-tmpfiles-probe/fake_root_suid': Permission denied
```

The attacker also cannot request `allow_other` or `allow_root`:

```text
fusermount3: option allow_other only allowed if 'user_allow_other' is set in /etc/fuse.conf
```

## tmpfiles-clean

Default tmpfiles config includes:

```text
D /tmp 1777 root root 30d
d /run/screen 1777 root utmp
d /var/cache/man 0755 man man 1w
z /var/log 0775 root syslog -
```

Running the default cleanup path against `/tmp` with the attacker FUSE mount active did not enter the FUSE filesystem:

```text
Running clean action for entry D /tmp
Cleanup threshold for directory "/tmp" is Thu 2026-04-16 11:52:53.472412 UTC; age-by: abcmABM
statx(/tmp/fuse-tmpfiles-probe) failed: Permission denied
```

The FUSE callback log stayed empty, and no root proof or symlink target was created:

```text
ls: cannot access '/root/fuse_tmpfiles_root_marker': No such file or directory
ls: cannot access '/tmp/fuse-root-proof': No such file or directory
```

Starting the real timer service also completed without FUSE callbacks:

```text
systemd-tmpfiles-clean.service: Deactivated successfully.
Finished systemd-tmpfiles-clean.service - Cleanup of Temporary Directories.
```

`/run/screen` is attacker-writable, but its tmpfiles rule only reconciles the directory itself. With a FUSE mount at `/run/screen/fuse-tmpfiles-screen`:

```text
ls: cannot access '/run/screen/fuse-tmpfiles-screen': Permission denied
Running clean action for entry d /run/screen
Running create action for entry d /run/screen
Found existing directory "/run/screen".
```

No FUSE callbacks fired.

## logrotate and man-db

The attacker cannot place FUSE mountpoints under the paths these services traverse:

```text
/var/log/fuse_probe mkdir_by_attacker=NO Permission denied
/var/cache/man/fuse_probe mkdir_by_attacker=NO Permission denied
/usr/share/man/fuse_probe mkdir_by_attacker=NO Permission denied
/usr/local/share/man/fuse_probe mkdir_by_attacker=NO Permission denied
```

With the `/tmp` FUSE mount active, both default services completed without touching it:

```text
logrotate_rc=0
mandb_rc=0
logrotate.service: Deactivated successfully.
man-db.service: Deactivated successfully.
```

The FUSE callback log stayed empty.

## Link/race checks

Hardlink and sticky-directory overwrite primitives were blocked before any root timer could use them:

```text
ln: failed to create hard link '/tmp/fuse_hardlink_shadow' => '/etc/shadow': Operation not permitted
sh: 1: cannot create /tmp/fuse_attacker_regular: Permission denied
```

An attacker symlink under `/tmp` did not lead tmpfiles into modifying the root target:

```text
-rw-r--r-- 1 root root 4 May 16 11:53 /root/fuse_symlink_target
target_content=keep
```

No useful race window was found: the only attacker-controlled mount locations reached by default cleanup either hit the FUSE access gate before lookup, or are not recursively traversed by the default rule. The root-traversed logrotate/man-db trees are not attacker-writable mount locations.

## Conclusion

No root file deletion, overwrite, chmod/chown, or code execution primitive was validated. The key blocker is default FUSE access control: uid1001 can mount FUSE, but cannot enable `allow_other`/`allow_root`, and root-run default cleanup in this target receives `EACCES` before entering attacker-controlled FUSE metadata. The remaining default root services tested do not traverse attacker-writable FUSE mountpoints.

Cleanup completed: both FUSE mounts were unmounted, `/tmp` probe binaries/logs and root marker files were removed, and `findmnt` showed no remaining `fuse-tmpfiles` or `fuse_allow` mounts.
