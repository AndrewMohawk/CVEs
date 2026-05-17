# Negative: util-linux/shadow setuid deep filesystem and parser audit

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no stock default local root privilege escalation was validated. I did not find a root-created attacker-selected directory/file before authorization, a helper temp-file/link race, an fstab/user option path to root-owned attacker-controlled filesystem state, or a locale/iconv/environment loader path that reached attacker-controlled files as root.

The only pre-auth privileged filesystem write observed was `su` appending a fixed 400-byte failed-login record to `/var/log/btmp`. That file already exists as `root:utmp` mode `0660`, the path is fixed, and the write is a structured auth log record rather than an attacker-selected path. The probe restored `btmp` afterward.

## Versions and modes

```text
Ubuntu 24.04.4 LTS
libpam-modules=1.5.3-5ubuntu5.5
libpam-modules-bin=1.5.3-5ubuntu5.5
login=1:4.13+dfsg1-4ubuntu3.2
mount=2.39.3-9ubuntu6.5
passwd=1:4.13+dfsg1-4ubuntu3.2
util-linux=2.39.3-9ubuntu6.5

/usr/bin/mount                  root:root   4755
/usr/bin/umount                 root:root   4755
/usr/bin/su                     root:root   4755
/usr/bin/chfn                   root:root   4755
/usr/bin/chsh                   root:root   4755
/usr/bin/passwd                 root:root   4755
/usr/bin/gpasswd                root:root   4755
/usr/bin/newgrp                 root:root   4755
/usr/bin/chage                  root:shadow 2755
/usr/bin/expiry                 root:shadow 2755
/usr/sbin/unix_chkpwd           root:shadow 2755
/usr/sbin/pam_extrausers_chkpwd root:shadow 2755
```

Baseline sensitive state:

```text
/etc                         root:root 0755
/etc/.pwd.lock               root:root 0600
/run/mount                   root:root 0755
/run/mount/utab              root:root 0644 empty
/run/mount/utab.lock         root:root 0644 empty
/var/log/btmp                root:utmp 0660
/var/lib/extrausers          absent
```

## util-linux mount/umount

Source review used the exact Ubuntu source versions from the archive, unpacked inside the target under `/tmp` and removed after review.

Relevant source boundaries:

```text
util-linux sys-utils/mount.c
- suid_drop() calls drop_permissions(), then verifies setuid(0) fails.
- __sanitize_env() runs before setlocale/gettext.
- non-root use of dangerous CLI options, including -o, -m/--mkdir, -T, bind/move/propgation, drops permanently before continuing.
- after an EPERM before a syscall in restricted mode, mount retries only after suid_drop().

util-linux libmount/src/hook_mkdir.c
- X-mount.mkdir/x-mount.mkdir is implemented by the mkdir hook.
- the hook calls ul_mkdir_p() only when the context is not restricted.
- in restricted setuid mode it returns -EPERM instead of creating the target.

util-linux libmount/src/context_mount.c
- mount helpers are resolved from the compiled helper search path, not attacker PATH.
- helper type strings containing /.. are rejected.
- the helper child calls drop_permissions() before execv().

util-linux libmount/src/context_umount.c
- restricted umount uses chdir-to-parent plus UMOUNT_NOFOLLOW to avoid symlink races.
- umount helpers are also executed only after drop_permissions().
```

Live `mount --mkdir` proof showed the important fallback behavior: missing mountpoints can be created, but only after permanent drop to uid1001.

```text
execve("/usr/bin/mount", ["/usr/bin/mount", "--mkdir", "/tmp/uls-deep-src", "/tmp/uls-strace-mkdir/leaf"], ...) = 0
setgid(1001) = 0
setuid(1001) = 0
setuid(0) = -1 EPERM
mkdirat(AT_FDCWD, "/tmp/uls-strace-mkdir", 0755) = 0
mkdirat(AT_FDCWD, "/tmp/uls-strace-mkdir/leaf", 0755) = 0
mount("/tmp/uls-deep-src", "/tmp/uls-strace-mkdir/leaf", "ext3", MS_SILENT, NULL) = -1 EPERM

/tmp/uls-strace-mkdir      attacker:attacker 0755
/tmp/uls-strace-mkdir/leaf attacker:attacker 0755
```

Other mount/fstab probes:

```text
mount -o X-mount.mkdir=0700 /tmp/uls-deep-src /root/uls-deep-root/leaf
=> /root/uls-deep-root absent

mount -T /home/attacker/uls-deep-fstab /tmp/uls-deep-alt/leaf
=> created /tmp/uls-deep-alt and leaf as attacker:attacker only

temporary root-owned /etc/fstab entry:
none /tmp/uls-deep-fstab/leaf tmpfs user,x-mount.mkdir 0 0
=> created /tmp/uls-deep-fstab and leaf as attacker:attacker only, then mount failed
```

The default `/etc/fstab` hash was restored to:

```text
a6b093c9916c6c54e5d634d3689f1a0132e14cce0b8e50ff445da8e85acfbd17  /etc/fstab
```

Attacker preplacement against utab was denied:

```text
ln -s /etc/shadow /run/mount/utab.lock => File exists
touch /run/mount/utab.lock             => Permission denied
ln -s /etc/shadow /run/mount/utab      => File exists
touch /run/mount/utab                  => Permission denied
```

`umount /tmp/uls-umount-link -> /` as attacker failed with `must be superuser to unmount`; `/run/mount/utab` and `utab.lock` remained root-owned empty files.

## shadow account helpers

Relevant source boundaries:

```text
shadow libmisc/env.c
- sanitize_env() removes _RLD_, BASH_ENV, ENV, HOME, IFS, KRB_CONF, LD_*, LIBPATH, MAIL, NLSPATH, PATH, SHELL, SHLIB_PATH.
- LANG/LANGUAGE/LC_* are removed when they contain slashes.

shadow libmisc/root_flag.c
- --root/-R/-Q first drops to real uid/gid, then chdir/chroot.
- attacker-controlled chroots therefore fail with EPERM before account files/PAM inside the tree are used.

shadow src/chfn.c and src/chsh.c
- self changes must pass PAM before setuid(0), pw_lock(), pw_open(), or passwd rewrite.
- newline/colon/comma GECOS and shell parser checks happen before update.

shadow src/passwd.c
- privileged flags are denied to non-root before update.
- normal password change uses PAM first; setuid(0) and shadow/passwd update are after PAM.

shadow src/gpasswd.c
- get_group() reads group/gshadow, then check_perms() runs before setuid(0) and open_files().

shadow src/newgrp.c
- group DBs are closed, then setgid() and setuid(getuid()) run before shell/command exec.

shadow src/chage.c and src/expiry.c
- chage writes are denied before lock/open.
- chage -l opens passwd/shadow read-only, then drops setgid shadow to uid/gid 1001 before printing.
- expiry only reads the caller's passwd/shadow data; expired-password execution of passwd is as the user.

shadow lib/commonio.c
- writable account DB opens use O_NOFOLLOW.
- lock/temp names are under /etc: /etc/passwd.<pid>, /etc/passwd.lock, /etc/passwd+, and equivalents.
- denied flows in this audit did not reach those lock/temp writes.
```

Attacker preplacement of account DB lock/temp names failed:

```text
/etc/passwd.lock   Permission denied
/etc/passwd+       Permission denied
/etc/passwd.99999  Permission denied
/etc/shadow.lock   Permission denied
/etc/shadow+       Permission denied
/etc/group.lock    Permission denied
/etc/group+        Permission denied
/etc/gshadow.lock  Permission denied
/etc/gshadow+      Permission denied
/var/lib/extrausers Permission denied
```

Denied/auth-failed helper run:

```text
chfn -r Room attacker                  => PAM: Authentication failure
chsh -s /bin/sh attacker               => PAM: Authentication failure
passwd attacker                        => Authentication token manipulation error; unchanged
gpasswd -a attacker sudo               => Permission denied
newgrp sudo                            => Invalid password
chage -E 2030-01-01 attacker           => Permission denied
chage -l attacker                      => rc=0, own aging data only
expiry -c                              => rc=0
unix_chkpwd attacker nullok            => rc=7
pam_extrausers_chkpwd attacker nullok  => rc=7
```

Account DB integrity after the run:

```text
hashes_changed=0
filelist_changed=0

/etc/passwd  e1468fa4ad17e48937e0fe2d6f1c64ea1d8477c339287f68bd3fc54aa9729ee0
/etc/shadow  2ec3e9bb41b5fb888cb810a494108784fb8f0c79802e528c69924d48f5b930ac
/etc/group   dff213c60bbb531abd3fcb0cd75921179da142bd89f2d78661aaad71f4b66271
/etc/gshadow ae4b5b1eb4b8c82d5234358edc450e3bbef3b0f6ac528f1658ef689183a13c08
```

Root-side strace summaries for representative helpers:

```text
chfn -r Room attacker:
  openat("/etc/passwd", O_RDONLY|O_CLOEXEC)
  openat("/etc/shadow", O_RDONLY|O_CLOEXEC)
  no /etc/passwd.lock, /etc/passwd+, rename, link, mkdir, or attacker path

chsh -s /bin/sh attacker:
  openat("/etc/passwd", O_RDONLY|O_CLOEXEC)
  openat("/etc/shadow", O_RDONLY|O_CLOEXEC)
  no account DB lock/temp writes

gpasswd -a attacker sudo:
  openat("/etc/group", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW)
  openat("/etc/gshadow", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW)
  no group/gshadow lock/temp writes

chage -l attacker:
  openat("/etc/passwd", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW)
  openat("/etc/shadow", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW)
  setregid(1001, 1001) = 0
  setreuid(1001, 1001) = 0

unix_chkpwd attacker nullok:
  openat("/etc/passwd", O_RDONLY|O_CLOEXEC)
  openat("/etc/shadow", O_RDONLY|O_CLOEXEC)

pam_extrausers_chkpwd attacker nullok:
  openat("/etc/passwd", O_RDONLY|O_CLOEXEC)
  openat("/etc/shadow", O_RDONLY|O_CLOEXEC)
```

`/var/lib/extrausers` is absent in the default target. Direct `pam_extrausers_chkpwd` did not create it or any `npasswd`, `nshadow`, `.pwdXXXXXX`, or `.pwd.lock` state.

## Environment and locale boundaries

Hostile environment used for `passwd -S attacker` and `mount --mkdir`:

```text
GCONV_PATH=/home/attacker/uls-deep-env
LOCPATH=/home/attacker/uls-deep-env
NLSPATH=/home/attacker/uls-deep-env/%N
PATH=/home/attacker/uls-deep-env
SHELL=/home/attacker/uls-deep-env/sh
HOME=/home/attacker/uls-deep-env
LANG=/home/attacker/uls-deep-env
LC_ALL=/home/attacker/uls-deep-env
CHARSET=EVIL
```

Root-side traces showed no `open()`/`openat()` of `/home/attacker/uls-deep-env` by either setuid helper. The only trace match for that path was the initial `/usr/bin/env` `execve()` argument vector. The mount case still dropped to uid1001 before `mkdirat()` and created only attacker-owned `/tmp` directories.

## su fixed-path log write

`su root -c id` with a bad password produced:

```text
su: Authentication failure
/var/log/btmp size before: 7600
/var/log/btmp size after:  8000
delta: 400
```

This is implemented by util-linux `su` as `updwtmpx(_PATH_BTMP, ...)` after PAM failure. It is a fixed existing log path, not attacker-selected filesystem creation, and the probe restored the original `btmp` file afterward.

## Cleanup

The target account files, `/etc/fstab`, `/run/mount/utab`, and `/var/log/btmp` were restored/verified after testing. Temporary source trees and probe logs under `/tmp` were removed.

No `notes/<finding>.md` or `pocs/<finding>.sh/.py` was created because no root LPE was validated.
