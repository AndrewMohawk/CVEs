# Negative: active tty polkit paths for UDisks and PackageKit

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`.

Result: no uid1001/selfauth-to-root LPE was validated. A real tty login on `/dev/tty1` can make a normal non-sudo user an active local `seat0` subject in this Docker target, which changes polkit behavior for UDisks and PackageKit. The reachable operations remained bounded: UDisks loop mounts force `nosuid,nodev` and reject `suid`, and PackageKit active refresh/proxy operations did not produce root command execution, root file overwrite, or a root connection to the user-provided frontend socket.

## Normal non-sudo user model

The original locked `attacker` account was retained. For self-auth and active-seat checks, a separate normal user was added:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
selfauth P 2026-05-16 0 99999 7 -1
```

`selfauth` is not in `sudo`, `adm`, `lxd`, `docker`, `disk`, or other privileged groups. This models the requested normal non-sudo local user with a password.

## Active tty proof

The active local seat was modeled by stopping `getty@tty1.service`, running `/bin/login -f selfauth` on `/dev/tty1`, and using a one-shot `/home/selfauth/.bash_profile` to run probes and exit. Inside that shell:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty1
Id=86
Seat=seat0
TTY=tty1
Active=yes
State=active
```

With that active subject:

```text
pkcheck org.freedesktop.udisks2.loop-setup -> rc 0
pkcheck org.freedesktop.packagekit.system-sources-refresh -> rc 0
```

The same actions from a pseudo-tty session without active `seat0` required authentication.

## UDisks setuid image test

Package versions:

```text
udisks2 2.10.1-6ubuntu1.3
polkitd 124-2ubuntu1.24.04.3
e2fsprogs 1.47.0-2.4~exp1ubuntu4.1
```

Policy:

```text
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
org.freedesktop.udisks2.loop-setup allow_active=yes
org.freedesktop.udisks2.filesystem-mount allow_active=yes
```

As active `selfauth`, an ext4 image was created and a root-owned setuid bash was inserted with `debugfs`:

```text
Inode: 12   Type: regular    Mode:  04755
User:     0   Group:     0   Size: 1543048
Mapped file /tmp/udisks-opt.img as /dev/loop0.
Mounted /dev/loop0 at /media/selfauth/b4dc92a5-2130-4703-89cc-aa453e1f1744
```

The decisive mount options were:

```text
/media/selfauth/b4dc92a5-2130-4703-89cc-aa453e1f1744 rw,nosuid,nodev,relatime,errors=remount-ro
```

Executing the setuid-root file did not change credentials:

```text
-rwsr-xr-x 1 0 0 1543048 ... /media/selfauth/.../bashroot
bashroot -p -c 'id > /tmp/udisks-opt-proof'
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Attempts to override the safety flags were rejected before mount:

```text
udisksctl mount -b /dev/loop0 -o suid,dev,exec
Error mounting /dev/loop0: ... OptionNotPermitted: Mount option `suid' is not allowed

udisksctl mount -b /dev/loop0 -o defaults,suid,dev,exec
Error mounting /dev/loop0: ... OptionNotPermitted: Mount option `defaults' is not allowed
```

Conclusion: active local users can create and mount attacker-controlled loop filesystems through UDisks, but the default policy and option filter prevent setuid/file-capability escalation.

## PackageKit active refresh and hints

Package versions:

```text
packagekit 1.2.8-2ubuntu1.5
packagekit-tools 1.2.8-2ubuntu1.5
polkitd 124-2ubuntu1.24.04.3
```

Policy:

```text
org.freedesktop.packagekit.system-sources-refresh allow_inactive=yes allow_active=yes
org.freedesktop.packagekit.system-network-proxy-configure allow_active=yes
```

From active `tty1`, `pkcon refresh force` succeeded without admin authentication:

```text
Transaction: Refreshing cache
Status: Running
Status: Finished
Results:
 Enabled http://ports.ubuntu.com/ubuntu-ports noble InRelease
 Enabled http://ports.ubuntu.com/ubuntu-ports noble-updates InRelease
 Enabled http://ports.ubuntu.com/ubuntu-ports noble-backports InRelease
 Enabled http://ports.ubuntu.com/ubuntu-ports noble-security InRelease
```

A same-connection Python D-Bus transaction had `CallerActive=1` and `Uid=1002`. Setting a user-controlled frontend socket hint succeeded, but root PackageKit did not connect to it during `RefreshCache(true)`:

```text
TX /70_decdebaa
CallerActive before 1
Uid 1002
SetHints ok
Refresh ok
server uid=1002 euid=1002
```

The socket server saw no accepted connection.

`SetProxy` accepted attacker strings containing newlines:

```text
http://127.0.0.1:9/
https://127.0.0.1:9/\nInjectedKey=injected
localhost,127.0.0.1\nNoProxyInject=1
pac+file:///tmp/pk.pac\nPacInject=1
```

No injected text appeared under `/etc/PackageKit`, `/var/lib/PackageKit`, `/var/cache/PackageKit`, `/run`, or root-owned apt config/state paths in this test. The only changed PackageKit file was the normal root-owned transaction database timestamp:

```text
644 root:root /var/lib/PackageKit/transactions.db
```

Conclusion: active local users can trigger root PackageKit refresh and configure in-memory proxy settings, but the tested paths did not expose attacker-controlled root execution, unsafe root file writes, or debconf/frontend socket callbacks.

## Cleanup

Cleanup performed:

```text
udisksctl unmount -b /dev/loop0
udisksctl loop-delete -b /dev/loop0
rm -f /tmp/udisks-*.img /tmp/udisks-*.cmd /tmp/udisks-*proof
rm -f /tmp/pkfrontend.sock /tmp/pkfrontend.log
rm -f /home/selfauth/.bash_profile
loginctl terminate-user selfauth
systemctl start getty@tty1.service
```

Final checks showed no `udisks` mounts or test loop devices remained.

## Why scanners may miss this

The interesting boundary depends on logind seat state rather than package presence alone. A plain shell or pseudo-tty has `CallerActive=false` and sees authentication prompts, while an actual tty login can exercise `allow_active=yes` and `allow_inactive=yes` methods. The vulnerable-looking primitive is semantic: active users can hand root daemons attacker-controlled filesystem images and proxy strings, but exploitability depends on UDisks mount flag enforcement and PackageKit backend callback behavior.

## Suggested hardening

No Ubuntu Security issue is supported by this evidence. Regression tests worth keeping:

```text
- Active local UDisks loop mounts must retain nosuid,nodev for user-owned backing files.
- UDisks must continue rejecting user-supplied suid/defaults options.
- PackageKit RefreshCache must not connect to frontend-socket hints unless a role genuinely needs debconf.
- PackageKit SetProxy should reject or normalize newlines even if current storage is not injectable.
```
