# systemd-sysext/confext varlink negative result

Target: `ubuntu24-server-lpe-target`, stock Ubuntu Server default container, uid `1001(attacker)` normal user.

Verdict: no uid1001 -> root LPE was found in `systemd-sysext`, `systemd-confext`, or the remaining default `/run/systemd/io.systemd.*` management sockets not already covered by journald/userdb/managed-oom/resolved.

## Package and default state

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'cat /etc/os-release; uname -a; dpkg-query -W systemd systemd-sysv systemd-resolved systemd-timesyncd libsystemd-shared libsystemd0; ps -p 1 -o pid,user,comm,args --no-headers'
```

Evidence:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
libsystemd-shared:arm64 255.4-1ubuntu8.15
libsystemd0:arm64        255.4-1ubuntu8.15
systemd                  255.4-1ubuntu8.15
systemd-resolved         255.4-1ubuntu8.15
systemd-sysv             255.4-1ubuntu8.15
systemd-timesyncd        255.4-1ubuntu8.15
1 root systemd /sbin/init
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'systemctl list-unit-files "systemd-sysext*" "systemd-confext*" --no-pager; systemctl status systemd-sysext.socket systemd-sysext.service systemd-confext.service --no-pager --full || true; systemctl list-sockets --all --no-pager | grep -E "sysext|confext|varlink|io.systemd" || true'
```

Evidence:

```text
UNIT FILE               STATE    PRESET
systemd-confext.service disabled enabled
systemd-sysext.service  disabled enabled
systemd-sysext@.service static   -
systemd-sysext.socket   disabled enabled

systemd-sysext.socket: Active: active (listening)
Listen: /run/systemd/io.systemd.sysext (Stream)
systemd-sysext.service: Active: inactive (dead)
systemd-confext.service: Active: inactive (dead)

/run/systemd/io.systemd.PCRExtend     systemd-pcrextend.socket        -
/run/systemd/io.systemd.sysext        systemd-sysext.socket           -
```

The sysext socket unit hard-codes `SocketMode=0600` and `Accept=yes`:

```text
[Socket]
ListenStream=/run/systemd/io.systemd.sysext
FileDescriptorName=varlink
SocketMode=0600
Accept=yes
```

Actual socket/path state:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'find /run/systemd -path "/run/systemd/units" -prune -o \( -type s -o -type p -o -type l \) -printf "%M %U:%G %p -> %l\n" 2>/dev/null | sort | grep "/io.systemd" || true'
```

```text
srw------- 0:0 /run/systemd/io.systemd.sysext ->
srw------- 0:0 /run/systemd/journal/io.systemd.journal ->
srw------- 991:991 /run/systemd/resolve/io.systemd.Resolve.Monitor ->
srw-rw-rw- 0:0 /run/systemd/io.systemd.ManagedOOM ->
srw-rw-rw- 0:0 /run/systemd/userdb/io.systemd.DynamicUser ->
srw-rw-rw- 991:991 /run/systemd/resolve/io.systemd.Resolve ->
```

`systemd-pcrextend.socket` is present as a default unit, but the default target did not instantiate the pathname because its condition is unmet:

```text
systemd-pcrextend.socket - TPM2 PCR Extension (Varlink)
Active: inactive (dead)
Condition: start condition unmet
ConditionSecurity=measured-uki was not met
Listen: /run/systemd/io.systemd.PCRExtend (Stream)
ls: cannot access '/run/systemd/io.systemd.PCRExtend': No such file or directory
```

## Varlink interface shape

Root introspection of `/run/systemd/io.systemd.sysext`:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'varlinkctl info /run/systemd/io.systemd.sysext; varlinkctl list-interfaces /run/systemd/io.systemd.sysext; varlinkctl introspect /run/systemd/io.systemd.sysext io.systemd.sysext'
```

Evidence:

```text
Vendor: The systemd Project
Product: systemd (systemd-sysext)
Version: 255 (255.4-1ubuntu8.15)
Interfaces: io.systemd
            io.systemd.sysext
            org.varlink.service

interface io.systemd.sysext

type ImageClass(
        sysext,
        confext
)

type ImageType(
        directory,
        subvolume,
        raw,
        block
)

method Merge(
        class: ?ImageClass,
        force: ?bool,
        noReload: ?bool,
        noexec: ?bool
) -> ()

method Unmerge(
        class: ?ImageClass,
        noReload: ?bool
) -> ()

method Refresh(
        class: ?ImageClass,
        force: ?bool,
        noReload: ?bool,
        noexec: ?bool
) -> ()

method List(
        class: ?ImageClass
) -> (
        Class: ImageClass,
        Type: ImageType,
        Name: string,
        Path: ?string,
        ReadOnly: bool,
        CreationTimestamp: ?int,
        ModificationTimestamp: ?int,
        Usage: ?int,
        UsageExclusive: ?int,
        Limit: ?int,
        LimitExclusive: ?int
)
```

There is no varlink parameter for an arbitrary extension image path. The methods only select `sysext` or `confext` and boolean flags. Image loading remains through fixed extension directories.

## Extension path permissions

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'for p in / /run /var /var/lib /etc /usr /usr/lib /usr/local /usr/local/lib /opt /.extra; do [ -e "$p" ] && stat -Lc "%A %U %G %n" "$p" || echo "MISSING $p"; done; namei -l /run/extensions /var/lib/extensions /etc/extensions /usr/lib/extensions /run/confexts /var/lib/confexts /usr/local/lib/confexts /usr/lib/confexts 2>&1 || true'
```

Evidence:

```text
drwxr-xr-x root root /
drwxr-xr-x root root /run
drwxr-xr-x root root /var
drwxr-xr-x root root /var/lib
drwxr-xr-x root root /etc
drwxr-xr-x root root /usr
drwxr-xr-x root root /usr/lib
drwxr-xr-x root root /usr/local
drwxr-xr-x root root /usr/local/lib
drwxr-xr-x root root /opt
MISSING /.extra

/run/extensions: No such file or directory under root-owned /run
/var/lib/extensions: No such file or directory under root-owned /var/lib
/etc/extensions: No such file or directory under root-owned /etc
/usr/lib/extensions: No such file or directory under root-owned /usr/lib
/run/confexts: No such file or directory under root-owned /run
/var/lib/confexts: No such file or directory under root-owned /var/lib
/usr/local/lib/confexts: No such file or directory under root-owned /usr/local/lib
/usr/lib/confexts: No such file or directory under root-owned /usr/lib
```

Attacker creation attempts all fail:

```sh
docker exec -u attacker ubuntu24-server-lpe-target bash -lc 'for d in /run/extensions /var/lib/extensions /etc/extensions /usr/lib/extensions /run/confexts /var/lib/confexts /usr/local/lib/confexts /usr/lib/confexts; do mkdir -p "$d" 2>/tmp/sysext_mkdir_err; rc=$?; printf "%s rc=%s err=%s\n" "$d" "$rc" "$(cat /tmp/sysext_mkdir_err)"; rmdir "$d" 2>/dev/null; done; rm -f /tmp/sysext_mkdir_err'
```

```text
/run/extensions rc=1 err=mkdir: cannot create directory '/run/extensions': Permission denied
/var/lib/extensions rc=1 err=mkdir: cannot create directory '/var/lib/extensions': Permission denied
/etc/extensions rc=1 err=mkdir: cannot create directory '/etc/extensions': Permission denied
/usr/lib/extensions rc=1 err=mkdir: cannot create directory '/usr/lib/extensions': Permission denied
/run/confexts rc=1 err=mkdir: cannot create directory '/run/confexts': Permission denied
/var/lib/confexts rc=1 err=mkdir: cannot create directory '/var/lib/confexts': Permission denied
/usr/local/lib/confexts rc=1 err=mkdir: cannot create directory '/usr/local/lib/confexts': Permission denied
/usr/lib/confexts rc=1 err=mkdir: cannot create directory '/usr/lib/confexts': Permission denied
```

## uid1001 authorization tests

Attacker identity and capabilities:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapAmb: 0000000000000000
```

Direct socket access is blocked by kernel DAC before method dispatch:

```sh
docker exec -u attacker ubuntu24-server-lpe-target bash -lc 'ls -l /run/systemd/io.systemd.sysext /run/systemd/io.systemd.PCRExtend 2>&1 || true; varlinkctl introspect /run/systemd/io.systemd.sysext io.systemd.sysext 2>&1 || true; for method in List Merge Refresh Unmerge; do varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.$method "{}" 2>&1 || true; done'
```

```text
ls: cannot access '/run/systemd/io.systemd.PCRExtend': No such file or directory
srw------- 1 root root 0 May 16 10:23 /run/systemd/io.systemd.sysext
Failed to connect to '/run/systemd/io.systemd.sysext': Permission denied
Failed to connect to '/run/systemd/io.systemd.sysext': Permission denied
Failed to connect to '/run/systemd/io.systemd.sysext': Permission denied
Failed to connect to '/run/systemd/io.systemd.sysext': Permission denied
Failed to connect to '/run/systemd/io.systemd.sysext': Permission denied
```

Direct sysext/confext state-changing CLI paths are also blocked:

```sh
docker exec -u attacker ubuntu24-server-lpe-target bash -lc 'for verb in list status merge unmerge refresh; do echo "-- sysext $verb"; systemd-sysext "$verb" 2>&1 || true; done; for verb in list status merge unmerge refresh; do echo "-- confext $verb"; systemd-confext "$verb" 2>&1 || true; done'
```

```text
-- sysext list
No OS extensions found.
-- sysext status
HIERARCHY EXTENSIONS SINCE
/opt      none       -
/usr      none       -
-- sysext merge
Need to be privileged.
-- sysext unmerge
Need to be privileged.
-- sysext refresh
Need to be privileged.

-- confext list
No OS extensions found.
-- confext status
HIERARCHY EXTENSIONS SINCE
/etc      none       -
-- confext merge
Need to be privileged.
-- confext unmerge
Need to be privileged.
-- confext refresh
Need to be privileged.
```

Attacker unit transition attempts through systemd manager APIs are denied:

```sh
docker exec -u attacker ubuntu24-server-lpe-target bash -lc 'for cmd in "start systemd-sysext.socket" "start systemd-sysext.service" "reload systemd-sysext.service" "restart systemd-sysext.service" "start systemd-pcrextend.socket"; do echo "-- systemctl $cmd"; systemctl $cmd 2>&1 || true; done; systemctl set-environment SYSTEMD_SYSEXT_PATH=/home/attacker 2>&1 || true'
```

```text
-- systemctl start systemd-sysext.socket
Failed to start systemd-sysext.socket: Interactive authentication required.
-- systemctl start systemd-sysext.service
Failed to start systemd-sysext.service: Interactive authentication required.
-- systemctl reload systemd-sysext.service
Failed to reload systemd-sysext.service: Interactive authentication required.
-- systemctl restart systemd-sysext.service
Failed to restart systemd-sysext.service: Interactive authentication required.
-- systemctl start systemd-pcrextend.socket
Failed to start systemd-pcrextend.socket: Interactive authentication required.
Failed to set environment: Access denied
```

## Attacker-controlled image/path test

An attacker can make `systemd-sysext --root=/tmp/attacker-root list` and `systemd-confext --root=/tmp/attacker-confroot list` enumerate attacker-controlled metadata under an attacker-controlled alternate root. This does not cross a privilege boundary because the same uid invokes an unprivileged binary, and `merge` still stops at the privilege check.

Command:

```sh
docker exec -u attacker ubuntu24-server-lpe-target bash -lc 'rm -rf /tmp/attacker-root; mkdir -p /tmp/attacker-root/usr /tmp/attacker-root/opt /tmp/attacker-root/etc /tmp/attacker-root/run/extensions/evil/usr/bin /tmp/attacker-root/run/extensions/evil/usr/lib/extension-release.d; printf "ID=ubuntu\nVERSION_ID=24.04\nSYSEXT_LEVEL=1.0\n" > /tmp/attacker-root/run/extensions/evil/usr/lib/extension-release.d/extension-release.evil; systemd-sysext --root=/tmp/attacker-root list; systemd-sysext --root=/tmp/attacker-root merge 2>&1 || true; rm -rf /tmp/attacker-root'
```

```text
NAME TYPE      PATH                                   TIME
evil directory /tmp/attacker-root/run/extensions/evil Sat 2026-05-16 11:39:06 UTC
Need to be privileged.
```

Confext behaved the same:

```text
NAME TYPE      PATH                                     TIME
evil directory /tmp/attacker-confroot/run/confexts/evil Sat 2026-05-16 11:39:26 UTC
Need to be privileged.
```

## Cleanup/final state

Final command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'systemd-sysext status; systemd-confext status; for d in /run/extensions /var/lib/extensions /etc/extensions /usr/lib/extensions /run/confexts /var/lib/confexts /usr/local/lib/confexts /usr/lib/confexts; do [ -e "$d" ] && stat -Lc "%A %U %G %n" "$d" || echo "MISSING $d"; done; for p in /tmp/attacker-root /tmp/attacker-confroot /tmp/attacker-ext /tmp/sysext-owned /tmp/sysext_mkdir_err; do [ -e "$p" ] && echo "PRESENT $p" || echo "ABSENT $p"; done'
```

Evidence:

```text
HIERARCHY EXTENSIONS SINCE
/opt      none       -
/usr      none       -
HIERARCHY EXTENSIONS SINCE
/etc      none       -
MISSING /run/extensions
MISSING /var/lib/extensions
MISSING /etc/extensions
MISSING /usr/lib/extensions
MISSING /run/confexts
MISSING /var/lib/confexts
MISSING /usr/local/lib/confexts
MISSING /usr/lib/confexts
ABSENT /tmp/attacker-root
ABSENT /tmp/attacker-confroot
ABSENT /tmp/attacker-ext
ABSENT /tmp/sysext-owned
ABSENT /tmp/sysext_mkdir_err
```

Conclusion: sysext/confext root merge and refresh are reachable only through root-owned extension paths plus root-only state-changing execution. The varlink API exposes no arbitrary path argument, the socket is `0600 root:root`, uid1001 cannot start/reload the units or set manager environment, and attacker-controlled `--root` images remain attacker-only parsing. No LPE PoC was produced.
