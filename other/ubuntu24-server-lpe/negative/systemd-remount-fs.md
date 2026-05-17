# Negative: systemd-remount-fs namespace/input boundary

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Artifacts:

```text
pocs/systemd_remount_fs_probe.sh
logs/systemd-remount-fs.out
```

## Result

No uid1001-to-root LPE was validated through `systemd-remount-fs.service`.

The service is default-installed, default-enabled at runtime, already active/exited, and runs a root helper. The plausible boundary was whether an unprivileged user/mount namespace could influence PID 1's mount namespace or the helper inputs consumed by `/usr/lib/systemd/systemd-remount-fs`. It did not.

## Default proof

Packages from the live target:

```text
systemd      255.4-1ubuntu8.15
mount        2.39.3-9ubuntu6.5
util-linux   2.39.3-9ubuntu6.5
```

Unit state:

```text
Id=systemd-remount-fs.service
LoadState=loaded
UnitFileState=enabled-runtime
ActiveState=active
SubState=exited
ConditionResult=yes
ExecStart=/usr/lib/systemd/systemd-remount-fs
User= / Group=  # root
```

Relevant root execution/config paths:

```text
/usr/lib/systemd/system/systemd-remount-fs.service:15-25
  DefaultDependencies=no
  Before=local-fs-pre.target local-fs.target
  Type=oneshot
  RemainAfterExit=yes
  ExecStart=/usr/lib/systemd/systemd-remount-fs

/usr/lib/systemd/systemd-remount-fs 0755 root:root
/etc/fstab 0644 root:root
/run/systemd/generator 0755 root:root
/run/systemd/generator/local-fs.target.wants 0755 root:root
/run/systemd/system 0755 root:root
/proc/self/mountinfo 0444 root:root
```

As uid1001, all tested helper inputs were not writable:

```text
/etc/fstab: not-writable
/run/systemd/generator: not-writable
/run/systemd/generator/local-fs.target.wants: not-writable
/run/systemd/system: not-writable
/proc/self/mountinfo: not-writable
```

## Trigger attempts

As uid1001, create a private user/mount namespace and mount attacker-controlled tmpfs:

```sh
runuser -u attacker -- bash -lc '
mkdir -p /tmp/remountfs-userns
unshare -Urmpf bash -lc "
  mount -t tmpfs tmpfs /tmp/remountfs-userns
  grep remountfs-userns /proc/self/mountinfo
"
'
```

Observed in the attacker namespace:

```text
uid=0(root) gid=0(root) groups=0(root)
317 92 0:80 / /tmp/remountfs-userns rw,relatime - tmpfs tmpfs rw,uid=1001,gid=1001
```

The mount did not appear in PID 1 or the target's initial namespace:

```text
PID1_MOUNTINFO
TARGET_MOUNTINFO
```

As uid1001, direct systemd triggers were admin-gated:

```sh
systemctl start systemd-remount-fs.service
busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager StartUnit ss systemd-remount-fs.service replace
```

Both returned:

```text
Interactive authentication required.
```

A root debug execution of the helper printed only:

```text
Found container virtualization docker.
```

## Why this is not a finding

The root helper is real and default-reached, but uid1001 cannot write `/etc/fstab`, systemd generator output, runtime unit directories, or initial-namespace mountinfo. User/mount namespace state remained private and did not bleed into PID 1's namespace. The default systemd D-Bus and `systemctl` start paths require authorization.

No root command execution, root-owned attacker-selected write, privileged group transition, or `uid=0` context was reached from the normal user.

## Cleanup

The probe removed `/tmp/remountfs-userns`. Final health:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
```

## Why scanners may miss it

Static inventory sees an enabled root oneshot that remounts filesystems and consumes global mount/fstab state. Exploitability depends on namespace propagation, PID 1's mount namespace, systemd generator ownership, and D-Bus authorization semantics, none of which are captured by mode or unit-file scanning alone.

## Suggested fix

No LPE fix is justified from this target state. Keep `systemd-remount-fs.service` starts admin-gated, keep generator/runtime unit directories root-owned, and avoid accepting mount metadata from caller-controlled namespaces.
