# Negative: fstrim timer and unprivileged FUSE mounts

Status: no validated uid1001-to-root LPE in the Docker stock Ubuntu 24.04 Server target.

## Default proof

Target:

```text
Ubuntu 24.04.4 LTS noble
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
systemd state: running
```

Relevant packages:

```text
fuse3       3.14.0-5build1
util-linux 2.39.3-9ubuntu6.5
```

The timer/service are installed and preset-enabled:

```text
fstrim.service static
fstrim.timer   enabled enabled
```

Unit paths:

```text
/usr/lib/systemd/system/fstrim.service:4 ConditionVirtualization=!container
/usr/lib/systemd/system/fstrim.service:8 ExecStart=/sbin/fstrim --listed-in /etc/fstab:/proc/self/mountinfo --verbose --quiet-unsupported
/usr/lib/systemd/system/fstrim.service:9 PrivateDevices=no
/usr/lib/systemd/system/fstrim.service:11 PrivateUsers=no
/usr/lib/systemd/system/fstrim.timer:4 ConditionVirtualization=!container
/usr/lib/systemd/system/fstrim.timer:8 OnCalendar=weekly
```

Live Docker state:

```text
fstrim.timer: inactive/dead, ConditionResult=no
fstrim.service: inactive/dead, ConditionResult=no
```

The skip reason from `systemctl status fstrim.timer`:

```text
fstrim.timer - Discard unused filesystem blocks once a week was skipped because of an unmet condition check (ConditionVirtualization=!container).
```

## Candidate

The risky shape is real on non-container installs: root periodically runs `fstrim` over `/proc/self/mountinfo`. If an unprivileged user can create a FUSE mount visible to root, root might issue filesystem ioctls into attacker-controlled FUSE server code. That is a semantic root/user boundary most scanners do not model.

In this Docker target, the root service is not default-reachable because of the container condition.

## Attacker tests

As uid1001:

```sh
systemctl start fstrim.service
```

Result:

```text
Failed to start fstrim.service: Interactive authentication required.
```

Direct execution stays in the attacker context and produces no root action:

```sh
/sbin/fstrim -av
echo fstrim_status:$?
/sbin/fstrim --listed-in /etc/fstab:/proc/self/mountinfo --verbose --quiet-unsupported
echo listed_status:$?
```

Result:

```text
fstrim_status:0
listed_status:0
```

FUSE is present but no default root trigger reached it:

```text
/usr/bin/fusermount3 is setuid root
/dev/fuse is crw-rw-rw- root:root
/etc/fuse.conf is root-owned 0644
```

Attempting a trivial FUSE mount without a real FUSE server did not create a mount:

```sh
mkdir -p /home/attacker/fstrim-mnt
mount.fuse3 /bin/true /home/attacker/fstrim-mnt
findmnt /home/attacker/fstrim-mnt
```

Result: no mount appeared.

## Why it is not a finding

No uid1001-controlled root execution or root-owned attacker-controlled write was validated. In the Docker target requested for this hunt, the root timer and service are condition-gated off by default, and an attacker cannot start the service through systemd. Direct `fstrim` execution has no privilege transition.

The non-container trust boundary remains worth remembering, but it does not satisfy the current Docker-validated completion bar.

## Cleanup

```sh
fusermount3 -u /home/attacker/fstrim-mnt 2>/dev/null || true
rmdir /home/attacker/fstrim-mnt 2>/dev/null || true
rm -f /home/attacker/fstrim-source
```
