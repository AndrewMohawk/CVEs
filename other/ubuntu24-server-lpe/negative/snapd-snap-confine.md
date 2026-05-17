# snapd.socket and snap-confine negative triage

Status: no validated stock Ubuntu 24.04 Server local privilege escalation from uid 1001.

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS, attacker `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

## Default install and reachability proof

- `baseline/live-target-standard/packages.txt:515` shows `snapd 2.74.1+ubuntu24.04.4`.
- `baseline/live-target-standard/packages.txt:541-546` show `ubuntu-minimal 1.539.2`, `ubuntu-server 1.539.2`, and `ubuntu-standard 1.539.2`.
- `baseline/live-target-standard/systemctl-sockets.txt:9` shows `snapd.socket loaded active listening`.
- `baseline/live-target-standard/systemctl-unit-files.txt:121-129,252,361` show snapd services, socket, and timer enabled/static as packaged.
- `baseline/live-target-standard/capabilities.txt:5` shows `/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p`.
- `/usr/lib/systemd/system/snapd.socket:5-10` listens on `/run/snapd.socket` and `/run/snapd-snap.socket` with `SocketMode=0666`, `SocketUser=root`, `SocketGroup=root`.
- Runtime perms:

```sh
stat -c "%A %U:%G %n" /run/snapd.socket /run/snapd-snap.socket /usr/lib/snapd/snap-confine /snap /var/lib/snapd /var/lib/snapd/snaps /var/lib/snapd/auto-import
srw-rw-rw- root:root /run/snapd.socket
srw-rw-rw- root:root /run/snapd-snap.socket
-rwxr-xr-x root:root /usr/lib/snapd/snap-confine
drwxr-xr-x root:root /snap
drwxr-xr-x root:root /var/lib/snapd
drwxr-xr-x root:root /var/lib/snapd/snaps
drwxr-xr-x root:root /var/lib/snapd/auto-import
```

No snaps are installed by default:

```sh
runuser -u attacker -- snap list
No snaps are installed yet. Try 'snap install hello-world'.
```

## Source-visible config and manifests

- `/usr/share/polkit-1/actions/io.snapcraft.snapd.policy:20-27` gates install/update/remove behind `io.snapcraft.snapd.manage` with `allow_any=auth_admin`, `allow_inactive=auth_admin`, `allow_active=auth_admin_keep`.
- `/usr/share/polkit-1/actions/io.snapcraft.snapd.policy:30-37` gates interface connects/disconnects behind admin auth.
- `/usr/share/polkit-1/actions/io.snapcraft.snapd.policy:40-47` gates configuration access behind admin auth.
- `/usr/lib/snapd/snap-confine.caps:1` is the packaged file-capability set applied to `snap-confine`.
- `/etc/apparmor.d/usr.lib.snapd.snap-confine.real:72-76` shows `SNAP_MOUNT_DIR` is probed from `/proc/1/root/snap` and the profile grants `capability sys_admin`.
- `/etc/apparmor.d/usr.lib.snapd.snap-confine.real:145-158` restricts profile changes away from `unconfined`.
- `/etc/apparmor.d/usr.lib.snapd.snap-confine.real:173-198` covers privileged rootfs/mount setup into `/tmp/snap.rootfs_*`.
- `/etc/apparmor.d/usr.lib.snapd.snap-confine.real:480-483` allows snap-confine lock handling under `/run/snapd/lock`.
- `/etc/apparmor.d/usr.lib.snapd.snap-confine.real:513-524` allows snap cookie reads and broad `/var/lib/** rw` for snap-confine.
- `/usr/lib/systemd/system/snapd.autoimport.service:4-7` disables auto-import on classic systems unless `snap_core` or `snapd_recovery_mode` is present on the kernel command line.

## REST API authorization probes

Read-only API calls are reachable by uid 1001:

```sh
curl --unix-socket /run/snapd.socket http://localhost/v2/system-info
HTTP/1.1 200 OK

curl --unix-socket /run/snapd.socket http://localhost/v2/snaps
HTTP/1.1 200 OK
{"result":[],"sources":["local"]}
```

Privileged API calls are blocked before action:

```sh
curl -i --unix-socket /run/snapd.socket -H 'Content-Type: application/json' \
  -X POST --data '{"action":"install","snaps":["hello-world"]}' http://localhost/v2/snaps
HTTP/1.1 401 Unauthorized
{"message":"access denied","kind":"login-required"}

curl -i --unix-socket /run/snapd.socket -H 'Content-Type: application/json' \
  -X POST --data '{"action":"install","snaps":["hello-world"],"dangerous":true}' http://localhost/v2/snaps
HTTP/1.1 401 Unauthorized
{"message":"access denied","kind":"login-required"}

curl -i --unix-socket /run/snapd.socket -H 'Content-Type: application/json' \
  -X POST --data '{"email":"root@example.invalid","sudoer":true}' http://localhost/v2/create-user
HTTP/1.1 403 Forbidden
{"message":"access denied","kind":"login-required"}
```

The snap-confined socket does not trust a normal process:

```sh
curl -i --unix-socket /run/snapd-snap.socket http://localhost/v2/system-info
HTTP/1.1 403 Forbidden
{"message":"could not determine snap name for pid: not supported","kind":"login-required"}

curl -i --unix-socket /run/snapd-snap.socket -H 'Content-Type: application/json' \
  -X POST --data '{"context-id":"bogus","args":["get","system"]}' http://localhost/v2/snapctl
HTTP/1.1 400 Bad Request
{"message":"snapctl: cannot invoke snapctl operation commands (here \"get\") from outside of a snap"}

curl -i --unix-socket /run/snapd-snap.socket -H 'Content-Type: application/json' \
  -X POST --data '{"context-id":"bogus","args":["set","system.foo=bar"]}' http://localhost/v2/snapctl
HTTP/1.1 403 Forbidden
{"message":"cannot use \"set\" with uid 1001, try with sudo","kind":"login-required"}
```

`X-Allow-Interaction: true` did not convert the non-admin attacker into an authorized subject; installs and interface changes still returned `401 Unauthorized`.

CLI equivalents are also denied:

```sh
runuser -u attacker -- snap install hello-world
error: access denied (try with sudo)

runuser -u attacker -- snap install --dangerous /tmp/snapd-not-a-snap
error: access denied (try with sudo)

runuser -u attacker -- snap set system experimental.parallel-instances=true
error: access denied (try with sudo)

runuser -u attacker -- snap ack /tmp/bad.assert
error: cannot assert: access denied
```

## snap-confine probes

Direct attacker execution reaches the file-capability boundary, but stays uid 1001 and fails before any controlled executable runs because the default server has no base snap:

```sh
runuser -u attacker -- env -i PATH=/usr/bin:/bin SNAPD_DEBUG=1 \
  SNAP_NAME=foo SNAP_INSTANCE_NAME=foo SNAP_REVISION=1 SNAP_COOKIE=cookie \
  /usr/lib/snapd/snap-confine snap.foo.app /bin/id

DEBUG: caps at startup: cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
DEBUG: ruid: 1001, euid: 1001, suid: 1001
DEBUG: after setting privileged caps: cap_chown,cap_dac_override,cap_sys_admin=eip cap_dac_read_search,cap_fowner,cap_sys_chroot,cap_sys_ptrace,cap_sys_resource+ep
DEBUG: SNAP_MOUNT_DIR (probed): /snap
DEBUG: base snap:    core
DEBUG: opening lock file: /run/snapd/lock/foo.lock
DEBUG: initializing mount namespace: foo
cannot locate base snap core: No such file or directory
```

`SNAP_MOUNT_DIR=/home/attacker/fakesnap` was ignored; snap-confine still logged `SNAP_MOUNT_DIR (probed): /snap`. Slash and dot-dot security tags were rejected:

```sh
/usr/lib/snapd/snap-confine 'snap.foo/../../tmp.app' /bin/id
security tag snap.foo/../../tmp.app not allowed

/usr/lib/snapd/snap-confine 'snap.foo..bar.app' /bin/id
security tag snap.foo..bar.app not allowed
```

Parallel-instance style names with underscores reached only root-owned lock creation, then failed on the missing base snap:

```sh
SNAP_INSTANCE_NAME=foo_bar /usr/lib/snapd/snap-confine snap.foo_bar.app /bin/id
DEBUG: opening lock file: /run/snapd/lock/foo_bar.lock
cannot locate base snap core: No such file or directory
```

Direct namespace helper execution did not inherit the `snap-confine` capabilities:

```sh
runuser -u attacker -- /usr/lib/snapd/snap-update-ns foo
cannot update snap namespace: CAP_SYS_ADMIN capability not in effective set: operation not permitted

runuser -u attacker -- /usr/lib/snapd/snap-discard-ns foo
missing capability cap_sys_admin
```

An unprivileged user namespace can fake uid 0 only inside that namespace; it did not cross into host root and snap-confine still failed:

```sh
runuser -u attacker -- unshare -Urnm bash -lc 'id; mount --bind /home/attacker/fakesnap /snap; env -i ... /usr/lib/snapd/snap-confine snap.foo.app /bin/id'
uid=0(root) gid=0(root) groups=0(root)
cannot fstatat canonical snap directory: Permission denied

# outside the namespace, a file created by namespace-root is still attacker-owned
ls -ln /home/attacker/userns-root-proof
-rw-r--r-- 1 1001 1001 13 May 16 10:34 /home/attacker/userns-root-proof
```

## Local snap import paths

`snapd.autoimport.service` is enabled in unit files but disabled on this classic server by conditions:

```sh
systemctl show snapd.autoimport.service -p ActiveState -p SubState -p ConditionResult
ActiveState=inactive
SubState=dead
ConditionResult=no

runuser -u attacker -- snap auto-import
auto-import is disabled on classic
```

Attacker-writable search under snapd state returned no writable paths:

```sh
runuser -u attacker -- find /run/snapd /var/lib/snapd /snap /var/snap -xdev \( -writable -o -perm -0002 -o -perm -0020 \) -printf '%M %u:%g %p\n' 2>/dev/null
# no output
```

## Cleanup

Commands used to clean probe artifacts:

```sh
rm -f /run/snapd/lock/foo.lock /run/snapd/lock/foo_bar.lock
runuser -u attacker -- rm -rf /home/attacker/fakesnap /home/attacker/userns-root-proof /tmp/snapd-not-a-snap /tmp/bad.assert
```

## Conclusion

This is a real default attack surface, but not a validated LPE in stock Ubuntu 24.04 Server default state. The world-writable REST sockets expose read-only information to uid 1001 while privileged state-changing endpoints require admin authorization. `snap-confine` is a privileged file-capability boundary and can briefly raise mount/DAC capabilities, but default Server installs no base snap and leaves `/snap` plus `/var/lib/snapd` root-owned, so attacker-controlled snap names/env values fail before executing attacker-controlled code.

Promising unresolved edge: if an in-scope default had a base snap already installed, the direct `snap-confine` path would deserve deeper mount-namespace/cookie/state-file review. On this stock Server target that precondition is absent, and installing or importing a local snap is itself authorization-gated or disabled on classic.
