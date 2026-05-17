# snapd REST/API and helper evidence, 2026-05-16

Target: `ubuntu24-server-lpe-target`

Attacker:

```sh
id attacker
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

## Default package and service reachability

```sh
dpkg-query -W snapd squashfs-tools apparmor policykit-1 polkitd dbus systemd
apparmor        4.0.1really4.0.1-0ubuntu0.24.04.6
dbus            1.14.10-4ubuntu4.1
policykit-1
polkitd         124-2ubuntu1.24.04.3
snapd           2.74.1+ubuntu24.04.4
squashfs-tools  1:4.6.1-1build1
systemd         255.4-1ubuntu8.15
```

```sh
snap version
snap          2.74.1+ubuntu24.04.4
snapd         2.74.1+ubuntu24.04.4
series        16
ubuntu        24.04
kernel        6.10.14-linuxkit
architecture  arm64
```

```sh
systemctl status --no-pager snapd.service snapd.socket snapd.seeded.service snapd.snap-repair.timer
snapd.service: loaded; enabled; active (running)
snapd.socket: loaded; enabled; active (running); Listen: /run/snapd.socket, /run/snapd-snap.socket
snapd.seeded.service: loaded; enabled; active (exited)
snapd.snap-repair.timer: loaded; enabled; inactive; ConditionKernelCommandLine=|snap_core and |snapd_recovery_mode unmet
```

```sh
stat -c '%a %U:%G %n' /run/snapd.socket /run/snapd-snap.socket /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns
666 root:root /run/snapd.socket
666 root:root /run/snapd-snap.socket
755 root:root /usr/lib/snapd/snap-confine
755 root:root /usr/lib/snapd/snap-update-ns
```

```sh
getcap /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
```

Default installed snap state:

```sh
runuser -u attacker -- snap list
No snaps are installed yet. Try 'snap install hello-world'.
```

Relevant packaged config:

```sh
nl -ba /usr/lib/systemd/system/snapd.socket
5  ListenStream=/run/snapd.socket
6  ListenStream=/run/snapd-snap.socket
7  SocketMode=0666
9  SocketUser=root
10 SocketGroup=root
```

```sh
nl -ba /usr/share/polkit-1/actions/io.snapcraft.snapd.policy
20 <action id="io.snapcraft.snapd.manage">
23 <defaults>
24   <allow_any>auth_admin</allow_any>
25   <allow_inactive>auth_admin</allow_inactive>
26   <allow_active>auth_admin_keep</allow_active>
30 <action id="io.snapcraft.snapd.manage-interfaces">
34   <allow_any>auth_admin</allow_any>
35   <allow_inactive>auth_admin</allow_inactive>
36   <allow_active>auth_admin_keep</allow_active>
40 <action id="io.snapcraft.snapd.manage-configuration">
44   <allow_any>auth_admin</allow_any>
45   <allow_inactive>auth_admin</allow_inactive>
46   <allow_active>auth_admin_keep</allow_active>
```

```sh
nl -ba /usr/lib/snapd/snap-confine.caps
1 cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
```

Classic-system disabled auto-import/repair paths:

```sh
nl -ba /usr/lib/systemd/system/snapd.autoimport.service
4 # don't run on classic
5 ConditionKernelCommandLine=|snap_core
7 ConditionKernelCommandLine=|snapd_recovery_mode
11 ExecStart=/usr/bin/snap auto-import
```

```sh
systemctl show snapd.autoimport.service snapd.snap-repair.timer -p Id -p ActiveState -p SubState -p ConditionResult
Id=snapd.autoimport.service
ActiveState=inactive
SubState=dead
ConditionResult=no

Id=snapd.snap-repair.timer
ActiveState=inactive
SubState=dead
ConditionResult=no
```

## REST API probes

Read-only calls are reachable:

```sh
runuser -u attacker -- curl -sS -i --unix-socket /run/snapd.socket http://localhost/v2/system-info
HTTP/1.1 200 OK
...
"version":"2.74.1+ubuntu24.04.4","virtualization":"docker"

runuser -u attacker -- curl -sS -i --unix-socket /run/snapd.socket http://localhost/v2/snaps
HTTP/1.1 200 OK
...
{"type":"sync","status-code":200,"status":"OK","result":[],"sources":["local"]}
```

State-changing endpoints are denied for uid1001, even with `X-Allow-Interaction: true`:

```sh
POST /v2/snaps {"action":"install","snaps":["hello-world"]}
HTTP/1.1 401 Unauthorized
{"message":"access denied","kind":"login-required"}

POST /v2/snaps {"action":"refresh","snaps":["core24"]}
HTTP/1.1 401 Unauthorized
{"message":"access denied","kind":"login-required"}

POST /v2/snaps {"action":"remove","snaps":["core24"]}
HTTP/1.1 401 Unauthorized
{"message":"access denied","kind":"login-required"}

POST /v2/interfaces {"action":"connect", ...}
HTTP/1.1 401 Unauthorized
{"message":"access denied","kind":"login-required"}

POST /v2/create-user {"email":"root@example.invalid","sudoer":true}
HTTP/1.1 403 Forbidden
{"message":"access denied","kind":"login-required"}

POST /v2/assertions not-an-assertion
HTTP/1.1 401 Unauthorized
{"message":"access denied","kind":"login-required"}
```

CLI equivalents:

```sh
runuser -u attacker -- snap set system experimental.parallel-instances=true
error: access denied (try with sudo)

runuser -u attacker -- snap ack /tmp/snapd_bad.assert
error: cannot assert: access denied
```

## Local snap install and try

I built a real throwaway local snap as uid1001 with an install hook that would write `/tmp/snapd_lpe_root_proof` if snapd executed it:

```sh
runuser -u attacker -- snap pack /tmp/snapd_lpe_src /tmp
built: /tmp/snapd-lpe-test_1.0_all.snap

ls -l /tmp/snapd-lpe-test_1.0_all.snap /tmp/snapd_lpe_src/meta/hooks/install
-rw-r--r-- 1 attacker attacker 16384 May 16 12:00 /tmp/snapd-lpe-test_1.0_all.snap
-rwxr-xr-x 1 attacker attacker    41 May 16 12:00 /tmp/snapd_lpe_src/meta/hooks/install
```

The hook:

```sh
#!/bin/sh
id > /tmp/snapd_lpe_root_proof
```

All install paths were denied before hook execution:

```sh
runuser -u attacker -- snap install --dangerous /tmp/snapd-lpe-test_1.0_all.snap
error: access denied (try with sudo)

runuser -u attacker -- snap try /tmp/snapd_lpe_src
error: access denied (try with sudo)

runuser -u attacker -- curl -sS -i --unix-socket /run/snapd.socket \
  -H 'X-Allow-Interaction: true' \
  -F action=install -F dangerous=true \
  -F snap=@/tmp/snapd-lpe-test_1.0_all.snap \
  http://localhost/v2/snaps
HTTP/1.1 401 Unauthorized
{"message":"access denied","kind":"login-required"}

ls -l /tmp/snapd_lpe_root_proof
ls: cannot access '/tmp/snapd_lpe_root_proof': No such file or directory
```

## snapd-snap.socket probes

The snap-confined socket is reachable, but normal uid1001 processes are not accepted as snap peers. Client-supplied snap headers did not change the peer decision:

```sh
curl --unix-socket /run/snapd-snap.socket http://localhost/v2/system-info
HTTP/1.1 403 Forbidden
{"message":"could not determine snap name for pid: not supported","kind":"login-required"}

curl --unix-socket /run/snapd-snap.socket -H 'X-Snapd-Snap:core' http://localhost/v2/system-info
HTTP/1.1 403 Forbidden
{"message":"could not determine snap name for pid: not supported","kind":"login-required"}

curl --unix-socket /run/snapd-snap.socket -H 'X-Snapd-Snap:snapd-lpe-test' -H 'X-Snapd-Context:bogus' http://localhost/v2/system-info
HTTP/1.1 403 Forbidden
{"message":"could not determine snap name for pid: not supported","kind":"login-required"}
```

Snapctl operations:

```sh
POST /v2/snapctl {"context-id":"bogus","args":["get","system"]}
HTTP/1.1 400 Bad Request
{"message":"snapctl: cannot invoke snapctl operation commands (here \"get\") from outside of a snap"}

POST /v2/snapctl {"context-id":"bogus","args":["set","system.foo=bar"]}
HTTP/1.1 403 Forbidden
{"message":"cannot use \"set\" with uid 1001, try with sudo","kind":"login-required"}
```

## snap-confine and snap-update-ns

Direct `snap-confine` execution is the only observed privileged edge. It begins as uid1001, raises the packaged capabilities, probes `/snap` from the host, then fails because the stock server has no base snap:

```sh
runuser -u attacker -- env LD_PRELOAD=/tmp/snapd_missing_preload.so \
  SNAPD_DEBUG=1 SNAP_CONFINE_DEBUG=1 SNAP_NAME=foo SNAP_INSTANCE_NAME=foo \
  SNAP_REVISION=1 SNAP_COOKIE=cookie \
  /usr/lib/snapd/snap-confine snap.foo.app /bin/id

DEBUG: caps at startup: cap_chown,cap_dac_override,...,cap_sys_resource=p
DEBUG: ruid: 1001, euid: 1001, suid: 1001
DEBUG: after setting privileged caps: cap_chown,cap_dac_override,cap_sys_admin=eip ...
DEBUG: SNAP_MOUNT_DIR (probed): /snap
DEBUG: security tag: snap.foo.app
DEBUG: executable:   /bin/id
DEBUG: base snap:    core
DEBUG: opening lock file: /run/snapd/lock/foo.lock
DEBUG: initializing mount namespace: foo
cannot locate base snap core: No such file or directory
```

There was no dynamic loader error for the missing `LD_PRELOAD`, consistent with secure-exec stripping the attacker preload for the file-capability binary.

`SNAP_MOUNT_DIR` was not attacker-controlled:

```sh
SNAP_MOUNT_DIR=/home/attacker/fakesnap ... /usr/lib/snapd/snap-confine snap.foo.app /bin/id
DEBUG: SNAP_MOUNT_DIR (probed): /snap
cannot locate base snap core: No such file or directory
```

Invalid security tags were rejected:

```sh
SNAP_NAME=foo SNAP_INSTANCE_NAME=foo ... /usr/lib/snapd/snap-confine 'snap.foo/../../tmp.app' /bin/id
security tag snap.foo/../../tmp.app not allowed

SNAP_NAME=foo..bar SNAP_INSTANCE_NAME=foo..bar ... /usr/lib/snapd/snap-confine 'snap.foo..bar.app' /bin/id
snap name must use lower case letters, digits or dashes
```

Parallel-instance style names reached only root-owned lock setup and then the same missing-base barrier:

```sh
SNAP_NAME=foo_bar SNAP_INSTANCE_NAME=foo_bar SNAP_REVISION=1 SNAP_COOKIE=cookie SNAPD_DEBUG=1 \
  /usr/lib/snapd/snap-confine snap.foo_bar.app /bin/id
DEBUG: opening lock file: /run/snapd/lock/foo_bar.lock
cannot locate base snap core: No such file or directory
```

Namespace helpers have no privilege when called directly:

```sh
runuser -u attacker -- /usr/lib/snapd/snap-update-ns foo
cannot update snap namespace: CAP_SYS_ADMIN capability not in effective set: operation not permitted

runuser -u attacker -- /usr/lib/snapd/snap-discard-ns foo
missing capability cap_sys_admin
```

User namespace spoofing did not cross into host root:

```sh
runuser -u attacker -- unshare -Urnm bash -lc \
  'id; mount --bind /home/attacker/snapd_fake_snap /snap &&
   SNAPD_DEBUG=1 SNAP_NAME=foo SNAP_INSTANCE_NAME=foo SNAP_REVISION=1 SNAP_COOKIE=cookie
   /usr/lib/snapd/snap-confine snap.foo.app /bin/id;
   id > /home/attacker/snapd_ns_proof'

uid=0(root) gid=0(root) groups=0(root)
DEBUG: caps at startup: =ep
DEBUG: ruid: 0, euid: 0, suid: 0
cannot fstatat canonical snap directory: Permission denied

ls -ln /home/attacker/snapd_ns_proof
-rw-r--r-- 1 1001 1001 39 May 16 12:01 /home/attacker/snapd_ns_proof
```

## Writable state and cleanup

No attacker-writable snapd state was found:

```sh
runuser -u attacker -- find /run/snapd /var/lib/snapd /snap /var/snap -xdev \
  \( -writable -o -perm -0002 -o -perm -0020 \) -printf '%M %u:%g %p\n' 2>/dev/null
# no output
```

No root proof or installed snap remained:

```sh
runuser -u attacker -- snap list
No snaps are installed yet. Try 'snap install hello-world'.
```

Cleanup run:

```sh
rm -rf /tmp/snapd_lpe_src /tmp/snapd-lpe-test_1.0_all.snap /tmp/snapd_lpe_pack.log \
  /tmp/snapd_lpe_root_proof /tmp/snapd_bad.assert \
  /run/snapd/lock/foo.lock /run/snapd/lock/foo_bar.lock
runuser -u attacker -- rm -rf /home/attacker/snapd_fake_snap /home/attacker/snapd_ns_proof \
  /home/attacker/fakesnap /tmp/snapd_lpe_src /tmp/snapd-lpe-test_1.0_all.snap \
  /tmp/snapd_lpe_pack.log /tmp/snapd_bad.assert
findmnt | grep -E 'snapd_fake_snap|snapd_lpe|/home/attacker/fakesnap' || true
snap list
```

Post-cleanup:

```sh
findmnt | grep -E 'snapd_fake_snap|snapd_lpe|/home/attacker/fakesnap'
# no output

snap list
No snaps are installed yet. Try 'snap install hello-world'.

ls -l /tmp/snapd_lpe_root_proof /home/attacker/snapd_ns_proof
ls: cannot access '/tmp/snapd_lpe_root_proof': No such file or directory
ls: cannot access '/home/attacker/snapd_ns_proof': No such file or directory
```
