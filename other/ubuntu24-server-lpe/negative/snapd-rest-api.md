# snapd REST/API, local snap, and helper surface

Status: no validated uid1001-to-root LPE in the stock Ubuntu 24.04 Server default Docker target.

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

## Default reachability

The surface is default-installed and reachable:

```sh
dpkg-query -W snapd squashfs-tools polkitd systemd
snapd           2.74.1+ubuntu24.04.4
squashfs-tools  1:4.6.1-1build1
polkitd         124-2ubuntu1.24.04.3
systemd         255.4-1ubuntu8.15

systemctl status snapd.service snapd.socket snapd.seeded.service
snapd.service: enabled, active (running)
snapd.socket: enabled, active; listens on /run/snapd.socket and /run/snapd-snap.socket
snapd.seeded.service: enabled, active (exited)

stat -c '%a %U:%G %n' /run/snapd.socket /run/snapd-snap.socket
666 root:root /run/snapd.socket
666 root:root /run/snapd-snap.socket
```

`/usr/lib/systemd/system/snapd.socket` lines 5-10 set both sockets and `SocketMode=0666`. The admin boundaries are packaged in `/usr/share/polkit-1/actions/io.snapcraft.snapd.policy`: `io.snapcraft.snapd.manage` lines 20-27, `manage-interfaces` lines 30-37, and `manage-configuration` lines 40-47 all require `auth_admin`/`auth_admin_keep`.

`snap-confine` is a real privileged helper boundary:

```sh
getcap /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
```

Default state has no installed snaps:

```sh
runuser -u attacker -- snap list
No snaps are installed yet. Try 'snap install hello-world'.
```

## Tested attack paths

Read-only REST calls over `/run/snapd.socket` are allowed to uid1001:

```sh
curl --unix-socket /run/snapd.socket http://localhost/v2/system-info
HTTP/1.1 200 OK

curl --unix-socket /run/snapd.socket http://localhost/v2/snaps
HTTP/1.1 200 OK
{"result":[],"sources":["local"]}
```

State-changing REST calls are blocked before action:

```sh
POST /v2/snaps {"action":"install","snaps":["hello-world"]}
HTTP/1.1 401 Unauthorized
{"message":"access denied","kind":"login-required"}

POST /v2/snaps {"action":"refresh","snaps":["core24"]}
HTTP/1.1 401 Unauthorized

POST /v2/interfaces {"action":"connect", ...}
HTTP/1.1 401 Unauthorized

POST /v2/create-user {"email":"root@example.invalid","sudoer":true}
HTTP/1.1 403 Forbidden

POST /v2/assertions not-an-assertion
HTTP/1.1 401 Unauthorized
```

I built a real local snap as `attacker` with an install hook that would write `id` to `/tmp/snapd_lpe_root_proof`. All local execution routes were authorization-gated before hook execution:

```sh
runuser -u attacker -- snap pack /tmp/snapd_lpe_src /tmp
built: /tmp/snapd-lpe-test_1.0_all.snap

runuser -u attacker -- snap install --dangerous /tmp/snapd-lpe-test_1.0_all.snap
error: access denied (try with sudo)

runuser -u attacker -- snap try /tmp/snapd_lpe_src
error: access denied (try with sudo)

curl --unix-socket /run/snapd.socket -H 'X-Allow-Interaction: true' \
  -F action=install -F dangerous=true \
  -F snap=@/tmp/snapd-lpe-test_1.0_all.snap http://localhost/v2/snaps
HTTP/1.1 401 Unauthorized

ls -l /tmp/snapd_lpe_root_proof
No such file or directory
```

`/run/snapd-snap.socket` did not trust a normal process or spoofed snap headers:

```sh
curl --unix-socket /run/snapd-snap.socket http://localhost/v2/system-info
HTTP/1.1 403 Forbidden
{"message":"could not determine snap name for pid: not supported","kind":"login-required"}

curl --unix-socket /run/snapd-snap.socket -H 'X-Snapd-Snap:core' http://localhost/v2/system-info
HTTP/1.1 403 Forbidden
{"message":"could not determine snap name for pid: not supported","kind":"login-required"}

POST /v2/snapctl {"context-id":"bogus","args":["get","system"]}
HTTP/1.1 400 Bad Request
{"message":"snapctl: cannot invoke snapctl operation commands (here \"get\") from outside of a snap"}

POST /v2/snapctl {"context-id":"bogus","args":["set","system.foo=bar"]}
HTTP/1.1 403 Forbidden
{"message":"cannot use \"set\" with uid 1001, try with sudo","kind":"login-required"}
```

Direct `snap-confine` execution can briefly raise its packaged capabilities but fails before attacker-controlled code runs because `/snap` is root-owned and no base snap is installed:

```sh
SNAPD_DEBUG=1 SNAP_NAME=foo SNAP_INSTANCE_NAME=foo SNAP_REVISION=1 SNAP_COOKIE=cookie \
  /usr/lib/snapd/snap-confine snap.foo.app /bin/id
DEBUG: ruid: 1001, euid: 1001, suid: 1001
DEBUG: after setting privileged caps: cap_chown,cap_dac_override,cap_sys_admin=eip ...
DEBUG: SNAP_MOUNT_DIR (probed): /snap
DEBUG: base snap:    core
cannot locate base snap core: No such file or directory
```

`LD_PRELOAD=/tmp/snapd_missing_preload.so` produced no loader error on `snap-confine`, consistent with secure-exec stripping attacker loader variables for the file-capability binary. `SNAP_MOUNT_DIR=/home/attacker/fakesnap` was ignored; debug still logged `SNAP_MOUNT_DIR (probed): /snap`. Slash/dot-dot and invalid snap-name tags were rejected.

Direct namespace helpers have no privilege:

```sh
runuser -u attacker -- /usr/lib/snapd/snap-update-ns foo
cannot update snap namespace: CAP_SYS_ADMIN capability not in effective set: operation not permitted

runuser -u attacker -- /usr/lib/snapd/snap-discard-ns foo
missing capability cap_sys_admin
```

A user namespace can make uid1001 appear as uid0 only inside that namespace, but it did not become host root or pass the snap-confine host-state checks:

```sh
runuser -u attacker -- unshare -Urnm bash -lc 'id; mount --bind /home/attacker/snapd_fake_snap /snap; ... snap-confine ...; id > /home/attacker/snapd_ns_proof'
uid=0(root) gid=0(root) groups=0(root)
cannot fstatat canonical snap directory: Permission denied

ls -ln /home/attacker/snapd_ns_proof
-rw-r--r-- 1 1001 1001 ... /home/attacker/snapd_ns_proof
```

No attacker-writable snapd state was found under `/run/snapd`, `/var/lib/snapd`, `/snap`, or `/var/snap`.

## Cleanup

Cleanup completed:

```sh
rm -rf /tmp/snapd_lpe_src /tmp/snapd-lpe-test_1.0_all.snap /tmp/snapd_lpe_pack.log \
  /tmp/snapd_lpe_root_proof /tmp/snapd_bad.assert \
  /run/snapd/lock/foo.lock /run/snapd/lock/foo_bar.lock
runuser -u attacker -- rm -rf /home/attacker/snapd_fake_snap /home/attacker/snapd_ns_proof \
  /home/attacker/fakesnap
findmnt | grep -E 'snapd_fake_snap|snapd_lpe|/home/attacker/fakesnap'
# no output
snap list
No snaps are installed yet. Try 'snap install hello-world'.
```

Conclusion: this is default-installed and default-reachable, but not a validated stock Ubuntu 24.04 Server LPE. The exposed REST socket allows read-only queries, but privileged operations require admin authorization. Local snap install/try would be root-code execution through snap hooks, but is also authorization-gated. The direct `snap-confine` path is privileged but remains blocked by root-owned snapd state and absence of any default base snap.
