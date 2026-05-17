# user namespace root against world sockets

Result: no validated root LPE. A normal user can create an unprivileged user namespace and become uid 0 inside that namespace, then connect to world-writable default sockets. The tested root daemons still treated the peer as the host-mapped uid 1001 subject and did not grant root/admin operations.

## Target proof

Target: `ubuntu24-server-lpe-target`, stock `ubuntu24-server-default-lpe:20260516-standard`.

```text
Ubuntu 24.04.4 LTS
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
user.max_user_namespaces = 31723
```

Package/socket proof:

```text
dbus        1.14.10-4ubuntu4.1
packagekit  1.2.8-2ubuntu1.5
polkitd     124-2ubuntu1.24.04.3
snapd       2.74.1+ubuntu24.04.4
systemd     255.4-1ubuntu8.15

srw-rw-rw- root:root 666 /run/snapd.socket
srw-rw-rw- root:root 666 /run/snapd-snap.socket
srw-rw-rw- root:root 666 /run/dbus/system_bus_socket
snapd.socket active
dbus.socket active
packagekit.service active/on-demand
```

## Trigger

Repro script:

```sh
ubuntu24-server-lpe/pocs/userns_socket_probe.sh ubuntu24-server-lpe-target
```

Core trigger:

```sh
runuser -u attacker -- unshare -Ur bash -lc '
  id
  cat /proc/self/uid_map
  curl --unix-socket /run/snapd.socket -i \
    -H "Content-Type: application/json" \
    -X POST --data "{\"email\":\"userns-root@example.invalid\",\"sudoer\":true}" \
    http://localhost/v2/create-user
  curl --unix-socket /run/snapd.socket -i \
    -H "Content-Type: application/json" \
    -X POST --data "{\"action\":\"install\",\"snaps\":[\"hello-world\"]}" \
    http://localhost/v2/snaps
  busctl --system call org.freedesktop.login1 /org/freedesktop/login1 \
    org.freedesktop.login1.Manager CanReboot
'
```

Inside the namespace:

```text
uid=0(root) gid=0(root) groups=0(root)
uid_map: 0 1001 1
gid_map: 0 1001 1
CapEff: 000001ffffffffff
```

Observed daemon responses:

```text
POST /v2/create-user {"sudoer":true}:
HTTP/1.1 403 Forbidden
{"message":"access denied","kind":"login-required"}

POST /v2/snaps {"action":"install","snaps":["hello-world"]}:
HTTP/1.1 401 Unauthorized
{"message":"access denied","kind":"login-required"}

login1 CanReboot:
s "challenge"

PackageKit CreateTransaction:
o "/2_ebdeedcc"
```

`PackageKit.CreateTransaction` is intentionally callable by unprivileged users; it did not grant install/update authority. The important checks are snapd's root/admin endpoints and logind's power policy, both of which stayed at the unprivileged host-user authorization level.

## Cleanup

The probe created only `/tmp/userns_*_resp` response captures inside the container and removed old marker names before running. Post-checks:

```text
getent passwd userns-root userns-root@example.invalid: no output
/root/userns-socket-root-* absent
/tmp/userns-socket-root-* absent
systemctl is-system-running: running
```

## Why scanners may miss it

The surface combines three common scanner triggers: unprivileged user namespaces are enabled, world-writable root daemon sockets are present, and several daemons authorize privileged methods for uid 0. The missing exploit condition is the kernel credential mapping seen by the daemon in the initial user namespace: the peer is mapped back to host uid 1001 for authorization, not treated as host root.

## Suggested triage conclusion

No Ubuntu Security LPE report from this candidate. Keep regression coverage around world-socket daemons that authorize uid 0, especially snapd and D-Bus/polkit paths, to ensure user-namespace root is never treated as initial-namespace root for local authorization.
