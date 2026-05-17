# lxd-installer default socket audit: no uid1001 -> root LPE

Status: negative. No local privilege escalation was found from the default `attacker` user (`uid=1001 gid=1001 groups=1001`) through `lxd-installer.socket`, `lxd-installer@.service`, the `/sbin/lxc` or `/sbin/lxd` shims, the `lxd` group boundary, or the snap install path used by the installer.

## Target package and default state

Test target:

```sh
docker ps --filter name=ubuntu24-server-lpe-target --format '{{.Names}} {{.Image}} {{.Status}}'
# ubuntu24-server-lpe-target ubuntu24-server-default-lpe:20260516-standard Up 2 hours
```

Package versions:

```sh
dpkg-query -W -f='${Package}\t${Version}\n' lxd-installer snapd systemd
# lxd-installer  4ubuntu0.1
# snapd          2.74.1+ubuntu24.04.4
# systemd        255.4-1ubuntu8.15
```

The package is default-installed and the socket is default-enabled/listening:

```sh
systemctl status lxd-installer.socket --no-pager
# Loaded: loaded (/usr/lib/systemd/system/lxd-installer.socket; enabled; preset: enabled)
# Active: active (listening)
# Listen: /run/lxd-installer.socket (Stream)
# Accepted: 0; Connected: 0

ls -l /run/lxd-installer.socket
# srw-rw---- 1 root lxd 0 ... /run/lxd-installer.socket

getent group lxd
# lxd:x:101:

id attacker
# uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

## Relevant code and configuration

`/usr/lib/systemd/system/lxd-installer.socket`:

```ini
5 ListenStream=/run/lxd-installer.socket
6 SocketUser=root
7 SocketGroup=lxd
8 SocketMode=0660
9 Accept=true
```

`/usr/lib/systemd/system/lxd-installer@.service`:

```ini
5 ExecStart=/bin/sh -eux /usr/share/lxd-installer/lxd-installer-service
6 StandardInput=socket
7 StandardOutput=socket
8 StandardError=journal
9 Restart=no
```

`/sbin/lxc` and `/sbin/lxd` are identical root-owned shell shims. The trigger is intentionally gated by writability of the socket:

```sh
1  #!/bin/sh
2  SNAP_BIN="/snap/bin/$(basename "$0")"
3  if [ ! -f "${SNAP_BIN}" ]; then
4      if [ ! -w "/run/lxd-installer.socket" ]; then
5        echo "Unable to trigger the installation of the LXD snap." >&2
6        echo "Please make sure you're a member of the 'lxd' system group." >&2
7        exit 1
8      fi
9
10     echo "Installing LXD snap, please be patient."
11     python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
12
13     for _ in $(seq 90); do
14       sleep 1
15       [ -x "${SNAP_BIN}" ] && break
16     done
17 fi
18 exec "$SNAP_BIN" "$@"
```

The root service ignores client data and runs a fixed snap install command:

```sh
2  lxd_channel() {
3      track="latest"
9      [ -r /etc/os-release ] && . /etc/os-release
10     case "${VERSION_ID:-""}" in
11       "24.04")
12         track="5.21";;
20     if [ -n "${VERSION_ID:-""}" ]; then
21       echo "${track}/stable/ubuntu-${VERSION_ID}"
27 snap install lxd --channel="$(lxd_channel)" 1>&2
28 echo 1
```

Inputs in that path are not attacker-controlled in the default state:

```sh
stat -c '%A %U:%G %n' /etc/os-release /usr/bin/snap /usr/local/sbin /usr/local/bin /snap
# lrwxrwxrwx root:root /etc/os-release -> /usr/lib/os-release
# -rwxr-xr-x root:root /usr/bin/snap
# drwxr-xr-x root:root /usr/local/sbin
# drwxr-xr-x root:root /usr/local/bin
# drwxr-xr-x root:root /snap

runuser -u attacker -- python3 - <<'PY'
import os
for d in ["/usr/local/sbin", "/usr/local/bin", "/snap"]:
    print(d, os.access(d, os.W_OK))
PY
# /usr/local/sbin False
# /usr/local/bin False
# /snap False
```

The service does not inherit client-controlled environment, and uid1001 cannot poison systemd activation state:

```sh
systemctl show lxd-installer@probe.service -p ExecStart -p Environment -p PassEnvironment -p User -p Group
# ExecStart={ path=/bin/sh ; argv[]=/bin/sh -eux /usr/share/lxd-installer/lxd-installer-service ; ... }
# Environment=
# PassEnvironment=
# User=
# Group=

runuser -u attacker -- systemctl set-environment PATH=/tmp:$PATH
# Failed to set environment: Access denied

runuser -u attacker -- busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus UpdateActivationEnvironment a{ss} 1 PATH /tmp
# Call failed: Access denied
```

## Unprivileged trigger attempts

The normal attacker cannot pass the shim gate:

```sh
runuser -u attacker -- sh -lc 'id; ls -l /run/lxd-installer.socket; test -w /run/lxd-installer.socket; echo test_w_status=$?; /sbin/lxc version 2>&1; echo lxc_status=$?'
# uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
# srw-rw---- 1 root lxd 0 ... /run/lxd-installer.socket
# test_w_status=1
# Unable to trigger the installation of the LXD snap.
# Please make sure you're a member of the 'lxd' system group.
# lxc_status=1
```

Direct socket connect also fails at the kernel permission boundary:

```sh
runuser -u attacker -- python3 - <<'PY'
import os, socket
path="/run/lxd-installer.socket"
print("uid", os.getuid(), "groups", os.getgroups())
print("access_w", os.access(path, os.W_OK))
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(path)
    print("connect_ok")
except OSError as e:
    print("connect_error", e.errno, e.strerror)
PY
# uid 1001 groups [1001]
# access_w False
# connect_error 13 Permission denied
```

Starting the accepted service directly through systemd is not available to uid1001:

```sh
runuser -u attacker -- systemctl start lxd-installer@attacker.service
# Failed to start lxd-installer@attacker.service: Interactive authentication required.
```

The `lxd` group itself is not joinable by the attacker:

```sh
grep '^lxd:' /etc/group /etc/gshadow
# /etc/group:lxd:x:101:
# /etc/gshadow:lxd:!::

runuser -u attacker -- sg lxd -c id
# Password: Invalid password.
```

## Snap install path

The installer's privileged action is exactly `snap install lxd --channel=5.21/stable/ubuntu-24.04` on this target. The attacker cannot invoke the same action through snapd directly:

```sh
runuser -u attacker -- sh -lc 'snap install lxd --channel=5.21/stable/ubuntu-24.04 2>&1; echo snap_install_status=$?'
# error: access denied (try with sudo)
# snap_install_status=1
```

Direct snapd API testing matches the CLI result:

```http
POST /v2/snaps/lxd HTTP/1.1
Host: localhost
Content-Type: application/json

{"action":"install","channel":"5.21/stable/ubuntu-24.04"}
```

Over `/run/snapd.socket` as uid1001:

```json
HTTP/1.1 401 Unauthorized
{"type":"error","status-code":401,"status":"Unauthorized","result":{"message":"access denied","kind":"login-required"}}
```

Over `/run/snapd-snap.socket` as uid1001:

```json
HTTP/1.1 403 Forbidden
{"type":"error","status-code":403,"status":"Forbidden","result":{"message":"access denied","kind":"login-required"}}
```

No LXD snap was installed during these tests:

```sh
snap list lxd
# error: no matching snaps installed

test -e /snap/bin/lxc; echo $?
# 1
```

## Result

No uid1001 -> root LPE was found.

The only default trigger for the root service is write/connect access to `/run/lxd-installer.socket`, and that socket is `root:lxd` `0660`. The default `lxd` group exists but has no members, and the scoped attacker is not a member. The client shims enforce the same boundary before connecting. The accepted service has no client-controlled command line or environment and only executes a fixed `snap install` command derived from root-owned `/etc/os-release`. Direct snapd install attempts are separately authorization-gated.

The path can install the LXD snap for users already in the `lxd` group, but `lxd` group membership is itself a privileged configuration choice and is explicitly outside this target scope. In the stock default state tested here, the normal unprivileged local user cannot reach that root transition.

## Cleanup

No persistent target changes were made by this audit. The attempted attacker commands did not activate `lxd-installer@.service`, did not install the LXD snap, and left `Accepted: 0` on `lxd-installer.socket`.

## Why generic scanners may miss this boundary

This is a negative trust-boundary result rather than a bug. A scanner may flag an enabled root socket-activated service that runs `snap install` and an unqualified `snap` command under a PATH containing `/usr/local/sbin` and `/usr/local/bin`. Manual reachability testing shows the decisive constraints: the socket is not writable/connectable by uid1001, `lxd` group is empty/default-unjoined, systemd environment mutation is denied, and every PATH element before the real snap binary is root-owned and not attacker-writable.

## Suggested hardening notes

No Ubuntu Security triage issue is recommended from this evidence. Defense-in-depth options would be to call `/usr/bin/snap` by absolute path in `/usr/share/lxd-installer/lxd-installer-service`, add explicit service hardening such as `NoNewPrivileges=yes` where compatible, and document that `lxd` group membership can trigger root-mediated LXD snap installation and should be treated as privileged.
