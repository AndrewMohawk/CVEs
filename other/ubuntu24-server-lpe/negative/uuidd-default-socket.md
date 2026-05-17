# uuidd default world socket negative

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, stock Ubuntu Server 24.04.4. Users tested: `attacker` uid 1001 with only group `attacker`, and `selfauth` uid 1002 with only group `selfauth`.

## Result

No root LPE or privileged account/group transition was validated. The default `/run/uuidd/request` socket is intentionally world-connectable, and a normal user can trigger socket activation and request UUID generation. The activated daemon runs as `uuidd:uuidd` (`101:102`) under systemd sandboxing, writes only its own `/var/lib/libuuid/clock.txt` state, and does not expose a user-controlled path, credential change, helper execution, or file write primitive.

## Default package and socket proof

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'cat /etc/os-release | sed -n "1,8p"; dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" uuid-runtime util-linux libuuid1'
```

Observed output:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
libuuid1:arm64	2.39.3-9ubuntu6.5	ii 
util-linux	2.39.3-9ubuntu6.5	ii 
uuid-runtime	2.39.3-9ubuntu6.5	ii 
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'systemctl status uuidd.socket uuidd.service --no-pager || true; systemctl is-enabled uuidd.socket uuidd.service || true'
```

Observed output:

```text
● uuidd.socket - UUID daemon activation socket
     Loaded: loaded (/usr/lib/systemd/system/uuidd.socket; enabled; preset: enabled)
     Active: active (listening) since Sat 2026-05-16 15:18:51 UTC; 7min ago
   Triggers: ● uuidd.service
     Listen: /run/uuidd/request (Stream)
     CGroup: /docker/4f5b414436aefb655c3e4b9b25b80c8483306cde6cc3186d655231e3631e5f6a/system.slice/uuidd.socket

May 16 15:18:51 4f5b414436ae systemd[1]: Listening on uuidd.socket - UUID daemon activation socket.

○ uuidd.service - Daemon for generating UUIDs
     Loaded: loaded (/usr/lib/systemd/system/uuidd.service; indirect; preset: enabled)
     Active: inactive (dead)
TriggeredBy: ● uuidd.socket
       Docs: man:uuidd(8)
enabled
indirect
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'stat -Lc "%F %a %u:%g %U:%G %n" /run/uuidd /run/uuidd/request /var/lib/libuuid 2>&1 || true'
```

Observed output:

```text
directory 755 0:0 root:root /run/uuidd
socket 666 0:0 root:root /run/uuidd/request
directory 2775 101:102 uuidd:uuidd /var/lib/libuuid
```

Relevant default unit settings:

```text
ExecStart=/usr/sbin/uuidd --socket-activation
Restart=no
User=uuidd
Group=uuidd
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
PrivateUsers=yes
ReadWritePaths=/var/lib/libuuid/
SystemCallFilter=@default @file-system @basic-io @system-service @signal @io-event @network-io
```

## Unprivileged reachability

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'runuser -u attacker -- id; runuser -u attacker -- /usr/sbin/uuidd --time --uuids 3; runuser -u attacker -- /usr/sbin/uuidd --random --uuids 3'
```

Observed output:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
a54b9824-513b-11f1-bc29-329de39b8406 and 2 subsequent UUIDs
List of UUIDs:
	89cc6e9d-44a6-4383-9dee-0da1a1950242
	8cd4b17a-2d14-4696-9335-68c223da34ac
	0a33289a-9bf2-40cf-87a4-e93bd498599b
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'runuser -u selfauth -- /usr/sbin/uuidd --time --uuids 1; runuser -u selfauth -- /usr/sbin/uuidd --random --uuids 1; runuser -u selfauth -- id'
```

Observed output:

```text
d042a5e0-513b-11f1-bc29-329de39b8406 and 0 subsequent UUIDs
List of UUIDs:
	c9e09d97-6f25-4b99-8abe-6abccf91f78d
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

After activation:

```text
uuidd                  101    1243       1 uuidd           /usr/sbin/uuidd --socket-activation
directory 2775 101:102 uuidd:uuidd /var/lib/libuuid
regular file 660 101:102 uuidd:uuidd /var/lib/libuuid/clock.txt
```

## Symlink, hardlink, race, and credential boundary

The socket path is replace-resistant for the tested local user because `/run/uuidd` is `0755 root:root`. The socket itself is `0666`, so `test -w` succeeds on the socket inode, but the user cannot unlink or replace it from the parent directory.

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'for p in /run/uuidd /run/uuidd/request /var/lib/libuuid /var/lib/libuuid/clock.txt; do echo "-- $p --"; runuser -u attacker -- test -r "$p"; echo read_rc=$?; runuser -u attacker -- test -w "$p"; echo write_rc=$?; done'
```

Observed output:

```text
-- /run/uuidd --
read_rc=0
write_rc=1
-- /run/uuidd/request --
read_rc=0
write_rc=0
-- /var/lib/libuuid --
read_rc=0
write_rc=1
-- /var/lib/libuuid/clock.txt --
read_rc=1
write_rc=1
```

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'runuser -u attacker -- bash -lc "touch /var/lib/libuuid/attacker-write-test 2>&1"; echo varlib_touch_rc=$?; rm -f /var/lib/libuuid/attacker-write-test; runuser -u attacker -- bash -lc "ln -s /etc/shadow /var/lib/libuuid/attacker-link-test 2>&1"; echo varlib_symlink_rc=$?; rm -f /var/lib/libuuid/attacker-link-test; runuser -u attacker -- bash -lc "rm -f /run/uuidd/request 2>&1"; echo run_socket_unlink_rc=$?'
```

Observed output:

```text
touch: cannot touch '/var/lib/libuuid/attacker-write-test': Permission denied
varlib_touch_rc=1
ln: failed to create symbolic link '/var/lib/libuuid/attacker-link-test': Permission denied
varlib_symlink_rc=1
rm: cannot remove '/run/uuidd/request': Permission denied
run_socket_unlink_rc=1
```

Peer identity does not become a privilege boundary in the default path: both `attacker` and `selfauth` can connect and receive UUIDs, but the only daemon action observed is UUID generation plus `clock.txt` maintenance as `uuidd`. A malformed request from `attacker` was reset without killing or re-uiding the service:

```text
recv_error=ConnectionResetError:[Errno 104] Connection reset by peer
malformed_rc=0
active
active
uuidd                  101    1243       1 uuidd           /usr/sbin/uuidd --socket-activation
```

## Why this is negative

The world-writable-looking socket is not a root write primitive. It is a systemd-created UNIX stream socket in a root-owned runtime directory, and socket activation hands the accepted connection to `/usr/sbin/uuidd --socket-activation` after systemd has already applied `User=uuidd` and `Group=uuidd`. The daemon's persistent state directory is group-setgid `uuidd:uuidd`, but neither default test user is in that group and direct creation of files or symlinks there failed. The daemon only updates `/var/lib/libuuid/clock.txt` as `uuidd:uuidd` mode `0660`.

Scanners may over-rank this because `/run/uuidd/request` is `srw-rw-rw-` and can be reached by any local user, and because socket activation starts a privileged-looking system service. The exploitable boundary is narrower: the default operation set returns UUID values and maintains daemon-owned clock state, with no attacker-controlled filename, helper command, root-owned output path, or privileged group membership change observed.

## Cleanup

No Docker restart, package install, service restart, or destructive Docker operation was used. The only mutation attempts used the fixed names `/var/lib/libuuid/attacker-write-test` and `/var/lib/libuuid/attacker-link-test`; both failed as `attacker`, and root cleanup `rm -f` was run for those names. The malformed socket request left `uuidd.service` and `uuidd.socket` active.
