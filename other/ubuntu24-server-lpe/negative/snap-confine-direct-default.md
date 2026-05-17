# snap-confine direct execution default-state audit

Target: `ubuntu24-server-lpe-target`

Verdict: negative. I did not find a uid1001-to-root escalation through direct `snap-confine` or `snap-update-ns` execution on the stock Ubuntu 24.04 Server Docker target.

The exposed privileged entry is `/usr/lib/snapd/snap-confine`: it is not setuid, but it has permitted file capabilities and can raise effective capabilities after direct execution by uid1001. The default install has no snaps installed, including no `core` base snap. Direct attacker-controlled invocations consistently stop before executing the attacker payload because `snap-confine` resolves the mount dir as `/snap` and then fails at `cannot locate base snap core: No such file or directory`. `SNAP_MOUNT_DIR`, fake `/tmp` snap trees, fake `PATH` `snap-update-ns`, `LD_PRELOAD`, `SNAP_COOKIE`, `SNAP_CONTEXT`, and malformed/traversal security tags did not reach payload execution.

`snap-update-ns` is not file-capability enabled and uid1001 direct execution fails immediately on missing effective `CAP_SYS_ADMIN`. The only root-owned file write observed from `snap-confine` was the expected sanitized lock file `/run/snapd/lock/fakesnap.lock`, mode `0600`, under a root-owned directory; traversal attempts did not redirect it. Test-created `/tmp` state and lock files were cleaned up.

## Default package, capabilities, snaps, sockets

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc '
id
cat /etc/os-release | sed -n "1,6p"
dpkg-query -W snapd
snap version
ls -l /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns
stat -c "%n %U:%G %a %A %u:%g %s" /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns
getcap -v /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns
snap list --all 2>&1 || true
ls -l /run/snapd.socket /run/snapd-snap.socket
systemctl is-active snapd.socket snapd.seeded.service snapd.service 2>&1 || true
ss -xlpn 2>/dev/null | grep -E "/run/snapd(\-snap)?\.socket" || true
getent passwd 1001
runuser -u attacker -- curl --silent --show-error --unix-socket /run/snapd.socket http://localhost/v2/system-info | head -c 240; echo
'
```

Result:

```text
uid=0(root) gid=0(root) groups=0(root)
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
snapd	2.74.1+ubuntu24.04.4
snap          2.74.1+ubuntu24.04.4
snapd         2.74.1+ubuntu24.04.4
series        16
ubuntu        24.04
kernel        6.10.14-linuxkit
architecture  arm64
-rwxr-xr-x 1 root root  199752 Apr  2 06:44 /usr/lib/snapd/snap-confine
-rwxr-xr-x 1 root root 5653152 Apr  2 06:44 /usr/lib/snapd/snap-update-ns
/usr/lib/snapd/snap-confine root:root 755 -rwxr-xr-x 0:0 199752
/usr/lib/snapd/snap-update-ns root:root 755 -rwxr-xr-x 0:0 5653152
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
/usr/lib/snapd/snap-update-ns
No snaps are installed yet. Try 'snap install hello-world'.
srw-rw-rw- 1 root root 0 May 16 10:23 /run/snapd-snap.socket
srw-rw-rw- 1 root root 0 May 16 10:23 /run/snapd.socket
active
active
active
u_str LISTEN 0      4096                                 /run/snapd.socket 11239625            * 0    users:(("snapd",pid=85635,fd=9),("systemd",pid=1,fd=114))
u_str LISTEN 0      4096                            /run/snapd-snap.socket 11239627            * 0    users:(("snapd",pid=85635,fd=10),("systemd",pid=1,fd=120))
attacker:x:1001:1001::/home/attacker:/bin/bash
{"type":"sync","status-code":200,"status":"OK","result":{"architecture":"arm64","build-id":"13476c98a1eccfcc83435dda3ccbd6db1b4f65be","confinement":"partial","features":{"apparmor-prompting":{"supported":false,"unsupported-reason":"cannot c
```

## Attacker writable snap state

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc '
runuser -u attacker -- sh -c '"'"'
for d in /snap /var/lib/snapd /var/lib/snapd/snaps /var/lib/snapd/ns /run/snapd /run/snapd/ns /tmp /var/tmp; do
  test -w "$d"; echo "test-w:$d:$?"
  touch "$d/sc_uid1001_probe" 2>&1; echo "touch:$d:$?"
  rm -f "$d/sc_uid1001_probe" 2>/dev/null || true
done
'"'"'
ls -ld /var/lib/snapd/ns /run/snapd/ns 2>&1 || true
'
```

Result:

```text
test-w:/snap:1
touch: cannot touch '/snap/sc_uid1001_probe': Permission denied
touch:/snap:1
test-w:/var/lib/snapd:1
touch: cannot touch '/var/lib/snapd/sc_uid1001_probe': Permission denied
touch:/var/lib/snapd:1
test-w:/var/lib/snapd/snaps:1
touch: cannot touch '/var/lib/snapd/snaps/sc_uid1001_probe': Permission denied
touch:/var/lib/snapd/snaps:1
test-w:/var/lib/snapd/ns:1
touch: cannot touch '/var/lib/snapd/ns/sc_uid1001_probe': No such file or directory
touch:/var/lib/snapd/ns:1
test-w:/run/snapd:1
touch: cannot touch '/run/snapd/sc_uid1001_probe': Permission denied
touch:/run/snapd:1
test-w:/run/snapd/ns:1
touch: cannot touch '/run/snapd/ns/sc_uid1001_probe': Permission denied
touch:/run/snapd/ns:1
test-w:/tmp:0
touch:/tmp:0
test-w:/var/tmp:0
touch:/var/tmp:0
ls: cannot access '/var/lib/snapd/ns': No such file or directory
drwxr-xr-x 2 root root 40 May 16 10:33 /run/snapd/ns
```

## Direct execution probes

The payload was an attacker-owned executable under `/tmp/sc-direct-audit/payload.sh` that would write `PAYLOAD_RAN`, `id`, and a `/bin/sh -p` id proof into `/tmp/sc-direct-audit` if executed.

Representative results:

```text
===== snap_confine_no_env =====
SNAP_INSTANCE_NAME is not set
rc=1
payload.out:MISSING
sh_p_id.out:MISSING

===== snap_confine_full_fake_env =====
cannot locate base snap core: No such file or directory
rc=1
payload.out:MISSING
sh_p_id.out:MISSING

===== snap_confine_debug_mount_dir_and_update_ns_path =====
DEBUG: SNAP_MOUNT_DIR (probed): /snap
DEBUG: security tag: snap.fakesnap.app
DEBUG: executable:   /tmp/sc-direct-audit/payload.sh
DEBUG: base snap:    core
DEBUG: opened snap-update-ns executable as file descriptor 5
DEBUG: opened snap-discard-ns executable as file descriptor 6
cannot locate base snap core: No such file or directory
fake-update-ns.out:MISSING
payload.out:MISSING

===== env_instance_traversal =====
snap name must use lower case letters, digits or dashes
rc=1
payload.out:MISSING
sh_p_id.out:MISSING

===== env_revision_traversal =====
cannot locate base snap core: No such file or directory
rc=1
payload.out:MISSING
sh_p_id.out:MISSING

===== env_component_traversal =====
snap component must contain a +
rc=1
payload.out:MISSING
sh_p_id.out:MISSING

===== malformed_security_tag_empty =====
security tag snap..app not allowed
rc=1
payload.out:MISSING
sh_p_id.out:MISSING

===== malformed_security_tag_slash =====
security tag snap.fakesnap/../../tmp/sc-direct-audit/trav-owner.app not allowed
rc=1
payload.out:MISSING
sh_p_id.out:MISSING

===== cookie_context_traversal =====
cannot locate base snap core: No such file or directory
rc=1
payload.out:MISSING
sh_p_id.out:MISSING

===== ld_preload =====
cannot locate base snap core: No such file or directory
rc=1
payload.out:MISSING
sh_p_id.out:MISSING

===== snap_update_ns_direct_uid1001 =====
cannot update snap namespace: CAP_SYS_ADMIN capability not in effective set: operation not permitted
rc=1
```

Notes from these probes:

- `SNAP_MOUNT_DIR=/tmp/sc-direct-audit/fake-mount` was ignored; debug still reported `SNAP_MOUNT_DIR (probed): /snap`.
- A fake attacker-controlled `PATH=/tmp/sc-direct-audit/pathbin:/usr/bin:/bin` containing `snap-update-ns` was not used; `snap-confine` opened the real helper by file descriptor and `fake-update-ns.out` stayed missing.
- `/tmp/snap-private-tmp` as an attacker-owned symlink and `/tmp/snap.rootfs_ATTACK` as an attacker-owned directory were not modified before the missing `core` base snap failure.
- `SNAP_INSTANCE_NAME` traversal was rejected. `SNAP_REVISION`, `SNAP_COOKIE`, and `SNAP_CONTEXT` traversal strings did not redirect writes or reach payload execution.

## Side effects and cleanup

Pre-cleanup state:

```text
-rwxr-xr-x attacker:attacker /tmp/sc-direct-audit/pathbin/snap-update-ns ->
-rwxr-xr-x attacker:attacker /tmp/sc-direct-audit/payload.sh ->
drwxr-xr-x attacker:attacker /tmp/sc-direct-audit ->
drwxr-xr-x attacker:attacker /tmp/sc-direct-audit/common ->
drwxr-xr-x attacker:attacker /tmp/sc-direct-audit/data ->
drwxr-xr-x attacker:attacker /tmp/sc-direct-audit/fake-mount ->
drwxr-xr-x attacker:attacker /tmp/sc-direct-audit/fake-mount/fakesnap ->
drwxr-xr-x attacker:attacker /tmp/sc-direct-audit/pathbin ->
drwxr-xr-x attacker:attacker /tmp/sc-direct-audit/private-target ->
drwxr-xr-x attacker:attacker /tmp/snap.rootfs_ATTACK ->
lrwxrwxrwx attacker:attacker /tmp/snap-private-tmp -> /tmp/sc-direct-audit/private-target
-rw------- root:root /run/snapd/lock/.lock 0
-rw------- root:root /run/snapd/lock/fakesnap.lock 0
drwxr-xr-x root:root /run/snapd/lock 80
drwxr-xr-x root:root /run/snapd/ns 40
```

Cleanup command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'rm -rf /tmp/sc-direct-audit /tmp/snap-private-tmp /tmp/snap.rootfs_ATTACK; rm -f /run/snapd/lock/fakesnap.lock; find /tmp -maxdepth 1 \( -name "sc-direct-audit" -o -name "snap-private-tmp" -o -name "snap.rootfs_*" \) -printf "%M %u:%g %p -> %l\n" | sort; find /run/snapd/lock -maxdepth 1 -printf "%M %u:%g %p %s\n" | sort'
```

Cleanup result:

```text
-rw------- root:root /run/snapd/lock/.lock 0
drwxr-xr-x root:root /run/snapd/lock 60
```
