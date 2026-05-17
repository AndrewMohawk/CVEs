# kernel/default sysctls/namespaces negative

Date: 2026-05-16

Status: no uid 1001 to root LPE was validated in this slice.

Scope: stock Ubuntu 24.04 Server default userspace from the `ubuntu24-server-lpe-target` container, starting as `attacker` uid/gid 1001 with no sudo or extra groups. This pass covered unprivileged user namespaces, AppArmor unprivileged-userns policy, unprivileged BPF, io_uring, overlayfs/FUSE/fusermount3, keyrings, perf_event, ptrace/Yama, protected symlink/hardlink/fifo/regular sysctls, and file-capability behavior inside user namespaces.

Important target caveat: the live target is Ubuntu 24.04.4 userspace on a Docker/LinuxKit host kernel, not a stock Ubuntu kernel boot. Kernel behavior below is useful reachability evidence, but it cannot prove or disprove a real stock-Ubuntu-kernel-only LPE. The container also has AppArmor disabled at the host kernel/security layer, so Ubuntu's AppArmor userns mediation is visible in userspace config but not enforceable in this target.

## Target proof

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'printf "== release ==\n"; cat /etc/os-release; uname -a; printf "== id/groups ==\n"; id attacker; getent group attacker sudo adm video input sgx'
```

Result:

```text
== release ==
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
== id/groups ==
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
attacker:x:1001:
sudo:x:27:ubuntu
adm:x:4:ubuntu,syslog
video:x:44:ubuntu
input:x:995:
sgx:x:994:
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'printf "== kernel packages ==\n"; dpkg-query -W "linux-image*" "linux-modules*" "linux-generic*" "linux-virtual*" 2>&1 | sort || true; printf "== running kernel files ==\n"; ls -l /boot /lib/modules 2>&1 || true'
```

Result:

```text
== kernel packages ==
dpkg-query: no packages found matching linux-generic*
dpkg-query: no packages found matching linux-image*
dpkg-query: no packages found matching linux-modules*
dpkg-query: no packages found matching linux-virtual*
== running kernel files ==
/boot:
total 0

/lib/modules:
total 0
```

## Default sysctl/config state

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'for k in kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns kernel.apparmor_restrict_unprivileged_unconfined kernel.apparmor_restrict_unprivileged_io_uring kernel.apparmor_restrict_unprivileged_userns_complain kernel.unprivileged_bpf_disabled kernel.io_uring_disabled kernel.io_uring_group kernel.perf_event_paranoid kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular user.max_user_namespaces user.max_mnt_namespaces user.max_pid_namespaces user.max_net_namespaces; do sysctl "$k" 2>&1; done'
```

Result:

```text
sysctl: cannot stat /proc/sys/kernel/unprivileged_userns_clone: No such file or directory
sysctl: cannot stat /proc/sys/kernel/apparmor_restrict_unprivileged_userns: No such file or directory
sysctl: cannot stat /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined: No such file or directory
sysctl: cannot stat /proc/sys/kernel/apparmor_restrict_unprivileged_io_uring: No such file or directory
sysctl: cannot stat /proc/sys/kernel/apparmor_restrict_unprivileged_userns_complain: No such file or directory
kernel.unprivileged_bpf_disabled = 0
kernel.io_uring_disabled = 0
kernel.io_uring_group = -1
kernel.perf_event_paranoid = 2
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
sysctl: cannot stat /proc/sys/kernel/yama/ptrace_scope: No such file or directory
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 2
user.max_user_namespaces = 31723
user.max_mnt_namespaces = 31723
user.max_pid_namespaces = 31723
user.max_net_namespaces = 31723
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'grep -RInE "unprivileged|apparmor|bpf|io_uring|perf_event|ptrace|protected_|max_user_namespaces|yama|kptr|dmesg" /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d 2>/dev/null || true'
```

Result:

```text
/etc/sysctl.d/10-kernel-hardening.conf:15:kernel.kptr_restrict = 1
/etc/sysctl.d/10-kernel-hardening.conf:20:# dmesg_restrict to "0" allows all users to view the kernel log buffer,
/etc/sysctl.d/10-kernel-hardening.conf:23:# dmesg_restrict defaults to 1 via CONFIG_SECURITY_DMESG_RESTRICT, only
/etc/sysctl.d/10-kernel-hardening.conf:25:# kernel.dmesg_restrict = 0
/etc/sysctl.d/10-ptrace.conf:12:# https://wiki.ubuntu.com/SecurityTeam/Roadmap/KernelHardening#ptrace
/etc/sysctl.d/10-ptrace.conf:22:kernel.yama.ptrace_scope = 1
/usr/lib/sysctl.d/99-protect-links.conf:7:fs.protected_fifos = 1
/usr/lib/sysctl.d/99-protect-links.conf:8:fs.protected_hardlinks = 1
/usr/lib/sysctl.d/99-protect-links.conf:9:fs.protected_regular = 2
/usr/lib/sysctl.d/99-protect-links.conf:10:fs.protected_symlinks = 1
/usr/lib/sysctl.d/10-apparmor.conf:1:# AppArmor restrictions of unprivileged user namespaces
/usr/lib/sysctl.d/10-apparmor.conf:3:# Allows to restrict the use of unprivileged user namespaces to applications
/usr/lib/sysctl.d/10-apparmor.conf:6:# be denied the use of unprivileged user namespaces.
/usr/lib/sysctl.d/10-apparmor.conf:9:# https://gitlab.com/apparmor/apparmor/-/wikis/unprivileged_userns_restriction
/usr/lib/sysctl.d/10-apparmor.conf:12:# additional file named /etc/sysctl.d/20-apparmor.conf which will override this
/usr/lib/sysctl.d/10-apparmor.conf:14:kernel.apparmor_restrict_unprivileged_userns = 1
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'dpkg -S /usr/lib/sysctl.d/10-apparmor.conf /etc/apparmor.d/unprivileged_userns 2>/dev/null || true; systemctl is-enabled apparmor 2>&1 || true; systemctl is-active apparmor 2>&1 || true; systemctl status apparmor --no-pager --lines=8 2>&1 || true'
```

Result:

```text
apparmor: /usr/lib/sysctl.d/10-apparmor.conf
apparmor: /etc/apparmor.d/unprivileged_userns
enabled
inactive
○ apparmor.service - Load AppArmor profiles
     Loaded: loaded (/usr/lib/systemd/system/apparmor.service; enabled; preset: enabled)
     Active: inactive (dead)
  Condition: start condition unmet at Sat 2026-05-16 10:23:54 UTC; 22min ago
             └─ ConditionSecurity=apparmor was not met
       Docs: man:apparmor(7)
             https://gitlab.com/apparmor/apparmor/wikis/home/

May 16 10:23:54 fd448ecbc136 systemd[1]: apparmor.service - Load AppArmor profiles was skipped because of an unmet condition check (ConditionSecurity=apparmor).
```

Ubuntu userspace ships the AppArmor unprivileged-userns restriction and profile. It could not be exercised in this container because the host kernel does not provide AppArmor security mediation.

## Namespace and mount probes

Command:

```sh
docker exec -i ubuntu24-server-lpe-target runuser -u attacker -- bash -s <<'ATTACKER'
set -u
base=/home/attacker/kernel-probe
rm -rf "$base" /tmp/kernel-probe-hardlink /tmp/kernel-probe-fifo /tmp/kernel-probe-symlink
mkdir -p "$base"
id
unshare --user --map-root-user sh -c 'id; printf uid_map=; cat /proc/self/uid_map; printf gid_map=; cat /proc/self/gid_map'
mkdir -p "$base/lower" "$base/upper" "$base/work" "$base/merged"
printf lower > "$base/lower/file"
unshare --user --map-root-user --mount sh -c "mount -t overlay overlay -o lowerdir=$base/lower,upperdir=$base/upper,workdir=$base/work $base/merged"
rm -rf "$base"
ATTACKER
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=0(root) gid=0(root) groups=0(root)
uid_map=         0       1001          1
gid_map=         0       1001          1
mount: /home/attacker/kernel-probe/merged: wrong fs type, bad option, bad superblock on overlay, missing codepage or helper program, or other error.
       dmesg(1) may have more information after failed mount system call.
```

Command:

```sh
docker exec -i ubuntu24-server-lpe-target runuser -u attacker -- bash -s <<'ATTACKER'
set -u
base=/home/attacker/kernel-probe2
rm -rf "$base"
mkdir -p "$base"
printf '== mqueue/ipc/pid/net namespace reachability ==\n'
for opts in '--ipc' '--pid --fork' '--net' '--uts'; do
  if unshare --user --map-root-user $opts sh -c 'id -u; true' 2>"$base/err"; then printf 'unshare %s: ok\n' "$opts"; else printf 'unshare %s: rc=%s err=%s\n' "$opts" "$?" "$(cat "$base/err")"; fi
done
printf '== userns tmpfs mount ==\n'
mkdir -p "$base/tmpfs"
if unshare --user --map-root-user --mount sh -c "mount -t tmpfs tmpfs '$base/tmpfs' && printf tmpfs_userns_mounted=ok && umount '$base/tmpfs'" 2>"$base/tmpfs-userns.err"; then printf '\n'; else printf 'tmpfs_userns_rc=%s err=%s\n' "$?" "$(cat "$base/tmpfs-userns.err")"; fi
rm -rf "$base"
ATTACKER
```

Result:

```text
== mqueue/ipc/pid/net namespace reachability ==
0
unshare --ipc: ok
0
unshare --pid --fork: ok
0
unshare --net: ok
0
unshare --uts: ok
== userns tmpfs mount ==
tmpfs_userns_mounted=ok
```

Command:

```sh
docker exec -i ubuntu24-server-lpe-target runuser -u attacker -- bash -s <<'ATTACKER'
set -u
base=/home/attacker/kernel-probe3
rm -rf "$base"
mkdir -p "$base/tmpfs" "$base/bpf" "$base/debugfs" "$base/tracefs"
for fs in tmpfs bpf debugfs tracefs; do
  if mount -t "$fs" "$fs" "$base/$fs" 2>"$base/$fs.err"; then printf 'mount_%s_unexpected_ok\n' "$fs"; umount "$base/$fs" || true; else printf 'mount_%s_rc=%s err=%s\n' "$fs" "$?" "$(cat "$base/$fs.err")"; fi
done
rm -rf "$base"
ATTACKER
```

Result:

```text
mount_tmpfs_rc=32 err=mount: /home/attacker/kernel-probe3/tmpfs: must be superuser to use mount.
       dmesg(1) may have more information after failed mount system call.
mount_bpf_rc=32 err=mount: /home/attacker/kernel-probe3/bpf: must be superuser to use mount.
       dmesg(1) may have more information after failed mount system call.
mount_debugfs_rc=32 err=mount: /home/attacker/kernel-probe3/debugfs: must be superuser to use mount.
       dmesg(1) may have more information after failed mount system call.
mount_tracefs_rc=32 err=mount: /home/attacker/kernel-probe3/tracefs: must be superuser to use mount.
       dmesg(1) may have more information after failed mount system call.
```

Interpretation: unprivileged user namespaces are reachable in this LinuxKit-backed container and namespace-root can create several child namespaces and mount tmpfs inside its own mount namespace. Direct host namespace mounts are denied. Overlayfs failed in the unprivileged user+mount namespace on this kernel. No host-root transition resulted.

## Namespaced file capabilities

Command:

```sh
docker exec -i ubuntu24-server-lpe-target runuser -u attacker -- bash -s <<'ATTACKER'
set -u
base=/home/attacker/kernel-probe
rm -rf "$base"
mkdir -p "$base"
cp /bin/sh "$base/ns-cap-sh"
unshare --user --map-root-user sh -c "/usr/sbin/setcap cap_setuid,cap_setgid+ep '$base/ns-cap-sh' && /usr/sbin/getcap -n '$base/ns-cap-sh' && '$base/ns-cap-sh' -c 'grep CapEff /proc/self/status; id'"
/usr/sbin/getcap -n "$base/ns-cap-sh" || true
"$base/ns-cap-sh" -c 'grep CapEff /proc/self/status; id' || true
rm -rf "$base"
ATTACKER
```

Result:

```text
/home/attacker/kernel-probe/ns-cap-sh cap_setgid,cap_setuid=ep
CapEff:	000001ffffffffff
uid=0(root) gid=0(root) groups=0(root)
/home/attacker/kernel-probe/ns-cap-sh cap_setgid,cap_setuid=ep [rootid=1001]
CapEff:	0000000000000000
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Interpretation: namespace-root can create a namespaced file capability, but outside that namespace it is tagged with `rootid=1001` and does not grant initial-namespace capabilities to uid 1001. This did not become host root.

## BPF, io_uring, perf_event, keyrings, ptrace

Command:

```sh
docker exec -i ubuntu24-server-lpe-target runuser -u attacker -- python3 - <<'PY'
import ctypes, errno, os, platform, struct
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
machine = platform.machine()
nums_by_arch = {
    'aarch64': {'bpf': 280, 'io_uring_setup': 425, 'perf_event_open': 241, 'add_key': 217, 'keyctl': 219},
    'x86_64': {'bpf': 321, 'io_uring_setup': 425, 'perf_event_open': 298, 'add_key': 248, 'keyctl': 250},
}
nums = nums_by_arch[machine]
print(f'== raw syscall probes arch={machine} ==')
def call(num, *args):
    ctypes.set_errno(0)
    rc = libc.syscall(ctypes.c_long(num), *args)
    return rc, ctypes.get_errno()
def show(name, rc, err):
    print(f'{name}: rc={rc} ok' if rc >= 0 else f'{name}: rc={rc} errno={err} {errno.errorcode.get(err, "?")}')
attr = bytearray(128)
struct.pack_into('=IIII', attr, 0, 2, 4, 8, 1)
buf = ctypes.create_string_buffer(bytes(attr), len(attr))
rc, err = call(nums['bpf'], ctypes.c_long(0), ctypes.c_void_p(ctypes.addressof(buf)), ctypes.c_uint(len(attr)))
show('bpf_map_create_array', rc, err)
if rc >= 0: os.close(rc)
params = ctypes.create_string_buffer(256)
rc, err = call(nums['io_uring_setup'], ctypes.c_uint(2), ctypes.c_void_p(ctypes.addressof(params)))
show('io_uring_setup_entries2', rc, err)
if rc >= 0: os.close(rc)
attr = bytearray(128)
flags = (1 << 0) | (1 << 5) | (1 << 6)
struct.pack_into('=IIQQQQQ', attr, 0, 1, 128, 0, 0, 0, 0, flags)
pattr = ctypes.create_string_buffer(bytes(attr), len(attr))
rc, err = call(nums['perf_event_open'], ctypes.c_void_p(ctypes.addressof(pattr)), ctypes.c_int(0), ctypes.c_int(-1), ctypes.c_int(-1), ctypes.c_ulong(0))
show('perf_event_open_self_user_cpu_clock', rc, err)
if rc >= 0: os.close(rc)
rc, err = call(nums['perf_event_open'], ctypes.c_void_p(ctypes.addressof(pattr)), ctypes.c_int(-1), ctypes.c_int(0), ctypes.c_int(-1), ctypes.c_ulong(0))
show('perf_event_open_system_cpu0', rc, err)
if rc >= 0: os.close(rc)
key_type = ctypes.create_string_buffer(b'user')
key_desc = ctypes.create_string_buffer(b'kernel-probe')
payload = ctypes.create_string_buffer(b'probe')
rc, err = call(nums['add_key'], ctypes.c_void_p(ctypes.addressof(key_type)), ctypes.c_void_p(ctypes.addressof(key_desc)), ctypes.c_void_p(ctypes.addressof(payload)), ctypes.c_size_t(5), ctypes.c_int(-2))
show('add_key_user_process_keyring', rc, err)
if rc >= 0:
    rc2, err2 = call(nums['keyctl'], ctypes.c_int(9), ctypes.c_long(rc), ctypes.c_int(-2), ctypes.c_ulong(0), ctypes.c_ulong(0))
    show('keyctl_unlink_probe_key', rc2, err2)
PTRACE_ATTACH = 16
ctypes.set_errno(0)
prc = libc.ptrace(ctypes.c_uint(PTRACE_ATTACH), ctypes.c_uint(1), ctypes.c_void_p(0), ctypes.c_void_p(0))
show('ptrace_attach_pid1', prc, ctypes.get_errno())
PY
```

Result:

```text
== raw syscall probes arch=aarch64 ==
bpf_map_create_array: rc=3 ok
io_uring_setup_entries2: rc=3 ok
perf_event_open_self_user_cpu_clock: rc=3 ok
perf_event_open_system_cpu0: rc=-1 errno=13 EACCES
add_key_user_process_keyring: rc=178718297 ok
keyctl_unlink_probe_key: rc=0 ok
ptrace_attach_pid1: rc=-1 errno=1 EPERM
```

Command:

```sh
docker exec -i ubuntu24-server-lpe-target runuser -u attacker -- python3 - <<'PY'
import ctypes, errno, os, platform, struct
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
arch = platform.machine()
nums = {'aarch64': 280, 'x86_64': 321}[arch]
print(f'== bpf program load probe arch={arch} ==')
def call(*args):
    ctypes.set_errno(0)
    rc = libc.syscall(ctypes.c_long(nums), *args)
    return rc, ctypes.get_errno()
def show(name, rc, err):
    print(f'{name}: rc={rc} ok' if rc >= 0 else f'{name}: rc={rc} errno={err} {errno.errorcode.get(err, "?")}')
insns = bytearray(16)
struct.pack_into('<BBhI', insns, 0, 0xb7, 0x00, 0, 0)
struct.pack_into('<BBhI', insns, 8, 0x95, 0x00, 0, 0)
insn_buf = ctypes.create_string_buffer(bytes(insns), len(insns))
lic = ctypes.create_string_buffer(b'GPL\0')
attr = bytearray(160)
struct.pack_into('=IIQQIIQI', attr, 0, 1, 2, ctypes.addressof(insn_buf), ctypes.addressof(lic), 0, 0, 0, 0)
attr_buf = ctypes.create_string_buffer(bytes(attr), len(attr))
rc, err = call(ctypes.c_long(5), ctypes.c_void_p(ctypes.addressof(attr_buf)), ctypes.c_uint(len(attr)))
show('bpf_prog_load_socket_filter_ret0', rc, err)
if rc >= 0: os.close(rc)
PY
```

Result:

```text
== bpf program load probe arch=aarch64 ==
bpf_prog_load_socket_filter_ret0: rc=3 ok
```

Interpretation: in this LinuxKit kernel, uid 1001 can create BPF maps, load a trivial socket-filter BPF program, create io_uring rings, create/unlink its own process key, and open a self user-space perf event. System-wide perf is blocked, and ptrace of root pid 1 is blocked. These are reachable attack surfaces, but no privilege-crossing primitive was validated.

## FUSE/fusermount3 and helpers

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'find /usr/bin /usr/sbin /bin /sbin -maxdepth 1 \( -iname "*fuse*" -o -iname "*overlay*" \) -ls 2>/dev/null | sort -k 11; find /usr/sbin /usr/bin -maxdepth 1 -name "mount.*" -ls 2>/dev/null | sort -k 11; ls -l /usr/bin/fusermount3 /usr/sbin/mount.fuse3 /etc/fuse.conf; sed -n "1,40p" /etc/fuse.conf'
```

Result:

```text
 19028214     68 -rwxr-xr-x   1 root     root        68696 Mar 31  2024 /usr/bin/fuser
 19017826      0 lrwxrwxrwx   1 root     root           11 Apr  8  2024 /usr/bin/fusermount -> fusermount3
 19017819     68 -rwsr-xr-x   1 root     root        67744 Apr  8  2024 /usr/bin/fusermount3
 19036762     68 -rwxr-xr-x   1 root     root        67760 Apr  2 06:44 /usr/bin/snapfuse
 19022860     68 -rwxr-xr-x   1 root     root        68088 Mar 25 19:34 /usr/bin/vmhgfs-fuse
 19022869     68 -rwxr-xr-x   1 root     root        68128 Mar 25 19:34 /usr/bin/vmware-vmblock-fuse
 19017827      0 lrwxrwxrwx   1 root     root           11 Apr  8  2024 /usr/sbin/mount.fuse -> mount.fuse3
 19017822     68 -rwxr-xr-x   1 root     root        67736 Apr  8  2024 /usr/sbin/mount.fuse3
 19033397      4 -rwxr-xr-x   1 root     root         2510 Jul  3  2024 /usr/sbin/overlayroot-chroot
 19017827      0 lrwxrwxrwx   1 root     root           11 Apr  8  2024 /usr/sbin/mount.fuse -> mount.fuse3
 19017822     68 -rwxr-xr-x   1 root     root        67736 Apr  8  2024 /usr/sbin/mount.fuse3
 19017912      0 lrwxrwxrwx   1 root     root           15 Apr 17 17:52 /usr/sbin/mount.lowntfs-3g -> /bin/lowntfs-3g
 19017913      0 lrwxrwxrwx   1 root     root           13 Apr 17 17:52 /usr/sbin/mount.ntfs -> mount.ntfs-3g
 19017914      0 lrwxrwxrwx   1 root     root           12 Apr 17 17:52 /usr/sbin/mount.ntfs-3g -> /bin/ntfs-3g
-rwsr-xr-x 1 root root 67744 Apr  8  2024 /usr/bin/fusermount3
-rwxr-xr-x 1 root root 67736 Apr  8  2024 /usr/sbin/mount.fuse3
-rw-r--r-- 1 root root   694 Apr  8  2024 /etc/fuse.conf
# The file /etc/fuse.conf allows for the following parameters:
#
# user_allow_other - Using the allow_other mount option works fine as root, in
# order to have it work as user you need user_allow_other in /etc/fuse.conf as
# well. (This option allows users to use the allow_other option.) You need
# allow_other if you want users other than the owner to access a mounted fuse.
# This option must appear on a line by itself. There is no value, just the
# presence of the option.

#user_allow_other
```

Command:

```sh
docker exec -i ubuntu24-server-lpe-target runuser -u attacker -- bash -s <<'ATTACKER'
set -u
base=/home/attacker/kernel-probe
rm -rf "$base"
mkdir -p "$base/fusemnt"
if fusermount3 -o allow_other "$base/fusemnt" 2>"$base/fusermount.err"; then echo fusermount_unexpected_ok; fusermount3 -u "$base/fusemnt" || true; else rc=$?; printf 'fusermount_rc=%s err=%s\n' "$rc" "$(cat "$base/fusermount.err")"; fi
rm -rf "$base"
ATTACKER
```

Result:

```text
fusermount_rc=1 err=fusermount3: old style mounting not supported
```

Interpretation: `fusermount3` is setuid root, but the default `allow_other` gate is disabled and direct old-style invocation did not create a mount. Other FUSE helpers are not setuid/file-cap privileged in this slice. Prior helper testing in `negative/setuid-setgid-helpers.md` also found that `mount.fuse3` executes subtype helpers as uid 1001, not root.

## Protected links/files

Command:

```sh
docker exec -i ubuntu24-server-lpe-target runuser -u attacker -- bash -s <<'ATTACKER'
set -u
base=/home/attacker/kernel-probe
rm -rf "$base" /tmp/kernel-probe-hardlink
mkdir -p "$base"
if ln /etc/shadow /tmp/kernel-probe-hardlink 2>"$base/hardlink.err"; then echo hardlink_shadow_unexpected_ok; else rc=$?; printf 'hardlink_shadow_rc=%s err=%s\n' "$rc" "$(cat "$base/hardlink.err")"; fi
rm -rf "$base" /tmp/kernel-probe-hardlink
ATTACKER
```

Result:

```text
hardlink_shadow_rc=1 err=ln: failed to create hard link '/tmp/kernel-probe-hardlink' => '/etc/shadow': Operation not permitted
```

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'base=/tmp/kernel-protected-probe; rm -rf "$base" /tmp/kernel-protected-symlink /tmp/kernel-protected-regular; mkdir -p "$base"; runuser -u attacker -- sh -lc "ln -s /etc/shadow /tmp/kernel-protected-symlink; printf attacker > /tmp/kernel-protected-regular; ls -ln /tmp/kernel-protected-symlink /tmp/kernel-protected-regular"; if head -c 1 /tmp/kernel-protected-symlink >/dev/null 2>"$base/symlink.err"; then echo root_follow_symlink_ok; else printf "root_follow_symlink_denied=%s\n" "$(cat $base/symlink.err)"; fi; if sh -c ": > /tmp/kernel-protected-regular" 2>"$base/regular.err"; then echo root_truncate_regular_ok; else printf "root_truncate_regular_denied=%s\n" "$(cat $base/regular.err)"; fi; rm -rf "$base" /tmp/kernel-protected-symlink /tmp/kernel-protected-regular'
```

Result:

```text
-rw-r--r-- 1 1001 1001  8 May 16 10:47 /tmp/kernel-protected-regular
lrwxrwxrwx 1 1001 1001 11 May 16 10:47 /tmp/kernel-protected-symlink -> /etc/shadow
root_follow_symlink_denied=head: cannot open '/tmp/kernel-protected-symlink' for reading: Permission denied
root_truncate_regular_denied=sh: 1: cannot create /tmp/kernel-protected-regular: Permission denied
```

Interpretation: hardlink creation to root-owned sensitive files is blocked for uid 1001. The root-opener simulation shows the sticky-directory symlink and regular-file protections are active. These defaults shut down the common temp-file link/truncation pivots in this slice.

## Capability helpers

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'getcap -r / 2>/dev/null | sort'
```

Result:

```text
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
```

No new namespace/capability crossing was validated. The relevant namespace-specific filecap test above stayed namespaced (`rootid=1001`) and did not grant initial-namespace caps. `snap-confine` is already covered separately in `negative/snapd-snap-confine.md`; it remained a real privileged boundary but not a validated default LPE.

## Conclusion

No uid 1001 to root LPE was validated in the kernel/default-sysctl/default-namespace slice.

Confirmed exposed or interesting surfaces:

- User namespaces and child IPC/PID/net/UTS namespaces are reachable in the container host kernel.
- Namespace-root can mount tmpfs inside its own mount namespace.
- BPF map creation and trivial socket-filter BPF program loading are reachable in the LinuxKit host kernel because `kernel.unprivileged_bpf_disabled = 0`.
- `io_uring_setup` is reachable because `kernel.io_uring_disabled = 0`.
- Process keyrings are reachable.
- Self user-space perf events are reachable, while system-wide perf is blocked by `perf_event_paranoid = 2`.
- `fusermount3` is setuid root, but direct old-style invocation failed and `allow_other` is disabled.

Boundaries that held:

- No host-root result from unprivileged namespaces.
- Overlayfs mount failed inside the unprivileged user+mount namespace on this host kernel.
- Namespaced file capabilities did not grant capabilities in the initial namespace.
- Direct pseudo-filesystem mounts (`tmpfs`, `bpf`, `debugfs`, `tracefs`) were denied outside a user namespace.
- Hardlink, symlink, and protected-regular-file guards blocked the tested default temp-file pivots.
- Ptrace attach to root pid 1 was denied.
- System-wide perf was denied.

Recommended VM retest if this slice is revisited: boot a real Ubuntu 24.04 Server VM with the stock Ubuntu kernel and AppArmor enabled, then repeat the same commands. The container target cannot exercise `kernel.apparmor_restrict_unprivileged_userns`, Yama, or Ubuntu kernel patch behavior because it is running LinuxKit `6.10.14-linuxkit` with no Ubuntu kernel packages in the container.

## Cleanup

All probe paths used in the target were removed during each command:

```text
/home/attacker/kernel-probe
/home/attacker/kernel-probe2
/home/attacker/kernel-probe3
/tmp/kernel-probe-hardlink
/tmp/kernel-probe-fifo
/tmp/kernel-probe-symlink
/tmp/kernel-protected-probe
/tmp/kernel-protected-symlink
/tmp/kernel-protected-regular
```

Final cleanup check:

Command:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'find /home/attacker /tmp -maxdepth 1 \( -name "kernel-probe*" -o -name "kernel-protected-*" \) -ls 2>/dev/null || true'
```

Result:

```text
```
