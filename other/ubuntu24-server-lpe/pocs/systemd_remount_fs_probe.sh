#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/systemd-remount-fs.out"
tmp_log="$(mktemp "$repo_dir/logs/systemd-remount-fs.out.tmp.XXXXXX")"

docker exec -i "$container" bash <<'TARGET' >"$tmp_log" 2>&1
set +e

section() {
  printf '\n## %s\n' "$1"
}

section "target and package state"
sed -n '1,8p' /etc/os-release
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  systemd mount util-linux 2>&1 | sort

section "unit state and root execution path"
systemctl cat systemd-remount-fs.service 2>&1
systemctl show systemd-remount-fs.service \
  -p Id -p LoadState -p UnitFileState -p ActiveState -p SubState \
  -p ConditionResult -p FragmentPath -p ExecStart -p User -p Group 2>&1
nl -ba /usr/lib/systemd/system/systemd-remount-fs.service 2>&1 | sed -n '1,120p'
stat -Lc '%A %a %U:%G %F %n' \
  /usr/lib/systemd/systemd-remount-fs \
  /etc/fstab \
  /run/systemd/generator \
  /run/systemd/generator/local-fs.target.wants \
  /run/systemd/system \
  /proc/self/mountinfo 2>&1

section "attacker write access to remount inputs"
runuser -u attacker -- bash -lc '
set +e
id
for p in /etc/fstab /run/systemd/generator /run/systemd/generator/local-fs.target.wants /run/systemd/system /proc/self/mountinfo; do
  printf "%s: " "$p"
  test -w "$p" && echo writable || echo not-writable
done
'

section "attacker namespace mount isolation"
rm -rf /tmp/remountfs-userns
runuser -u attacker -- bash -lc '
set +e
id
mkdir -p /tmp/remountfs-userns
unshare -Urmpf bash -lc "
  set +e
  id
  mount -t tmpfs tmpfs /tmp/remountfs-userns 2>&1
  echo ATTACKER_NS_MOUNTINFO
  grep remountfs-userns /proc/self/mountinfo || true
  touch /tmp/remountfs-userns/attacker-ns-file 2>&1 || true
" 2>&1
echo unshare_rc=$?
'
echo PID1_MOUNTINFO
grep remountfs-userns /proc/1/mountinfo || true
echo TARGET_MOUNTINFO
grep remountfs-userns /proc/self/mountinfo || true
stat -Lc '%A %U:%G %F %n' /tmp/remountfs-userns 2>&1 || true
ls -la /tmp/remountfs-userns 2>&1 || true

section "attacker service trigger attempts"
runuser -u attacker -- bash -lc '
set +e
id
systemctl start systemd-remount-fs.service 2>&1
echo systemctl_start_rc=$?
busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager StartUnit ss systemd-remount-fs.service replace 2>&1
echo busctl_start_rc=$?
'

section "root helper debug run"
SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-remount-fs 2>&1 | sed -n '1,200p'

section "post-trigger state and health"
systemctl show systemd-remount-fs.service -p Id -p ActiveState -p SubState -p Result 2>&1
journalctl -b -u systemd-remount-fs.service --no-pager 2>&1 | tail -80
rm -rf /tmp/remountfs-userns
systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend 2>&1 || true
TARGET

mv "$tmp_log" "$log_path"
sed -n '1,360p' "$log_path"
