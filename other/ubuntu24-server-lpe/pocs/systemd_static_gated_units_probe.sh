#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/systemd-static-gated-units.out"
tmp_log="$(mktemp "$repo_dir/logs/systemd-static-gated-units.out.tmp.XXXXXX")"

docker exec -i "$container" bash <<'TARGET' >"$tmp_log" 2>&1
set +e

section() {
  printf '\n## %s\n' "$1"
}

units='
systemd-rfkill.socket
systemd-rfkill.service
systemd-suspend.service
systemd-hibernate.service
systemd-hybrid-sleep.service
systemd-suspend-then-hibernate.service
plymouth-reboot.service
plymouth-poweroff.service
plymouth-halt.service
plymouth-kexec.service
rescue.service
emergency.service
systemd-volatile-root.service
'

section "target and packages"
sed -n '1,8p' /etc/os-release
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  systemd plymouth rfkill 2>&1 | sort

section "default unit state"
for u in $units; do
  echo "### $u"
  systemctl show "$u" \
    -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState \
    -p FragmentPath -p ConditionResult -p AssertResult -p ExecStart \
    -p User -p Group 2>&1
done

section "unit files with line numbers"
for p in \
  /usr/lib/systemd/system/systemd-rfkill.socket \
  /usr/lib/systemd/system/systemd-rfkill.service \
  /usr/lib/systemd/system/systemd-suspend.service \
  /usr/lib/systemd/system/systemd-hibernate.service \
  /usr/lib/systemd/system/systemd-hybrid-sleep.service \
  /usr/lib/systemd/system/systemd-suspend-then-hibernate.service \
  /usr/lib/systemd/system/plymouth-reboot.service \
  /usr/lib/systemd/system/plymouth-poweroff.service \
  /usr/lib/systemd/system/plymouth-halt.service \
  /usr/lib/systemd/system/plymouth-kexec.service \
  /usr/lib/systemd/system/rescue.service \
  /usr/lib/systemd/system/emergency.service \
  /usr/lib/systemd/system/systemd-volatile-root.service; do
  echo "### $p"
  nl -ba "$p" 2>&1 | sed -n '1,120p'
done

section "condition and input path proof"
for p in \
  /dev/rfkill \
  /sys/class/rfkill \
  /sys/power/state \
  /lib/systemd/system-sleep \
  /etc/initrd-release \
  /sysroot \
  /usr/lib/systemd/systemd-rfkill \
  /usr/lib/systemd/systemd-sleep \
  /usr/bin/plymouth \
  /sbin/sulogin; do
  stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>&1 || true
done
for c in \
  'ConditionVirtualization=!container' \
  'ConditionKernelCommandLine=splash' \
  'AssertPathExists=/etc/initrd-release'; do
  echo "### $c"
  systemd-analyze condition "$c" 2>&1 || true
done
echo "### login1 sleep/reboot capability checks"
for m in CanSuspend CanHibernate CanHybridSleep CanSuspendThenHibernate CanReboot CanPowerOff; do
  echo "$m"
  busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
    org.freedesktop.login1.Manager "$m" 2>&1 || true
done

section "attacker trigger attempts"
runuser -u attacker -- bash -lc '
set +e
id
for u in \
  systemd-rfkill.socket \
  systemd-suspend.service \
  systemd-hibernate.service \
  systemd-hybrid-sleep.service \
  systemd-suspend-then-hibernate.service \
  plymouth-reboot.service \
  plymouth-poweroff.service \
  rescue.service \
  emergency.service \
  systemd-volatile-root.service; do
  echo "### start $u"
  systemctl start "$u" 2>&1
  echo "rc=$?"
done
echo "### isolate rescue.target"
systemctl isolate rescue.target 2>&1
echo "rc=$?"
for m in CanSuspend CanHibernate CanHybridSleep CanSuspendThenHibernate CanReboot CanPowerOff; do
  echo "### $m"
  busctl call --system org.freedesktop.login1 /org/freedesktop/login1 \
    org.freedesktop.login1.Manager "$m" 2>&1
  echo "rc=$?"
done
'

section "post-trigger state and health"
for u in $units; do
  systemctl show "$u" -p Id -p ActiveState -p SubState -p Result 2>&1
done
systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend 2>&1 || true
TARGET

mv "$tmp_log" "$log_path"
sed -n '1,360p' "$log_path"
