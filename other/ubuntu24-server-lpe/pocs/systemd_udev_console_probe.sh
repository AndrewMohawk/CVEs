#!/usr/bin/env bash
set -euo pipefail

target="${1:-ubuntu24-server-lpe-target}"

section() {
  printf '\n### %s\n' "$1"
}

in_target() {
  docker exec "$target" bash -lc "$1"
}

as_attacker() {
  docker exec --user 1001:1001 "$target" bash -lc "$1"
}

section "target"
in_target 'cat /etc/os-release | sed -n "1,8p"; uname -a; id attacker; systemctl is-system-running; systemctl --failed --no-legend | wc -l'

section "packages"
in_target 'dpkg-query -W systemd udev util-linux login 2>/dev/null | sort'

section "systemd-udev-trigger-default-proof"
in_target '
  systemctl show systemd-udev-trigger.service \
    -p Id -p FragmentPath -p UnitFileState -p ActiveState -p SubState \
    -p ConditionResult -p ExecStart -p Environment -p ExecSearchPath
  nl -ba /usr/lib/systemd/system/systemd-udev-trigger.service | sed -n "1,80p"
  stat -Lc "%A %U:%G %n" \
    /sys \
    /run/udev/control \
    /usr/bin/udevadm \
    /usr/lib/systemd/system/systemd-udev-trigger.service 2>&1 || true
'

section "systemd-udev-trigger-attacker"
as_attacker '
  id
  systemctl start systemd-udev-trigger.service 2>&1 | sed -n "1,50p" || true
  err=$(udevadm trigger --type=all --action=add --prioritized-subsystem=module,block,tpmrm,net,tty,input 2>&1 >/dev/null) || rc=$?
  rc=${rc:-0}
  echo "udevadm_trigger_rc=$rc"
  printf "%s\n" "$err" | sed -n "1,60p"
  printf add > /sys/module/block/uevent 2>&1 || true
  touch /run/udev/attacker 2>&1 || true
'

section "console-getty-default-proof"
in_target '
  systemctl show console-getty.service \
    -p Id -p LoadState -p FragmentPath -p UnitFileState -p ActiveState \
    -p SubState -p ConditionResult -p ExecStart -p TTYPath -p ImportCredential
  nl -ba /usr/lib/systemd/system/console-getty.service | sed -n "1,90p"
  stat -Lc "%A %U:%G %n" \
    /run/credentials \
    /dev/console \
    /dev/tty0 \
    /sbin/agetty \
    /usr/lib/systemd/system/console-getty.service 2>&1 || true
'

section "console-getty-attacker"
as_attacker '
  id
  systemctl start console-getty.service 2>&1 | sed -n "1,80p" || true
  test -w /run/credentials && echo WRITE_CREDS || echo NO_WRITE_CREDS
  mkdir -p /run/credentials/console-getty.service 2>&1 || true
  printf pwn > /run/credentials/console-getty.service/login.pwn 2>&1 || true
  printf pwn > /dev/console 2>&1 || true
'

section "root-marker-check"
in_target '
  for p in /root/systemd_udev_console_root /run/systemd_udev_console_root /tmp/systemd_udev_console_root; do
    if [ -e "$p" ]; then stat -Lc "%A %U:%G %n" "$p"; cat "$p"; else echo "absent $p"; fi
  done
'

section "cleanup-health"
in_target 'rm -f /root/systemd_udev_console_root /run/systemd_udev_console_root /tmp/systemd_udev_console_root; systemctl is-system-running; systemctl --failed --no-legend | wc -l'

section "result"
echo "ROOT_PROOF=NO"
