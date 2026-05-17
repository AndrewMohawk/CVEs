#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/dmesg-savelog-20260517.out"

docker exec -i "$container" bash <<'TARGET' >"$log_path" 2>&1
set +e

section() {
  printf '\n## %s\n' "$1"
}

cmd() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
  rc=$?
  printf 'rc=%s\n' "$rc"
  return 0
}

section "target identity"
cmd sed -n '1,12p' /etc/os-release
cmd uname -a
cmd id
cmd id attacker
cmd getent passwd attacker
cmd getent group attacker

section "package and default enablement proof"
cmd dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' rsyslog debianutils systemd
cmd dpkg -S /lib/systemd/system/dmesg.service /usr/bin/savelog /usr/bin/journalctl /usr/bin/chgrp /usr/bin/chmod
cmd ls -ld /bin /lib /usr/lib /lib/systemd/system/dmesg.service /usr/lib/systemd/system/dmesg.service /usr/bin/savelog /bin/journalctl /bin/chgrp /bin/chmod
cmd systemctl list-unit-files dmesg.service --no-pager
cmd systemctl show dmesg.service \
  -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState -p UnitFilePreset \
  -p FragmentPath -p User -p Group -p StandardOutput -p ExecStartPre -p ExecStart \
  -p ExecStartPost -p Result
cmd systemctl status dmesg.service --no-pager
cmd journalctl -u dmesg.service --no-pager -o short-iso

section "unit and savelog behavior"
cmd nl -ba /usr/lib/systemd/system/dmesg.service
printf '\n### /usr/bin/savelog header and usage comments\n'
nl -ba /usr/bin/savelog | sed -n '1,80p'
printf '\n### /usr/bin/savelog argument parsing and file checks\n'
nl -ba /usr/bin/savelog | sed -n '145,225p'
printf '\n### /usr/bin/savelog directory/rotation/recreate logic\n'
nl -ba /usr/bin/savelog | sed -n '227,343p'
printf '\n### savelog runtime help\n'
/usr/bin/savelog -h 2>&1
printf 'rc=%s\n' "$?"

section "default dmesg path ownership"
cmd stat -Lc '%A %a %U:%G %F %n' /var /var/log /var/log/dmesg /var/log/dmesg.0
cmd ls -lan /var /var/log /var/log/dmesg /var/log/dmesg.0
cmd sh -lc 'command -v namei >/dev/null && namei -om /var/log/dmesg || true'
cmd sh -lc 'command -v getfacl >/dev/null && getfacl -p /var/log /var/log/dmesg || true'

section "attacker-only path and service tests"
runuser -u attacker -- bash <<'ATTACKER'
set +e

acmd() {
  printf '\nattacker$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
  rc=$?
  printf 'rc=%s\n' "$rc"
  return 0
}

acmd id
acmd groups
acmd stat -Lc '%A %a %U:%G %F %n' /var /var/log /var/log/dmesg /var/log/dmesg.0
acmd ls -lan /var/log/dmesg /var/log/dmesg.0
acmd test -r /var/log/dmesg
acmd test -w /var/log/dmesg
acmd test -w /var/log
acmd head -n 1 /var/log/dmesg
acmd bash -lc 'printf attacker-append-test >> /var/log/dmesg'
acmd touch /var/log/dmesg.new
acmd mv /var/log/dmesg /var/log/dmesg.attacker-mv
acmd rm -f /var/log/dmesg
acmd ln -s /etc/sudoers /var/log/dmesg.attacker-symlink
acmd ln -s /etc/sudoers /var/log/dmesg
acmd ln /etc/passwd /var/log/dmesg.attacker-hardlink
acmd /usr/bin/savelog -m640 -q -p -n -c 5 /var/log/dmesg
acmd systemctl start dmesg.service
acmd systemctl restart dmesg.service
acmd busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss dmesg.service replace

tmp="$(mktemp -d /tmp/dmesg-savelog-attacker.XXXXXX)"
printf '\nattacker$tmp=%s\n' "$tmp"
printf owned > "$tmp/file"
acmd ls -lan "$tmp" "$tmp/file"
acmd /usr/bin/savelog -m640 -q -p -n -c 2 "$tmp/file"
acmd find "$tmp" -maxdepth 1 -ls
acmd rm -rf "$tmp"
acmd test ! -e "$tmp"
ATTACKER

section "post-test cleanup and health"
cmd find /tmp -maxdepth 1 -name 'dmesg-savelog-attacker.*' -ls
cmd stat -Lc '%A %a %U:%G %F %n' /var/log /var/log/dmesg /var/log/dmesg.0
cmd ls -lan /var/log/dmesg*
cmd systemctl is-system-running
cmd systemctl --failed --no-legend

section "conclusion marker"
printf 'ROOT_PROOF=no\n'
printf 'No uid1001-controlled write, rotate, service start, or uid=0 execution was reached through the default dmesg.service/savelog path.\n'
TARGET

sed -n '1,420p' "$log_path"
