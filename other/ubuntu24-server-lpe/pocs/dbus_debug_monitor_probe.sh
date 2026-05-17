#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
ATTACKER="${ATTACKER:-attacker}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/dbus-debug-monitor.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

section() {
  printf '\n## %s\n' "$1"
}

target_root() {
  local label="$1"
  section "$label"
  printf '$ docker exec -i %q bash -s\n' "$TARGET"
  docker exec -i -e ATTACKER="$ATTACKER" "$TARGET" bash -s
}

target_attacker() {
  local label="$1"
  section "$label"
  printf '$ docker exec -i %q runuser -u %q -- bash -s\n' "$TARGET" "$ATTACKER"
  docker exec -i -e ATTACKER="$ATTACKER" "$TARGET" runuser -u "$ATTACKER" -- bash -s
}

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

echo "D-Bus Debug.Stats and Monitoring system-bus probe"
echo "target=$TARGET attacker=$ATTACKER"
date '+%Y-%m-%dT%H:%M:%S%z'

target_root "cleanup before probe" <<'TARGET'
set +e
rm -rf /tmp/dbus_debug_monitor_probe* \
  "/home/${ATTACKER}/dbus_debug_monitor_probe" \
  /root/dbus_debug_monitor_root 2>/dev/null || true
pkill -u "$ATTACKER" -f 'dbus-monitor --system' 2>/dev/null || true
true
TARGET

target_root "target identity, packages, and system bus reachability" <<'TARGET'
set +e
export LC_ALL=C

echo "== identity =="
cat /etc/os-release | sed -n '1,14p'
uname -a
ps -p 1 -o pid=,user=,comm=,args=
id "$ATTACKER"
runuser -u "$ATTACKER" -- bash -lc 'id; groups; command -v sudo >/dev/null && sudo -n true; echo sudo_rc=$?' 2>&1

echo
echo "== package versions =="
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  dbus dbus-bin dbus-daemon dbus-system-bus-common libdbus-1-3 systemd polkitd 2>/dev/null | sort

echo
echo "== system bus service/socket state =="
systemctl show -p LoadState -p ActiveState -p SubState -p FragmentPath -p ExecStart dbus.service dbus.socket 2>&1
ps -eo user,pid,comm,args | grep '[d]bus-daemon.*--system' || true
for p in /run/dbus/system_bus_socket /usr/bin/dbus-daemon /usr/bin/busctl /usr/bin/dbus-monitor \
  /usr/bin/dbus-send /usr/share/dbus-1/system.conf /usr/lib/systemd/system/dbus.service \
  /usr/lib/systemd/system/dbus.socket; do
  [ -e "$p" ] || [ -L "$p" ] && stat -Lc '%A %a %U:%G %F %n -> %N' "$p" || echo "MISSING $p"
done
dpkg -S /usr/share/dbus-1/system.conf /usr/lib/systemd/system/dbus.service /usr/lib/systemd/system/dbus.socket 2>&1

echo
echo "== bus name and interface reachability =="
busctl --system list --no-pager | sed -n '1,60p'
echo "-- Debug.Stats introspection as root --"
busctl --system introspect org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Debug.Stats --no-pager 2>&1
echo "-- Monitoring introspection as root --"
busctl --system introspect org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Monitoring --no-pager 2>&1

echo
echo "== root-only Debug.Stats control calls prove interface is compiled/enabled =="
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Debug.Stats GetStats 2>&1
echo "root_getstats_rc=$?"
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Debug.Stats GetConnectionStats s :1.1 2>&1
echo "root_getconnectionstats_rc=$?"
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Debug.Stats GetAllMatchRules 2>&1 | sed -n '1,16p'
echo "root_getallmatchrules_rc=${PIPESTATUS[0]}"
TARGET

target_root "relevant D-Bus policy/config snippets" <<'TARGET'
set +e
export LC_ALL=C

echo "== /usr/share/dbus-1/system.conf relevant lines =="
nl -ba /usr/share/dbus-1/system.conf | sed -n '44,104p'

echo
echo "== policy hits for Debug.Stats / Monitoring / eavesdrop =="
grep -RIn 'Debug\.Stats\|Monitoring\|BecomeMonitor\|GetStats\|GetConnectionStats\|GetAllMatchRules\|eavesdrop\|send_destination="org.freedesktop.DBus"' \
  /usr/share/dbus-1/system.conf /usr/share/dbus-1/system.d /etc/dbus-1/system.d 2>/dev/null | sed -n '1,260p'
TARGET

target_attacker "uid1001 direct interface and monitor trigger attempts" <<'ATTACKER'
set +e
export LC_ALL=C
work="$HOME/dbus_debug_monitor_probe"
marker=/root/dbus_debug_monitor_root
mkdir -p "$work"

echo "== attacker identity and root marker precheck =="
id
groups
printf 'DBUS_SYSTEM_BUS_ADDRESS=%s\n' "${DBUS_SYSTEM_BUS_ADDRESS-unset}"
stat "$marker" 2>&1 || echo "marker_absent_before"

run() {
  local label="$1"
  shift
  printf '\n### %s\n' "$label"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  timeout 8 "$@"
  printf 'rc=%s\n' "$?"
}

run_shell() {
  local label="$1"
  local cmd="$2"
  local timeout_s="${3:-8}"
  printf '\n### %s\n$ %s\n' "$label" "$cmd"
  timeout "$timeout_s" bash -lc "$cmd"
  printf 'rc=%s\n' "$?"
}

run "introspect Debug.Stats" \
  busctl --system introspect org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Debug.Stats --no-pager
run "introspect Monitoring" \
  busctl --system introspect org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Monitoring --no-pager

run "Debug.Stats.GetStats" \
  busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Debug.Stats GetStats
run "Debug.Stats.GetConnectionStats root unique name" \
  busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Debug.Stats GetConnectionStats s :1.1
run "Debug.Stats.GetAllMatchRules" \
  busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Debug.Stats GetAllMatchRules

run "Monitoring.BecomeMonitor via busctl" \
  busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Monitoring BecomeMonitor asu 0 0
run "Monitoring.BecomeMonitor via dbus-send" \
  dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply \
    /org/freedesktop/DBus org.freedesktop.DBus.Monitoring.BecomeMonitor array:string: uint32:0

run_shell "dbus-monitor --system default attempt" \
  'timeout 4 dbus-monitor --system 2>&1 | sed -n "1,90p"; printf "dbus_monitor_rc=%s\n" "${PIPESTATUS[0]}"' 7
run_shell "dbus-monitor explicit eavesdrop method-call attempt" \
  'timeout 4 dbus-monitor --system "eavesdrop=true,type=method_call" 2>&1 | sed -n "1,90p"; printf "dbus_monitor_eavesdrop_rc=%s\n" "${PIPESTATUS[0]}"' 7

echo
echo "== root marker post-trigger check from uid1001 =="
stat "$marker" 2>&1 || echo "marker_absent_after_attacker_triggers"
ATTACKER

target_root "root proof check, cleanup, and final target state" <<'TARGET'
set +e
export LC_ALL=C
marker=/root/dbus_debug_monitor_root

echo "== root marker/root proof check =="
if [ -e "$marker" ]; then
  echo "ROOT_MARKER_PRESENT"
  stat -Lc '%A %a %U:%G %s %n' "$marker"
  sed -n '1,40p' "$marker" 2>/dev/null || true
else
  echo "NO_ROOT_MARKER $marker"
fi

echo
echo "== cleanup =="
rm -rf /tmp/dbus_debug_monitor_probe* "/home/${ATTACKER}/dbus_debug_monitor_probe" 2>/dev/null || true
pkill -u "$ATTACKER" -f 'dbus-monitor --system' 2>/dev/null || true
if [ -e "$marker" ]; then
  rm -f "$marker"
  echo "removed unexpected marker"
else
  echo "no marker to remove"
fi

echo
echo "== final health =="
systemctl is-system-running 2>&1 || true
systemctl --failed --no-pager 2>&1 || true
TARGET
