#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/dbus-polkit-residual.out"

mkdir -p "$repo_dir/logs"
: >"$log_path"
exec > >(tee -a "$log_path") 2>&1

echo "residual D-Bus/polkit state-changing API probe"
echo "target=$container"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $container" >&2
  exit 1
fi

docker exec -i "$container" bash -s <<'TARGET'
set +e
export LC_ALL=C

WORK=/tmp/dbus-polkit-residual
OUT=$WORK/target.out
MARKER=/root/dbus_polkit_residual_root
USER_SELF=selfauth
USER_ATTACKER=attacker
USER_HOME=/home/selfauth
ACTIVE_PROBE=$USER_HOME/dbus-polkit-residual-active.sh

rm -rf "$WORK"
mkdir -p "$WORK"
chmod 0755 "$WORK"
rm -f "$MARKER"
: >"$OUT"

rm -f /home/selfauth/.bash_profile /home/selfauth/dbus-polkit-residual-active.sh
loginctl disable-linger attacker 2>/dev/null || true
loginctl disable-linger selfauth 2>/dev/null || true
loginctl terminate-user selfauth 2>/dev/null || true
pkill -u selfauth 2>/dev/null || true
systemctl stop packagekit.service systemd-hostnamed.service systemd-localed.service \
  systemd-timedated.service ModemManager.service bolt.service fwupd.service 2>/dev/null || true
systemctl reset-failed 2>/dev/null || true

exec > >(tee -a "$OUT") 2>&1

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
  timeout 12 "$@"
  printf 'rc=%s\n' "$?"
}

run_shell() {
  local label="$1"
  local cmd="$2"
  local timeout_s="${3:-12}"
  printf '\n### %s\n$ %s\n' "$label" "$cmd"
  timeout "$timeout_s" bash -lc "$cmd"
  printf 'rc=%s\n' "$?"
}

run_as() {
  local user="$1"
  local label="$2"
  shift 2
  printf '\n### as %s: %s\n' "$user" "$label"
  printf '$'
  printf ' %q' runuser -u "$user" -- "$@"
  printf '\n'
  timeout 14 runuser -u "$user" -- "$@"
  printf 'rc=%s\n' "$?"
}

run_as_shell() {
  local user="$1"
  local label="$2"
  local cmd="$3"
  local timeout_s="${4:-14}"
  printf '\n### as %s: %s\n$ %s\n' "$user" "$label" "$cmd"
  timeout "$timeout_s" runuser -u "$user" -- bash -lc "$cmd"
  printf 'rc=%s\n' "$?"
}

hash_state() {
  local label="$1"
  section "$label"
  for p in \
    /etc/hostname \
    /etc/machine-info \
    /etc/locale.conf \
    /etc/default/locale \
    /etc/default/keyboard \
    /etc/localtime \
    /etc/systemd/resolved.conf \
    /etc/systemd/timesyncd.conf \
    /etc/netplan \
    /etc/apt/sources.list.d \
    /var/lib/systemd/linger \
    /system-update \
    /var/lib/PackageKit/offline-update-action \
    /var/lib/PackageKit/prepared-update \
    "$MARKER"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      stat -Lc '%A %U:%G %s %Y %n -> %N' "$p" 2>&1
      [ -f "$p" ] && sha256sum "$p" 2>&1
    else
      echo "MISSING $p"
    fi
  done
  find /etc/netplan /etc/apt/sources.list.d /var/lib/systemd/linger -maxdepth 2 -printf '%m %u:%g %p -> %l\n' 2>/dev/null | sort
}

section "target identity"
cat /etc/os-release | sed -n '1,14p'
uname -a
systemctl --version | head -1
id "$USER_ATTACKER"
id "$USER_SELF" 2>&1 || true
getent group sudo adm lxd docker disk systemd-journal || true
systemctl is-system-running 2>&1 || true

section "package proof"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  accountsservice dbus dbus-daemon dbus-user-session fwupd modemmanager netplan.io \
  packagekit packagekit-tools polkitd software-properties-common systemd systemd-resolved \
  systemd-timesyncd udisks2 update-notifier-common 2>&1 | sort
command -v pkexec || echo "pkexec absent"
ls -l /usr/lib/update-notifier/package-system-locked 2>&1 || true

section "system bus names before activation"
busctl --system list --no-pager | egrep 'Accounts|SoftwareProperties|ModemManager|PackageKit|UDisks2|bolt|fwupd|hostname1|locale1|login1|network1|resolve1|systemd1|timedate1|timesync1|netplan|PolicyKit' || true

section "D-Bus activation files and directory permissions"
for d in /usr/share/dbus-1/system-services /usr/share/dbus-1/system.d /etc/dbus-1/system.d; do
  stat -Lc '%A %U:%G %n' "$d" 2>&1
done
python3 - <<'PY'
import glob
focus = (
    "Accounts", "SoftwareProperties", "ModemManager", "PackageKit", "UDisks2",
    "bolt", "fwupd", "hostname1", "locale1", "login1", "network1",
    "resolve1", "systemd1", "timedate1", "timesync1", "netplan",
)
for path in sorted(glob.glob("/usr/share/dbus-1/system-services/*.service")):
    vals = {}
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                vals[k] = v
    name = vals.get("Name", "")
    if any(token in name or token in path for token in focus):
        print(f"{path}\tName={name}\tUser={vals.get('User','')}\tSystemdService={vals.get('SystemdService','')}\tExec={vals.get('Exec','')}")
PY
find /usr/share/dbus-1/system-services /usr/share/dbus-1/system.d /etc/dbus-1/system.d -maxdepth 1 -type f -printf '%m %u:%g %p\n' | sort | sed -n '1,220p'

section "default unit/service state"
for unit in \
  accounts-daemon.service \
  dbus.service polkit.service \
  systemd-logind.service systemd-hostnamed.service systemd-localed.service systemd-timedated.service \
  systemd-resolved.service systemd-timesyncd.service systemd-networkd.service systemd-networkd.socket \
  packagekit.service udisks2.service com.ubuntu.SoftwareProperties.service \
  ModemManager.service bolt.service fwupd.service fwupd-refresh.timer; do
  echo "### $unit"
  systemctl show -p LoadState -p ActiveState -p SubState -p UnitFileState -p ConditionResult -p FragmentPath -p MainPID -p User -p BusName "$unit" 2>&1
done

section "polkit action inventory"
python3 - <<'PY'
import glob
import xml.etree.ElementTree as ET
focus_prefixes = (
    "com.ubuntu.softwareproperties.",
    "com.ubuntu.update-notifier.",
    "io.netplan.",
    "org.freedesktop.Accounts.",
    "org.freedesktop.ModemManager1.",
    "org.freedesktop.PackageKit.",
    "org.freedesktop.UDisks2.",
    "org.freedesktop.bolt.",
    "org.freedesktop.fwupd.",
    "org.freedesktop.hostname1.",
    "org.freedesktop.locale1.",
    "org.freedesktop.login1.",
    "org.freedesktop.network1.",
    "org.freedesktop.packagekit.",
    "org.freedesktop.resolve1.",
    "org.freedesktop.systemd1.",
    "org.freedesktop.timedate1.",
    "org.freedesktop.timesync1.",
)
rows = []
active_or_any = []
for path in sorted(glob.glob("/usr/share/polkit-1/actions/*.policy")):
    try:
        root = ET.parse(path).getroot()
    except Exception as exc:
        print(f"parse_error\t{path}\t{exc}")
        continue
    for action in root.findall("action"):
        aid = action.get("id") or ""
        vals = {}
        for key in ("allow_any", "allow_inactive", "allow_active"):
            node = action.find("defaults/" + key)
            vals[key] = (node.text or "").strip() if node is not None else ""
        row = (aid, path, vals["allow_any"], vals["allow_inactive"], vals["allow_active"])
        if any(aid.startswith(prefix) for prefix in focus_prefixes):
            rows.append(row)
        if vals["allow_any"] == "yes" or vals["allow_active"] == "yes" or "auth_self" in " ".join(vals.values()):
            active_or_any.append(row)

print("[focus]")
for aid, path, anyv, inactivev, activev in sorted(rows):
    print(f"{aid}\t{path}\tany={anyv}\tinactive={inactivev}\tactive={activev}")
print("[any_yes_active_yes_auth_self]")
for aid, path, anyv, inactivev, activev in sorted(active_or_any):
    tag = "focus" if any(aid.startswith(prefix) for prefix in focus_prefixes) else "other"
    print(f"{tag}\t{aid}\t{path}\tany={anyv}\tinactive={inactivev}\tactive={activev}")
if not any("auth_self" in f"{r[2]} {r[3]} {r[4]}" for r in active_or_any):
    print("[auth_self] none")
PY

hash_state "root-owned state before"

section "normal uid1001 attacker tests for any=yes actions and admin-gated mutators"
run_as_shell "$USER_ATTACKER" "pkcheck any=yes login1 actions" '
for action in \
  org.freedesktop.login1.set-self-linger \
  org.freedesktop.login1.inhibit-delay-shutdown \
  org.freedesktop.login1.inhibit-delay-sleep \
  org.freedesktop.login1.inhibit-block-idle \
  org.freedesktop.systemd1.manage-units \
  org.freedesktop.hostname1.set-static-hostname \
  org.freedesktop.packagekit.system-sources-refresh \
  org.freedesktop.udisks2.loop-setup; do
  printf "ACTION %s\n" "$action"
  timeout 4 pkcheck --action-id "$action" --process $$ 2>&1
  printf "rc=%s\n" "$?"
done
' 60
run_as "$USER_ATTACKER" "login1 SetUserLinger self true" busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SetUserLinger ubb 1001 true false
ls -l /var/lib/systemd/linger/attacker 2>&1 || true
run_as "$USER_ATTACKER" "login1 SetUserLinger root true denied" busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SetUserLinger ubb 0 true false
run_as "$USER_ATTACKER" "login1 Inhibit shutdown delay" busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager Inhibit ssss shutdown dbus-polkit-residual audit delay
run_as "$USER_ATTACKER" "DBus UpdateActivationEnvironment denied" busctl --system call org.freedesktop.DBus / org.freedesktop.DBus UpdateActivationEnvironment a{ss} 2 LD_PRELOAD /tmp/nope DBUS_POLKIT_RESIDUAL 1
run_as_shell "$USER_ATTACKER" "systemd root transient denied" "systemd-run --system --collect --unit=dbus-polkit-residual-root /bin/sh -c 'id > $MARKER'"
run_as "$USER_ATTACKER" "systemd SetEnvironment denied" busctl --system call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SetEnvironment as 1 DBUS_POLKIT_RESIDUAL=1
run_as "$USER_ATTACKER" "hostnamed SetStaticHostname denied" busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetStaticHostname sb dbus-polkit-residual false
run_as "$USER_ATTACKER" "localed SetLocale denied" busctl --system call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetLocale asb 1 LANG=C false
run_as "$USER_ATTACKER" "timedated SetTimezone denied" busctl --system call org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetTimezone sb Etc/UTC false
ifidx="$(cat /sys/class/net/eth0/ifindex 2>/dev/null || echo 2)"
run_as "$USER_ATTACKER" "resolved SetLinkDNS denied" busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNS 'ia(iay)' "$ifidx" 1 2 4 127 0 0 1
run_as "$USER_ATTACKER" "networkd Reload default inactive/denied" busctl --system call org.freedesktop.network1 /org/freedesktop/network1 org.freedesktop.network1.Manager Reload
run_as "$USER_ATTACKER" "netplan Config denied" busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Config
run_as "$USER_ATTACKER" "SoftwareProperties Reload read-only" gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.Reload
run_as "$USER_ATTACKER" "SoftwareProperties AddSourceFromLine denied" gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddSourceFromLine 'deb http://127.0.0.1/ubuntu noble main'
run_as "$USER_ATTACKER" "PackageKit CreateTransaction reachable" busctl --system call org.freedesktop.PackageKit /org/freedesktop/PackageKit org.freedesktop.PackageKit CreateTransaction
run_as_shell "$USER_ATTACKER" "PackageKit refresh from no-seat attacker" "pkcon refresh force"
run_as_shell "$USER_ATTACKER" "UDisks loop setup denied from no-seat attacker" "truncate -s 4M /tmp/dbus-polkit-residual-attacker.img; udisksctl loop-setup -f /tmp/dbus-polkit-residual-attacker.img"
run_as "$USER_ATTACKER" "Accounts-like bus name absent" busctl --system introspect org.freedesktop.Accounts /org/freedesktop/Accounts

hash_state "state after normal attacker tests"

section "active tty selfauth tests for active=yes surfaces"
if ! id "$USER_SELF" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USER_SELF"
fi
echo "$USER_SELF:$USER_SELF" | chpasswd
usermod -G "$USER_SELF" "$USER_SELF"
chown "$USER_SELF:$USER_SELF" "$WORK"

cat >"$ACTIVE_PROBE" <<'ACTIVE'
#!/usr/bin/env bash
set +e
export LC_ALL=C
WORK=/tmp/dbus-polkit-residual
MARKER=/root/dbus_polkit_residual_root
exec >>"$WORK/active.out" 2>&1

section() {
  printf '\n## %s\n' "$1"
}

run_shell() {
  local label="$1"
  local cmd="$2"
  local timeout_s="${3:-10}"
  printf '\n### %s\n$ %s\n' "$label" "$cmd"
  timeout "$timeout_s" bash -c "$cmd"
  printf 'rc=%s\n' "$?"
}

section "active subject proof"
id
tty
echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote -p Leader 2>&1
fi
groups
passwd -S selfauth 2>&1 || true

section "active pkcheck selected actions"
for action in \
  com.ubuntu.update-notifier.pkexec.package-system-locked \
  org.freedesktop.login1.set-self-linger \
  org.freedesktop.login1.reboot \
  org.freedesktop.packagekit.system-sources-refresh \
  org.freedesktop.packagekit.system-network-proxy-configure \
  org.freedesktop.packagekit.trigger-offline-update \
  org.freedesktop.udisks2.loop-setup \
  org.freedesktop.udisks2.filesystem-mount \
  org.freedesktop.fwupd.update-internal-trusted \
  org.freedesktop.ModemManager1.Device.Control \
  org.freedesktop.systemd1.manage-units \
  org.freedesktop.hostname1.set-static-hostname; do
  printf 'ACTION %s\n' "$action"
  timeout 4 pkcheck --action-id "$action" --process $$ 2>&1
  printf 'rc=%s\n' "$?"
done

section "active semantic checks"
run_shell "login1 self linger fixed-path write" "loginctl enable-linger selfauth; ls -l /var/lib/systemd/linger/selfauth; loginctl disable-linger selfauth"
run_shell "login1 CanReboot active query only" "loginctl show-session \"${XDG_SESSION_ID:-}\" -p Active -p Seat -p TTY; busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot"
run_shell "hostnamed remains admin-gated for non-admin active user" "busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetStaticHostname sb dbus-polkit-active false"
run_shell "systemd transient root marker remains admin-gated" "systemd-run --system --collect --unit=dbus-polkit-residual-active /bin/sh -c 'id > $MARKER'"
run_shell "resolved active mutator remains admin-gated" "ifidx=\$(cat /sys/class/net/eth0/ifindex 2>/dev/null || echo 2); busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDomains 'ia(sb)' \$ifidx 1 dbus-polkit-residual.invalid false"
run_shell "PackageKit active refresh bounded" "pkcon refresh force" 35
run_shell "PackageKit active SetProxy newline bounded" "python3 - <<'PY'
import dbus
bus = dbus.SystemBus()
obj = bus.get_object('org.freedesktop.PackageKit', '/org/freedesktop/PackageKit')
pk = dbus.Interface(obj, 'org.freedesktop.PackageKit')
try:
    pk.SetProxy('http://127.0.0.1:9/\\nInjected=1', '', '', '', 'localhost\\nNoProxy=1', '')
    print('SetProxy OK')
except Exception as exc:
    print(type(exc).__name__ + ': ' + str(exc))
PY"
run_shell "UDisks active loop setup and cleanup" "img=/tmp/dbus-polkit-residual-selfauth.img; truncate -s 4M \$img; dev=\$(udisksctl loop-setup -f \$img 2>&1 | tee /tmp/dbus-polkit-residual/udisks-loop.out | sed -n 's/.* as \\([^.]\\+\\)\\./\\1/p' | tail -1); echo dev=\$dev; [ -n \"\$dev\" ] && udisksctl loop-delete -b \"\$dev\"; rm -f \$img" 20
run_shell "update-notifier helper has no pkexec root path" "command -v pkexec || true; mkdir -p /tmp/dbus-polkit-residual/bin; printf '#!/bin/sh\\nid > /root/dbus_polkit_residual_root\\n' >/tmp/dbus-polkit-residual/bin/fuser; chmod 755 /tmp/dbus-polkit-residual/bin/fuser; PATH=/tmp/dbus-polkit-residual/bin:\$PATH /usr/lib/update-notifier/package-system-locked; ls -l /root/dbus_polkit_residual_root 2>&1 || true"
run_shell "fwupd condition-gated in container" "fwupdmgr get-devices --no-reboot-check --no-unreported-check" 16
run_shell "ModemManager condition-gated/no modems" "busctl --system introspect org.freedesktop.ModemManager1 /org/freedesktop/ModemManager1 --no-pager; busctl --system tree org.freedesktop.ModemManager1" 16
run_shell "bolt condition-gated/admin-gated" "busctl --system introspect org.freedesktop.bolt /org/freedesktop/bolt --no-pager" 16

section "active root marker check"
if [ -e "$MARKER" ]; then
  echo "ROOT_PROOF=yes"
  ls -l "$MARKER"
  sed -n '1,20p' "$MARKER"
else
  echo "ROOT_PROOF=no"
  ls -l "$MARKER" 2>&1 || true
fi
ACTIVE
chmod 0755 "$ACTIVE_PROBE"
chown "$USER_SELF:$USER_SELF" "$ACTIVE_PROBE"
cat >"$USER_HOME/.bash_profile" <<EOF
"$ACTIVE_PROBE"
exit
EOF
chown "$USER_SELF:$USER_SELF" "$USER_HOME/.bash_profile"

systemctl stop getty@tty1.service getty@tty2.service 2>/dev/null || true
timeout 180 openvt -c 2 -s -f -w -- /bin/login -f "$USER_SELF"
echo "openvt_rc=$?"
systemctl start getty@tty1.service 2>/dev/null || true
loginctl terminate-user "$USER_SELF" 2>/dev/null || true
cat "$WORK/active.out" 2>&1

hash_state "state after active selfauth tests"

section "cleanup"
loginctl disable-linger attacker 2>/dev/null || true
loginctl disable-linger selfauth 2>/dev/null || true
loginctl terminate-user selfauth 2>/dev/null || true
systemctl stop dbus-polkit-residual-root.service dbus-polkit-residual-active.service 2>/dev/null || true
systemctl reset-failed dbus-polkit-residual-root.service dbus-polkit-residual-active.service 2>/dev/null || true
rm -f \
  /tmp/dbus-polkit-residual-attacker.img \
  /tmp/dbus-polkit-residual-selfauth.img \
  /home/selfauth/.bash_profile \
  "$ACTIVE_PROBE" \
  /system-update \
  /var/lib/PackageKit/offline-update-action \
  /var/lib/PackageKit/prepared-update
rm -rf /tmp/dbus-polkit-residual/bin
systemctl restart packagekit.service 2>/dev/null || true
systemctl stop systemd-hostnamed.service systemd-localed.service systemd-timedated.service ModemManager.service bolt.service fwupd.service 2>/dev/null || true
systemctl start getty@tty1.service 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

if [ -e "$MARKER" ]; then
  echo "root marker unexpectedly exists after cleanup:"
  ls -l "$MARKER"
  sed -n '1,20p' "$MARKER"
else
  echo "root marker absent"
fi
echo "is-system-running:"
systemctl is-system-running 2>&1 || true
echo "failed units:"
systemctl --failed --no-legend --no-pager 2>&1 || true
TARGET

docker exec "$container" bash -lc 'cat /tmp/dbus-polkit-residual/target.out 2>/dev/null >/dev/null; rm -rf /tmp/dbus-polkit-residual' >/dev/null 2>&1 || true
