#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/systemd-sysupdate-repart.out"

mkdir -p "$repo_dir/logs"
: >"$log_path"
exec > >(tee -a "$log_path") 2>&1

echo "systemd sysupdate/repart/offline-update LPE probe"
echo "target=$container"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $container" >&2
  exit 1
fi

docker exec -i "$container" bash -s <<'TARGET'
set +e

WORK=/tmp/systemd-sysupdate-repart-probe
ACTIVE=/tmp/systemd-sysupdate-repart-active
ROOT_MARKER=/root/systemd_sysupdate_repart_lpe
TMP_MARKER=/tmp/systemd_sysupdate_repart_lpe

rm -rf "$WORK" "$ACTIVE" "$ROOT_MARKER" "$TMP_MARKER"
mkdir -p "$WORK" "$ACTIVE"
chmod 1777 "$WORK" "$ACTIVE"

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

run_user_block() {
  local user="$1"
  local label="$2"
  shift 2
  printf '\n### %s: %s\n' "$user" "$label"
  runuser -u "$user" -- bash -lc "$*"
  printf 'rc=%s\n' "$?"
}

section "target identity, package, and binary proof"
{
  uname -a
  sed -n '1,8p' /etc/os-release
  id attacker
  id selfauth
  groups attacker
  groups selfauth
  systemctl --version | head -1
  dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
    systemd systemd-sysv libsystemd-shared polkitd policykit-1 dbus dbus-daemon \
    packagekit fwupd 2>/dev/null | sort
  for p in /usr/lib/systemd/systemd-sysupdate /usr/bin/systemd-repart \
           /usr/lib/systemd/system-generators/systemd-system-update-generator \
           /usr/libexec/pk-offline-update /usr/libexec/fwupd/fwupdoffline; do
    stat -Lc '%A %U:%G %s %n' "$p" 2>&1 || true
    getcap "$p" 2>/dev/null || true
  done
}

section "default units and root transitions"
systemctl list-unit-files --no-pager \
  'systemd-sysupdate*' 'systemd-repart*' 'system-update*' \
  'factory-reset.target' 'packagekit-offline-update.service' \
  'fwupd-offline-update.service' 2>&1
systemctl list-units --all --no-pager \
  'systemd-sysupdate*' 'systemd-repart*' 'system-update*' \
  'factory-reset.target' 'packagekit-offline-update.service' \
  'fwupd-offline-update.service' 2>&1
for u in systemd-sysupdate.service systemd-sysupdate-reboot.service \
         systemd-sysupdate.timer systemd-sysupdate-reboot.timer \
         systemd-repart.service system-update.target system-update-cleanup.service \
         factory-reset.target packagekit-offline-update.service fwupd-offline-update.service; do
  echo "### $u"
  systemctl show -p FragmentPath -p UnitFileState -p ActiveState -p SubState \
    -p ConditionResult -p ExecStart -p Environment -p LoadCredential -p SetCredential "$u" 2>&1
  systemctl cat "$u" 2>&1 | sed -n '1,120p'
done

section "package-owned config and image search paths"
dpkg -L systemd packagekit fwupd 2>/dev/null | grep -E '(sysupdate|repart|system-update|offline-update|factory-reset|fwupdoffline|pk-offline)' | sort
for p in \
  /etc/sysupdate.d /run/sysupdate.d /usr/local/lib/sysupdate.d /usr/lib/sysupdate.d /var/lib/systemd/sysupdate \
  /etc/repart.d /run/repart.d /usr/local/lib/repart.d /usr/lib/repart.d \
  /etc/systemd/repart/definitions /run/systemd/repart/definitions \
  /usr/local/lib/systemd/repart/definitions /usr/lib/systemd/repart/definitions \
  /system-update /etc/system-update /run/systemd/system/system-update.target.wants \
  /usr/lib/systemd/system/system-update.target.wants /var/lib/PackageKit /var/lib/fwupd /var/lib/systemd \
  /usr/local/bin /usr/local/sbin /run/systemd/system; do
  stat -Lc '%A %U:%G %n' "$p" 2>&1 || true
done
find /etc/sysupdate.d /run/sysupdate.d /usr/local/lib/sysupdate.d /usr/lib/sysupdate.d \
     /etc/repart.d /run/repart.d /usr/local/lib/repart.d /usr/lib/repart.d \
     /etc/systemd/repart/definitions /run/systemd/repart/definitions \
     /usr/local/lib/systemd/repart/definitions /usr/lib/systemd/repart/definitions \
     -maxdepth 3 -type f -printf '%M %u:%g %p\n' 2>/dev/null | sort

section "polkit and D-Bus reachability"
busctl --system list --no-pager 2>/dev/null | grep -Ei 'systemd1|sysupdate|repart|PackageKit|fwupd|PolicyKit' || true
find /run /var/run -maxdepth 4 \( -iname '*sysupdate*' -o -iname '*repart*' \) -printf '%M %u:%g %p\n' 2>/dev/null | sort
grep -RHE 'sysupdate|repart|SystemUpdate|PackageKit|fwupd|systemd1' \
  /usr/share/dbus-1/system-services /usr/share/dbus-1/system.d /usr/share/polkit-1/actions 2>/dev/null | sed -n '1,260p'
for action in \
  org.freedesktop.systemd1.manage-units \
  org.freedesktop.systemd1.manage-unit-files \
  org.freedesktop.systemd1.reload-daemon \
  org.freedesktop.systemd1.set-environment \
  org.freedesktop.packagekit.trigger-offline-update \
  org.freedesktop.packagekit.clear-offline-update \
  org.freedesktop.fwupd.update-internal \
  org.freedesktop.fwupd.update-internal-trusted \
  org.freedesktop.fwupd.modify-config; do
  echo "### $action"
  pkaction --verbose --action-id "$action" 2>/dev/null | sed -n '1,90p'
done

section "PackageKit offline default state"
systemctl start packagekit.service >/dev/null 2>&1 || true
gdbus introspect --system --dest org.freedesktop.PackageKit --object-path /org/freedesktop/PackageKit \
  2>&1 | sed -n '/interface org.freedesktop.PackageKit.Offline/,/};/p'
gdbus call --system --dest org.freedesktop.PackageKit --object-path /org/freedesktop/PackageKit \
  --method org.freedesktop.DBus.Properties.GetAll org.freedesktop.PackageKit.Offline 2>&1
for p in /system-update /etc/system-update /var/lib/PackageKit/offline-update-action \
         /var/lib/PackageKit/offline-update-competed /var/lib/PackageKit/prepared-update \
         /var/lib/PackageKit/prepared-upgrade /var/lib/fwupd/pending.db; do
  ls -l "$p" 2>&1 || true
done

section "no-session polkit checks"
for user in attacker selfauth; do
  run_user_block "$user" "pkcheck" '
    id
    for action in org.freedesktop.systemd1.manage-units \
                  org.freedesktop.systemd1.set-environment \
                  org.freedesktop.packagekit.trigger-offline-update \
                  org.freedesktop.packagekit.clear-offline-update; do
      printf "%s " "$action"
      timeout 4 pkcheck --action-id "$action" --process $$ 2>&1
      echo "rc=$?"
    done
  '
done

section "no-session writable path attempts"
for user in attacker selfauth; do
  run_user_block "$user" "write gates" '
    id
    for p in /etc/sysupdate.d /run/sysupdate.d /usr/local/lib/sysupdate.d /usr/lib/sysupdate.d /var/lib/systemd/sysupdate \
             /etc/repart.d /run/repart.d /usr/local/lib/repart.d /usr/lib/repart.d \
             /etc/systemd/repart/definitions /run/systemd/repart/definitions \
             /usr/local/lib/systemd/repart/definitions /usr/lib/systemd/repart/definitions \
             /system-update /etc/system-update /run/systemd/system/system-update.target.wants \
             /var/lib/PackageKit /var/lib/fwupd /usr/local/bin /usr/local/sbin; do
      printf "PATH=%s " "$p"
      test -w "$p"
      echo "write_rc=$?"
    done
    mkdir -p /etc/sysupdate.d /run/sysupdate.d /usr/local/lib/sysupdate.d /usr/lib/sysupdate.d /var/lib/systemd/sysupdate 2>&1
    echo "mkdir_sysupdate_rc=$?"
    mkdir -p /etc/repart.d /run/repart.d /usr/local/lib/repart.d /usr/lib/repart.d /run/systemd/system/system-update.target.wants 2>&1
    echo "mkdir_repart_update_rc=$?"
    ln -s /tmp/attacker-system-update /system-update 2>&1
    echo "ln_system_update_rc=$?"
    ln -s /tmp/attacker-system-update /etc/system-update 2>&1
    echo "ln_etc_system_update_rc=$?"
    printf test > /var/lib/PackageKit/prepared-update 2>&1
    echo "write_pk_prepared_rc=$?"
    mkdir -p /var/lib/fwupd 2>&1
    echo "mkdir_fwupd_rc=$?"
  '
done

section "direct helper attempts as normal users"
for user in attacker selfauth; do
  run_user_block "$user" "systemd-sysupdate/systemd-repart direct execution" '
    id
    export SYSTEMD_LOG_LEVEL=debug
    export SYSTEMD_REPART_OVERRIDE_FSTYPE=ext4
    /usr/lib/systemd/systemd-sysupdate --version 2>&1
    timeout 8 /usr/lib/systemd/systemd-sysupdate components 2>&1
    echo "sysupdate_components_rc=$?"
    timeout 8 /usr/lib/systemd/systemd-sysupdate check-new 2>&1
    echo "sysupdate_check_new_rc=$?"
    timeout 8 /usr/lib/systemd/systemd-sysupdate update --verify=no 2>&1
    echo "sysupdate_update_noverify_rc=$?"
    timeout 8 systemd-repart --dry-run=yes 2>&1
    echo "repart_dry_rc=$?"
    timeout 8 systemd-repart --dry-run=no --factory-reset=yes 2>&1
    echo "repart_factory_rc=$?"
    timeout 8 systemd-repart --can-factory-reset 2>&1
    echo "repart_can_factory_rc=$?"
  '
done

section "system manager method and unit start attempts"
for user in attacker selfauth; do
  run_user_block "$user" "systemd unit and environment attempts" '
    id
    rm -f /tmp/systemd_sysupdate_repart_lpe
    for unit in systemd-sysupdate.service systemd-sysupdate-reboot.service systemd-repart.service \
                packagekit-offline-update.service fwupd-offline-update.service \
                system-update-cleanup.service system-update.target factory-reset.target; do
      echo "UNIT=$unit"
      timeout 8 systemctl --no-ask-password start "$unit" 2>&1
      echo "systemctl_start_rc=$?"
      timeout 8 busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager StartUnit ss "$unit" replace 2>&1
      echo "busctl_start_rc=$?"
    done
    timeout 8 systemctl --no-ask-password isolate system-update.target 2>&1
    echo "isolate_system_update_rc=$?"
    timeout 8 systemctl --no-ask-password set-environment \
      SYSTEMD_SYSUPDATE_VERIFY=0 SYSTEMD_REPART_OVERRIDE_FSTYPE=ext4 PATH=/home/$USER:/usr/local/bin:/usr/bin 2>&1
    echo "set_environment_rc=$?"
    timeout 8 busctl call --system org.freedesktop.DBus / org.freedesktop.DBus \
      UpdateActivationEnvironment a{ss} 3 LD_PRELOAD /tmp/notreal SYSTEMD_LOG_LEVEL debug SYSTEMD_SYSUPDATE_VERIFY 0 2>&1
    echo "dbus_update_activation_env_rc=$?"
    timeout 8 systemd-run --unit=systemd-sysupdate-repart-lpe /bin/sh -c "id > /tmp/systemd_sysupdate_repart_lpe" 2>&1
    echo "systemd_run_rc=$?"
  '
done
systemctl show-environment 2>&1 | grep -E 'SYSTEMD_SYSUPDATE|SYSTEMD_REPART|LD_PRELOAD|/home/(attacker|selfauth)' || true
ls -l "$ROOT_MARKER" "$TMP_MARKER" 2>&1 || true

section "no-session PackageKit offline calls"
for user in attacker selfauth; do
  run_user_block "$user" "PackageKit Offline Trigger" '
    id
    timeout 8 gdbus call --system --dest org.freedesktop.PackageKit --object-path /org/freedesktop/PackageKit \
      --method org.freedesktop.PackageKit.Offline.GetPrepared 2>&1
    echo "getprepared_rc=$?"
    timeout 8 gdbus call --system --dest org.freedesktop.PackageKit --object-path /org/freedesktop/PackageKit \
      --method org.freedesktop.PackageKit.Offline.Trigger reboot 2>&1
    echo "trigger_rc=$?"
  '
done

section "active selfauth local-session boundary"
if command -v openvt >/dev/null 2>&1 && [ -e /dev/tty1 ]; then
  profile=/home/selfauth/.bash_profile
  backup=$WORK/selfauth.bash_profile.bak
  state=$WORK/selfauth.bash_profile.state
  if [ -e "$profile" ]; then
    cp -a "$profile" "$backup"
    echo present >"$state"
  else
    echo absent >"$state"
  fi
  cat >"$profile" <<'PROFILE'
set +e
OUT=/tmp/systemd-sysupdate-repart-active/user.out
exec >"$OUT" 2>&1
id
tty
echo "XDG_SESSION_ID=$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" -p Id -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote 2>&1
python3 - <<'PY'
import dbus

bus = dbus.SystemBus()
pol = bus.get_object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
auth = dbus.Interface(pol, "org.freedesktop.PolicyKit1.Authority")
subj = ("system-bus-name", {"name": dbus.String(bus.get_unique_name(), variant_level=1)})
for action in [
    "org.freedesktop.systemd1.manage-units",
    "org.freedesktop.systemd1.set-environment",
    "org.freedesktop.packagekit.trigger-offline-update",
    "org.freedesktop.packagekit.clear-offline-update",
]:
    try:
        res = auth.CheckAuthorization(subj, action, {}, 0, "", timeout=5)
        print(f"CanAuthorize {action} -> {int(res[0])}")
    except Exception as exc:
        print(f"CanAuthorize ERR {action}: {type(exc).__name__}: {exc}")

obj = bus.get_object("org.freedesktop.PackageKit", "/org/freedesktop/PackageKit")
off = dbus.Interface(obj, "org.freedesktop.PackageKit.Offline")
props = dbus.Interface(obj, "org.freedesktop.DBus.Properties")
try:
    print("Offline props before:", props.GetAll("org.freedesktop.PackageKit.Offline"))
except Exception as exc:
    print("Offline props before ERR:", exc)
try:
    print("GetPrepared:", off.GetPrepared())
except Exception as exc:
    print("GetPrepared ERR:", type(exc).__name__, exc)
try:
    print("Trigger reboot:", off.Trigger("reboot"))
except Exception as exc:
    print("Trigger reboot ERR:", type(exc).__name__, exc)
try:
    print("Offline props after:", props.GetAll("org.freedesktop.PackageKit.Offline"))
except Exception as exc:
    print("Offline props after ERR:", exc)
PY
for unit in systemd-sysupdate.service systemd-sysupdate-reboot.service systemd-repart.service packagekit-offline-update.service fwupd-offline-update.service system-update.target factory-reset.target; do
  echo "ACTIVE_UNIT=$unit"
  timeout 8 systemctl --no-ask-password start "$unit" 2>&1
  echo "active_systemctl_rc=$?"
done
for p in /system-update /etc/system-update /var/lib/PackageKit/offline-update-action /var/lib/PackageKit/prepared-update /var/lib/PackageKit/prepared-upgrade; do
  ls -l "$p" 2>&1 || true
done
exit
PROFILE
  chown selfauth:selfauth "$profile"
  systemctl stop getty@tty1.service >/dev/null 2>&1 || true
  timeout 75 openvt -c 1 -s -f -w -- /bin/login -f selfauth 2>&1
  echo "openvt_rc=$?"
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  if grep -qx present "$state" 2>/dev/null; then
    cp -a "$backup" "$profile"
  else
    rm -f "$profile"
  fi
  cat "$ACTIVE/user.out" 2>&1 || true
else
  echo "openvt or /dev/tty1 unavailable; active selfauth branch skipped"
fi

section "post-probe root proof and cleanup check"
for p in "$ROOT_MARKER" "$TMP_MARKER" /system-update /etc/system-update \
         /var/lib/PackageKit/offline-update-action /var/lib/PackageKit/prepared-update \
         /var/lib/PackageKit/prepared-upgrade /var/lib/fwupd/pending.db; do
  ls -l "$p" 2>&1 || true
done
systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend 2>&1 || true

rm -rf "$WORK" "$ACTIVE" "$TMP_MARKER"
exit 0
TARGET
