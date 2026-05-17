#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/polkit-allow-active-gap.out"
target_work="/tmp/polkit-allow-active-gap"

mkdir -p "$repo_dir/logs"

docker exec -i "$container" bash -s <<'ROOTSH'
set +e

WORK=/tmp/polkit-allow-active-gap
OUT=$WORK/probe.out
MARKER=/root/polkit_allow_active_gap_root
USER=selfauth
TTYNUM=7
USER_HOME=/home/$USER
USER_PROBE=$USER_HOME/polkit-allow-active-gap-user.sh
PROFILE=$USER_HOME/.bash_profile
PROFILE_BAK=$WORK/bash_profile.bak
PROFILE_STATE=$WORK/profile_state

rm -rf "$WORK" "$MARKER"
mkdir -m 1777 -p "$WORK"
: >"$OUT"
chmod 0666 "$OUT"

section() {
  printf '\n## %s\n' "$1" >>"$OUT"
}

cleanup_target() {
  set +e
  loginctl terminate-user "$USER" >/dev/null 2>&1 || true
  systemctl start "getty@tty${TTYNUM}.service" >/dev/null 2>&1 || true
  if [ -f "$PROFILE_STATE" ] && grep -qx existed "$PROFILE_STATE"; then
    cp -a "$PROFILE_BAK" "$PROFILE" 2>/dev/null || true
    chown "$USER:$USER" "$PROFILE" 2>/dev/null || true
  else
    rm -f "$PROFILE"
  fi
  for dev in $(losetup -j "$WORK/active-loop.img" 2>/dev/null | cut -d: -f1); do
    losetup -d "$dev" >/dev/null 2>&1 || true
  done
  rm -f "$USER_PROBE" "$WORK/active-loop.img"
  rm -f "$MARKER"
}
trap cleanup_target EXIT

if ! id "$USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USER"
fi
echo "$USER:$USER" | chpasswd

if [ -e "$PROFILE" ]; then
  cp -a "$PROFILE" "$PROFILE_BAK"
  echo existed >"$PROFILE_STATE"
else
  echo absent >"$PROFILE_STATE"
fi

section "target identity and package state"
{
  cat /etc/os-release | sed -n '1,8p'
  uname -a
  id attacker 2>&1 || true
  id "$USER" 2>&1 || true
  getent group sudo adm docker lxd disk input tty 2>&1 || true
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    dbus polkitd systemd libpam-systemd udisks2 libudisks2-0 packagekit \
    modemmanager fwupd update-notifier-common pkexec policykit-1 2>&1 | sort
} >>"$OUT" 2>&1

section "live allow_active=yes and auth_self action inventory"
python3 - <<'PY' >>"$OUT" 2>&1
import glob
import subprocess
import xml.etree.ElementTree as ET

focus = {
    "org.freedesktop.udisks2.power-off-drive",
    "org.freedesktop.udisks2.eject-media",
    "org.freedesktop.udisks2.modify-device",
    "org.freedesktop.udisks2.rescan",
    "org.freedesktop.udisks2.ata-smart-update",
    "org.freedesktop.udisks2.nvme-smart-update",
    "org.freedesktop.udisks2.cancel-job",
}

rows = []
auth_self = []
for path in sorted(glob.glob("/usr/share/polkit-1/actions/*.policy")):
    try:
        pkg = subprocess.check_output(
            ["dpkg-query", "-S", path],
            text=True,
            stderr=subprocess.DEVNULL,
        ).split(":", 1)[0]
    except Exception:
        pkg = "unknown"
    root = ET.parse(path).getroot()
    for action in root.findall("action"):
        aid = action.get("id")
        vals = {}
        for key in ("allow_any", "allow_inactive", "allow_active"):
            node = action.find("defaults/" + key)
            vals[key] = (node.text or "").strip() if node is not None else ""
        if any("auth_self" in v for v in vals.values()):
            auth_self.append((aid, pkg, path, vals))
        if vals["allow_active"] == "yes" or any("auth_self" in v for v in vals.values()):
            if aid in focus:
                tag = "probe-focus"
            elif aid.startswith("org.freedesktop.udisks2."):
                tag = "udisks-covered-adjacent"
            elif aid.startswith("org.freedesktop.packagekit."):
                tag = "packagekit-covered"
            elif aid.startswith("org.freedesktop.login1."):
                tag = "login1-covered"
            elif aid.startswith("org.freedesktop.ModemManager1."):
                tag = "modemmanager-condition-gated"
            elif aid.startswith("org.freedesktop.fwupd."):
                tag = "fwupd-condition-gated"
            elif aid.startswith("com.ubuntu.update-notifier."):
                tag = "pkexec-absent"
            else:
                tag = "unclassified"
            rows.append((tag, aid, pkg, path, vals))

for tag, aid, pkg, path, vals in sorted(rows):
    print(f"{tag}\t{aid}\tpkg={pkg}\tany={vals['allow_any']}\tinactive={vals['allow_inactive']}\tactive={vals['allow_active']}\t{path}")

if auth_self:
    print("[auth_self]")
    for aid, pkg, path, vals in auth_self:
        print(f"{aid}\tpkg={pkg}\tany={vals['allow_any']}\tinactive={vals['allow_inactive']}\tactive={vals['allow_active']}\t{path}")
else:
    print("[auth_self] none")
PY

section "default service and object reachability"
{
  busctl --system list --no-pager | grep -E 'UDisks2|PackageKit|login1|ModemManager|fwupd|PolicyKit|update|systemd1' || true
  echo
  for unit in udisks2.service packagekit.service systemd-logind.service ModemManager.service fwupd.service polkit.service dbus.service; do
    echo "### $unit"
    systemctl show "$unit" -p LoadState -p ActiveState -p SubState -p UnitFileState -p ConditionResult -p ExecStart -p User --no-pager 2>&1
  done
  echo
  command -v pkexec || echo "pkexec=ABSENT"
  echo
  echo "UDisks tree:"
  busctl --system tree org.freedesktop.UDisks2 --list 2>&1 | sed -n '1,220p'
  echo
  echo "Drive properties:"
  for d in /org/freedesktop/UDisks2/drives/VirtIO_Disk /org/freedesktop/UDisks2/drives/VirtIO_Disk_1; do
    echo "### $d"
    busctl --system get-property org.freedesktop.UDisks2 "$d" org.freedesktop.UDisks2.Drive Model 2>&1
    busctl --system get-property org.freedesktop.UDisks2 "$d" org.freedesktop.UDisks2.Drive Seat 2>&1
    busctl --system get-property org.freedesktop.UDisks2 "$d" org.freedesktop.UDisks2.Drive CanPowerOff 2>&1
    busctl --system get-property org.freedesktop.UDisks2 "$d" org.freedesktop.UDisks2.Drive Ejectable 2>&1
    busctl --system get-property org.freedesktop.UDisks2 "$d" org.freedesktop.UDisks2.Drive Configuration 2>&1
  done
} >>"$OUT" 2>&1

section "root-owned state before"
{
  ls -l "$MARKER" 2>&1 || true
  find /etc/udisks2 /var/lib/udisks2 /run/udisks2 -maxdepth 3 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
  findmnt -rn -o SOURCE,TARGET,FSTYPE,OPTIONS | sed -n '1,80p'
  lsblk -o NAME,MAJ:MIN,TYPE,SIZE,MOUNTPOINTS,FSTYPE,LABEL,MODEL,TRAN,RO,RM | sed -n '1,120p'
} >>"$OUT" 2>&1

cat >"$USER_PROBE" <<'USERPROBE'
#!/usr/bin/env bash
set +e

WORK=/tmp/polkit-allow-active-gap
OUT=$WORK/probe.out
IMG=$WORK/active-loop.img
exec >>"$OUT" 2>&1

section() {
  printf '\n## %s\n' "$1"
}

section "active tty subject"
id
tty
printf 'XDG_SESSION_ID=%s\n' "${XDG_SESSION_ID:-}"
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" \
    -p Id -p Name -p User -p Path -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote -p Leader 2>&1
fi
groups

section "active pkcheck for probe-focus UDisks actions"
for action in \
  org.freedesktop.udisks2.power-off-drive \
  org.freedesktop.udisks2.eject-media \
  org.freedesktop.udisks2.modify-device \
  org.freedesktop.udisks2.rescan \
  org.freedesktop.udisks2.ata-smart-update \
  org.freedesktop.udisks2.nvme-smart-update \
  org.freedesktop.udisks2.cancel-job; do
  printf '### %s\n' "$action"
  timeout 6 pkcheck --action-id "$action" --process "$$" >/tmp/polkit-allow-active-gap/pkcheck.out 2>&1
  rc=$?
  sed -n '1,20p' /tmp/polkit-allow-active-gap/pkcheck.out
  printf 'rc=%s\n' "$rc"
done

section "UDisks residual control method semantics"
truncate -s 8M "$IMG"
python3 - <<'PY'
import os
import subprocess
import sys
import traceback

import dbus
import dbus.types

BUS = "org.freedesktop.UDisks2"
WORK = "/tmp/polkit-allow-active-gap"
IMG = os.path.join(WORK, "active-loop.img")

bus = dbus.SystemBus()

def obj(path):
    return bus.get_object(BUS, path)

def props(path, iface):
    return dbus.Interface(obj(path), "org.freedesktop.DBus.Properties").GetAll(iface)

def call(label, fn):
    print(f"CALL {label}", flush=True)
    try:
        ret = fn()
        print(f"  OK {ret!r}", flush=True)
        return ret
    except dbus.exceptions.DBusException as exc:
        print(f"  FAIL {exc.get_dbus_name()}: {exc}", flush=True)
    except Exception as exc:
        print(f"  FAIL {type(exc).__name__}: {exc}", flush=True)
        traceback.print_exc()
    return None

def variant_dict(d=None):
    d = d or {}
    return dbus.Dictionary(d, signature="sv")

print("dbus uid=%d euid=%d" % (os.getuid(), os.geteuid()), flush=True)
print("lsblk snapshot:")
subprocess.run(["lsblk", "-o", "NAME,MAJ:MIN,TYPE,SIZE,MOUNTPOINTS,FSTYPE,LABEL,RO,RM"], check=False)

manager = dbus.Interface(obj("/org/freedesktop/UDisks2/Manager"), "org.freedesktop.UDisks2.Manager")
loop_path = None
fd = os.open(IMG, os.O_RDWR)
try:
    loop_path = call(
        "Manager.LoopSetup(user-owned 8M image)",
        lambda: manager.LoopSetup(dbus.types.UnixFd(fd), variant_dict({"read-only": dbus.Boolean(False, variant_level=1)})),
    )
finally:
    os.close(fd)

block_paths = [
    "/org/freedesktop/UDisks2/block_devices/vdb",
    "/org/freedesktop/UDisks2/block_devices/vda1",
]
if loop_path:
    block_paths.insert(0, str(loop_path))

for path in block_paths:
    print(f"BLOCK {path}")
    try:
        bp = props(path, "org.freedesktop.UDisks2.Block")
        print("  Device=%r Drive=%s IdUsage=%s IdType=%s HintSystem=%s" % (
            bytes(bp.get("Device", b"")).split(b"\0", 1)[0],
            bp.get("Drive"),
            bp.get("IdUsage"),
            bp.get("IdType"),
            bp.get("HintSystem"),
        ))
    except Exception as exc:
        print(f"  props failed: {exc}")
        continue
    block = dbus.Interface(obj(path), "org.freedesktop.UDisks2.Block")
    call(f"{path}.Block.Rescan({{}})", lambda block=block: block.Rescan(variant_dict()))
    call(f"{path}.Block.OpenDevice('r', {{}})", lambda block=block: block.OpenDevice("r", variant_dict()))

drive_paths = [
    "/org/freedesktop/UDisks2/drives/VirtIO_Disk_1",
    "/org/freedesktop/UDisks2/drives/VirtIO_Disk",
]
for path in drive_paths:
    print(f"DRIVE {path}")
    try:
        dp = props(path, "org.freedesktop.UDisks2.Drive")
        print("  Model=%s Seat=%s CanPowerOff=%s Ejectable=%s Removable=%s Configuration=%r" % (
            dp.get("Model"),
            dp.get("Seat"),
            dp.get("CanPowerOff"),
            dp.get("Ejectable"),
            dp.get("Removable"),
            dict(dp.get("Configuration", {})),
        ))
    except Exception as exc:
        print(f"  props failed: {exc}")
        continue
    drive = dbus.Interface(obj(path), "org.freedesktop.UDisks2.Drive")
    if bool(dp.get("CanPowerOff")):
        print("  SKIP PowerOff because CanPowerOff=true")
    else:
        call(f"{path}.Drive.PowerOff({{}})", lambda drive=drive: drive.PowerOff(variant_dict()))
    if bool(dp.get("Ejectable")):
        print("  SKIP Eject because Ejectable=true")
    else:
        call(f"{path}.Drive.Eject({{}})", lambda drive=drive: drive.Eject(variant_dict()))
    marker = dbus.String("polkit-allow-active-gap", variant_level=1)
    config = variant_dict({"x-probe-marker": marker})
    call(f"{path}.Drive.SetConfiguration(marker dict)", lambda drive=drive, config=config: drive.SetConfiguration(config, variant_dict()))

print("Job objects:")
subprocess.run(["busctl", "--system", "tree", BUS, "--list"], check=False)

if loop_path:
    loop = dbus.Interface(obj(str(loop_path)), "org.freedesktop.UDisks2.Loop")
    call(f"{loop_path}.Loop.Delete({{}})", lambda: loop.Delete(variant_dict()))
PY

section "state after active method calls"
find /etc/udisks2 /var/lib/udisks2 /run/udisks2 -maxdepth 3 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
grep -RIn 'polkit-allow-active-gap\|x-probe-marker' /etc/udisks2 /var/lib/udisks2 /run/udisks2 2>/dev/null || true
losetup -a 2>/dev/null | grep polkit-allow-active-gap || true
ls -l /root/polkit_allow_active_gap_root 2>&1 || true
USERPROBE

chown "$USER:$USER" "$USER_PROBE"
chmod 0755 "$USER_PROBE"
cat >"$PROFILE" <<EOF
"$USER_PROBE"
exit
EOF
chown "$USER:$USER" "$PROFILE"
chmod 0644 "$PROFILE"

section "launch active tty selfauth probe"
{
  systemctl stop "getty@tty${TTYNUM}.service" 2>&1 || true
  timeout 75 openvt -c "$TTYNUM" -s -f -w -- /bin/login -f "$USER" 2>&1
  echo "openvt_rc=$?"
} >>"$OUT" 2>&1

section "root proof and cleanup precheck"
{
  if [ -e "$MARKER" ]; then
    echo "ROOT_PROOF=yes"
    ls -l "$MARKER"
    cat "$MARKER"
  else
    echo "ROOT_PROOF=no"
    ls -l "$MARKER" 2>&1 || true
  fi
  grep -RIn 'polkit-allow-active-gap\|x-probe-marker' /etc/udisks2 /var/lib/udisks2 /run/udisks2 2>/dev/null || true
  losetup -a 2>/dev/null | grep polkit-allow-active-gap || true
  systemctl is-system-running 2>&1 || true
  systemctl --failed --no-legend 2>&1 || true
} >>"$OUT" 2>&1

cleanup_target
trap - EXIT

section "cleanup verification"
{
  loginctl list-sessions --no-legend 2>&1 | grep "$USER" || true
  ls -l "$MARKER" 2>&1 || true
  grep -RIn 'polkit-allow-active-gap\|x-probe-marker' /etc/udisks2 /var/lib/udisks2 /run/udisks2 2>/dev/null || true
  losetup -a 2>/dev/null | grep polkit-allow-active-gap || true
  systemctl is-system-running 2>&1 || true
  systemctl --failed --no-legend 2>&1 || true
} >>"$OUT" 2>&1
ROOTSH

docker exec "$container" cat "$target_work/probe.out" > "$log_path"
docker exec "$container" rm -rf "$target_work"
sed -n '1,520p' "$log_path"
