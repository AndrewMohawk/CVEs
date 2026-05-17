#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

de() {
  docker exec "$container" bash -lc "$1"
}

echo "== os/package proof =="
de 'cat /etc/os-release | sed -n "1,8p"; dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" uuid-runtime util-linux libuuid1'

echo
echo "== default unit/socket state =="
de 'systemctl status uuidd.socket uuidd.service --no-pager || true; systemctl is-enabled uuidd.socket uuidd.service || true'

echo
echo "== default paths =="
de 'stat -Lc "%F %a %u:%g %U:%G %n" /run/uuidd /run/uuidd/request /var/lib/libuuid 2>&1 || true'

echo
echo "== unprivileged reachability =="
de 'runuser -u attacker -- id; runuser -u attacker -- /usr/sbin/uuidd --time --uuids 2; runuser -u attacker -- /usr/sbin/uuidd --random --uuids 2'

echo
echo "== daemon identity/state after activation =="
de 'ps -eo user:20,uid,pid,ppid,comm,args | grep -E "[u]uidd|PID" || true; stat -Lc "%F %a %u:%g %U:%G %n" /var/lib/libuuid /var/lib/libuuid/* 2>&1 || true'

echo
echo "== attacker write/replacement checks =="
de 'for p in /run/uuidd /run/uuidd/request /var/lib/libuuid /var/lib/libuuid/clock.txt; do echo "-- $p --"; runuser -u attacker -- test -r "$p"; echo read_rc=$?; runuser -u attacker -- test -w "$p"; echo write_rc=$?; done'
de 'runuser -u attacker -- bash -lc "touch /var/lib/libuuid/attacker-write-test 2>&1"; echo varlib_touch_rc=$?; rm -f /var/lib/libuuid/attacker-write-test'
de 'runuser -u attacker -- bash -lc "ln -s /etc/shadow /var/lib/libuuid/attacker-link-test 2>&1"; echo varlib_symlink_rc=$?; rm -f /var/lib/libuuid/attacker-link-test'
de 'runuser -u attacker -- bash -lc "rm -f /run/uuidd/request 2>&1"; echo run_socket_unlink_rc=$?'

echo
echo "== malformed request survivability =="
de 'runuser -u attacker -- timeout 3 python3 - <<'"'"'PY'"'"'
import socket, struct
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1.0)
s.connect("/run/uuidd/request")
s.sendall(struct.pack("ii", 0x7fffffff, 1))
try:
    data = s.recv(64)
    print("recv_len=%d recv_hex=%s" % (len(data), data.hex()))
except Exception as e:
    print("recv_error=%s:%s" % (type(e).__name__, e))
PY
rc=$?; echo malformed_rc=$rc; systemctl is-active uuidd.service uuidd.socket || true'
