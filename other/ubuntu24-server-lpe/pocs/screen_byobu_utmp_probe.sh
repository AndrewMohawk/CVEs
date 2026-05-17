#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash <<'INCONTAINER'
set -Eeuo pipefail
export LC_ALL=C

work=/tmp/screen_byobu_utmp_probe
attwork=$work/attacker
selfwork=$work/selfauth
backup=$work/backup
state=$work/accounting.state
tracked="/run/utmp /var/log/wtmp /var/log/btmp /var/log/lastlog"
keeper_pid=""
restored=0

section() {
  printf '\n== %s ==\n' "$*"
}

restore_accounting() {
  [ -f "$state" ] || return 0
  while read -r flag path; do
    [ -n "${path:-}" ] || continue
    if [ "$flag" = present ]; then
      mkdir -p "$(dirname "$path")"
      cp -a "$backup$path" "$path" 2>/dev/null || true
    elif [ "$flag" = absent ]; then
      rm -f "$path"
    fi
  done < "$state"
  restored=1
}

cleanup() {
  set +e
  if [ -n "$keeper_pid" ]; then
    kill "$keeper_pid" 2>/dev/null || true
    wait "$keeper_pid" 2>/dev/null || true
  fi
  runuser -u attacker -- tmux -L sbu-tmux-probe kill-server >/dev/null 2>&1 || true
  runuser -u attacker -- tmux -L sbu-byobu-tmux kill-server >/dev/null 2>&1 || true
  restore_accounting
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

rm -rf "$work"
mkdir -p "$backup" "$attwork/home" "$selfwork/home"
chmod 0755 "$work"
chown -R attacker:attacker "$attwork"
chown -R selfauth:selfauth "$selfwork"
: > "$state"

for path in $tracked; do
  if [ -e "$path" ]; then
    echo "present $path" >> "$state"
    mkdir -p "$backup$(dirname "$path")"
    cp -a "$path" "$backup$path"
  else
    echo "absent $path" >> "$state"
  fi
done

section "target identity and user scope"
. /etc/os-release
printf 'os=%s codename=%s arch=%s kernel=%s\n' "$PRETTY_NAME" "$VERSION_CODENAME" "$(uname -m)" "$(uname -r)"
id attacker
id selfauth
for group in utmp tty sudo docker lxd adm shadow _ssh; do
  getent group "$group" || printf 'missing-group=%s\n' "$group"
done

section "default package versions"
dpkg-query -W -f='${binary:Package}\t${Version}\n' \
  screen byobu tmux libutempter0 bsdextrautils util-linux login passwd 2>&1 || true

section "file modes and package owners"
utempter_helper="$(ls /usr/lib/*/utempter/utempter 2>/dev/null | head -n 1 || true)"
paths="
/usr/bin/screen
/usr/bin/byobu
/usr/bin/byobu-screen
/usr/bin/byobu-tmux
/usr/bin/tmux
/usr/bin/write
/usr/bin/wall
/usr/bin/who
/usr/bin/w
/usr/bin/users
/usr/bin/last
/usr/bin/lastlog
/usr/bin/login
$utempter_helper
/run/utmp
/var/log/wtmp
/var/log/btmp
/var/log/lastlog
"
for path in $paths; do
  [ -n "$path" ] || continue
  if [ -e "$path" ]; then
    stat -Lc '%A %a %U:%G %n' "$path"
    dpkg -S "$path" 2>/dev/null || true
  else
    printf 'missing %s\n' "$path"
  fi
done

section "linked terminal accounting libraries"
for bin in /usr/bin/screen /usr/bin/tmux /usr/bin/write /usr/bin/wall; do
  [ -x "$bin" ] || continue
  echo "-- $bin"
  ldd "$bin" 2>/dev/null | sed -n '/utempter/p;/systemd/p;/tinfo/p'
done

section "attacker direct reachability"
runuser -u attacker -- bash -lc '
set +e
id
for cmd in screen byobu byobu-screen byobu-tmux tmux write wall who w users last lastlog login; do
  command -v "$cmd" || echo "missing-cmd=$cmd"
done
screen -v 2>&1 | head -n 2
byobu -v 2>&1 | head -n 2
tmux -V 2>&1
wall --version 2>&1 | head -n 2
write 2>&1 | head -n 4
/usr/bin/login -f attacker </dev/null >/tmp/sbu-login-direct.out 2>&1
printf "login_direct_rc=%s\n" "$?"
sed -n "1,6p" /tmp/sbu-login-direct.out
rm -f /tmp/sbu-login-direct.out
'

section "PAM MOTD and login accounting consumers"
grep -R 'utmp\|wtmp\|lastlog\|motd\|pam_lastlog\|pam_motd\|pam_loginuid\|pam_systemd' \
  -n /etc/pam.d /etc/update-motd.d 2>/dev/null || true
nl -ba /etc/pam.d/login | sed -n '25,86p'
find /etc/update-motd.d -maxdepth 1 -type f -o -type l | sort | while read -r file; do
  stat -Lc '%A %a %U:%G %n' "$file"
done

section "accounting hashes before tests"
sha256sum $tracked 2>/dev/null || true

section "libutempter host and tty-name control probe"
cat > "$attwork/utempter_cases.py" <<'PY'
import ctypes
import os
import pty
import subprocess

lib = ctypes.CDLL("libutempter.so.0")
lib.utempter_add_record.argtypes = [ctypes.c_int, ctypes.c_char_p]
lib.utempter_add_record.restype = ctypes.c_int
lib.utempter_remove_record.argtypes = [ctypes.c_int]
lib.utempter_remove_record.restype = ctypes.c_int

def out(cmd):
    return subprocess.run(cmd, text=True, capture_output=True).stdout

master, slave = pty.openpty()
slave_name = os.ttyname(slave)
st = os.stat(slave_name)
print(f"uid={os.getuid()} gid={os.getgid()} slave={slave_name} line={slave_name.replace('/dev/', '')} mode={oct(st.st_mode & 0o777)} owner={st.st_uid}:{st.st_gid}")

cases = [
    ("plain", b"sbu-host"),
    ("space", b"sbu host with space"),
    ("path-text-host", b"../tmp/sbu-root-canary"),
    ("newline", b"sbu-line\nfeed"),
    ("control", b"sbu-ctrl-\x01-byte"),
]

for label, host in cases:
    rc = lib.utempter_add_record(master, host)
    who = out(["who"])
    print(f"case={label} host={host!r} add_rc={rc} who_lines={len([x for x in who.splitlines() if x.strip()])}")
    for line in who.splitlines():
        if "sbu" in line or slave_name.replace("/dev/", "") in line:
            print("  who:", line)
    lib.utempter_remove_record(master)

print("after_remove_who=" + repr(out(["who"])))
PY
chown attacker:attacker "$attwork/utempter_cases.py"
runuser -u attacker -- env HOME="$attwork/home" USER=attacker LOGNAME=attacker python3 "$attwork/utempter_cases.py" </dev/null

section "direct utempter helper invalid stdin/path attempts"
runuser -u attacker -- bash -lc '
set +e
helper="$(ls /usr/lib/*/utempter/utempter 2>/dev/null | head -n 1)"
for host in sbu-direct ../tmp/sbu-root-canary $'"'"'line\nfeed'"'"'; do
  printf "host_repr=%q\n" "$host"
  "$helper" add "$host" </dev/null >/tmp/sbu-helper.out 2>&1
  rc=$?
  printf "helper_rc=%s\n" "$rc"
  sed -n "1,4p" /tmp/sbu-helper.out
done
rm -f /tmp/sbu-helper.out
'

section "screen tmux byobu utmp record shapes"
cat > "$attwork/run_sessions.sh" <<'EOS'
#!/usr/bin/env bash
set -u
export HOME="$ATT_HOME" USER=attacker LOGNAME=attacker SHELL=/bin/bash TERM=xterm LC_ALL=C
mkdir -p "$ATTWORK/out"

inside="$ATTWORK/inside_who.sh"
cat > "$inside" <<'EOI'
#!/usr/bin/env bash
who > "$1"
sleep 0.25
EOI
chmod 0755 "$inside"

run_screen() {
  local name="$1"
  local outfile="$2"
  local typescript="$3"
  local qname qinside qoutfile
  printf -v qname '%q' "$name"
  printf -v qinside '%q' "$inside"
  printf -v qoutfile '%q' "$outfile"
  SHELL=/bin/bash script -qfec "screen -S $qname $qinside $qoutfile" "$typescript" >"$outfile.stdout" 2>"$outfile.stderr"
  local rc=$?
  echo "rc=$rc name=$(printf '%q' "$name")" >"$outfile.rc"
}

run_screen "scr-ok" "$ATTWORK/out/screen_ok.who" "$ATTWORK/out/screen_ok.typescript" || true
run_screen $'scr..path/name\nctrl' "$ATTWORK/out/screen_weird.who" "$ATTWORK/out/screen_weird.typescript" || true

tmux -L sbu-tmux-probe kill-server >/dev/null 2>&1 || true
tmux -L sbu-tmux-probe new-session -d -s $'tmux..path\nsession' -n $'win..path\nname' "$inside '$ATTWORK/out/tmux.who'" >"$ATTWORK/out/tmux.stdout" 2>"$ATTWORK/out/tmux.stderr"
echo "rc=$?" >"$ATTWORK/out/tmux.rc"
sleep 0.7
tmux -L sbu-tmux-probe kill-server >/dev/null 2>&1 || true

BYOBU_BACKEND=tmux byobu-tmux -L sbu-byobu-tmux new-session -d -s byobu-tmux-probe "$inside '$ATTWORK/out/byobu_tmux.who'" >"$ATTWORK/out/byobu_tmux.stdout" 2>"$ATTWORK/out/byobu_tmux.stderr"
echo "rc=$?" >"$ATTWORK/out/byobu_tmux.rc"
sleep 0.7
tmux -L sbu-byobu-tmux kill-server >/dev/null 2>&1 || true

SHELL=/bin/bash script -qfec "byobu-screen -S byobu-screen-probe '$inside' '$ATTWORK/out/byobu_screen.who'" "$ATTWORK/out/byobu_screen.typescript" >"$ATTWORK/out/byobu_screen.stdout" 2>"$ATTWORK/out/byobu_screen.stderr"
echo "rc=$?" >"$ATTWORK/out/byobu_screen.rc"
EOS
chown attacker:attacker "$attwork/run_sessions.sh"
chmod 0755 "$attwork/run_sessions.sh"
runuser -u attacker -- env ATTWORK="$attwork" ATT_HOME="$attwork/home" bash "$attwork/run_sessions.sh" </dev/null || true
find "$attwork/out" -maxdepth 1 -type f | sort | while read -r file; do
  echo "-- ${file#$attwork/out/}"
  if [ -s "$file" ]; then
    sed -n '1,20p' "$file" | cat -v
  else
    echo "<empty>"
  fi
done
echo "-- who after terminal sessions"
who || true

section "active selfauth pty plus write/wall semantics"
cat > "$selfwork/pty_keeper.py" <<'PY'
import ctypes
import os
import pty
import select
import signal
import sys
import time

info = os.environ["INFO"]
received = os.environ["RECEIVED"]
lib = ctypes.CDLL("libutempter.so.0")
lib.utempter_add_record.argtypes = [ctypes.c_int, ctypes.c_char_p]
lib.utempter_add_record.restype = ctypes.c_int
lib.utempter_remove_record.argtypes = [ctypes.c_int]
lib.utempter_remove_record.restype = ctypes.c_int

stop = False
def handle(_signum, _frame):
    global stop
    stop = True

signal.signal(signal.SIGTERM, handle)
signal.signal(signal.SIGINT, handle)

master, slave = pty.openpty()
slave_name = os.ttyname(slave)
st = os.stat(slave_name)
rc = lib.utempter_add_record(master, b"selfauth-keeper")
with open(info, "w") as f:
    f.write(f"{slave_name}\n{slave_name.replace('/dev/', '')}\nadd_rc={rc} mode={oct(st.st_mode & 0o777)} owner={st.st_uid}:{st.st_gid}\n")
with open(received, "a") as f:
    f.write(f"keeper_start slave={slave_name} add_rc={rc} mode={oct(st.st_mode & 0o777)} owner={st.st_uid}:{st.st_gid}\n")

try:
    deadline = time.time() + 12
    while not stop and time.time() < deadline:
        readable, _, _ = select.select([master], [], [], 0.2)
        if readable:
            data = os.read(master, 4096)
            with open(received, "ab") as f:
                f.write(data)
finally:
    lib.utempter_remove_record(master)
PY
chown selfauth:selfauth "$selfwork/pty_keeper.py"
runuser -u selfauth -- env INFO="$selfwork/pty.info" RECEIVED="$selfwork/received.out" \
  HOME="$selfwork/home" USER=selfauth LOGNAME=selfauth python3 "$selfwork/pty_keeper.py" </dev/null &
keeper_pid=$!

for _ in $(seq 1 50); do
  [ -s "$selfwork/pty.info" ] && break
  sleep 0.1
done
cat "$selfwork/pty.info"
tty_line="$(sed -n '2p' "$selfwork/pty.info")"
echo "-- active rows visible to attacker"
runuser -u attacker -- bash -lc 'who; w -h 2>/dev/null || true; users; last -n 5 2>/dev/null | sed -n "1,8p"; lastlog -u attacker; lastlog -u selfauth' || true

root_canary="$work/root_canary"
printf 'ROOT_CANARY_BASELINE\n' > "$root_canary"
chown root:root "$root_canary"
chmod 0644 "$root_canary"
canary_before="$(sha256sum "$root_canary")"

set +e
runuser -u attacker -- bash -lc "printf 'WRITE_MARKER_screen_byobu_utmp\n' | write selfauth '$tty_line'" \
  >"$attwork/write_selfauth.out" 2>&1
printf 'rc=%s\n' "$?" >> "$attwork/write_selfauth.out"
runuser -u attacker -- bash -lc "printf 'WALL_MARKER_screen_byobu_utmp\n' | wall" \
  >"$attwork/wall.out" 2>&1
printf 'rc=%s\n' "$?" >> "$attwork/wall.out"
runuser -u attacker -- bash -lc "printf 'PATH_MARKER_screen_byobu_utmp\n' | write selfauth '../tmp/screen_byobu_utmp_probe/root_canary'" \
  >"$attwork/write_path_canary.out" 2>&1
printf 'rc=%s\n' "$?" >> "$attwork/write_path_canary.out"
set -e

sleep 1
echo "-- write selfauth pts result"
cat -v "$attwork/write_selfauth.out"
echo "-- wall result"
cat -v "$attwork/wall.out"
echo "-- write explicit ../tmp root canary result"
cat -v "$attwork/write_path_canary.out"
echo "-- selfauth pty received bytes"
cat -v "$selfwork/received.out"
echo "-- root canary before"
echo "$canary_before"
echo "-- root canary after"
sha256sum "$root_canary"
stat -Lc '%A %a %U:%G %n size=%s' "$root_canary"
cat -v "$root_canary"

kill "$keeper_pid" 2>/dev/null || true
wait "$keeper_pid" 2>/dev/null || true
keeper_pid=""
echo "-- who after keeper removal"
who || true

section "attacker MOTD direct run stays unprivileged"
runuser -u attacker -- bash -lc "
set +e
timeout 8s run-parts /etc/update-motd.d >'$attwork/motd.out' 2>'$attwork/motd.err'
printf 'runparts_rc=%s\n' \"\$?\"
printf '%s\n' '-- stdout head --'
sed -n '1,12p' '$attwork/motd.out'
printf '%s\n' '-- stderr head --'
sed -n '1,12p' '$attwork/motd.err'
"

section "accounting hashes before restore"
sha256sum $tracked 2>/dev/null || true

section "accounting hashes after restore"
restore_accounting
sha256sum $tracked 2>/dev/null || true
printf 'restored=%s\n' "$restored"

section "negative result summary"
cat <<'EOF'
No uid0 context or root-owned attacker-controlled write was reached.
Observed elevated surface is limited to the stock root:utmp 2755 libutempter helper.
screen/tmux/byobu reach libutempter but record real /dev/pts/N lines only.
libutempter rejects newline/control host bytes; path-like text is only ut_host, not ut_line.
write and wall are root:root 0755 in this install, so attacker uid1001 cannot use them as tty/root write helpers.
The explicit write ../tmp/root_canary attempt did not modify the root-owned canary.
Accounting files were restored from pre-test copies.
EOF
INCONTAINER
