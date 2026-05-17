#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/undercovered-user-cli-packages.out"
tmp_log="$(mktemp "$repo_dir/logs/undercovered-user-cli-packages.out.tmp.XXXXXX")"

docker exec -i "$container" bash <<'TARGET' >"$tmp_log" 2>&1
set +e

section() {
  printf '\n## %s\n' "$1"
}

pkgs='pastebinit run-one xdg-user-dirs overlayroot unminimize sosreport'

section "target and package proof"
sed -n '1,8p' /etc/os-release
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' $pkgs 2>&1 | sort

section "default root launcher search"
systemctl --no-pager --plain list-units --all --type=service --type=timer --type=socket |
  grep -Ei 'pastebinit|run-one|xdg-user-dirs|overlayroot|unminimize|sos|sosreport' || true
grep -RInE 'pastebinit|pbput|pbget|pbputs|run-one|xdg-user-dir|overlayroot|unminimize|sosreport|sos-collector|/usr/bin/sos\b' \
  /etc /usr/lib/systemd /lib/systemd /usr/lib/tmpfiles.d /usr/lib/sysusers.d /usr/share/dbus-1 /usr/share/polkit-1 \
  2>/dev/null | sed -n '1,220p'

section "relevant files and maintainer scripts"
for p in $pkgs; do
  echo "### $p"
  dpkg -L "$p" 2>/dev/null | grep -E '(^/usr/bin/|^/usr/sbin/|^/etc/|systemd|cron|tmpfiles|logrotate|dbus|polkit)' | sed -n '1,120p'
  for s in preinst postinst prerm postrm triggers conffiles; do
    f="/var/lib/dpkg/info/$p.$s"
    [ -e "$f" ] && { echo "--- $f"; nl -ba "$f" | sed -n '1,120p'; }
  done
done

section "file modes and attacker writeability"
for p in \
  /usr/bin/pastebinit /usr/bin/pbput /usr/bin/pbget /usr/bin/pbputs \
  /usr/bin/run-one /usr/bin/run-this-one /usr/bin/keep-one-running \
  /usr/bin/run-one-constantly /usr/bin/run-one-until-success /usr/bin/run-one-until-failure \
  /usr/bin/xdg-user-dir /usr/bin/xdg-user-dirs-update \
  /usr/sbin/overlayroot-chroot /etc/update-motd.d/97-overlayroot /etc/overlayroot.conf \
  /usr/bin/unminimize /etc/update-motd.d/60-unminimize \
  /usr/bin/sos /usr/bin/sosreport /usr/bin/sos-collector /etc/sos /etc/sos/extras.d \
  /etc/sos/groups.d /etc/sos/presets.d /etc/xdg /usr/local /usr/local/sbin /dev/shm; do
  [ -e "$p" ] && stat -Lc '%A %a %U:%G %F %n' "$p"
done
runuser -u attacker -- bash -lc '
set +e
id
for p in /etc/sos /etc/sos/extras.d /etc/sos/groups.d /etc/sos/presets.d /etc/xdg /usr/local /usr/local/sbin /etc/overlayroot.conf /dev/shm; do
  [ -e "$p" ] || continue
  printf "%s: " "$p"
  test -w "$p" && echo writable || echo not-writable
done
'

section "non-privileged direct execution checks"
runuser -u attacker -- bash -lc '
set +e
rm -rf /tmp/undercovered-user-cli /dev/shm/run-one_attacker_probe
mkdir -p /tmp/undercovered-user-cli /dev/shm/run-one_attacker_probe
id
echo "### pastebinit help only, no upload"
pastebinit --help 2>&1 | sed -n "1,14p"
echo "pastebinit_help_rc=${PIPESTATUS[0]}"
echo "### run-one caller-owned lock path"
HOME=/home/attacker run-one /bin/sh -c "id > /tmp/undercovered-user-cli/run-one.id"
echo "run_one_rc=$?"
cat /tmp/undercovered-user-cli/run-one.id 2>/dev/null || true
find /home/attacker/.cache/run-one /dev/shm -maxdepth 2 -name "run-one*" -o -name ".cache" 2>/dev/null | sed -n "1,40p"
echo "### xdg-user-dirs user context"
XDG_CONFIG_HOME=/tmp/undercovered-user-cli/xdg xdg-user-dir DESKTOP 2>&1
echo "xdg_user_dir_rc=$?"
xdg-user-dirs-update --dummy-output /tmp/undercovered-user-cli/user-dirs.dirs 2>&1
echo "xdg_update_rc=$?"
stat -Lc "%A %U:%G %n" /tmp/undercovered-user-cli/user-dirs.dirs 2>/dev/null || true
echo "### overlayroot and unminimize"
overlayroot-chroot /bin/id 2>&1 | sed -n "1,8p"
echo "overlayroot_chroot_rc=${PIPESTATUS[0]}"
timeout 3 unminimize </dev/null 2>&1 | sed -n "1,12p"
echo "unminimize_rc=${PIPESTATUS[0]}"
echo "### sos non-root gate"
sos report --batch --tmp-dir /tmp/undercovered-user-cli/sos --quiet 2>&1 | sed -n "1,16p"
echo "sos_report_rc=${PIPESTATUS[0]}"
'

section "post-check cleanup and health"
rm -rf /tmp/undercovered-user-cli /dev/shm/run-one_attacker_probe /home/attacker/.cache/run-one
systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend 2>&1 || true
TARGET

mv "$tmp_log" "$log_path"
sed -n '1,420p' "$log_path"
