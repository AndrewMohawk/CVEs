#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$target" bash -s <<'INNER'
set +e

tmp=/tmp/apparmor_console_probe
rm -rf "$tmp"
mkdir -p "$tmp"
trap 'rm -rf "$tmp" /tmp/codex-aa-profile.* /tmp/codex-apparmor-console-*' EXIT INT TERM

echo "## target"
sed -n '1,8p' /etc/os-release
uname -a
getent passwd attacker selfauth
id attacker
id selfauth
groups attacker
groups selfauth

echo "## package versions"
for pkg in apparmor apparmor-utils libapparmor1 console-setup console-setup-linux keyboard-configuration kbd systemd systemd-sysv plymouth; do
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null \
    || printf '%s\tnot-installed\n' "$pkg"
done
dpkg-query -S /usr/sbin/aa-load /usr/sbin/apparmor_parser /usr/bin/aa-enabled /usr/bin/aa-exec /usr/sbin/aa-status 2>/dev/null || true

echo "## default unit state"
systemctl --no-pager --plain list-unit-files \
  apparmor.service \
  systemd-binfmt.service \
  systemd-sysctl.service \
  systemd-modules-load.service \
  systemd-tmpfiles-setup.service \
  systemd-tmpfiles-setup-dev.service \
  console-setup.service \
  keyboard-setup.service \
  setvtrgb.service \
  plymouth-start.service \
  plymouth-quit.service \
  plymouth-quit-wait.service \
  plymouth-read-write.service 2>&1
for u in \
  apparmor.service \
  systemd-binfmt.service \
  systemd-sysctl.service \
  systemd-modules-load.service \
  systemd-tmpfiles-setup.service \
  systemd-tmpfiles-setup-dev.service \
  console-setup.service \
  keyboard-setup.service \
  setvtrgb.service \
  plymouth-start.service \
  plymouth-quit.service \
  plymouth-quit-wait.service \
  plymouth-read-write.service
do
  printf '%s\t' "$u"
  systemctl is-enabled "$u" 2>/dev/null || true
  printf '\t'
  systemctl is-active "$u" 2>/dev/null || true
done

echo "## apparmor service and status"
aa-status 2>&1 || true
systemctl --no-pager --plain --full status apparmor.service 2>&1 | sed -n '1,35p'
systemctl --no-pager --plain cat apparmor.service 2>&1 | sed -n '1,80p'
nl -ba /lib/apparmor/apparmor.systemd | sed -n '72,98p'
nl -ba /etc/apparmor/parser.conf | sed -n '20,45p'

echo "## root-owned inputs and setup directories"
for p in \
  /etc/apparmor \
  /etc/apparmor.d \
  /etc/apparmor/parser.conf \
  /var/cache/apparmor \
  /lib/apparmor/apparmor.systemd \
  /sys/kernel/security \
  /sys/kernel/security/apparmor \
  /sys/kernel/security/apparmor/.load \
  /etc/binfmt.d \
  /run/binfmt.d \
  /usr/lib/binfmt.d \
  /etc/sysctl.d \
  /run/sysctl.d \
  /usr/lib/sysctl.d \
  /etc/modules-load.d \
  /run/modules-load.d \
  /usr/lib/modules-load.d \
  /etc/tmpfiles.d \
  /run/tmpfiles.d \
  /usr/lib/tmpfiles.d \
  /run/credentials \
  /etc/default/keyboard \
  /etc/default/console-setup \
  /etc/console-setup \
  /etc/console-setup/cached_setup_keyboard.sh \
  /etc/vtrgb \
  /sbin/setvtrgb \
  /dev/tty0 \
  /dev/tty \
  /run/plymouth \
  /run/plymouth/socket \
  /run/systemd/seats \
  /run/systemd/sessions
do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -c '%A %U:%G %F %n -> %N' "$p"
  else
    echo "MISSING $p"
  fi
done

echo "## file capabilities"
getcap -r /sbin /usr/sbin /usr/bin /lib/apparmor 2>/dev/null \
  | grep -E 'apparmor|aa-|setupcon|loadkeys|setvtrgb|plymouth|systemd-(binfmt|sysctl|modules-load|tmpfiles)' \
  || echo "no relevant file capabilities"

probe_user() {
  user="$1"
  echo "## unprivileged probes as $user"
  runuser -u "$user" -- bash -s <<'USERPROBE'
set +e
echo "identity: $(id)"
profile="/tmp/codex-aa-profile.$$"
cat > "$profile" <<'EOF'
#include <tunables/global>
profile codex-aa-probe /bin/true {
  file,
}
EOF

for p in \
  /etc/apparmor.d/codex-test \
  /var/cache/apparmor/codex-test \
  /etc/binfmt.d/codex-test.conf \
  /run/binfmt.d/codex-test.conf \
  /etc/sysctl.d/99-codex-test.conf \
  /run/sysctl.d/99-codex-test.conf \
  /etc/modules-load.d/codex-test.conf \
  /run/modules-load.d/codex-test.conf \
  /etc/tmpfiles.d/codex-test.conf \
  /run/tmpfiles.d/codex-test.conf \
  /etc/default/keyboard \
  /etc/default/console-setup \
  /etc/console-setup/cached_setup_keyboard.sh \
  /etc/vtrgb \
  /run/credentials/systemd-sysctl.service/codex
do
  printf 'WRITE %s: ' "$p"
  (printf test > "$p") >/tmp/codex-apparmor-console-write.out 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "OK"
  else
    tr '\n' ' ' </tmp/codex-apparmor-console-write.out
    echo " rc=$rc"
  fi
done

for u in apparmor.service systemd-binfmt.service systemd-sysctl.service systemd-modules-load.service systemd-tmpfiles-setup.service systemd-tmpfiles-setup-dev.service console-setup.service keyboard-setup.service setvtrgb.service plymouth-start.service; do
  printf 'START %s: ' "$u"
  timeout 5 systemctl start "$u" >/tmp/codex-apparmor-console-systemctl.out 2>&1
  rc=$?
  tr '\n' ' ' </tmp/codex-apparmor-console-systemctl.out | cut -c1-220
  echo " rc=$rc"
done

for cmd in \
  "aa-enabled" \
  "aa-status" \
  "aa-exec -p unconfined -- /usr/bin/id" \
  "apparmor_parser -r $profile" \
  "apparmor_parser -Q -r $profile" \
  "aa-load $profile" \
  "aa-remove-unknown" \
  "aa-teardown" \
  "/usr/lib/systemd/systemd-binfmt" \
  "/usr/lib/systemd/systemd-sysctl" \
  "/usr/lib/systemd/systemd-modules-load" \
  "systemd-tmpfiles --create --boot --prefix=/tmp/codex-tmpfiles-nothing" \
  "setupcon --save" \
  "loadkeys /etc/console-setup/cached_UTF-8_del.kmap.gz" \
  "/usr/sbin/setvtrgb /etc/vtrgb" \
  "plymouth --ping"
do
  printf 'CMD %s: ' "$cmd"
  timeout 5 bash -lc "$cmd" >/tmp/codex-apparmor-console-helper.out 2>&1
  rc=$?
  tr '\n' ' ' </tmp/codex-apparmor-console-helper.out | cut -c1-260
  echo " rc=$rc"
done

for p in /dev/tty0 /dev/tty /run/plymouth/socket /run/systemd/seats /run/systemd/sessions; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    printf 'ACCESS %s ' "$p"
    [ -r "$p" ] && printf r || printf -
    [ -w "$p" ] && printf w || printf -
    [ -x "$p" ] && printf x || printf -
    echo
  else
    echo "MISSING $p"
  fi
done

rm -f "$profile" /tmp/codex-apparmor-console-write.out /tmp/codex-apparmor-console-systemctl.out /tmp/codex-apparmor-console-helper.out
USERPROBE
}

probe_user attacker
probe_user selfauth

echo "## login/session state"
loginctl --no-pager list-sessions 2>&1 || true
loginctl --no-pager user-status selfauth 2>&1 | sed -n '1,40p' || true
find /run/systemd/seats /run/systemd/sessions -maxdepth 1 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

echo "## cleanup verification"
find /tmp -maxdepth 1 \( -name 'codex-aa-profile.*' -o -name 'codex-apparmor-console-*' \) -print
INNER
