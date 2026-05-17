#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -euo pipefail

marker=/root/pam_namespace_user_runtime_root_marker
work=/home/attacker/pam_namespace_user_runtime

cleanup() {
  rm -f "$marker"
  rm -rf "$work" /tmp/pam_namespace_user_runtime_*
  rm -f /var/lib/systemd/linger/attacker /var/lib/systemd/linger/selfauth
  systemctl stop user@1001.service user-runtime-dir@1001.service user@1002.service user-runtime-dir@1002.service >/dev/null 2>&1 || true
  systemctl reset-failed user@1001.service user-runtime-dir@1001.service user@1002.service user-runtime-dir@1002.service pam_namespace.service >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
cleanup

run_root() {
  echo "### root: $*"
  set +e
  timeout 15s bash -lc "$*" 2>&1
  rc=$?
  set -e
  echo "rc=$rc"
}

run_attacker() {
  echo "### attacker: $*"
  set +e
  runuser -u attacker -- timeout 15s bash -lc "$*" 2>&1
  rc=$?
  set -e
  echo "rc=$rc"
}

run_selfauth() {
  echo "### selfauth: $*"
  set +e
  runuser -u selfauth -- timeout 15s bash -lc "$*" 2>&1
  rc=$?
  set -e
  echo "rc=$rc"
}

echo "## target and package proof"
id
id attacker
id selfauth
sed -n '1,8p' /etc/os-release
uname -a
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  libpam-modules libpam-runtime systemd dbus polkitd 2>&1 | sort

echo "## unit and config proof"
systemctl cat pam_namespace.service user-runtime-dir@.service user@.service --no-pager
systemctl list-unit-files pam_namespace.service 'user@.service' 'user-runtime-dir@.service' --no-pager || true
for p in /usr/sbin/pam_namespace_helper /usr/lib/systemd/systemd-user-runtime-dir /etc/security/namespace.conf /var/lib/systemd/linger /run/user /run/systemd/users /run/systemd/sessions; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %n type=%F' "$p"
  else
    echo "MISSING $p"
  fi
done
sed -n '1,160p' /usr/sbin/pam_namespace_helper
sed -n '1,140p' /etc/security/namespace.conf
grep -RIn 'pam_namespace\|pam_systemd\|pam_env\|user_readenv\|pam_exec' /etc/pam.d /etc/security 2>/dev/null | sed -n '1,220p'

echo "## attacker cannot alter namespace/PAM/system unit config"
run_attacker '
id
for p in /etc/security/namespace.conf /usr/sbin/pam_namespace_helper /etc/pam.d/common-session /etc/pam.d/login /usr/lib/systemd/system/pam_namespace.service /etc/systemd/system/pam_namespace.service.d/probe.conf /run/systemd/system/pam_namespace.service.d/probe.conf; do
  echo "--- $p"
  mkdir -p "$(dirname "$p")" 2>/tmp/pam_namespace_user_runtime_mkdir.err || true
  printf owned > "$p" 2>/tmp/pam_namespace_user_runtime_write.err
  echo "write_rc=$? err=$(cat /tmp/pam_namespace_user_runtime_write.err 2>/dev/null)"
done
'

echo "## pam_namespace helper direct and service boundaries"
run_attacker '
mkdir -p "$HOME/pam_namespace_user_runtime/bin"
cat > "$HOME/pam_namespace_user_runtime/bin/sed" <<\EOF
#!/bin/sh
id > /tmp/pam_namespace_user_runtime_fake_sed
exec /usr/bin/sed "$@"
EOF
cat > "$HOME/pam_namespace_user_runtime/bin/mkdir" <<\EOF
#!/bin/sh
id > /tmp/pam_namespace_user_runtime_fake_mkdir
exec /usr/bin/mkdir "$@"
EOF
chmod 755 "$HOME/pam_namespace_user_runtime/bin/"*
PATH="$HOME/pam_namespace_user_runtime/bin:/usr/bin:/bin" /usr/sbin/pam_namespace_helper
echo helper_rc=$?
cat /tmp/pam_namespace_user_runtime_fake_sed 2>/dev/null || echo no_fake_sed
cat /tmp/pam_namespace_user_runtime_fake_mkdir 2>/dev/null || echo no_fake_mkdir
'
run_attacker 'systemctl start pam_namespace.service 2>&1; echo start_rc=$?'
run_root 'rm -f /tmp/pam_namespace_user_runtime_fake_sed /tmp/pam_namespace_user_runtime_fake_mkdir; systemctl start pam_namespace.service 2>&1; echo root_start_rc=$?; cat /tmp/pam_namespace_user_runtime_fake_sed /tmp/pam_namespace_user_runtime_fake_mkdir 2>/dev/null || true'

echo "## loginctl self-linger boundary"
run_attacker 'loginctl enable-linger root 2>&1; echo root_linger_rc=$?'
run_attacker 'loginctl enable-linger ../root 2>&1; echo traversal_linger_rc=$?'
run_attacker 'loginctl enable-linger attacker 2>&1; echo self_linger_rc=$?'
ls -l /var/lib/systemd/linger 2>&1 || true
stat -Lc '%A %a %U:%G %n' /var/lib/systemd/linger/attacker 2>&1 || true
systemctl status user@1001.service user-runtime-dir@1001.service --no-pager -l 2>&1 | sed -n '1,120p' || true
find /run/user /run/systemd/users /run/systemd/sessions -maxdepth 2 -ls 2>/dev/null | sed -n '1,220p'
run_root 'systemctl start user@1001.service; sleep 1; systemctl status user@1001.service user-runtime-dir@1001.service --no-pager -l 2>&1 | sed -n "1,140p"; find /run/user/1001 -maxdepth 2 -ls 2>/dev/null | sed -n "1,160p"'

echo "## user manager stays uid1001"
run_attacker '
export XDG_RUNTIME_DIR=/run/user/1001
export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus
id
ls -la /run/user/1001 2>&1 || true
systemctl --user status --no-pager 2>&1 | sed -n "1,80p"
systemctl --user set-environment PATH="$HOME/pam_namespace_user_runtime/bin:/usr/bin:/bin" 2>&1
systemd-run --user --unit=pam-namespace-user-runtime-probe /bin/sh -c "id > /tmp/pam_namespace_user_runtime_user_service_id; touch /root/pam_namespace_user_runtime_root_marker 2>/dev/null || true" 2>&1
sleep 1
systemctl --user status pam-namespace-user-runtime-probe.service --no-pager 2>&1 | sed -n "1,80p" || true
cat /tmp/pam_namespace_user_runtime_user_service_id 2>/dev/null || echo no_user_service_id
test -e /root/pam_namespace_user_runtime_root_marker && echo root_marker_seen || echo no_root_marker_from_user_service
'

echo "## user runtime path abuse checks"
run_attacker '
for p in /run/user /run/user/1001 /run/systemd/users /run/systemd/users/1001 /run/systemd/sessions /var/lib/systemd/linger/attacker; do
  echo "--- $p"
  stat -Lc "%A %a %U:%G %n type=%F" "$p" 2>&1 || true
  ln -s /root/pam_namespace_user_runtime_root_marker "$p.link" 2>&1 || true
  printf owned > "$p" 2>&1 || true
done
'

echo "## root proof before cleanup"
if [ -e "$marker" ]; then
  echo ROOT_PROOF=yes
  stat -Lc '%A %a %U:%G %n' "$marker"
  cat "$marker" 2>/dev/null || true
else
  echo ROOT_PROOF=no
fi
cat /tmp/pam_namespace_user_runtime_user_service_id 2>/dev/null || true

cleanup

echo "## cleanup and health"
for p in "$marker" "$work" /var/lib/systemd/linger/attacker /var/lib/systemd/linger/selfauth /tmp/pam_namespace_user_runtime_user_service_id; do
  [ -e "$p" ] || [ -L "$p" ] && echo "LEFT $p" || echo "ABSENT $p"
done
systemctl is-system-running || true
systemctl --failed --no-legend || true
TARGET
