#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/systemd-user-sessions.out"
tmp_log="$(mktemp "$repo_dir/logs/systemd-user-sessions.out.tmp.XXXXXX")"

docker exec -i "$container" bash <<'TARGET' >"$tmp_log" 2>&1
set +e
name=systemd-user-sessions
root_marker=/root/systemd_user_sessions_probe_root
tmp_marker=/tmp/systemd_user_sessions_probe_root

section() {
  printf '\n## %s\n' "$1"
}

cleanup() {
  /usr/lib/systemd/systemd-user-sessions start >/dev/null 2>&1 || true
  rm -f "$root_marker" "$tmp_marker" /tmp/systemd_user_sessions_probe_attacker_* \
    /tmp/systemd_user_sessions_probe_root_* 2>/dev/null || true
  systemctl reset-failed systemd-user-sessions.service >/dev/null 2>&1 || true
}
cleanup

section "target and packages"
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  systemd libpam-modules login 2>&1 | sort

section "default unit and nologin paths"
systemctl show systemd-user-sessions.service \
  -p LoadState -p ActiveState -p SubState -p UnitFileState -p FragmentPath \
  -p ExecStart -p ExecStop -p User -p Group 2>&1
systemctl cat systemd-user-sessions.service 2>&1
for p in /usr/lib/systemd/systemd-user-sessions /run/nologin /etc/nologin /run /etc; do
  stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>&1 || true
done
grep -RIn 'pam_nologin\|nologin' /etc/pam.d /usr/share/pam-configs 2>/dev/null || true

section "attacker direct path"
runuser -u attacker -- bash -lc '
set +e
id
printf attacker > /run/nologin 2>/tmp/systemd_user_sessions_probe_attacker_write.err
echo "write_run_nologin_rc=$?"
cat /tmp/systemd_user_sessions_probe_attacker_write.err 2>/dev/null || true
ln -sf /root/systemd_user_sessions_probe_root /run/nologin 2>/tmp/systemd_user_sessions_probe_attacker_link.err
echo "symlink_run_nologin_rc=$?"
cat /tmp/systemd_user_sessions_probe_attacker_link.err 2>/dev/null || true
rm -f /run/nologin 2>/tmp/systemd_user_sessions_probe_attacker_rm.err
echo "rm_run_nologin_rc=$?"
cat /tmp/systemd_user_sessions_probe_attacker_rm.err 2>/dev/null || true
systemctl restart systemd-user-sessions.service 2>&1
echo "restart_unit_rc=$?"
/usr/lib/systemd/systemd-user-sessions stop 2>&1
echo "direct_stop_rc=$?"
/usr/lib/systemd/systemd-user-sessions start 2>&1
echo "direct_start_rc=$?"
ls -l /run/nologin /tmp/systemd_user_sessions_probe_root 2>&1 || true
'

section "root helper canary"
rm -f /run/nologin "$root_marker" "$tmp_marker"
/usr/lib/systemd/systemd-user-sessions stop 2>&1
echo "root_stop_rc=$?"
stat -Lc '%A %a %U:%G %F %s %n -> %N' /run/nologin 2>&1 || true
sed -n '1,20p' /run/nologin 2>/dev/null || true
echo "root marker test" > "$root_marker"
/usr/lib/systemd/systemd-user-sessions start 2>&1
echo "root_start_rc=$?"
stat -Lc '%A %a %U:%G %F %n -> %N' /run/nologin "$root_marker" "$tmp_marker" 2>&1 || true

section "root proof"
if [ -e "$tmp_marker" ] || [ -e "$root_marker" ]; then
  echo "ROOT_MARKER_PRESENT_ONLY_FROM_ROOT_CANARY"
else
  echo "ROOT_MARKER_ABSENT"
fi
ls -l "$root_marker" "$tmp_marker" /run/nologin 2>&1 || true

section "cleanup and health"
cleanup
ls -l "$root_marker" "$tmp_marker" /run/nologin 2>&1 || true
systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend 2>&1 || true
TARGET

mv "$tmp_log" "$log_path"
sed -n '1,260p' "$log_path"
