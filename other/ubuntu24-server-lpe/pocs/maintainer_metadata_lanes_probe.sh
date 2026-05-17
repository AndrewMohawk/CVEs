#!/usr/bin/env bash
set -euo pipefail

target="${1:-ubuntu24-server-lpe-target}"

section() {
  printf '\n### %s\n' "$1"
}

in_target() {
  docker exec "$target" bash -lc "$1"
}

section "target"
in_target 'cat /etc/os-release | sed -n "1,8p"; uname -a; id attacker; id selfauth; systemctl is-system-running; systemctl --failed --no-legend | wc -l'

section "packages"
in_target 'dpkg-query -W apparmor netplan-generator netplan.io python3-netplan base-passwd passwd login libc6 systemd apt unattended-upgrades 2>/dev/null | sort'

section "apparmor-homedirs-default-proof"
in_target 'systemctl is-enabled apparmor.service; systemctl is-active apparmor.service || true; nl -ba /var/lib/dpkg/info/apparmor.postinst | sed -n "38,74p"; getent passwd attacker selfauth; stat -Lc "%A %U:%G %n" /etc/passwd /etc/apparmor.d/tunables/home.d /etc/apparmor.d/tunables/home.d/ubuntu'

section "apparmor-homedirs-attacker-writes"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  for p in /etc/passwd /etc/apparmor.d/tunables/home.d/ubuntu /etc/apparmor.d/tunables/home.d/attacker; do
    printf "write-test %s -> " "$p"
    if [ -d "$p" ]; then touch "$p/probe" 2>&1 && rm -f "$p/probe" || true
    else printf x > "$p" 2>&1 || true
    fi
  done
'"'"''

section "apparmor-homedirs-root-data-shape"
in_target 'awk -F: '"'"'$3 >= 1000 && $3 < 30000 {printf "%s\n", $6}'"'"' /etc/passwd | xargs -d "\n" -n 1 dirname | grep -v "^/home$" | sed -e '"'"'s#\(.*\)#\1/#g'"'"' | sed -e '"'"'/ / { s#\(.*\)#"\1"#g }'"'"' | sort -u | tr "\n" " "; echo; sed -n "1,12p" /etc/apparmor.d/tunables/home.d/ubuntu'

section "netplan-generator-default-proof"
in_target 'nl -ba /var/lib/dpkg/info/netplan-generator.postinst | sed -n "12,19p"; stat -Lc "%A %U:%G %n" /run /run/systemd /run/systemd/network 2>&1 || true; find /run/systemd -maxdepth 2 -type d -printf "%M %u:%g %p\n" | sort | sed -n "1,60p"'

section "netplan-generator-attacker-writes"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  mkdir -p /run/systemd/network 2>&1 || true
  printf "network" > /run/systemd/network/90-netplan-pwn.network 2>&1 || true
  ln -s /root/netplan_generator_pwn /run/systemd/network/91-netplan-pwn.network 2>&1 || true
  find /run/systemd/network -maxdepth 1 -type f -name "*-netplan*" -print 2>&1 || true
'"'"''

section "netplan-generator-root-no-files-trigger"
in_target 'rm -f /root/netplan_generator_pwn; /bin/sh -x /var/lib/dpkg/info/netplan-generator.postinst configure 2>&1 | sed -n "1,80p"; if [ -e /root/netplan_generator_pwn ]; then cat /root/netplan_generator_pwn; else echo NO_ROOT_MARKER; fi'

section "base-passwd-default-proof"
in_target 'nl -ba /var/lib/dpkg/info/base-passwd.postinst | sed -n "55,118p"; stat -Lc "%A %U:%G %n" /etc/passwd /etc/group /etc/shadow /usr/sbin/update-passwd'

section "base-passwd-attacker-reconcile"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  /usr/sbin/update-passwd --dry-run 2>&1 | sed -n "1,80p"
  printf x > /etc/passwd 2>&1 || true
  printf x > /etc/group 2>&1 || true
  ln -s /root/base_passwd_pwn /etc/passwd.probe 2>&1 || true
'"'"''

section "base-passwd-root-dry-run"
in_target 'rm -f /root/base_passwd_pwn; /usr/sbin/update-passwd --dry-run 2>&1 | sed -n "1,120p"; if [ -e /root/base_passwd_pwn ]; then cat /root/base_passwd_pwn; else echo NO_ROOT_MARKER; fi'

section "libc-services-need-default-proof"
in_target 'systemctl is-enabled apt-daily-upgrade.timer unattended-upgrades.service; nl -ba /var/lib/dpkg/info/libc6:arm64.preinst | sed -n "309,427p"; nl -ba /var/lib/dpkg/info/libc6:arm64.postinst | sed -n "27,105p"; stat -Lc "%A %U:%G %n" /run /var/run /run/services.need_restart /run/services.need_start 2>&1 || true'

section "libc-services-need-attacker-writes"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  echo cron > /var/run/services.need_restart 2>&1 || true
  echo cron > /var/run/services.need_start 2>&1 || true
  ln -s /root/libc_services_need_pwn /var/run/services.need_start 2>&1 || true
  ls -l /var/run/services.need_restart /var/run/services.need_start 2>&1 || true
'"'"''

section "libc-services-need-metachar-root-simulation"
in_target 'rm -f /root/libc_services_need_pwn; service="cron;touch /root/libc_services_need_pwn"; invoke-rc.d ${service} status >/tmp/libc-services-need-invoke.out 2>&1 || true; sed -n "1,40p" /tmp/libc-services-need-invoke.out; if [ -e /root/libc_services_need_pwn ]; then cat /root/libc_services_need_pwn; else echo NO_ROOT_MARKER; fi; rm -f /tmp/libc-services-need-invoke.out /root/libc_services_need_pwn'

section "cleanup-health"
in_target 'rm -f /root/netplan_generator_pwn /root/base_passwd_pwn /root/libc_services_need_pwn; systemctl is-system-running; systemctl --failed --no-legend | wc -l; ls -l /run/services.need_restart /run/services.need_start 2>/dev/null || true'

section "result"
echo "ROOT_PROOF=NO"
