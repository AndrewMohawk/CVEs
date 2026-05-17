#!/bin/sh
set -eu

TARGET="${1:-ubuntu24-server-lpe-target}"

dx() {
  printf '\n### %s\n' "$1"
  docker exec "$TARGET" sh -lc "$2" 2>&1 || true
}

dx "target and identity" '
cat /etc/os-release | sed -n "1,6p"
uname -a
id attacker
id selfauth 2>/dev/null || true
systemctl is-system-running 2>&1 || true
systemd-detect-virt -v 2>&1 || true
systemd-detect-virt -c 2>&1 || true
'

dx "relevant packages" '
dpkg-query -W -f='\''${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'\'' \
  dhcpcd-base dhcpcd5 cloud-init cloud-guest-utils cloud-initramfs-copymods \
  cloud-initramfs-dyn-netconf netplan.io python3-netplan pollinate \
  ubuntu-pro-client ubuntu-advantage-tools landscape-common resolvconf \
  openresolv networkd-dispatcher systemd systemd-resolved 2>&1 | sort
'

dx "relevant unit files" '
systemctl list-unit-files --no-pager --no-legend \
  "*dhcpcd*" "*cloud*" "*netplan*" "*pollinate*" "*advantage*" \
  "*ua-*" "*landscape*" "*resolv*" "*networkd-dispatcher*" 2>&1 | sort
'

dx "service state and conditions" '
for u in dhcpcd.service cloud-init-local.service cloud-init.service cloud-config.service \
  cloud-final.service pollinate.service ubuntu-advantage.service ua-timer.service \
  ua-timer.timer networkd-dispatcher.service resolvconf.service systemd-resolved.service \
  netplan-ovs-cleanup.service; do
  echo "### $u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p Result -p ConditionResult -p FragmentPath -p User -p ExecStart "$u" 2>&1 || true
done
'

dx "hook and state path inventory" '
for p in /usr/lib/dhcpcd /lib/dhcpcd /etc/dhcpcd.enter-hook /etc/dhcpcd.exit-hook \
  /etc/dhcpcd.conf /var/lib/dhcpcd /run/dhcpcd /etc/cloud /var/lib/cloud \
  /run/cloud-init /etc/netplan /run/netplan /usr/lib/netplan /usr/libexec/netplan \
  /etc/networkd-dispatcher /usr/lib/networkd-dispatcher /etc/default/networkd-dispatcher \
  /etc/pollinate /etc/default/pollinate /var/cache/pollinate /var/lib/ubuntu-advantage \
  /run/ubuntu-advantage /etc/ubuntu-advantage /etc/landscape /var/lib/landscape \
  /var/log/landscape /etc/resolvconf /run/resolvconf /etc/resolv.conf; do
  [ -e "$p" ] && stat -Lc "%A %U:%G %F %n" "$p" || echo "MISSING $p"
done
'

dx "hook tree files" '
for d in /usr/lib/dhcpcd /lib/dhcpcd /etc/networkd-dispatcher \
  /usr/lib/networkd-dispatcher /etc/netplan /usr/lib/netplan /usr/libexec/netplan \
  /etc/cloud /var/lib/cloud/scripts /etc/pollinate /etc/ubuntu-advantage /etc/landscape; do
  [ -e "$d" ] && find "$d" -xdev -maxdepth 4 -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sort
done
'

dx "attacker write attempts" '
runuser -u attacker -- sh -lc '"'"'
for p in /etc/dhcpcd.enter-hook /usr/lib/dhcpcd/dhcpcd-hooks/99-attacker \
  /var/lib/dhcpcd/attacker /run/dhcpcd/attacker \
  /etc/cloud/cloud.cfg.d/99-attacker.cfg /var/lib/cloud/scripts/per-boot/99-attacker \
  /etc/netplan/99-attacker.yaml /run/netplan/99-attacker.yaml \
  /etc/networkd-dispatcher/routable.d/99-attacker \
  /usr/lib/networkd-dispatcher/routable.d/99-attacker /etc/default/pollinate \
  /var/cache/pollinate/attacker /var/lib/ubuntu-advantage/status.json \
  /run/ubuntu-advantage/attacker /etc/landscape/client.conf /var/lib/landscape/attacker \
  /var/log/landscape/attacker /etc/resolvconf/update.d/99-attacker \
  /run/resolvconf/attacker; do
  printf "touch %s -> " "$p"
  touch "$p" 2>&1 && rm -f "$p" && echo OK || echo FAIL
done
'"'"'
'

dx "attacker service starts" '
for u in pollinate.service ubuntu-advantage.service ua-timer.service ua-timer.timer \
  networkd-dispatcher.service netplan-ovs-cleanup.service; do
  echo "### $u"
  runuser -u attacker -- systemctl start "$u" 2>&1 || true
done
'

dx "attacker direct helper probes" '
echo "### dhcpcd-run-hooks TEST"
runuser -u attacker -- env interface=eth0 reason=TEST /usr/lib/dhcpcd/dhcpcd-run-hooks 2>&1 || true
echo "### pollinate user-agent"
runuser -u attacker -- /usr/bin/pollinate --print-user-agent 2>&1 || true
echo "### landscape wrapper"
runuser -u attacker -- sh -lc '"'"'
  /usr/share/landscape/landscape-sysinfo.wrapper >/tmp/network_cloud_landscape.out 2>/tmp/network_cloud_landscape.err
  echo "wrapper_rc=$?"
  ls -l /tmp/network_cloud_landscape.out /tmp/network_cloud_landscape.err
  rm -f /tmp/network_cloud_landscape.out /tmp/network_cloud_landscape.err
'"'"'
'

dx "attacker netplan and D-Bus probes" '
for cmd in "netplan get" "netplan generate" "netplan apply"; do
  echo "### attacker $cmd"
  runuser -u attacker -- sh -lc "$cmd" 2>&1 | sed -n "1,80p"
done
runuser -u attacker -- busctl call --system io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Config 2>&1 || true
runuser -u attacker -- busctl call --system io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Generate 2>&1 || true
runuser -u attacker -- busctl call --system io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Apply 2>&1 || true
'

dx "root proof sweep" '
find /tmp /home/attacker -maxdepth 2 \( -name "*network*cloud*proof*" -o -name "*nc_*proof*" -o -name "*root-proof*" \) \
  -printf "%M %u:%g %p\n" 2>/dev/null || true
'
