#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/userns-netdev-udev-sysctl.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -euo pipefail

base=/tmp/userns-netdev-udev-sysctl
ready="$base/persist-ready"
rm -rf "$base"
mkdir -p "$base"
chmod 1777 "$base"

cleanup() {
  set +e
  ip link del rootctl0 >/dev/null 2>&1 || true
  ip link del rootdbg0 >/dev/null 2>&1 || true
  udevadm control --log-priority=info >/dev/null 2>&1 || true
  systemctl reset-failed iscsid.service iscsid.socket >/dev/null 2>&1 || true
  rm -rf "$base"
}
trap cleanup EXIT

section() {
  printf '\n## %s\n' "$1"
}

cursor_now() {
  journalctl -n 0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p' | tail -n1 || true
}

journal_since() {
  local cursor="$1"
  local outfile="$2"
  if [ -n "$cursor" ]; then
    journalctl --after-cursor "$cursor" --no-pager >"$outfile" 2>&1 || true
  else
    journalctl -n 200 --no-pager >"$outfile" 2>&1 || true
  fi
}

section "target and attacker"
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker
printf 'container_system_state=%s\n' "$(systemctl is-system-running 2>/dev/null || true)"

section "default sysctls"
for key in \
  user.max_user_namespaces \
  user.max_net_namespaces \
  kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns \
  kernel.apparmor_restrict_unprivileged_unconfined \
  net.ipv4.conf.all.accept_redirects \
  net.ipv4.conf.default.accept_redirects \
  net.ipv4.conf.all.rp_filter \
  net.ipv4.conf.default.rp_filter \
  net.ipv6.conf.all.disable_ipv6 \
  net.ipv6.conf.default.disable_ipv6; do
  sysctl "$key" 2>&1 || true
done

section "default packages"
dpkg-query -W -f='${binary:Package}\t${Version}\n' \
  systemd udev netplan.io networkd-dispatcher systemd-resolved open-iscsi \
  cloud-init 2>&1 | sort || true

section "default services"
systemctl --no-pager --plain status \
  systemd-udevd.service \
  systemd-sysctl.service \
  systemd-networkd.service \
  systemd-networkd.socket \
  networkd-dispatcher.service \
  netplan-ovs-cleanup.service --lines=0 2>&1 | sed -n '1,180p' || true

section "default sysctl config touching net device prefixes"
systemd-sysctl --cat-config 2>/dev/null \
  | grep -nE '^# /|^[[:space:]]*net\.(ipv4|ipv6)\.(conf|neigh)\.' \
  | sed -n '1,220p' || true

section "default udev net rules"
nl -ba /usr/lib/udev/rules.d/99-systemd.rules | sed -n '50,76p'
nl -ba /usr/lib/udev/rules.d/70-iscsi-network-interface.rules 2>/dev/null || true
nl -ba /usr/lib/udev/rules.d/80-net-setup-link.rules | sed -n '1,40p'
nl -ba /usr/lib/udev/rules.d/81-net-dhcp.rules | sed -n '1,40p'

section "root initial-netns control event"
root_cursor="$(cursor_now)"
udevadm control --log-priority=debug || true
( timeout 8 udevadm monitor --kernel --udev --property --subsystem-match=net >"$base/root-monitor.log" 2>&1 || true ) &
root_mon=$!
sleep 1
ip link del rootctl0 >/dev/null 2>&1 || true
ip link add name rootctl0 type dummy
ip link set rootctl0 up || true
udevadm settle --timeout=5 || true
ip link del rootctl0 || true
udevadm settle --timeout=5 || true
wait "$root_mon" || true
journal_since "$root_cursor" "$base/root-journal.log"
printf '%s\n' "[root monitor relevant]"
grep -E 'rootctl0|ACTION=|SUBSYSTEM=|INTERFACE=|SYSTEMD_ALIAS|SEQNUM' "$base/root-monitor.log" | sed -n '1,160p' || true
printf '%s\n' "[root udev debug relevant]"
grep -E 'rootctl0|systemd-sysctl|net-interface-handler|99-systemd|70-iscsi|RUN ' "$base/root-journal.log" | sed -n '1,220p' || true

section "attacker userns plus netns event probe"
attacker_cursor="$(cursor_now)"
( timeout 12 udevadm monitor --kernel --udev --property --subsystem-match=net >"$base/attacker-monitor.log" 2>&1 || true ) &
attacker_mon=$!
sleep 1
rm -f "$ready"
runuser -u attacker -- unshare -Urn bash >"$base/attacker.out" 2>&1 <<'ATTACKER' &
set +e
base=/tmp/userns-netdev-udev-sysctl
printf '%s\n' "inner_id=$(id)"
printf '%s\n' "uid_map=$(cat /proc/self/uid_map)"
printf '%s\n' "gid_map=$(cat /proc/self/gid_map)"
grep -E '^(Uid|Gid|CapEff|NSpid|NoNewPrivs):' /proc/self/status
printf '%s\n' "[initial private-netns links]"
ip -o link show

names=(
  "unvns0"
  "all"
  "default"
  "lo.probe"
  "net.ipv4"
  "x;y"
  "abc\"q"
  "dollar\$x"
  "x y"
  "x:y"
  "a/b"
  "abcdefghijklmnop"
)

for name in "${names[@]}"; do
  printf '%s\n' "name_test=<$name>"
  ip link add name "$name" type dummy 2>&1
  rc=$?
  printf '%s\n' "ip_link_add_rc=$rc"
  if [ "$rc" -eq 0 ]; then
    ip link set "$name" up 2>&1
    ip -d -o link show dev "$name" 2>&1
    sleep 0.15
    ip link del "$name" 2>&1
  fi
done

printf '%s\n' "[persistent private device]"
ip link add name persist0 type dummy 2>&1
persist_rc=$?
printf '%s\n' "persist_add_rc=$persist_rc"
if [ "$persist_rc" -eq 0 ]; then
  ip link set persist0 up 2>&1
  ip -d -o link show dev persist0 2>&1
  printf ready >"$base/persist-ready"
  sleep 4
  ip link del persist0 2>&1
fi
ATTACKER
attacker_pid=$!

for _ in $(seq 1 30); do
  [ -e "$ready" ] && break
  sleep 0.2
done

printf '%s\n' "[root initial-netns visibility while attacker persist0 is alive]"
ip -o link show | sed -n '1,80p'
if [ -e /sys/class/net/persist0 ]; then
  printf '%s\n' "root_sysfs_persist0=present"
else
  printf '%s\n' "root_sysfs_persist0=absent"
fi
find /run/udev/data -maxdepth 1 -type f -print0 2>/dev/null \
  | xargs -0 grep -H -E 'persist0|unvns0|lo\.probe|net\.ipv4|x;y|abc"q|dollar' 2>/dev/null \
  | sed -n '1,80p' || true

wait "$attacker_pid" || true
wait "$attacker_mon" || true
udevadm settle --timeout=5 || true
journal_since "$attacker_cursor" "$base/attacker-journal.log"
udevadm control --log-priority=info || true

printf '%s\n' "[attacker namespace output]"
sed -n '1,260p' "$base/attacker.out"
printf '%s\n' "[attacker monitor full]"
sed -n '1,220p' "$base/attacker-monitor.log"
printf '%s\n' "[attacker udev debug relevant]"
grep -E 'persist0|unvns0|lo\.probe|net\.ipv4|x;y|abc"q|dollar|systemd-sysctl|net-interface-handler|99-systemd|70-iscsi' "$base/attacker-journal.log" \
  | sed -n '1,220p' || true

section "root-control cleanup"
systemctl reset-failed iscsid.service iscsid.socket >/dev/null 2>&1 || true
printf 'container_system_state_after_root_control_cleanup=%s\n' "$(systemctl is-system-running 2>/dev/null || true)"

section "post checks"
printf '%s\n' "[systemd units mentioning tested names]"
systemctl list-units --all --no-pager 2>&1 \
  | grep -E 'persist0|unvns0|lo\.probe|net\.ipv4|rootctl0' || true
printf '%s\n' "[root markers]"
ls -l /root/userns-netdev-udev-sysctl* /tmp/userns-netdev-udev-sysctl-root* 2>&1 || true
printf 'container_system_state_after=%s\n' "$(systemctl is-system-running 2>/dev/null || true)"
systemctl --failed --no-legend || true
EOS

sed -n '1,360p' "$log"
