#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/networkd-dispatcher.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -euo pipefail

base=/tmp/networkd-dispatcher-probe
rm -rf "$base"
mkdir -p "$base"
chmod 1777 "$base"

cleanup() {
  set +e
  rm -rf "$base"
  rm -rf /tmp/ndisp-attacker-scripts
  rm -f /tmp/ndisp-direct-marker
}
trap cleanup EXIT

section() {
  printf '\n## %s\n' "$1"
}

as_user() {
  local user="$1"
  shift
  printf '\n### %s: %s\n' "$user" "$*"
  runuser -u "$user" -- "$@" 2>&1 || true
}

as_user_sh() {
  local user="$1"
  local label="$2"
  local script="$3"
  printf '\n### %s: %s\n' "$user" "$label"
  runuser -u "$user" -- bash -lc "$script" 2>&1 || true
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

section "target and users"
cat /etc/os-release | sed -n '1,8p'
uname -a
systemd-detect-virt -v 2>&1 || true
systemd-detect-virt -c 2>&1 || true
printf 'container_system_state=%s\n' "$(systemctl is-system-running 2>/dev/null || true)"
id attacker
id selfauth

section "default packages"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  networkd-dispatcher systemd systemd-resolved dbus dbus-daemon netplan.io \
  2>&1 | sort || true

section "default unit reachability"
systemctl --no-pager status \
  networkd-dispatcher.service \
  systemd-networkd.service \
  systemd-networkd.socket --lines=0 2>&1 | sed -n '1,180p' || true
systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState \
  -p Result -p ConditionResult -p FragmentPath -p User -p ExecStart \
  networkd-dispatcher.service systemd-networkd.service systemd-networkd.socket 2>&1 || true
printf '\n[condition evaluation]\n'
systemd-analyze condition \
  'ConditionPathExistsGlob=|/etc/networkd-dispatcher/*/*' \
  'ConditionPathExistsGlob=|/usr/lib/networkd-dispatcher/*/*' \
  'ConditionCapability=CAP_NET_ADMIN' 2>&1 || true
printf '\n[unit files]\n'
systemctl cat networkd-dispatcher.service systemd-networkd.service systemd-networkd.socket 2>&1 \
  | sed -n '1,220p' || true

section "root script dirs and dispatcher code boundary"
for p in /etc/default/networkd-dispatcher /etc/networkd-dispatcher /usr/lib/networkd-dispatcher; do
  [ -e "$p" ] && stat -Lc '%A %U:%G %F %n' "$p" || echo "MISSING $p"
done
for d in /etc/networkd-dispatcher /usr/lib/networkd-dispatcher; do
  echo "### $d"
  find "$d" -maxdepth 2 -printf '%M %u:%g %y %p -> %l\n' 2>/dev/null | sort
done
printf '\n[networkd-dispatcher relevant source]\n'
nl -ba /usr/bin/networkd-dispatcher | sed -n '46,52p;167,224p;356,388p;393,408p;486,493p'

section "systemd-networkd dbus boundary"
for p in \
  /usr/share/dbus-1/system-services/org.freedesktop.network1.service \
  /etc/systemd/system/dbus-org.freedesktop.network1.service \
  /usr/lib/systemd/system/dbus-org.freedesktop.network1.service \
  /usr/share/dbus-1/system.d/org.freedesktop.network1.conf \
  /usr/share/polkit-1/rules.d/systemd-networkd.rules; do
  echo "### $p"
  if [ -e "$p" ]; then
    stat -Lc '%A %U:%G %F %n' "$p"
    nl -ba "$p" 2>/dev/null | sed -n '1,120p' || true
  else
    echo MISSING
  fi
done
printf '\n[bus names]\n'
busctl --system --no-pager list 2>&1 | grep -E 'network1|netplan|dbus' || true
for user in attacker selfauth; do
  as_user "$user" dbus-send --system --print-reply --dest=org.freedesktop.DBus / \
    org.freedesktop.DBus.RequestName string:org.freedesktop.network1 uint32:0
  as_user "$user" timeout 8 busctl --system --no-pager tree org.freedesktop.network1
  as_user "$user" timeout 8 busctl --system call org.freedesktop.network1 \
    /org/freedesktop/network1 org.freedesktop.DBus.ObjectManager GetManagedObjects
  as_user_sh "$user" "fake PropertiesChanged signal" \
    'set +e; busctl --system emit /org/freedesktop/network1/link/_33 org.freedesktop.DBus.Properties PropertiesChanged sa{sv}as org.freedesktop.network1.Link 1 OperationalState s routable 0 2>&1; echo emit_rc=$?'
done

section "attacker writes and service starts"
for user in attacker selfauth; do
  as_user_sh "$user" "write attempts" '
for p in \
  /etc/networkd-dispatcher/routable.d/zz-attacker \
  /usr/lib/networkd-dispatcher/routable.d/zz-attacker \
  /etc/networkd-dispatcher/off.d/zz-attacker \
  /usr/lib/networkd-dispatcher/off.d/zz-attacker \
  /etc/default/networkd-dispatcher \
  /run/networkd-dispatcher/zz-attacker \
  /run/systemd/netif/links/999 \
  /run/systemd/netif/leases/999 \
  /run/systemd/netif/lldp/999 \
  /etc/systemd/network/99-attacker.network \
  /run/systemd/network/99-attacker.network \
  /etc/netplan/99-attacker.yaml \
  /run/netplan/99-attacker.yaml; do
  printf "touch %s -> " "$p"
  touch "$p" 2>&1 && rm -f "$p" && echo OK || echo FAIL
done'
  as_user_sh "$user" "systemctl start attempts" '
for svc in networkd-dispatcher.service systemd-networkd.service systemd-networkd.socket; do
  echo "### $svc"
  systemctl start "$svc" 2>&1 || true
done'
done

section "direct dispatcher execution is not privileged"
rm -rf /tmp/ndisp-attacker-scripts /tmp/ndisp-direct-marker
as_user_sh attacker "attacker-owned script-dir check" '
set -eu
tmp=/tmp/ndisp-attacker-scripts
rm -rf "$tmp"
mkdir -p "$tmp/routable.d"
printf "#!/bin/sh\nid > /tmp/ndisp-direct-marker\n" > "$tmp/routable.d/01-owned"
chmod 755 "$tmp/routable.d/01-owned"
python3 - <<PY
import importlib.machinery
import importlib.util
loader = importlib.machinery.SourceFileLoader("ndisp", "/usr/bin/networkd-dispatcher")
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)
print("scripts_in_attacker_dir=%r" % (mod.scripts_in_path("/tmp/ndisp-attacker-scripts", "routable.d"),))
PY
timeout 3 /usr/bin/networkd-dispatcher -T -v --script-dir="$tmp" 2>&1 || true
ls -l /tmp/ndisp-direct-marker 2>&1 || true
rm -rf "$tmp"
rm -f /tmp/ndisp-direct-marker'

section "networkctl and state files"
printf '[networkctl as root]\n'
networkctl list --no-pager --no-legend 2>&1 || true
printf '\n[/run systemd network state]\n'
for d in /run/systemd/netif /run/systemd/netif/links /run/systemd/netif/leases \
  /run/systemd/netif/lldp /run/systemd/network /var/lib/systemd/network \
  /etc/systemd/network /run/netplan /etc/netplan; do
  echo "### $d"
  if [ -e "$d" ]; then
    find "$d" -maxdepth 2 -printf '%M %u:%g %s %p -> %l\n' 2>/dev/null | sort
  else
    echo MISSING
  fi
done
for user in attacker selfauth; do
  as_user "$user" networkctl list --no-pager --no-legend
  as_user "$user" timeout 8 networkctl status --no-pager --lines=0 --all
done

section "netlink and userns netns link-state influence"
cursor="$(cursor_now)"
( timeout 10 udevadm monitor --kernel --udev --property --subsystem-match=net >"$base/userns-monitor.log" 2>&1 || true ) &
monitor_pid=$!
sleep 1
for tuple in attacker:ndatt0 selfauth:ndself0; do
  user="${tuple%%:*}"
  ifname="${tuple##*:}"
  as_user_sh "$user" "initial namespace netlink and private netns $ifname" "
set +e
ip link add name ${ifname}init type dummy 2>&1
echo init_ip_add_rc=\$?
ip link set lo down 2>&1
echo init_lo_down_rc=\$?
unshare -Urn bash -lc 'set +e; echo inner_id=\$(id); ip link add name ${ifname} type dummy 2>&1; echo ns_ip_add_rc=\$?; ip link set ${ifname} up 2>&1; ip -o link show dev ${ifname} 2>&1; sleep 1'
"
done
wait "$monitor_pid" || true
journal_since "$cursor" "$base/userns-journal.log"
printf '\n[root initial namespace visibility]\n'
ip -o link show | grep -E 'ndatt0|ndself0' || true
for n in ndatt0 ndself0; do
  if [ -e "/sys/class/net/$n" ]; then
    echo "root_sysfs_${n}=present"
  else
    echo "root_sysfs_${n}=absent"
  fi
done
printf '\n[udev monitor relevant]\n'
grep -E 'ndatt0|ndself0|ACTION=|SUBSYSTEM=|INTERFACE=' "$base/userns-monitor.log" | sed -n '1,180p' || true
printf '\n[journal relevant]\n'
grep -E 'networkd-dispatcher|systemd-networkd|ndatt0|ndself0' "$base/userns-journal.log" | sed -n '1,180p' || true
printf '\n[/run/udev/data relevant]\n'
find /run/udev/data -maxdepth 1 -type f -print0 2>/dev/null \
  | xargs -0 grep -H -E 'ndatt0|ndself0' 2>/dev/null | sed -n '1,80p' || true

section "root proof sweep and cleanup state"
ls -l /root/ndisp* /tmp/ndisp* 2>&1 || true
systemctl --no-pager status networkd-dispatcher.service systemd-networkd.service systemd-networkd.socket --lines=0 2>&1 \
  | sed -n '1,120p' || true
printf 'container_system_state_after=%s\n' "$(systemctl is-system-running 2>/dev/null || true)"
systemctl --failed --no-legend || true
EOS

sed -n '1,460p' "$log"
