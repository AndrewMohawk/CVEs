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
in_target 'cat /etc/os-release | sed -n "1,8p"; uname -a; id attacker; systemctl is-system-running; systemctl --failed --no-legend | wc -l'

section "packages"
in_target 'dpkg-query -W libpam-cap init-system-helpers sg3-utils sg3-utils-udev thin-provisioning-tools hdparm busybox-initramfs klibc-utils libselinux1 adduser 2>/dev/null | sort'

section "libpam-cap-default-proof"
in_target 'grep -R "pam_cap" -n /etc/pam.d /usr/share/pam-configs 2>/dev/null; stat -c "%A %U:%G %n" /etc/security/capability.conf /usr/lib/*/security/pam_cap.so; sed -n "1,80p" /etc/security/capability.conf'

section "libpam-cap-attacker"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  printf "cap_setuid+ep attacker\n" > /etc/security/capability.conf 2>&1 || true
  capsh --print | sed -n "1,12p"
'"'"''

section "init-system-helpers-default-proof"
in_target 'stat -c "%A %U:%G %n" /usr/bin/deb-systemd-helper /usr/bin/deb-systemd-invoke /usr/sbin/invoke-rc.d /usr/sbin/update-rc.d /var/lib/systemd /var/lib/systemd/deb-systemd-helper-enabled /etc/systemd/system; grep -n "SYSTEM_INSTANCE_ENABLED_STATE_DIR\\|record_in_statefile\\|systemctl.*@start_units\\|exec('\''systemctl" /usr/bin/deb-systemd-helper /usr/bin/deb-systemd-invoke | sed -n "1,80p"'

section "init-system-helpers-attacker"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  deb-systemd-helper enable cron.service 2>&1 | sed -n "1,30p" || true
  deb-systemd-invoke restart cron.service 2>&1 | sed -n "1,30p" || true
  deb-systemd-invoke --no-dbus daemon-reload 2>&1 | sed -n "1,30p" || true
  rm -rf /tmp/dsh-root
  mkdir -p /tmp/dsh-root/usr/lib/systemd/system /tmp/dsh-root/etc/systemd/system
  cp /usr/lib/systemd/system/cron.service /tmp/dsh-root/usr/lib/systemd/system/
  DPKG_ROOT=/tmp/dsh-root deb-systemd-helper enable cron.service 2>&1 | sed -n "1,50p" || true
  find /tmp/dsh-root -maxdepth 5 -printf "%M %u:%g %p -> %l\n" | sort | sed -n "1,80p"
  rm -rf /tmp/dsh-root
'"'"''

section "sg3-utils-udev-default-proof"
in_target 'systemctl is-active systemd-udevd.service systemd-udevd-kernel.socket; nl -ba /usr/lib/udev/rules.d/55-scsi-sg3_id.rules /usr/lib/udev/rules.d/58-scsi-sg3_symlink.rules /usr/share/initramfs-tools/hooks/sg3-utils 2>/dev/null | sed -n "1,220p"; stat -c "%A %U:%G %n" /usr/bin/sg_inq /usr/bin/sg_vpd /usr/lib/udev/rules.d/55-scsi-sg3_id.rules /usr/lib/udev/rules.d/58-scsi-sg3_symlink.rules'

section "sg3-utils-attacker"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  printf x > /usr/lib/udev/rules.d/55-scsi-sg3_id.rules 2>&1 || true
  udevadm trigger --subsystem-match=block 2>&1 | sed -n "1,30p" || true
  sg_inq --export /tmp/non-scsi-probe 2>&1 | sed -n "1,30p" || true
'"'"''

section "hdparm-default-proof"
in_target 'nl -ba /usr/lib/udev/rules.d/85-hdparm.rules /usr/lib/udev/hdparm /lib/hdparm/hdparm-functions /etc/hdparm.conf 2>/dev/null | sed -n "1,340p"; stat -c "%A %U:%G %n" /etc/hdparm.conf /usr/lib/udev/hdparm /lib/hdparm/hdparm-functions /usr/lib/udev/rules.d/85-hdparm.rules /sbin/hdparm'

section "hdparm-attacker"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  printf "command_line { --security-unlock pwn }\n" > /etc/hdparm.conf 2>&1 || true
  DEVNAME=/tmp/fake-disk /usr/lib/udev/hdparm 2>&1 | sed -n "1,40p" || true
  udevadm trigger --subsystem-match=block 2>&1 | sed -n "1,30p" || true
'"'"''

section "thin-busybox-klibc-default-proof"
in_target 'dpkg -L thin-provisioning-tools | sort | sed -n "1,120p"; stat -c "%A %U:%G %n" /usr/sbin/pdata_tools /usr/sbin/thin_check /usr/sbin/cache_check /usr/share/initramfs-tools/hooks/thin-provisioning-tools /usr/share/initramfs-tools/hooks/zz-busybox-initramfs /usr/share/initramfs-tools/hooks/klibc-utils /usr/lib/initramfs-tools/bin/busybox /usr/lib/klibc/bin/sh /usr/lib/klibc-*.so; nl -ba /usr/share/initramfs-tools/hooks/thin-provisioning-tools /usr/share/initramfs-tools/hooks/zz-busybox-initramfs /usr/share/initramfs-tools/hooks/klibc-utils 2>/dev/null | sed -n "1,180p"'

section "thin-busybox-klibc-attacker"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  udevadm trigger --subsystem-match=block 2>&1 | sed -n "1,30p" || true
  dd if=/dev/zero of=/tmp/thin-fake.meta bs=4096 count=1 status=none
  thin_check /tmp/thin-fake.meta 2>&1 | sed -n "1,40p" || true
  printf x > /usr/share/initramfs-tools/hooks/zz-busybox-initramfs 2>&1 || true
  BUSYBOX=y CASPER_GENERATE_UUID=1 DESTDIR=/tmp/initramfs-attacker /usr/share/initramfs-tools/hooks/zz-busybox-initramfs 2>&1 | sed -n "1,50p" || true
  find /tmp/initramfs-attacker -maxdepth 2 -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sort | sed -n "1,50p"
  rm -rf /tmp/thin-fake.meta /tmp/initramfs-attacker
'"'"''

section "libselinux1-tmpfiles-default-proof"
in_target 'nl -ba /usr/lib/tmpfiles.d/libselinux1.conf; systemctl is-active systemd-tmpfiles-setup.service; systemctl is-enabled systemd-tmpfiles-clean.timer; stat -c "%A %U:%G %n" /run/setrans /usr/lib/tmpfiles.d/libselinux1.conf 2>&1 || true'

section "libselinux1-tmpfiles-attacker"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  touch /run/setrans/attacker 2>&1 || true
  printf "d /run/setrans 0777 root root - -\n" > /usr/lib/tmpfiles.d/libselinux1.conf 2>&1 || true
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/libselinux1.conf 2>&1 | sed -n "1,30p" || true
'"'"''

section "adduser-default-proof"
in_target 'stat -c "%A %U:%G %n" /etc/adduser.conf /usr/sbin/adduser /usr/sbin/addgroup /usr/share/perl5/Debian/AdduserCommon.pm /etc/skel; grep -nE "system\\(|open\\(|copy_to_dir|chown|chmod|NAME_REGEX|skel|zsysctl" /usr/sbin/adduser /usr/sbin/addgroup /usr/share/perl5/Debian/Adduser*.pm /etc/adduser.conf 2>/dev/null | sed -n "1,160p"'

section "adduser-attacker"
in_target 'runuser -u attacker -- sh -lc '"'"'
  id
  printf "DIR_MODE=0777\n" > /etc/adduser.conf 2>&1 || true
  timeout 5 adduser --system --no-create-home pkspecprobe 2>&1 | sed -n "1,60p" || true
  timeout 5 adduser --system --home /root/pkspecprobe --shell /bin/sh pkspecprobe2 2>&1 | sed -n "1,60p" || true
  getent passwd pkspecprobe pkspecprobe2 || true
'"'"''

section "cleanup-health"
in_target 'rm -rf /tmp/dsh-root /tmp/initramfs-attacker /tmp/thin-fake.meta /root/package_specific_helpers_root; systemctl is-system-running; systemctl --failed --no-legend | wc -l'

section "result"
echo "ROOT_PROOF=NO"
