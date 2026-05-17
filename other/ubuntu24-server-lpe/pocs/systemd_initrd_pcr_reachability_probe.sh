#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/systemd-initrd-pcr-reachability-20260517.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -Eeuo pipefail

name=systemd-initrd-pcr-reachability-20260517
work="/tmp/$name"
root_marker="/root/${name}-root"

cleanup() {
  rm -rf "$work" "/home/attacker/$name" /tmp/${name}-*
  rm -f "$root_marker"
  systemctl reset-failed \
    initrd-parse-etc.service initrd-udevadm-cleanup-db.service \
    initrd-switch-root.service systemd-hibernate-resume.service \
    systemd-tpm2-setup-early.service systemd-pcrphase-initrd.service \
    systemd-pcrphase-sysinit.service systemd-pcrphase.service \
    systemd-pcrfs-root.service systemd-udev-settle.service >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
cleanup

units='initrd-parse-etc.service initrd-udevadm-cleanup-db.service initrd-switch-root.service systemd-hibernate-resume.service systemd-tpm2-setup-early.service systemd-pcrphase-initrd.service systemd-pcrphase-sysinit.service systemd-pcrphase.service systemd-pcrfs-root.service systemd-pcrfs@.service systemd-udev-settle.service'
helpers='/usr/lib/systemd/system-generators/systemd-fstab-generator /usr/lib/systemd/systemd-hibernate-resume /usr/lib/systemd/systemd-tpm2-setup /usr/lib/systemd/systemd-pcrextend /usr/bin/udevadm /usr/bin/systemctl'

echo "systemd initrd/PCR/TPM reachability probe"
date --iso-8601=seconds
echo

echo "== default target proof =="
sed -n '1,8p' /etc/os-release
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  systemd udev initramfs-tools 2>&1 | sort
echo

echo "== unit files and live state =="
for u in $units; do
  echo "-- $u"
  systemctl show "$u" \
    -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p ConditionResult -p FragmentPath -p AssertResult \
    -p ExecStart -p User -p Group --no-pager 2>&1 || true
done
echo

echo "== unit config snippets =="
for u in $units; do
  echo "-- cat $u"
  systemctl cat "$u" 2>/dev/null | sed -n '1,120p' || true
done
echo

echo "== helper metadata =="
for b in $helpers; do
  if [ -e "$b" ]; then
    stat -Lc '%A %a %U:%G %s %n' "$b"
    getcap -v "$b" 2>/dev/null || true
  else
    echo "MISSING $b"
  fi
done
echo

echo "== reachability path permissions =="
for p in \
  /etc/initrd-release /sysroot /sysroot/etc /sysroot/etc/fstab \
  /run/initramfs /run/udev /run/udev/data /run/udev/tags \
  /run/systemd /run/systemd/system /run/systemd/io.systemd.PCRExtend \
  /dev/tpm0 /dev/tpmrm0 /sys/firmware/efi /sys/fs/pstore /sys/power/resume; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$p" 2>&1 || ls -ld "$p" 2>&1 || true
  else
    echo "ABSENT $p"
  fi
done
echo

echo "== attacker trigger attempts =="
runuser -u attacker -- bash -s <<'ATTACKER'
set +e
name=systemd-initrd-pcr-reachability-20260517
work="/home/attacker/$name"
mkdir -p "$work"/{gen-normal,gen-early,gen-late,sysroot/etc}
printf 'tmpfs /tmp/%s tmpfs defaults 0 0\n' "$name" > "$work/sysroot/etc/fstab"
echo "attacker id: $(id)"

for p in \
  /sysroot/etc/fstab \
  /run/udev/data/attacker \
  /run/udev/tags/systemd/attacker \
  /run/systemd/io.systemd.PCRExtend \
  /sys/power/resume; do
  printf 'probe' > "$p" 2>"$work/write.err"
  rc=$?
  printf 'write %-45s rc=%s ' "$p" "$rc"
  cat "$work/write.err"
done

for u in \
  initrd-parse-etc.service \
  initrd-udevadm-cleanup-db.service \
  initrd-switch-root.service \
  systemd-hibernate-resume.service \
  systemd-tpm2-setup-early.service \
  systemd-pcrphase-initrd.service \
  systemd-pcrphase-sysinit.service \
  systemd-pcrphase.service \
  systemd-pcrfs-root.service \
  systemd-udev-settle.service; do
  echo "-- attacker systemctl start $u"
  timeout 6 systemctl start "$u" 2>&1
  echo "rc=$?"
done

echo "-- direct fstab generator as attacker into attacker-owned dirs"
SYSTEMD_SYSROOT_FSTAB="$work/sysroot/etc/fstab" \
  timeout 6 /usr/lib/systemd/system-generators/systemd-fstab-generator \
  "$work/gen-normal" "$work/gen-early" "$work/gen-late" 2>&1
echo "generator_rc=$?"
find "$work" -maxdepth 3 -type f -printf '%M %u:%g %p\n' | sort

echo "-- direct root helpers as attacker"
timeout 6 /usr/bin/udevadm info --cleanup-db 2>&1
echo "udevadm_cleanup_rc=$?"
timeout 6 /usr/bin/udevadm settle 2>&1
echo "udevadm_settle_rc=$?"
timeout 6 /usr/lib/systemd/systemd-pcrextend --graceful --file-system="$work" 2>&1
echo "pcrextend_fs_rc=$?"
timeout 6 /usr/lib/systemd/systemd-pcrextend --graceful attacker-phase 2>&1
echo "pcrextend_phase_rc=$?"
timeout 6 /usr/lib/systemd/systemd-tpm2-setup --early=yes 2>&1
echo "tpm2_setup_rc=$?"
timeout 6 /usr/lib/systemd/systemd-hibernate-resume 2>&1
echo "hibernate_resume_rc=$?"

echo "-- login1 reboot/hibernate authorization without active seat"
for a in \
  org.freedesktop.login1.reboot \
  org.freedesktop.login1.hibernate \
  org.freedesktop.login1.power-off; do
  pkcheck --action-id "$a" --process $$ >/dev/null 2>&1
  echo "$a rc=$?"
done
ATTACKER
echo

echo "== root proof and health =="
if [ -e "$root_marker" ]; then
  echo "ROOT_MARKER_PRESENT"
  ls -l "$root_marker"
  cat "$root_marker" 2>/dev/null || true
else
  echo "ROOT_MARKER_ABSENT"
fi
echo "ROOT_PROOF=$(test -e "$root_marker" && echo yes || echo no)"
systemctl is-system-running || true
systemctl --failed --no-pager || true
EOS

echo "wrote $log"
