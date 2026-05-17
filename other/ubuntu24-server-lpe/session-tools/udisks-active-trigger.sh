#!/usr/bin/env bash
set -u

method="${1:-Check}"
fstype="${2:-ext4}"
work="/home/selfauth/udisks-missing-goto-active"
mkdir -p "$work"
cd "$work"

echo "identity=$(id)"
echo "session:"
loginctl user-status "$(id -u)" --no-pager 2>/dev/null | sed -n '1,35p' || true

img="$work/${fstype}-${method}.img"
rm -f "$img"
case "$fstype" in
  ext4)
    truncate -s 96M "$img"
    mkfs.ext4 -F -q "$img"
    ;;
  xfs)
    truncate -s 512M "$img"
    mkfs.xfs -f -q "$img"
    ;;
  vfat)
    truncate -s 64M "$img"
    mkfs.vfat "$img"
    ;;
  ntfs)
    truncate -s 96M "$img"
    mkfs.ntfs -F -Q -L UDISKSNTFS "$img"
    ;;
  btrfs)
    truncate -s 128M "$img"
    mkfs.btrfs -q -f "$img"
    ;;
  *)
    echo "unsupported fstype: $fstype" >&2
    exit 2
    ;;
esac

echo "image=$img"
loop_out="$(udisksctl loop-setup -f "$img" 2>&1)"
loop_rc=$?
echo "$loop_out"
echo "loop_setup_rc=$loop_rc"
if [ "$loop_rc" -ne 0 ]; then
  exit "$loop_rc"
fi

dev="$(printf '%s\n' "$loop_out" | sed -n 's/.* as \(\/dev\/loop[0-9][0-9]*\).*/\1/p' | tail -n 1)"
if [ -z "$dev" ]; then
  echo "failed to parse loop device" >&2
  exit 3
fi
base="${dev##*/}"
obj="/org/freedesktop/UDisks2/block_devices/$base"
echo "dev=$dev"
echo "obj=$obj"

sleep 1
gdbus call --system \
  --dest org.freedesktop.UDisks2 \
  --object-path "$obj" \
  --method org.freedesktop.UDisks2.Block.Rescan "{}" 2>&1 || true
sleep 1

mount_out="$(udisksctl mount -b "$dev" 2>&1)"
mount_rc=$?
echo "$mount_out"
echo "mount_rc=$mount_rc"
findmnt "$dev" || true
sleep 1

case "$method" in
  Check|Repair)
    python3 /tmp/udisks-missing-goto-gdb-persistent-call.py "$obj" "$method"
    ;;
  Resize)
    python3 /tmp/udisks-missing-goto-gdb-persistent-call.py "$obj" "$method" 33554432
    ;;
  *)
    echo "unsupported method: $method" >&2
    exit 4
    ;;
esac
echo "method_rc=$?"
