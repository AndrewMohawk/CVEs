#!/bin/sh
set -eu

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
VM_DIR="$ROOT_DIR/vm"
IMG="$VM_DIR/noble-server-cloudimg-arm64.img"
DISK="$VM_DIR/noble-server-cloudimg-arm64-work.qcow2"
SEED="$VM_DIR/seed.iso"
SEED_SRC="$VM_DIR/seed-src"
VARS="$VM_DIR/edk2-aarch64-vars.fd"
QEMU=${QEMU:-/usr/local/bin/qemu-system-aarch64}
QEMU_IMG=${QEMU_IMG:-/usr/local/bin/qemu-img}
FIRMWARE=${FIRMWARE:-/usr/local/share/qemu/edk2-aarch64-code.fd}

mkdir -p "$VM_DIR" "$ROOT_DIR/logs/vm"

if [ ! -f "$IMG" ]; then
  curl -fL --retry 3 -o "$IMG.tmp" \
    https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img
  mv "$IMG.tmp" "$IMG"
fi

if [ ! -f "$DISK" ]; then
  "$QEMU_IMG" convert -f qcow2 -O qcow2 "$IMG" "$DISK"
  "$QEMU_IMG" resize "$DISK" 16G
fi

if [ ! -f "$SEED" ] || [ "$VM_DIR/user-data" -nt "$SEED" ] || [ "$VM_DIR/meta-data" -nt "$SEED" ]; then
  rm -f "$SEED"
  rm -rf "$SEED_SRC"
  mkdir -p "$SEED_SRC"
  cp "$VM_DIR/user-data" "$SEED_SRC/user-data"
  cp "$VM_DIR/meta-data" "$SEED_SRC/meta-data"
  hdiutil makehybrid -iso -joliet -default-volume-name cidata \
    -o "$SEED" "$SEED_SRC" >/dev/null
fi

if [ ! -f "$VARS" ]; then
  cp /usr/local/share/qemu/edk2-arm-vars.fd "$VARS"
fi

exec "$QEMU" \
  -machine virt,accel=tcg,highmem=off \
  -cpu cortex-a72 \
  -smp 2 \
  -m 2048 \
  -nographic \
  -drive if=pflash,format=raw,readonly=on,file="$FIRMWARE" \
  -drive if=pflash,format=raw,file="$VARS" \
  -drive if=virtio,format=qcow2,file="$DISK" \
  -drive if=virtio,format=raw,readonly=on,file="$SEED" \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=net0
