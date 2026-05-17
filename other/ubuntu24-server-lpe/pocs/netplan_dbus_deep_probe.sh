#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/netplan-dbus-deep.out"

mkdir -p "$repo_dir/logs"
tmp_log="$(mktemp "$repo_dir/logs/netplan-dbus-deep.out.tmp.XXXXXX")"

docker exec -i "$container" bash -s >"$tmp_log" 2>&1 <<'ROOTSH'
set +e

WORK=/tmp/netplan-dbus-deep
FAKEBIN=$WORK/fakebin
ROOT_MARKER=/root/netplan_dbus_deep_root_marker
FAKE_MARKER=/root/netplan_dbus_deep_fake_helper
ESCAPE_ROOT=/root/netplan_dbus_deep_origin_escape.yaml
CMD_ROOT=/root/netplan_dbus_deep_cmd_marker
ESCAPE_TMP=/tmp/netplan-dbus-deep-origin-escape.yaml
ABS_TMP=/tmp/netplan-dbus-deep-abs.yaml
SYMLINK_TARGET=/tmp/netplan-dbus-deep-symlink-target.yaml
ATTACKER_ESCAPE=/tmp/netplan-dbus-deep-attacker-escape.yaml

mkdir -p "$WORK" "$FAKEBIN"
chmod 0755 "$WORK" "$FAKEBIN"
rm -f "$ROOT_MARKER" "$FAKE_MARKER" "$ESCAPE_ROOT" "$CMD_ROOT" \
      "$ESCAPE_TMP" "$ABS_TMP" "$SYMLINK_TARGET" "$ATTACKER_ESCAPE" \
      /tmp/netplan-dbus-deep-state-*.sha256

section() {
  printf '\n## %s\n' "$1"
}

run_root() {
  local label="$1"
  shift
  section "$label"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
  local rc=$?
  printf 'rc=%s\n' "$rc"
}

run_root_sh() {
  local label="$1"
  local cmd="$2"
  local timeout_s="${3:-10}"
  section "$label"
  printf '$ %s\n' "$cmd"
  timeout "$timeout_s" bash -lc "$cmd"
  local rc=$?
  printf 'rc=%s\n' "$rc"
}

run_as() {
  local user="$1"
  local label="$2"
  local cmd="$3"
  local timeout_s="${4:-10}"
  section "$user: $label"
  printf '$ runuser -u %s -- bash -lc %q\n' "$user" "$cmd"
  timeout "$timeout_s" runuser -u "$user" -- bash -lc "$cmd"
  local rc=$?
  printf 'rc=%s\n' "$rc"
}

state_digest() {
  local label="$1"
  section "state digest: $label"
  python3 - "$label" <<'PY'
import hashlib
import os
import stat
import sys

label = sys.argv[1]
roots = ["/etc/netplan", "/run/netplan", "/run/systemd/network", "/run/NetworkManager"]
h = hashlib.sha256()

for root in roots:
    if not os.path.lexists(root):
        h.update(f"MISSING\t{root}\n".encode())
        continue
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs.sort()
        files.sort()
        names = dirs + files
        for name in names:
            path = os.path.join(base, name)
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            meta = f"{path}\t{st.st_mode:o}\t{mode:o}\t{st.st_uid}:{st.st_gid}\t{st.st_size}"
            if stat.S_ISLNK(st.st_mode):
                try:
                    meta += "\tLINK=" + os.readlink(path)
                except OSError as exc:
                    meta += "\tLINKERR=" + repr(exc)
            h.update((meta + "\n").encode())
            if stat.S_ISREG(st.st_mode) and st.st_size <= 1024 * 1024:
                try:
                    with open(path, "rb") as f:
                        h.update(hashlib.sha256(f.read()).hexdigest().encode() + b"\n")
                except OSError as exc:
                    h.update((f"READERR={exc!r}\n").encode())

print(f"{label}={h.hexdigest()}")
PY
}

state_ls() {
  local label="$1"
  section "state listing: $label"
  for p in /etc/netplan /run/netplan /run/systemd/network /run/NetworkManager; do
    echo "### $p"
    find "$p" -maxdepth 6 -printf '%M %u:%g %s %p -> %l\n' 2>&1 | sort
  done
}

new_config_object() {
  local out obj
  out="$(busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Config 2>&1)"
  printf '%s\n' "$out" >&2
  obj="$(printf '%s\n' "$out" | sed -nE 's/^o "([^"]+)"/\1/p')"
  printf '%s\n' "$obj"
}

cancel_config_object() {
  local obj="$1"
  if [ -n "$obj" ]; then
    busctl --system call io.netplan.Netplan "$obj" io.netplan.Netplan.Config Cancel
  fi
}

cat >"$FAKEBIN/netplan" <<'SH'
#!/bin/sh
id > /root/netplan_dbus_deep_fake_helper
printf 'fake netplan executed\n' >> /root/netplan_dbus_deep_fake_helper
exit 77
SH
cat >"$FAKEBIN/generate" <<'SH'
#!/bin/sh
id > /root/netplan_dbus_deep_fake_helper
printf 'fake generate executed\n' >> /root/netplan_dbus_deep_fake_helper
exit 77
SH
chmod 0755 "$FAKEBIN/netplan" "$FAKEBIN/generate"

section "target identity, default packages, users"
{
  cat /etc/os-release
  uname -a
  id attacker
  id selfauth
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    netplan.io libnetplan1 dbus dbus-daemon dbus-system-bus-common systemd polkitd policykit-1 2>&1 | sort
}

section "default active and reachable state"
{
  stat -c '%A %U:%G %n' /run/dbus/system_bus_socket 2>&1
  systemctl is-active dbus.service 2>&1
  systemctl status dbus.service --no-pager --lines=25 2>&1
  busctl --system list --no-pager | egrep 'io.netplan.Netplan|org.freedesktop.DBus|PolicyKit|systemd1' || true
  busctl --system status io.netplan.Netplan 2>&1
  cat /usr/share/dbus-1/system-services/io.netplan.Netplan.service 2>&1
  cat /usr/share/dbus-1/system.d/io.netplan.Netplan.conf 2>&1
}

section "netplan D-Bus interface"
{
  busctl --system tree io.netplan.Netplan 2>&1
  busctl --system introspect io.netplan.Netplan /io/netplan/Netplan --xml-interface 2>&1
  busctl --system introspect io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan 2>&1
}

state_digest before-unprivileged-triggers
state_ls before-unprivileged-triggers

for user in attacker selfauth; do
  run_as "$user" "identity and bus visibility" 'id; groups; busctl --system list --no-pager | egrep "io.netplan.Netplan|org.freedesktop.DBus" || true'
  run_as "$user" "root object introspection is readable" 'busctl --system introspect io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan'
  run_as "$user" "Info denied" 'busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Info'
  run_as "$user" "Generate denied" 'busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Generate'
  run_as "$user" "Apply denied" 'busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Apply'
  run_as "$user" "Config denied" 'busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Config'
  run_as "$user" "system-bus activation environment denied" \
    "busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus UpdateActivationEnvironment a{ss} 2 DBUS_TEST_NETPLAN_ROOT $WORK/activation-root PATH $FAKEBIN"
  run_as "$user" "caller PATH/env does not reach denied Generate" \
    "PATH=$FAKEBIN:\$PATH DBUS_TEST_NETPLAN_ROOT=$WORK/user-root busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Generate"
done

state_digest after-unprivileged-root-object-triggers

section "root-created config object for unprivileged method checks"
CFG_OBJ="$(new_config_object)"
CFG_TAG="${CFG_OBJ##*/}"
CFG_DIR="/run/netplan/config-$CFG_TAG"
echo "CFG_OBJ=$CFG_OBJ"
echo "CFG_DIR=$CFG_DIR"
stat -c '%A %U:%G %n' /run/netplan "$CFG_DIR" "$CFG_DIR/etc" "$CFG_DIR/etc/netplan" 2>&1
busctl --system introspect io.netplan.Netplan "$CFG_OBJ" --xml-interface 2>&1
busctl --system introspect io.netplan.Netplan "$CFG_OBJ" io.netplan.Netplan.Config 2>&1

for user in attacker selfauth; do
  run_as "$user" "known config object Get denied" \
    "busctl --system call io.netplan.Netplan $CFG_OBJ io.netplan.Netplan.Config Get"
  run_as "$user" "known config object Set normal denied" \
    "busctl --system call io.netplan.Netplan $CFG_OBJ io.netplan.Netplan.Config Set ss network.version=2 attacker-origin"
  run_as "$user" "known config object Set path traversal denied" \
    "busctl --system call io.netplan.Netplan $CFG_OBJ io.netplan.Netplan.Config Set ss network.version=2 ../../../../tmp/netplan-dbus-deep-attacker-escape"
  run_as "$user" "known config object Set absolute root path denied" \
    "busctl --system call io.netplan.Netplan $CFG_OBJ io.netplan.Netplan.Config Set ss network.version=2 /root/netplan_dbus_deep_attacker_abs"
  run_as "$user" "known config object Try denied" \
    "busctl --system call io.netplan.Netplan $CFG_OBJ io.netplan.Netplan.Config Try u 1"
  run_as "$user" "known config object Apply denied" \
    "busctl --system call io.netplan.Netplan $CFG_OBJ io.netplan.Netplan.Config Apply"
  run_as "$user" "known config object Cancel denied" \
    "busctl --system call io.netplan.Netplan $CFG_OBJ io.netplan.Netplan.Config Cancel"
  run_as "$user" "temp path traversal and symlink attempts fail" \
    "set +e; ls -ld /run/netplan $CFG_DIR $CFG_DIR/etc/netplan; touch $CFG_DIR/etc/netplan/attacker.yaml; ln -s /root/netplan_dbus_deep_root_marker $CFG_DIR/etc/netplan/race.yaml; rm -f $CFG_DIR/etc/netplan/99-probe.yaml; find /run/netplan -maxdepth 3 -ls"
done

section "attacker race against root-owned temp config path"
race_err=/tmp/netplan-dbus-deep-race.err
rm -f "$race_err"
touch "$race_err"
chmod 0666 "$race_err"
runuser -u attacker -- bash -lc "set +e; for i in \$(seq 1 3); do mkdir -p '$CFG_DIR/etc/netplan' 2>>'$race_err'; ln -sf /root/netplan_dbus_deep_root_marker '$CFG_DIR/etc/netplan/race.yaml' 2>>'$race_err'; echo x > '$CFG_DIR/etc/netplan/99-race.yaml' 2>>'$race_err'; done; sort -u '$race_err' | sed -n '1,20p'"
printf 'rc=%s\n' "$?"
find "$CFG_DIR" -maxdepth 5 -printf '%M %u:%g %s %p -> %l\n' 2>&1 | sort
ls -l "$ROOT_MARKER" "$ATTACKER_ESCAPE" 2>&1 || true
rm -f "$race_err"

section "root-control Set/Get, origin path handling, and symlink handling"
busctl --system call io.netplan.Netplan "$CFG_OBJ" io.netplan.Netplan.Config Set ss network.version=2 99-deep
echo "set-version-rc=$?"
busctl --system call io.netplan.Netplan "$CFG_OBJ" io.netplan.Netplan.Config Set ss ethernets.eth999.dhcp4=true 99-deep
echo "set-eth-rc=$?"
busctl --system call io.netplan.Netplan "$CFG_OBJ" io.netplan.Netplan.Config Get
echo "get-rc=$?"
find "$CFG_DIR" -maxdepth 6 -printf '%M %u:%g %s %p -> %l\n' 2>&1 | sort
find "$CFG_DIR" -maxdepth 6 -type f -printf 'FILE %M %u:%g %s %p\n' -exec sed -n '1,80p' {} \; 2>&1

for hint in ../escape ../../../../tmp/netplan-dbus-deep-origin-escape /tmp/netplan-dbus-deep-abs /root/netplan_dbus_deep_origin_escape 'semi;touch /root/netplan_dbus_deep_cmd_marker' weird/name; do
  echo "origin-hint=$hint"
  busctl --system call io.netplan.Netplan "$CFG_OBJ" io.netplan.Netplan.Config Set ss network.version=2 "$hint"
  echo "origin-rc=$?"
done
ls -l "$ESCAPE_TMP" "$ABS_TMP" "$ESCAPE_ROOT" "$CMD_ROOT" 2>&1 || true

ln -s "$SYMLINK_TARGET" "$CFG_DIR/etc/netplan/symlink.yaml"
ls -l "$CFG_DIR/etc/netplan/symlink.yaml"
busctl --system call io.netplan.Netplan "$CFG_OBJ" io.netplan.Netplan.Config Set ss network.version=2 symlink
echo "symlink-set-rc=$?"
ls -l "$CFG_DIR/etc/netplan/symlink.yaml" "$SYMLINK_TARGET" 2>&1 || true

section "root-control caller environment and helper execution checks"
env PATH="$FAKEBIN:$PATH" DBUS_TEST_NETPLAN_ROOT="$WORK/root-env" \
  busctl --system call io.netplan.Netplan /io/netplan/Netplan io.netplan.Netplan Generate
echo "root-generate-env-rc=$?"
ls -l "$FAKE_MARKER" "$WORK/root-env" 2>&1 || true

section "cleanup first config object"
cancel_config_object "$CFG_OBJ"
echo "cancel-first-rc=$?"
busctl --system introspect io.netplan.Netplan "$CFG_OBJ" io.netplan.Netplan.Config 2>&1
echo "post-cancel-introspect-rc=$?"
ls -ld "$CFG_DIR" 2>&1 || true

section "root-control Try and Cancel semantics on empty config"
TRY_OBJ="$(new_config_object)"
TRY_TAG="${TRY_OBJ##*/}"
TRY_DIR="/run/netplan/config-$TRY_TAG"
echo "TRY_OBJ=$TRY_OBJ"
echo "TRY_DIR=$TRY_DIR"
timeout 8 busctl --system call io.netplan.Netplan "$TRY_OBJ" io.netplan.Netplan.Config Try u 1
echo "try-empty-rc=$?"
find "$TRY_DIR" -maxdepth 5 -printf '%M %u:%g %s %p -> %l\n' 2>&1 | sort
cancel_config_object "$TRY_OBJ"
echo "cancel-try-rc=$?"
busctl --system introspect io.netplan.Netplan "$TRY_OBJ" io.netplan.Netplan.Config 2>&1
echo "post-try-cancel-introspect-rc=$?"
ls -ld "$TRY_DIR" 2>&1 || true

state_digest after-cleanup
state_ls after-cleanup

section "root proof and cleanup verification"
{
  ls -l "$ROOT_MARKER" "$FAKE_MARKER" "$ESCAPE_ROOT" "$CMD_ROOT" \
        "$ESCAPE_TMP" "$ABS_TMP" "$SYMLINK_TARGET" "$ATTACKER_ESCAPE" 2>&1 || true
  rm -f "$ROOT_MARKER" "$FAKE_MARKER" "$ESCAPE_ROOT" "$CMD_ROOT" \
        "$ESCAPE_TMP" "$ABS_TMP" "$SYMLINK_TARGET" "$ATTACKER_ESCAPE"
  rm -rf "$WORK"
  echo "remaining netplan deep temp:"
  find /tmp -maxdepth 1 -name 'netplan-dbus-deep*' -printf '%M %u:%g %p\n' 2>&1 | sort
  echo "active netplan objects:"
  busctl --system tree io.netplan.Netplan 2>&1
  echo "system state:"
  systemctl is-system-running 2>&1
  systemctl --failed --no-pager 2>&1
}
ROOTSH

mv "$tmp_log" "$log_path"
printf 'wrote %s\n' "$log_path"
