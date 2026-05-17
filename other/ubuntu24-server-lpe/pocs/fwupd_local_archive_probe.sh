#!/usr/bin/env bash
set -uo pipefail

TARGET_CONTAINER="${TARGET_CONTAINER:-ubuntu24-server-lpe-target}"

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

T=34
tmp="$(mktemp -d /tmp/fwupd-local-archive.XXXXXX)"
chmod 755 "$tmp"

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
  rm -rf "$tmp"
}
trap cleanup EXIT

section "target identity and package proof"
cat /etc/os-release
uname -a
id attacker
id selfauth
getent group sudo adm plugdev fwupd 2>/dev/null || true
dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' \
  fwupd fwupd-signed libfwupd2 libjcat1 libarchive13 dbus systemd polkitd 2>/dev/null || true

section "default fwupd service and policy proof"
busctl --system --no-pager list 2>/dev/null | awk '/fwupd|PolicyKit/{print}'
systemctl show fwupd.service fwupd-refresh.timer \
  -p Id -p LoadState -p ActiveState -p SubState -p UnitFileState \
  -p FragmentPath -p ConditionResult -p Result --no-pager 2>/dev/null
printf '\n[dbus service]\n'
sed -n '1,80p' /usr/share/dbus-1/system-services/org.freedesktop.fwupd.service
printf '\n[systemd unit]\n'
sed -n '1,80p' /usr/lib/systemd/system/fwupd.service
printf '\n[fwupd polkit actions]\n'
python3 - <<'PY'
import xml.etree.ElementTree as ET
root = ET.parse("/usr/share/polkit-1/actions/org.freedesktop.fwupd.policy").getroot()
for action in root.findall("action"):
    action_id = action.attrib.get("id", "")
    if not action_id.startswith("org.freedesktop.fwupd."):
        continue
    defaults = action.find("defaults")
    def val(name):
        node = defaults.find(name) if defaults is not None else None
        return node.text if node is not None else ""
    print(f"{action_id}\tany={val('allow_any')}\tinactive={val('allow_inactive')}\tactive={val('allow_active')}")
PY

section "direct activation checks as attacker"
run_user attacker "busctl --system --timeout=6 call org.freedesktop.fwupd / org.freedesktop.DBus.Peer Ping"
run_user attacker "fwupdmgr --version"
run "systemctl start fwupd.service"
run "systemctl status fwupd.service --no-pager -l | sed -n '1,120p'"

section "attacker-controlled archive inputs"
printf 'not a cabinet\n' > "$tmp/notcab.cab"
printf 'probe firmware\n' > "$tmp/probe.bin"
sha="$(sha256sum "$tmp/probe.bin" | awk '{print $1}')"
cat > "$tmp/probe.metainfo.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<component type="firmware">
  <id>com.example.fwupd-local-archive.probe</id>
  <name>fwupd local archive probe</name>
  <summary>fwupd local archive probe</summary>
  <description><p>Probe metadata for default-reachability testing.</p></description>
  <provides>
    <firmware type="flashed">aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</firmware>
  </provides>
  <releases>
    <release version="1.0" date="2026-05-16">
      <checksum target="content" filename="probe.bin" type="sha256">$sha</checksum>
    </release>
  </releases>
</component>
EOF
timeout "$T" fwupdtool build-cabinet "$tmp/probe.cab" "$tmp/probe.bin" "$tmp/probe.metainfo.xml" 2>&1
printf '[build-cabinet rc=%s]\n' "$?"
ls -l "$tmp"
chown -R attacker:attacker "$tmp"
run_user attacker "fwupdmgr --no-metadata-check get-details '$tmp/notcab.cab'"
run_user attacker "fwupdmgr --no-metadata-check get-details '$tmp/probe.cab'"
run_user attacker "fwupdmgr --assume-yes --no-metadata-check --no-reboot-check --no-device-prompt local-install '$tmp/probe.cab'"

section "active selfauth policy and archive path"
cat > "$tmp/selfauth-inner.sh" <<'EOF'
#!/usr/bin/env bash
set +e
bad="$1"
cab="$2"
echo "[selfauth identity]"
id
echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
tty || true
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" -p Active -p Remote -p Type -p Class -p State -p Name -p User -p TTY 2>/dev/null || true
fi
loginctl user-status selfauth 2>/dev/null | sed -n '1,80p' || true
for action in org.freedesktop.fwupd.update-internal-trusted org.freedesktop.fwupd.update-hotplug-trusted; do
  echo
  echo "$ pkcheck --action-id $action --process $$"
  timeout 12 pkcheck --action-id "$action" --process "$$" 2>&1
  echo "[pkcheck rc=$?]"
done
echo
echo "$ fwupdmgr --no-metadata-check get-details $bad"
timeout 34 fwupdmgr --no-metadata-check get-details "$bad" </dev/null 2>&1
echo "[rc=$?]"
echo
echo "$ fwupdmgr --no-metadata-check get-details $cab"
timeout 34 fwupdmgr --no-metadata-check get-details "$cab" </dev/null 2>&1
echo "[rc=$?]"
echo
echo "$ fwupdmgr --assume-yes --no-metadata-check --no-reboot-check --no-device-prompt local-install $cab"
timeout 34 fwupdmgr --assume-yes --no-metadata-check --no-reboot-check --no-device-prompt local-install "$cab" </dev/null 2>&1
echo "[rc=$?]"
EOF
chmod 755 "$tmp/selfauth-inner.sh"
chown selfauth:selfauth "$tmp/selfauth-inner.sh" "$tmp/notcab.cab" "$tmp/probe.cab"
cat > "$tmp/selfauth-input" <<EOF
$tmp/selfauth-inner.sh $tmp/notcab.cab $tmp/probe.cab
exit
EOF
timeout 130 script -q -e -c "su - selfauth" /dev/null < "$tmp/selfauth-input" 2>&1
printf '[active-selfauth rc=%s]\n' "$?"

section "post-check and verdict"
systemctl show fwupd.service -p ActiveState -p SubState -p Result -p ConditionResult --no-pager 2>/dev/null
busctl --system --no-pager list 2>/dev/null | awk '/fwupd|PolicyKit/{print}'
find /root -maxdepth 1 -name 'fwupd-local-archive*' -printf '%M %u %g %p\n' 2>/dev/null || true
if systemctl is-active --quiet fwupd.service; then
  echo "verdict=unexpected-fwupd-active-review-log"
else
  echo "verdict=no-root-lpe-default-fwupd-blocked-by-ConditionVirtualization-container"
fi
TARGET_SH
