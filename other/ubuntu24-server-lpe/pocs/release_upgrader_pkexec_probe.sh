#!/usr/bin/env bash
set -euo pipefail

MARK=/root/release_upgrader_pkexec_root_marker
TMP=/tmp/release-upgrader-pkexec

log() { printf '[%s] %s\n' "$(date -Is)" "$*"; }
run() {
  log "CMD $*"
  set +e
  "$@" 2>&1 | sed 's/^/    /'
  local rc=${PIPESTATUS[0]}
  set -e
  log "RC $rc"
}

rm -rf "$TMP"
mkdir -p "$TMP"
rm -f "$MARK"

log "identity"
id attacker
id selfauth

log "package versions"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  ubuntu-release-upgrader-core update-manager-core python3-update-manager \
  update-notifier-common polkitd dbus pkexec 2>&1 | sed 's/^/    /'

log "default files"
for p in \
  /usr/bin/do-release-upgrade \
  /usr/lib/ubuntu-release-upgrader/do-partial-upgrade \
  /usr/lib/update-notifier/cddistupgrader \
  /usr/share/polkit-1/actions/com.ubuntu.release-upgrader.policy \
  /usr/share/polkit-1/actions/com.ubuntu.update-notifier.policy
do
  [ -e "$p" ] && stat -Lc '%A %U:%G %n' "$p" || echo "    MISSING $p"
done
command -v pkexec >/dev/null && echo "    pkexec=$(command -v pkexec)" || echo "    pkexec=ABSENT"

log "policy snippets"
grep -nE 'action id=|exec.path|allow_(any|inactive|active)' \
  /usr/share/polkit-1/actions/com.ubuntu.release-upgrader.policy \
  /usr/share/polkit-1/actions/com.ubuntu.update-notifier.policy | sed 's/^/    /'

log "system dbus release-upgrader exposure"
find /usr/share/dbus-1/system-services /usr/share/dbus-1/system.d /etc/dbus-1/system.d \
  -maxdepth 1 -type f -print 2>/dev/null | xargs grep -l 'release-upgrader\|DistUpgrade\|cddist' 2>/dev/null | sed 's/^/    /' || true

log "attacker direct helper execution"
run runuser -u attacker -- env -i HOME=/home/attacker USER=attacker LOGNAME=attacker SHELL=/bin/bash \
  PATH="$TMP/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  PYTHONPATH="$TMP/py" \
  /usr/bin/do-release-upgrade --help
run runuser -u attacker -- env -i HOME=/home/attacker USER=attacker LOGNAME=attacker SHELL=/bin/bash \
  PATH="$TMP/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  PYTHONPATH="$TMP/py" \
  /usr/bin/do-release-upgrade -f DistUpgradeViewNonInteractive -m server -q
run runuser -u attacker -- env -i HOME=/home/attacker USER=attacker LOGNAME=attacker SHELL=/bin/bash \
  PATH="$TMP/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  PYTHONPATH="$TMP/py" \
  /usr/lib/ubuntu-release-upgrader/do-partial-upgrade
run runuser -u attacker -- env -i HOME=/home/attacker USER=attacker LOGNAME=attacker SHELL=/bin/bash \
  PATH="$TMP/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  PYTHONPATH="$TMP/py" \
  /usr/lib/update-notifier/cddistupgrader

log "attacker cannot use pkexec path when pkexec absent"
run runuser -u attacker -- sh -lc 'command -v pkexec || true; pkexec /usr/bin/do-release-upgrade --help'

log "attacker systemd start attempts"
run runuser -u attacker -- systemctl start update-notifier-motd.service
run runuser -u attacker -- systemctl start update-notifier-download.service

log "root marker proof"
if [ -e "$MARK" ]; then
  stat -Lc '%A %U:%G %n' "$MARK"
  cat "$MARK"
  echo "ROOT_PROOF=yes"
else
  echo "ROOT_PROOF=no"
fi

log "cleanup"
rm -rf "$TMP"
rm -f "$MARK"
find /tmp /root -maxdepth 1 -name '*release-upgrader-pkexec*' -ls 2>/dev/null || true
systemctl is-system-running || true
systemctl --failed --no-legend || true
