#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="$WORKSPACE/logs/open-iscsi-ipc-semantics.out"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

echo "open-iscsi IPC semantics probe"
echo "target=$TARGET"
date '+%Y-%m-%dT%H:%M:%S%z'

docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail
set +e

WORK=/tmp/open-iscsi-ipc-semantics
ROOT_MARKER=/root/open_iscsi_ipc_semantics_root
NODES_BACKUP=$WORK/nodes.backup
SEND_BACKUP=$WORK/send_targets.backup
HAD_NODES=0
HAD_SEND=0

cleanup() {
  set +e
  rm -f "$ROOT_MARKER"
  if [ "$HAD_NODES" = 1 ]; then
    rm -rf /etc/iscsi/nodes
    cp -a "$NODES_BACKUP" /etc/iscsi/nodes
  else
    rm -rf /etc/iscsi/nodes
  fi
  if [ "$HAD_SEND" = 1 ]; then
    rm -rf /etc/iscsi/send_targets
    cp -a "$SEND_BACKUP" /etc/iscsi/send_targets
  else
    rm -rf /etc/iscsi/send_targets
  fi
  rm -rf /run/lock/iscsi "$WORK"
  systemctl reset-failed iscsid.service iscsid.socket >/dev/null 2>&1 || true
  systemctl start iscsid.socket >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$WORK" "$ROOT_MARKER"
mkdir -p "$WORK"
if [ -e /etc/iscsi/nodes ]; then
  HAD_NODES=1
  cp -a /etc/iscsi/nodes "$NODES_BACKUP"
fi
if [ -e /etc/iscsi/send_targets ]; then
  HAD_SEND=1
  cp -a /etc/iscsi/send_targets "$SEND_BACKUP"
fi
rm -rf /etc/iscsi/nodes /etc/iscsi/send_targets /run/lock/iscsi
systemctl reset-failed iscsid.service iscsid.socket >/dev/null 2>&1 || true
systemctl restart iscsid.socket >/dev/null 2>&1 || true

section() {
  printf '\n## %s\n' "$1"
}

section "default target and package proof"
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  open-iscsi libopeniscsiusr systemd 2>&1 | sort
systemctl cat iscsid.socket iscsid.service open-iscsi.service | sed -n '1,220p'

section "default runtime state"
systemctl status iscsid.socket iscsid.service open-iscsi.service --no-pager -l | sed -n '1,180p' || true
ss -xlpn | grep -Ei 'iscsi|ISCSI' || true
find /etc/iscsi -maxdepth 5 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

section "uid1001 direct node creation attempt"
runuser -u attacker -- iscsiadm -m node --op new \
  --targetname iqn.2026-05.invalid:codex \
  --portal 127.0.0.1:3260 2>&1
echo "node_new_rc=$?"
find /etc/iscsi -maxdepth 7 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

section "uid1001 discoverydb creation/update attempt"
runuser -u attacker -- iscsiadm -m discoverydb -t sendtargets \
  -p 127.0.0.1:3260 --op new 2>&1
echo "discoverydb_new_rc=$?"
runuser -u attacker -- iscsiadm -m discoverydb -t sendtargets \
  -p 127.0.0.1:3260 --op update \
  -n discovery.sendtargets.auth.authmethod -v None 2>&1
echo "discoverydb_update_rc=$?"
find /etc/iscsi -maxdepth 7 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

section "uid1001 discovery network trigger"
runuser -u attacker -- timeout 8 iscsiadm -m discovery -t sendtargets \
  -p 127.0.0.1:3260 2>&1
echo "discovery_rc=$?"
systemctl status iscsid.socket iscsid.service --no-pager -l | sed -n '1,180p' || true
journalctl -u iscsid.service --no-pager -n 80 | sed -n '1,140p' || true
find /etc/iscsi -maxdepth 7 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

section "root proof and health"
if [ -e "$ROOT_MARKER" ]; then
  echo "ROOT_PROOF=yes"
  stat -Lc '%A %U:%G %n' "$ROOT_MARKER"
  cat "$ROOT_MARKER"
else
  echo "ROOT_PROOF=no"
fi
systemctl reset-failed iscsid.service iscsid.socket >/dev/null 2>&1 || true
systemctl start iscsid.socket >/dev/null 2>&1 || true
systemctl is-system-running || true
systemctl --failed --no-legend || true

TARGET_SCRIPT
