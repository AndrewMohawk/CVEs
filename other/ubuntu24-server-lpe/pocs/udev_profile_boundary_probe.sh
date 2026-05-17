#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/udev-profile-boundary.out"
tmp_log="$(mktemp "$repo_dir/logs/udev-profile-boundary.out.tmp.XXXXXX")"

docker exec -i "$container" bash <<'TARGET' >"$tmp_log" 2>&1
set +e
root_marker=/root/udev_profile_boundary_root
attacker_marker=/tmp/udev_profile_boundary_attacker

section() {
  printf '\n## %s\n' "$1"
}

cleanup() {
  rm -f "$root_marker" "$attacker_marker" /tmp/udev_profile_boundary_* 2>/dev/null || true
}
cleanup

section "target and packages"
sed -n '1,8p' /etc/os-release
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  udev systemd base-files gawk 2>&1 | sort

section "udev rules and helper ownership"
for p in \
  /usr/lib/udev/rules.d/75-probe_mtd.rules \
  /usr/lib/udev/mtd_probe \
  /usr/lib/udev/rules.d/73-special-net-names.rules \
  /run/udev/control; do
  stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>&1 || true
done
echo "### /usr/lib/udev/rules.d/75-probe_mtd.rules"
nl -ba /usr/lib/udev/rules.d/75-probe_mtd.rules 2>&1
echo "### /usr/lib/udev/rules.d/73-special-net-names.rules"
nl -ba /usr/lib/udev/rules.d/73-special-net-names.rules 2>&1 | sed -n '1,80p'

section "hardware/sysfs reachability"
for p in /sys/class/mtd /sys/bus/vio /sys/devices/vio /sys/class/net; do
  stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>&1 || true
done
find /sys/class/mtd /sys/bus/vio /sys/devices/vio -maxdepth 3 -ls 2>&1 | sed -n '1,120p'
echo "### net devices"
find /sys/class/net -maxdepth 1 -mindepth 1 -printf '%p -> ' -exec readlink -f {} \; 2>&1 | sed -n '1,80p'

section "attacker udev trigger attempts"
runuser -u attacker -- bash -lc '
set +e
id
echo "### trigger mtd"
udevadm trigger --subsystem-match=mtd 2>&1
echo "rc=$?"
echo "### trigger net"
udevadm trigger --subsystem-match=net 2>&1 | sed -n "1,40p"
echo "rc=$?"
echo "### udevadm test current net devices"
for d in /sys/class/net/*; do
  [ -e "$d" ] || continue
  udevadm test "$d" 2>&1 | grep -E "73-special-net-names|ibmveth|mtd_probe|PROGRAM|Permission denied" | sed -n "1,30p"
done
'

section "ibmveth shell parser injection canary"
for d in \
  '/devices/vio/30000002/net/eth1' \
  '/devices/vio/3000;id>/root/udev_profile_boundary_root/net/eth1' \
  '/devices/vio/$(id>/root/udev_profile_boundary_root)/net/eth1' \
  '/devices/vio/`id>/root/udev_profile_boundary_root`/net/eth1' \
  '/devices/vio/3000
id>/root/udev_profile_boundary_root/net/eth1'; do
  printf 'DEVPATH=%q -> ' "$d"
  DEVPATH="$d" /bin/sh -ec 'D=${DEVPATH#*/vio/}; D=${D%%/*}; D=${D#????}; D=${D#0}; D=${D#0}; D=${D#0}; D=${D#0}; echo ${D:-0}' 2>&1
done
stat -Lc '%A %a %U:%G %F %n' "$root_marker" 2>&1 || true

section "profile scripts and locale-check behavior"
for p in /etc/profile /etc/profile.d /etc/profile.d/01-locale-fix.sh /usr/bin/locale-check /etc/profile.d/gawk.sh; do
  stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>&1 || true
done
echo "### /etc/profile.d/01-locale-fix.sh"
nl -ba /etc/profile.d/01-locale-fix.sh 2>&1
echo "### /etc/profile.d/gawk.sh"
nl -ba /etc/profile.d/gawk.sh 2>&1

for var in LANG LC_ALL LC_ADDRESS LC_COLLATE LC_CTYPE LC_MESSAGES LC_MONETARY LC_NUMERIC LC_TIME LANGUAGE; do
  for val in 'bad;id>/root/udev_profile_boundary_root' 'bad$(id>/root/udev_profile_boundary_root)' 'en_US.UTF-8@x;id>/root/udev_profile_boundary_root'; do
    echo "### locale-check $var=$val"
    env "$var=$val" /usr/bin/locale-check C.UTF-8 2>&1
  done
done
echo "### root login-shell locale eval canary"
env -i HOME=/root PATH=/usr/bin:/bin \
  LC_ALL='bad;id>/root/udev_profile_boundary_root' \
  LANG='bad$(id>/root/udev_profile_boundary_root)' \
  bash -l -c 'printf "LC_ALL=%s LANG=%s\n" "$LC_ALL" "$LANG"' 2>&1
stat -Lc '%A %a %U:%G %F %n' "$root_marker" 2>&1 || true

section "attacker profile/gawk path hijack stays unprivileged"
runuser -u attacker -- bash -lc '
set +e
id
tmp=$(mktemp -d /tmp/udev_profile_boundary_gawk.XXXXXX)
cat > "$tmp/gawk" <<'"'"'EOF'"'"'
#!/bin/sh
id > /tmp/udev_profile_boundary_attacker
printf fake-gawk
EOF
chmod +x "$tmp/gawk"
PATH="$tmp:/usr/bin:/bin" bash -l -c '"'"'type gawkpath_default; gawkpath_default; echo "rc=$?"; printf "AWKPATH=%s\n" "$AWKPATH"'"'"' 2>&1
cat /tmp/udev_profile_boundary_attacker 2>&1 || true
rm -rf "$tmp"
'
stat -Lc '%A %a %U:%G %F %n' "$root_marker" "$attacker_marker" 2>&1 || true

section "cleanup and health"
cleanup
stat -Lc '%A %a %U:%G %F %n' "$root_marker" "$attacker_marker" 2>&1 || true
systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend 2>&1 || true
TARGET

mv "$tmp_log" "$log_path"
sed -n '1,380p' "$log_path"
