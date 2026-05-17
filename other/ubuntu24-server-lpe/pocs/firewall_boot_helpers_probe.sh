#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$target" bash -s <<'TARGET'
set +e
export LC_ALL=C

probe="firewall_boot_helpers"
base="/tmp/${probe}"
ahome="/home/attacker/${probe}"
root_marker="/root/${probe}.root_marker"

section() {
  printf '\n## %s\n' "$1"
}

run_attacker() {
  label="$1"
  shift
  printf '\n### attacker: %s\n' "$label"
  runuser -u attacker -- timeout 20s bash -lc "$*" 2>&1
  printf 'rc=%s\n' "$?"
}

cleanup_probe() {
  rm -rf "${base}" "${base}".* "${ahome}" /tmp/firewall_boot_helpers* \
    /home/attacker/firewall_boot_helpers* 2>/dev/null || true
  rm -f "${root_marker}" /root/firewall_boot_helpers* 2>/dev/null || true
}

cleanup_probe

section "target and attacker"
sed -n '1,8p' /etc/os-release
uname -a
ps -p 1 -o user=,comm=,args=
id attacker
systemctl is-system-running 2>&1 || true

section "default package proof"
for pkg in ubuntu-server ubuntu-standard ufw iptables nftables \
  iptables-persistent netfilter-persistent systemd procps kmod \
  linux-base initramfs-tools; do
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null ||
    printf '%s\t(not installed)\tun\n' "$pkg"
done | sort

section "default enabled and reachable unit state"
systemctl list-unit-files --no-pager --no-legend \
  'ufw*' 'nftables*' 'netfilter*' 'iptables*' 'ip6tables*' \
  'systemd-sysctl*' 'systemd-modules-load*' 2>&1 | sort
for u in ufw.service nftables.service netfilter-persistent.service \
  iptables.service ip6tables.service systemd-sysctl.service \
  systemd-modules-load.service; do
  echo "### $u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p Result -p ConditionResult -p FragmentPath -p User -p ExecStart \
    -p ExecReload -p ExecStop "$u" 2>&1 || true
done
echo "### ufw status"
ufw status verbose 2>&1 || true

section "root-executed service files and firewall config"
for f in /usr/lib/systemd/system/ufw.service \
  /usr/lib/systemd/system/nftables.service \
  /usr/lib/systemd/system/systemd-sysctl.service \
  /usr/lib/systemd/system/systemd-modules-load.service \
  /etc/ufw/ufw.conf /etc/default/ufw /etc/ufw/before.init \
  /etc/ufw/after.init /etc/nftables.conf; do
  echo "### $f"
  if [ -e "$f" ] || [ -L "$f" ]; then
    stat -Lc '%A %a %U:%G %F %n' "$f"
    sed -n '1,180p' "$f" 2>&1
  else
    echo "MISSING $f"
  fi
done

section "helper and import path modes"
for p in /usr/sbin/ufw /usr/lib/ufw /usr/lib/ufw/ufw-init \
  /usr/lib/ufw/ufw-init-functions /lib/ufw /usr/share/ufw \
  /etc/ufw /etc/ufw/applications.d /etc/ufw/before.rules \
  /etc/ufw/after.rules /etc/ufw/user.rules /etc/ufw/sysctl.conf \
  /run/ufw /run/ufw.lock /lib/ufw/ufw.lock \
  /usr/sbin/nft /etc/nftables.conf /etc/default/nftables \
  /etc/iptables /var/lib/iptables /usr/share/netfilter-persistent \
  /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d /run/sysctl.d \
  /run/credentials /run/credentials/systemd-sysctl.service \
  /etc/modules /etc/modules-load.d /usr/lib/modules-load.d \
  /run/modules-load.d /etc/modprobe.d /usr/lib/modprobe.d \
  /run/modprobe.d /etc/systemd/system /run/systemd/system; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n -> %N' "$p"
  else
    echo "MISSING $p"
  fi
done

section "selected helper code trust points"
echo "### /usr/lib/ufw/ufw-init"
nl -ba /usr/lib/ufw/ufw-init | sed -n '1,120p'
echo "### /usr/lib/ufw/ufw-init-functions"
nl -ba /usr/lib/ufw/ufw-init-functions | sed -n '1,170p'
nl -ba /usr/lib/ufw/ufw-init-functions | sed -n '360,410p'
echo "### /usr/sbin/ufw lock path"
nl -ba /usr/sbin/ufw | sed -n '115,132p'
nl -ba /usr/lib/python3/dist-packages/ufw/util.py | sed -n '1100,1106p'

section "maintainer and trigger paths"
for f in /var/lib/dpkg/info/ufw.postinst /var/lib/dpkg/info/ufw.prerm \
  /var/lib/dpkg/info/ufw.triggers /var/lib/dpkg/info/nftables.postinst \
  /var/lib/dpkg/info/iptables.postinst /var/lib/dpkg/info/kmod.postinst \
  /var/lib/dpkg/info/procps.postinst; do
  echo "### $f"
  if [ -f "$f" ]; then
    grep -nE 'ufw|nft|iptables|sysctl|modules-load|modprobe|systemctl|trigger|/tmp|mktemp|run-parts|/etc/ufw|applications.d' "$f" 2>/dev/null |
      sed -n '1,160p'
  else
    echo "MISSING $f"
  fi
done

section "systemd sysctl and modules-load import resolution"
echo "### systemd-sysctl --cat-config"
/usr/lib/systemd/systemd-sysctl --cat-config 2>&1 | sed -n '1,220p'
echo "### modules-load config tree"
for d in /etc/modules-load.d /usr/lib/modules-load.d /run/modules-load.d \
  /etc/modprobe.d /usr/lib/modprobe.d /run/modprobe.d; do
  [ -e "$d" ] && find "$d" -xdev -maxdepth 2 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
done

section "attacker write attempts to root trust paths"
run_attacker "write firewall/sysctl/modules hook paths" '
rm -f /tmp/firewall_boot_helpers.touch.err
for p in \
  /etc/ufw/ufw.conf \
  /etc/default/ufw \
  /etc/ufw/before.rules \
  /etc/ufw/after.rules \
  /etc/ufw/user.rules \
  /etc/ufw/before.init \
  /etc/ufw/after.init \
  /etc/ufw/applications.d/firewall-boot-helpers \
  /run/ufw.lock \
  /lib/ufw/ufw.lock \
  /usr/lib/ufw/ufw-init-functions \
  /etc/nftables.conf \
  /etc/default/nftables \
  /etc/iptables/rules.v4 \
  /var/lib/iptables/rules-save \
  /etc/sysctl.conf \
  /etc/sysctl.d/99-firewall-boot-helpers.conf \
  /usr/lib/sysctl.d/99-firewall-boot-helpers.conf \
  /run/sysctl.d/99-firewall-boot-helpers.conf \
  /run/credentials/systemd-sysctl.service/sysctl.firewall \
  /etc/modules \
  /etc/modules-load.d/firewall-boot-helpers.conf \
  /usr/lib/modules-load.d/firewall-boot-helpers.conf \
  /run/modules-load.d/firewall-boot-helpers.conf \
  /etc/modprobe.d/firewall-boot-helpers.conf \
  /usr/lib/modprobe.d/firewall-boot-helpers.conf \
  /run/modprobe.d/firewall-boot-helpers.conf \
  /etc/systemd/system/ufw.service.d/firewall.conf \
  /run/systemd/system/ufw.service.d/firewall.conf; do
  rm -f /tmp/firewall_boot_helpers.mkdir.err /tmp/firewall_boot_helpers.touch.err
  printf "touch %s -> " "$p"
  if mkdir -p "$(dirname "$p")" 2>/tmp/firewall_boot_helpers.mkdir.err &&
     touch "$p" 2>/tmp/firewall_boot_helpers.touch.err; then
    rm -f "$p"
    echo OK
  else
    cat /tmp/firewall_boot_helpers.mkdir.err /tmp/firewall_boot_helpers.touch.err 2>/dev/null
  fi
done
rm -f /tmp/firewall_boot_helpers.mkdir.err /tmp/firewall_boot_helpers.touch.err
'

section "attacker systemd re-entry attempts"
for u in ufw.service nftables.service systemd-sysctl.service \
  systemd-modules-load.service netfilter-persistent.service; do
  for verb in start restart reload stop; do
    echo "### attacker systemctl $verb $u"
    runuser -u attacker -- timeout 10s systemctl "$verb" "$u" 2>&1 | sed -n '1,80p'
  done
done

section "attacker direct helper boundary probes"
run_attacker "ufw direct status and dry-run are unprivileged" '
ufw status verbose 2>&1 | sed -n "1,80p"
ufw --dry-run allow 12345/tcp 2>&1 | sed -n "1,120p"
'
run_attacker "ufw-init direct execution with hostile PATH stays uid1001" '
rm -rf "$HOME/firewall_boot_helpers"
mkdir -p "$HOME/firewall_boot_helpers/bin"
cat > "$HOME/firewall_boot_helpers/bin/iptables" <<EOF
#!/bin/sh
id > /tmp/firewall_boot_helpers.path_iptables_id
exit 1
EOF
chmod 755 "$HOME/firewall_boot_helpers/bin/iptables"
PATH="$HOME/firewall_boot_helpers/bin:$PATH" /usr/lib/ufw/ufw-init status \
  >/tmp/firewall_boot_helpers.ufw_init_status.out 2>/tmp/firewall_boot_helpers.ufw_init_status.err
echo "ufw_init_status_rc=$?"
cat /tmp/firewall_boot_helpers.ufw_init_status.out /tmp/firewall_boot_helpers.ufw_init_status.err
cat /tmp/firewall_boot_helpers.path_iptables_id 2>/dev/null || echo no_hostile_path_marker
'
run_attacker "ufw-init fake rootdir is caller-controlled but not privileged" '
rm -rf "$HOME/firewall_boot_helpers/rootdir"
mkdir -p "$HOME/firewall_boot_helpers/rootdir/etc/ufw" "$HOME/firewall_boot_helpers/rootdir/lib/ufw"
cat > "$HOME/firewall_boot_helpers/rootdir/etc/ufw/ufw.conf" <<EOF
ENABLED=yes
EOF
cat > "$HOME/firewall_boot_helpers/rootdir/lib/ufw/ufw-init-functions" <<EOF
ufw_start() { id > /tmp/firewall_boot_helpers.fake_rootdir_id; echo fake_start; }
ufw_stop() { id > /tmp/firewall_boot_helpers.fake_rootdir_id; echo fake_stop; }
ufw_reload() { id > /tmp/firewall_boot_helpers.fake_rootdir_id; echo fake_reload; }
ufw_status() { id > /tmp/firewall_boot_helpers.fake_rootdir_id; echo fake_status; }
EOF
chmod 755 "$HOME/firewall_boot_helpers/rootdir/lib/ufw/ufw-init-functions"
/usr/lib/ufw/ufw-init --rootdir "$HOME/firewall_boot_helpers/rootdir" start quiet
cat /tmp/firewall_boot_helpers.fake_rootdir_id 2>/dev/null || echo no_fake_rootdir_marker
'
run_attacker "nft and check-requirements need netfilter privilege" '
nft -f /etc/nftables.conf 2>&1 | sed -n "1,80p"
printf "n\\n" | /usr/share/ufw/check-requirements 2>&1 | sed -n "1,120p"
'
run_attacker "systemd sysctl/modules-load direct execution is not root" '
/usr/lib/systemd/systemd-sysctl --prefix=net.ipv4.ip_forward 2>&1 | sed -n "1,80p"
/usr/lib/systemd/systemd-modules-load 2>&1 | sed -n "1,80p"
'

section "root proof sweep and cleanup"
find /root /tmp /home/attacker -maxdepth 3 \( -name '*firewall_boot_helpers*' -o -name '*firewall-boot-helpers*' \) \
  -printf '%M %u:%g %p\n' 2>/dev/null | sort
if [ -e "$root_marker" ]; then
  echo "ROOT_MARKER_PRESENT"
  cat "$root_marker" 2>/dev/null || true
else
  echo "NO_ROOT_MARKER"
fi
cleanup_probe
echo "cleanup_done"
TARGET
