#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -euo pipefail

base=/home/attacker/sudo_no_sudo_user_probe
root_markers="
/root/sudo_no_sudo_user_root_marker
/root/sudo_no_sudo_user_editor_marker
/root/sudo_no_sudo_user_askpass_marker
/root/sudo_no_sudo_user_path_marker
/root/sudo_no_sudo_user_chroot_marker
/root/sudo_no_sudo_user_nss_marker
/root/sudo_no_sudo_user_gconv_marker
"
tmp_glob=/tmp/sudo_no_sudo_user_*

pre_ts=0
pre_lecture=0
[ -e /run/sudo/ts/attacker ] && pre_ts=1
[ -e /var/lib/sudo/lectured/attacker ] && pre_lecture=1

cleanup() {
  rm -rf "$base" /tmp/mininit.so /tmp/mininit_marker $tmp_glob
  for m in $root_markers; do
    rm -f "$m"
  done
  if [ "$pre_ts" = 0 ]; then
    rm -rf /run/sudo/ts/attacker
  fi
  if [ "$pre_lecture" = 0 ]; then
    rm -rf /var/lib/sudo/lectured/attacker
  fi
}
trap cleanup EXIT INT TERM
cleanup

run_as_attacker() {
  local label="$1"
  local cmd="$2"
  echo "== $label =="
  set +e
  runuser -u attacker -- timeout 8s bash -lc "$cmd" </dev/null 2>&1
  local rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "rc=$rc"
  fi
}

show_path_state() {
  local label="$1"
  echo "== $label =="
  for p in \
    /run/sudo /run/sudo/ts /run/sudo/ts/attacker \
    /var/lib/sudo /var/lib/sudo/lectured /var/lib/sudo/lectured/attacker \
    /var/log/auth.log /var/log/syslog; do
    if [ -e "$p" ]; then
      stat -Lc '%A %a %U %G %n' "$p" 2>&1 || true
    else
      echo "absent $p"
    fi
  done
}

echo "== target and sudo package =="
sed -n '1,8p' /etc/os-release
uname -a
dpkg-query -W sudo libc6 libpam-modules libnss-systemd 2>/dev/null || true
zgrep -i 'CVE-2025-32462\|CVE-2025-32463\|chroot option\|host option' /usr/share/doc/sudo/changelog.Debian.gz 2>/dev/null || true

echo "== sudo binary mode and sudoers defaults =="
sudo -V | sed -n '1,90p'
for p in /usr/bin/sudo /usr/bin/sudoedit /etc/sudoers /etc/sudoers.d; do
  stat -Lc '%A %a %U %G %n' "$p"
done
find /etc/sudoers.d -maxdepth 1 -mindepth 1 -printf '%M %m %u %g %p -> %l\n' | sort
sed -n '1,180p' /etc/sudoers

echo "== attacker identity and excluded groups =="
id attacker
getent group sudo admin adm lxd docker shadow root | sed 's/^/group: /' || true
if id -nG attacker | tr ' ' '\n' | grep -Eq '^(sudo|admin|adm|lxd|docker|shadow|root)$'; then
  echo "attacker_group_boundary=failed"
else
  echo "attacker_group_boundary=ok_not_privileged"
fi

install -d -o attacker -g attacker -m 0755 \
  "$base/bin" "$base/gconv" "$base/locale" "$base/nss" \
  "$base/chroot/etc" "$base/chroot/lib/aarch64-linux-gnu" "$base/chroot/usr/lib/aarch64-linux-gnu"
chown attacker:attacker "$base"

for name in editor vi nano sensible-editor pager askpass id env sh sudo sudoedit; do
  {
    printf '#!/bin/sh\n'
    printf 'name="$(basename "$0")"\n'
    printf '/usr/bin/printf "fake_%%s real=%%s effective=%%s args=%%s\\n" "$name" "$(/usr/bin/id -ru)" "$(/usr/bin/id -u)" "$*" >> /tmp/sudo_no_sudo_user_path_marker\n'
    printf '/usr/bin/touch /root/sudo_no_sudo_user_root_marker 2>/dev/null || true\n'
    printf 'case "$name" in\n'
    printf '  askpass) /usr/bin/touch /root/sudo_no_sudo_user_askpass_marker 2>/dev/null || true; /usr/bin/printf "badpass\\n"; exit 0 ;;\n'
    printf '  editor|vi|nano|sensible-editor) /usr/bin/touch /root/sudo_no_sudo_user_editor_marker 2>/dev/null || true; exit 77 ;;\n'
    printf '  id|env|sh|sudo|sudoedit) /usr/bin/touch /root/sudo_no_sudo_user_path_marker 2>/dev/null || true; exit 77 ;;\n'
    printf 'esac\n'
    printf 'exit 77\n'
  } > "$base/bin/$name"
  chmod 755 "$base/bin/$name"
  chown attacker:attacker "$base/bin/$name"
done

cat > "$base/gconv/gconv-modules" <<'EOF'
module  INTERNAL  SUDO-PROBE//  sudo_probe  2
module  SUDO-PROBE//  INTERNAL  sudo_probe  2
EOF
printf '#!/bin/sh\n/usr/bin/touch /root/sudo_no_sudo_user_gconv_marker 2>/dev/null\nexit 77\n' > "$base/gconv/sudo_probe.so"
chmod 755 "$base/gconv/sudo_probe.so"
chown -R attacker:attacker "$base/gconv"

cat > "$base/chroot/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
attacker:x:1001:1001:attacker:/home/attacker:/bin/bash
EOF
cat > "$base/chroot/etc/group" <<'EOF'
root:x:0:
attacker:x:1001:
sudo:x:27:
admin:x:118:
EOF
cat > "$base/chroot/etc/nsswitch.conf" <<'EOF'
passwd: files sudo_probe
group: files sudo_probe
shadow: files sudo_probe
hosts: files dns
EOF
printf 'not-an-elf\n' > "$base/chroot/lib/aarch64-linux-gnu/libnss_sudo_probe.so.2"
cp "$base/chroot/lib/aarch64-linux-gnu/libnss_sudo_probe.so.2" "$base/chroot/usr/lib/aarch64-linux-gnu/libnss_sudo_probe.so.2"
chown -R attacker:attacker "$base/chroot"

hostile_env="env -i HOME=/home/attacker USER=attacker LOGNAME=attacker SHELL=$base/bin/sh TERM=xterm PATH=$base/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin EDITOR=$base/bin/editor VISUAL=$base/bin/editor SUDO_EDITOR=$base/bin/editor PAGER=$base/bin/pager SUDO_ASKPASS=$base/bin/askpass GCONV_PATH=$base/gconv LOCPATH=$base/locale CHARSET=SUDO-PROBE LANG=zz_ZZ.UTF-8 LC_ALL=zz_ZZ.UTF-8 LANGUAGE=zz"

show_path_state "sudo state before probes"

run_as_attacker "sudo -k timestamp invalidation only" "/usr/bin/sudo -k"
run_as_attacker "sudo -n -l no password" "/usr/bin/sudo -n -l"
run_as_attacker "sudo -n -ll no password" "/usr/bin/sudo -n -ll"
run_as_attacker "sudo -n -v no password" "/usr/bin/sudo -n -v"
run_as_attacker "sudo -n command denied" "/usr/bin/sudo -n /usr/bin/id"
run_as_attacker "sudo PATH command lookup denied before fake id exec" "$hostile_env /usr/bin/sudo -n id"
run_as_attacker "sudo askpass no sudoers boundary" "$hostile_env /usr/bin/sudo -A /usr/bin/id"
run_as_attacker "sudo -e editor denied before editor" "$hostile_env /usr/bin/sudo -e -n /etc/hosts"
run_as_attacker "sudoedit editor denied before editor" "$hostile_env /usr/bin/sudoedit -n /etc/hosts"
run_as_attacker "sudoedit shell/parser legacy form" "$hostile_env /usr/bin/sudoedit -s -n /etc/hosts"
run_as_attacker "locale and gconv env denied" "$hostile_env /usr/bin/sudo -n -l"
run_as_attacker "chroot recent parser list path denied" "/usr/bin/sudo -R $base/chroot -n -l"
run_as_attacker "chroot recent parser command path denied" "/usr/bin/sudo -R $base/chroot -n /usr/bin/id"
run_as_attacker "chdir option denied" "/usr/bin/sudo -D $base -n /usr/bin/id"
run_as_attacker "runas root denied" "/usr/bin/sudo -u root -g root -n /usr/bin/id"
run_as_attacker "runas numeric root denied" "/usr/bin/sudo -u#0 -g#0 -n /usr/bin/id"
run_as_attacker "runas negative id parser denied" "/usr/bin/sudo -u#-1 -n /usr/bin/id"
run_as_attacker "runas max uid parser denied" "/usr/bin/sudo -u#4294967295 -n /usr/bin/id"
run_as_attacker "host option localhost list denied" "/usr/bin/sudo -h localhost -n -l"
run_as_attacker "host option current hostname list denied" "/usr/bin/sudo -h $(hostname) -n -l"
run_as_attacker "host option nonlocal list denied" "/usr/bin/sudo -h not-the-host -n -l"
run_as_attacker "list another user privileges denied" "/usr/bin/sudo -U root -n -l"
run_as_attacker "list self privileges denied" "/usr/bin/sudo -U attacker -n -l"
run_as_attacker "sudoers include write/stat denied" "printf 'attacker ALL=(ALL:ALL) NOPASSWD:ALL\n' > $base/attacker_sudoers; ls -ld /etc/sudoers /etc/sudoers.d /etc/sudoers.d/README; touch /etc/sudoers.d/00-sudo-no-sudo-user-probe 2>&1 || true; ln -s $base/attacker_sudoers /etc/sudoers.d/00-sudo-no-sudo-user-probe 2>&1 || true; test -e /etc/sudoers.d/00-sudo-no-sudo-user-probe && ls -l /etc/sudoers.d/00-sudo-no-sudo-user-probe || true; /usr/bin/sudo -n -l"

show_path_state "sudo state after probes before cleanup"

echo "== marker check before cleanup =="
root_proof=no
for m in $root_markers; do
  if [ -e "$m" ]; then
    root_proof=yes
    echo "present $m"
    stat -Lc '%A %a %U %G %n' "$m" || true
    sed -n '1,5p' "$m" 2>/dev/null || true
  else
    echo "absent $m"
  fi
done
if compgen -G "$tmp_glob" >/dev/null; then
  echo "tmp_markers=present"
  ls -l $tmp_glob
  for f in $tmp_glob; do
    sed -n '1,10p' "$f" 2>/dev/null || true
  done
else
  echo "tmp_markers=absent"
fi
echo "root_proof=$root_proof"

cleanup

echo "== cleanup verification =="
if find /home/attacker /tmp /root -maxdepth 1 \( -name 'sudo_no_sudo_user_probe' -o -name 'sudo_no_sudo_user_*' -o -name 'mininit.so' -o -name 'mininit_marker' \) -print | grep -q .; then
  find /home/attacker /tmp /root -maxdepth 1 \( -name 'sudo_no_sudo_user_probe' -o -name 'sudo_no_sudo_user_*' -o -name 'mininit.so' -o -name 'mininit_marker' \) -print
  echo "cleanup_leftovers=present"
else
  echo "cleanup_leftovers=absent"
fi

echo "== systemd health =="
systemctl is-system-running || true
systemctl --failed --no-legend || true
TARGET
