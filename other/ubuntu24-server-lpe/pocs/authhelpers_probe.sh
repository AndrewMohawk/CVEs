#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -euo pipefail

base=/home/attacker/authhelpers_probe
root_marker=/root/authhelpers_env_marker
symlink_marker=/root/authhelpers_symlink_escape

cleanup() {
  rm -rf "$base" /tmp/authhelpers_env_marker /tmp/authhelpers_fake_executed
  rm -f "$root_marker" "$symlink_marker"
}
trap cleanup EXIT
cleanup

run_as_attacker() {
  local label="$1"
  local cmd="$2"
  echo "== $label =="
  runuser -u attacker -- timeout 5s bash -lc "$cmd" </dev/null 2>&1 || echo "rc=$?"
}

echo "== os and attacker =="
sed -n '1,8p' /etc/os-release
id attacker
getent group sudo adm lxd docker shadow root | sed 's/^/group: /' || true
awk -F: '$1=="attacker"{print "attacker_shadow_field=" $2}' /etc/shadow

echo "== owning package versions =="
dpkg-query -W passwd login util-linux sudo polkitd libpam-modules libpam-modules-bin 2>/dev/null

echo "== helper modes =="
for f in \
  /usr/bin/chfn /usr/bin/chsh /usr/bin/passwd /usr/bin/gpasswd \
  /usr/bin/newgrp /usr/bin/su /usr/bin/sudo /usr/bin/chage /usr/bin/expiry \
  /usr/sbin/unix_chkpwd /usr/sbin/pam_extrausers_chkpwd \
  /usr/lib/polkit-1/polkit-agent-helper-1; do
  stat -Lc '%A %a %U %G %n' "$f"
done

echo "== account file modes =="
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/login.defs /etc/shells; do
  stat -Lc '%A %a %U %G %n' "$f"
done

before=$(sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow)
echo "== account file hashes before =="
printf '%s\n' "$before"

install -d -o attacker -g attacker "$base/bin" "$base/chroot/etc" "$base/gconv"
for name in sh bash dash passwd chfn chsh gpasswd newgrp su sudo getent groups id editor pager askpass; do
  {
    printf '#!/bin/sh\n'
    printf '/usr/bin/id > /tmp/authhelpers_fake_executed\n'
    printf '/usr/bin/id > /root/authhelpers_env_marker 2>/dev/null || true\n'
    printf 'exit 77\n'
  } > "$base/bin/$name"
  chmod 755 "$base/bin/$name"
  chown attacker:attacker "$base/bin/$name"
done

cp /etc/passwd "$base/chroot/etc/passwd"
cp /etc/group "$base/chroot/etc/group"
cp /etc/shadow "$base/chroot/etc/shadow"
cp /etc/gshadow "$base/chroot/etc/gshadow"
chown -R attacker:attacker "$base/chroot"
chmod 644 "$base/chroot/etc/passwd" "$base/chroot/etc/group"
chmod 600 "$base/chroot/etc/shadow" "$base/chroot/etc/gshadow"

evil_env="PATH=$base/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin SHELL=$base/bin/sh EDITOR=$base/bin/editor VISUAL=$base/bin/editor PAGER=$base/bin/pager SUDO_ASKPASS=$base/bin/askpass GCONV_PATH=$base/gconv CHARSET=UTF-8"

run_as_attacker "chfn newline full-name injection" "printf '\\n' | chfn -f \$'Bad\\nroot:x:0:0:root:/root:/bin/bash' attacker"
run_as_attacker "chfn newline allowed room-field injection" "printf '\\n' | chfn -r \$'101\\nroot:x:0:0:root:/root:/bin/bash' attacker"
run_as_attacker "chfn colon allowed work-phone field injection" "printf '\\n' | chfn -w '1:2:3' attacker"
run_as_attacker "chfn disallowed other-field blocked" "printf '\\n' | chfn -o 'x:y:z' attacker"
run_as_attacker "chsh newline shell injection" "printf '\\n' | chsh -s \$'/bin/sh\\n/bin/bash' attacker"
run_as_attacker "chsh unlisted attacker path" "printf '\\n' | chsh -s $base/bin/sh attacker"
run_as_attacker "passwd root delete denied" "printf 'bad\\n' | passwd -d root"
run_as_attacker "passwd attacker status only" "passwd -S attacker"
run_as_attacker "gpasswd add attacker to root denied" "gpasswd -a attacker root"
run_as_attacker "gpasswd member-list overwrite denied" "gpasswd -M attacker root"
run_as_attacker "newgrp privileged group denied" "printf 'bad\\n' | newgrp shadow"
run_as_attacker "su root denied with hostile env" "$evil_env /usr/bin/su -c '/usr/bin/id; touch /root/authhelpers_su_root' root <<<'bad'"
run_as_attacker "sudo no rights with hostile env" "$evil_env /usr/bin/sudo -S /usr/bin/id <<<'bad'"
run_as_attacker "sudo askpass no rights" "$evil_env /usr/bin/sudo -A -n /usr/bin/id"
run_as_attacker "chage root write denied" "chage -E -1 root"
run_as_attacker "chage attacker list" "chage -l attacker"
run_as_attacker "expiry check" "expiry -c"
run_as_attacker "polkit helper direct bad cookie" "printf 'bad\\n' | /usr/lib/polkit-1/polkit-agent-helper-1 attacker cookie"
run_as_attacker "unix_chkpwd direct" "printf 'bad\\n' | /usr/sbin/unix_chkpwd attacker chkexpiry"
run_as_attacker "unix_chkpwd newline user" "printf 'bad\\n' | /usr/sbin/unix_chkpwd \$'attacker\\nroot' chkexpiry"
run_as_attacker "pam_extrausers_chkpwd direct" "printf 'bad\\n' | /usr/sbin/pam_extrausers_chkpwd attacker chkexpiry"

run_as_attacker "chfn --root attacker chroot denied" "chfn -R $base/chroot -f Probe attacker"
run_as_attacker "chsh --root attacker chroot denied" "chsh -R $base/chroot -s /bin/sh attacker"
run_as_attacker "passwd --root attacker chroot denied" "passwd -R $base/chroot -S attacker"
run_as_attacker "gpasswd --root attacker chroot denied" "gpasswd -Q $base/chroot -a attacker root"
run_as_attacker "chage --root attacker chroot denied" "chage -R $base/chroot -l attacker"

rm -f "$base/chroot/etc/passwd" "$base/chroot/etc/group" "$base/chroot/etc/shadow" "$base/chroot/etc/gshadow"
ln -s /root/authhelpers_symlink_escape "$base/chroot/etc/passwd"
ln -s /root/authhelpers_symlink_escape "$base/chroot/etc/group"
ln -s /root/authhelpers_symlink_escape "$base/chroot/etc/shadow"
ln -s /root/authhelpers_symlink_escape "$base/chroot/etc/gshadow"
chown -h attacker:attacker "$base/chroot/etc/passwd" "$base/chroot/etc/group" "$base/chroot/etc/shadow" "$base/chroot/etc/gshadow"

run_as_attacker "chfn --root symlink passwd denied before account-file write" "chfn -R $base/chroot -f Symlink attacker"
run_as_attacker "gpasswd --root symlink group denied before account-file write" "gpasswd -Q $base/chroot -a attacker root"
run_as_attacker "attacker cannot preplace /etc passwd lock/swap symlinks" "for f in /etc/.pwd.lock /etc/passwd.lock /etc/passwd+ /etc/group+ /etc/gshadow+; do ln -s /root/authhelpers_symlink_escape \"\$f\" && echo created:\$f || true; done"

run_as_attacker "hostile env against chfn/chsh/passwd/gpasswd/chage" "$evil_env /bin/bash -lc 'printf \"\\n\" | /usr/bin/chfn -f EnvProbe attacker; printf \"\\n\" | /usr/bin/chsh -s /bin/sh attacker; /usr/bin/passwd -S attacker; /usr/bin/gpasswd -a attacker root; /usr/bin/chage -l attacker' || true"

after=$(sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow)
echo "== account file hashes after =="
printf '%s\n' "$after"
if [ "$before" = "$after" ]; then
  echo "account_files_unchanged=yes"
else
  echo "account_files_unchanged=no"
fi

echo "== env/path/symlink markers =="
if [ -e "$root_marker" ]; then
  echo "root_env_marker=present"
  ls -l "$root_marker"
else
  echo "root_env_marker=absent"
fi
if [ -e "$symlink_marker" ]; then
  echo "root_symlink_marker=present"
  ls -l "$symlink_marker"
else
  echo "root_symlink_marker=absent"
fi
if [ -e /tmp/authhelpers_fake_executed ]; then
  echo "attacker_env_helper_marker=present"
  cat /tmp/authhelpers_fake_executed
else
  echo "attacker_env_helper_marker=absent"
fi

cleanup
echo "cleanup_leftovers=$(find /home/attacker /tmp /root -maxdepth 1 \( -name 'authhelpers*' -o -name 'authhelpers_*' \) -print | wc -l)"
TARGET
