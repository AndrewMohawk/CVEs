#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash -s <<'TARGET'
set -euo pipefail

base=/home/attacker/account_session_deep
tmp=/tmp/account_session_deep
backup_dir=
root_marker=/root/account_session_deep_root_marker
root_sg_marker=/root/account_session_deep_sg_marker
root_userns_marker=/root/account_session_deep_userns_root
account_files=(/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/subuid /etc/subgid)
before_hash=
restored=0

section() {
  printf '\n== %s ==\n' "$1"
}

run_attacker() {
  local label="$1"
  local cmd="$2"
  section "$label"
  runuser -u attacker -- timeout 7s bash -lc "$cmd" </dev/null 2>&1 || printf 'rc=%s\n' "$?"
}

hash_account_files() {
  sha256sum "${account_files[@]}"
}

restore_account_files_if_changed() {
  [ -n "${backup_dir:-}" ] || return 0
  [ -n "${before_hash:-}" ] || return 0
  [ "$restored" -eq 0 ] || return 0

  local after_hash
  after_hash="$(hash_account_files)"
  if [ "$before_hash" = "$after_hash" ]; then
    printf 'account_files_unchanged=yes\n'
  else
    printf 'account_files_unchanged=no\n'
    printf 'restoring_account_file_backups=yes\n'
    for f in "${account_files[@]}"; do
      cp -a "$backup_dir/$(basename "$f")" "$f"
    done
  fi
  restored=1
}

cleanup_artifacts() {
  rm -rf "$base" "$tmp"
  rm -f \
    /tmp/account_session_deep_shell_id \
    /tmp/account_session_deep_sg_id \
    /tmp/account_session_deep_strace_sg_id \
    /tmp/account_session_deep_chpasswd.in \
    "$root_marker" "$root_sg_marker" "$root_userns_marker"
  [ -z "${backup_dir:-}" ] || rm -rf "$backup_dir"
}

trap 'restore_account_files_if_changed >/dev/null 2>&1 || true; cleanup_artifacts >/dev/null 2>&1 || true' EXIT

section "target and default proof"
sed -n '1,8p' /etc/os-release
uname -a
id attacker
getent passwd attacker
getent group attacker sudo adm shadow root | sed 's/^/group: /' || true
awk -F: '$1=="root" || $1=="ubuntu" || $1=="attacker" || $1=="selfauth" {print $1 ":" $2 ":" $3 ":" $4 ":" $5 ":" $6 ":" $7 ":" $8 ":" $9}' /etc/shadow
apt-get -s full-upgrade 2>&1 | sed -n '1,12p'

section "package versions"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  passwd login libpam-modules libpam-modules-bin libpam-runtime util-linux uidmap 2>&1 | sort || true

section "helper modes"
for f in \
  /usr/bin/chfn /usr/bin/chsh /usr/bin/passwd /usr/bin/gpasswd \
  /usr/bin/newgrp /usr/bin/sg /usr/bin/login /usr/bin/su /usr/sbin/runuser \
  /usr/bin/chage /usr/bin/expiry \
  /usr/bin/newuidmap /usr/bin/newgidmap /usr/sbin/faillock /usr/sbin/pam_tally2 \
  /usr/bin/faillog /usr/bin/lastlog \
  /usr/sbin/usermod /usr/sbin/groupmod /usr/sbin/useradd /usr/sbin/groupadd \
  /usr/sbin/newusers /usr/sbin/chpasswd /usr/sbin/vipw /usr/sbin/vigr; do
  if [ -e "$f" ]; then
    stat -Lc '%A %a %U:%G %n' "$f"
  else
    printf 'MISSING %s\n' "$f"
  fi
done

section "account and accounting file modes"
for p in \
  /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/.pwd.lock \
  /etc/subuid /etc/subgid /etc/login.defs /etc/shells \
  /var/log/faillog /var/log/tallylog /run/faillock /var/run/faillock \
  /var/log/lastlog /var/log/wtmp /var/log/btmp /run/utmp; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %s %n' "$p" 2>&1 || ls -ld "$p"
  else
    printf 'MISSING %s\n' "$p"
  fi
done

section "pam account-session reachability"
grep -RInE 'pam_(faillock|tally|tally2|lastlog|nologin|securetty|shells|wheel|group|limits|env|systemd)' \
  /etc/pam.d /usr/lib/pam.d 2>/dev/null | sort || true

section "subuid subgid state"
printf '%s\n' '-- /etc/subuid --'
cat /etc/subuid
printf '%s\n' '-- /etc/subgid --'
cat /etc/subgid

rm -rf "$base" "$tmp"
install -d -o attacker -g attacker -m 0700 "$base/bin" "$base/env" "$tmp"
cat >"$base/bin/fake-shell" <<'EOF'
#!/bin/sh
/usr/bin/id > /tmp/account_session_deep_shell_id
/usr/bin/id > /root/account_session_deep_root_marker 2>/dev/null || true
exit 0
EOF
chown attacker:attacker "$base/bin/fake-shell"
chmod 0755 "$base/bin/fake-shell"

backup_dir="$(mktemp -d /tmp/account_session_deep_backup.XXXXXX)"
chmod 0700 "$backup_dir"
for f in "${account_files[@]}"; do
  cp -a "$f" "$backup_dir/$(basename "$f")"
done
before_hash="$(hash_account_files)"

section "account file hashes before"
printf '%s\n' "$before_hash"

run_attacker "attacker cannot preplace account lock temp or accounting links" '
for f in \
  /etc/passwd.lock /etc/shadow.lock /etc/group.lock /etc/gshadow.lock \
  /etc/passwd+ /etc/shadow+ /etc/group+ /etc/gshadow+ \
  /etc/passwd.12345 /etc/shadow.12345 /etc/group.12345 /etc/gshadow.12345 \
  /etc/subuid.lock /etc/subgid.lock /etc/subuid+ /etc/subgid+ \
  /var/log/tallylog /run/faillock /var/run/faillock; do
  printf "TRY %s: " "$f"
  ln -s /root/account_session_deep_root_marker "$f" 2>&1 || true
done
printf "TRY /var/log/faillog: "
ln -s /root/account_session_deep_root_marker /var/log/faillog 2>&1 || true
'

run_attacker "login is not an attacker-reachable setuid session transition" \
  "/usr/bin/login -f attacker"

run_attacker "newgrp own group uses attacker shell after dropping privilege" \
  "env -i HOME=/home/attacker USER=attacker LOGNAME=attacker SHELL=$base/bin/fake-shell PATH=/usr/bin:/bin /usr/bin/newgrp attacker"
section "newgrp shell proof"
cat /tmp/account_session_deep_shell_id 2>/dev/null || printf 'newgrp_shell_marker=absent\n'
if [ -e "$root_marker" ]; then
  stat -Lc 'newgrp_root_marker=present %A %U:%G %n' "$root_marker"
else
  printf 'newgrp_root_marker=absent\n'
fi
rm -f /tmp/account_session_deep_shell_id "$root_marker"

run_attacker "sg own group command runs as uid1001" \
  "/usr/bin/sg attacker -c 'id > /tmp/account_session_deep_sg_id; id > /root/account_session_deep_sg_marker'"
section "sg own group proof"
cat /tmp/account_session_deep_sg_id 2>/dev/null || printf 'sg_user_marker=absent\n'
if [ -e "$root_sg_marker" ]; then
  stat -Lc 'sg_root_marker=present %A %U:%G %n' "$root_sg_marker"
else
  printf 'sg_root_marker=absent\n'
fi
rm -f /tmp/account_session_deep_sg_id "$root_sg_marker"

section "sg privileged group denials"
for g in root shadow sudo adm; do
  printf -- '-- sg %s --\n' "$g"
  runuser -u attacker -- timeout 5s bash -lc "printf 'bad\n' | /usr/bin/sg '$g' -c id" 2>&1 || printf 'rc=%s\n' "$?"
done

section "newgrp privileged group denials"
for g in root shadow sudo adm; do
  printf -- '-- newgrp %s --\n' "$g"
  runuser -u attacker -- timeout 5s bash -lc "printf 'bad\n' | /usr/bin/newgrp '$g'" 2>&1 || printf 'rc=%s\n' "$?"
done

run_attacker "gpasswd own group and group-file writes denied" '
printf "x\nx\n" | /usr/bin/gpasswd attacker
/usr/bin/gpasswd -a attacker attacker
/usr/bin/gpasswd -M attacker attacker
/usr/bin/gpasswd -d attacker attacker
/usr/bin/gpasswd -A attacker attacker
/usr/bin/gpasswd -R attacker
'

run_attacker "passwd and chage account lock transitions denied" '
/usr/bin/passwd -l attacker
/usr/bin/passwd -u attacker
/usr/bin/passwd -d attacker
/usr/bin/passwd -S root
/usr/bin/passwd -S attacker
/usr/bin/chage -l root
/usr/bin/chage -l attacker
/usr/bin/chage -E 2030-01-01 attacker
/usr/bin/expiry -c
'

run_attacker "plain account database tools cannot lock account files" '
printf "attacker:x\n" >/tmp/account_session_deep_chpasswd.in
/usr/sbin/chpasswd </tmp/account_session_deep_chpasswd.in
printf "probe:x:2999:2999::/home/probe:/bin/sh\n" | /usr/sbin/newusers
/usr/sbin/usermod -U attacker
/usr/sbin/usermod -G sudo attacker
/usr/sbin/groupmod -n root attacker
EDITOR=/bin/true /usr/sbin/vipw -s
EDITOR=/bin/true /usr/sbin/vigr -s
'

run_attacker "faillock faillog tally paths are non-privileged or absent" '
/usr/sbin/faillock --user attacker
/usr/sbin/faillock --user root
/usr/sbin/faillock --reset --user attacker
/usr/sbin/faillock --reset --user root
command -v faillog >/dev/null && /usr/bin/faillog -u attacker || true
command -v faillog >/dev/null && /usr/bin/faillog -r -u root || true
command -v pam_tally2 >/dev/null && /usr/sbin/pam_tally2 --user attacker || true
'

section "faillock tally files after triggers"
find /run /var/run /var/log -maxdepth 2 \( -name faillock -o -name tallylog -o -name faillog \) \
  -printf '%M %u:%g %s %p -> %l\n' 2>/dev/null | sort || true

section "newuidmap newgidmap and user namespace boundary"
if command -v newuidmap >/dev/null 2>&1; then
  run_attacker "newuidmap direct invalid map" "newuidmap \$\$ 0 0 1"
else
  printf 'newuidmap_absent=yes\n'
fi
if command -v newgidmap >/dev/null 2>&1; then
  run_attacker "newgidmap direct invalid map" "newgidmap \$\$ 0 0 1"
else
  printf 'newgidmap_absent=yes\n'
fi
run_attacker "unshare user namespace root is mapped uid1001 not container root" \
  "unshare -Ur sh -c 'id; cat /proc/self/uid_map; cat /proc/self/gid_map; touch /root/account_session_deep_userns_root'"
if [ -e "$root_userns_marker" ]; then
  stat -Lc 'userns_root_marker=present %A %U:%G %n' "$root_userns_marker"
else
  printf 'userns_root_marker=absent\n'
fi
rm -f "$root_userns_marker"

section "strace sg and gpasswd account-file boundary"
rm -rf "$tmp/strace"
mkdir -p "$tmp/strace"
timeout 6s strace -ff -s 180 -o "$tmp/strace/sg" -e trace=file,process,setuid,setgid \
  -u attacker env -i HOME=/home/attacker USER=attacker LOGNAME=attacker \
  SHELL="$base/bin/fake-shell" PATH="$base/bin:/usr/bin:/bin" \
  GCONV_PATH="$base/env" LOCPATH="$base/env" NLSPATH="$base/env/%N" \
  /usr/bin/sg attacker -c 'id >/tmp/account_session_deep_strace_sg_id' >/dev/null 2>&1 || true
timeout 6s strace -ff -s 180 -o "$tmp/strace/gpasswd" -e trace=file,process,setuid,setgid \
  -u attacker bash -lc "printf 'x\nx\n' | /usr/bin/gpasswd attacker" >/dev/null 2>&1 || true
cat /tmp/account_session_deep_strace_sg_id 2>/dev/null || true
grep -hE '/etc/(passwd|shadow|group|gshadow|subuid|subgid)([.+[:alnum:]_-]*|\.lock)?|/home/attacker/account_session_deep|set(uid|gid|re[ug]id)' \
  "$tmp"/strace/* 2>/dev/null | sed -n '1,180p' || true

section "account file hashes after"
after_hash="$(hash_account_files)"
printf '%s\n' "$after_hash"
restore_account_files_if_changed

section "root proof markers"
for p in "$root_marker" "$root_sg_marker" "$root_userns_marker"; do
  if [ -e "$p" ]; then
    stat -Lc 'ROOT_MARKER_PRESENT %A %U:%G %n' "$p"
    cat "$p" 2>/dev/null || true
  else
    printf 'ROOT_MARKER_ABSENT %s\n' "$p"
  fi
done

section "cleanup"
cleanup_artifacts
leftovers="$(find /home/attacker /tmp /root -maxdepth 1 \( -name 'account_session_deep' -o -name 'account_session_deep_*' \) -print 2>/dev/null | wc -l)"
printf 'cleanup_leftovers=%s\n' "$leftovers"
trap - EXIT
TARGET
