#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$target" bash -s <<'INNER'
set +e

probe=/tmp/file_acl_probe
root_marker=/root/file_acl_probe_root_marker

mode() {
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      stat -c '%A %a %U %G %n -> %N' "$p" 2>/dev/null
    else
      echo "ABSENT $p"
    fi
  done
}

echo "## target/default proof"
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker
printf 'attacker supplementary groups: '
id -Gn attacker

echo "## package proof"
for pkg in util-linux bsdextrautils libutempter0 cron logrotate rsyslog apport systemd uuid-runtime postfix mailutils bsd-mailx; do
  dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null || echo "$pkg not-installed"
done

echo "## helper mode proof"
for f in \
  /usr/bin/write \
  /usr/bin/wall \
  /usr/lib/aarch64-linux-gnu/utempter/utempter \
  /usr/bin/mail \
  /usr/bin/mailx \
  /usr/sbin/sendmail \
  /usr/bin/crontab
do
  mode "$f"
done

echo "## writable/group-file baseline"
find / /run -xdev \( -type d -perm -0002 -o -type d -perm -0020 -o -type f -perm -0020 \) \
  -printf '%M %m %u %g %p\n' 2>/dev/null | sort

echo "## kernel link protections"
for k in fs.protected_hardlinks fs.protected_symlinks fs.protected_regular fs.protected_fifos; do
  sysctl "$k"
done

echo "## active root consumers"
systemctl --no-pager --plain --type=service --type=timer --state=active \
  | sed -n '1,90p'

echo "## relevant tmpfiles/cron/logrotate config"
grep -RsnE '(^[^#].*(/tmp|/var/tmp|/run/screen|/var/crash|/var/mail|/var/log|/var/spool/cron|/var/local))' \
  /etc/tmpfiles.d /usr/lib/tmpfiles.d 2>/dev/null | sed -n '1,180p'
grep -RsnE '(/tmp|/var/tmp|/run/screen|/var/crash|/var/mail|/var/log|/var/spool/cron|/var/local)' \
  /etc/cron* /etc/logrotate* /usr/lib/systemd/system/logrotate.service 2>/dev/null | sed -n '1,220p'

echo "## attacker direct write/read reachability"
runuser -u attacker -- bash -s <<'ATTACKER'
set +e
probe=/tmp/file_acl_probe
rm -rf "$probe"
find /tmp /var/tmp /run/lock /run/screen /var/crash -maxdepth 1 \
  \( -name 'file_acl_probe*' -o -name '.X0-lock' -o -name '123456789012' \) \
  -exec rm -rf -- {} + 2>/dev/null
mkdir -p "$probe"

echo "attacker identity"
id

echo "helper execution reachability"
/usr/bin/write --help >/tmp/file_acl_probe.write_help.out 2>&1
echo "write_help_rc=$?"
sed -n '1,5p' /tmp/file_acl_probe.write_help.out
printf 'file-acl wall probe\n' > "$probe/wall_input"
/usr/bin/wall --timeout 1 "$probe/wall_input" >/tmp/file_acl_probe.wall.out 2>&1
echo "wall_file_rc=$?"
sed -n '1,8p' /tmp/file_acl_probe.wall.out
if [ -x /usr/lib/aarch64-linux-gnu/utempter/utempter ]; then
  /usr/lib/aarch64-linux-gnu/utempter/utempter >/tmp/file_acl_probe.utempter_direct.out 2>&1
  echo "utempter_direct_rc=$?"
  sed -n '1,8p' /tmp/file_acl_probe.utempter_direct.out
fi
for m in /usr/bin/mail /usr/bin/mailx /usr/sbin/sendmail; do
  [ -e "$m" ] && "$m" --help >/tmp/file_acl_probe.mail.out 2>&1 && echo "mail_helper_${m}_rc=$?"
done

echo "group/root path direct write checks"
for p in \
  /var/mail \
  /var/local \
  /var/lib/libuuid \
  /etc/landscape \
  /var/log \
  /var/spool/cron/crontabs \
  /var/cache/man \
  /etc/cron.d \
  /etc/logrotate.d \
  /etc/tmpfiles.d \
  /usr/local/bin \
  /usr/local/sbin
do
  rm -f "$p/file_acl_probe_touch" 2>/dev/null
  if touch "$p/file_acl_probe_touch" 2>/tmp/file_acl_probe.touch.err; then
    stat -c "WRITE_OK %A %U %G %n" "$p/file_acl_probe_touch"
    rm -f "$p/file_acl_probe_touch"
  else
    echo "WRITE_DENY $p $(cat /tmp/file_acl_probe.touch.err)"
  fi
done

echo "group-writable regular file write checks"
for f in /run/utmp /var/log/wtmp /var/log/btmp /var/log/lastlog /var/lib/libuuid/clock.txt; do
  if [ -e "$f" ]; then
    if sh -c "printf x >> '$f'" 2>/tmp/file_acl_probe.append.err; then
      echo "APPEND_OK $f"
    else
      echo "APPEND_DENY $f $(cat /tmp/file_acl_probe.append.err)"
    fi
    test -r "$f" && echo "READ_OK $f" || echo "READ_DENY $f"
  fi
done

echo "utempter bounded accounting write"
python3 - <<'PY'
import ctypes
import os
import pty
import subprocess

master, slave = pty.openpty()
print("pty", os.ttyname(slave), "uid", os.getuid(), "gid", os.getgid(), "groups", os.getgroups())
lib = ctypes.CDLL("libutempter.so.0")
lib.utempter_add_record.argtypes = [ctypes.c_int, ctypes.c_char_p]
lib.utempter_remove_record.argtypes = [ctypes.c_int]
lib.utempter_add_record(master, b"file-acl-probe")
print("who_after_add")
subprocess.run(["who"], check=False)
lib.utempter_remove_record(master)
print("who_after_remove")
subprocess.run(["who"], check=False)
PY
who | grep -F file-acl-probe || echo "no stale utempter record"

echo "sticky dir hardlink and regular-file protections"
for d in /tmp /var/tmp /run/lock /run/screen /var/crash; do
  test -d "$d" || continue
  rm -f "$d/file_acl_probe_hardlink" "$d/file_acl_probe_regular" "$d/file_acl_probe_symlink"
  printf attacker > "$d/file_acl_probe_regular"
  ln /etc/shadow "$d/file_acl_probe_hardlink" >/tmp/file_acl_probe.hardlink.out 2>&1
  rc=$?
  echo "HARDLINK $d rc=$rc $(cat /tmp/file_acl_probe.hardlink.out)"
  ln -s /etc/shadow "$d/file_acl_probe_symlink" 2>/dev/null
  stat -c "PRE_REGULAR $d %A %U %G %n" "$d/file_acl_probe_regular" 2>/dev/null
  stat -c "PRE_SYMLINK $d %A %U %G %n -> %N" "$d/file_acl_probe_symlink" 2>/dev/null
done
ATTACKER

echo "## root-side sticky directory write-follow tests"
for d in /tmp /var/tmp /run/lock /run/screen /var/crash; do
  test -d "$d" || continue
  sh -c "printf root > '$d/file_acl_probe_regular'" >/tmp/file_acl_probe.root_trunc.out 2>&1
  rc=$?
  echo "ROOT_TRUNCATE $d rc=$rc err=$(cat /tmp/file_acl_probe.root_trunc.out)"
  mode "$d/file_acl_probe_regular" "$d/file_acl_probe_symlink" "$d/file_acl_probe_hardlink"
done

echo "## tmpfiles symlink/cleanup tests"
printf sentinel > "$root_marker"
runuser -u attacker -- bash -s <<'ATTACKER'
set +e
rm -f /tmp/.X0-lock /run/screen/file_acl_probe_old /run/screen/file_acl_probe_link
ln -s /root/file_acl_probe_root_marker /tmp/.X0-lock
printf old > /run/screen/file_acl_probe_old
touch -d 1970-01-01 /run/screen/file_acl_probe_old
ln -s /root/file_acl_probe_screen_marker /run/screen/file_acl_probe_link
stat -c 'PRE_TMPFILES %A %U %G %n -> %N' /tmp/.X0-lock /run/screen/file_acl_probe_old /run/screen/file_acl_probe_link 2>/dev/null
ATTACKER
systemd-tmpfiles --clean --prefix=/tmp >/tmp/file_acl_probe.tmpfiles_tmp.out 2>&1
systemd-tmpfiles --remove --boot --prefix=/tmp/.X0-lock >/tmp/file_acl_probe.tmpfiles_xlock.out 2>&1
systemd-tmpfiles --create --clean --prefix=/run/screen >/tmp/file_acl_probe.tmpfiles_screen.out 2>&1
echo "tmpfiles_tmp_rc=$? out=$(cat /tmp/file_acl_probe.tmpfiles_tmp.out)"
echo "tmpfiles_xlock_out=$(cat /tmp/file_acl_probe.tmpfiles_xlock.out)"
echo "tmpfiles_screen_out=$(cat /tmp/file_acl_probe.tmpfiles_screen.out)"
mode "$root_marker" /root/file_acl_probe_screen_marker /tmp/.X0-lock /run/screen/file_acl_probe_old /run/screen/file_acl_probe_link

echo "## apport /var/crash cron symlink tests"
runuser -u attacker -- bash -s <<'ATTACKER'
set +e
rm -rf /var/crash/file_acl_probe_zero.crash /var/crash/file_acl_probe_old.crash /var/crash/123456789012
printf sentinel > /var/crash/file_acl_probe_zero.crash
: > /var/crash/file_acl_probe_empty.crash
ln -s /root/file_acl_probe_root_marker /var/crash/file_acl_probe_old.crash
mkdir -p /var/crash/123456789012
ln -s /root/file_acl_probe_crash_dir_marker /var/crash/123456789012/link
touch -h -d 1970-01-01 /var/crash/file_acl_probe_old.crash 2>/dev/null || true
touch -d 1970-01-01 /var/crash/file_acl_probe_empty.crash /var/crash/123456789012 2>/dev/null
stat -c 'PRE_CRASH %A %U %G %n -> %N' /var/crash/file_acl_probe_zero.crash /var/crash/file_acl_probe_empty.crash /var/crash/file_acl_probe_old.crash /var/crash/123456789012 /var/crash/123456789012/link 2>/dev/null
ATTACKER
/etc/cron.daily/apport >/tmp/file_acl_probe.apport.out 2>&1
echo "apport_cron_rc=$? out=$(cat /tmp/file_acl_probe.apport.out)"
mode "$root_marker" /root/file_acl_probe_crash_dir_marker /var/crash/file_acl_probe_zero.crash /var/crash/file_acl_probe_empty.crash /var/crash/file_acl_probe_old.crash /var/crash/123456789012 /var/crash/123456789012/link

echo "## logrotate/root log path write checks"
runuser -u attacker -- bash -s <<'ATTACKER'
set +e
for f in /var/log/syslog /var/log/auth.log /var/log/mail.log /var/log/cron.log /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/dpkg.log /var/log/apt/history.log; do
  [ -e "$f" ] || continue
  if sh -c "printf file_acl_probe >> '$f'" 2>/tmp/file_acl_probe.logappend.err; then
    echo "LOG_APPEND_OK $f"
  else
    echo "LOG_APPEND_DENY $f $(cat /tmp/file_acl_probe.logappend.err)"
  fi
done
ATTACKER
logrotate -d /etc/logrotate.conf 2>&1 | grep -E 'reading config file|considering log|rotating pattern|error:' | sed -n '1,120p'

echo "## cleanup"
find /tmp /var/tmp /run/lock /run/screen /var/crash -maxdepth 1 \
  \( -name 'file_acl_probe*' -o -name '.X0-lock' -o -name '123456789012' \) \
  -exec rm -rf -- {} + 2>/dev/null
rm -f /root/file_acl_probe_root_marker /root/file_acl_probe_screen_marker /root/file_acl_probe_crash_dir_marker
find /tmp /var/tmp /run/lock /run/screen /var/crash /root -maxdepth 2 \( -name 'file_acl_probe*' -o -name '.X0-lock' -o -name '123456789012' \) -printf 'LEFT %M %u %g %p -> %l\n' 2>/dev/null
echo "no root proof marker remains"
INNER
