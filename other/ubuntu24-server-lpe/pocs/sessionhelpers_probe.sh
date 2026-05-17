#!/bin/sh
set -eu

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash <<'INCONTAINER'
set -eu

backup=/tmp/sessionhelpers_backup.$$
mkdir -p "$backup"
state=/tmp/sessionhelpers_state.$$
tracked="
/var/lib/landscape/landscape-sysinfo.cache
/var/lib/update-notifier/fsck-at-reboot
/var/lib/ubuntu-release-upgrader/release-upgrade-available
"

cleanup() {
  rm -rf /home/attacker/sessionhelpers_probe /tmp/sessionhelpers_probe_* /tmp/sessionhelpers_path_marker /tmp/sessionhelpers_py_marker
  while read -r flag path; do
    [ -n "${path:-}" ] || continue
    if [ "$flag" = absent ]; then
      rm -f "$path"
    elif [ "$flag" = present ]; then
      cp -a "$backup$path" "$path" 2>/dev/null || true
    fi
  done < "$state" 2>/dev/null || true
  rm -rf "$backup" "$state"
}
trap cleanup EXIT INT TERM

for path in $tracked; do
  if [ -e "$path" ]; then
    echo "present $path" >> "$state"
    mkdir -p "$backup$(dirname "$path")"
    cp -a "$path" "$backup$path"
  else
    echo "absent $path" >> "$state"
  fi
done

echo "== versions =="
dpkg-query -W login passwd libpam0g libpam-modules libpam-runtime util-linux landscape-common pollinate ubuntu-pro-client ubuntu-release-upgrader-core update-notifier-common 2>/dev/null || true

echo "== reachable PAM and helper lines =="
nl -ba /etc/pam.d/login | sed -n '29,35p'
nl -ba /usr/share/landscape/landscape-sysinfo.wrapper | sed -n '5,29p'
nl -ba /etc/update-motd.d/91-release-upgrade | sed -n '13,20p'
nl -ba /usr/lib/ubuntu-release-upgrader/release-upgrade-motd | sed -n '23,39p'

echo "== attacker cannot execute login with euid root =="
runuser -u attacker -- bash -lc '/usr/bin/login -f attacker </dev/null >/tmp/sessionhelpers_probe_login_attacker.out 2>&1; rc=$?; echo rc=$rc; sed -n "1,5p" /tmp/sessionhelpers_probe_login_attacker.out'

echo "== hostile PATH/PYTHONPATH fixture =="
install -d -o attacker -g attacker -m 0755 /home/attacker/sessionhelpers_probe/pwnbin /home/attacker/sessionhelpers_probe/pyhook
for cmd in find bc cut id; do
  cat >"/home/attacker/sessionhelpers_probe/pwnbin/$cmd" <<EOF
#!/bin/sh
/bin/echo "FAKE-$cmd uid=\$(/usr/bin/id -u) euid=\$(/usr/bin/id -u) args=\$*" >> /tmp/sessionhelpers_path_marker
exec /usr/bin/$cmd "\$@"
EOF
  chmod 0755 "/home/attacker/sessionhelpers_probe/pwnbin/$cmd"
done
cat >/home/attacker/sessionhelpers_probe/pyhook/sitecustomize.py <<'EOF'
import os, sys
with open("/tmp/sessionhelpers_py_marker", "a") as f:
    f.write("sitecustomize uid=%s euid=%s argv=%r\n" % (os.getuid(), os.geteuid(), sys.argv))
EOF
chown -R attacker:attacker /home/attacker/sessionhelpers_probe

echo "== direct attacker update-motd run stays uid1001 =="
rm -f /tmp/sessionhelpers_path_marker /tmp/sessionhelpers_py_marker
runuser -u attacker -- env HOME=/home/attacker USER=attacker LOGNAME=attacker PATH=/home/attacker/sessionhelpers_probe/pwnbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin PYTHONPATH=/home/attacker/sessionhelpers_probe/pyhook run-parts /etc/update-motd.d >/tmp/sessionhelpers_probe_runparts.out 2>/tmp/sessionhelpers_probe_runparts.err || true
cat /tmp/sessionhelpers_path_marker /tmp/sessionhelpers_py_marker 2>/dev/null || true

echo "== root-side PAM login does not inherit hostile PATH/PYTHONPATH =="
rm -f /tmp/sessionhelpers_path_marker /tmp/sessionhelpers_py_marker /tmp/sessionhelpers_probe_login_root.out /tmp/sessionhelpers_probe_login_root.typescript
printf 'exit\n' | timeout 6s script -qfec "env -i HOME=/home/attacker USER=attacker LOGNAME=attacker SHELL=/bin/bash TERM=xterm PATH=/home/attacker/sessionhelpers_probe/pwnbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin PYTHONPATH=/home/attacker/sessionhelpers_probe/pyhook /usr/bin/login -p -f attacker" /tmp/sessionhelpers_probe_login_root.typescript >/tmp/sessionhelpers_probe_login_root.out 2>&1 || true
if [ -e /tmp/sessionhelpers_path_marker ] || [ -e /tmp/sessionhelpers_py_marker ]; then
  echo "unexpected marker"
  cat /tmp/sessionhelpers_path_marker /tmp/sessionhelpers_py_marker 2>/dev/null || true
else
  echo "no hostile env markers from PAM login"
fi

echo "== attacker cannot start root helper services or poison systemd manager env =="
runuser -u attacker -- bash -lc 'for u in motd-news.service update-notifier-motd.service update-notifier-download.service ua-timer.service ubuntu-advantage.service pollinate.service; do echo "service=$u"; systemctl start "$u" 2>&1 || true; done; systemctl set-environment PATH=/home/attacker/sessionhelpers_probe/pwnbin:/usr/bin PYTHONPATH=/home/attacker/sessionhelpers_probe/pyhook 2>&1 || true; systemctl show-environment | sed -n "1,5p"'

echo "== direct pro/release helpers are attacker uid only =="
rm -f /tmp/sessionhelpers_py_marker
runuser -u attacker -- bash -lc 'cd /home/attacker; PYTHONPATH=/home/attacker/sessionhelpers_probe/pyhook /usr/bin/pro status --format json >/tmp/sessionhelpers_probe_pro.out 2>/tmp/sessionhelpers_probe_pro.err || true; PYTHONPATH=/home/attacker/sessionhelpers_probe/pyhook timeout 8s /usr/bin/do-release-upgrade -c >/tmp/sessionhelpers_probe_dorelease.out 2>/tmp/sessionhelpers_probe_dorelease.err || true'
cat /tmp/sessionhelpers_py_marker 2>/dev/null || true

echo "== service-account writable state is not attacker-writable =="
runuser -u landscape -- bash -lc 'touch /var/lib/landscape/sessionhelpers_probe_landscape && rm -f /var/lib/landscape/sessionhelpers_probe_landscape'
runuser -u attacker -- bash -lc 'touch /var/lib/landscape/sessionhelpers_probe_attacker' 2>&1 || true
runuser -u pollinate -- bash -lc 'touch /var/cache/pollinate/sessionhelpers_probe_pollinate && rm -f /var/cache/pollinate/sessionhelpers_probe_pollinate'
runuser -u attacker -- bash -lc 'touch /var/cache/pollinate/sessionhelpers_probe_attacker' 2>&1 || true
INCONTAINER
