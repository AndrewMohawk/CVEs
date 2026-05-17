#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
method="${2:-Check}"
fstype="${3:-ext4}"
probe_dir="/tmp/udisks-missing-goto-strace"

docker cp tools/udisks-active-trigger.sh "$container:$probe_dir-trigger.sh"
docker cp tools/udisks-persistent-call.py "$container:$probe_dir-persistent-call.py"

docker exec "$container" bash -lc "
set -euo pipefail
mkdir -p '$probe_dir'
chmod 0777 '$probe_dir'
rm -f '$probe_dir'/strace* '$probe_dir'/user.log '$probe_dir'/user.rc '$probe_dir'/openvt.log
chmod 0755 '$probe_dir-trigger.sh' '$probe_dir-persistent-call.py'
chown selfauth:selfauth '$probe_dir-trigger.sh' '$probe_dir-persistent-call.py'

loginctl terminate-user selfauth >/dev/null 2>&1 || true
systemctl restart udisks2.service
sleep 2
pid=\$(pidof udisksd)
echo \"udisksd_pid=\$pid\" | tee '$probe_dir/root.log'

strace -ff -s 300 -e trace=execve,clone,fork,vfork -p \"\$pid\" -o '$probe_dir/strace' >/dev/null 2>&1 &
stracepid=\$!
sleep 1

old_profile_state=absent
if [ -e /home/selfauth/.bash_profile ]; then
  old_profile_state=present
  cp -a /home/selfauth/.bash_profile '$probe_dir/bash_profile.bak'
fi

cat >/home/selfauth/.bash_profile <<'PROFILE'
#!/usr/bin/env bash
set +e
/tmp/udisks-missing-goto-strace-trigger.sh METHOD_PLACEHOLDER FSTYPE_PLACEHOLDER >/tmp/udisks-missing-goto-strace/user.log 2>&1
echo \$? >/tmp/udisks-missing-goto-strace/user.rc
exit
PROFILE
sed -i 's/METHOD_PLACEHOLDER/'\"$method\"'/; s/FSTYPE_PLACEHOLDER/'\"$fstype\"'/' /home/selfauth/.bash_profile
chown selfauth:selfauth /home/selfauth/.bash_profile
chmod 0644 /home/selfauth/.bash_profile

set +e
timeout 60 openvt -c 2 -s -f -w -- /bin/login -f selfauth >'$probe_dir/openvt.log' 2>&1
openvt_rc=\$?
echo \"openvt_rc=\$openvt_rc\" >>'$probe_dir/root.log'

sleep 3
kill \"\$stracepid\" >/dev/null 2>&1 || true
wait \"\$stracepid\" >/dev/null 2>&1 || true

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
echo '=== exec trace ==='
grep -hE 'execve|clone|fork|vfork' '$probe_dir'/strace* | sed -n '1,260p' || true
echo '=== journal crash lines ==='
journalctl -u udisks2.service -n 30 --no-pager | sed -n '1,120p' || true
"
