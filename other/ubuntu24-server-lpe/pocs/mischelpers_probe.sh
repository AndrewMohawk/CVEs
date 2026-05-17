#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$target" bash -s <<'INNER'
set +e

echo "## target"
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker

echo "## package versions and default helper modes"
for pkg in openssh-client libutempter0 dbus mtr-tiny iputils-ping; do
  dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg"
done
for f in \
  /usr/lib/openssh/ssh-keysign \
  /usr/lib/aarch64-linux-gnu/utempter/utempter \
  /usr/bin/ssh-agent \
  /usr/bin/mtr-packet \
  /usr/bin/ping \
  /usr/lib/dbus-1.0/dbus-daemon-launch-helper
do
  stat -c '%A %a %U %G %n' "$f"
  getcap "$f" 2>/dev/null
done

echo "## ssh config and host-key state"
nl -ba /etc/ssh/ssh_config | sed -n '18,55p'
find /etc/ssh/ssh_config.d -maxdepth 1 -printf '%m %u %g %p\n'
ls -la /etc/ssh

echo "## group-owned files for helper groups"
find / -xdev \( -group _ssh -o -group utmp -o -group messagebus \) \
  -printf '%m %u %g %p\n' 2>/dev/null | sort

runuser -u attacker -- bash -s <<'ATTACKER'
set +e
base=/tmp/mischelpers_probe
home=/home/attacker/mischelpers_probe
rm -rf "$base"* "$home"
mkdir -p "$home/home/.ssh" "$home/bin" "$home/xdg/dbus-1/system-services"

echo "## attacker"
id

echo "## ssh-keysign: user config/env/cwd do not enable root signing or root exec"
cat > "$home/home/.ssh/config" <<'EOF'
Host *
  EnableSSHKeysign yes
  HostbasedAuthentication yes
Match exec "id > /tmp/mischelpers_probe.ssh_match_exec"
EOF
cat > "$home/bin/sh" <<'EOF'
#!/bin/sh
id > /tmp/mischelpers_probe.fake_sh
exec /bin/sh "$@"
EOF
chmod 755 "$home/bin/sh"
HOME="$home/home" PATH="$home/bin:$PATH" LD_PRELOAD="$home/nope.so" \
  timeout 3 /usr/lib/openssh/ssh-keysign </dev/null \
  >"$base.sshkeysign.out" 2>"$base.sshkeysign.err"
echo "ssh-keysign_rc=$?"
cat "$base.sshkeysign.err"
ls -l /tmp/mischelpers_probe.ssh_match_exec /tmp/mischelpers_probe.fake_sh 2>/dev/null \
  || echo "no ssh-keysign user-config or PATH exec marker"
ssh -F "$home/home/.ssh/config" -G example.com >/dev/null 2>"$base.sshG.err"
echo "ssh_client_config_parse_rc=$?"
cat /tmp/mischelpers_probe.ssh_match_exec 2>/dev/null \
  || echo "no ssh client marker"
rm -f /tmp/mischelpers_probe.ssh_match_exec /tmp/mischelpers_probe.fake_sh

echo "## ssh-agent: command, socket, and helper exec stay uid1001/gid1001"
cat > "$home/pkcs11_helper.sh" <<'EOF'
#!/bin/sh
id > /tmp/mischelpers_probe.pkcs11_helper_id
exit 1
EOF
chmod 755 "$home/pkcs11_helper.sh"
SSH_PKCS11_HELPER="$home/pkcs11_helper.sh" \
  timeout 8 /usr/bin/ssh-agent -a "$base.agent.sock" sh -c \
  'id; ssh-add -s /usr/lib/aarch64-linux-gnu/libc.so.6 </dev/null >/tmp/mischelpers_probe.sshadd.out 2>/tmp/mischelpers_probe.sshadd.err; echo ssh_add_rc=$?; cat /tmp/mischelpers_probe.sshadd.err; ls -ln /tmp/mischelpers_probe.agent.sock'
echo "pkcs11 helper id:"
cat /tmp/mischelpers_probe.pkcs11_helper_id 2>/dev/null || echo "no pkcs11 helper marker"
ln -sf /root/mischelpers_probe_root_target "$base.agent.link"
timeout 5 /usr/bin/ssh-agent -a "$base.agent.link" true >"$base.agent_link.out" 2>"$base.agent_link.err"
echo "ssh-agent_symlink_bind_rc=$?"
cat "$base.agent_link.err"
test ! -e /root/mischelpers_probe_root_target && echo "no root symlink target created"

echo "## utempter: lib path can add/remove attacker utmp record only"
timeout 5 python3 - <<'PY'
import ctypes
import os
import pty
import subprocess

master, slave = pty.openpty()
print("pty", os.ttyname(slave), "uid", os.getuid(), "gid", os.getgid(), "groups", os.getgroups())
lib = ctypes.CDLL("libutempter.so.0")
lib.utempter_add_record.argtypes = [ctypes.c_int, ctypes.c_char_p]
lib.utempter_remove_record.argtypes = [ctypes.c_int]
lib.utempter_add_record(master, b"mischelpers-probe")
print("who_after_add")
subprocess.run(["who"], check=False)
lib.utempter_remove_record(master)
print("who_after_remove")
subprocess.run(["who"], check=False)
PY
who | grep -F mischelpers-probe || echo "no stale active utmp record"

echo "## cap_net_raw helpers: reachable packet primitive, no uid/gid/root transition"
printf '4 send-probe ip-4 127.0.0.1 protocol icmp timeout 1\n' | timeout 3 /usr/bin/mtr-packet
timeout 5 bash -c '(sleep 3) | /usr/bin/mtr-packet >/tmp/mischelpers_probe.mtr_wait.out 2>&1' &
mtr_pid=$!
sleep 0.3
grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):' "/proc/$mtr_pid/status" 2>/dev/null
wait "$mtr_pid"
timeout 5 /usr/bin/ping -c 3 -i 1 127.0.0.1 >/tmp/mischelpers_probe.ping.out 2>&1 &
ping_pid=$!
sleep 0.3
grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):' "/proc/$ping_pid/status" 2>/dev/null
wait "$ping_pid"
sed -n '1,5p' /tmp/mischelpers_probe.ping.out

echo "## dbus launch helper: direct execute blocked, user system-service dir ignored"
timeout 3 /usr/lib/dbus-1.0/dbus-daemon-launch-helper </dev/null \
  >"$base.dbus_helper.out" 2>"$base.dbus_helper.err"
echo "dbus_helper_rc=$?"
cat "$base.dbus_helper.err"
cat > "$home/xdg/dbus-1/system-services/com.attacker.Misc.service" <<'EOF'
[D-BUS Service]
Name=com.attacker.Misc
Exec=/bin/sh -c "id >/tmp/mischelpers_probe.dbus_user_service_ran"
User=root
EOF
XDG_DATA_HOME="$home/xdg" \
  busctl call org.freedesktop.DBus /org/freedesktop/DBus \
  org.freedesktop.DBus StartServiceByName su com.attacker.Misc 0 \
  >"$base.dbus_start.out" 2>"$base.dbus_start.err"
echo "dbus_user_service_start_rc=$?"
cat "$base.dbus_start.err"
cat "$base.dbus_start.out"
ls -l /tmp/mischelpers_probe.dbus_user_service_ran 2>/dev/null \
  || echo "no user service marker"

echo "## attacker cleanup"
rm -rf "$base"* "$home" /tmp/mischelpers_probe.*
ATTACKER

echo "## root cleanup verification"
pgrep -a -u attacker ssh-agent | awk '/mischelpers_probe/ {print $1}' | xargs -r kill
rm -rf /tmp/mischelpers_probe* /home/attacker/mischelpers_probe
who | grep -F mischelpers || true
find /tmp /home/attacker -maxdepth 2 \( -name 'mischelpers_probe*' -o -name 'mh_*' \) -print 2>/dev/null
test ! -e /root/mischelpers_probe_root_target && echo "no root proof or root write marker"
INNER
