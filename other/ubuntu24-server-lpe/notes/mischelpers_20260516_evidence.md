# mischelpers evidence 2026-05-16

Container: `ubuntu24-server-lpe-target`

Probe script: `pocs/mischelpers_probe.sh`

## Baseline

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Packages:

```text
openssh-client	1:9.6p1-3ubuntu13.16	ii
libutempter0	1.2.1-3build1	ii
dbus	1.14.10-4ubuntu4.1	ii
mtr-tiny	0.95-1.1ubuntu0.1	ii
iputils-ping	3:20240117-1ubuntu0.1	ii
```

Modes/capabilities:

```text
-rwsr-xr-x 4755 root root /usr/lib/openssh/ssh-keysign
-rwxr-sr-x 2755 root utmp /usr/lib/aarch64-linux-gnu/utempter/utempter
-rwxr-sr-x 2755 root _ssh /usr/bin/ssh-agent
-rwxr-xr-x 755 root root /usr/bin/mtr-packet
/usr/bin/mtr-packet cap_net_raw=ep
-rwxr-xr-x 755 root root /usr/bin/ping
/usr/bin/ping cap_net_raw=ep
-rwsr-xr-- 4754 root messagebus /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

Package owners:

```text
openssh-client: /usr/lib/openssh/ssh-keysign
libutempter0:arm64: /usr/lib/aarch64-linux-gnu/utempter/utempter
openssh-client: /usr/bin/ssh-agent
mtr-tiny: /usr/bin/mtr-packet
iputils-ping: /usr/bin/ping
dbus: /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

Default SSH config:

```text
/etc/ssh/ssh_config:19: Include /etc/ssh/ssh_config.d/*.conf
/etc/ssh/ssh_config:26: #   HostbasedAuthentication no
/etc/ssh/ssh_config.d: 755 root root
/etc/ssh contents: ssh_config and ssh_config.d only; no ssh_host_* private keys
```

System D-Bus activation:

```text
dbus.service active
dbus.socket active
/usr/share/dbus-1/system-services/*.service: 644 root root
/etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf: 644 root root
/usr/share/dbus-1/system.d/*.conf: 644 root root
```

Binary string checks showed the expected fixed helper surfaces:

```text
ssh-keysign: ../../ssh-keysign.c, /etc/ssh/ssh_config, /etc/ssh/ssh_host_*_key, "ssh-keysign not enabled in %s"
utempter: pututline, updwtmp, /var/log/wtmp, "cannot find slave pty", "belongs to another user"
mtr-packet: check-support, send-probe, icmp, tcp, udp, "Failure to open IPv4 sockets"
dbus helper: /usr/share/dbus-1/system.conf, /dbus-1/system-services, "not invoked from user '%s'", Exec, User
```

## Trigger evidence

### ssh-keysign

Trigger used a hostile attacker-controlled home/config/path:

```sh
HOME=/home/attacker/mischelpers_probe/home \
PATH=/home/attacker/mischelpers_probe/bin:$PATH \
LD_PRELOAD=/home/attacker/mischelpers_probe/nope.so \
timeout 3 /usr/lib/openssh/ssh-keysign </dev/null
```

Observed:

```text
ssh-keysign_rc=255
ERROR: ld.so: object '/home/attacker/mischelpers_probe/nope.so' ... ignored.
ssh-keysign not enabled in /etc/ssh/ssh_config
no ssh-keysign user-config or PATH exec marker
```

The same user config contained:

```text
Host *
  EnableSSHKeysign yes
  HostbasedAuthentication yes
Match exec "id > /tmp/mischelpers_probe.ssh_match_exec"
```

Control check with the normal client parser:

```text
ssh_client_config_parse_rc=0
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Conclusion: per-user `Match exec` is reachable in the attacker `ssh` client, not in the root `ssh-keysign` helper path.

### ssh-agent

Command child:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
srw------- 1 1001 1001 0 /tmp/mischelpers_probe.agent.sock
```

PKCS#11 helper-exec with attacker `SSH_PKCS11_HELPER`:

```text
ssh_add_rc=1
Could not add card "/usr/lib/aarch64-linux-gnu/libc.so.6": agent refused operation
pkcs11 helper id:
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Symlink/socket write test:

```text
ssh-agent_symlink_bind_rc=1
unix_listener: cannot bind to path /tmp/mischelpers_probe.agent.link: Address already in use
no root symlink target created
```

Conclusion: no `_ssh` group execution, no root execution, no symlink root write.

### utempter

Python/ctypes PTY trigger:

```text
pty /dev/pts/0 uid 1001 gid 1001 groups [1001]
who_after_add
attacker pts/0        May 16 12:22 (mischelpers-probe)
who_after_remove
no stale active utmp record
```

Direct attacker write to `/var/log/wtmp` failed, while read was world-readable:

```text
bash: /var/log/wtmp: Permission denied
```

Conclusion: the helper can perform bounded accounting writes via `utmp`/`wtmp`; this did not become arbitrary file write or root execution.

### mtr-packet and ping

`mtr-packet` command trigger:

```text
printf '4 send-probe ip-4 127.0.0.1 protocol icmp timeout 1\n' | timeout 3 /usr/bin/mtr-packet
4 reply ip-4 127.0.0.1 round-trip-time 27
```

`mtr-packet` process status while waiting for commands:

```text
Uid:	1001	1001	1001	1001
Gid:	1001	1001	1001	1001
Groups:	1001
CapPrm:	0000000000002000
CapEff:	0000000000002000
CapAmb:	0000000000000000
```

`ping` process status after socket setup:

```text
Uid:	1001	1001	1001	1001
Gid:	1001	1001	1001	1001
Groups:	1001
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapAmb:	0000000000000000
PING 127.0.0.1 ... 0% packet loss
```

Conclusion: reachable packet capability only; no uid/gid/root transition.

### dbus-daemon-launch-helper

Direct trigger:

```text
timeout 3 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
dbus_helper_rc=126
Permission denied
```

Attacker-created system service under `$XDG_DATA_HOME`:

```text
[D-BUS Service]
Name=com.attacker.Misc
Exec=/bin/sh -c "id >/tmp/mischelpers_probe.dbus_user_service_ran"
User=root
```

System bus activation result:

```text
dbus_user_service_start_rc=1
Call failed: The name com.attacker.Misc was not provided by any .service files
no user service marker
```

Existing root-owned service activation control:

```text
StartServiceByName org.freedesktop.PolicyKit1 -> u 2
```

Conclusion: direct helper exec is blocked by mode/group; system service file injection from attacker paths is ignored.

## Cleanup

Commands performed:

```sh
pgrep -a -u attacker ssh-agent | awk '/mischelpers_probe/ {print $1}' | xargs -r kill
rm -rf /tmp/mischelpers_probe* /home/attacker/mischelpers_probe
who | grep -F mischelpers || true
find /tmp /home/attacker -maxdepth 2 \( -name 'mischelpers_probe*' -o -name 'mh_*' \) -print
test ! -e /root/mischelpers_probe_root_target
```

Observed:

```text
no root proof or root write marker
```

No valid LPE was produced.
