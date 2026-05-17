# Negative: network diagnostics tools and tcpdump postrotate hooks

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server image. Attacker identity was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no uid1001 -> root local privilege escalation was validated in this lane. The default network diagnostic tools are installed, and `tcpdump` has a scanner-attractive postrotate hook option, but none of the tested tools is setuid/root or file-capability privileged except the previously covered `ping`/`mtr-packet` helpers. There is no default root `tcpdump` service, timer, cron, or logrotate consumer in this Server state.

Artifacts:

```text
pocs/network_diagnostics_tools_probe.sh
logs/network-diagnostics-tools.out
```

## Default package proof

Relevant default package versions:

```text
bind9-dnsutils      1:9.18.39-0ubuntu0.24.04.3
bind9-host          1:9.18.39-0ubuntu0.24.04.3
curl                8.5.0-2ubuntu10.9
ftp                 20230507-2build3
inetutils-telnet    2:2.5-3ubuntu4.1
iputils-ping        3:20240117-1ubuntu0.1
iputils-tracepath   3:20240117-1ubuntu0.1
libpcap0.8t64       1.10.4-4.1ubuntu3
mtr-tiny            0.95-1.1ubuntu0.1
netcat-openbsd      1.226-1ubuntu2
tcpdump             4.99.4-3ubuntu4.24.04.1
tnftp               20230507-2build3
wget                1.21.4-1ubuntu4.1
```

Helper modes:

```text
/usr/bin/tcpdump    0755 root:root
/usr/bin/tracepath  0755 root:root
/usr/bin/nc.openbsd 0755 root:root
/usr/bin/dig        0755 root:root
/usr/bin/host       0755 root:root
/usr/bin/curl       0755 root:root
/usr/bin/wget       0755 root:root
```

Default file capabilities in this family are limited to the already-covered helpers:

```text
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping       cap_net_raw=ep
```

`tcpdump` itself has no setuid bit and no file capabilities.

## Reachability and blocking boundary

No default `tcpdump`, `pcap`, `mtr`, or `tracepath` unit exists. The only related unit in the broad service-name query was `rsync.service`, which is disabled and condition-gated by the absence of `/etc/rsyncd.conf`.

uid1001 could not plant hooks or units:

```text
/etc/logrotate.d/network-diagnostics-lpe             Permission denied
/etc/cron.daily/network-diagnostics-lpe              Permission denied
/usr/lib/systemd/system/network-diagnostics-lpe.service Permission denied
/run/systemd/system/network-diagnostics-lpe.service  Permission denied
/etc/tcpdump/network-diagnostics-lpe                 No such file or directory
```

Direct `tcpdump` execution listed interfaces, but capture and postrotate hook execution failed before any payload path because the process lacked packet-capture privilege:

```text
tcpdump -D -> interface list returned
tcpdump -i lo -c 1 -w /tmp/network_diag_attacker.pcap
  tcpdump: lo: You don't have permission to perform this capture on that device
  (socket: Operation not permitted)

tcpdump -i lo -G 1 -W 1 -w /tmp/network_diag_rotate.pcap -z /home/attacker/.../postrotate.sh
  tcpdump: lo: You don't have permission to perform this capture on that device
  (socket: Operation not permitted)
no_direct_root_marker
```

Other network CLI tools ran as normal uid1001 data-plane utilities:

```text
tracepath 127.0.0.1 -> reached localhost
dig localhost       -> normal DNS answer
host localhost      -> normal host answer
nc.openbsd -h       -> help text only
```

Service and environment attempts were also blocked:

```text
systemctl start tcpdump.service -> Interactive authentication required
systemctl start rsync.service   -> Interactive authentication required
systemctl set-environment PATH=... -> Access denied
```

Root-starting the only adjacent fixed service proved the default condition gate:

```text
rsync.service skipped: ConditionPathExists=/etc/rsyncd.conf
ROOT_PROOF=no
```

## Cleanup

The probe removed `/root/network_diagnostics_tools_lpe_marker`, `/home/attacker/network_diagnostics_tools_probe`, and transient `/tmp/network_diag_*` files. Final health was `systemctl is-system-running -> running`.

## Conclusion

Negative. `tcpdump -z` is a real dangerous option when a privileged operator supplies attacker-controlled arguments, but a normal local user on stock Ubuntu Server cannot reach a root `tcpdump` caller and cannot capture packets directly with the packaged binary. The default diagnostic tools here either have no privilege boundary or only expose bounded raw-network capability already covered in the capability-helper lane.
