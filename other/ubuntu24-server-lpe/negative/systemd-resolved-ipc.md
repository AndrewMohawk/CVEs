# systemd-resolved IPC audit: no uid1001 -> root LPE

Status: negative. No local privilege escalation was found from the default
`attacker` user (`uid=1001 gid=1001 groups=1001`) through the default
`systemd-resolved` D-Bus API, varlink sockets, DNS stub listener, `resolvectl`,
or NSS resolver path on the Docker Ubuntu Server target.

## Target package and default reachability

Target:

```sh
docker ps --filter name=ubuntu24-server-lpe-target --format '{{.Names}} {{.Image}} {{.Status}}'
# ubuntu24-server-lpe-target ubuntu24-server-default-lpe:20260516-standard Up 2 hours
```

Package and identity proof:

```text
OS=Ubuntu 24.04.4 LTS
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)

dbus              1.14.10-4ubuntu4.1
systemd           255.4-1ubuntu8.15
systemd-resolved  255.4-1ubuntu8.15
libnss-resolve    not installed
libnss-myhostname not installed
```

The service is default-enabled and active:

```text
systemd-resolved.service: enabled, active/running
Bus name: org.freedesktop.resolve1
Process: /usr/lib/systemd/systemd-resolved
Runtime uid/gid: systemd-resolve:systemd-resolve
```

Default reachable IPC and resolver state:

```text
/run/systemd/resolve/io.systemd.Resolve         srw-rw-rw- systemd-resolve:systemd-resolve
/run/systemd/resolve/io.systemd.Resolve.Monitor srw------- systemd-resolve:systemd-resolve
/run/systemd/resolve/resolv.conf                -rw-r--r-- systemd-resolve:systemd-resolve
/run/systemd/resolve/stub-resolv.conf           -rw-r--r-- systemd-resolve:systemd-resolve

UDP/TCP DNS stub listeners:
127.0.0.53%lo:53
127.0.0.54:53

/etc/nsswitch.conf:12: hosts:          files dns
/etc/resolv.conf: regular Docker-provided file, not the resolved stub symlink
resolvectl: resolv.conf mode: foreign
```

## Relevant default configuration

`/usr/lib/systemd/system/systemd-resolved.service`:

```ini
24 AmbientCapabilities=CAP_SETPCAP CAP_NET_RAW CAP_NET_BIND_SERVICE
25 BusName=org.freedesktop.resolve1
26 CapabilityBoundingSet=CAP_SETPCAP CAP_NET_RAW CAP_NET_BIND_SERVICE
27 ExecStart=!!/usr/lib/systemd/systemd-resolved
30 NoNewPrivileges=yes
31 PrivateDevices=yes
32 PrivateTmp=yes
39 ProtectSystem=strict
42 RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
43 RestrictNamespaces=yes
46 RuntimeDirectory=systemd/resolve
52 User=systemd-resolve
59 Alias=dbus-org.freedesktop.resolve1.service
```

`/usr/share/dbus-1/system-services/org.freedesktop.resolve1.service`:

```ini
11 Name=org.freedesktop.resolve1
12 Exec=/bin/false
13 User=root
14 SystemdService=dbus-org.freedesktop.resolve1.service
```

`/usr/share/dbus-1/system.d/org.freedesktop.resolve1.conf` allows transport
access to the bus name, but not authorization for mutating methods:

```xml
16 <policy user="systemd-resolve">
17   <allow own="org.freedesktop.resolve1"/>
18   <allow send_destination="org.freedesktop.resolve1"/>
19   <allow receive_sender="org.freedesktop.resolve1"/>
22 <policy context="default">
23   <allow send_destination="org.freedesktop.resolve1"/>
24   <allow receive_sender="org.freedesktop.resolve1"/>
```

`/usr/share/polkit-1/actions/org.freedesktop.resolve1.policy` gates persistent
resolver state changes. Examples:

```xml
43  <action id="org.freedesktop.resolve1.set-dns-servers">
47    <allow_any>auth_admin</allow_any>
48    <allow_inactive>auth_admin</allow_inactive>
49    <allow_active>auth_admin_keep</allow_active>

54  <action id="org.freedesktop.resolve1.set-domains">
58    <allow_any>auth_admin</allow_any>
59    <allow_inactive>auth_admin</allow_inactive>
60    <allow_active>auth_admin_keep</allow_active>

76  <action id="org.freedesktop.resolve1.set-llmnr">
80    <allow_any>auth_admin</allow_any>
81    <allow_inactive>auth_admin</allow_inactive>
82    <allow_active>auth_admin_keep</allow_active>

131 <action id="org.freedesktop.resolve1.revert">
135   <allow_any>auth_admin</allow_any>
136   <allow_inactive>auth_admin</allow_inactive>
137   <allow_active>auth_admin_keep</allow_active>
```

`/etc/systemd/resolved.conf` is root-owned and ships only commented defaults:

```ini
19 [Resolve]
24 #DNS=
26 #Domains=
29 #MulticastDNS=no
30 #LLMNR=no
33 #DNSStubListener=yes
```

## Attacker trigger results

The attacker has no logind session or lingering user manager:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
Failed to get user: User ID 1001 is not logged in or lingering
```

Read-only/query APIs are reachable:

```sh
runuser -u attacker -- resolvectl status
runuser -u attacker -- resolvectl query localhost
runuser -u attacker -- getent hosts localhost
```

Observed:

```text
resolvectl status: succeeded, showed global DNS server 192.168.65.7
resolvectl query localhost: returned 127.0.0.1 and ::1 from synthetic data
getent hosts localhost: returned ::1 localhost ip6-localhost ip6-loopback
```

The public varlink socket is also reachable, but its exposed IDL is query-only:

```text
Interfaces: io.systemd, io.systemd.Resolve, org.varlink.service

io.systemd.Resolve methods:
  ResolveHostname(ifindex, name, family, flags)
  ResolveAddress(ifindex, family, address, flags)
```

Attacker varlink calls:

```sh
runuser -u attacker -- varlinkctl call /run/systemd/resolve/io.systemd.Resolve \
  io.systemd.Resolve.ResolveHostname '{"ifindex":11,"name":"localhost","family":2,"flags":0}'
# {"addresses":[{"ifindex":1,"family":2,"address":[127,0,0,1]}],"name":"localhost","flags":786945}

runuser -u attacker -- varlinkctl call /run/systemd/resolve/io.systemd.Resolve \
  io.systemd.Resolve.ResolveAddress '{"ifindex":null,"family":2,"address":[1,2,3],"flags":null}'
# org.varlink.service.InvalidParameter {"parameter":"ifindex"}
```

The private monitor socket blocks the attacker:

```sh
runuser -u attacker -- varlinkctl info /run/systemd/resolve/io.systemd.Resolve.Monitor
# Failed to connect to '/run/systemd/resolve/io.systemd.Resolve.Monitor': Permission denied
```

Unauthenticated D-Bus manager calls that only reset volatile resolver state
succeeded, but did not produce a file write or privilege transition:

```sh
runuser -u attacker -- busctl --system call org.freedesktop.resolve1 \
  /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager FlushCaches
# rc=0

runuser -u attacker -- busctl --system call org.freedesktop.resolve1 \
  /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResetStatistics
# rc=0

runuser -u attacker -- busctl --system call org.freedesktop.resolve1 \
  /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResetServerFeatures
# rc=0
```

Persistent resolver mutations are denied:

```sh
runuser -u attacker -- busctl --system call org.freedesktop.resolve1 \
  /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNS 'ia(iay)' \
  2 1 2 4 8 8 8 8
# Call failed: Interactive authentication required.

runuser -u attacker -- busctl --system call org.freedesktop.resolve1 \
  /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDomains 'ia(sb)' \
  2 1 attacker.invalid false
# Call failed: Interactive authentication required.

runuser -u attacker -- busctl --system call org.freedesktop.resolve1 \
  /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager RevertLink i 2
# Call failed: Interactive authentication required.
```

The per-link object for `eth0` is reachable at
`/org/freedesktop/resolve1/link/_311`, but its mutators are also denied:

```sh
runuser -u attacker -- busctl --system call org.freedesktop.resolve1 \
  /org/freedesktop/resolve1/link/_311 org.freedesktop.resolve1.Link SetDNS 'a(iay)' \
  1 2 4 8 8 4 4
# Call failed: Interactive authentication required.

runuser -u attacker -- busctl --system call org.freedesktop.resolve1 \
  /org/freedesktop/resolve1/link/_311 org.freedesktop.resolve1.Link Revert
# Call failed: Interactive authentication required.
```

`resolvectl` confirms the same boundary:

```text
resolvectl dns eth0 8.8.8.8        -> Interactive authentication required
resolvectl domain eth0 attacker.invalid -> Interactive authentication required
resolvectl default-route eth0 false -> Interactive authentication required
resolvectl mdns eth0 yes           -> Interactive authentication required
resolvectl dnsovertls eth0 yes     -> Interactive authentication required
resolvectl dnssec eth0 yes         -> Interactive authentication required
resolvectl nta eth0 attacker.invalid -> Interactive authentication required
resolvectl revert eth0             -> Interactive authentication required
```

DNS-SD registration did not expose a default path because mDNS is disabled:

```sh
runuser -u attacker -- busctl --system call org.freedesktop.resolve1 \
  /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager RegisterService \
  'sssqqqaa{say}' attacker _http._tcp local 12345 0 0 0
# Call failed: Support for MulticastDNS is disabled

runuser -u attacker -- resolvectl mdns eth0 yes
# Failed to set MulticastDNS configuration: Interactive authentication required.
```

Diagnostic and log-control surfaces stayed read-only or monitor-gated:

```text
resolvectl statistics        -> Failed to connect to query monitoring service: Permission denied
resolvectl show-cache        -> Failed to connect to query monitoring service: Permission denied
resolvectl show-server-state -> Failed to connect to query monitoring service: Permission denied
resolvectl monitor           -> Failed to connect to query monitoring service: Permission denied
busctl get LogControl1.LogLevel -> s "info"
busctl set LogControl1.LogLevel debug -> Access denied
```

Attacker write checks:

```text
/run/systemd/resolve                         writable_rc=1
/run/systemd/resolve/resolv.conf             writable_rc=1
/run/systemd/resolve/stub-resolv.conf        writable_rc=1
/run/systemd/resolve/io.systemd.Resolve      writable_rc=0
/run/systemd/resolve/io.systemd.Resolve.Monitor writable_rc=1
/etc/resolv.conf                             writable_rc=1
/etc/systemd/resolved.conf                   writable_rc=1
/var/lib/systemd                             writable_rc=1
```

The only writable object is the public query varlink socket. It does not accept
state-changing or file-path parameters.

## Root proof status

No uid1001 -> root primitive was found. No root shell, root command execution,
root-owned attacker-controlled file write, or privileged group transition was
obtained.

The resolved daemon itself runs as `systemd-resolve`, with
`NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateDevices=yes`,
`PrivateTmp=yes`, and a restricted address-family set. Even a hypothetical
memory corruption in the query parser would start from the service account and
its service sandbox, not direct root execution in the tested default unit.

## Cleanup

No persistent probe files were created for this audit. The only successful
mutations were volatile cache/stat/server-feature resets. After testing:

```text
systemd-resolved.service active
resolv.conf mode: foreign
Global DNS server: 192.168.65.7
Link 11 (eth0): no per-link DNS/domain/default-route/mDNS/LLMNR changes
```

## Why scanners may flag this but miss the actual boundary

The D-Bus policy allows any local user to send to `org.freedesktop.resolve1`,
and `/run/systemd/resolve/io.systemd.Resolve` is mode `0666`. A static scanner
or socket-permission sweep can easily rank those as high-risk IPC. The security
boundary is semantic: the public varlink socket exposes only resolver queries,
the private monitor socket is `0600`, and persistent D-Bus state changes are
polkit-mediated at method execution time. Generic enumeration does not prove
whether the reachable methods can write files, execute helpers, or cross from
the `systemd-resolve` service account to root.

## Ubuntu Security triage recommendation

No LPE fix is indicated from this audit. Hardening-only considerations:

```text
1. Keep monitor/cache-dump APIs on the private 0600 monitor socket.
2. Keep SetLink*, Revert*, DNS-SD registration, and LogControl writes behind polkit.
3. Consider documenting that FlushCaches, ResetStatistics, and ResetServerFeatures are intentionally unprivileged volatile operations.
4. If those reset calls are considered undesirable local disruption, gate them with a low-impact polkit action; this would be defense-in-depth, not an LPE fix.
```
