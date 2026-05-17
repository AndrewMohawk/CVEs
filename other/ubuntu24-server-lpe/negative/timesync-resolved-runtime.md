# timesync/resolved runtime API negative result

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server default container.  
Attacker: normal local user `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, no sudo/admin groups.  
Verdict: no uid1001 -> root LPE found through `org.freedesktop.timesync1`, `org.freedesktop.resolve1`, `/run/systemd/resolve` varlink sockets, or fixed systemd unit transitions.

Evidence log and repeatable probe:

```sh
./pocs/timesync_resolved_runtime_probe.sh ubuntu24-server-lpe-target
# writes logs/timesync-resolved-runtime.out
```

## Package, service, and reachability proof

Observed target identity:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
Linux 4f5b414436ae 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64
systemd 255 (255.4-1ubuntu8.15)
dbus              1.14.10-4ubuntu4.1
polkitd           124-2ubuntu1.24.04.3
systemd           255.4-1ubuntu8.15
systemd-resolved  255.4-1ubuntu8.15
systemd-timesyncd 255.4-1ubuntu8.15
uid=991(systemd-resolve) gid=991(systemd-resolve)
uid=996(systemd-timesync) gid=996(systemd-timesync)
```

Default unit state in the Docker target:

```text
systemd-resolved.service: enabled, active/running
  MainPID=771164
  User=systemd-resolve
  BusName=org.freedesktop.resolve1
  RuntimeDirectory=systemd/resolve
  ProtectSystem=strict
  NoNewPrivileges=yes
  CapabilityBoundingSet=cap_setpcap cap_net_bind_service cap_net_raw

systemd-timesyncd.service: enabled, inactive/dead
  User=systemd-timesync
  BusName=org.freedesktop.timesync1
  ConditionResult=no
  ConditionVirtualization=!container
  CapabilityBoundingSet=cap_sys_time
```

Reachable IPC:

```text
org.freedesktop.resolve1      systemd-resolve systemd-resolved.service
org.freedesktop.timesync1     (activatable)

/run/systemd/resolve/io.systemd.Resolve         srw-rw-rw- systemd-resolve:systemd-resolve
/run/systemd/resolve/io.systemd.Resolve.Monitor srw------- systemd-resolve:systemd-resolve
/run/systemd/resolve/resolv.conf                -rw-r--r-- systemd-resolve:systemd-resolve
/run/systemd/resolve/stub-resolv.conf           -rw-r--r-- systemd-resolve:systemd-resolve

DNS listeners:
127.0.0.53%lo:53 tcp/udp
127.0.0.54:53 tcp/udp
```

The timesync D-Bus policy allows only `SetRuntimeNTPServers` from default users, but the polkit action is `auth_admin/auth_admin/auth_admin_keep`. The resolved D-Bus policy allows sends to `org.freedesktop.resolve1`, but mutating link/DNS operations are gated by `org.freedesktop.resolve1.*` polkit actions with `auth_admin` defaults.

## Attacker D-Bus results

Read/query/cache APIs reachable by uid1001:

```text
get-property Manager DNS                                      rc=0
FlushCaches                                                   rc=0
ResetStatistics                                               rc=0
ResetServerFeatures                                           rc=0
ResolveHostname(0, "localhost", AF_INET, 0)                   rc=0 -> 127.0.0.1
```

Runtime DNS/link mutators were denied:

```text
SetLinkDNS                          Call failed: Interactive authentication required.
SetLinkDNSEx                        Call failed: Interactive authentication required.
SetLinkDomains                      Call failed: Interactive authentication required.
SetLinkDefaultRoute                 Call failed: Interactive authentication required.
SetLinkLLMNR                        Call failed: Interactive authentication required.
SetLinkMulticastDNS                 Call failed: Interactive authentication required.
SetLinkDNSOverTLS                   Call failed: Interactive authentication required.
SetLinkDNSSEC                       Call failed: Interactive authentication required.
SetLinkDNSSECNegativeTrustAnchors   Call failed: Interactive authentication required.
RevertLink                          Call failed: Interactive authentication required.
RegisterService                     Call failed: Support for MulticastDNS is disabled
```

`SetRuntimeNTPServers` did not reach a running daemon in this default container:

```text
busctl ... org.freedesktop.timesync1.Manager SetRuntimeNTPServers as 2 \
  127.0.0.1 'attacker.invalid;touch /root/timesync_resolved_runtime_lpe'

Call failed: Failed to activate service 'org.freedesktop.timesync1': timed out (service_start_timeout=25000ms)
```

No root-owned runtime config write or helper execution occurred.

## Varlink results

The public resolved varlink socket is reachable, but its IDL is query-only:

```text
Interfaces: io.systemd, io.systemd.Resolve, org.varlink.service

method ResolveHostname(ifindex: ?int, name: string, family: ?int, flags: ?int)
method ResolveAddress(ifindex: ?int, family: int, address: []int, flags: ?int)
```

Attacker calls:

```text
ResolveHostname localhost                         rc=0 -> 127.0.0.1
ResolveAddress 127.0.0.1                          rc=0 -> localhost
SetLinkDNS on public varlink socket               org.varlink.service.MethodNotFound
Monitor socket info                               Permission denied
```

There is no varlink method for DNS/link mutation, path injection, environment injection, or unit execution on the public socket.

## Service-account and fixed-unit transition checks

Non-mutating writability checks were run as `attacker`, `systemd-resolve`, and `systemd-timesync` against root-consumed runtime/config paths:

```text
attacker:
  /run/systemd/system, /run/systemd/generator*, /run/credentials*,
  /etc/systemd/system, /etc/systemd/*.conf.d, /etc/systemd/*.conf,
  /run/systemd/resolve/*                                  all rc=1

systemd-resolve:
  /run/systemd/resolve                                    rc=0
  /run/systemd/resolve/resolv.conf                        rc=0
  /run/systemd/resolve/stub-resolv.conf                   rc=0
  /run/systemd/system, /run/systemd/generator*, /run/credentials*,
  /etc/systemd/system, /etc/systemd/*.conf.d, /etc/systemd/*.conf  all rc=1

systemd-timesync:
  /run/systemd/system, /run/systemd/generator*, /run/credentials*,
  /run/systemd/resolve, /run/systemd/timesync,
  /etc/systemd/system, /etc/systemd/*.conf.d, /etc/systemd/*.conf  all rc=1
```

`systemd-resolve` can write its own service-owned runtime resolver files, but those are not root-owned and are not fixed systemd unit input. Neither service account can write root unit paths, generator paths, credential directories, D-Bus activation directories, or `/etc/systemd` configuration.

Attacker attempts to trigger fixed root units or a transient root command all failed at polkit:

```text
systemctl start systemd-resolved.service                  Interactive authentication required
systemctl start systemd-timesyncd.service                 Interactive authentication required
systemctl start dbus-org.freedesktop.resolve1.service     Interactive authentication required
systemctl start dbus-org.freedesktop.timesync1.service    Interactive authentication required
systemd-run --unit timesync-resolved-runtime-lpe ...      Interactive authentication required
```

## State and cleanup

Before/after hashes matched for persistent root-owned config and resolved runtime files:

```text
/etc/systemd/timesyncd.conf
  e6734751f8aaf19fddfff891ad246387f5f59bd9ff1a5f0cac2c34bc81941c62
/etc/systemd/resolved.conf
  bccfe8136332d623efa0745c5799c54d71868ba7fe392d4677b4587038c03ae7
/run/systemd/resolve/resolv.conf
  37c0dfed66126bf4cfa08d2b086c1991cddd7c7efea2e45794998bc6d249fd8b
/run/systemd/resolve/stub-resolv.conf
  ebdf560272a77357195c39e98340b77e18c8a8ce2025ee950e9e0c7b01467ab8
```

Root proof markers were absent:

```text
no root marker at /root/timesync_resolved_runtime_lpe
no tmp marker at /tmp/timesync_resolved_runtime_lpe
```

The probe cleanup removed `/tmp/timesync-resolved-runtime-*`, `/tmp/systemd-lpe.service.d`, `/tmp/resolved-lpe-dropin.conf`, reset failed timesync units, and left the target with `systemctl is-system-running` reporting `running`.
