# Negative: default file-capability helpers

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server image. Attacker identity was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no uid1001 -> root local privilege escalation was validated in this lane. The default capability-bearing helpers are installed and executable, but the tested paths either require snap authorization/state that is absent on stock Server, drop capabilities before attacker-controlled protocol handling, or expose only bounded raw-network operations.

Artifacts:

```text
pocs/capability_helpers_probe.sh
logs/capability-helpers.out
```

## Default package and file proof

The target is Ubuntu 24.04.4 LTS. Relevant default packages and versions:

```text
snapd                         2.74.1+ubuntu24.04.4
libgstreamer1.0-0:arm64       1.24.2-1ubuntu0.1
iputils-ping                  3:20240117-1ubuntu0.1
mtr-tiny                      0.95-1.1ubuntu0.1
ubuntu-server                 1.539.2
ubuntu-standard               1.539.2
ubuntu-minimal                1.539.2
```

Default file capabilities:

```text
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
```

The attacker starts without capabilities:

```text
Uid: 1001 1001 1001 1001
Gid: 1001 1001 1001 1001
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapAmb: 0000000000000000
```

Direct network-admin mutation fails:

```text
ip link set lo down
RTNETLINK answers: Operation not permitted
```

## snapd and snap-confine

Default snapd sockets are world-connectable:

```text
/run/snapd.socket      srw-rw-rw- root:root
/run/snapd-snap.socket srw-rw-rw- root:root
```

Read-only REST APIs work, but privileged requests are denied:

```text
GET /v2/system-info -> HTTP/1.1 200 OK
GET /v2/snaps       -> HTTP/1.1 200 OK, result []
POST /v2/snaps install hello-world -> HTTP/1.1 401 Unauthorized
POST /v2/create-user sudoer=true   -> HTTP/1.1 403 Forbidden
/run/snapd-snap.socket /v2/system-info -> HTTP/1.1 403 Forbidden
```

Writable snap state checks were negative for uid1001:

```text
/snap, /var/lib/snapd, /var/lib/snapd/snaps, /var/snap,
/run/snapd, /run/snapd/lock, /run/snapd/ns, /sys/fs/cgroup,
and /sys/fs/bpf were not writable by attacker.
```

Direct `snap-confine` execution reached the packaged capability boundary and temporarily raised capabilities inside the helper, but stopped before payload execution because the stock Server target has no installed snaps and no base snap:

```text
DEBUG: caps at startup: cap_chown,cap_dac_override,...,cap_sys_resource=p
DEBUG: after setting privileged caps: cap_chown,cap_dac_override,cap_sys_admin=eip ...
DEBUG: base snap: core
cannot locate base snap core: No such file or directory
payload.out: MISSING
fake-update-ns.out: MISSING
snap_confine_rc=1
```

Malformed security tags were rejected:

```text
snap..app                         -> security tag not allowed
snap.fakesnap/../../tmp.x         -> security tag not allowed
snap.foo..bar.app                 -> security tag not allowed
```

Running `snap-confine` inside an attacker-created user/mount namespace gave namespace-root capabilities only inside that namespace; it did not cross into initial-namespace root and failed at canonical snap directory checks:

```text
uid=0(root) gid=0(root) groups=0(root)
bind_snap_rc=0
cannot fstatat canonical snap directory: Permission denied
sc_userns_rc=1
```

## gst-ptp-helper

The helper is executable by uid1001 and initially has `cap_net_bind_service`, `cap_net_admin`, and `cap_sys_nice`. The probe showed it drops all effective/permitted capabilities before processing attacker-controlled stdin protocol frames:

```text
pid 765890
clock_frame_len 11 hex 0008020102030405060708
Uid: 1001 1001 1001 1001
Gid: 1001 1001 1001 1001
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapAmb: 0000000000000000
getpcaps: =
```

A valid PTP stdin frame produced a normal send-time ACK, proving reachability of the intended bounded protocol:

```text
ack_len 15
ack_hex 000c03000008b592a74c7301001234
```

A mismatched clock identity produced no extra privileged operation, and `LD_PRELOAD` did not load attacker code into the privileged helper path. No file descriptor passing, shell execution, arbitrary netlink/ioctl, root-owned write, or persistent network state change was observed.

## ping and mtr-packet

`ping` can send ICMP as uid1001, but the live process drops capabilities after setup:

```text
ping -c1 127.0.0.1 -> 1 received
ping -m 123 -> WARNING: failed to set mark: Operation not permitted
live ping CapPrm: 0000000000000000
live ping CapEff: 0000000000000000
getpcaps: =
```

`mtr-packet` retains `cap_net_raw=ep` while running and accepts its line protocol, but the tested commands were limited to support checks, ICMP probes, and `unknown-command` for path-like input:

```text
check-support send-probe -> support ok
check-support mark       -> support ok
send-probe 127.0.0.1     -> reply
../../etc/shadow ...     -> unknown-command
live mtr-packet CapPrm/CapEff: 0000000000002000
getpcaps: cap_net_raw=ep
```

No conversion from `cap_net_raw` to root, privileged group access, file write, or command execution was found.

## Cleanup

The probe removed its work directory and transient socket/protocol files. A copied probe script left under `/root` was removed after the worker timed out:

```sh
rm -f /root/capability_helpers_probe.sh /root/capability_helpers_* /root/gst_* /root/mtr_* /root/ping_*
rm -rf /tmp/capability-helpers-probe /tmp/snap.rootfs_ATTACK
```

Final health after cleanup:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend | wc -l -> 0
```

## Conclusion

Negative. These helpers are real default local trust boundaries, but this Docker stock Server target did not expose a root LPE through snapd REST authorization, direct `snap-confine`, `gst-ptp-helper`, `ping`, or `mtr-packet`. No root marker or `id` from an initial-namespace root context was produced.
