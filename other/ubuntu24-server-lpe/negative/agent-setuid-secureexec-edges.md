# Negative: agent setuid secure-exec and helper-edge recheck

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, stock Ubuntu 24.04.4 Server on `aarch64`.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, no sudo or helper groups, no starting capabilities.

Artifacts:

```text
pocs/agent_setuid_secureexec_edges_probe.sh
logs/agent_setuid_secureexec_edges.out
```

Result: negative. No `uid1001 -> root` LPE was validated. No root marker was created, and account/accounting hashes matched before and after the probe.

## Scope

This was a focused recheck of the setuid/setgid/file-capability lane after reading the existing negatives. It did not repeat a broad helper sweep. The probe targeted the remaining easy-to-miss trust boundaries:

- privileged dynamic-loader and locale/env path handling;
- attacker-controlled helper execution through `mount`, `crontab`, `sudo`, `ssh-agent`, and `newgrp`;
- symlink/hardlink edges around root paths;
- the retained `cap_net_raw` parser boundary in `mtr-packet`.

The target was current at run time:

```text
apt-get -s full-upgrade: 0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
```

Representative package versions:

```text
dbus                    1.14.10-4ubuntu4.1
fuse3                   3.14.0-5build1
iputils-ping            3:20240117-1ubuntu0.1
libgstreamer1.0-0:arm64 1.24.2-1ubuntu0.1
libutempter0:arm64      1.2.1-3build1
login                   1:4.13+dfsg1-4ubuntu3.2
mount                   2.39.3-9ubuntu6.5
mtr-tiny                0.95-1.1ubuntu0.1
openssh-client          1:9.6p1-3ubuntu13.16
passwd                  1:4.13+dfsg1-4ubuntu3.2
polkitd                 124-2ubuntu1.24.04.3
sudo                    1.9.15p5-3ubuntu5.24.04.2
ubuntu-server           1.539.2
util-linux              2.39.3-9ubuntu6.5
```

Default capability-bearing files in scope:

```text
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
```

## Secure-exec environment paths

Root-side `strace` ran representative helpers as `attacker` with hostile environment:

```text
LD_PRELOAD=/home/attacker/agent_setuid_secureexec_edges/libagent.so
LD_AUDIT=/home/attacker/agent_setuid_secureexec_edges/audit.so
GCONV_PATH=/home/attacker/agent_setuid_secureexec_edges/gconv
LOCPATH=/home/attacker/agent_setuid_secureexec_edges/locale
NLSPATH=/home/attacker/agent_setuid_secureexec_edges/nls/%N
BASH_ENV=/home/attacker/agent_setuid_secureexec_edges/bashenv
ENV=/home/attacker/agent_setuid_secureexec_edges/shenv
TMPDIR=/home/attacker/agent_setuid_secureexec_edges/tmp
PATH=/home/attacker/agent_setuid_secureexec_edges/bin:...
```

No trace showed a privileged open/exec of those attacker-controlled paths after the target helper `execve()`.

Observed representative privilege boundaries:

```text
ping -V:
  capset(... permitted=CAP_NET_RAW ...)
  setuid(1001)

gst-ptp-helper -i eth0:
  capset(... effective=0, permitted=0, inheritable=0)

chage -l attacker:
  setregid(1001, 1001)
  setreuid(1001, 1001)

ssh-keysign:
  setresgid(1001, 1001, 1001)
  setresuid(1001, 1001, 1001)
```

Dead end: hostile dynamic-loader, locale, shell-startup, temp, and `PATH` environment variables did not become root-controlled file loads or helper execution.

## Attacker-controlled helper execution

The probe installed one attacker-owned helper under `/home/attacker/agent_setuid_secureexec_edges/bin` and routed these paths to it:

```text
mount.fuse.agentedge
mount.agentedge
agentedge
editor
askpass
pkcs11-helper
shell
```

The following helper dispatch paths were reached:

```text
mount -t fuse.agentedge
crontab -e with VISUAL/EDITOR
sudo -A with SUDO_ASKPASS
ssh-agent + ssh-add with SSH_PKCS11_HELPER
newgrp attacker with SHELL
```

Every attacker helper ran only as the attacker with no effective capabilities:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapAmb: 0000000000000000
```

The root marker check stayed negative:

```text
helper_root_marker_rc=1
```

Dead end: these helper-exec surfaces are real, but privilege is dropped before attacker-controlled code runs.

## Symlink and hardlink edges

Symlink and root-path probes stayed bounded:

```text
ssh-agent -a /home/attacker/.../agent.sock where agent.sock -> /root/agent_setuid_secureexec_edges_socket
  unix_listener: cannot bind to path ... Address already in use
  root_socket_exists_rc=1

mount --mkdir /tmp/agent_setuid_secureexec_edges/src /root/agent_setuid_secureexec_edges_mount
  mount: ... operation permitted for root only.
  root_mount_exists_rc=1

fusermount3 -u symlink-to-/
  entry ... not found in /etc/mtab

ln /etc/shadow /home/attacker/.../shadow.hardlink
  Operation not permitted

ln /usr/bin/sudo /home/attacker/.../sudo.hardlink
  Operation not permitted
```

Dead end: no root-owned attacker-selected socket, mountpoint, hardlink, or symlink-follow write was produced.

## mtr-packet

`mtr-packet` remains the only tested helper in this recheck that keeps a non-root privilege while processing attacker protocol input:

```text
Uid: 1001 1001 1001 1001
Gid: 1001 1001 1001 1001
CapPrm: 0000000000002000
CapEff: 0000000000002000
getpcaps: cap_net_raw=ep
```

The tested line protocol inputs produced bounded parser responses:

```text
1 feature-support support ok
2 feature-support support ok
3 reply ip-4 127.0.0.1 round-trip-time 53
4 unknown-command
5 invalid-argument
```

Surviving candidate: `mtr-packet` is still a privilege-bearing parser worth keeping on the radar for memory corruption or arbitrary raw-packet side effects, but this pass did not produce root, file write, command execution, or a broader capability gain.

## Integrity

Sensitive hashes matched before and after:

```text
/etc/passwd  e1468fa4ad17e48937e0fe2d6f1c64ea1d8477c339287f68bd3fc54aa9729ee0
/etc/shadow  0f8fc7e1080707f5ab9951b14262ed4d862f5e7fb0a2ae8168a0cc16ab9f9fb7
/etc/group   6f9dbca3bed6a13aa64baadf58ccdccf3d6f18eac2bf8e6e6dd3ea08634ae5be
/etc/gshadow 3470f908cc636edf0f69d37ed04b7947031ad0487977ec3973f0d8d64d3461c3
/run/utmp    698e7c69cd5e5745e25dcf31b2c08a85950c0e2a1f9924384ef159966d4568c5
/var/log/wtmp 726e3b15b40a39e40cf9e0232f871b5dde266ad6c49e7f57ae6e3ad3b4d2078d
/var/log/btmp e88ffb31f27ecc80b2aae77fa7855ab0def528a63f6b3c96773af654beb1847c
```

Conclusion: no valid LPE in this secure-exec/helper-edge slice. `ROOT_PROOF=NO`.
