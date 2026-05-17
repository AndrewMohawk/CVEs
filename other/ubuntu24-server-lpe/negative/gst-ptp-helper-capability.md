# gst-ptp-helper file-capability audit: negative

## Verdict

No local privilege escalation or real privilege increase was validated against the current Docker-only Ubuntu 24.04.4 Server userspace target `ubuntu24-server-lpe-target`.

The default-installed helper is reachable by uid 1001 and does execute with file capabilities long enough to set up PTP UDP sockets, bind them to the selected interface, join multicast, and raise process priority. The privileged surface exposed to an attacker is limited to:

- command-line selection of existing PTP-capable interfaces, TTL, verbosity, and clock ID;
- a stdin/stdout protocol that can send valid PTP packets for the helper's clock ID to multicast `224.0.1.129:{319,320}`;
- receipt/forwarding of PTP packets from those sockets.

I did not find a path to retain `cap_net_admin`, execute attacker-controlled code under the helper's capabilities, pass file descriptors, perform arbitrary netlink/ioctl operations, write files, change host/container network state persistently, or convert the transient capabilities to root.

## Target/default proof

Commands were run from `/Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe`; target commands used `docker exec -u 1001 ubuntu24-server-lpe-target ...` unless noted.

```sh
id
uname -a
cat /etc/os-release
grep -E '^(Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):' /proc/self/status
```

Result:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
NoNewPrivs: 0
Seccomp: 0
```

Package/file proof:

```sh
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' libgstreamer1.0-0
dpkg -V libgstreamer1.0-0; echo dpkgV_rc=$?
sha256sum /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper
stat -c '%U %G %a %s %n' /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper
getcap -v /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper
```

Result:

```text
libgstreamer1.0-0:arm64	1.24.2-1ubuntu0.1	arm64	gstreamer1.0	1.24.2-1ubuntu0.1
dpkgV_rc=0
f723f9178d47e0476cbc092b6e07b83955e7a866d7144025e9aac4a95489546f  /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper
root root 755 526528 /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper
/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
```

Other file-capability defaults in `/usr`:

```text
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
```

Network state:

```text
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0@if59        UP             172.17.0.5/16
default via 172.17.0.1 dev eth0
172.17.0.0/16 dev eth0 proto kernel scope link src 172.17.0.5
net.ipv4.ip_unprivileged_port_start = 0
```

The starting attacker cannot perform direct `net_admin` operations:

```sh
ip link set lo multicast off 2>&1; echo ip_link_rc=$?
```

Result:

```text
RTNETLINK answers: Operation not permitted
ip_link_rc=2
```

## Source package and paths

Source package: `gstreamer1.0 1.24.2-1ubuntu0.1`.

Source retrieved without writing source trees:

```sh
curl -fsSL 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/gstreamer1.0/1.24.2-1ubuntu0.1/gstreamer1.0_1.24.2.orig.tar.xz' | tar -tJf - | rg 'libs/gst/helpers/ptp|libs/gst/net/gstptpclock.c'
curl -fsSL 'https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/gstreamer1.0/1.24.2-1ubuntu0.1/gstreamer1.0_1.24.2-1ubuntu0.1.debian.tar.xz' | tar -tJf - | rg '(rules|install|patch)'
```

Relevant source line references:

- `debian/rules:36-38`: Ubuntu Linux build sets `-Dptp-helper-permissions=capabilities`.
- `debian/libgstreamer1.0-0.install:1-3`: installs `gst-ptp-helper` into `libgstreamer1.0-0`.
- `debian/patches/CVE-2024-47606.patch:21-54`: only touches `gst/gstallocator.c`, not the PTP helper.
- `libs/gst/helpers/ptp/meson.build:66-91`: selects capabilities mode and compiles with `ptp_helper_permissions="setcap"`.
- `libs/gst/helpers/ptp/meson.build:103-122`: builds `gst-ptp-helper`, links `libcap`, and runs post-install script.
- `libs/gst/helpers/ptp/ptp_helper_post_install.sh:19-21`: runs `setcap cap_sys_nice,cap_net_bind_service,cap_net_admin+ep "$ptp_helper"`.
- `libs/gst/helpers/ptp/main.rs:11-18`: helper purpose is privileged PTP socket setup and stdin/stdout forwarding.
- `libs/gst/helpers/ptp/main.rs:119-160`: parse args, list interfaces, bind sockets, join multicast, derive clock ID, set priority, then drop privileges.
- `libs/gst/helpers/ptp/main.rs:163-178`: initial stdout frame is clock ID.
- `libs/gst/helpers/ptp/main.rs:294-363`: stdin frame parser and only send operation.
- `libs/gst/helpers/ptp/main.rs:416-421`: top-level errors are logged; process exits with status 0.
- `libs/gst/helpers/ptp/privileges.rs:75-83` and `230-244`: capabilities mode clears all process capabilities with `cap_clear`/`cap_set_proc`.
- `libs/gst/helpers/ptp/thread.rs:20-30`: `cap_sys_nice` is used only for `setpriority(PRIO_PROCESS, 0, -5)`.
- `libs/gst/helpers/ptp/net.rs:269-368`: creates UDP socket, sets reuse/bind-to-interface options, binds to requested PTP port.
- `libs/gst/helpers/ptp/net.rs:371-445`: joins multicast and sets multicast interface.
- `libs/gst/helpers/ptp/net.rs:539-643`: Linux `SO_REUSEADDR`, `SO_REUSEPORT`, `SO_BINDTOIFINDEX`, fallback `SO_BINDTODEVICE`.
- `libs/gst/helpers/ptp/io.rs:231-337`: poll only PTP sockets plus stdin.
- `libs/gst/helpers/ptp/io.rs:340-459`: Unix stdio wrappers use raw `read(0,...)`, `write(1,...)`, `write(2,...)`.
- `libs/gst/helpers/ptp/parse.rs:141-172`: PTP parser rejects messages shorter than 34 bytes, non-v2 PTP, and inconsistent PTP message lengths.
- `libs/gst/helpers/ptp/parse.rs:188-304`: only parses known PTP payload variants; unknown PTP message types become `Other`.
- `libs/gst/helpers/ptp/rand.rs:199-223`: clock ID fallback uses `getrandom`, hardcoded `/dev/urandom`, then PID/time fallback.
- `libs/gst/net/gstptpclock.c:240-249`: documents stdio message types and 3-byte stdout/stdin header.
- `libs/gst/net/gstptpclock.c:1081-1118`: normal GStreamer parent sends only a DELAY_REQ frame to helper stdin.
- `libs/gst/net/gstptpclock.c:2058-2190`: parent reads helper stdout and rejects stdout body sizes over 8192.
- `libs/gst/net/gstptpclock.c:2772-2860`: parent may choose helper path from `GST_PTP_HELPER_1_0`/`GST_PTP_HELPER`, then starts child with stdin/stdout/stderr pipes only.

## Protocol audit

Protocol constants from source:

- frame header is `u16be payload_size` + `u8 type`;
- type `0` = event socket PTP frame;
- type `1` = general socket PTP frame;
- type `2` = clock ID;
- type `3` = send-time ACK.

Helper-to-parent clock-ID frame on deterministic clock ID:

```sh
python3 - <<'PY'
import subprocess
p = '/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper'
r = subprocess.run([p, '-i', 'eth0', '--clock-id', '0x0102030405060708'],
                   input=b'', stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
print('rc', r.returncode)
print('stdout_len', len(r.stdout), 'stdout_hex', r.stdout.hex())
PY
```

Result:

```text
rc 0
stdout_len 11 stdout_hex 0008020102030405060708
stderr includes: Exited with error: Failed polling / Hang up during polling on stdin
```

Capability state after setup/drop, while helper remains alive:

```text
pid 9965 clock_pkt_hex 0008020102030405060708
Uid: 1001 1001 1001 1001
Gid: 1001 1001 1001 1001
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
NoNewPrivs: 0
Seccomp: 0
getpcaps 9965: =
```

Valid event-socket stdin frame with matching clock ID:

```text
input_len 56 body_len 53 ptp_len 44
clock_pkt_len 11 clock_pkt_hex 0008020102030405060708
ack_len 15 ack_hex 000c030001101c3bb260ae01001234
ack_decoded {'size': 12, 'type': 3, 'send_time_nonzero': True, 'msg_type': 1, 'domain': 0, 'seq': '0x1234'}
```

This proves the attacker can cause the helper to send a syntactically valid PTP DELAY_REQ to the event multicast socket after setup. It is not arbitrary networking: destination is fixed in source to `224.0.1.129:319` for event and `224.0.1.129:320` for general.

Mismatched clock ID is rejected before send:

```text
clock_pkt_hex 0008020102030405060708
rc 0
extra_stdout_len 0 extra_stdout_hex
stderr_has_unexpected_clock True
Exited with error: PTP message with unexpected clock identity on stdin
```

Oversized stdin body length is rejected before body read:

```text
clock_pkt_hex 0008020102030405060708
rc 0
extra_stdout_len 0 extra_stdout_hex
stderr_has_invalid_size True
Exited with error: Invalid packet size on stdin 65535
```

Unknown stdin message type is ignored, not dispatched:

```text
clock_pkt_hex 0008020102030405060708
rc -9
extra_stdout_len 0 extra_stdout_hex
stderr_has_unexpected_type True
Unexpected stdin message type 2
```

## Trust-boundary findings

### File descriptor passing

No file descriptor passing path was found.

Source grep over `libs/gst/helpers/ptp/*.rs` for `recvmsg|sendmsg|SCM_|CMSG|ancill|RawFd|FromRawFd|Command|exec|spawn|open|File|env::|var(|PATH|HOME|GST_|cap_|setuid|setgid|setpriority|socket|setsockopt|ioctl|bind(|read(|write(` found:

- Unix helper stdio uses `read`/`write` wrappers around fd 0/1/2 in `io.rs:340-459`.
- UDP sockets are created internally from raw fds in `net.rs:269-368`.
- No `recvmsg`, `sendmsg`, `SCM_RIGHTS`, `CMSG`, subprocess, shell, or command execution in the helper.
- The GStreamer parent starts the helper with `G_SUBPROCESS_FLAGS_STDIN_PIPE | STDOUT_PIPE | STDERR_PIPE` only (`gstptpclock.c:2857-2860`).

### Length handling

The stdin length field is attacker-controlled but bounded:

- `main.rs:301-304`: rejects `size > stdinout_buffer.len()`; buffer is `8192 + 4 + 8` at `main.rs:184-185`.
- `main.rs:316-318`: rejects body shorter than `1 + 8 + 34`.
- `parse.rs:141-172`: rejects too-short PTP messages, unsupported PTP version, and internal PTP length larger than available bytes.
- `gstptpclock.c:2181-2184`: parent rejects helper stdout bodies larger than 8192.

No unchecked length led to retained capabilities, root, write primitive, or privileged operation beyond the intended PTP send.

### Command variants and privileged operations

Attacker-controlled command-line variants:

- `-i/--interface`: filters to an existing interface name, alternate name, or IPv4 address (`args.rs:43-46`, `main.rs:85-114`).
- `-c/--clock-id`: sets deterministic helper clock ID (`args.rs:47-54`).
- `--ttl`: sets unicast/multicast TTL (`args.rs:55-58`, `main.rs:65-73`).
- `-v/--verbose`: changes logging only.

Privileged operations performed before drop:

- socket bind to UDP ports 319/320;
- `SO_BINDTOIFINDEX` or fallback `SO_BINDTODEVICE`;
- multicast membership/interface setup;
- `setpriority(..., -5)`.

Those operations are fixed to PTP socket setup. I found no command variant for routes, addresses, qdisc, nftables, sysctls, namespaces, module loading, arbitrary netlink writes, file writes, or process execution.

### Env/config/path use

The installed helper itself reads command-line arguments via `env::args()` (`args.rs:34-38`). It does not read `PATH`, `HOME`, `GST_*`, config files, plugin paths, or attacker-provided helper paths after acquiring capabilities.

Live env scrub test:

```sh
env -i PATH=/tmp HOME=/tmp GST_DEBUG=9 RUST_BACKTRACE=1 \
  /usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper \
  -i eth0 --clock-id 0x0102030405060708 </dev/null
```

Result after cleanup of temporary redirected files:

```text
rc=0
stdout bytes=11
stderr bytes=1881
stdout first bytes: 00 08 02 01 02 03 04 05 06 07 08
```

The GStreamer library side can use `GST_PTP_HELPER_1_0` or `GST_PTP_HELPER` to choose a helper path (`gstptpclock.c:2772-2780`), but that occurs in the unprivileged parent process. Pointing it at an attacker-owned executable would execute that executable without the installed file capabilities. It is not a default uid1001-to-root/capability path.

### Capability retention / root conversion

The critical live proof is the running helper after setup:

```text
Uid/Gid: 1001
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapAmb: 0000000000000000
getpcaps: =
```

That aligns with `privileges.rs:75-83`, which clears all process capabilities before the protocol loop. Since the stdin protocol starts after the drop (`main.rs:157-161`), attacker-controlled protocol data is handled without `cap_net_admin`, `cap_net_bind_service`, or `cap_sys_nice`.

Within this Docker-only target, low UDP ports are also not a useful privilege boundary because `net.ipv4.ip_unprivileged_port_start = 0`; the meaningful capability is `cap_net_admin`, and I found no path to retain or repurpose it.

## Cleanup

Cleanup/leftover check:

```sh
pgrep -a gst-ptp-helper || true
ss -lunp | grep -E ':(319|320)\b' || true
find /tmp -maxdepth 1 -name 'gst-env-test.*' -print -delete
```

Result: no output. No helper process, PTP listener, or temporary `gst-env-test.*` file remained.

Only this report file was written under the workspace.
