# Negative: systemd initctl legacy FIFO

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server Docker target  
Result: no validated uid1001-to-root LPE. `ROOT_PROOF=no`.

## Default proof

Packages:

```text
systemd       255.4-1ubuntu8.15
systemd-sysv 255.4-1ubuntu8.15
util-linux    2.39.3-9ubuntu6.5
```

The compatibility FIFO is present and active by default:

```text
/usr/lib/systemd/system/systemd-initctl.socket:
ListenFIFO=/run/initctl
Symlinks=/dev/initctl
SocketMode=0600

/usr/lib/systemd/system/systemd-initctl.service:
ExecStart=/usr/lib/systemd/systemd-initctl
NoNewPrivileges=yes
```

Live mode:

```text
prw------- 600 root:root fifo /run/initctl
prw------- 600 root:root fifo /dev/initctl
systemd-initctl.socket active (listening)
systemd-initctl.service inactive (socket-activated)
```

## Trigger attempts

As `attacker`:

```sh
printf x > /run/initctl
printf x > /dev/initctl
telinit q
telinit u
telinit 3
systemctl daemon-reload
systemctl isolate multi-user.target
```

Observed:

```text
write /run/initctl -> Permission denied
write /dev/initctl -> Permission denied
telinit q -> kill() failed: Operation not permitted
telinit u -> kill() failed: Operation not permitted
telinit 3 -> Failed to open /run/initctl: Permission denied
systemctl daemon-reload -> Interactive authentication required.
systemctl isolate multi-user.target -> Interactive authentication required.
```

Raw legacy request payloads shaped like initctl messages also failed before
parser reachability:

```text
bash: line 1: /run/initctl: Permission denied
rc 1
```

## Conclusion

The root parser/control plane exists by default, but the FIFO is `0600
root:root`, `/dev/initctl` is only a root-owned symlink to it, and `telinit`
is just the unprivileged `systemctl` compatibility frontend. uid1001 cannot
write legacy init requests, signal PID 1 through `telinit q/u`, reload the
manager, or isolate targets. No root-owned attacker-controlled write or root
command execution was reached.

## Cleanup

The probe created only temporary `/tmp/systemd-initctl-legacy-*.bin` payload
files and removed them. It reset failed state for `systemd-initctl.socket` and
`systemd-initctl.service`; final health was `systemctl is-system-running ->
running` and no failed units.

## Why scanners may miss it

Static unit/socket listings show a root compatibility daemon that accepts
binary init control messages and can translate them into PID1 operations. The
live exploitability boundary is the socket unit's `SocketMode=0600`, which
blocks a normal local user before the parser or runlevel semantics are
reachable.
