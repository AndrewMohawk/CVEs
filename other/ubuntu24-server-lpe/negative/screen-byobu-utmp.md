# Negative: screen/byobu/tmux/libutempter terminal accounting

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default state. Scope was normal local users `attacker` uid1001 and `selfauth` uid1002, each only in its own primary group.

Result: no validated uid1001/uid1002-to-root LPE. The only elevated helper in this lane is the stock setgid `utmp` libutempter helper. It can update terminal accounting records for the caller's real pty, but the tested host/session-name/path-control cases did not produce root execution, root-owned attacker-controlled writes, or a root/group privilege increase.

Probe/log:

```text
pocs/screen_byobu_utmp_probe.sh
logs/screen-byobu-utmp.out
```

## Default proof

Relevant packages:

```text
bsdextrautils             2.39.3-9ubuntu6.5
byobu                     6.11-0ubuntu1
libutempter0:arm64        1.2.1-3build1
login                     1:4.13+dfsg1-4ubuntu3.2
passwd                    1:4.13+dfsg1-4ubuntu3.2
screen                    4.9.1-1ubuntu1
tmux                      3.4-1ubuntu0.1
util-linux                2.39.3-9ubuntu6.5
```

Relevant file modes:

```text
/usr/bin/screen                                      0755 root:root
/usr/bin/byobu                                       0755 root:root
/usr/bin/byobu-screen                                0755 root:root
/usr/bin/byobu-tmux                                  0755 root:root
/usr/bin/tmux                                        0755 root:root
/usr/bin/write                                       0755 root:root
/usr/bin/wall                                        0755 root:root
/usr/bin/login                                       0755 root:root
/usr/lib/aarch64-linux-gnu/utempter/utempter         2755 root:utmp
/run/utmp                                            0664 root:utmp
/var/log/wtmp                                        0664 root:utmp
/var/log/btmp                                        0660 root:utmp
/var/log/lastlog                                     0664 root:utmp
```

`screen` and `tmux` link `libutempter.so.0`, so they are default-installed, locally reachable, and able to ask the setgid helper to record terminal sessions.

## Trigger attempts

The probe exercised:

```text
direct libutempter add/remove records for attacker ptys
host strings with spaces, path-like text, newline bytes, and control bytes
direct utempter helper stdin/path attempts
screen -S normal and hostile names
byobu-screen and byobu-tmux session creation
tmux session creation
active selfauth pty plus write/wall semantics
explicit write target ../tmp/.../root_canary
direct attacker run-parts /etc/update-motd.d execution
```

Observed behavior:

```text
plain host:       who shows attacker pts/0 (... sbu-host)
space host:       who shows attacker pts/0 (... sbu host with space)
path-like host:   who shows attacker pts/0 (... ../tmp/sbu-root-canary)
newline host:     add_rc=0, no who row
control host:     add_rc=0, no who row
screen normal:    who row uses real pts and screen-generated host
screen weird:     rejected as "Cannot identify account 'scr..path'"
tmux/byobu:       who rows use real pts and tmux/screen host strings
```

The path-like data landed only in the `ut_host` field. It did not become `ut_line`, a filesystem path, a root-open target, or a command.

The write/wall checks stayed unprivileged:

```text
/usr/bin/write and /usr/bin/wall are 0755 root:root
write selfauth pts: effective gid does not match group of /dev/pts/0
write ../tmp/.../root_canary: "selfauth is not logged in on ../tmp/..."
wall: rc=0, broadcast only
```

The root-owned canary was unchanged:

```text
17aaa243ca00dd62f68c70966e185144b92d3917b990e467e95bd4d3d8955cd8  /tmp/screen_byobu_utmp_probe/root_canary
-rw-r--r-- 644 root:root /tmp/screen_byobu_utmp_probe/root_canary
ROOT_CANARY_BASELINE
```

Running MOTD scripts directly as uid1001 printed normal MOTD data and stayed unprivileged.

## Cleanup

The probe saved hashes of `/run/utmp`, `/var/log/wtmp`, `/var/log/btmp`, and `/var/log/lastlog`, then restored the files from pre-test copies. Final hashes matched the pre-test values:

```text
/run/utmp      restored to ecf30a214fbbda9ebdca87b1cf26a16588a3f02bbef46f8190710b167d498f73
/var/log/wtmp  restored to 9cb8f8621d8ebb43653ef4dfed34e18cb5eb5ba573879aa54a856b5cf1c3f96b
/var/log/btmp  restored to 47c668c9337ea8930495510380e4cb4b712bc4240ed2bcb578eb404d5c8da351
/var/log/lastlog restored to e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
restored=1
```

No screen/byobu/tmux probe processes remained, and the target system state stayed `running` with zero failed units.

## Verdict

Negative. This surface has a real privileged boundary, but it is limited to structured terminal accounting updates through the setgid `utmp` helper. The helper records real pty lines, rejects newline/control host bytes, and path-like host strings remain display data. No default root consumer interpreted the accounting fields as commands or paths, and the `write`/`wall` tools are not setgid tty in this install.

## Why scanners may miss it

A mode scanner will flag setgid `utmp` and linked terminal multiplexers, but exploitability depends on the exact `ut_line` versus `ut_host` semantics, tty ownership, `write` group behavior, and downstream consumers of utmp/wtmp records. Those trust-boundary semantics are not visible from file modes alone.
