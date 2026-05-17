# Negative: residual privileged helper parser/trust-boundary review

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS, stock Server userspace. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)` with no `sudo`, `docker`, `lxd`, `adm`, `_ssh`, or `utmp` membership.

Result: no uid1001-to-root local privilege escalation was validated. No root proof, root-owned attacker-selected file write, retained privileged exec, namespace crossing into initial-namespace root, or helper-created symlink/race primitive was produced.

Artifacts:

```text
pocs/residual_helper_parser_probe.sh
logs/residual-helper-parser.out
```

## Default proof

Relevant default packages in the target:

```text
fuse3                         3.14.0-5build1
libgstreamer1.0-0:arm64       1.24.2-1ubuntu0.1
libmount1:arm64               2.39.3-9ubuntu6.5
libutempter0:arm64            1.2.1-3build1
mtr-tiny                      0.95-1.1ubuntu0.1
openssh-client                1:9.6p1-3ubuntu13.16
util-linux                    2.39.3-9ubuntu6.5
```

Relevant helper modes and capabilities:

```text
/usr/bin/mtr-packet                                      0755 root:root cap_net_raw=ep
/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper
                                                         0755 root:root cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
/usr/bin/ssh-agent                                      2755 root:_ssh
/usr/lib/aarch64-linux-gnu/utempter/utempter            2755 root:utmp
/usr/bin/fusermount3                                    4755 root:root
/usr/bin/mount                                          4755 root:root
/usr/bin/umount                                         4755 root:root
```

`dpkg -V` reported missing documentation/manpage files only; the reviewed helper binaries, configs, modes, and capabilities were present.

## Source review highlights

The probe downloaded exact Ubuntu source tarballs into a temporary target directory and grepped the relevant parser and privilege-boundary files:

- `mtr` `cmdparse.c` tokenizes into bounded arrays and `command.c` dispatches only `check-support` and `send-probe`; unknown/path-like command names return `unknown-command` or `invalid-argument`.
- `gst-ptp-helper` binds sockets and joins multicast before `privileges::drop()`. Source shows `cap_clear`/`cap_set_proc`, and stdin handling starts after the drop.
- `ssh-agent` calls `setegid(getgid())` and `setgid(getgid())` at startup before normal command/helper paths.
- `utempter` derives the terminal from `ptsname(STDIN_FILENO)`, checks ownership against `getuid()`, validates hostname printability, and writes only fixed utmp/wtmp records.
- `fusermount3` reads only fixed `/etc/fuse.conf`, rejects `allow_other` without `user_allow_other`, uses dropped fsuid checks around mountpoints, pins file mountpoints through `/proc/self/fd`, and uses `UMOUNT_NOFOLLOW` on unmount.
- `mount`/`umount` sanitize setuid env, drop permissions before helper exec and restricted mkdir paths, and fail namespace switching for the non-root caller.

## Live probe results

`mtr-packet` retained only `cap_net_raw=ep`. Its line protocol accepted support checks and ICMP probes, rejected a path-like `../../etc/shadow` address as `invalid-argument`, rejected `/bin/sh -c id` as `unknown-command`, and did not create/read an attacker env config marker.

`gst-ptp-helper` produced a valid PTP clock frame and ACK, proving protocol reachability. While alive after socket setup, it had `CapPrm=0` and `CapEff=0`. Bad interface and bad clock-id argv values only produced parser errors; hostile `GST_*`/`LD_PRELOAD` env did not produce attacker file writes or retained-capability execution.

`ssh-agent` command mode, PKCS#11 helper execution, and socket creation stayed uid/gid 1001 with no capabilities. The daemon process retained saved gid `_ssh` in `/proc`, but effective gid and filesystem-visible socket ownership stayed attacker-owned. A symlink listener path to `/root/residual-helper-parser-agent-target` failed without creating the root target.

`utempter` direct non-PTY execution failed. PTY-driven add/remove calls produced bounded `who` rows for printable host strings and no stale active `residual-helper` record. The root-side probe restored `/run/utmp` and `/var/log/wtmp` afterward.

`fusermount3` mounted a normal FUSE mount only as `rw,nosuid,nodev,...,user_id=1001,group_id=1001`; `allow_other` was denied by default config; a symlink mountpoint to a missing `/root` path was rejected; a swap-race loop produced zero successful mounts and no `/root/residual-helper-parser-fuse-race-target`.

`mount`/`umount` edge tests stayed bounded. `mount -t fuse.rhphelper` executed the attacker helper as uid/gid 1001 with `CapEff=0`. Attacker `-T` fstab and `--mkdir` paths created only attacker-owned `/tmp` directories before mount failure. `/root/...` mkdir was denied. `mount -N /proc/1/ns/mnt` and `umount -N /proc/1/ns/mnt` failed with permission denied. An unprivileged user namespace could mount tmpfs as namespace-root, but the mount and root-owned file were not visible outside that namespace.

## Cleanup

The probe unmounted transient FUSE/tmpfs mounts, killed matching attacker helper processes, restored `utmp`/`wtmp`, removed `/tmp` and `/home/attacker` probe state, checked absence of all root marker paths, and reset a transient failed `user@1002.service` state. Final target health was:

```text
systemctl is-system-running -> running
no residual-helper paths under /tmp or /home/attacker
no residual-helper who records
```

## Conclusion

Negative. The named residual helpers remain real default privileged boundaries, but this source-level and live parser pass found only bounded raw-network, accounting, FUSE, and setuid-mount behavior. No stock-default local root LPE was validated.

ROOT_PROOF: no
