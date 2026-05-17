# Negative: systemd-tmpfiles public directory rules

Status: no uid 1001 `attacker` to root LPE was found.

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 Server, systemd running.

Probe command:

```sh
./pocs/tmpfiles_public_dirs_probe.sh ubuntu24-server-lpe-target | tee logs/tmpfiles-public-dirs.out
```

## Default proof

Package/rule evidence from `logs/tmpfiles-public-dirs.out`:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
systemd 255.4-1ubuntu8.15 ii
snapd 2.74.1+ubuntu24.04.4 ii
screen 4.9.1-1ubuntu1 ii
passwd 1:4.13+dfsg1-4ubuntu3.2 ii
x11-common un
systemd-tmpfiles-clean.timer -> systemd-tmpfiles-clean.service
systemd-tmpfiles-clean.service ExecStart=systemd-tmpfiles --clean
```

Relevant installed tmpfiles rules:

```text
/usr/lib/tmpfiles.d/x11.conf:       D! /tmp/.X11-unix ... ; r! /tmp/.X[0-9]*-lock
/usr/lib/tmpfiles.d/snapd.conf:     D! /tmp/snap-private-tmp 0700 root root ; X exclusions
/usr/lib/tmpfiles.d/systemd-tmp.conf: R! /tmp/systemd-private-* ; R! /var/tmp/systemd-private-*
/usr/lib/tmpfiles.d/passwd.conf:    r! /etc/{gshadow,shadow,passwd,group,subuid,subgid}.lock
/etc/tmpfiles.d/screen-cleanup.conf: d /run/screen 1777 root utmp
/usr/lib/tmpfiles.d/debian.conf:    L /run/shm - - - - /dev/shm
/usr/lib/tmpfiles.d/00rsyslog.conf and systemd.conf contain z/Z rules under /var/log and /run/log.
```

Attacker-writable public paths were `/tmp`, `/dev/shm`, `/run/shm` and `/run/screen`. Attacker could not write `/run`, `/etc`, `/var/log`, `/run/log`, or `/run/log/journal`. Kernel protections were enabled: `protected_symlinks=1`, `protected_hardlinks=1`, `protected_regular=2`, `protected_fifos=1`.

## Results

`x11.conf`: attacker could pre-place `/tmp/.X11-unix` and `/tmp/.X77-lock` as symlinks to root-owned decoys. Root `stat` through those sticky-directory symlinks returned `Permission denied`; tmpfiles `D!` did not chown/chmod/write the decoy. An exact `r! /tmp/.X77-lock` action unlinked the attacker symlink only; `/tmp/tmpfiles-public-dirs-root-decoys/xlock-target` stayed `root:root 0644` with original content.

`snapd.conf`: attacker could pre-place `/tmp/snap-private-tmp` as a top-level symlink. tmpfiles reported `Cannot open directory "/tmp/snap-private-tmp": Not a directory` and did not alter the root decoy. When attacker pre-created a real tree, tmpfiles changed only the top directory to `root:root 0700`; nested attacker files/symlinks remained present and the root decoy target stayed unchanged.

`systemd-tmp.conf`: the default `R! /tmp/systemd-private-*` glob is installed. To avoid broad cleanup of live service private tmpdirs, the probe used an exact transient `R! /tmp/systemd-private-tpfprobe` rule on the same path shape. tmpfiles ran `rm -rf "/tmp/systemd-private-tpfprobe"` and removed the attacker tree and symlink, but the root decoy target stayed `root:root 0644` with original content.

`passwd.conf`: attacker could not create any `/etc/*.lock` symlink or file: every `/etc/{passwd,shadow,group,gshadow,subuid,subgid}.lock` attempt failed with `Permission denied`. No attacker-controlled object can reach the boot-only lock cleanup rule.

`screen-cleanup`: `/run/screen` is attacker-writable, but the rule is only `d /run/screen`. `--create` found the existing directory and `--clean` did not descend into attacker entries. `/run/screen/tpf-link` and `/run/screen/tpf-file` remained attacker-owned; the root decoy was unchanged.

`/run/shm`: attacker could write through `/run/shm` because it resolves to `/dev/shm`, but could not replace `/run/shm` itself. tmpfiles `L /run/shm ... /dev/shm` found the existing root-owned symlink and did not touch attacker symlinks inside `/dev/shm` or their targets.

`z/Z` behavior: transient safe rules showed tmpfiles skips chmod/chown on symlinks (`Skipping mode fix for symlink ...`) and did not alter root-owned decoy targets. It did chmod/chown real in-tree files/directories named by the rule. The default `z/Z` rules are under `/var/log` and `/run/log`, where uid 1001 cannot create replacement paths.

Hardlink/race checks: hardlinks to `/etc/shadow` and root-owned decoys failed (`Invalid cross-device link` or `Operation not permitted`). A short symlink race against exact `R!` and `r!` probe rules did not change root decoy ownership, mode, or content.

## Cleanup

The probe removed `/tmp/tmpfiles-public-dirs-probe`, `/tmp/tmpfiles-public-dirs-root-decoys`, `/tmp/.X77-lock`, `/tmp/.X78-lock`, `/tmp/snap-private-tmp`, `/tmp/systemd-private-tpfprobe`, `/tmp/systemd-private-raceprobe`, `/run/screen/tpf-*`, and `/dev/shm/tpf-link`. It restored the default X11 tmpfiles directories as `root:root 1777`.

Conclusion: no root file write, ownership/mode change of a root target, symlink-follow primitive, hardlink primitive, race primitive, or root code execution path was validated from the normal non-sudo attacker.
