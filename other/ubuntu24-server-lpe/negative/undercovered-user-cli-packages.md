# Negative: under-covered user CLI packages

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Artifacts:

```text
pocs/undercovered_user_cli_packages_probe.sh
logs/undercovered-user-cli-packages.out
```

## Result

No uid1001-to-root LPE was validated through the under-covered default packages `pastebinit`, `run-one`, `xdg-user-dirs`, `overlayroot`, `unminimize`, or `sosreport`.

This pass was driven by the package coverage gap map. These packages are default-installed, but they do not expose default root services, timers, sockets, polkit actions, D-Bus launchers, setuid/setgid helpers, file capabilities, or root consumers of attacker-writable state in the stock target.

## Default Proof

Packages from the live target:

```text
overlayroot    0.49~24.04.1
pastebinit     1.6.2-1
run-one        1.17-0ubuntu2
sosreport      4.10.2-0ubuntu0~24.04.1
unminimize     0.2.1
xdg-user-dirs  0.18-1build1
```

No matching root service/timer/socket was loaded:

```sh
systemctl --no-pager --plain list-units --all --type=service --type=timer --type=socket |
  grep -Ei 'pastebinit|run-one|xdg-user-dirs|overlayroot|unminimize|sos|sosreport'
```

The only default launcher/config hits were non-privileged or already-bounded paths:

```text
/etc/update-motd.d/60-unminimize: prints text about unminimize
/etc/update-motd.d/97-overlayroot: reads /proc/mounts and prints overlayroot lines
/etc/xdg/autostart/xdg-user-dirs.desktop: Exec=xdg-user-dirs-update
/etc/xdg/user-dirs.conf: user-login behavior for user directories
```

Relevant file modes:

```text
/usr/bin/pastebinit                 0755 root:root
/usr/bin/pbput                      0755 root:root
/usr/bin/run-one                    0755 root:root
/usr/bin/xdg-user-dir               0755 root:root
/usr/bin/xdg-user-dirs-update       0755 root:root
/usr/sbin/overlayroot-chroot        0755 root:root
/etc/update-motd.d/97-overlayroot   0755 root:root
/etc/overlayroot.conf               0644 root:root
/usr/bin/unminimize                 0755 root:root
/etc/update-motd.d/60-unminimize    0755 root:root
/usr/bin/sos                        0755 root:root
/usr/bin/sosreport                  0755 root:root
/usr/bin/sos-collector              0755 root:root
/etc/sos                            0755 root:root
/etc/xdg                            0755 root:root
/usr/local/sbin                     0755 root:root
/dev/shm                            1777 root:root
```

As uid1001, root config directories were not writable:

```text
/etc/sos: not-writable
/etc/sos/extras.d: not-writable
/etc/sos/groups.d: not-writable
/etc/sos/presets.d: not-writable
/etc/xdg: not-writable
/usr/local: not-writable
/usr/local/sbin: not-writable
/etc/overlayroot.conf: not-writable
/dev/shm: writable
```

## Candidate Results

`pastebinit`: no maintainer scripts, no root unit, and no default root consumer of its `/tmp`/`$TMPDIR` helper behavior. The probe ran only `pastebinit --help` to avoid network uploads; it stayed uid1001.

`run-one`: uses caller-owned `$HOME/.cache/run-one` or `/dev/shm/run-one_$USER*` lock state. The probe executed `run-one /bin/sh -c id` and confirmed the child ran as uid1001. No stock root unit/cron invokes `run-one`.

`xdg-user-dirs`: only default trigger is user-session autostart. `xdg-user-dir` and `xdg-user-dirs-update --dummy-output` wrote attacker-owned files under `/tmp` when run by uid1001. Root-owned `/etc/xdg` config was not writable.

`overlayroot`: `/etc/overlayroot.conf` defaults to `overlayroot_cfgdisk="disabled"` and `overlayroot=""`. The MOTD script only greps `/proc/mounts`; `overlayroot-chroot` failed with `ERROR: Unable to find an overlayroot filesystem`. Initramfs triggers are dpkg/root lifecycle only.

`unminimize`: `/etc/update-motd.d/60-unminimize` prints text only. Direct uid1001 execution of `unminimize` reached the interactive warning and exited with no package changes or privilege change. Its postinst can remove `/usr/local/sbin/unminimize`, but `/usr/local/sbin` is not uid1001-writable.

`sosreport`: `sos`, `sosreport`, and `sos-collector` are normal root-owned CLIs. `sos report --batch --tmp-dir ...` returned `Component must be run with root privileges`. The known `sys.path.insert(0, os.getcwd())` hazard is not reachable through a default root caller.

## Cleanup

The probe removed:

```text
/tmp/undercovered-user-cli
/dev/shm/run-one_attacker_probe
/home/attacker/.cache/run-one
```

Final target health:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
```

## Why Scanners May Miss It

These packages have shell/Python wrappers, MOTD hooks, autostart files, initramfs hooks, `/dev/shm` lock use, and support-tool import behavior. Static scans can over-rank those patterns without proving a default root caller. The decisive facts are the absence of root service/timer/socket launchers, root-owned config paths, and direct uid1001 execution staying unprivileged.

## Suggested Fix

No LPE fix is justified from this target state. Preserve the current boundaries: keep support-tool config roots unwritable by normal users, keep `sos report` root-gated, keep overlayroot disabled by default, and avoid adding default root jobs that call `pastebinit`, `run-one`, `xdg-user-dirs-update`, or `sos` from attacker-writable directories.
