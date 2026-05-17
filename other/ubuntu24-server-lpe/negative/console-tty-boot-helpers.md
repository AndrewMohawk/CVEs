# console / TTY / boot helper audit

Status: negative. No uid1001 -> root local privilege escalation was found in the default console, TTY, Plymouth, getty/login, wall, or utmp helper surface on the Docker stock Ubuntu 24.04 Server target.

## Target proof

Container: `ubuntu24-server-lpe-target`

Attacker identity:

```sh
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Relevant default packages and versions:

```text
console-setup            1.226ubuntu1
kbd                      2.6.4-2ubuntu2
keyboard-configuration   1.226ubuntu1
libutempter0:arm64       1.2.1-3build1
login                    1:4.13+dfsg1-4ubuntu3.2
plymouth                 24.004.60-1ubuntu7.1
systemd                  255.4-1ubuntu8.15
util-linux               2.39.3-9ubuntu6.5
```

Default active/relevant units:

```text
console-setup.service                 active exited
keyboard-setup.service                active exited
setvtrgb.service                      active exited
getty@tty1.service                    active running
systemd-ask-password-console.path     active waiting
systemd-ask-password-wall.path        active waiting
plymouth-start.service                inactive dead
plymouth-quit.service                 active exited
plymouth-quit-wait.service            active exited
plymouth-read-write.service           active exited
```

## Code and configuration paths

Console setup is root-started only. `/usr/lib/systemd/system/console-setup.service:7,11` gates on `/bin/setupcon` and runs `/lib/console-setup/console-setup.sh`; `/usr/lib/systemd/system/keyboard-setup.service:6,10` runs `/lib/console-setup/keyboard-setup.sh`. The scripts use root-owned inputs under `/etc/default` and `/etc/console-setup`:

```text
/lib/console-setup/console-setup.sh:10-18 checks cached setup freshness
/lib/console-setup/console-setup.sh:31 runs setupcon --save
/lib/console-setup/keyboard-setup.sh:3-15 runs cached_setup_keyboard.sh or setupcon -k
/etc/default/console-setup is 0644 root:root
/etc/default/keyboard is 0644 root:root
/etc/console-setup/cached_setup_*.sh are 0755 root:root
```

`setvtrgb` is also root-started only. `/usr/lib/systemd/system/setvtrgb.service:6-11` requires `/sbin/setvtrgb` and `/dev/tty0`, then runs `/sbin/setvtrgb /etc/vtrgb`; `/usr/sbin/setvtrgb` is `0755 root:root`, and `/etc/vtrgb` resolves to a `0644 root:root` file.

Plymouth boot startup is not attacker-reachable in this Docker target. `/usr/lib/systemd/system/plymouth-start.service:7-15` requires kernel command line `splash`, excludes containers with `ConditionVirtualization=!container`, and starts `/usr/sbin/plymouthd` as root only during boot. The client and daemon binaries are `0755 root:root` with no file capabilities.

The getty/login boundary is physical-console/root-unit driven. `/usr/lib/systemd/system/getty@.service:32,39-57` requires `/dev/tty0`, starts `/sbin/agetty`, binds `TTYPath=/dev/%I`, and clears locale variables. `/usr/sbin/agetty`, `/usr/bin/login`, and `/usr/sbin/sulogin` are not setuid and have no file capabilities.

The ask-password wall/console agents watch a root-owned directory. `/usr/lib/systemd/system/systemd-ask-password-console.path:24-26` and `/usr/lib/systemd/system/systemd-ask-password-wall.path:21-23` watch `/run/systemd/ask-password`; that directory is `0755 root:root`. The corresponding services run `systemd-tty-ask-password-agent --watch --console` and `systemd-tty-ask-password-agent --wall` from root-started systemd units.

`wall` and `write` are ordinary `0755 root:root` binaries. `/usr/lib/aarch64-linux-gnu/utempter/utempter` is setgid `utmp` (`2755 root:utmp`), not setuid root; `/run/utmp` is `0664 root:utmp`.

## Unprivileged trigger results

All root unit starts from uid1001 required interactive authorization:

```sh
systemctl restart console-setup.service
systemctl restart keyboard-setup.service
systemctl start setvtrgb.service
systemctl start plymouth-start.service
systemctl start getty@tty9.service
systemctl start systemd-ask-password-wall.service
```

Representative result:

```text
Failed to start ...: Interactive authentication required.
```

The ask-password directory was not writable and unprivileged password request creation failed:

```text
touch /run/systemd/ask-password/ask.attacker
touch: cannot touch '/run/systemd/ask-password/ask.attacker': Permission denied

systemd-ask-password --timeout=1 --no-tty attacker-prompt
Failed to query password: Permission denied
```

The kbd/VT helpers were executable but not usable from the uid1001 shell as a console privilege boundary:

```text
setupcon --save
setupcon: /etc/console-setup is not writable. No files will be saved there.
setupcon: We are not on the console, the console is left unconfigured.

loadkeys /etc/console-setup/cached_UTF-8_del.kmap.gz
Couldn't get a file descriptor referring to the console

dumpkeys
fgconsole
chvt 1
openvt -c 9 -- sh -c id
deallocvt 9
/usr/sbin/setvtrgb /etc/vtrgb
Couldn't get a file descriptor referring to the console
```

Plymouth client commands did not reach a root daemon:

```text
plymouth --ping                         exit=1
plymouth show-splash                    exit=1
plymouth message --text=attacker        exit=1
plymouth ask-for-password --prompt=...  exit=1
```

The login boundary did not expose root semantics to an already-unprivileged shell:

```text
login -f root
login: Cannot possibly work without effective root
```

`wall` could broadcast as the attacker but did not cross into root execution. `write root` failed because root was not logged in. Direct `/run/utmp` append was denied, and the setgid `utempter` helper did not add a usable forged entry from the synthetic pty probe.

## Cleanup

The utmp probe briefly left synthetic `attacker` rows in `/run/utmp`. They were removed by dumping `/run/utmp`, filtering rows containing `[attacker]`, reconstructing with `utmpdump -r`, and verifying:

```sh
utmpdump /run/utmp | grep attacker || true
```

No attacker rows remained after cleanup. No workspace PoC was created because no LPE was validated.

## Why this is a dead end

The default-installed components are real root/boot/TTY code, but uid1001 cannot trigger them in a privileged context. The root units are systemd/polkit-protected, their mutable inputs are root-owned, Plymouth startup is boot/container-condition gated, and direct helper execution lacks either setuid root, file capabilities, a console fd, or a writable root-watched path. Physical virtual-console behavior remains out of scope for this goal unless it can be reached from the normal uid1001 shell in default state; this pass did not find such a path.

Normal scanners can flag many of these helpers as interesting because they touch TTYs, utmp, or boot-time root units, but the exploitable trust boundary collapses only after checking the default systemd authorization path, the console fd requirement, and the ownership of `/run/systemd/ask-password` and `/run/utmp`.
