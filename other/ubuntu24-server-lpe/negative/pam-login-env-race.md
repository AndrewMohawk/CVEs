# Negative: pam-login-env-race

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server package set. User model was a normal passworded non-admin user (`selfauth`, uid 1002) and the existing non-sudo `attacker` user. No sudo/docker/lxd/adm path was used.

Result: no validated local privilege escalation in the login/PAM/local-tty environment and runtime-dir boundary. The probe created no root-owned attacker marker and ended with `ROOT_PROOF=no`.

## Validation

Probe:

```sh
bash -n pocs/pam_login_env_race_probe.sh
./pocs/pam_login_env_race_probe.sh > logs/pam-login-env-race.out 2>&1
```

The probe exited `0`, restored account files, home dotfiles, utmp/wtmp/btmp/lastlog, linger state, and tty1 mode/owner, and the final container health check returned `running`.

## Coverage

The probe backed up target state, temporarily set `selfauth:selfauth` only to drive real password prompts, then restored `/etc/passwd`, `/etc/shadow`, `/etc/group`, and `/etc/gshadow`.

It exercised:

- passworded `/bin/login -p selfauth` through a pty, with hostile `PATH`, `PYTHONPATH`, `BASH_ENV`, `TMPDIR`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, `~/.pam_environment`, `~/.bash_profile`, and `~/.hushlogin -> /root/...`;
- setuid-root `/usr/bin/su -p selfauth` from uid 1002 with the same runtime/env spoofing;
- `pam_systemd` user runtime creation and restart after uid 1002 replaced `/run/user/1002/{systemd,bus,gnupg,pk-debconf-socket}` with symlinks to a root canary tree;
- `loginctl enable-linger` for root, path traversal, and self;
- tty ownership, utmp/wtmp/lastlog mode and hash changes, with accounting files restored afterward.

## Key evidence

`login -p` authenticated normally and created an active tty session, but `pam_systemd` replaced the spoofed runtime and bus paths:

```text
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1002/bus
XDG_RUNTIME_DIR=/run/user/1002
Id=37
TTY=pts/0
Type=tty
Class=user
Active=yes
```

The login shell ran only as uid 1002. `PATH` was reset to the normal login path, `~/.pam_environment` was not imported (`PAM_LOGIN_ENV_RACE_USERENV` absent), and the hostile root write in `.bash_profile` failed:

```text
tty_stat=crw------- selfauth:tty character special file /dev/pts/0
MISSING /tmp/pam-login-env-race-fake-*.uid
MISSING /root/pam-login-env-race-fake-*.root
MISSING /root/pam-login-env-race-login-bash-profile.root
```

The MOTD path printed normally, but hostile `PATH`/`PYTHONPATH`/`BASH_ENV` hooks were not hit in root context. No fake `id`, `uname`, `bc`, `systemctl`, Python `sitecustomize`, or shell env hook produced a root marker.

`su -p selfauth` was attacker-reachable as a setuid-root PAM path, but it also ended in a uid 1002 session with fixed runtime variables:

```text
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1002/bus
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
XDG_RUNTIME_DIR=/run/user/1002
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
MISSING /root/pam-login-env-race-su-root
```

The runtime symlink test produced a denial/DoS of the user manager, not a root write. uid 1002 could plant symlinks under its runtime dir:

```text
lrwxrwxrwx selfauth:selfauth /run/user/1002/systemd -> /root/pam-login-env-race-runtime-canary/systemd-target
lrwxrwxrwx selfauth:selfauth /run/user/1002/bus -> /root/pam-login-env-race-runtime-canary/bus-target
```

Restarting `user@1002.service` over those symlinks failed as the user with `Permission denied`; the root canary remained unchanged and present:

```text
Failed to allocate manager object: Permission denied
canary_after_stop=present
```

`loginctl enable-linger root` as uid 1002 required interactive admin auth, `../root` was rejected as an unknown user, and self-linger created only the expected root-owned empty file under `/var/lib/systemd/linger/selfauth`.

## Conclusion

No stock Ubuntu 24.04 Server LPE was found in this lane. The interesting behaviors are bounded: passworded `login -p` can carry some benign user environment into the final user shell (`TMPDIR`, `PYTHONPATH`), but privileged PAM/MOTD/runtime setup did not execute attacker-controlled code; `pam_systemd` overwrote spoofed runtime variables; user runtime symlink planting broke the uid 1002 user manager without following links into root-owned paths; and accounting writes stayed structured in root:utmp files.

Artifacts:

- `pocs/pam_login_env_race_probe.sh`
- `logs/pam-login-env-race.out`
