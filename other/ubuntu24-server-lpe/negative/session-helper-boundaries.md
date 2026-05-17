# Session helper boundaries: no uid1001-to-root LPE

Result: negative. I did not find a valid local privilege escalation from `attacker` (`uid=1001`, no sudo/adm/lxd/docker groups) through the default PAM/login/session/update-motd/landscape/pollinate/release-upgrader/ubuntu-advantage/update-notifier helper surface.

## Why this looked interesting

The default server image has root-executed session/status helper paths:

- `/etc/pam.d/login:33-34` invokes `pam_motd.so`.
- `/usr/share/landscape/landscape-sysinfo.wrapper:5-29` writes `/var/lib/landscape/landscape-sysinfo.cache`.
- `/etc/update-motd.d/91-release-upgrade:13-20` executes `/usr/lib/ubuntu-release-upgrader/release-upgrade-motd` only when `id -u` is root.
- `/usr/lib/update-notifier/update-motd-updates-available:15-66` and `/usr/lib/update-notifier/update-motd-fsck-at-reboot:11-86` refresh root-owned stamps.
- `/usr/lib/update-notifier/package-data-downloader:247-287` can run hook `Script` entries from package-data metadata.

Those scripts contain normal shell/Python trust-boundary smells: unqualified shell commands, Python imports, root cache writes, and service-account-owned state directories.

## Default reachability proof

Installed default package versions:

```text
login 1:4.13+dfsg1-4ubuntu3.2
libpam-modules 1.5.3-5ubuntu5.5
landscape-common 24.02-0ubuntu5.7
pollinate 4.33-3.1ubuntu1.3
ubuntu-pro-client 37.2ubuntu~24.04
ubuntu-release-upgrader-core 1:24.04.28
update-notifier-common 3.192.68.2
```

Default timers/services were present for MOTD/update-notifier. `pollinate.service` is enabled but skipped in this Docker target by `ConditionVirtualization=!container`; Ubuntu Pro timer/services are enabled but inactive without a Pro machine token or cloud auto-attach trigger.

The already-local attacker cannot invoke `/usr/bin/login` with effective root because it is not setuid:

```text
$ runuser -u attacker -- /usr/bin/login -f attacker
login: Cannot possibly work without effective root
```

`su` and `runuser` do not include `pam_motd`, so they do not expose this update-motd root path to the attacker shell.

## Exploitability tests

I tested hostile `PATH`, `PYTHONPATH/sitecustomize.py`, cwd, and direct helper execution.

Direct attacker `run-parts /etc/update-motd.d` reaches the scripts, but all hooks ran as `uid=1001/euid=1001`.

Root-side PAM login simulation with malicious `PATH` and `PYTHONPATH` printed MOTD but created no hostile markers, showing the attacker environment did not propagate into the privileged update-motd execution.

Direct attacker execution of `pro`, `do-release-upgrade`, `apt_check.py`, `check-new-release`, and `landscape-sysinfo` honored Python import hooks only as `uid=1001`. No root context was reached.

Attacker attempts to start the root helper units or poison systemd manager environment failed with interactive-auth/access-denied errors.

Attacker write attempts to relevant configs, cache dirs, stamps, and package-data hook dirs failed with `Permission denied`. `/usr/share/package-data-downloads` is root-owned and empty on this stock target, so the root `package-data-downloader` timer has no attacker-provided hook to execute.

`/var/lib/landscape` is writable by the `landscape` service account and `/var/cache/pollinate` by `pollinate`, but neither account is reachable from `uid1001` in default state. The observed service-account writable state did not produce an in-scope normal-user-to-root path.

## Conclusion

No valid stock Ubuntu 24.04 Server default LPE was found in this bounded surface. The interesting primitives are either root-owned but not attacker-triggerable with attacker-controlled environment, attacker-triggerable only as uid1001, or service-account state with no default uid1001 path into the service account.

Reproducer/evidence script: `pocs/sessionhelpers_probe.sh`.

Cleanup performed: removed `/home/attacker/sessionhelpers*`, `/tmp/sessionhelpers_*`, and root-owned MOTD cache files created only by the login simulation when they were absent before the test.
