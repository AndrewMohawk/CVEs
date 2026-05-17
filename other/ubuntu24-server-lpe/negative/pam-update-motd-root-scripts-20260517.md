# Negative: PAM/update-motd root-script influence

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default package/service state. Attacker model was the existing normal non-sudo `attacker` account, `uid=1001 gid=1001`, with no sudo, adm, docker, lxd, or package-install capability.

Result: no validated uid1001-to-root LPE in the PAM/login/update-motd/motd-news/landscape/ubuntu-advantage/fwupd/update-notifier slice.

Primary log:

```text
logs/pam-update-motd-root-scripts-20260517.out
```

## Default reachability

The only default PAM stack containing `pam_motd` is `/etc/pam.d/login`:

```text
/etc/pam.d/login:33:session optional pam_motd.so motd=/run/motd.dynamic
/etc/pam.d/login:34:session optional pam_motd.so noupdate
```

`/usr/bin/login` is not setuid, so uid1001 cannot launch that PAM stack as root:

```text
login: Cannot possibly work without effective root
login_rc=1
login_p_rc=1
```

`openssh-server` is not installed and localhost SSH refused port 22. `su` is setuid, but the default `su` stack has no `pam_motd`; the locked attacker account also failed self/root authentication in this target. `runuser` rejected non-root callers:

```text
ssh: connect to host localhost port 22: Connection refused
su: Authentication failure
runuser: may not be used by non-root users
```

uid1001 also could not push hostile environment into the root systemd manager or start the relevant root services:

```text
systemctl set-environment ... -> Access denied
systemctl start motd-news.service -> Interactive authentication required
systemctl start update-notifier-motd.service -> Interactive authentication required
systemctl start apt-news.service -> Interactive authentication required
systemctl start esm-cache.service -> Interactive authentication required
systemctl start fwupd-refresh.service -> Interactive authentication required
```

`loginctl enable-linger attacker` was allowed, but only created/enabled the fixed user-manager state for uid1001 (`Linger=yes`, `State=opening`). It did not invoke `pam_motd` or any root update-motd script, and was cleaned up.

## Env and import probes

Root-only canaries confirmed the suspicious shapes would matter if uid1001 could inject environment into a root update-motd execution:

```text
env CACHE=/root/pam-update-motd-root-scripts-20260517.root /etc/update-motd.d/50-motd-news
-> -rw-r--r-- root:root /root/pam-update-motd-root-scripts-20260517.root

run-parts with hostile root PATH
-> ROOT_PATH_HIT name=uname uid=0 ...
-> ROOT_PATH_HIT name=cat uid=0 ...
```

The actual uid1001 direct `run-parts /etc/update-motd.d` execution hit attacker payloads only as uid1001:

```text
UID1001_PATH_HIT name=uname uid=1001 ruid=1001
UID1001_PATH_HIT name=cat uid=1001 ruid=1001
ROOT_PROOF_SUPPLEMENT=NO
```

A real tty-backed root `/bin/login -p -f attacker` upper-bound test preserved hostile `CACHE`, `PYTHONPATH`, `APT_CONFIG`, `UA_*`, `XDG_*`, and `URLS` into the final uid1001 shell, while login reset `PATH` to the normal login path. No root marker was created by PATH wrappers, Python `sitecustomize`, shell env files, `APT_CONFIG`, `UA_DATA_DIR`, or `CACHE`:

```text
CACHE=/root/pam-update-motd-root-scripts-20260517.root
PYTHONPATH=/home/attacker/pam-update-motd-root-scripts-20260517/py
UA_DATA_DIR=/home/attacker/pam-update-motd-root-scripts-20260517/ua-data
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

stat: cannot statx '/root/pam-update-motd-root-scripts-20260517.root': No such file or directory
```

The Landscape cache stayed root-owned, and the attacker-controlled HOME/sysinfo config was not imported into the root `landscape-sysinfo` path:

```text
-rw-r--r-- root:root /var/lib/landscape/landscape-sysinfo.cache
find: '/home/attacker/.landscape': No such file or directory
```

Root systemd-triggered services with the uid1001 payload tree present used the clean system manager environment and created no markers:

```text
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
systemctl start motd-news.service -> rc=0
systemctl start update-notifier-motd.service -> rc=0
systemctl start apt-news.service -> rc=0
systemctl start esm-cache.service -> rc=0
systemctl start update-notifier-download.service -> rc=0
markers after root systemd triggers: no /root marker, no /tmp marker
```

`fwupd-refresh.service` failed under this container target during the root clean-env trigger, consistent with the already-known fwupd container/default-state boundary, but it did not consume attacker state or create a marker. Failed unit state was reset afterward and the target returned to `systemctl is-system-running -> running`.

## Cache and TOCTOU checks

The relevant write/cache roots were not attacker-writable:

```text
/run/motd.dynamic                              root:root 0644
/etc/update-motd.d                            root:root 0755
/etc/default/motd-news                        root:root 0644
/var/cache/motd-news                          root:root 0644
/var/lib/landscape/landscape-sysinfo.cache    root:root 0644
/var/lib/update-notifier/updates-available    root:root 0644
/var/lib/update-notifier/package-data-downloads root:root 0755
/var/lib/ubuntu-advantage                     root:root 0755
/run/ubuntu-advantage                         root:root 0755
```

uid1001 symlink/write attempts into `/run/motd.dynamic`, `/var/cache/motd-news`, `/var/lib/landscape/landscape-sysinfo.cache`, `/var/lib/update-notifier/updates-available`, `/var/lib/ubuntu-advantage/messages/...`, and `/var/lib/fwupd/pending.db` failed with `Permission denied`, existing root-owned files, or missing root-owned parent directories.

## Conclusion

No root file write or command execution primitive was validated. The exploitable-looking pieces are real static hazards only under a missing precondition:

- `50-motd-news` trusts `CACHE`, but uid1001 cannot inject it into a root caller.
- update-motd scripts run relative commands, but uid1001-controlled `PATH` reaches only uid1001 executions.
- Python/Ubuntu Pro/Landscape import and HOME variables survived into the final user shell in an upper-bound login test, but did not execute in root context.
- root cache/state paths are not writable or replaceable by uid1001.
- `ssh`, direct `login`, `su`, `runuser`, systemd service starts, and system manager environment writes do not provide a default root update-motd trigger to the attacker.

No `notes/pam-motd-*.md` or `pocs/pam-motd-*` artifact was created because there is no real LPE proof in this slice.
