# server-support-packages: no uid1001 -> root LPE

## Result

No local privilege escalation was found in the assigned default server support package slice on `ubuntu24-server-lpe-target`.

Target context:

```text
Ubuntu 24.04.4 LTS (noble)
systemctl is-system-running: running
attacker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Installed/default package proof:

```text
landscape-common                 24.02-0ubuntu5.7        ii
command-not-found                23.04.0                 ii
sosreport                        4.10.2-0ubuntu0~24.04.1 ii
ubuntu-release-upgrader-core     1:24.04.28              ii
update-manager-core              1:24.04.12              ii
update-notifier-common           3.192.68.2              ii
apport                           2.28.1-0ubuntu3.8       ii
command-not-found-data           not installed
sos                              not installed
ubuntu-release-upgrader-gtk      not installed
update-manager                   not installed
popularity-contest               not installed
```

## Default-Reachable Surface

`update-notifier-common` installs and enables the root timer/services:

```text
update-notifier-download.timer   enabled, active/waiting
update-notifier-motd.timer       enabled, active/waiting
update-notifier-download.service static
update-notifier-motd.service     static
```

The relevant unit/config paths are:

```text
/usr/lib/systemd/system/update-notifier-motd.service: ExecStart=/usr/lib/ubuntu-release-upgrader/release-upgrade-motd
/usr/lib/systemd/system/update-notifier-motd.timer: OnCalendar=Sun *-*-* 06:00:00, RandomizedDelaySec=1w, Persistent=true
/usr/lib/systemd/system/update-notifier-download.service: ExecStart=/usr/lib/update-notifier/package-data-downloader
/usr/lib/systemd/system/update-notifier-download.timer: OnStartupSec=5m, OnUnitActiveSec=24h
```

`landscape-common` installs an update-motd hook:

```text
/etc/update-motd.d/50-landscape-sysinfo -> /usr/share/landscape/landscape-sysinfo.wrapper
target mode: -rwxr-xr-x root:root
```

The apparent `0777` mode is only the symlink lstat mode. The symlink target and all parent directories are root-owned and not attacker-writable.

`command-not-found` installs a root apt update hook and unprivileged shell hooks:

```text
/etc/apt/apt.conf.d/50command-not-found
/etc/bash.bashrc
/etc/zsh_command_not_found
```

`sosreport` is installed, but no default `sos` service, timer, socket, path unit, cron entry, or logrotate entry exists. Its `report` component is CLI-only and root-required.

## Code and Config Evidence

Landscape:

* `/var/lib/dpkg/info/landscape-common.postinst:50-54` fixes `/etc/landscape`, `/var/lib/landscape`, and `/var/log/landscape` ownership; `/etc/landscape` is `root:landscape 0775`, but `attacker` is not in `landscape`.
* `/var/lib/dpkg/info/landscape-common.postinst:90-96` creates `/etc/update-motd.d/50-landscape-sysinfo` as a symlink to `/usr/share/landscape/landscape-sysinfo.wrapper` and runs the wrapper during package configure.
* `/usr/share/landscape/landscape-sysinfo.wrapper:5-10` uses `/var/lib/landscape/landscape-sysinfo.cache`; `/usr/share/landscape/landscape-sysinfo.wrapper:24-29` runs `/usr/bin/landscape-sysinfo`, writes the cache, and chmods it `0644`.

Command-not-found:

* `/etc/apt/apt.conf.d/50command-not-found:13-15` registers `APT::Update::Post-Invoke-Success` and calls absolute `/usr/lib/cnf-update-db`.
* `/usr/lib/cnf-update-db:19-32` uses `/var/lib/command-not-found/commands.db` and `/var/lib/apt/lists/*Commands-*`.
* `/usr/lib/python3/dist-packages/CommandNotFound/db/creator.py:92-113` creates `commands.db.tmp`, renames it into place, then writes metadata. The directory is root-owned.
* `/usr/lib/python3/dist-packages/CommandNotFound/db/creator.py:137-146` parses apt list files through absolute `/usr/lib/apt/apt-helper`.
* `/etc/bash.bashrc:56-62` and `/etc/zsh_command_not_found:7-12` run `/usr/lib/command-not-found` only in the user's shell context.

Update notifier and release upgrader:

* `/usr/lib/systemd/system/update-notifier-motd.service:5-7` runs absolute `/usr/lib/ubuntu-release-upgrader/release-upgrade-motd` as a oneshot root service.
* `/etc/update-motd.d/91-release-upgrade:13-19` exits for non-root callers and execs the release-upgrade check only as root.
* `/usr/lib/ubuntu-release-upgrader/release-upgrade-motd:23-40` reads/writes `/var/lib/ubuntu-release-upgrader/release-upgrade-available`; the parent directory is root-owned.
* `/usr/bin/do-release-upgrade:74-75` enters check-only mode when invoked as `check-new-release`.
* `/usr/share/polkit-1/actions/com.ubuntu.release-upgrader.policy:10-140` gates release upgrades with `allow_any=no`, `allow_inactive=no`, `allow_active=auth_admin`.
* `/usr/share/polkit-1/actions/com.ubuntu.release-upgrader.policy:143-269` similarly gates partial upgrades with `auth_admin`.
* `/usr/lib/ubuntu-release-upgrader/do-partial-upgrade:91-98` uses `/usr/bin/pkexec` when non-root; `pkexec` is absent in this server target.
* `/usr/lib/update-notifier/package-data-downloader:36-42` fixes hook and stamp locations under `/usr/share/package-data-downloads` and `/var/lib/update-notifier`.
* `/usr/lib/update-notifier/package-data-downloader:229-287` processes hook files and executes the hook `Script`, but `/usr/share/package-data-downloads` is root-owned and empty in the default target.
* `/var/lib/dpkg/info/update-notifier-common.postinst:12-29` runs `package-data-downloader` for dpkg triggers/configure; `/var/lib/dpkg/info/update-notifier-common.triggers:1` registers `interest-noawait /usr/share/package-data-downloads`.

Sosreport:

* `/usr/bin/sos:13-15` inserts `os.getcwd()` into `sys.path` before importing `sos`, which is interesting if root runs `sos` from an attacker-controlled directory.
* `/usr/lib/python3/dist-packages/sos/report/__init__.py:82-88` marks `sos report` as `root_required = True`.
* `/usr/lib/python3/dist-packages/sos/__init__.py:167-178` refuses root-required components for non-root callers before component execution.
* No default root service, timer, cron, socket, or apport hook invokes `sos` from an attacker-controlled cwd.

Apport package hooks:

* `/usr/share/apport/package-hooks/source_ubuntu-release-upgrader.py:47-58` attaches root command output and crash report metadata.
* `/usr/share/apport/package-hooks/source_update-manager.py:68-83` attaches root command output and HWE status.
* These hooks are mediated by apport's reporting path; this audit did not find a default root execution path where uid1001 controls hook code, command resolution, or writable report destinations.

## Writable State Checks

Relevant default state:

```text
/etc/update-motd.d                         drwxr-xr-x root:root
/usr/share/landscape/landscape-sysinfo.wrapper -rwxr-xr-x root:root
/etc/landscape                             drwxrwxr-x root:landscape
/var/lib/landscape                         drwxr-xr-x landscape:landscape
/var/log/landscape                         drwxr-xr-x landscape:landscape
/var/lib/command-not-found                 drwxr-xr-x root:root
/var/lib/command-not-found/commands.db     -rw-r--r-- root:root
/var/lib/apt/lists                         drwxr-xr-x root:root
/etc/update-manager                        drwxr-xr-x root:root
/etc/update-manager/release-upgrades       -rw-r--r-- root:root
/etc/update-manager/release-upgrades.d     drwxr-xr-x root:root
/var/lib/ubuntu-release-upgrader           drwxr-xr-x root:root
/var/lib/update-manager                    drwxr-xr-x root:root
/usr/share/package-data-downloads          drwxr-xr-x root:root
/var/lib/update-notifier/package-data-downloads drwxr-xr-x root:root
/var/lib/update-notifier/package-data-downloads/partial drwx------ _apt:root
/var/lib/update-notifier/user.d            drwxr-xr-x root:root
/etc/sos                                   drwxr-xr-x root:root
/etc/sos/extras.d                          drwxr-xr-x root:root
/etc/sos/presets.d                         drwxr-xr-x root:root
```

Attacker writes to each root hook/config/state location failed with `Permission denied`.

## Attacker Trigger Evidence

Commands were run as `uid=1001(attacker)`.

```sh
touch /etc/landscape/attacker-write
touch /var/lib/landscape/attacker-write
touch /var/log/landscape/attacker-write
touch /var/lib/command-not-found/attacker-write
touch /var/lib/apt/lists/attacker-write
touch /etc/update-manager/release-upgrades.d/attacker-write
touch /var/lib/ubuntu-release-upgrader/attacker-write
touch /var/lib/update-manager/attacker-write
touch /usr/share/package-data-downloads/attacker-write
touch /var/lib/update-notifier/package-data-downloads/attacker-write
touch /var/lib/update-notifier/user.d/attacker-write
touch /etc/sos/extras.d/attacker-write
touch /etc/sos/presets.d/attacker-write
```

All returned `rc=1` and `Permission denied`.

Root service/systemd triggers:

```sh
systemctl start update-notifier-motd.service
systemctl start update-notifier-download.service
systemctl set-environment PATH=/home/attacker/bin:/usr/bin:/bin
```

Observed:

```text
Failed to start update-notifier-motd.service: Interactive authentication required.
Failed to start update-notifier-download.service: Interactive authentication required.
Failed to set environment: Access denied
```

Unprivileged helper execution:

```sh
/usr/lib/command-not-found -- server-support-nonexistent-cmd
/usr/bin/do-release-upgrade --check-dist-upgrade-only -q
/usr/bin/sos report --batch --tmp-dir /tmp/server-support-sos --only host --quiet
/etc/update-motd.d/50-landscape-sysinfo
/etc/update-motd.d/91-release-upgrade
```

Observed:

```text
command-not-found rc=127; ran as attacker only.
do-release-upgrade --check-dist-upgrade-only rc=1; no privilege transition.
sos report rc=1; "Could not initialize 'report': Component must be run with root privileges".
landscape-sysinfo MOTD hook rc=0; produced sysinfo as attacker and could not create root-owned cache.
91-release-upgrade rc=0; zero stdout/stderr for non-root due root check.
root marker: absent
```

## Cleanup

Temporary files removed:

```text
/tmp/server-support-sos
/tmp/server-support-probe
/tmp/cnf.out
/tmp/dru.out
/tmp/sos.out
/tmp/landscape.out
/tmp/landscape.err
/tmp/release-motd.out
/tmp/release-motd.err
```

Final state:

```text
systemctl is-system-running: running
id attacker: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
No attacker-created root-path residue under the probed paths.
```

## Why Generic Scanners May Mis-rank This Surface

* `50-landscape-sysinfo` and `check-new-release` appear as `0777` in naive scans because they are symlinks; target resolution shows root-owned executable targets.
* `sos` inserts `os.getcwd()` into `sys.path`, which is a real footgun if root manually runs it from attacker-controlled cwd, but there is no default root daemon/timer/hook invoking it.
* `package-data-downloader` executes hook-defined scripts as root, but the default hook directory is root-owned and empty.
* `command-not-found` has both root apt hooks and shell hooks; the root hook consumes root-owned apt metadata, while shell hooks run in the unprivileged user's context.
* Release upgrader code has privileged helper paths and polkit actions, but default server state requires admin authentication and uid1001 cannot alter root service environment or state.

## Suggested Hardening

* Keep `/usr/share/package-data-downloads` root-owned and verify hook files are regular, root-owned, non-writable files before executing their `Script` entries.
* In distro-packaged `/usr/bin/sos` and `/usr/bin/sosreport`, avoid adding `os.getcwd()` to `sys.path` unless an explicit developer-mode guard is present.
* In `landscape-sysinfo.wrapper`, use absolute paths or set a safe `PATH` before executing common utilities, and consider writing the cache through a root-owned temp file plus atomic rename.
* Continue requiring `auth_admin` for release-upgrader polkit actions and keep `pkexec` absent from minimal/server default where not needed.
* Keep command-not-found databases and apt list inputs root-owned; consider isolated Python mode for root apt hooks to reduce import-path surprises.

## Conclusion

This package slice contains root hooks and helper execution points, but every default path either runs only as uid1001, requires admin authorization, consumes root-owned state, or has no default root trigger. No `uid=1001(attacker)` to root escalation was validated, so no finding note or PoC was created.
