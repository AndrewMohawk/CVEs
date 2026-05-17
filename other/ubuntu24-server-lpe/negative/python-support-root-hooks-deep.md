# Negative: Python support root hook/plugin deep audit

Date: 2026-05-16
Target: Docker container `ubuntu24-server-lpe-target`
Image: `ubuntu24-server-default-lpe:20260516-standard`
Result: no validated uid1001-to-root local privilege escalation.

## Scope

Attacker:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
sudo: a password is required
```

This pass focused on default Python/maintainer/update support surfaces that either run from root timers/services or are exposed through local authenticated helper flows:

- `command-not-found` / `/usr/lib/cnf-update-db`
- `update-manager-core` and `update-notifier-common`
- `ubuntu-release-upgrader-core`
- `landscape-common`
- `sosreport`
- apport hook/plugin discovery, excluding the already-covered apport coredump bug class

The audit specifically checked root-executed hook/plugin discovery, Python module search paths and environment handling, writable cache/state directories, and package-maintainer trust boundaries.

## Default proof

OS and packages:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble

apport                         2.28.1-0ubuntu3.8             ii
apport-core-dump-handler       2.28.1-0ubuntu3.8             ii
apt                            2.8.3                         ii
command-not-found              23.04.0                       ii
landscape-common               24.02-0ubuntu5.7              ii
python3-apport                 2.28.1-0ubuntu3.8             ii
python3-commandnotfound        23.04.0                       ii
python3-distupgrade            1:24.04.28                    ii
python3-update-manager         1:24.04.12                    ii
sosreport                      4.10.2-0ubuntu0~24.04.1       ii
systemd                        255.4-1ubuntu8.15             ii
ubuntu-pro-client              37.2ubuntu~24.04              ii
ubuntu-release-upgrader-core   1:24.04.28                    ii
update-manager-core            1:24.04.12                    ii
update-notifier-common         3.192.68.2                    ii
```

Default root units/timers in this lane:

```text
apt-daily.timer                enabled
apt-daily-upgrade.timer        enabled
update-notifier-download.timer enabled
update-notifier-motd.timer     enabled
apport.service                 enabled, inactive in container: ConditionVirtualization=!container
apport-forward.socket          enabled, active, /run/apport.socket srw------- root:root
apport-autoreport.path/timer   enabled but inactive: /var/lib/apport/autoreport absent
apt-news.service               static, root Python helper started by root apt hooks
```

`systemctl show` for `apt-daily.service`, `update-notifier-download.service`, `update-notifier-motd.service`, `apt-news.service`, and `apport.service` showed `User=`, `Group=`, `Environment=`, and `WorkingDirectory=` empty. These are root oneshots with no attacker-provided unit environment or working directory.

In this Docker target, `/etc/apt/apt.conf.d/docker-disable-periodic-update:1` sets:

```text
APT::Periodic::Enable "0";
```

`/usr/lib/apt/apt.systemd.daily:355-360` reads that key and exits early when it is `0`. The unit is still root-reachable and starts successfully, but the periodic apt update body is disabled in this target.

No `landscape-client` package or landscape systemd service is installed. No sos systemd unit is installed.

`pkexec` is not installed. The installed polkit policies are therefore not executable through `pkexec` on this target.

## Writable state

As uid1001:

```text
NO_W /usr/share/package-data-downloads
NO_W /usr/lib/update-notifier
NO_W /usr/lib/ubuntu-release-upgrader
NO_W /usr/share/apport
NO_W /usr/share/apport/package-hooks
NO_W /usr/share/apport/general-hooks
NO_W /usr/share/apport/symptoms
NO_W /usr/lib/python3/dist-packages/CommandNotFound
NO_W /usr/lib/python3/dist-packages/DistUpgrade
NO_W /usr/lib/python3/dist-packages/UpdateManager
NO_W /usr/lib/python3/dist-packages/sos
NO_W /etc/sos
NO_W /var/lib/update-notifier
NO_W /var/lib/update-notifier/package-data-downloads
NO_W /var/lib/update-notifier/package-data-downloads/partial
NO_W /var/lib/ubuntu-release-upgrader
NO_W /var/lib/command-not-found
NO_W /var/lib/apport
W    /var/crash
W    /tmp
W    /var/tmp
```

No non-symlink world/group-writable files or directories were found under the audited package/config/state trees:

```sh
find /usr/share/package-data-downloads /usr/lib/update-notifier \
  /usr/lib/ubuntu-release-upgrader /usr/share/apport \
  /usr/lib/python3/dist-packages/CommandNotFound \
  /usr/lib/python3/dist-packages/DistUpgrade \
  /usr/lib/python3/dist-packages/UpdateManager \
  /usr/lib/python3/dist-packages/sos /etc/sos \
  /var/lib/update-notifier /var/lib/ubuntu-release-upgrader \
  /var/lib/command-not-found /var/lib/apport \
  -xdev -maxdepth 5 \( -perm -002 -o -perm -020 \) -not -type l -print
```

Observed output: empty.

Package-data downloader state:

```text
/usr/share/package-data-downloads                         drwxr-xr-x root:root, empty
/var/lib/update-notifier/package-data-downloads            drwxr-xr-x root:root
/var/lib/update-notifier/package-data-downloads/partial    drwx------ _apt:root
```

Apport hook inventory is package-owned: 22 package hooks, 8 general hooks, and 9 symptoms, all root-owned. `/etc/sos/{extras.d,presets.d,groups.d}` are root-owned `0755`.

## Code findings

### update-notifier package-data-downloader

Root reachability:

```text
update-notifier-download.timer -> update-notifier-download.service
ExecStart=/usr/lib/update-notifier/package-data-downloader
```

Root starts succeeded:

```text
systemctl start update-notifier-download.service
Result=success ExecMainStatus=0 User= Group=
```

Code boundary:

- `/usr/lib/update-notifier/package-data-downloader:36-37` hard-code `DATADIR=/usr/share/package-data-downloads/` and `STAMPDIR=/var/lib/update-notifier/package-data-downloads/`.
- `:161-169` enumerates files from `DATADIR`.
- `:179-195` downloads only into `STAMPDIR/partial` through `/usr/lib/apt/apt-helper download-file` with `SHA256:<hash>`.
- `:247-255` parses hook stanzas and uses the package-provided `Script` field as `command = [para['Script']]`.
- `:287-295` executes the command and removes downloaded files after success.

This is a real root command-execution primitive for package-maintainer-controlled hook files, not for uid1001. The hook directory is root-owned and empty, the stamp directory is root-owned, and the download partial directory is `_apt` `0700`.

### command-not-found and APT hooks

APT hook:

```text
/etc/apt/apt.conf.d/50command-not-found:14-15
APT::Update::Post-Invoke-Success {
    "if /usr/bin/test -w /var/lib/command-not-found/ -a -e /usr/lib/cnf-update-db; then /usr/lib/cnf-update-db > /dev/null; fi";
};
```

`/usr/lib/cnf-update-db`:

- `:19-23` initializes apt config, uses fixed `CommandNotFound.dbpath`, and exits if the DB directory is not writable.
- `:25-32` reads only `/var/lib/apt/lists/*Commands-*` or `*Contents*` and creates the DB.

`/usr/lib/python3/dist-packages/CommandNotFound/CommandNotFound.py:53` fixes the DB path at `/var/lib/command-not-found/commands.db`.

`/usr/lib/python3/dist-packages/CommandNotFound/db/creator.py`:

- `:92-113` writes `commands.db.tmp`, renames it into place, and writes metadata under `/var/lib/command-not-found`.
- `:139-146` reads apt list files through absolute `/usr/lib/apt/apt-helper cat-file`.
- `:151-178` inserts parsed strings with sqlite parameters, not shell execution.

Attacker cannot write `/var/lib/apt/lists`, `/var/lib/command-not-found`, or the root apt hook config. A uid1001 `PYTHONPATH` import hijack affects only uid1001 direct executions; the root systemd units have empty `Environment=` and uid1001 cannot run `systemctl set-environment`.

### update-manager/update-notifier MOTD helpers

`/usr/lib/update-notifier/update-motd-updates-available`:

- `:15` writes `/var/lib/update-notifier/updates-available`.
- `:20-25` reads apt config keys for state/status paths.
- `:49` uses `mktemp -p $(dirname "$stamp")`, which is `/var/lib/update-notifier`, not `/tmp`.
- `:62` runs absolute `/usr/lib/update-notifier/apt-check`.
- `:65-66` moves the temp file to the root-owned stamp and makes it readable.

`/usr/lib/update-notifier/apt-check` is a Python script with direct imports from the script/dist-package paths. A planted `/tmp/apt_check.py` did not get imported from cwd.

`/usr/lib/update-notifier/update-motd-hwe-eol:55-65` uses the same root-owned stamp-directory `mktemp` pattern. `/usr/lib/update-notifier/update-motd-fsck-at-reboot:82` writes to fixed `/var/lib/update-notifier/fsck-at-reboot`; uid1001 cannot replace that path.

### ubuntu-release-upgrader

Root timer:

```text
update-notifier-motd.timer -> update-notifier-motd.service
ExecStart=/usr/lib/ubuntu-release-upgrader/release-upgrade-motd
```

Root starts succeeded:

```text
systemctl start update-notifier-motd.service
Result=success ExecMainStatus=0 User= Group=
```

`/usr/lib/ubuntu-release-upgrader/release-upgrade-motd`:

- `:23` fixes the stamp at `/var/lib/ubuntu-release-upgrader/release-upgrade-available`.
- `:31` and `:39` run absolute `/usr/lib/ubuntu-release-upgrader/check-new-release -q > "$stamp"`.

`/usr/bin/do-release-upgrade`:

- `:85-87` accepts `--data-dir`, defaulting to `/usr/share/ubuntu-release-upgrader/`.
- `:98-100` accepts `--frontend`.
- `:223-230` accepts `--env`, but this is command-line-controlled by the caller, not read from a user-writable root service path.
- `:252` only re-execs through `/usr/bin/pkexec` for GUI frontends when non-root.

`/usr/lib/ubuntu-release-upgrader/do-partial-upgrade:91-97` similarly attempts `/usr/bin/pkexec` when non-root. On this target `pkexec` is absent, so uid1001 execution fails with `FileNotFoundError`.

DistUpgrade package-maintainer boundaries:

- `/usr/lib/python3/dist-packages/DistUpgrade/DistUpgradeConfigParser.py:30` defines the override dir as `/etc/update-manager/release-upgrades.d`.
- `:57-59` reads `*.cfg` from that root-owned override dir.
- `/usr/share/ubuntu-release-upgrader/DistUpgrade.cfg:39` defines `PostInstallScripts=./xorg_fix_proprietary.py`.
- `/etc/update-manager/release-upgrades.d/ubuntu-advantage-upgrades.cfg:4` adds Ubuntu Pro post-install scripts.
- `/usr/lib/python3/dist-packages/DistUpgrade/DistUpgradeController.py:2106-2114` executes configured post-install scripts.

Those scripts/configs are root-owned. uid1001 cannot add override config or replace the data dir used by the root timer. Passing a malicious `--data-dir` would require the attacker to already control a root/auth_admin release-upgrader invocation.

### apport hook discovery

`/usr/lib/python3/dist-packages/apport/report.py`:

- `:52-54` derives `GENERAL_HOOK_DIR` and `PACKAGE_HOOK_DIR` from `APPORT_DATA_DIR`, defaulting to `/usr/share/apport`.
- `:262-270` opens and `exec()`s a hook file.
- `:1105-1119` documents package/general hook execution.
- `:1134-1149` strips package/source package names and rejects `/` path traversal.
- `:1151-1192` searches general hooks, binary package hooks, source package hooks, and package-owned `/opt/.../share/apport/package-hooks`.

`/usr/lib/python3/dist-packages/apport/hookutils.py`:

- `:510-519` documents root command attachment through pkexec unless already root.
- `:524-527` builds `root_info_wrapper` from `APPORT_DATA_DIR`.
- `:528-544` uses a fresh `tempfile.mkdtemp()` workdir and runs `_root_command_prefix() + [wrapper_path, script_path]`.

Direct uid1001 probes confirmed that `APPORT_DATA_DIR` can redirect hooks only inside the uid1001 process:

```text
hook_report 1001
euid=1001 uid=1001
```

The `root_info_wrapper` path also remained uid1001 because `pkexec` is absent:

```text
caller 1001 1001
probe uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

The apport coredump daemon path drops privileges before writing report user data (`/usr/share/apport/apport:1195-1202`) and does not provide a default root-run `add_hooks_info()` path for attacker-supplied hook directories in this target. `/run/apport.socket` is `0600 root:root`, and `/var/lib/apport/autoreport` is absent.

### sosreport / sos

`/usr/bin/sos:14-15` and `/usr/bin/sosreport:19-20` insert `os.getcwd()` at the front of `sys.path` before importing `sos`. That is an unsafe operator-root pattern if root runs `sos` from an attacker-controlled directory.

Default reachability does not cross privilege:

```text
cd /tmp/sos-cwd-hijack; /usr/bin/sos report --help
sos_rc:77
euid=1001 uid=1001

cd /home/attacker; /usr/bin/sos report --batch --dry-run
sos_direct_clean_rc:1
Could not initialize 'report': Component must be run with root privileges
```

No default root timer/service invokes `sos`.

Sos plugin/config discovery is package/admin controlled:

- `/usr/lib/python3/dist-packages/sos/report/__init__.py:855-907` imports and loads installed plugins from the package tree.
- `/usr/lib/python3/dist-packages/sos/report/plugins/sos_extras.py:42` fixes extras at `/etc/sos/extras.d/`.
- `sos_extras.py:47-53` skips extras if the directory is not root-owned or is group/world-writable.
- `sos_extras.py:59-86` executes commands from extras files only after that directory ownership/mode check.

`/etc/sos/extras.d`, `/etc/sos/presets.d`, and `/etc/sos/groups.d` are root-owned `0755`.

### landscape-common

No `landscape-client` package or root service is present. The installed MOTD/sysinfo helper was inspected only for missed Python path/config issues.

`/usr/bin/landscape-sysinfo:6-13` inserts `./` into `sys.path` only when `argv[0]` is under a `scripts` directory, i.e. the development checkout case. A cwd `landscape` module planted by uid1001 did not import under the installed `/usr/bin/landscape-sysinfo`.

`/usr/lib/python3/dist-packages/landscape/sysinfo/deployment.py:34-38` uses `/etc/landscape/client.conf` by default, and only adds `~/.landscape/sysinfo.conf` when `os.getuid() != 0`.

`/usr/share/landscape/landscape-sysinfo.wrapper:5` fixes the cache at `/var/lib/landscape/landscape-sysinfo.cache`; `:25-29` invokes absolute `/usr/bin/landscape-sysinfo`, writes the cache, and chmods it. uid1001 is not in group `landscape` and cannot write `/etc/landscape`, `/var/lib/landscape`, or `/var/log/landscape`.

### local authenticated helper policies

`pkexec` is missing, so none of these policies are executable through pkexec on this target.

Relevant policy boundaries:

```text
com.ubuntu.apport.root-info
  exec=/usr/share/apport/root_info_wrapper
  allow_any/allow_inactive/allow_active = auth_admin

com.ubuntu.release-upgrader.release-upgrade
  exec=/usr/bin/do-release-upgrade
  allow_any=no allow_inactive=no allow_active=auth_admin

com.ubuntu.release-upgrader.partial-upgrade
  exec=/usr/lib/ubuntu-release-upgrader/do-partial-upgrade
  allow_any=no allow_inactive=no allow_active=auth_admin

com.ubuntu.update-notifier.pkexec.cddistupgrader
  exec=/usr/lib/update-notifier/cddistupgrader
  allow_any/allow_inactive/allow_active = auth_admin

com.ubuntu.update-notifier.pkexec.package-system-locked
  exec=/usr/lib/update-notifier/package-system-locked
  allow_any=no allow_inactive=yes allow_active=yes
```

`/usr/lib/update-notifier/package-system-locked:6-16` only checks fixed apt/dpkg lock files with `fuser` and exits `0`, `1`, or `2`. Direct uid1001 execution stayed uid1001.

`/usr/lib/update-notifier/cddistupgrader:17-31` uses `mktemp -t -d distupgrade.XXXXXX`, extracts a CD-ROM upgrader tarball, applies package-owned patches, and executes the extracted upgrader. It is `auth_admin` gated in policy and `pkexec` is absent. Direct uid1001 execution without a CD-ROM argument created an attacker-owned `/tmp/distupgrade.*` and failed; the temp dir was cleaned up.

## Trigger attempts

uid1001 could not write hook/config/state insertion points:

```text
/usr/share/package-data-downloads/uid1001.hook: Permission denied
/usr/share/apport/general-hooks/uid1001.py: Permission denied
/usr/share/apport/package-hooks/source_uid1001.py: Permission denied
/usr/share/apport/symptoms/uid1001.py: Permission denied
/etc/sos/extras.d/uid1001: Permission denied
/etc/sos/presets.d/uid1001: Permission denied
/etc/update-manager/release-upgrades.d/uid1001.cfg: Permission denied
/usr/lib/update-notifier/uid1001: Permission denied
/usr/lib/ubuntu-release-upgrader/uid1001: Permission denied
/var/lib/update-notifier/package-data-downloads/uid1001: Permission denied
/var/lib/ubuntu-release-upgrader/release-upgrade-available: Permission denied
/var/lib/command-not-found/commands.db.tmp: Permission denied
/var/lib/apport/autoreport: Permission denied
```

uid1001 could not start root units or alter the system manager environment:

```text
systemctl start apt-daily.service
  Failed to start apt-daily.service: Interactive authentication required.

systemctl start update-notifier-download.service
  Failed to start update-notifier-download.service: Interactive authentication required.

systemctl start update-notifier-motd.service
  Failed to start update-notifier-motd.service: Interactive authentication required.

systemctl start apt-news.service
  Failed to start apt-news.service: Interactive authentication required.

systemctl set-environment PYTHONPATH=/home/attacker/pwn ...
  Failed to set environment: Access denied
```

Direct helper attempts:

```text
command -v pkexec || echo pkexec:MISSING
pkexec:MISSING

/usr/bin/do-release-upgrade -c -q
do_release_rc:1

/usr/lib/ubuntu-release-upgrader/do-partial-upgrade --data-dir=/tmp/nonexistent
FileNotFoundError: [Errno 2] No such file or directory
partial_rc:1

/usr/lib/update-notifier/package-system-locked
pkg_locked_rc:0

/usr/lib/update-notifier/cddistupgrader
cddist_rc:127
```

Python/CWD probes:

```text
PYTHONPATH=/tmp/py-support-hijack /usr/lib/command-not-found -- definitely_missing_py_support_test
user_cnf_rc:1
marker euid: 1001

marker_absent_before_root
systemctl start apt-news.service
systemctl start update-notifier-download.service
no_root_unit_py_marker

cd /tmp; planted apt_check.py; /usr/lib/update-notifier/apt-check --human-readable
aptcheck_rc:0
no_marker

cd /tmp/landscape-cwd; planted landscape/__init__.py; /usr/bin/landscape-sysinfo
landscape_rc:0
no_marker
```

Root service starts performed by root for reachability proof all returned success and did not consume attacker-controlled module or hook paths.

## Cleanup

Removed probe artifacts from the target:

```text
/tmp/py-support-hijack
/tmp/py-support-markers
/tmp/apport-hook-hijack
/tmp/apport-hook-marker
/tmp/apport-root-wrapper
/tmp/apport-root-wrapper-hit
/tmp/sos-cwd-hijack
/tmp/sos-cwd-marker
/tmp/sos-*.out
/tmp/landscape-cwd
/tmp/landscape-marker
/tmp/apt-check-hijack.out
/tmp/update-motd-aptcheck-marker
/tmp/apt_check.py
/tmp/distupgrade.*
/tmp/root-unit-py-hijack
/tmp/root-unit-py-marker
```

Post-cleanup `find /tmp -maxdepth 1` for those probe name patterns returned no entries.

## Scanner-miss notes

- `package-data-downloader` should be flagged as a package-maintainer trust boundary, not a normal-user LPE: `Script` execution is root, but hook files live in root-owned `/usr/share/package-data-downloads`, empty by default.
- `APPORT_DATA_DIR` is environment-controlled hook discovery, but direct uid1001 use runs hooks as uid1001. Root escalation would require a root/apport/pkexec path that preserves attacker-controlled `APPORT_DATA_DIR`; none is present by default here.
- `sos` and `sosreport` have a real cwd import hazard for an already-root operator running from an attacker directory. There is no default timer/service/pkexec path from uid1001 to root `sos`.
- DistUpgrade `PostInstallScripts`, `--data-dir`, and config override handling are root/admin/package controlled. uid1001 cannot write `/etc/update-manager/release-upgrades.d` or the default data dir, and `pkexec` is absent.
- `mktemp` hits in this lane were either safe random directories in `/tmp` used by uid1001 direct execution, or files created under root-owned stamp directories. No predictable root tmp-file overwrite was found.
- Root units in scope do not set attacker-controlled `PYTHONPATH`, `APPORT_DATA_DIR`, `TMPDIR`, `PATH`, or `WorkingDirectory`. uid1001 cannot set the system manager environment or start those units.
- `/var/crash` remains writable, but the apport coredump path was intentionally not re-reported here; this pass found no separate root hook/plugin discovery primitive reachable from `/var/crash`.
