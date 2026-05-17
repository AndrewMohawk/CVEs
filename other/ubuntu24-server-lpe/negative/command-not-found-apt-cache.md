# command-not-found / APT cache helper audit negative

Date: 2026-05-16
Target: Docker container `ubuntu24-server-lpe-target`
Image: `ubuntu24-server-default-lpe:20260516-standard`
Result: no uid1001-to-root LPE found in command-not-found, cnf-update-db, APT post-update hooks, AppStream cache refresh, PackageKit cache notification, or user-triggered shell command-not-found execution.

## Default package/version/reachability

Container identity and OS:

```text
uid=0(root) gid=0(root) groups=0(root)
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble
attacker:x:1001:1001::/home/attacker:/bin/bash
```

Relevant package versions:

```text
appstream                 1.0.2-1build6
apt                       2.8.3
apt-utils                 2.8.3
command-not-found         23.04.0
packagekit                1.2.8-2ubuntu1.5
python3-commandnotfound   23.04.0
update-notifier-common    3.192.68.2
```

Shell reachability is enabled for interactive users:

```text
/etc/bash.bashrc:56:# if the command-not-found package is installed, use it
/etc/bash.bashrc:58: function command_not_found_handle {
/etc/bash.bashrc:61:    /usr/lib/command-not-found -- "$1"
/etc/zsh_command_not_found:9: function command_not_found_handler {
/etc/zsh_command_not_found:11: /usr/lib/command-not-found -- ${1+"$1"} && :
```

APT root/package-maintainer interaction:

```text
/etc/apt/apt.conf.d/50command-not-found:
APT::Update::Post-Invoke-Success {
    "if /usr/bin/test -w /var/lib/command-not-found/ -a -e /usr/lib/cnf-update-db; then /usr/lib/cnf-update-db > /dev/null; fi";
};

/etc/apt/apt.conf.d/50appstream:
APT::Update::Post-Invoke-Success {
    "if /usr/bin/test -w /var/cache/swcatalog -a -e /usr/bin/appstreamcli; then appstreamcli refresh --source=os > /dev/null || true; fi";
};

/etc/apt/apt.conf.d/20packagekit:
APT::Update::Post-Invoke-Success and DPkg::Post-Invoke call PackageKit StateHasChanged cache-update over system D-Bus.
```

Root timer context:

```text
apt-daily.timer -> apt-daily.service -> /usr/lib/apt/apt.systemd.daily update
apt-daily-upgrade.timer -> apt-daily-upgrade.service -> /usr/lib/apt/apt.systemd.daily install
update-notifier-download.timer and update-notifier-motd.timer are present.

APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Enable "0";   # set by /etc/apt/apt.conf.d/docker-disable-periodic-update in this container
```

## Code and permissions

Critical path permissions:

```text
-rw-r--r-- root root 644 /etc/apt/apt.conf.d/50command-not-found
-rw-r--r-- root root 644 /etc/apt/apt.conf.d/50appstream
-rw-r--r-- root root 644 /etc/apt/apt.conf.d/20packagekit
-rwxr-xr-x root root 755 /usr/lib/command-not-found
-rwxr-xr-x root root 755 /usr/lib/cnf-update-db
drwxr-xr-x root root 755 /usr/lib/python3/dist-packages/CommandNotFound
-rw-r--r-- root root 644 /usr/lib/python3/dist-packages/CommandNotFound/CommandNotFound.py
-rw-r--r-- root root 644 /usr/lib/python3/dist-packages/CommandNotFound/db/creator.py
drwxr-xr-x root root 755 /var/lib/command-not-found
-rw-r--r-- root root 644 /var/lib/command-not-found/commands.db
-rw-r--r-- root root 644 /var/lib/command-not-found/commands.db.metadata
drwxr-xr-x root root 755 /var/lib/apt/lists
drwx------ _apt root 700 /var/lib/apt/lists/partial
drwxr-xr-x root root 755 /var/cache/swcatalog
drwxr-xr-x root root 755 /var/lib/swcatalog/yaml
```

`/usr/lib/cnf-update-db` uses the fixed DB path from `CommandNotFound.dbpath`, exits if that directory is not writable by the current uid, and reads only `/var/lib/apt/lists/*Commands-*` unless CNF index targets are disabled. `DbCreator.create()` writes `/var/lib/command-not-found/commands.db.tmp`, renames it over `commands.db`, and writes `commands.db.metadata`; the directory is not attacker-writable. Command metadata parsing uses `/usr/lib/apt/apt-helper cat-file <root-owned-list-file>` and inserts package/command strings into sqlite with parameterized inserts, not shell execution.

The user command-not-found path reads `/var/lib/command-not-found/commands.db`, optionally calls hardcoded `/usr/bin/snap advise-snap`, and its optional install prompt runs `subprocess.call(install_command.split(), shell=False)`. It executes as the invoking shell uid.

The AppStream catalog path is root-owned. `/var/lib/swcatalog/yaml/*Components-arm64.yml.gz` entries are symlinks to root-owned `/var/lib/apt/lists/*_dep11_Components-arm64.yml.gz`, and `/var/cache/swcatalog/cache/*.xb` is root-owned `0644` under root-owned `0755` directories.

## uid1001 attacker trigger results

Attacker identity:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
sudo: a password is required
sudo_rc=1
```

Writable insertion attempts all failed:

```text
touch /var/lib/command-not-found/uid1001-write-test
=> Permission denied

printf x > /var/lib/apt/lists/UID1001_cnf_Commands-arm64
=> Permission denied

touch /var/cache/swcatalog/uid1001-write-test
=> Permission denied

touch /var/lib/swcatalog/yaml/uid1001-write-test
=> Permission denied
```

Interactive shell trigger stayed uid1001:

```text
bash -ic 'id >&2; definitely_missing_uid1001_command_xyz'
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
definitely_missing_uid1001_command_xyz: command not found
rc=127
```

Known-command advice did not grant install rights:

```text
/usr/lib/command-not-found -- ifconfig
Command 'ifconfig' not found, but can be installed with:
apt install net-tools
Please ask your administrator.
rc=127
```

`PYTHONPATH` can affect the user-invoked Python helper, but only in the attacker's process:

```text
PYTHONPATH=/home/attacker/cnfpy /usr/lib/command-not-found -- missing_py_hijack
marker:
module import uid=1001 euid=1001
advise uid=1001 euid=1001 command=missing_py_hijack
attacker attacker 664 /tmp/cnf-py-hit
```

Default `apt-get update` as uid1001 did not reach root hooks:

```text
rc=100
Reading package lists...
E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)
E: Unable to lock directory /var/lib/apt/lists/
```

An attacker-owned APT state/cache update fetched metadata as uid1001 but still did not cross the command-not-found hook gate because the hook tests writability of the real root-owned `/var/lib/command-not-found/`:

```text
PYTHONPATH=/home/attacker/cnfpy apt-get update \
  -o Dir::State=/home/attacker/aptstate \
  -o Dir::State::status=/var/lib/dpkg/status \
  -o Dir::Cache=/home/attacker/aptcache \
  -o Debug::NoLocking=1

Fetched 48.6 MB in 3s
Reading package lists...
hook_marker:
cat: /tmp/cnf-root-hook-hit: No such file or directory
ls: cannot access '/tmp/cnf-root-hook-hit': No such file or directory
ls: cannot access '/var/lib/command-not-found/commands.db.tmp': No such file or directory
```

Direct `cnf-update-db` as uid1001 imported attacker-controlled Python only as uid1001 and exited before DB creation:

```text
PYTHONPATH=/home/attacker/cnfpy /usr/lib/cnf-update-db --verbose
datbase directory /var/lib/command-not-found/commands.db not writable
marker:
module import uid=1001 euid=1001
creator import uid=1001 euid=1001
cat: /tmp/cnf-root-hook-hit: No such file or directory
root root 755 /var/lib/command-not-found
root root 644 /var/lib/command-not-found/commands.db
root root 644 /var/lib/command-not-found/commands.db.metadata
```

Direct AppStream refresh as uid1001 stayed user-scoped:

```text
appstreamcli refresh --source=os --verbose
Only refreshing metadata cache specific to the current user.
Updating software metadata cache for the operating system.
Using cache file: /var/cache/swcatalog/cache/C-os-catalog.xb
Using cache file: /var/cache/swcatalog/cache/C-local-metainfo.xb
Metadata cache update is not necessary.
```

## Cleanup

Probe cleanup removed attacker test modules, attacker APT state/cache directories, temporary markers, and the malformed first-pass `/tmp/cnf_uid1001_probe.sh`. Final check:

```text
ls: cannot access '/home/attacker/cnfpy': No such file or directory
ls: cannot access '/home/attacker/aptstate': No such file or directory
ls: cannot access '/home/attacker/aptcache': No such file or directory
ls: cannot access '/var/lib/command-not-found/uid1001-write-test': No such file or directory
ls: cannot access '/var/lib/apt/lists/UID1001_cnf_Commands-arm64': No such file or directory
ls: cannot access '/var/cache/swcatalog/uid1001-write-test': No such file or directory
ls: cannot access '/var/lib/swcatalog/yaml/uid1001-write-test': No such file or directory
ls: cannot access '/tmp/cnf_uid1001_probe.sh': No such file or directory
```

Conclusion: the reachable root-owned maintenance paths are real, but the stock install does not expose a uid1001-controlled write/input boundary into their root execution. User-triggered command-not-found execution is attacker-context only; APT/AppStream/cache-update helpers are root-owned and only root/package-maintainer/timer contexts can update the shared caches.
