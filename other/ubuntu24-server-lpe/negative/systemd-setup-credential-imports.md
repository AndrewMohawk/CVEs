# systemd setup credential imports and early-boot state: negative

## Scope and target

- Target: `ubuntu24-server-lpe-target`
- OS: Ubuntu 24.04.4 LTS (`noble`)
- Package versions:
  - `systemd 255.4-1ubuntu8.15`
  - `systemd-sysv 255.4-1ubuntu8.15`
  - `udev 255.4-1ubuntu8.15`
  - `dbus 1.14.10-4ubuntu4.1`
  - `polkitd 124-2ubuntu1.24.04.3`
  - `libc-bin 2.39-0ubuntu8.7`
- Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`
- Result: no uid1001 -> root local privilege escalation found.

## Default-install and default-reachability proof

The audited units are present in the stock server target:

```text
ldconfig.service                             static
systemd-firstboot.service                    static
systemd-hwdb-update.service                  static
systemd-journal-catalog-update.service       static
systemd-machine-id-commit.service            static
systemd-random-seed.service                  static
systemd-sysusers.service                     static
systemd-tmpfiles-setup-dev-early.service     static
systemd-tmpfiles-setup-dev.service           static
systemd-tmpfiles-setup.service               static
systemd-update-done.service                  static
```

Boot state in the live Docker target:

```text
systemd-sysusers.service                 loaded active   exited
systemd-tmpfiles-setup-dev-early.service loaded active   exited
systemd-tmpfiles-setup-dev.service       loaded active   exited
systemd-tmpfiles-setup.service           loaded active   exited
systemd-update-done.service              loaded active   exited
systemd-journal-catalog-update.service   loaded active   exited
ldconfig.service                         loaded active   exited
systemd-firstboot.service                loaded inactive dead
systemd-random-seed.service              loaded inactive dead
systemd-machine-id-commit.service        loaded inactive dead
systemd-hwdb-update.service              loaded inactive dead
```

The inactive units are condition-gated in the default container state:

- `systemd-firstboot.service`: skipped by `ConditionFirstBoot=yes`.
- `systemd-random-seed.service`: skipped by `ConditionVirtualization=!container`.
- `systemd-machine-id-commit.service`: skipped by `ConditionPathIsMountPoint=/etc/machine-id`.
- `systemd-hwdb-update.service`: skipped by its update/input conditions.

## Code/config trust boundaries checked

Credential-importing setup units:

- `/usr/lib/systemd/system/systemd-sysusers.service`
  - line 14: `ConditionNeedsUpdate=|/etc`
  - line 15: `ConditionCredential=|sysusers.extra`
  - line 28: `ExecStart=systemd-sysusers`
  - lines 34-39: imports `passwd.hashed-password.root`, `passwd.plaintext-password.root`, `passwd.shell.root`, and `sysusers.*`
- `/usr/lib/systemd/system/systemd-tmpfiles-setup.service`
  - line 24: `ExecStart=systemd-tmpfiles --create --remove --boot --exclude-prefix=/dev`
  - lines 26-30: imports `tmpfiles.*`, `login.motd`, `login.issue`, `network.hosts`, and `ssh.authorized_keys.root`
- `/usr/lib/systemd/system/systemd-tmpfiles-setup-dev.service`
  - line 24: `ExecStart=systemd-tmpfiles --prefix=/dev --create --boot`
  - line 26: `ImportCredential=tmpfiles.*`
- `/usr/lib/systemd/system/systemd-tmpfiles-setup-dev-early.service`
  - line 23: `ExecStart=systemd-tmpfiles --prefix=/dev --create --boot --graceful`
  - line 25: `ImportCredential=tmpfiles.*`
- `/usr/lib/systemd/system/systemd-firstboot.service`
  - lines 14-15: `/etc` writable and first-boot conditions
  - line 34: prompts for locale/timezone/root password
  - lines 42-45: imports root password/shell credentials and `firstboot.*`

Credential-consuming tmpfiles rules:

- `/usr/lib/tmpfiles.d/provision.conf`
  - line 13: `f^ /etc/motd.d/50-provision.conf ... login.motd`
  - line 14: `f^ /etc/issue.d/50-provision.conf ... login.issue`
  - line 17: `f^ /etc/hosts ... network.hosts`
  - lines 20-22: creates `/root/.ssh/authorized_keys` from `ssh.authorized_keys.root`
- `/usr/lib/tmpfiles.d/credstore.conf`
  - lines 10-13: `/etc/credstore`, `/etc/credstore.encrypted`, `/run/credstore`, and `/run/credstore.encrypted` are root-owned `0700`

Other setup one-shots:

- `/usr/lib/systemd/system/systemd-random-seed.service`
  - line 14: `ConditionVirtualization=!container`
  - line 20: `RequiresMountsFor=/var/lib/systemd/random-seed`
  - lines 28-29: load/save random seed
- `/usr/lib/systemd/system/systemd-machine-id-commit.service`
  - lines 17-18: requires writable `/etc` and `/etc/machine-id` as a mount point
  - line 23: `systemd-machine-id-setup --commit`
- `/usr/lib/systemd/system/systemd-update-done.service`
  - lines 17-18: `ConditionNeedsUpdate=|/etc` and `|/var`
  - line 23: `/usr/lib/systemd/systemd-update-done`
- `/usr/lib/systemd/system/systemd-journal-catalog-update.service`
  - line 14: `ConditionNeedsUpdate=/var`
  - line 25: `journalctl --update-catalog`
- `/usr/lib/systemd/system/systemd-hwdb-update.service`
  - lines 14-17: update/input conditions
  - line 28: `systemd-hwdb update`
- `/usr/lib/systemd/system/ldconfig.service`
  - lines 14-15: update/cache conditions
  - line 26: `/sbin/ldconfig -X`

## Attacker trigger attempts

Credential/config/state writes were denied. Representative uid1001 attempts:

```sh
mkdir -p /run/credentials/systemd-sysusers.service
mkdir -p /run/credentials/systemd-tmpfiles-setup.service
mkdir -p /run/credentials/systemd-firstboot.service
printf x > /etc/sysusers.d/LPE_SETUP.conf
printf x > /usr/lib/sysusers.d/LPE_SETUP.conf
printf x > /etc/tmpfiles.d/LPE_SETUP.conf
printf x > /usr/lib/tmpfiles.d/LPE_SETUP.conf
printf x > /etc/udev/hwdb.d/99-lpe-setup.hwdb
printf x > /etc/ld.so.conf.d/lpe-setup.conf
printf x > /var/lib/systemd/random-seed
printf x > /var/lib/systemd/catalog/database
printf x > /etc/systemd/system/lpe-setup.service
```

All failed with `Permission denied` or parent-directory creation denied. The relevant live modes were:

```text
drwxr-xr-x root:root /run/credentials
drwx------ root:root /etc/credstore
drwx------ root:root /etc/credstore.encrypted
drwxr-xr-x root:root /usr/lib/sysusers.d
drwxr-xr-x root:root /etc/tmpfiles.d
drwxr-xr-x root:root /usr/lib/tmpfiles.d
drwxr-xr-x root:root /etc/udev/hwdb.d
drwxr-xr-x root:root /usr/lib/udev/hwdb.d
drwxr-xr-x root:root /etc/ld.so.conf.d
drwxr-xr-x root:root /var/lib/systemd
-rw-r--r-- root:root /etc/machine-id
-rw-r--r-- root:root /etc/.updated
-rw-r--r-- root:root /var/.updated
```

System manager triggers were denied:

```sh
systemctl restart systemd-sysusers.service
systemctl restart systemd-tmpfiles-setup.service
systemctl restart systemd-tmpfiles-setup-dev.service
systemctl restart systemd-tmpfiles-setup-dev-early.service
systemctl restart systemd-firstboot.service
systemctl restart systemd-random-seed.service
systemctl restart systemd-machine-id-commit.service
systemctl restart systemd-update-done.service
systemctl restart systemd-journal-catalog-update.service
systemctl restart systemd-hwdb-update.service
systemctl restart ldconfig.service
```

Each returned `Interactive authentication required`.

Manager environment/transient-unit mutation was also denied:

```sh
busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager SetEnvironment as 1 PATH=/tmp
# Call failed: Access denied

systemd-run --system --unit=lpe-setup-transient /bin/sh -c 'id > /root/LPE_SETUP_TRANSIENT'
# Failed to start transient service unit: Interactive authentication required.
```

Direct helper execution as uid1001 did not cross privilege:

```sh
systemd-sysusers /tmp/lpe-setup-sysusers.conf
# Failed to take /etc/passwd lock: Permission denied

systemd-tmpfiles --create /tmp/lpe-setup-tmpfiles.conf
# Failed to create file /root/LPE_SETUP_CREDENTIAL_IMPORT_MARKER: Permission denied

CREDENTIALS_DIRECTORY=/tmp/lpe-setup-creds systemd-tmpfiles --create
# read attacker-supplied credentials, but failed to create /root/.ssh and /root marker

CREDENTIALS_DIRECTORY=/tmp/lpe-setup-creds systemd-sysusers
# Failed to take /etc/passwd lock: Permission denied

systemd-firstboot --force --root-password=lpesetup
# Failed to take a lock on /etc/passwd: Permission denied

/usr/lib/systemd/systemd-update-done
# Failed to write "/etc/.updated" and "/var/.updated": Permission denied

journalctl --update-catalog
# Failed to open/write /var/lib/systemd/catalog/database: Permission denied

systemd-hwdb update
# Failed to write database /etc/udev/hwdb.bin: Permission denied

/sbin/ldconfig -X
# Can't create temporary cache file /etc/ld.so.cache~: Permission denied
```

`systemd-machine-id-setup --commit` returned `0` for uid1001, but it was a no-op in this state: the SHA256 of `/etc/machine-id` was unchanged before and after. uid1001 also could not make the required mount-point precondition:

```text
/etc/machine-id writable? no
/run/machine-id writable? no
mount tmpfs: DENIED must be superuser to use mount
```

The dynamic linker cache input paths were not attacker-writable:

```text
/etc/ld.so.conf:
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d/aarch64-linux-gnu.conf:
2 /usr/local/lib/aarch64-linux-gnu
3 /lib/aarch64-linux-gnu
4 /usr/lib/aarch64-linux-gnu

/etc/ld.so.conf.d/libc.conf:
2 /usr/local/lib
```

Live modes:

```text
drwxr-xr-x root:root /lib/aarch64-linux-gnu
drwxr-xr-x root:root /usr/lib/aarch64-linux-gnu
drwxr-xr-x root:root /usr/lib
drwxr-xr-x root:root /usr/local/lib
```

No configured `ldconfig` directory was writable by `attacker`.

## Root proof

No root context was obtained. The attempted root markers were absent:

```text
ABSENT /root/LPE_SETUP_CREDENTIAL_IMPORT_MARKER
ABSENT /root/LPE_SETUP_TRANSIENT
ABSENT /root/.ssh/authorized_keys
```

## Cleanup

No persistent target changes remained from this slice:

```text
find /tmp /run /etc /var/lib/systemd /root -xdev \
  \( -name '*LPE_SETUP*' -o -name 'lpe-setup*' -o -name 'setup_cred_probe.sh' \)
# no output

systemctl list-units --all 'lpe-setup*'
# 0 loaded units listed

systemctl is-system-running
# running

id attacker
# uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

## Why generic scanners can miss this

The interesting-looking surface is not a parser crash or a simple writable-file check. The units explicitly import credentials that, if supplied by root or a container manager, can create root accounts, root SSH keys, `/etc/hosts`, login banners, users, devices, and root-owned files. A scanner may flag those `ImportCredential=` and `f^ ... credential` paths as root-write primitives without proving who can seed the system manager credential store, who can write `/run/credentials/<unit>/`, and who can retrigger the root oneshot in the default booted state. In this target, each required boundary is root/systemd-manager controlled.

## Hardening notes

- Keep `/run/credentials`, `/etc/credstore*`, `/run/credstore*`, `/etc/sysusers.d`, `/run/sysusers.d`, `/etc/tmpfiles.d`, `/run/tmpfiles.d`, `/etc/udev/hwdb.d`, `/run/udev/hwdb.d`, and `/etc/ld.so.conf.d` root-owned and non-writable by normal users.
- Avoid adding `allow_active` polkit rules for restarting these setup one-shots; a restart can consume powerful credentials if a deployment system has seeded them.
- Consider monitoring non-root write attempts to `/run/credentials/*`, credential stores, and setup config directories, because successful writes there would be high-signal misconfiguration.
- Preserve absolute `ExecStart` paths for setup services where possible; Ubuntu's default systemd manager environment already prevented uid1001 `PATH` poisoning in this target.
