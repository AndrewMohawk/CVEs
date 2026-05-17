# Negative: MOTD, landscape-common, and update-notifier timers

Scope: stock Ubuntu 24.04 Server default install in Docker container `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, starting from unprivileged uid 1001 `attacker`.

Result: no validated uid1001-to-root local privilege escalation. The default root-run paths are reachable, but every executable/config/cache path that can affect those root runs is root-owned or service-user-owned and not writable by uid1001. Direct uid1001 execution only runs as uid1001, and uid1001 cannot start the root systemd services or reach `pam_motd` through a setuid login path.

## Default package and unit proof

```text
base-files                         13ubuntu10.4          ii
cron                               3.0pl1-184ubuntu2     ii
landscape-common                   24.02-0ubuntu5.7      ii
libpam-modules:arm64               1.5.3-5ubuntu5.5      ii
libpam-runtime                     1.5.3-5ubuntu5.5      ii
libpam0g:arm64                     1.5.3-5ubuntu5.5      ii
python3-update-manager             1:24.04.12            ii
systemd                            255.4-1ubuntu8.15     ii
ubuntu-release-upgrader-core       1:24.04.28            ii
update-manager-core                1:24.04.12            ii
update-notifier-common             3.192.68.2            ii
```

Default relevant units/timers:

```text
motd-news.timer                    enabled
motd-news.service                  static
  ExecStart=/etc/update-motd.d/50-motd-news --force

update-notifier-download.timer     enabled
update-notifier-download.service   static
  ExecStart=/usr/lib/update-notifier/package-data-downloader

update-notifier-motd.timer         enabled
update-notifier-motd.service       static
  ExecStart=/usr/lib/ubuntu-release-upgrader/release-upgrade-motd

apt-news.service                   static
  ExecStart=/usr/bin/python3 /usr/lib/ubuntu-advantage/apt_news.py
```

Root reachability was proven in-container:

```text
run-parts --lsbsysinit /etc/update-motd.d
  rc=0
  created /var/lib/landscape/landscape-sysinfo.cache as root:root 0644 during the probe

systemctl start motd-news.service
  rc=0, Result=success, User= empty/root

systemctl start update-notifier-motd.service
  rc=0, Result=success, User= empty/root

systemctl start update-notifier-download.service
  rc=0, Result=success, User= empty/root
```

`pam_motd` is present only in `/etc/pam.d/login`:

```text
/etc/pam.d/login:33 session optional pam_motd.so motd=/run/motd.dynamic
/etc/pam.d/login:34 session optional pam_motd.so noupdate
/etc/pam.d/sshd MISSING
openssh-server uninstalled
/usr/bin/login -rwxr-xr-x root:root, not setuid
```

## Code and permission evidence

Landscape MOTD path:

```text
/etc/update-motd.d/50-landscape-sysinfo -> /usr/share/landscape/landscape-sysinfo.wrapper
/usr/share/landscape/landscape-sysinfo.wrapper  -rwxr-xr-x root:root
/usr/bin/landscape-sysinfo                      -rwxr-xr-x root:root
/usr/lib/python3/dist-packages/landscape         drwxr-xr-x root:root
/etc/landscape                                   drwxrwxr-x root:landscape
/var/lib/landscape                               drwxr-xr-x landscape:landscape
/var/log/landscape                               drwxr-xr-x landscape:landscape
```

The wrapper hard-codes `CACHE=/var/lib/landscape/landscape-sysinfo.cache`, runs `/usr/bin/landscape-sysinfo`, then writes and chmods the cache. uid1001 is not in group `landscape`, so it cannot plant the cache or replace the wrapper/config. `landscape-sysinfo` root runs load only `/etc/landscape/client.conf`; user config `~/.landscape/sysinfo.conf` is added only when `os.getuid() != 0`.

MOTD/news/update-notifier cache paths:

```text
/etc/update-motd.d                                drwxr-xr-x root:root
/etc/update-motd.d/50-motd-news                  -rwxr-xr-x root:root
/etc/default/motd-news                           -rw-r--r-- root:root
/var/cache/motd-news                             -rw-r--r-- root:root
/var/lib/update-notifier                         drwxr-xr-x root:root
/var/lib/update-notifier/updates-available       -rw-r--r-- root:root
/var/lib/update-notifier/package-data-downloads  drwxr-xr-x root:root
/var/lib/update-notifier/package-data-downloads/partial drwx------ _apt:root
/var/lib/update-notifier/user.d                  drwxr-xr-x root:root
/usr/share/package-data-downloads                drwxr-xr-x root:root, empty
/var/lib/ubuntu-release-upgrader                 drwxr-xr-x root:root
/var/lib/ubuntu-release-upgrader/release-upgrade-available -rw-r--r-- root:root
```

Important code shapes checked:

```text
/etc/update-motd.d/50-motd-news
  sources /etc/default/motd-news
  requires ENABLED=1
  allows only https:// URLs
  writes CACHE=/var/cache/motd-news

/usr/lib/update-notifier/update-motd-updates-available
  mktemp -p /var/lib/update-notifier
  mv temp to /var/lib/update-notifier/updates-available

/usr/lib/update-notifier/update-motd-hwe-eol
  root path writes /var/lib/update-notifier/hwe-eol

/usr/lib/update-notifier/update-motd-fsck-at-reboot
  root path writes /var/lib/update-notifier/fsck-at-reboot

/usr/lib/ubuntu-release-upgrader/release-upgrade-motd
  root path writes /var/lib/ubuntu-release-upgrader/release-upgrade-available

/usr/lib/update-notifier/package-data-downloader
  reads hooks from /usr/share/package-data-downloads
  writes stamps under /var/lib/update-notifier/package-data-downloads
  executes hook Script fields only from package-controlled hook files
```

## uid1001 attacker tests

Identity:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Writable and symlink attempts all failed with permission denied:

```text
/var/lib/landscape/landscape-sysinfo.cache
/var/lib/landscape/attacker-created
/var/log/landscape/attacker-created
/etc/landscape/attacker-created
/etc/update-motd.d/49-attacker
/var/cache/motd-news
/var/lib/update-notifier/updates-available
/var/lib/update-notifier/attacker-created
/var/lib/update-notifier/package-data-downloads/attacker-created
/var/lib/update-notifier/user.d/attacker-created
/var/lib/ubuntu-release-upgrader/release-upgrade-available

ln -sf /tmp/ubulpe-root-proof /var/lib/landscape/landscape-sysinfo.cache
  rc=1, Permission denied
ln -sf /tmp/ubulpe-root-proof /var/cache/motd-news
  rc=1, Permission denied
```

Direct script execution as uid1001:

```text
/usr/share/landscape/landscape-sysinfo.wrapper
  rc=0, printed sysinfo only

/usr/bin/landscape-sysinfo
  rc=0, printed sysinfo only

/etc/update-motd.d/50-motd-news
  rc=0, printed cached news only

/etc/update-motd.d/50-motd-news --force
  rc=0, printed fetched/cached news; cache write is not root-controlled by attacker

/usr/lib/update-notifier/update-motd-updates-available --force
  rc=1
  find: '/var/lib/apt/lists/partial': Permission denied
  mktemp: failed to create file via template '/var/lib/update-notifier/tmp.XXXXXXXXXX': Permission denied

/usr/lib/update-notifier/update-motd-hwe-eol --force
  rc=0, no output, no writable root path

/usr/lib/update-notifier/update-motd-fsck-at-reboot --force
  rc=2
  cannot create /var/lib/update-notifier/fsck-at-reboot: Permission denied

/usr/lib/ubuntu-release-upgrader/release-upgrade-motd
  rc=0, no output, no writable root path

/usr/lib/update-notifier/package-data-downloader
  rc=0, no hooks in /usr/share/package-data-downloads
```

uid1001 could not start root services:

```text
systemctl start motd-news.service                 rc=1 Interactive authentication required
systemctl start update-notifier-motd.service      rc=1 Interactive authentication required
systemctl start update-notifier-download.service  rc=1 Interactive authentication required
systemctl start apt-news.service                  rc=1 Interactive authentication required
```

uid1001 could not reach the PAM `login` root path:

```text
/usr/bin/login -f attacker
  rc=1
  login: Cannot possibly work without effective root

run-parts --lsbsysinit /etc/update-motd.d
  rc=0
  printed MOTD only as uid1001
```

No `/tmp/ubulpe-root-proof` file was created, and no uid1001 trigger produced a root-owned attacker-controlled artifact.

## Cleanup

Removed only artifacts created by this audit:

```text
/tmp/ubuntu24-motd-root-run.out
/tmp/ubuntu24-motd-root-run.err
/tmp/ubulpe-*
/var/lib/landscape/landscape-sysinfo.cache
/var/lib/update-notifier/fsck-at-reboot
/home/attacker/.landscape/sysinfo.log
/home/attacker/.landscape, if empty
```

Cleanup verification:

```text
MISSING:/tmp/ubuntu24-motd-root-run.out
MISSING:/tmp/ubulpe-landscape-wrapper.out
MISSING:/var/lib/landscape/landscape-sysinfo.cache
MISSING:/var/lib/update-notifier/fsck-at-reboot
MISSING:/home/attacker/.landscape
```
