# AppArmor / console / boot helper boundary audit

Status: negative. No uid1001/uid1002 to root LPE was found in the stock Ubuntu 24.04.4 Server Docker target through AppArmor loading/cache paths, default systemd setup helpers, console setup, setvtrgb, or Plymouth.

## Target proof

Container and image:

```sh
docker ps --filter name=ubuntu24-server-lpe-target --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
```

Observed:

```text
NAMES                        IMAGE                                           STATUS
ubuntu24-server-lpe-target   ubuntu24-server-default-lpe:20260516-standard   Up 7 minutes
```

Probe command:

```sh
./ubuntu24-server-lpe/pocs/apparmor_console_probe.sh ubuntu24-server-lpe-target
```

Target identity from the probe:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION="24.04.4 LTS (Noble Numbat)"
Linux 4f5b414436ae 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
attacker:x:1001:1001::/home/attacker:/bin/bash
selfauth:x:1002:1002::/home/selfauth:/bin/bash
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
attacker : attacker
selfauth : selfauth
```

Relevant default package state:

```text
apparmor	4.0.1really4.0.1-0ubuntu0.24.04.6	ii
apparmor-utils		un
libapparmor1:arm64	4.0.1really4.0.1-0ubuntu0.24.04.6	ii
console-setup	1.226ubuntu1	ii
console-setup-linux	1.226ubuntu1	ii
keyboard-configuration	1.226ubuntu1	ii
kbd	2.6.4-2ubuntu2	ii
systemd	255.4-1ubuntu8.15	ii
systemd-sysv	255.4-1ubuntu8.15	ii
plymouth	24.004.60-1ubuntu7.1	ii
```

Default unit state:

```text
apparmor.service                   enabled enabled / inactive
systemd-binfmt.service             static  -       / active
systemd-sysctl.service             static  -       / active
systemd-modules-load.service       static  -       / active
systemd-tmpfiles-setup.service     static  -       / active
systemd-tmpfiles-setup-dev.service static  -       / active
console-setup.service              enabled enabled / active
keyboard-setup.service             enabled enabled / active
setvtrgb.service                   enabled enabled / active
plymouth-start.service             static  -       / inactive
plymouth-quit.service              static  -       / active
plymouth-quit-wait.service         static  -       / active
plymouth-read-write.service        static  -       / active
```

## AppArmor boundary

`apparmor.service` is installed/enabled but skipped in this Docker target:

```text
aa-status:
apparmor not present.

apparmor.service:
Active: inactive (dead)
Condition: start condition unmet
└─ ConditionSecurity=apparmor was not met
AssertPathIsReadWrite=/sys/kernel/security/apparmor/.load
ExecStart=/lib/apparmor/apparmor.systemd reload
```

The package ships parser/helper binaries, but they are ordinary root-owned executables with no relevant file capabilities:

```text
apparmor: /usr/sbin/aa-load
apparmor: /usr/bin/aa-enabled
apparmor: /usr/bin/aa-exec
apparmor: /usr/sbin/aa-status
no relevant file capabilities
```

Root-consumed AppArmor inputs are not attacker-writable, and apparmorfs is absent:

```text
drwxr-xr-x root:root directory /etc/apparmor
drwxr-xr-x root:root directory /etc/apparmor.d
-rw-r--r-- root:root regular file /etc/apparmor/parser.conf
drwxr-xr-x root:root directory /var/cache/apparmor
dr-xr-xr-x root:root directory /sys/kernel/security
MISSING /sys/kernel/security/apparmor
MISSING /sys/kernel/security/apparmor/.load
```

Both `attacker` and `selfauth` got the same write and trigger failures:

```text
WRITE /etc/apparmor.d/codex-test: Permission denied rc=1
WRITE /var/cache/apparmor/codex-test: Permission denied rc=1
START apparmor.service: Failed to start apparmor.service: Interactive authentication required. rc=1
CMD aa-exec -p unconfined -- /usr/bin/id: aa-exec: ERROR: AppArmor interface not available rc=1
CMD apparmor_parser -r /tmp/codex-aa-profile.*: unable to find a suitable fs in /proc/mounts rc=1
CMD apparmor_parser -Q -r /tmp/codex-aa-profile.*: Cache read/write disabled: interface file missing rc=0
CMD aa-load /tmp/codex-aa-profile.*: Sorry. You need root privileges to run this program. rc=1
CMD aa-teardown: mount: /sys/kernel/security: must be superuser to use mount ... AppArmor module is not loaded rc=1
```

`apparmor_parser -Q` is only a parse/skip-kernel-load path; it did not write cache or load policy. `/etc/apparmor/parser.conf` also leaves `write-cache` commented by default.

## systemd setup helpers

The systemd-binfmt, sysctl, modules-load, and tmpfiles root units read only root-owned package/default directories in this image:

```text
drwxr-xr-x root:root directory /etc/binfmt.d
MISSING /run/binfmt.d
drwxr-xr-x root:root directory /usr/lib/binfmt.d
drwxr-xr-x root:root directory /etc/sysctl.d
MISSING /run/sysctl.d
drwxr-xr-x root:root directory /usr/lib/sysctl.d
drwxr-xr-x root:root directory /etc/modules-load.d
MISSING /run/modules-load.d
drwxr-xr-x root:root directory /usr/lib/modules-load.d
drwxr-xr-x root:root directory /etc/tmpfiles.d
MISSING /run/tmpfiles.d
drwxr-xr-x root:root directory /usr/lib/tmpfiles.d
drwxr-xr-x root:root directory /run/credentials
```

Unprivileged users could not create override files or start the root units:

```text
WRITE /etc/binfmt.d/codex-test.conf: Permission denied rc=1
WRITE /run/binfmt.d/codex-test.conf: No such file or directory rc=1
WRITE /etc/sysctl.d/99-codex-test.conf: Permission denied rc=1
WRITE /etc/modules-load.d/codex-test.conf: Permission denied rc=1
WRITE /etc/tmpfiles.d/codex-test.conf: Permission denied rc=1
WRITE /run/credentials/systemd-sysctl.service/codex: No such file or directory rc=1
START systemd-binfmt.service: Interactive authentication required rc=1
START systemd-sysctl.service: Interactive authentication required rc=1
START systemd-modules-load.service: Interactive authentication required rc=1
START systemd-tmpfiles-setup.service: Interactive authentication required rc=1
```

Direct execution of the systemd helper binaries as uid1001/uid1002 did not cross privileges. They are not setuid/capability-bearing, used root-owned config, and either no-op'd or failed on missing/non-writable kernel state:

```text
CMD /usr/lib/systemd/systemd-binfmt: rc=0
CMD /usr/lib/systemd/systemd-sysctl: Couldn't write '1' to 'kernel/apparmor_restrict_unprivileged_userns', ignoring: No such file or directory ... rc=0
CMD /usr/lib/systemd/systemd-modules-load: Failed to find module 'dm-multipath' rc=0
CMD systemd-tmpfiles --create --boot --prefix=/tmp/codex-tmpfiles-nothing: rc=0
```

## Console and boot helpers

The root-started console helpers consume root-owned files:

```text
-rw-r--r-- root:root regular file /etc/default/keyboard
-rw-r--r-- root:root regular file /etc/default/console-setup
drwxr-xr-x root:root directory /etc/console-setup
-rwxr-xr-x root:root regular file /etc/console-setup/cached_setup_keyboard.sh
lrwxrwxrwx root:root symbolic link /etc/vtrgb -> /etc/alternatives/vtrgb
-rwxr-xr-x root:root regular file /sbin/setvtrgb
crw--w---- root:tty character special file /dev/tty0
MISSING /run/plymouth
MISSING /run/plymouth/socket
```

Both normal users were denied writes to the consumed console files and denied root unit starts:

```text
WRITE /etc/default/keyboard: Permission denied rc=1
WRITE /etc/default/console-setup: Permission denied rc=1
WRITE /etc/console-setup/cached_setup_keyboard.sh: Permission denied rc=1
WRITE /etc/vtrgb: Permission denied rc=1
START console-setup.service: Interactive authentication required rc=1
START keyboard-setup.service: Interactive authentication required rc=1
START setvtrgb.service: Interactive authentication required rc=1
START plymouth-start.service: Interactive authentication required rc=1
```

Direct helper execution stayed unprivileged and lacked a usable console/Plymouth device boundary:

```text
CMD setupcon --save: /etc/console-setup is not writable ... We are not on the console rc=0
CMD loadkeys /etc/console-setup/cached_UTF-8_del.kmap.gz: Couldn't get a file descriptor referring to the console rc=1
CMD /usr/sbin/setvtrgb /etc/vtrgb: Couldn't get a file descriptor referring to the console rc=1
CMD plymouth --ping: rc=1
ACCESS /dev/tty0 ---
ACCESS /dev/tty rw-
MISSING /run/plymouth/socket
```

The target did not expose a logged-in `selfauth` seat during this run:

```text
loginctl list-sessions:
No sessions.

loginctl user-status selfauth:
Failed to get user: User ID 1002 is not logged in or lingering

/run/systemd/seats/seat0: -rw-r--r-- root:root
/run/systemd/sessions: drwxr-xr-x root:root
```

Even treating `selfauth` as the passworded active-seat test account, the tested privilege boundary did not change: uid1002 had only group `selfauth`, no `tty`/admin groups, no write access to `/dev/tty0`, no Plymouth socket, and the same systemd authorization failures as uid1001.

## Cleanup

The probe used only `/tmp/codex-aa-profile.*`, `/tmp/codex-apparmor-console-*`, and `/tmp/apparmor_console_probe`, all removed by trap. Cleanup verification printed no remaining probe paths:

```text
## cleanup verification
```

No root proof file, root-owned marker, policy load, service restart, Docker restart, or destructive Docker operation was performed.

## Why scanners might miss this

Static scanners can flag these surfaces because they are boot-time root units, parse policy/config languages, touch `/proc/sys`, write tmpfiles, or interact with virtual consoles. On the default Server Docker target the exploitable chain breaks at all required trust edges: AppArmor is not present in the kernel namespace; AppArmor policy/cache/config paths are root-owned; setup override dirs and systemd credentials are root-owned or absent; unit starts require interactive authorization; helper binaries are not setuid/capability-bearing; console helpers require a real privileged console fd; and Plymouth has no running socket.
