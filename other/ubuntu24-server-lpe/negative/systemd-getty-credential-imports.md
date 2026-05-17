# systemd getty/login credential imports: negative

## Scope and target

- Target: `ubuntu24-server-lpe-target`
- OS: Ubuntu 24.04.4 LTS (`noble`)
- Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`
- Packages:
  - `systemd 255.4-1ubuntu8.15`
  - `systemd-sysv 255.4-1ubuntu8.15`
  - `login 1:4.13+dfsg1-4ubuntu3.2`
  - `util-linux 2.39.3-9ubuntu6.5`
  - `libpam-modules 1.5.3-5ubuntu5.5`
  - `libpam-systemd 255.4-1ubuntu8.15`
- Result: no uid1001 -> root local privilege escalation found.

Probe/log:

```text
pocs/systemd_getty_credential_imports_probe.sh
logs/systemd-getty-credential-imports.out
```

## Default-install and default-reachability proof

The getty/login path is default-installed and active on stock Server in the target:

```text
getty@.service        enabled
console-getty.service enabled-runtime
getty-static.service  static
getty@tty1.service    active
```

The live root process was:

```text
/sbin/agetty -o "-p -- \\u" --noclear - linux
```

## Code/config path checked

`/usr/lib/systemd/system/getty@.service` imports credentials into the root-owned getty instance:

```text
39 ExecStart=-/sbin/agetty -o '-p -- \\u' --noclear - $TERM
52 ImportCredential=agetty.*
53 ImportCredential=login.*
```

`/usr/lib/systemd/system/console-getty.service` has the same import boundary:

```text
23 ExecStart=-/sbin/agetty -o '-p -- \\u' --noclear --keep-baud - 115200,38400,9600 $TERM
34 ImportCredential=agetty.*
35 ImportCredential=login.*
```

Credential stores were not attacker-writable:

```text
drwxr-xr-x root:root /run/credentials
drwx------ root:root /etc/credstore
drwx------ root:root /etc/credstore.encrypted
-rwxr-xr-x root:root /sbin/agetty
-rwxr-xr-x root:root /usr/bin/login
```

## Unprivileged trigger attempts

uid1001 attempted to create service-specific runtime credential directories and global credstores:

```sh
mkdir -p /run/credentials/getty@tty1.service
mkdir -p /run/credentials/console-getty.service
mkdir -p /run/credstore
mkdir -p /run/credstore.encrypted
```

All runtime credential writes failed with `Permission denied` or missing root-owned parent directories. `/etc/credstore` and `/etc/credstore.encrypted` already existed, but mode `0700 root:root` blocked file creation.

uid1001 attempted to inject plausible getty/login credentials:

```sh
printf 'root\n' > /run/credentials/getty@tty1.service/agetty.autologin
printf '1\n' > /run/credentials/getty@tty1.service/login.noauth
printf 'x\n' > /run/credentials/getty@tty1.service/login.motd
printf 'x\n' > /run/credentials/getty@tty1.service/login.issue
printf 'root\n' > /etc/credstore/agetty.autologin
printf '1\n' > /etc/credstore/login.noauth
```

All writes failed. uid1001 then tried to force the root service to reload credentials:

```sh
systemctl restart getty@tty1.service
systemctl restart console-getty.service
systemd-run --system --unit=getty-credential-lpe \
  -p 'LoadCredential=agetty.autologin:/tmp/nonexistent' \
  /bin/sh -c 'id > /root/systemd_getty_credential_imports_root'
busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager StartUnit ss getty@tty1.service replace
```

The system manager returned `Interactive authentication required`.

Direct helper execution stayed in uid1001 context:

```sh
CREDENTIALS_DIRECTORY=/tmp/systemd-getty-credentials /usr/bin/login -f root
# login: Cannot possibly work without effective root

env CREDENTIALS_DIRECTORY=/tmp/systemd-getty-credentials /sbin/agetty --help
# ran as attacker and only wrote attacker-owned help output under /tmp
```

## Root proof

No root marker was created:

```text
stat: cannot statx '/root/systemd_getty_credential_imports_root': No such file or directory
stat: cannot statx '/tmp/systemd_getty_credential_imports_root': No such file or directory
```

The target remained healthy:

```text
getty@tty1.service: active
systemctl is-system-running: running
systemctl --failed: no failed units
```

## Cleanup

The probe removed its temporary attacker-owned files:

```sh
rm -f /tmp/systemd_getty_credential_imports_root /tmp/systemd_getty_agetty_help
```

No root-owned credential files were created.

## Why scanners may miss the boundary

This is a semantic systemd credential boundary, not a file-mode-only issue. The risky-looking primitive is that a default root login service imports `agetty.*` and `login.*`; exploitability depends on whether a normal user can supply system credentials or restart the importing service, not whether the getty binary itself is setuid.

## Ubuntu Security triage note

No vulnerability is claimed. The current default state is blocked by root-owned credential stores and polkit-protected system manager operations. If future changes allow unprivileged per-unit credential injection, keep login/getty credential names denylisted for user-controlled sources or require admin authorization before they can be attached to root login services.
