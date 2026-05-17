# Negative: systemd ask-password wall watcher

Status: no validated uid1001 -> root local privilege escalation.

## Default proof

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS.

Attacker:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Affected/default packages:

```text
systemd 255.4-1ubuntu8.15
```

The wall watcher is active by default:

```text
systemd-ask-password-wall.path    active running
systemd-ask-password-wall.service active running
MainPID: systemd-tty-ask-password-agent --wall
```

## Code/config boundary

`/usr/lib/systemd/system/systemd-ask-password-wall.path`:

```text
21 [Path]
22 DirectoryNotEmpty=/run/systemd/ask-password
23 MakeDirectory=yes
```

`/usr/lib/systemd/system/systemd-ask-password-wall.service`:

```text
16 ExecStartPre=-systemctl stop systemd-ask-password-console.path systemd-ask-password-console.service systemd-ask-password-plymouth.path systemd-ask-password-plymouth.service
17 ExecStart=systemd-tty-ask-password-agent --wall
```

`/usr/lib/tmpfiles.d/systemd.conf:13` creates the watched directory as root-only writable:

```text
d /run/systemd/ask-password 0755 root root -
```

Live permissions:

```text
drwxr-xr-x root:root /run/systemd/ask-password
drwxr-xr-x root:root /run/systemd
```

## Attacker trigger

As uid1001:

```sh
id
ls -ld /run/systemd/ask-password /run/systemd
test -w /run/systemd/ask-password && echo writable || echo not_writable
touch /run/systemd/ask-password/ask.attacker
systemd-ask-password --no-tty --timeout=1 "attacker prompt"
```

Observed:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
not_writable
touch: cannot touch '/run/systemd/ask-password/ask.attacker': Permission denied
Failed to query password: Permission denied
```

## Why this is not a finding

The active root service is a real default trust boundary, but uid1001 cannot create request files in the watched directory and cannot use the packaged client to ask PID 1 to create one. No attacker-controlled prompt file reaches the root `systemd-tty-ask-password-agent`, and no root-owned file write or root code execution was produced.

## Scanner-miss note

A unit/path scanner will flag `DirectoryNotEmpty=/run/systemd/ask-password` plus a root service that parses files and writes to logged-in terminals. The exploitability depends on the tmpfiles-created directory mode, which blocks normal users before parser or symlink/race behavior is reachable.

## Cleanup

No target cleanup was required; no uid1001 file was created.
