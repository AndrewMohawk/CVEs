# Negative: update-notifier `package-system-locked` pkexec action

Status: no validated LPE.

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

## Default proof

Installed/default package state:

```text
update-notifier-common  ii  3.192.68.2
update-notifier         un
pkexec                  un
policykit-1             un
polkitd                 ii  124-2ubuntu1.24.04.3
```

`update-notifier-common` installs `/usr/share/polkit-1/actions/com.ubuntu.update-notifier.policy`, including:

```text
action: com.ubuntu.update-notifier.pkexec.package-system-locked
allow_any=no
allow_inactive=yes
allow_active=yes
exec.path=/usr/lib/update-notifier/package-system-locked
```

The helper is a shell script:

```text
/usr/lib/update-notifier/package-system-locked:1 #!/bin/sh
/usr/lib/update-notifier/package-system-locked:6 for f in /var/lib/dpkg/lock /var/cache/apt/archives/lock ...
/usr/lib/update-notifier/package-system-locked:11     if fuser $f; then
```

## Tested trigger

Direct execution as the attacker is not privileged:

```sh
runuser -u attacker -- /usr/lib/update-notifier/package-system-locked
echo $?
# 0
```

The pkexec route is not default-reachable on this stock Server target because `pkexec`/`policykit-1` are not installed:

```sh
runuser -u attacker -- sh -lc 'command -v pkexec || true; pkexec /usr/lib/update-notifier/package-system-locked; echo rc:$?'
```

Observed:

```text
sh: 1: pkexec: not found
rc:127
```

The only packaged references are the polkit action itself:

```text
/usr/share/polkit-1/actions/com.ubuntu.update-notifier.policy:79 action id
/usr/share/polkit-1/actions/com.ubuntu.update-notifier.policy:144 exec.path
```

## Why this is not a finding

The policy would be risky on a system where `pkexec` is installed because an active or inactive user could run a root shell helper that invokes `fuser` without an absolute path. That precondition is not present in the stock Ubuntu 24.04 Server Docker target: `pkexec` is not installed and no default root service invokes this helper. Direct execution stays uid 1001, and there is no root proof.

## Cleanup

No persistent state was created.

## Suggested fix

Either remove the stale pkexec policy from `update-notifier-common` on systems without `pkexec`, or harden the helper anyway by invoking `/usr/bin/fuser` with a fixed safe `PATH`.
