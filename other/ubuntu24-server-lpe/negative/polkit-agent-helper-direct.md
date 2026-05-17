# Negative: polkit-agent-helper-1 direct PAM/auth path

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server default Docker target.

Result: no normal-user to root LPE was validated through direct execution of
`/usr/lib/polkit-1/polkit-agent-helper-1`.

## Reproducer

```sh
/Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe/pocs/polkit_agent_helper_direct_probe.sh ubuntu24-server-lpe-target
```

Full log:

```text
/Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe/logs/polkit-agent-helper-direct.out
```

## Default reachability proven

The helper is present, setuid root, and executable by the passworded non-sudo
model user:

```text
polkitd 124-2ubuntu1.24.04.3 arm64 ii
/usr/lib/polkit-1/polkit-agent-helper-1 mode=4755 perms=-rwsr-xr-x owner=root:root uid=0 gid=0 size=67664
selfauth_can_execute_helper_rc=0
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
group: sudo:x:27:ubuntu
```

`selfauth` is not in `sudo`, `admin`, `adm`, `shadow`, or `root`.

`pkexec`/`policykit-1` are not installed as separate packages in this image,
but the setuid helper is installed by `polkitd` and is reachable through its
canonical path plus the compatibility symlinks under `/usr/lib/policykit-1`
and `/usr/libexec`.

## Protocol and policy result

The helper binary exposes the expected guards and PAM/polkit flow:

```text
wrong number of arguments
stdin is a tty
pam_start / pam_authenticate / pam_acct_mgmt
polkit_authority_authentication_agent_response_sync
FAILURE
SUCCESS
```

Default policy did not expose an `auth_self` action:

```text
[auth_self_actions]
none
org.freedesktop.policykit.exec any=auth_admin inactive=auth_admin active=auth_admin
org.freedesktop.systemd1.manage-units any=auth_admin inactive=auth_admin active=auth_admin_keep
```

Direct helper runs with the correct `selfauth` password authenticated through
PAM, but fake, empty, long, or action-name cookies all failed at polkitd with
`No session for cookie`. Wrong argc and TTY stdin were rejected. Root,
nonexistent, and newline-containing usernames failed PAM. Malformed stdin
variants, including no trailing newline, extra lines, embedded NUL, and an
oversized response, did not bypass the cookie/session requirement.

For a real cookie captured by a minimal registered authentication agent against
`org.freedesktop.systemd1.manage-units`, polkitd bound the request to the admin
identity `uid=1000` (`ubuntu`). Supplying `selfauth` to the helper with that
live cookie produced:

```text
The authenticated identity is wrong
FAILURE
```

Supplying `ubuntu` with the `selfauth` password failed PAM authentication.

## Side effects and races

The hostile environment probe set attacker-controlled `PATH`, `HOME`, `SHELL`,
`GCONV_PATH`, `CHARSET`, `LD_PRELOAD`, `LD_AUDIT`, and `PAM_USER=root`.
No fake helper binary executed and no root marker was created:

```text
fakebin_executed=no
ROOT_PROOF=no
```

The 24-way concurrent fake-cookie stress produced only failures:

```text
success_count=0
24 FAILURE
24 No session for cookie
```

The strace pass for the valid-PAM/fake-cookie path showed one helper `execve`,
NSS/userdb lookups, and a system bus connection/response. The write/exec summary
did not show root-side `O_WRONLY`, `O_RDWR`, `O_CREAT`, rename, unlink, symlink,
chmod, chown, setxattr, or secondary command execution.

Root-owned state snapshots for account files, PAM config, polkit rules, and
polkit state were unchanged after the final run; the final snapshot diff was
empty. Cleanup removed `/tmp/polkit-agent-helper-direct`,
`/root/polkit_agent_helper_direct_root`, and related marker files.

## Conclusion

This is a real default setuid-root surface, but it stays bound to the normal
polkit authentication-cookie model. A passworded non-sudo user can reach PAM in
the helper, but cannot mint a valid authorization, substitute itself for an
admin identity on a live cookie, trigger root command execution, or produce a
root-side write primitive in the bounded probes above.
