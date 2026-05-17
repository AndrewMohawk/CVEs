# passworded self-service account fields

Result: no validated root LPE. A passworded non-sudo user can legitimately use setuid account helpers to modify some of their own account metadata, but stock Ubuntu Server did not consume those fields as root-executable code or privileged paths.

## Target proof

Target: `ubuntu24-server-lpe-target`, stock `ubuntu24-server-default-lpe:20260516-standard`.

```text
Ubuntu 24.04.4 LTS
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Relevant package and mode proof:

```text
passwd	1:4.13+dfsg1-4ubuntu3.2
login	1:4.13+dfsg1-4ubuntu3.2
libpam-modules:arm64	1.5.3-5ubuntu5.5
libpam-runtime	1.5.3-5ubuntu5.5
libpam0g:arm64	1.5.3-5ubuntu5.5

/usr/bin/chfn    root:root 4755
/usr/bin/chsh    root:root 4755
/usr/bin/passwd  root:root 4755
/etc/passwd      root:root 0644
/etc/shadow      root:shadow 0640
/etc/shells      root:root 0644
```

`/etc/login.defs:214` has `CHFN_RESTRICT rwh`, so normal users can change room/work/home phone fields only, not full name or other arbitrary GECOS fields.

`/etc/shells` default valid shells:

```text
/bin/sh
/usr/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/usr/bin/dash
/usr/bin/screen
/usr/bin/tmux
```

## Trigger commands

The probe backed up `/etc/passwd`, `/etc/shadow`, `/etc/group`, and `/etc/gshadow`, restored them in a trap, and ran:

```sh
runuser -u selfauth -- bash -lc '
  for args in "-r Room42" "-w 5551212" "-h 5553131" "-o Other" "-f FullName"; do
    printf "selfauth\n" | timeout 5 sh -c "chfn $args selfauth"
    getent passwd selfauth
  done
'

runuser -u selfauth -- bash -lc '
  for sh in /bin/sh /usr/bin/dash /tmp/self-account-shell /bin/false /usr/sbin/nologin /bin/bash; do
    printf "selfauth\n" | timeout 5 chsh -s "$sh" selfauth
    getent passwd selfauth
  done
'

runuser -u selfauth -- bash -lc '
  printf "selfauth\nnextselfauth\nnextselfauth\n" | timeout 8 passwd selfauth
  printf "nextselfauth\nrootpw\nrootpw\n" | timeout 8 passwd root
'
```

Observed:

```text
chfn -r/-w/-h: password accepted; selfauth GECOS subfields updated
chfn -o Other: Permission denied
chfn -f FullName: Permission denied

chsh /bin/sh: accepted
chsh /usr/bin/dash: accepted
chsh /tmp/self-account-shell: invalid shell
chsh /bin/false: invalid shell
chsh /usr/sbin/nologin: invalid shell
chsh /bin/bash: accepted

passwd selfauth: password updated successfully
passwd root: You may not view or modify password information for root.
```

## Consumer test

To test whether root consumers execute GECOS content, the probe temporarily forced a syntactically valid hostile GECOS string as root, then restored `/etc/passwd`:

```text
selfauth:x:1002:1002:$(id>/tmp/self-account-root-gecos) semi;id>/tmp/self-account-root-semi:/home/selfauth:/bin/bash
```

Default consumers tested:

```sh
loginctl user-status selfauth
run-parts /etc/update-motd.d
su - selfauth -c true
```

Observed:

```text
loginctl user-status selfauth: no shell execution
run-parts /etc/update-motd.d: MOTD rendered normally
su - selfauth -c true: completed without creating markers
ls /tmp/self-account-root-*: no such file or directory
```

Searches through default root scripts/config found `/etc/security/namespace.init` parsing home/gid from `getent passwd`, MOTD scripts, PAM configs, and byobu user-context helpers, but no default root path that evaluates GECOS or shell fields as code. `chsh` restricts the shell field to root-owned entries from `/etc/shells`.

## Cleanup

```sh
cp -a /root/self-account-backup/passwd /etc/passwd
cp -a /root/self-account-backup/shadow /etc/shadow
cp -a /root/self-account-backup/group /etc/group
cp -a /root/self-account-backup/gshadow /etc/gshadow
rm -f /tmp/self-account-*
```

Final verification:

```text
selfauth:x:1002:1002::/home/selfauth:/bin/bash
/tmp/self-account-* absent
systemctl is-system-running: running
```

## Why scanners may miss it

Static review can over-rank this because `chfn`, `chsh`, and `passwd` are setuid root and do write attacker-influenced bytes into root-owned account databases after successful self-authentication. The exploitability depends on the field-specific policy: `CHFN_RESTRICT` blocks arbitrary full-name/other fields, `chsh` limits shells to `/etc/shells`, `passwd` gates other users, and default root consumers treat the remaining self-controlled fields as data.

## Suggested triage conclusion

No Ubuntu Security LPE report from this candidate. Regression tests should keep `CHFN_RESTRICT` effective for normal users, ensure `chsh` continues to require root-owned `/etc/shells` entries, and verify root MOTD/PAM/session helpers do not evaluate GECOS as shell.
