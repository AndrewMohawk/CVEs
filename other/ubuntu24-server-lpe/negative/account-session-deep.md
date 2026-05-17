# Negative: account/session/group-file transition deep probe

Target: `ubuntu24-server-lpe-target`, stock `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Attacker scope: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, not in `sudo`, `adm`, `shadow`, or `root`.

Result: no uid1001-to-root LPE was validated in this lane. The tested account/session/group-file transitions were reachable where default-installed, but they ended in policy denial, user-context execution, absent helpers, or namespace-local root without a container-root write.

Reproducer:

```sh
./pocs/account_session_deep_probe.sh ubuntu24-server-lpe-target > logs/account-session-deep.out 2>&1
```

Probe exit: `0`.

## Exact package/default proof

From `logs/account-session-deep.out`:

```text
Ubuntu 24.04.4 LTS
Linux 4f5b414436ae 6.10.14-linuxkit aarch64
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded

passwd                  1:4.13+dfsg1-4ubuntu3.2
login                   1:4.13+dfsg1-4ubuntu3.2
libpam-modules:arm64    1.5.3-5ubuntu5.5
libpam-modules-bin      1.5.3-5ubuntu5.5
libpam-runtime          1.5.3-5ubuntu5.5
util-linux              2.39.3-9ubuntu6.5
uidmap                  not installed
```

Relevant modes:

```text
/usr/bin/chfn       4755 root:root
/usr/bin/chsh       4755 root:root
/usr/bin/passwd     4755 root:root
/usr/bin/gpasswd    4755 root:root
/usr/bin/newgrp     4755 root:root
/usr/bin/sg         4755 root:root
/usr/bin/login      0755 root:root
/usr/bin/su         4755 root:root
/usr/bin/chage      2755 root:shadow
/usr/bin/expiry     2755 root:shadow
/usr/sbin/faillock  0755 root:root
/usr/bin/newuidmap  missing
/usr/bin/newgidmap  missing
```

Account files and stores were root-owned: `/etc/passwd` `0644 root:root`, `/etc/shadow` `0640 root:shadow`, `/etc/group` `0644 root:root`, `/etc/gshadow` `0640 root:shadow`, `/etc/.pwd.lock` `0600 root:root`, `/etc/subuid` and `/etc/subgid` `0644 root:root`. `/var/log/faillog` existed as `0644 root:root`; `/var/log/tallylog`, `/run/faillock`, and `/var/run/faillock` were absent.

PAM default proof: `login` has `pam_group`, `pam_lastlog`, `pam_env`, and `pam_limits`, but `/usr/bin/login` is not setuid and `login -f attacker` as uid1001 returned `Cannot possibly work without effective root`. No default PAM line enabled `pam_faillock`, `pam_tally`, or `pam_tally2`.

## Trigger coverage

The probe exercised:

```text
lock/symlink preplacement for /etc/passwd.lock, shadow.lock, group.lock,
gshadow.lock, passwd+/shadow+/group+/gshadow+, passwd.<pid>, subuid/subgid
locks, /var/log/tallylog, /run/faillock, /var/run/faillock, and faillog

login -f attacker
newgrp attacker with SHELL=/home/attacker/account_session_deep/bin/fake-shell
sg attacker -c 'id > /tmp/...; id > /root/...'
sg/newgrp root, shadow, sudo, adm with a bad group password
gpasswd attacker, -a/-M/-d/-A/-R attacker
passwd -l/-u/-d attacker, passwd -S root/attacker
chage -l root/attacker, chage -E attacker, expiry -c
chpasswd, newusers, usermod, groupmod, vipw, vigr
faillock --user/--reset for attacker and root, faillog -u attacker, faillog -r -u root
unshare -Ur with a /root write attempt
strace of sg/gpasswd file opens, setgid, and setuid transitions
```

Key observed boundaries:

```text
newgrp attacker: fake shell ran as uid=1001; root marker absent
sg attacker: command ran as uid=1001; /root write denied; root marker absent
sg/newgrp privileged groups: Invalid password
gpasswd and account mutation commands: Permission denied / cannot lock /etc/passwd
faillock reset/read: no faillock/tally store created; faillog root reset denied
newuidmap/newgidmap: absent
unshare -Ur: uid=0 only inside a namespace mapping 0 -> 1001; /root write denied
strace sg: opened account DBs read-only, then setgid(1001) and setuid(1001)
```

## Root proof absence

The account database hashes before and after matched for:

```text
/etc/passwd
/etc/shadow
/etc/group
/etc/gshadow
/etc/subuid
/etc/subgid
```

The log ended with:

```text
account_files_unchanged=yes
ROOT_MARKER_ABSENT /root/account_session_deep_root_marker
ROOT_MARKER_ABSENT /root/account_session_deep_sg_marker
ROOT_MARKER_ABSENT /root/account_session_deep_userns_root
cleanup_leftovers=0
```

No command produced root code execution, root-owned attacker-controlled file creation, writable account/group database state, or a root-followed symlink/lock primitive.

## Cleanup

The probe creates only `/home/attacker/account_session_deep`, `/tmp/account_session_deep*`, temporary root markers under `/root/account_session_deep_*`, and a temporary account-file backup under `/tmp`. It backs up `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/subuid`, and `/etc/subgid`, restores them if changed, removes probe artifacts, and verified `cleanup_leftovers=0`.

## Why scanners miss

Static scanners over-rank this slice because `sg`, `newgrp`, `gpasswd`, `passwd`, `chfn`, and `chsh` are setuid root, `chage`/`expiry` are setgid shadow, `/etc/subuid` and `/etc/subgid` grant subordinate ranges, and PAM login config contains account/session modules. The exploitability depends on transition order and default reachability: `login` is not setuid, `sg/newgrp` drop to uid1001 before command or shell execution, privileged group entries are password-locked, account-file locks live under non-writable root-owned directories, `newuidmap/newgidmap` are absent, and the only uid0 observed was user-namespace root mapped back to uid1001.
