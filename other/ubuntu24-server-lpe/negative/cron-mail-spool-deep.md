# Negative: cron, run-parts, MAILTO, and mail spool deep pass

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Probe: `pocs/cron_mail_spool_deep_probe.sh`

Full log: `logs/cron-mail-spool-deep.out`

Verdict: no stock Ubuntu 24.04 Server default uid1001-to-root LPE was found in this residual cron/mail-spool slice. The only root-consumed user-writable path observed was `/etc/cron.daily/apport` cleanup of old `/var/crash` entries; it deleted attacker-owned stale files/directories but did not follow symlinks into a root decoy or create a root-controlled write primitive.

## Default proof

Relevant installed/default state from the probe:

```text
cron                 3.0pl1-184ubuntu2          ii
cron-daemon-common   3.0pl1-184ubuntu2          ii
debianutils          5.17build1                 ii
systemd              255.4-1ubuntu8.15          ii
apport               2.28.1-0ubuntu3.8          ii
sysstat              12.6.1-2                   ii
e2fsprogs            1.47.0-2.4~exp1ubuntu4.1   ii
anacron              un
at                   NOT_INSTALLED
bsd-mailx            un
mailutils/postfix/exim4/nullmailer/msmtp-mta NOT_INSTALLED
run-parts_version=Debian run-parts program, version 5.17
cron_enabled=enabled
cron_active=active
```

`cron.service` runs `/usr/sbin/cron -f -P`; `/etc/crontab` uses unqualified `run-parts`, but PID 1 provides `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, and uid1001 could not write any of those directories or `/etc/cron.*`.

## Boundaries tested

Setgid crontab/spool:

```text
/usr/bin/crontab mode=2755 owner=root group=crontab
/var/spool/cron/crontabs mode=1730 owner=root group=crontab
attacker_groups=attacker
direct_spool_ls: Permission denied
direct_cat_own_spool: Permission denied
editor id: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

The helper can install/list the attacker's crontab, but direct spool traversal is blocked and attacker-controlled editors do not inherit group `crontab`.

`run-parts` parsing:

```text
accepted/executed: --dash, --report, 00ok, README, alpha-beta, alpha_beta
rejected: .hidden, evil.sh, evil space, newline name, plus+name, tilde~, colon:name
```

Leading-dash names are accepted by the default regex, but execution uses the full path under the supplied directory, so this was not option injection. The default root cron directories are root-owned `0755`, so uid1001 cannot place such files where root cron will run them.

Cron daily/user-owned input:

`/etc/cron.daily/apport` runs under cron because `anacron` is absent and does not have the systemd skip guard used by apt/dpkg/logrotate/man-db/sysstat. It prunes `/var/crash` (`03777 root:root`). The probe planted an old attacker-owned file, a new file, a symlink to `/root/..._root_decoy`, and an old 12-digit attacker-owned directory. Running `/etc/cron.daily/apport` removed the stale file/directory, left the new file and symlink, and left the root decoy unchanged.

Other default cron scripts either skip on `/run/systemd/system` or use fixed root-owned paths. `/etc/cron.d/sysstat` is active and sets `PATH=/usr/lib/sysstat:/usr/sbin:/usr/sbin:/usr/bin:/sbin:/bin`; those directories were not attacker-writable.

MAILTO/MTA/mail spool:

```text
/usr/sbin/sendmail missing
/usr/lib/sendmail missing
/usr/bin/mail missing
/usr/bin/mailx missing
/var/mail mode=2775 owner=root group=mail
/var/spool/mail -> ../mail
touch/link under /var/mail and /var/spool/mail as attacker: Permission denied
```

A safe `MAILTO=root` user cron with output ran as attacker and logged `No MTA installed, discarding output`; no `/var/mail` file appeared. An unsafe `MAILTO=root;touch /tmp/...` was rejected as `UNSAFE MAIL`, and the shell-looking fragment was not executed.

Anacron/at:

```text
/usr/sbin/anacron missing
/etc/anacrontab missing
/usr/bin/at, atq, atrm and /usr/sbin/atd missing
Unit anacron.service could not be found.
Unit atd.service could not be found.
at_rc=127
```

## Root proof

No root proof file was created:

```text
ROOT_PROOF=NO
system_state_after=running
0 failed units
```

Cleanup removed the probe crontab and temporary paths; `crontab -l` for attacker returned `no crontab for attacker` after cleanup.
