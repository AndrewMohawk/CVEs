# Negative: cron user crontab parser semantics

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Probe: `pocs/cron_user_crontab_semantics_probe.sh`. Full log: `logs/cron-user-crontab-semantics.out`.

Verdict: no validated default uid1001-to-root LPE was found in this focused user-crontab/setgid-helper/root-daemon parser boundary.

## Default proof

The probe first captured stock package and service state before installing any test crontabs:

```text
cron                    3.0pl1-184ubuntu2        ii
cron-daemon-common      3.0pl1-184ubuntu2        ii
systemd                 255.4-1ubuntu8.15        ii
anacron                 un
at                      NOT_INSTALLED
bsd-mailx               un
mailutils/postfix/exim4/nullmailer/msmtp-mta NOT_INSTALLED
cron_enabled=enabled
cron_active=active
/usr/bin/crontab mode=2755 owner=root group=crontab
/var/spool/cron/crontabs mode=1730 owner=root group=crontab
```

The target attacker was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

## Boundary results

Direct uid1001 spool traversal and creation attempts under `/var/spool/cron/crontabs` failed with permission denied. An attacker-controlled `crontab -e` editor ran as `uid=1001 gid=1001 groups=1001`, not with the `crontab` group, while the temp file itself was `attacker:crontab`.

Replacing the helper temp file with a symlink to `/var/spool/cron/crontabs/root` failed with `Can't open tempfile after edit`; no root spool appeared. Creating a hardlink to the temp file caused `No modification made`; no attacker spool was installed.

Installed user crontab parser probes ran as attacker:

```text
user job id: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
system-style user field: /bin/sh: 1: root: not found
percent split id: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
percent stdin: root /bin/id > /root/..._percent_fake_root
/root write attempt: Permission denied
newline/user-field fake root line: /bin/sh: 1: root: not found
```

The attacker could set `USER=root`, `PATH=/home/attacker/...`, and `ATTACKER_SENTINEL` in their own crontab environment, but a controlled root crontab canary did not inherit them. The root canary saw only root/default daemon state such as `HOME=/root`, `LOGNAME=root`, `SHELL=/bin/sh`, and the default root cron PATH; `command -v user_in_path_marker` returned empty.

`MAILTO=root;touch /tmp/...` was logged as `UNSAFE MAIL`; `/tmp/..._mailto_shell` was not created. With no default MTA installed, cron logged output discard behavior rather than invoking a mail path.

Daemon reload behavior matched expectation: the attacker crontab produced one `reload_counter` tick, `crontab -r` removed it, and the next minute left the counter unchanged:

```text
reload_counter_before_remove=1
reload_counter_after_remove=1
reload_remove_result=stopped_after_crontab_r
ROOT_PROOF=NO
```

Cleanup restored the original absent root and attacker crontabs, removed tag-specific files, and left `cron.service` active/running.
