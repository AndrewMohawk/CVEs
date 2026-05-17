# Negative: cron/crontab default path

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no real `uid=1001(attacker)` to root LPE was found in stock Ubuntu 24.04 Server cron, crontab, or default cron path handling. User crontabs execute as the user, `crontab` does not leak the `crontab` group to attacker-controlled editors, direct spool writes are blocked, root-named forged spools are rejected by owner checks, and default root cron paths are root-owned/non-writable.

## Default proof

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'cat /etc/os-release; uname -a; id attacker'
```

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

```sh
docker exec ubuntu24-server-lpe-target bash -lc '
for p in cron adduser passwd login libpam-modules systemd base-files ubuntu-minimal ubuntu-standard ubuntu-server; do
  dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${Status}\n" "$p"
done
systemctl is-enabled cron.service
systemctl is-active cron.service
systemctl status cron.service --no-pager -l | sed -n "1,12p"'
```

```text
cron	3.0pl1-184ubuntu2	install ok installed
adduser	3.137ubuntu1	install ok installed
passwd	1:4.13+dfsg1-4ubuntu3.2	install ok installed
login	1:4.13+dfsg1-4ubuntu3.2	install ok installed
libpam-modules:arm64	1.5.3-5ubuntu5.5	install ok installed
systemd	255.4-1ubuntu8.15	install ok installed
base-files	13ubuntu10.4	install ok installed
ubuntu-minimal	1.539.2	install ok installed
ubuntu-standard	1.539.2	install ok installed
ubuntu-server	1.539.2	install ok installed
enabled
active
● cron.service - Regular background program processing daemon
     Loaded: loaded (/usr/lib/systemd/system/cron.service; enabled; preset: enabled)
     Active: active (running)
   Main PID: 255 (cron)
             └─255 /usr/sbin/cron -f -P
```

## Modes and root cron path

```sh
docker exec ubuntu24-server-lpe-target bash -lc '
ls -l /usr/sbin/cron /usr/bin/crontab
stat -c "%n mode=%a owner=%U group=%G uid=%u gid=%g type=%F" /usr/sbin/cron /usr/bin/crontab
stat -c "%n mode=%a owner=%U group=%G" /etc/crontab /etc/cron.* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null'
```

```text
-rwxr-sr-x 1 root crontab 68072 Mar 31  2024 /usr/bin/crontab
-rwxr-xr-x 1 root root    68008 Mar 31  2024 /usr/sbin/cron
/usr/sbin/cron mode=755 owner=root group=root uid=0 gid=0 type=regular file
/usr/bin/crontab mode=2755 owner=root group=crontab uid=0 gid=997 type=regular file
/etc/crontab mode=644 owner=root group=root
/etc/cron.d mode=755 owner=root group=root
/etc/cron.daily mode=755 owner=root group=root
/etc/cron.hourly mode=755 owner=root group=root
/etc/cron.monthly mode=755 owner=root group=root
/etc/cron.weekly mode=755 owner=root group=root
/etc/cron.yearly mode=755 owner=root group=root
/var/spool/cron mode=755 owner=root group=root
/var/spool/cron/crontabs mode=1730 owner=root group=crontab
```

`/etc/crontab` root entries:

```text
SHELL=/bin/sh
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6	* * 7	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6	1 * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

`cron.service` runs `/usr/sbin/cron -f -P`; its inherited environment had:

```text
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
USER=root
```

The root cron directories and `/etc/cron.d` entries were root-owned, not group/world-writable, and had no symlinks. `/etc/cron.d/sysstat` sets its own root-owned PATH:

```text
PATH=/usr/lib/sysstat:/usr/sbin:/usr/sbin:/usr/bin:/sbin:/bin
/usr/lib/sysstat mode=755 owner=root group=root
/usr/sbin mode=755 owner=root group=root
/usr/bin mode=755 owner=root group=root
/usr/local/sbin mode=755 owner=root group=root
/usr/local/bin mode=755 owner=root group=root
```

## User crontab execution

Attacker installing their own crontab works, but execution stays `uid=1001`:

```sh
cat >/tmp/cron_input <<'EOF'
SHELL=/bin/sh
PATH=/home/attacker/cron-audit:/usr/bin:/bin
* * * * * id > /tmp/cron_user_job_id
EOF
chown attacker:attacker /tmp/cron_input
su -s /bin/bash attacker -c 'crontab /tmp/cron_input'
```

Observed after the next minute:

```text
/tmp/cron_user_job_id:
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)

journalctl -u cron.service:
CRON[19887]: pam_unix(cron:session): session opened for user attacker(uid=1001) by attacker(uid=0)
CRON[19889]: (attacker) CMD (id > /tmp/cron_user_job_id)
CRON[19887]: pam_unix(cron:session): session closed for user attacker
```

Adding a system-crontab-style username field to a user crontab is parsed as part of the command, not as a privilege selector:

```text
crontab line: * * * * * root id > /tmp/cron_user_field_id 2>&1
/tmp/cron_user_field_id: /bin/sh: 1: root: not found
journalctl: (attacker) CMD (root id > /tmp/cron_user_field_id 2>&1)
```

`USER=root`, attacker-controlled `PATH`, and `SHELL=/bin/sh` only affect the attacker job environment:

```text
HOME=/home/attacker
LOGNAME=attacker
MAILTO=root
PATH=/home/attacker/cron-audit:/usr/bin:/bin
PWD=/home/attacker
SHELL=/bin/sh
USER=root
```

The PATH probe executed as attacker:

```text
/tmp/cron_path_marker:
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

## PAM/env and mailer

`/etc/pam.d/cron` uses system env files only:

```text
session required pam_env.so
session required pam_env.so envfile=/etc/default/locale
@include common-account
@include common-session-noninteractive
session required pam_limits.so
```

No `user_readenv` or attacker home env file was enabled for cron. The user crontab can set environment keys like `USER=root`, but the PAM session and job UID remained attacker.

No default MTA was present:

```sh
command -v sendmail || true
ls -l /usr/sbin/sendmail /usr/lib/sendmail /usr/bin/mail /usr/bin/mailx 2>/dev/null || true
```

No output was returned. An unredirected attacker job with `MAILTO=root` logged:

```text
CRON[20598]: (attacker) CMD (echo CRON_MAIL_PROBE_$$)
CRON[20597]: (CRON) info (No MTA installed, discarding output)
```

## Setgid crontab/editor behavior

The most plausible setgid issue was an attacker-controlled editor inheriting group `crontab`. It did not:

```sh
cat >/home/attacker/cron-audit/editor.sh <<'EOF'
#!/bin/sh
id > /tmp/cron_editor_id
( umask 077; echo '* * * * * id > /tmp/cron_bad_root_from_editor' > /var/spool/cron/crontabs/root ) 2>/tmp/cron_editor_spool_touch || true
exit 0
EOF
chown attacker:attacker /home/attacker/cron-audit/editor.sh
chmod 755 /home/attacker/cron-audit/editor.sh
su -s /bin/bash attacker -c 'VISUAL=/home/attacker/cron-audit/editor.sh EDITOR=/home/attacker/cron-audit/editor.sh crontab -e'
```

Evidence:

```text
no crontab for attacker - using an empty one
No modification made
/tmp/cron_editor_id:
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
/tmp/cron_editor_spool_touch:
/home/attacker/cron-audit/editor.sh: 4: cannot create /var/spool/cron/crontabs/root: Permission denied
/var/spool/cron/crontabs/root: absent
```

The temporary editor path was private and cleaned up:

```text
dir /tmp/crontab.n4u3Y5 directory mode=700 owner=attacker group=crontab
file /tmp/crontab.n4u3Y5/crontab regular file mode=600 owner=attacker group=crontab nlink=1 size=889
editor id: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
after: /tmp/crontab.n4u3Y5/crontab removed; /tmp/crontab.n4u3Y5 removed
```

## Spool write, symlink, hardlink, and root-name checks

Direct attacker writes to the spool fail, including the attacker's own spool file because the directory blocks traversal to non-`crontab` groups:

```text
echo x > /var/spool/cron/crontabs/root
# Permission denied
ln -s /tmp/cron_link_target /var/spool/cron/crontabs/root
# Permission denied
ln /etc/passwd /var/spool/cron/crontabs/root
# Permission denied
crontab -u root -l
# must be privileged to use -u
crontab -u root /tmp/cron_input
# must be privileged to use -u
```

Own crontab installation creates a normal user-owned spool:

```text
/var/spool/cron/crontabs/attacker regular file mode=600 owner=attacker group=crontab nlink=1
cat /var/spool/cron/crontabs/attacker as attacker: Permission denied
append /var/spool/cron/crontabs/attacker as attacker: Permission denied
```

Preexisting symlink and hardlink behavior was tested by creating artificial root-controlled setup states and then invoking `crontab` as attacker:

```text
symlink before: /var/spool/cron/crontabs/attacker -> /tmp/cron_symlink_target, owner=root group=root
crontab: crontabs/attacker: rename: Operation not permitted
target-content=original

hardlink before: /tmp/cron_hard_target and /var/spool/cron/crontabs/attacker same inode, owner=attacker, nlink=2
crontab install exit=0
after target: same original inode, nlink=1, content=original
after spool: new inode, owner=attacker group=crontab, nlink=1
```

So `crontab` did not follow a symlink to overwrite the target, and a preexisting hardlink was replaced rather than used as the write target.

A forged `root` spool file owned by attacker was rejected by cron daemon owner checks and did not execute as root:

```sh
cat >/var/spool/cron/crontabs/root <<'EOF'
* * * * * id > /tmp/cron_fake_root_id
EOF
chown attacker:crontab /var/spool/cron/crontabs/root
chmod 600 /var/spool/cron/crontabs/root
```

After cron reloaded:

```text
/tmp/cron_fake_root_id: absent
journalctl -u cron.service:
cron[255]: (root) WRONG FILE OWNER (crontabs/root)
```

## Cleanup

Cleanup performed:

```sh
su -s /bin/bash attacker -c 'crontab -r' || true
rm -rf /home/attacker/cron-audit
find /tmp -maxdepth 1 \( -name 'cron_*' -o -name 'crontab.*' \) -exec rm -rf -- {} +
rm -f /var/spool/cron/crontabs/root
find /var/spool/cron/crontabs -maxdepth 1 -mindepth 1 -printf '%M %u %g %p\n'
find /tmp -maxdepth 1 \( -name 'cron_*' -o -name 'crontab.*' \) -printf '%M %u %g %p\n'
systemctl is-active cron.service
```

Final verification:

```text
remaining spool: empty
remaining cron probes: empty
cron.service: active
```

No PoC was created because this lane did not produce a valid root LPE. DoS, attacker-only execution, and artificial root-created setup states were not counted as vulnerabilities.
