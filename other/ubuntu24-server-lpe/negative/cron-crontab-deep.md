# Negative: deep cron/crontab/anacron semantics

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Attacker: `uid=1001(attacker)` non-sudo.

Result: no stock Ubuntu 24.04 Server default `uid=1001(attacker)` to root LPE was found in the deeper cron/crontab/anacron lane. The setgid `crontab` boundary did not expose the `crontab` group to attacker-controlled editors, direct spool access was blocked, temp-file link manipulation either aborted or installed a fresh attacker-owned spool copy, forged root/system cron files were rejected by cron daemon owner/mode checks, and default mail/anacron/root run-parts paths were not attacker-writable.

DoS, user crons executing as `uid=1001`, and root-created artificial setup states were not counted.

## Default proof

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'cat /etc/os-release; echo ---; uname -a; echo ---; dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" cron cron-daemon-common anacron bsd-mailx mailutils 2>&1 || true; echo ---; apt-cache policy cron cron-daemon-common anacron 2>/dev/null | sed -n "1,80p"; echo ---; systemctl is-enabled cron.service; systemctl is-active cron.service; systemctl status cron.service --no-pager -l | sed -n "1,14p"; echo ---; id attacker; id selfauth; getent group crontab; command -v sendmail || true; ls -l /usr/sbin/sendmail 2>&1 || true'
```

Output:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
---
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
---
dpkg-query: no packages found matching mailutils
anacron		un 
bsd-mailx		un 
cron	3.0pl1-184ubuntu2	ii 
cron-daemon-common	3.0pl1-184ubuntu2	ii 
---
cron:
  Installed: 3.0pl1-184ubuntu2
  Candidate: 3.0pl1-184ubuntu2
  Version table:
 *** 3.0pl1-184ubuntu2 500
        500 http://ports.ubuntu.com/ubuntu-ports noble/main arm64 Packages
        100 /var/lib/dpkg/status
cron-daemon-common:
  Installed: 3.0pl1-184ubuntu2
  Candidate: 3.0pl1-184ubuntu2
  Version table:
 *** 3.0pl1-184ubuntu2 500
        500 http://ports.ubuntu.com/ubuntu-ports noble/main arm64 Packages
        100 /var/lib/dpkg/status
anacron:
  Installed: (none)
  Candidate: 2.3-39ubuntu2
  Version table:
     2.3-39ubuntu2 500
        500 http://ports.ubuntu.com/ubuntu-ports noble/main arm64 Packages
---
enabled
active
● cron.service - Regular background program processing daemon
     Loaded: loaded (/usr/lib/systemd/system/cron.service; enabled; preset: enabled)
     Active: active (running) since Sat 2026-05-16 10:23:55 UTC; 4h 4min ago
       Docs: man:cron(8)
   Main PID: 255 (cron)
      Tasks: 1 (limit: 9517)
     Memory: 348.0K (peak: 7.0M)
        CPU: 285ms
     CGroup: /docker/fd448ecbc1369b3391fb69933b0f55af5a71ce4cbe66aa844e9905aebffa2ea1/system.slice/cron.service
             └─255 /usr/sbin/cron -f -P
---
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
crontab:x:997:
ls: cannot access '/usr/sbin/sendmail': No such file or directory
```

Starting state was empty:

```text
spool-before:
attacker-crontab-before:
no crontab for attacker
attacker-crontab-rc=1
root-spool-before:
absent
```

## Default cron paths

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'stat -c "%n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h" /usr/bin/crontab /usr/sbin/cron /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly /var/spool/cron /var/spool/cron/crontabs /etc/default/cron /etc/pam.d/cron 2>&1; echo ---; find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly -maxdepth 1 -mindepth 1 -printf "%M %u:%g %p -> %l\n" | sort; echo ---; sed -n "1,120p" /etc/crontab; echo ---; sed -n "1,120p" /etc/default/cron; echo ---; sed -n "1,140p" /etc/pam.d/cron'
```

Output excerpt:

```text
/usr/bin/crontab regular file mode=2755 owner=root group=crontab uid=0 gid=997 nlink=1
/usr/sbin/cron regular file mode=755 owner=root group=root uid=0 gid=0 nlink=1
/etc/crontab regular file mode=644 owner=root group=root uid=0 gid=0 nlink=1
/etc/cron.d directory mode=755 owner=root group=root uid=0 gid=0 nlink=1
/var/spool/cron/crontabs directory mode=1730 owner=root group=crontab uid=0 gid=997 nlink=1
---
-rw-r--r-- root:root /etc/cron.d/.placeholder -> 
-rw-r--r-- root:root /etc/cron.d/e2scrub_all -> 
-rw-r--r-- root:root /etc/cron.d/sysstat -> 
-rwxr-xr-x root:root /etc/cron.daily/apport -> 
-rwxr-xr-x root:root /etc/cron.daily/apt-compat -> 
-rwxr-xr-x root:root /etc/cron.daily/dpkg -> 
-rwxr-xr-x root:root /etc/cron.daily/logrotate -> 
-rwxr-xr-x root:root /etc/cron.daily/man-db -> 
-rwxr-xr-x root:root /etc/cron.daily/sysstat -> 
-rwxr-xr-x root:root /etc/cron.weekly/man-db -> 
---
SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6	* * 7	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6	1 * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
---
session       required   pam_env.so
session       required   pam_env.so envfile=/etc/default/locale
@include common-account
@include common-session-noninteractive 
session    required   pam_limits.so
```

The package creates the crontab group and spool mode via tmpfiles/sysusers:

```text
== tmpfiles/sysusers ==
d /var/spool/cron/crontabs 1730 root crontab
g crontab - -
```

The maintainer script also contains upgrade-time sanity checks for existing spools:

```text
# Iterate over each entry in the spool directory, perform some sanity
# checks (see CVE-2017-9525), and chown/chgroup the crontabs
for tab_name in *
do
    [ "$tab_name" = "*" ] && continue
    tab_links=`stat -c '%h' "$tab_name"`
    tab_owner=`stat -c '%U' "$tab_name"`

    if [ ! -f "$tab_name" ]
    then
        echo "Warning: $tab_name is not a regular file!"
        continue
    elif [ "$tab_links" -ne 1 ]
    then
        echo "Warning: $tab_name has more than one hard link!"
        continue
    elif [ "$tab_owner" != "$tab_name" ]
    then
        echo "Warning: $tab_name name differs from owner $tab_owner!"
        continue
    fi
```

## Setgid editor and temp files

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'BASE=/home/attacker/cron-deep; mkdir -p "$BASE/customtmp"; chown -R attacker:attacker "$BASE"; cat > "$BASE/editor_env2.sh" <<'"'"'EOF'"'"'
#!/bin/sh
sleep 1
{
  echo "argv:$*"
  id
  awk "/^(Uid|Gid|Groups|NoNewPrivs):/ {print}" /proc/$$/status
  env | sort | grep -E "^(VISUAL|EDITOR|TMPDIR|SHELL|PATH|LD_|BASH_ENV|ENV|HOME|LOGNAME|USER|MAILTO|IFS)=" || true
  p="$1"; d=$(dirname -- "$p")
  stat -Lc "before-file %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s" "$p"
  stat -Lc "before-dir %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h" "$d"
} > /tmp/cron_deep_editor_env2.out 2>&1
printf "# cron deep editor env install 2\n* * * * * id > /tmp/cron_deep_should_not_run2\n" > "$1"
stat -Lc "after-file %n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s" "$1" >> /tmp/cron_deep_editor_env2.out 2>&1
exit 0
EOF
chown attacker:attacker "$BASE/editor_env2.sh"; chmod 755 "$BASE/editor_env2.sh"; runuser -u attacker -- env TMPDIR="$BASE/customtmp" VISUAL="$BASE/editor_env2.sh" EDITOR="$BASE/editor_env2.sh" SHELL=/tmp/cron_deep_fake_shell PATH="$BASE:/usr/bin:/bin" LD_PRELOAD=/tmp/cron_deep_fake_preload.so BASH_ENV=/tmp/cron_deep_bash_env ENV=/tmp/cron_deep_env MAILTO="root;touch /tmp/cron_deep_mail_env" USER=root LOGNAME=root IFS=":;" /usr/bin/crontab -e > /tmp/cron_deep_crontab_e2.stdout 2> /tmp/cron_deep_crontab_e2.stderr; echo "crontab-e-rc=$?"; cat /tmp/cron_deep_crontab_e2.stderr; cat /tmp/cron_deep_editor_env2.out; stat -Lc "%n %F mode=%a owner=%U group=%G uid=%u gid=%g nlink=%h size=%s" /var/spool/cron/crontabs/attacker; sed -n "1,12p" /var/spool/cron/crontabs/attacker; runuser -u attacker -- crontab -r'
```

Output:

```text
crontab-e-rc=0
no crontab for attacker - using an empty one
crontab: installing new crontab
argv:/tmp/crontab.W9LytJ/crontab
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
Uid:	1001	1001	1001	1001
Gid:	1001	1001	1001	1001
Groups:	1001 
NoNewPrivs:	0
BASH_ENV=/tmp/cron_deep_bash_env
EDITOR=/home/attacker/cron-deep/editor_env2.sh
ENV=/tmp/cron_deep_env
HOME=/home/attacker
IFS= 	
LOGNAME=root
MAILTO=root;touch /tmp/cron_deep_mail_env
PATH=/home/attacker/cron-deep:/usr/bin:/bin
SHELL=/tmp/cron_deep_fake_shell
USER=root
VISUAL=/home/attacker/cron-deep/editor_env2.sh
before-file /tmp/crontab.W9LytJ/crontab regular file mode=600 owner=attacker group=crontab uid=1001 gid=997 nlink=1 size=889
before-dir /tmp/crontab.W9LytJ directory mode=700 owner=attacker group=crontab uid=1001 gid=997 nlink=2
after-file /tmp/crontab.W9LytJ/crontab regular file mode=600 owner=attacker group=crontab uid=1001 gid=997 nlink=1 size=79
/var/spool/cron/crontabs/attacker regular file mode=600 owner=attacker group=crontab uid=1001 gid=997 nlink=1 size=280
# DO NOT EDIT THIS FILE - edit the master and reinstall.
# (/tmp/crontab.W9LytJ/crontab installed on Sat May 16 14:30:28 2026)
# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)
# cron deep editor env install 2
* * * * * id > /tmp/cron_deep_should_not_run2
```

Takeaways:

- The editor ran as real/effective/saved uid and gid 1001, with no supplementary `crontab` group.
- `TMPDIR` and `LD_PRELOAD` were absent in the editor environment, and the temp path was `/tmp/crontab.*`.
- Attacker-controlled `USER`, `LOGNAME`, `MAILTO`, `SHELL`, `PATH`, `BASH_ENV`, and `ENV` reached only the attacker editor process.
- The installed spool was a new `0600 attacker:crontab` file with link count 1. The attacker still could not read it directly because the spool directory blocks traversal.

## Temp symlink and hardlink manipulation

The editor replaced the temp path with a symlink to `/etc/passwd`:

```text
== symlink-to-etc-passwd rc=1 ==
--- stderr
no crontab for attacker - using an empty one
Temporary crontab no longer owned by you.
Error while editing crontab
--- editor
editor-id=uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
before /tmp/crontab.PE0mLc/crontab regular file mode=600 owner=attacker group=crontab nlink=1 size=889
lrwxrwxrwx 1 attacker attacker 11 May 16 14:31 /tmp/crontab.PE0mLc/crontab -> /etc/passwd
after-deref /tmp/crontab.PE0mLc/crontab regular file mode=644 owner=root group=root nlink=1 size=1704
--- passwd hashes
e1468fa4ad17e48937e0fe2d6f1c64ea1d8477c339287f68bd3fc54aa9729ee0  /etc/passwd
e1468fa4ad17e48937e0fe2d6f1c64ea1d8477c339287f68bd3fc54aa9729ee0  /etc/passwd
--- crontab-list
no crontab for attacker
```

Replacing the temp path with attacker-owned symlink or hardlink content installed attacker content only, as a fresh spool copy:

```text
== symlink-to-valid rc=0 ==
crontab: installing new crontab
lrwxrwxrwx 1 attacker attacker 45 May 16 14:31 /tmp/crontab.skknoF/crontab -> /home/attacker/cron-deep/valid_symlink_target
target /tmp/crontab.skknoF/crontab regular file mode=644 owner=attacker group=attacker nlink=1 size=72 inode=19050599
spool /var/spool/cron/crontabs/attacker mode=600 owner=attacker group=crontab nlink=1 size=273 inode=19050610
# target valid symlink
* * * * * id > /tmp/cron_deep_valid_from_symlink

== hardlink-to-valid rc=0 ==
crontab: installing new crontab
temp /tmp/crontab.VhPiiB/crontab mode=644 owner=attacker group=attacker nlink=2 size=74 inode=19050615
target /home/attacker/cron-deep/valid_hardlink_target mode=644 owner=attacker group=attacker nlink=2 size=74 inode=19050615
target /home/attacker/cron-deep/valid_hardlink_target mode=644 owner=attacker group=attacker nlink=1 size=74 inode=19050615
# target valid hardlink
* * * * * id > /tmp/cron_deep_valid_from_hardlink
spool /var/spool/cron/crontabs/attacker mode=600 owner=attacker group=crontab nlink=1 size=275 inode=19050620
# DO NOT EDIT THIS FILE - edit the master and reinstall.
# (/tmp/crontab.VhPiiB/crontab installed on Sat May 16 14:31:14 2026)
# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)
# target valid hardlink
* * * * * id > /tmp/cron_deep_valid_from_hardlink
```

## Crontab install input links

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'BASE=/home/attacker/cron-deep; runuser -u attacker -- bash -lc "printf \"# input real\n* * * * * id > /tmp/cron_deep_input_real_job\n\" > $BASE/input_real && ln -sf $BASE/input_real $BASE/input_link && rm -f $BASE/input_hard && ln $BASE/input_real $BASE/input_hard && ls -li $BASE/input_real $BASE/input_link $BASE/input_hard"; runuser -u attacker -- /usr/bin/crontab "$BASE/input_link"; stat -Lc "real %n inode=%i nlink=%h mode=%a owner=%U group=%G size=%s" "$BASE/input_real"; stat -Lc "spool %n inode=%i nlink=%h mode=%a owner=%U group=%G size=%s" /var/spool/cron/crontabs/attacker; sed -n "1,8p" /var/spool/cron/crontabs/attacker; runuser -u attacker -- crontab -r; runuser -u attacker -- /usr/bin/crontab "$BASE/input_hard"; stat -Lc "hard %n inode=%i nlink=%h mode=%a owner=%U group=%G size=%s" "$BASE/input_hard"; stat -Lc "spool %n inode=%i nlink=%h mode=%a owner=%U group=%G size=%s" /var/spool/cron/crontabs/attacker; sed -n "1,8p" /var/spool/cron/crontabs/attacker; runuser -u attacker -- crontab -r; runuser -u attacker -- /usr/bin/crontab /etc/shadow 2>&1 || true'
```

Output:

```text
19050611 -rw-r--r-- 2 attacker attacker 58 May 16 14:31 /home/attacker/cron-deep/input_hard
19050620 lrwxrwxrwx 1 attacker attacker 35 May 16 14:31 /home/attacker/cron-deep/input_link -> /home/attacker/cron-deep/input_real
19050611 -rw-r--r-- 2 attacker attacker 58 May 16 14:31 /home/attacker/cron-deep/input_real
real /home/attacker/cron-deep/input_real inode=19050611 nlink=2 mode=644 owner=attacker group=attacker size=58
spool /var/spool/cron/crontabs/attacker inode=19050627 nlink=1 mode=600 owner=attacker group=crontab size=267
# DO NOT EDIT THIS FILE - edit the master and reinstall.
# (/home/attacker/cron-deep/input_link installed on Sat May 16 14:31:31 2026)
# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)
# input real
* * * * * id > /tmp/cron_deep_input_real_job
hard /home/attacker/cron-deep/input_hard inode=19050611 nlink=2 mode=644 owner=attacker group=attacker size=58
spool /var/spool/cron/crontabs/attacker inode=19050633 nlink=1 mode=600 owner=attacker group=crontab size=267
# DO NOT EDIT THIS FILE - edit the master and reinstall.
# (/home/attacker/cron-deep/input_hard installed on Sat May 16 14:31:31 2026)
# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)
# input real
* * * * * id > /tmp/cron_deep_input_real_job
/etc/shadow: Permission denied
```

`crontab /path` copied link target content into a fresh spool. It did not preserve input hardlinks, and setgid `crontab` did not gain access to `/etc/shadow`.

Kernel link protections were enabled:

```text
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 1
passwd_hard_rc=1
ln: failed to create hard link '/tmp/cron_deep_passwd_hard' => '/etc/passwd': Operation not permitted
shadow_hard_rc=1
ln: failed to create hard link '/tmp/cron_deep_shadow_hard' => '/etc/shadow': Operation not permitted
```

## Spool access and replacement

Direct attacker access:

```text
direct_write_rc=1
bash: line 1: /var/spool/cron/crontabs/root: Permission denied
symlink_rc=1
hardlink_rc=1
crontab_u_l_rc=1
crontab_u_install_rc=1
ln: failed to create hard link '/var/spool/cron/crontabs/root' => '/etc/passwd': Permission denied
ln: failed to create symbolic link '/var/spool/cron/crontabs/root': Permission denied
must be privileged to use -u
must be privileged to use -u
--- root-spool
absent
```

Traversal and artificial preexisting spool states:

```text
== attacker traversal ==
ls_rc=2
ls: cannot open directory '/var/spool/cron/crontabs': Permission denied

== preexisting symlink at attacker spool ==
lrwxrwxrwx 1 root root 35 May 16 14:32 /var/spool/cron/crontabs/attacker -> /tmp/cron_deep_spool_symlink_target
rc=1
crontab: crontabs/attacker: rename: Operation not permitted
target=original

== preexisting root-owned file at attacker spool ==
before /var/spool/cron/crontabs/attacker mode=600 owner=root group=crontab nlink=1 inode=19050681
rc=1
crontab: crontabs/attacker: rename: Operation not permitted
after /var/spool/cron/crontabs/attacker mode=600 owner=root group=crontab nlink=1 inode=19050681 size=9
rootowned

== preexisting hardlink at attacker spool ==
before-target /tmp/cron_deep_spool_hard_target mode=600 owner=attacker group=crontab nlink=2 inode=19050681 size=13
before-spool /var/spool/cron/crontabs/attacker mode=600 owner=attacker group=crontab nlink=2 inode=19050681 size=13
rc=0
after-target /tmp/cron_deep_spool_hard_target mode=600 owner=attacker group=crontab nlink=1 inode=19050681 size=13
original-hard
after-spool /var/spool/cron/crontabs/attacker mode=600 owner=attacker group=crontab nlink=1 inode=19050702 size=286
# DO NOT EDIT THIS FILE - edit the master and reinstall.
# (/home/attacker/cron-deep/install_spool_test installed on Sat May 16 14:32:22 2026)
# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)
# spool replace test
* * * * * id > /tmp/cron_deep_spool_replace_job
```

The attacker cannot plant a spool entry. If a root-created symlink or root-owned file already occupies the attacker's spool name, sticky-directory semantics prevent setgid `crontab` from replacing it. If an attacker-owned hardlink occupies the spool name, install replaces the spool with a new link-count-1 file and leaves the old hardlink target unchanged.

## Cron daemon parsing checks

Command summary:

```sh
docker exec ubuntu24-server-lpe-target bash -lc '
cat > /var/spool/cron/crontabs/root <<EOF
* * * * * id > /tmp/cron_deep_fake_root_id
EOF
chown attacker:crontab /var/spool/cron/crontabs/root; chmod 600 /var/spool/cron/crontabs/root
cat > /var/spool/cron/crontabs/attacker <<EOF
* * * * * id > /tmp/cron_deep_wrong_owner_attacker
EOF
chown root:crontab /var/spool/cron/crontabs/attacker; chmod 600 /var/spool/cron/crontabs/attacker
cat > /var/spool/cron/crontabs/selfauth <<EOF
* * * * * id > /tmp/cron_deep_selfauth_badmode
EOF
chown selfauth:crontab /var/spool/cron/crontabs/selfauth; chmod 666 /var/spool/cron/crontabs/selfauth
cat > /etc/cron.d/cron-deep-owner <<EOF
* * * * * root id > /tmp/cron_deep_etc_bad_owner
EOF
chown attacker:attacker /etc/cron.d/cron-deep-owner; chmod 644 /etc/cron.d/cron-deep-owner
cat > /etc/cron.d/cron-deep-mode <<EOF
* * * * * root id > /tmp/cron_deep_etc_bad_mode
EOF
chown root:root /etc/cron.d/cron-deep-mode; chmod 666 /etc/cron.d/cron-deep-mode
cat > /tmp/cron_deep_etc_symlink_target <<EOF
* * * * * root id > /tmp/cron_deep_etc_symlink
EOF
chown attacker:attacker /tmp/cron_deep_etc_symlink_target; chmod 644 /tmp/cron_deep_etc_symlink_target
ln -s /tmp/cron_deep_etc_symlink_target /etc/cron.d/cron-deep-link
touch /var/spool/cron/crontabs /etc/cron.d
sec=$(date +%S); sec=$((10#$sec)); sleep_for=$((70 - sec)); if [ "$sleep_for" -lt 15 ]; then sleep_for=$((sleep_for + 60)); fi; echo "sleep_for=$sleep_for"; sleep "$sleep_for"
'
```

Planted states:

```text
/var/spool/cron/crontabs/root regular file mode=600 owner=attacker group=crontab uid=1001 gid=997 nlink=1
/var/spool/cron/crontabs/attacker regular file mode=600 owner=root group=crontab uid=0 gid=997 nlink=1
/var/spool/cron/crontabs/selfauth regular file mode=666 owner=selfauth group=crontab uid=1002 gid=997 nlink=1
/etc/cron.d/cron-deep-owner regular file mode=644 owner=attacker group=attacker uid=1001 gid=1001 nlink=1
/etc/cron.d/cron-deep-mode regular file mode=666 owner=root group=root uid=0 gid=0 nlink=1
/etc/cron.d/cron-deep-link symbolic link mode=777 owner=root group=root uid=0 gid=0 nlink=1
/tmp/cron_deep_etc_symlink_target regular file mode=644 owner=attacker group=attacker uid=1001 gid=1001 nlink=1
lrwxrwxrwx 1 root root 33 May 16 14:33 /etc/cron.d/cron-deep-link -> /tmp/cron_deep_etc_symlink_target
sleep_for=35
```

After cron scan:

```text
/tmp/cron_deep_fake_root_id absent
/tmp/cron_deep_wrong_owner_attacker PRESENT attacker:attacker mode=664 size=60
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
/tmp/cron_deep_selfauth_badmode absent
/tmp/cron_deep_etc_bad_owner absent
/tmp/cron_deep_etc_bad_mode absent
/tmp/cron_deep_etc_symlink absent
```

Journal:

```text
2026-05-16T14:34:01+00:00 fd448ecbc136 cron[255]: (*system*cron-deep-link) WRONG FILE OWNER (/etc/cron.d/cron-deep-link)
2026-05-16T14:34:01+00:00 fd448ecbc136 cron[255]: (*system*cron-deep-mode) INSECURE MODE (group/other writable) (/etc/cron.d/cron-deep-mode)
2026-05-16T14:34:01+00:00 fd448ecbc136 cron[255]: (*system*cron-deep-owner) WRONG FILE OWNER (/etc/cron.d/cron-deep-owner)
2026-05-16T14:34:01+00:00 fd448ecbc136 cron[255]: (root) WRONG FILE OWNER (crontabs/root)
2026-05-16T14:34:01+00:00 fd448ecbc136 cron[255]: (selfauth) INSECURE MODE (mode 0600 expected) (crontabs/selfauth)
2026-05-16T14:34:01+00:00 fd448ecbc136 CRON[103830]: (attacker) CMD (id > /tmp/cron_deep_wrong_owner_attacker)
```

Spool symlink daemon check:

```text
start_utc=2026-05-16 14:41:00
--- planted
lrwxrwxrwx 1 root root 41 May 16 14:41 /var/spool/cron/crontabs/attacker -> /tmp/cron_deep_spool_link_attacker_target
lrwxrwxrwx 1 root root 37 May 16 14:41 /var/spool/cron/crontabs/root -> /tmp/cron_deep_spool_link_root_target
lrwxrwxrwx 1 root root 41 May 16 14:41 /var/spool/cron/crontabs/selfauth -> /tmp/cron_deep_spool_link_selfauth_target
/var/spool/cron/crontabs/root deref regular file mode=644 owner=attacker group=attacker uid=1001 gid=1001 nlink=1
/var/spool/cron/crontabs/attacker deref regular file mode=644 owner=attacker group=attacker uid=1001 gid=1001 nlink=1
/var/spool/cron/crontabs/selfauth deref regular file mode=644 owner=selfauth group=selfauth uid=1002 gid=1002 nlink=1
sleep_for=70
--- markers
/tmp/cron_deep_spool_link_root absent
/tmp/cron_deep_spool_link_attacker absent
/tmp/cron_deep_spool_link_selfauth absent
--- journal
2026-05-16T14:41:02+00:00 fd448ecbc136 cron[255]: (attacker) CAN'T OPEN (crontabs/attacker)
2026-05-16T14:41:02+00:00 fd448ecbc136 cron[255]: (root) CAN'T OPEN (crontabs/root)
2026-05-16T14:41:02+00:00 fd448ecbc136 cron[255]: (selfauth) CAN'T OPEN (crontabs/selfauth)
```

Interpretation:

- An attacker-owned `root` spool did not execute as root.
- Attacker-owned or group/world-writable `/etc/cron.d` entries did not execute as root.
- A symlink in `/etc/cron.d` to an attacker-owned target was rejected by owner checks.
- Symlinked user spool entries were not executed; cron logged `CAN'T OPEN`.
- A root-owned file named `crontabs/attacker` executed only as `attacker`. That is not an LPE, and the attacker cannot plant that file in the default spool directory.

## Mail and log interactions

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'echo "--- mailer-default"; command -v sendmail || true; ls -l /usr/sbin/sendmail /usr/lib/sendmail /usr/bin/mail /usr/bin/mailx 2>&1 || true; cat > /tmp/cron_deep_mail_cron <<'"'"'EOF'"'"'
SHELL=/bin/sh
MAILTO=root;touch /tmp/cron_deep_mail_pwn
* * * * * echo CRON_DEEP_MAIL_MARKER; id > /tmp/cron_deep_mail_marker
EOF
chown attacker:attacker /tmp/cron_deep_mail_cron
runuser -u attacker -- /usr/bin/crontab /tmp/cron_deep_mail_cron
sec=$(date +%S); sec=$((10#$sec)); sleep_for=$((70 - sec)); if [ "$sleep_for" -lt 15 ]; then sleep_for=$((sleep_for + 60)); fi; echo "sleep_for=$sleep_for"; sleep "$sleep_for"
journalctl -u cron.service --since "$START UTC" --no-pager -o short-iso | grep -E "cron_deep_mail|CRON_DEEP_MAIL|No MTA|CMD" || true'
```

Output:

```text
--- mailer-default
ls: cannot access '/usr/sbin/sendmail': No such file or directory
ls: cannot access '/usr/lib/sendmail': No such file or directory
ls: cannot access '/usr/bin/mail': No such file or directory
ls: cannot access '/usr/bin/mailx': No such file or directory
install_rc=0
spool /var/spool/cron/crontabs/attacker mode=600 owner=attacker group=crontab size=324
SHELL=/bin/sh
MAILTO=root;touch /tmp/cron_deep_mail_pwn
* * * * * echo CRON_DEEP_MAIL_MARKER; id > /tmp/cron_deep_mail_marker
sleep_for=35
--- markers
/tmp/cron_deep_mail_pwn absent
/tmp/cron_deep_mail_marker PRESENT attacker:attacker mode=664 size=60
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
--- journal
2026-05-16T14:35:01+00:00 fd448ecbc136 CRON[104156]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)
2026-05-16T14:35:01+00:00 fd448ecbc136 CRON[104157]: (attacker) CMD (echo CRON_DEEP_MAIL_MARKER; id > /tmp/cron_deep_mail_marker)
2026-05-16T14:35:01+00:00 fd448ecbc136 CRON[104155]: (attacker) UNSAFE MAIL (root;touch /tmp/cron_deep_mail_pwn)
```

The malicious `MAILTO` value was logged as unsafe. The job still ran as `attacker`; the `touch` in `MAILTO` was not executed. No default MTA/sendmail binary existed.

## Anacron and root run-parts

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'echo "== anacron-default =="; dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" anacron 2>&1 || true; test -x /usr/sbin/anacron; echo anacron_x_rc=$?; ls -ld /usr/sbin/anacron /etc/anacrontab /var/spool/anacron 2>&1 || true; echo "== root-cron-run-parts =="; run-parts --test /etc/cron.hourly; run-parts --test /etc/cron.daily; run-parts --test /etc/cron.weekly; run-parts --test /etc/cron.monthly; echo "== attacker-create-root-cron-dirs =="; for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly; do runuser -u attacker -- bash -lc "touch $d/cron_deep_attacker 2>/tmp/cron_deep_touch.err"; rc=$?; printf "%s touch_rc=%s " "$d" "$rc"; cat /tmp/cron_deep_touch.err; rm -f /tmp/cron_deep_touch.err; done'
```

Output:

```text
== anacron-default ==
anacron		un 
anacron_x_rc=1
ls: cannot access '/usr/sbin/anacron': No such file or directory
ls: cannot access '/etc/anacrontab': No such file or directory
ls: cannot access '/var/spool/anacron': No such file or directory
== root-cron-run-parts ==
/etc/cron.daily/apport
/etc/cron.daily/apt-compat
/etc/cron.daily/dpkg
/etc/cron.daily/logrotate
/etc/cron.daily/man-db
/etc/cron.daily/sysstat
/etc/cron.weekly/man-db
== attacker-create-root-cron-dirs ==
/etc/cron.d touch_rc=1 touch: cannot touch '/etc/cron.d/cron_deep_attacker': Permission denied
/etc/cron.hourly touch_rc=1 touch: cannot touch '/etc/cron.hourly/cron_deep_attacker': Permission denied
/etc/cron.daily touch_rc=1 touch: cannot touch '/etc/cron.daily/cron_deep_attacker': Permission denied
/etc/cron.weekly touch_rc=1 touch: cannot touch '/etc/cron.weekly/cron_deep_attacker': Permission denied
/etc/cron.monthly touch_rc=1 touch: cannot touch '/etc/cron.monthly/cron_deep_attacker': Permission denied
/etc/cron.yearly touch_rc=1 touch: cannot touch '/etc/cron.yearly/cron_deep_attacker': Permission denied
```

Cron's service environment and root PATH directories were root-owned:

```text
ExecStart={ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f -P $EXTRA_OPTS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=
User=
Group=
FragmentPath=/usr/lib/systemd/system/cron.service
DropInPaths=
pid=255
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
USER=root
/usr/local/sbin mode=755 owner=root group=root
/usr/local/bin mode=755 owner=root group=root
/usr/sbin mode=755 owner=root group=root
/usr/bin mode=755 owner=root group=root
/sbin mode=755 owner=root group=root
/bin mode=755 owner=root group=root
/usr/lib/sysstat mode=755 owner=root group=root
```

## Cleanup

Cleanup command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'runuser -u attacker -- crontab -r >/dev/null 2>&1 || true; rm -rf /home/attacker/cron-deep; rm -f /var/spool/cron/crontabs/root /var/spool/cron/crontabs/attacker /var/spool/cron/crontabs/selfauth; rm -f /etc/cron.d/cron-deep-owner /etc/cron.d/cron-deep-mode /etc/cron.d/cron-deep-link; find /tmp -maxdepth 1 -name "cron_deep_*" -exec rm -rf -- {} +; touch /var/spool/cron/crontabs /etc/cron.d; echo "spool-after:"; find /var/spool/cron/crontabs -maxdepth 1 -mindepth 1 -printf "%M %u:%g %p -> %l\n" | sort || true; echo "attacker-crontab-after:"; runuser -u attacker -- crontab -l 2>&1; echo "attacker-crontab-rc=$?"; echo "probe-leftovers:"; find /tmp -maxdepth 1 -name "cron_deep_*" -printf "%M %u:%g %p\n" | sort || true; ls /etc/cron.d/cron-deep-* 2>&1 || true; [ -d /home/attacker/cron-deep ] && ls -ld /home/attacker/cron-deep || echo home-probe-absent; echo "cron-active:"; systemctl is-active cron.service'
```

Output:

```text
spool-after:
attacker-crontab-after:
no crontab for attacker
attacker-crontab-rc=1
probe-leftovers:
ls: cannot access '/etc/cron.d/cron-deep-*': No such file or directory
home-probe-absent
cron-active:
active
```

No PoC was created because no root LPE was validated in this lane.
