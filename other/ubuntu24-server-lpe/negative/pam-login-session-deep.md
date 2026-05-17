# Negative: PAM/login/session/byobu/screen/locale deep pass

Date: 2026-05-16

Target: Docker image `ubuntu24-server-default-lpe:20260516-standard`, container `ubuntu24-server-lpe-target`, Ubuntu 24.04.4, `attacker` uid/gid 1001 with no sudo/admin groups. `selfauth` uid/gid 1002 is also non-admin and passworded for active-auth style checks.

Result: no stock Ubuntu 24.04 Server default uid1001-to-root LPE was found in this deeper PAM/login/session/update-motd/byobu/screen/locale/environment slice. The root-reachable pieces are either not attacker-triggerable, are polkit/admin gated, or consume only root-owned inputs. The user-controlled byobu and PAM environment files execute or appear only after the session has dropped to the target user.

## Default proof

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'cat /etc/os-release | sed -n "1,8p"; id attacker; id selfauth; dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n" openssh-server openssh-client byobu screen tmux libpam-modules libpam-runtime login passwd util-linux systemd locales polkitd dbus 2>&1 | sort; for b in /usr/bin/byobu /usr/bin/byobu-launch /usr/bin/screen /usr/bin/tmux /usr/bin/login /usr/bin/su /usr/bin/chsh /usr/bin/chfn /usr/sbin/update-locale /usr/bin/localectl /usr/bin/hostnamectl; do [ -e "$b" ] && stat -Lc "%A %U:%G %n" "$b"; done; systemctl list-unit-files screen-cleanup.service systemd-tmpfiles-setup.service systemd-localed.service systemd-hostnamed.service motd-news.timer update-notifier-motd.timer --no-pager'
```

Key output:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
byobu 6.11-0ubuntu1 ii
screen 4.9.1-1ubuntu1 ii
tmux 3.4-1ubuntu0.1 ii
libpam-modules:arm64 1.5.3-5ubuntu5.5 ii
login 1:4.13+dfsg1-4ubuntu3.2 ii
locales 2.39-0ubuntu8.7 ii
openssh-server un
systemd 255.4-1ubuntu8.15 ii
polkitd 124-2ubuntu1.24.04.3 ii
-rwxr-xr-x root:root /usr/bin/byobu
-rwxr-xr-x root:root /usr/bin/screen
-rwxr-xr-x root:root /usr/bin/login
-rwsr-xr-x root:root /usr/bin/su
-rwsr-xr-x root:root /usr/bin/chsh
-rwsr-xr-x root:root /usr/bin/chfn
screen-cleanup.service masked enabled
systemd-localed.service static -
systemd-hostnamed.service static -
motd-news.timer enabled enabled
update-notifier-motd.timer enabled enabled
```

PAM reachability command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'grep -RInE "pam_(motd|env|systemd|mail|lastlog|limits|umask|exec|namespace)" /etc/pam.d | sort'
```

Relevant output:

```text
/etc/pam.d/login:33:session optional pam_motd.so motd=/run/motd.dynamic
/etc/pam.d/login:34:session optional pam_motd.so noupdate
/etc/pam.d/login:51:session required pam_env.so readenv=1
/etc/pam.d/login:54:session required pam_env.so readenv=1 envfile=/etc/default/locale
/etc/pam.d/su:36:session required pam_env.so readenv=1
/etc/pam.d/su:39:session required pam_env.so readenv=1 envfile=/etc/default/locale
/etc/pam.d/common-session:29:session optional pam_systemd.so
```

`pam_motd` is still only on `/etc/pam.d/login`; `openssh-server` is absent; `/usr/bin/login` is not setuid. `su` is setuid, but its default stack has no MOTD or executable PAM hook.

## Screen cleanup

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'stat -Lc "%A %U:%G %F %n" /run/screen /etc/init.d/screen-cleanup /etc/tmpfiles.d/screen-cleanup.conf /usr/lib/tmpfiles.d/screen-cleanup.conf; systemctl status screen-cleanup.service --no-pager 2>&1 | sed -n "1,20p"; runuser -u attacker -- bash -lc '"'"'set -x; mkfifo /run/screen/pamdeep_fifo; ln -s /etc/shadow /run/screen/pamdeep_shadow_link; mkdir /run/screen/S-pamdeep; find /run/screen -maxdepth 1 -name "pamdeep*" -printf "%M %u:%g %p -> %l\n"; systemctl start screen-cleanup.service; systemd-tmpfiles --create /etc/tmpfiles.d/screen-cleanup.conf; /etc/init.d/screen-cleanup start; find /run/screen -maxdepth 1 -name "pamdeep*" -printf "%M %u:%g %p -> %l\n"'"'"'; systemctl start screen-cleanup.service 2>&1; systemd-tmpfiles --create /etc/tmpfiles.d/screen-cleanup.conf 2>&1; stat -Lc "%A %U:%G %F %n" /run/screen'
```

Key output:

```text
drwxrwxrwt root:utmp directory /run/screen
screen-cleanup.service Loaded: masked
mkfifo /run/screen/pamdeep_fifo
ln -s /etc/shadow /run/screen/pamdeep_shadow_link
Failed to start screen-cleanup.service: Interactive authentication required.
chmod: changing permissions of '/run/screen': Operation not permitted
lrwxrwxrwx attacker:attacker /run/screen/pamdeep_shadow_link -> /etc/shadow
Failed to start screen-cleanup.service: Unit screen-cleanup.service is masked.
drwxrwxrwt root:utmp directory /run/screen
```

The init script can be executed directly by uid1001, but then it runs as uid1001. It deleted the attacker-owned FIFO and failed at the root-owned directory chmod. The actual systemd service is masked even for root, and root tmpfiles only ensures `/run/screen` exists with `1777 root:utmp`; it did not follow attacker symlinks or create a write primitive.

## PAM env and byobu

Probe setup and trigger command:

```sh
docker exec -i ubuntu24-server-lpe-target bash <<'INCONTAINER'
install -d -o attacker -g attacker -m 0700 /home/attacker/.ubulpe-pamdeep-byobu /home/attacker/.ubulpe-pamdeep-bin
cat >/home/attacker/.pam_environment <<'EOF'
UBULPE_PAMENV DEFAULT=attacker_pamenv
PATH DEFAULT=/home/attacker/.ubulpe-pamdeep-bin:/usr/bin:/bin
PYTHONPATH DEFAULT=/home/attacker/.ubulpe-pamdeep-py
LC_BYOBU DEFAULT=1
EOF
cat >/home/selfauth/.pam_environment <<'EOF'
UBULPE_PAMENV DEFAULT=selfauth_pamenv
LC_BYOBU DEFAULT=1
EOF
cat >/home/attacker/.byoburc <<'EOF'
/usr/bin/printf "byoburc uid=%s euid=%s user=%s home=%s shell=%s\n" "$(/usr/bin/id -ru)" "$(/usr/bin/id -u)" "$USER" "$HOME" "$SHELL" >> /tmp/pamdeep_byobu_marker
export BYOBU_CONFIG_DIR=/home/attacker/.ubulpe-pamdeep-byobu
/bin/mkdir -p "$BYOBU_CONFIG_DIR"
/usr/bin/touch "$BYOBU_CONFIG_DIR/disable-autolaunch"
EOF
chown attacker:attacker /home/attacker/.pam_environment /home/attacker/.byoburc
chown selfauth:selfauth /home/selfauth/.pam_environment
su - attacker -c 'env | grep UBULPE || true; id'
su - selfauth -c 'env | grep UBULPE || true; id'
rm -f /tmp/pamdeep_byobu_marker
printf 'env | grep UBULPE || true; id; exit\n' | timeout 10s script -qfec "env -i LC_BYOBU=1 TERM=xterm HOME=/home/attacker USER=attacker LOGNAME=attacker SHELL=/bin/bash /usr/bin/login -p -f attacker" /tmp/pamdeep_login_env.typescript >/tmp/pamdeep_login_env.out 2>&1 || true
sed -n '1,80p' /tmp/pamdeep_login_env.out
cat /tmp/pamdeep_byobu_marker 2>/dev/null || echo NONE
[ -e /tmp/pamdeep_byobu_marker ] && stat -Lc '%A %U:%G %n' /tmp/pamdeep_byobu_marker
INCONTAINER
```

Key output:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
env | grep UBULPE || true; id; exit
Welcome to Ubuntu 24.04.4 LTS ...
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
byoburc uid=1001 euid=1001 user=attacker home=/home/attacker shell=/bin/bash
byoburc uid=1001 euid=1001 user=attacker home=/home/attacker shell=/bin/bash
-rw-rw-r-- attacker:attacker /tmp/pamdeep_byobu_marker
```

The default `pam_env.so` lines did not read `~/.pam_environment` for `attacker` or `selfauth`; no `UBULPE_PAMENV` reached the session. Forcing `LC_BYOBU=1` through a root-owned `login -p -f attacker` simulation did source attacker-controlled `.byoburc`, but only after uid/euid had become 1001. That gives user-session code execution, not root execution.

## Locale, hostname, and manager environment

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'pkaction --verbose 2>/dev/null | awk '"'"'/org.freedesktop.(locale1|hostname1).(set-locale|set-hostname|set-static-hostname|set-machine-info)/{show=1} show{print} /^$/{show=0}'"'"' | sed -n "1,120p"; runuser -u attacker -- bash -lc '"'"'set -x; localectl set-locale LANG=en_US.UTF-8; hostnamectl set-hostname pamdeep-host; busctl call org.freedesktop.locale1 /org/freedesktop/locale1 org.freedesktop.locale1 SetLocale asb 1 LANG=xx_XX.UTF-8 false; systemctl set-environment PAMDEEP=1'"'"'; for p in /etc/locale.conf /etc/default/locale /etc/hostname /etc/environment /etc/profile.d /usr/lib/environment.d; do [ -e "$p" ] && stat -Lc "%A %U:%G %F %n" "$p" || echo "MISSING $p"; done'
```

Key output:

```text
org.freedesktop.hostname1.set-hostname implicit any/inactive/active: auth_admin_keep
org.freedesktop.hostname1.set-machine-info implicit any/inactive/active: auth_admin_keep
org.freedesktop.hostname1.set-static-hostname implicit any/inactive/active: auth_admin_keep
org.freedesktop.locale1.set-locale implicit any/inactive/active: auth_admin_keep
Failed to issue method call: Interactive authentication required.
Could not set static hostname: Interactive authentication required.
Call failed: Interactive authentication required.
Failed to set environment: Access denied
-rw-r--r-- root:root regular file /etc/locale.conf
-rw-r--r-- root:root regular file /etc/default/locale
-rw-r--r-- root:root regular file /etc/hostname
-rw-r--r-- root:root regular file /etc/environment
drwxr-xr-x root:root directory /etc/profile.d
drwxr-xr-x root:root directory /usr/lib/environment.d
```

`systemd-localed` and `systemd-hostnamed` are root D-Bus services that can write locale/hostname files, but the default policy requires admin authentication even for active subjects. uid1001 could not set locale, hostname, or the system manager environment.

## Setuid locale/env secure-exec check

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'install -d -o attacker -g attacker -m 0700 /home/attacker/.ubulpe-pamdeep-locale /home/attacker/.ubulpe-pamdeep-gconv /home/attacker/.ubulpe-pamdeep-nls /home/attacker/.ubulpe-pamdeep-terminfo; timeout 4s strace -f -s 180 -e trace=file -o /tmp/pamdeep_su.strace -u attacker env -i HOME=/home/attacker USER=attacker LOGNAME=attacker SHELL=/bin/bash GCONV_PATH=/home/attacker/.ubulpe-pamdeep-gconv LOCPATH=/home/attacker/.ubulpe-pamdeep-locale NLSPATH=/home/attacker/.ubulpe-pamdeep-nls/%N TERMINFO=/home/attacker/.ubulpe-pamdeep-terminfo LANG=zz_ZZ.UTF-8 LC_ALL=zz_ZZ.UTF-8 /usr/bin/su root -c true </dev/null >/tmp/pamdeep_su.out 2>/tmp/pamdeep_su.err || true; timeout 4s strace -f -s 180 -e trace=file -o /tmp/pamdeep_chfn.strace -u attacker env -i HOME=/home/attacker USER=attacker LOGNAME=attacker GCONV_PATH=/home/attacker/.ubulpe-pamdeep-gconv LOCPATH=/home/attacker/.ubulpe-pamdeep-locale NLSPATH=/home/attacker/.ubulpe-pamdeep-nls/%N TERMINFO=/home/attacker/.ubulpe-pamdeep-terminfo LANG=zz_ZZ.UTF-8 LC_ALL=zz_ZZ.UTF-8 /usr/bin/chfn --help >/tmp/pamdeep_chfn.out 2>/tmp/pamdeep_chfn.err || true; sed -n "1,20p" /tmp/pamdeep_su.out /tmp/pamdeep_su.err 2>/dev/null; grep -hE "/home/attacker/\\.ubulpe-pamdeep-(gconv|locale|nls|terminfo)" /tmp/pamdeep_su.strace /tmp/pamdeep_chfn.strace 2>/dev/null | sed -n "1,80p" || true; grep -hE "execve\\(\"/(usr/bin/su|usr/bin/chfn)|/usr/lib/locale" /tmp/pamdeep_su.strace /tmp/pamdeep_chfn.strace 2>/dev/null | sed -n "1,120p" || true'
```

Key output:

```text
Password: su: Authentication failure
execve("/usr/bin/su", ["/usr/bin/su", "root", "-c", "true"], ... ) = 0
openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = -1 ENOENT
openat(AT_FDCWD, "/usr/lib/locale/zz_ZZ.UTF-8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = -1 ENOENT
execve("/usr/bin/chfn", ["/usr/bin/chfn", "--help"], ... ) = 0
openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = -1 ENOENT
openat(AT_FDCWD, "/usr/lib/locale/zz_ZZ.UTF-8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = -1 ENOENT
```

The only `/home/attacker/.ubulpe-pamdeep-*` strings in the trace were pre-setuid `/usr/bin/env` argument vectors. After `su` and `chfn` exec, locale loading consulted system paths under `/usr/lib/locale`; no attacker `GCONV_PATH`, `LOCPATH`, `NLSPATH`, or `TERMINFO` path was opened by the setuid helpers.

## Cleanup

The probe used backups for touched dotfiles, but the first trap deleted its state file before restoration. I then removed only files whose contents matched the probe signatures and verified no probe artifacts remained:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'clean_if_probe() { p="$1"; sig="$2"; if [ -f "$p" ] && grep -q "$sig" "$p"; then rm -f "$p"; echo "removed $p"; else echo "kept $p"; fi; }; clean_if_probe /home/attacker/.byoburc "pamdeep_byobu_marker"; clean_if_probe /home/attacker/.pam_environment "UBULPE_PAMENV DEFAULT=attacker_pamenv"; clean_if_probe /home/selfauth/.pam_environment "UBULPE_PAMENV DEFAULT=selfauth_pamenv"; find /tmp /home/attacker /home/selfauth /run/screen -maxdepth 2 \( -name "pamdeep*" -o -name ".ubulpe-pamdeep*" \) -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sort || true; for p in /home/attacker/.byoburc /home/attacker/.pam_environment /home/selfauth/.pam_environment; do [ -e "$p" ] || [ -L "$p" ] && ls -ld "$p" || echo MISSING "$p"; done'
```

Cleanup output:

```text
removed /home/attacker/.byoburc
removed /home/attacker/.pam_environment
removed /home/selfauth/.pam_environment
MISSING /home/attacker/.byoburc
MISSING /home/attacker/.pam_environment
MISSING /home/selfauth/.pam_environment
```

Final artifact verification:

```sh
docker exec ubuntu24-server-lpe-target bash -lc 'find /tmp /home/attacker /home/selfauth /run/screen -maxdepth 2 \( -name "pamdeep*" -o -name ".ubulpe-pamdeep*" \) -printf "%M %u:%g %p -> %l\n" 2>/dev/null | sort || true'
```

Output was empty.

## Conclusion

This pass found no real root-executed default helper boundary that consumes uid1001-controlled files, environment, terminal state, hostname/locale, writable directories, run-parts paths, or hooks in a way that yields root code execution or a root-owned arbitrary write. The remaining interesting edges are scanner-attractive but not exploitable in the default Docker server state:

- `/run/screen` is world-writable/sticky, but the root cleanup service is masked and tmpfiles only creates the directory.
- byobu sources `~/.byoburc`, but only in the user's shell after uid/euid are 1001.
- `~/.pam_environment` was not read by the default `pam_env.so` configuration.
- localed/hostnamed writes are admin-polkit gated.
- setuid auth helpers ignored attacker-controlled locale loader paths and used system locale directories.
