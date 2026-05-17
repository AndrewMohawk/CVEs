# aptnr evidence notes, 2026-05-16

Scope: `ubuntu24-server-lpe-target`, uid1001 non-sudo attacker, apt hooks, needrestart, unattended-upgrades shutdown, apt daily, dpkg-db-backup.

Most relevant negative probes:

```text
systemctl set-environment PATH=/home/attacker/bin:/usr/bin:/bin
Failed to set environment: Access denied

systemctl start apt-daily.service
Failed to start apt-daily.service: Interactive authentication required.

busctl ... org.freedesktop.systemd1.Manager SetEnvironment ...
Call failed: Access denied
```

```text
runuser -u attacker -- find /etc/apt /etc/needrestart /usr/lib/needrestart \
  /usr/share/perl5/NeedRestart /usr/share/unattended-upgrades /usr/lib/apt \
  /usr/libexec/dpkg /var/cache/apt /var/backups /var/lib/apt /var/lib/dpkg \
  -maxdepth 3 -writable

# no writable files/dirs in scoped roots
```

```text
Needrestart malicious interpreter-env test:
[Core] #22088 is a NeedRestart::Interp::Python
[Python] #22088: source=/home/attacker/aptnr_py/sleeper.py
[Core] #22089 is a NeedRestart::Interp::Perl
[Perl] #22089: source=/home/attacker/aptnr_perl/sleeper.pl
ls: cannot access '/tmp/aptnr_py_root': No such file or directory
ls: cannot access '/tmp/aptnr_perl_root': No such file or directory
```

```text
Needrestart stale user source test:
[Core] #22121 uses obsolete script file(s):
[Core] #22121  /home/attacker/aptnr_py/sleeper2.py
[main] #22121 unexpected cgroup '/docker/.../init.scope'
[main] trying systemctl status
# no NEEDRESTART-SVC
```

```text
Namespace spoof test:
unshare -Urm; bind mount /bin/sleep over /usr/bin/python3; run /usr/bin/python3 120.
readlink /proc/22441/exe -> /usr/bin/python3.12
mountinfo showed /usr/bin/sleep mounted on /usr/bin/python3.12
needrestart classified it as Python but did not execute attacker code:
[Python] #22441: source file not found, skipping
```

```text
unattended-upgrades pid/progress/signal:
mkdir -p /run/needrestart -> Permission denied
echo $$ > /var/run/unattended-upgrades.pid -> Permission denied
kill -TERM 317 -> Operation not permitted
head /proc/317/environ -> Permission denied
```

```text
dpkg-db-backup service PATH:
systemctl show-environment -> PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
root:root 0755 /usr/local /usr/local/bin /usr/local/sbin
after rm -f /tmp/aptnr_path_pwn and systemctl start dpkg-db-backup.service:
ls: cannot access '/tmp/aptnr_path_pwn': No such file or directory
```
