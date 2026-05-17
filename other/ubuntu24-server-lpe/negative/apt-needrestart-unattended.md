# apt / needrestart / unattended-upgrades / dpkg-db-backup negative audit

Target: `ubuntu24-server-lpe-target`, stock Ubuntu Server 24.04 Docker/systemd target.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no real uid1001 -> root LPE was found in the scoped apt hooks, needrestart scanners, unattended-upgrades shutdown helper, apt daily timer, or dpkg-db-backup timer paths. I did not create a PoC because the tested influence paths either require root-controlled environment/configuration, only cause attacker-owned execution, or amount to DoS.

## Default state proved

Package and OS state:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
apt                     2.8.3
dpkg                    1.22.6ubuntu6.6
needrestart             3.6-7ubuntu4.5
perl                    5.38.2-3.2ubuntu0.2
python3                 3.12.3-0ubuntu2.1
systemd                 255.4-1ubuntu8.15
unattended-upgrades     2.9.1+nmu4ubuntu1
```

Default timer/service roots:

```text
apt-daily.timer                enabled, active, triggers apt-daily.service
apt-daily-upgrade.timer        enabled, active, triggers apt-daily-upgrade.service
dpkg-db-backup.timer           enabled, active, triggers dpkg-db-backup.service
unattended-upgrades.service    enabled, active, PID 317

apt-daily.service              ExecStart=/usr/lib/apt/apt.systemd.daily update
apt-daily-upgrade.service      ExecStart=/usr/lib/apt/apt.systemd.daily install
dpkg-db-backup.service         ExecStart=/usr/libexec/dpkg/dpkg-db-backup
unattended-upgrades.service    ExecStart=/usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
```

Root-run script and directory permissions:

```text
root:root 0644 /etc/apt/apt.conf.d/99needrestart
root:root 0755 /usr/lib/needrestart/apt-pinvoke
root:root 0755 /usr/sbin/needrestart
root:root 0755 /usr/share/unattended-upgrades/unattended-upgrade-shutdown
root:root 0755 /usr/lib/apt/apt.systemd.daily
root:root 0755 /usr/libexec/dpkg/dpkg-db-backup
root:root 0755 /var/cache/apt /var/cache/apt/archives /var/backups /var/lib/apt /var/lib/dpkg
```

Needrestart apt hook:

```text
DPkg::Post-Invoke {"test -x /usr/lib/needrestart/apt-pinvoke && /usr/lib/needrestart/apt-pinvoke -m u || true"; };
```

`apt-pinvoke` only executes `/usr/sbin/needrestart` when root-created `/run/needrestart/unpacked` exists, and uid1001 cannot create `/run/needrestart` or `unpacked`.

## Tested influence paths

Systemd manager environment and unit control are not uid1001-controlled:

```text
systemctl set-environment PATH=/home/attacker/bin:/usr/bin:/bin
Failed to set environment: Access denied

systemctl import-environment PATH
Failed to import environment: Access denied

systemctl start apt-daily.service
Failed to start apt-daily.service: Interactive authentication required.

systemd-run --unit=aptnr-attacker /bin/true
Failed to start transient service unit: Interactive authentication required.

busctl ... Manager SetEnvironment ...
Call failed: Access denied
```

The service manager environment stayed root-controlled:

```text
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
root:root 0755 /usr/local /usr/local/bin /usr/local/sbin
```

No scoped tree was writable by uid1001:

```text
find /etc/apt /etc/needrestart /usr/lib/needrestart /usr/share/perl5/NeedRestart \
  /usr/share/unattended-upgrades /usr/lib/apt /usr/libexec/dpkg \
  /var/cache/apt /var/backups /var/lib/apt /var/lib/dpkg -maxdepth 3 -writable

# no output as attacker
```

Needrestart interpreter scanner tests:

* Python, Perl, Ruby, and Java scanners were inspected under `/usr/share/perl5/NeedRestart/Interp`.
* Python/Ruby scanner child execution uses `local %ENV` and an empty working directory before invoking the interpreter to query include paths.
* Perl scanner uses `local %ENV` before invoking Perl for `@INC`.
* User `PYTHONPATH`, `PERL5LIB`, and source files are parsed/stat'ed for stale-file detection, but attacker modules were not imported by root in the patched package.

Runtime proof:

```text
# after starting attacker Python/PERL processes, deleting their side-effect files,
# and running root needrestart -v -b -r l:

[Core] #22088 is a NeedRestart::Interp::Python
[Python] #22088: source=/home/attacker/aptnr_py/sleeper.py
[Core] #22089 is a NeedRestart::Interp::Perl
[Perl] #22089: source=/home/attacker/aptnr_perl/sleeper.pl

ls: cannot access '/tmp/aptnr_py_root': No such file or directory
ls: cannot access '/tmp/aptnr_perl_root': No such file or directory
```

Process stale-source spoofing did not turn into a service restart or root command execution:

```text
[Core] #22121 uses obsolete script file(s):
[Core] #22121  /home/attacker/aptnr_py/sleeper2.py
[main] #22121 unexpected cgroup '/docker/.../init.scope'
[main] trying systemctl status
[main] #22121 running /etc/needrestart/hook.d/10-dpkg
[main] #22121 running /etc/needrestart/hook.d/20-rpm
[main] #22121 running /etc/needrestart/hook.d/90-none

# no NEEDRESTART-SVC for the attacker process
```

Private mount namespace interpreter spoofing was also negative. uid1001 could `unshare -Urm` and bind mount `/bin/sleep` over `/usr/bin/python3`, but root needrestart still did not execute attacker code:

```text
readlink /proc/22441/exe
/usr/bin/python3.12

/proc/22441/mountinfo:
/usr/bin/sleep /usr/bin/python3.12 ...

[Core] #22441 is a NeedRestart::Interp::Python
[Python] #22441: source file not found, skipping
[Python] #22441:  reduced ARGV: 120
```

Cgroup/unit attribution is kernel/systemd controlled. uid1001 had no writable `cgroup.procs`, no user systemd bus in this target, and root systemd DBus methods that would place a process in a root service cgroup required authentication.

Unattended-upgrades shutdown helper:

* The running helper is root PID 317: `/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal`.
* It reads `/var/run/unattended-upgrades.pid` and `/var/run/unattended-upgrades.progress`, but `/var/run` is `/run`, mode 0755 root-owned, and those files were absent/root-only.
* uid1001 could not create the pid/progress files, signal PID 317, or read its environment.

Evidence:

```text
touch /run/needrestart/unpacked
touch: cannot touch '/run/needrestart/unpacked': No such file or directory

mkdir -p /run/needrestart
mkdir: cannot create directory '/run/needrestart': Permission denied

echo $$ > /var/run/unattended-upgrades.pid
bash: /var/run/unattended-upgrades.pid: Permission denied

kill -TERM 317
bash: kill: (317) - Operation not permitted

head -c 200 /proc/317/environ
head: cannot open '/proc/317/environ' for reading: Permission denied
```

uid1001 could emit a fake `PrepareForShutdown` signal and take a logind delay inhibitor, but the fake signal did not change the service log or execute attacker-controlled code. The inhibitor is DoS/noise only and out of scope.

`apt.systemd.daily` and `dpkg-db-backup` PATH/config tests:

* `apt.systemd.daily` uses `apt-config`, `apt-get`, and `unattended-upgrade`, but root timer services have no attacker-controlled `Environment=` and apt config paths are root-owned.
* This Docker target also has `APT::Periodic::Enable "0"` from Docker apt config, so the daily apt script exits after setup unless root changes config.
* `dpkg-db-backup` uses `DPKG_DATADIR` and unqualified commands such as `basename`, `tar`, and `savelog`, but the timer does not inherit uid1001 environment and uid1001 cannot set the system manager environment.

Directly running `dpkg-db-backup` under an attacker-controlled `PATH` as uid1001 demonstrated why the script would be unsafe under a hostile root environment, but that is not a default LPE because uid1001 cannot supply that environment to the root timer. A clean systemd-triggered run after deleting the marker did not execute `/home/attacker/bin`:

```text
rm -f /tmp/aptnr_path_pwn
systemctl start dpkg-db-backup.service
ls -l /tmp/aptnr_path_pwn
ls: cannot access '/tmp/aptnr_path_pwn': No such file or directory
```

## Cleanup

Removed test artifacts from the target:

```text
/home/attacker/aptnr_py
/home/attacker/aptnr_perl
/home/attacker/aptnr_*.pid
/home/attacker/bin
/home/attacker/ns_pid
/home/attacker/ns_shell.pid
/home/attacker/ns.log
/tmp/aptnr_*
/tmp/aptnr_cg
/tmp/aptnr_ns
```

No `aptnr`, `sleeper.py`, `sleeper.pl`, `sleeper2.py`, or `python3 120` test processes remained after cleanup.
