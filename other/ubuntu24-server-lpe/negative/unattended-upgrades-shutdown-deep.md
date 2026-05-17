# Negative: unattended-upgrades shutdown helper

Status: no validated LPE.

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

## Default proof

Installed package versions:

```text
unattended-upgrades  2.9.1+nmu4ubuntu1
apt                  2.8.3
python3-apt          2.7.7ubuntu5.2
python3-dbus         1.3.2-5build3
systemd              255.4-1ubuntu8.15
```

The root service is default-enabled and active:

```text
/usr/lib/systemd/system/unattended-upgrades.service
ExecStart=/usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
KillMode=process
TimeoutStopSec=1800

Active: active (running)
Main PID: 317 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
```

Default config:

```text
/etc/apt/apt.conf.d/20auto-upgrades:
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";

/etc/apt/apt.conf.d/50unattended-upgrades:
//Unattended-Upgrade::InstallOnShutdown "false";
//Unattended-Upgrade::Automatic-Reboot "false";
```

## Code paths checked

`/usr/share/unattended-upgrades/unattended-upgrade-shutdown`:

```text
91  progress = "/var/run/unattended-upgrades.progress"
93  msg += "\n" + open(progress).read()
100 pidfile = "/var/run/unattended-upgrades.pid"
102 pid = int(open(pidfile).read())
105 os.kill(pid, signal.SIGTERM)
301 apt_pkg.config.find_b("Unattended-Upgrade::InstallOnShutdown", False)
307 subprocess.Popen(["unattended-upgrade"], env=env)
339 res = apt_pkg.get_lock(self.options.lock_file)
384 default lock file: /var/run/unattended-upgrades.lock
403 if not os.path.exists(logdir): os.makedirs(logdir)
405 logfile = os.path.join(logdir, "unattended-upgrades-shutdown.log")
```

The high-risk shapes are root reads of `/var/run/unattended-upgrades.pid` and `/var/run/unattended-upgrades.progress`, root lock handling of `/var/run/unattended-upgrades.lock`, and root spawning of `unattended-upgrade` on shutdown when configured.

## Unprivileged trigger tests

The attacker cannot create or replace the root-consumed runtime files:

```sh
runuser -u attacker -- bash -lc '
  printf $$ > /var/run/unattended-upgrades.pid; echo PID_RC:$?
  printf owned > /var/run/unattended-upgrades.progress; echo PROG_RC:$?
  printf owned > /var/run/unattended-upgrades.lock; echo LOCK_RC:$?
'
```

Observed:

```text
bash: /var/run/unattended-upgrades.pid: Permission denied
PID_RC:1
bash: /var/run/unattended-upgrades.progress: Permission denied
PROG_RC:1
bash: /var/run/unattended-upgrades.lock: Permission denied
LOCK_RC:1
```

The attacker also cannot signal or control the root service directly:

```text
systemctl kill -s HUP unattended-upgrades.service
=> Failed to kill unit unattended-upgrades.service: Interactive authentication required.
```

Runtime path permissions:

```text
drwxr-xr-x root:root /run
drwxr-xr-x root:root /var/run
drwxr-x--- root:adm  /var/log/unattended-upgrades
drwxr-xr-x root:root /var/lib/unattended-upgrades
```

The default logind policy does allow any user to take a delay shutdown inhibitor, and active users may normally request reboot/poweroff:

```text
org.freedesktop.login1.inhibit-delay-shutdown: any=yes inactive=yes active=yes
org.freedesktop.login1.reboot: any=auth_admin_keep inactive=auth_admin_keep active=yes
org.freedesktop.login1.power-off: any=auth_admin_keep inactive=auth_admin_keep active=yes
```

A normal attacker can obtain an inhibitor FD:

```sh
runuser -u attacker -- busctl call --system org.freedesktop.login1 \
  /org/freedesktop/login1 org.freedesktop.login1.Manager Inhibit \
  ssss shutdown ubulpe-test test delay
```

Observed:

```text
h 4
```

That does not provide attacker-controlled input to `unattended-upgrade-shutdown`; it only exercises the expected logind inhibitor interface.

## Why this is not a finding

The root service is default-active, but all root-consumed files are under root-owned `/run` or root-owned apt configuration paths. The attacker cannot plant the PID file that would make the root helper signal an arbitrary process, cannot plant the progress file read into root logs/plymouth messages, cannot replace the lock file, cannot change `InstallOnShutdown`, and cannot signal the service through systemd. Reboot/poweroff/inhibitor semantics can trigger shutdown paths for an active user, but no attacker-controlled code or root-owned arbitrary write is reached.

## Cleanup

No persistent attacker files were created. Verification:

```text
no /var/run/unattended-upgrades.pid
no /var/run/unattended-upgrades.progress
no attacker-owned unattended-upgrades paths
unattended-upgrades.service remains active
```

## Why scanners may miss it

The interesting part is semantic: a default root daemon reads PID/progress files and may spawn a root upgrade process on shutdown, but exploitability depends on who can create the runtime files and alter apt configuration. A simple scanner will flag root `open()`/`kill()`/`Popen()` paths but not prove that `/run` and apt config ownership block normal users in the default state.

## Suggested hardening

Keep runtime state under a dedicated root-owned `RuntimeDirectory=` with explicit mode, and validate PID file ownership/type before `os.kill()`. This is hardening only; no LPE was validated.
