# Negative: Ubuntu Pro / ubuntu-advantage default surfaces

Status: no validated uid1001 -> root local privilege escalation.

## Scope

Target was the live Docker Ubuntu Server target `ubuntu24-server-lpe-target`, using the stock server package set already established for this hunt. Attacker identity:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Relevant default package versions:

```text
Ubuntu 24.04.4 LTS (noble)
apt                    2.8.3
motd-news-config       13ubuntu10.4
ubuntu-pro-client      37.2ubuntu~24.04
unattended-upgrades    2.9.1+nmu4ubuntu1
```

`/usr/bin/pro` and `/usr/bin/ua` are root-owned non-setuid symlinks to `ubuntu-advantage`.

## Default-install and reachability proof

Default unit files are present:

```text
apt-news.service
esm-cache.service
ua-reboot-cmds.service
ua-timer.service
ua-timer.timer
ubuntu-advantage.service
motd-news.service
motd-news.timer
update-notifier-motd.service
update-notifier-motd.timer
```

Default live state:

```text
motd-news.timer              active/waiting
update-notifier-motd.timer   active/waiting
apt-daily.timer              active/waiting
apt-daily-upgrade.timer      active/waiting
ua-timer.timer               inactive/dead; ConditionResult=no
ubuntu-advantage.service     inactive/dead; ConditionResult=no
ua-reboot-cmds.service       inactive/dead; ConditionResult=no
```

No Ubuntu Pro D-Bus service is present on the system bus. The only matching Ubuntu D-Bus service in this target was `com.ubuntu.SoftwareProperties`, which is a separate package/surface.

Relevant state/config paths are not attacker-writable:

```text
/etc/ubuntu-advantage/uaclient.conf           -rw-r--r-- root root
/var/lib/ubuntu-advantage                     drwxr-xr-x root root
/var/lib/ubuntu-advantage/status.json         -rw-r--r-- root root
/run/ubuntu-advantage                         drwxr-xr-x root root
/run/ubuntu-advantage/apt-news                drwxr-xr-x _apt root
/run/ubuntu-advantage/apt-news/aptnews.json   -rw-r--r-- root root
/etc/default/motd-news                        -rw-r--r-- root root
/var/cache/motd-news                          -rw-r--r-- root root
```

## Code and config evidence

`/usr/lib/systemd/system/ubuntu-advantage.service` only runs in unattached cloud/retry states: line 20 requires absence of the machine token, while lines 26-29 require a GCE/Azure/LXD cloud marker or auto-attach failure flag. Its root entrypoint is line 32, `/usr/bin/python3 /usr/lib/ubuntu-advantage/daemon.py`.

`/usr/lib/systemd/system/ua-timer.timer` is attached-only: lines 5-6 require `/var/lib/ubuntu-advantage/private/machine-token.json`. `ua-timer.service` line 14 runs `/usr/lib/ubuntu-advantage/timer.py`.

`/usr/lib/systemd/system/ua-reboot-cmds.service` is attached-and-marker-only: lines 10-12 require reboot marker state plus the private machine token. Line 17 runs `/usr/lib/ubuntu-advantage/reboot_cmds.py`.

`/etc/apt/apt.conf.d/20apt-esm-hook.conf` is root-gated:

```text
1 APT::Update::Pre-Invoke {
2   "[ ! -e /run/systemd/system ] || [ $(id -u) -ne 0 ] || systemctl start --no-block apt-news.service esm-cache.service >/dev/null 2>&1 || true";
5 binary::apt::AptCli::Hooks::Upgrade {
6   "[ ! -f /usr/lib/ubuntu-advantage/apt-esm-json-hook ] || [ $(id -u) -ne 0 ] || /usr/lib/ubuntu-advantage/apt-esm-json-hook 2>> /var/log/ubuntu-advantage-apt-hook.log || true";
```

`/usr/lib/systemd/system/apt-news.service` lines 15-17 run `/usr/bin/python3 /usr/lib/ubuntu-advantage/apt_news.py` with an AppArmor profile and capability restrictions. `apt_news.py` lines 201-209 create/chown only the fixed `/run/ubuntu-advantage/apt-news` cache path, and lines 273-288 write/delete fixed Ubuntu Pro message files.

`/etc/update-motd.d/91-contract-ua-esm-status` lines 2-8 only `cat` fixed stamp files under `/var/lib/ubuntu-advantage/messages`.

State-changing Pro CLI commands are root-decorated: `uaclient/cli/cli_util.py` lines 83-91 enforce `assert_root`; `uaclient/cli/config.py` line 66 applies it to `pro config set`; `uaclient/cli/refresh.py` line 46 applies it to `pro refresh`.

## Attacker probes

Read-only status works as uid1001 and confirms unattached state:

```sh
runuser -u attacker -- pro status --format json
```

Observed:

```text
"attached": false
"result": "success"
"version": "37.2ubuntu~24.04"
```

State-changing commands fail before privileged effects:

```sh
runuser -u attacker -- pro config set apt_news=false
runuser -u attacker -- pro refresh
runuser -u attacker -- pro api u.pro.attach.auto.configure_retry_service.v1 --data '{}'
```

Observed:

```text
This command must be run as root (try using sudo).
This command must be run as root (try using sudo).
[Errno 13] Permission denied: '/var/lib/ubuntu-advantage/tmpxmlog5z9'
```

Starting root units and poisoning the system manager environment are denied:

```sh
runuser -u attacker -- systemctl start apt-news.service
runuser -u attacker -- systemctl start esm-cache.service
runuser -u attacker -- systemctl start ua-timer.service
runuser -u attacker -- systemctl start ubuntu-advantage.service
runuser -u attacker -- systemctl set-environment PYTHONPATH=/tmp/proinj
```

Observed:

```text
Failed to start ...: Interactive authentication required.
Failed to set environment: Access denied
```

Direct helper execution is not privileged:

```sh
runuser -u attacker -- /etc/update-motd.d/91-contract-ua-esm-status
runuser -u attacker -- /usr/lib/ubuntu-advantage/apt-esm-json-hook
runuser -u attacker -- apt-get update
```

Observed:

```text
# MOTD Pro status hook produced no output
pro-hook: missing socket fd
E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)
```

Attacker writes into Pro/MOTD state are denied:

```text
/var/lib/ubuntu-advantage/status.json: Permission denied
/var/lib/ubuntu-advantage/messages: Permission denied
/run/ubuntu-advantage/apt-news/aptnews.json: Permission denied
/run/ubuntu-advantage/apt-news/attacker: Permission denied
/var/cache/motd-news: Permission denied
```

## Why this is not a finding

The default root-executed Ubuntu Pro paths are either condition-gated out in the unattached stock state, started only by root apt/systemd timers with fixed unit environments, or read fixed root-owned state. The uid1001 user can read Pro status and run helpers in their own context, but cannot write Pro config, Pro state, apt-news state, MOTD cache, systemd manager environment, or start the root services. No tested path produced root-owned attacker-controlled writes or root code execution.

## Scanner-miss notes

A scanner can reasonably flag this surface because it has root timers, apt hooks, shell snippets with unqualified `id`/`systemctl`, MOTD shell code, Python state-file writers, `_apt` chown behavior, and an executable apt hook binary. The exploitability hinges on default reachability: the root hooks require uid 0, the attached timers require a missing private token, the state parents are root-owned, and systemd/polkit block uid1001 service starts and environment injection.

## Cleanup

No persistent target changes were required. Temporary MOTD probe files under `/tmp` were removed, and no `/var/lib/ubuntu-advantage/tmp*` files remained after the failed uid1001 API probe.

## Triage hardening ideas

No Ubuntu Security LPE fix is suggested from this negative result. Defense-in-depth changes worth considering separately: use absolute `/usr/bin/id` and `/usr/bin/systemctl` in the apt hook, quote `$CACHE` in `50-motd-news`, and add stronger systemd hardening to `apt-news.service`/`esm-cache.service` where compatibility allows.
