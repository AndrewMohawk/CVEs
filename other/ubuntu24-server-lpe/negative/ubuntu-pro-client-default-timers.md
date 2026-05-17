# Negative: ubuntu-pro-client timers and hooks

Status: no validated privilege escalation.

## Default proof

Target baseline: `baseline/live-target-standard`.

Installed packages:

```text
ubuntu-pro-client       37.2ubuntu~24.04
ubuntu-pro-client-l10n  37.2ubuntu~24.04
```

Default root units exist:

```text
ubuntu-advantage.service  ExecStart=/usr/bin/python3 /usr/lib/ubuntu-advantage/daemon.py
ua-timer.timer            triggers ua-timer.service
ua-timer.service          ExecStart=/usr/bin/python3 /usr/lib/ubuntu-advantage/timer.py
ua-reboot-cmds.service    ExecStart=/usr/bin/python3 /usr/lib/ubuntu-advantage/reboot_cmds.py
apt-news.service          ExecStart=/usr/bin/python3 /usr/lib/ubuntu-advantage/apt_news.py
esm-cache.service         ExecStart=/usr/bin/python3 /usr/lib/ubuntu-advantage/esm_cache.py
```

Default state on the stock target:

```text
/etc/ubuntu-advantage              drwxr-xr-x root root
/etc/ubuntu-advantage/uaclient.conf -rw-r--r-- root root
/var/lib/ubuntu-advantage          drwxr-xr-x root root
```

## Candidate

The candidate was a root periodic-job/config boundary: if a normal user could influence Ubuntu Pro client config or marker files, root timers might execute attacker-controlled network/config behavior.

## Code/config evidence

Systemd unit gating prevents the root background jobs from running in the unattached default state:

- `ubuntu-advantage.service` has `ConditionPathExists=!/var/lib/ubuntu-advantage/private/machine-token.json` plus OR conditions for cloud/pro retry markers under `/run/cloud-init/...` or `/run/ubuntu-advantage/flags/auto-attach-failed`.
- `ua-timer.timer` has `ConditionPathExists=/var/lib/ubuntu-advantage/private/machine-token.json`.
- `ua-reboot-cmds.service` requires both marker files and `/var/lib/ubuntu-advantage/private/machine-token.json`.

The apt/news helpers are root-owned unit scripts under `/usr/lib/ubuntu-advantage/`, and their configuration path is root-owned.

## Attacker tests

As `attacker`:

```sh
pro status
pro api u.pro.status.is_attached.v1
pro refresh
```

Observed:

```text
This machine is not attached to an Ubuntu Pro subscription.
{"type": "IsAttached", "attributes": {"is_attached": false, ...}, "result": "success"}
This command must be run as root (try using sudo).
```

## Why it is not a finding

The normal user can read status but cannot write Pro client state, attachment data, or service marker files. The recurring privileged jobs are gated on root-owned files that are absent by default, and the direct state-changing CLI path enforces root. No default unprivileged trigger reaches root execution or root-controlled file writes.

Cleanup: none required.
