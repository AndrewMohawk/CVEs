# support/reporting helpers lane: negative

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS, attacker `uid=1001(attacker)` with only group `attacker`.

Probe: `pocs/support_reporting_helpers_probe.sh`
Log: `logs/support-reporting-helpers.out`

## Result

No local privilege escalation was found in the default support/reporting-helper lane.

No root shell, root-owned marker, attacker-controlled root execution, or attacker-controlled root file overwrite was produced. The only attacker-writable handoff locations observed were `/tmp`, `/var/tmp`, and `/var/crash`; the tested root contexts either rejected uid1001, were not default-active/reachable in this Docker target, or kept generated artifacts attacker-owned.

## Default reachability proven

- Installed/default packages in scope included `sosreport 4.10.2-0ubuntu0~24.04.1`, `open-vm-tools 2:13.0.0-2~ubuntu0.24.04.1`, `apport 2.28.1-0ubuntu3.8`, `apport-core-dump-handler`, `finalrd`, `friendly-recovery`, `byobu`, `unminimize`, `motd-news-config`, and `update-notifier-common`.
- `apport-forward.socket` was enabled and active, but `/run/apport.socket` was `0600 root:root`; uid1001 connect failed with `PermissionError`.
- Apport's root coredump path was reachable by simulating a uid1001 crash through `/usr/share/apport/apport`; a normal report became `/var/crash/_usr_bin_sleep.1001.crash` as `0640 attacker:root`.
- `finalrd.service` was enabled and active/exited with root `ExecStop=/usr/bin/finalrd`.
- `motd-news.timer` and `update-notifier-motd.timer` were enabled and active root timers.
- `open-vm-tools.service` was installed/enabled but had `ConditionVirtualization=vmware` and `ConditionResult=no` in this Docker target, so the root daemon was not active/reachable.
- `friendly-recovery.service` and the Apport autoreport path/timer were installed but had `ConditionResult=no`/inactive in this target.

## Negative evidence

- uid1001 `systemctl start` attempts for `apport-autoreport.service`, `motd-news.service`, `update-notifier-motd.service`, `finalrd.service`, `friendly-recovery.service`, and `open-vm-tools.service` all failed with interactive authentication required.
- uid1001 could not create or modify root handoff/config paths under `/run/finalrd`, `/run/motd.d`, `/etc/update-motd.d`, `/usr/share/finalrd`, `/lib/recovery-mode/options`, `/etc/vmware-tools`, `/var/cache/motd-news`, `/run/motd.dynamic`, `/var/lib/update-notifier/updates-available`, or `/var/lib/ubuntu-release-upgrader/release-upgrade-available`.
- `sos report --batch --dry-run` failed before collection with `Component must be run with root privileges`; the hostile `PATH` marker did not run.
- `vm-support` failed with `Please re-run this program as root`; its script hardcodes root-safe `PATH` and uses `mktemp -d /tmp/vm-support.XXXXXX`.
- `unminimize`, `finalrd`, and `vmware-checkvm` direct uid1001 execution did not cross privilege boundaries.
- `apport-cli` and `ubuntu-bug --save` produced only attacker-owned `.apport` files in `/tmp`.
- Apport `attach_root_command_outputs()` produced `uid=1001(attacker)` because `pkexec` is not installed in the target; no root command prefix was available.
- A symlink planted at Apport's expected crash path to `/root/support_reporting_helpers_apport_symlink_marker` was not followed; Apport returned nonzero and the root marker was absent.

## Conclusion

This lane is negative for the stated stock Ubuntu 24.04 Server Docker target and uid1001 attacker model. No `notes/support-reporting-helpers.md` was created because no root LPE was proven.
