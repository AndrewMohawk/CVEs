# Negative: release-upgrader and update-notifier pkexec policy paths

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Attacker is `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

## Result

No root LPE was validated. The Server default install includes the release-upgrader and update-notifier helper programs plus Polkit action XML for pkexec launch, but `pkexec` itself is not installed. Direct helper execution stays uid1001, root systemd service starts are polkit/admin gated, and there is no system D-Bus release-upgrader service.

Artifacts:

```text
pocs/release_upgrader_pkexec_probe.sh
logs/release-upgrader-pkexec.out
```

## Default package and reachability proof

Probe output:

```text
ubuntu-release-upgrader-core  1:24.04.28     ii
update-manager-core           1:24.04.12     ii
python3-update-manager        1:24.04.12     ii
update-notifier-common        3.192.68.2     ii
polkitd                       124-2ubuntu1.24.04.3 ii
dbus                          1.14.10-4ubuntu4.1 ii
pkexec                                         un
```

Default helper files:

```text
/usr/bin/do-release-upgrade                              -rwxr-xr-x root:root
/usr/lib/ubuntu-release-upgrader/do-partial-upgrade      -rwxr-xr-x root:root
/usr/lib/update-notifier/cddistupgrader                  -rwxr-xr-x root:root
/usr/share/polkit-1/actions/com.ubuntu.release-upgrader.policy root:root 0644
/usr/share/polkit-1/actions/com.ubuntu.update-notifier.policy  root:root 0644
```

Policy entries exist:

```text
com.ubuntu.release-upgrader.release-upgrade
  exec.path=/usr/bin/do-release-upgrade
  allow_active=auth_admin

com.ubuntu.release-upgrader.partial-upgrade
  exec.path=/usr/lib/ubuntu-release-upgrader/do-partial-upgrade
  allow_active=auth_admin

com.ubuntu.update-notifier.pkexec.cddistupgrader
  exec.path=/usr/lib/update-notifier/cddistupgrader
  allow_any/auth_inactive/auth_active=auth_admin
```

But `command -v pkexec` returned absent, and searching system D-Bus service/policy directories for release-upgrader/DistUpgrade/cddist returned no root D-Bus service.

## Trigger attempts

The probe ran the helpers as uid1001 with hostile `PATH` and `PYTHONPATH`:

```sh
runuser -u attacker -- env -i HOME=/home/attacker USER=attacker LOGNAME=attacker \
  PATH=/tmp/release-upgrader-pkexec/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  PYTHONPATH=/tmp/release-upgrader-pkexec/py \
  /usr/bin/do-release-upgrade -f DistUpgradeViewNonInteractive -m server -q

runuser -u attacker -- env -i ... /usr/lib/ubuntu-release-upgrader/do-partial-upgrade
runuser -u attacker -- env -i ... /usr/lib/update-notifier/cddistupgrader
runuser -u attacker -- sh -lc 'command -v pkexec || true; pkexec /usr/bin/do-release-upgrade --help'
runuser -u attacker -- systemctl start update-notifier-motd.service
runuser -u attacker -- systemctl start update-notifier-download.service
```

Observed results:

```text
do-release-upgrade --help                     rc=0, uid1001 only
do-release-upgrade noninteractive server mode rc=1, no root marker
do-partial-upgrade                            FileNotFoundError: /usr/bin/pkexec
cddistupgrader                                attacker-owned /tmp/distupgrade.* failure only
pkexec do-release-upgrade                     sh: pkexec: not found
systemctl start update-notifier-*.service     Interactive authentication required
```

`cddistupgrader` did create an attacker-owned `/tmp/distupgrade.*` working directory while running as uid1001; it did not execute in root context and did not write a privileged file.

## Root proof

Negative:

```text
ROOT_PROOF=no
```

No `/root/release_upgrader_pkexec_root_marker` or other root-owned attacker-controlled artifact was created.

## Cleanup

Removed:

```sh
rm -rf /tmp/distupgrade.* /tmp/release-upgrader-pkexec
rm -f /root/release_upgrader_pkexec_probe.sh /root/release_upgrader_pkexec_root_marker
```

Post-cleanup:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> no failed units
```

## Why scanners may over-rank this

Static policy scans see root-owned helper programs with Polkit `exec.path` annotations and updater code that manipulates temporary directories and distribution-upgrade archives. The default Server boundary depends on the installed package split: `polkitd` is present, but `pkexec` is not, and no system D-Bus service exposes these helpers. A scanner that does not test exact default executable availability and uid1001 trigger semantics will incorrectly treat the policy XML as a root launch path.

## Triage suggestion

No Ubuntu Security LPE is supported by this evidence. Hardening/documentation suggestions: make the release-upgrader/update-notifier package descriptions clear that these Polkit XML entries are inert on minimal/server systems without `pkexec`, and keep all release-upgrader launch paths admin-authenticated if `pkexec` is installed later.
