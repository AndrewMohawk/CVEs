# Current active polkit map: no new uid1001 -> root LPE

Date: 2026-05-17
Target: `ubuntu24-server-lpe-target`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`
Result: negative map update. No root proof or working LPE PoC was produced.

## Why this note exists

An earlier broad XML sweep was run through `docker exec` without `-i`, so the Python
heredoc was not delivered to the container. That made the sweep's empty output
invalid. Re-running the map with stdin attached produced active-user `yes` actions.

Correct command shape:

```sh
docker exec -i ubuntu24-server-lpe-target python3 - <<'PY'
# parse /usr/share/polkit-1/actions/*.policy
PY
```

## Active-user `yes` surfaces

The corrected map found these default-installed actions with `yes` or self-style
authorization for active/inactive users:

```text
com.ubuntu.update-notifier.pkexec.package-system-locked active=yes inactive=yes

org.freedesktop.ModemManager1.Device.Control active=yes
org.freedesktop.ModemManager1.Contacts       active=yes
org.freedesktop.ModemManager1.Messaging      active=yes
org.freedesktop.ModemManager1.Voice          active=yes
org.freedesktop.ModemManager1.Time           active=yes
org.freedesktop.ModemManager1.Location       active=yes
org.freedesktop.ModemManager1.USSD           active=yes

org.freedesktop.udisks2.filesystem-mount             active=yes
org.freedesktop.udisks2.encrypted-unlock             active=yes
org.freedesktop.udisks2.encrypted-change-passphrase  active=yes
org.freedesktop.udisks2.loop-setup                   active=yes
org.freedesktop.udisks2.power-off-drive              active=yes
org.freedesktop.udisks2.eject-media                  active=yes
org.freedesktop.udisks2.modify-device                active=yes
org.freedesktop.udisks2.rescan                       active=yes
org.freedesktop.udisks2.ata-smart-update             active=yes
org.freedesktop.udisks2.ata-check-power              active=yes
org.freedesktop.udisks2.ata-standby                  active=yes
org.freedesktop.udisks2.nvme-smart-update            active=yes
org.freedesktop.udisks2.cancel-job                   active=yes

org.freedesktop.fwupd.update-internal-trusted active=yes
org.freedesktop.fwupd.update-hotplug-trusted  active=yes

org.freedesktop.login1 self/session/inhibit actions include active=yes for
inhibit operations, set-self-linger, chvt, and local power/sleep actions.

org.freedesktop.packagekit.system-sources-refresh        active=yes inactive=yes
org.freedesktop.packagekit.system-network-proxy-configure active=yes
org.freedesktop.packagekit.trigger-offline-update         active=yes
org.freedesktop.packagekit.clear-offline-update           active=yes
```

## Current blocker summary

The active surfaces above are real and remain high-value. They are not current valid
LPEs in this target state:

```text
ModemManager:
  Installed as modemmanager 1.23.4-0ubuntu2, but ModemManager.service is
  condition-gated in Docker by ConditionVirtualization=!container. Manual semantic
  probes showed unprivileged ReportKernelEvent is denied, so uid1001 cannot create
  fake modem objects from a PTY or serial-looking path.

UDisks2:
  udisks2 2.10.1-6ubuntu1.3 is active and exposes many active-user methods. Prior
  focused notes cover loop, filesystem, LUKS, partition, metadata, LVM, mdadm,
  btrfs, xfs, and e2scrub paths. Effects stayed inside nosuid/nodev mounts,
  admin-gated paths, root-owned state, missing kernel modules, or fixed escaped
  helper arguments.

fwupd:
  fwupd 1.9.34-0ubuntu1~24.04.1 has active=yes trusted update actions, but
  fwupd.service and fwupd-refresh.timer are condition-gated in Docker by
  ConditionVirtualization=!container. uid1001 cannot create /var/lib/fwupd/pending.db
  or /system-update, and local fwupdtool parsing runs as uid1001 rather than through
  a reachable root daemon.

logind:
  systemd 255.4-1ubuntu8.15 allows self/session operations such as self-linger and
  inhibitors. These create own-user session state or delay/power semantics, not root
  execution. Cross-user/root session operations remained admin-gated.

PackageKit:
  packagekit 1.2.8-2ubuntu1.5 allows active refresh/proxy/offline state operations.
  Prior probes reached root PackageKit network/proxy influence, but no root code
  execution, root file-content write, or valid package install/update without admin
  authorization.

update-notifier:
  update-notifier-common 3.192.68.2 ships package-system-locked policy, but pkexec
  is not installed by default in this target and no default root service invokes that
  helper for uid1001.
```

## Scanner-miss rationale

The important distinction is method semantics after policy allows the call. Static
policy scans correctly identify active `yes` actions, but they do not show whether
the caller can create a root-consumed object, whether the daemon is condition-gated,
whether the method is limited to own-user state, or whether downstream helper
arguments are fixed/escaped.

## Cleanup

This map did not create target state. The target remained `systemctl is-system-running
-> running` with zero failed units.
