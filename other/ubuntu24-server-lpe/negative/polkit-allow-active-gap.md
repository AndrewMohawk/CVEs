# Negative: polkit allow_active gap probe

Result: no stock Ubuntu 24.04 Server local root LPE was validated from the
remaining default `allow_active=yes` / `auth_self` polkit surface.

Probe/log:

```text
pocs/polkit_allow_active_gap_probe.sh
logs/polkit-allow-active-gap.out
```

## Live target proof

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS.

Normal users:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Relevant default packages:

```text
dbus 1.14.10-4ubuntu4.1
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
udisks2 2.10.1-6ubuntu1.3
packagekit 1.2.8-2ubuntu1.5
modemmanager 1.23.4-0ubuntu2
fwupd 1.9.34-0ubuntu1~24.04.1
update-notifier-common 3.192.68.2
pkexec uninstalled
```

The live policy inventory found no `auth_self` defaults. The remaining
`allow_active=yes` actions were in already-known families: login1, PackageKit,
UDisks2, ModemManager, fwupd, and the stale update-notifier pkexec action.
ModemManager and fwupd are D-Bus activatable but condition-gated in this Docker
target, and `pkexec` is absent.

## Focused gap

This pass focused on the less-tested UDisks2 active-user control actions:

```text
org.freedesktop.udisks2.power-off-drive
org.freedesktop.udisks2.eject-media
org.freedesktop.udisks2.modify-device
org.freedesktop.udisks2.rescan
org.freedesktop.udisks2.ata-smart-update
org.freedesktop.udisks2.nvme-smart-update
org.freedesktop.udisks2.cancel-job
```

`udisks2.service` was live and root-owned. A real `selfauth` tty7 login had
`Seat=seat0`, `Active=yes`, and `pkcheck` returned `rc=0` for all seven focus
actions.

## Results

Active `selfauth` could ask root UDisks to create a loop for a user-owned image
and rescan that loop. It could also rescan the default `vdb` and `vda1` block
objects:

```text
Manager.LoopSetup(user-owned 8M image) -> OK /org/freedesktop/UDisks2/block_devices/loop0
loop0.Block.Rescan({}) -> OK
vdb.Block.Rescan({}) -> OK
vda1.Block.Rescan({}) -> OK
```

The privilege-relevant effects stayed blocked:

```text
Block.OpenDevice('r', {}) -> NotAuthorizedCanObtain
VirtIO_Disk_1.PowerOff/Eject/SetConfiguration -> NotAuthorizedCanObtain
VirtIO_Disk.PowerOff/Eject -> DeviceBusy because vda1 is mounted
VirtIO_Disk.SetConfiguration(marker dict) -> NotAuthorizedCanObtain
```

No ATA/NVMe SMART interfaces were present on the default VirtIO drives, no job
objects were present to cancel, and the attempted marker config did not appear
under `/etc/udisks2`, `/var/lib/udisks2`, or `/run/udisks2`.

## Cleanup

The user loop was deleted, the temporary tty profile was restored/removed, the
`selfauth` session was terminated, and `getty@tty7.service` was restarted.

Final checks:

```text
ROOT_PROOF=no
/root/polkit_allow_active_gap_root absent
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
```

Conclusion: the remaining live gap is a bounded active-user UDisks rescan
surface, not a root file write, raw block device FD, root execution, or
privileged account/group transition.
