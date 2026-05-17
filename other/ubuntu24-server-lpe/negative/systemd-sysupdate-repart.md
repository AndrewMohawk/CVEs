# Negative: systemd-sysupdate, systemd-repart, offline update, factory reset

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server default Docker target.  
Users: `uid=1001(attacker)` and `uid=1002(selfauth)`, each only in its own primary group.

Verdict: no validated local privilege escalation. No root proof file was created, and no attacker-controlled root unit, update image/config path, offline-update symlink, or root environment propagation path was reached.

Full probe/log:

```text
pocs/systemd_sysupdate_repart_probe.sh
logs/systemd-sysupdate-repart.out
```

## Default proof

Relevant default packages from the target:

```text
systemd 255.4-1ubuntu8.15
polkitd 124-2ubuntu1.24.04.3
packagekit 1.2.8-2ubuntu1.5
fwupd 1.9.34-0ubuntu1~24.04.1
dbus 1.14.10-4ubuntu4.1
```

Relevant binaries are normal root-owned executables, with no file capabilities observed:

```text
-rwxr-xr-x root:root /usr/lib/systemd/systemd-sysupdate
-rwxr-xr-x root:root /usr/bin/systemd-repart
-rwxr-xr-x root:root /usr/lib/systemd/system-generators/systemd-system-update-generator
-rwxr-xr-x root:root /usr/libexec/pk-offline-update
-rwxr-xr-x root:root /usr/libexec/fwupd/fwupdoffline
```

Installed unit state:

```text
systemd-sysupdate.service             indirect enabled, inactive
systemd-sysupdate-reboot.service      indirect enabled, inactive
systemd-sysupdate.timer               disabled enabled, inactive
systemd-sysupdate-reboot.timer        disabled enabled, inactive
systemd-repart.service                static, inactive
system-update.target                  static, inactive
system-update-cleanup.service         static, inactive
factory-reset.target                  static, inactive
packagekit-offline-update.service     static, inactive
fwupd-offline-update.service          static, inactive
```

`systemd-sysupdate*` and `systemd-repart.service` are container-gated with `ConditionVirtualization=!container`. `systemd-repart.service` also requires non-empty repart definitions under root-owned search paths. The sysupdate service command is fixed as `/usr/lib/systemd/systemd-sysupdate update`; the repart service command is fixed as `/usr/bin/systemd-repart --dry-run=no`.

## Dead ends

Writable/search paths: default sysupdate/repart directories under `/etc`, `/run`, `/usr/local/lib`, `/usr/lib`, `/var/lib/systemd`, and `/usr/lib/systemd/repart/definitions` were missing or root-owned non-writable. Both users failed to create sysupdate/repart config dirs, `/system-update`, `/etc/system-update`, `/run/systemd/system/system-update.target.wants`, `/var/lib/PackageKit/prepared-update`, and `/var/lib/fwupd`.

Direct helper execution: as both users, `systemd-sysupdate components` reported no components, `check-new`/`update --verify=no` reported `No transfer definitions found`, and `systemd-repart`/factory-reset modes failed at root block-device discovery. These direct runs stayed unprivileged.

System manager transitions: both users were denied `systemctl` and direct `org.freedesktop.systemd1.Manager.StartUnit` starts for `systemd-sysupdate.service`, `systemd-sysupdate-reboot.service`, `systemd-repart.service`, `packagekit-offline-update.service`, `fwupd-offline-update.service`, `system-update.target`, `system-update-cleanup.service`, and `factory-reset.target`. `systemctl set-environment`, D-Bus `UpdateActivationEnvironment`, and `systemd-run` root proof attempts were also denied.

Active local `selfauth`: an active tty1 session could authorize PackageKit offline trigger/clear actions (`CanAuthorize -> 1`), but not systemd unit management or environment setting (`CanAuthorize -> 0`). In the default state `UpdatePrepared=false`; `Offline.Trigger("reboot")` failed with `Prepared update not found: /var/lib/PackageKit/prepared-update` and did not create `/system-update`.

Post-probe state:

```text
/root/systemd_sysupdate_repart_lpe: absent
/tmp/systemd_sysupdate_repart_lpe: absent
/system-update: absent
/etc/system-update: absent
/var/lib/PackageKit/offline-update-action: absent
/var/lib/PackageKit/prepared-update: absent
/var/lib/PackageKit/prepared-upgrade: absent
/var/lib/fwupd/pending.db: absent
systemctl is-system-running: running
```

Conclusion: the default package/config/reachability exists, but the root-running transitions are blocked by root-owned inputs, container/unit conditions, and systemd/polkit authorization. The one active-user PackageKit offline permission reaches only a fixed offline-update state machine and is inert in the default state without a root-created prepared update.
