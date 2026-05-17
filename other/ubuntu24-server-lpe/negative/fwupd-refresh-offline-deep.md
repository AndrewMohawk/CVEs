# Negative: fwupd Refresh, Offline Update, and Local File Root Boundaries

Result: no stock Ubuntu 24.04 Server default local root LPE was proven from this fwupd refresh/offline surface on `ubuntu24-server-lpe-target`.

Artifacts:

```text
pocs/fwupd_refresh_offline_deep_probe.sh
logs/fwupd-refresh-offline-deep.out
```

## Default Proof

Target identity:

```text
Ubuntu 24.04.4 LTS (Noble)
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Default-installed package versions from the target:

```text
dbus                         1.14.10-4ubuntu4.1
fwupd                        1.9.34-0ubuntu1~24.04.1
fwupd-signed                 1.52+1.4-1
libarchive13t64:arm64        3.7.2-2ubuntu0.6
libfwupd2:arm64              1.9.34-0ubuntu1~24.04.1
libjcat1:arm64               0.2.0-2build3
polkitd                      124-2ubuntu1.24.04.3
systemd                      255.4-1ubuntu8.15
```

The default D-Bus service is activatable and advertises a root daemon:

```text
/usr/share/dbus-1/system-services/org.freedesktop.fwupd.service:2 Name=org.freedesktop.fwupd
/usr/share/dbus-1/system-services/org.freedesktop.fwupd.service:4 Exec=/usr/libexec/fwupd/fwupd
/usr/share/dbus-1/system-services/org.freedesktop.fwupd.service:5 User=root
/usr/share/dbus-1/system-services/org.freedesktop.fwupd.service:6 SystemdService=fwupd.service
```

The actual daemon and timer are not default-reachable in this Docker target:

```text
/usr/lib/systemd/system/fwupd.service:6 ConditionVirtualization=!container
/usr/lib/systemd/system/fwupd.service:13 BusName=org.freedesktop.fwupd
/usr/lib/systemd/system/fwupd.service:14 ExecStart=/usr/libexec/fwupd/fwupd
/usr/lib/systemd/system/fwupd-refresh.timer:3 ConditionVirtualization=!container
fwupd.service: ActiveState=inactive, ConditionResult=no
fwupd-refresh.timer: ActiveState=inactive, UnitFileState=enabled, ConditionResult=no
```

The refresh service is a static service-account path rather than a root helper path:

```text
/usr/lib/systemd/system/fwupd-refresh.service:10 CacheDirectory=fwupdmgr
/usr/lib/systemd/system/fwupd-refresh.service:12 ProtectSystem=strict
/usr/lib/systemd/system/fwupd-refresh.service:14 User=fwupd-refresh
/usr/lib/systemd/system/fwupd-refresh.service:21 ExecStart=/usr/bin/fwupdmgr refresh
```

The offline update unit is a root transition, but it is static and gated on a root-owned marker database:

```text
/usr/lib/systemd/system/fwupd-offline-update.service:4 ConditionPathExists=/var/lib/fwupd/pending.db
/usr/lib/systemd/system/fwupd-offline-update.service:12 ExecStart=/usr/libexec/fwupd/fwupdoffline
```

The system bus policy only lets root own the fwupd name, while allowing callers to send messages that the daemon must authorize:

```text
/usr/share/dbus-1/system.d/org.freedesktop.fwupd.conf:11-14 root owns org.freedesktop.fwupd
/usr/share/dbus-1/system.d/org.freedesktop.fwupd.conf:16-26 default callers may send to org.freedesktop.fwupd
```

## Probe Coverage

The probe exercised these unprivileged triggers:

```sh
runuser -u attacker -- mkdir -p /var/lib/fwupd
runuser -u attacker -- touch /var/lib/fwupd/pending.db
runuser -u attacker -- ln -s /root/fwupd_refresh_offline_deep_root /var/lib/fwupd/pending.db
runuser -u attacker -- ln -s /root/fwupd_refresh_offline_deep_root /system-update
runuser -u attacker -- systemctl --no-ask-password start fwupd-refresh.service
runuser -u attacker -- systemctl --no-ask-password start fwupd-offline-update.service
runuser -u attacker -- systemctl --no-ask-password start system-update.target
runuser -u attacker -- busctl --system --timeout=8 call org.freedesktop.fwupd / org.freedesktop.DBus.Peer Ping
runuser -u attacker -- fwupdmgr --no-authenticate refresh <metadata.xml.gz> <metadata.xml.gz.asc> lvfs
runuser -u attacker -- fwupdmgr --offline --assume-yes --no-authenticate local-install <payload.cab>
runuser -u attacker -- fwupdmgr --no-authenticate modify-remote lvfs Enabled false
runuser -u attacker -- fwupdmgr --no-authenticate modify-config DisabledDevices fwupd-refresh-offline-deep
runuser -u attacker -- fwupdtool get-details <payload.cab>
runuser -u attacker -- fwupdtool refresh
runuser -u attacker -- fwupdtool reboot-cleanup
```

It also created an active local `selfauth` TTY/logind session and repeated the same refresh, offline, systemd, marker-file, and D-Bus calls from a non-admin active user:

```text
User=1002
Name=selfauth
TTY=pts/0
Remote=no
Type=tty
Class=user
Active=yes
State=active
```

## Results

The marker and state roots were not attacker-writable:

```text
mkdir: cannot create directory '/var/lib/fwupd': Permission denied
touch: cannot touch '/var/lib/fwupd/pending.db': No such file or directory
mkdir: cannot create directory '/var/cache/fwupdmgr': Permission denied
ln: failed to create symbolic link '/system-update': Permission denied
```

Unprivileged systemd starts did not reach the root units:

```text
Failed to start fwupd-refresh.service: Interactive authentication required.
Failed to start fwupd-offline-update.service: Interactive authentication required.
Failed to start system-update.target: Interactive authentication required.
```

The D-Bus and `fwupdmgr` refresh/offline/local-file entrypoints failed before daemon-side root parsing or root state mutation:

```text
Call failed: Connection timed out
Failed to connect to daemon: Error calling StartServiceByName for org.freedesktop.fwupd: Failed to activate service 'org.freedesktop.fwupd': timed out
```

Direct `fwupdtool` parsing from uid1001 did not cross a privilege boundary and failed on root-owned fwupd state creation:

```text
Failed to create '/var/lib/fwupd/quirks.d': Permission denied
```

The active selfauth session did not change that outcome. Direct `pkcheck` calls for the tested fwupd actions returned `Authorization requires authentication and -u wasn't passed`, and the D-Bus daemon still failed to activate because `fwupd.service` is condition-skipped in the Docker target.

Root proof:

```text
ROOT_PROOF=NO
```

Post-cleanup health:

```text
systemctl is-system-running: running
systemctl --failed --no-legend | wc -l: 0
no /root/fwupd_refresh_offline_deep_root
no /system-update
no /var/lib/fwupd, /var/cache/fwupd, /var/cache/fwupdmgr, /run/fwupd, or /run/motd.d left by the probe
```

## Conclusion

No normal local user path reached a root fwupd refresh, offline, cleanup, or local-file parser boundary in the stock Docker target. The interesting static trust boundaries are real: a root D-Bus service, active-user trusted update policies, a static root offline update service, and firmware/archive parsers. In this tested default state, the exploitable chain breaks at multiple gates:

```text
fwupd.service and fwupd-refresh.timer are skipped by ConditionVirtualization=!container.
fwupd-refresh.service runs fwupdmgr as fwupd-refresh, not as root.
fwupd-offline-update.service requires /var/lib/fwupd/pending.db, and uid1001 cannot create /var/lib/fwupd.
/system-update is root-owned and cannot be created by uid1001 or active non-admin selfauth.
systemd unit starts require interactive admin authentication.
```

Scanner-miss rationale: static scanners can flag `org.freedesktop.fwupd` as root-activatable, `allow_active=yes` trusted update actions, `fwupdoffline` as a root oneshot, and archive/metadata parsing commands. Exploitability here depends on systemd condition evaluation, marker-file ownership, service-account execution, and the difference between direct user `fwupdtool` parsing and daemon-side root parsing.

Suggested hardening for Ubuntu triage: no LPE fix is justified from this target state. Defense-in-depth options would be to add the same container condition to `fwupd-refresh.service` itself for clearer manual-start behavior in containers, keep `/var/lib/fwupd` and `/system-update` strictly root-owned, and make fwupd D-Bus activation failures return quickly when systemd has already condition-skipped `fwupd.service`.
