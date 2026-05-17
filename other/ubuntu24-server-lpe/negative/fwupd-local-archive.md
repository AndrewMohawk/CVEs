# Negative: fwupd Local CAB/Archive Parsing via Default D-Bus Service

Result: no stock Ubuntu 24.04 Server default local root LPE was proven from this fwupd surface on `ubuntu24-server-lpe-target`.

Artifacts:

```text
pocs/fwupd_local_archive_probe.sh
logs/fwupd-local-archive.out
```

## Default Proof

Target identity:

```text
Ubuntu 24.04.4 LTS (Noble)
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Installed default packages confirmed by the probe:

```text
fwupd              1.9.34-0ubuntu1~24.04.1
fwupd-signed       1.52+1.4-1
libfwupd2          1.9.34-0ubuntu1~24.04.1
libjcat1           0.2.0-2build3
polkitd            124-2ubuntu1.24.04.3
dbus               1.14.10-4ubuntu4.1
systemd            255.4-1ubuntu8.15
```

The D-Bus service file is present and advertises a root service:

```text
Name=org.freedesktop.fwupd
Exec=/usr/libexec/fwupd/fwupd
User=root
SystemdService=fwupd.service
```

The stock unit blocks activation in this Docker target:

```text
/usr/lib/systemd/system/fwupd.service: ConditionVirtualization=!container
fwupd.service: ActiveState=inactive, SubState=dead, ConditionResult=no
fwupd-refresh.timer: ActiveState=inactive, SubState=dead, ConditionResult=no
```

## Probe Coverage

The probe built two attacker-controlled inputs in `/tmp/fwupd-local-archive.*`:

```text
notcab.cab    malformed archive
probe.cab     valid fwupd cabinet from fwupdtool build-cabinet
```

As `attacker`, `busctl`, `fwupdmgr --version`, `fwupdmgr get-details`, and `fwupdmgr local-install` all failed before daemon-side archive parsing:

```text
Failed to activate service 'org.freedesktop.fwupd': timed out
fwupd.service was skipped because of an unmet condition check (ConditionVirtualization=!container)
```

The active selfauth harness created a real local tty/logind session:

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

Even there, the archive entrypoints still failed at `org.freedesktop.fwupd` activation. Direct checks of the two interesting trusted update actions did not produce passwordless authorization in this container:

```text
org.freedesktop.fwupd.update-internal-trusted: Authorization requires authentication and -u wasn't passed.
org.freedesktop.fwupd.update-hotplug-trusted: Authorization requires authentication and -u wasn't passed.
```

## Conclusion

No attacker-supplied CAB/archive reached a default root fwupd parser in this Docker target. The interesting scanner signal is real in static inventory: `org.freedesktop.fwupd` is activatable, runs as root, and has `active=yes` trusted update policies. In the actual default target, however, systemd refuses to start fwupd under Docker because of `ConditionVirtualization=!container`, so local archive parsing is not a reachable root boundary here.

Scanner-miss rationale: a scanner can flag the root D-Bus service, active-user trusted update actions, local CAB entrypoints, and cache/state directories, but it will miss the semantic gate that matters for this target: D-Bus activation delegates to `fwupd.service`, and that stock unit is condition-skipped in containers before any attacker-controlled archive is parsed by root.

Cleanup was verified: no `/tmp/fwupd-local-archive.*` directories remained, no attacker/selfauth `fwupdmgr` processes remained, and `fwupd.service` was still inactive.
