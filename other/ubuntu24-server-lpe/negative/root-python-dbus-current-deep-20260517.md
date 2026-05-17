# Negative: current root Python/D-Bus import, config, and environment boundaries

Date: 2026-05-17
Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default container
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, non-sudo
Result: no validated uid1001-to-root local privilege escalation.

Artifacts:

```text
pocs/root_python_dbus_current_deep_probe.sh
logs/root-python-dbus-current-deep-20260517.out
```

## Scope

This pass re-audited default root Python/D-Bus services and Python root helpers from live target state:

- Root system-bus services: `com.ubuntu.SoftwareProperties`, `io.netplan.Netplan`, PackageKit as an apt trigger surface.
- Root Python/system helpers: Ubuntu Pro `apt-news`/`esm-cache`/`ua-timer`, update-notifier, command-not-found update DB, release-upgrader MOTD checks, apport hooks/autoreport, networkd-dispatcher, update-motd paths, and package maintenance hooks.
- Trust boundaries: D-Bus activation environment, systemd manager environment, `PATH`/`PYTHONPATH`/`UA_*`/`APPORT_DATA_DIR`/`APT_CONFIG`, writable module/plugin/config dirs, root file writes, and symlink following.

## Default proof

The target was running under systemd as PID 1 and the attacker had no sudo:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
sudo: a password is required
```

Relevant installed versions:

```text
software-properties-common 0.99.49.4
netplan.io 1.1.2-8ubuntu1~24.04.2
command-not-found 23.04.0
ubuntu-pro-client 37.2ubuntu~24.04
ubuntu-release-upgrader-core 1:24.04.28
update-notifier-common 3.192.68.2
apport 2.28.1-0ubuntu3.8
packagekit 1.2.8-2ubuntu1.5
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
```

Default root D-Bus/service proof:

```text
/usr/share/dbus-1/system-services/com.ubuntu.SoftwareProperties.service
  Exec=/usr/lib/software-properties/software-properties-dbus
  User=root

/usr/share/dbus-1/system-services/io.netplan.Netplan.service
  Exec=/usr/libexec/netplan/netplan-dbus
  User=root

apt-news.service -> /usr/bin/python3 /usr/lib/ubuntu-advantage/apt_news.py
esm-cache.service -> /usr/bin/python3 /usr/lib/ubuntu-advantage/esm_cache.py
ua-timer.service -> /usr/bin/python3 /usr/lib/ubuntu-advantage/timer.py
update-notifier-download.service -> /usr/lib/update-notifier/package-data-downloader
update-notifier-motd.service -> /usr/lib/ubuntu-release-upgrader/release-upgrade-motd
```

## Evidence

`SoftwarePropertiesDBus.py` gates source/key/config mutators through `_check_policykit_privilege()` and `com.ubuntu.softwareproperties.applychanges`. The only unprivileged method that succeeded was `Reload`; attacker-controlled `AddSourceFromLine`, `AddKey`, `UpdateKeys`, and `SetUpdateInterval` all returned `PermissionDeniedByPolicy`.

`netplan-dbus` is root-owned and activatable, and it exposes `Info`, `Config`, `Generate`, and `Apply`, but all four returned `org.freedesktop.DBus.Error.AccessDenied` for uid1001. Strings show it can honor `DBUS_TEST_NETPLAN_ROOT` and `DBUS_TEST_NETPLAN_CMD`, but uid1001 could not inject those variables into D-Bus activation or systemd.

Environment propagation was blocked:

```text
systemctl set-environment ... -> Failed to set environment: Access denied
org.freedesktop.DBus.UpdateActivationEnvironment -> Call failed: Access denied
```

Starting root helper units as uid1001 was blocked with `Interactive authentication required` for `apt-news`, `esm-cache`, `ua-timer`, `update-notifier-*`, `motd-news`, `apt-daily*`, `apport-autoreport`, and `networkd-dispatcher`.

Direct helper hijacks stayed in the attacker process only:

```text
PATH_HIT name=dpkg euid=1001 ruid=1001
PATH_HIT name=mktemp euid=1001 ruid=1001
PY_HIT euid=1001 uid=1001 argv=['/usr/lib/cnf-update-db', '--verbose']
PY_HIT euid=1001 uid=1001 argv=['/usr/lib/command-not-found', '--', 'ifconfig']
PY_HIT euid=1001 uid=1001 argv=['/usr/bin/pro', 'status']
```

All audited trust roots were root-owned and not writable by uid1001 except `/var/crash`:

```text
NO_W /usr/lib/software-properties
NO_W /usr/lib/python3/dist-packages/softwareproperties
NO_W /usr/lib/python3/dist-packages/netplan
NO_W /usr/lib/python3/dist-packages/CommandNotFound
NO_W /usr/lib/ubuntu-advantage
NO_W /usr/lib/python3/dist-packages/uaclient
NO_W /usr/lib/update-notifier
NO_W /usr/lib/ubuntu-release-upgrader
NO_W /usr/share/apport/package-hooks
NO_W /usr/share/apport/general-hooks
NO_W /usr/share/package-data-downloads
NO_W /etc/netplan
NO_W /etc/apt/apt.conf.d
NO_W /etc/apt/sources.list.d
NO_W /var/lib/command-not-found
NO_W /var/lib/update-notifier
NO_W /var/lib/ubuntu-advantage
W    /var/crash
```

Write and symlink attempts into `/etc/netplan`, apt source/config paths, command-not-found DB, update-notifier stamps, MOTD cache, package-data-download hooks, apport package hooks, and Ubuntu Pro message state failed with permission errors or existing root-owned files. The planted `/var/crash/root_python_dbus_current_deep.upload -> /root/...` symlink was not followed into a root write.

As an upper-bound check, root started the relevant one-shot units with the attacker payload tree present. The system manager environment stayed clean:

```text
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
```

No root marker was created:

```text
/root/root_python_dbus_current_deep*: ABSENT
/root/root_python_dbus_lpe*: ABSENT
ROOT_PROOF=NO
```

## Conclusion

No root shell, root file write, root import, or root-controlled attacker-influenced config path was validated. The viable-looking surfaces are real default attack surfaces, but stock Ubuntu 24.04 Server blocks uid1001 before attacker input reaches root:

- D-Bus mutators are denied by Polkit or netplan's privileged method checks.
- D-Bus and systemd activation environments are not attacker-controllable.
- Root Python import/plugin/config directories are not writable.
- Direct `PATH`/`PYTHONPATH`/`APT_CONFIG`/`APPORT_DATA_DIR` payloads execute only as uid1001.
- PackageKit refresh and root service starts require authentication in this target.
- `/var/crash` is writable, but the tested symlink did not become a root write/import path.

The target was left healthy: `systemctl is-system-running` returned `running`, and probe cleanup removed the attacker payload tree and temporary markers.
