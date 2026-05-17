# Negative: ubuntu-drivers/update-notifier OEM helper lane

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server default state. Scope was normal local users `attacker` uid1001 and `selfauth` uid1002, with no sudo/docker/lxd/adm assumptions.

## Result

No root LPE was validated.

Probe command:

```sh
./pocs/ubuntu_drivers_oem_helper_probe.sh
```

Full transcript:

```text
logs/ubuntu-drivers-oem-helper.out
```

## Default package proof

`ubuntu-drivers-common` is not installed in this server target:

```text
dpkg-query: no packages found matching ubuntu-drivers-common
ubuntu-drivers-common:
  Installed: (none)
```

`update-notifier-common` is installed and owns `/usr/lib/update-notifier/list-oem-metapackages`, but the helper imports `UbuntuDrivers.detect`, and that module is absent without `ubuntu-drivers-common`:

```text
update-notifier-common  3.192.68.2  ii
/usr/lib/update-notifier/list-oem-metapackages root:root 0755
UbuntuDrivers=MISSING
UbuntuDrivers.detect=ERROR:ModuleNotFoundError:No module named 'UbuntuDrivers'
ModuleNotFoundError: No module named 'UbuntuDrivers'
```

## Root reachability

The active default root update-notifier units are:

```text
update-notifier-download.service ExecStart=/usr/lib/update-notifier/package-data-downloader
update-notifier-motd.service     ExecStart=/usr/lib/ubuntu-release-upgrader/release-upgrade-motd
update-notifier-download.timer   enabled/active
update-notifier-motd.timer       enabled/active
```

APT/MOTD hooks call update-notifier MOTD writers, not the OEM helper:

```text
/etc/apt/apt.conf.d/99update-notifier:
  /usr/lib/update-notifier/update-motd-updates-available

/etc/update-motd.d/90-updates-available:
  cat /var/lib/update-notifier/updates-available

/etc/update-motd.d/91-release-upgrade:
  /usr/lib/ubuntu-release-upgrader/release-upgrade-motd
```

A recursive reference scan under `/etc`, `/usr/lib`, `/usr/share`, and `/var/lib/dpkg/info` found `list-oem-metapackages` and `ubuntu-drivers-oem.package-list` only in the helper itself and its package metadata. Other generic `XDG_RUNTIME_DIR` and `ubuntu-drivers` text hits were unrelated comments/support code, not default root invocations of this helper. No default root systemd unit, APT hook, MOTD script, or maintainer script invokes it.

## Runtime/cache trust checks

The helper computes:

```python
STAMP_FILE = os.path.join(GLib.get_user_runtime_dir(), "ubuntu-drivers-oem.package-list")
```

As uid1001 with attacker-controlled `PYTHONPATH` and `XDG_RUNTIME_DIR`, direct execution can import an attacker-provided `UbuntuDrivers.detect` and write:

```text
/home/attacker/ubuntu-drivers-oem-probe/runtime/ubuntu-drivers-oem.package-list
uid=1001 euid=1001
oem-attacker-direct-meta
```

That is not a root path. The default root services do not invoke this helper and do not inherit the attacker environment.

Relevant root-owned paths were not writable by uid1001:

```text
/usr/share/package-data-downloads                         root:root
/var/lib/update-notifier                                  root:root
/var/lib/update-notifier/user.d                           root:root
/var/lib/update-notifier/package-data-downloads            root:root
/var/lib/update-notifier/package-data-downloads/partial    _apt:root 0700
/var/lib/ubuntu-drivers-common                            missing
/var/cache/ubuntu-drivers-common                          missing
/run/user/1001                                            missing
/run/user/1002                                            missing
```

Starting `update-notifier-*.service` as uid1001 returned interactive authentication required. Starting the same services as root completed successfully and did not create a root marker or touch the OEM runtime file.

## Verdict

Negative. In this stock Ubuntu 24.04 Server target, the OEM helper is a package-owned but unreachable/broken helper because `ubuntu-drivers-common` is absent. The reachable root update-notifier paths use root-owned package-data and MOTD state, not attacker runtime files, and uid1001 cannot plant hooks or trigger the root services without authorization.
