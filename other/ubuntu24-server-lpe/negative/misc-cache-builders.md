# Negative: miscellaneous cache-builder triggers

Date: 2026-05-16
Target: `ubuntu24-server-lpe-target`
Probe: `pocs/misc_cache_builders_probe.sh`
Log: `logs/misc-cache-builders.out`

Verdict: no validated uid1001-to-root LPE in this lane.

## Scope and default package proof

The probe covered default-installed trigger/cache builders outside the man-db and system-cache lanes:

```text
info                    7.1-3build2
install-info            7.1-3build2
shared-mime-info        2.4-4
sgml-base               1.31
xml-core                0.19
libglib2.0-0t64:arm64   2.80.0-6ubuntu3.8
libglib2.0-bin          2.80.0-6ubuntu3.8
debianutils             5.17build1
python3-twisted         24.3.0-1ubuntu0.1
```

Not installed in the stock server target: `fontconfig`, `desktop-file-utils`, `hicolor-icon-theme`, `xdg-utils`, `mailcap`. Hicolor icon/application directories exist as payload data from other packages, but the corresponding icon/desktop cache helpers are not present.

## Default trigger/code evidence

Default dpkg trigger registrations exist for:

```text
/usr/share/info -> install-info
/usr/share/mime/packages -> shared-mime-info
/etc/sgml, /usr/share/sgml, /usr/share/xml -> sgml-base
/usr/share/glib-2.0/schemas and /usr/lib/aarch64-linux-gnu/gio/modules -> libglib2.0-0t64
/usr/share/debianutils/shells.d -> debianutils
twisted-plugins-cache -> python3-twisted
```

Notable trust-boundary-looking code paths:

```text
/var/lib/dpkg/info/install-info.postinst:33 -> update-info-dir
/usr/sbin/update-info-dir:67 -> install-info "$file" "$INFODIR/dir"
/var/lib/dpkg/info/shared-mime-info.postinst:5-12 -> which/update-mime-database
/var/lib/dpkg/info/sgml-base.postinst:64,69 -> update-catalog --update-super
/usr/sbin/update-catalog:136 -> system("dpkg-trigger /etc/sgml")
/usr/sbin/update-xmlcatalog:145,496 -> /var/lib/xml-core catalog data writes
/var/lib/dpkg/info/libglib2.0-0t64:arm64.postinst:17,24 -> absolute glib helpers
/usr/sbin/update-shells:83,146-150 -> dpkg-realpath/sync/mv
/var/lib/dpkg/info/python3-twisted.postinst:19-22 -> rebuilds dropin.cache by importing plugins
```

## Reachability results

uid1001 could not write the default parser inputs or cache outputs: `/usr/share/info`, `/usr/share/mime/packages`, `/usr/share/mime/mime.cache`, `/usr/share/xml`, `/etc/xml`, `/var/lib/xml-core`, `/usr/share/sgml`, `/etc/sgml`, `/var/lib/sgml-base`, `/usr/share/glib-2.0/schemas`, `/usr/lib/aarch64-linux-gnu/gio/modules`, `/usr/share/debianutils/shells.d`, `/etc/shells`, `/var/lib/shells.state`, `/usr/lib/python3/dist-packages/twisted/plugins`, `/usr/share/icons/hicolor`, and `/usr/share/applications`.

Unprivileged trigger commands failed at the dpkg/systemd boundary:

```text
/usr/bin/dpkg-trigger --no-await /usr/share/info -> Permission denied on /var/lib/dpkg/triggers/Lock
/usr/bin/dpkg-trigger --no-await twisted-plugins-cache -> Permission denied on /var/lib/dpkg/triggers/Lock
/usr/bin/dpkg --triggers-only --pending -> requested operation requires superuser privilege
systemctl set-environment/import-environment -> Access denied
install-info.service/shared-mime-info.service/... -> no default units found
```

Direct uid1001 runs with hostile `PATH`/`PYTHONPATH` only affected attacker-owned custom trees. `update-catalog --super` reached the fake `dpkg-trigger` and `update-shells --root` reached fake `dpkg-realpath`, `chmod`, `chown`, `sync`, and `mv`, but all hits were `uid=1001`.

## Root-trigger simulation

The probe ran the default root maintainer-script trigger paths with a clean dpkg-like environment after attacker setup:

```sh
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root SHELL=/bin/sh LOGNAME=root /var/lib/dpkg/info/install-info.postinst triggered /usr/share/info
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root SHELL=/bin/sh LOGNAME=root /var/lib/dpkg/info/shared-mime-info.postinst triggered /usr/share/mime/packages
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root SHELL=/bin/sh LOGNAME=root /var/lib/dpkg/info/sgml-base.postinst triggered update-sgmlcatalog
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root SHELL=/bin/sh LOGNAME=root /var/lib/dpkg/info/libglib2.0-0t64:arm64.postinst triggered /usr/share/glib-2.0/schemas /usr/lib/aarch64-linux-gnu/gio/modules
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root SHELL=/bin/sh LOGNAME=root /var/lib/dpkg/info/debianutils.postinst triggered /usr/share/debianutils/shells.d
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root SHELL=/bin/sh LOGNAME=root /var/lib/dpkg/info/python3-twisted.postinst triggered twisted-plugins-cache
```

Result:

```text
NO_HELPER_HITS_AFTER_DEFAULT_ROOT_TRIGGERS
NO_ROOT_MARKER
systemctl is-system-running -> running
failed units -> 0
```

## Non-default primitive

Several helpers will write root-owned files if root is explicitly pointed at attacker-owned custom directories. In the controlled `/tmp/misc_cache_builders_probe_custom` test, root-created files appeared under attacker-owned custom MIME/schema/info trees, and `update-catalog --add` followed an attacker-controlled catalog symlink to create a root-owned victim file:

```text
/tmp/misc_cache_builders_probe_custom/victims/sgml-catalog root:root
```

This is not a stock Ubuntu Server LPE: default dpkg triggers use fixed root-owned paths, and uid1001 cannot make root choose the attacker-controlled custom directory or replace the fixed inputs/sinks.

## Cleanup

The probe removes `/home/attacker/misc_cache_builders_probe`, `/tmp/misc_cache_builders_probe*`, `/root/misc_cache_builders_probe*`, and any probe-derived `/var/lib/xml-core/_*_misc_cache_builders_probe*` files. Cache files touched during root trigger simulation are backed up and restored. Final target health was `running` with zero failed units.

## Why scanners likely flag but miss exploitability

Static checks can flag unqualified helper execution (`install-info`, `which`, `update-mime-database`, `dpkg-trigger`, `update-shells` internals), root cache writes, symlink-sensitive custom-path behavior, and Twisted plugin imports during cache rebuild. The missing exploit chain is the default reachability: normal users cannot write the consumed system trees, cannot acquire the dpkg trigger lock, cannot start nonexistent root units, and cannot inject environment into the root context that runs package triggers.

## Hardening notes

Use absolute helper paths in maintainer scripts where practical, especially `install-info`, `which`, `update-mime-database`, `update-catalog`, and `update-shells` internals. Cache builders that accept arbitrary output/catalog paths should use no-follow open/rename semantics for root-owned runs. Keep `/usr/local/share/{info,mime,xml,sgml,glib-2.0,applications,icons}` and all dpkg trigger input trees root-owned and non-writable by normal users.
