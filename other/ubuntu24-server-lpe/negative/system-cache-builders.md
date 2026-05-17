# Negative: system root cache builders

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default Docker target.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, no sudo/admin groups.

Result: no validated uid1001-to-root local privilege escalation in the scoped system cache-builder lane covering `ldconfig`, journal catalog rebuilds, `dmesg.service`/`savelog`, locale generation, `systemd-hwdb`, and `kmod static-nodes`.

Rerun:

```sh
bash -n pocs/system_cache_builders_probe.sh
pocs/system_cache_builders_probe.sh ubuntu24-server-lpe-target
```

Evidence log: `logs/system-cache-builders.out`.

## Default root consumers proven

Installed default packages included:

```text
libc-bin 2.39-0ubuntu8.7
locales 2.39-0ubuntu8.7
systemd 255.4-1ubuntu8.15
systemd-hwe-hwdb 255.1.7
kmod 31+20240202-2ubuntu7.2
util-linux/bsdutils 2.39.3-9ubuntu6.5
```

Default root units and maintainer paths were present:

```text
/usr/lib/systemd/system/ldconfig.service
  ExecStart=/sbin/ldconfig -X
  ConditionNeedsUpdate=|/etc
  ConditionFileNotEmpty=|!/etc/ld.so.cache

/usr/lib/systemd/system/systemd-journal-catalog-update.service
  ExecStart=journalctl --update-catalog
  ConditionNeedsUpdate=/var

/usr/lib/systemd/system/dmesg.service
  ExecStartPre=-/usr/bin/savelog -m640 -q -p -n -c 5 /var/log/dmesg
  ExecStart=/bin/journalctl --boot 0 --dmesg --output short-monotonic --quiet --no-pager --no-hostname
  ExecStartPost=/bin/chgrp adm /var/log/dmesg
  ExecStartPost=/bin/chmod 0640 /var/log/dmesg

/usr/lib/systemd/system/systemd-update-done.service
  ExecStart=/usr/lib/systemd/systemd-update-done

/usr/lib/systemd/system/systemd-hwdb-update.service
  ExecStart=systemd-hwdb update
  ConditionDirectoryNotEmpty=|/etc/udev/hwdb.d/

/usr/lib/systemd/system/kmod-static-nodes.service
  ExecStart=/usr/bin/kmod static-nodes --format=tmpfiles --output=/run/tmpfiles.d/static-nodes.conf
  ConditionCapability=CAP_SYS_MODULE
  ConditionFileNotEmpty=/lib/modules/%v/modules.devname
```

`libc-bin` declares the `ldconfig` trigger, `locales.postinst` invokes `locale-gen`, `locale-gen` reads `/usr/local/share/i18n/locales` if present and shells out to `localedef`, and `/usr/bin/savelog` appends system directories to `PATH` before using helpers such as `chown`, `chgrp`, `chmod`, `mv`, and `gzip`.

## Boundary checks

uid1001 could not write the root-owned parser/config/cache inputs:

```text
NO_W /etc/ld.so.conf.d
NO_W /usr/local
NO_W /usr/local/lib
NO_W /usr/lib/systemd/catalog
NO_W /var/lib/systemd/catalog
NO_W /var/lib/systemd/catalog/database
NO_W /var/log
NO_W /var/log/dmesg
NO_W /etc/locale.gen
NO_W /usr/share/i18n
NO_W /usr/share/i18n/SUPPORTED
NO_W /usr/local/share
NO_W /etc/udev/hwdb.d
NO_W /usr/lib/udev/hwdb.d
NO_W /usr/lib/udev/hwdb.bin
```

Write and symlink attempts into `/etc/ld.so.conf.d`, `/usr/local/lib`, systemd catalog directories, `/var/lib/systemd/catalog/database`, `/var/log/dmesg`, `/etc/locale.gen`, `/usr/local/share/i18n`, udev hwdb directories, `/lib/modules/.../modules.devname`, and `/run/tmpfiles.d/static-nodes.conf` failed with `Permission denied`, `File exists`, or missing root-owned parent directories.

The direct attacker-controlled `PATH`/`TMPDIR`/`LOCPATH` runs proved the helper-execution primitive is only user-owned:

```text
ldconfig uid=1001 euid=1001 args=-n /home/attacker/system_cache_builders_probe/lib
journalctl uid=1001 euid=1001 args=--update-catalog --root=/home/attacker/system_cache_builders_probe
savelog uid=1001 euid=1001 args=-m640 -q -p -n -c 2 /home/attacker/system_cache_builders_probe/log/dmesg
systemd-hwdb uid=1001 euid=1001 args=update --root=/home/attacker/system_cache_builders_probe
kmod uid=1001 euid=1001 args=static-nodes --format=tmpfiles --output=/home/attacker/system_cache_builders_probe/static-nodes.conf
```

uid1001 could not start the root units or poison the root systemd manager environment:

```text
systemctl start ldconfig.service                         -> Interactive authentication required
systemctl start systemd-journal-catalog-update.service   -> Interactive authentication required
systemctl start dmesg.service                            -> Interactive authentication required
systemctl start systemd-update-done.service              -> Interactive authentication required
systemctl start systemd-hwdb-update.service              -> Interactive authentication required
systemctl start kmod-static-nodes.service                -> Interactive authentication required
systemctl set-environment PATH=...                       -> Access denied
systemctl import-environment TMPDIR PATH                 -> Access denied
```

Root-triggered checks then ran after hostile attacker state was planted:

```text
root_ldconfig_rc=0
root_journalctl_catalog_rc=0
root_savelog_rc=0
root_locale_gen_rc=0
root_hwdb_rc=0
root_kmod_rc=0
NO_HELPER_HITS_AFTER_ROOT
NO_ROOT_MARKER
```

The cleanup restored `/var/log/dmesg` from a root-side backup, removed the transient `/run/tmpfiles.d/static-nodes.conf`, reset failed units, and ended with `systemctl is-system-running` reporting `running` and zero failed units.

## Conclusion

The interesting trust boundaries are real: root units rebuild caches from filesystem trees, `locale-gen` can prefer `/usr/local/share/i18n`, and `savelog` uses PATH-resolved helpers. In the stock Ubuntu Server default state, the normal local user cannot control those root input directories, cannot write the generated cache targets, cannot propagate hostile environment into the system manager, and cannot start the root units. The same helper names are reachable only in uid1001-owned direct executions. No root code execution or privileged file-write primitive was validated.
