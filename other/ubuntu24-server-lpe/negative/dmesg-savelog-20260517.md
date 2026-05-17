# Negative: dmesg.service savelog path

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Artifacts:

```text
pocs/dmesg_savelog_probe.sh
logs/dmesg-savelog-20260517.out
```

## Result

No uid1001-to-root LPE was validated through the default `dmesg.service` / `savelog` path.

The service is default-installed and enabled, and it does run root-owned log rotation/write commands:

```text
rsyslog      8.2312.0-3ubuntu9.2  provides /lib/systemd/system/dmesg.service
debianutils 5.17build1            provides /usr/bin/savelog
systemd     255.4-1ubuntu8.15

dmesg.service enabled enabled
Loaded: /usr/lib/systemd/system/dmesg.service; enabled; preset: enabled
```

Unit behavior:

```ini
Type=idle
StandardOutput=file:/var/log/dmesg
ExecStartPre=-/usr/bin/savelog -m640 -q -p -n -c 5 /var/log/dmesg
ExecStart=/bin/journalctl --boot 0 --dmesg --output short-monotonic --quiet --no-pager --no-hostname
ExecStartPost=/bin/chgrp adm /var/log/dmesg
ExecStartPost=/bin/chmod 0640 /var/log/dmesg
```

`savelog -p` is worth checking because it preserves the original file owner/mode, creates `$filename.new`, hardlinks the old file to `$filename.0`, then replaces the original path. In this default target that primitive is not attacker-reachable: the fixed path is under `/var/log`, and the attacker is not in `syslog` or `adm`.

## Attacker tests

Default path state:

```text
/var/log        drwxrwxr-x root:syslog
/var/log/dmesg  -rw-r----- root:adm
/var/log/dmesg.0 -rw-r----- root:adm
```

As `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`:

```text
test -r /var/log/dmesg                         rc=1
test -w /var/log/dmesg                         rc=1
test -w /var/log                               rc=1
head -n 1 /var/log/dmesg                       Permission denied
printf ... >> /var/log/dmesg                   Permission denied
touch /var/log/dmesg.new                       Permission denied
mv /var/log/dmesg ...                          Permission denied
rm -f /var/log/dmesg                           Permission denied
ln -s /etc/sudoers /var/log/dmesg...           Permission denied / File exists
ln /etc/passwd /var/log/dmesg...               Operation not permitted
/usr/bin/savelog ... /var/log/dmesg            directory /var/log/ is not writable
systemctl start dmesg.service                  Interactive authentication required
systemctl restart dmesg.service                Interactive authentication required
busctl StartUnit dmesg.service replace         Interactive authentication required
```

Running `savelog` as the attacker on an attacker-owned `/tmp` file only produced attacker-owned rotated files, with no privilege transition.

## Cleanup

The probe removed its attacker-owned `/tmp/dmesg-savelog-attacker.*` directory. Post-test state stayed clean:

```text
find /tmp -maxdepth 1 -name 'dmesg-savelog-attacker.*' -ls  -> no output
/var/log/dmesg and /var/log/dmesg.0 remained root:adm 0640
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
```

## Conclusion

`ROOT_PROOF=no`.

This path remains an interesting root log-rotation surface, but the stock Ubuntu 24.04 Server defaults do not give uid/gid 1001 control over the fixed `/var/log/dmesg` path, the adjacent `dmesg.new`/rotation names, or the systemd trigger needed to run the root service. No root command execution, privileged file write, or attacker-controlled root-owned replacement was reached.
