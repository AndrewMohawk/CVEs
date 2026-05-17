# Negative: systemd generators and `/run` config/credential injection

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04 Server default Docker/systemd target.

Users: `uid=1001(attacker)` and `uid=1002(selfauth)`, each only in its own primary group.

Verdict: no validated local privilege escalation. No root proof file, uid 0 sysusers entry, attacker binfmt registration, runtime unit, generator output, or injected service credential was created.

Full probe/log:

```text
pocs/systemd_generators_run_config_probe.sh
logs/systemd-generators-run-config.out
```

## Default proof

Relevant default packages:

```text
systemd 255.4-1ubuntu8.15
systemd-dev 255.4-1ubuntu8.15
systemd-sysv 255.4-1ubuntu8.15
udev 255.4-1ubuntu8.15
kmod 31+20240202-2ubuntu7.2
```

Relevant root units are installed in the default image:

```text
kmod-static-nodes.service                static, inactive
systemd-binfmt.service                   static, active/exited
systemd-firstboot.service                static, inactive
systemd-hwdb-update.service              static, inactive
systemd-journal-catalog-update.service   static, active/exited
systemd-sysusers.service                 static, active/exited
systemd-tmpfiles-setup-dev-early.service static, active/exited
systemd-tmpfiles-setup-dev.service       static, active/exited
systemd-tmpfiles-setup.service           static, active/exited
```

The sensitive imports/searches are real:

```text
systemd-binfmt.service: ConditionDirectoryNotEmpty=|/run/binfmt.d
systemd-sysusers.service: ImportCredential=sysusers.* passwd.*.root
systemd-tmpfiles-setup*.service: ImportCredential=tmpfiles.*
systemd-tmpfiles-setup.service: also imports login.motd, login.issue, network.hosts, ssh.authorized_keys.root
kmod-static-nodes.service: writes /run/tmpfiles.d/static-nodes.conf, but is gated by CAP_SYS_MODULE and modules.devname
journal-catalog-update.service: journalctl --update-catalog
firstboot.service: ImportCredential=firstboot.* passwd.*.root, but ConditionFirstBoot=no in this state
```

`/usr/lib/tmpfiles.d/provision.conf` would write credential-backed root material such as `/root/.ssh/authorized_keys`, but `/usr/lib/tmpfiles.d/credstore.conf` makes `/etc/credstore*` and `/run/credstore*` root-only `0700`.

## Blockers

The exact `/run` config and generator paths are not writable by either user:

```text
/run                            drwxr-xr-x root:root
/run/binfmt.d                   missing, parent /run root:root 0755
/run/sysusers.d                 missing, parent /run root:root 0755
/run/tmpfiles.d                 missing, parent /run root:root 0755
/run/udev/hwdb.d                missing, parent /run/udev root:root 0755
/run/modules-load.d             missing, parent /run root:root 0755
/run/modprobe.d                 missing, parent /run root:root 0755
/run/systemd/system             drwxr-xr-x root:root
/run/systemd/generator          drwxr-xr-x root:root
/run/systemd/generator.early    missing, parent /run/systemd root:root 0755
/run/systemd/generator.late     missing, parent /run/systemd root:root 0755
/run/systemd/catalog            missing, parent /run/systemd root:root 0755
/run/credentials                drwxr-xr-x root:root
/run/credstore                  missing, parent /run root:root 0755
/run/credstore.encrypted        missing, parent /run root:root 0755
/etc/credstore                  drwx------ root:root
/etc/credstore.encrypted        drwx------ root:root
```

As `attacker`, mkdir/write attempts into `/run/binfmt.d`, `/run/sysusers.d`, `/run/tmpfiles.d`, `/run/udev/hwdb.d`, `/run/systemd/{system,generator,generator.early,generator.late,catalog}`, `/run/credstore*`, and `/run/credentials/systemd-*.service/*` all failed with `Permission denied` or missing parent after denied parent creation. `selfauth` hit the same boundary. Writing `/proc/cmdline` to influence kernel-cmdline generators was also denied.

Starting or reloading root systemd state was not reachable from either user:

```text
systemctl start systemd-{hwdb-update,binfmt,sysusers,tmpfiles-setup*,journal-catalog-update,firstboot}.service -> Interactive authentication required
systemctl start kmod-static-nodes.service -> Interactive authentication required
busctl Manager.StartUnit for the same units -> Interactive authentication required
systemctl daemon-reload -> Interactive authentication required
systemctl set-environment -> Access denied
busctl Manager.SetEnvironment -> Access denied
systemd-run --system -p SetCredential=... -> Interactive authentication required
```

Direct helper execution accepted attacker-controlled files only in the caller's unprivileged context:

```text
systemd-sysusers attacker config/credentials -> Failed to take /etc/passwd lock: Permission denied
systemd-tmpfiles attacker config/credentials -> failed to create /root/systemd_generators_run_config_lpe and /root/.ssh
systemd-hwdb update -> Failed to write database /etc/udev/hwdb.bin: Permission denied
journalctl --update-catalog -> Failed to write /var/lib/systemd/catalog/database: Permission denied
systemd-firstboot --force --root-password=... -> Failed to take a lock on /etc/passwd: Permission denied
systemd-creds encrypt into /run/credstore.encrypted -> Failed to determine local credential host secret: Permission denied
```

`/usr/lib/systemd/systemd-binfmt` returned `0` when run directly with an attacker config file, but a direct write to `/proc/sys/fs/binfmt_misc/register` was denied and the post-check showed only the stock entries:

```text
python3.12
register
status
ABSENT /proc/sys/fs/binfmt_misc/lpe-attacker
ABSENT /proc/sys/fs/binfmt_misc/lpe-selfauth
ABSENT /proc/sys/fs/binfmt_misc/lpewrite
```

`kmod static-nodes --output=/run/tmpfiles.d/lpe-$USER.conf` also returned `0` because `/lib/modules/6.10.14-linuxkit/modules.devname` is absent; no `/run/tmpfiles.d/lpe-*` file was created.

## Result

No root marker or fallback marker exists:

```text
ls: cannot access '/root/systemd_generators_run_config_lpe': No such file or directory
ls: cannot access '/tmp/systemd_generators_run_config_lpe': No such file or directory
```

Conclusion: the default package/config/reachability exists, but uid1001 cannot place files in the `/run` search paths or service credential paths, cannot mutate systemd's system manager state, and direct helper execution remains unprivileged. This lane is negative in the stock Ubuntu 24.04 Server target under the stated normal-user assumptions.
