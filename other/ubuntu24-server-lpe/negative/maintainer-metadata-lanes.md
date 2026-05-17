# Negative: maintainer-script metadata lanes

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server Docker target  
Probe: `pocs/maintainer_metadata_lanes_probe.sh`  
Log: `logs/maintainer-metadata-lanes.out`  
Result: no validated uid1001-to-root LPE. `ROOT_PROOF=NO`.

## Default proof

Relevant default packages:

```text
apparmor            4.0.1really4.0.1-0ubuntu0.24.04.6
netplan-generator   1.1.2-8ubuntu1~24.04.2
netplan.io          1.1.2-8ubuntu1~24.04.2
python3-netplan     1.1.2-8ubuntu1~24.04.2
base-passwd         3.6.3build1
passwd              1:4.13+dfsg1-4ubuntu3.2
login               1:4.13+dfsg1-4ubuntu3.2
libc6:arm64         2.39-0ubuntu8.7
systemd             255.4-1ubuntu8.15
apt                 2.8.3
unattended-upgrades 2.9.1+nmu4ubuntu1
```

The target remained healthy after the probe:

```text
systemctl is-system-running -> running
failed units -> 0
```

## Candidate 1: AppArmor homedirs postinst

Default root code path:

```text
/var/lib/dpkg/info/apparmor.postinst:38-45
  builds apparmor/homedirs from /etc/passwd field 6 for uid 1000..29999

/var/lib/dpkg/info/apparmor.postinst:52-73
  writes /etc/apparmor.d/tunables/home.d/ubuntu as root
```

The generated file and its inputs are root-owned:

```text
/etc/passwd                                  -rw-r--r-- root:root
/etc/apparmor.d/tunables/home.d             drwxr-xr-x root:root
/etc/apparmor.d/tunables/home.d/ubuntu      -rw-r--r-- root:root
```

uid1001 cannot alter the consumed account home field or replace the generated policy file:

```text
/etc/passwd: Permission denied
/etc/apparmor.d/tunables/home.d/ubuntu: Permission denied
/etc/apparmor.d/tunables/home.d/attacker: Permission denied
```

The live account data for `attacker` and `selfauth` both use ordinary `/home/...` paths. The postinst pipeline filters `/home` parents, so the generated value was empty and the shipped `#@{HOMEDIRS}+=` remained.

## Candidate 2: netplan-generator postinst

Default root code path:

```text
/var/lib/dpkg/info/netplan-generator.postinst:12-18
  find /run/systemd/network/*-netplan*.{network,netdev}
  if any exist, run /usr/libexec/netplan/generate as root
```

The runtime search root is not attacker-writable:

```text
/run          drwxr-xr-x root:root
/run/systemd  drwxr-xr-x root:root
/run/systemd/network: absent
```

uid1001 could not create the gate directory, a matching file, or a symlink:

```text
mkdir /run/systemd/network -> Permission denied
write /run/systemd/network/90-netplan-pwn.network -> Directory nonexistent
symlink /run/systemd/network/91-netplan-pwn.network -> No such file or directory
```

A root postinst replay with no files did not run the generator and created no marker:

```text
FILES=
NO_ROOT_MARKER
```

## Candidate 3: base-passwd update-passwd reconcile

Default root code path:

```text
/var/lib/dpkg/info/base-passwd.postinst:67-72
  update-passwd --dry-run, then update-passwd --verbose on detected changes

/var/lib/dpkg/info/base-passwd.postinst:97-100
  update-passwd --verbose may update passwd/group as root
```

Inputs and helper:

```text
/etc/passwd              -rw-r--r-- root:root
/etc/group               -rw-r--r-- root:root
/etc/shadow              -rw-r----- root:shadow
/usr/sbin/update-passwd  -rwxr-xr-x root:root
```

Direct uid1001 execution cannot read `/etc/shadow` and cannot write the account databases:

```text
update-passwd --dry-run -> Error opening shadow file /etc/shadow: Permission denied
/etc/passwd: Permission denied
/etc/group: Permission denied
/etc/passwd.probe symlink: Permission denied
```

Root dry-run on the live default account database reported:

```text
No changes needed
NO_ROOT_MARKER
```

## Candidate 4: libc services.need_* restart lists

Default root code path:

```text
/var/lib/dpkg/info/libc6:arm64.preinst:309-427
  detects installed services and writes /var/run/services.need_start or
  /var/run/services.need_restart during old-version upgrades

/var/lib/dpkg/info/libc6:arm64.postinst:27-105
  reads those files and runs invoke-rc.d ${service} restart/reload
```

Default timers/services that could run package maintenance are enabled:

```text
apt-daily-upgrade.timer     enabled
unattended-upgrades.service enabled
```

But the restart-list files are absent under a root-owned `/run`:

```text
/run     drwxr-xr-x root:root
/var/run drwxr-xr-x root:root
/run/services.need_restart absent
/run/services.need_start   absent
```

uid1001 cannot create or symlink either file:

```text
/var/run/services.need_restart: Permission denied
/var/run/services.need_start: Permission denied
symlink /var/run/services.need_start: Permission denied
```

A root metacharacter simulation confirmed the unquoted variable expansion did not become shell syntax execution in this shape; the payload was passed as arguments to `invoke-rc.d`, and no marker was created:

```text
invoke-rc.d: policy-rc.d denied execution of /root/libc_services_need_pwn.
NO_ROOT_MARKER
```

## Why this is not a finding

All four lanes are real root maintainer-script or upgrade-time trust boundaries, but none is attacker-reachable from a normal non-sudo local user in the default state. The attacker cannot control AppArmor's consumed home-directory field, cannot seed netplan-generator's `/run/systemd/network` gate, cannot write base-passwd account databases or read shadow as `update-passwd`, and cannot create libc's `/var/run/services.need_*` restart-list files. No root command executed attacker-controlled code, no root file write landed in an attacker-selected path, and no root proof marker was created.

## Cleanup

The probe removed its marker paths:

```sh
rm -f /root/netplan_generator_pwn /root/base_passwd_pwn /root/libc_services_need_pwn
```

No `/run/services.need_restart` or `/run/services.need_start` files existed after cleanup, and the final system state was `running` with zero failed units.

## Why scanners may miss it

SAST can flag the exact risky shapes: account metadata flowing into AppArmor policy text, root `find` over `/run/systemd/network`, account-database reconciliation in `update-passwd`, and unquoted `${service}` in a root libc maintainer script. The exploitable question is whether uid1001 can seed those inputs before the default root maintainer path runs. In this stock Server state, every input root crosses is root-owned or derived from fixed package/service metadata, so the static patterns did not compose into LPE.

## Suggested fixes

No Ubuntu Security LPE fix is warranted from this negative result. Defense-in-depth options:

```text
apparmor: validate generated HOMEDIRS tokens against strict AppArmor variable syntax.
netplan-generator: keep /run/systemd/network root/service-owned and avoid following symlinks if the gate ever becomes writable by a service user.
base-passwd: keep update-passwd account parsing strict and avoid acting on user-controlled GECOS/shell fields.
libc6 maintscripts: quote invoke-rc.d service arguments and validate services.need_* entries against init-script names before restart.
```
