# Negative: condition-gated/default service surfaces

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS Server Docker target.

Artifacts:

```text
pocs/condition_gated_services_probe.sh
logs/condition-gated-services-20260517.out
```

## Result

No uid1001-to-root LPE was found through:

```text
vgauth.service
open-vm-tools.service / vmtoolsd.service
rsync.service
rc-local.service
system-update-cleanup.service / system-update.target
```

`ROOT_PROOF=no`: the probe checked `/root/condition_gated_services_20260517_root_proof` after all trigger attempts and reported `ROOT_PROOF_ABSENT`.

## Default package and target proof

Live target proof:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
systemd 255 (255.4-1ubuntu8.15)
systemctl is-system-running: running
systemd-detect-virt -v: vm-other
systemd-detect-virt -c: docker
systemd-detect-virt --vm: vm-other
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
CapEff: 0000000000000000
```

Default package versions:

```text
ubuntu-minimal   1.539.2
ubuntu-standard  1.539.2
ubuntu-server    1.539.2
systemd          255.4-1ubuntu8.15
systemd-sysv     255.4-1ubuntu8.15
open-vm-tools    2:13.0.0-2~ubuntu0.24.04.1
rsync            3.2.7-1ubuntu1.2
polkitd          124-2ubuntu1.24.04.3
```

Not installed in this target: `open-vm-tools-desktop`, `open-vm-tools-containerinfo`, `open-vm-tools-sdmp`, `policykit-1`, `initscripts`.

## Default service state

Before and after triggers:

```text
vgauth.service                  enabled, inactive/dead, ConditionResult=no
open-vm-tools.service           enabled, inactive/dead, ConditionResult=no
vmtoolsd.service                alias to open-vm-tools.service, inactive/dead, ConditionResult=no
rsync.service                   disabled, inactive/dead, ConditionResult=no
rc-local.service                static, inactive/dead, ConditionResult=no
system-update-cleanup.service   static, inactive/dead, ConditionResult=no
system-update.target            static, inactive/dead, ConditionResult=no
```

No matching rsync, VMware tools, VGAuth, rc-local, or system-update listener/process was present before or after probing.

## Condition and input blockers

`vgauth.service` and `open-vm-tools.service` both contain `ConditionVirtualization=vmware`; the target reports Docker/container virtualization, not VMware. The helpers and config paths are root-owned:

```text
/usr/bin/VGAuthService                         root:root 0755
/usr/bin/vmtoolsd                              root:root 0755
/etc/vmware-tools                              root:root 0755
/etc/vmware-tools/tools.conf                   root:root 0644
/etc/vmware-tools/vgauth.conf                  root:root 0644
/etc/vmware-tools/scripts/vmware/network       root:root 0755
```

`rsync.service` contains `ConditionPathExists=/etc/rsyncd.conf`; `/etc/rsyncd.conf` is absent and `/etc` is root-owned `0755`. The probe did not create a custom `/etc/rsyncd.conf` as root.

`rc-local.service` contains `ConditionFileIsExecutable=/etc/rc.local`; `/etc/rc.local` is absent and `/etc` is root-owned `0755`. The probe did not create `/etc/rc.local` as root.

`system-update-cleanup.service` only runs if `/system-update`, `/etc/system-update`, or corresponding symlink conditions are true. Both paths are absent, `/` and `/etc` are root-owned `0755`, and the service only executes `rm -fv /system-update /etc/system-update`.

## Attacker attempts

As uid1001, all root-gated inputs were non-writable:

```text
/etc/rsyncd.conf -> no
/etc/rc.local -> no
/system-update -> no
/etc/system-update -> no
/etc/vmware-tools/tools.conf -> no
/etc/vmware-tools/vgauth.conf -> no
/etc/vmware-tools/scripts/vmware/network -> no
/etc/vmware-tools/scripts/vmware -> no
/etc/vmware-tools -> no
/run/vmware -> no
/var/run/vmware -> no
/var/lib/vmware -> no
/var/log/vmware -> no
```

Plant attempts as uid1001 failed with permission denied or missing parent for `/etc/rsyncd.conf`, `/etc/rc.local`, VMware tool script/config paths, `/run/vmware`, `/var/run/vmware`, `/var/lib/vmware`, `/var/log/vmware`, `/system-update`, and `/etc/system-update`.

Unit activation attempts as uid1001 failed through both `systemctl start` and systemd D-Bus `StartUnit`:

```text
vgauth.service
open-vm-tools.service
vmtoolsd.service
rsync.service
rc-local.service
system-update-cleanup.service
system-update.target
```

Each returned `Interactive authentication required`.

Direct helper/daemon attempts stayed unprivileged:

```text
vmware-checkvm -> not inside a VMware hypervisor
vmtoolsd --cmd -> rc=1
vmware-toolbox-cmd -> must be run inside a virtual machine
VGAuthService -> failed initializing alias store under /var/lib/vmware as uid1001
rsync --daemon --no-detach -> failed parsing absent /etc/rsyncd.conf
/etc/rc.local start -> no such file
rm -fv /system-update /etc/system-update -> uid1001 unprivileged no-op
```

A temporary uid1001 rsync daemon using a `/tmp` config and high port ran only as `attacker`; it was killed and removed. It did not involve `/etc/rsyncd.conf` or root service activation.

## Cleanup

The probe removed its `/tmp` scratch state and checked that the target stayed healthy:

```text
systemctl is-system-running: running
cleanup complete
```

Post-run verification confirmed these paths were absent:

```text
/root/condition_gated_services_20260517_root_proof
/etc/rsyncd.conf
/etc/rc.local
/system-update
/etc/system-update
/tmp/condition_gated_services_20260517
/tmp/condition_gated_services_20260517_rsyncd.conf
```

## Why this is not an LPE

The only root execution paths are behind systemd conditions plus privileged unit activation. The normal uid1001 account cannot satisfy the default input files, cannot create the marker/symlink paths that would make the units eligible, cannot start the units through systemd, and cannot write the VMware/rsync/rc-local configuration or script paths. Direct helper execution either detects the missing VMware environment, fails as uid1001, or runs only with uid1001 privileges. No root command execution, root-owned attacker-controlled write, privileged group transition, or uid0 proof was reached.
