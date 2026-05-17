# Hypervisor and guest-agent default surfaces: no uid1001/selfauth -> root LPE

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Tested users were `attacker` (`uid=1001 gid=1001 groups=1001`) and `selfauth` (`uid=1002 gid=1002 groups=1002`).

Result: negative. No uid0 execution, root-owned attacker-controlled write, or root-controlled write primitive was reached.

Evidence log: `logs/hypervisor-agent-default.out`

## Default package and service state

Installed/default in this target:

```text
open-vm-tools                    2:13.0.0-2~ubuntu0.24.04.1
lxd-agent-loader                 0.7ubuntu0.1
lxd-installer                    4ubuntu0.1
pollinate                        4.33-3.1ubuntu1.3
cloud-initramfs-copymods         0.49~24.04.1
cloud-initramfs-dyn-netconf      0.49~24.04.1
cloud-guest-utils                0.33-1
initramfs-tools                  0.142ubuntu25.8
systemd                          255.4-1ubuntu8.15
```

Not installed: `cloud-init`, `cloud-initramfs-tools`, `open-vm-tools-desktop`, `open-vm-tools-containerinfo`, `open-vm-tools-sdmp`, `policykit-1`.

Default unit state before triggers:

```text
open-vm-tools.service            loaded/enabled, inactive, ConditionResult=no
vmtoolsd.service                 alias for open-vm-tools, inactive, ConditionResult=no
vgauth.service                   loaded/enabled, inactive, ConditionResult=no
lxd-agent.service                loaded/static, inactive, ConditionResult=no
lxd-installer.socket             loaded/enabled, active/listening, ConditionResult=yes
lxd-installer@.service           static template
pollinate.service                loaded/enabled, inactive, User=pollinate, ConditionResult=no
cloud-init*.service              not found
```

## Blockers

`open-vm-tools`/`vgauth`: both root services are VMware-gated by `ConditionVirtualization=vmware`. The Docker target reports `systemd-detect-virt -c=docker` and `systemd-detect-virt --vm=vm-other`, so `vmtoolsd` and `VGAuthService` stay inactive. `/etc/vmware-tools`, `tools.conf`, `vgauth.conf`, and lifecycle script paths are root-owned and not writable by either user.

`lxd-agent-loader`: `lxd-agent.service` is static and udev/hardware-triggered for LXD virtio ports. `/dev/virtio-ports` and `/run/lxd_agent` are absent. Direct `lxd-agent-setup` execution as either user fails creating `/run/lxd_agent`.

`lxd-installer`: the default socket is active, but `/run/lxd-installer.socket` is `srw-rw---- root:lxd`. Neither test user is in `lxd`; direct socket connect and `/sbin/lxc`/`/sbin/lxd` shim triggers fail with permission denied/group gating.

`pollinate`: the service is condition-gated by `ConditionVirtualization=!container` and runs as `User=pollinate`, not root. `/etc/default/pollinate` is root-owned and `/var/cache/pollinate` is `pollinate:daemon 0750`; neither user can write either path. Direct `pollinate --print-user-agent` is unprivileged metadata output only.

`cloud-initramfs` helpers: `cloud-init` is absent. Installed initramfs hooks/scripts are root-owned under `/usr/share/initramfs-tools` and `/etc/initramfs-tools`; neither user can write hook/config paths. `/boot` is root-owned, `/var/lib/initramfs-tools` is absent, and `update-initramfs -u -v` reports `Available versions:` then `Nothing to do, exiting.`

Local IPC/RPC: no VMware/vgauth/LXD-agent system bus name or Unix socket is reachable by the users. `/dev/vsock` is world-openable, but there is no active default root VMware service or guest-agent endpoint attached to it in this target.

## Trigger commands tested

Reproduce:

```sh
bash -n pocs/hypervisor_agent_default_probe.sh
pocs/hypervisor_agent_default_probe.sh ubuntu24-server-lpe-target > logs/hypervisor-agent-default.out 2>&1
```

The probe attempted, for both `attacker` and `selfauth`:

```text
test -w and payload writes to VMware, LXD, pollinate, cloud-initramfs, /boot, and cloud hook paths
systemctl start open-vm-tools/vmtoolsd/vgauth/lxd-agent/pollinate/lxd-installer@
systemd D-Bus StartUnit for the guest-agent services
direct /run/lxd-installer.socket connect and /sbin/lxc / /sbin/lxd shims
vmtoolsd --cmd, vmware-toolbox-cmd, vmware-checkvm
/lib/systemd/lxd-agent-setup
pollinate --print-user-agent
update-initramfs -u -v
```

No payload write returned `WRITE_OK`; service and D-Bus starts returned `Interactive authentication required`; lxd-installer socket connects returned `EACCES`; direct VMware tools reported non-VMware/hardware gating; lxd-agent setup failed on `/run/lxd_agent`; final sweep reported `NO_ROOT_MARKER`.

## Cleanup

The probe removes its candidate payload paths and `/tmp` scratch state. Manual cleanup if needed:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'rm -rf /tmp/hypervisor_agent_default* /home/attacker/hypervisor_agent_default /home/selfauth/hypervisor_agent_default /root/hypervisor_agent_default_root_marker'
```

## Why this is not an LPE

The only active root-owned socket in this lane is `lxd-installer.socket`, and the kernel socket mode blocks both normal users before the fixed root installer service can be activated. All other root guest-agent services are inactive due to virtualization/hardware conditions or absent cloud-init services. The writable surface exposed to the users is limited to unprivileged direct helper execution and `/dev/vsock` open access without a default root endpoint. No attacker-controlled data reached root execution or a root-owned write.
