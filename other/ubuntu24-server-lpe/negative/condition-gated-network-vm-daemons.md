# condition-gated-network-vm-daemons negative note

## Result

No uid1001 -> root local privilege escalation was found in the assigned stock Ubuntu 24.04 Server default Docker target slice.

Scope covered:

- `networkd-dispatcher`
- `pollinate`
- `ModemManager`
- `open-vm-tools` / `vgauth`
- `lxd-agent-loader` / `lxd-agent`
- `systemd-networkd`, `systemd-timesyncd`, `systemd-network-generator`
- netplan-generated network cleanup path

## Target proof

Target container:

```text
docker ps --filter name=ubuntu24-server-lpe-target
ubuntu24-server-lpe-target   Up 3 hours   ubuntu24-server-default-lpe:20260516-standard
```

OS and attacker identity:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
VERSION_CODENAME=noble
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
systemctl is-system-running: running
```

Default-install proof:

```text
apt-mark showmanual:
ubuntu-minimal
ubuntu-server
ubuntu-standard

ubuntu-minimal       1.539.2
ubuntu-standard      1.539.2
ubuntu-server        1.539.2
```

Relevant packages and versions:

```text
lxd-agent-loader     0.7ubuntu0.1
modemmanager         1.23.4-0ubuntu2
netplan.io           1.1.2-8ubuntu1~24.04.2
networkd-dispatcher  2.2.4-1
open-vm-tools        2:13.0.0-2~ubuntu0.24.04.1
pollinate            4.33-3.1ubuntu1.3
systemd              255.4-1ubuntu8.15
systemd-timesyncd    255.4-1ubuntu8.15
```

`cloud-init`, `NetworkManager`, `open-vm-tools-desktop`, `open-vm-tools-containerinfo`, and `open-vm-tools-sdmp` are not installed in this default target.

## Unit and condition state

Relevant unit-file state:

```text
ModemManager.service                 enabled
networkd-dispatcher.service          enabled
pollinate.service                    enabled
systemd-timesyncd.service            enabled
vgauth.service                       enabled
open-vm-tools.service                enabled
lxd-agent.service                    static
systemd-networkd.service             disabled
systemd-networkd.socket              disabled
systemd-network-generator.service    disabled
netplan-ovs-cleanup.service          enabled-runtime
```

Runtime state after probing:

```text
networkd-dispatcher.service       inactive dead ConditionResult=no
pollinate.service                 inactive dead ConditionResult=no
ModemManager.service              inactive dead ConditionResult=no
open-vm-tools.service             inactive dead ConditionResult=no
vgauth.service                    inactive dead ConditionResult=no
lxd-agent.service                 inactive dead
systemd-networkd.service          inactive dead ConditionResult=no
systemd-networkd.socket           inactive dead ConditionResult=no
systemd-network-generator.service inactive dead ConditionResult=no
systemd-timesyncd.service         inactive dead ConditionResult=no
netplan-ovs-cleanup.service       inactive dead ConditionResult=no
```

Docker/virtualization detection:

```text
systemd-detect-virt -v  -> vm-other
systemd-detect-virt -c  -> docker
systemd-detect-virt --vm -> vm-other
```

The decisive unit conditions:

- `/usr/lib/systemd/system/networkd-dispatcher.service:3-4` requires at least one hook file under `/etc/networkd-dispatcher/*/*` or `/usr/lib/networkd-dispatcher/*/*`; the default hook trees are empty, so the service is skipped.
- `/usr/lib/systemd/system/pollinate.service:5-6` has `ConditionVirtualization=!container` and `ConditionPathExists=!/var/cache/pollinate/seeded`; Docker fails the virtualization condition.
- `/usr/lib/systemd/system/ModemManager.service:5` has `ConditionVirtualization=!container`; Docker fails it.
- `/usr/lib/systemd/system/open-vm-tools.service:4` and `/usr/lib/systemd/system/vgauth.service:4` require `ConditionVirtualization=vmware`; Docker is not VMware.
- `/usr/lib/systemd/system/systemd-timesyncd.service:13-14` requires `CAP_SYS_TIME` and `ConditionVirtualization=!container`; Docker fails the virtualization condition.
- `/usr/lib/systemd/system/systemd-networkd.service:14` and `/usr/lib/systemd/system/systemd-networkd.socket:13` require `CAP_NET_ADMIN`; the unit is also disabled in this target.
- `/usr/lib/systemd/system/systemd-network-generator.service:23` runs `/usr/lib/systemd/systemd-network-generator`, but the unit is disabled and root-owned output paths are required.
- `/run/systemd/system/netplan-ovs-cleanup.service:6,14` only runs if `/usr/bin/ovs-vsctl` exists and executes `/usr/sbin/netplan apply --only-ovs-cleanup`; OVS is not present in this target.

## Code and config trust boundaries

### networkd-dispatcher

The root service would execute state hooks if the service had valid default hooks and systemd-networkd events:

- `/usr/lib/systemd/system/networkd-dispatcher.service:8` starts `/usr/bin/networkd-dispatcher`.
- `/usr/bin/networkd-dispatcher:48` sets `DEFAULT_SCRIPT_DIR = '/etc/networkd-dispatcher:/usr/lib/networkd-dispatcher'`.
- `/usr/bin/networkd-dispatcher:167-182` checks exact owner/mode for candidate hook paths.
- `/usr/bin/networkd-dispatcher:185-224` enumerates executable hooks in state subdirectories.
- `/usr/bin/networkd-dispatcher:356-388` builds the event environment and executes hooks with `subprocess.Popen(script, env=script_env)`.

Default hook/config permissions:

```text
drwxr-xr-x root:root /etc/networkd-dispatcher
drwxr-xr-x root:root /etc/networkd-dispatcher/{carrier,degraded,dormant,no-carrier,off,routable}.d
drwxr-xr-x root:root /usr/lib/networkd-dispatcher
drwxr-xr-x root:root /usr/lib/networkd-dispatcher/{carrier,degraded,dormant,no-carrier,off,routable}.d
-rw-r--r-- root:root /etc/default/networkd-dispatcher
```

The default hook trees contain only root-owned directories and no executable hook files.

### pollinate

The service is a non-root oneshot:

- `/usr/lib/systemd/system/pollinate.service:10-13` runs as `User=pollinate` with `CacheDirectory=pollinate` mode `0750`.
- `/usr/bin/pollinate:25-27` uses `/var/cache/pollinate`, `/var/cache/pollinate/seeded`, and `/var/cache/pollinate/log`.
- `/usr/bin/pollinate:256-257` sources `/etc/default/pollinate` if present.
- `/usr/bin/pollinate:319-323` refuses normal execution if the caller cannot write `/var/cache/pollinate`.
- `/usr/bin/pollinate:348-350` only touches the seeded flag when not in testing mode.

Default permissions:

```text
drwxr-xr-x  root:root      /etc/pollinate
drwxr-x---  pollinate:daemon /var/cache/pollinate
```

### ModemManager

The D-Bus service is root-capable but condition-gated:

- `/usr/lib/systemd/system/ModemManager.service:5` has `ConditionVirtualization=!container`.
- `/usr/lib/systemd/system/ModemManager.service:8-10` is a D-Bus service owning `org.freedesktop.ModemManager1` and executing `/usr/sbin/ModemManager`.
- `/usr/lib/systemd/system/ModemManager.service:13-19` limits capabilities to `CAP_SYS_ADMIN CAP_NET_ADMIN`, enables `ProtectSystem=true`, `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`, and runs as root.
- `/usr/share/dbus-1/system-services/org.freedesktop.ModemManager1.service:8-11` maps D-Bus activation to `dbus-org.freedesktop.ModemManager1.service`.

Default permissions:

```text
drwxr-xr-x root:root /etc/ModemManager
/var/lib/ModemManager absent
/run/ModemManager absent
```

### open-vm-tools / vgauth

The root VM guest services are installed but VMware-gated:

- `/usr/lib/systemd/system/open-vm-tools.service:4,13` requires `ConditionVirtualization=vmware` and runs `/usr/bin/vmtoolsd`.
- `/usr/lib/systemd/system/vgauth.service:4,11` requires `ConditionVirtualization=vmware` and runs `/usr/bin/VGAuthService`.
- `/lib/udev/rules.d/60-open-vm-tools.rules:1-6` only makes `/dev/vsock` mode `0666` when that VMware-related device exists.
- `/etc/vmware-tools/scripts/vmware/network:47-91` reads logging configuration with `vmware-toolbox-cmd`.
- `/etc/vmware-tools/scripts/vmware/network:127-155` writes the selected log path only if the log directory is writable and then chmods the file.
- `/etc/vmware-tools/scripts/vmware/network:243-260` can call `systemctl` for network service changes, but the script is only reachable from VMware tool lifecycle events in this target slice.

Default permissions:

```text
drwxr-xr-x root:root /etc/vmware-tools
-rw-r--r-- root:root /etc/vmware-tools/tools.conf
-rw-r--r-- root:root /etc/vmware-tools/vgauth.conf
-rwxr-xr-x root:root /etc/vmware-tools/scripts/vmware/network
/run/vmware absent
/var/lib/vmware absent
```

### lxd-agent-loader / lxd-agent

The LXD guest agent service is static and udev-triggered:

- `/usr/lib/systemd/system/lxd-agent.service:1-3` states that it is dynamically triggered by udev when virtio ports are detected.
- `/usr/lib/systemd/system/lxd-agent.service:12-14` runs `/lib/systemd/lxd-agent-setup` and then `/run/lxd_agent/lxd-agent`.
- `/lib/udev/rules.d/99-lxd-agent.rules:1-5` starts `lxd-agent.service` for `virtio-ports/com.canonical.lxd` or `virtio-ports/org.linuxcontainers.lxd`.
- `/lib/systemd/lxd-agent-setup:29-38` creates `/run/lxd_agent`, mounts a tmpfs, mounts read-only virtiofs or 9p named `config`, then copies agent files into `/run/lxd_agent`.

Default state:

```text
/run/lxd_agent absent
/dev/virtio-ports absent
-rwxr-xr-x root:root /lib/systemd/lxd-agent-setup
-rw-r--r-- root:root /lib/udev/rules.d/99-lxd-agent.rules
```

### systemd-networkd, timesyncd, network generator, netplan

The root/network service paths require root-owned config or privileged unit activation:

- `/usr/lib/systemd/system/systemd-networkd.service:23-27` grants network capabilities only inside the service and executes `/usr/lib/systemd/systemd-networkd`.
- `/usr/lib/systemd/system/systemd-networkd.service:38,43,45,52` uses `ProtectSystem=strict`, `RestrictNamespaces=yes`, `RestrictSUIDSGID=yes`, and `User=systemd-network`.
- `/usr/lib/systemd/system/systemd-network-generator.service:23` runs `/usr/lib/systemd/systemd-network-generator`.
- `/usr/lib/systemd/system/systemd-timesyncd.service:22-29` grants only `CAP_SYS_TIME` inside the service and executes `/usr/lib/systemd/systemd-timesyncd`.
- `/usr/lib/systemd/system/systemd-timesyncd.service:42,46,48,55` uses `ProtectSystem=strict`, `RestrictNamespaces=yes`, `RestrictSUIDSGID=yes`, and `User=systemd-timesync`.
- `/usr/share/dbus-1/system-services/org.freedesktop.network1.service:10-14` and `/usr/share/dbus-1/system-services/org.freedesktop.timesync1.service:10-14` D-Bus-activate through their systemd services, not directly through attacker-controlled exec paths.

Default permissions:

```text
drwxr-xr-x root:root /etc/systemd/network
/run/systemd/network absent
drwxr-xr-x root:root /usr/lib/systemd/network
-rw-r--r-- root:root /etc/systemd/timesyncd.conf
/etc/systemd/timesyncd.conf.d absent
/run/systemd/timesync absent
/var/lib/systemd/timesync absent
drwx------ root:root /run/netplan
drwxr-xr-x root:root /etc/netplan
```

## Attacker trigger attempts

All trigger attempts below were executed as:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
Current capabilities: =
```

Starting root units through systemd was denied:

```text
systemctl start networkd-dispatcher.service       -> Interactive authentication required
systemctl start pollinate.service                 -> Interactive authentication required
systemctl start ModemManager.service              -> Interactive authentication required
systemctl start open-vm-tools.service             -> Interactive authentication required
systemctl start vgauth.service                    -> Interactive authentication required
systemctl start lxd-agent.service                 -> Interactive authentication required
systemctl start systemd-networkd.service          -> Interactive authentication required
systemctl start systemd-networkd.socket           -> Interactive authentication required
systemctl start systemd-network-generator.service -> Interactive authentication required
systemctl start systemd-timesyncd.service         -> Interactive authentication required
systemctl start netplan-ovs-cleanup.service       -> Interactive authentication required
```

Writing hooks/configs was denied:

```text
touch /etc/networkd-dispatcher/routable.d/attacker-hook      -> Permission denied
touch /usr/lib/networkd-dispatcher/routable.d/attacker-hook  -> Permission denied
printf x > /etc/default/networkd-dispatcher                  -> Permission denied
printf x > /etc/pollinate/add-user-agent                     -> Permission denied
printf x > /etc/ModemManager/attacker.conf                   -> Permission denied
printf x > /etc/vmware-tools/tools.conf                      -> Permission denied
mkdir -p /run/lxd_agent && touch /run/lxd_agent/lxd-agent    -> Permission denied
printf x > /etc/systemd/network/99-attacker.network          -> Permission denied
mkdir -p /run/systemd/network ...                            -> Permission denied
printf x > /etc/systemd/timesyncd.conf                       -> Permission denied
mkdir -p /etc/systemd/timesyncd.conf.d ...                   -> Permission denied
printf x > /etc/netplan/99-attacker.yaml                     -> Permission denied
printf x > /run/netplan/99-attacker.yaml                     -> Permission denied
```

Udev and fake-device triggers were denied:

```text
mknod /tmp/attacker-virtio c 1 3          -> Operation not permitted
udevadm trigger --subsystem-match=virtio-ports
  -> Failed to write 'change' to .../uevent: Permission denied
udevadm control --reload                  -> Permission denied
```

D-Bus/client activation did not bypass the systemd conditions:

```text
mmcli -L
  -> error: couldn't find the ModemManager process in the bus

busctl --system tree org.freedesktop.ModemManager1
  -> timed out

busctl --system call org.freedesktop.ModemManager1 ... Introspect
  -> Failed to activate service 'org.freedesktop.ModemManager1': timed out

networkctl list --no-pager
  -> systemd-networkd is not running, output might be incomplete

busctl --system tree org.freedesktop.network1
  -> Unit dbus-org.freedesktop.network1.service not found

timedatectl timesync-status --no-pager
  -> timed out

busctl --system tree org.freedesktop.timesync1
  -> Failed to activate service 'org.freedesktop.timesync1': timed out
```

Direct userland execution stayed in uid1001 or failed before root context:

```text
networkd-dispatcher --help
  -> usable only as uid1001; default root service still skipped and hook dirs are not writable

networkd-dispatcher --run-startup-triggers --no-daemon --debug
  -> unsupported arguments; no privileged execution

pollinate --print-user-agent
  -> prints user agent as uid1001

pollinate --wait 1 --server http://127.0.0.1:9
  -> rc=1; normal mode requires writable /var/cache/pollinate

pollinate --testing --wait 1 --server http://127.0.0.1:9
  -> rc=0; testing mode writes to stdout, not a privileged target

vmtoolsd --cmd 'info-get guestinfo.codex'
  -> rc=1

vmware-toolbox-cmd config get logging network.data
  -> vmware-toolbox-cmd must be run inside a virtual machine

VGAuthService -s
  -> reads /etc/vmware-tools/vgauth.conf and aborts as uid1001; no root context

/lib/systemd/lxd-agent-setup
  -> mkdir: cannot create directory '/run/lxd_agent': Permission denied

/usr/lib/systemd/systemd-network-generator
  -> Failed to create directory /run/systemd/network: Permission denied

netplan generate
  -> cannot create /run/systemd/system/netplan-ovs-cleanup.service; daemon-reload denied

netplan apply
  -> cannot create /run/systemd/system/netplan-ovs-cleanup.service

netplan status --all
  -> attempts to start systemd-networkd; Interactive authentication required
```

## Reachability conclusion by surface

- `networkd-dispatcher`: potentially interesting because it runs root hooks with a rich environment, but default Docker state has no hook files, root-owned hook/config dirs, inactive `systemd-networkd`, and unprivileged users cannot start the service. No root transition.
- `pollinate`: default-installed and enabled through `ubuntu-server`, but container-gated and runs as `pollinate`, not root. Attacker cannot write `/var/cache/pollinate` or `/etc/pollinate`; direct testing mode has no privileged write. No root transition.
- `ModemManager`: installed and D-Bus activatable in principle, but Docker fails `ConditionVirtualization=!container`; attacker D-Bus activation times out/skips and no modem objects or state-changing methods are reachable. No root transition.
- `open-vm-tools` / `vgauth`: installed and enabled, but gated on `ConditionVirtualization=vmware`; `/dev/vsock` and VMware backdoor paths are absent/unusable in this default Docker target. Config/script dirs are root-owned. No root transition.
- `lxd-agent`: static service is only udev-triggered by LXD virtio-port symlinks; default Docker target has no `/dev/virtio-ports`, attacker cannot create device nodes or reload/trigger udev, and `/run/lxd_agent` is root-only. No root transition.
- `systemd-networkd` / generator: disabled/inactive; D-Bus service alias is not activatable in this target; direct generator execution cannot write `/run/systemd/network`; netplan cannot write `/run/systemd/system` or reload systemd. No root transition.
- `systemd-timesyncd`: enabled but container-gated; D-Bus activation times out/skips and config/state dirs are root-owned. No root transition.

## Cleanup and final state

No persistent changes were needed. Residue check:

```text
absent /etc/networkd-dispatcher/routable.d/attacker-hook
absent /usr/lib/networkd-dispatcher/routable.d/attacker-hook
absent /etc/pollinate/add-user-agent
absent /etc/ModemManager/attacker.conf
absent /run/lxd_agent
absent /etc/systemd/network/99-attacker.network
absent /run/systemd/network/99-attacker.network
absent /etc/systemd/timesyncd.conf.d/attacker.conf
absent /etc/netplan/99-attacker.yaml
absent /run/netplan/99-attacker.yaml
absent /tmp/attacker-virtio
absent /var/log/vmware-network.log
absent /core
absent /home/attacker/core
```

Final state:

```text
systemctl is-system-running -> running
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
No root marker files found under /root, /tmp, or /var/tmp for this slice.
```

## Why scanners may still flag this slice

This slice contains several root service boundaries that look attractive in static output:

- root services with D-Bus activation files;
- root hook execution in `networkd-dispatcher`;
- VMware state-change shell scripts that call `systemctl`, manipulate logs, and run networking helpers;
- LXD agent setup that copies and executes `/run/lxd_agent/lxd-agent`;
- netplan/systemd network generators writing root-owned runtime units.

The default-state exploitability depends on runtime conditions and ownership, not just code shape. In the live Ubuntu 24.04 Server Docker target, the relevant conditions are unmet, writable hook/config directories are absent, D-Bus activation stays tied to systemd conditions, and uid1001 cannot trigger udev/systemd transitions that would enter a root context.

## Suggested hardening notes

No security bug was validated. Defense-in-depth ideas for Ubuntu triage:

- Keep `networkd-dispatcher` permission validation strict and continue rejecting non-root-owned hooks and parent directories before root execution.
- Consider making condition-gated D-Bus activation fail fast with clear condition errors rather than timing out for ModemManager/timesyncd in containers.
- Keep LXD agent startup constrained to root-owned udev events and root-created `/run/lxd_agent`; do not allow user-created virtio-port names to request the service.
- Keep VM guest tool config and script directories root-owned, and avoid honoring untrusted per-user VMware tool configuration from root lifecycle scripts.
- Keep netplan generated-unit writes under root-owned `/run/systemd/system` and require privileged systemd daemon reloads.

No `notes/` finding or `pocs/` exploit was created because there is no validated uid1001 -> root privilege escalation in this assigned slice.
