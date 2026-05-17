# userns/netns netdev udev/sysctl probe

Date: 2026-05-16

Result: negative. I did not validate a stock Ubuntu 24.04 Server local root LPE from this candidate. A normal non-sudo user can create dummy network devices inside an unprivileged user namespace plus network namespace, including some metacharacter-looking interface names, but those devices were not visible to the target initial namespace's root `systemd-udevd`, `systemd-sysctl`, netplan, networkd, or systemd unit machinery.

Artifacts:

```sh
pocs/userns_netdev_udev_sysctl_probe.sh ubuntu24-server-lpe-target
logs/userns-netdev-udev-sysctl.out
```

## Target/default proof

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS userspace, LinuxKit host kernel in the Docker target.

Attacker:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

Relevant sysctls:

```text
user.max_user_namespaces = 31723
user.max_net_namespaces = 31723
kernel.unprivileged_userns_clone: absent in this kernel
kernel.apparmor_restrict_unprivileged_userns: absent in this kernel
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
```

Relevant packages/services:

```text
systemd                255.4-1ubuntu8.15
udev                   255.4-1ubuntu8.15
netplan.io             1.1.2-8ubuntu1~24.04.2
networkd-dispatcher    2.2.4-1
open-iscsi             2.1.9-3ubuntu5.4

systemd-udevd.service:        active/running
systemd-sysctl.service:       active/exited
systemd-networkd.service:     inactive
systemd-networkd.socket:      inactive
networkd-dispatcher.service:  inactive, condition unmet
netplan-ovs-cleanup.service:  inactive
```

Default `systemd-sysctl --cat-config` had no active `net.ipv4.conf.*`, `net.ipv4.neigh.*`, `net.ipv6.conf.*`, or `net.ipv6.neigh.*` entries. The relevant default root udev hooks are still present:

```text
/usr/lib/udev/rules.d/70-iscsi-network-interface.rules:
  SUBSYSTEM=="net", ACTION=="add", RUN+="/usr/lib/open-iscsi/net-interface-handler start"
  SUBSYSTEM=="net", ACTION=="remove", RUN+="/usr/lib/open-iscsi/net-interface-handler stop"

/usr/lib/udev/rules.d/99-systemd.rules:
  SUBSYSTEM=="net", KERNEL!="lo", TAG+="systemd", ENV{SYSTEMD_ALIAS}+="/sys/subsystem/net/devices/$name"
  ACTION=="add", SUBSYSTEM=="net", KERNEL!="lo", RUN+="/usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/$name --prefix=/net/ipv4/neigh/$name --prefix=/net/ipv6/conf/$name --prefix=/net/ipv6/neigh/$name"
```

## Control

The probe first created `rootctl0` as root in the target initial network namespace. This validated the instrumentation: `udevadm monitor` saw both kernel and udev events, and debug journald logs showed root `systemd-udevd` running both `/usr/lib/open-iscsi/net-interface-handler start` and `/usr/lib/systemd/systemd-sysctl --prefix=/net/.../rootctl0`.

The root-control side effect was bounded and cleaned up by deleting `rootctl0`, restoring udev log level to `info`, and resetting transient `iscsid.service` / `iscsid.socket` failed state.

## Attacker trigger

The attacker ran:

```sh
runuser -u attacker -- unshare -Urn bash
```

Inside the namespace:

```text
uid=0(root) gid=0(root) groups=0(root)
uid_map: 0 1001 1
gid_map: 0 1001 1
CapEff: 000001ffffffffff
```

Accepted attacker-controlled dummy interface names:

```text
unvns0
lo.probe
net.ipv4
x;y
abc"q
dollar$x
persist0
```

Rejected names:

```text
all      -> RTNETLINK answers: Invalid argument
default  -> RTNETLINK answers: Invalid argument
x y      -> not a valid ifname
x:y      -> RTNETLINK answers: Invalid argument
a/b      -> not a valid ifname
abcdefghijklmnop -> overlength, not a valid ifname
```

While attacker-created `persist0` was alive, root in the target initial namespace did not see it:

```text
root_sysfs_persist0=absent
```

The root udev monitor for the attacker phase printed only its banner and no `KERNEL` or `UDEV` events. The debug journal after the attacker phase had no matching `persist0`, `unvns0`, `lo.probe`, `net.ipv4`, `x;y`, `abc"q`, `dollar$x`, `systemd-sysctl`, or `net-interface-handler` lines. `/run/udev/data` also had no records for the attacker-created names, and `systemctl list-units --all` had no units mentioning the tested names.

## Conclusion

No LPE. The exploitable-looking root hooks exist for initial-namespace network devices, but unprivileged userns+netns-created devices did not cross into root udev/systemd processing in this Docker stock Server target. Since root `systemd-udevd` never received attacker netdev events, attacker-controlled interface names could not influence root `systemd-sysctl` prefixes, `SYSTEMD_ALIAS`, unit instances, netplan, networkd, or networkd-dispatcher. No root-owned marker, account, file write, or command execution primitive was produced.

Cleanup verified:

```text
container_system_state_after_root_control_cleanup=running
container_system_state_after=running
/root/userns-netdev-udev-sysctl*: absent
/tmp/userns-netdev-udev-sysctl-root*: absent
```
