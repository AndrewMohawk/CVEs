# Negative: kernel/initramfs/update hook boundaries

Date: 2026-05-16
Target: Docker container `ubuntu24-server-lpe-target`
Result: no validated uid1001-to-root local privilege escalation.

## Scope

This lane covered stock Ubuntu 24.04 Server kernel/initramfs/update hook boundaries: `initramfs-tools`, `dracut-install`, kernel install hooks, `depmod`/`modprobe`, module-load, sysctl, sysusers, hwdb, binfmt, `ucf`, `update-alternatives`, dpkg trigger/helper transitions, root cache/rebuild services, writable temp paths, symlink bait, and hostile `PATH`/`TMPDIR`/hook roots.

## Default proof

Target identity:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
Linux 4f5b414436ae 6.10.14-linuxkit ... aarch64
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
sudo: a password is required
```

Default package versions from the live target:

```text
dpkg 1.22.6ubuntu6.6
dracut-install 060+5-1ubuntu3.3
initramfs-tools 0.142ubuntu25.8
initramfs-tools-bin 0.142ubuntu25.8
initramfs-tools-core 0.142ubuntu25.8
kmod 31+20240202-2ubuntu7.2
linux-base 4.5ubuntu9+24.04.2
systemd 255.4-1ubuntu8.15
ucf 3.0043+nmu1
udev 255.4-1ubuntu8.15
dracut-core not installed
binfmt-support not installed
```

Default root consumers observed:

```text
systemd-modules-load.service -> /usr/lib/systemd/systemd-modules-load
systemd-sysctl.service -> /usr/lib/systemd/systemd-sysctl
systemd-sysusers.service -> systemd-sysusers
systemd-binfmt.service -> /usr/lib/systemd/systemd-binfmt
systemd-hwdb-update.service -> systemd-hwdb update
kmod-static-nodes.service -> /usr/bin/kmod static-nodes --format=tmpfiles --output=/run/tmpfiles.d/static-nodes.conf
```

Relevant code/config paths:

```text
/usr/sbin/update-initramfs:14-15 defers maintainer-script updates via dpkg-trigger
/usr/sbin/update-initramfs:142-143 invokes mkinitramfs then renames initrd
/usr/sbin/update-initramfs:160-161 invokes /etc/initramfs/post-update.d via run-parts
/usr/sbin/mkinitramfs:4 resets PATH to /usr/bin:/sbin:/bin
/usr/sbin/mkinitramfs:102,124 sources initramfs config from CONFDIR
/usr/sbin/mkinitramfs:298-305 creates mktemp files/dirs under TMPDIR or /var/tmp
/usr/sbin/mkinitramfs:445,448 runs /usr/share/initramfs-tools/hooks and /etc/initramfs-tools/hooks
/usr/share/initramfs-tools/hook-functions:999 runs hook scripts
/etc/kernel/postinst.d/initramfs-tools:36 calls update-initramfs -c
/etc/kernel/postrm.d/initramfs-tools:36 calls update-initramfs -d
/usr/lib/kernel/install.d/50-depmod.install:33 execs depmod -a
/usr/lib/kernel/install.d/55-initrd.install:21 symlinks /boot/initrd.img-$version into staging
/usr/bin/ucf:298 defaults state to /var/lib/ucf
```

All default trust roots tested were root-owned and not writable by uid1001, including `/boot`, `/etc/initramfs-tools`, `/etc/initramfs-tools/{conf.d,hooks,scripts}`, `/usr/share/initramfs-tools/hooks`, `/etc/kernel/postinst.d`, `/usr/lib/kernel/install.d`, `/etc/{depmod.d,modprobe.d,modules-load.d,sysctl.d,binfmt.d,udev/hwdb.d}`, `/usr/lib/{modprobe.d,modules-load.d,sysctl.d,binfmt.d,sysusers.d,udev/hwdb.d}`, `/var/lib/dpkg/triggers`, `/var/lib/ucf`, `/etc/alternatives`, and `/var/lib/dpkg/alternatives`.

## Probe results

Attacker attempts to cross into root-managed transitions were blocked:

```text
systemctl set-environment ... -> Failed to set environment: Access denied
systemctl start systemd-hwdb-update.service -> Interactive authentication required
systemctl start kmod-static-nodes.service -> Interactive authentication required
systemctl start systemd-binfmt.service -> Interactive authentication required
systemctl start systemd-sysctl.service -> Interactive authentication required
systemctl start systemd-sysusers.service -> Interactive authentication required
systemctl start systemd-modules-load.service -> Interactive authentication required
dpkg-trigger --no-await update-initramfs -> /var/lib/dpkg/triggers/Lock: Permission denied
```

Direct helper execution with hostile `PATH`, `TMPDIR`, attacker initramfs hooks, attacker kernel config root, and attacker temp roots remained uid1001-only:

```text
PATH_PAYLOAD cmd=mkinitramfs euid=1001 ruid=1001
PATH_PAYLOAD cmd=rm euid=1001 ruid=1001
INITRAMFS_HOOK euid=1001 ruid=1001 DESTDIR=/home/attacker/.../tmp/mkinitramfs_Xua29T
PATH_PAYLOAD cmd=cp euid=1001 ruid=1001
NO_ROOT_MARKER_FROM_DIRECT_RUNS
```

Root trigger commands exercised after attacker state was planted:

```sh
systemctl start systemd-hwdb-update.service
systemctl start kmod-static-nodes.service
systemctl start systemd-binfmt.service
systemctl start systemd-sysctl.service
systemctl start systemd-sysusers.service
systemctl start systemd-modules-load.service
env -i HOME=/root LOGNAME=root PATH=/usr/bin:/usr/sbin:/bin:/sbin /usr/sbin/update-initramfs -u -k all
env -i HOME=/root LOGNAME=root PATH=/usr/bin:/usr/sbin:/bin:/sbin /usr/sbin/mkinitramfs -o /tmp/kernel_initramfs_hooks_probe_root_initrd.img 0.0-probe
env -i HOME=/root LOGNAME=root PATH=/usr/bin:/usr/sbin:/bin:/sbin /usr/lib/dracut/dracut-install -D /tmp/kernel_initramfs_hooks_probe_dracut_root /bin/sh
env -i HOME=/root LOGNAME=root PATH=/usr/bin:/usr/sbin:/bin:/sbin /usr/sbin/depmod -a "$(uname -r)"
```

Root proof absence:

```text
root_update_initramfs_rc=0
root_mkinitramfs_rc=0
root_dracut_install_rc=0
NO_ROOT_MARKER
/tmp/kernel_initramfs_hooks_probe_tmp_link remained attacker-owned symlink
/run/lock/kernel_initramfs_hooks_probe_lock_link remained attacker-owned symlink
cleanup_done
target health: running
```

## Cleanup

`pocs/kernel_initramfs_hooks_probe.sh` removes `/home/attacker/kernel_initramfs_hooks_probe`, `/tmp/kernel_initramfs_hooks_probe*`, `/var/tmp/kernel_initramfs_hooks_probe*`, `/run/lock/kernel_initramfs_hooks_probe*`, and `/root/kernel_initramfs_hooks_probe*`, then resets failed state on touched systemd units. Post-run checks showed no probe leftovers, zero failed units, and `systemctl is-system-running` returned `running`.

Validation:

```sh
bash -n pocs/kernel_initramfs_hooks_probe.sh
pocs/kernel_initramfs_hooks_probe.sh ubuntu24-server-lpe-target
```

## Why scanners might flag this

Static review will flag root shell hooks, unqualified commands in `update-initramfs`, `TMPDIR`/`mktemp` use in `mkinitramfs`, root-run kernel install plugins, writable sticky directories, dpkg triggers, and `ucf`/`update-alternatives` state transitions. In the default server state, those primitives did not become LPE because uid1001 cannot write the root hook/config/state directories, cannot set the system manager environment, cannot start the root units, cannot enqueue dpkg triggers, and direct execution of the helpers stays at uid1001.
