# Cloud-init default boot hooks and cloud helpers: no uid1001 -> root LPE

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS. Attacker identity was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Evidence log: `logs/cloud-init-default.out`

Result: negative. No root-owned attacker-controlled write, root command execution, or later root cloud-init/growpart/cloud-final trigger was reached.

## Default package and service state

Installed/default in this target:

```text
cloud-guest-utils                  0.33-1
cloud-initramfs-copymods           0.49~24.04.1
cloud-initramfs-dyn-netconf        0.49~24.04.1
initramfs-tools                    0.142ubuntu25.8
initramfs-tools-core               0.142ubuntu25.8
systemd                            255.4-1ubuntu8.15
udev                               255.4-1ubuntu8.15
util-linux                         2.39.3-9ubuntu6.5
fdisk                              2.39.3-9ubuntu6.5
gdisk                              1.0.10-1build1
parted                             3.6-4build1
e2fsprogs                          1.47.0-2.4~exp1ubuntu4.1
xfsprogs                           6.6.0-1ubuntu2.1
```

Not installed/default in this Docker target:

```text
cloud-init
cloud-initramfs-growroot
cloud-initramfs-rescuevol
cloud-initramfs-tools
cloud-utils
growpart package name
```

`/usr/bin/growpart` is installed, but it is owned by `cloud-guest-utils: /usr/bin/growpart`; there is no separate installed `growpart` package.

Cloud-init reachability is absent by default: `cloud-init status --long` returns `cloud-init: command not found`, and `cloud-init-local.service`, `cloud-init.service`, `cloud-config.service`, `cloud-final.service`, `cloud-init.target`, `cloud-init-hotplugd.socket`, `cloud-init-hotplugd.service`, `cloud-init-main.service`, `cloud-init-network.service`, `growpart.service`, and `cloud-initramfs-growroot.service` all show `LoadState=not-found`.

The only grow/initramfs-adjacent loaded units observed were `systemd-growfs-root.service`, `systemd-growfs@.service`, `mdadm-grow-continue@.service`, and `plymouth-switch-root-initramfs.service`; they are static/inactive and did not expose a uid1001-controlled cloud-init/growpart hook.

## Trust boundary checks

`/etc/cloud` exists as `root:root 0755`, but `/etc/cloud/cloud.cfg`, `/etc/cloud/cloud.cfg.d`, `/etc/cloud/templates`, and `/etc/cloud/ds-identify.cfg` are absent or root-only. uid1001 cannot create config under `/etc/cloud`.

All live cloud-init state and seed paths are absent: `/var/lib/cloud`, `/var/lib/cloud/seed/nocloud`, `/var/lib/cloud/seed/nocloud-net`, `/var/lib/cloud/scripts/per-boot`, `/var/lib/cloud/scripts/per-instance`, `/run/cloud-init`, `/run/cloud-init/instance-data.json`, and `/run/cloud-init/instance-data-sensitive.json`. uid1001 cannot create the missing parents under `/var/lib` or `/run`.

Installed cloud-initramfs scripts are root-owned `0755` under `/usr/share/initramfs-tools`, and writable hook/config parents under `/etc/initramfs-tools` are root-owned `0755`. uid1001 cannot plant initramfs hooks, growroot flags, or boot scripts.

`growpart` is a normal root-owned executable, not setuid/capability-backed. A direct uid1001 run with attacker-controlled `PATH`, `TMPDIR`, and fake helper binaries executed the fake `sfdisk` as `FAKE_sfdisk_UID=1001`; no root environment/path propagation was present.

## Trigger commands tested

Reproduce:

```sh
bash -n pocs/cloud_init_default_probe.sh
pocs/cloud_init_default_probe.sh ubuntu24-server-lpe-target > logs/cloud-init-default.out 2>&1
```

uid1001 trigger attempts included:

```text
touch/mkdir under /etc/cloud, /var/lib/cloud seed/state, /run/cloud-init, /etc/initramfs-tools, /usr/share/initramfs-tools, and /boot
symlink/hardlink planting into cloud seed/script/state paths
systemctl start cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service cloud-init.target cloud-init-hotplugd.socket cloud-init-hotplugd.service growpart.service cloud-initramfs-growroot.service systemd-growfs-root.service plymouth-switch-root-initramfs.service
cloud-init status/init/modules/single, cloud-id, cloud-init-per
update-initramfs -u -v
growpart -N on an attacker-owned image with attacker PATH helpers
```

All sensitive writes failed with `Permission denied` or missing root-owned parents. `systemctl start` attempts returned `Interactive authentication required`. Direct cloud-init commands were absent. `update-initramfs -u -v` reported no available kernel versions and did not run a root hook. Direct `growpart` remained uid1001-only.

## Root proof and cleanup

The probe recorded no unexpected sensitive writes:

```text
unexpected sensitive path writes recorded: none
root proof sweep before cleanup: NO_ROOT_MARKER
cleanup: cleanup_complete
```

Manual cleanup if needed:

```sh
docker exec ubuntu24-server-lpe-target sh -lc 'rm -rf /tmp/cloud_init_default* /home/attacker/cloud_init_default /root/cloud_init_default_root_marker'
```

## Why scanners miss

Name-based scans flag `cloud-guest-utils`, `/usr/bin/growpart`, `cloud-initramfs-copymods`, and `cloud-initramfs-dyn-netconf` as cloud boot surfaces, and the dyn-netconf script sources `/run/net-*.conf` during initramfs boot. In this stock Docker target, however, `cloud-init` itself is absent, the cloud-init unit/generator/state tree is absent, NoCloud seed paths are not user-creatable, the initramfs hooks are root-owned build-time/boot-time files, and local uid1001 cannot trigger a later root cloud-final/growpart execution path.
