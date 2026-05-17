# Negative: support and overlay helper boundaries

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server default in Docker. Attacker identity was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no validated uid1001 -> root LPE. Root proof: no.

Rerun:

```sh
pocs/support_overlay_helpers_probe.sh ubuntu24-server-lpe-target > logs/support-overlay-helpers.out 2>&1
```

## Default package and reachability proof

Installed/default in this target:

```text
apport                         2.28.1-0ubuntu3.8
apport-core-dump-handler       2.28.1-0ubuntu3.8
cloud-guest-utils              0.33-1
cloud-initramfs-copymods       0.49~24.04.1
cloud-initramfs-dyn-netconf    0.49~24.04.1
finalrd                        9build1
friendly-recovery              0.2.42
overlayroot                    0.49~24.04.1
python3-apport                 2.28.1-0ubuntu3.8
sosreport                      4.10.2-0ubuntu0~24.04.1
unminimize                     0.2.1
```

Not installed as packages: `cloud-init`, `cloud-initramfs-tools`, `growpart`, `sos`, `policykit-1`, `pkexec`. The `/usr/bin/growpart` command is installed by `cloud-guest-utils`. `polkitd` is installed, but this pass did not use active polkit paths and `pkexec` is absent.

Relevant units:

```text
apport.service                 enabled, inactive, ConditionResult=no
apport-forward.socket          enabled, active, /run/apport.socket is 0600 root:root
apport-autoreport.path         enabled, inactive, ConditionResult=no
apport-autoreport.timer        enabled, inactive, ConditionResult=no
finalrd.service                enabled, active/exited, ExecStop=/usr/bin/finalrd
friendly-recovery.service      static, inactive, ConditionResult=no
cloud-init*.service            not-found
```

No `sos`, `overlayroot`, `growpart`, or `unminimize` root service/timer/socket was present.

## Writable state and hook checks

All relevant helper commands were regular root-owned `0755` files with no setuid/setgid bit and no file capability: `sos`, `sosreport`, `apport-cli`, `ubuntu-bug`, `apport-bug`, `root_info_wrapper`, `overlayroot-chroot`, `growpart`, `finalrd`, `update-initramfs`, `mkinitramfs`, `unminimize`, `recovery-menu`, and the `friendly-recovery` generator.

uid1001 could not write the root hook/config/state paths:

```text
/etc/sos/extras.d
/etc/sos/presets.d
/usr/share/apport/package-hooks
/usr/share/apport/general-hooks
/etc/apport
/etc/overlayroot.conf
/etc/overlayroot.local.conf
/etc/update-motd.d/97-overlayroot
/usr/share/initramfs-tools/hooks
/usr/share/initramfs-tools/scripts/init-bottom
/etc/initramfs-tools/hooks
/etc/initramfs-tools/conf.d
/usr/share/finalrd
/etc/finalrd
/run/finalrd
/lib/recovery-mode/options
/run/friendly_recovery.resume
/var/lib/dpkg/info/overlayroot.postinst
```

`/var/crash` is writable (`3777 root:root`), but the default autoreport path/timer/service are inactive because `/var/lib/apport/autoreport` is absent, and the active container apport socket is `0600 root:root`.

## Primitive results

`sos`/`sosreport`: the known cwd import behavior is reachable only as the caller. A fake `sos` module under the attacker cwd produced `SOS_IMPORT_EUID=1001`; `sos report --batch --dry-run` failed with `Component must be run with root privileges`. No default root hook invokes `sos` from attacker cwd.

`apport`/`ubuntu-bug`: a controlled `APPORT_DATA_DIR/root_info_wrapper` ran as uid1001, and `attach_root_command_outputs()` returned `uid=1001(attacker)`. Connecting to `/run/apport.socket` failed with `PermissionError`. `apport-cli` stayed in the user CLI path and did not produce a privileged transition.

`overlayroot`: `/etc/overlayroot.conf` defaults to disabled, `/etc/overlayroot.local.conf` is absent, and initramfs scripts are root-owned. Direct hostile `PATH` probes against `overlayroot-chroot` and `/etc/update-motd.d/97-overlayroot` only executed attacker markers as `uid=1001`.

`cloud-initramfs-*` and `growpart`: cloud-init services are absent. The copymods/dyn-netconf scripts are initramfs boot scripts, not live uid1001 triggers. A hostile `PATH` probe against `/usr/bin/growpart` executed only as `uid=1001`; there is no default root growpart consumer in this target.

`finalrd`: the enabled root boundary is `finalrd.service` `ExecStop=/usr/bin/finalrd`, which is shutdown-time only. Its hook directories are root-owned, `/etc/finalrd` and `/run/finalrd` are absent, and uid1001 cannot create them. uid1001 cannot set the system manager environment or stop `finalrd.service`. A direct hostile `PATH` probe against `/usr/bin/finalrd` executed only as `uid=1001`.

`friendly-recovery` and `unminimize`: recovery is boot/cmdline-gated and its option scripts are root-owned. uid1001 cannot start `friendly-recovery.service` or create `/run/friendly_recovery.resume`. `unminimize` is a normal root-owned CLI; direct attacker execution aborted at the prompt with no package changes and no privilege change.

## Cleanup and health

The probe removed `/tmp/support_overlay_helpers*`, `/home/attacker/support_overlay_helpers*`, `/var/crash/support_overlay_helpers*`, and any matching `/root/support_overlay_helpers*` marker. Final verification:

```text
ROOT_PROOF_ABSENT
root_marker_absent_after_cleanup=yes
systemctl is-system-running: running
systemctl --failed: 0 loaded units listed
```

Conclusion: this bounded pass did not find a default support/boot/overlay helper path where uid1001 controls root-consumed state, root hook code, systemd environment, a package hook, or a local socket/DBus trigger. No root proof was produced.
