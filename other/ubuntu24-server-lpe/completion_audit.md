# Completion audit: Ubuntu 24.04 Server default LPE hunt

Date: 2026-05-17

Status: not achieved. Validated LPE findings: 0 of 5 requested.

This audit maps the original goal to the artifacts currently present in this dedicated workspace. It is not a claim that Ubuntu Server has no local privilege escalation bugs; it is the current Docker-based stock Ubuntu 24.04 Server default-surface audit state. Every candidate tested so far remained below the root-proof bar.

## Current 2026-05-17 update

Validated LPEs remain `0/5`. Additional current-pass closures added since the original audit:

```text
negative/packagekit-local-file-semantics-20260517.md
negative/root-python-dbus-current-deep-20260517.md
negative/snapd-current-default-deep-20260517.md
negative/udisks-filesystem-mounted-uaf-20260517.md
negative/active-udisks-ext4-suid-20260517.md
```

The strongest current bug remains the UDisks mounted `Filesystem.Check`/`Repair` missing-goto/UAF path in `udisks2 2.10.1-6ubuntu1.3`: a default active local user can trigger root fixed-argv fsck execution against their mounted loop device and crash `udisksd`, but no root code execution or root state change has been validated. PackageKit local-file semantics, current snapd/snap-confine, root Python/D-Bus helpers, and UDisks ext4 setuid-image mounting all ended with `ROOT_PROOF=NO`.

## Target proof

Dedicated workspace:

```text
/Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe
```

Docker target:

```text
Image:     ubuntu24-server-default-lpe:20260516-standard
Container: ubuntu24-server-lpe-target
State:     systemd running
```

Target construction is recorded in `tools/Dockerfile.ubuntu-server-target`:

```dockerfile
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get -y full-upgrade \
    && apt-get install -y ubuntu-minimal ubuntu-standard ubuntu-server \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash attacker \
    && passwd -l attacker
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
```

Current target facts:

```text
Ubuntu:    Ubuntu 24.04.4 LTS (noble)
Kernel:    6.10.14-linuxkit aarch64
Attacker:  uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
Self-auth: uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
Upgrade:   0 upgraded, 0 newly installed, 0 to remove
System:    running, 0 failed units after cleanup
```

`selfauth` is a passworded non-sudo/non-admin user created only to model active local TTY/polkit/self-auth cases. Kernel-only issues were treated as out of scope for stock Ubuntu kernel proof because the Docker host kernel is LinuxKit.

Baseline evidence is under `baseline/live-target-standard/`:

```text
os-release.txt
packages.txt
systemctl-unit-files.txt
systemctl-active.txt
systemctl-sockets.txt
setuid-setgid.txt
capabilities.txt
dbus-system.txt
polkit-actions.txt
tmpfiles-cron-logrotate-systemd.txt
users-groups.txt
writable.txt
sysctls.txt
apt-manual.txt
```

## Surface Covered

Root/setuid/capability surfaces:

```text
setuid/setgid helpers, auth/account helpers, fusermount3, mount/umount,
ssh-keysign, polkit-agent-helper, dbus-daemon-launch-helper, gst-ptp-helper,
snap-confine, ping/mtr capabilities
```

D-Bus/polkit/systemd surfaces:

```text
systemd manager, logind, timedated, hostnamed, localed, resolved,
netplan-dbus, software-properties, systemd-networkd, PackageKit, UDisks2,
fwupd, bolt, snapd REST API, lxd-installer.socket, sysext/userdb/ManagedOOM
varlinks
```

Root timer/maintenance surfaces:

```text
apt-daily, apt-daily-upgrade, unattended-upgrades, needrestart hooks,
dpkg-db-backup, logrotate, tmpfiles-clean, man-db, sysstat, update-notifier,
motd-news, Ubuntu Pro/UA timers, cron/run-parts/mail-spool boundaries,
e2scrub/mdadm/xfs maintenance units
```

Filesystem/session/misc surfaces:

```text
world-writable directories and sockets, /var/crash, apport forwarding,
FUSE and mount helpers, Docker device/proc edge cases, PAM/MOTD/session
helpers, console/TTY/boot helpers, screen/byobu, udev/hotplug helper rules,
PackageKit active-session proxy/refresh/offline update, UDisks active-session
loop/mount/bcache/mdadm metadata, command-not-found caches, open-iscsi locks,
network/VM condition-gated daemons, systemd setup credential imports,
systemd getty/login credential imports,
cryptsetup/initramfs/recovery/finalrd helpers, ask-password wall forwarding,
systemd notify socket spoofing, systemd LogControl/varlink mutators,
remaining setuid/cap helpers, WWAN/modem
hotplug helpers, filesystem fsck/mount temp handling, support/reporting helpers,
trust-store/GnuPG helpers, network diagnostics tools, system/root cache builders,
man-db/groff cache builders, UDisks metadata-to-systemd/tmpfiles propagation, and
Python/update hook D-Bus activation helpers, kernel/initramfs hooks, network client
hooks, UDisks module loading, open-iscsi socket activation semantics, Apport
crash metadata parsing, Python/update hook discovery paths, and systemd initctl
legacy FIFO semantics, active-seat UDisks NTFS/ntfs3 mount option filtering,
and D-Bus Containers1 runtime exposure, plus maintainer-script metadata lanes for
AppArmor homedirs, netplan-generator runtime gates, base-passwd account reconcile,
and libc restart-list handling, PackageKit local-file root-only `.deb` parsing,
current snapd/snap-confine socket and namespace paths, root Python/D-Bus import
and activation environment boundaries, UDisks mounted-check/repair UAF
exploitability, and active-seat UDisks ext4 setuid-image mount behavior
```

## Candidate Inventory

Negative candidate notes: 200.

```text
negative/active-seat-packagekit-proxy-refresh.md
negative/active-seat-udisks-udev-bcache.md
negative/active-login1-power-session.md
negative/active-login1-session-devices.md
negative/active-polkit-remaining-methods.md
negative/active-systemd-transient.md
negative/active-tty-polkit-udisks-packagekit.md
negative/account-session-deep.md
negative/active-udisks-btrfs-udev.md
negative/active-udisks-e2scrub-timer.md
negative/active-udisks-label-uuid.md
negative/active-udisks-luks-unlock.md
negative/active-udisks-lvm-udev.md
negative/active-udisks-mdadm-assembly.md
negative/active-udisks-ntfs-options.md
negative/active-udisks-opath-fd.md
negative/active-udisks-partition-metadata.md
negative/active-udisks-takeownership.md
negative/active-udisks-xfs-scrub.md
negative/appstream-swcatalog.md
negative/apparmor-console-boot-helpers.md
negative/apport-autoreport-deep.md
negative/codex_apport_meta.md
negative/apport-coredump-second-pass.md
negative/apport-normal-user-coredump.md
negative/apport-var-crash-and-coredump.md
negative/apt-maintainer-timers.md
negative/apt-needrestart-deep.md
negative/apt-needrestart-unattended.md
negative/auth-setuid-edge-helpers.md
negative/bolt-dbus-default.md
negative/byobu-postinst-screen-chown.md
negative/capability-helpers.md
negative/command-not-found-apt-cache.md
negative/cloud-init-default.md
negative/condition-gated-network-vm-daemons.md
negative/console-tty-boot-helpers.md
negative/cron-crontab-deep.md
negative/cron-crontab.md
negative/cron-user-crontab-semantics.md
negative/cron-mail-spool-deep.md
negative/cryptsetup-initramfs-recovery.md
negative/current-active-polkit-map.md
negative/current-local-socket-timer-recheck.md
negative/current-root-python-dbus-services.md
negative/current-writable-lock-state.md
negative/dbus-polkit-default-apis.md
negative/dbus-polkit-residual.md
negative/dbus-activation-helper.md
negative/dbus-containers1-runtime.md
negative/dbus-debug-monitor.md
negative/default-runtime-socket.md
negative/default-writable-acls.md
negative/diagnostic-support-tools.md
negative/docker-device-proc-edges.md
negative/dpkg-db-backup.md
negative/file-acl-boundaries-second-pass.md
negative/filesystem-maintenance-helpers.md
negative/firewall-boot-helpers.md
negative/fsck-mount-tmp.md
negative/fs-maintenance-helpers.md
negative/fstrim-fuse-mounts.md
negative/fuse-tmpfiles-clean.md
negative/fwupd-local-archive.md
negative/fwupd-refresh-offline-deep.md
negative/gst-ptp-helper-capability.md
negative/hostname-localed-timedated-active-dbus.md
negative/hypervisor-agent-default.md
negative/journald-userdb-varlink.md
negative/journald-userdb-world-sockets.md
negative/kernel-default-sysctls-namespaces.md
negative/kernel-initramfs-hooks.md
negative/log-ingestion-rotation.md
negative/lxd-installer-default-socket.md
negative/man-db-cache-builders.md
negative/man-db-timer.md
negative/maintainer-metadata-lanes.md
negative/misc-default-daemons.md
negative/misc-cache-builders.md
negative/misc-privileged-helpers.md
negative/modemmanager-active-methods.md
negative/motd-news-cache-env.md
negative/motd-landscape-update-timers.md
negative/multipathd-local-ipc.md
negative/netplan-dbus-deep.md
negative/netplan-software-properties-dbus.md
negative/network-cloud-hooks-default.md
negative/network-client-hooks.md
negative/network-diagnostics-tools.md
negative/networkd-dispatcher.md
negative/open-iscsi-lockdir-root-file-create.md
negative/open-iscsi-ipc-semantics.md
negative/openssh-default-local-boundaries.md
negative/openssh-local-deep.md
negative/package-specific-helpers.md
negative/packagekit-active-proxy-injection.md
negative/packagekit-cve-2026-41651-regression.md
negative/packagekit-fwupd-udisks.md
negative/packagekit-local-deb-parser.md
negative/packagekit-sethints-env.md
negative/packagekit-sethints-running.md
negative/packagekit-transaction-deep2.md
negative/pam-motd-landscape-ruid.md
negative/pam-login-session-deep.md
negative/pam-login-env-race.md
negative/pam-namespace-user-runtime.md
negative/pam-secondary-modules.md
negative/pam-session-motd.md
negative/passworded-self-account-fields.md
negative/polkit-agent-helper-direct.md
negative/polkit-agent-subject-spoof.md
negative/polkit-allow-active-gap.md
negative/python-support-root-hooks-deep.md
negative/remaining-setuid-cap-helpers-deep.md
negative/residual-helper-parser.md
negative/root-daemon-sockets-deep.md
negative/root-script-import-path.md
negative/root-timers-tmpfiles-logrotate.md
negative/rsyslog-journald-logrotate.md
negative/rsyslog-journal-logrotate-deep.md
negative/rsyslog-logrotate-deep.md
negative/screen-byobu-utmp.md
negative/screen-postrm-remove.md
negative/release-upgrader-pkexec.md
negative/secureboot-snap-autoimport.md
negative/server-daemon-ipc-misc.md
negative/server-support-packages.md
negative/session-helper-boundaries.md
negative/setuid-account-helpers.md
negative/setuid-setgid-helpers.md
negative/snap-confine-direct-default.md
negative/snap-confine-fake-base-deep.md
negative/snapd-cve-2026-3888-regression.md
negative/snapd-boot-services.md
negative/snapd-rest-deep.md
negative/snapd-rest-api.md
negative/snapd-session-agent.md
negative/snapd-snap-confine.md
negative/software-properties-dbus.md
negative/storage-daemon-ipc.md
negative/storage-ipc-sockets.md
negative/systemd-generators-run-config.md
negative/systemd-logcontrol-varlink-gap.md
negative/system-cache-builders.md
negative/sudo-no-sudo-user.md
negative/support-overlay-helpers.md
negative/support-reporting-helpers.md
negative/sysstat-timers.md
negative/systemd-ask-password-wall.md
negative/systemd-boot-shutdown-units.md
negative/systemd-dbus-methods.md
negative/systemd-identity-session-dbus.md
negative/systemd-initctl-legacy.md
negative/systemd-notify-world-socket.md
negative/systemd-pcr-pstore.md
negative/systemd-resolved-ipc.md
negative/systemd-getty-credential-imports.md
negative/systemd-setup-credential-imports.md
negative/systemd-storage-quota-misc.md
negative/systemd-static-gated-units.md
negative/systemd-remount-fs.md
negative/systemd-sysext-varlink.md
negative/systemd-sysupdate-repart.md
negative/systemd-template-instance-boundaries.md
negative/systemd-udev-console.md
negative/systemd-update-boot-misc.md
negative/systemd-user-sessions.md
negative/timesync-resolved-runtime.md
negative/tmpfiles-public-dirs.md
negative/trust-store-gnupg.md
negative/undercovered-user-cli-packages.md
negative/ubuntu-drivers-oem-helper.md
negative/ubuntu-pro-advantage-surfaces.md
negative/ubuntu-pro-apt-news.md
negative/ubuntu-pro-client-default-timers.md
negative/udev-profile-boundaries.md
negative/udev-hotplug-helper-rules.md
negative/udisks2-libblockdev-deep.md
negative/udisks-enable-module-gap.md
negative/udisks-metadata-systemd.md
negative/unattended-upgrades-shutdown-deep.md
negative/update-notifier-package-data-downloader.md
negative/update-notifier-pkexec-package-system-locked.md
negative/user-session-package-helpers.md
negative/userns-netdev-udev-sysctl.md
negative/userns-root-world-sockets.md
negative/util-linux-shadow-setuid-deep.md
negative/uuidd-default-socket.md
negative/wwan-modem-helpers.md
```

Supporting evidence notes:

```text
notes/aptnr_20260516_evidence.md
notes/authhelpers_20260516_evidence.md
notes/devproc_20260516_evidence.md
notes/fuse_tmpfiles_probe.md
notes/mischelpers_20260516_evidence.md
notes/pkgfwudisks_20260516_evidence.md
notes/sessionhelpers_20260516_evidence.md
notes/snapd_20260516_evidence.md
notes/storageipc_20260516_evidence.md
```

Negative probe scripts:

```text
pocs/apparmor_console_probe.sh
pocs/account_session_deep_probe.sh
pocs/active_login1_devices_probe.sh
pocs/active_polkit_remaining_probe.sh
pocs/active_systemd_transient_probe.sh
pocs/active_udisks_btrfs_udev_probe.sh
pocs/active_udisks_e2scrub_probe.sh
pocs/active_udisks_label_uuid_probe.sh
pocs/active_udisks_luks_unlock_probe.sh
pocs/active_udisks_lvm_udev_probe.sh
pocs/active_udisks_mdadm_assembly_probe.sh
pocs/active_udisks_ntfs_options_probe.sh
pocs/active_udisks_opath_fd_probe.sh
pocs/active_udisks_partition_metadata_probe.sh
pocs/active_udisks_takeownership_probe.sh
pocs/active_udisks_xfs_scrub_probe.sh
pocs/appstream_swcatalog_probe.sh
pocs/apport_autoreport_deep_probe.sh
pocs/codex_apport_meta_probe.sh
pocs/apport_coredump_second_pass_probe.sh
pocs/authhelpers_probe.sh
pocs/byobu_postinst_screen_chown_probe.sh
pocs/capability_helpers_probe.sh
pocs/cloud_init_default_probe.sh
pocs/cron_user_crontab_semantics_probe.sh
pocs/cron_mail_spool_deep_probe.sh
pocs/devproc_probe.sh
pocs/dpkg_db_backup_probe.sh
pocs/dbus_activation_helper_probe.sh
pocs/dbus_containers1_probe.sh
pocs/dbus_debug_monitor_probe.sh
pocs/dbus_polkit_residual_probe.sh
pocs/default_runtime_socket_probe.sh
pocs/file_acl_probe.sh
pocs/firewall_boot_helpers_probe.sh
pocs/fsck_mount_tmp_probe.sh
pocs/fuse_tmpfiles_probe.sh
pocs/fwupd_local_archive_probe.sh
pocs/fwupd_refresh_offline_deep_probe.sh
pocs/host_locale_time_probe.sh
pocs/hypervisor_agent_default_probe.sh
pocs/kernel_initramfs_hooks_probe.sh
pocs/man_db_cache_probe.sh
pocs/maintainer_metadata_lanes_probe.sh
pocs/misc_cache_builders_probe.sh
pocs/mischelpers_probe.sh
pocs/modemmanager_active_methods_probe.sh
pocs/motd_news_cache_env_probe.sh
pocs/netplan_dbus_deep_probe.sh
pocs/network_cloud_hooks_probe.sh
pocs/network_client_hooks_probe.sh
pocs/network_diagnostics_tools_probe.sh
pocs/networkd_dispatcher_probe.sh
pocs/openssh_local_probe.sh
pocs/open_iscsi_ipc_semantics_probe.sh
pocs/openssh_local_deep_probe.sh
pocs/package_specific_helpers_probe.sh
pocs/packagekit_active_proxy_injection_probe.sh
pocs/packagekit_cve41651_regression_probe.sh
pocs/packagekit_local_deb_parser_probe.sh
pocs/packagekit_sethints_env_probe.sh
pocs/packagekit_sethints_running_probe.sh
pocs/packagekit_transaction_deep2_probe.sh
pocs/pam_motd_landscape_ruid_probe.sh
pocs/pam_login_env_race_probe.sh
pocs/pam_namespace_user_runtime_probe.sh
pocs/pam_secondary_modules_probe.sh
pocs/pkgfwudisks_probe.sh
pocs/polkit_allow_active_gap_probe.sh
pocs/polkit_agent_helper_direct_probe.sh
pocs/polkit_agent_subject_spoof_probe.sh
pocs/residual_helper_parser_probe.sh
pocs/rsyslog_journald_logrotate_probe.sh
pocs/rsyslog_journal_logrotate_deep_probe.sh
pocs/root_script_import_path_probe.sh
pocs/release_upgrader_pkexec_probe.sh
pocs/screen_byobu_utmp_probe.sh
pocs/screen_postrm_remove_probe.sh
pocs/sessionhelpers_probe.sh
pocs/snap_confine_fake_base_deep_probe.sh
pocs/snapd_boot_services_probe.sh
pocs/snapd_cve3888_regression_probe.sh
pocs/snapd_rest_deep_probe.sh
pocs/snapd_session_agent_probe.sh
pocs/software_properties_dbus_probe.sh
pocs/sudo_no_sudo_user_probe.sh
pocs/support_overlay_helpers_probe.sh
pocs/support_reporting_helpers_probe.sh
pocs/system_cache_builders_probe.sh
pocs/systemd_getty_credential_imports_probe.sh
pocs/systemd_generators_run_config_probe.sh
pocs/systemd_initctl_legacy_probe.sh
pocs/systemd_logcontrol_varlink_gap_probe.sh
pocs/systemd_pcr_pstore_probe.sh
pocs/systemd_storage_quota_misc_probe.sh
pocs/systemd_static_gated_units_probe.sh
pocs/systemd_remount_fs_probe.sh
pocs/systemd_sysupdate_repart_probe.sh
pocs/systemd_template_probe.sh
pocs/systemd_udev_console_probe.sh
pocs/systemd_user_sessions_probe.sh
pocs/timesync_resolved_runtime_probe.sh
pocs/tmpfiles_public_dirs_probe.sh
pocs/trust_store_gnupg_probe.sh
pocs/undercovered_user_cli_packages_probe.sh
pocs/ubuntu_drivers_oem_helper_probe.sh
pocs/ubuntu_pro_apt_news_probe.sh
pocs/udev_profile_boundary_probe.sh
pocs/udisks_enable_module_gap_probe.sh
pocs/udisks_metadata_systemd_probe.sh
pocs/userns_netdev_udev_sysctl_probe.sh
pocs/userns_socket_probe.sh
pocs/uuidd_probe.sh
pocs/wwan_modem_helpers_probe.sh
```

These are reproducible negative probes, not exploit PoCs. No `notes/<finding>.md` or `pocs/<finding>.sh` with root proof exists because no candidate reached validated LPE.

## Notable Non-Findings

High-signal primitives that did not meet the bar:

```text
Package-specific helper boundaries: libpam-cap, init-system-helpers, sg3/hdparm
udev helpers, thin/busybox/klibc initramfs hooks, libselinux tmpfiles, and adduser
are default-installed root-adjacent surfaces. They stayed below LPE because their
configs/rules/state/hooks are root-owned, uid1001 cannot trigger the relevant root
package/udev/initramfs paths, and direct helper execution or attacker
DPKG_ROOT/DESTDIR values affected only uid1001-owned scratch state.

systemd-remount-fs namespace/input boundary: `systemd-remount-fs.service` is
default-enabled at runtime and executes `/usr/lib/systemd/systemd-remount-fs` as
root, but uid1001 cannot write `/etc/fstab`, generator output, runtime unit
directories, or mountinfo. An attacker-created user/mount namespace tmpfs mount
remained private and did not appear in PID 1's namespace, while direct service
start and D-Bus `StartUnit` attempts were authorization-gated.

screen postrm remove boundary: `/run/screen` is default `1777 root:utmp` and
uid1001 can populate it, while `/var/lib/dpkg/info/screen.postrm` does
`rm -rf /run/screen` as root during package remove/purge. A disposable clone
proved attacker symlinks to `/root` were deleted as links, not followed, root
decoys survived, and the root package-removal trigger is not available to a
normal non-sudo user.

Byobu postinst screen chown: `/run/screen` is default `1777 root:utmp`, and
`/var/lib/dpkg/info/byobu.postinst` uses `chown --reference $(dirname "$1")`
over `/run/screen/S-*` names. A disposable clone proved a uid1001-planted
`S-byoburef etc` directory makes root `byobu.postinst configure` chown `/etc`
to `attacker:attacker`, after which uid1001 can replace account files and get
`uid=0(root)`. This is not counted because the live target is fully upgraded,
`apt-get -s upgrade` reports `0 upgraded`, and uid1001 cannot run
`dpkg --configure`, `dpkg-reconfigure`, or start `apt-daily-upgrade.service`.

Under-covered user CLI packages: `pastebinit`, `run-one`, `xdg-user-dirs`,
`overlayroot`, `unminimize`, and `sosreport` are installed, but no matching
root service, timer, socket, D-Bus service, polkit action, setuid/cap helper,
or default root consumer was present. Direct uid1001 execution stayed
unprivileged; `run-one` used caller-owned lock state, `xdg-user-dirs` wrote
attacker-owned user config, `overlayroot` was disabled/no overlay filesystem,
`unminimize` did not perform package changes as uid1001, and `sos report`
refused non-root execution.

PackageKit active-session proxy/refresh/offline-update: selfauth on active tty1 can
set proxy strings and route root APT metadata fetches through attacker-controlled
proxy state, but no root command execution, package install, source modification,
or arbitrary root file write was reached.

PackageKit active-session proxy/config injection: active selfauth can set newline-bearing
proxy strings that root PackageKit/APT uses for repository refreshes. The injected
`APT_CONFIG`/`Acquire::*` strings stayed inside single proxy environment values, fake
proxy responses were rejected as unsigned metadata, frontend sockets were not contacted,
and real update/install paths stayed auth-blocked. Clearing proxy state left stale
credentialed proxy use, but only as privacy/DoS hardening impact.

PackageKit SetHints environment splitting: active selfauth can pass newline-bearing
`locale`, `cache-age`, and unknown hint values into root PackageKit/APT refresh state.
Raw NUL-separated environment capture showed apparent `APT_CONFIG` and `PYTHONPATH`
lines were embedded inside single `LANG`/`LANGUAGE` entries, not separate variables.
The malicious APT pre-invoke config and Python `sitecustomize.py` never executed as
root.

PackageKit transaction deep2: active selfauth could reach root APT refresh, transaction
cancel/reuse, local `.deb` metadata parsing, `/proc/self/fd` local-file probes, and
frontend socket validation. Install/update/source mutators stayed admin-gated, simulated
transactions did not run maintainer scripts, fake proxy metadata was rejected, and no
root package install or root marker was produced.

PackageKit CVE-2026-41651 regression: the default D-Bus service is reachable and
uid1001 can create transactions, but `packagekit 1.2.8-2ubuntu1.5` rejects the
same-transaction `InstallFiles(flags=8)` then `InstallFiles(flags=0)` pattern with
`org.freedesktop.PackageKit.Transaction.InvalidState`; the malicious local package
postinst never ran as root and the marker package was not installed.

login1 active-seat power/session methods: selfauth on active tty1 can satisfy polkit
for reboot/power and future ScheduleShutdown/CancelScheduledShutdown, but reboot-target
setters reject the container/bootloader state, direct WallMessage mutation remains
admin-gated, and the accepted schedule state did not create root-controlled content
or execution.

login1 active-session device methods: selfauth on active tty1 can take session control,
change some own-session hints, and use TIOCSTI on its own tty, but TakeDevice did not
hand out other console/input devices, direct device opens stayed denied, and there was
no root consumer on that tty.

uuidd world socket: `/run/uuidd/request` is `0666` and any local user can trigger
UUID generation through socket activation, but the daemon runs as `uuidd:uuidd`,
has only `/var/lib/libuuid` writable, and exposed no root write or privileged
group transition.

passworded self-service account fields: selfauth can change restricted room/work/home
GECOS fields, valid shells from `/etc/shells`, and its own password after authentication,
but default root consumers treat those values as data and do not execute them.

AppArmor/console boot helpers: AppArmor policy/cache paths, systemd setup override
directories, and console/Plymouth inputs are root-owned or absent; direct helper
execution stays unprivileged and default unit starts require authorization.

OpenSSH default local boundaries: openssh-client and local helpers are default, but
openssh-server/sshd/unit/socket/host keys are absent in this Server image; ssh-keysign
is disabled by global config, ssh-agent runs as the caller, and utempter only mutates
structured utmp/wtmp accounting.

OpenSSH deep client/helper pass: `openssh-client 1:9.6p1-3ubuntu13.16` is default, but
`openssh-server`, `sshd`, server PAM/config/host keys, and `sftp-server` are absent.
`ssh-keysign` stayed globally disabled, `ssh-agent` dropped setgid `_ssh` privileges,
PKCS11/SK helpers, ControlPath, ProxyCommand, scp/sftp helper paths, and utempter
adjacency all remained uid1001-only or default-gated.

hostname/localed/timedated active D-Bus: root-owned config-write methods exist, but
changed values from attacker and selfauth are admin-authenticated, no-op current-state
calls do not alter hashes, and newline/path traversal payloads are rejected by validators.

user-namespace root against world sockets: attacker can become uid 0 inside a user
namespace and connect to snapd/D-Bus sockets, but snapd root/admin endpoints and
login1 authorization still treat the peer as host uid1001, not initial-namespace root.

UDisks active-session loop/mount: selfauth on active tty1 can loop-setup and mount
attacker ext4 images, but mounts are nosuid/nodev and suid/dev/defaults options are
blocked. bcache/mdadm/label paths encoded or truncated hostile metadata.

UDisks filesystem metadata into systemd/tmpfiles: active selfauth can mount attacker
ext4/vfat/xfs loop images with hostile labels, UUIDs, backing filenames, root-owned
setuid metadata, and mounted unit/tmpfiles payloads. UDisks enforced `nosuid,nodev`,
rejected `suid`, `dev`, and vfat `uid=0`, encoded metadata into udev symlinks, and
systemd/tmpfiles did not consume files from `/media/selfauth`.

UDisks NTFS/ntfs3 mount options: active selfauth can create and mount an attacker
NTFS loop image. The default path selected `ntfs3` and mounted as
`rw,nosuid,nodev,uid=1002,gid=1002`; `uid=0`, `suid`, `dev`, `permissions`,
`allow_other`, comma-style option injection, and direct D-Bus `Mount` bypass attempts
were rejected. `Check` and `Repair` returned success without a root marker.

UDisks btrfs/udev metadata: active selfauth can loop-setup attacker-owned btrfs
images and root udev imports `ID_FS_LABEL`, `ID_FS_LABEL_ENC`, and `ID_BTRFS_READY`
through default `64-btrfs.rules`. Hostile labels remained encoded `/dev/disk`
symlink data, did not become `SYSTEMD_WANTS`, and the fixed root `udevadm trigger`
rule did not execute attacker-controlled units or commands.

UDisks raw file-descriptor LoopSetup: active selfauth can call the raw D-Bus
`LoopSetup(h fd, ...)` method, not just `udisksctl -f`. `O_PATH` descriptors to
`/etc/shadow`, `/etc/sudoers`, debconf secrets, and `/etc/passwd` opened locally but
were rejected by kernel loop association as bad file descriptors. A normal readable
`/etc/passwd` fd could become a loop, but raw `OpenDevice` and mount stayed denied
or unavailable and did not create a privilege boundary crossing. Deleting that loop
triggered a transient `udisksd` SIGSEGV in Docker, recorded only as DoS/crash.

UDisks partition metadata setters: active selfauth can create a GPT loop disk and
reach `Partition.SetName`, `SetType`, `SetUUID`, and `SetFlags` on the transient
partition object. Valid GUID/UUID/flag values were accepted, traversal-looking
names were accepted as data, invalid type/UUID payloads were rejected, and overlong
shell/newline names hit GPT length checks. The Docker target exposed `/sys/class/block/loop0p1`
but no `/dev/loop0p1` node, no attacker by-partlabel/by-partuuid symlink, no
`SYSTEMD_WANTS` property, and no root marker.

UDisks EnableModule/EnableModules: a plain non-sudo uid1001 caller can invoke the
module-loading methods without an active session and without polkit, but accepted module
names resolve only under `/usr/lib/aarch64-linux-gnu/udisks2/modules/`, traversal and
malformed names are rejected, the default Server image has no module directory, D-Bus
signature checks reject options-dict injection, and attacker-controlled module/library
environment did not influence the root daemon.

needrestart process metadata: stale attacker processes can influence root
needrestart's service-name restart list, e.g. `NEEDRESTART-SVC: cron`, during a
later root needrestart run. This remained restart/DoS influence, not root code
execution or root file write.

open-iscsi lock directory: attacker can pre-own `/run/lock/iscsi`, and a later root
`iscsiadm` follows `/run/lock/iscsi/lock` as a symlink to create an empty root-owned
file. Default Server has no non-sudo path that runs root `iscsiadm`, and the primitive
did not provide content control or execution.

open-iscsi socket activation/database semantics: uid1001 can hit the enabled abstract
`@ISCSIADM_ABSTRACT_NAMESPACE` socket and activate root `iscsid`, but in this Docker
target the daemon exits on missing `NETLINK_ISCSI`; uid1001 cannot create
`/etc/iscsi/nodes`, `/etc/iscsi/send_targets`, or satisfy `open-iscsi.service` conditions
for root `iscsiadm --loginall=automatic`.

update-notifier pkexec action: policy allows `package-system-locked` for active/inactive
users, but `pkexec` is not installed by default on this target and no root service invokes
that helper.

systemd notify socket: `/run/systemd/notify` is world-writable, and uid1001 can send
ready/status/fdstore messages that return success, but PID1 did not attribute spoofed
messages to root services and journald's FD store count did not change.

systemd ask-password wall: the root watcher is active by default, but
`/run/systemd/ask-password` is `0755 root:root`; uid1001 cannot create request files
or use `systemd-ask-password` to inject one.

systemd user-sessions nologin helper: `systemd-user-sessions.service` is active-exited
by default and root `ExecStop` creates a fixed `/run/nologin` file while `ExecStart`
removes it. uid1001 cannot create, replace, symlink, or remove `/run/nologin`, cannot
restart/stop the root unit without admin authorization, and direct helper execution
runs without privilege. The PAM `nologin` consumer treats the file as policy data, not
code.

systemd static/gated root units: rfkill, sleep/hibernate, Plymouth shutdown splash,
rescue/emergency shell, and volatile-root initrd units are stock-installed root
execution surfaces, but they are inactive/static and require missing rfkill/sleep/initrd
state, non-container splash boot conditions, privileged target isolation, or systemd/
logind authorization. Direct uid1001 unit starts returned "Interactive authentication
required"; the units stayed inactive and no root marker/context was reached.

udev/profile boundary pass: default MTD and IBM `ibmveth` udev rules are root hotplug
boundaries, and `/etc/profile.d/01-locale-fix.sh` uses `eval` while `gawk.sh` defines
functions with unqualified `gawk`. The required MTD/VIO hardware was absent, uid1001
could not write sysfs uevents or `/run/udev`, the ibmveth shell fragment did not
re-evaluate metacharacters from `DEVPATH`, `locale-check` emitted quoted replacement
assignments for hostile locale values, and attacker `PATH` hijacking of `gawk` executed
only as uid1001.

systemd initctl legacy FIFO: `systemd-initctl.socket` and `systemd-initctl.service`
exist by default, but `/run/initctl` and `/dev/initctl` are `0600 root:root`.
uid1001 cannot write binary initctl requests, use `telinit` to signal PID1, reload
the manager, or isolate targets without polkit.

systemd udev/console units: `systemd-udev-trigger.service` root-runs default coldplug
but uid1001 cannot start it or write sysfs uevent nodes, and `/run/udev/control` is
root-only. `console-getty.service` is enabled-runtime but condition-gated in the
Docker Server target because `/dev/console` is absent; `/run/credentials` and tty
devices are not attacker-writable, so `ImportCredential=login.*` was not seedable.

systemd LogControl/varlink gap: `org.freedesktop.LogControl1` read access exists on
systemd/logind/resolved, and world-writable varlink sockets exist for ManagedOOM,
DynamicUser, and resolved. LogLevel/LogTarget writes and malformed path/control payloads
were denied or rejected, ManagedOOM/DynamicUser calls did not expose a root mutator, and
no root write/exec/state transition occurred.

current local socket/timer recheck: `lxd-installer.socket` is enabled but
`root:lxd` `0660`, and the default attacker is not in `lxd`. `systemd-sysext`,
`dm-event`, `lvmpolld`, `initctl`, and ask-password root parser surfaces were blocked
by `0600` sockets/FIFOs or a non-writable root-owned request directory. `sysstat` and
`update-notifier` root timers had only root-owned inputs.

current active polkit map: a corrected `docker exec -i` XML sweep shows active-user
`yes` actions on UDisks2, ModemManager, fwupd trusted updates, logind session/self
operations, PackageKit refresh/proxy/offline helpers, and update-notifier
`package-system-locked`. These are real semantic surfaces, but current probes still
stop at condition-gated daemons, missing object-creation paths, own-user-only state,
admin-gated downstream operations, or root-owned trigger files.

D-Bus Debug.Stats/Monitoring: the stock system bus exposes these interfaces and root can
use `Debug.Stats`, but default `/usr/share/dbus-1/system.conf` denies uid1001
`Debug.Stats` calls and non-root `Monitoring.BecomeMonitor`. Explicit eavesdrop
method-call monitoring was rejected, broadcast signal visibility did not leak a root
transition, and no root marker appeared.

Default runtime sockets: `/run/uuidd/request` is world-reachable, but socket activation
runs `uuidd` as `uuidd:uuidd` and only updates `/var/lib/libuuid/clock.txt`.
`dmeventd`, `lvmpolld`, `apport-forward`, and `systemd-udevd` runtime IPC endpoints are
default-present but protected by `0600` sockets/FIFOs or root-only parents, so uid1001
could not reach their privileged parser/control surfaces or create a root marker.

UDisks2/libblockdev deep active-seat pass: an active non-admin TTY user can drive loop,
mount, format, repair, resize, LUKS, and GPT helpers on self-created images. The effects
stayed inside `nosuid,nodev` mounts or admin-gated paths; one `udisksd` SIGSEGV did not
produce a root file write or execution primitive.

UDisks/e2scrub timer boundary: an active non-admin TTY user can create UDisks-backed ext4
loop devices, but default `e2scrub_all.service` exits in service mode because periodic
scrubbing is disabled, and forced non-service scans only LVM metadata rather than raw
attacker loop devices.

UDisks label/UUID helpers: an active non-admin TTY user can call `SetLabel` and a valid
`SetUUID` on a self-created ext4 loop device. Hostile labels containing traversal,
shell syntax, environment-looking strings, and leading-dash content were stored as data
and escaped in `/dev/disk/by-label`; invalid UUID strings were rejected before helper
execution. No root marker or unit transition occurred.

UDisks/LVM udev activation: an active non-admin TTY user can map attacker-supplied LVM
PV images and cause root udev to run transient `lvm-activate-*` systemd jobs from
`69-lvm.rules`, but accepted VG names are limited to `a-zA-Z0-9.-_+` and the root
command stayed fixed as `/usr/sbin/lvm vgchange -aay --autoactivation event <vg>`.

UDisks/mdadm assembly: an active non-admin TTY user can map mdadm member images and
root udev imports attacker-supplied array metadata, but the Docker target lacks MD
kernel support, mdadm failed before `/dev/md*` creation, newline metadata was truncated,
and no systemd wants or root marker appeared.

UDisks TakeOwnership: an active non-admin TTY user can create and mount an
attacker-controlled ext4 loop image containing a setuid-looking payload and symlinks
to `/root` and `/run`, but `Filesystem.TakeOwnership` is separately
`auth_admin_keep` and returned `NotAuthorizedCanObtain`. The mount stayed
`nosuid,nodev`, the payload ran only as `selfauth`, and no root marker appeared.

UDisks/xfs scrub: an active non-admin TTY user can mount crafted XFS images through
UDisks, and `xfs_scrub_all` can see those mountpoints, but the packaged scrub helper
failed before useful work in this target, direct `xfs_scrub@` instances ran as
`User=nobody`, and attacker labels/paths stayed single escaped arguments.

man-db/groff cache builders: attacker-controlled roff unsafe-mode payloads, `MANPATH`,
`MANROFFOPT`, `PAGER`, `LESSOPEN`, per-user manpath config, and cache symlinks produced
only uid1001 execution in direct `mandb`/`catman`/`groff` runs. The default
`man-db.timer` path runs `mandb --quiet` as `User=man` with protected home/system
settings, and root service/cron/tmpfiles triggers produced no root marker.

Remaining active-polkit methods: the remaining `allow_active=yes` actions were either
non-root-service account/device-condition paths, `pkexec` helpers absent from the
default Server install, or admin-gated mutators for hostnamed/localed/timedated/systemd/
resolved/networkd/software-properties/bolt. The captured root marker stayed absent.

Polkit allow_active gap pass: no `auth_self` defaults were present, and the remaining
live `allow_active=yes` surface stayed within login1, PackageKit, UDisks2, fwupd,
ModemManager, and stale update-notifier pkexec policy. Focused UDisks actions such as
rescan, eject, power-off-drive, modify-device, SMART update, and cancel-job were active
authorized for selfauth where applicable, but raw block fds and persistent device config
writes stayed denied and no root marker/config appeared.

Residual D-Bus/polkit state-changing APIs: a final bounded pass re-proved package,
service, bus activation, and polkit action reachability for hostname1/timedate1/
locale1/logind/systemd1/networkd/resolved/PackageKit/UDisks/Ubuntu-specific
services and Accounts-like absence. Normal uid1001 could only use logind fixed-path
self-linger/inhibitors; active tty selfauth could satisfy `active=yes` for PackageKit,
UDisks, login1, update-notifier, fwupd, and ModemManager actions, but effects stayed
fixed-path, condition-gated, admin-gated, or data-only. `/root/dbus_polkit_residual_root`
stayed absent and root-owned state hashes matched.

D-Bus Containers1 runtime socket factory: default config creates `/run/dbus/containers`
as `messagebus:root 0755` and system bus policy allows sends to
`org.freedesktop.DBus.Containers1`, but this `dbus-daemon` runtime does not advertise
or implement the interface. uid1001 cannot write the directory directly, and guessed
`AddServer`/`StopListening` calls return "does not understand message".

netplan D-Bus deep pass: `io.netplan.Netplan` is an active root service on the system
bus, but uid1001 and uid1002 hit `Access denied` on `Info`, `Generate`, `Apply`,
`Config`, and config-object methods. Root-created temp trees under `/run/netplan` were
`0700 root:root`, origin/path traversal and symlink tests stayed inside the temp tree,
and state digests matched before/after cleanup.

software-properties D-Bus: `com.ubuntu.SoftwareProperties` is root-run and activatable,
but source/key/config mutators all hit `com.ubuntu.softwareproperties.applychanges`
with `auth_admin`/`auth_admin_keep` before attacker-controlled source lines, key paths,
or helper execution are processed. Direct helper/module execution stayed uid1001 or
failed D-Bus ownership policy.

firewall/network boot helpers: UFW, nftables, iptables, sysctl, and modules-load helpers
are default-installed in relevant parts, and `ufw.service` is enabled active-exited, but
stock UFW has `ENABLED=no`, nftables is disabled, netfilter-persistent is absent, config
and import paths are root-owned, and uid1001 systemd start/reload attempts require auth.

Apport/coredump second pass: `/var/crash` is sticky world-writable and root apport
paths exist, but default `kernel.core_pattern=core` keeps normal crashes local,
`/run/apport.socket` is `0600 root:root`, autoreport is gated by absent root-owned
`/var/lib/apport/autoreport`, whoopsie is absent, and symlink/FIFO report races did
not create root targets.

Apport autoreport deep pass: uid1001 can stage `.crash`, `.upload`, `.uploaded`,
symlink, FIFO, and locked-report state under `/var/crash`, but the enabled path and
timer stay inactive because root-owned `/var/lib/apport/autoreport` is absent, direct
starts require admin authentication, and `whoopsie.path` is not installed/enabled.
Direct user processing stayed uid1001: `.upload` symlinks to `/tmp` created only
attacker-owned files, `.upload` symlinks to `/root` failed with `PermissionError`,
report symlinks hit `O_NOFOLLOW`, FIFO behavior was a hang only, and no root target
was created.

systemd template and instance boundaries: unprivileged users can create user units and
request self linger, but system template instances, udev/storage instance names, and
socket-activated root units remained root/kernel/admin controlled.

active systemd transient units: an active non-admin TTY user can send PID1 manager
mutators over the system bus, but `systemd-run --system`, direct `StartTransientUnit`
with attacker `ExecStart`/`Environment`/`WorkingDirectory`/`RootImage`/`User`,
unit-file linking/enabling, reload/reexec/isolate, and root manager environment
mutation all hit polkit or D-Bus policy. No transient root unit, unit-file write,
manager environment change, or root marker occurred.

Remaining setuid/cap helpers: FUSE, D-Bus launch helper, ssh-keysign, utempter,
ssh-agent, sudo, ping, and mtr-packet were reachable but did not cross into root
execution or attacker-controlled root writes.

Residual helper parser pass: `mtr-packet`, `gst-ptp-helper`, `ssh-agent`, `utempter`,
`fusermount3`, `mount`, and `umount` were source-reviewed and exercised for parser,
fd, namespace, helper-exec, symlink, and race edges. `mtr-packet` retained only bounded
`cap_net_raw`, `gst-ptp-helper` dropped capabilities before stdin protocol handling,
`ssh-agent` dropped effective `_ssh`, utempter wrote only structured accounting,
FUSE mounts were `nosuid,nodev` and `allow_other` was denied, and namespace/mount helper
attempts stayed uid1001 or private-userns only.

Default capability helpers: snap-confine, gst-ptp-helper, ping, and mtr-packet are
default file-capability boundaries. snapd REST mutators are auth-gated and direct
snap-confine stops before payload execution because stock Server has no base snaps;
gst-ptp-helper drops caps before stdin protocol handling; ping drops caps after setup;
mtr-packet retains only `cap_net_raw` for bounded probe commands.

snap-confine fake-base deep pass: host-namespace direct execution reaches the file-cap
boundary but cannot redirect `/snap` or locate a default base snap from attacker env/fake
state. User/mount/pid namespace fake-base attempts advanced parsing but privileges were
namespace-scoped and root-owned snapd runtime locks/state blocked payload execution.

snapd CVE-2026-3888 regression: stock Server has snapd sockets and `snap-confine`, but
no installed snaps/base snap, REST install paths require authorization, direct
`snap-confine` stops at `cannot locate base snap core`, and the updated tmpfiles policy
preserves snap private tmp paths.

snapd REST deep pass: `/run/snapd.socket` and `/run/snapd-snap.socket` are `0666`
and read-only REST routes are reachable by uid1001, but install/try, local snap
upload, assertions, configuration, snapshots/import, systems/recovery, interfaces,
create-user, and snapctl routes all hit login/polkit or snap-peer gates. The crafted
snap install hook and snapshot traversal payloads never wrote a root marker, and no
snap was installed.

snapd boot/helper services: enabled/static snapd units for core-fixup, recovery chooser,
snap-repair, apparmor, failure, autoimport, system-shutdown, and seeded were root-owned
but either condition-skipped on this classic Docker Server target or consumed only
root-owned snapd state. uid1001 could not preseed environment/seed/cache/auto-import
paths, could not start units, and root-start/race validation produced no root marker.

sudo no-sudo-user pre-auth: `sudo 1.9.15p5-3ubuntu5.24.04.2` is setuid root, but an
attacker outside sudo/admin groups stayed at password-required or sudoers-denied paths.
Hostile askpass/editor/PATH/chroot/locale/NSS probes did not create root markers.

support/overlay helpers: sosreport, apport CLI, overlayroot, growpart, finalrd,
friendly-recovery, unminimize, and initramfs support helpers are default-installed
or present through Server dependencies, but their root consumers are condition-gated,
root-owned, shutdown/boot-only, or direct execution stays uid1001.

cloud-init/default boot hooks: `cloud-init` and its systemd generator/units are absent
from this stock Docker Server target; `cloud-guest-utils` provides `growpart`, and
cloud-initramfs copy/dyn-netconf hooks are present, but all seed/state/initramfs paths
are root-owned or absent. Direct `growpart` helper/PATH influence ran as uid1001 only.

rsyslog/journald/logrotate ingestion: uid1001 can inject messages through `/dev/log`
and journald sockets, but control bytes/newlines are escaped, journald preserves peer
identity as `_UID=1001`, `/var/log` and `/run/log` remain unwritable, and default
logrotate scripts operate on fixed root-owned paths.

rsyslog/journald/logrotate second pass: raw `/run/systemd/journal/stdout`,
`logger --journald` structured fields, direct imuxsock datagrams, emerg
`:omusrmsg:*`, rsyslog dynamic-action/template grep, and logrotate
state/lock/create/copytruncate/script/mail semantics were rechecked. uid1001 could
spoof log text and accepted data fields, but `_UID/_PID/_SYSTEMD_UNIT` stayed
credential-derived, no dynamic rsyslog file/action sink existed, no logrotate mail
hook was configured, and config/state/log preconditions stayed unwritable.

screen/byobu/tmux/libutempter accounting: screen and tmux reach the setgid `utmp`
helper and can create utmp/wtmp records for real ptys, but newline/control host bytes
are rejected, path-like values stay in `ut_host`, weird screen names are rejected,
`write`/`wall` are not setgid tty, and accounting files were restored after testing.

PackageKit local `.deb` parser: uid1001 can call `GetDetailsLocal` and `GetFilesLocal`
on attacker-owned package files, and `GetFilesLocal` reports normalized `/root/...`
paths from hostile tar entries. The parser did not write those paths, `InstallFiles`
without simulation remained polkit-blocked, and simulated install did not run maintainer
scripts or commit a package.

PackageKit SetHints on running transactions: uid1001 can still call `SetHints` with
`frontend-socket` after an unauthenticated `SIMULATE` or `ONLY_DOWNLOAD` transaction
starts, but those paths do not fork dpkg or maintainer scripts. A real local `.deb`
install remains polkit-blocked, and the patched transaction guard blocks a second
`InstallFiles(flags=0)` call on the same transaction.

PAM secondary modules: default PAM reaches `pam_cap` and `pam_keyinit` through `su`/
account helpers and `pam_loginuid` through cron, but policy files are root-owned,
`pam_namespace` is not enabled, `pam_time` is commented, and tested sessions ended as
the target user with no effective/permitted/ambient capabilities or root writes.

PAM login environment/race pass: passworded `login -p selfauth`, setuid `su -p`,
hostile `PATH`/`PYTHONPATH`/shell env, `~/.pam_environment`, `.bash_profile`, runtime
symlinks under `/run/user/1002`, tty ownership, utmp/wtmp/lastlog, and self-linger
paths were exercised. PAM/systemd reset runtime variables, login shells ran as uid1002,
root MOTD/helper contexts did not import hostile hooks, runtime symlink replacement only
caused user-manager denial, and no root marker appeared.

PAM MOTD Landscape real/effective UID check: a real `/bin/login -f selfauth`
session triggered root `pam_motd` and `/etc/update-motd.d/50-landscape-sysinfo`.
Even though `landscape-sysinfo` has `os.getuid()`-based user-config logic and dynamic
plugin imports, the PAM-time run ignored `~/.landscape/sysinfo.conf`, created only the
default root-owned `/var/lib/landscape/landscape-sysinfo.cache`, created no user
sysinfo log, and produced no root marker.

Account/session/group-file deep pass: setuid `sg`, `newgrp`, `gpasswd`, `passwd`,
`chfn`, `chsh`, setgid `chage`/`expiry`, PAM login modules, faillog/faillock paths, and
`/etc/subuid`/`/etc/subgid` were reachable where installed. The helpers dropped to
uid1001 for own-group commands, privileged group transitions required locked group
passwords, account lock/temp paths were not user-writable, `newuidmap/newgidmap` were
absent, and user-namespace uid0 could not write initial-namespace root paths.

PAM namespace/user runtime: `pam_namespace.service`, `pam_namespace_helper`, logind
self-linger, `user-runtime-dir@.service`, and `user@.service` are default local
boundaries. uid1001 can enable linger for its own account, causing a root-owned
`/var/lib/systemd/linger/attacker` file, but cannot target root or path traversal; the
resulting user manager and transient user units run as uid1001 and cannot write root
state.

systemd-tmpfiles public directory rules: default tmpfiles rules clean/create `/tmp`
X11 locks, snap private tmp, systemd-private tmp trees, `/run/shm`, `/run/screen`, and
log path modes. Attacker symlinks/hardlinks/races in sticky or world-writable dirs
were unlinked or skipped without following into root decoys, and root-owned `/etc`,
`/var/log`, `/run/log`, and systemd metadata paths were not attacker-writable.

timesync/resolved runtime APIs: `systemd-resolved` is active and the public varlink and
`resolve1` read/query APIs are reachable. DNS/link mutators and fixed root unit starts
are polkit/admin-gated, the public varlink interface is query-only, the monitor socket
is service-owner-only, and `systemd-timesyncd` is container-condition-gated in this
Docker target.

fwupd local archive/CAB parser: the fwupd D-Bus service and active-user update policies
are installed by default, but the stock unit is skipped in this Docker target by
`ConditionVirtualization=!container`. Both attacker and active selfauth archive entrypoints
failed before daemon-side root parsing.

fwupd refresh/offline/local-file deep pass: `pocs/fwupd_refresh_offline_deep_probe.sh`
and `logs/fwupd-refresh-offline-deep.out` cover `fwupd-refresh.timer/service`,
`fwupd-offline-update.service`, `/var/lib/fwupd`, `/var/cache/fwupd`, `/var/cache/fwupdmgr`,
metadata refresh, local CAB/offline scheduling, D-Bus policy, and polkit actions. The
negative note is `negative/fwupd-refresh-offline-deep.md`. uid1001 and active non-admin
selfauth could not create pending/offline markers, start root units, activate the
condition-skipped daemon, or make direct `fwupdtool` parsing cross into root; `ROOT_PROOF=NO`.

ModemManager active methods: active-user modem-object policy grants exist, but the service
is condition-gated in this Docker target, there are no default modem objects without
hardware, `ReportKernelEvent` is not allowed for non-root callers, and pseudo-PTY injection
did not create a root-controlled modem object.

polkit-agent-helper direct execution: the helper is setuid root and reachable, but direct
PAM success still requires a valid authority cookie and expected identity. Live-cookie,
fake-cookie, malformed-stdin, and race probes did not produce a `SUCCESS` bypass.

polkit authentication-agent subject spoofing: uid1001 and active selfauth can register
agents only for same-uid subjects; cross-user, root PID, locked-admin, forged-uid, and
foreign-session subjects are rejected. Auth-admin cookies did not accept selfauth as the
admin identity, locked `ubuntu` remained unauthenticated, post-cancel cookie reuse failed,
and a polkitd ABRT was crash-only with no root marker or unit start.

UDisks LUKS unlock and mapper naming: active selfauth can create and unlock own LUKS loop
images, but UDisks ignored a hostile direct D-Bus `name` option, default mapper names stayed
`luks-<uuid>`, udev escaped hostile UUID/label content, and malformed UUID activation failed.

userns/netns device-name udev/sysctl crossing: uid1001 can create devices in a private
network namespace, but those interfaces did not enter the host namespace, did not trigger
host udev/sysctl rules, and did not create `/run/udev` or journald evidence in the root
namespace.

AppStream/swcatalog root apt hook: root `appstreamcli` follows a cache symlink when root
is deliberately pointed at an attacker-writable `--cachepath`, but the default
`/etc/apt/apt.conf.d/50appstream` hook uses fixed root-owned `/var/cache/swcatalog` and
does not accept user-controlled cache/data paths.

systemd sysupdate/repart/offline update units: sysupdate, repart, PackageKit offline
update, fwupd offline update, `system-update.target`, and `factory-reset.target` are
installed as root transitions, but config/search paths and marker files are root-owned,
container-gated where relevant, and active selfauth cannot start the units through systemd.

systemd PCR/pstore/storage helpers: pstore, pcrextend, pcrlock, TPM2 setup, and
storage-target-mode units/helpers are default-installed, but the live target had no
attacker-writable pstore/PCR policy path, the PCR varlink socket was disabled and
`ConditionSecurity=measured-uki` gated, pstore was `ConditionVirtualization=!container`
gated, and uid1001 could not start the root units or write their input/drop-in paths.

systemd storage/quota maintenance misc: a separate pass over `systemd-storagetm`,
`quotaon`, `systemd-quotacheck`, `systemd-battery-check`, `systemd-bsod`, and
`systemd-machine-id-commit` found no root transition reachable by uid1001. Quota helper
binaries were absent, storage/battery/BSOD/machine-id unit conditions failed in the live
Docker Server state, system manager environment/start/reload/link attempts were denied,
fixed root input paths were not writable, and direct helper execution stayed uid1001-only.

system root cache builders: `ldconfig`, journal catalog rebuilds, `dmesg.service`/
`savelog`, `locale-gen`, `systemd-hwdb`, and `kmod static-nodes` are default root
cache/update paths with parser and helper boundaries. uid1001 could not write the
root-owned input/cache trees, start the units, or set manager environment; hostile
`PATH`, `TMPDIR`, locale, catalog, hwdb, and module-state payloads executed only as
uid1001 and root-triggered rebuilds produced no helper hits.

miscellaneous cache builders: `install-info`, `shared-mime-info`, `sgml-base`/`xml-core`,
GLib schema/GIO cache, `update-shells`, and Twisted plugin cache triggers are default
maintainer-script surfaces. uid1001 could not write consumed system trees or acquire
dpkg trigger locks; hostile helper/PYTHONPATH payloads ran only in user-controlled
custom trees, and root trigger simulations used fixed root-owned paths with no root
marker. Root explicitly pointed at attacker custom paths can create root-owned files,
but that chooser is not default-reachable.

maintainer-script metadata lanes: AppArmor's homedirs generator, netplan-generator's
`/run/systemd/network/*-netplan*` gate, base-passwd `update-passwd`, and libc6
`/var/run/services.need_*` restart lists are real root upgrade-time trust boundaries.
uid1001 could not write the consumed account files, AppArmor tunables, netplan runtime
gate, base-passwd databases, or libc restart-list files; root replay/simulation created
no marker and left no restart-list state.

systemd generator/run-config/credential injection: root generators, `/run/*.d` config
imports, and `ImportCredential=` paths exist for sysusers, tmpfiles, binfmt, hwdb, and
firstboot, but `/run` search paths, `/run/credentials`, and credstore directories are
root-owned; uid1001 cannot trigger system-manager reload/start/SetCredential, and direct
helper execution remains unprivileged.

Root script import/PATH/env helpers: default root timers/services/cron/logrotate/apt hooks
invoke many shell, Python, and Perl helpers. Direct `PATH`, `PYTHONPATH`, and `PERL5LIB`
hijacks only executed as uid1001; root trust roots under `/usr`, `/etc`, `/var/cache`,
`/var/lib`, and `/var/backups` were not writable; systemd manager environment/start
attempts were denied; root-triggered services/cron produced no payload hits or root marker.

dpkg-db-backup timer: the default-enabled root daily timer runs a shell script with
unqualified `tar`/`savelog` and `DPKG_DATADIR` sourcing, but uid1001 cannot write
`/var/backups` or `/var/lib/dpkg`, cannot inject the systemd manager environment, and
cannot start the unit. Root-triggered validation created only root-owned backups and did
not touch the attacker target or root marker.

networkd-dispatcher/systemd-networkd: the dispatcher package and enabled unit exist, but
default hook trees are empty so the service is inactive. Users cannot plant hooks, start
networkd/dispatcher, own `org.freedesktop.network1`, write `/run/systemd/netif`, or make
private userns/netns links appear in the initial namespace.

hypervisor/guest-agent defaults: open-vm-tools and vgauth are VMware-condition-gated,
LXD agent devices are absent, `lxd-installer.socket` is `root:lxd` `0660`, pollinate is
container-gated and `User=pollinate`, and cloud-initramfs hook paths are root-owned.

snapd session-agent: root clients can connect to a replaced active-user session-agent
socket, but snapd REST state-changing requests return `401 Unauthorized` before using the
agent, and user service-control remains inside the uid1002 user manager.

ubuntu-drivers/update-notifier OEM helper: update-notifier owns the helper, but
`ubuntu-drivers-common` is not default-installed on this Server target, the helper cannot
import `UbuntuDrivers.detect`, and active root update-notifier units invoke package-data
downloader/release-upgrade MOTD paths rather than the OEM helper.

Ubuntu Pro apt-news/ESM hooks: root apt update can start `apt-news.service` and
`esm-cache.service`, but normal users cannot control Pro configuration, news URLs, ESM
cache files, MOTD stamps, manager environment, or root service starts.

release-upgrader/update-notifier pkexec paths: release-upgrader and update-notifier ship
Polkit XML for pkexec helpers, but `pkexec` is absent from this Server default target.
Direct helper execution stays uid1001 and update-notifier service starts remain
systemd/polkit-admin gated.

WWAN ModemManager/QMI/MBIM/usb-modeswitch helpers: `qmi-network` and `mbim-network`
source user-controlled profiles/state files and invoke CLI helpers through PATH when run
directly, but stock Server has no default root caller with attacker-controlled arguments.
ModemManager is container-condition-gated in this Docker target, service starts are
polkit/admin-gated, usb_modeswitch needs a real root udev/hardware event, and all
ModemManager/usb-modeswitch trust roots are root-owned.

fsck/mount public temp maintenance: `/usr/sbin/fsck.xfs` has a risky-looking
`/tmp/repair_mnt` branch, but uid1001 cannot trigger the root forced-fsck path, write
`/forcefsck`, alter fstab/kernel block state, start root maintenance units, or create
usable SUID `mount`/loop/bind mounts. Root-started default services left attacker
precreated `/tmp/repair_mnt` symlinks untouched.

GnuPG/apt-key/ca-certificates trust-store helpers: default root apt and CA update
paths use temporary GnuPG homes, hooks, `TMPDIR`, cert symlink creation, and apt-key
verification, but uid1001 could not write cert hooks, local CA directories, apt
configuration/keyring paths, debconf temp roots, `/etc/ssl/certs`, or root systemd
environment. Root `update-ca-certificates`, `apt-key`, and apt update/gpgv checks
ignored hostile attacker `PATH`, `TMPDIR`, and `GNUPGHOME` state.

Support/reporting helpers: sosreport, vm-support/open-vm-tools, Apport, ubuntu-bug,
unminimize, finalrd, friendly-recovery, byobu, MOTD, and update-notifier report paths
were default-present where package state allowed, but uid1001 service starts were
auth-gated, writable handoff paths stayed under `/tmp`, `/var/tmp`, or `/var/crash`,
root Apport did not follow a crash-path symlink to `/root`, and direct helpers either
refused non-root execution or produced attacker-owned report files.

Apport crash metadata parsing: root `/usr/share/apport/apport` handling of
attacker-controlled cwd/argv/env/interpreter metadata, report symlinks, and `.hanging`
markers was rechecked. `/run/apport.socket` remained uid1001-inaccessible, autoreport
was condition-gated, attacker environment did not affect root handler paths, unpackaged
attacker scripts were ignored, report symlinks were not followed, and no root marker was
created.

Network diagnostics tools: tcpdump, libpcap, tracepath, bind DNS utilities, netcat,
curl, wget, ftp, and telnet are default-installed user utilities. `tcpdump -z` is a
dangerous postrotate hook if a privileged caller supplies attacker-controlled arguments,
but the packaged `tcpdump` has no setuid bit or file capabilities, uid1001 cannot capture
on `lo`, no default root tcpdump unit/cron/logrotate path exists, and adjacent rsync
daemon startup is condition-gated by absent `/etc/rsyncd.conf`.

D-Bus activation helpers: uid1001 can trigger default system-bus service activation, but
cannot write searched system service directories, own system names, call
`UpdateActivationEnvironment`, execute the setuid launch helper directly, or make a
user-owned fake system bus execute root services. Forced activation launched the intended
absolute root paths for SoftwareProperties and hostnamed with no fake PATH hits.

Kernel/initramfs/update hooks: initramfs-tools, kernel-install, depmod, module-load,
sysctl, binfmt, sysusers, hwdb, ucf, update-alternatives, and dpkg trigger paths expose
many root hook/config boundaries, but uid1001 could not write their trust roots, set root
manager environment, start root rebuild units, or enqueue the `update-initramfs` trigger.
Hostile PATH/TMPDIR/initramfs hook payloads ran only as uid1001.

Network client hooks: dhcpcd hook runner, ethtool ifupdown scripts, netplan generated
services, pollinate, rsync, resolved, and userns/netns device-name attempts did not cross
into root. Hook roots and state paths were unwritable, service starts were auth-gated or
condition-gated, fake helpers ran only as uid1001, and user-namespace devices never
appeared in the initial namespace for root udev/network hooks.

Cron/mail spool deep pass: setgid `crontab` did not leak group `crontab` to
attacker-controlled editors, `/var/spool/cron/crontabs` blocked direct traversal, and
default root cron/run-parts directories were not attacker-writable. `run-parts` accepts
leading-dash names such as `--report`, but executes them as directory-qualified paths.
`/etc/cron.daily/apport` pruned old attacker-owned `/var/crash` entries without following
symlinks into a root decoy. With no default MTA/mailx installed, safe `MAILTO=root`
output was discarded and unsafe shell-looking `MAILTO` was rejected; `/var/mail` remained
non-writable to uid1001. `anacron` and `at/atd` were absent.

Cron user-crontab semantics: uid1001 can install per-user crontabs through the setgid
helper, but jobs still execute as `attacker`. System-crontab-style `root` fields are
parsed as command text, `%` only feeds stdin, `/root` writes fail, unsafe `MAILTO` is
rejected, and a controlled root canary job did not inherit attacker crontab env/PATH.
```

## Goal Mapping

1. Exact affected package name/version from target

For valid findings: none. Package/version proof is present in each negative note and in `baseline/live-target-standard/packages.txt`.

2. Exact default-install/default-enabled proof

Completed for the Docker target. Baseline files prove package list, active/enabled services, timers, sockets, D-Bus services, polkit actions, setuid/setgid files, capabilities, writable paths, tmpfiles, cron, logrotate, and systemd units. Candidate notes include default reachability proof.

3. Exact vulnerable code/config path

No vulnerable path was validated. Candidate notes identify tested code/config paths and the permission, policy, state, or semantic boundary that blocked escalation.

4. Exact unprivileged trigger commands

Recorded in negative notes and probe scripts for tested candidates. None produced root execution or a root-owned attacker-controlled write.

5. Working PoC script or command sequence

No working LPE PoC exists. The `pocs/` scripts are negative probes only.

6. Root proof

No root proof exists. No tested trigger produced `uid=0(root)` from `attacker` or non-admin `selfauth`.

7. Cleanup steps

Candidate cleanup is recorded in the negative notes. Final cleanup removed probe paths under `/tmp`, `/home/attacker`, `/home/selfauth`, `/run/lock/iscsi`, loop devices, active test sessions, snap-confine lock probes, UDisks loop/mount artifacts, and stale crash/upload probes. The Docker target remains running with `systemctl is-system-running` reporting `running` and `systemctl --failed` reporting zero failed units.

8. Why normal scanners/fuzzers likely miss it

For valid findings: not applicable. Negative notes still document scanner-miss-style trust boundaries, especially active-session polkit semantics, D-Bus method authorization, root timers, maintainer hooks, lock-directory reuse, and process-metadata heuristics.

9. Novelty check

For valid findings: not applicable. No targeted public novelty checks were performed for a reportable bug because no candidate reached the root-proof bar.

10. Suggested fixes suitable for Ubuntu Security triage

No Ubuntu Security triage fix is proposed as a proven LPE. Several negative notes include hardening suggestions for non-finding primitives, such as open-iscsi lock ownership validation and clearer PackageKit transaction-state boundaries.

## Current Conclusion

Current validated result is 0/5. The strict completion bar is not met, and the `/goal` remains active.

The highest-value remaining direction is not another broad scanner pass. It is continued targeted reasoning over default package-specific trust boundaries, or a non-Docker Ubuntu Server VM reproduction pass for Docker-condition-gated services where the container model may hide default Server behavior.
