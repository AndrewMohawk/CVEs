# Negative: setuid/setgid/file-capability helper tail

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, stock Ubuntu 24.04.4 Server default state on `aarch64`.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, no privileged groups and no starting capabilities.

Result: no real `uid1001 -> root` local privilege escalation was validated. `ROOT_PROOF=NO`.

Artifacts:

```text
pocs/setuid_cap_tail_20260517_probe.sh
logs/setuid-cap-tail-20260517.out
```

## Default package/version proof

The target was current at probe time:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
Linux bf51bb670420 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64
apt-get -s full-upgrade: 0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
```

Installed default packages:

```text
ubuntu-minimal            1.539.2
ubuntu-standard           1.539.2
ubuntu-server             1.539.2
libgstreamer1.0-0:arm64   1.24.2-1ubuntu0.1
openssh-client            1:9.6p1-3ubuntu13.16
libutempter0:arm64        1.2.1-3build1
fuse3                     3.14.0-5build1
mount                     2.39.3-9ubuntu6.5
util-linux                2.39.3-9ubuntu6.5
passwd                    1:4.13+dfsg1-4ubuntu3.2
login                     1:4.13+dfsg1-4ubuntu3.2
libpam-modules:arm64      1.5.3-5ubuntu5.5
libpam-modules-bin        1.5.3-5ubuntu5.5
dbus                      1.14.10-4ubuntu4.1
dbus-daemon               1.14.10-4ubuntu4.1
polkitd                   124-2ubuntu1.24.04.3
iputils-ping              3:20240117-1ubuntu0.1
mtr-tiny                  0.95-1.1ubuntu0.1
```

Relevant helper metadata:

```text
/usr/lib/aarch64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper 0755 root:root cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
/usr/lib/aarch64-linux-gnu/utempter/utempter                         2755 root:utmp
/usr/bin/ssh-agent                                                    2755 root:_ssh
/usr/lib/openssh/ssh-keysign                                          4755 root:root
/usr/bin/fusermount3                                                  4755 root:root  (dpkg path: /bin/fusermount3, merged-/usr alias)
/usr/bin/mount                                                        4755 root:root
/usr/bin/umount                                                       4755 root:root
/usr/bin/ping                                                         0755 root:root cap_net_raw=ep
/usr/bin/mtr-packet                                                   0755 root:root cap_net_raw=ep
/usr/sbin/unix_chkpwd                                                 2755 root:shadow
/usr/sbin/pam_extrausers_chkpwd                                       2755 root:shadow
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                           4754 root:messagebus
/usr/lib/polkit-1/polkit-agent-helper-1                               4755 root:root
```

`dpkg -V` returned no helper-binary mismatches for the scoped packages; the only emitted differences were missing documentation/manpage files in the minimized image.

## Tested primitives

`gst-ptp-helper`: hostile `PATH`, `GST_PTP_HELPER`, `GST_PLUGIN_PATH`, `GST_DEBUG_FILE`, and `LD_PRELOAD` did not execute the fake helper or create a root marker. A live helper accepted a valid PTP frame and returned an ACK, but after setup it was still `Uid: 1001`, `Gid: 1001`, `CapPrm: 0`, `CapEff: 0`, `getpcaps: =`.

```text
gst_direct_rc=0
clock_len 11 clock_hex 0008020102030405060708
CapEff: 0000000000000000
ack_len 15 ack_hex 000c0300000411356cb7ab01000517
gst_fake_helper_marker_rc=1
gst_root_marker_rc=1
```

`ssh-agent`: the command path, PKCS#11 helper path, and socket path stayed in uid/gid 1001. The attacker-controlled `SSH_PKCS11_HELPER` ran only as attacker. A symlink socket path to `/root/...` failed without creating the root target.

```text
ssh_agent_command_rc=0
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
srw------- 600 attacker:attacker .../agent/dir/sock
ssh_add_rc=1
pkcs11 helper marker: uid=1001(attacker) gid=1001(attacker)
root_agent_sock_rc=1
ssh_agent_root_marker_rc=1
```

`utempter`: PTY-mediated calls with `UTMP_FILE`, `WTMP_FILE`, and `LD_PRELOAD` did not redirect accounting to attacker-selected files or `/root`. It only touched the fixed utmp/wtmp accounting files, which were restored from root-side backups during cleanup.

```text
pty_slave /dev/pts/0
add_record b'tail-host' rc 1
add_record b'../root/escape' rc 1
add_record b'bad\nhost' rc 0
path_exists .../attacker.utmp False
path_exists .../attacker.wtmp False
path_exists /root/setuid-cap-tail-20260517-root False
direct_utempter_rc=1
```

`ssh-keysign`: direct execution remained disabled by global `/etc/ssh/ssh_config`; user SSH config `EnableSSHKeysign yes`, `HostbasedAuthentication yes`, `Match exec`, and `ProxyCommand` executed only in the unprivileged client context. No host keys existed.

```text
direct_keysign_rc=255
ssh-keysign not enabled in /etc/ssh/ssh_config
ssh_client_rc=255
match/proxy markers: uid=1001(attacker) gid=1001(attacker)
ls: cannot access '/etc/ssh/ssh_host_*': No such file or directory
keysign_root_marker_rc=1
```

`fusermount3`, `mount`, and `umount`: `_FUSE_COMMFD` mounting worked, but the resulting mount was forced to `user_id=1001,group_id=1001,nosuid,nodev`; `suid` and `dev` were ignored. `allow_other` stayed disabled. Attacker fstab and `--mkdir` paths created attacker-owned `/tmp` directories only; root mountpoint creation, namespace switching, and symlink unmounts failed.

```text
fusermount_rc 0 got_fd True
/tmp/.../fuse-mnt fuse rw,nosuid,nodev,relatime,user_id=1001,group_id=1001
unsafe option suid ignored
unsafe option dev ignored
fuse_unmount_symlink_rc=1
fuse_allow_other_rc=1
mount_attacker_fstab_rc=32
mount_root_mkdir_rc=1
root_mount_dir_rc=1
mount_namespace_rc=2
umount_namespace_symlink_rc=2
umount_symlink_rc=32
```

`ping` and `mtr-packet`: both exposed packet operations, not root. `ping` dropped `cap_net_raw` after setup and could not set packet mark. `mtr-packet` retained `cap_net_raw=ep` while alive and accepted its line protocol, but path-like and shell-like inputs were rejected as parser data.

```text
ping from iputils 20240117
ping: WARNING: failed to set mark: 123: Operation not permitted
ping live CapEff: 0000000000000000
mtr live CapPrm/CapEff: 0000000000002000
5 invalid-argument
6 unknown-command
3 reply ip-4 127.0.0.1 ...
4 reply ip-4 127.0.0.1 ...
```

`unix_chkpwd` and `pam_extrausers_chkpwd`: hostile usernames, path-like names, newline-containing names, and attacker-controlled extrausers environment variables did not produce output, file creation, or root. `unix_chkpwd` returned `7` for wrong passwords and `9` for invalid/missing users; `pam_extrausers_chkpwd` returned failure only. Strace showed fixed `/etc/passwd` and `/etc/shadow` reads; `/var/lib/extrausers` was absent and not created.

```text
/var/lib/extrausers: absent
unix_chkpwd attacker/root -> helper_rc=7
unix_chkpwd ../etc/shadow/newline/missing -> helper_rc=9
pam_extrausers_chkpwd tested users -> helper_rc=7
openat("/etc/passwd", O_RDONLY|O_CLOEXEC)
openat("/etc/shadow", O_RDONLY|O_CLOEXEC)
var_lib_extrausers_exists_rc=1
```

`dbus-daemon-launch-helper` and `polkit-agent-helper-1`: existing notes already cover the deeper activation/cookie paths. This pass only verified current state: system D-Bus and polkit were active, direct helper execution was denied by `4754 root:messagebus`, fake polkit cookie authentication failed, and system-bus activation environment update was denied.

```text
dbus.service/dbus.socket/polkit.service: active
dbus_helper_direct_rc=126
polkit-agent-helper-1: pam_authenticate failed: Authentication failure
polkit_helper_fake_cookie_rc=1
dbus_update_env_rc=1
```

## Cleanup and integrity proof

The probe restored `/run/utmp` and `/var/log/wtmp` from pre-test root-side backups. Final hashes for account and accounting files matched the baseline captured at the beginning:

```text
/etc/passwd  e1468fa4ad17e48937e0fe2d6f1c64ea1d8477c339287f68bd3fc54aa9729ee0
/etc/shadow  11ae553af516257768d364fc633162128e094c33e1711ff7dc40df0a964880d5
/etc/group   dff213c60bbb531abd3fcb0cd75921179da142bd89f2d78661aaad71f4b66271
/etc/gshadow ae4b5b1eb4b8c82d5234358edc450e3bbef3b0f6ac528f1658ef689183a13c08
/run/utmp    6f5554ee5d316058ce430c55423a5212eecb626caceeb7997a368d682c58fe12
/var/log/wtmp 3feddef21718e0b44c3ad2686be960484fe1f63771186be8caa6d3fffd6c1184
/var/log/btmp e88ffb31f27ecc80b2aae77fa7855ab0def528a63f6b3c96773af654beb1847c
```

Root marker and root-target checks were absent:

```text
root_marker_exists_rc=1
root_agent_sock_exists_rc=1
root_mount_dir_exists_rc=1
```

Transient work cleanup succeeded:

```text
tmp_work_removed_rc=0
attacker_work_removed_rc=0
systemctl is-system-running -> running
pgrep attacker ssh-agent/mtr-packet/gst-ptp-helper -> no output
```

## Conclusion

The remaining helper tail is default-installed and reachable, but this pass found only bounded file-capability packet/PTP operations, setgid accounting/shadow reads, disabled OpenSSH hostbased signing, caller-owned FUSE mounts, restricted setuid mount/umount semantics, and policy-gated D-Bus/polkit helpers. No root shell, root command execution, root-owned attacker-selected file write, or durable privilege escalation primitive was produced.

ROOT_PROOF=NO
