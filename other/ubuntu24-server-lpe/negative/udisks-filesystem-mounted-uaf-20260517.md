# UDisks mounted Check/Repair missing-goto UAF

Result: `ROOT_PROOF=NO`. I did not validate a uid1001-to-root privilege escalation on the stock Ubuntu 24.04 Server target. The issue is a reachable root-daemon crash/DoS plus unintended root-side fsck execution on the caller's mounted loop device.

Artifacts:
- `pocs/udisks_filesystem_mounted_uaf_probe.sh`
- `logs/udisks-filesystem-mounted-uaf-20260517.out`

## Package and reachability

Target: Ubuntu 24.04.4 LTS, aarch64. The container's uid1001 account is `attacker`; `selfauth` is uid1002. The fresh proof used an active tty9 `attacker` session with `Active=yes`; the pre-existing `/tmp/udisks-missing-goto-*` artifacts show the same path from `selfauth`.

Relevant packages from the log:
- `udisks2 2.10.1-6ubuntu1.3`
- `libudisks2-0 2.10.1-6ubuntu1.3`
- `libblockdev3 3.1.1-1ubuntu0.1`
- `libblockdev-fs3 3.1.1-1ubuntu0.1`
- `polkitd 124-2ubuntu1.24.04.3`
- `systemd 255.4-1ubuntu8.15`

`udisks2.service` is default enabled/active and runs `/usr/libexec/udisks2/udisksd` as the system bus service. Polkit defaults allow an active local user to use `org.freedesktop.udisks2.loop-setup`, `filesystem-mount`, and `modify-device` with `allow_active=yes` (log lines 18-52). Runtime `pkcheck` from the active uid1001 session returned rc 0 for all three actions (log lines 367-442).

## Exact trigger

From an active uid1001 tty session:

```sh
truncate -s 96M Check.ext4.img
mkfs.ext4 -F -q -L UAFCheck Check.ext4.img
udisksctl loop-setup -f Check.ext4.img --no-user-interaction
udisksctl mount -b /dev/loop0 --no-user-interaction
python3 persistent-call.py /org/freedesktop/UDisks2/block_devices/loop0 Check
```

The same sequence with `Repair.ext4.img`, `/dev/loop1`, and `Repair` reproduces the repair path. The D-Bus calls return:
- `Cannot check filesystem filesystem on /dev/loop0 if mounted`
- `Cannot repair filesystem filesystem on /dev/loop1 if mounted`

## Source and debugger evidence

In `/tmp/udisks2-2.10.1/src/udiskslinuxfilesystem.c`, `handle_repair()` returns the mounted-filesystem error at lines 2158-2168 but lacks `goto out`, then continues to `modify-device` authorization and `bd_fs_repair()` at lines 2170-2212. `handle_check()` has the same pattern at lines 2326-2336 and continues to authorization and `bd_fs_check()` at lines 2338-2380 (log lines 55-330).

GDB confirms the same `GDBusMethodInvocation *` receives `return_dbus_error`, is reused in `udisks_daemon_util_check_authorization_sync_with_error`, reaches `bd_fs_check`, then `udisksd` SIGSEGVs in `g_type_check_instance_is_fundamentally_a`/`g_object_unref` (log lines 455-610).

Strace on the Repair trigger shows fixed root helper execution:

```text
execve("/usr/sbin/e2fsck", ["e2fsck", "-f", "-y", "-C", "1", "/dev/loop1"], ... "USER=root" ...)
```

The searched helper path directories and `/usr/sbin/e2fsck` are root-owned 0755 (log lines 611-614 and 685-691).

## Why this is not a root escalation proof

The attacker controls the mounted filesystem image bytes and can choose Check vs Repair, but the root-side execution primitive is only libblockdev invoking a fixed fsck helper with fixed argv against `/dev/loopN`. There is no shell, no attacker-controlled executable path, no attacker-controlled argv beyond the block device, and the daemon environment is not inherited from the uid1001 caller. The mounted filesystem is mounted under `/media/attacker/...` with `nosuid,nodev`; corrupting or repairing that loop image as root did not create root-owned files, execute attacker code, or alter host root state.

The observed memory bug is the returned invocation being reused/double-unreffed after the missing `goto`, producing a reliable SIGSEGV in the root daemon. I did not get instruction pointer or object/vtable control sufficient for execution; the validated effect is daemon crash plus root fsck of the user's loop device.

## Cleanup proof

Root markers stayed absent:
- `/root/udisks_filesystem_mounted_uaf_root`
- `/run/udisks_filesystem_mounted_uaf_root`
- `/tmp/udisks_filesystem_mounted_uaf_root`

The final cleanup proof shows `udisks2_active=active`, no failed units, no probe loop devices, no probe mounts, and external post-run health confirms `loops=0` and `mounts=0` (log lines 668-699).

Conclusion: `ROOT_PROOF=NO`.
