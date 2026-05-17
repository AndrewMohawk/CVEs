# Negative: active UDisks O_PATH fd-passing

Result: no stock Ubuntu 24.04 Server local root LPE was validated through
UDisks2 `Manager.LoopSetup` file-descriptor passing.

Probe/log:

```text
pocs/active_udisks_opath_fd_probe.sh
logs/active-udisks-opath-fd.out
```

## Default proof

Live target: Ubuntu 24.04.4 LTS, `ubuntu24-server-lpe-target`.

Relevant packages:

```text
udisks2 2.10.1-6ubuntu1.3
libudisks2-0 2.10.1-6ubuntu1.3
dbus 1.14.10-4ubuntu4.1
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
python3-dbus 1.3.2-5build3
```

`udisks2.service` is enabled/active and root-owned. The D-Bus manager exposes:

```text
LoopSetup(in h fd, in a{sv} options, out o resulting_device)
```

The default polkit action allows an active local user:

```xml
<action id="org.freedesktop.udisks2.loop-setup">
  <allow_active>yes</allow_active>
</action>
```

## Tested trigger

The probe logged `selfauth` into `tty10` with `Active=yes` and directly sent
file descriptors over D-Bus, bypassing `udisksctl -f` path handling:

```python
fd = os.open("/etc/shadow", os.O_PATH | os.O_CLOEXEC)
Manager.LoopSetup(dbus.types.UnixFd(fd), {"read-only": True})
```

It tested `O_PATH` fds for:

```text
/etc/shadow
/etc/sudoers
/var/cache/debconf/passwords.dat
/etc/passwd
```

It also tested an ordinary `O_RDONLY` fd for `/etc/passwd` as a control.

## Result

`O_PATH` could open root-owned files under searchable directories, but the kernel
loop association rejected those fds before a loop device was created:

```text
shadow-opath: open ok ... LoopSetup error ... Failed to associate ... Bad file descriptor
sudoers-opath: open ok ... LoopSetup error ... Bad file descriptor
debconf-passwords-opath: open ok ... LoopSetup error ... Bad file descriptor
passwd-opath-rw-request: open ok ... LoopSetup error ... Bad file descriptor
```

The ordinary readable `/etc/passwd` fd did create `/dev/loop0`, proving the
active-user fd path is real:

```text
LoopSetup OK /org/freedesktop/UDisks2/block_devices/loop0
loop_setup_by_uid=1002 backing=/etc/passwd
```

That did not become a privilege increase. Raw block access and mount remained
unavailable:

```text
OpenDevice(r)  -> NotAuthorizedCanObtain
OpenDevice(w)  -> NotAuthorizedCanObtain
OpenDevice(rw) -> NotAuthorizedCanObtain
Mount(ro)      -> no Filesystem interface
```

The safe root-owned victim under `/root` could not be opened because directory
search permission blocked the path before `O_PATH`:

```text
open error PermissionError: /root/active_udisks_opath_fd_victim
```

No root marker was created:

```text
ROOT_PROOF_ABSENT /root/active_udisks_opath_fd_root
```

Deleting the loop backed by `/etc/passwd` produced a transient `udisksd` SIGSEGV
in this Docker target. The probe restarts `udisks2.service`; this is recorded as
a DoS/crash observation only and is not counted as LPE.

## Cleanup

The probe deletes any created loop device, removes the temporary `selfauth`
profile and `/tmp` state, restarts `udisks2.service` if it crashed, and removes
the root marker/safe victim. Final health:

```text
udisks2.service active
systemctl is-system-running -> running
systemctl --failed --no-legend -> no failed units
```

## Why scanners may miss it

Most UDisks tests use `udisksctl loop-setup -f`, which opens the file normally
as the caller. The important trust-boundary question is the raw D-Bus `h` fd
argument with `O_PATH` descriptors to otherwise unreadable root files. The live
probe showed that this path stops at kernel loop fd validation.

## Suggested triage

No LPE report from the fd-bypass hypothesis. The `udisksd` crash on loop cleanup
for a non-filesystem root-owned readable file may merit separate DoS hardening,
but it does not satisfy this goal's privilege-escalation bar.
