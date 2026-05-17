# active UDisks SetLabel/SetUUID: negative

Verdict: no local privilege escalation from a normal non-admin active local user
through `org.freedesktop.UDisks2.Filesystem.SetLabel` or `SetUUID` on a
stock Ubuntu 24.04 Server default target.

Artifacts:

```text
pocs/active_udisks_label_uuid_probe.sh
logs/active-udisks-label-uuid.out
```

Default proof:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
udisks2 2.10.1-6ubuntu1.3
libudisks2-0:arm64 2.10.1-6ubuntu1.3
e2fsprogs 1.47.0-2.4~exp1ubuntu4.1
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
udev 255.4-1ubuntu8.15
```

`udisks2.service` is enabled and active. The relevant policy split is that an
active local user can modify a non-system device, while system devices remain
admin-gated:

```text
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
org.freedesktop.udisks2.modify-device:
  allow_any=auth_admin
  allow_inactive=auth_admin
  allow_active=yes

org.freedesktop.udisks2.modify-device-system:
  allow_any=auth_admin
  allow_inactive=auth_admin
  allow_active=auth_admin_keep
```

Trigger:

```sh
./pocs/active_udisks_label_uuid_probe.sh ubuntu24-server-lpe-target
```

The PoC logs in `selfauth` on `/dev/tty1`, creates an ext4 image, maps it with
active-user `udisksctl loop-setup`, then calls `SetLabel` and `SetUUID` over the
system bus with exact attacker-controlled Python D-Bus strings.

Reachable root-helper input:

```text
### SetLabel repr='SAFESET'
SetLabel_OK result=None

### SetLabel repr='../../root/pwn'
SetLabel_OK result=None
DEVLINKS=... /dev/disk/by-label/..\x2f..\x2froot\x2fpwn

### SetLabel repr='semi;id>/root/x'
SetLabel_OK result=None
DEVLINKS=... /dev/disk/by-label/semi\x3bid\x3e\x2froot\x2fx

### SetLabel repr='$(id>/root/x)'
SetLabel_OK result=None
DEVLINKS=... /dev/disk/by-label/\x24\x28id\x3e\x2froot\x2fx\x29

### SetLabel repr='LD_PRELOAD=/x'
SetLabel_OK result=None
DEVLINKS=... /dev/disk/by-label/LD_PRELOAD=\x2fx

### SetLabel repr='-L/root/pwn'
SetLabel_OK result=None
DEVLINKS=... /dev/disk/by-label/-L\x2froot\x2fpwn
```

Rejected input:

```text
### SetLabel repr='line\nSYSTEMD_WANTS=active-udisks-label-uuid.service'
SetLabel_ERR ... Label for ext filesystem must be at most 16 characters long.

### SetUUID repr='../../root/pwn'
SetUUID_ERR ... Provided UUID is not a valid RFC-4122 UUID.
### SetUUID repr='semi;id>/root/x'
SetUUID_ERR ... Provided UUID is not a valid RFC-4122 UUID.
### SetUUID repr='$(id>/root/x)'
SetUUID_ERR ... Provided UUID is not a valid RFC-4122 UUID.
### SetUUID repr='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\nSYSTEMD_WANTS=x.service'
SetUUID_ERR ... Provided UUID is not a valid RFC-4122 UUID.
```

A valid attacker-chosen UUID was accepted and encoded into the normal udev
symlink:

```text
SetUUID repr='11111111-2222-4333-8444-555555555555'
SetUUID_OK result=None
/dev/disk/by-uuid/11111111-2222-4333-8444-555555555555 -> ../../loop0
```

Root proof check:

```text
/media/selfauth/-L_root_pwn /dev/loop0 ext4 rw,nosuid,nodev,relatime,errors=remount-ro
stat: cannot statx '/root/active-udisks-label-uuid-root': No such file or directory
stat: cannot statx '/run/active-udisks-label-uuid-root': No such file or directory
stat: cannot statx '/tmp/active-udisks-label-uuid-user': No such file or directory
ROOT_PROOF=no
```

Dead-end reason:

The helper boundary is real and default-reachable for an active non-admin user:
root `udisksd` accepts label changes on the user's loop device. The tested
labels were passed as data, not shell, option, environment, path, or unit
syntax. Udev exported them as escaped symlink components, and invalid UUIDs
were rejected before helper execution. The final mount remained `nosuid,nodev`,
and ext4 ownership left the mounted tree root-owned. No root-owned marker,
helper execution, systemd unit transition, or writable root path was produced.

Why scanners may miss this:

Generic scans usually see only that `modify-device` is `allow_active=yes`.
The LPE question depends on active-session polkit, UDisks helper argv handling,
filesystem label validation, udev escaping, mountpoint sanitization, and final
mount options. The dangerous-looking strings all stayed data.

Cleanup:

The PoC unmounted `/media/selfauth/-L_root_pwn`, deleted the loop device,
terminated the active `selfauth` login, removed `/home/selfauth/active-udisks-label-uuid`,
`/tmp/active-udisks-label-uuid*`, `/root/active-udisks-label-uuid*`, and
`/run/active-udisks-label-uuid*`, then reset failed UDisks/udev/getty units.
