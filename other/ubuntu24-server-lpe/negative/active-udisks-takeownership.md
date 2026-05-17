# active UDisks TakeOwnership: negative

Verdict: no local privilege escalation from a normal non-admin local user through
`org.freedesktop.UDisks2.Filesystem.TakeOwnership` on the stock Ubuntu 24.04
Server target.

Artifacts:

```text
pocs/active_udisks_takeownership_probe.sh
logs/active-udisks-takeownership.out
```

Default proof from the target:

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
Linux 508d797cbad0 6.10.14-linuxkit ... aarch64
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
udisks2 2.10.1-6ubuntu1.3
libudisks2-0:arm64 2.10.1-6ubuntu1.3
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
e2fsprogs 1.47.0-2.4~exp1ubuntu4.1
```

`udisks2.service` is default enabled and active:

```text
enabled
active
/usr/lib/systemd/system/udisks2.service
ExecStart=/usr/libexec/udisks2/udisksd
```

Relevant default authorization:

```text
/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy
492 <action id="org.freedesktop.udisks2.filesystem-take-ownership">
543 <defaults>
544   <allow_any>auth_admin</allow_any>
545   <allow_inactive>auth_admin</allow_inactive>
546   <allow_active>auth_admin_keep</allow_active>
```

Trigger exercised:

```sh
./pocs/active_udisks_takeownership_probe.sh ubuntu24-server-lpe-target
```

The script logs in `selfauth` on `/dev/tty1`, verifies an active local session,
creates an attacker-controlled ext4 image, prepopulates it with a setuid-looking
payload and symlinks to `/root` and `/run`, maps it with active-user
`udisksctl loop-setup`, mounts it with UDisks, then calls:

```sh
gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/block_devices/loop0 \
  --method org.freedesktop.UDisks2.Filesystem.TakeOwnership \
  "{'auth.no_user_interaction': <true>}"

gdbus call --system --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/block_devices/loop0 \
  --method org.freedesktop.UDisks2.Filesystem.TakeOwnership "{}"
```

Observed result:

```text
Id=73
User=1002
Name=selfauth
TTY=tty1
Active=yes

Mounted /dev/loop0 at /media/selfauth/TAKEOWN
/media/selfauth/TAKEOWN /dev/loop0 ext4 rw,nosuid,nodev,relatime,errors=remount-ro
-rwsr-xr-x 4755 root:root /media/selfauth/TAKEOWN/attacker_dir/runme.sh
lrwxrwxrwx root:root link_to_root_decoy -> /root/active-udisks-takeownership-decoy

Error: GDBus.Error:org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: Not authorized to perform operation
takeownership_rc=1
Error: GDBus.Error:org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: Not authorized to perform operation
takeownership_rc=1

ROOT_PROOF=no
```

The mounted filesystem remained `nosuid,nodev`, the prebuilt setuid file ran as
`selfauth`, the root-owned decoy under `/root` stayed `root:root 0600`, and no
root marker appeared under `/root` or `/run`.

Dead-end reason:

The active local user can create a loop device and mount the owned image under
the default active-session UDisks policy, but `TakeOwnership` is separately
`auth_admin_keep` even for active sessions. A normal non-admin user cannot reach
the root helper semantics, so the symlink-follow and recursive-chown escape
questions are not exploitable in the default Server state.

Why scanners may miss this:

Static policy sweeps see both an active-user mount permission and a root
recursive ownership method on the same D-Bus object. The exploitable question is
semantic and session-dependent: whether ownership of the loop/mount relaxes the
`TakeOwnership` action at runtime. It does not.

Cleanup:

The PoC unmounts `/media/selfauth/TAKEOWN`, deletes the loop device, terminates
the `selfauth` login, removes `/home/selfauth/active-udisks-takeownership`,
`/tmp/active-udisks-takeownership*`, `/root/active-udisks-takeownership*`, and
`/run/active-udisks-takeownership*`, and resets failed UDisks/udev/getty units.
