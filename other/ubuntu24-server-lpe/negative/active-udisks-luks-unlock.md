# Negative: active UDisks LUKS unlock to dm-crypt mapper/udev/systemd

Status: no validated LPE. The path is default-reachable from an active local non-sudo user, but attacker-controlled LUKS metadata did not become root command execution or an arbitrary root write.

## Target and default proof

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, Ubuntu 24.04.4 LTS.

Users:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
sudo:x:27:ubuntu
```

Default packages/services:

```text
udisks2 2.10.1-6ubuntu1.3
libudisks2-0:arm64 2.10.1-6ubuntu1.3
libblockdev-crypto3:arm64 3.1.1-1ubuntu0.1
cryptsetup 2:2.7.0-1ubuntu4.2
cryptsetup-bin 2:2.7.0-1ubuntu4.2
systemd 255.4-1ubuntu8.15
udev 255.4-1ubuntu8.15
polkitd 124-2ubuntu1.24.04.3
udisks2.service enabled active, Type=dbus, BusName=org.freedesktop.UDisks2, ExecStart=/usr/libexec/udisks2/udisksd, User=root
```

Polkit defaults allow active users for both relevant actions:

```text
org.freedesktop.udisks2.loop-setup: allow_active yes
org.freedesktop.udisks2.encrypted-unlock: allow_active yes
```

## Probe

Run:

```sh
./pocs/active_udisks_luks_unlock_probe.sh ubuntu24-server-lpe-target
```

Full log:

```text
logs/active-udisks-luks-unlock.out
```

The probe used an active tty session for `selfauth`:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
/dev/tty1
Seat=seat0
TTY=tty1
Active=yes
State=active
```

It created attacker-owned LUKS images with controlled labels, subsystems, UUIDs, one direct D-Bus unlock options attempt, and one patched LUKS1 header with a malformed UUID containing path traversal plus `SYSTEMD_WANTS=`.

## Results

Active `selfauth` could attach and unlock normal LUKS2 images:

```text
Mapped file .../luks-default.img as /dev/loop0.
Unlocked /dev/loop0 as /dev/dm-0.
Mapped file .../luks-label-escape.img as /dev/loop1.
Unlocked /dev/loop1 as /dev/dm-1.
Mapped file .../luks-label-unit.img as /dev/loop2.
Unlocked /dev/loop2 as /dev/dm-2.
```

The direct D-Bus attempt with `{'name': <'evil.service'>, 'allow-discards': <true>}` also returned success, but UDisks ignored the attacker name for the mapper. The resulting root-side dm names stayed UUID-derived:

```text
luks-11111111-2222-3333-4444-555555555555
luks-22222222-3333-4444-5555-666666666666
luks-33333333-4444-5555-6666-777777777777
luks-44444444-5555-6666-7777-888888888888
```

Root udev properties showed fixed dm metadata:

```text
DM_NAME=luks-44444444-5555-6666-7777-888888888888
DM_UUID=CRYPT-LUKS2-44444444555566667777888888888888-luks-44444444-5555-6666-7777-888888888888
SYSTEMD_READY=0
```

LUKS labels and malformed LUKS1 UUIDs did reach root-created `/dev/disk` symlink names, but udev escaped separators/control bytes and kept them under `/dev/disk`:

```text
/dev/disk/by-label/..\x2froot\x2fescape\x20label\x3bsemi -> ../../loop1
/dev/disk/by-label/active-udisks-luks.service -> ../../loop2
/dev/disk/by-uuid/..\x2f..\x2froot\x2fevil\x0aSYSTEMD_WANTS=x.serviceX -> ../../loop4
```

The malformed LUKS1 UUID remained visible to blkid/UDisks as crypto metadata, but cryptsetup refused activation:

```text
UUID=../../root/evil^JSYSTEMD_WANTS=x.serviceX
Error unlocking /dev/loop4: ... Failed to activate device: Invalid argument
unlock_rc=1
```

`cryptsetup luksFormat --uuid '../root/evil'` also failed at creation time:

```text
Wrong LUKS UUID format provided.
uuid_bad_option_rc=1
```

## Why it is not an LPE

The reachable root work is limited to UDisks/cryptsetup opening dm-crypt mappings and udev creating escaped device symlinks. I did not find a path where attacker-controlled LUKS label, subsystem, UUID, D-Bus `name`, cryptsetup option, udev property, or systemd device unit name became root command execution, root-owned file creation outside `/dev`, or privileged identity change.

Root proof markers and traversal targets were absent:

```text
ROOT_PROOF_ABSENT /root/active_udisks_luks_unlock_root
ROOT_PROOF_ABSENT /run/active_udisks_luks_unlock_root
ROOT_PROOF_ABSENT /tmp/active_udisks_luks_unlock_root
ROOT_PROOF_ABSENT /root/escape
ROOT_PROOF_ABSENT /root/evil
```

Cleanup completed:

```text
losetup -a | grep active-udisks-luks-unlock -> no output
systemctl is-system-running -> running
systemctl --failed --no-legend -> no output
```

## Root-side code/config touched by metadata

The relevant default rules are:

```text
/usr/lib/udev/rules.d/60-persistent-storage.rules:
  SYMLINK+="disk/by-uuid/$env{ID_FS_UUID_ENC}"
  SYMLINK+="disk/by-label/$env{ID_FS_LABEL_ENC}"

/usr/lib/udev/rules.d/55-dm.rules:
  ENV{DM_NAME}="$attr{dm/name}", ENV{DM_UUID}="$attr{dm/uuid}"
  SYMLINK+="mapper/$env{DM_NAME}"

/usr/lib/udev/rules.d/60-persistent-storage-dm.rules:
  SYMLINK+="disk/by-id/dm-name-$env{DM_NAME}"
  SYMLINK+="disk/by-id/dm-uuid-$env{DM_UUID}"

/usr/lib/udev/rules.d/99-systemd.rules:
  SUBSYSTEM=="block", TAG+="systemd"
  ENV{DM_UUID}=="CRYPT-*", ENV{ID_PART_TABLE_TYPE}=="", ENV{ID_FS_USAGE}=="", ENV{SYSTEMD_READY}="0"
```
