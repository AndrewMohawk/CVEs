# Negative: active UDisks partition metadata setters

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server Docker target  
Probe: `pocs/active_udisks_partition_metadata_probe.sh`  
Log: `logs/active-udisks-partition-metadata.out`  
Result: no validated uid1001-to-root LPE. `ROOT_PROOF=NO`.

## Default proof

Relevant default packages:

```text
dbus                  1.14.10-4ubuntu4.1
gdisk                 1.0.10-1build1
libudisks2-0:arm64    2.10.1-6ubuntu1.3
parted                3.6-4build1
polkitd               124-2ubuntu1.24.04.3
python3-dbus          1.3.2-5build3
systemd               255.4-1ubuntu8.15
udev                  255.4-1ubuntu8.15
udisks2               2.10.1-6ubuntu1.3
util-linux            2.39.3-9ubuntu6.5
```

Default service:

```text
/usr/lib/systemd/system/udisks2.service
Type=dbus
BusName=org.freedesktop.UDisks2
ExecStart=/usr/libexec/udisks2/udisksd
WantedBy=graphical.target
```

The service was default-enabled and active:

```text
systemctl is-enabled udisks2.service -> enabled
systemctl is-active udisks2.service  -> active
```

The active test subject was a real local seat login:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
TTY=/dev/tty1
Seat=seat0
Active=yes
```

Relevant polkit actions are present in
`/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy`:

```text
1143  <action id="org.freedesktop.udisks2.loop-setup">
2035  <action id="org.freedesktop.udisks2.modify-device">
2121  <action id="org.freedesktop.udisks2.modify-device-system">
```

Root udev consumers for partition metadata are default-installed and root-owned:

```text
/usr/lib/udev/rules.d/60-persistent-storage.rules:148
  ENV{ID_PART_ENTRY_UUID}=="?*", SYMLINK+="disk/by-partuuid/$env{ID_PART_ENTRY_UUID}"

/usr/lib/udev/rules.d/60-persistent-storage.rules:149
  ENV{ID_PART_ENTRY_SCHEME}=="gpt", ENV{ID_PART_ENTRY_NAME}=="?*", SYMLINK+="disk/by-partlabel/$env{ID_PART_ENTRY_NAME}"

/usr/lib/udev/rules.d/60-persistent-storage-dm.rules:31-32
  equivalent by-partuuid/by-partlabel links for dm partitions
```

## Reached D-Bus surface

Active `selfauth` could create a loop device from an owned image:

```text
loop_path=/org/freedesktop/UDisks2/block_devices/loop0
loop_dev=/dev/loop0
```

`Block.Format("gpt")` succeeded:

```text
Format_gpt_OK None
PartitionTable.Type = 'gpt'
```

The reachable partition-table interface has the expected mutators:

```text
CreatePartition(in t offset, in t size, in s type, in s name, in a{sv} options, out o created_partition)
CreatePartitionAndFormat(in t offset, in t size, in s type, in s name, in a{sv} options, in s format_type, in a{sv} format_options, out o created_partition)
```

`CreatePartition` hit a Docker-specific block node problem while wiping the new
partition, but UDisks still exposed the transient partition object:

```text
CreatePartition_ERR ... Error wiping newly created partition /dev/loop0p1:
  Failed to open the device '/dev/loop0p1': No such file or directory

CreatePartition_recovered_part_obj=/org/freedesktop/UDisks2/block_devices/loop0p1
```

The partition object exposed the target setters:

```text
interface org.freedesktop.UDisks2.Partition {
  SetType(in s type, in a{sv} options);
  SetName(in s name, in a{sv} options);
  SetUUID(in s uuid, in a{sv} options);
  SetFlags(in t flags, in a{sv} options);
  Resize(in t size, in a{sv} options);
  Delete(in a{sv} options);
}
```

## Setter results

`SetName` accepted benign names, path-looking names, and leading-option-looking
names:

```text
SetName('SAFEPART2')            -> OK
SetName('../../root/partpwn')   -> OK
SetName('--attributes=1:set:2') -> OK
```

Long shell/newline markers were rejected before helper execution by the GPT name
length check:

```text
SetName('semi;id>/root/active-udisks-partition-metadata-root')
  -> Max partition name length is 36 characters

SetName('$(id>/root/active-udisks-partition-metadata-root)')
  -> Max partition name length is 36 characters

SetName('line\nSYSTEMD_WANTS=active-udisks-partition-metadata.service')
  -> Max partition name length is 36 characters
```

`SetType` accepted valid GUIDs and rejected traversal/shell/newline strings as
invalid UUID syntax:

```text
SetType('0FC63DAF-8483-4772-8E79-3D69D8477DE4') -> OK
SetType('21686148-6449-6E6F-744E-656564454649') -> OK
SetType('../../root/parttype')                   -> Given type is not a valid UUID
SetType('$(id>/root/active-udisks-partition-metadata-root)') -> not a valid UUID
SetType('11111111-2222-4333-8444-555555555555\nSYSTEMD_WANTS=x.service') -> not a valid UUID
```

`SetUUID` accepted valid RFC-4122 UUIDs and rejected traversal/shell/newline strings:

```text
SetUUID('11111111-2222-4333-8444-555555555555') -> OK
SetUUID('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee') -> OK
SetUUID('../../root/partuuid')                  -> Provided UUID is not valid
SetUUID('$(id>/root/active-udisks-partition-metadata-root)') -> not valid
SetUUID('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\nSYSTEMD_WANTS=x.service') -> not valid
```

`SetFlags` accepted the tested numeric values but did not produce observable
privileged side effects:

```text
SetFlags(0x0000000000000000) -> OK
SetFlags(0x0000000000000001) -> OK
SetFlags(0x0000000000000002) -> OK
SetFlags(0x0000000000000004) -> OK
SetFlags(0x8000000000000000) -> OK
SetFlags(0xffffffffffffffff) -> OK
```

After every mutation, the loop partition had a sysfs object but no device node:

```text
/dev/loop0p1                  absent
/sys/class/block/loop0p1      present
```

The udev properties did not expose attacker-controlled `ID_PART_ENTRY_NAME` or
`ID_PART_ENTRY_UUID` for the loop partition:

```text
DEVLINKS=/dev/disk/by-loop-inode/0:60-5425972-part1 /dev/disk/by-diskseq/63-part1
DEVNAME=/dev/loop0p1
ID_PART_TABLE_TYPE=gpt
ID_PART_TABLE_UUID=b681d0bd-079b-459a-85f1-1af24a207c47
```

Only the host/system disk's existing by-partuuid link was present:

```text
/dev/disk/by-partuuid/7b0c49f7-01 -> ../../vda1
```

No root marker was created:

```text
ROOT_MARKER_ABSENT /root/active-udisks-partition-metadata-root
ROOT_MARKER_ABSENT /run/active-udisks-partition-metadata-root
ROOT_MARKER_ABSENT /tmp/active-udisks-partition-metadata-root
ROOT_PROOF=NO
```

## Why this is not a finding

This is a real active-user-to-root trust boundary: a non-admin active TTY user can
drive root UDisks partition tooling against a self-created loop disk, and the default
udev rules would create by-partlabel/by-partuuid symlinks from root-parsed partition
metadata if complete partition properties were exported. In this default Docker
Server target, the path stayed below LPE because `/dev/loop0p1` was absent,
`CreatePartition` could not finish wiping the new partition node, udev exported only
diskseq/loop-inode links for the transient partition, invalid type/UUID strings were
rejected, overlong shell/newline names were rejected, and accepted names did not
become a privileged file write, command, or systemd unit transition. No root context
executed attacker-controlled code.

## Cleanup

The probe deleted the loop and removed markers/scratch paths:

```text
Loop.Delete_OK
rm -rf /home/selfauth/active-udisks-partition-metadata
rm -rf /tmp/active-udisks-partition-metadata
rm -f /root/active-udisks-partition-metadata-root /run/active-udisks-partition-metadata-root /tmp/active-udisks-partition-metadata-root
```

The final health check was `running` with zero failed units.

## Why scanners may miss it

Generic D-Bus scanners see `CreatePartition`, `SetName`, `SetType`, `SetUUID`, and
`SetFlags` as root-service mutators, while filesystem scanners see udev rules that
turn `ID_PART_ENTRY_NAME` and `ID_PART_ENTRY_UUID` into root-created symlinks. The
actual exploitability depends on active-session polkit, loop-device ownership,
kernel partition-node creation, UDisks validation, and the exact udev properties
exported after mutation. Those cross-layer runtime details are easy to miss.

## Suggested fixes

No Ubuntu Security LPE fix is warranted from this negative result. Defense-in-depth
options:

```text
udisks2: reject or escape partition names containing path separators/control characters before passing them to helper tools.
udisks2: report failure if SetName/SetType/SetUUID cannot refresh and verify the resulting partition object state.
udev: keep by-partlabel/by-partuuid link generation escaped and ensure ID_PART_ENTRY_* cannot inject additional properties.
systemd/udev: keep systemd unit activation tied only to trusted SYSTEMD_WANTS properties, not arbitrary imported partition labels.
```
