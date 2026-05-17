# Negative: active-seat UDisks loop devices into root udev storage metadata

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`  
Packages: `udisks2 2.10.1-6ubuntu1.3`, `bcache-tools 1.0.8-5build1`, `mdadm 4.3-1ubuntu2.1`, `systemd/udev 255.4-1ubuntu8.15`  
Active-seat user used for the authorized path: `uid=1002(selfauth) gid=1002(selfauth)`; the target also has `uid=1001(attacker)`.

## Result

No real selfauth-to-root LPE was validated in the active-seat UDisks loop setup -> root udev storage metadata path.

With a real tty1/logind active session, `selfauth` can ask UDisks to create loop devices and mount filesystems without an admin prompt. Root udev then probes attacker-controlled loop images. The tested metadata did not create attacker-controlled root code execution, did not import `SYSTEMD_WANTS`, and did not create path-traversing root symlinks.

## Active-seat and UDisks authorization proof

The one-shot tty1 login was active when the UDisks operations ran:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
tty=/dev/tty1 XDG_SESSION_ID=109
Id=109
User=1002
Name=selfauth
Seat=seat0
TTY=tty1
Remote=no
Type=tty
Class=user
Active=yes
State=active
```

UDisks loop setup and mount were authorized from that active session:

```text
Mapped file /tmp/as-udisks-udev-seat/ext4.img as /dev/loop0.
Mounted /dev/loop0 at /media/selfauth/A_.._B=1
/media/selfauth/A_.._B=1 /dev/loop0 ext4 rw,nosuid,nodev,relatime,errors=remount-ro
```

The `nosuid,nodev` mount options blocked the usual active-user mounted-image setuid/device path.

## Rule and helper boundaries

Relevant installed rule snippets:

```text
/usr/lib/udev/rules.d/69-bcache.rules:16 IMPORT{program}="probe-bcache -o udev $tempnode"
/usr/lib/udev/rules.d/69-bcache.rules:18 ENV{ID_FS_UUID_ENC}=="?*", SYMLINK+="disk/by-uuid/$env{ID_FS_UUID_ENC}"
/usr/lib/udev/rules.d/69-bcache.rules:22 RUN+="bcache-register $tempnode"
/usr/lib/udev/rules.d/69-bcache.rules:26 IMPORT{program}="bcache-export-cached $tempnode"
/usr/lib/udev/rules.d/69-bcache.rules:27 ENV{CACHED_UUID}=="?*", SYMLINK+="bcache/by-uuid/$env{CACHED_UUID}"
/usr/lib/udev/rules.d/69-bcache.rules:28 ENV{CACHED_LABEL}=="?*", SYMLINK+="bcache/by-label/$env{CACHED_LABEL}"

/usr/lib/udev/rules.d/80-udisks2.rules:20 IMPORT{program}="/bin/sh -c '/sbin/mdadm --examine --export $tempnode | /bin/sed s/^MD_/UDISKS_MD_MEMBER_/g'"

/usr/lib/udev/rules.d/60-persistent-storage.rules:140 ENV{ID_FS_USAGE}=="filesystem|other|crypto", ENV{ID_FS_UUID_ENC}=="?*", SYMLINK+="disk/by-uuid/$env{ID_FS_UUID_ENC}"
/usr/lib/udev/rules.d/60-persistent-storage.rules:141 ENV{ID_FS_USAGE}=="filesystem|other|crypto", ENV{ID_FS_LABEL_ENC}=="?*", SYMLINK+="disk/by-label/$env{ID_FS_LABEL_ENC}"
/usr/lib/udev/rules.d/60-persistent-storage.rules:149 ENV{ID_PART_ENTRY_SCHEME}=="gpt", ENV{ID_PART_ENTRY_NAME}=="?*", SYMLINK+="disk/by-partlabel/$env{ID_PART_ENTRY_NAME}"
/usr/lib/udev/rules.d/60-persistent-storage.rules:157 ENV{ID_LOOP_BACKING_DEVICE}!="", ENV{ID_LOOP_BACKING_INODE}!="", SYMLINK+="disk/by-loop-inode/$env{ID_LOOP_BACKING_DEVICE}-$env{ID_LOOP_BACKING_INODE}$env{.PART_SUFFIX}"
/usr/lib/udev/rules.d/60-persistent-storage.rules:163 ENV{ID_LOOP_BACKING_FILENAME_ENC}!="", SYMLINK+="disk/by-loop-ref/$env{ID_LOOP_BACKING_FILENAME_ENC}$env{.PART_SUFFIX}"
```

## Filesystem and loop-name metadata

An ext4 label containing slashes and `=` was imported as raw label data but symlinked only through the encoded property:

```text
ID_FS_LABEL=A/../B=1
ID_FS_LABEL_ENC=A\x2f..\x2fB=1
DEVLINKS=/dev/disk/by-diskseq/71 /dev/disk/by-label/A\x2f..\x2fB=1 /dev/disk/by-loop-inode/0:64-19045659 /dev/disk/by-uuid/9f6fa219-28bd-4bd0-bf6f-6b372197c7f0
/dev/disk/by-label/A\x2f..\x2fB=1 -> ../../loop0 (root:root 777)
```

A backing filename containing `SYSTEMD_WANTS=evil.service` did not produce `ID_LOOP_BACKING_FILENAME_ENC` or `/dev/disk/by-loop-ref`; this UDisks path produced only inode-based loop links:

```text
Mapped file /tmp/as-udisks-udev-seat/loop ref SYSTEMD_WANTS=evil.service as /dev/loop0.
ID_LOOP_BACKING_DEVICE=0:64
ID_LOOP_BACKING_INODE=19045667
/dev/disk/by-loop-inode/0:64-19045667 -> ../../loop0 (root:root 777)
```

## GPT partition labels

The hostile image did contain a GPT partition name:

```text
Name: ../SYSTEMD_WANTS=evil
```

In the provided Docker target, active-seat UDisks loop setup exposed the parent loop's GPT table but did not produce a usable partition-device label symlink:

```text
ID_PART_TABLE_TYPE=gpt
ID_PART_TABLE_UUID=865c3f0f-d666-4fb8-8a71-3774a58b36c6
/dev/disk/by-loop-inode/0:64-19045671-part1 -> ../../loop0p1
no /dev/disk/by-partlabel entry
```

A root-assisted `losetup -P` check also failed to produce a `/dev/loop0p1` node on this target, so the partition label path was not an active selfauth-to-root primitive in this Docker kernel configuration.

## bcache

For a selfauth-owned bcache backing image, root udev imported only UUID/type and created the normal encoded UUID link:

```text
ID_FS_TYPE=bcache
ID_FS_UUID=b4382f0a-64c0-417b-825f-76f2648fcca9
ID_FS_UUID_ENC=b4382f0a-64c0-417b-825f-76f2648fcca9
/dev/disk/by-uuid/b4382f0a-64c0-417b-825f-76f2648fcca9 -> ../../loop0 (root:root 777)
```

The root registration helper ran but did not create a bcache device in this Docker target:

```text
systemd-udevd: loop0: Process 'bcache-register /dev/loop0' failed with exit code 1.
```

No `CACHED_UUID`, `CACHED_LABEL`, `/dev/bcache/by-label`, or `/dev/bcache/by-uuid` properties/links appeared from the active loop.

The `bcache-export-cached` helper path was still checked with a valid bcache superblock containing a hostile label. `bcache-super-show` percent-encoded slash and equals before the helper's awk emitted `CACHED_LABEL`:

```text
dev.label        ..%2fSYSTEMD_WANTS%3devil.service
CACHED_UUID=dabadd11-f1bd-47dd-98ba-39a6ac7a11f7
CACHED_LABEL=..%2fSYSTEMD_WANTS%3devil.service
```

That is a single property value, not a new udev assignment. It contains no raw `/`, newline, or `SYSTEMD_WANTS=` property line.

## mdadm export

A crafted mdadm 1.2 member with a raw newline in the array name was accepted by `mdadm --examine`, but `--export` truncated at newline:

```text
mdadm --examine:
Name : evil
SYSTEMD_WANTS=x.service

mdadm --examine --export:
MD_LEVEL=raid1
MD_DEVICES=2
MD_NAME=evil
MD_ARRAY_SIZE=33.55MB
MD_UUID=00112233:44556677:8899aabb:ccddeeff
MD_UPDATE_TIME=1778940380
MD_DEV_UUID=ffeeddcc:bbaa9988:77665544:33221100
MD_EVENTS=1
```

The upstream mdadm 4.3 `export_examine_super1()` code does this explicitly:

```text
for (i = 0; i < 32; i++)
    if (sb->set_name[i] == '\n' || sb->set_name[i] == '\0') {
        len = i;
        break;
    }
if (len)
    printf("MD_NAME=%.*s\n", len, sb->set_name);
```

When the same hostile member was attached through active-seat UDisks and root udev imported `80-udisks2.rules`, the resulting udev database contained only prefixed, truncated mdadm properties:

```text
ID_FS_LABEL=evil_SYSTEMD_WANTS=x.service
ID_FS_LABEL_ENC=evil\x0aSYSTEMD_WANTS=x.service
ID_FS_TYPE=linux_raid_member
ID_FS_USAGE=raid
UDISKS_MD_MEMBER_LEVEL=raid1
UDISKS_MD_MEMBER_DEVICES=2
UDISKS_MD_MEMBER_NAME=evil
UDISKS_MD_MEMBER_ARRAY_SIZE=33.55MB
UDISKS_MD_MEMBER_UUID=00112233:44556677:8899aabb:ccddeeff
UDISKS_MD_MEMBER_DEV_UUID=ffeeddcc:bbaa9988:77665544:33221100
UDISKS_MD_MEMBER_EVENTS=1
```

There was no imported `SYSTEMD_WANTS`, and the raw newline label reached only encoded label fields, not symlink paths.

## Root proof and cleanup

No root marker was created:

```text
/root/as-udisks-udev-pwn absent
/run/as-udisks-udev-pwn absent
/tmp/as-udisks-udev-pwn absent
```

Cleanup performed:

```text
detached test loop devices
removed /tmp/as-udisks-udev-seat, /tmp/as-bcache-helper-valid, /tmp/mdadm-src
removed /home/selfauth/as-udisks-seat-probe.* and /home/selfauth/as-mdmember-hostile.img
restored getty@tty1.service active
verified no losetup entries for as-udisks remain
```

## Conclusion

The active-seat UDisks authorization makes this surface reachable, but the tested root udev metadata paths did not cross into root execution. Filesystem labels use encoded symlink variables, UDisks loop setup did not expose attacker-controlled loop-ref strings, bcache backing devices only reached UUID/type plus a failed fixed helper, `bcache-export-cached` percent-encodes hostile labels, and mdadm export truncates newline-bearing names before udev imports them under the `UDISKS_MD_MEMBER_` prefix.
