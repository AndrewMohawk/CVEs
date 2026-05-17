# snap-confine fake base deep probe

Target: `ubuntu24-server-lpe-target`

Verdict: negative. I did not validate a uid1001-to-host-root or retained-privileged-capability execution path through direct `/usr/lib/snapd/snap-confine` on stock Ubuntu 24.04 Server with no installed snaps.

## Baseline proven

Probe: `pocs/snap_confine_fake_base_deep_probe.sh`

Log: `logs/snap-confine-fake-base-deep.out`

The target is Ubuntu 24.04.4 with `snapd 2.74.1+ubuntu24.04.4`. `snap list --all` returns no installed snaps. `/usr/lib/snapd/snap-confine` is root-owned mode `0755` and has permitted file capabilities:

```text
cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
```

`snap-update-ns` has no file capabilities. `/snap`, `/var/lib/snapd`, `/var/lib/snapd/snaps`, `/run/snapd`, `/run/snapd/ns`, and `/run/snapd/lock` are root-owned and not writable by uid1001. The uid1001 install paths are still gated: `snap install hello-world` returns `access denied`, `/run/snapd.socket` install POST returns `401 Unauthorized`, and `/run/snapd-snap.socket` system-info returns `403 Forbidden`.

## Probe coverage

The script created attacker-owned fake state under `/tmp/scfbd-work`, including fake `/snap/core/current/meta/snap.yaml`, fake `/snap/snapd/current`, fake `/snap/scfbd/current/meta/snap.yaml`, an attacker payload, fake `snap-update-ns`/`snap-discard-ns` in `PATH`, and a fake `/var/lib/snapd/mount/snap.scfbd.fstab`.

Direct uid1001 execution with realistic `SNAP_*` state reached the file-capability boundary and raised effective caps inside `snap-confine`, but it still probed `SNAP_MOUNT_DIR` as `/snap`, opened the real helpers by fd, selected `base snap: core`, and failed before payload execution:

```text
cannot locate base snap core: No such file or directory
```

`SNAP_MOUNT_DIR=/tmp/scfbd-work/fake-snap`, fake helper `PATH`, `SNAP_BASE=none`, component-style tags, hook tags, malformed tags, and traversal tags did not redirect execution. Malformed/traversal tags were rejected or still reached the same missing-base gate.

User namespace probes showed namespace root is not host root. A marker created as namespace uid 0 was host-owned by uid1001 outside the namespace. Without a pid namespace, fake `/snap` bind mounts did not affect `snap-confine`'s canonical `/proc/1/root/snap` check and failed with:

```text
cannot fstatat canonical snap directory: Permission denied
```

With user+mount+pid namespaces and fake `/snap`, `/proc/1/root/snap` could be made to point at the fake snap tree, but `snap-confine` then failed on host-root-owned snapd runtime state:

```text
cannot open lock file: /run/snapd/lock/.lock: Permission denied
```

When fake `/snap`, fake `/var/lib/snapd`, and fake `/run/snapd` were all bind-mounted in the namespace, `snap-confine` got past lock opening and reached `initializing mount namespace: scfbd`, then hung until the harness timeout terminated it. The payload never ran and no host-root artifact or suid shell was created.

## Result

No `PAYLOAD_RAN`, `/root/scfbd-root-proof`, `/tmp/scfbd-host-root-proof`, or `/tmp/scfbd-host-root-proof.suid` artifact appeared in any case. Final health still showed snapd active and no snaps installed. Cleanup removed `/tmp/scfbd-work`, `/tmp/scfbd-userns-owner-proof`, root-proof markers, and the named `/run/snapd/lock/scfbd.lock` side effect.

Key reason: in the host namespace, direct `snap-confine` cannot satisfy the missing default `core` base from attacker-controlled env or fake `/tmp` state; in user/pid/mount namespaces, fake base state can advance parsing but privileges are namespace-scoped and root-owned snapd runtime locks/state remain a boundary before attacker code execution.
