# snapd/snap-confine current default deep pass, 2026-05-17

Verdict: negative. I did not validate a stock Ubuntu 24.04 Server default uid1001-to-root LPE through current snapd or snap-confine.

Target: `ubuntu24-server-lpe-target`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`

Probe: `pocs/snapd_current_default_deep_probe.sh`
Evidence log: `logs/snapd-current-default-deep-20260517.out`

## Default state proven

- Ubuntu 24.04.4 LTS, arm64 Docker target.
- `snapd 2.74.1+ubuntu24.04.4`, `systemd 255.4-1ubuntu8.15`, `polkitd 124-2ubuntu1.24.04.3`, `apparmor 4.0.1really4.0.1-0ubuntu0.24.04.6`.
- `snap list --all` as root and as uid1001 returned: `No snaps are installed yet. Try 'snap install hello-world'.`
- `snapd.service`, `snapd.socket`, and `snapd.seeded.service` were active/enabled.
- `snapd.socket` exposes `/run/snapd.socket` and `/run/snapd-snap.socket` with `SocketMode=0666`.
- `/usr/lib/snapd/snap-confine` is root-owned mode `0755` with file capabilities `cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p`.
- `snap-update-ns` and `snap-discard-ns` are root-owned `0755` without file capabilities.
- `snapd.autoimport.service` and `snapd.snap-repair.timer` were inactive with `ConditionResult=no` on classic, and `snap auto-import` as uid1001 returned `auto-import is disabled on classic`.
- The Docker target reports AppArmor not present, but the packaged snap-confine AppArmor profile was reviewed in the log for mount/profile rules.

## Source/config review

The probe unpacked/reused exact source `snapd-2.74.1+ubuntu24.04.4` and reviewed the current trust boundaries:

- REST access control uses Unix peer credentials from `SO_PEERCRED`; snapd passes both peer pid and uid to polkit checks.
- `openAccess` is restricted to `/run/snapd.socket`; `authenticatedAccess` and `rootAccess` are also restricted away from `/run/snapd-snap.socket`.
- `snapAccess` is restricted to `/run/snapd-snap.socket`, then snapctl receives the peer uid.
- Snap install/remove/refresh, interface changes, snap config, warnings, aliases, app service control, assertions write, and snapshots write are authenticated/admin-gated in current route definitions.
- `snap-confine` validates `SNAP_INSTANCE_NAME`, component names, and security tags; probes the real snap mount dir via `/proc/1/root/snap`; opens `snap-update-ns`/`snap-discard-ns` by fd from the expected snap-confine directory with `O_NOFOLLOW`; uses `mkdtemp("/tmp/snap.rootfs_XXXXXX")`; and validates seccomp profile paths as root-owned and not other-writable before loading.
- Lock helpers and atomic writers use `O_NOFOLLOW`/exclusive temp files plus rename/fsync patterns.

## REST results

Reachable read/default routes to uid1001 on `/run/snapd.socket` included:

```text
GET /v2/system-info                         200
GET /v2/snaps                               200 result:[]
GET /v2/find?name=core24                    200 store metadata only
GET /v2/interfaces                          200 result:{}
GET /v2/connections                         200 empty
GET /v2/changes                             200 empty
GET /v2/apps?select=service                 200 empty
GET /v2/model                               200 generic-classic model assertion
GET /v2/system-info/storage-encrypted       200 indeterminate
GET /v2/quotas                              200 empty
GET /v2/notices                             200 public/user-visible notices
GET /v2/assertions                          200 assertion type names
GET /v2/debug?aspect=features               200 endpoint inventory
```

Privileged paths were blocked before root hook/action execution:

```text
POST /v2/snaps store install                401 login-required
POST /v2/snaps local snap-path install      401 login-required
POST /v2/snaps multipart dangerous snap     401 login-required
snap install --dangerous local snap         access denied
snap try attacker tree                      access denied
POST /v2/interfaces connect                 401 login-required
PUT  /v2/snaps/system/conf                  401 login-required
POST /v2/assertions invalid assertion       401 login-required
POST /v2/debug add-warning                  403 login-required
POST /v2/notices snap-run-inhibit via curl  403 only snap command can record notices
POST /v2/warnings okay                      401 login-required
POST /v2/aliases alias                      401 login-required
POST /v2/apps start                         401 login-required
POST /v2/quotas ensure                      403 login-required
POST /v2/model                              403 login-required
POST /v2/systems install-like               403 login-required
```

The local snap included an install hook that would write `/root/snapd_current_default_deep_root_marker`, `/tmp/snapd_current_default_deep_tmp_marker`, and a suid shell marker if any unauthenticated install path reached root hook execution. All marker checks returned `ROOT_PROOF_CANDIDATE=NO`.

On `/run/snapd-snap.socket`, normal uid1001 processes were not accepted as snap peers:

```text
GET /v2/system-info                         403 could not determine snap name for pid
GET /v2/system-info with spoof headers      403 could not determine snap name for pid
POST /v2/snapctl get                        400 outside of a snap
POST /v2/snapctl set                        403 cannot use set with uid 1001
```

## snap-confine results

Direct uid1001 execution reaches the file-capability boundary but did not execute attacker code:

- Strict/default invocation ignored attacker `SNAP_MOUNT_DIR=/tmp/...`, probed `/snap`, opened real helper fds, and failed at `cannot locate base snap core`.
- `--base core24` failed at `cannot locate base snap core24`.
- `--classic` dropped effective caps before payload exec and failed loading the missing root-owned seccomp profile: `cannot stat /var/lib/snapd/seccomp: No such file or directory`.
- Traversal and malformed tags were rejected with `security tag ... not allowed`; a syntactically valid hook tag still failed at the missing base snap.
- Direct `snap-update-ns` and `snap-discard-ns` as uid1001 failed for missing `CAP_SYS_ADMIN`.
- In a user namespace, namespace uid0 mapped back to host uid1001. Fake `/snap`, `/var/lib/snapd`, and `/run/snapd` bind mounts succeeded only inside that namespace; snap-confine reached mount namespace initialization and timed out without running the payload or creating host-root artifacts.

## Writable/race surface

uid1001 had no writable paths under `/run/snapd`, `/var/lib/snapd`, `/var/snap`, `/snap`, or `/usr/lib/snapd`. Direct touch attempts in `/run/snapd/lock`, `/run/snapd/ns`, `/var/lib/snapd`, `/var/lib/snapd/snaps`, `/snap`, and `/var/snap` failed. Precreating a lock symlink in `/run/snapd/lock` failed with permission denied, and hardlinking `/usr/lib/snapd/snap-confine` into `/tmp` failed with `Operation not permitted`.

## Default snap hooks/helpers

There are no default installed snap hooks: `/snap` only contains `README`, `/var/lib/snapd/snaps` is empty except `partial`, and `/var/lib/snapd/seed` is absent. User-invokable defaults (`snap version`, `snap debug sandbox-features`, `snap run not-installed`, `snap auto-import`, `snap known account`) did not cross into root execution; `snap run not-installed` reported the snap was not installed, and auto-import is disabled on classic.

## Cleanup

The probe removed `/tmp/snapd-current-default-deep*`, the local snap, root/tmp/suid markers, userns proof files, and `/run/snapd/lock/scd*.lock`. Final health showed `snapd.socket`, `snapd.service`, and `snapd.seeded.service` active, no installed snaps, and no root markers.

Final result: `FINAL_ROOT_PROOF=NO`.
