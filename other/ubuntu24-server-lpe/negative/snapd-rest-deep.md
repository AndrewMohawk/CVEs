# snapd REST deep probe

Verdict: negative. I did not validate a stock Ubuntu 24.04 Server default uid1001-to-root LPE through snapd REST API routes on `/run/snapd.socket` or `/run/snapd-snap.socket`.

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 LTS. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Evidence log: `logs/snapd-rest-deep.out`. Probe: `pocs/snapd_rest_deep_probe.sh`.

## Default reachability

The package and sockets are default reachable:

```text
snapd  2.74.1+ubuntu24.04.4
systemd 255.4-1ubuntu8.15
polkitd 124-2ubuntu1.24.04.3

snapd.service: active, enabled
snapd.socket: active, enabled
snapd.seeded.service: active, enabled

/run/snapd.socket      srw-rw-rw- 666 root:root
/run/snapd-snap.socket srw-rw-rw- 666 root:root
```

`snapd.socket` packages both `ListenStream=/run/snapd.socket` and `ListenStream=/run/snapd-snap.socket` with `SocketMode=0666`. The packaged polkit actions `io.snapcraft.snapd.manage`, `manage-interfaces`, `manage-configuration`, and `manage-fde` require `auth_admin` or `auth_admin_keep`.

Default snap state remained empty before and after the run:

```text
No snaps are installed yet. Try 'snap install hello-world'.
```

## Probe coverage

Read-only routes on `/run/snapd.socket` were reachable to uid1001: `/v2/system-info`, `/v2/snaps`, `/v2/apps?select=service`, `/v2/interfaces`, `/v2/connections`, `/v2/changes`, `/v2/snapshots`, `/v2/model`, and `/v2/notices`.

Privileged operations were authorization-gated:

```text
POST /v2/snaps install/refresh/remove                      401 login-required
POST /v2/snaps JSON snap-path install and try directory     401 login-required
POST /v2/snaps multipart dangerous local snap upload        401 login-required
snap install --dangerous /tmp/snapd-rest-deep-lpe_1.0...   access denied
snap try /tmp/snapd-rest-deep/snap-src                      access denied
POST /v2/interfaces connect                                 401 login-required
POST /v2/assertions invalid assertion                       401 login-required
PUT  /v2/snaps/system/conf path/env-like values             401 login-required
POST /v2/snapshots save/restore/import raw/multipart        401 login-required
POST /v2/create-user sudoer                                 403 login-required
POST /v2/systems install-like action                        403 login-required
POST /v2/system-recovery-keys reveal                        403 login-required
```

The local snap payload had an install hook that would write `/root/snapd_rest_deep_root_marker` and `/tmp/snapd_rest_deep_tmp_marker` if any unauthenticated install or try path reached root hook execution. The snapshot/import payload included relative, absolute, and traversal-like marker members. Every marker check returned `ROOT_PROOF=NO` and `TMP_MARKER=NO`; final verdict was `FINAL_ROOT_PROOF=NO`.

The snap-confined socket did not trust a normal process or spoofed headers:

```text
GET /v2/system-info on /run/snapd-snap.socket                403 could not determine snap name for pid
GET /v2/snaps with X-Snapd-Snap/X-Snapd-Context spoofing     403 could not determine snap name for pid
POST /v2/snapctl get/services                                400 outside of a snap
POST /v2/snapctl set system marker                           403 cannot use set with uid 1001
```

Cleanup removed `/tmp/snapd-rest-deep`, the local snap, assertion/import payloads, `/root/snapd_rest_deep_root_marker`, and `/tmp/snapd_rest_deep_tmp_marker`. `snapd.service`, `snapd.socket`, and `snapd.seeded.service` remained active, with no failed systemd units and no installed snaps.

Conclusion: snapd's default REST sockets are world-reachable, and several read-only APIs are accessible to a normal non-sudo user, but every tested root-write/root-exec path was gated by snapd/polkit authorization or snap peer validation before attacker-controlled snap hooks, config values, assertions, snapshot imports, or snapctl operations could execute as root.
