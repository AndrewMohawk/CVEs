# misc privileged helpers: negative

Target: `ubuntu24-server-lpe-target`, Ubuntu 24.04.4 Server default package set.
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no uid1001-to-root LPE found in the bounded non-account helper surface.

## Default install and modes

Validated default packages:

```text
openssh-client    1:9.6p1-3ubuntu13.16    ii
libutempter0      1.2.1-3build1           ii
dbus              1.14.10-4ubuntu4.1      ii
mtr-tiny          0.95-1.1ubuntu0.1       ii
iputils-ping      3:20240117-1ubuntu0.1   ii
```

Validated helper modes:

```text
-rwsr-xr-x 4755 root root       /usr/lib/openssh/ssh-keysign
-rwxr-sr-x 2755 root utmp       /usr/lib/aarch64-linux-gnu/utempter/utempter
-rwxr-sr-x 2755 root _ssh       /usr/bin/ssh-agent
-rwxr-xr-x 0755 root root       /usr/bin/mtr-packet    cap_net_raw=ep
-rwxr-xr-x 0755 root root       /usr/bin/ping          cap_net_raw=ep
-rwsr-xr-- 4754 root messagebus /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

Only group-owned writable targets for `_ssh`, `utmp`, and `messagebus` were login accounting files:

```text
660 root utmp /var/log/btmp
664 root utmp /var/log/lastlog
664 root utmp /var/log/wtmp
```

## Tested boundaries

`ssh-keysign`:

- Default `/etc/ssh/ssh_config` includes only root-owned `/etc/ssh/ssh_config.d/*.conf`; no default `EnableSSHKeysign yes`.
- `/etc/ssh` contains no default host private keys in this stock Docker server target.
- A hostile attacker `HOME`, `PATH`, `LD_PRELOAD`, and per-user SSH config containing `EnableSSHKeysign yes`, `HostbasedAuthentication yes`, and `Match exec "id > /tmp/..."` did not enable the setuid helper.
- Direct helper trigger returned `ssh-keysign not enabled in /etc/ssh/ssh_config`.
- The same hostile config's `Match exec` ran only when parsed by the normal `ssh` client and produced `uid=1001(attacker)`, proving no root helper exec through user config.

`ssh-agent`:

- `ssh-agent command` dropped to `uid=1001 gid=1001 groups=1001`; the command did not inherit `_ssh`.
- `SSH_PKCS11_HELPER=/home/attacker/... ssh-add -s ...` caused the helper-exec path to run, but the marker showed `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.
- `ssh-agent -a` created an attacker-owned `srw-------` socket.
- Binding `-a` to an attacker symlink pointing at `/root/mischelpers_probe_root_target` failed with `Address already in use`; no root target was created.

`utempter`:

- The libutempter path is reachable with an attacker PTY and can add an attacker login-accounting record: `attacker pts/0 ... (mischelpers-probe)`.
- `utempter_remove_record()` removed the active record; `who | grep mischelpers-probe` was empty after cleanup.
- Impact is limited to `utmp`/`wtmp` accounting mutation as `utmp`, not root execution or arbitrary file write. The helper derives the line from the PTY fd and validates ownership/device state; no attacker path argument reached root file access.

`ping` and `mtr-packet`:

- `mtr-packet` is reachable and can send ICMP probes as intended.
- Runtime status for `mtr-packet` remained `Uid: 1001`, `Gid: 1001`, `Groups: 1001`, with only `CapEff=0000000000002000` (`CAP_NET_RAW`).
- Runtime status for `ping` remained `Uid: 1001`, `Gid: 1001`, `Groups: 1001`; after socket setup `CapEff=0`.
- No file path, helper exec, uid/gid transition, or root-write primitive was exposed.

`dbus-daemon-launch-helper`:

- Direct attacker execution is blocked by mode `4754 root:messagebus`: `Permission denied`.
- The system bus is active, and root-owned system service files are present under `/usr/share/dbus-1/system-services`.
- An attacker-controlled `$XDG_DATA_HOME/dbus-1/system-services/com.attacker.Misc.service` was ignored by the system bus: `The name com.attacker.Misc was not provided by any .service files`.
- Existing activatable services are root-owned service definitions and require their own D-Bus/polkit authorization; this helper surface did not provide arbitrary `Exec=` control.

## Cleanup

Removed probe files under `/tmp/mischelpers_probe*` and `/home/attacker/mischelpers_probe`, killed no persistent probe-named `ssh-agent`, verified no active `who` record containing `mischelpers`, and verified `/root/mischelpers_probe_root_target` was not created.

## Conclusion

This surface has privileged helper edges, but each default boundary held:

- `ssh-keysign` is disabled by global config and has no default host keys.
- `ssh-agent` helper execution drops to the attacker identity.
- `utempter` grants only bounded login accounting writes.
- `ping`/`mtr-packet` expose only packet capabilities.
- `dbus-daemon-launch-helper` is not directly executable by the attacker and only consumes root-owned system service files.

No valid stock Ubuntu 24.04 Server local privilege escalation was found.
