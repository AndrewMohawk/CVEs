# OpenSSH Local Deep Probe - Negative

Target: `ubuntu24-server-lpe-target`, image `ubuntu24-server-default-lpe:20260516-standard`, stock Ubuntu 24.04.4 Server default state.

Result: no local privilege escalation was found. This deeper pass did not duplicate `negative/openssh-default-local-boundaries.md`; it specifically re-tested OpenSSH client/helper trust boundaries reachable by uid 1001 with user-controlled config, sockets, provider paths, symlinks, and client helper commands.

Artifacts:

- Probe: `pocs/openssh_local_deep_probe.sh`
- Log: `logs/openssh-local-deep.out`

## Default-install and default-reachability proof

- `openssh-client` is installed as `1:9.6p1-3ubuntu13.16`; `openssh-server` is not installed (`un`); `openssh-sftp-server` is not installed; `libutempter0:arm64` is installed as `1.2.1-3build1` (`logs/openssh-local-deep.out`:32-35).
- `ssh.service` and `ssh.socket` are not found/inactive, and the only TCP listeners are systemd-resolved loopback DNS sockets (`logs/openssh-local-deep.out`:68-78).
- Server-side OpenSSH paths are absent by default: `/usr/sbin/sshd`, `/etc/ssh/sshd_config`, `/etc/pam.d/sshd`, `/etc/ssh/ssh_host_*`, and `/usr/lib/openssh/sftp-server` (`logs/openssh-local-deep.out`:167-172).
- Installed privileged/client-adjacent helpers are `/usr/bin/ssh-agent` setgid `_ssh`, `/usr/lib/openssh/ssh-keysign` setuid root, and `utempter` setgid `utmp`; `ssh-pkcs11-helper` and `ssh-sk-helper` are non-setuid root-owned binaries (`logs/openssh-local-deep.out`:150-165).

## Boundary checks

- The attacker cannot write OpenSSH root-owned config/helper directories or files under `/etc/ssh`, `/etc/ssh/ssh_config.d`, `/usr/lib/openssh`, `/usr/lib/systemd/user`, `/etc/X11`, or `/usr/sbin` (`logs/openssh-local-deep.out`:318-331).
- `ssh-keysign` remains gated by global `/etc/ssh/ssh_config`; direct execution returns `ssh-keysign not enabled in /etc/ssh/ssh_config`, hostile `PATH`/`HOME`/`SSH_ASKPASS`/`LD_PRELOAD` did not create a root marker, and hostbased auth did not reach `ssh-keysign` before localhost connection refusal (`logs/openssh-local-deep.out`:452-470).
- `ssh-agent` drops to uid/gid 1001 despite the file being setgid `_ssh`, creates attacker-owned `0700`/`0600` socket paths, and refuses a symlinked custom socket path pointing at `/etc/shadow` without modifying the target (`logs/openssh-local-deep.out`:475-494).
- PKCS11 and security-key paths stayed in attacker context: `ssh-add -s` ran under an attacker-owned agent and refused the attacker-owned fake provider; `ssh-keygen -t ed25519-sk -w <attacker path>` invoked non-setuid `/usr/lib/openssh/ssh-sk-helper` and failed provider validation (`logs/openssh-local-deep.out`:497-514).
- The user `ssh-agent.service` is gated by `ConditionPathExists=/etc/X11/Xsession.options`, and `agent-launch` only execs `ssh-agent` when `/etc/X11/Xsession.options` contains `use-ssh-agent`; the direct attacker trigger created no socket (`logs/openssh-local-deep.out`:229-246, 248-295, 517-520).
- `ControlPath`, `ProxyCommand`, `scp -S`, and `sftp -S` user-controlled helper paths executed only as uid 1001 and did not write through symlinks to `/etc/shadow` (`logs/openssh-local-deep.out`:523-544).
- `utempter` is only a setgid-`utmp` adjacency; neither `ssh` nor `ssh-keysign` links it, and direct execution did not produce root (`logs/openssh-local-deep.out`:546-560).

## Trigger and cleanup

Re-run:

```sh
cd /Users/andrewmohawk/Documents/UbuntuLPE/ubuntu24-server-lpe
./pocs/openssh_local_deep_probe.sh ubuntu24-server-lpe-target > logs/openssh-local-deep.out 2>&1
```

Root proof check was negative: `no root marker created by OpenSSH deep probe` (`logs/openssh-local-deep.out`:564-566). Cleanup verification found no OpenSSH probe temp files and no attacker-owned `ssh-agent` processes, and the container ended `running` with zero failed units (`logs/openssh-local-deep.out`:575-580).

## Why scanners might miss or mis-rank this

SUID scanners may flag `ssh-keysign` and SGID scanners may flag `ssh-agent`, but the exploitable server-side surface is absent in this default target. Config scanners may over-rank `AuthorizedKeysCommand`, `AuthorizedPrincipalsCommand`, `ChrootDirectory`, `ForceCommand`, PAM session hooks, host keys, and SFTP server helpers without first proving that `openssh-server`, `sshd_config`, host keys, PAM sshd config, `ssh.service`, or `ssh.socket` exist. Client-feature scanners may also miss that `ssh-agent` drops the `_ssh` egid and that ProxyCommand/scp/sftp helper execution remains uid 1001.

## Suggested fixes or hardening notes

No Ubuntu Security LPE fix is suggested from this default state because no privilege increase was validated. Hardening worth preserving: keep `ssh-keysign` disabled unless explicitly enabled in root-owned global config, keep host keys/server PAM absent when `openssh-server` is not installed, keep `ssh-agent` dropping setgid privileges, and keep the user `ssh-agent.service` gated away from non-graphical server sessions.
