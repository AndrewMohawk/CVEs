# Negative: PAM namespace and user runtime boundaries

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server image. Attacker identity was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no uid1001 -> root local privilege escalation was validated in this lane. The default PAM namespace boot helper, logind self-linger path, and `user@.service` runtime directory transitions are installed and reachable, but the tested trust boundaries stayed constrained to root-owned configuration files or the caller's own uid.

Artifacts:

```text
pocs/pam_namespace_user_runtime_probe.sh
logs/pam-namespace-user-runtime.out
```

## Default package and file proof

The target is Ubuntu 24.04.4 LTS. Relevant default packages and versions:

```text
dbus                         1.14.10-4ubuntu4.1
libpam-modules:arm64         1.5.3-5ubuntu5.5
libpam-runtime               1.5.3-5ubuntu5.5
polkitd                      124-2ubuntu1.24.04.3
systemd                      255.4-1ubuntu8.15
```

Default files and directories:

```text
/usr/sbin/pam_namespace_helper                  0755 root:root
/usr/lib/systemd/systemd-user-runtime-dir       0755 root:root
/etc/security/namespace.conf                    0644 root:root
/var/lib/systemd/linger                         0755 root:root
/run/user                                       0755 root:root
/run/systemd/users                              0755 root:root
/run/systemd/sessions                           0755 root:root
```

The relevant installed code/config paths are:

```text
/usr/sbin/pam_namespace_helper:7-12
  sed ... < /etc/security/namespace.conf | while read ...; do
      mkdir --parents --mode=0 -Z "$instance_prefix"
  done

/usr/lib/systemd/system/pam_namespace.service:10-12
  ExecStart=/usr/sbin/pam_namespace_helper
  Type=oneshot

/usr/lib/systemd/system/user@.service:31-35
  User=%i
  PAMName=systemd-user
  ExecStart=/usr/lib/systemd/systemd --user

/usr/lib/systemd/system/user-runtime-dir@.service:85-90
  ExecStart=/usr/lib/systemd/systemd-user-runtime-dir start %i
  ExecStop=/usr/lib/systemd/systemd-user-runtime-dir stop %i
```

## PAM namespace helper

The helper is not setuid and is only root-run through `pam_namespace.service`. The default `/etc/security/namespace.conf` contains only commented example namespace rules. The attacker could not modify the helper, the namespace config, PAM stack files, or systemd unit/drop-in paths:

```text
/etc/security/namespace.conf: Permission denied
/usr/sbin/pam_namespace_helper: Permission denied
/etc/pam.d/common-session: Permission denied
/usr/lib/systemd/system/pam_namespace.service: Permission denied
```

Direct execution with attacker-controlled `PATH` reached fake `sed` only as uid1001:

```text
helper_rc=0
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
no_fake_mkdir
```

Starting the system unit as uid1001 was polkit-gated:

```text
Failed to start pam_namespace.service: Interactive authentication required.
start_rc=1
```

A root-started `pam_namespace.service` did not execute the attacker's fake helpers.

## logind self-linger and user runtime

The interesting reachable primitive is `loginctl enable-linger attacker` from the unprivileged account. It succeeds and asks root/logind to create a root-owned linger file for the caller:

```text
self_linger_rc=0
-rw-r--r-- root:root /var/lib/systemd/linger/attacker
```

The same interface did not allow targeting root or path traversal:

```text
loginctl enable-linger root     -> Interactive authentication required
loginctl enable-linger ../root  -> Failed to look up user ../root: No such process
```

After simulating the root-managed linger activation with `systemctl start user@1001.service`, the user manager and runtime directory were owned by `attacker`, not root:

```text
Active: active (running) ... user@1001.service
Main PID: ... /usr/lib/systemd/systemd --user
/run/user/1001 drwx------ attacker:attacker
/run/user/1001/bus srw-rw-rw- attacker:attacker
```

Running a user transient unit through that bus produced uid1001 code execution and could not create the root marker:

```text
Running as unit: pam-namespace-user-runtime-probe.service
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
no_root_marker_from_user_service
```

The attacker also could not write or symlink over root-owned runtime metadata:

```text
/run/systemd/users/1001 0644 root:root
ln ... Permission denied
write ... Permission denied
/var/lib/systemd/linger/attacker 0644 root:root
ln ... Permission denied
write ... Permission denied
```

## Cleanup

The probe removed its work directory, fake helper files, transient markers, and any test linger state:

```text
ABSENT /root/pam_namespace_user_runtime_root_marker
ABSENT /home/attacker/pam_namespace_user_runtime
ABSENT /var/lib/systemd/linger/attacker
ABSENT /var/lib/systemd/linger/selfauth
ABSENT /tmp/pam_namespace_user_runtime_user_service_id
systemctl is-system-running -> running
```

## Conclusion

Negative. The default PAM namespace helper and logind/user-runtime transitions are real local privilege boundaries, but on this stock Ubuntu Server target they did not provide a root LPE. The only unprivileged privileged-write behavior found was logind's intended self-linger creation for the caller's own account; the resulting service manager runs as the caller and cannot write root-owned state.
