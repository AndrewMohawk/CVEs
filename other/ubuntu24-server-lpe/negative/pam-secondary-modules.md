# Negative: PAM secondary modules

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default state. Scope was normal non-sudo local users `attacker` uid 1001 and `selfauth` uid 1002 only.

Result: no validated local privilege escalation in the default PAM secondary-module lane (`pam_namespace`, `pam_cap`, `pam_keyinit`, `pam_loginuid`, `pam_group`, `pam_time`, and adjacent session helpers). The reachable paths either run after dropping to the target uid, read only root-owned policy files, or are not enabled/default-reachable from an unprivileged caller.

## Validation

Probe:

```sh
bash -n pocs/pam_secondary_modules_probe.sh
./pocs/pam_secondary_modules_probe.sh > logs/pam-secondary-modules.out 2>&1
```

The probe completed with exit code 0. Cleanup verification left no `attacker` crontab, no `pam_secondary_modules_*` temp files under `/tmp`, `/home/attacker`, or `/home/selfauth`, no root markers, and restored `selfauth` to:

```text
selfauth:x:1002:1002::/home/selfauth:/bin/bash
```

## Default reachability

Active relevant PAM lines in the target:

```text
/etc/pam.d/common-auth:25:auth optional pam_cap.so
/etc/pam.d/cron:6:session required pam_loginuid.so
/etc/pam.d/login:27:session required pam_loginuid.so
/etc/pam.d/login:63:auth optional pam_group.so
/etc/pam.d/login:69:# account requisite pam_time.so
/etc/pam.d/login:95:session optional pam_keyinit.so force revoke
/etc/pam.d/su-l:5:session optional pam_keyinit.so force revoke
/etc/pam.d/su:29:# account requisite pam_time.so
```

`pam_namespace` is not present in any default service file. `pam_time` is commented in `login` and `su`. `pam_group` is present only in `login`; `/usr/bin/login` is mode `0755`, and uid1001 direct execution fails with `login: Cannot possibly work without effective root`.

The setuid/default-triggerable pieces are:

```text
/usr/bin/su      4755 root:root
/usr/bin/chsh    4755 root:root
/usr/bin/chfn    4755 root:root
/usr/bin/passwd  4755 root:root
/usr/bin/crontab 2755 root:crontab
/usr/sbin/cron   0755 root:root, active daemon
```

`passwd` has only `@include common-password`, so this lane's secondary modules are not in its default stack.

## Policy and race edges

All relevant policy paths are root-owned and non-writable by uid1001:

```text
/etc/security/capability.conf 0644 root:root
/etc/security/group.conf      0644 root:root
/etc/security/time.conf       0644 root:root
/etc/security/namespace.conf  0644 root:root
/etc/security/namespace.init  0755 root:root
/etc/security/namespace.d     0755 root:root
/run/user                     0755 root:root
```

Active non-comment policy was only:

```text
/etc/security/capability.conf:37:none  *
```

uid1001 write and symlink precreation attempts against `/etc/security/*`, `/etc/security/namespace.d`, `/etc/security/limits.d`, and `/run/user/{1001,1002}` all failed with `Permission denied`.

## Reachable module behavior

`su - selfauth` from uid1001 with the known `selfauth` password reached `pam_cap` and `pam_keyinit`. The trace showed `/etc/security/capability.conf` opened and `keyctl(KEYCTL_JOIN_SESSION_KEYRING, NULL)`, but the resulting shell ran as uid/gid 1002 with no inheritable/permitted/effective/ambient caps:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
loginuid=4294967295
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapAmb: 0000000000000000
touch: cannot touch '/root/pam_secondary_modules_su.root': Permission denied
su_root_marker=absent
```

`chsh -s /bin/bash selfauth` and interactive `chfn selfauth` as `selfauth` both reached `pam_cap` and opened `/etc/security/capability.conf`; neither reached `pam_namespace`, `pam_group`, `pam_time`, or `pam_loginuid`. `chfn` only changed the normal GECOS field during the probe and it was restored.

The cron path is the default root-daemon path in this lane. An uid1001 crontab job triggered `/etc/pam.d/cron` and produced:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
loginuid=1001
CapInh/CapPrm/CapEff/CapAmb: all zero
ls: cannot access '/run/user/1001': No such file or directory
touch: cannot touch '/root/pam_secondary_modules_..._cron.root': Permission denied
cron_root_marker=absent
```

## Conclusion

No default uid1001/uid1002-to-root primitive was found. The only active `pam_cap` policy is the restrictive `none *`; keyring changes from `pam_keyinit` stay tied to the opened user session; `pam_loginuid` in cron records uid1001 but does not create privileges; `pam_group`, `pam_time`, and `pam_namespace` have no default attacker-reachable privileged configuration path.
