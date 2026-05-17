# Negative: UDisks2 EnableModule/EnableModules boundary

Date: 2026-05-16  
Target: `ubuntu24-server-lpe-target`  
Result: no validated root LPE from `org.freedesktop.UDisks2.Manager.EnableModule` or deprecated `EnableModules`.

## Default/reachability

Stock target versions:

```text
udisks2	2.10.1-6ubuntu1.3	ii
libudisks2-0:arm64	2.10.1-6ubuntu1.3	ii
libblockdev3:arm64	3.1.1-1ubuntu0.1	ii
polkitd	124-2ubuntu1.24.04.3	ii
systemd	255.4-1ubuntu8.15	ii
```

UDisks is default enabled and D-Bus activated as root:

```text
enabled
active
Type=dbus
BusName=org.freedesktop.UDisks2
ExecStart=/usr/libexec/udisks2/udisksd
User=root
SystemdService=udisks2.service
```

The system bus config allows anyone to send to UDisks, and there is no UDisks polkit action for module enabling:

```text
<policy context="default">
  <allow send_destination="org.freedesktop.UDisks2"/>
</policy>
### polkit module action grep
```

Manager introspection exposes the methods without an options dict:

```text
.EnableModule                   method    sb         -
.EnableModules                  method    b          -  deprecated
```

A plain non-active, non-sudo `attacker` can reach both methods; failures are module-load errors, not authorization failures:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
Failed to get user: User ID 1001 is not logged in or lingering

### EnableModule 'evil' true
Error initializing module 'evil': /usr/lib/aarch64-linux-gnu/udisks2/modules/libudisks2_evil.so: cannot open shared object file: No such file or directory
rc=1
### EnableModules true
()
rc=0
```

The same result holds from an active local `selfauth` tty session:

```text
Active=yes
State=active
### active EnableModule gap_evil true
Error initializing module 'gap_evil': /usr/lib/aarch64-linux-gnu/udisks2/modules/libudisks2_gap_evil.so: cannot open shared object file: No such file or directory
rc=1
### active EnableModules true
()
rc=0
```

## Exploit angles tested

Path traversal and malformed module names were rejected before path construction:

```text
Requested module name '../tmp/evil' is not a valid udisks2 module name.
Requested module name '/tmp/evil' is not a valid udisks2 module name.
Requested module name 'evil..name' is not a valid udisks2 module name.
Requested module name 'evil name' is not a valid udisks2 module name.
```

Accepted names are resolved under a fixed root-owned path. On the stock server image, that module directory is absent:

```text
ls: cannot access '/usr/lib/aarch64-linux-gnu/udisks2': No such file or directory
ls: cannot access '/usr/lib/aarch64-linux-gnu/udisks2/modules': No such file or directory
drwxr-xr-x 1 root root 20480 May 16 10:22 /usr/lib/aarch64-linux-gnu
```

Attacker-controlled environment variables and fake modules in `/tmp` did not steer loading, including across D-Bus activation:

```text
-rwxr-xr-x 1 attacker attacker 20 /tmp/libudisks2_gap_evil.so
-rwxr-xr-x 1 attacker attacker 20 /tmp/udisks2/modules/libudisks2_gap_evil.so
Call failed: Error initializing module 'gap_evil': /usr/lib/aarch64-linux-gnu/udisks2/modules/libudisks2_gap_evil.so: cannot open shared object file: No such file or directory
activation_env_EnableModule_rc=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
```

`LIBBLOCKDEV_CONFIG_DIR` is present in libblockdev, but the running root `udisksd` did not inherit client-supplied values. The default config is root-owned under `/etc/libblockdev/3/conf.d`, and a client-env `EnableModules` call still only reported the missing UDisks module directory:

```text
drwxr-xr-x 2 root root 4096 /etc/libblockdev/3/conf.d
LIBBLOCKDEV_CONFIG_DIR
libblockdev_env_EnableModules_rc=0
Error loading modules: Error opening directory “/usr/lib/aarch64-linux-gnu/udisks2/modules”: No such file or directory
```

Options dict injection is blocked by the D-Bus signature:

```text
Type of message, ?(sba{sv})?, does not match expected type ?(sb)?
Type of message, ?(ba{sv})?, does not match expected type ?(b)?
```

No new LVM2/BTRFS Manager interfaces appeared after `EnableModules`. `Manager.NVMe` was present before and after, so it was not unlocked by this method on the default image.

Root proof markers stayed absent:

```text
ROOT_PROOF_ABSENT /root/udisks_enable_module_gap_root
ROOT_PROOF_ABSENT /tmp/udisks_enable_module_gap_root
```

Full reproducible log: `logs/udisks-enable-module-gap.out`.
