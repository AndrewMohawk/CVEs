# Negative: server daemon IPC misc audit

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`
Image: `ubuntu24-server-default-lpe:20260516-standard`
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`

## Result

No uid1001-to-root local privilege escalation was validated in this focused pass over default Ubuntu 24.04 Server storage/network daemon IPC and helper surfaces outside the already-covered multipath/udisks/snapd paths.

The live target exposes some default IPC, especially `iscsid.socket`, `uuidd.socket`, the system bus, and journald sockets. The reachable paths either run as non-root service users, reject uid1001 before mutation/root execution, are condition-gated inactive in the container, or require root-owned config that uid1001 cannot write.

## Package and default state proof

Package status from the live container:

```text
chrony                         un
dbus                           ii  1.14.10-4ubuntu4.1
mdadm                          ii  4.3-1ubuntu2.1
netplan.io                     ii  1.1.2-8ubuntu1~24.04.2
open-iscsi                     ii  2.1.9-3ubuntu5.4
openssh-client                 ii  1:9.6p1-3ubuntu13.16
openssh-server                 un
polkitd                        ii  124-2ubuntu1.24.04.3
pollinate                      ii  4.33-3.1ubuntu1.3
rsync                          ii  3.2.7-1ubuntu1.2
software-properties-common     ii  0.99.49.4
systemd                        ii  255.4-1ubuntu8.15
systemd-timesyncd              ii  255.4-1ubuntu8.15
uuid-runtime                   ii  2.39.3-9ubuntu6.5
```

Relevant unit/socket state:

```text
iscsid.socket                  enabled         active      listening   ConditionResult=yes
iscsid.service                 disabled        inactive    dead        ConditionResult=yes
open-iscsi.service             enabled         inactive    dead        ConditionResult=no
mdmonitor-oneshot.timer        enabled         inactive    dead        ConditionResult=no
mdmonitor-oneshot.service      static          inactive    dead        ConditionResult=no
rsync.service                  disabled        inactive    dead        ConditionResult=no
rsync.socket                   not-found       inactive    dead
pollinate.service              enabled         inactive    dead        ConditionResult=no
uuidd.socket                   enabled         active      running     ConditionResult=yes
uuidd.service                  indirect        active      running     ConditionResult=yes
chrony.service                 not-found       inactive    dead
systemd-timesyncd.service      enabled         inactive    dead        ConditionResult=no
ssh.service                    not-found       inactive    dead
ssh.socket                     not-found       inactive    dead
```

Important unit/config boundaries:

```text
iscsid.socket: ListenStream=@ISCSIADM_ABSTRACT_NAMESPACE
iscsid.service: ExecStart=/usr/sbin/iscsid
open-iscsi.service: ConditionDirectoryNotEmpty=|/etc/iscsi/nodes or /sys/class/iscsi_session
mdmonitor-oneshot.service: EnvironmentFile=-/etc/default/mdadm; ExecStart=/sbin/mdadm --monitor --oneshot --scan
rsync.service: ConditionPathExists=/etc/rsyncd.conf; ExecStart=/usr/bin/rsync --daemon --no-detach
pollinate.service: ConditionVirtualization=!container; User=pollinate; CacheDirectoryMode=0750
uuidd.service: User=uuidd; Group=uuidd; ProtectSystem=strict; ReadWritePaths=/var/lib/libuuid/
systemd-timesyncd.service: ConditionVirtualization=!container; User=systemd-timesync; CapabilityBoundingSet=CAP_SYS_TIME
io.netplan.Netplan.service: Exec=/usr/libexec/netplan/netplan-dbus; User=root
com.ubuntu.SoftwareProperties.service: Exec=/usr/lib/software-properties/software-properties-dbus; User=root
```

Path permissions:

```text
drwxr-xr-x root:root /etc/iscsi
-rw-r--r-- root:root /etc/iscsi/iscsid.conf
-rw------- root:root /etc/iscsi/initiatorname.iscsi
-rw-r--r-- root:root /etc/mdadm/mdadm.conf
-rw-r--r-- root:root /etc/default/mdadm
-rw-r--r-- root:root /etc/default/rsync
missing /etc/rsyncd.conf
drwxr-x--- pollinate:daemon /var/cache/pollinate
-rw-r--r-- root:root /etc/default/pollinate
srw-rw-rw- root:root /run/uuidd/request
-rw-r--r-- root:root /etc/systemd/timesyncd.conf
-rw-r--r-- root:root /etc/ssh/ssh_config
drwxr-xr-x root:root /etc/ssh/ssh_config.d
-rwsr-xr-x root:root /usr/lib/openssh/ssh-keysign
-rwxr-sr-x root:_ssh /usr/bin/ssh-agent
srw-rw-rw- root:root /run/dbus/system_bus_socket
srwx------ root:root /run/systemd/private
srw------- root:root /run/udev/control
srw-rw-rw- root:root /run/systemd/journal/socket
```

## uid1001 trigger results

### open-iscsi / iscsid

```text
iscsiadm -m node
=> iscsiadm: No records found

iscsiadm -m discovery -t sendtargets -p 127.0.0.1
=> iscsiadm: read error (-1/104), daemon died?
=> iscsiadm: Could not make /etc/iscsi/send_targets: Permission denied

iscsiadm -m iface -o new -I servermisc0
=> Could not make /etc/iscsi/ifaces folder(13 Permission denied)

raw connect to abstract \0ISCSIADM_ABSTRACT_NAMESPACE
=> ConnectionRefusedError [Errno 111] Connection refused
```

Journal proof for the daemon death:

```text
iscsid: can not create NETLINK_ISCSI socket [Protocol not supported]
iscsid.service: Main process exited, code=exited, status=1/FAILURE
```

No root-controlled iSCSI database entry or root helper execution was reached; uid1001 cannot write `/etc/iscsi`.

### mdadm monitor

```text
mdadm --monitor --scan --oneshot --test
=> no root context; command ran as attacker

mdadm --assemble --scan
=> mdadm: must be super-user to perform this action

systemctl start mdmonitor-oneshot.service
=> Failed to start mdmonitor-oneshot.service: Interactive authentication required.
```

The root timer/service reads root-owned `/etc/default/mdadm` and `/etc/mdadm/mdadm.conf`; uid1001 cannot alter those inputs or start the root unit.

### rsync service/socket

```text
rsync --version
=> rsync version 3.2.7 protocol version 31

systemctl start rsync.service
=> Failed to start rsync.service: Interactive authentication required.

rsync rsync://127.0.0.1/
=> failed to connect to 127.0.0.1: Connection refused
=> rsync_probe_rc=10
```

There is no `rsync.socket`, `/etc/rsyncd.conf` is absent, and `rsync.service` is disabled/inactive with `ConditionPathExists=/etc/rsyncd.conf`.

### pollinate

```text
systemctl start pollinate.service
=> Failed to start pollinate.service: Interactive authentication required.

pollinate --print-user-agent
=> cloud-init/ curl/8.5.0-2ubuntu10.9 pollinate/4.33-3.1ubuntu1.3 Ubuntu/24.04.4/LTS ...
=> pollinate_ua_rc=0

pollinate --server 127.0.0.1 --seed-file /tmp/servermisc_pollinate_seed
=> pollinate_direct_rc=1
```

The default service is condition-gated in Docker and runs as `pollinate`, not root, when reachable on a non-container boot. The cache directory is `pollinate:daemon 0750`, not writable by uid1001.

### uuidd

```text
connect /run/uuidd/request
=> CONNECT_OK

uuidd -r
=> ac6846ea-5bc4-407c-ad19-9cf4e029dbdc

uuidd -t
=> 6e7c6f62-512c-11f1-817d-fe62605aa36f
```

This socket is intentionally world reachable, but the daemon runs as `uuidd` with `ProtectSystem=strict` and only `/var/lib/libuuid/` writable.

### chrony / systemd-timesyncd

```text
chronyc tracking
=> sh: 1: chronyc: not found

timedatectl status
=> System clock synchronized: no
=> NTP service: inactive

timedatectl set-ntp true
=> Failed to set ntp: Interactive authentication required.

systemctl start systemd-timesyncd.service
=> Failed to start systemd-timesyncd.service: Interactive authentication required.
```

`chrony` is not installed. `systemd-timesyncd` is installed/enabled but inactive in this target because of `ConditionVirtualization=!container`; its config is root-owned.

### SSH helpers

```text
openssh-server package
=> un

ssh.service / ssh.socket
=> not-found

/usr/lib/openssh/ssh-keysign </dev/null
=> ssh-keysign not enabled in /etc/ssh/ssh_config
=> ssh_keysign_rc=255

grep HostbasedAuthentication /etc/ssh/ssh_config
=> #   HostbasedAuthentication no

ls /etc/ssh/ssh_host_*_key
=> No such file or directory

ssh-agent -a /tmp/servermisc_agent/sock sh -c 'stat ...; id'
=> srw------- attacker:attacker /tmp/servermisc_agent/sock
=> uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

The setuid `ssh-keysign` helper is present through `openssh-client`, but default global config disables it and no host private keys exist in this stock Docker target. `ssh-agent` is setgid `_ssh`, but attacker-launched agent commands and sockets remain attacker-owned.

### Root-run local IPC helpers

Active root helper processes with local IPC included `/usr/libexec/netplan/netplan-dbus`, `software-properties-dbus`, `systemd-logind`, `systemd-udevd`, and journald/systemd sockets.

uid1001 reachability results:

```text
connect /run/dbus/system_bus_socket
=> CONNECT_OK

connect /run/systemd/private
=> PermissionError [Errno 13] Permission denied

connect /run/udev/control
=> PermissionError [Errno 13] Permission denied

udevadm control --ping
=> Failed to send a ping message: Permission denied

logger server-daemon-ipc-misc-attacker-log-test
=> logger_rc=0
```

Root D-Bus mutator probes:

```text
busctl call io.netplan.Netplan Config
=> Call failed: Access denied

busctl call io.netplan.Netplan Apply
=> Call failed: Access denied

busctl call com.ubuntu.SoftwareProperties Reload
=> reload_rc=0

busctl call com.ubuntu.SoftwareProperties AddSourceFromLine 'deb http://127.0.0.1/ubuntu noble main'
=> Call failed: com.ubuntu.softwareproperties.applychanges

busctl call com.ubuntu.SoftwareProperties AddKey /tmp/servermisc-test-key.gpg
=> Call failed: com.ubuntu.softwareproperties.applychanges
```

The system bus is reachable, but these root helpers enforce runtime authorization for mutating methods. Journald accepts unprivileged log messages only; no root file write outside the log path or root command execution was produced.

## Cleanup

Performed:

```sh
rm -f /tmp/servermisc_pollinate_seed /tmp/servermisc-test-key.gpg /tmp/servermisc_pkcs11_helper_id /tmp/servermisc_ssh_add.out
rm -rf /tmp/servermisc_ssh /tmp/servermisc_agent
systemctl reset-failed iscsid.service iscsid.socket mdmonitor-oneshot.service rsync.service pollinate.service systemd-timesyncd.service
systemctl start iscsid.socket
```

Post-cleanup state:

```text
iscsid.socket                  active
iscsid.service                 inactive
rsync.service                  inactive
pollinate.service              inactive
systemd-timesyncd.service      inactive
uuidd.socket                   active
uuidd.service                  active
find /tmp -maxdepth 1 -name 'servermisc*' produced no output
```

No `notes/<finding>.md` or `pocs/<finding>.sh` was created because no uid1001-to-root LPE was proven.
