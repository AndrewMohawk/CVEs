# Negative: WWAN ModemManager, QMI/MBIM, and usb-modeswitch helpers

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server image. Attacker identity was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no uid1001 -> root local privilege escalation was validated in this lane. The interesting primitives in `qmi-network` and `mbim-network` are real user-controlled shell/source/PATH surfaces, but the stock Server state did not provide a default root caller for those scripts. ModemManager and usb-modeswitch root transitions were either condition-gated, polkit/systemd-gated, or hardware/udev-event-gated.

Artifacts:

```text
pocs/wwan_modem_helpers_probe.sh
logs/wwan-modem-helpers.out
```

## Default package and unit proof

Relevant package versions:

```text
libmbim-utils     1.31.2-0ubuntu3.1
libqmi-utils      1.35.2-0ubuntu2
modemmanager      1.23.4-0ubuntu2
usb-modeswitch    2.6.1-3ubuntu3
```

The default units are present:

```text
ModemManager.service     enabled
usb_modeswitch@.service  static
```

Relevant unit boundaries:

```text
/usr/lib/systemd/system/ModemManager.service
  ConditionVirtualization=!container
  Type=dbus
  BusName=org.freedesktop.ModemManager1
  ExecStart=/usr/sbin/ModemManager
  CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN
  ProtectSystem=true
  ProtectHome=true
  PrivateTmp=true
  NoNewPrivileges=true
  User=root

/usr/lib/systemd/system/usb_modeswitch@.service
  Type=oneshot
  ExecStart=/usr/sbin/usb_modeswitch_dispatcher --switch-mode %i
  Environment="TMPDIR=/run"
```

The system bus advertised `org.freedesktop.ModemManager1` as activatable, but the service condition prevented activation in the Docker target.

## Vulnerable-looking code paths

`/usr/bin/qmi-network`:

```text
107 PROFILE_FILE=/etc/qmi-network.conf
149 STATE_FILE=/tmp/qmi-network-state-`basename $DEVICE`
153 if [ -f "$PROFILE_FILE" ]; then
155     . $PROFILE_FILE
223 if [ -f "$STATE_FILE" ]; then
225     . $STATE_FILE
248 DEVICE_DATA_FORMAT_CMD="qmicli -d $DEVICE ..."
514 STATUS_CMD="qmicli -d $DEVICE ..."
```

`/usr/bin/mbim-network`:

```text
93  PROFILE_FILE=/etc/mbim-network.conf
135 STATE_FILE=/tmp/mbim-network-state-`basename $DEVICE`
139 if [ -f "$PROFILE_FILE" ]; then
141     . $PROFILE_FILE
218 if [ -f "$STATE_FILE" ]; then
220     . $STATE_FILE
391 STATUS_CMD="mbimcli -d $DEVICE ..."
```

`/usr/sbin/usb_modeswitch_dispatcher` also has root log/state writes:

```text
131 set setup(dbdir_etc) /etc/usb_modeswitch.d
663 exec echo ... >/var/log/usb_modeswitch_$device
800 set listfile /var/lib/usb_modeswitch/$name
```

These are trust-boundary-relevant because a root caller with attacker-controlled profile, state, PATH, or device name would be dangerous.

## Reachability and blocking boundary

The root trust roots were not attacker-writable:

```text
/usr/bin/qmi-network                         0755 root:root
/usr/bin/mbim-network                        0755 root:root
/usr/sbin/ModemManager                       0755 root:root
/usr/sbin/usb_modeswitch_dispatcher          0755 root:root
/usr/lib/udev/rules.d/40-usb_modeswitch.rules 0644 root:root
/etc/ModemManager                            0755 root:root
/etc/ModemManager/fcc-unlock.d               0755 root:root
/etc/ModemManager/connection.d               0755 root:root
/etc/usb_modeswitch.d                        0755 root:root
/var/lib/usb_modeswitch                      0755 root:root
/run/udev                                    0755 root:root
/sys                                         0555 root:root
```

uid1001 write attempts to `/etc/qmi-network.conf`, `/etc/mbim-network.conf`, `/etc/ModemManager/*`, `/etc/usb_modeswitch.d`, `/var/lib/usb_modeswitch`, `/run/udev`, and `/sys` all failed with `Permission denied`.

The direct script primitives only executed as uid1001:

```text
profile_qmi_uid:  uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
profile_mbim_uid: uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
qmicli_uid:       uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
mbimcli_uid:      uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
no_direct_root_marker
```

The service and hardware trigger attempts were blocked:

```text
systemctl start ModemManager.service          Interactive authentication required
systemctl start usb_modeswitch@wwanlpe.service Interactive authentication required
udevadm trigger --subsystem-match=usb         Permission denied writing sysfs uevent files
busctl ModemManager introspection             timed out on activatable service
```

Root-starting the services only showed the default gates:

```text
ModemManager.service skipped: ConditionVirtualization=!container was not met
usb_modeswitch@wwanlpe.service failed before creating /var/log or /var/lib state because no matching kernel USB device existed
ROOT_PROOF=no
```

## Cleanup

The probe removed the marker, attacker workspace, `/tmp/qmi-network-state-wwanlpe`, `/tmp/mbim-network-state-wwanlpe`, and any tested usb-modeswitch log/state paths. Final health was `systemctl is-system-running -> running`.

## Conclusion

Negative. A normal local user can exercise `qmi-network`/`mbim-network` profile sourcing, `/tmp` state sourcing, and PATH-controlled `qmicli`/`mbimcli` execution, but only in the user's own process. The default Server root paths do not call those scripts with attacker-controlled inputs; ModemManager is condition-gated in the Docker target, and usb-modeswitch requires a root udev/hardware event or an authenticated unit start. Generic scanners are likely to flag the shell sourcing and `/tmp` state files, but the live default-reachability check keeps this below the LPE bar.
