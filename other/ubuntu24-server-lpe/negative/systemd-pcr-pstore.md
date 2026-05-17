# Negative: systemd PCR, pstore, and storage target helpers

Date: 2026-05-16

Target: Docker container `ubuntu24-server-lpe-target`, stock updated Ubuntu 24.04 Server image. Attacker identity was `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Result: no uid1001 -> root local privilege escalation was validated in this lane. The systemd pstore, PCR extension, PCR lock, TPM2 setup, and storage-target helpers are default-installed root transition points, but on the stock Docker Server target they were condition-gated, admin-gated, or only directly executable as uid1001.

Artifacts:

```text
pocs/systemd_pcr_pstore_probe.sh
logs/systemd-pcr-pstore.out
```

## Default package and unit proof

The target is Ubuntu 24.04.4 LTS. Relevant package versions:

```text
systemd                255.4-1ubuntu8.15
libsystemd0:arm64      255.4-1ubuntu8.15
```

Installed helper ownership:

```text
/usr/lib/systemd/systemd-pstore       0755 root:root
/usr/lib/systemd/systemd-pcrextend    0755 root:root
/usr/lib/systemd/systemd-pcrlock      0755 root:root
/usr/lib/systemd/systemd-storagetm    0755 root:root
/usr/lib/systemd/systemd-tpm2-setup   0755 root:root
```

Relevant default unit paths:

```text
/usr/lib/systemd/system/systemd-pstore.service
  ConditionDirectoryNotEmpty=/sys/fs/pstore
  ConditionVirtualization=!container
  ExecStart=/usr/lib/systemd/systemd-pstore
  StateDirectory=systemd/pstore

/usr/lib/systemd/system/systemd-pcrextend.socket
  ConditionSecurity=measured-uki
  ListenStream=/run/systemd/io.systemd.PCRExtend
  SocketMode=0600
  Accept=yes

/usr/lib/systemd/system/systemd-pcrextend@.service
  ExecStart=-/usr/lib/systemd/systemd-pcrextend

/usr/lib/systemd/system/systemd-storagetm.service
  ConditionVirtualization=!container
  FailureAction=reboot
  SuccessAction=reboot
  ExecStart=/usr/lib/systemd/systemd-storagetm --all

/usr/lib/systemd/system/systemd-tpm2-setup.service
  ConditionSecurity=measured-uki
  ExecStart=/usr/lib/systemd/systemd-tpm2-setup

/usr/lib/systemd/system/systemd-pcrmachine.service
  ConditionSecurity=measured-uki
  ExecStart=/usr/lib/systemd/systemd-pcrextend --graceful --machine-id
```

The default unit states were:

```text
systemd-pstore.service                 enabled
systemd-pcrextend.socket               disabled
systemd-pcrextend@.service             static
systemd-pcrlock-*.service              disabled
systemd-pcrmachine.service             static
systemd-storagetm.service              static
systemd-tpm2-setup.service             static
```

## Reachability and blocking boundary

The relevant input and state paths were root-owned:

```text
/sys/fs/pstore                         0555 root:root
/var/lib/systemd/pstore                0755 root:root
/run/systemd                           0755 root:root
/run/systemd/system                    0755 root:root
/usr/lib/pcrlock.d                     0755 root:root
```

uid1001 could not place files, symlinks, sockets, or drop-ins at pstore/PCR paths:

```text
/sys/fs/pstore/attacker                         No such file or directory
/var/lib/systemd/pstore/attacker                Permission denied
/run/systemd/io.systemd.PCRExtend               Permission denied
/run/systemd/system/systemd-pstore.service.d    No such file or directory
/usr/lib/pcrlock.d/probe.conf                   Permission denied
```

Attempts to start the root units/sockets as uid1001 were all polkit/systemd-gated:

```text
systemd-pstore.service               Interactive authentication required
systemd-pcrextend.socket             Interactive authentication required
systemd-pcrlock-file-system.service  Interactive authentication required
systemd-tpm2-setup.service           Interactive authentication required
systemd-pcrmachine.service           Interactive authentication required
systemd-storagetm.service            Interactive authentication required
```

Root-starting the low-risk socket/service only proved the default condition gates:

```text
systemd-pcrextend.socket skipped: ConditionSecurity=measured-uki was not met
/run/systemd/io.systemd.PCRExtend did not exist

systemd-pstore.service skipped: ConditionVirtualization=!container was not met
```

Direct helper execution as uid1001 did not cross privilege. `systemd-pcrextend --graceful --machine-id` exited because TPM2 support was absent, the helper `--help` paths ran as uid1001, and an explicit marker write to `/root/systemd_pcr_pstore_lpe_marker` failed:

```text
No complete TPM2 support detected, exiting gracefully.
no_direct_root_marker
ROOT_PROOF=no
```

## Cleanup

The probe removed transient files under `/tmp`, `/home/attacker`, and the test marker path. It also stopped/reset the tested socket/service states:

```text
ABSENT /root/systemd_pcr_pstore_lpe_marker
ABSENT /home/attacker/systemd_pcr_pstore_probe
ABSENT /run/systemd/io.systemd.PCRExtend
systemctl is-system-running -> running
```

## Conclusion

Negative. These systemd helpers are default-installed root transitions that scanners often treat as low priority because they are condition-gated. The actual live Server state showed no attacker-writable pstore/PCR policy path, no world-reachable PCR varlink socket, no unauthenticated unit start, and no direct helper path that executes as root.
