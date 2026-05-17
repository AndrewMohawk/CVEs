# Negative: screen postrm remove over attacker-writable /run/screen

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Artifacts:

```text
pocs/screen_postrm_remove_probe.sh
logs/screen-postrm-remove.out
```

## Result

No uid1001-to-root LPE was validated through the `screen` package maintainer-script removal path.

The interesting boundary is real: `/run/screen` is default-created as sticky world-writable, and `screen.postrm` performs a root recursive deletion of that directory during package remove/purge. The boundary did not become an LPE because normal uid1001 cannot trigger package removal, and GNU `rm -rf` removed attacker symlinks without following them into root-owned targets.

## Default proof

Package from the live target:

```text
screen  4.9.1-1ubuntu1
```

Default input state:

```text
/run/screen     drwxrwxrwt 1777 root:utmp
/var/run/screen drwxrwxrwt 1777 root:utmp
```

As uid1001:

```text
touch /run/screen/attacker-default-write-test
-rw-r--r-- 1 attacker attacker 0 /run/screen/attacker-default-write-test
```

Relevant maintainer-script paths:

```text
/var/lib/dpkg/info/screen.postinst:7-24
  install -g utmp -m 0775 -d /run/screen
  chmod 1777 /run/screen
  echo 'd /run/screen 1777 root utmp' >> /etc/tmpfiles.d/screen-cleanup.conf

/var/lib/dpkg/info/screen.postrm:4-5
  if [ "$1" = purge ] || [ "$1" = remove ]; then
    rm -rf /run/screen
  fi
```

## Trigger attempts

The destructive root-maintainer-script test was run in a disposable clone of the same target image:

```sh
docker run --name screen-postrm-probe ubuntu24-server-default-lpe:20260516-standard bash -lc '
id attacker >/dev/null 2>&1 || useradd -m -u 1001 attacker
mkdir -p /run/screen
chown root:utmp /run/screen 2>/dev/null || chown root:root /run/screen
chmod 1777 /run/screen
mkdir -p /root/screen-postrm-dir
printf ROOT_DECOY > /root/screen-postrm-decoy
printf ROOT_NESTED > /root/screen-postrm-dir/nested
runuser -u attacker -- bash -lc "
  mkdir -p /run/screen/S-attacker
  printf ATTACKER_FILE > /run/screen/attacker-file
  ln -s /root/screen-postrm-decoy /run/screen/root-file-link
  ln -s /root/screen-postrm-dir /run/screen/root-dir-link
  mkfifo /run/screen/attacker-fifo
"
/var/lib/dpkg/info/screen.postrm remove
'
```

Observed result:

```text
postrm_rc=0
DECOY_FILE_OK
DECOY_DIR_OK
RUN_SCREEN_REMOVED
/root/screen-postrm-dir/nested remained root:root
```

## Why this is not a finding

The attacker controls entries below `/run/screen`, but the root deletion path removes those entries and does not traverse symlinks to root-owned files or directories. Package removal/purge is also not default-triggerable by a normal non-sudo user.

No root command execution, root-owned attacker-selected write/delete outside `/run/screen`, privileged group transition, or `uid=0` context was reached from uid1001.

## Cleanup

The live target was not package-modified. The only live-target file created was `/run/screen/attacker-default-write-test`, removed by the probe. The destructive test ran in a container named `screen-postrm-probe-*`, which the probe removed with `docker rm -f`.

## Why scanners may miss it

A maintainer-script scanner can over-rank `rm -rf` over a sticky world-writable directory. Exploitability depends on package-manager trigger authority and exact `rm -rf` symlink traversal behavior, so a finding requires dynamic proof against root canaries rather than string matching.

## Suggested fix

No LPE fix is justified from this target state. For defense in depth, the maintainer script could use `rm -rf --one-file-system -- /run/screen` or delegate cleanup to tmpfiles, but the tested default path did not follow attacker symlinks or delete root targets.
