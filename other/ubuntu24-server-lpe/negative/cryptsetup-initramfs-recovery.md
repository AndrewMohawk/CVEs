# Negative: cryptsetup/initramfs/finalrd/friendly-recovery/ask-password default-state LPE audit

Target: `ubuntu24-server-lpe-target` (`ubuntu24-server-default-lpe:20260516-standard`)  
Date: 2026-05-16  
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`  
Result: no uid1001-to-root escalation and no attacker-controlled root write found in the default state.

## Package/default/reachability proof

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'id; getent passwd 1001 || true; uname -a; cat /etc/os-release'
uid=0(root) gid=0(root) groups=0(root)
attacker:x:1001:1001::/home/attacker:/bin/bash
Linux fd448ecbc136 6.10.14-linuxkit #1 SMP Sat May 17 08:28:57 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=noble
```

```sh
$ docker exec ubuntu24-server-lpe-target dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' cryptsetup cryptsetup-bin cryptsetup-initramfs initramfs-tools initramfs-tools-core finalrd friendly-recovery systemd systemd-sysv
cryptsetup	2:2.7.0-1ubuntu4.2	ii 
cryptsetup-bin	2:2.7.0-1ubuntu4.2	ii 
cryptsetup-initramfs	2:2.7.0-1ubuntu4.2	ii 
finalrd	9build1	ii 
friendly-recovery	0.2.42	ii 
initramfs-tools	0.142ubuntu25.8	ii 
initramfs-tools-core	0.142ubuntu25.8	ii 
systemd	255.4-1ubuntu8.15	ii 
systemd-sysv	255.4-1ubuntu8.15	ii 
```

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'ps -p 1 -o user=,comm=,args=; systemctl is-system-running 2>&1 || true; systemctl list-unit-files "*crypt*" "*finalrd*" "*friendly*" "*ask-password*" --no-pager 2>&1 || true; systemctl list-units "*crypt*" "*finalrd*" "*friendly*" "*ask-password*" --all --no-pager 2>&1 || true'
root     systemd         /sbin/init
running
UNIT FILE                             STATE    PRESET
systemd-ask-password-console.path     static   -
systemd-ask-password-plymouth.path    static   -
systemd-ask-password-wall.path        static   -
cryptdisks-early.service              masked   enabled
cryptdisks.service                    masked   enabled
finalrd.service                       enabled  enabled
friendly-recovery.service             static   -
systemd-ask-password-console.service  static   -
systemd-ask-password-plymouth.service static   -
systemd-ask-password-wall.service     static   -
system-systemd\x2dcryptsetup.slice    static   -
cryptsetup-pre.target                 static   -
cryptsetup.target                     static   -
friendly-recovery.target              static   -
remote-cryptsetup.target              disabled enabled

  systemd-ask-password-console.path     loaded active   waiting Dispatch Password Requests to Console Directory Watch
  systemd-ask-password-wall.path        loaded active   waiting Forward Password Requests to Wall Directory Watch
  finalrd.service                       loaded active   exited  Create final runtime dir for shutdown pivot root
  cryptsetup.target                     loaded active   active  Local Encrypted Volumes
```

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'systemctl list-units "systemd-cryptsetup@*" --all --no-pager 2>&1 || true'
  UNIT LOAD ACTIVE SUB DESCRIPTION

0 loaded units listed.
```

Default `/etc/crypttab` contains only the package comment, so no generated `systemd-cryptsetup@...` unit exists in the default state:

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target sh -lc 'id; test -r /etc/crypttab && cat /etc/crypttab || echo /etc/crypttab-unreadable-or-missing; command -v cryptsetup || true; command -v update-initramfs || true; command -v finalrd || true; command -v systemd-ask-password || true; command -v systemd-tty-ask-password-agent || true'
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
# <target name>	<source device>		<key file>	<options>
/usr/sbin/cryptsetup
/usr/sbin/update-initramfs
/usr/bin/finalrd
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
```

## Root-owned config/scripts and writable checks

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'ls -ld /etc/cryptsetup-initramfs /etc/initramfs-tools /etc/initramfs-tools/conf.d /etc/initramfs-tools/hooks /etc/initramfs-tools/scripts /etc/systemd/system /run/systemd /run/systemd/ask-password 2>&1; ls -l /etc/crypttab /etc/cryptsetup-initramfs/conf-hook /etc/initramfs-tools/initramfs.conf /etc/initramfs-tools/update-initramfs.conf /lib/systemd/system/finalrd.service /lib/systemd/system/friendly-recovery.service /lib/systemd/system/friendly-recovery.target /lib/systemd/system-generators/friendly-recovery 2>&1'
drwxr-xr-x  2 root root 4096 May 16 10:22 /etc/cryptsetup-initramfs
drwxr-xr-x  5 root root 4096 May 16 10:22 /etc/initramfs-tools
drwxr-xr-x  2 root root 4096 Feb  4 17:01 /etc/initramfs-tools/conf.d
drwxr-xr-x  2 root root 4096 Feb  4 17:01 /etc/initramfs-tools/hooks
drwxr-xr-x 12 root root 4096 May 16 10:22 /etc/initramfs-tools/scripts
drwxr-xr-x  1 root root 4096 May 16 10:22 /etc/systemd/system
drwxr-xr-x 22 root root  560 May 16 13:12 /run/systemd
drwxr-xr-x  2 root root   40 May 16 10:23 /run/systemd/ask-password
-rw-r--r-- 1 root root 1644 Jun  5  2024 /etc/cryptsetup-initramfs/conf-hook
-rw-r--r-- 1 root root   54 May 16 10:22 /etc/crypttab
-rw-r--r-- 1 root root 1502 Apr 22  2024 /etc/initramfs-tools/initramfs.conf
-rw-r--r-- 1 root root  378 Feb  8  2021 /etc/initramfs-tools/update-initramfs.conf
-rwxr-xr-x 1 root root  286 Jun 21  2019 /lib/systemd/system-generators/friendly-recovery
-rw-r--r-- 1 root root  419 Feb 16  2022 /lib/systemd/system/finalrd.service
-rw-r--r-- 1 root root  618 Oct  2  2018 /lib/systemd/system/friendly-recovery.service
-rw-r--r-- 1 root root  172 Oct  2  2018 /lib/systemd/system/friendly-recovery.target
```

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target sh -lc 'find /etc/cryptsetup-initramfs /etc/initramfs-tools /lib/cryptsetup /usr/share/initramfs-tools /usr/share/cryptsetup/initramfs /usr/lib/finalrd /usr/share/finalrd /lib/recovery-mode /run/systemd/ask-password -xdev -writable -printf "%M %u %g %p\n" 2>/dev/null | sort'
# no output
```

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'find /etc/cryptsetup-initramfs /etc/initramfs-tools /lib/cryptsetup /usr/share/initramfs-tools /usr/share/cryptsetup/initramfs /usr/lib/finalrd /usr/share/finalrd /lib/recovery-mode -xdev \( -perm -0002 -o -perm -0020 \) -printf "%M %u %g %p\n" 2>/dev/null | sort; find /etc/cryptsetup-initramfs /etc/initramfs-tools /lib/cryptsetup /usr/share/initramfs-tools /usr/share/cryptsetup/initramfs /usr/lib/finalrd /usr/share/finalrd /lib/recovery-mode -xdev ! -user root -printf "%M %u %g %p\n" 2>/dev/null | sort'
# no output
```

No reviewed helper had setuid/setgid bits or file capabilities:

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'getcap -r /usr/sbin/cryptsetup /usr/bin/finalrd /usr/bin/systemd-ask-password /usr/bin/systemd-tty-ask-password-agent /sbin/cryptdisks_start /sbin/cryptdisks_stop /usr/sbin/update-initramfs /usr/sbin/mkinitramfs /lib/recovery-mode 2>/dev/null || true; find /usr/sbin/cryptsetup /usr/bin/finalrd /usr/bin/systemd-ask-password /usr/bin/systemd-tty-ask-password-agent /sbin/cryptdisks_start /sbin/cryptdisks_stop /usr/sbin/update-initramfs /usr/sbin/mkinitramfs /lib/recovery-mode -perm /6000 -printf "%M %u %g %p\n" 2>/dev/null | sort'
# no output
```

## ask-password boundary

The active path units watch `/run/systemd/ask-password`, but the directory is root-owned and not writable by uid1001.

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'stat -c "%A %U %G %n" /run /run/systemd /run/systemd/ask-password /run/systemd/inaccessible /run/systemd/incoming 2>&1; find /run/systemd/ask-password -maxdepth 1 -printf "%M %u %g %p\n" 2>&1'
drwxr-xr-x root root /run
drwxr-xr-x root root /run/systemd
drwxr-xr-x root root /run/systemd/ask-password
drwxr-xr-x root root /run/systemd/inaccessible
drwxr-xr-x root root /run/systemd/incoming
drwxr-xr-x root root /run/systemd/ask-password
```

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target sh -lc 'set -x; touch /run/systemd/ask-password/uid1001-probe 2>&1; mkfifo /run/systemd/ask-password/uid1001-fifo 2>&1; systemd-ask-password --timeout=1 "uid1001 prompt" </dev/null 2>&1; systemd-tty-ask-password-agent --query --watch 2>&1 & p=$!; sleep 1; kill $p 2>/dev/null || true; wait $p 2>/dev/null || true; ls -la /run/systemd/ask-password 2>&1'
+ touch /run/systemd/ask-password/uid1001-probe
touch: cannot touch '/run/systemd/ask-password/uid1001-probe': Permission denied
+ mkfifo /run/systemd/ask-password/uid1001-fifo
mkfifo: cannot create fifo '/run/systemd/ask-password/uid1001-fifo': Permission denied
+ systemd-ask-password --timeout=1 'uid1001 prompt'
Failed to query password: Permission denied
+ p=78139
+ sleep 1
+ systemd-tty-ask-password-agent --query --watch
+ kill 78139
+ wait 78139
+ ls -la /run/systemd/ask-password
total 0
drwxr-xr-x  2 root root  40 May 16 10:23 .
drwxr-xr-x 22 root root 560 May 16 13:12 ..
```

A root-created prompt uses a world-readable request file but a root-only reply socket. uid1001 can list the request, but cannot query/respond or write to the request/socket.

```sh
$ docker exec ubuntu24-server-lpe-target bash -lc 'rm -f /tmp/root-ask.out /tmp/root-ask.err /tmp/root-ask.rc; (systemd-ask-password --no-tty --timeout=4 "root ask-password probe" > /tmp/root-ask.out 2>/tmp/root-ask.err; echo rc=$? > /tmp/root-ask.rc) & p=$!; sleep 0.7; echo "### root view"; find /run/systemd/ask-password -maxdepth 1 -printf "%M %u %g %p -> %l\n" | sort; echo "### uid1001 list"; runuser -u attacker -- systemd-tty-ask-password-agent --list 2>&1 || true; echo "### uid1001 query"; runuser -u attacker -- sh -lc "timeout 1 systemd-tty-ask-password-agent --query </dev/null" 2>&1 || true; echo "### uid1001 write attempts"; runuser -u attacker -- sh -lc "for f in /run/systemd/ask-password/*; do [ -e \"\$f\" ] || continue; printf x >>\"\$f\" 2>&1 || true; done"; wait $p || true; echo "### root ask result"; cat /tmp/root-ask.rc /tmp/root-ask.out /tmp/root-ask.err 2>/dev/null; rm -f /tmp/root-ask.out /tmp/root-ask.err /tmp/root-ask.rc'
### root view
-rw-r--r-- root root /run/systemd/ask-password/ask.kYG8fv -> 
drwxr-xr-x root root /run/systemd/ask-password -> 
srw------- root root /run/systemd/ask-password/sck.e1e7554997dff60b -> 
### uid1001 list
'root ask-password probe' (PID 85230)
### uid1001 query
Not querying 'root ask-password probe' (PID 85230), lacking privileges.
### uid1001 write attempts
sh: 1: cannot create /run/systemd/ask-password/ask.kYG8fv: Permission denied
sh: 1: cannot create /run/systemd/ask-password/sck.e1e7554997dff60b: Permission denied
### root ask result
rc=1
Failed to query password: Timer expired
```

## cryptsetup/initramfs parser boundary

Relevant parser behavior:

- `/lib/cryptsetup/functions` validates `check=` and `keyscript=` as existing executable files. Relative names are resolved under `/lib/cryptsetup/checks` and `/lib/cryptsetup/scripts`; absolute paths are accepted.
- `run_keyscript()` ultimately uses `exec "$keyscript" "$keyscriptarg"`.
- In the default system this is not attacker-controlled root execution because `/etc/crypttab`, `/etc/default/cryptdisks`, `/etc/cryptsetup-initramfs/conf-hook`, and `/etc/initramfs-tools/*` are root-owned and not uid1001-writable. The initramfs `cryptopts=` path is kernel-command-line input, not uid1001 input.

Evidence:

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'nl -ba /lib/cryptsetup/functions | sed -n "201,228p"; nl -ba /lib/cryptsetup/functions | sed -n "281,299p"'
   201	        check)
   202	            if [ -z "${VALUE+x}" ]; then
   203	                if [ -n "${CRYPTDISKS_CHECK-}" ]; then
   204	                    VALUE="$CRYPTDISKS_CHECK"
   205	                else
   206	                    unset -v OPTION
   207	                    return 0
   208	                fi
   209	            fi
   210	            if [ "${VALUE#/}" = "$VALUE" ]; then
   211	                VALUE="/lib/cryptsetup/checks/$VALUE"
   212	            fi
   213	            if [ ! -x "$VALUE" ] || [ ! -f "$VALUE" ]; then
   214	                return 1
   215	            fi
   216	        ;;
   220	        keyscript)
   221	            [ -n "${VALUE:+x}" ] || return 1 # must have a value
   222	            if [ "${VALUE#/}" = "$VALUE" ]; then
   223	                VALUE="/lib/cryptsetup/scripts/$VALUE"
   224	            fi
   225	            if [ ! -x "$VALUE" ] || [ ! -f "$VALUE" ]; then
   226	                return 1
   227	            fi
   228	        ;;
   281	run_keyscript() {
   282	    local keyscript keyscriptarg="$CRYPTTAB_KEY"
   283	    export CRYPTTAB_NAME CRYPTTAB_SOURCE CRYPTTAB_OPTIONS
   284	    export _CRYPTTAB_NAME _CRYPTTAB_SOURCE _CRYPTTAB_OPTIONS
   285	    export CRYPTTAB_TRIED="$1"
   287	    if [ -n "${CRYPTTAB_OPTION_keyscript+x}" ] && \
   288	            [ "$CRYPTTAB_OPTION_keyscript" != "/lib/cryptsetup/askpass" ]; then
   289	        export CRYPTTAB_KEY _CRYPTTAB_KEY
   290	        keyscript="$CRYPTTAB_OPTION_keyscript"
   292	    elif [ "$keyscriptarg" = "none" ]; then
   294	        keyscript="/lib/cryptsetup/askpass"
   295	        keyscriptarg="Please unlock disk $CRYPTTAB_NAME: "
   298	    exec "$keyscript" "$keyscriptarg"
   299	}
```

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'nl -ba /usr/share/initramfs-tools/scripts/local-top/cryptroot | sed -n "198,228p"'
   198	# Do we have any kernel boot arguments?
   199	if ! grep -qE '^(.*\s)?cryptopts=' /proc/cmdline; then
   200	    touch -- "$TABFILE"
   203	else
   205	    tr ' ' '\n' </proc/cmdline | sed -n 's/^cryptopts=//p' | while IFS= read cryptopts; do
   211	        IFS=","
   212	        for x in $cryptopts; do
   214	                target=*) target="${x#target=}";;
   215	                source=*) source="${x#source=}";;
   216	                key=*) key="${x#key=}";;
   217	                *) options="${options+$options,}$x";;
   225	            printf '%s %s %s %s\n' "${target:-cryptroot}" "$source" "${key:-none}" "${options-}"
   227	    done >"$TABFILE"
```

An attacker-owned absolute `keyscript=` is accepted if a caller already controls the crypttab-like option string, but the default attacker does not control any root-run option source:

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target bash -lc 'set -x; install -d /tmp/crypt-lpe-owned; printf "#!/bin/sh\nid > /tmp/crypt-lpe-owned/ran\n" > /tmp/crypt-lpe-owned/hook.sh; chmod +x /tmp/crypt-lpe-owned/hook.sh; cat > /tmp/crypt-lpe-owned/probe.sh <<'"'"'EOF'"'"'
. /lib/cryptsetup/functions
CRYPTTAB_NAME=t
CRYPTTAB_SOURCE=/dev/null
CRYPTTAB_KEY=none
_CRYPTTAB_OPTIONS=keyscript=/tmp/crypt-lpe-owned/hook.sh
crypttab_parse_options --export --missing-path=fail
rv=$?
printf "rv=%s\nkeyscript=%s\ntype=%s\n" "$rv" "${CRYPTTAB_OPTION_keyscript-}" "${CRYPTTAB_TYPE-}"
EOF
bash /tmp/crypt-lpe-owned/probe.sh 2>&1; rm -rf /tmp/crypt-lpe-owned'
cryptsetup: WARNING: t: couldn't determine device type, assuming default (plain).
cryptsetup: WARNING: Option 'cipher' missing in crypttab for plain dm-crypt mapping t. Please read /usr/share/doc/cryptsetup-initramfs/README.initramfs.gz and add the correct 'cipher' option to your crypttab(5).
cryptsetup: WARNING: Option 'size' missing in crypttab for plain dm-crypt mapping t. Please read /usr/share/doc/cryptsetup-initramfs/README.initramfs.gz and add the correct 'size' option to your crypttab(5).
cryptsetup: WARNING: Option 'hash' missing in crypttab for plain dm-crypt mapping t. Please read /usr/share/doc/cryptsetup-initramfs/README.initramfs.gz and add the correct 'hash' option to your crypttab(5).
rv=0
keyscript=/tmp/crypt-lpe-owned/hook.sh
type=plain
```

Direct helper execution stays at uid1001 or fails for lack of privileges:

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target sh -lc 'set -x; timeout 5 cryptdisks_start notarealtarget 2>&1; timeout 5 cryptdisks_stop notarealtarget 2>&1; printf pass | timeout 5 cryptsetup open --type plain --key-file - /tmp/no-such-device uid1001crypt 2>&1; id; ls -l /dev/mapper/uid1001crypt 2>&1'
+ timeout 5 cryptdisks_start notarealtarget
 * /usr/sbin/cryptdisks_start needs root privileges
+ timeout 5 cryptdisks_stop notarealtarget
 * /usr/sbin/cryptdisks_stop needs root privileges
+ printf pass
+ timeout 5 cryptsetup open --type plain --key-file - /tmp/no-such-device uid1001crypt
WARNING: Using default options for cipher (aes-xts-plain64, key size 256 bits) that could be incompatible with older versions.
Device /tmp/no-such-device does not exist or access denied.
+ id
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
+ ls -l /dev/mapper/uid1001crypt
ls: cannot access '/dev/mapper/uid1001crypt': No such file or directory
```

## initramfs root-exec/write boundary

`mkinitramfs` runs hook directories, including `/etc/initramfs-tools/hooks`, but those directories are root-owned. uid1001 can create a user-owned initrd in `/tmp`, which runs hooks as uid1001 and does not become root execution.

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'nl -ba /usr/sbin/mkinitramfs | sed -n "444,449p"; nl -ba /usr/share/initramfs-tools/hook-functions | sed -n "1014,1028p"'
   444	export STAGE_KERNEL_MODULE_COPYING=1
   445	run_scripts_optional /usr/share/initramfs-tools/hooks
   446	unset STAGE_KERNEL_MODULE_COPYING
   447	apply_add_modules
   448	run_scripts_optional "${CONFDIR}"/hooks
  1014	run_scripts()
  1015	{
  1016		scriptdir=${2:-}
  1017		initdir=${1}
  1018		[ ! -d "${initdir}" ] && return
  1020		runlist=$(get_prereq_pairs | tsort)
  1021		call_scripts "$scriptdir"
  1022	}
  1024	run_scripts_optional()
  1025	{
  1026		call_scripts_optional=y
  1027		run_scripts "$@"
  1028	}
```

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target sh -lc 'set -x; printf "#!/bin/sh\nid > /tmp/initramfs_uid1001_hook_ran\n" > /tmp/uid1001-hook; chmod +x /tmp/uid1001-hook; cp /tmp/uid1001-hook /etc/initramfs-tools/hooks/uid1001-hook 2>&1; cp /tmp/uid1001-hook /etc/initramfs-tools/scripts/local-top/uid1001-hook 2>&1; timeout 8 mkinitramfs -o /tmp/uid1001-initrd-probe.img >/tmp/uid1001-mkinitramfs.out 2>&1; rc=$?; echo rc=$rc; ls -l /tmp/initramfs_uid1001_hook_ran /etc/initramfs-tools/hooks/uid1001-hook /etc/initramfs-tools/scripts/local-top/uid1001-hook /tmp/uid1001-initrd-probe.img 2>&1; sed -n "1,80p" /tmp/uid1001-mkinitramfs.out; rm -f /tmp/uid1001-hook /tmp/uid1001-initrd-probe.img /tmp/uid1001-mkinitramfs.out /tmp/initramfs_uid1001_hook_ran'
+ cp /tmp/uid1001-hook /etc/initramfs-tools/hooks/uid1001-hook
cp: cannot create regular file '/etc/initramfs-tools/hooks/uid1001-hook': Permission denied
+ cp /tmp/uid1001-hook /etc/initramfs-tools/scripts/local-top/uid1001-hook
cp: cannot create regular file '/etc/initramfs-tools/scripts/local-top/uid1001-hook': Permission denied
rc=0
+ ls -l /tmp/initramfs_uid1001_hook_ran /etc/initramfs-tools/hooks/uid1001-hook /etc/initramfs-tools/scripts/local-top/uid1001-hook /tmp/uid1001-initrd-probe.img
ls: cannot access '/tmp/initramfs_uid1001_hook_ran': No such file or directory
ls: cannot access '/etc/initramfs-tools/hooks/uid1001-hook': No such file or directory
ls: cannot access '/etc/initramfs-tools/scripts/local-top/uid1001-hook': No such file or directory
-rw-r--r-- 1 attacker attacker 15721937 May 16 13:14 /tmp/uid1001-initrd-probe.img
W: Kernel configuration /boot/config-6.10.14-linuxkit is missing, cannot check for zstd compression support (CONFIG_RD_ZSTD)
W: missing /lib/modules/6.10.14-linuxkit
W: Ensure all necessary drivers are built into the linux image!
cryptsetup: ERROR: Couldn't resolve device overlay
cryptsetup: WARNING: Couldn't determine root device
cp: cannot open '/etc/iscsi/initiatorname.iscsi' for reading: Permission denied
```

`update-initramfs -u -k all` returns successfully only because there is no initrd under `/boot` to update in this container:

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target sh -lc 'set -x; timeout 5 update-initramfs -u -k all 2>&1; echo rc=$?; ls -la /boot | sed -n "1,120p"'
+ timeout 5 update-initramfs -u -k all
rc=0
+ ls -la /boot
total 8
drwxr-xr-x 2 root root 4096 Apr 22  2024 .
drwxr-xr-x 1 root root 4096 May 16 12:00 ..
```

## finalrd ExecStop boundary

`finalrd.service` is active/exited and has root `ExecStop=/usr/bin/finalrd`. `finalrd` runs `*.finalrd` hooks from `/usr/share/finalrd`, `/etc/finalrd`, and `/run/finalrd`, but only `/usr/share/finalrd` exists by default and is root-owned. `/run` is not uid1001-writable, so uid1001 cannot create `/run/finalrd` or place a shutdown hook there.

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'systemctl cat finalrd.service --no-pager 2>&1; nl -ba /usr/bin/finalrd | sed -n "1,80p"; stat -c "%A %U %G %n" /run /run/finalrd /etc/finalrd /run/initramfs /run/finalrd-libs.conf 2>&1'
# /usr/lib/systemd/system/finalrd.service
[Service]
RemainAfterExit=yes
Type=oneshot
ExecStart=/bin/true
ExecStop=/usr/bin/finalrd
     1	#!/bin/sh
     8	export DESTDIR=/run/initramfs
    15	[ ! -x $DESTDIR/bin/sh ] || exit 0
    19	mount -o remount,exec /run
    56	for d in /usr/share/finalrd /etc/finalrd /run/finalrd
    57	do
    58	    if [ -d $d ]
    59	    then
    60		run-parts -v --regex='^.*\.finalrd$' --arg=setup -- $d || :
    61		find $d -executable -name '*.finalrd' -exec cp -- "{}" $DESTDIR/lib/systemd/system-shutdown \;
    62	    fi
    63	done
drwxr-xr-x root root /run
stat: cannot statx '/run/finalrd': No such file or directory
stat: cannot statx '/etc/finalrd': No such file or directory
stat: cannot statx '/run/initramfs': No such file or directory
stat: cannot statx '/run/finalrd-libs.conf': No such file or directory
```

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target sh -lc 'set -x; mkdir /run/finalrd 2>&1; mkdir /etc/finalrd 2>&1; printf "#!/bin/sh\nid > /tmp/finalrd_uid1001_ran\n" > /tmp/uid1001.finalrd; chmod +x /tmp/uid1001.finalrd; cp /tmp/uid1001.finalrd /run/finalrd/uid1001.finalrd 2>&1; cp /tmp/uid1001.finalrd /etc/finalrd/uid1001.finalrd 2>&1; timeout 5 /usr/bin/finalrd 2>&1; ls -l /tmp/finalrd_uid1001_ran /run/initramfs 2>&1; rm -f /tmp/uid1001.finalrd /tmp/finalrd_uid1001_ran 2>/dev/null || true'
+ mkdir /run/finalrd
mkdir: cannot create directory '/run/finalrd': Permission denied
+ mkdir /etc/finalrd
mkdir: cannot create directory '/etc/finalrd': Permission denied
+ cp /tmp/uid1001.finalrd /run/finalrd/uid1001.finalrd
cp: cannot create regular file '/run/finalrd/uid1001.finalrd': No such file or directory
+ cp /tmp/uid1001.finalrd /etc/finalrd/uid1001.finalrd
cp: cannot create regular file '/etc/finalrd/uid1001.finalrd': No such file or directory
+ timeout 5 /usr/bin/finalrd
mount: /run: must be superuser to use mount.
+ ls -l /tmp/finalrd_uid1001_ran /run/initramfs
ls: cannot access '/tmp/finalrd_uid1001_ran': No such file or directory
ls: cannot access '/run/initramfs': No such file or directory
```

uid1001 also cannot stop `finalrd.service` to trigger root `ExecStop`:

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target sh -lc 'set -x; timeout 5 systemctl stop finalrd.service 2>&1'
+ timeout 5 systemctl stop finalrd.service
Failed to stop finalrd.service: Interactive authentication required.
See system logs and 'systemctl status finalrd.service' for details.
```

## friendly-recovery boundary

The generator only switches default target when `/proc/cmdline` contains `recovery`; the target and option scripts are root-owned. uid1001 cannot create `/run/friendly_recovery.resume` and cannot start/isolate the recovery target without authentication.

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'cat /proc/cmdline; ls -l /run/friendly_recovery.resume 2>&1 || true; stat -c "%A %U %G %n" /lib/systemd/system-generators/friendly-recovery /lib/recovery-mode/recovery-menu /lib/recovery-mode/options/*'
init=/init loglevel=1 root=/dev/vdb rootfstype=erofs ro vsyscall=emulate panic=0 eth0.dhcp eth1.dhcp linuxkit.unified_cgroup_hierarchy=1 console=hvc0   virtio_net.disable_csum=1 vpnkit.connect=connect://2/1999 com.docker.VMID=4fbac003-a656-4a95-bebf-3a971e6c6566
ls: cannot access '/run/friendly_recovery.resume': No such file or directory
-rwxr-xr-x root root /lib/systemd/system-generators/friendly-recovery
-rwxr-xr-x root root /lib/recovery-mode/recovery-menu
-rwxr-xr-x root root /lib/recovery-mode/options/apt-snapshots
-rwxr-xr-x root root /lib/recovery-mode/options/clean
-rwxr-xr-x root root /lib/recovery-mode/options/dpkg
-rwxr-xr-x root root /lib/recovery-mode/options/failsafeX
-rwxr-xr-x root root /lib/recovery-mode/options/fsck
-rwxr-xr-x root root /lib/recovery-mode/options/grub
-rwxr-xr-x root root /lib/recovery-mode/options/network
-rwxr-xr-x root root /lib/recovery-mode/options/root
-rwxr-xr-x root root /lib/recovery-mode/options/system-summary
```

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target sh -lc 'set -x; touch /run/friendly_recovery.resume 2>&1; /lib/systemd/system-generators/friendly-recovery /tmp/gen-normal /tmp/gen-early /tmp/gen-late 2>&1; echo rc=$?; find /tmp/gen-normal /tmp/gen-early /tmp/gen-late -maxdepth 2 -ls 2>&1; rm -rf /tmp/gen-normal /tmp/gen-early /tmp/gen-late'
+ touch /run/friendly_recovery.resume
touch: cannot touch '/run/friendly_recovery.resume': Permission denied
+ /lib/systemd/system-generators/friendly-recovery /tmp/gen-normal /tmp/gen-early /tmp/gen-late
+ echo rc=0
rc=0
+ find /tmp/gen-normal /tmp/gen-early /tmp/gen-late -maxdepth 2 -ls
find: '/tmp/gen-normal': No such file or directory
find: '/tmp/gen-early': No such file or directory
find: '/tmp/gen-late': No such file or directory
```

```sh
$ docker exec -u 1001:1001 ubuntu24-server-lpe-target sh -lc 'set -x; timeout 5 systemctl start friendly-recovery.service 2>&1; timeout 5 systemctl isolate friendly-recovery.target 2>&1; timeout 5 systemctl restart systemd-ask-password-console.path 2>&1; timeout 5 systemctl start systemd-ask-password-wall.service 2>&1'
+ timeout 5 systemctl start friendly-recovery.service
Failed to start friendly-recovery.service: Interactive authentication required.
See system logs and 'systemctl status friendly-recovery.service' for details.
+ timeout 5 systemctl isolate friendly-recovery.target
Failed to start friendly-recovery.target: Interactive authentication required.
See system logs and 'systemctl status friendly-recovery.target' for details.
+ timeout 5 systemctl restart systemd-ask-password-console.path
Failed to restart systemd-ask-password-console.path: Interactive authentication required.
See system logs and 'systemctl status systemd-ask-password-console.path' for details.
+ timeout 5 systemctl start systemd-ask-password-wall.service
Failed to start systemd-ask-password-wall.service: Interactive authentication required.
See system logs and 'systemctl status systemd-ask-password-wall.service' for details.
```

## Cleanup verification

All probe files under `/tmp` were removed; no ask-password request remained:

```sh
$ docker exec ubuntu24-server-lpe-target sh -lc 'find /tmp -maxdepth 1 \( -name "root-ask.*" -o -name "uid1001*" -o -name "finalrd_uid1001_ran" -o -name "initramfs_uid1001_hook_ran" -o -name "crypt-lpe-owned" -o -name "gen-*" \) -printf "%M %u %g %p\n" 2>/dev/null; find /run/systemd/ask-password -maxdepth 1 -printf "%M %u %g %p\n" 2>/dev/null | sort'
drwxr-xr-x root root /run/systemd/ask-password
```

## Conclusion

Negative. The default Ubuntu 24.04 Server target has the audited packages installed and several relevant systemd units active, but uid1001 cannot control the root-run inputs:

- cryptsetup `keyscript=` and `check=` can execute configured executables, including absolute paths, but only from root-owned crypttab/initramfs/kernel-command-line sources in this default state.
- initramfs hook execution is reachable by `mkinitramfs`, but root execution requires root-owned hook directories; uid1001 can only build an attacker-owned image in `/tmp`.
- finalrd has a root `ExecStop` hook surface, but default hook directories are root-owned/nonexistent and uid1001 cannot create `/run/finalrd`, `/etc/finalrd`, or stop the service.
- friendly-recovery is gated by kernel command line/systemctl authorization and root-owned option scripts.
- systemd ask-password request files are visible enough to list root prompts, but the reply socket is `srw------- root root` and uid1001 cannot create prompts, query root prompts, or write replies.

No `notes/<finding>.md` or `pocs/<finding>.sh` were created because no real uid1001-to-root escalation was validated.
