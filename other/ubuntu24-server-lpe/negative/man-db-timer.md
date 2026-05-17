# man-db / mandb timer negative LPE audit

Target: `ubuntu24-server-lpe-target`, stock Ubuntu `24.04.4 LTS (noble)`
Docker/systemd server image.  Attacker: uid `1001(attacker)`, gid
`1001(attacker)`, no sudo or special groups.

Conclusion: no uid1001 -> root LPE was found in the default `man-db.timer` /
`man-db.service` / `mandb` path.  The only root operation in the timer is a
fixed `install -d` for `/var/cache/man`; `mandb` itself runs as uid `man`
(`6`) and the default scanned source paths and cache paths are not writable by
the attacker.  User-controlled manpage content, decompression, preprocessors,
locale/env/PATH, symlink/hardlink preseed, and cache writes did not produce
root code execution or root-owned file overwrite.

## Default state proof

Command:

```sh
docker exec ubuntu24-server-lpe-target bash -lc '
  id attacker
  cat /etc/os-release
  systemctl cat man-db.timer man-db.service
  systemctl list-timers --all --no-pager | grep -E "man-db|mandb" || true
'
docker exec ubuntu24-server-lpe-target bash -lc \
  "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${db:Status-Abbrev}\n' \
   man-db groff-base xz-utils gzip bzip2 2>&1 || true"
```

Evidence:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
PRETTY_NAME="Ubuntu 24.04.4 LTS"

bzip2          un
groff-base     1.23.0-3build2                 ii
gzip           1.12-1ubuntu3.1                ii
man-db         2.12.0-4build2                 ii
xz-utils       5.6.1+really5.4.5-1ubuntu0.2  ii

# /usr/lib/systemd/system/man-db.timer
[Timer]
OnCalendar=daily
RandomizedDelaySec=12h
Persistent=true

# /usr/lib/systemd/system/man-db.service
ExecStart=+/usr/bin/install -d -o man -g man -m 0755 /var/cache/man
ExecStart=/usr/bin/mandb --quiet
User=man
ProtectSystem=full
PrivateTmp=true
ProtectHome=true

man-db.timer - Daily man-db regeneration
Loaded: loaded (/usr/lib/systemd/system/man-db.timer; enabled; preset: enabled)
Active: active (waiting)
Triggers: man-db.service
```

Binary/debconf state:

```text
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
attacker:x:1001:1001::/home/attacker:/bin/bash
man-db/install-setuid: false
man-db/auto-update: true

-rwxr-xr-x root root /usr/bin/mandb
-rwxr-xr-x root root /usr/bin/manpath
-rwxr-xr-x root root /usr/bin/man-recode
-rwxr-xr-x root root /usr/bin/lexgrog
-rwxr-xr-x root root /usr/bin/catman
-rwxr-xr-x root root /usr/sbin/accessdb
```

There is no standalone `/usr/bin/manconv` in this install.

## Configured manpaths and permissions

Active `/etc/manpath.config` directives:

```text
MANDATORY_MANPATH            /usr/man
MANDATORY_MANPATH            /usr/share/man
MANDATORY_MANPATH            /usr/local/share/man
MANDB_MAP /usr/man           /var/cache/man/fsstnd
MANDB_MAP /usr/share/man     /var/cache/man
MANDB_MAP /usr/local/man     /var/cache/man/oldlocal
MANDB_MAP /usr/local/share/man /var/cache/man/local
MANDB_MAP /usr/X11R6/man     /var/cache/man/X11R6
MANDB_MAP /opt/man           /var/cache/man/opt
MANDB_MAP /snap/man          /var/cache/man/snap
```

`manpath -g` returned:

```text
/usr/man:/usr/share/man:/usr/local/man:/usr/local/share/man:/usr/X11R6/man:/opt/man:/snap/man
```

Path metadata:

```text
/usr/share/man               root:root 0755
/usr/local/share/man         root:root 0755
/usr/local/man -> share/man  root:root symlink through root-owned parents
/var/cache/man               man:man   0755
/usr/man                     absent; parent /usr is root:root 0755
/usr/X11R6/man               absent; parent /usr is root:root 0755
/opt/man                     absent; parent /opt is root:root 0755
/snap/man                    absent; parent /snap is root:root 0755
```

Attacker-writable directory search under all configured source/cache roots:

```sh
runuser -u attacker -- bash -lc '
  for p in /usr/man /usr/share/man /usr/local/man /usr/local/share/man \
           /usr/X11R6/man /opt/man /snap/man /var/cache/man; do
    [ -e "$p" ] && find "$p" -xdev -type d -writable -printf "%M %u:%g %p\n"
  done
'
```

Output was empty.

Direct placement and link probes as attacker:

```text
-- /usr/share/man
mkdir: Permission denied
touch: Permission denied
symlink: Permission denied
hardlink /etc/shadow: Operation not permitted
-- /usr/local/share/man
mkdir: Permission denied
touch: Permission denied
symlink: Permission denied
hardlink /etc/shadow: Operation not permitted
-- /var/cache/man
mkdir: Permission denied
touch: Permission denied
symlink: Permission denied
hardlink /etc/shadow: Operation not permitted
-- /var/cache/man/cat1
mkdir: Permission denied
touch: Permission denied
symlink: Permission denied
hardlink /etc/shadow: Operation not permitted
```

No `mandb_lpe_*` probe artifacts remained afterward.

## Service trigger, environment, and PATH

The attacker cannot directly trigger the root unit:

```text
$ runuser -u attacker -- systemctl start man-db.service
Failed to start man-db.service: Interactive authentication required.
```

Effective unit environment is not attacker-supplied:

```text
Environment=
PassEnvironment=
UnsetEnvironment=
User=man
ProtectSystem=full
PrivateTmp=yes
ProtectHome=yes
```

External helper lookup directories observed/tested for decompression are all
root-owned and not writable by uid1001:

```text
/usr/local/sbin not-writable
/usr/local/bin  not-writable
/usr/sbin       not-writable
/usr/bin        not-writable
/sbin           not-writable
/bin            not-writable
```

Attacker-controlled `MANPATH` only affects attacker-run `mandb`; it does not
feed the timer.  As uid1001:

```text
mandb: warning: $MANPATH set, ignoring /etc/manpath.config
Only the 'man' user can create or update system-wide databases; acting as if
the --user-db option was used.
final search path = /tmp/mandb_attacker_man
create_db(/tmp/mandb_attacker_man): /tmp/mandb_attacker_man/<pid>
```

## mandb behavior under the service user

A real service run completed with the root `install -d` followed by
unprivileged `mandb`:

```text
Process: ExecStart=/usr/bin/install -d -o man -g man -m 0755 /var/cache/man
         (code=exited, status=0/SUCCESS)
Process: ExecStart=/usr/bin/mandb --quiet
         (code=exited, status=0/SUCCESS)
```

`mandb --debug --no-purge --test` as `man` showed the effective IDs and
scanner roots:

```text
ruid=6, euid=6
rgid=12, egid=12
final search path = /usr/share/man:/usr/local/man
create_db(/usr/share/man): /var/cache/man/<pid>
```

Current cache files after the default service run are unprivileged `man:man`
database/tag files, not root-owned outputs:

```text
-rw-r--r-- man:man 16384 /var/cache/man/index.db
-rw-r--r-- man:man 16384 /var/cache/man/*/index.db
-rw-r--r-- man:man   190 /var/cache/man/CACHEDIR.TAG
-rw-r--r-- man:man   190 /var/cache/man/*/CACHEDIR.TAG
```

For a synthetic root-owned page under default `/usr/local/share/man`, a
non-test write trace as `man` showed only cache writes under `/var/cache/man`
using a temporary pid file and `renameat` to `index.db`:

```text
mkdirat(AT_FDCWD, "/var/cache/man/local", 0755) = 0
mkdirat(AT_FDCWD, "/var/cache/man/local/cat1", 0755) = 0
openat(AT_FDCWD, "/var/cache/man/local/<pid>", O_RDWR|O_CREAT, 0644) = 4
openat(AT_FDCWD, "/usr/local/share/man/man1/mandb_lpe_final.1.gz", O_RDONLY) = 5
renameat(AT_FDCWD, "/var/cache/man/local/<pid>",
         AT_FDCWD, "/var/cache/man/local/index.db") = 0
```

Because uid1001 cannot create files in `/var/cache/man` or its cat/cache
subdirectories, the attacker cannot preseed temp files, symlinks, hardlinks, or
replacement database paths for this write path.  The root `install -d` target
is also not path-controllable because `/var/cache` is `root:root` `0755`, so
uid1001 cannot replace `/var/cache/man` with a symlink.

## Decompression, preprocessors, and manpage content

Synthetic root-owned page used to test roff shell escapes:

```roff
.\" t
.TH MANDB_LPE_PROBE 1 "2026-05-16" "probe" "probe"
.SH NAME
mandb_lpe_probe \- mandb lpe probe
.SH DESCRIPTION
.sy /bin/sh -c "id > /tmp/mandb_lpe_owned"
.pso /bin/sh -c "id >> /tmp/mandb_lpe_owned"
```

Running `mandb --debug --no-purge --test /usr/local/share/man` as uid `man`
indexed the page but did not execute the roff shell escapes:

```text
test_manfile: considering /usr/local/share/man/man1/mandb_lpe_probe.1
loading seccomp filter (permissive: 0)
trying encoding UTF-8 -> UTF-8//IGNORE
"mandb_lpe_probe - mandb lpe probe"
record = 'mandb_lpe_probe - mandb lpe probe'

shell escape proof file: not created
```

`strace -ff -e trace=execve` for the plain page showed no child exec beyond
`/usr/bin/mandb`.  For `.xz` compressed synthetic pages, `mandb` did invoke
`xz -dc`, but from the uid `man` process and through non-attacker-writable
PATH entries:

```text
execve("/usr/bin/mandb", ["/usr/bin/mandb", "--debug", "--no-purge",
       "--test", "/usr/local/share/man"], ...) = 0
execve("/usr/local/sbin/xz", ["xz", "-dc"], ...) = -1 ENOENT
execve("/usr/local/bin/xz",  ["xz", "-dc"], ...) = -1 ENOENT
execve("/usr/sbin/xz",      ["xz", "-dc"], ...) = -1 ENOENT
execve("/usr/bin/xz",       ["xz", "-dc"], ...) = 0

shell escape proof file: not created
```

`.gz` pages were indexed without external `gzip` execution in the observed
trace.  `bzip2` is not installed in this default target.  In all cases, the
timer's content-processing privilege is uid `man`, not root, and uid1001 has
no default path to place the content.

## Cleanup

Synthetic files and cache directories created for probing were removed:

```text
find /usr/local/share/man /var/cache/man /tmp /home/attacker \
  -name "mandb_lpe*" -o -name "mandb_attacker_man"

# output: empty

/var/cache/man/local absent
/var/cache/man/oldlocal absent
/usr/local/share/man/man1 absent
```

A final `systemctl start man-db.service` still completed cleanly:

```text
ExecStart=/usr/bin/install -d -o man -g man -m 0755 /var/cache/man
ExecStart=/usr/bin/mandb --quiet
code=exited, status=0/SUCCESS
```
