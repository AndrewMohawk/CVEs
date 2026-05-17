# Negative: PAM MOTD landscape-sysinfo real/effective UID boundary

Result: no validated local privilege escalation. A real `/bin/login -f selfauth`
PAM session triggered `pam_motd` and root `/etc/update-motd.d/50-landscape-sysinfo`,
but the Landscape sysinfo process did not import the user's
`~/.landscape/sysinfo.conf`, did not create a user sysinfo log, and produced only the
default root-owned MOTD cache. No root marker was created.

Artifacts:

```text
pocs/pam_motd_landscape_ruid_probe.sh
logs/pam-motd-landscape-ruid.out
```

## Default proof

The target was stock Ubuntu 24.04.4 Server with:

```text
landscape-common 24.02-0ubuntu5.7
libpam-modules:arm64 1.5.3-5ubuntu5.5
login 1:4.13+dfsg1-4ubuntu3.2
systemd 255.4-1ubuntu8.15
```

The default PAM login stack runs MOTD only from `login`:

```text
/etc/pam.d/login:33 session optional pam_motd.so motd=/run/motd.dynamic
/etc/pam.d/login:34 session optional pam_motd.so noupdate
```

The suspicious wrapper is root-owned and writes a fixed cache:

```text
/etc/update-motd.d/50-landscape-sysinfo:5  CACHE="/var/lib/landscape/landscape-sysinfo.cache"
/etc/update-motd.d/50-landscape-sysinfo:17 [ -f /etc/default/locale ] && . /etc/default/locale
/etc/update-motd.d/50-landscape-sysinfo:27 "$(/usr/bin/landscape-sysinfo)"
```

The reason for checking this was that `landscape-sysinfo` uses `os.getuid()` rather than
`os.geteuid()` to decide whether to include a user config:

```text
/usr/lib/python3/dist-packages/landscape/sysinfo/deployment.py:34 default_config_filenames = ("/etc/landscape/client.conf",)
/usr/lib/python3/dist-packages/landscape/sysinfo/deployment.py:35 if os.getuid() != 0:
/usr/lib/python3/dist-packages/landscape/sysinfo/deployment.py:37 os.path.expanduser("~/.landscape/sysinfo.conf")
/usr/lib/python3/dist-packages/landscape/sysinfo/deployment.py:93-96 namedClass("landscape.sysinfo.<plugin>.<Plugin>")
```

## Probe

The probe planted a user-controlled canary config:

```ini
[sysinfo]
sysinfo-plugins = TestPlugin
width = 80
```

If the root MOTD process had loaded that file, the cache would have contained
`Test header`. After removing the stale cache and logging in on tty1 with
`openvt -c 1 -s -f -w -- /bin/login -f selfauth`, the login shell ran as:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

The generated cache was root-owned and contained only the default sysinfo output:

```text
-rw-r--r-- root:root /var/lib/landscape/landscape-sysinfo.cache
USER_CONFIG_IMPORTED=NO
ROOT_PROOF=NO
```

No `/home/selfauth/.landscape/sysinfo.log` appeared, which matches the root path in
`get_landscape_log_directory()` and confirms the PAM-time process did not combine
user real UID config selection with root effective UID execution.

## Why scanners may miss it

This is a PAM-time real/effective UID trust-boundary question, not a parser crash or
simple writable-path bug. A scanner can flag `os.getuid()` and dynamic plugin imports,
but exploitability depends on the exact credentials used by `pam_motd` while running
`/etc/update-motd.d` under `/bin/login`.

## Suggested fix

No Ubuntu Security fix is warranted from this probe because no LPE was proven.
Defense-in-depth would be to use `os.geteuid()` for root/user configuration and log-path
decisions in `landscape-sysinfo`, making the boundary explicit if any future PAM caller
changes credential ordering.
