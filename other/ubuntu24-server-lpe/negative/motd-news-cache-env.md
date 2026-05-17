# motd-news CACHE environment propagation: negative

## Scope and target

- Target: `ubuntu24-server-lpe-target`
- OS: Ubuntu 24.04.4 LTS (`noble`)
- Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`
- Passworded non-admin model user: `uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)`
- Packages:
  - `base-files 13ubuntu10.4`
  - `login 1:4.13+dfsg1-4ubuntu3.2`
  - `libpam-modules 1.5.3-5ubuntu5.5`
  - `libpam-runtime 1.5.3-5ubuntu5.5`
  - `python3-pexpect 4.9-2`
  - `wget 1.21.4-1ubuntu4.1`
  - `systemd 255.4-1ubuntu8.15`
- Result: no uid1001 -> root LPE found.

Probe/log:

```text
pocs/motd_news_cache_env_probe.sh
logs/motd-news-cache-env.out
```

## Why this looked interesting

`/etc/update-motd.d/50-motd-news` is root-owned, default-enabled, and uses `CACHE` from the inherited environment unless the variable is empty:

```text
33 [ -r /etc/default/motd-news ] && . /etc/default/motd-news
37 [ "$ENABLED" = "1" ] || exit 0
40 [ -n "$URLS" ] || URLS="https://motd.ubuntu.com"
42 [ -n "$CACHE" ] || CACHE="/var/cache/motd-news"
55 if [ "$FORCED" != "1" ]; then
56     if [ -r $CACHE ]; then
58         safe_print $CACHE
59     elif [ "$(id -u)" -eq 0 ]; then
60         : > $CACHE
```

The forced systemd-timer path also writes to an unquoted `$CACHE`:

```text
140 safe_print "$NEWS" 2>/dev/null >$CACHE || true
142 : > "$CACHE"
```

Running the script directly as root with a hostile `CACHE` proved the primitive would matter if uid1001 could inject that environment into a root invocation:

```sh
env -i CACHE=/root/motd_news_cache_env_root URLS=https://example.invalid ENABLED=1 \
  /etc/update-motd.d/50-motd-news
```

Result:

```text
-rw-r--r-- root:root 0 /root/motd_news_cache_env_root
```

## Default reachability proof

The default login PAM stack includes MOTD only in `/etc/pam.d/login`:

```text
33 session optional pam_motd.so motd=/run/motd.dynamic
34 session optional pam_motd.so noupdate
```

No other default PAM service in the target includes `pam_motd`. The relevant files are root-owned:

```text
-rw-r--r-- root:root /etc/default/motd-news
-rwxr-xr-x root:root /etc/update-motd.d/50-motd-news
-rw-r--r-- root:root /etc/pam.d/login
-rwxr-xr-x root:root /usr/bin/login
-rwsr-xr-x root:root /usr/bin/su
drwxr-xr-x root:root /var/cache
```

## Unprivileged trigger attempts

uid1001 direct execution stayed unprivileged and could not write `/root`:

```sh
runuser -u attacker -- env CACHE=/root/motd_news_cache_env_root \
  URLS=https://example.invalid ENABLED=1 /etc/update-motd.d/50-motd-news
```

`/usr/bin/login` is not setuid, so a shell user cannot invoke the login PAM stack as root:

```text
login: Cannot possibly work without effective root
```

uid1001 also could not poison the system manager environment or manually run the timer service:

```text
systemctl set-environment CACHE=/root/motd_news_cache_env_root
# Failed to set environment: Access denied

systemctl start motd-news.service
# Interactive authentication required
```

## Real PAM session result

The probe drove a real pty-backed root `/bin/login -p selfauth` session with hostile `CACHE`, `URLS`, and `ENABLED` in the login process environment. The final non-admin shell did inherit those variables:

```text
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
CACHE=/root/motd_news_cache_env_root
ENABLED=1
URLS=https://example.invalid
```

But no root marker was created:

```text
stat: cannot statx '/root/motd_news_cache_env_root': No such file or directory
stat: cannot statx '/tmp/motd_news_cache_env_root': No such file or directory
```

This shows the attacker-visible preserved login environment did not become the environment for a privileged `50-motd-news` root write in the default PAM path.

The setuid `su -p selfauth` path also preserved the variables into the final uid1002 command, but `/etc/pam.d/su` has no `pam_motd` entry and created no marker.

## Root proof

No root proof exists. The only root-owned marker was created by the root-only impact canary and removed before the trigger tests. The actual uid1001 and real PAM-session attempts left both markers absent:

```text
/root/motd_news_cache_env_root: absent
/tmp/motd_news_cache_env_root: absent
```

Final target health:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> no failed units
```

## Cleanup

```sh
rm -f /root/motd_news_cache_env_root /tmp/motd_news_cache_env_root
systemctl unset-environment CACHE URLS ENABLED
```

## Why scanners may miss the boundary

A static scanner can correctly flag unquoted root shell writes through `$CACHE`, but exploitability depends on the exact caller. The default systemd timer has a clean root environment, uid1001 cannot set the system manager environment, `/usr/bin/login` is not setuid, and the real PAM login path did not pass the preserved user-visible variables into a root `50-motd-news` write.

## Ubuntu Security triage note

No vulnerability is claimed. Defense in depth would still be to initialize `CACHE` from `/etc/default/motd-news` or a fixed default after clearing inherited environment, and quote `"$CACHE"` consistently in `50-motd-news`.
