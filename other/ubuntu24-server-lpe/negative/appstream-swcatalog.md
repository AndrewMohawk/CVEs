# AppStream / swcatalog negative result

Verdict: no validated default LPE for normal non-sudo users `attacker` uid1001 or `selfauth` uid1002 in `ubuntu24-server-lpe-target`.

## Exact target/package state

Probe log: `logs/appstream-swcatalog.out`

Target is Ubuntu 24.04.4 LTS noble. Users are plain primary-group-only accounts:

```text
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1002(selfauth) gid=1002(selfauth) groups=1002(selfauth)
```

Installed versions:

```text
appstream              1.0.2-1build6
libappstream5:arm64    1.0.2-1build6
packagekit             1.2.8-2ubuntu1.5
packagekit-tools       1.2.8-2ubuntu1.5
apt                    2.8.3
AppStream version      1.0.2
```

## Default root hook/config evidence

`/etc/apt/apt.conf.d/50appstream` is root-owned `0644` and installs DEP-11 index targets plus this root apt update hook:

```text
APT::Update::Post-Invoke-Success {
    "if /usr/bin/test -w /var/cache/swcatalog -a -e /usr/bin/appstreamcli; then appstreamcli refresh --source=os > /dev/null || true; fi";
};
```

`appstreamcli status --verbose` showed the default OS sources as root-owned local metadata and apt DEP-11 catalog data:

```text
Data from locally installed software
  /usr/share/applications
  /usr/share/metainfo
Using cache file: /var/cache/swcatalog/cache/C-local-metainfo.xb
```

APT DEP-11 inputs are present under `/var/lib/apt/lists/*_dep11_Components-arm64.yml.gz`, all root-owned `0644`; `/var/lib/apt/lists/partial` is `_apt:root` `0700`.

## Reachability attempts

Both `attacker` and `selfauth` lack write access to the relevant default root inputs/sinks:

```text
/var/cache/swcatalog          writable=no
/var/cache/swcatalog/cache    writable=no
/usr/share/metainfo           writable=no
/var/lib/apt/lists            writable=no
/etc/apt/apt.conf.d           writable=no
/usr/local/bin                writable=no
```

Explicit symlink placement attempts as uid1001 into `/var/cache/swcatalog`, `/var/cache/swcatalog/cache`, `/usr/share/metainfo`, `/var/lib/apt/lists`, and `/usr/local/bin/appstreamcli` all failed with `Permission denied`.

Unprivileged trigger commands tested:

```bash
HOME=/tmp/as-swcatalog-apt-home timeout 20s apt-get update
HOME=/tmp/as-swcatalog-home-attacker timeout 25s pkcon refresh force
HOME=/tmp/as-swcatalog-home-selfauth timeout 25s pkcon refresh force
HOME=/tmp/as-swcatalog-home-attacker XDG_CACHE_HOME=/tmp/as-swcatalog-home-attacker/.cache appstreamcli refresh --source=os --force
appstreamcli refresh --source=os --force --datapath=/tmp/as-swcatalog-probe/data --cachepath=/tmp/as-swcatalog-probe/cache
```

Results:

```text
apt-get update: Could not open lock file /var/lib/apt/lists/lock - Permission denied
pkcon refresh force: Fatal error: Failed to obtain authentication
appstreamcli refresh: Only refreshing metadata cache specific to the current user
```

The uid1001 AppStream refresh wrote only attacker-owned cache files under the chosen user cache path, including with attacker-controlled XML containing path traversal-like launchable text and a `file:///root/...` URL. No root-owned output or root execution resulted.

PackageKit is D-Bus activated as root (`Exec=/usr/libexec/packagekitd`, `User=root`). Its refresh policy has `allow_active=yes` and `allow_inactive=yes`, but the tested non-session uid1001/uid1002 commands still failed authentication. Even if a real active local session can trigger refresh on another deployment, this lane did not find a default way for that user to influence the root-owned AppStream/APT metadata inputs or cache path.

## Symlink/race result

There is a real sink if root is deliberately pointed at an attacker-writable cache path. In a controlled `/tmp` test, root `appstreamcli refresh --datapath=/tmp/... --cachepath=/tmp/.../cache` followed a preplaced attacker-owned cache symlink and wrote a root-owned victim file:

```text
lrwxrwxrwx attacker attacker ... cache/C-...xb -> /tmp/as-swcatalog-symlink/victim
-rw-r--r-- root root 97785 /tmp/as-swcatalog-symlink/victim
```

This is not a default LPE because the default root hook uses `/var/cache/swcatalog/cache`, and uid1001/uid1002 cannot create or replace files there. The hook also does not accept user-provided `--cachepath` or `--datapath`.

## Cleanup

`pocs/appstream_swcatalog_probe.sh` removes its temporary paths on exit:

```text
/tmp/as-swcatalog-probe
/tmp/as-swcatalog-symlink
/tmp/as-swcatalog-apt-home
/tmp/as-swcatalog-source
/tmp/as-swcatalog-home-attacker
/tmp/as-swcatalog-home-selfauth
```

The generated log confirms all six paths were removed.

## Scanner-miss reason

A scanner can reasonably flag three suspicious facts: root APT runs an AppStream cache hook, the hook invokes `appstreamcli` without an absolute command path, and root AppStream cache writes follow a final symlink when root is given an attacker-writable cache path. The exploitable chain is missing in the stock target: normal users cannot write the cache, metadata, apt list, apt hook, or earlier PATH directories, and unprivileged AppStream refreshes are user-cache-only.

## Hardening notes

Use `/usr/bin/appstreamcli` in `50appstream` to remove PATH ambiguity. Keep `/var/cache/swcatalog{,/cache}`, `/usr/share/metainfo`, `/var/lib/apt/lists`, and `/usr/local/{sbin,bin}` root-owned and non-writable by normal users. AppStream should avoid following final cache-path symlinks for system refreshes, for example with no-follow open/rename semantics. On servers that do not need desktop software management, disabling PackageKit or tightening its refresh policy reduces root refresh surface.
