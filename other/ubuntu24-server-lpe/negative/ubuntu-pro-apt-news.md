# Negative: Ubuntu Pro apt-news and apt hook surfaces

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default in Docker. Scope was normal local users `attacker` uid1001 and `selfauth` uid1002, without sudo/docker/lxd/adm assumptions.

Result: no validated uid1001/uid1002 -> root LPE. Root proof: no.

Rerun:

```sh
bash -n pocs/ubuntu_pro_apt_news_probe.sh
pocs/ubuntu_pro_apt_news_probe.sh ubuntu24-server-lpe-target
```

The executed log is `logs/ubuntu-pro-apt-news.out`.

## Default package and hook proof

Default installed versions observed:

```text
apt                         2.8.3
ubuntu-pro-client           37.2ubuntu~24.04
ubuntu-pro-client-l10n      37.2ubuntu~24.04
update-notifier-common      3.192.68.2
unattended-upgrades         2.9.1+nmu4ubuntu1
libpam-modules:arm64        1.5.3-5ubuntu5.5
login                       1:4.13+dfsg1-4ubuntu3.2
systemd                     255.4-1ubuntu8.15
```

The apt hook file is root-owned `0644`:

```text
/etc/apt/apt.conf.d/20apt-esm-hook.conf
APT::Update::Pre-Invoke {
  "[ ! -e /run/systemd/system ] || [ $(id -u) -ne 0 ] || systemctl start --no-block apt-news.service esm-cache.service >/dev/null 2>&1 || true";
};

binary::apt::AptCli::Hooks::Upgrade {
  "[ ! -f /usr/lib/ubuntu-advantage/apt-esm-json-hook ] || [ $(id -u) -ne 0 ] || /usr/lib/ubuntu-advantage/apt-esm-json-hook 2>> /var/log/ubuntu-advantage-apt-hook.log || true";
};
```

Root-triggered reachability was confirmed: `systemctl start apt-news.service esm-cache.service` returned `0`, root `apt-get update` returned `0`, and journald showed both services starting and finishing. The system manager environment before the trigger was fixed to `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin` with no `PYTHONPATH` or `UA_DATA_DIR`.

## Data/control boundaries

`apt-news.service` runs `/usr/bin/python3 /usr/lib/ubuntu-advantage/apt_news.py`. The code reads `apt_news` and `apt_news_url` from Ubuntu Pro user config, defaulting to `https://motd.ubuntu.com/aptnews.json`, fetches JSON into `/run/ubuntu-advantage/apt-news`, validates message shape/length/control chars/selectors, and writes fixed files `apt-news` and `apt-news-raw` under `/var/lib/ubuntu-advantage/messages` only when a message applies.

Post-trigger state was not user-writable:

```text
/run/ubuntu-advantage                         drwxr-xr-x root:root
/run/ubuntu-advantage/apt-news                drwxr-xr-x _apt:root
/run/ubuntu-advantage/apt-news/aptnews.json   -rw-r--r-- root:root
/var/lib/ubuntu-advantage                     drwxr-xr-x root:root
/var/lib/ubuntu-advantage/status.json         -rw-r--r-- root:root
/var/lib/ubuntu-advantage/apt-esm             drwxr-xr-x root:root
/var/lib/ubuntu-advantage/apt-esm/.../status  -rw-r--r-- root:root
/var/lib/apt/periodic/update-success-stamp    -rw-r--r-- root:root
```

No symlinks were present under `/run/ubuntu-advantage` or `/var/lib/ubuntu-advantage` within the probed depth. Both users failed to write or symlink into the apt hook, Pro config, Pro status, apt-news cache, ESM cache, MOTD cache, and apt periodic stamp paths with `Permission denied` or missing root-owned parents.

## Attacker and selfauth triggers

Both users could read Pro status and unattached state. Both failed to change Pro state:

```text
pro config set apt_news=false                         -> This command must be run as root
pro config set apt_news_url=https://example.invalid   -> This command must be run as root
pro refresh                                           -> This command must be run as root
```

Both users failed to start root services or poison the system manager environment:

```text
systemctl start apt-news.service       -> Interactive authentication required
systemctl start esm-cache.service      -> Interactive authentication required
systemctl start apt-daily.service      -> Interactive authentication required
systemctl set-environment PATH=...     -> Access denied
systemctl set-environment PYTHONPATH=... -> Access denied
systemctl set-environment UA_DATA_DIR=... -> Access denied
```

Hostile `PATH`/`PYTHONPATH` probes confirmed direct execution stayed at caller UID. Fake `id` markers from `apt -s upgrade` were owned by `attacker`/`selfauth`; fake `systemctl` was never reached; Python `sitecustomize` markers from `pro`, `apt_news.py`, and `esm_cache.py` recorded euid 1001 or 1002 only. Unprivileged `apt-get update` failed on apt list locks before reaching root hook effects.

The apt CLI hook binary `/usr/lib/ubuntu-advantage/apt-esm-json-hook` is a normal root-owned ELF. Direct root/user execution without the apt hook socket returned `pro-hook: missing socket fd`; user execution was not privileged.

## Login/MOTD path

Only `/etc/pam.d/login` references `pam_motd` in this target. `/usr/bin/login` is not setuid, so uid1001 cannot launch the login PAM stack directly. A root-side `login -p -f selfauth` simulation with attacker-controlled `PATH`, `PYTHONPATH`, and `CACHE` printed MOTD but did not execute the fake `id`, did not import the fake `sitecustomize`, did not create the attacker `CACHE`, and did not create `/root/ubuntu_pro_apt_news_lpe_proof`.

## Conclusion

The default root apt/update paths are real and reachable by root timers/root apt, but the normal users cannot control the hook configuration, apt-news URL/config, apt-news JSON/cache path, ESM cache files, MOTD Pro stamp files, systemd manager environment, or service start. Package-cache selectors are read from root-maintained dpkg/apt state. The observed user-controlled environment effects remain in user processes only. No root-owned attacker-controlled write or root code execution primitive was validated.

Cleanup removed only probe markers under `/tmp`, `/home/attacker`, `/home/selfauth`, and `/root/ubuntu_pro_apt_news_*`. Final health: `systemctl is-system-running` reported `running`, `systemctl --failed` listed zero units, and `ROOT_PROOF_ABSENT` was logged.
