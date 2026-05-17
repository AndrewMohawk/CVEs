# Negative: GnuPG, apt-key, and ca-certificates trust-store helpers

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default Docker target.

Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, no sudo/admin groups.

Result: no validated uid1001-to-root local privilege escalation in the scoped GnuPG, apt-key, ca-certificates, debconf preconfigure, or trust-store update-helper lane.

Rerun:

```sh
bash -n pocs/trust_store_gnupg_probe.sh
pocs/trust_store_gnupg_probe.sh ubuntu24-server-lpe-target
```

Evidence log: `logs/trust-store-gnupg.out`.

## Default root consumers proven

Installed default packages included:

```text
apt 2.8.3
apt-utils 2.8.3
ca-certificates 20240203
debconf 1.5.86ubuntu1
gnupg/gpg/gpgv/gpg-agent/dirmngr/gpgconf/keyboxd 2.4.4-2ubuntu17.4
openssl 3.0.13-0ubuntu3.9
ubuntu-keyring 2023.11.28.1
systemd 255.4-1ubuntu8.15
```

Default root paths were live: `apt-daily.timer`, `apt-daily-upgrade.timer`, root apt hooks, `DPkg::Pre-Install-Pkgs` via `/usr/sbin/dpkg-preconfigure --apt`, `ca-certificates` dpkg triggers `update-ca-certificates` and `update-ca-certificates-fresh`, `/usr/sbin/update-ca-certificates`, `/usr/bin/apt-key`, and apt signature verification through `/usr/bin/apt-key --quiet --readonly --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg verify`.

GnuPG user services are installed and globally enabled as user sockets (`gpg-agent*`, `dirmngr`, `keyboxd`), but they are user units with `SocketMode=0600` and `DirectoryMode=0700`. In this Docker target there was no `/run/user/1001`; attacker `GNUPGHOME` resolved under `/home/attacker/.../gnupg` and produced only attacker-owned `0600` keybox/trustdb files.

## Boundary checks

uid1001 could not write or symlink into the relevant root trust/code paths:

```text
NO_W /etc/ca-certificates/update.d
NO_W /usr/local/share/ca-certificates
NO_W /usr/share/ca-certificates
NO_W /etc/ssl/certs
NO_W /etc/apt/apt.conf.d
NO_W /etc/apt/trusted.gpg.d
NO_W /etc/apt/keyrings
NO_W /usr/share/keyrings
NO_W /var/cache/debconf
NO_W /var/lib/dpkg/info
```

Direct write/symlink attempts to cert hooks, local CA certs, apt config snippets, apt keyrings, `/etc/ssl/certs/ca-certificates.crt.new`, and `/var/cache/debconf/tmp.ci` failed with `Permission denied` or missing root-owned parent.

Attacker-controlled `PATH`, `TMPDIR`, and `GNUPGHOME` payloads fired only as uid1001. With a normal PATH, `/usr/bin/apt-key add ...` returned `E: This command can only be used by root.` Attacker attempts to push env into root systemd or trigger apt root units failed:

```text
systemctl set-environment PATH=...   -> Access denied
systemctl set-environment TMPDIR=... -> Access denied
systemctl import-environment ...     -> Access denied
systemctl start apt-daily.service    -> Interactive authentication required
apt-get update as uid1001            -> apt list lock permission denied
```

Root-triggered checks then ran after hostile attacker state was planted:

```text
root_update_ca_rc=0
root_apt_key_list_rc=0
apt_key_gpghome_tmp_count before=0 after=0
root_apt_update_rc=0
NO_PAYLOAD_HITS_FROM_ROOT_TRIGGERS
NO_ROOT_PAYLOAD_MARKER
```

The root apt update debug output showed apt verifying repository metadata with `/usr/bin/apt-key --quiet --readonly --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg verify`, successful `GOODSIG`/`VALIDSIG`, and the expected `Signed-By` key fingerprint. No attacker binary, attacker `GNUPGHOME`, attacker gpg-agent/dirmngr/keyboxd socket, or attacker cert hook was consumed by root.

## Conclusion

The interesting code surfaces are real: `update-ca-certificates` uses `TMPDIR`, writes `/etc/ssl/certs/ca-certificates.crt.new`, creates cert symlinks, and runs `/etc/ca-certificates/update.d` hooks; `apt-key` creates temporary GnuPG homes and shells out to GnuPG helpers; `dpkg-preconfigure` uses a fixed tempdir and PATH-based `apt-extracttemplates`. On the stock target, uid1001 has no default way to control the root hook directories, root keyring/config directories, root cert directories, root systemd manager environment, root apt invocation, or root GnuPG homes/sockets. No root trust-store write or root code execution primitive was validated.

Cleanup completed, and a post-run check found no remaining `/home/attacker/trust_store_gnupg_probe`, `/tmp/trust_store_gnupg_probe*`, disposable apt-list directory, or root proof marker.
