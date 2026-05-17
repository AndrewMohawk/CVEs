# Negative: diagnostic/support tooling surfaces

Status: no validated privilege escalation.

## Scope

Target: `ubuntu24-server-lpe-target`, stock Ubuntu Server target in Docker.
Attacker: `uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)`, not in `sudo`, `adm`, or `lxd`.

This pass covered `sosreport`/`sos`, `apport-cli`/`ubuntu-bug` and apport helper hooks not already covered by the `/var/crash` note, `command-not-found`/cnf update hooks, `ubuntu-release-upgrader-core`, `update-manager-core` including `ubuntu-security-status`, and matching polkit `pkexec` annotations.

## Default proof

OS and default metapackages:

```text
Distributor ID: Ubuntu
Description:    Ubuntu 24.04.4 LTS
Release:        24.04
Codename:       noble

ubuntu-minimal   1.539.2  ii
ubuntu-server    1.539.2  ii
ubuntu-standard  1.539.2  ii
```

Installed package versions:

```text
apport                         2.28.1-0ubuntu3.8           ii
apport-core-dump-handler       2.28.1-0ubuntu3.8           ii
command-not-found              23.04.0                     ii
polkitd                        124-2ubuntu1.24.04.3        ii
python3-apport                 2.28.1-0ubuntu3.8           ii
python3-commandnotfound        23.04.0                     ii
python3-update-manager         1:24.04.12                  ii
sosreport                      4.10.2-0ubuntu0~24.04.1     ii
ubuntu-pro-client              37.2ubuntu~24.04            ii
ubuntu-release-upgrader-core   1:24.04.28                  ii
update-manager-core            1:24.04.12                  ii
update-notifier-common         3.192.68.2                  ii
pkexec                         (none)                      un
policykit-1                    (none)                      un
ubuntu-advantage-tools         (none)                      un
```

Default package linkage observed with `apt-cache rdepends --installed`:

```text
sosreport                Reverse Depends: ubuntu-server
apport                   Reverse Depends: ubuntu-server, apport-core-dump-handler, python3-apport
command-not-found        Reverse Depends: ubuntu-standard, python3-commandnotfound
ubuntu-release-upgrader-core Reverse Depends: update-manager-core
update-manager-core      Reverse Depends: ubuntu-standard, update-notifier-common, python3-update-manager
```

Command paths and ownership:

```text
-rwxr-xr-x root:root /usr/bin/sosreport
-rwxr-xr-x root:root /usr/bin/sos
-rwxr-xr-x root:root /usr/bin/apport-cli
lrwxrwxrwx root:root /usr/bin/ubuntu-bug -> apport-bug
-rwxr-xr-x root:root /usr/bin/do-release-upgrade
-rwxr-xr-x root:root /usr/bin/ubuntu-security-status
-rwxr-xr-x root:root /usr/lib/ubuntu-release-upgrader/do-partial-upgrade
-rwxr-xr-x root:root /usr/share/apport/root_info_wrapper
-rwxr-xr-x root:root /usr/share/apport/apport
-rwxr-xr-x root:root /usr/lib/cnf-update-db
-rwxr-xr-x root:root /usr/lib/command-not-found
MISSING /usr/share/apport/apport-gtk
MISSING /usr/bin/pkexec
```

Default units/timers relevant to this pass:

```text
apport.service                 enabled, inactive in container: ConditionVirtualization=!container was not met
apport-forward.socket          enabled, active in container only, /run/apport.socket mode 0600 root:root
apport-autoreport.path         enabled, inactive: /var/lib/apport/autoreport absent
apport-autoreport.timer        enabled, inactive: /var/lib/apport/autoreport absent
apt-daily.timer                enabled
update-notifier-motd.timer     enabled
```

Important writable state:

```text
NO_W /var/lib/apt/lists
NO_W /var/lib/command-not-found
NO_W /var/lib/update-notifier
NO_W /var/lib/ubuntu-release-upgrader
NO_W /var/log/dist-upgrade
W    /var/crash
NO_W /etc/sos/extras.d
NO_W /etc/sos/presets.d
NO_W /etc/sos/groups.d
NO_W /usr/share/apport/package-hooks
NO_W /usr/share/apport/general-hooks
```

No non-symlink world/group-writable files or directories were found under the audited package trees:

```sh
find /usr/share/apport /usr/lib/python3/dist-packages/apport \
  /usr/lib/python3/dist-packages/CommandNotFound \
  /usr/lib/python3/dist-packages/DistUpgrade \
  /usr/lib/python3/dist-packages/UpdateManager \
  /usr/lib/python3/dist-packages/sos /etc/sos /etc/apport /etc/update-manager \
  -maxdepth 5 -not -type l \( -perm -002 -o -perm -020 \) -print
```

Observed output: empty.

## Polkit and pkexec

The target has polkit policy files but no `/usr/bin/pkexec` binary installed by default.

Relevant policy annotations:

```text
com.ubuntu.apport.root-info
  exec=/usr/share/apport/root_info_wrapper
  defaults allow_any=auth_admin allow_inactive=auth_admin allow_active=auth_admin

com.ubuntu.apport.apport-gtk-root
  exec=/usr/share/apport/apport-gtk
  defaults allow_any=auth_admin allow_inactive=auth_admin allow_active=auth_admin
  note: apport-gtk executable is missing in this server target

com.ubuntu.release-upgrader.release-upgrade
  exec=/usr/bin/do-release-upgrade
  defaults allow_any=no allow_inactive=no allow_active=auth_admin

com.ubuntu.release-upgrader.partial-upgrade
  exec=/usr/lib/ubuntu-release-upgrader/do-partial-upgrade
  defaults allow_any=no allow_inactive=no allow_active=auth_admin

com.ubuntu.update-notifier.pkexec.cddistupgrader
  exec=/usr/lib/update-notifier/cddistupgrader
  defaults allow_any=auth_admin allow_inactive=auth_admin allow_active=auth_admin

com.ubuntu.update-notifier.pkexec.package-system-locked
  exec=/usr/lib/update-notifier/package-system-locked
  defaults allow_any=no allow_inactive=yes allow_active=yes
```

Why this is not exploitable here: `pkexec` is not installed, and the actions that would execute release-upgrader/apport helpers are either `auth_admin` gated or point to missing GUI helpers. The attacker has no admin group membership.

## sosreport / sos

Candidate checked: Python import hijack and plugin/config execution when an unprivileged user influences cwd, plugin dirs, temp dirs, archive names, or presets.

Code shape:

```python
# /usr/bin/sos and /usr/bin/sosreport
sys.path.insert(0, os.getcwd())
from sos import SoS
```

Attacker proof of cwd import:

```sh
runuser -u attacker -- bash -lc '
  mkdir -p /tmp/diag-sos-cwd/sos
  printf "%s\n" "import os" "print(\"HIJACK_EUID=%s\" % os.geteuid())" "raise SystemExit(77)" > /tmp/diag-sos-cwd/sos/__init__.py
  cd /tmp/diag-sos-cwd
  /usr/bin/sos report --help
'
```

Observed:

```text
RC=77
HIJACK_EUID=1001
```

Attacker reachability:

```text
/usr/bin/sos report --batch --dry-run
sos_rc=1
Could not initialize 'report': Component must be run with root privileges
```

`sos` does have an attacker-controlled cwd import if a privileged operator runs it from an attacker directory. That is not a default uid1001-to-root path in this target: the binary is not setuid, there is no enabled root service/timer/polkit annotation for sos, and `/etc/sos/{extras.d,presets.d,groups.d}` plus the installed plugin tree are not attacker-writable.

## apport CLI / ubuntu-bug / root info helpers

Candidate checked: unprivileged apport hooks causing root to execute attacker-controlled `root_info_wrapper`, package hooks, symptom scripts, or shell commands.

Relevant helper code:

```text
/usr/lib/python3/dist-packages/apport/hookutils.py
  _root_command_prefix() returns [] for non-root callers when /usr/bin/pkexec is absent.
  attach_root_command_outputs() builds APPORT_DATA_DIR/root_info_wrapper and runs it with that prefix.

/usr/share/apport/root_info_wrapper
  #!/bin/sh
  exec sh "$@"
```

Direct attacker probe:

```sh
runuser -u attacker -- bash -lc '
  mkdir -p /tmp/diag-apport-data
  printf "%s\n" "#!/bin/sh" "id > /tmp/diag-apport-wrapper-id" "exec sh \"\$@\"" > /tmp/diag-apport-data/root_info_wrapper
  chmod 755 /tmp/diag-apport-data/root_info_wrapper
  APPORT_DATA_DIR=/tmp/diag-apport-data python3 - <<PY
import apport, os
from apport.hookutils import attach_root_command_outputs
r=apport.Report()
attach_root_command_outputs(r, {"Probe": "id"})
print("caller_euid", os.geteuid())
print("probe", r.get("Probe", "missing").strip())
PY
  cat /tmp/diag-apport-wrapper-id
'
```

Observed:

```text
caller_euid 1001
probe uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
uid=1001(attacker) gid=1001(attacker) groups=1001(attacker)
```

`apport-cli` report generation as attacker writes attacker-owned output:

```text
timeout 15 /usr/bin/apport-cli -f -p command-not-found --save /tmp/diag-apport-cnf.apport
apport_rc=0
-rw-r--r-- 1 attacker attacker 3173 /tmp/diag-apport-cnf.apport
```

The container-specific apport forwarder is not user reachable:

```text
srw------- 1 root root 0 /run/apport.socket
CONNECT_FAIL PermissionError [Errno 13] Permission denied euid 1001
```

Why this is not exploitable here: the only pkexec annotations require admin authentication and `pkexec` is absent. Without pkexec, apport's root-command helpers run as the calling uid, as shown above. Package hooks and symptom directories are root-owned and not attacker-writable. The active container apport socket is mode `0600` root:root. The autoreport path is inactive by default because `/var/lib/apport/autoreport` is absent.

## command-not-found / cnf update hook

Candidate checked: root `apt-daily`/`apt update` post-invoke hook executing cnf updater with attacker-controlled metadata/database path or Python import.

Default apt hook:

```text
/etc/apt/apt.conf.d/50command-not-found
APT::Update::Post-Invoke-Success {
  "if /usr/bin/test -w /var/lib/command-not-found/ -a -e /usr/lib/cnf-update-db; then /usr/lib/cnf-update-db > /dev/null; fi";
};
```

Updater code:

```text
/usr/lib/cnf-update-db
  db = CommandNotFound.dbpath
  if not os.access(os.path.dirname(db), os.W_OK): exit 0
  command_files = glob.glob("/var/lib/apt/lists/*Commands-*")
  DbCreator(command_files).create(db)
```

Attacker probes:

```text
/usr/lib/cnf-update-db --debug
datbase directory /var/lib/command-not-found/commands.db not writable

/usr/lib/command-not-found -- definitely-not-a-real-ubuntu-cmd-xyz
definitely-not-a-real-ubuntu-cmd-xyz: command not found
```

Why this is not exploitable here: the root hook is tied to apt update execution and only writes `/var/lib/command-not-found`, which is root-owned and not attacker-writable. The apt list directory is also not attacker-writable. The interactive shell command-not-found path executes as the shell user, not root.

## release upgrader / update-manager-core / ubuntu-security-status

Candidate checked: attacker-controlled release-upgrader data dirs, frontend imports, motd stamp paths, and Python imports feeding root timers/state.

Default root motd/timer path:

```text
/etc/update-motd.d/91-release-upgrade exits immediately for non-root users.
/usr/lib/ubuntu-release-upgrader/release-upgrade-motd writes:
  /var/lib/ubuntu-release-upgrader/release-upgrade-available
```

State directory:

```text
drwxr-xr-x root:root /var/lib/ubuntu-release-upgrader
NO_W /var/lib/ubuntu-release-upgrader
```

Attacker probes:

```text
/usr/lib/ubuntu-release-upgrader/do-partial-upgrade --version
do-partial-upgrade: version 24.04.28

/usr/lib/ubuntu-release-upgrader/do-partial-upgrade --frontend=DistUpgradeViewText
partial_rc=1
Traceback (most recent call last):
  File "/usr/lib/ubuntu-release-upgrader/do-partial-upgrade", line 97, in <module>
    os.execv("/usr/bin/pkexec", ["pkexec"] + sys.argv)
FileNotFoundError: [Errno 2] No such file or directory

/usr/bin/do-release-upgrade -c
dru_check_rc=1
Checking for a new Ubuntu release
There is no development version of an LTS available.
To upgrade to the latest non-LTS development release set Prompt=normal in /etc/update-manager/release-upgrades.
```

`ubuntu-security-status` ownership and import probe:

```text
update-manager-core: /usr/bin/ubuntu-security-status
/usr/bin/ubuntu-security-status from cwd containing attacker apt.py
uss_rc=0
575 packages installed:
    575 packages from Ubuntu Main/Restricted repository
```

The fake cwd `apt.py` was not imported; the script's `sys.path[0]` is `/usr/bin`, not the attacker cwd. `ubuntu-security-status` is also a user command and, on this target, prints that it has been replaced by `/usr/bin/pro security-status`; it does not create a root execution path.

Why this is not exploitable here: the root motd stamp directory is not attacker-writable, release upgrade execution either runs as the user in check mode or attempts missing `/usr/bin/pkexec`, and policy execution would require admin authentication even if `pkexec` were installed. No default root timer consumes attacker-writable release-upgrader or update-manager state.

## Conclusion

No uid1001-to-root LPE validated in the default Ubuntu 24.04 Server Docker target for these diagnostic/support tooling surfaces.

The only notable bug-shaped primitive is `sos`/`sosreport` importing from cwd before the packaged module path. In this target it remains an operator-assisted root-cwd footgun, not a default local privilege escalation: the attacker cannot cause a default root service, timer, apt hook, or polkit action to run `sos` from an attacker-controlled directory.

Cleanup performed:

```text
removed /tmp/diag-sos-*
removed /tmp/diag-apport-*
removed /tmp/diag-pyhi
removed /home/attacker/.cache/update-manager-core/meta-release-lts created by do-release-upgrade -c
no remaining /tmp, /var/tmp, /var/crash, or /home/attacker diagnostic probe files matched diag-*/diagnostic_*/sosreport-diagprobe*/meta-release*
```
