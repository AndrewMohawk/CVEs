# Negative: PackageKit SetHints environment splitting

Result: no stock Ubuntu 24.04 Server local root LPE was validated through
PackageKit `SetHints` newline/environment propagation.

Probe/log:

```text
pocs/packagekit_sethints_env_probe.sh
logs/packagekit-sethints-env.out
```

## Default proof

Live target: Ubuntu 24.04.4 LTS, `ubuntu24-server-lpe-target`.

Relevant packages:

```text
packagekit 1.2.8-2ubuntu1.5
packagekit-tools 1.2.8-2ubuntu1.5
libpackagekit-glib2-18 1.2.8-2ubuntu1.5
gir1.2-packagekitglib-1.0 1.2.8-2ubuntu1.5
apt 2.8.3
dbus 1.14.10-4ubuntu4.1
polkitd 124-2ubuntu1.24.04.3
systemd 255.4-1ubuntu8.15
```

`packagekit.service` is a root D-Bus service:

```ini
BusName=org.freedesktop.PackageKit
User=root
ExecStart=/usr/libexec/packagekitd
```

The default PackageKit policy allows active users to refresh system sources:

```xml
<action id="org.freedesktop.packagekit.system-sources-refresh">
  <allow_active>yes</allow_active>
</action>
```

## Tested trigger

The probe logged in `selfauth` as a non-sudo active local user and called:

```python
Transaction.SetHints([
  "locale=C.UTF-8\nAPT_CONFIG=/tmp/packagekit-sethints-env/evil-apt.conf\nPK_HINT_SPLIT=1",
  "interactive=true",
  "background=false",
  "cache-age=1",
])
Transaction.RefreshCache(True)
```

It also tested newline payloads in `cache-age`, unknown hint names, and:

```text
locale=C.UTF-8\nPYTHONPATH=/tmp/packagekit-sethints-env/py\nPK_HINT_PYTHONPATH_SPLIT=1
```

The fake APT config contained:

```text
APT::Update::Pre-Invoke { "id > /root/packagekit_sethints_env_root"; };
```

The fake `PYTHONPATH` contained `sitecustomize.py` that would write:

```text
/root/packagekit_sethints_env_pythonpath_root
```

## Result

`SetHints` accepted newline-bearing values and root PackageKit/APT children
received them, but the values remained inside single `LANG`/`LANGUAGE`
environment entries. Raw NUL-boundary environment capture showed entries such as:

```text
ENV_ENTRY_REPR=b'LANG=C.UTF-8\nAPT_CONFIG=/tmp/packagekit-sethints-env/evil-apt.conf\nPK_HINT_SPLIT=1'
ENV_ENTRY_REPR=b'LANG=C.UTF-8\nPYTHONPATH=/tmp/packagekit-sethints-env/py\nPK_HINT_PYTHONPATH_SPLIT=1'
```

They did not become separate `APT_CONFIG` or `PYTHONPATH` variables. Root APT
refreshes completed, but neither proof marker was created:

```text
ROOT_PROOF_ABSENT /root/packagekit_sethints_env_root
PYTHONPATH_ROOT_PROOF_ABSENT /root/packagekit_sethints_env_pythonpath_root
```

Some lines printed by `tr '\0' '\n'` looked like standalone `APT_CONFIG=...`,
but the `ENV_ENTRY_REPR` evidence proves those were embedded newlines inside
`LANG` or `LANGUAGE`, not distinct environment variables.

## Cleanup

The probe removed `/tmp/packagekit-sethints-env`, the temporary
`selfauth` profile, root marker paths, and terminated the test login session.
Final health:

```text
systemctl is-system-running -> running
systemctl --failed --no-legend -> no failed units
```

## Why scanners may miss it

A line-oriented process-environment collector will misread newline-containing
`LANG`/`LANGUAGE` values as separate variables and report apparent root
`APT_CONFIG`/`PYTHONPATH` injection. The exploitable boundary depends on checking
raw NUL-separated environment entries and proving a root hook marker.

## Suggested triage

No LPE report. Hardening would still be reasonable: reject control characters in
PackageKit `locale` hints or normalize them before exporting to root backend
processes, because the current behavior creates misleading logs and potential
downstream parser risk.
