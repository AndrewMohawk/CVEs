# Negative: PackageKit local .deb parser/metadata methods

Result: no root LPE proven on `ubuntu24-server-lpe-target`.

Probe command:

```sh
./pocs/packagekit_local_deb_parser_probe.sh
```

Full transcript:

```text
logs/packagekit-local-deb-parser.out
```

## Default reachability

Target package/version evidence:

```text
Ubuntu 24.04.4 LTS
packagekit                   1.2.8-2ubuntu1.5        arm64
packagekit-tools             1.2.8-2ubuntu1.5        arm64
libpackagekit-glib2-18:arm64 1.2.8-2ubuntu1.5        arm64
polkitd                      124-2ubuntu1.24.04.3    arm64
dbus                         1.14.10-4ubuntu4.1      arm64
systemd                      255.4-1ubuntu8.15       arm64
dpkg                         1.22.6ubuntu6.6         arm64
```

`packagekit.service` is a default D-Bus service:

```text
Type=dbus
BusName=org.freedesktop.PackageKit
User=root
ExecStart=/usr/libexec/packagekitd
/run/dbus/system_bus_socket srw-rw-rw- root root
```

Both unprivileged users could create PackageKit transactions over the system bus, and the transaction interface exposed the candidate methods:

```text
GetDetailsLocal(in as files)
GetFilesLocal(in as files)
InstallFiles(in t transaction_flags, in as full_paths)
Uid=1001/1002
```

## Corpus and trigger paths

The probe built four attacker-owned local packages under `/tmp/packagekit-local-deb-parser`:

```text
pk-local-normal.deb              postinst writes /root/packagekit_local_deb_parser_postinst if executed
pk-local-weird.deb               multiline/control-field punctuation, percent escapes, shell-looking strings, root-looking paths
pk-local-control-traversal.deb   manual ar/tar .deb with control.tar absolute and ../../root members
pk-local-data-traversal.deb      manual ar/tar .deb with data.tar absolute and ../../root members
```

As `attacker` and `selfauth`, the D-Bus driver called `GetDetailsLocal`, `GetFilesLocal`, and `InstallFiles` with flags `8` and `0` for every file. The read-only parser methods returned metadata and file lists. The data traversal package is especially useful evidence: `GetFilesLocal` reported root-looking data members as paths, but reporting them did not create those files:

```text
Files('pk-local-data-traversal;1.0;all;/tmp/packagekit-local-deb-parser/pk-local-data-traversal.deb',
  ['/usr/local/share/packagekit-local-deb-parser/data.txt',
   '/root/packagekit_local_deb_parser_data_parent_escape',
   '/root/packagekit_local_deb_parser_data_absolute_escape'])
```

`InstallFiles(flags=8)` returned PackageKit "success" signals for all packages, but this behaved as a non-committing parse/simulation path. `InstallFiles(flags=0)` reached the install authorization path and failed for both users:

```text
ErrorCode (48, 'Failed to obtain authentication.')
PackageKit: uid 1001/1002 failed to obtain auth
```

## Root proof result

No root execution or root file write occurred:

```text
ROOT_MARKER_ABSENT
dpkg-query: no packages found matching pk-local-normal
dpkg-query: no packages found matching pk-local-weird
dpkg-query: no packages found matching pk-local-control-traversal
dpkg-query: no packages found matching pk-local-data-traversal
```

Cleanup removed the attacker temp directory and any possible root markers, and left the services healthy:

```text
no root markers
no /tmp probe directory
packagekit.service active
polkit.service active
dbus.service active
systemctl --failed: 0 loaded units listed
```

## Why scanners would miss it

A scanner can flag the scary pieces: root `packagekitd`, world-reachable system bus socket, unauthenticated local `.deb` metadata methods, `InstallFiles`, and archive members that normalize to `/root/...`. The exploitable boundary is semantic: `GetDetailsLocal`/`GetFilesLocal` parse and report attacker-controlled metadata but do not install or run maintainer scripts, `InstallFiles(flags=8)` logs "success" for the non-committing path, and `InstallFiles(flags=0)` is still gated by `org.freedesktop.packagekit.package-install-untrusted` before maintainer scripts or package commit. On this stock target that leaves parser exposure and confusing telemetry, not uid-to-root escalation.
