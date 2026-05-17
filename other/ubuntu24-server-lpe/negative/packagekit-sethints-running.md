# Negative: PackageKit SetHints on running transactions

Date: 2026-05-16

Target: `ubuntu24-server-lpe-target`, stock Ubuntu 24.04.4 Server default Docker/systemd target.

Users: `uid=1001(attacker)` and `uid=1002(selfauth)`, each only in its own primary group.

Result: no validated local privilege escalation. `SetHints` remains callable on a running PackageKit transaction, but the reachable unauthenticated transaction flags do not enter the root dpkg/maintainer-script path, and real local `.deb` installation remains polkit-blocked.

Probe/log:

```text
pocs/packagekit_sethints_running_probe.sh
logs/packagekit-sethints-running.out
```

## Default proof

Relevant packages in the target:

```text
apt                         2.8.3
dbus                        1.14.10-4ubuntu4.1
debconf                     1.5.86ubuntu1
gir1.2-packagekitglib-1.0   1.2.8-2ubuntu1.5
libpackagekit-glib2-18      1.2.8-2ubuntu1.5
packagekit                  1.2.8-2ubuntu1.5
packagekit-tools            1.2.8-2ubuntu1.5
polkitd                     124-2ubuntu1.24.04.3
systemd                     255.4-1ubuntu8.15
```

Default root service:

```text
/usr/lib/systemd/system/packagekit.service
Type=dbus
BusName=org.freedesktop.PackageKit
User=root
ExecStart=/usr/libexec/packagekitd
```

The PackageKit system bus service is reachable by uid1001 through `CreateTransaction`, and local `.deb` actions are exposed through `org.freedesktop.PackageKit.Transaction.InstallFiles`.

## Code path

Installed source reviewed from the applied Noble package source in `/tmp/pk-src-noble/unpack`.

`src/pk-transaction.c` allows `SetHints` before the one-action state guard:

```text
5264 if (g_strcmp0 (method_name, "SetHints") == 0) {
5265     pk_transaction_set_hints (transaction, parameters, invocation);
5266     return;
...
5278 if (priv->state != PK_TRANSACTION_STATE_NEW) {
5279     g_dbus_method_invocation_return_error (... InvalidState ...)
```

The same file accepts an existing absolute `frontend-socket` path and stores it on the backend job:

```text
4798 if (g_strcmp0 (key, "frontend-socket") == 0) {
4810     if (value[0] != '/') ... "frontend-socket has to be an absolute path"
4819     if (!g_file_test (value, G_FILE_TEST_EXISTS)) ... "frontend-socket does not exist"
4828     pk_backend_job_set_frontend_socket (priv->job, value);
4937 g_variant_get (params, "(^a&s)", &hints);
4942 for (i = 0; hints[i] != NULL; i++) ...
```

Authentication is skipped for `ONLY_DOWNLOAD` and `SIMULATE` transaction flags:

```text
2902 /* we don't need to authenticate at all to just download */
2904 if (pk_bitfield_contain (... ONLY_DOWNLOAD) ||
2906     pk_bitfield_contain (... SIMULATE) ||
2908     priv->skip_auth_check == TRUE) {
2910     pk_transaction_set_state (transaction, PK_TRANSACTION_STATE_READY);
2911     return TRUE;
```

The APT backend only exports the attacker-provided frontend socket to debconf/dpkg when it reaches interactive install/conffile handling:

```text
1899 const gchar *socket = pk_backend_job_get_frontend_socket(m_job);
1900 if ((m_interactive) && (socket != NULL)) {
1902     envp[0] = g_strdup("DEBIAN_FRONTEND=passthrough");
1903     envp[1] = g_strdup_printf("DEBCONF_PIPE=%s", socket);
...
2520 if (pk_bitfield_contain(flags, PK_TRANSACTION_FLAG_ENUM_ONLY_DOWNLOAD)) {
2521     return true;
...
2575 const gchar *socket = pk_backend_job_get_frontend_socket(m_job);
2576 if ((m_interactive) && (socket != NULL)) {
2577     g_setenv("DEBIAN_FRONTEND", "passthrough", TRUE);
2578     g_setenv("DEBCONF_PIPE", socket, TRUE);
```

## Trigger attempts

The probe creates an attacker-owned Debian package with `config`, `templates`, and `postinst` scripts. The `postinst` would write `/root/packagekit_sethints_running_root` if PackageKit reached root dpkg execution.

As uid1001, the probe then creates PackageKit transactions and runs:

```text
SetHints(["frontend-socket=/tmp/packagekit-sethints-running/<case>.sock", "interactive=true"])
InstallFiles(flags=SIMULATE, [attacker_deb])
InstallFiles(flags=ONLY_DOWNLOAD, [attacker_deb])
InstallFiles(flags=0, [attacker_deb])
InstallFiles(flags=ONLY_DOWNLOAD, [attacker_deb]); SetHints(...) while running
InstallFiles(flags=ONLY_DOWNLOAD, ...); InstallFiles(flags=0, ...) on same transaction
```

Observed results:

```text
simulate-pre:       SetHints ok, InstallFiles flags=4 ok, no listener connect
only-download-pre:  SetHints ok, InstallFiles flags=8 ok, no listener connect
only-download-post: SetHints post-start ok, InstallFiles flags=8 ok, no listener connect
real-install:       SetHints ok, InstallFiles flags=0 method return, no listener connect, no marker
second action:      InvalidState: cannot call InstallFiles ... already in state running
```

The listener did not receive any PackageKit/APT root connection; only its close-time self-poke/error was recorded. Post-probe state:

```text
ROOT_MARKER_ABSENT
dpkg-query: no packages found matching packagekit-sethints-running-root
systemctl is-system-running: running
systemctl --failed: none
```

## Verdict

Negative. The adjacent trust-boundary behavior is real and scanner-interesting: a uid1001-owned D-Bus transaction can keep changing `frontend-socket` after the transaction starts. In the default Ubuntu 24.04 Server package, however, the unauthenticated `SIMULATE` and `ONLY_DOWNLOAD` paths do not fork dpkg or maintainer scripts, while the real install path stays behind PackageKit/polkit authorization and the patched transaction guard blocks replacing an authenticated action with a second unauthenticated/privileged action.

## Cleanup

The probe removed:

```sh
dpkg -r packagekit-sethints-running-root 2>/dev/null || true
rm -rf /tmp/packagekit-sethints-running /root/packagekit_sethints_running_root
systemctl restart packagekit.service || true
```

No root marker, package install, failed unit, or lingering attacker socket remained.

## Why scanners may miss it

This is a semantic D-Bus state-machine edge. A fuzzer can see that `SetHints` is still accepted while running, but the security question depends on transaction flags, PackageKit's authorization shortcut, the APT backend's early `ONLY_DOWNLOAD` return, and whether a root dpkg/debconf child is reached. The tested default state did not cross that boundary.
