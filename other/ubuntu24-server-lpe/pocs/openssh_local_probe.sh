#!/usr/bin/env bash
set -u

container="${1:-ubuntu24-server-lpe-target}"

run() {
  printf '\n$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
  rc=$?
  printf '[rc=%d]\n' "$rc"
}

run docker inspect --format '{{.Name}} {{.Config.Image}} {{.State.Status}} {{.State.StartedAt}}' "$container"
run docker exec "$container" cat /etc/os-release
run docker exec "$container" dpkg-query -W '-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' openssh-client openssh-server
run docker exec "$container" apt-cache policy openssh-client openssh-server
run docker exec "$container" systemctl --no-pager is-enabled ssh.service ssh.socket
run docker exec "$container" systemctl --no-pager is-active ssh.service ssh.socket
run docker exec "$container" ss -ltnp

run docker exec "$container" sh -lc 'ls -ld /etc/ssh /etc/ssh/* 2>&1; grep -RIn "^[[:space:]]*[^#[:space:]]" /etc/ssh 2>/dev/null || true'
run docker exec "$container" sh -lc 'ls -l /usr/sbin/sshd /etc/ssh/sshd_config /etc/pam.d/sshd /etc/ssh/ssh_host_* 2>&1'
run docker exec "$container" sh -lc 'stat -c "%A %a %U %G %n" /usr/bin/ssh /usr/bin/ssh-agent /usr/bin/scp /usr/bin/sftp /usr/lib/openssh/ssh-keysign /usr/lib/openssh/ssh-pkcs11-helper /usr/lib/openssh/ssh-sk-helper /usr/lib/aarch64-linux-gnu/utempter/utempter'
run docker exec "$container" sh -lc 'getent passwd root attacker selfauth; getent group _ssh ssh utmp; id attacker; id selfauth'

run docker exec "$container" runuser -u attacker -- ssh -G -T localhost
run docker exec "$container" runuser -u attacker -- /usr/lib/openssh/ssh-keysign
run docker exec "$container" runuser -u attacker -- sh -lc 'tmp=$(mktemp -d /tmp/openssh-keysign-env.XXXXXX); trap "rm -rf \"$tmp\"" EXIT; printf x > "$tmp/preload.so"; HOME="$tmp" PATH="$tmp:$PATH" LD_PRELOAD="$tmp/preload.so" SSH_AUTH_SOCK="$tmp/sock" /usr/lib/openssh/ssh-keysign'

run docker exec "$container" runuser -u attacker -- ssh-agent sh -c 'id; printf "SSH_AUTH_SOCK=%s\nSSH_AGENT_PID=%s\n" "$SSH_AUTH_SOCK" "$SSH_AGENT_PID"; stat -c "%A %a %U %G %n" "$(dirname "$SSH_AUTH_SOCK")" "$SSH_AUTH_SOCK"; ps -o pid,user,group,euid,egid,comm -p "$SSH_AGENT_PID"; ssh-add -l 2>&1'
run docker exec "$container" runuser -u attacker -- sh -lc 'mkdir -p "$HOME/.ssh"; ln -sf /etc/shadow "$HOME/.ssh/known_hosts"; ssh -oBatchMode=yes -oConnectTimeout=1 -vvv 127.0.0.1 true 2>&1 | sed -n "/known_hosts/p;/Permission denied/p;/Connection refused/p"; rm -f "$HOME/.ssh/known_hosts"; rmdir "$HOME/.ssh" 2>/dev/null || true'
run docker exec "$container" sh -lc 'ldd /usr/bin/ssh | grep -i utempter || true; ldd /usr/lib/openssh/ssh-keysign | grep -i utempter || true; test -e /etc/X11/Xsession.options; echo xsession_options_exists=$?; systemctl --no-pager --user --machine selfauth@ status ssh-agent.service 2>&1 || true'
