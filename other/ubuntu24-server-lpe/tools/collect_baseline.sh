#!/usr/bin/env bash
set -euo pipefail

out="${1:-baseline}"
mkdir -p "$out"

run() {
  local name="$1"
  shift
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n'
    "$@" 2>&1 || true
  } > "$out/$name.txt"
}

run os-release sh -lc 'cat /etc/os-release; uname -a; id; ps -p 1 -o pid,user,comm,args'
run packages sh -lc 'dpkg-query -W | sort'
run apt-manual sh -lc 'apt-mark showmanual | sort'
run systemctl-unit-files systemctl list-unit-files
run systemctl-active sh -lc 'systemctl --type=service,timer,path,socket --state=running,active --no-pager --plain || true'
run systemctl-sockets sh -lc 'systemctl --type=socket --state=running,active --no-pager --plain || true'
run setuid-setgid sh -lc 'find / -xdev -perm /6000 -type f -ls 2>/dev/null | sort -k 11'
run capabilities sh -lc 'getcap -r / 2>/dev/null | sort'
run dbus-system sh -lc 'busctl --system list --no-pager || true'
run polkit-actions sh -lc 'find /usr/share/polkit-1/actions -maxdepth 1 -type f -print | sort'
run tmpfiles-cron-logrotate-systemd sh -lc 'find /etc/tmpfiles.d /usr/lib/tmpfiles.d /etc/cron* /etc/logrotate.d /usr/lib/systemd/system -type f 2>/dev/null | sort'
run writable sh -lc 'find / -xdev \( -writable -o -perm -0002 -o -perm -0020 \) -ls 2>/dev/null | sort -k 11'
run users-groups sh -lc 'getent passwd; printf "\n--- groups ---\n"; getent group'
run sysctls sh -lc 'sysctl kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns kernel.unprivileged_bpf_disabled fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular 2>/dev/null || true'
