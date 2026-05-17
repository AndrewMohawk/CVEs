#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash <<'INCONTAINER'
set -Eeuo pipefail
export LC_ALL=C

work=/tmp/tmpfiles-public-dirs-probe
decoy=/tmp/tmpfiles-public-dirs-root-decoys
att_home=/home/attacker
race_log=$work/race.log

section() {
  printf '\n== %s ==\n' "$*"
}

as_attacker() {
  runuser -u attacker -- bash -lc "$*"
}

show_path() {
  local p
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      stat -Lc 'stat-follow %A %a %U:%G %F %n -> %N' "$p" 2>&1 || true
      stat -c 'stat-nofollow %A %a %U:%G %F %n -> %N' "$p" 2>&1 || true
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        printf 'content %s: ' "$p"
        sed -n '1p' "$p" 2>/dev/null || true
      fi
    else
      printf 'missing %s\n' "$p"
    fi
  done
}

run_tmpfiles() {
  local label="$1"
  shift
  printf '\n-- tmpfiles %s: systemd-tmpfiles %s --\n' "$label" "$*"
  SYSTEMD_LOG_LEVEL=debug systemd-tmpfiles "$@" 2>&1 |
    grep -E '^(Running|Created|Found|Removing|rm|Changing|Skipping|Entry|Would|statx|chmod|chown|unlink|rmdir|Cannot|Failed|Refusing|Ignoring|Detected|Temporarily|Writing|Setting|Symlink|/usr/lib/tmpfiles.d|/etc/tmpfiles.d)' |
    sed -n '1,180p' || true
}

cleanup_tmp() {
  set +e
  pkill -f tmpfiles-public-dirs-race-attacker 2>/dev/null || true
  rm -rf "$work" "$decoy"
  rm -rf /tmp/.X11-unix /tmp/.ICE-unix /tmp/.XIM-unix /tmp/.font-unix
  rm -f /tmp/.X77-lock /tmp/.X78-lock /tmp/.X79-lock /tmp/.X80-lock
  rm -rf /tmp/snap-private-tmp /tmp/systemd-private-tpfprobe /tmp/systemd-private-raceprobe
  rm -f /run/screen/tpf-link /run/screen/tpf-file
  rm -f /dev/shm/tpf-link
}

restore_default_xdirs() {
  systemd-tmpfiles --boot --create \
    --prefix=/tmp/.X11-unix \
    --prefix=/tmp/.ICE-unix \
    --prefix=/tmp/.XIM-unix \
    --prefix=/tmp/.font-unix >/dev/null 2>&1 || true
}

cleanup_trap() {
  cleanup_tmp
  restore_default_xdirs
}
trap cleanup_trap EXIT INT TERM

cleanup_tmp
mkdir -p "$work" "$decoy"
chmod 0755 "$work" "$decoy"
printf 'root-decoy-file-keep\n' > "$decoy/file"
printf 'root-decoy-xlock-keep\n' > "$decoy/xlock-target"
printf 'root-decoy-rmtree-keep\n' > "$decoy/rmtree-target"
printf 'root-decoy-z-keep\n' > "$decoy/z-target"
mkdir -p "$decoy/dir" "$decoy/snap-target-dir"
printf 'root-decoy-dir-child-keep\n' > "$decoy/dir/child"
chown -R root:root "$decoy"
chmod 0644 "$decoy/"* 2>/dev/null || true
chmod 0755 "$decoy" "$decoy/dir" "$decoy/snap-target-dir"

section "target identity and default package proof"
. /etc/os-release
printf 'os=%s version_id=%s codename=%s arch=%s kernel=%s\n' "$PRETTY_NAME" "$VERSION_ID" "$VERSION_CODENAME" "$(uname -m)" "$(uname -r)"
id attacker
printf 'container_system_state='
systemctl is-system-running || true
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  systemd systemd-sysv systemd-timesyncd libsystemd0 snapd screen passwd login base-passwd x11-common 2>&1 || true
printf 'systemd-tmpfiles binary: '
command -v systemd-tmpfiles
dpkg -S "$(command -v systemd-tmpfiles)" 2>/dev/null || true

section "default tmpfiles timer and installed rule files"
systemctl list-timers --all --no-pager | sed -n '1p;/tmpfiles/p;/snapd.snap-repair/p'
systemctl cat systemd-tmpfiles-clean.service systemd-tmpfiles-clean.timer 2>/dev/null | sed -n '1,120p'
for f in \
  /usr/lib/tmpfiles.d/x11.conf \
  /usr/lib/tmpfiles.d/snapd.conf \
  /usr/lib/tmpfiles.d/systemd-tmp.conf \
  /usr/lib/tmpfiles.d/passwd.conf \
  /etc/tmpfiles.d/screen-cleanup.conf \
  /usr/lib/tmpfiles.d/screen-cleanup.conf \
  /usr/lib/tmpfiles.d/debian.conf \
  /usr/lib/tmpfiles.d/tmp.conf \
  /usr/lib/tmpfiles.d/00rsyslog.conf \
  /usr/lib/tmpfiles.d/systemd.conf; do
  if [ -e "$f" ]; then
    printf '\n-- %s --\n' "$f"
    stat -Lc '%A %a %U:%G %n' "$f"
    dpkg -S "$f" 2>/dev/null || true
    sed -n '1,80p' "$f"
  else
    printf '\n-- missing %s --\n' "$f"
  fi
done

section "active public path modes and kernel link protections"
for p in /tmp /var/tmp /dev/shm /run /run/shm /run/screen /etc /var/log /run/log /run/log/journal; do
  show_path "$p"
done
sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_regular fs.protected_fifos 2>/dev/null || true

section "attacker direct write and replacement reachability"
as_attacker '
set +e
id
for p in /tmp /dev/shm /run /run/shm /run/screen /etc /var/log /run/log /run/log/journal; do
  testfile="$p/tpf_attacker_write_test"
  printf "write-test %s: " "$p"
  if ( : > "$testfile" ) 2>/tmp/tpf_write_err; then
    rm -f "$testfile"
    echo WRITABLE
  else
    printf "NO "
    sed -n "1p" /tmp/tpf_write_err
  fi
done
rm -f /tmp/tpf_write_err
for p in /run/shm /run/screen /etc/passwd.lock /etc/shadow.lock /tmp/snap-private-tmp /tmp/.X11-unix; do
  printf "replace-attempt %s: " "$p"
  rm -rf "$p" 2>/tmp/tpf_replace_err && ln -s /tmp/nonexistent "$p" 2>>/tmp/tpf_replace_err && echo REPLACED || { printf "NO "; sed -n "1p" /tmp/tpf_replace_err; }
done
rm -f /tmp/tpf_replace_err
'
rm -f /tmp/.X11-unix

section "x11.conf D! top-level symlink handling"
as_attacker 'ln -s /tmp/tmpfiles-public-dirs-root-decoys/dir /tmp/.X11-unix && ln -s /tmp/tmpfiles-public-dirs-root-decoys/xlock-target /tmp/.X77-lock && ls -ld /tmp/.X11-unix /tmp/.X77-lock'
show_path /tmp/.X11-unix /tmp/.X77-lock "$decoy/dir" "$decoy/dir/child" "$decoy/xlock-target"
run_tmpfiles "x11 create+remove+clean against attacker symlinks" --boot --create --remove --clean --prefix=/tmp/.X11-unix --prefix=/tmp/.X77-lock
show_path /tmp/.X11-unix /tmp/.X77-lock "$decoy/dir" "$decoy/dir/child" "$decoy/xlock-target"

section "x11.conf r! lock unlink semantics"
cat > "$work/xlockrules.conf" <<'EOF'
r! /tmp/.X77-lock
EOF
run_tmpfiles "x11 exact r lock unlink for default-glob-shaped path" --boot --remove "$work/xlockrules.conf"
show_path /tmp/.X77-lock "$decoy/xlock-target"

section "x11.conf D! cleanup of old attacker entries inside public X11 dir"
rm -rf /tmp/.X11-unix
mkdir /tmp/.X11-unix
chown root:root /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix
as_attacker '
printf attacker-old > /tmp/.X11-unix/old-file
ln -s /tmp/tmpfiles-public-dirs-root-decoys/file /tmp/.X11-unix/link-to-root-decoy
touch -h -d 1970-01-01 /tmp/.X11-unix/link-to-root-decoy 2>/dev/null || true
touch -d 1970-01-01 /tmp/.X11-unix/old-file
ls -la /tmp/.X11-unix
'
show_path /tmp/.X11-unix/old-file /tmp/.X11-unix/link-to-root-decoy "$decoy/file"
run_tmpfiles "x11 clean old contents" --boot --clean --prefix=/tmp/.X11-unix
show_path /tmp/.X11-unix/old-file /tmp/.X11-unix/link-to-root-decoy "$decoy/file"

section "snapd.conf D!/X handling"
rm -rf /tmp/snap-private-tmp
as_attacker 'ln -s /tmp/tmpfiles-public-dirs-root-decoys/snap-target-dir /tmp/snap-private-tmp && ls -ld /tmp/snap-private-tmp'
show_path /tmp/snap-private-tmp "$decoy/snap-target-dir"
run_tmpfiles "snapd create against top-level symlink" --boot --create --clean --prefix=/tmp/snap-private-tmp
show_path /tmp/snap-private-tmp "$decoy/snap-target-dir"
rm -rf /tmp/snap-private-tmp
as_attacker '
mkdir -p /tmp/snap-private-tmp/attacker/tmp
printf snap-old > /tmp/snap-private-tmp/attacker/tmp/old-file
ln -s /tmp/tmpfiles-public-dirs-root-decoys/file /tmp/snap-private-tmp/attacker/tmp/link-to-root-decoy
touch -d 1970-01-01 /tmp/snap-private-tmp/attacker/tmp/old-file
touch -h -d 1970-01-01 /tmp/snap-private-tmp/attacker/tmp/link-to-root-decoy 2>/dev/null || true
find /tmp/snap-private-tmp -maxdepth 3 -printf "%M %u:%g %p -> %l\n"
'
run_tmpfiles "snapd create+clean on attacker-created tree" --boot --create --clean --prefix=/tmp/snap-private-tmp
find /tmp/snap-private-tmp -maxdepth 3 -printf '%M %u:%g %p -> %l\n' 2>&1 || true
show_path /tmp/snap-private-tmp/attacker/tmp/old-file /tmp/snap-private-tmp/attacker/tmp/link-to-root-decoy "$decoy/file"

section "systemd-tmp.conf R! recursive removal"
rm -rf /tmp/systemd-private-tpfprobe
cat > "$work/rmrules.conf" <<'EOF'
R! /tmp/systemd-private-tpfprobe
EOF
as_attacker '
mkdir -p /tmp/systemd-private-tpfprobe/sub
printf old > /tmp/systemd-private-tpfprobe/sub/old-file
ln -s /tmp/tmpfiles-public-dirs-root-decoys/rmtree-target /tmp/systemd-private-tpfprobe/sub/link-to-root-decoy
find /tmp/systemd-private-tpfprobe -maxdepth 3 -printf "%M %u:%g %p -> %l\n"
'
show_path "$decoy/rmtree-target"
run_tmpfiles "systemd-private exact R remove for default-glob-shaped path" --boot --remove "$work/rmrules.conf"
show_path /tmp/systemd-private-tpfprobe /tmp/systemd-private-tpfprobe/sub/link-to-root-decoy "$decoy/rmtree-target"

section "passwd lock cleanup reachability"
as_attacker '
set +e
for p in /etc/passwd.lock /etc/shadow.lock /etc/group.lock /etc/gshadow.lock /etc/subuid.lock /etc/subgid.lock; do
  printf "attacker-create %s: " "$p"
  ln -s /tmp/tmpfiles-public-dirs-root-decoys/file "$p" 2>/tmp/tpf_lock_err && echo CREATED || { printf "NO "; sed -n "1p" /tmp/tpf_lock_err; }
done
rm -f /tmp/tpf_lock_err
'
for p in /etc/passwd.lock /etc/shadow.lock /etc/group.lock /etc/gshadow.lock /etc/subuid.lock /etc/subgid.lock; do show_path "$p"; done
show_path "$decoy/file"

section "screen-cleanup d /run/screen behavior"
mkdir -p /run/screen
chown root:utmp /run/screen
chmod 1777 /run/screen
as_attacker '
ln -s /tmp/tmpfiles-public-dirs-root-decoys/file /run/screen/tpf-link
printf attacker > /run/screen/tpf-file
touch -d 1970-01-01 /run/screen/tpf-file
ls -la /run/screen | sed -n "1,20p"
'
show_path /run/screen /run/screen/tpf-link /run/screen/tpf-file "$decoy/file"
run_tmpfiles "screen create" --create --prefix=/run/screen
run_tmpfiles "screen clean" --clean --prefix=/run/screen
show_path /run/screen /run/screen/tpf-link /run/screen/tpf-file "$decoy/file"

section "debian.conf /run/shm link rule"
show_path /run/shm /dev/shm
as_attacker '
set +e
printf "attacker-unlink-/run/shm: "
rm -f /run/shm 2>/tmp/tpf_shm_err && echo REMOVED || { printf "NO "; sed -n "1p" /tmp/tpf_shm_err; }
printf "attacker-symlink-inside-devshm: "
ln -s /tmp/tmpfiles-public-dirs-root-decoys/file /dev/shm/tpf-link && echo CREATED || echo NO
ls -ld /dev/shm/tpf-link 2>/dev/null || true
'
run_tmpfiles "run shm create" --create --prefix=/run/shm
show_path /run/shm /dev/shm/tpf-link "$decoy/file"

section "generic z/Z symlink chmod/chown semantics with transient safe config"
rm -rf "$work/zpublic"
mkdir -p "$work/zpublic/zdir"
chmod 1777 "$work/zpublic" "$work/zpublic/zdir"
as_attacker '
ln -s /tmp/tmpfiles-public-dirs-root-decoys/z-target /tmp/tmpfiles-public-dirs-probe/zpublic/z-link
ln -s /tmp/tmpfiles-public-dirs-root-decoys/z-target /tmp/tmpfiles-public-dirs-probe/zpublic/zdir/nested-link
printf attacker > /tmp/tmpfiles-public-dirs-probe/zpublic/zdir/attacker-file
ls -la /tmp/tmpfiles-public-dirs-probe/zpublic /tmp/tmpfiles-public-dirs-probe/zpublic/zdir
'
cat > "$work/zrules.conf" <<EOF
z $work/zpublic/z-link 0666 attacker attacker -
Z $work/zpublic/zdir 0666 attacker attacker -
EOF
show_path "$work/zpublic/z-link" "$work/zpublic/zdir/nested-link" "$work/zpublic/zdir/attacker-file" "$decoy/z-target"
run_tmpfiles "transient z/Z safe config" --create "$work/zrules.conf"
show_path "$work/zpublic/z-link" "$work/zpublic/zdir/nested-link" "$work/zpublic/zdir/attacker-file" "$decoy/z-target"

section "hardlink protections"
as_attacker '
set +e
for target in /etc/shadow /tmp/tmpfiles-public-dirs-root-decoys/file; do
  out="/tmp/tpf-hardlink-$(basename "$target")"
  rm -f "$out"
  printf "hardlink %s -> %s: " "$target" "$out"
  ln "$target" "$out" 2>/tmp/tpf_hl_err && { ls -l "$out"; rm -f "$out"; } || { printf "NO "; sed -n "1p" /tmp/tpf_hl_err; }
done
rm -f /tmp/tpf_hl_err
'

section "short symlink race checks"
rm -rf /tmp/systemd-private-raceprobe /tmp/.X78-lock
: > "$race_log"
cat > "$work/racerules.conf" <<'EOF'
R! /tmp/systemd-private-raceprobe
r! /tmp/.X78-lock
EOF
runuser -u attacker -- bash -lc '
for i in $(seq 1 200); do
  rm -rf /tmp/systemd-private-raceprobe /tmp/.X78-lock 2>/dev/null || true
  mkdir -p /tmp/systemd-private-raceprobe/sub 2>/dev/null || true
  ln -s /tmp/tmpfiles-public-dirs-root-decoys/rmtree-target /tmp/systemd-private-raceprobe/sub/link 2>/dev/null || true
  ln -s /tmp/tmpfiles-public-dirs-root-decoys/xlock-target /tmp/.X78-lock 2>/dev/null || true
done
' tmpfiles-public-dirs-race-attacker &
race_pid=$!
for i in $(seq 1 60); do
  systemd-tmpfiles --boot --remove "$work/racerules.conf" >/dev/null 2>>"$race_log" || true
done
wait "$race_pid" 2>/dev/null || true
show_path /tmp/systemd-private-raceprobe /tmp/.X78-lock "$decoy/rmtree-target" "$decoy/xlock-target"
printf 'race stderr sample:\n'
sed -n '1,20p' "$race_log"

section "final root decoy integrity"
find "$decoy" -maxdepth 2 -printf '%M %u:%g %p -> %l\n' | sort
printf '\nsha256:\n'
sha256sum "$decoy/file" "$decoy/xlock-target" "$decoy/rmtree-target" "$decoy/z-target" "$decoy/dir/child" 2>/dev/null || true

section "cleanup verification"
cleanup_tmp
restore_default_xdirs
for p in "$work" "$decoy" /tmp/.X11-unix /tmp/.X77-lock /tmp/.X78-lock /tmp/snap-private-tmp /tmp/systemd-private-tpfprobe /tmp/systemd-private-raceprobe /run/screen/tpf-link /run/screen/tpf-file /dev/shm/tpf-link; do
  [ ! -e "$p" ] && [ ! -L "$p" ] && printf 'removed %s\n' "$p" || show_path "$p"
done
printf 'restored default x11 tmpfiles dirs:\n'
show_path /tmp/.X11-unix /tmp/.ICE-unix /tmp/.XIM-unix /tmp/.font-unix
INCONTAINER
