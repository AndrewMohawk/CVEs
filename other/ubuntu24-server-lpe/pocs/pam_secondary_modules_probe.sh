#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"

docker exec -i "$container" bash <<'TARGET'
set -euo pipefail

probe="pam_secondary_modules"
run_id="${probe}_$$"
work="/tmp/${run_id}.work"
cron_tag="${run_id}_cron"
cron_job="/home/attacker/.${cron_tag}.sh"
cron_out="/tmp/${cron_tag}.out"
orig_selfauth_gecos="$(getent passwd selfauth 2>/dev/null | cut -d: -f5 || true)"

mkdir -p "$work"

section() {
  printf '\n== %s ==\n' "$1"
}

restore_selfauth_gecos() {
  local current
  current="$(getent passwd selfauth 2>/dev/null | cut -d: -f5 || true)"
  case "$current" in
    ",,,"|"pam-secondary-modules,,,"|"pam-secondary-modules")
      usermod -c "$orig_selfauth_gecos" selfauth 2>/dev/null || true
      ;;
  esac
}

cleanup() {
  set +e
  if id attacker >/dev/null 2>&1; then
    if runuser -u attacker -- crontab -l >"$work/cron.current" 2>/dev/null; then
      grep -v "$cron_tag" "$work/cron.current" >"$work/cron.filtered" || true
      if [ -s "$work/cron.filtered" ]; then
        runuser -u attacker -- crontab "$work/cron.filtered" >/dev/null 2>&1
      else
        runuser -u attacker -- crontab -r >/dev/null 2>&1
      fi
    fi
    rm -f "$cron_job"
  fi
  restore_selfauth_gecos
  rm -f "$cron_out" /root/${run_id}_*.root /tmp/${run_id}_*.out /tmp/${run_id}_*.typescript
  rm -f /tmp/${run_id}_*.strace /tmp/${run_id}_*.strace.*
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

section "target identity"
sed -n '1,8p' /etc/os-release
uname -a
id attacker
id selfauth
getent passwd attacker selfauth
getent group attacker selfauth sudo adm shadow crontab root
passwd -S attacker 2>&1 || true
passwd -S selfauth 2>&1 || true

section "package and helper modes"
(dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
  login passwd util-linux cron libpam0g libpam-modules libpam-runtime libpam-cap \
  libcap2-bin keyutils libkeyutils1 2>&1 || true) | sort
for f in \
  /usr/bin/su /bin/su /usr/bin/chsh /usr/bin/chfn /usr/bin/passwd \
  /usr/bin/login /bin/login /usr/sbin/cron /usr/bin/crontab /usr/sbin/runuser \
  /usr/sbin/pam_timestamp_check /usr/sbin/unix_chkpwd /usr/sbin/pam_extrausers_chkpwd; do
  [ -e "$f" ] && stat -Lc '%A %a %U:%G %F %n' "$f" || echo "MISSING $f"
done

section "default PAM reachability map"
grep -RInE 'pam_(namespace|cap|keyinit|loginuid|group|time)' /etc/pam.d | sort || true
for f in \
  /etc/pam.d/login /etc/pam.d/su /etc/pam.d/su-l /etc/pam.d/chsh \
  /etc/pam.d/chfn /etc/pam.d/passwd /etc/pam.d/cron /etc/pam.d/runuser \
  /etc/pam.d/runuser-l /etc/pam.d/common-auth /etc/pam.d/common-account \
  /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
  if [ -e "$f" ]; then
    echo "--- $f"
    nl -ba "$f"
  else
    echo "--- $f MISSING"
  fi
done

section "security policy file state"
for f in \
  /etc/security/capability.conf /etc/security/group.conf /etc/security/time.conf \
  /etc/security/namespace.conf /etc/security/namespace.init /etc/security/namespace.d \
  /etc/security/limits.conf /etc/security/limits.d /etc/security/pam_env.conf \
  /etc/environment /etc/default/locale /run/user; do
  [ -e "$f" ] || [ -L "$f" ] && stat -Lc '%A %a %U:%G %F %n' "$f" || echo "MISSING $f"
done
for f in /etc/security/capability.conf /etc/security/group.conf /etc/security/time.conf /etc/security/namespace.conf; do
  echo "--- active non-comment lines in $f"
  awk 'NF && $1 !~ /^#/ { print NR ":" $0 }' "$f" || true
done
echo "--- namespace.init root-helper header"
sed -n '1,70p' /etc/security/namespace.init

section "attacker write and precreation attempts"
set +e
runuser -u attacker -- bash <<'ATTACKER'
set +e
for p in \
  /etc/security/capability.conf /etc/security/group.conf /etc/security/time.conf \
  /etc/security/namespace.conf /etc/security/namespace.d/pam_secondary_modules \
  /etc/security/limits.d/pam_secondary_modules.conf /etc/security/namespace.init \
  /run/user/1001 /run/user/1002 /run/user/pam_secondary_modules; do
  printf 'write %s: ' "$p"
  (printf 'pam_secondary_modules\n' >"$p") 2>&1 && echo WROTE
done
for p in \
  /etc/security/capability.conf.link /etc/security/group.conf.link \
  /etc/security/namespace.d/pam_secondary_modules.link /run/user/1001.link; do
  printf 'symlink %s: ' "$p"
  (ln -s /root/pam_secondary_modules_symlink_target "$p") 2>&1 && echo CREATED
done
ATTACKER
attacker_write_rc=$?
set -e
echo "attacker_write_rc=$attacker_write_rc"
find /run/user -maxdepth 2 -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort || true

section "login direct reachability"
set +e
timeout 5s runuser -u attacker -- /usr/bin/login -f attacker </dev/null >"/tmp/${run_id}_login.out" 2>&1
login_rc=$?
set -e
echo "login_rc=$login_rc"
sed -n '1,80p' "/tmp/${run_id}_login.out"

section "su to selfauth: pam_cap and pam_keyinit reachable, no privilege retained"
set +e
printf 'selfauth\n' | timeout 20s strace -ff -s 180 \
  -o "/tmp/${run_id}_su.strace" \
  -e trace=file,keyctl,add_key,request_key,capset,setuid,setgid,setgroups \
  runuser -u attacker -- su - selfauth -c \
  'id; printf loginuid=; cat /proc/self/loginuid 2>/dev/null || true; grep "^Cap" /proc/self/status; printf groups=; id -Gn; ls -ld /run/user /run/user/$(id -u) 2>&1 || true; touch /root/pam_secondary_modules_su.root 2>&1 || echo root_touch_denied=$?' \
  >"/tmp/${run_id}_su.out" 2>&1
su_rc=$?
set -e
echo "su_rc=$su_rc"
sed -n '1,120p' "/tmp/${run_id}_su.out"
echo "--- su trace highlights"
grep -hE 'pam_(cap|keyinit|loginuid|group|time|namespace)|capability.conf|group.conf|time.conf|namespace.conf|keyctl|add_key|request_key|capset|setgroups|setgid|setuid|/run/user' \
  /tmp/${run_id}_su.strace* 2>/dev/null | sed -n '1,220p' || true
[ -e /root/pam_secondary_modules_su.root ] && stat -Lc 'su_root_marker=%A %U:%G %n' /root/pam_secondary_modules_su.root || echo "su_root_marker=absent"

section "chsh no-op as selfauth: pam_cap reachable only"
set +e
printf 'selfauth\n' | timeout 20s strace -ff -s 180 \
  -o "/tmp/${run_id}_chsh.strace" \
  -e trace=file,keyctl,add_key,request_key,capset,setuid,setgid,setgroups \
  runuser -u selfauth -- chsh -s /bin/bash selfauth \
  >"/tmp/${run_id}_chsh.out" 2>&1
chsh_rc=$?
set -e
echo "chsh_rc=$chsh_rc"
sed -n '1,100p' "/tmp/${run_id}_chsh.out"
echo "--- chsh trace highlights"
grep -hE 'pam_(cap|keyinit|loginuid|group|time|namespace)|capability.conf|group.conf|time.conf|namespace.conf|keyctl|capset|setgroups|setgid|setuid' \
  /tmp/${run_id}_chsh.strace* 2>/dev/null | sed -n '1,180p' || true
getent passwd selfauth

section "chfn as selfauth: pam_cap reachable, GECOS restored"
set +e
printf 'selfauth\n\n\n\n\n' | timeout 20s strace -ff -s 180 \
  -o "/tmp/${run_id}_chfn.strace" \
  -e trace=file,keyctl,add_key,request_key,capset,setuid,setgid,setgroups \
  runuser -u selfauth -- chfn selfauth \
  >"/tmp/${run_id}_chfn.out" 2>&1
chfn_rc=$?
set -e
echo "chfn_rc=$chfn_rc"
sed -n '1,120p' "/tmp/${run_id}_chfn.out"
echo "selfauth_after_chfn=$(getent passwd selfauth)"
echo "--- chfn trace highlights"
grep -hE 'pam_(cap|keyinit|loginuid|group|time|namespace)|capability.conf|group.conf|time.conf|namespace.conf|keyctl|capset|setgroups|setgid|setuid' \
  /tmp/${run_id}_chfn.strace* 2>/dev/null | sed -n '1,180p' || true
restore_selfauth_gecos
echo "selfauth_after_restore=$(getent passwd selfauth)"

section "passwd service has no secondary module hooks"
nl -ba /etc/pam.d/passwd
runuser -u selfauth -- passwd -S selfauth 2>&1 || true

section "cron PAM session trigger from uid1001 crontab"
systemctl is-active cron 2>&1 || true
ps -ef | grep -E '[c]ron' || true
cat >"$cron_job" <<EOF
#!/bin/bash
{
  echo cron_probe_start
  date -Is
  id
  printf loginuid=
  cat /proc/self/loginuid 2>/dev/null || true
  grep '^Cap' /proc/self/status
  printf groups=
  id -Gn
  printf umask=
  umask
  printf 'env_USER=%s env_LOGNAME=%s env_HOME=%s env_SHELL=%s\n' "\${USER:-}" "\${LOGNAME:-}" "\${HOME:-}" "\${SHELL:-}"
  ls -ld /run/user /run/user/\$(id -u) 2>&1 || true
  touch /root/${run_id}_cron.root 2>&1 || echo root_touch_denied=\$?
} >> '$cron_out' 2>&1
EOF
chown attacker:attacker "$cron_job"
chmod 700 "$cron_job"
runuser -u attacker -- bash -lc "(crontab -l 2>/dev/null || true; echo '# $cron_tag'; echo '* * * * * /bin/bash $cron_job # $cron_tag') | crontab -"
runuser -u attacker -- crontab -l | tail -n 8
for _ in $(seq 1 80); do
  [ -s "$cron_out" ] && break
  sleep 1
done
if [ -s "$cron_out" ]; then
  sed -n '1,160p' "$cron_out"
else
  echo "cron_probe_output=missing"
fi
[ -e /root/${run_id}_cron.root ] && stat -Lc 'cron_root_marker=%A %U:%G %n' /root/${run_id}_cron.root || echo "cron_root_marker=absent"

section "post-probe root marker and cleanup check"
cleanup
trap - EXIT INT TERM
for p in /root/pam_secondary_modules_su.root /root/${run_id}_cron.root; do
  [ -e "$p" ] && stat -Lc '%A %U:%G %n' "$p" || echo "absent $p"
done
find /tmp /home/attacker /home/selfauth -maxdepth 2 \
  \( -name "${run_id}*" -o -name ".${cron_tag}.sh" \) \
  -printf '%M %u:%g %p -> %l\n' 2>/dev/null | sort || true
echo "selfauth_final=$(getent passwd selfauth)"
TARGET
