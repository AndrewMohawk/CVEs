#!/bin/bash
out=/tmp/active-login1-probe.out
exec >"$out" 2>&1
set +e
printf "== identity ==\n"
id
tty
echo "XDG_SESSION_ID=${XDG_SESSION_ID:-}"
loginctl show-session "${XDG_SESSION_ID:-}" -p Id -p User -p Name -p Seat -p TTY -p Remote -p Type -p Class -p Active -p State 2>&1
printf "== pkcheck ==\n"
for a in \
  org.freedesktop.login1.set-reboot-parameter \
  org.freedesktop.login1.set-reboot-to-boot-loader-entry \
  org.freedesktop.login1.set-reboot-to-boot-loader-menu \
  org.freedesktop.login1.set-reboot-to-firmware-setup \
  org.freedesktop.login1.reboot \
  org.freedesktop.login1.power-off \
  org.freedesktop.login1.set-wall-message \
  org.freedesktop.login1.inhibit-block-shutdown; do
  timeout 3 pkcheck --action-id "$a" --process $$ >/tmp/pkcheck.$$.out 2>&1
  rc=$?
  printf "%s rc=%s out=%s\n" "$a" "$rc" "$(tr "\n" "|" </tmp/pkcheck.$$.out)"
done
rm -f /tmp/pkcheck.$$.out
printf "== can methods ==\n"
for m in CanReboot CanPowerOff CanHalt CanSuspend CanHibernate CanRebootParameter CanRebootToFirmwareSetup CanRebootToBootLoaderMenu CanRebootToBootLoaderEntry; do
  printf "%s: " "$m"
  busctl call --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager "$m" 2>&1
  echo rc:$?
done
printf "== initial properties ==\n"
for p in RebootParameter RebootToBootLoaderEntry RebootToBootLoaderMenu RebootToFirmwareSetup ScheduledShutdown WallMessage EnableWallMessages NCurrentInhibitors; do
  printf "%s: " "$p"
  busctl get-property --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager "$p" 2>&1
  echo rc:$?
done
printf "== mutation attempts ==\n"
for cmd in \
  "SetRebootParameter s ubulpe-param-1002" \
  "SetRebootToBootLoaderEntry s ubulpe-entry" \
  "SetRebootToBootLoaderMenu t 7" \
  "SetRebootToFirmwareSetup b true"; do
  echo "CALL $cmd"
  busctl call --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager $cmd 2>&1
  echo rc:$?
done
printf "== properties after reboot setters ==\n"
for p in RebootParameter RebootToBootLoaderEntry RebootToBootLoaderMenu RebootToFirmwareSetup; do
  printf "%s: " "$p"
  busctl get-property --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager "$p" 2>&1
  echo rc:$?
done
printf "== wall direct should fail ==\n"
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SetWallMessage sb "ubulpe-wall" false 2>&1
echo rc:$?
busctl set-property --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager WallMessage s "ubulpe-prop-wall" 2>&1
echo rc:$?
printf "== inhibitors ==\n"
for what in shutdown sleep idle handle-power-key handle-reboot-key; do
  echo "Inhibit $what block"
  busctl call --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager Inhibit ssss "$what" ubulpe-login1 "probe-$what" block 2>&1
  echo rc:$?
done
printf "== schedule shutdown then cancel ==\n"
when=$(( $(date +%s) + 7200 ))
echo "when=$when"
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ScheduleShutdown st reboot "$when" 2>&1
echo rc:$?
printf "ScheduledShutdown: "; busctl get-property --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ScheduledShutdown 2>&1; echo rc:$?
busctl call --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CancelScheduledShutdown 2>&1
echo rc:$?
printf "ScheduledShutdownAfterCancel: "; busctl get-property --system org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ScheduledShutdown 2>&1; echo rc:$?
printf "== done ==\n"
