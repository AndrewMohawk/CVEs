#!/usr/bin/env bash
set -euo pipefail

container="${1:-ubuntu24-server-lpe-target}"
out_dir="/tmp/active-login1-devices"

docker exec -i "$container" bash -s <<'EOS'
set -euo pipefail

id selfauth >/dev/null 2>&1 || useradd -m -s /bin/bash selfauth
echo selfauth:selfauth | chpasswd
usermod -G selfauth selfauth
rm -rf /tmp/active-login1-devices
mkdir -p /tmp/active-login1-devices
chown selfauth:selfauth /tmp/active-login1-devices

cat >/home/selfauth/active-login1-devices-probe.py <<'PY'
#!/usr/bin/env python3
import dbus
import fcntl
import os
import pty
import stat
import subprocess
import sys
import termios
import time

OUT = "/tmp/active-login1-devices/probe.out"

def log(msg):
    print(msg, flush=True)

def run(argv):
    log("$ " + " ".join(argv))
    try:
        p = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=8)
        log(f"rc={p.returncode}")
        if p.stdout:
            log(p.stdout.rstrip())
    except Exception as e:
        log(f"EXC {type(e).__name__}: {e}")

def devnums(path):
    st = os.stat(path)
    return os.major(st.st_rdev), os.minor(st.st_rdev)

def try_take(sess, path):
    try:
        maj, minr = devnums(path)
        log(f"TAKE {path} maj={maj} min={minr}")
        fd_obj, paused = sess.TakeDevice(dbus.UInt32(maj), dbus.UInt32(minr))
        fd = fd_obj.take()
        log(f"  OK fd={fd} paused={bool(paused)}")
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            log(f"  flags=0x{flags:x}")
        except Exception as e:
            log(f"  fcntl(F_GETFL)={type(e).__name__}:{e}")
        try:
            os.set_blocking(fd, False)
            data = os.read(fd, 64)
            log(f"  read={data!r}")
        except Exception as e:
            log(f"  read={type(e).__name__}:{e}")
        try:
            sess.ReleaseDevice(dbus.UInt32(maj), dbus.UInt32(minr))
            log("  ReleaseDevice OK")
        except Exception as e:
            log(f"  ReleaseDevice={type(e).__name__}:{e}")
        try:
            os.close(fd)
        except OSError:
            pass
    except Exception as e:
        log(f"  FAIL {type(e).__name__}: {e}")

def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    sys.stdout = open(OUT, "w", buffering=1)
    sys.stderr = sys.stdout

    log("=== identity/session ===")
    run(["id"])
    run(["tty"])
    log(f"XDG_SESSION_ID={os.environ.get('XDG_SESSION_ID')!r}")
    if os.environ.get("XDG_SESSION_ID"):
        run(["loginctl", "show-session", os.environ["XDG_SESSION_ID"], "-p", "Id", "-p", "Name", "-p", "User", "-p", "Path", "-p", "Seat", "-p", "TTY", "-p", "Active", "-p", "State", "-p", "Type", "-p", "Class", "-p", "Remote", "-p", "Leader"])

    log("=== device node modes ===")
    for root, _, files in os.walk("/dev"):
        for name in files:
            p = os.path.join(root, name)
            if p.startswith(("/dev/tty", "/dev/vcs", "/dev/input/", "/dev/dri/")) or p == "/dev/console":
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if stat.S_ISCHR(st.st_mode):
                    log(f"{stat.filemode(st.st_mode)} {st.st_uid}:{st.st_gid} {os.major(st.st_rdev)}:{os.minor(st.st_rdev)} {p}")

    log("=== direct open checks before logind fd brokering ===")
    for p in ["/dev/tty1", "/dev/tty0", "/dev/console", "/dev/vcs1", "/dev/vcsa1", "/dev/input/mice"]:
        if os.path.exists(p):
            try:
                fd = os.open(p, os.O_RDWR | os.O_NONBLOCK)
                log(f"open {p} O_RDWR OK fd={fd}")
                os.close(fd)
            except Exception as e:
                log(f"open {p} O_RDWR FAIL {type(e).__name__}:{e}")

    bus = dbus.SystemBus()
    mgr = dbus.Interface(bus.get_object("org.freedesktop.login1", "/org/freedesktop/login1"), "org.freedesktop.login1.Manager")
    sid = os.environ.get("XDG_SESSION_ID")
    if not sid:
        log("no XDG_SESSION_ID; aborting active session probe")
        return
    path = str(mgr.GetSession(sid))
    log(f"session_path={path}")
    sess = dbus.Interface(bus.get_object("org.freedesktop.login1", path), "org.freedesktop.login1.Session")

    log("=== session control ===")
    for force in (False, True):
        try:
            sess.TakeControl(force)
            log(f"TakeControl({force}) OK")
            break
        except Exception as e:
            log(f"TakeControl({force}) FAIL {type(e).__name__}:{e}")

    log("=== TakeDevice probes ===")
    candidates = ["/dev/tty1", "/dev/tty0", "/dev/console", "/dev/vcs1", "/dev/vcsa1", "/dev/vcsu1", "/dev/input/mice"]
    for p in candidates:
        if os.path.exists(p):
            try_take(sess, p)

    log("=== session mutators ===")
    for method, args in [
        ("SetIdleHint", (dbus.Boolean(True),)),
        ("SetLockedHint", (dbus.Boolean(True),)),
        ("SetType", (dbus.String("x11"),)),
        ("SetClass", (dbus.String("greeter"),)),
        ("Activate", ()),
        ("Lock", ()),
    ]:
        try:
            getattr(sess, method)(*args)
            log(f"{method} OK")
        except Exception as e:
            log(f"{method} FAIL {type(e).__name__}:{e}")

    log("=== tty ioctl checks ===")
    run(["sh", "-c", "sysctl dev.tty.legacy_tiocsti 2>/dev/null || true"])
    try:
        fcntl.ioctl(0, termios.TIOCSTI, b"Z")
        log("TIOCSTI stdin OK")
    except Exception as e:
        log(f"TIOCSTI stdin FAIL {type(e).__name__}:{e}")

    log("=== marker/root-proof check ===")
    for marker in ["/tmp/active-login1-root", "/root/active-login1-root"]:
        log(f"{marker} exists={os.path.exists(marker)}")

    try:
        sess.ReleaseControl()
        log("ReleaseControl OK")
    except Exception as e:
        log(f"ReleaseControl FAIL {type(e).__name__}:{e}")

if __name__ == "__main__":
    main()
PY
chmod 0755 /home/selfauth/active-login1-devices-probe.py
chown selfauth:selfauth /home/selfauth/active-login1-devices-probe.py

cat >/home/selfauth/.bash_profile <<'SH'
/usr/bin/python3 /home/selfauth/active-login1-devices-probe.py
exit
SH
chown selfauth:selfauth /home/selfauth/.bash_profile

systemctl stop getty@tty1.service 2>/dev/null || true
timeout 60 openvt -c 1 -s -f -w -- /bin/login -f selfauth || true
systemctl start getty@tty1.service 2>/dev/null || true
loginctl terminate-user selfauth 2>/dev/null || true
rm -f /home/selfauth/.bash_profile /home/selfauth/active-login1-devices-probe.py
EOS

mkdir -p "ubuntu24-server-lpe/logs"
for _ in 1 2 3 4 5; do
  if docker exec "$container" test -s "$out_dir/probe.out"; then
    docker exec "$container" cat "$out_dir/probe.out" >"ubuntu24-server-lpe/logs/active-login1-devices-probe.out"
    break
  fi
  sleep 1
done
docker exec "$container" bash -lc 'rm -rf /tmp/active-login1-devices; systemctl start getty@tty1.service 2>/dev/null || true; loginctl terminate-user selfauth 2>/dev/null || true'

sed -n '1,240p' "ubuntu24-server-lpe/logs/active-login1-devices-probe.out"
