#!/usr/bin/env bash
set -u

container="${CONTAINER:-ubuntu24-server-lpe-target}"
marker="/root/devproc_lpe_marker"

echo "== target =="
docker exec "$container" bash -lc 'cat /etc/os-release | sed -n "1,6p"; uname -a; id attacker; groups attacker'

echo
echo "== root-side device inventory =="
docker exec "$container" bash -lc '
for p in /dev/uinput /dev/mapper/control /dev/net/tun /dev/fuse /dev/cuse /dev/vsock /dev/ppp /dev/hwrng /proc/sys/kernel/ns_last_pid; do
  if [ -e "$p" ]; then
    stat -Lc "%A %a %U %G %t:%T %F %n" "$p"
  else
    echo "MISSING $p"
  fi
done
find /dev -maxdepth 1 \( -name "hvc*" -o -name "usbmon*" \) -exec stat -Lc "%A %a %U %G %t:%T %F %n" {} \; 2>/dev/null | sort
'

echo
echo "== stock udev rule evidence =="
docker exec "$container" bash -lc '
grep -RInE "uinput|mapper/control|net/tun|fuse|cuse|vsock|ppp|hvc|usbmon|hwrng|device-mapper|KERNEL==\"tun\"|KERNEL==\"fuse\"" /usr/lib/udev/rules.d /etc/udev/rules.d /lib/udev/rules.d 2>/dev/null | sed -n "1,220p" || true
'

echo
echo "== attacker shell access bits =="
docker exec -i "$container" bash <<'TARGET'
runuser -u attacker -- bash <<'ATTACKER'
set -u
id
for p in /dev/uinput /dev/mapper/control /dev/net/tun /dev/fuse /dev/cuse /dev/vsock /dev/ppp /dev/hwrng /proc/sys/kernel/ns_last_pid; do
  if [ -e "$p" ]; then
    r=-; w=-
    [ -r "$p" ] && r=r
    [ -w "$p" ] && w=w
    printf "%s%s %s\n" "$r" "$w" "$p"
  else
    echo "-- MISSING $p"
  fi
done
find /dev -maxdepth 1 \( -name "hvc*" -o -name "usbmon*" \) -exec sh -c '
  for x; do r=-; w=-; [ -r "$x" ] && r=r; [ -w "$x" ] && w=w; printf "%s%s %s\n" "$r" "$w" "$x"; done
' sh {} + 2>/dev/null | sort
ATTACKER
TARGET

echo
echo "== attacker privileged-operation gates =="
docker exec -i "$container" bash <<'TARGET'
runuser -u attacker -- bash <<'ATTACKER'
set +e
echo "-- dmsetup version"
timeout 5 /usr/sbin/dmsetup version 2>&1
echo "rc=$?"
echo "-- dmsetup create devproc_dm"
printf '0 8 zero\n' | timeout 5 /usr/sbin/dmsetup create devproc_dm 2>&1
echo "rc=$?"
echo "-- ip tuntap add"
timeout 5 /usr/sbin/ip tuntap add dev devproc_tun0 mode tun user attacker 2>&1
echo "rc=$?"
timeout 5 /usr/sbin/ip link show devproc_tun0 2>&1
echo "rc=$?"
echo "-- ns_last_pid shell write"
old="$(cat /proc/sys/kernel/ns_last_pid 2>&1)"
echo "old=$old"
printf '%s\n' "$old" > /proc/sys/kernel/ns_last_pid 2>&1
echo "rc=$?"
ATTACKER
TARGET

echo
echo "== attacker direct device/ioctl probes =="
docker exec -i "$container" bash <<'TARGET'
runuser -u attacker -- python3 <<'PY'
import errno
import fcntl
import glob
import os
import socket
import struct
import time

def result(name, ok, detail):
    print(f"{name}: {'OK' if ok else 'FAIL'}: {detail}")

def open_any(path, flags=os.O_RDWR | os.O_NONBLOCK):
    for mode, candidate in (
        ("rdwr", flags),
        ("rdonly", os.O_RDONLY | os.O_NONBLOCK),
        ("wronly", os.O_WRONLY | os.O_NONBLOCK),
    ):
        try:
            return mode, os.open(path, candidate)
        except OSError as exc:
            last = exc
    raise last

def err(exc):
    if isinstance(exc, OSError):
        return f"{exc.__class__.__name__} errno={exc.errno} {os.strerror(exc.errno)}"
    return repr(exc)

paths = [
    "/dev/uinput",
    "/dev/mapper/control",
    "/dev/net/tun",
    "/dev/fuse",
    "/dev/cuse",
    "/dev/vsock",
    "/dev/ppp",
    "/dev/hwrng",
]
paths.extend(sorted(glob.glob("/dev/hvc*")))
paths.extend(sorted(glob.glob("/dev/usbmon*")))

for path in paths:
    if not os.path.exists(path):
        result(path, False, "missing")
        continue
    fd = None
    try:
        mode, fd = open_any(path)
        detail = f"open mode={mode}"
        if path == "/dev/hwrng":
            try:
                data = os.read(fd, 16)
                detail += f"; read_len={len(data)}"
            except OSError as exc:
                detail += f"; read={err(exc)}"
        elif path.startswith("/dev/usbmon"):
            try:
                data = os.read(fd, 64)
                detail += f"; read_len={len(data)}"
            except OSError as exc:
                detail += f"; read={err(exc)}"
        elif path == "/dev/ppp":
            try:
                written = os.write(fd, b"\x00")
                detail += f"; one_byte_write={written}"
            except OSError as exc:
                detail += f"; one_byte_write={err(exc)}"
        result(path, True, detail)
    except OSError as exc:
        result(path, False, err(exc))
    finally:
        if fd is not None:
            os.close(fd)

# Linux ioctl helpers for the current architecture's generic ioctl encoding.
IOC_NRBITS = 8
IOC_TYPEBITS = 8
IOC_SIZEBITS = 14
IOC_NRSHIFT = 0
IOC_TYPESHIFT = IOC_NRSHIFT + IOC_NRBITS
IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
IOC_DIRSHIFT = IOC_SIZESHIFT + IOC_SIZEBITS
IOC_NONE = 0
IOC_WRITE = 1
IOC_READ = 2

def IOC(direction, type_chr, nr, size):
    return (
        (direction << IOC_DIRSHIFT)
        | (ord(type_chr) << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT)
    )

def IO(type_chr, nr):
    return IOC(IOC_NONE, type_chr, nr, 0)

def IOR(type_chr, nr, size):
    return IOC(IOC_READ, type_chr, nr, size)

def IOW(type_chr, nr, size):
    return IOC(IOC_WRITE, type_chr, nr, size)

# /dev/net/tun: querying features is harmless; TUNSETIFF is the capability gate.
try:
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    TUNGETFEATURES = IOR("T", 207, 4)
    TUNSETIFF = IOW("T", 202, 4)
    try:
        buf = fcntl.ioctl(fd, TUNGETFEATURES, struct.pack("I", 0), True)
        features = struct.unpack("I", buf[:4])[0]
        result("tun TUNGETFEATURES", True, f"features=0x{features:x}")
    except OSError as exc:
        result("tun TUNGETFEATURES", False, err(exc))
    ifr = b"devproc0\x00" + b"\x00" * (16 - len("devproc0") - 1) + struct.pack("H", 0x0001 | 0x1000) + b"\x00" * 22
    try:
        fcntl.ioctl(fd, TUNSETIFF, ifr)
        result("tun TUNSETIFF", True, "unexpectedly created devproc0")
    except OSError as exc:
        result("tun TUNSETIFF", False, err(exc))
    os.close(fd)
except OSError as exc:
    result("tun ioctl open", False, err(exc))

# /dev/uinput: verify the ioctl path and, if allowed, create/destroy a harmless
# virtual device without sending input events.
uinput_fd = None
created = False
try:
    uinput_fd = os.open("/dev/uinput", os.O_WRONLY | os.O_NONBLOCK)
    UI_SET_EVBIT = IOW("U", 100, 4)
    UI_SET_KEYBIT = IOW("U", 101, 4)
    UI_DEV_SETUP = IOW("U", 3, 92)
    UI_DEV_CREATE = IO("U", 1)
    UI_DEV_DESTROY = IO("U", 2)
    try:
        fcntl.ioctl(uinput_fd, UI_SET_EVBIT, 0x01)  # EV_KEY
        fcntl.ioctl(uinput_fd, UI_SET_KEYBIT, 30)   # KEY_A
        setup = struct.pack("HHHH80sI", 0x06, 0x1234, 0x5678, 1, b"devproc-audit\x00", 0)
        fcntl.ioctl(uinput_fd, UI_DEV_SETUP, setup)
        fcntl.ioctl(uinput_fd, UI_DEV_CREATE)
        created = True
        result("uinput create/destroy", True, "created virtual input device; sent no events")
    except OSError as exc:
        result("uinput create/destroy", False, err(exc))
finally:
    if uinput_fd is not None:
        if created:
            try:
                fcntl.ioctl(uinput_fd, UI_DEV_DESTROY)
                time.sleep(0.1)
            except OSError as exc:
                result("uinput destroy", False, err(exc))
        os.close(uinput_fd)

# AF_VSOCK can exist independently of opening /dev/vsock. Do not connect to a
# host service; just prove socket creation and local bind behavior.
try:
    fam = getattr(socket, "AF_VSOCK")
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(0.2)
    result("AF_VSOCK socket", True, "created stream socket")
    s.close()
except Exception as exc:
    result("AF_VSOCK socket", False, err(exc))

# ns_last_pid is mode 0666 in the target but modern kernels gate writes.
try:
    with open("/proc/sys/kernel/ns_last_pid", "r", encoding="ascii") as f:
        old = f.read().strip()
    try:
        with open("/proc/sys/kernel/ns_last_pid", "w", encoding="ascii") as f:
            f.write(old + "\n")
        result("ns_last_pid write", True, f"wrote current value {old}")
    except OSError as exc:
        result("ns_last_pid write", False, err(exc))
except OSError as exc:
    result("ns_last_pid read", False, err(exc))
PY
TARGET

echo
echo "== cleanup and root proof check =="
docker exec "$container" bash -lc '
set +e
/usr/sbin/ip link del devproc_tun0 2>/dev/null
/usr/sbin/dmsetup remove -f devproc_dm 2>/dev/null
rm -rf /tmp/devproc_* /home/attacker/devproc_* 2>/dev/null
if [ -e /root/devproc_lpe_marker ]; then
  echo "ROOT_MARKER_PRESENT"
  ls -l /root/devproc_lpe_marker
  cat /root/devproc_lpe_marker
else
  echo "no root marker"
fi
findmnt | grep devproc || true
ip link show devproc_tun0 2>&1 || true
dmsetup info devproc_dm 2>&1 || true
'
