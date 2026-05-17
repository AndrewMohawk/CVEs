#!/usr/bin/env python3
import sys
import time
import os

import dbus


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} OBJECT_PATH METHOD [SIZE]", file=sys.stderr)
        return 2

    object_path = sys.argv[1]
    method = sys.argv[2]
    size = int(sys.argv[3]) if len(sys.argv) > 3 else 33554432

    bus = dbus.SystemBus()
    obj = bus.get_object("org.freedesktop.UDisks2", object_path)
    filesystem = dbus.Interface(obj, "org.freedesktop.UDisks2.Filesystem")
    options = dbus.Dictionary({}, signature="sv")

    print(f"unique_name={bus.get_unique_name()}", flush=True)
    try:
        if method == "Check":
            result = filesystem.Check(options, timeout=120)
        elif method == "Repair":
            result = filesystem.Repair(options, timeout=120)
        elif method == "Resize":
            result = filesystem.Resize(dbus.UInt64(size), options, timeout=120)
        else:
            print(f"unsupported method: {method}", file=sys.stderr, flush=True)
            return 2
        print(f"result={result!r}", flush=True)
    except Exception as exc:
        print(f"exception={type(exc).__name__}: {exc}", flush=True)

    hold_secs = int(os.environ.get("UDISKS_HOLD_SECS", "8"))
    print(f"holding_system_bus_name={hold_secs}s", flush=True)
    time.sleep(hold_secs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
