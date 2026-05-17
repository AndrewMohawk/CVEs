#!/usr/bin/env python3
import os
import sys
import tempfile
import traceback

import dbus


BUS = "org.freedesktop.fwupd"
PATH = "/"
IFACE = "org.freedesktop.fwupd"


def call(label, fn):
    print(f"=== {label} ===")
    try:
        rv = fn()
        print(f"OK: {rv!r}")
    except Exception as exc:
        print(f"ERR: {type(exc).__name__}: {exc}")
        if os.environ.get("FWUPD_PROBE_TRACE"):
            traceback.print_exc()


def make_file(prefix, data):
    fd, path = tempfile.mkstemp(prefix=prefix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def unixfd(fd):
    if hasattr(dbus, "UnixFd"):
        return dbus.UnixFd(fd)
    from dbus.types import UnixFd

    return UnixFd(fd)


def main():
    bus = dbus.SystemBus()
    obj = bus.get_object(BUS, PATH)
    fwupd = dbus.Interface(obj, IFACE)
    props = dbus.Interface(obj, "org.freedesktop.DBus.Properties")

    print(f"uid={os.getuid()} euid={os.geteuid()} groups={os.getgroups()}")
    call("DaemonVersion", lambda: props.Get(IFACE, "DaemonVersion"))
    call("OnlyTrusted", lambda: props.Get(IFACE, "OnlyTrusted"))

    bad_cab = make_file("fwupd-bad-cab-", b"MSCF" + b"\x00" * 128)
    xml = make_file(
        "fwupd-meta-",
        b"<?xml version='1.0' encoding='UTF-8'?><components version='0.14'></components>\n",
    )
    sig = make_file("fwupd-sig-", b"not-a-valid-signature\n")

    def get_details_bad():
        fd = os.open(bad_cab, os.O_RDONLY)
        try:
            return fwupd.GetDetails(unixfd(fd), timeout=30)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def update_metadata_vendor_directory():
        fd1 = os.open(xml, os.O_RDONLY)
        fd2 = os.open(sig, os.O_RDONLY)
        try:
            return fwupd.UpdateMetadata(
                "vendor-directory", unixfd(fd1), unixfd(fd2), timeout=30
            )
        finally:
            for fd in (fd1, fd2):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def update_metadata_vendor():
        fd1 = os.open(xml, os.O_RDONLY)
        fd2 = os.open(sig, os.O_RDONLY)
        try:
            return fwupd.UpdateMetadata("vendor", unixfd(fd1), unixfd(fd2), timeout=30)
        finally:
            for fd in (fd1, fd2):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def emulation_load():
        return fwupd.EmulationLoad(dbus.ByteArray(b'{"UsbDevices":[]}'), timeout=30)

    def emulation_save():
        return fwupd.EmulationSave(timeout=30)

    def modify_device_fake():
        return fwupd.ModifyDevice(
            "ffffffffffffffffffffffffffffffffffffffff", "Flags", "reported", timeout=30
        )

    call("GetDetails(bad cab)", get_details_bad)
    call("UpdateMetadata(vendor-directory)", update_metadata_vendor_directory)
    call("UpdateMetadata(vendor disabled)", update_metadata_vendor)
    call("EmulationLoad", emulation_load)
    call("EmulationSave", emulation_save)
    call("ModifyDevice(fake history id)", modify_device_fake)

    for path in (bad_cab, xml, sig):
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
