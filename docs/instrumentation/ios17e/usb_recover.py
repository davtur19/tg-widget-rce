#!/usr/bin/env python3
"""Recover the USB link to a stuck iPhone (usbmuxd does not list it).

Run as root (or with passwordless sudo for systemctl). The procedure is the
one documented in vulns/0day-2-RCE-PARSER-SCOPE/IOS27/README.md:

  1. close stale forwarders;
  2. stop usbmuxd;
  3. pyusb dev.reset(); fallback set_configuration(3) with retries;
  4. start usbmuxd;
  5. check `pymobiledevice3 usbmux list` for the UDID.

This script never writes to the phone. It only resets the USB device and
restarts the host daemon. The phone must be awake and unlocked; tap Trust if
the dialog appears.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time

VENDOR = 0x05AC
PRODUCT = 0x12A8


def run(cmd: list[str], check: bool = False) -> int:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, check=check).returncode


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--udid", default="<UDID>")
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--pymobiledevice3",
                    default="<HOME>/ailocal/Telegram/ios_sideload/venv/bin/pymobiledevice3")
    a = ap.parse_args()

    run(["pkill", "-f", "pymobiledevice3 usbmux forward"])
    run(["pkill", "-f", "/idund"])

    try:
        import usb.core
    except ImportError:
        print("pyusb is missing: pip install pyusb", file=sys.stderr)
        return 2

    for attempt in range(1, a.attempts + 1):
        print(f"--- attempt {attempt}/{a.attempts} ---")
        run(["sudo", "-n", "systemctl", "stop", "usbmuxd"])
        time.sleep(2)
        dev = usb.core.find(idVendor=VENDOR, idProduct=PRODUCT)
        if dev is None:
            print("device not on the USB bus; replug it with the phone awake")
        else:
            try:
                dev.reset()
                print("reset OK")
            except Exception as exc:  # noqa: BLE001
                print("reset failed:", exc)
                for _ in range(4):
                    dev = usb.core.find(idVendor=VENDOR, idProduct=PRODUCT)
                    try:
                        dev.set_configuration(3)
                        print("set_configuration(3) OK")
                        break
                    except Exception as exc2:  # noqa: BLE001
                        print("set_configuration busy:", exc2)
                        time.sleep(1.5)
        run(["sudo", "-n", "systemctl", "start", "usbmuxd"])
        time.sleep(5)
        out = subprocess.run([a.pymobiledevice3, "usbmux", "list"],
                             capture_output=True, text=True)
        print(out.stdout.strip() or out.stderr.strip())
        if a.udid in out.stdout:
            print("RECOVERED")
            return 0
        print("not listed yet")
    print("FAILED: wake/unlock the phone, tap Trust, replug the cable, retry")
    return 1


if __name__ == "__main__":
    sys.exit(main())
