#!/usr/bin/env python3
"""Recover the USB link to a stuck iPhone (usbmuxd does not list it).

Sanitized vendored copy of the documented campaign procedure
(``tg-rce/docs/instrumentation/ios17e/usb_recover.py``).  Numbers and order:

  1. close stale forwarders;
  2. stop usbmuxd;
  3. pyusb ``dev.reset()``; fallback ``set_configuration(3)`` with retries;
  4. start usbmuxd;
  5. check ``pymobiledevice3 usbmux list`` for the UDID.

Run as root (or with passwordless sudo for systemctl).  This script never
writes to the phone.  The phone must be awake and unlocked; tap Trust if the
dialog appears.

No UDID, home path or token is stored in this file.  ``--udid`` is required.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time

VENDOR = 0x05AC
PRODUCT = 0x12A8


def run(cmd: list[str], *, timeout: float = 30.0, check: bool = False) -> int:
    print("+", " ".join(cmd), flush=True)
    try:
        return subprocess.run(cmd, check=check, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        print("command timed out: %s" % " ".join(cmd), file=sys.stderr)
        return 124
    except FileNotFoundError as exc:
        print("command not found: %s (%s)" % (cmd[0], exc), file=sys.stderr)
        return 127


def usbmux_list(p3: str) -> str:
    try:
        result = subprocess.run(
            [p3, "usbmux", "list"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30.0,
        )
        return (result.stdout or "") + (result.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "usbmux list failed: %s" % exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True, help="target device UDID")
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--pymobiledevice3", default=None,
                        help="pymobiledevice3 executable (default: PATH)")
    parser.add_argument("--no-sudo", action="store_true",
                        help="call systemctl directly (already root)")
    parser.add_argument("--skip-reset", action="store_true",
                        help="only restart usbmuxd (no pyusb reset)")
    parser.add_argument("--post-wait", type=float, default=5.0)
    args = parser.parse_args()

    p3 = args.pymobiledevice3 or shutil.which("pymobiledevice3") or "pymobiledevice3"
    sudo: list[str] = [] if args.no_sudo else ["sudo", "-n"]

    run(["pkill", "-f", "pymobiledevice3 usbmux forward"])
    run(["pkill", "-f", "/idund"])

    usb_core = None
    if not args.skip_reset:
        try:
            import usb.core  # type: ignore

            usb_core = usb.core
        except ImportError:
            print("pyusb is missing: pip install pyusb", file=sys.stderr)
            return 2

    for attempt in range(1, args.attempts + 1):
        print("--- attempt %d/%d ---" % (attempt, args.attempts), flush=True)
        run([*sudo, "systemctl", "stop", "usbmuxd"], timeout=30.0)
        time.sleep(2)

        if not args.skip_reset and usb_core is not None:
            dev = usb_core.find(idVendor=VENDOR, idProduct=PRODUCT)
            if dev is None:
                print("device not on the USB bus; replug it with the phone awake")
            else:
                try:
                    dev.reset()
                    print("reset OK")
                except Exception as exc:  # noqa: BLE001
                    print("reset failed:", exc)
                    for _ in range(4):
                        dev = usb_core.find(idVendor=VENDOR, idProduct=PRODUCT)
                        try:
                            dev.set_configuration(3)
                            print("set_configuration(3) OK")
                            break
                        except Exception as exc2:  # noqa: BLE001
                            print("set_configuration busy:", exc2)
                            time.sleep(1.5)

        run([*sudo, "systemctl", "start", "usbmuxd"], timeout=30.0)
        time.sleep(args.post_wait)
        output = usbmux_list(p3)
        print(output.strip())
        if args.udid in output:
            print("RECOVERED")
            return 0
        print("not listed yet", flush=True)

    print("FAILED: wake/unlock the phone, tap Trust, replug the cable, retry")
    return 1


if __name__ == "__main__":
    sys.exit(main())
