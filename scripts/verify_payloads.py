#!/usr/bin/env python3
"""Check the canonical payload sizes, zlib9 values and SHA-256 pins.

Usage:
    python3 scripts/verify_payloads.py
    python3 scripts/verify_payloads.py --strict-zlib

The manifest is `docs/PAYLOAD_HASHES.json`. Raw length and SHA-256 are
strict checks. zlib9 is reported always and checked strictly only with
--strict-zlib, because compressed bytes depend on the zlib build (the
manifest records zlib 1.3.1).

No device, bot or network action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MANIFEST = os.path.join(ROOT, "docs", "PAYLOAD_HASHES.json")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--strict-zlib", action="store_true")
    args = p.parse_args()

    data = json.load(open(MANIFEST, encoding="utf-8"))
    files = data.get("files", [])
    if not files:
        print("FAIL: empty manifest")
        return 1

    failures = 0
    zlib_mismatch = 0
    status = {}
    for row in files:
        path = os.path.join(ROOT, row["path"])
        if not os.path.isfile(path):
            print("MISSING %s" % row["path"])
            failures += 1
            continue
        b = open(path, "rb").read()
        sha = hashlib.sha256(b).hexdigest()
        z = len(zlib.compress(b, 9))
        if len(b) != row["raw"]:
            print("RAW  %s: %d != %d" % (row["path"], len(b), row["raw"]))
            failures += 1
        if sha != row["sha256"]:
            print("SHA  %s: %s != %s" % (row["path"], sha[:16], row["sha256"][:16]))
            failures += 1
        if z != row["zlib9"]:
            zlib_mismatch += 1
            print("ZLIB %s: %d != %d%s"
                  % (row["path"], z, row["zlib9"],
                     "" if args.strict_zlib else " (warning; use --strict-zlib to fail)"))
            if args.strict_zlib:
                failures += 1
        status[row.get("status", "unknown")] = status.get(row.get("status", "unknown"), 0) + 1

    # Shape invariants that must not drift silently.
    def raw(rel):
        return len(open(os.path.join(ROOT, rel), "rb").read())

    checks = [
        ("android two-phase pair equal length",
         raw("payloads/two_phase/detector.html") == raw("payloads/two_phase/final_inline.html")),
        ("ios15 pair equal length (ungated)",
         raw("payloads/two_phase/ios15/at_probe_h400.html") == raw("payloads/two_phase/ios15/at_final_h400.html")),
        ("ios15 pair equal length (gated)",
         raw("payloads/two_phase/ios15_gated/at_probe_h400.html") == raw("payloads/two_phase/ios15_gated/at_final_h400.html")),
        ("ios27 proven family keeps 8,647 B",
         all(raw("payloads/ios27_rel/p%d%s.html" % (i, s)) == 8647
             for i, s in [(0, "_proven"), (1, "_pad768"), (2, "_pad384"),
                          (3, "_n3000"), (4, "_n3000_pad768")])),
        ("ios27 gated final is 9,139 B",
         raw("payloads/two_phase/ios27_gated/final_ios27.html") == 9139),
        ("ios27 gated detector is 2,540 B",
         raw("payloads/two_phase/ios27_gated/detector_ios27.html") == 2540),
    ]
    for name, ok in checks:
        print("%-45s %s" % (name, "PASS" if ok else "FAIL"))
        if not ok:
            failures += 1

    final = open(os.path.join(ROOT, "payloads/two_phase/final_inline.html"), "rb").read()
    beta = b"org.telegram.messenger.beta/files/n1"
    release = b"org.telegram.messenger/files/n1"
    if release in final and beta not in final:
        print("NOTE  two-phase final_inline.html writes the release package path;")
        print("      the Sony beta run needs a 5-byte longer rebuild and is not shipped.")
    elif beta in final:
        print("FAIL  two-phase final_inline.html unexpectedly writes the beta path")
        failures += 1

    print("STATUS %s" % json.dumps(status, sort_keys=True))
    print("ZLIB   mismatches: %d (manifest zlib %s, runtime %s)"
          % (zlib_mismatch, data.get("zlib"), zlib.ZLIB_VERSION))
    print("RESULT: %s" % ("PASS" if failures == 0 else "FAIL (%d)" % failures))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
