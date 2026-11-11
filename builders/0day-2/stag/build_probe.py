#!/usr/bin/env python3
"""Build the 72801 route-2 stage-A probe byte-identically.

The probe is the terser-minified stage-A source plus a fixed 177-byte stage-C
reporter padded to 408 bytes, wrapped in a two-script HTML page.

Usage:
  python3 build_probe.py --check
  python3 build_probe.py --out /tmp/probe.html
"""
import argparse
import hashlib
import os
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
PAY = os.environ.get("STAG_PAYLOAD_DIR", os.path.join(
    HERE, "..", "..", "..", "vulns", "0day-2-RCE-PARSER-SCOPE", "STAG", "payloads"))
STAGE_A = os.path.join(PAY, "route2", "src", "stage-a-device-72801.js")
CANONICAL = os.path.join(PAY, "route2", "stage-a-probe-72801.html")
PIN = "a534a8725b8a1a07efacf7a5c8108ab5c31488d4b0e2e1bc7558d548a7f39412"

STAGE_C = ('if(1){try{var m=typeof mark!="undefined"?mark:"-",'
           'e=typeof MEGA!="undefined"?MEGA:"-";var x="S1 "+m+" END="+e;'
           'var D=document.getElementById("v");D&&(D.textContent=x)}catch(r){}}')


def pad(s, n):
    d = n - len(s)
    if d < 0:
        raise SystemExit("stage C is longer than %d" % n)
    if d == 0:
        return s
    if d < 4:
        return s + " " * d
    return s + "/*" + "P" * (d - 4) + "*/"


def build():
    src = open(STAGE_A, encoding="utf-8").read()
    r = subprocess.run(["terser", "-c", "passes=2", "-m", "--", "/dev/stdin"],
                       input=src, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("terser failed: %s" % r.stderr[:400])
    a = r.stdout.strip()
    c = pad(STAGE_C, 408)
    return ('<!doctype html><body><div id="v">Ok</div>'
            '<script id="stageA">' + a + '</script>'
            '<script id="stageC">' + c + '</script>')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    html = build()
    sha = hashlib.sha256(html.encode()).hexdigest()
    raw, z = len(html.encode()), len(zlib.compress(html.encode(), 9))
    print("raw=%d zlib9=%d sha256=%s" % (raw, z, sha))
    if a.check:
        ok = sha == PIN
        print("RESULT:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    if a.out:
        open(a.out, "w", encoding="utf-8").write(html)
        print("written", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
