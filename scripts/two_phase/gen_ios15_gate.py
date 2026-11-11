#!/usr/bin/env python3
"""iOS 15 (6s) at_probe/at_final pair with the early desktop gate — host-only.

Both pages keep equal raw length (the gate+marker prefix/suffix is identical);
the proven at_* pair content is otherwise unchanged.
"""
import hashlib, os, re, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "ios15")
OUT = os.path.join(HERE, "ios15_gated")

GATE = ("var GD=1;var N=navigator,U=''+N.userAgent,C=(TelegramWidget&&TelegramWidget.contentSafeAreaInset)||{},"
        "S=(screen&&screen.width)||0;if(U.length<40&&U.indexOf('TelegramWidget')>=0&&"
        "typeof __twReceive=='undefined'&&typeof __hostOps=='undefined'&&typeof webkit=='undefined'&&S<=800&&"
        "((C.bottom||0)+(C.cornerLeft||0)+(C.cornerRight||0)>0||(devicePixelRatio||1)>=2))GD=0;")
DESK = "if(GD){try{var d=document.getElementById('v');if(d)d.textContent='DESKTOP OK'}catch(e){}}"
ENV_MOBILE = ('var navigator={userAgent:"Mozilla/5.0 TelegramWidget/1.0",platform:"TelegramWidget"};'
              'var screen={width:375,height:667};var devicePixelRatio=2;'
              'var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};')
ENV_DESKTOP = ('var navigator={userAgent:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
               'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",platform:"Win32"};'
               'var screen={width:1920,height:1080};var devicePixelRatio=1;'
               'var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};')


def gated(src):
    m = re.search(r'<script[^>]*>(.*?)</script>', src, re.S)
    body = m.group(1)
    nb = GATE + "if(!GD){" + body + "}" + DESK
    return src[:m.start(1)] + nb + src[m.end(1):]


def main():
    os.makedirs(OUT, exist_ok=True)
    out = {}
    for h in (64, 200, 400, 500):
        for kind in ("probe", "final"):
            f = "at_%s_h%d.html" % (kind, h)
            s = gated(open(os.path.join(SRC, f), encoding="utf-8").read())
            open(os.path.join(OUT, f), "w").write(s)
            out[f] = {"raw": len(s.encode()), "zlib9": len(zlib.compress(s.encode(), 9)),
                      "sha256": hashlib.sha256(s.encode()).hexdigest()}
    # host mocks for h400 (env script in front; host-only)
    for kind in ("probe", "final"):
        s = open(os.path.join(OUT, "at_%s_h400.html" % kind), encoding="utf-8").read()
        for tag, env in (("m", ENV_MOBILE), ("m_desk", ENV_DESKTOP)):
            p = s.replace('<script', '<script id="env0">' + env + '</script><script', 1)
            open(os.path.join(OUT, "%s_%s.html" % (tag, kind)), "w").write(p)
    import json
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
