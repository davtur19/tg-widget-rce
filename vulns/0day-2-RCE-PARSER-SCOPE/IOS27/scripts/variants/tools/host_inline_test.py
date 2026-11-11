#!/usr/bin/env python3
"""Host driver for an inline-ROP exploit HTML.

Extracts the stage-A <script> from the exploit, fakes document/localStorage, and
injects the stage B source (host twin or the real iOS one), then runs it under
the qjs017 app_multi harness.

Options:
  --stageb PATH     stage B source placed under n1s2 (default: host twin)
  --host            use the host inline variant as-is (no change; only affects
                    which file you pass)
  --strip-ub        remove the stage-A UB allocation block (negative control:
                    expect U_NOUB from the inline ROP)
  --pad RAW         pad the HTML to RAW bytes first (cosmetic on host)
  --out PATH        driver output (default /tmp/opencode/host_inline_driver.js)
"""
import argparse, json, os, re, sys

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('html')
    ap.add_argument('--stageb',default='/tmp/opencode/ios_chain_20261108/stage2_host_twin_fixed.js')
    ap.add_argument('--strip-ub',action='store_true')
    ap.add_argument('--pad',type=int,default=0)
    ap.add_argument('--out',default='/tmp/opencode/host_inline_driver.js')
    a=ap.parse_args()
    h=open(a.html).read()
    if a.pad:
        pad=a.pad-len(h)-len('\n<!--')-len('-->')
        assert pad>=0,(len(h),a.pad)
        h=h+'\n<!--'+'A'*pad+'-->'
    src=re.findall(r'<script>(.*?)</script>',h,re.S)[0]
    if a.strip_ub:
        i=src.find('var UB=new Uint8Array(2048)')
        j=src.find('globalThis.UB=UB;')
        assert i>0 and j>i, 'UB block not found'
        src=src[:i]+src[j+len('globalThis.UB=UB;'):]
    B=open(a.stageb).read()
    d=('var __v={textContent:""};\n'
       'globalThis.document={getElementById:function(id){if(id==="v")return __v;return null;}};\n'
       'globalThis.localStorage={getItem:function(k){return '+json.dumps(B)+';},setItem:function(k,v){}};\n'
       +src+'\nglobalThis.RESULT="DRIVER "+globalThis.RESULT+" V="+__v.textContent;\n')
    open(a.out,'w').write(d)
    print(a.out,len(d))

if __name__=='__main__':
    main()
