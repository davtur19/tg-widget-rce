#!/usr/bin/env python3
"""Build the new seed row at 3,969 uncompressed / exactly 1,888 zlib9,
storing the real 3,617-byte stage B under n1s2.  A minified wrapper plus an
incompressible HTML comment tunes the compressed length to the inline's."""
import hashlib, json, os, random, sys, zlib
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE); PAY=os.path.join(LAB,'payload')
B=open(os.path.join(LAB,'..','qjs_postsnapshot','ios_n1','payload','n1ios_stage2_ab72.js')).read()
LIT=json.dumps(B)
base=('<div id="v">N1IOS_SEED_INLINE</div><script>try{var B='+LIT+
      ';localStorage.setItem("n1s2",B);document.getElementById("v").textContent="SEED OK "+B.length}'
      'catch(e){document.getElementById("v").textContent="SEED ERR "+e}</script>')
TARGET=3969; TARGET_Z=1888
ov=len('\n<!--')+len('-->')
body_len=TARGET-len(base)-ov
print('stageB',len(B),'literal',len(LIT),'base',len(base),'comment_body',body_len)
assert body_len>=0
alpha='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
def build(body):
    return base+'\n<!--'+body+'-->'
def zlen(body): return len(zlib.compress(build(body).encode(),9))
found=None
for r in range(0,body_len+1):
    for seed in range(0,3):
        rng=random.Random(seed*1315423911+r)
        body=''.join(rng.choice(alpha) for _ in range(r))+'A'*(body_len-r)
        z=zlen(body)
        if found is None or abs(z-TARGET_Z)<abs(found[0]-TARGET_Z): found=(z,r,seed,body)
        if z==TARGET_Z:
            print('FOUND r',r,'seed',seed,'z',z); found=(z,r,seed,body); break
    if found and found[0]==TARGET_Z: break
if not found or found[0]!=TARGET_Z:
    print('no exact; best',found[0] if found else None,'target',TARGET_Z)
    for r in range(body_len,-1,-1):
        for seed in range(0,200):
            rng=random.Random(seed*2654435761+r)
            body=''.join(rng.choice(alpha) for _ in range(r))+'A'*(body_len-r)
            if zlen(body)==TARGET_Z:
                found=(TARGET_Z,r,seed,body); print('FOUND2',r,seed); break
        if found and found[0]==TARGET_Z: break
assert found and found[0]==TARGET_Z, 'cannot tune seed'
h=build(found[3]); open(os.path.join(PAY,'ls_seed_inline_1888.html'),'w').write(h)
print('seed raw',len(h),'zlib9',len(zlib.compress(h.encode(),9)),'sha',hashlib.sha256(h.encode()).hexdigest())
