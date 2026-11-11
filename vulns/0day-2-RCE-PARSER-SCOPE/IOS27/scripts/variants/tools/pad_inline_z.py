#!/usr/bin/env python3
"""Pad an inline HTML to TARGET_RAW bytes with a trailing comment whose body is
tuned so the zlib9 length equals TARGET_Z exactly.  The all-'A' body is the
most compressible; random bytes raise the compressed size, so TARGET_Z must be
>= the all-'A' value at that body length."""
import hashlib, random, sys, zlib

ALPHA='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def all_a(html, target_raw):
    ov=len('\n<!--')+len('-->')
    body_len=target_raw-len(html)-ov
    assert body_len>=0,(len(html),target_raw)
    d=html+'\n<!--'+'A'*body_len+'-->'
    return d, len(zlib.compress(d.encode(),9)), body_len

def pad_to_z(html, target_raw, target_z, tries=600):
    d0,z0,body_len=all_a(html,target_raw)
    if z0==target_z: return d0,z0
    if z0>target_z: return None,z0   # cannot go below the all-A minimum
    best=None
    for r in range(1,min(body_len,64)+1):
        for sd in range(0,tries):
            rng=random.Random((sd*2654435761+r*1315423911)&0xffffffff)
            body=''.join(rng.choice(ALPHA) for _ in range(r))+'A'*(body_len-r)
            d=html+'\n<!--'+body+'-->'
            z=len(zlib.compress(d.encode(),9))
            if best is None or abs(z-target_z)<abs(best[0]-target_z): best=(z,d,r,sd)
            if z==target_z: return d,z
    return None,best

if __name__=='__main__':
    src,out,raw,z=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4])
    h=open(src).read()
    d,info=pad_to_z(h,raw,z)
    if d is None:
        print('FAIL target',z,'got',info if isinstance(info,int) else info[0]); sys.exit(1)
    open(out,'w').write(d)
    print(out,'raw',len(d),'zlib9',len(zlib.compress(d.encode(),9)),
          'sha',hashlib.sha256(d.encode()).hexdigest())
