#!/usr/bin/env python3
import json, sys
f=sys.argv[1]
t=open(f).read(); i=t.find('\n{'); b=json.loads(t[i:])
th=b['threads'][b['faultingThread']]
st=th.get('threadState',{})
xs=st.get('x',[])
def x(n): return xs[n]['value'] if len(xs)>n else None
print("time:", b.get('captureTime',''))
print("exc:", b['exception'].get('type'), b['exception'].get('signal'), b['exception'].get('subtype'))
print("thread:", th.get('name'))
print("frames:", [hex(fr['imageOffset']) for fr in th['frames'][:6] if fr.get('imageOffset') is not None])
if xs: print("x9=%s x10=%s x11=%s x12=%s" % (hex(x(9)), hex(x(10)), hex(x(11)), hex(x(12))))
print("vm:", " ".join((b.get('vmregioninfo') or '').split())[:400])
