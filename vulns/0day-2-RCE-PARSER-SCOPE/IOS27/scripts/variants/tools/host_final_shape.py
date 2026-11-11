#!/usr/bin/env python3
"""Host driver for the final-shaped probe/final: document stub + stage A."""
import json, os, re, subprocess, sys
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE)
ROOT=os.path.dirname(os.path.dirname(LAB))
PAY=os.path.join(LAB,'payload')
B=open(os.path.join(ROOT,'lab','qjs_postsnapshot','ios_n1','payload','n1ios_stage2_ab72.js')).read()
TWIN=open('/tmp/opencode/ios_chain_20261108/stage2_host_twin_fixed.js').read()
assert len(TWIN)<=len(B)
TWIN_PAD=TWIN + '/*' + 'A'*(len(B)-len(TWIN)-4) + '*/'
assert len(TWIN_PAD)==len(B)
def stage_a(html):
    return re.findall(r'<script>(.*?)</script>', html, re.S)[0]
def driver(a, s2):
    return ('var __v={textContent:""};\n'
            'globalThis.document={getElementById:function(id){if(id==="v")return __v;if(id==="s2")return {textContent:'+json.dumps(s2)+'};return null;}};\n'
            + a + '\n'
            'globalThis.RESULT="DRIVER "+globalThis.RESULT+" V="+__v.textContent;\n')
def run(html, s2, label, n=3):
    a=stage_a(html); d=driver(a,s2)
    open('/tmp/opencode/fs_driver.js','w').write(d)
    out=[]
    for k in range(n):
        p=subprocess.run(['/tmp/opencode/qjs017/build/app_multi','/tmp/opencode/fs_driver.js'],capture_output=True,text=True,env={**os.environ,'QJS_HEAP_LIMIT':'8388608'})
        txt=p.stderr+p.stdout
        m=re.search(r'(HOLE C=34[^\n]*)',txt)
        hit=m.group(1) if m else 'NO_RESULT'
        ok='N1HOST_OK' in txt
        out.append((p.returncode,hit,ok))
    print(label, out[:3])
if __name__=='__main__':
    H=int(sys.argv[1]) if len(sys.argv)>1 else 400
    html=open(os.path.join(PAY,f'fs_final_h{H}.html')).read()
    run(html, '/*'+'A'*(len(B)-4)+'*/', f'H={H} inert')
    run(html, B, f'H={H} stageB')
    run(html, TWIN_PAD, f'H={H} twin')
