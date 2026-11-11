#!/usr/bin/env python3
"""Conservative JS minifier: strip /* */ and // comments, collapse whitespace
outside strings.  Keeps string literals byte-identical."""
import sys
def minify(s):
    out=[]; i=0; n=len(s); instr=None
    while i<n:
        c=s[i]
        if instr:
            out.append(c)
            if c=='\\' and i+1<n:
                out.append(s[i+1]); i+=2; continue
            if c==instr: instr=None
            i+=1; continue
        if c in ('"',"'",'`'):
            instr=c; out.append(c); i+=1; continue
        if c=='/' and i+1<n and s[i+1]=='*':
            j=s.find('*/',i+2); i=n if j<0 else j+2; continue
        if c=='/' and i+1<n and s[i+1]=='/':
            j=s.find('\n',i+2); i=n if j<0 else j+1; continue
        if c in ' \t\r\n':
            j=i
            while j<n and s[j] in ' \t\r\n': j+=1
            prev=out[-1] if out else ''
            nxt=s[j] if j<n else ''
            if prev and nxt and (prev.isalnum() or prev in '_$') and (nxt.isalnum() or nxt in '_$'):
                out.append(' ')
            i=j; continue
        out.append(c); i+=1
    return ''.join(out)
if __name__=='__main__':
    src=sys.argv[1]; dst=sys.argv[2]
    s=open(src).read(); m=minify(s); open(dst,'w').write(m)
    print(src,len(s),'->',dst,len(m))
