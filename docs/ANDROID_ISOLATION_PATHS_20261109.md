# Android 73029 — isolation-escape paths (2026-11-09)

Status: **app-process M3 marker is harness-driven; no-G1 and C5/C6 are
closed negatives; G1 is the only route. The F4 front is **closed**: the
device SIGSYS is a Scudo 1 MiB reuse memory-safety crash, not stack/seccomp;
the parser leak-S/CALA is the route. The parser-only direct-call is
host 10/10 but the 64-bit leak is missing; the **text-cap logcat channel is
host-proven** and the leak/shaping pages are ready (the natural `0x110` pair
is refuted; **the live leak runner is a negative — all 294913/294912
diagnostics, no 64-bit hit**; the F4 `g1_diag` is a live negative (engine
dies before the validator); **the CALA Android port is host 5/5 and the
arm64 leak-S is found** (`S=bits+0x3F0`; CALA anchor-complete in one session;
`leak_s` pages 11/11); the **leak-S live**: all chunks hit, high 32 stable
`0x74`, low 32 varies (S must be self-computed), cleanup done, current
delivery **@<BOT_USERNAME> → <TG_USERNAME>**; the combined leak-S+CALA page next; the
**stock fork-tree trigger/endgame is host-ready** (page 14,285/2,467) with
G-B (real BpBinder), G-D app addresses and W2 timing still missing; the **final
stealth page/harness is host-ready/inert** (1,700/678; gaps G1–G7); the
**stock integrator is host-ready** (S0–S8; 8,687/3,756 + 7,540/3,339;
G-B confirmed, mHandle +0x10; **real BpBinder next**); the Binder
vehicle is host-proven but the clone(220) is
**W1-unschedulable**; the **fork tree bypasses W1/W2** (host-proven; the
children survive and transact), and the **one fatal gate is the 64-bit
disclosure**; maps P1/endgame give the Frida-forced app-side arbitrary read
and a clean `system()` session path (live `MAPS_PC_OK` + session files with
hashes) — **debug only, no final credit** — but the **stock maps trigger and
64-bit app leak are blocked**; no deterministic app-process escape yet.**
This page collects the post-M3 path work; the M3 run details are in
`ANDROID_M3_STOCK_20261109.md`.

## M3 — the app-process marker (harness-driven)

- `W2_DEFINEIMAGE_OK` as UID 10346, app survived: 477.3 s, 3,313 cycles,
  159,040 sprays, 0 errors, `reclaim 5,341/6,603 (81 %)`, `systemCalls 1`.
- Config: CPU7 injector-free (`inj-count 7`), arm CPU6, `gdelay 6.731 ms`,
  `win 7.5 ms`, single-reused-Parcel spray.
- **Session stealer: 0/2 dedicated runs** — the race did not hit; the marker
  run remains 1/1 at 477 s. The chain is race-based, not deterministic.
- **Not a stock page**: a stock widget page cannot express the trigger — no
  `record`/`transact` API, no threads/affinity/nice/timerslack, no truncated
  kamikaze DLs, no raw premul image bytes, and the blob needs per-boot code
  pointers. The 5-attempt stock carrier (`stock_m3_session_20261109/`) is a
  negative control; the stock Android final needs G1 (native code in
  `:widgets`).

## C1 — shader phase only

- Setter map verified on the device binary: `setMaskFilter 0x34e4a8 (+0x10)`,
  `setPathEffect 0x34e50c (+0x00)`, `setShader 0x34e570 (+0x08)`,
  `setBlender 0x34e8ec (+0x28)`. The earlier path-effect/mask-filter C1
  negative is **withdrawn** — it hooked `setBlender`.
- Shader phase (op 6 install / op 2 clear): 3.19–5.06 M `setShader`, **0 live
  double-reads** (every counted pair had `old = NULL`; the install is
  deferred under the Paint monitor).
- The 20k/80k pe payloads were 2.24–2.28 MB, above the ~1 MB Binder limit;
  the regenerated **`dl_c1_pe_install_2k_proven.bin`** (256,024 B, sha
  `1ff28e0f…`) is 2,000× the 152-B `dl_c1_pe_probe_install_proven.bin`
  (`9fc1e053…`), which is **byte-identical to the device-proven
  `dl_w1_race_7pt_dash.bin`**. The real setter is `setPathEffect
  0x34e50c`; the pe run must use it.

## C3 — cached `SkBlurMaskFilterImpl` in `z0.m`

- Op 14 (shadow) is path-free and uses the **same cached**
  `SkBlurMaskFilterImpl` (24 B, class 0x30) for every op; two overlapping
  records both load the same non-null `old` and the unguarded `setMaskFilter`
  `ldr old; str new; unref old` at `0x34e4a8` double-unrefs 2→0, freeing the
  filter while `z0.m` still holds it; later ops re-install the dangling
  pointer (persistent, unlike C1).
- Oracle: Phase 0 `setMaskFilter 112,250`, `install 56,004 / clear 56,246`,
  `distinctNew 1`, **`doubleRead 9,383`**; Phase 1 `doubleRead 45,552`,
  `unrefTo0 0`, `installFreed 0`, `uaf.* 0`; the app crashed at 37 s in
  `SkPathPriv::IsRectContour ← SkCanvas::clipPath ← Canvas.clipOutPath ←
  z0.d+4316`.
- Device-dex truth: `0x030E` (op 14, flags `0x03` = s+rect, 8×4.0 radii,
  flag 0) reaches **`0x69c clipOutRect` + `0x6de drawRoundRect`**. A
  flags-bit-clear “non-rounded” variant **cannot** reach `0x69c` in this
  `z0.d`: `s=0` → `v23=0` → `0x6b4 z0.k` + `clipOutPath`; the rect branch
  requires `s=1`, uniform positive radii and `flag=0`.
- The p0a `branch.path=100` was an **oracle artifact**: the Java
  `Canvas.clipOutRect(RectF)` wrapper can be inlined by ART (the hook never
  fires), the Java counters were global/engine (`clipPath=102` is not our
  op 14), and 100/100 is too systematic for the shared-`z0.s` race (the 72
  extra clears show the engine active, not a 100 % duty in every window).
- **Oracle v3 (native, per-thread)**: hooks
  `android::SkiaCanvas::clipRect` `B+0x25e6dc` and `clipPath` `B+0x25e9dc`;
  the `WSB.record` fingerprint (`dl` length + first body u32 at offset 20)
  attributes our record threads. Gate:
  **`branch.nativeRect==100 && branch.nativePath==0`**. A `javaRect=0`
  with `nativeRect=100` is the inlining artifact, not a failure. Probe
  matrix: `0x030E` primary; `0x010E`/`0x050E`/`0x070E` controls;
  `0x010E+r8` live-dex check; `verify_z0_dl.py` prints the prediction.
- If the native gate still shows `nativePath=100` on the `s=1` probes, the
  exact wall is the engine’s own `z0.s=false` write in the window
  `0xbc→0x5f8` (prologue → mask-filter install). No payload byte can make
  PC `0x5fe` atomic; the rect branch then needs a quiesced/blocked engine or
  a session not shared with the engine. A flipped op is harmless when the
  engine is quiet; the second `z0.f` writer is the crash.
- Run p0a (`dl_z0_mf_100.bin` 0x030E primary; `_rect`/`_t`/`_rect_t`/
  `_rect_r8` controls) with `z0_run.py --phase p0a --probe`; then p0b/p1
  with `dl_z0_mf_2k_v2.bin` (152,024 B, sha `947f84c3…`) / `2k_rect` on a
  quiet session; a third record tid during p1 is the engine — stop.
- p1-rect (180 s): 352 k installs, `distinctNew 1`, **`free.dtor 0`,
  `installFreed 0`, `uaf.* 0`**; the v3 per-thread branch counters stayed 0
  in the runner path because `setOurDl` is only called by the host driver —
  a runner hook is needed before the filter under-count can be attributed.
  The C3 filter under-count was not reached in this window.
- Endgame: class 0x30 (32 B usable) cannot hold the M3 dispatcher command at
  `+0x30`/`&system` at `+0x68`; the small gadget `0x6e64d0`
  (`ldr x8,[x0,#0x10]; ldr x0,[x0,#0x18]; blr x8`) has no table reference in
  libhwui. The UAF proof is deliverable; the RCE needs a gadget/leak/larger
  victim.

## C4 — `z0.b` fPathEffect slot, `SkDashImpl` (new)

- The `z0` native surface is exactly **9 objects**: 4 `SkPaint` (80 B,
  class 0x60: `a/b/c/d`) + 3 `SkPath`→`SkPathRef` (120 B, class 0x90:
  `e/f/g`), plus two session caches (`z0.m` blur filters, `z0.n` Paint
  clones). The painter is a `private final` field of
  `WidgetSandboxBackend`, constructed once by the `i1` session and shared by
  every `o0` binder thread. 34 setter annotations are verified against the
  bytecode (`z0_fields/tools/setter_matrix.py`).
- **Op 1/3 and op 11 use the shared `z0.b` fPathEffect slot**; op 11 does
  three setters per op (clear/install/clear) **only if the stroke block is
  entered**. The setter `Paint.setPathEffect` **`0x34e50c`** is unguarded —
  every call executes `ldr old; str new; unref`; unlike C1's shader install
  (inside the synchronized `getNativeInstance()`) the non-null install races
  too.
- **Root cause of the earlier zero attribution (2026-11-09):** `z0.d` op-11
  is gated by
  `stroke_bit && ((colour>>>24)==0 || strokeShaderKind!=0) && width>0`.
  Both the device-proven W2 op (`0xFF000000`, opaque, no stroke shader) and
  the first C4 op (`0xFF102030`, no stroke shader) take `jump :cond_60b`,
  so the whole stroke block — `DashPathEffect`, `setPathEffect`, `drawPath`
  — is skipped. The W2 proof only exercised `z0.i` (before the gate); its
  "proven dash" never called the setter. The same gate explains the
  `dl_c1_pe_*` gap. A second silent path: the 240-record/s ring returns
  `REC_OK` without work; v2 measures `acceptedOurs/gateRejectedOurs`.
- Corrected payload families (host-verified, `strokeBlock=YES`):
  **A** `dl_pe_c40*` alpha 0 (`0x00102030`) passes the alpha arm but the RT
  culls it (`nothingToDraw`); **B** `dl_pe_c40sh*`/`dl_pe_ctrl*` uses
  `0xFF102030` + a 3-stop linear stroke shader, passes the shader arm and is
  RT-visible. `dl_pe_ctrl_1.bin` is the corrected 1-op control with the
  7-pt/2-dash geometry. Reader bug fixed in `tools/reader_z0f.py` (the
  stroke shader blob had an extra `kind` int).
- **Oracle v2** (`frida/z0_pe_oracle_v2.js`) attributes at paint
  (`z0.a/b/d` native pointer via `getNativeInstance`), window (`z0.e`/`z0.d`
  DL fingerprint depth flag) and Java (`Paint.setPathEffect` identity,
  `DashPathEffect.$init` native instance) levels; refcount events are
  restricted to attributed setters. `frida/iso_recordn.js` now registers a
  unique class name per load (second attach failed) and has `recordOnce`.
  Hard control gate (`tools/check_control.py`):
  `rec.acceptedOurs=1`, `dl.dOurs=1`, `dl.pathBuildsOurs=1`, `pe.ours=3`,
  `pe.installOurs=1`, `pe.clearOurs=2`, `dash.makeDuringDraw=1`,
  `ctx.setMaskFilterOurs=0`; soft `java.pe.ours=3`,
  `java.ctor.duringDraw=1`. `pe_run.py p0` writes `out/control_stats.json`
  and aborts on `DRIVER_ERROR`.
- The old device p0 (`dl_pe_c40_1.bin`, 176 B) showed `rec.record=1`,
  `ours=true`, `ms≈1` but `pe.install=0`, `clear=108`, `ctx.makeDash=0`; the
  108 clears / 54 mask filters were the engine's own ops. The proven
  control also showed 0 with the old oracle — that is the gate root cause
  above, not a C4 payload verdict.
- **Corrected p0 (2026-11-09): the payload reaches the stroke block.**
  `dl_pe_ctrl_1.bin` (208 B): `rec.acceptedOurs=1`, global `pe.install=1`,
  `dash.make=1`; a `DashPathEffect` **is** created. The `check_control`
  FAIL is **attribution**, not payload: `paint.resolved=3, nptrs=0`,
  `dl.dOurs=0`, `pe.ours=0`, `dash.makeDuringDraw=0`. The shipped oracle v2
  still carries the Frida-17 `'D'/'F'` overload and `iso_recordn.js` still
  hits `Java.registerClass`; the live run used `r1_driver.js`. Host fix in
  progress: resolve real `z0.a/b/d` native pointers and match the exact DL
  object identity. p1/p2/p3 remain blocked until the control PASSes.
- **Oracle v2.1 host-validated (2026-11-09).** Two causes fixed: Frida
  resolves `z.a` to the method, not the field (use
  `getDeclaredField('a'|'b'|'d').get(z)`); and
  `Paint.getNativeInstance()` is hidden-API gated (read private
  `mNativePaint` via JNI/reflection). DL attribution now has four paths
  (`byRec`, `byI`, `byBytes`, `byContent`); the record overload tries the
  `'[B','[B','double','int','int','float','float','int','int'` form first
  with a `'D'/'I'/'F'` fallback; `iso_recordn.js` has a direct two-way
  `recordOnce` (no Java worker) and unique class names. `check_control.py
  --selftest` embeds the live pre-fix counters and asserts the post-fix
  set PASSes. Next p0 expected: `paintAttr=3`, `ours=3`, `dOurs=1`,
  `byRec=1`, `nptrs≥1`; p1 only after that.
- Victim **`SkDashImpl`, Scudo class 0x40** (usable 48 B), vtable
  `0x80ac58`, `onFilterPath` slot 7 `0x3d0f70`, dispatch at
  `SkPathEffect::filterPath 0x359ad4`. Two outcomes: (a) two-load
  double-unref → the **wrapper survives** and its finalizer re-unrefs → a
  deterministic `-1` write at `freed+8`; (b) three-load dispatch UAF in
  `SkDashImpl::onFilterPath`.
- C4 is weaker than C3 per burst (no map holder; model ≈0.5× C3) but has
  more setter density and a different class. New class-0x40 spray geometry:
  a 12-interval dash array (48 B, controlled) and a 5-point path points array
  (SkTDArray reserve 6 slots = 48 B, controlled), both allocated before the
  dash object; `dl_pe_c40_41_2k.bin` writes `0x41414141` into their first 8
  bytes → a controlled reclaim gives vptr `0x4141414141414141` (leak-free
  controlled-crash proof; execution still needs a leak).
- Harness: `z0_fields/tools/pe_run.py` (p0/p0b control; p1 two threads ×
  the corrected family-B 2k; p2 trio; p3 tombstone), oracle v2,
  `check_control.py`, `path_model.py` (28 anchors). Gate p0: the hard
  control above; p1 hit = any of `doubleReadRc2`/`rc0`/`tripleReadRc2` > 0.
  Do not run p3 (deliberate crash) until p1 hits and the crash proof is
  scheduled.
- Negatives closed in the same static pass: `SkImage`/bitmap (op 5),
  text/`SkTypeface`/`SkTextBlob` (op 4 clone is a Java no-op), text effects,
  clip (`clipOutRect` canvas-local; `clipPath(z0.f)` = W2), RenderNode/effect
  (op 17 per-op), op 15 layer (per-record), `z0.n` clones, deviceFont paints,
  Java maps (DoS only). `h` painter mirrors are the wordcode agent's scope.

## Fast W2 — 2–13 s trigger, double-unref/steal

- Paired records with 2k-gradient DLs crash in **2–13 s** in the shared
  `z0.e` path code — ~50× faster than the M3 for the same corruption.
- The dynamic-P hook works (`R1DYN_PATCH`/`R1P14_PATCH`); the peer16
  controlled reclaim is blocked by the app-side **record prologue jitter
  (1–3 ms)** vs the ~100 ns window (all-peer16: 180 s, 15,960 shared, no
  collision).
- peer14: the null `SkPath::moveTo` is the **steal** — both threads allocate
  a new 120 B pathref after the free, one takes P, and the DL later frees it
  while `z0.e` still points there. The new oracle distinguishes
  `RECLAIM_MATCH` (peer points array at P) vs `STEAL` (new pathref at P); the
  pre9 `publishWaitMs` keeps the frame alive. The stock pathref still needs
  P/leak.

## Leak2 — raw-premultiplied canvas bypass

- No non-premultiplied canvas exists: `canvasRun` hardcodes ARGB_8888
  premultiplied; op-6 `setPixels` premultiplies and zeroes the raw
  `0x00000001`.
- A **premultiplied ARGB_8888 image with raw invalid bytes** delivered by
  `defineImage` (createBitmap + copyPixelsFromBuffer) drawn source-over on a
  zero destination preserves the raw word (`dst = src + dst*(1-a) = src`).
- `canvasRead`'s unpremultiply is invertible for valid-premul pointer words
  (`B,G,R < A`); `0xb4000075e4e2cad0` is recovered exactly. The earlier
  "read cannot transport a pointer" came from invalid-premul op-6 pixels.
- The previous S0–S5 negative also used a **fixed canvas id**; `canvasRun`
  reuses the same-size bitmap, so a **fresh canvas id per attempt** is
  mandatory.
- Root cause: the **canvas wordcode** (transact 10 → `h.g`/`h.c`, kind 5)
  and the **DL wordcode** (transact 6 → `z0.d`, `(flags<<8)|kind`) were
  mixed. `canvasRun` kind 5 needs **23 words** (image id = word[13]); `0x105`
  is a **DL** op word (kind 5 + preamble bit 8). The DL image records into
  the RenderNode and **never touches `canvases[cid].o`**, so the leak page
  must use **transact 10**.
  Exact layouts: canvas kind 5 = kind, clips, evenodd, matrix 6, alpha,
  composite, hasShadow, canvas, image, src 4, dst 4, smoothing; canvas kind
  6 = 6, dx,dy,w,h,byteLen,pixels; DL kind 5 = 0x105, dx,dy,dw,dh, canvas,
  image; DL kind 11 flags&2 = hasPath, path, paintFlags, cap,
  strokeShaderKind, width, color, join, miter, dashCount, dashes…, phase.
- Live stages: **S1** defineImage 1×1 `03 02 01 FF` + canvasRun(newCid,
  30,1,[op5 word13=id]) + canvasRead → word0 `0xFF030201`, rest 0; **S2**
  raw `01 00 00 00` + same op → reply 0, the `SkConvertPixels` hook
  (`libhwui+0x2f6af8`) must show `a[1].readU32() == 1`; **S3** raw
  `0x40000001` → reply `0x40040000` (the premul-store control gives
  `0x40000000`). Payloads: `canvas_op5_image_1x1.bin` (92 B,
  `c5b2bd2b…`), `canvas_op5_image_1x1_4x4.bin`, `canvas_op6_putimage_raw1`,
  `dl_op5_image_1x1.bin` (52 B, `89bff5f8…`), harness
  `poc/leak2_smoke_v2.js`.
- **Device result (2026-11-09): S3 matches — the raw-blit store bypass is
  live.** S1 opaque `0xFF010203` via canvas op5 (23 words) → `0xFF010203`,
  rest 0 (path works; the script's `0xFF030201` is a packing-convention
  mismatch). S2 raw `0x00000001` → 0 by design. S3 raw `0x40000001` via the
  image blit → **`0x40000004`** (A=0x40, B=4 = `round(1·255/64)`); the same
  bytes via `PutImage` (stock premul store) → **0**. The blit preserves the
  invalid premul word; the stock store collapses it. This is the dtor-safe
  **`[P]=1` writer**.
- Next: the fresh-canvas **S0–S5 leak** (transact 10, fresh canvas id per
  attempt, the raw-blit for `[P]=1`, `0x40000001`-style words for the A/P
  read). The S2 `SkConvertPixels` hook still needs the info-offset fix; S3
  proves the semantics hook-free.
- **S0–S5 page delivered (2026-11-09)**: `leak2/poc/leak2_s0_s5.js`
  (isolated `:widgets` runner `start/stats/stop`, `cycle`, `s0..s5`,
  `configure`, `trigger`) + app gate printer `leak2_s0_s5_app_gates.js`;
  host **29 PASS/0 FAIL**, payload builders byte-identical to
  `gen_rt_uaf_v2`, op5 sha `c5b2bd2b…`, read inverse equals
  `canvas_ops.invert_read` for 65,536 words, CModule pthread smoke. Sequence:
  S0 op11 1-pt → P rc=2; S1 two CModule peers truncated 6-pt rewind (both
  `z0.i` hit P; 1→0 free; no `i1.b`); S2 15 fresh `canvasRun(cid,30,1,
  [op5])` + raw 1×1 `[P]=1` via `defineImage`; S3 R2 9-pt complete draw
  destroys R0's pending DL → `~SkPathRef(P)`; S4 R3 9-pt truncated rewind
  Q=P + `resetToSize(9)` → A; S5 `canvasRead` ×30 inverse. Gates G1–G5
  (`RT_REFREWIND`, `LEAK_GATE_S2/S3_DTOR/S4_NEWP`, `LEAK_S5_HIT`), G6/G7
  opt-in only. Unknowns: binder TSD routing, S3 pending-frame ~2–4 ms
  window, `canvasRead` cannot show `+0x24`/`+0x48` (match pointer words),
  A low word ~1/12 (`full=0` retry). Debug `:widgets` CModule, not the stock
  final; live run queued behind the stock S2/C4/maps.

## Decoder topology

Widget image decoding runs in **`:widgets` (UID 99084)**, not the app; the
app never decodes widget bytes. libwebp 1.2.4 and the PNG-inflate no-cap are
isolated-process code exec/DoS; app-side `Bitmap_createFromParcel` is safe;
`RenderNode`/`ImageReader` has no deterministic UAF. The app-process escape
is still the W2/M3 surface.

## Maps — canvas bitmap UAF (class 0xB0, new)

- The canvas maps are **not** JVM-only DoS. The canvas working bitmap has a
  native lifetime defect: `canvasRelease`/`canvasRun`-resize recycle the Java
  wrapper and drop `h.q`; `Bitmap.recycle()` only resets the wrapper's `sp`,
  so the `Canvas`'s native `SkBitmap` was the last real reference. The
  `NativeAllocationRegistry` cleaner then deletes the `SkiaCanvas`, unrefs the
  `android::Bitmap` (`operator new(0xa0)`) to zero and **frees it** (device
  `~Bitmap` `0x240e18`/`0x240f50`).
- **Use window**: `Bitmap_getPixels` loads the wrapper pointer once
  (`0x20fb28`, `cbz 0x20fb2c`) then calls `android::Bitmap::getSkBitmap`
  (`0x2410f8`), which reads `+0x70/+0x58/+0x20` and only takes its `ref` at
  `0x241158`. A reader paused in that band (`cbz → ref`, ~20 instructions)
  after the wrapper reset uses freed memory. The known `assertValid` abort is
  the same race with the reset before the `cbz`.
- **Reclaim**: the freed 0xA0 object is Scudo class **0xB0** (176-B block,
  160 usable). `defineImage` with an **IN_PLACE** blob allocates the pixel
  buffer with `calloc(160)` + `memcpy` of attacker bytes (512-B blob so the
  reader's temp is class 0x250, not the victim). The fake `SkPixelRef`
  (`+0x18 fPixels`, `+0x20 fRowBytes`, `+0x58 mInfo`, `+0x70 storage`) gives
  **arbitrary read** — `fPixels` → `SkPixmap::readPixels` → `canvasRead`
  reply — and **PC control** — the out-bitmap `unref` calls
  `sk_sp<SkPixelRef>::~sk_sp` (`0x2c31c4`), i.e. `[[fake]+0x10](fake)`;
  `internal_dispose` uses `+0x8`. A poisoned vtable faults at `0x41414151`.
- **Determinism**: `maps_hunt/frida/app_maps_uaf_proof.js` forces the whole
  chain (pause in `getSkBitmap`, release, run `Canvas.mFinalizer`, verify
  `~Bitmap`, reclaim the 0xB0 chunk, write fake, resume): P0 assert, P1 UAF
  + exact read match, P2 vtable marker/poison. The real chain needs a
  W2-style targeted hold + GC pressure + spray (S2 schedule); it is
  **post-isolation-RCE** (parser 0day → CModule), not a pure-JS app trigger.
- **Rev B harness host-validated (2026-11-09).** The first live P0 crashed
  in the Frida/ART bridge (`Java.performNow(canvasRelease)` inside the
  native `getPixels` hook), not at the bitmap assert. Rev B uses a native
  parking worker (`maps_p1_worker.c`, CModule pthread, raw JNIEnv): mode 0
  `canvasRelease`, mode 1 pre-read `canvases → h.q → Canvas.mFinalizer`,
  release, `mFinalizer.run()`, `malloc(160)` until `self` (same TSD, class
  0xB0), copy fake, patch `*(self+0x18)=self`; the JS hooks only park/poll
  and contain **no `Java.*`** in the hook region. Lazy module/`buildId`,
  exports survive init failure, `NewGlobalRef(Canvas)` before the manual
  finalizer, generation handshake, P2 disabled. Host loopback PASS. Live
  next: P0 → P1 only, restart the app between phases; P1 gate
  `{freed:true, reclaims>0, match:true}` with `held == self`.
- **Live P0 PASS (2026-11-10):** real `Bitmap_getPixels+412` assert, no
  ART/Frida bridge. **P1 not reached**: a harness `TypeError` in the `uaf`
  branch before any Java call; the later death was the CModule-unload
  artifact, not the primitive. P0 proves the app-side UAF path. **P1 harness
  fixed (rev C):** the target Frida runtime lacks
  `DataView.setBigUint64`/`getBigUint64`; the fake object and `buildId` are
  now BigInt-free, `dispose()` stops the worker before detach, P2 disabled;
  host loopback **PASS 9** `{len:128, match:true, freed:true, reclaims:1,
  held==self, workerOk, workerDone}`. Live P1 retry now.
- **Live P1 PASS (2026-11-10):** `[MAPS] PARK/RESUME uaf` →
  `{ok:true,len:128,match:true,matchMode:"swapBR",freed:true,reclaims:1,
  held==self=0xb4000075f4f790e0,workerOk:true,workerDone:true,bmpFrees:0}`,
  `dispose` clean; app 4509 / `:widgets` 4708 alive; BuildId
  `056e592fad8f6c3d4d7473d4d511e078` matches. Four live runtime fixes:
  `Memory.writeByteArray/readByteArray` absent → NativePointer;
  `wr64` `parseInt` >2^53 rounding → split exact hi/lo; `getSkBitmap`
  `ref()` increments the fake refcount → `swapBR`; Frida 17
  `PathClassLoader`/`Module` shim and Java replacements/`~Bitmap` observer
  disabled. P2 not run. **The app-side arbitrary read is device-proven
  (Frida-forced); the stock vehicle is still the `:widgets`
  parser-only/Binder clone.**
- **Maps endgame (host-proven, Frida-forced):** `readAt` reads **64 KiB per
  UAF**; `mapRanges` parses `/proc/self/maps`; a bounded `scan` walks
  `r`-mapped regions for `tgnet_v5`, `userconf`, `saved_tokens`/
  `login_tokens`, `tokens/json_tokens`, `authkey` and the session file names.
  Clean PC control: `sk_sp<SkPixelRef>::~sk_sp` (`libhwui+0x2c31c4`) →
  `[[fake]+0x10](fake)` with vptr `self+0x80` → `libhwui+0x6e64c0`
  (`Execute` **entry**, not body `0x6e64d0`) → `[fake+0x10]=&system`,
  `[fake+0x18]=command`; the gadget returns through the dtor into
  `Bitmap_getPixels`, **app survives, no UI, no poison**. Exact app map
  `0x703da00000`, runtime gadget `0x703e0e64c0`, dtor `0x703dcc31c4`;
  `verify_endgame.py` ALL PASS; live sequence after the flood
  (`readAt` → `scan` → `pc` marker → `pc` session LAN → `dispose`).
  **Still stock:** the trigger and a 64-bit app leak; the Frida worker
  patches `self`, a stock `defineImage` reclaim cannot. The endgame is the
  app-side read/PC primitive, not the final stock chain.
- **Live endgame (2026-11-10):** the app-side `pc` marker **`MAPS_PC_OK`**
  (`systemRc:1`) and the LAN session command returned the **session files
  with hashes**; the bounded scan found 34 JS-string hits; app alive. This
  is the **Android app-side session read, Frida-forced** — **debug only**.
  Session files: `tgnet.dat` 5,960/`44d26983…`, `cache4.db`
  10,629,120/`e2e75cfb…`, `userconfing.xml` 5,550/`db0c052d…`; scan 34
  JS-string hits; **maps Frida work stopped**; the stock trigger and 64-bit
  leak remain the gates.
- **Frida-forced = debug only; not accepted for the final session claim.**
  The maps P1/endgame session files are a reference for the app-side
  `Execute`/`system`; the final Android proof must be the **stock** chain
  (parser 0day → 64-bit leak → fork tree → Binder 11/12 → app-side maps UAF
  → the same endgame), with no Frida/root, delivered by the bot. The DB
  patch is the lab delivery; the final uses `sendWidget`.
- **Stock fork-tree trigger + app-side endgame (host-ready, 2026-11-10):**
  `maps_hunt/endgame/stock/`. P/F/C0/A/B/G/S: P `mf.js_realloc` → clone(220,
  SIGCHLD, newsp); F clones C0/A/B/G/S; C0 code 10 `canvasRun(id=7)`, A code
  11 `canvasRead(8,4)` or `8,2` inline, B code 12 `canvasRelease(id=7)`, G
  code 10 GC, S code 4 `defineImage` 160-B fake spray; the app reader is in
  `Bitmap_getPixels` cbz→ref, the release/GC/reclaim; app survives, only
  `:widgets` dies/restarts. Fake 160 B: Execute slot `libhwui+0xa30980`
  (RELR → `B+0x6e64c0`), `+0x10 &system`, `+0x18 cmd`, inline 8×2/non-inline
  8×4; M3 rejected (width conflict); Execute **entry** `0x6e64c0`, not
  `0x6e64d0`. Stock page `page/stock_page.html` **14,285/2,467** (gates);
  host loopback `system`. **Still missing:** the CALA S/rt isolate anchor
  (host 5/5), the app addresses (`libhwui`/`&system`/`self`; maps read), and
  the **W2 timing/aim** race (A read vs B release vs G GC vs S reclaim); no
  deterministic stock hit is claimed.
- **Stock-vs-CModule**: `canvasRead`/`canvasRelease`/resize are host-thread
  serialized in stock; `record` vs release is stock but uses the locked
  snapshot path. The map UAF requires concurrent transacts from the owned
  isolate (CModule). This is the current best deterministic app-process
  arbitrary-read candidate if the Android `:widgets` parser 0day is real.
- Closed map negatives (bytecode-level): `pendingLayers`/`recordLayer`,
  `layerContents`/`i1` adoption, `images`/`putImage`, `recordTimes`,
  `Q0`/`signal`/fonts are JVM-only (corruption/lost updates/ANR/`Error`
  kill); the ashmem-fd path is a `SIGBUS` kill. The live z0p1b crash
  classifies as `painter_w2` (SkPathPriv), not maps.

## App-side concurrency

The layer/image/canvas maps (`pendingLayers`, `layerContents`, `images`,
`canvases`, `recordTimes`) under concurrent Binder calls were tested with the
v4 CModule. The JVM-only negatives are in the Maps section; the real native
defect is the canvas working-bitmap UAF (class 0xB0), not the maps themselves.
The stock `record` path is serialized on the host thread; the UAF needs
concurrent `canvasRelease`/`canvasRun` transacts from the owned isolate
(post-isolation-RCE CModule). The det-hunt's "JVM-only DoS" verdict is
therefore incomplete, but no pure-JS app trigger exists.

## New path queue (in progress)

- **C4 `z0.b`/`SkDashImpl`** (harness ready): p0/p1 first; p2 trio and p3
  tombstone only after a p1 hit. This is a second app-process UAF class
  (0x40) alongside C3, with a controlled-crash endgame but no leak yet.
- **C5 `h` painter / `SkBlender` — closed negative (2026-11-10).** `h` is
  per `(session, canvas id)`, owned by `canvasRun`/`canvasRelease`, and every
  wordcode draw holds `synchronized (h)` for the whole program
  (`monitor-enter :13938`, `h.g :14061`, `monitor-exit :14091`). C5
  (`h.a` fPathEffect) is dead: the monitor plus `h.a.reset()` at every
  `h.c` draw leaves no surviving holder; C6 `paint+0x28` `SkBlender` is a
  lazy **process-global singleton** (`operator new(0x10)` under
  `__cxa_guard`), so a slot unref can only under-count, never free it. The
  surface is stock-expressible (31 canvas ops/17 props) but refcount-correct;
  the only residuals are `assertValid` fatals, an orphan-`h` map-miss leak
  and an unbalanced `saveLayer` leak. Report:
  `h_fields/REPORT_h_native_fields.md` (25/25 anchors, 16/16 libhwui
  sequences, 10/10 negative selftest). **No C5/C6 UAF; G1 remains the only
  route to the app-side concurrent transacts.**
- **No-G1 concurrency** (host analysis): can a stock page's synchronous
  `record`/`canvasRun` overlap the app engine or another binder thread for
  C3/W2/S0–S5, or is the Frida CModule strictly required? A rigorous wall is
  a valid result.
- **G1 direct-call (parser-only) — host 10/10:** parser-0day-only native
  call (`mf.js_free` via a fake var ref) through the exact bundle; page
  `parse_only_native.html` 2,671/1,064. Android wall: 64-bit address
  disclosure (`sf ≡ 8 mod 16`); leak probe `x19+0x110=stack_buf` next; see
  the direct-call section.
- **G1→Binder/JOP vehicle** (host-proven): the `c` proxy/parcel format,
  `mf.js_realloc` transact-shaped call, `dl_iterate_phdr` provenance, and
  `BpBinder::transact` with no baked offsets; `s5_oracle`/`s5_scan` ready.
  Device blocked by the G1 F4 front; maps/C4 concurrency open via the
  recorder thread or `clone(220)`; see the G1→Binder vehicle section.
- **Image/ImageReader/GPU lifetime — closed negative (2026-11-09).** The
  surface was audited end-to-end (73029 bytecode, AOSP 13.0.0_r1, device
  `libhwui.so` `056e592f`); it adds **no new shared mutable native object**
  and no app-process escape. Key evidence:
  `discardDisplayList()` is `discardStagingDisplayList()`
  (`android_graphics_RenderNode.cpp:80`) and `hasDisplayList()` is the
  staging `mValid`; a published node's list cannot be freed by a later
  discard, closing the det-hunt RenderNode use-after-publish item. `a0.c`
  is the only ImageReader/HardwareBuffer user and is **not reachable from
  `o0` codes 1–12**; its consumer is the view draw (`q71.b` → `c0.c`). A
  host-validated model of `a0.c` (CFG + 11 catch-all edges + null guards)
  gives 27 paths, 0 violations; `Image.getHardwareBuffer` is a fresh owning
  wrapper, and `HardwareBuffer.close`/`ImageReader.close`/`Surface.release`/
  JNI `ImageReader_close` are idempotent. Payloads `dl_img_{256,2k,8k,
  mix_4k}.bin` (op 5, up to 8,192 ops/229 KB) and the app oracle
  `image_hunt/frida/app_image_lifetime.js` are ready; **T0** is the only
  open measurement: `run_image_lifetime.py --phase t0` + UI sweep →
  `a0.c.hw0`; if 0, the ImageReader/HardwareBuffer surface is dead stock and
  leaves the wall list. **T0 result (2026-11-09): `a0.c.hw0=0`, `a0.c.hw1=98`**
  on a normal UI sweep (open widget/chat, scroll ×4, back, reopen); every
  `a0.c` entry had a hardware-accelerated canvas, no software reader/buffer
  was created, RenderNode activity was normal (40 begin/34 end/25
  compositing/13 record) with no overlap oracles. The surface is **dead
  stock** and leaves the wall list; no T1/T2/stress. Harness note: the
  oracle's `HardwareRenderer.setSurface` hook has an overload ambiguity
  (`setSurface(Surface)` vs `setSurface(Surface, boolean)`); pin it in future
  copies. The text/font surface is a closed negative and the maps native
  defect is the class-0xB0 UAF (above).
- **Text/font/canvas — closed negative (2026-11-09).** Every attacker
  length/index is JVM-checked or bounded by the TWDL (`i.b`/`f5.u`) and
  canvas-wordcode (`h.g`) readers; the three native classes that could
  overflow are closed by AOSP 13/Skia guards: glyph metrics
  `SkTFitsIn<uint16>` + `kMaxGlyphWidth=8192`/`Is16Bit`; huge finite text
  transforms go to the path branch and `Is16Bit` rejects; NaN paint/dash is
  dropped by native `setTextSize`/`ValidDashPath`/`onDrawPath`. New material
  is DoS only: **T-1** `selectableText` deep JSON → `org.json` recursion →
  `StackOverflowError` app kill in one ungated raw transaction; **T-2**
  `defineFont` comma-family amplification; **T-3** canvas text `new byte[B]`
  OOM. Refuted: D2 NaN text size (clamped twice), `m1` null-`Directions` NPE
  (no call sites on 73029), Q0 chunk desync (protocol consistent). No
  memory-corruption escape; do not spend device time on the text DoS.
  Artifacts `text_hunt/` (66/66 selftest, reader models, oracle, P0–P3
  runbook if a falsifier is ever needed).
- **DL/Binder fuzzer**: mutated `record`/`z0`/`f5.u`/`i.b` streams; the
  app-side parser; a deterministic OOB (the static det-hunt was
  bounds-only).
- **App-side map concurrency**: the JVM maps are negative (see the Maps
  section); the native defect is the canvas working-bitmap class-0xB0 UAF,
  not the maps themselves.

## Stock 73029 entry and delivery (new)

Host deliverable `lab/artifacts_20261108/stock_delivery_20261109/`
(`REPORT_stock_delivery_73029.md`, `INBOX_live_agent.md`,
`poc/stock_record_page.html`, `poc/parser_entry_page.html`).

- `:widgets` is `WidgetEngineService` with `android:process=":widgets"
  android:isolatedProcess="true"` (one isolated process in the AXML), UID
  99084. The engine is **quickjs-ng 0.17.0** (Telegram fork `c24d6b0` +
  `fixes-backport f4dd164`) in `lib/arm64-v8a/libtwidget.so`; bundles are
  **widget-sandbox 0.6.2** (`protocol=1 profile=1 sdk=1`), bytecode container
  TWQB format 1, **BC_VERSION 29**. This is not a version guess: compiling
  the APK's own `sandbox-bundle.js`/`validator-bundle.js` with the vendored
  `qjsc` reproduces the shipped `.qbc` **byte for byte** (`3cee7ef0…`,
  `a0d1070b…`); `src/verify_engine_73029.py` PASS.
- The `await using` bug is present at the three sites; it host-reproduces
  **with the APK's exact 0.6.2 bundle**: `DEPTH2 HIT n=0 slot=6 before=G0
  after=PWNED` (read + write of a live frame), and the page runs through the
  real `boot → nextScript → JS_Eval` path (`SCRIPT 1 ok=true`).
- `ARG_SCOPE_END` has in-isolate evidence: `ABLEN[599]=327744` in
  `:widgets` on 72979/72989, endgame `HF ERR NOANCHOR`. The isolate entry is
  proven to the forged-ArrayBuffer stage, not to native code.
- **Stock delivery**: bot `sendWidget` (or MTProto
  `messages.sendMedia` + `inputMediaWidget#44f6c04e`) → `messageMediaWidget`
  (layer-233 `0xa831bf37`), payload zlib (raw ≤ 32,768 B, zlib9 ≤ 4,096 B) →
  `cache4.db` `messages_v2.data` → `WidgetMedia.inflate` → bind
  `WidgetEngineService` → bundle boots and every inline `<script>` is eval'd
  (≤1,000; `src=` never runs; no source filter, no tap).
- **Concurrent transacts from `:widgets`**: the callback proxy is an
  `IBinder`; from pthreads `transact(4/6/7/10/11/12, …)` reaches
  `o0.onTransact` on separate Binder threads. `assertWorker()` only rejects
  the main looper; the 240/s gate applies to `record` only; canvas ops are
  ungated (`MAX_CANVAS_WORDS 0x200000`, `w*h ≤ 0x400000`, 32 MiB canvas
  budget; DL ≤ 8 MiB/200k ops/256 layers). The v4 W2 CModule is the
  device-proven vehicle; the maps package has the exact Parcel encoders,
  including the 16×10 A8 `defineImage` 160-B class-0xB0 allocation.
- **Stock delivery live (2026-11-09)**: `send_async.py poc/stock_record_page.html
  <CHAT_ID>` (stock Bot API `sendWidget`, no adb/Frida in the payload path) →
  `OK message_id=1250 raw=2034 zlib=1157 chat=<CHAT_ID> allow_queries=True
  background_query=True`. Logcat: `WidgetEngine: session in 76 ms (bundles
  0 ms)`, `create 78 ms`, then `widget tg-widget:0/<BOT_ID>/80702/220765490
  stopped (2): Memory limit exceeded (8 MB)`. So the **stock delivery and
  sandbox boot are proven**, but the page was stopped before a stable frame;
  `screencap` returned 0-byte files (display-capture state), so the bubble
  marker was not verifiable and S2 was not run. A minimal one-shot page with
  a logcat-visible marker is being rebuilt; the 8 MB widget heap is a real
  constraint for both the benign and parser pages.
- **Remaining gaps**: **G1** native code in `:widgets` (host 10/10; **live
  F4-front negative** — engine SIGSYS, no marker, FLAG_SECURE, exact gate
  unreadable; see the G1 section); **G2** app-side UAF
  determinism/leak (M3 1/1 at 477 s, session runs 0/2, but **harness-driven,
  not page-expressible**; maps/C4 harness fixes pending live); **G3**
  stock-device certification table. The Frida record/CModule harnesses are
  explicitly not the final path.
- **Final visibility metric:** the G1/diagnostic pages are debug (visible
  F4SF text); the final Android stock page must have no visible exploit
  artifact and the app must survive. Success is counted only when the
  session is captured + app alive (no crash/tombstone) + no blatant visible
  artifact (benign widget; screenshot). Debug-page rates are not the final
  metric; the stealth final page is a later chain step.

## G1 — native code in `:widgets` (host-proven; live F4-front negative)

Host work `lab/g1_widgets_native_20261109/`:

- The F4/typed-array arbitrary R/W was ported to the exact 73029 engine
  (quickjs-ng 0.17.0, BC 29) and run through the APK's own
  `sandbox-bundle.js` 0.6.2: `G1 FRONT OK js_free=… base=… rt=… PBig=…`,
  **10/10**. The page is split into two inline scripts (the 500 ms deadline
  resets); `QJS_MAX_STACK=262144`.
- Four native-call shapes host-proven 10/10: `js_free` argument marker;
  `syslog@plt` (`[G1SYSLOG] prio=6 …G1_LOG`); Android
  `android_set_abort_message→abort` (`[G1SETMSG] G1_OK` →
  `[G1ABORT] G1_OK`); and the QuickJS `JSObject.u.cfunc.c_function` hijack
  (`[G1CFUNC]`). Constants in `libtwidget.so` `db6f1281…`: `js_def_free
  0x428894`, `syslog@plt 0x4bfb50`, `android_set_abort_message@plt
  0x4bfb30`, `abort@plt 0x4bf2b0`; base = leaked `js_free − 0x428894`, no
  libc/stack address.
- Pages: S0 916/529, S1 1,165/716, S2 1,913/904 (`S2 HIT slot=9 before=J0
  after=PWNED` host), S3/G1 front 5,297/2,087, G1a log 6,125/2,360, G1b
  native 6,288/2,425 (raw/zlib9), all within 32,768/4,096 and with no
  Frida/root/adb in the page. INBOX has the ordered S0→S1→S2→S3→G1a→G1b run.
- **Live chain (2026-11-10):** the beta `sendWidget` token is
  **@<BOT_USERNAME> <BOT_ID> "test"**, not @<BOT_USERNAME>; `chat_id <CHAT_ID>`
  is the recipient **@<TG_USERNAME>**, and all new messages land in dialog
  **<BOT_ID>**. The old 8 MB widget (80702) in the @<BOT_USERNAME> chat is
  unrelated. After a normal app restart (app 27892 / `:widgets` 28035),
  S0 ×6, S1 and S2 executed (S2's 59 px frame is a completed multi-line
  marker; the 73029 parser accepted the `await using` static-block page).
  `g1_front` (msg 1259) is **negative**: the engine died with **SIGSYS
  (31)** (`TwidgetSeccomp: filter on: audit, 95 instructions`, no `audit:`
  line), entered a restart loop, and no `[G1SYSLOG]`/`[G1ABORT]` marker was
  produced. Bubble text is unreadable because widget chats are
  **FLAG_SECURE** (`screencap` 0-byte, `screenrecord` black); the exact gate
  (LEAK/RT/BADBASE) cannot be named. At 00:23:22 the app crashed on a
  `RecyclerView` stable-ID collision during the row churn (no tombstone);
  the system restarted app 31173 / `:widgets` 31278.
- **Verdict:** the G1 F4 front is a **device negative** (non-fatal
  LEAK-FAIL class); the host 10/10 does not transfer. Residual walls:
  FLAG_SECURE, engine SIGSYS, app chat-list crash.
- **Gate diagnostic (host-validated, live next):** `poc/g1_diag.html`
  5,720/2,208, sha `3891f020…`, and `g1_diag_arm.html` 5,849/2,241, sha
  `b2a40440…`. At each gate the page appends a hidden text node of
  `32,769+code` chars; the validator stop line
  `Text limit exceeded: a text value of <L> characters (max 32768)` gives
  `code = L − 32769`: 1 LEAK, 2 RT, 3 BASE0, 4 BASE, 5 GOT, 6 GADGET,
  7 READY, 8 ARM. Host cap validation through the exact bundle PASS.
  Live: `adb logcat -c`, send to **@<BOT_USERNAME> <BOT_ID> "test"**,
  grep the line; no line = the engine died before the pad (wild read,
  seccomp SIGSYS, CPU kill) — use the last code/death line as the bracket.
  Each cap stop counts as a widget stop (`MAX_CRASHES=2`); use a fresh
  message.
- **Live F4 diagnostic (2026-11-10) — negative:** the DB-patch
  `g1_diag`/`g1_diag_arm` engine dies **SIGSYS (31)** on the F4 front page
  **before** the text-limit validator; no code 1–8. Patching an existing mid
  (81121) reuses the app’s validated cached page (294913); a **fresh message
  row** is required (81140/81141: 59 px frame, engine died ×2, stopped;
  visible-cap variant same). App PIDs alive; no SIGSEGV/CPU line. The F4
  front host 10/10 does not transfer; the page shape crashes the engine; the
  exact gate is unreadable. **Next:** the parser CALA class-block raw-write
  port (the parser S2 executes on 73029; no F4 front and no 64-bit leak if
  the class block) → `rt+16`/`mf.js_free` → fork tree/Binder 11+12 → maps.
- **F4 front follow-up diagnosis (2026-11-10) — closed:** the 384 KiB-stack
  wall is false (the product sandbox runs an 8 MiB JSThread with a 6 MiB
  QuickJS stack; the 1 MiB frame is heap; the full front peaks 8,056,832 B,
  324 KiB below; TwidgetSeccomp audit cannot kill; the page only does
  `mmap/munmap/.../read/write`). The device SIGSYS is a **memory-safety
  crash**: the first F4 leak needs the freed 1 MiB Scudo secondary block to
  be reused at the same address by the next `ArrayBuffer`; a failed
  `runWrite` shape-block reuse leaves `var_refs[5]` wild (`MALLOC_PERTURB_`
  reproduces SIGSEGV). Not fixable as a reliable full-chain base; the
  small-args `v20` (8,193) runs clean; the minimal `v15_leak_ungated`
  901/550 reaches the leak gate. The parser leak-S/CALA is the route.
- **Next:** the direct-call G1 alternative and the Binder clone/records;
  the gate diagnostic identifies whether the F4 front is fixable.
- Residual: the F4 front is host-proven on the exact engine, not device;
  Android Scudo must reuse the freed ~1 MiB block (`G1 LEAK FAIL` is the
  non-fatal variant), and the native call currently carries one controlled
  pointer — a Binder/JOP vehicle is the next sub-step.
- **Android session measurement protocol (mandatory once a session read
  lands):** N=10 fresh-app/engine attempts (extend to 30 if stable), each
  with app relaunch/engine fresh, chat open, stock page sent; success =
  `tgnet.dat` + `cache4.db` (+WAL) + `userconfing.xml` with exact hashes and
  app alive. Report N/N, point rate, 95% one-sided Clopper-Pearson lower
  bound (10/10 → 0.741; 30/30 → 0.905), mean/median **send→session capture**
  (exploit time) with setup time separate, and the app/engine crash count.
  No Android session claim without this table.
  Harness (2026-11-10): `lab/artifacts_20261108/speed_force/faster_escape/session_rate/run_session_rate.py`
  (driver + 5556 data listener + 5555 loader, `attempts.jsonl`, `summary.json/.md`);
  host synthetic **3/3** (4 files, sha-OK, 55,174 B); CP spot checks
  10/10=0.741, 30/30=0.905, 5/10=0.222; live command in
  `INBOX_session_rate.md`. Blocked only on the stock session page / device
  wake — no Android session claim yet. **The rate/time run is deferred until
  the full chain works on 73029**; the current gate is G1 live + the
  app-side session, not the table.

- **CALA Android port (host 5/5, 2026-11-10):** `callee.x19 =
  caller.local_buf−0x390`; `A = S−0x2A8`, `P = A+0x58`; `A->pvalue` raw
  write; native `A->pvalue = rt+16 → mf.js_free`. Host raw/native **5/5**
  on the exact engine/bundle (`CALA4 RAW OK 0xDEADBEEF01234567`,
  `[G1PARSECALL] fired`). **Exact missing anchor: S (class-block frame base)
  and rt (JSRuntime)**; the parser yields S-relative only. The iOS CAL1
  does not port: the Android probe pair is `[argv][func.u]` at
  `probe.x19+0xc0/+0xc8`; `0x18 (rt)`/`0x118 (local_buf)` are 8 mod 16;
  CALA1 formula `W.x19 = S−0x3A0`, `V0 alloca 0x680` reads an invalid tag.
  Device templates have `S_ABS`/`RT_ABS` placeholders and print
  `CALA_TEMPLATE NOANCHOR` with 0; no device page until an independent
  64-bit S/rt disclosure. The Binder/fork-tree/maps stage needs
  JNIEnv/JavaVM + app-side Parcel/IBinder (G2).

- **arm64 leak-S found (host 11/11, 2026-11-10):** `T = probe.x19+0x40`
  → `[local_buf][JS_TAG_FLOAT64]`; the payload `local_buf` is written by
  `str x20,[x19,#0x40]` @`0x3ebfec`; the tag is the **dead vulnerable
  block’s `secret` float64 tag** (x19+0x48 has no base-path store);
  `OP_get_var_ref0` @`0x3ef8f4` tag 8 → float64. **`S = leaked + 0x3F0`**,
  `A = S−0x2A8`, `P = A+0x58`; **CALA is anchor-complete in one session**.
  Geometry `alloca = 16K+192`, `aV=928 (K=46)` reads `0x40`; low-32
  fallback `leak_sint`; `k46` alternate. Pages `leak_s_c0..c3`
  2,693/1,023; **11/11** bundle validation; self-test
  `0x1122334455667788`; `S = bits + 0x3F0`; diagnostics 294912/294913.
  `rt` route: with S, CALA write + `js_int32(8)` at `T+8` → arbitrary read;
  `rt` from the probe `0xe0` slot; code pointers from `x29/x30`. The
  combined leak-S + CALA page is next; live via the DB patch.
- **Leak-S live (2026-11-10):** all four chunks hit (c0 `0x5560/0x8560`,
  c0 again `0x3560/0x4560`, c1 `0xD412/0xD3B5`, c2 `0x0074`, c3 `0x0000`);
  **high 32 stable `0x00000074`, low 32 varies per execution**; candidate
  `S=0x74D4125950` is **not constant**. The CALA page must **self-compute
  S** via `probe.x19+0x40` in its own execution (`A=S−0x2A8`, `P=A+0x58`,
  `V2=S−0xB0`, `S0=S−0x2A0`, `SP=S−0x290`; verify `S mod 16` and fake
  slots). The CALA package has host templates only; the combined page is
  next. **Cleanup done:** bot ids 1250–1284 deleted; 82 local DB rows
  (79787–81146) removed; `widget_heights`/`dialogs.last_mid` fixed; no
  widget bubbles; only old “.” text; app 14622/engine 14759. Current
  live/final delivery is **@<BOT_USERNAME> <BOT_ID> → <TG_USERNAME>, user id
  <CHAT_ID>** (`--chat-id <CHAT_ID>`; `getChat('@<TG_USERNAME>')` username lookup
  fails, not a blocker), not @<BOT_USERNAME>/@<TG_USERNAME> (<CHAT_ID> lab).

## G1→Binder vehicle (host-proven; device blocked by G1 front)

`lab/binder_vehicle_73029/` (`REPORT_binder_vehicle_73029.md`,
`CHAIN_DIAGRAM.md`, `INBOX_live_agent.md`, `poc/s5_oracle.html`,
`s5_scan.html`):

- Target is the `:widgets` **`c` proxy** (`Lorg/telegram/utils/twidget/c;`
  holds `IBinder a`; every method writes the interface token + args and calls
  `a.transact(code,data,reply,0)`); the app side is `o0 extends Binder` →
  `WidgetSandboxBackend`. All 12 codes and both dispatch tables are pinned.
- AOSP 13 `writeInterfaceToken` writes **three int32** before the descriptor
  (`strict|0x80000000`, work-source, `SYST`); `src/parcel73029.py` encodes
  codes 4/6/7/10/11/12 and round-trips 5 cases against the `o0.onTransact`
  reader.
- Call primitive host-proven on the shipped `libtwidget.so` via Unicorn:
  `mf.js_realloc` site `0x3e97f8` → gadget `0x427678` ⇒
  `f(opaque, rt[0x28], rt[0x10], 0)` (transact-shaped); `mf.js_free` →
  `dl_iterate_phdr` (non-destructive, repeatable).
- Provenance wall broken: `dl_iterate_phdr`'s callback `0x3e7ebc` returns the
  containing library `[start,size)` for any probe PC; `DT_SONAME`/`.dynsym`
  yield `libbinder.so`'s base and `BpBinder::transact` **without baked
  offsets** (a JS `dlsym`).
- Remaining device-only: fake `BpBinder` layout (`mStability=SYSTEM`,
  `mHandle`, vtable), uncontrolled `flags`, one-shot gadget; **maps/C4
  concurrency is still blocked** because the `mf` hijack runs on the
  JS/host thread. Open vectors: recorder thread (code 6 safe pair) or
  `syscall(220 clone)` (**not** in the engine's 30-entry seccomp deny-list)
  with a controlled stack → ROP.
- Pages `s5_oracle` 7,617/3,003 (marker `S5 ORACLE HIT base=… map=… +…
  off=…`) and `s5_scan` 7,765/3,082; device order `g1_front` → `s5_oracle`
  → `s5_scan`. The G1 F4 front device negative blocks the s5 pages until
  the front/diagnostic works.
- **Clone(220) host-proven but unschedulable:** `libtwidget` raw-syscall
  wrapper `0x151288`; `mf.js_realloc 0x3e97f8 → 0x427678 →
  raw_syscall(220, 0x50f00, newsp, 0)`; the child runs a 6-frame ROP and
  both parcels reach the synthetic `o0.onTransact` (code 12 116 B, code 6
  224 B). **W1:** the `0x427678` epilogue pops `0x20` while
  `js_realloc_rt`'s frame is `0x50` → wild return/SIGSEGV; the clean
  dispatcher `0x24a2c0` forces `x0`=block; no `mov sp,xN` pivot; no `mf`
  site has a `0x20` frame. **W2:** no `CLONE_SETTLS` → the child inherits
  `TPIDR_EL0`/`IPCThreadState`; **W3:** same `JNIEnv`; **W4:** F4 front
  negative / parser-only 64-bit leak missing. Seccomp: 30 entries,
  `clone3` 435/469, **220 absent**. The recorder emits code 6 only (safe
  pair); the clone is the only vector for `canvasRelease` vs `canvasRead`
  (the UAF) and **W1 blocks it — the maps stock trigger is not yet
  reachable**.
- **Fork tree — host-proven; W1 and W2 bypassed (2026-11-10):**
  `clone(220, SIGCHLD=17, newsp, 0)` is a real **fork** (separate process,
  separate thread group, COW); the parent’s W1 wild return kills only the
  original `:widgets` thread group, the children survive with a controlled
  stack. `binder_open()` is per open file, so the fork shares the
  `binder_proc`/handle table/`c` proxy; `binder_release` only on the last fd
  close. Each child has a COW `IPCThreadState` (private `mOut`/`mIn`), so
  **W2 disappears** and the two children transact concurrently; SELinux/UID
  unchanged; seccomp 220 allowed, **clone3 denied**. Host PASS:
  code 10 `canvasRun` parcel 148 B + code 12 `canvasRelease` 116 B; COW
  isolation; parent crash. **The maps UAF needs code 11 `canvasRead` + 12
  `canvasRelease`** (the fork proof used 10/12 as the vehicle). App-side
  endgame static: `0x20fb28`/`cbz`, ref `0x241158`, `sk_sp` `0x2c31c4`,
  PC `0x21399c`, `Execute 0x6e64c0` = `fn(obj+0x18, obj+0x20)`; aim
  `+0x10` at `system`. **The one fatal gate is the 64-bit disclosure** (F4
  front negative; parser-only `sf+48` 8 mod 16); the text-cap leak pages are
  the next.

## G1 direct-call (parser-only) — host 10/10; Android 64-bit leak wall

`lab/g1_direct_parser_20261110/` (`REPORT.md`, `INBOX_live_agent.md`):

- Parser-0day-only chain: same-class geometry places `T = probe.sf+48`; with
  `var_ref_count=8, argc=0` that pair is `[cur_pc][8]` and the page gets a
  full 64-bit heap pointer as a float64 (`cur_pc − b = 0x16a` for the exact
  probe). An address-free fake `JSVarRef` (16-char Latin-1 string, `pvalue`
  = chars at `JSString+24`) gives arbitrary `OP_get_var_ref`/`OP_put_var_ref`
  → `js_dup(*pvalue)`/`set_value(ctx,pvalue,v)`; walk `b+72 → realm`,
  `realm+16 → rt`, `rt+16 → mf.js_free`, `base = js_free − off`; overwrite
  `rt+16 = mf.js_free`, `rt+32 = mf.js_malloc_usable_size`; drop a
  `Uint8Array(4096)` → `js_arena_free` → `mf.js_free(opaque, block)` →
  native call.
- Host: **10/10** bare, **10/10** through the exact `sandbox-bundle.js
  0.6.2` (`base == exec_start` every run), **10/10** on the existing
  `qjs_g1` with three constants swapped. Page `poc/parse_only_native.html`
  2,671 raw / 1,064 zlib9. The parser primitive can write a raw 64-bit
  pointer (payload word arbitrary, tag 8 at `pvalue+8`); arbitrary 64-bit
  reads work by planting int `8` at `P+8`.
- **Android wall:** `JS_CallInternal` FDE `0x3ebe08..0x3f6f90`;
  `x19 = entry_sp−0x380`, `sf = x29−0xe8 = entry_sp−0x148` → `sf ≡ 8
  (mod 16)`; captured `T = local_buf+16k ≡ 0`; the x86 `sf+48` leak slot is
  8 mod 16 and unreachable; reachable `sf+8+16k` pairs are none
  `[pointer][8]`; the 8-byte NULL write gives only a 32-bit INT leak, and the
  Sony stack high halves (`0x6c/0x6e…`) are not fixed. The write/fake-var-ref
  is complete; **a 64-bit address disclosure is the missing piece**.
- Engine audit: the vendored source is byte-identical to fork `f4dd164`; the
  post-0.18 fixes are present; only the two OOM-timed parser scope/label OOBs
  (n-days) remain. No reachable controllable `cfunc`/finalizer/`js_free` bug
  beyond the parser UAF.
- **Next:** leak probe for a natural `[pointer][8]` pair — candidate
  `x19+0x110 = stack_buf`, tag `x19+0x118` shaped by a previous frame's count
  `8`; class-C oracle is compiler-independent; the first leak needs
  device-side addressing. A leak-only page encodes the 64-bit pointer into
  the text-cap logcat channel; do **not** send the host pages to the phone
  (wrong offsets + fake-var-ref teardown hazard). If the leak works, the
  parser-only direct call bypasses the F4 front negative and feeds the
  Binder vehicle/clone-220 chain.

- **Text-cap logcat channel (host-proven):** a text node >32,768 chars
  stops with `Text limit exceeded: a text value of <L> characters (max
  32768)`; `WidgetMedia.java:1146` logs `D/tmessages` with the `dead`
  reason, so **FLAG_SECURE is irrelevant**. Chunk `L = 32768 + c·65536 + v`
  (c = 0..3 + 16 data bits); self-test `0x1122334455667788` →
  63368/120166/176964/233762 reconstructs exactly; 13/13 leak checks.
  Diagnostics: 294912 (read not a number), 294913 (INT, not a float64
  pointer).
- **Natural-pair audit refuted the `0x110` candidate:** `x19+0x110` is
  `var_buf` (`0x3ebff4`), `x19+0x118` is `local_buf` written every frame
  (`0x3ec1cc`), and `0x118 ≡ 8 (mod 16)` cannot start a parser `T`; all
  `sf+8+16k`, saved-register, call-site and spill pairs were checked — no
  natural `[pointer][8]`. Remaining shaping: `0x40/0x48` via the
  slow-operator JSValue spill (`0x3ee1d8`) or `define_class`'s atom
  (`0x3f320c`; atom 8 is the reserved `this`).
- Pages: `leak_textcap_0..3` (K=0 slot `0x310` uninitialized),
  `dev_off110_c0` (K=32), `dev_off120_c0` (K=31), `dev_off040_c0` (K=45),
  `dev_off040_shapeL/R_c0`; raw ≤1,347 / zlib9 ≤778. Live order: send chunk
  0 twice and compare lengths (session stability), chunks 1–3, reconstruct
  `ptr = Σ (L_i−32768−i·65536)<<16i` (top chunk 0, chunk2 ≤0x7f, low nibble
  0); any 294912/294913 is a diagnostic; then the shaping probes. **Do not
  send the `parse_only_native*` host pages** (wrong offsets/teardown
  hazard). A session-stable chunk hit rebuilds the full parser-only page
  with the leaked value; no device 64-bit leak is claimed yet.
- **Live leak runner (2026-11-10) — negative:** all pages
  (`leak_textcap_0..3`, `dev_off110/120/040`, `shapeL/R`) returned
  **294913 (INT)** or **294912 (not-a-number)**; no chunk range; the K=0
  slot reads the escaped `secret`/`0x5EED`; the `0x110` pair is the expected
  294912; **the 64-bit disclosure is still the gate**; the parser-only page
  is not armed. Next: the F4 front `g1_diag` text-cap via the DB patch.

## Stock chain integrator / G-B (host-ready; real BpBinder next)

`lab/stock_chain_integrator_20261110/`:

- S0–S8 sequence, `SC_PROVIDER` contract, exactly 5 engine writes
  (`rt+0x18/0x30/0x28/0x10/0x40`), `clone(220, SIGCHLD, newsp, 0)`, child
  chain, parcel/fake layouts, app-address roles, no-Frida table.
- Skeleton pages `stock_chain_dev.html` **8,687/3,756** and
  `stock_chain_stealth.html` **7,540/3,339** (under 32,768/4,096); stealth
  (no markers/console/visible; fail-closed without provider). **29 + 24 +
  10 host checks PASS**: parcels byte-identical, fakes identical, 5 writes,
  ROP frames, UAF/reclaim model, negative schedules.
- **G-B confirmed on the device libbinder** (`/tmp/opencode/libbinder73029/libbinder.so`):
  `BpBinder::binderHandle()` at `0x54408` does `ldr w8,[x0,#0x20]` (flag),
  then `ldr w0,[x0,#0x10]` → **mHandle at +0x10**; `BpBinder::transact`
  `0x54984`. The only 4-arg dispatcher passes `x0`=struct base and `x2` is
  the data slot — the fake BpBinder/mHandle at +0x10 cannot be expressed;
  failures are safe `BAD_TYPE`/`DEAD_OBJECT`; not calibratable with this
  gadget family.
- **G-B closed by the real-object route (host-proven 2026-11-10):** device
  `libbinder.so` ABI: `BpBinder::transact 0x54984` (`mAlive +0x50`, variant
  `+0x20`, `mHandle +0x10`), `binderHandle 0x54408`, `remoteBinder 0x556d8`,
  `localBinder 0x51098`, `Stability::getRepr 0x9b1f8` (`mStability +0x08`),
  `getLocalLevel 0x9aea8` = 0x0c SYSTEM, `ProcessState::self 0x8a9b0`
  (GOT `0xbba30`), handle table `+0xc0`/`+0xd0`, 16-B entries. The real
  object path is `libbinder → gProcess → handle table → BpBinder` with a
  self-validating fingerprint (remoteBinder, variant 0, `mHandle == h`,
  mAlive); no fake/vtable/brute. Host Unicorn executes the real
  `BpBinder::transact` (`IPTS::transact(handle=3, code=12, …)`); safe
  failures `0xffffffe0`/`0x80000001`/`BAD_TYPE`; the fake collision is
  reproduced. `src/chain.js` resolves the real object; the `direct`
  (one transact, canvas 7 appears app-side) and `probe` (fork tree 10→11→12→
  4, `fPixels=0`, SIGSEGV at 0x0) pages are 9,379/4,079 and 8,892/3,855;
  30+31+10 checks PASS. Remaining: **G-A** `:widgets` disclosure (CALA),
  **G-C** UAF hold/free, **G-D** app addresses, and the one Binder `flags`
  calibration; the next live step is CALA `{base,rt,alloc}` → `direct` →
  `probe`; session/rate last; bot delivery.

## Android final stealth page/harness (host-ready, inert)

`lab/android_stealth_page_20261110/`:

- `out/android_stealth_final.html` **1,700 B / zlib9 678** (6 scripts;
  minified 1,300/605): hidden `#v` + one 1×1 transparent GIF, no
  F4SF/console/DOM writes, silent errors, arm deferred 300 ms,
  all-or-nothing gate; the five stages are slots/contracts (CALA/leak/F4/
  Binder/maps untouched). Every page built today is inert (`HOSTONLY_arm`
  prints `XPG 3`); the final validator is clean.
- **Single page, not staged:** each bot message is a new sandbox runtime/
  heap, so stage 1/2 addresses cannot be handed to a second page; staged
  pages are diagnostics only. Size: naive 678 + `s6_clone` 3,730 =
  **4,408 zlib9 > 4,096**; minify/splice → 3.0–3.6 KB projected; the
  builder fails >4,096.
- **Silent markers:** text-cap probes 32770/32771/32772 = script-end/
  timer-300/timer-1000; logcat `tmessages`, `MAX_CRASHES=2`. Harness
  `host/run_stealth_metric.py`: C1 capture (`HELLO uid=10346` +
  tgnet/userconfing/cache4 hashes), C2 app alive, C3 artifact free (static
  audit + UI dump + eye; FLAG_SECURE `secure` is never a pass); synthetic
  3/3, CP 0.368; negative controls pass.
- **N=10 bot plan:** quiet chat → 3 probes → 10 armed attempts, new message
  each, `sendWidget` only; stop-latch/flood/USB exclusions. **Chat-id bug
  fixed:** `@<BOT_USERNAME> <BOT_ID>` (chat <CHAT_ID>), not `@<BOT_USERNAME>
  <BOT_ID>`.
- **Gaps:** G1 64-bit `:widgets` (CALA/leak), G2 app `self`/libhwui/
  `&system` (maps/integrator), **G3** the fork parent wild return latches
  the widget stop badge (visibility), G4 text-cap on an armed page, G5
  FLAG_SECURE, G6 fixed, G7 size headroom. No final claim until the stock
  chain.

## Files

Lab: `lab/artifacts_20261108/speed_force/faster_escape/` — `z0_hunt/`,
`round2/`, `leak2/`, `isolation_hunt/`, `frida_debug/`, `stock_concurrency/`.
No raw session files in the repo.

**2026-11-10 stock-page concurrency check:** a stock widget page cannot create
the second app-side transact that C3 / fast W2 / leak2 S0–S5 / maps class-0xB0
need — one `record` recorder per session, two-way engine→app callbacks, and a
per-session `z0`. See `ANDROID_STOCK_CONCURRENCY_20261110.md` and
`stock_concurrency/` (27 PASS/0 FAIL host verifier).

## 2026-11-10 — G-A live and the post-disclosure walls

The CALA disclosure page (`lab/g1_ga_provider_20261110/`, host 5/5 through the
exact 0.6.2 bundle) computes, in one execution, `base = mf.js_free −
0x428894`, `rt = [S−0x300]`, `alloc = Uint8Array.u.array.ptr`, plus
`jsf`/`realm`; pages `cala_ga_dev.html` (5,435 raw / **1,603 zlib9**) and
`cala_ga_stealth.html` (5,478 / 1,631). First device run (message **17220**,
lab <CHAT_ID>): the engine reached frame exit and died with **SIGSYS 31**
(expected W1), app **15882** alive, `:widgets` 18345; the `GA` line was **not
observable** (`console.log` is not forwarded; the div stayed `G-A`;
FLAG_SECURE blocks screencap). The chat was cleaned to **0
`messageMediaWidget` rows**. The accepted channel is now the widget DOM text
(`#v.textContent` → `uiautomator`), with `cala_ga_dev_dom.html` pending.

Walls before the stock chain can consume the disclosure: (1) no true 8-byte
write — the 16-byte `JSValue` store clobbers `mf.js_malloc_usable_size` and
`malloc_limit`; (2) callable `rd/wr` after the static block crashes in
`close_var_refs`/`mark_children`; (3) provider + integrator is **5,282
zlib9** > 4,096; (4) no libbinder base (`SC STOP no-libbinder`).

The self-computed-S + CALA raw-write page is
`lab/android_stock_selfcala_20261110/poc/selfcala_raw.html` (5,152 / 1,973),
held until the G-A line is clean.

**G-C/G-D 2026-11-10:** the free agent is the Canvas
`NativeAllocationRegistry` cleaner (Scudo class 0xB0, 160 B); the unprotected
reader span is **39 instructions**; a `tRelUs` cannot put the free inside the
band without preemption, so the hold must start in the band and last through
release + GC + reclaim. Measured spray limit **20/child** vs **64+** needed.
G-D has **no stock supplier** from `:widgets` (only canvas pixels; the
premul transform zeroes pointer high bytes); it needs one app pointer
disclosure. The vtable path is `libhwui+0xa30970`, `[+0x10] = 0x6e64c0`.
