# Android 73029 — app-process M3 gradient endgame marker (2026-11-09)

Status: **app-process `system()` as UID 10346 on 73029, app survived — but
the trigger is harness-driven (Frida CModule in `:widgets`), not a stock
widget page.** Session stealer 0/2; the stock-page fallback is **closed
negative**; the stock Android final still needs G1 (native code in
`:widgets`). No 90% claim.

## Result

Run `runs/m3b_73029_20261109_183028`:

- 477.3 s, 3,313 cycles, 16,570 records, **159,040 sprays, 0 errors**.
- Marker: `MARKER_SYSTEM cmd=log -t W2 W2_DEFINEIMAGE_OK`; logcat
  `I/W2 (21901): W2_DEFINEIMAGE_OK`.
- Oracle: `ctorGrad 6,627 / gradFree 6,603 / reclaim 5,341 (81 %)`;
  `freeTid` RenderThread 4 vs ReferenceQueueD 6,599; `unrefAt0 0`;
  **`systemCalls 1`**; app survived.
- Working config: **CPU7 injector-free** (`inj-count 7`), arm CPU6,
  **`gdelay 6.731 ms`**, **`win 7.5 ms`**, single-reused-Parcel spray.

## What it is (and what it is not)

The app-side payload is stock: the freed gradient chunk is reclaimed by the
`defineImage` 256-byte blob; the stale unref calls the dispatcher and
`system` with the blob's command. No heap leak; no root in the payload.
**The delivery/race is not stock:** a Frida CModule in `:widgets` runs 4
peers (CPUs 0–3, nice −20) sending 60/76-byte truncated kamikaze DLs, one
grower (CPU 7) at `t_release + 6.731 ms`, and 7 injector pthreads (only CPU 6
armed at `t_release + 2.656 s`, busy-holding 7.5 ms), with
`PR_SET_TIMERSLACK=1`, absolute `CLOCK_MONOTONIC` sleeps and CPU affinity.
The remaining race is the final 1→0 unref; the v4 config made it hit in
~8 min.

## Stock-page fallback — closed negative (2026-11-09)

A stock widget page **cannot** trigger the M3 race. Exact walls:

1. no page vehicle: no `record`/`transact` API, no threads/Workers, no
   affinity/nice/timerslack, no way to busy-hold CPU 6; the recorder emits
   one well-formed frame at a time;
2. the kamikaze peers are deliberately truncated op-11 DLs (store at C=1,
   throw before RenderNode adoption); the page encoder only emits complete
   DLs;
3. the blob needs `libhwui+0x821a08` and `system` (per-boot code pointers;
   M3 "address-free" means no heap address, not no code address);
4. no raw bytes: the page's only `defineImage` channel is a PNG →
   valid-premultiplied ARGB_8888; the fake vptr/system words are invalid
   premul; leak2 says the raw-byte bypass is not reachable from JS alone;
   the 8×8 geometry hits the 256-B class but the parcel temp is 0x120, not
   M3's 0x250;
5. rate/cache unknown (≤160 image loads/s vs 333/s).

The closest stock carrier (`stock_m3_session_20261109/poc/stock_m3_session_page.html`,
4,127 B / zlib9 1,253; minimal 1,487/829; host 45 PASS) and the 5-attempt
run table are a carrier/negative control, not a session path. Do not spend
device time on the 0/5 table.

## Session runs and new paths (2026-11-09 evening)

- **Session stealer: 0/2 dedicated runs** — the M3 race did not hit; the
  marker run remains 1/1 at 477 s. The chain is race-based; the rate is the
  honest metric.
- New native paths, details in `ANDROID_ISOLATION_PATHS_20261109.md`:
  C1 shader phase (setter map corrected; 0 live double-reads), C3 cached
  `SkBlurMaskFilterImpl` (oracle 9,383/45,552 double-reads; rect branch
  pending), fast W2 2–13 s trigger with double-unref/steal, and the leak2
  raw-premultiplied canvas bypass (wordcode pending).

## det-hunt negative (same session)

- App-side Java/Binder/DL: **no deterministic memory-corruption/escape**. All
  `o0` handlers catch `java.lang.Exception` only; `java.lang.Error` kills the
  app (`signal` JSON `StackOverflowError`, `canvasRun` OOM) → DoS, not escape.
- `canvas`/`canvasRead` 64-bit checks; `defineImage` blocked by Skia
  `setInfo` + `computeAllocationSize` + 32 MB budget; `h.g` setPixels
  bounded; `defineFont` is a family name, not a font blob; `z0`/`i.b`/`f5.u`
  bounds-checked; `filterPixels` unreachable on API 33; NaN/Inf refuted at
  `SkCanvas::onDrawPath`.
- `RenderNode`/`ImageReader` lifetime: every delete/reuse on the
  RenderThread; no double-publish; **no deterministic single-threaded
  UAF/use-after-publish**. The only deterministic app-side primitive remains
  the DoS.

## Next

1. **G1 is the stock Android gate**: native code in `:widgets` from the stock
   parser page (F4/RW + QuickJS C-function hijack port), then the
   Binder/maps app-process UAF and the 72929 session package. The M3 marker
   is a debug result, not the stock trigger.
2. No more M3 session runs: the 0/5 stock-page table is a negative control;
   the M3 harness needs Frida and is out of the final path.
3. The deterministic hunts continue on the native decoder/renderer surface;
   none has produced a deterministic primitive yet.

No raw session files in the repo; lab copies at mode 600, not committed.
