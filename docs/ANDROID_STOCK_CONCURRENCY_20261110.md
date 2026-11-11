# Android 73029 — stock-page concurrency wall for the app-process UAFs (no G1)

Date: 2026-11-10. Target **73029** (13.2.2, app UID 10346, `:widgets` isolated
UID 99084, `libtwidget.so` `db6f1281…`, `classes4.dex` `0966b6bd…`).

Status: **host/static negative; no device action.** Work dir and full evidence:
`lab/artifacts_20261108/speed_force/faster_escape/stock_concurrency/`
(`REPORT_stock_page_concurrency_20261110.md`, `INBOX_stock_page_concurrency.md`,
`tools/verify_stock_concurrency.py`, 27 PASS / 0 FAIL).

## Verdict

A stock widget page **cannot** create the second concurrent app-side
transaction that C3 (`SkBlurMaskFilterImpl`), fast W2/pathref, leak2 S0–S5 or
the maps canvas class-0xB0 UAF need. All of them stay post-isolation-RCE app
stages (parser 0day → owned `:widgets` isolate → CModule/arbitrary transacts).
This extends the M3 stock-page negative to the newer native paths.

## The exact wall

1. **No page vehicle.** The page's host functions are `bridge, clearTimer,
   intl, listen, log, now, ops, pd, raf, random, stat, storage, timer, diag,
   query`; `__hostCanvas`/`__hostOps` flush the canvas/DOM streams. There is
   no `record`, no `transact`, no raw Binder. The display list is a binary
   `TWDL` stream (`i.b`: magic "TWDL", version 1, ≤200,000 ops) encoded by the
   engine, not the page.
2. **Single JS thread.** No `Worker`/`SharedWorker` (throwing stubs), no
   `SharedArrayBuffer`/`Atomics`; rAF and timers (max 64) are tasks in the
   same runtime.
3. **Two-way callbacks.** Every engine→app `IWidgetEngineCallback` method does
   `IBinder.transact(code, data, reply, 0)` + `readException()`; `record` is
   code 6. The recorder blocks in the app while `record` runs. (App→engine
   `tick` is one-way, `create` two-way.)
4. **One recorder.** In the device `libtwidget.so` the `AndroidRenderer` tick
   tests `recording_` (`this+0xbaf`); if set it sets `paintWaiting_`
   (`+0xbb0`) and returns, else sets `recording_=true` and dispatches the job
   to the `widget-record` JSThread. `record` clears it and re-signals. One
   `record` in flight per session.
5. **Per-session painter.** `WidgetSandboxBackend.<init>` allocates
   `new z0()`; `i1.<init>` allocates the backend. `z0.e` is called only by
   `WidgetSandboxBackend.record` and `.layers` (the latter only from
   `record`); `z0.d` only by `z0.e`/`w0.a`. A second page/session has a
   different painter.
6. **The app UI/RenderThread does not use `z0`**; it replays the published
   `c0` RenderNode (`q71.b`).

## Stock concurrency that does exist (and why it does not help)

The engine's **host** thread (canvasRun 10, canvasRead 11, canvasRelease 12,
defineImage 4, fonts, signal) and its **recorder** thread (record 6,
recordLayer 7, selectableText 8) are two different Binder clients; their
app-side handlers can run on two binder threads. That is the maps report's
`record` vs `canvasRelease`/`canvasRun` pair: safe by construction (`record`
uses the locked `canvas(id)` snapshot under `monitor(h)`; the canvas lifetime
calls are host-thread-serial with each other). It gives no second `z0` op and
no second canvas-lifetime op, so C3/W2/leak2/maps remain closed.

## The engine as the second peer (C3 counters)

The C3 oracle counters are global; the live widget's own record stream was
active in those windows (extra clears, `clipPath=102`, "third tid = engine").
It is a second client only against an injected `record` (CModule). A page can
steer its engine's op 14 to the same `z0.d` paint and `z0.m` blur key (CSS
`box-shadow`; `border-radius` for the rect branch's `s`/radii bits), but it
cannot make the engine emit two records. One recorder is the wall.

## Files

* Lab: `lab/artifacts_20261108/speed_force/faster_escape/stock_concurrency/`
  (`REPORT_stock_page_concurrency_20261110.md`,
  `INBOX_stock_page_concurrency.md`, `tools/verify_stock_concurrency.py`,
  `out/verify_stock_concurrency.{txt,json}`).
* Related: `ANDROID_ISOLATION_PATHS_20261109.md` (C3, fast W2, leak2, maps),
  `ANDROID_M3_STOCK_20261109.md` (stock-page fallback), and the
  `z0_hunt`/`z0_fields`/`maps_hunt`/`leak2` reports.
