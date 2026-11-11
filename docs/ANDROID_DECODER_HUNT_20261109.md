# Android 73029 — decoder/renderer hunt: isolated-process bugs, app escape negative (2026-11-09)

Status: **no deterministic app-process (UID 10346) escape found in the
decoder/renderer surface.** The decoder bugs found live in `:widgets`
(UID 99084), not the app. The stock M3 gradient race remains the only
app-process `system()`; the session run is in progress.

## Process topology correction

`WidgetEngineBackend` (native engine, `libtwidget.so`, image decode) runs in
`:widgets` (`android:isolatedProcess="true"`), **not** the app. The app-side
callback interface `d` has no image/font-byte entry point (`A,D,F,G,J0,Q0,
Z0,f1,h0,p0,t0,v0`); `defineImage` is a Bitmap Parcel, `signal` is case 9.
`loadImage(I[B)[F` is registered in the isolated process
(`WidgetSandboxNative_create`, `libtwidget.so+0x380cd0`) and calls
`decodeImage` statically there; only the resulting Bitmap crosses to the app.
**The app never decodes widget bytes.** Earlier device WebP tests looked for
app tombstones; any decoder effect must be sought under UID 99084.

## Findings

- **D1 — libwebp 1.2.4 decode in `:widgets`.** `data:image/webp` reaches
  `decodeImage → BitmapFactory.decodeByteArray → SkWebpCodec → libwebp 1.2.4`
  synchronously, single-threaded, before layout. The device `libhwui.so`
  carries the pre-fix libwebp (IDA-confirmed earlier); PoCs 236 B / 230 B.
  This is isolated-process code exec/DoS, not the app escape; it does not
  cross the Binder Bitmap boundary.
- **D2 — Telegram PNG IDAT inflate with no output cap.** `decodeImage`'s
  hand-rolled PNG path inflates IDAT without a cap: 261 KB PNG / 348 KB data
  URI → 256 MiB (knob to ~1.4 GiB within the 2 MiB string cap);
  `OutOfMemoryError` is an `Error`, bypasses both `Exception` catches and
  kills the engine process. Deterministic DoS in `:widgets`, not RCE.

## Negatives (evidence-backed)

- App-side `Bitmap_createFromParcel`: field order, colour types `{1,2,3,4,13}`,
  `setInfo`, 64-bit `computeAllocationSize`, `allocationSize ≤ blob size`,
  `memcpy(allocationSize)` — no overflow/undersize bypass.
- RenderNode/ImageReader lifetime: published frame `i1.H` is never discarded;
  all `discardDisplayList`/`c0.b()` act on unpublished frames under `i1.s`;
  `q71.b` re-reads and validity-checks; `RenderNodeDrawable` holds
  `sp<RenderNode>`. **No use-after-publish.** Residual risks: `a0.f` software
  cache, unvalidated layer bounds, unbounded `layerContents`, `H` never
  released (DoS).

## Consequence

The Android deterministic **app-process** escape is not in the Java/Binder/DL
surface (det_hunt) or the decoder/RenderNode surface (this hunt). The stock
app-process `system()` is the M3 gradient race (~8 min to marker on 73029);
the session stealer and 3–5 reliability runs are the next impact step. A new
deterministic bug would need a native free/write in an app-side call that is
not refcount-protected and not a race; none found yet.

Artifacts: `faster_escape/decoder_hunt/` (REPORT, PoCs, hooks, live test),
`faster_escape/det_hunt/`. No raw session files in the repo.
