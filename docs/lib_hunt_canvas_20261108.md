# Canvas library hunt — Telegram widget `<canvas>`/2D (2026-11-08)

Worker scope: **canvas only** (not DOM/bridge, CSS, litehtml layout, SVG, images,
Lottie, fonts). Host-only: no device, no Frida, no bot, no network payload
delivery. The Pixel remains crash-log-only; iPhone and Sony were not touched.
This note is the deliverable; artifacts are in `lab/lib_hunt_canvas/` and durable
facts in `notes/LEMMALOG_FACTS_canvas_20261108.txt`.

Targets:

| object | identity |
|---|---|
| Android 13.2.1 (72889) lib | `lab/pixel72801_route2/libs/libtmessages.49.so`, sha256 `f12c3cb8b5e0345f51b543887b923001c8a8e04cda5cd38aed513d2d365f5f13` |
| Android 13.2.2 (72929) lib | `lab/qjs_fork_audit/zeroday_hunt_parser/device/updates/72929/lib/libtmessages.49.so`, sha256 `f2178927433b9faf9de6831d1a0b5cd9341e106d506a642debd14fa9df707534` |
| iOS 13.2 (36535) framework | `TelegramUIFramework` from `ios_sideload/Telegram_13.2.0_decrypted.ipa`, sha256 `577d3c7e1b1edec3350264f2bb66340933950686d4c1543ac52f75d5c3059f74` (122,824,000 B, arm64) |
| canonical source | `lab/qjs_fork_audit/twidget-canonical` @ `759fcafe` (core/src/canvas.cpp etc.) |
| widget JS | `lab/qjs_fork_audit/bundle_72889/WidgetJS/{sandbox,renderer,validator}-bundle.js` |

## 0. Verdict (short)

**No unreported memory-corruption primitive (OOB R/W, UAF, type confusion,
length/pointer) was found in the widget canvas/2D surface in this pass.** The
Android shipped canvas path is `native Canvas interpreter -> int[] -> Kotlin
bounds-checked Path/Paint/Bitmap` and every Java-visible index is array-bounds
checked; the Kotlin and C++ bounds were re-verified, and the iOS `/wr::canvas`
outer guards (side ≤ 16384, ≤ 4 M px per widget, ≤ 512 state stack, clip depth
≤ 63, command-count cap) are present.

What is new and useful:

1. **Patch-diff negative (strong):** the widget/renderer text range
   `0x8b0000..0x9a0000` (245,760 instructions) is **instruction-identical**
   between the 72889 and 72929 shipped libraries after operand normalisation;
   the Kotlin canvas interpreter `org.telegram.utils.twidget.d` has an
   **instruction-identical dump** in both `classes4.dex` (same SHA-256). No
   canvas memory fix is visible between these two builds, so no n-day can be
   inferred from that delta.
2. **CAN-DOS-1 (new, non-corruption):** the canvas interpreter has **unbounded
   native Geometry growth** via `Path2D.addPath`; with the sandbox context's
   `_push` (a normal prototype method in the 72889 bundle) ~64 tiny commands grow
   two paths exponentially (Fibonacci) and allocate gigabytes on the render
   thread. `MAX_OBJECTS` (4096) caps object count, not bytes. Host artifacts:
   `trigger_path2d_addpath.html`, `dos_canvas_amplification.md`.
3. **CAN-DOS-2 (new, non-corruption):** each `clip` deep-copies the whole clip
   vector and the clip path (`canvas.cpp:693`); 4000 `clip` commands on one state
   copy ~8 M path records (`trigger_clip_amplify.html`).
4. **CAN-HARD-1 (hardening, not reachable/not corruption):** shipped
   `WidgetSandboxBackend.canvasRead` checks `w*h > 4194304` with a 32-bit
   multiply that overflows (e.g. 65536×65536); the subsequent byte array and
   pixel loop are Java bounds-checked, and the native consumer re-checks the
   returned length in 64-bit, so the result is a cleared `AIOOBE`/`null`, not a
   native primitive. It is also unreachable from widget JS in this build: the
   shim's `getImageData` returns a zeroed `ImageData` and never calls the host
   (`bundle_72889/.../sandbox-bundle.js`, `getImageData(...){return new yn(...)}`).
5. **iOS `CanvasWords` audit (negative):** the Swift binary-canvas decoder's
   string-length/index arithmetic was modelled exactly and searched over 300,000
   adversarial Float64 buffers/strings in this session (plus 200,000 in the saved
   harness log): zero out-of-range slices, zero exceptions. All indices are
   validated against `words.count`/`strings.count` before slicing; malformed
   payloads only fail the batch.

## 1. What is actually shipped where

### 1.1 Android (72889/72929)

The shipped canvas engine is **not** the open-source Kotlin
`CanvasBitmaps`/`DisplayListPainter` backend: those class names are absent from
all four DEX files of both 72889 and 72929 (`CanvasBitmaps`,
`DisplayListPainter`, `LitehtmlBackend`, `twlite`/`tw-canvas` → `-1`; `canvasRun`
and `canvasRead` are present in the old `WidgetSandboxBackend` form). The
shipped path is:

```
widget JS Zr._push(["c",...])  ->  __host("ops", json)  ->  renderer
    -> AndroidRenderer::message (0x98c210, JSON depth 128)
    -> twlite::Canvas::run / apply_ops (0x969f44)          [native core]
    -> int[] producer 0x9974e4 (std::vector<int32_t>, NewIntArray/SetIntArrayRegion)
    -> Kotlin d.g/d.f  (org.telegram.utils.twidget.d)       [Java, bounds-checked]
    -> android.graphics.Path/Paint/Bitmap/Canvas          [platform Skia]
```

Native checks re-verified in the shipped binary:

* `canvas_run` producer: vector begin/end, count `(end-begin)/4`, `NewIntArray(count)`,
  `SetIntArrayRegion(0,count,data)` — same count, no underallocation
  (`REPORT_canvas_int_array_producer_20261107.md`, re-checked here).
* `canvas_read` consumer at `0x99769c`: `GetArrayLength`, then
  `length == (uint64)w*h*4` before `GetByteArrayRegion` into the destination
  vector; size mismatch returns false. `w/h < 1` and the 4 M guard are in the
  Kotlin side; values reaching it are clamped to ≤ 8192 by `Renderer::imageData`.
* `Canvas::resize` clamps side to 8192 and pixels to 2^24 (16,777,216), with the
  widget-wide allowance (`Canvas::MAX_PIXELS`); the Kotlin `checkCanvasSize`
  additionally caps `w*h` at 4,194,304 and updates a 32 MiB canvas budget.

Kotlin `d.f` (path decode) reads `A = int[opCount]`, `B = int[pointWords]`, then
`A` opcodes and consumes 2/4/6 words per Move/Line, Quad, Cubic, 0 for Close.
`d.g` reads command words and calls `Bitmap.getPixels/setPixels` with clipped
rectangles. All of these are Java array accesses: a malformed/truncated stream
raises `ArrayIndexOutOfBoundsException` (or `NegativeArraySizeException`), which
the native caller clears (`ExceptionCheck/Describe/Clear` at 0x99755c..0x997580).
No path from those exceptions to a native write was found.

### 1.2 Patch diff 72889 ↔ 72929

`lab/lib_hunt_canvas/diff_canvas_region.py` disassembles both libraries over the
Twidget range, normalises hex immediates/branch targets/symbol names, and
compares instruction by instruction:

```
region 0x8b0000..0x9a0000: A=245760 insns B=245760 insns
changed instructions: 0
region 0x960000..0x975000 (canvas ops): changed instructions: 0
```

Kotlin class dump (methods `<clinit> <init> b a c d e f g`) from the two
`classes4.dex`: SHA-256 of the full disassembly identical
(`5798a4ef...c961795`, `out/diff_kotlin_canvas_d.txt`).

Caveat: this compares instruction *semantics* after address normalisation; it
does not rule out changes in global data (e.g. a different limit constant stored
in `.data`). The canvas limit constants that matter were checked separately
(8192/16 M in native; 4 M/32 MiB in Kotlin) and match both builds.

### 1.3 iOS (36535)

The framework has no `twlite`/`canvasRun` symbols. Its canvas engine is the
`wr::canvas` C++ family: RTTI names `N2wr6canvas10CanvasHostE`,
`N2wr6canvas11CanvasStateE`, `N2wr17HTMLCanvasElementE`,
`N2wr24CanvasRenderingContext2DE`, `N2wr3ios15IOSCanvasBitmapE`, and the
`CanvasRenderingContext2D.*` error strings. Observed guards (static, capstone):

* canvas allocation `0x3d04e44`: requires `1 <= w,h <= 0x4000` and
  `(uint64)w*h <= remaining budget` (budget starts at `0x400000` = 4,194,304 px,
  accumulated with `umull`); on failure it reports the `canvas-pixels` limit and
  returns null.
* canvas command count `0x3cf00c0`: `[+0x28] < [+0x3e0]`, otherwise the
  "Canvas limit exceeded: more than …" fatal depending on the strict flag.
* state/clip machinery `0x3cfddac`: a chain count at `[+0xb8]` is rejected when
  `> 0x3f` (clip depth ≤ 63); the state-context vector is capped at `0x200`
  (512) at `0x3cefe1c`, matching `MAX_STACK`.
* element side check requires both width and height > 0
  (`0x3cee198..0x3cee1ac`, `the canvas has a side of 0.`).

`CanvasWords` (Swift, the binary canvas-word decoder used only on iOS/macOS —
`docs/protocol.md` feature table says `canvasWords` = Swift yes, Kotlin/C++ no)
was reconstructed from `widget-sandbox` git:
`packages/ios/Sources/WidgetSandbox/CanvasWords.swift` plus
`WidgetSandboxProtocol/WidgetCanvasBatch.swift`. `batch()` validates
`words.count` (≤ 2,000,000), `strings` bytes (≤ 4 MiB), the trailing string count
`m` (≤ min(65536, words.count-1)), every length (`>=0`, integral, remaining
bytes/units ≥ length) before `UnsafeBufferPointer(rebasing:)`. `forEach` validates
kind/name/argc/tag/payload against both arrays before any slice. The model in
`lab/lib_hunt_canvas/canvas_words_model.py` mirrors these guards (including
Swift's `inf.rounded()==inf`, `NaN != NaN`) and found **0 OOB slices** over
200,000 random adversarial buffers (saved log) and 300,000 in-session cases.

## 2. New canvas resource findings (not memory corruption)

### CAN-DOS-1 — native Geometry amplification via `Path2D.addPath`

Source: `core/src/canvas.cpp:887-901`:

```cpp
} else if (verb == Method::addPath) {
    auto it = paths_.find(int(a[0].ref));
    if (it == paths_.end() || &it->second == &b) return;
    Geometry g = transformed(it->second.geometry, m);        // full copy
    b.geometry.ops.insert(b.geometry.ops.end(), g.ops...);   // append
    b.geometry.points.insert(b.geometry.points.end(), g.points...);
```

There is no cap on the size of a `Geometry`. `MAX_OBJECTS = 4096` (line 86) caps
how many path objects may exist, never their bytes. The sandbox's `_push` method
(prototype method of the minified `Zr` class, `sandbox-bundle.js` ~469,6xx) lets
a widget send raw `["pc", id, "addPath", {p: other}]` commands. Two paths then
grow as Fibonacci numbers: 64 commands reach F64 ≈ 10^13 points (terabytes) and
a 4 GB phone exhausts native memory around 42-45 commands. The JS/validator sees
only ~64 tiny commands (the validator's `wu` set includes `addPath`, and the
per-payload command cap is 4000), so neither the 6 MiB JS heap nor the canvas
pixel budget (16 M px) bounds it.

Status: **reachability source-confirmed; not executed on device.** The validator
explicitly accepts `pc` with `addPath` (`validator-bundle.js`: `case "pc": … wu.has(i[0])`,
`wu` contains `addPath`) and accepts `{p:<int>}` (`canvasArg`), and `Zr.prototype._push`
is a public prototype method with no freeze/delete. Only the device run (which the
orchestrator owns) is missing. Impact: OOM /
`std::bad_alloc` on the render thread, at worst an app kill. The allocation
failure paths (`std::vector::insert`) are exception-safe; the observable state
is a `bad_alloc` (caught at the renderer boundary per round 7) or an OOM kill.
**No write primitive.**

### CAN-DOS-2 — quadratic clip copying

`core/src/canvas.cpp:684-697`: every `clip` allocates
`make_shared<vector<CanvasClip>>(*s.clips)` (deep copy of every earlier clip,
each with a geometry copy) and then appends the new clip path. 4000 `clip`
commands on one state perform ~8 M path-record copies; with a non-trivial clip
path this is a quadratic CPU/memory bomb inside one native `Canvas::run`, after
the JS CPU quota has already been paid. `MAX_STACK` (512) bounds states, not
clips per state. Same status/impact as CAN-DOS-1: DoS only.

### CAN-HARD-1 — 32-bit product in `WidgetSandboxBackend.canvasRead`

`jadx_72889_widget/WidgetSandboxBackend.java:268`:

```java
if (i12 <= 0 || i13 <= 0 || i12 * i13 > 4194304) return null;   // int product
...
byte[] bArr = new byte[Math.max(i13,0) * Math.max(i12,0) * 4]; // int product
```

`65536 * 65536` wraps to 0, so the guard can be bypassed and a zero-length array
returned; the pixel loop then indexes it with `((col-x) + (row-y)*w)*4` and
throws `ArrayIndexOutOfBoundsException` (Java). The native consumer checks
`length == (uint64)w*h*4` (64-bit) and refuses the copy, so nothing native is
overwritten. In this build the method is not reachable from widget JS anyway
(`getImageData` in the shim returns a fresh zeroed `ImageData` without a host
call). Reclassify as hardening, not a vulnerability; do not report as memory
corruption.

## 3. Existing canvas sanitizer results (re-logged, not re-claimed)

From `REPORT_canvas_campaign_20261107.md` / `REPORT_canvas_ubsan_20261107.md`:

* `arc_segments()` NaN→int at `core/src/canvas.cpp:136` with
  `M0 0 A1e30 1e30 45 1 1 1e300 1e30`; release keeps one segment, no array
  access. UBSan only.
* `base64()` signed left shifts (`canvas.cpp:92-117`), no array access. UBSan.
* ASan-only native canvas fuzz: 4,021,823 execs, 2,603 edges, zero ASan reports.
* Kotlin interpreter malformed streams: Java AIOOBE, observed and cleared.

These are included so the ledger has no silent duplicates; none is a carrier.

## 4. CVE / method research applied

Known canvas/2D bug families and what was checked here:

| reference | mechanism | analogue checked in canvas scope | result |
|---|---|---|---|
| CVE-2023-6345 (Skia MeshOp, Project Zero RCA) | accumulated `int` counts → under-allocation → OOB write | gradient stops (≤256), paths (≤4096), stack (≤512), dash (≤64), canvas pixel sum (64-bit), iOS budget (`umull`, 64-bit), `CanvasWords` sums (Double, then per-slice check) | no 32-bit accumulator reaches an allocation |
| CVE-2018-6126 (SkScan::FillPath precision) | rasterizer edge precision → heap overflow | path geometry is handed to platform Skia/CoreGraphics; Telegram builds no rasterizer | outside Telegram code; platform-patched |
| CVE-2025-32318 / CVE-2023-6345 family (Skia heap overflow) | malformed graphics → heap overflow | canvas primitives reach `android.graphics`/Skia only through bounded Path/Paint; no raw Skia object from widget bytes | platform, monthly security level dependent |
| Blink/WebKit ImageData size/stride family | declared `w/h` vs real data length | C++ `putImageData` checks `pixels.size() >= (size_t)w*h*4` and `w,h ≤ 8192`, `w*h ≤ 2^24`; Java checks `bytes.size == w*h*4` (Int overflow, Java-only); iOS binary path cannot express ImageData (falls back to JSON; same C++ check) | no native mismatch found |
| Skia `SkMaskBlurFilter` zero-size bitmap (issue 40092463) | 0-dimension bitmap in blur/extractAlpha | Telegram shadows/filters allocate only when `w>0 && h>0` (`DisplayListPainter.shadow`, `filtered`); `filterPixels` rejects non-RGBA and uses `AndroidBitmap_getInfo` dimensions | not reachable via 0-size |

Method notes (what was actually used, and why): function-normalised patch
diffing (the strongest evidence here), stripped-ARM64 static RE with capstone and
Mach-O chained-fixup decoding, DEX/Java diffing, JNI boundary mapping, a Swift
bounds model, source audit against the upstream canonical tree, prior ASan/UBSan
campaigns, and vendor/Project-Zero/OSS-Fuzz method writeups. For this target the
highest-value method was the **72889↔72929 diff** (it removes a whole class of
"maybe fixed" hypotheses) followed by **re-deriving every length check on the
actual data path** rather than trusting the public-tree Kotlin backend (which is
not shipped).

## 5. Domain / MTE / PAC applicability

* Any native canvas corruption would live in C++ `std::vector`/`std::string`
  allocations (`Geometry`, clip vectors, strings) — Android Scudo primary heap,
  **MTE-tagged** when MTE is on; a tagged OOB would fault at the access. Small
  objects (<~1 KiB) may come from Scudo's primary/arena; QuickJS-side arena
  objects are tag 0 (prior project facts). CAN-DOS-1/2 only stress the allocator;
  they do not defeat tagging.
* iOS: iPhone 6s/iOS 15.8 has no MTE; iPhone 17 app is arm64 with no
  `checked_allocations`/`hardened_heap` entitlement (prior facts), so a future
  native write in `wr::canvas` would be a plain heap write, PAC only protects
  code pointers. Canvas bitmaps are data allocations (no PAC).
* The Android Kotlin layer cannot produce native memory corruption: all pixel
  and path indices are Java array accesses (bounds-checked) and the JNI caller
  clears exceptions.

## 6. Payload / endgame assessment

There is **no memory-corruption primitive to weaponize** from this pass. For the
DoS findings the endgame is at most an app kill/OOM; no code execution, no
persistence. If a future audit finds a write in `Geometry` handling, the likely
shape would be a `std::vector` length/capacity corruption in the render thread;
the endgame would need a same-tag (Scudo) victim adjacent to a canvas geometry
allocation and a way to survive the render-boundary exception handler — neither
exists today. I am not claiming one.

## 7. Heavy fuzzing plan (needs orchestrator approval — NOT started)

Per the task rule, heavy runs were not started. Requested approval:

| id | target | harness | corpus | run | resources |
|---|---|---|---|---|---|
| HF-1 | canonical `twidget_core` Canvas (`canvas.cpp`, `encode.cpp`) | libFuzzer stateful grammar: command sequences incl. `pn`/`pc/addPath`, `clip` chains, 4096-object churn, putImageData size/stride, 9-arg drawImage, text at 4096-byte boundary, gradient eviction | 183 seeds from `fuzz_canvas_native.cpp` + generated 4,000-command traces + Path2D Fibonacci/clip bombs | 30 min, 2 workers, ASan+UBSan, `-rss_limit_mb=1024`, `-timeout=10` | ~2 cores, ≤1 GiB RSS, ~10 M execs |
| HF-2 | Android serializer↔Kotlin decoder differential | host model of `d.f`/`d.g` index arithmetic; mutate `CanvasOp` streams from HF-1; assert every Java index is either in-bounds or throws (no native path) | HF-1 corpus + handcrafted op/point count mismatches | 15 min, 1 worker | 1 core, ≤512 MiB |
| HF-3 | iOS `CanvasWords.batch`/`forEach` exhaustive | extend `canvas_words_model.py` with structured mutation over Double bit patterns, UTF-8/UTF-16 boundary strings, 2M-word buffers | current 300 k cases + 20 M structured cases | 20 min, 1 worker | 1 core, ≤1 GiB |

Blocking prerequisite for HF-1: the `widget-sandbox` checkout in
`lab/qjs_fork_audit/widget-sandbox` is missing `packages/desktop/sandbox`
(`twidget/json.h`, `gesture_policy.cpp`); they exist in its git history and can
be restored (`git show HEAD:packages/...`) into a scratch tree — no network.

Approval requested for HF-1+HF-2 (≈35 min, 2 cores). HF-3 is light and could run
in-session with approval if desired.

## 8. Honest negative and dead ends

* No OOB/UAF/type confusion in the shipped Android canvas pipeline, canonical
  C++ canvas, or the iOS `CanvasWords` decoder.
* No canvas memory fix between 72889 and 72929.
* `canvasRead` is dead from widget JS (zeroed `getImageData` shim) and its 32-bit
  guard is Java-only.
* `putImageData` cannot express a length mismatch that reaches native: the C++
  check is 64-bit and the Java check's overflow only yields Java exceptions.
* `drawImage` of a canvas/image resolves ids at paint time through maps; no
  dangling pointer found (canvas release/resize removes the map entry; the
  painter skips a missing id).
* `filterPixels`/shadow paths were not re-audited here (filter/DOM scope); prior
  audits found only CPU/OOM.
* Not resolved: the internals of `wr::canvas`'s software pixel path on iOS
  (`IOSCanvasBitmap::execute` at the object vtable +0x10, reached from
  `0x3cefa08`). Static vtable recovery was blocked by the stripped/relative-RTTI
  layout; this remains the highest-value iOS follow-up (HF-4:
  map `IOSCanvasBitmap` vtable via the +0x60 creator, then audit
  putImageData/drawImage software blits).

## 9. Artifacts

`lab/lib_hunt_canvas/`:

| file | content |
|---|---|
| `diff_canvas_region.py` | normalised instruction diff of two shipped `.so`s |
| `out/diff_72889_72929_twidget.txt` | whole Twidget range diff (0 changes) |
| `out/diff_72889_72929_canvas_ops.txt` | canvas ops range diff (0 changes) |
| `dex_dump_class_d.py`, `diff_kotlin_canvas_class.py`, `out/diff_kotlin_canvas_d.txt` | Kotlin canvas interpreter dump + diff (identical) |
| `canvas_words_model.py`, `out/canvas_words_model.log` | iOS CanvasWords guard model (0 OOB) |
| `trigger_path2d_addpath.html` | CAN-DOS-1 probe |
| `trigger_clip_amplify.html` | CAN-DOS-2 probe |
| `dos_canvas_amplification.md` | source-level analysis of both DoS findings |
| `ios_canvas_surface.md` | iOS `wr::canvas` static map, addresses, guards |
| `README.md` | artifact index and reproduction commands |
