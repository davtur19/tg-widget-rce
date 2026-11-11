# Native `twidget` engine audit — Telegram Android 13.2.0 beta 72799

Date: 2026-11-02
Target: `org.telegram.messenger.beta` 72799, `libtmessages.49.so`
(arm64-v8a, BuildId `645cce3998197329915f6cbfcc9ffd7f124d9f86`,
md5 `2c0caa68a07fc26f79d13519af6c3526`).
Scope: the **Telegram-specific native widget engine** (`twidget::*`, `twlite::*`)
that runs *around* the QuickJS sandbox — not the QuickJS VM itself, not upstream
Skia/FFmpeg.

Method: IDA Pro (idalib) on a **private copy** of the library
(`/tmp/opencode/tg49_twidget.so`; IDB `/tmp/opencode/tg49_twidget.so.i64`,
durable copy `<HOME>/ailocal/voda/.opencode/idbs/libtmessages_49_twidget_audit.i64`),
plus the 72799 smali tree and the shipped widget JS bundles. Host-only: the
library is aarch64 Android and was **not executed**; all dyn. claims are static
plus host-side arithmetic replicas (clearly marked).

Companion data: `lab/twidget_native_audit/` (function dumps, op table, cost model).

---

## 0. Verdict (short)

* **No memory-corruption primitive (OOB write/read, UAF, type confusion) was
  found in the Telegram-specific native twidget code in this pass.** The code is
  unusually defensive: the JSON parser is depth-limited and bounds-checked, the
  CSS-filter pixel loops are coordinate-guarded, and the canvas-op handlers check
  argument counts and clamp sizes.
* **Three native DoS classes are reachable from widget content** (no QuickJS bug
  needed):
  1. `filter: blur(<large>px)` → the native box-blur runs `O(radius)` work per
     pixel, 6 passes; a legal CSS value hangs the render thread for
     minutes-to-hours (§3, F1).
  2. A filtered layer is limited only by `w*h <= 0x1000000`; `filterPixels`
     allocates **16 bytes of float RGBA scratch per pixel** and a second
     same-size buffer for `drop-shadow` → up to ~244 MiB + ~244 MiB per pass
     (§3, F2).
  3. Deeply nested HTML/CSS reaches recursive litehtml DOM/CSS/layout walkers;
     no depth limit was found in the twidget layer (§5, F3, hypothesis).
* **One Java-side DoS on the same delivery path**: the widget payload is
  gunzipped with no decompressed-size limit (`p.m([B)`), so a few tens of KiB
  of gzip (e.g. 64 KiB → 64 MiB here) becomes a Java `OutOfMemoryError`
  (§7, F4).
* **Correction to the previous audit** (`notes/native_appdata_audit.md` §4.1):
  the twidget JSON parser is **not** an "nlohmann-style upstream parser". It is a
  hand-written recursive-descent parser (`0x79083C`) with a hard depth limit of
  128. `json11` exists in the binary only for `tgcalls`
  (`tgcalls::CallCoreHost::executeSetLocalDescription(json11::Json)`), not for
  widgets.
* The canvas **`int[]` op-stream encoder** and the **`canvasRead` consumer** were
  not fully traced (gaps G1/G2). They remain the only plausible place for a
  native length bug in this subsystem that this pass did not rule out.

---

## 1. Engine map — what is parsed natively, and from where

```
 messageMediaWidget.payload (attacker)
        │  Java: p.m([B)  gzip/inflate, no size cap           [F4]
        ▼
 w.b (String)  ─────────────► k0.d ──► WidgetSandboxNative.create(...)  0x980858
        │                                   arg1 = HTML document
        │                                   arg8 = theme JSON (client)
        │                                   arg9 = limits JSON (resource)
        ▼
 twidget::WidgetHost (5040-byte object)  ──► twlite::Renderer  (litehtml + gumbo)
        │                                        │
        │  sandbox/renderer JS (QuickJS)         └─ CSS parser 0x7BF8EC
        │      │  {"type":"ops", ...}                 └─ filter list "fl"
        │      ▼                                          │
        │  AndroidRenderer::message 0x98C210              ▼
        │      └─ twlite::Renderer::apply_ops 0x969F44   Java layer bitmap
        │            └─ op table → handlers              (a0.e, area ≤ 0x1000000)
        │                                                 │
        └─ data() 0x9868A8 → custom JSON → WidgetData     ▼
           theme() 0x98623C → WidgetTheme          filterPixels 0x987790
           safeArea() 0x9866D0                     └─ sub_97FA68 0x97FA68
                                                        └─ blur 0x980434 / 0x9805E4
```

### 1.1 JNI surface (all exports are `WidgetSandboxNative.*`)

| address | JNI | native role | attacker input |
|---|---|---|---|
| `0x980858` | `create([B[B[BFFI[B[B[B[BZBackend)J` | builds WidgetHost; **arg1 = HTML** | **yes** (payload) |
| `0x98623c` | `theme(J,[B)` | theme JSON → `WidgetTheme` | no (client theme) |
| `0x9866d0` | `safeArea(J,[B)` | safe-area JSON | no (client) |
| `0x9868a8` | `data(J,[B)` | widget data JSON → `WidgetData` | **yes** (Java-built from chat/public data) |
| `0x986bc4` | `answerRequest(JJI[B)` | query answer bytes | yes (bot answer) |
| `0x986f18` | `width(J,F)` | width | no |
| `0x987028` | `tick(JFZZZ)` | frame tick | no |
| `0x987168` | `repaint(J)` | repaint | no |
| `0x987264` | `touch(JIFFIZZII)` | touch stream | UI |
| `0x9873c4` | `hover(JIFFI)` | hover | UI |
| `0x9874f0`–`0x987768` | `arbiter*` | gesture arbiter | UI |
| `0x987790` | `filterPixels(Bitmap,[B,F)` | CSS filter list → pixels | **yes** (CSS `filter`) |
| `0x987bd4` | `conformance(Z)` | sets global flag | **no caller in DEX** |
| `0x987bec` | `limits([B)` | stores global limits JSON | **no caller in DEX** |
| `0x987c94` | `attackScan(Z)` | sets global flag | **no caller in DEX** |

`conformance`/`attackScan`/`limits` have **zero** call sites in the 72799 smali
(`grep` over all `*.smali`); they are dead in this build. Their globals
(`byte_19EBD44`, `byte_19EBD40`, `unk_19EBC58`) gate debug-only paths, e.g. the
`data-conformance` / `data-stress` attribute probes inside
`AndroidRenderer::message` (`0x98C210`) — they cannot be switched on by a widget.

### 1.2 Trusted vs attacker-controlled strings

From the Java side (exact evidence):

* `w.<init>(Context,String a,String b)` → `w.a` = widget id, **`w.b` = b = `m.t`**
  (`w.smali:63-90`).
* `p.i()` sets `w.b = m.t`, `w.t = Locale.toLanguageTag()`, `w.u = null`,
  `w.w = p.e(m)` (context JSON), `w.v = p.g(m.p, m.q)` (data JSON)
  (`p.smali:2110-2199`).
* `m.t = p.m(m.g)` (`p.smali:2060-2120`), and `p.m([B)` gunzips/inflates the
  payload (magic `1F 8B` → `GZIPInputStream`, else `InflaterInputStream`) with
  **no decompressed-size cap** (`p.smali:2894-3060`).
* `k0.<init>(context, d=w.b, z=w.s|theme, e=w.d, f=w.t, g=w.u)`
  (`p.smali:4933/4994`) and the JNI call
  `create(dir, d, z, width/density, e, f, g, themeJson, limitsJson, visible, backend)`
  (`k0.smali:1180-1264`).

So in the normal widget path: **arg1 (`d`) is the decompressed widget payload =
the HTML document**, `f` is a locale tag, `g` is null, `z` is a client theme
JSON, and `data()` receives a JSON object built by `p.g()` from the widget's
`chatData`/`publicData` strings.

---

## 2. The native JSON parser (`0x78EB30` / `0x79083C`)

All native JSON consumers (`create` options, `theme`, `data`, `safeArea`,
`filterPixels`, the ops protocol) go through:

* `0x78EB30` — wrapper: `(ptr, len, flag, max_depth, out)`; stores
  `{ptr, len, pos=0, max_depth, flag}`; calls the parser with depth 0.
  All twidget call sites pass **max_depth = 128**.
* `0x79083C` — recursive-descent parser. First check:
  `if (ctx->max_depth < depth) return 0;` (ctx+24). Depth grows on every
  array/object recursion, so nesting is capped at 128 — no stack-overflow path
  through JSON.
* `0x791430` — string scanner. Every byte read is guarded by `pos < len`
  (`if (v5 >= v2) return`); escape handling covers `" \ / b f n r t u`; a
  NUL/control byte terminates with failure.
* `0x7919E4` — `\uXXXX` hex4 (bounds-checked); `0x791B98` — UTF-8 append.
  Surrogate-pair logic handles lone low/high surrogates (replacement U+FFFD
  unless the "raw" flag at ctx+28 is set).
* `0x7916A4` — number path: scans `-?digits(.digits)?([eE][+-]?digits)?`, then
  copies the token into a temporary `std::string` (SSO ≤ 22 bytes, else
  `malloc((len|15)+1)`) and calls `strtod`. The copy is `len+1`; the token
  length is `min(remaining, consumed)` — no overflow.
* Value model: `Json` 88-byte nodes / object pairs 112 bytes / array 88 bytes;
  strings are `std::string`.

**Audit result: no memory-safety issue found.** The only observable weakness is
resource use (size of the input × number of arrays), not corruption. Note that
the "exceeded maximum nesting depth" string at `0x233189` is **not** this parser
(it belongs to `sub_AE0E10`, a different component).

---

## 3. `filterPixels` — the only native pixel-buffer writer

Chain (all native, attacker CSS in, bitmap pixels out):

```
litehtml CSS value parser 0x7BF8EC   "filter: blur(..) ..."  → 16-byte CSS value
    │  name table 0x18BA4D8..0x18BA540 (brightness=1, contrast=2, grayscale=3,
    │  invert=5, opacity=6, saturate=7, sepia=8; hue-rotate=4, drop-shadow=9
    │  and blur=0 handled inline; `blur` compare is the immediate 0x72756C62)
    ▼  (twlite serialises "fl":[[type,p1,p2,p3,color],...] into the layer record)
Java a0.e(): creates ARGB layer bitmap, area = bbox(transform(rect)),
             rejects w*h > 0x1000000 (a0.smali:2112)          [F2 bound]
    ▼
WidgetSandboxNative.filterPixels(bitmap, json, factor)   0x987790
    └─ JSON parse (depth 128) → 20-byte records {u8 type; u24 width;
       f32 p1,p2,p3; u32 color}
    ▼
sub_97FA68(addr, w, h, stride, 0, recs, factor)          0x97FA68
    ├─ scratch = malloc(16 * w * h); memset 0                 [F2]
    ├─ ARGB → premultiplied float RGBA, per row using stride
    ├─ per record:
    │    type 0  → blur: sub_980434(scratch, p1*factor*0.5)    [F1]
    │    type 9  → drop-shadow: offset p2,p3*factor + colour
    │    type 1..8 → colour matrix sub_97F678 → apply
    └─ float RGBA → ARGB writeback, per row using stride
```

### 3.1 Bounds audit (negative result)

* `w`, `h`, `stride` come from `AndroidBitmap_getInfo`; width/height are
  rejected if < 1; `w*h` is computed in 64-bit and only `>= 2^60` is rejected.
* All three loops (convert, filter, writeback) index the scratch by `w`/`h` and
  the bitmap by `stride`, 4 bytes per pixel; reads/writes stay inside the
  respective row.
* `drop-shadow` (the only place with signed offsets): the source index is
  `4*(x-dx) + 4*w*(y-dy) + 3`, and the read is guarded by
  `0 <= x-dx < w` and `0 <= y-dy < h`. I re-derived the algebra for negative
  large `dx/dy` and for `llroundf` saturation; the guards make the pointer
  arithmetic consistent. No OOB found.
* `blur` (`0x9805E4`) indexes with the same guards and clamps; no OOB found.
* The blur pass is the DoS (below); it is not an overflow.

### 3.2 F1 — `filter: blur(<large>px)` → O(radius) native work per pixel

`0x980434` computes the box-blur radius as

```c
v9 = (int)truncf((float)((float)((float)(r * 3.0f) * 2.5066f) * 0.25f) + 0.5f) / 2;
R  = (v9 <= 1) ? 1 : v9;         /* r = record.p1 * factor * 0.5 */
```

and then calls `sub_9805E4` **six times** (3 horizontal + 3 vertical box
passes); each pass performs `2R+1` source reads per output pixel. There is no
upper clamp on the CSS length anywhere on this path (`0x7BF8EC` clamps to 1.0
only for a few unitless amount types; `blur()` lengths go through `0x7C7E58`
unclamped).

Cost (host replicate `lab/twidget_native_audit/f1_blur_cost.c`, exact float
arithmetic of `0x980434`):

| CSS blur | R | taps | 1000×1000 layer | 4000×4000 layer |
|---|---|---|---|---|
| 100 px | 47 | 95 | 5.7e8 | 9.1e9 |
| 1 000 px | 470 | 941 | 5.6e9 | 9.0e10 |
| 10 000 px | 4 700 | 9 401 | 5.6e10 | 9.0e11 |
| 1 000 000 px | 469 987 | 939 975 | 5.6e12 | 9.0e13 |

`blur(1e6px)` on a full-screen widget layer (≈2.6 M px) is ~10^13 memory
accesses on the UI/render thread — an ANR/watchdog kill, not corruption.
`filter: blur()` is valid CSS and the whole chain (CSS parse → `"fl"` JSON →
`filterPixels`) is native, so no JS vulnerability is required; if the document
is ingested natively at engine start (gap G5) it does not even need script
execution.

**Severity: DoS (high). Not memory corruption.**

### 3.3 F2 — 16 bytes/pixel scratch, second buffer for drop-shadow

`sub_97FA68` allocates `16 * w * h` (float RGBA) and zeroes it; `drop-shadow`
(type 9) allocates a second buffer of the same size. The Java layer bitmap is
capped only by `w*h <= 0x1000000` (16 777 216 px, `a0.smali:2112`), which is
~244 MiB of scratch **per buffer**, plus the ARGB bitmap itself (64 MiB) and the
Java heap. On a 4 GB device this is a plausible `std::bad_alloc`
(`sub_16E94A0` failure path) or LMK kill.

**Severity: DoS/OOM (medium).**

---

## 4. Canvas op protocol (`apply_ops 0x969F44`)

The renderer/sandbox JS sends JSON messages to `AndroidRenderer::message`
(`0x98C210`), which parses them with the depth-128 parser and dispatches. Ops are
encoded compactly (single-letter op classes; per-command names from the table):

```
["c","<command>",args...]   command ops
["s","<property>",value]    canvas state property (17 properties)
["r",w,h]                   resize/reallocate the canvas
["g",...]                   gradient/color-stop builder
["gs"/"pn"/"pc", ...]       internal 2-char ops
```

* Command/property name tables are compile-time `{char*,len,id}` arrays:
  `0x18C6A10` (17 properties) and `0x18C6C78` (31 commands: `beginPath`,
  `clearRect`, `clip`, `drawImage`, `fill`, `fillRect`, `fillText`,
  `putImageData`, `resetTransform`, `restore`, `rotate`, `save`, `scale`,
  `setLineDash`, `setTransform`, `stroke`, `strokeRect`, `strokeText`,
  `transform`, `translate`, `addPath`, `arc`, `arcTo`, `bezierCurveTo`,
  `closePath`, `ellipse`, `lineTo`, `moveTo`, `quadraticCurveTo`, `rect`,
  `roundRect`). Full dump: `lab/twidget_native_audit/canvas_op_table.tsv`.
* `0x9706F0` = name→id lookup; `0x969F44` = apply_ops loop (rejects ops with
  `args.size() < 2` or a non-string first element);
  `0x96AE60` = state/geometry handler; `0x96C3CC` = property setter;
  `0x966928` = path/fill/stroke/text/image handler (large, inlined);
  `0x969A90` = resize.
* Defensive checks observed: canvas resize clamps `w,h` to `0x2000` (`0x969A90`);
  `setLineDash` rejects > 64 entries and NaN/Inf values;
  `globalAlpha` clamped to [0,1]; `shadowBlur` clamped to 100; gradient
  colour-stop handling uses capacity-checked vector growth with `>>62` overflow
  guards. Spot-audited `drawImage`, `putImageData`,
  `setLineDash`, `rect/fillRect/clearRect/strokeRect` argument extraction: no
  missing count check found.
* Pixel work is delegated to Java (`canvasRun(III[I)` →
  `WidgetSandboxBackend.canvasRun` → per-canvas `Bitmap`); `checkCanvasSize`
  enforces `w*h <= 0x400000` per canvas and a `0x2000000` (32 MiB) total budget
  at 8 bytes/px across all canvases plus `imageBytes`
  (`WidgetSandboxBackend.smali:261-470`). The native side only serialises the
  op stream.
* `canvasRead(IIIII)[B` returns pixels to native (used by the JS
  `getImageData` path). The native consumer was **not located** (gap G1) — if it
  indexes the Java byte array with JS-supplied `x/y/w/h` without re-checking the
  length, that would be an OOB read → JS-visible info leak. This is the
  highest-value unverified item in the canvas surface.

---

## 5. HTML / CSS / DOM (litehtml + gumbo) — native parse, no QuickJS bug required

Evidence that the widget document is materialised by the native engine, not by
QuickJS:

* `twlite::Container` implements `litehtml::document_container`
  (typeinfo object `0x18C5B30`, name `N6twlite9ContainerE` at `0x2b1cf9`), i.e.
  the drawing callbacks (`draw_*`, `create_font`, `get_image`) are the Telegram
  Java backend.
* `litehtml::document` RTTI/vtable (`0x18baf00`), `litehtml::css_properties`,
  `litehtml::el_*`, `litehtml::render_item*`, `litehtml::media_query_list*`.
* Gumbo HTML5 parser is linked in: gumbo DOCTYPE/tokenizer strings
  (`about:legacy-compat 0x22746b`, `PUBLIC/SYSTEM 0x29902e/0x21d998`,
  `<html`/`<!DOCTYPE html>` serialiser strings `0x25c29c`/`0x285727`), the
  HTML5 tag-spec string table (`annotation-xml 0x24db3a`, `noembed 0x21d986`,
  `frameset 0x248ad9`), and litehtml callbacks that take `GumboInternalNode*`
  (`document::build_template`, `document::update_structure` RTTI closures at
  `0x2abfa0`/`0x2ac7a5`). The gumbo code itself lives at `0x17b...`–`0x17d...`
  (litehtml calls `0x17BCE3C`, `0x17C827C`, `0x17C84D4`, `0x17B5FF4`).
* The widget HTML is the argument `k0.d` described in §1.2; the renderer object
  (`AndroidRenderer`, typeinfo `0x18c74d0`, vtable entries from `0x18c74d8`;
  methods `0x98BF44/0x98C070/0x98C094/0x98C210/0x98CBD4/0x98CD74/0x98CF08`) is
  produced by the factory `__func` registered in `create` (vtable `0x18c7460`;
  the function that allocates the 3024-byte `twidget::Renderer` and builds the
  twlite renderer at +128 via `0x8B7194` is `0x98BC8C`). The document string is
  retained by `WidgetHost` (5040-byte object); the renderer bundle's `document`
  abstraction (`documentElement/head/body`) is served through the native
  message protocol (`0x98C210`). The exact call that feeds the payload text into
  `gumbo_parse` was **not pinned** (gap G5); the HTML is nevertheless the only
  document text in the pipeline and litehtml+gumbo is the only HTML parser in
  the library, so the parse is native either at engine start or when the
  renderer receives the document over the bridge.

CSS parsing, including `filter`, gradients, `@media`, flex/grid, and the twlite
extensions (`tw-canvas:` scheme, `data-twid`, `data-conformance`/`data-stress`)
is therefore native C++ on attacker text. `litehtml::document` vtable: `0x18baf00`.

**F3 (hypothesis, DoS): deep nesting → stack exhaustion.** The litehtml build has
658 self-recursive functions in the `0x7a0000`–`0x990000` range (DOM walkers,
CSS selectors, render tree); no depth limit was found in the twidget layer and
whether gumbo caps element nesting was not determined. A widget whose payload is
e.g. 200k nested `<div>`s (≈1.4 MB, well under message limits) should overflow
the 8 MB render thread stack inside the recursive DOM/CSS walk at first layout.
This is a crash (and a repeatable one: the widget message persists), not
corruption. Not executed on device in this pass — treat as LIKELY, not
CONFIRMED.

---

## 6. Images and fonts — handed to the platform, not parsed by libtmessages

* `loadImage(int id, byte[] data)`: the `[B` is the **data: URI string**; Java
  checks `startsWith("data:")`, rejects `svg`, caps the URI at
  `0x200000` chars, Base64-decodes and calls `BitmapFactory`
  (`WidgetSandboxBackend.smali:4077+`). Decoding is Android's
  libwebp/libjpeg-turbo/Skia — outside `libtmessages` (prior audit's CVE-2023-4863
  note applies, unchanged).
* `createFont(byte[] family, float size, int weight, bool italic, byte[] features)`:
  the `[B` is the **font family name**, not a TTF; it is split on `,`, quotes
  stripped, lowercased, mapped to system families and passed to
  `Typeface.create(...)` (`WidgetSandboxBackend.smali:3624-3850`,
  `typeface()` at 1600). No font file bytes are parsed by Telegram native code.
* `textWidth(int, byte[])` measures via `Paint`; `formatIntl(byte[])` uses the
  platform ICU.

---

## 7. Reachability, persistence, survival

* **Trigger**: widget render happens when a widget view is bound/visible in a
  chat (`hl0`/`o81` → `p.s(w)` → `p.y(m)` → `k0.e` → `create`), when the
  prewarm/cache builder runs `p.o()` (it creates up to 3 sandbox engines for
  widget entries, including off-screen "placeholder"/"cache of width …"
  entries), or from the Wallet screen (`Wallet/x0` posts a runnable that calls
  `k0.e`). `create` builds the engine and renderer; `visible()`/`tick()` drive
  it. The only `create` caller is `k0.e`; there is no direct call from the
  launch path, but the cache/prewarm builder (`p.o`) can instantiate engines
  off-screen shortly after widget entries are refreshed, so a malicious widget
  can be rendered without the user scrolling to it (the chat still has to be
  opened or its widget entries refreshed/attached first).
* **No file I/O, no loader restart**: in `0x770000`–`0x990000` there are **zero**
  callers of `open/openat/fopen/__open_2/AAssetManager_open/gzopen/inflate/dlopen`
  (checked by import xrefs). The twidget engine cannot read app-data files and
  cannot `dlopen` anything, so it cannot restart the `ks` loader; the only native
  `dlopen` wrappers in the library are elsewhere (WebRTC netd, SQLite wrapper).
* **Persistence**: the widget is a normal MTProto message; a crashing payload
  (F1/F3) re-crashes the app every time that chat is opened. That is
  message-level persistence (server side), not code persistence. The native
  engine ships in `libtmessages.49.so`, so it survives cache/data clears and app
  updates of the same build; there is no per-widget native component to
  replace.
* **Delivery**: as established in the project's main report, widget *messages*
  are gated server-side (`INPUT_MEDIA_WIDGET_NOT_ALLOWED` for non-whitelisted
  bots/accounts), so F1–F4 are a threat from a whitelisted/compromised sender
  (or from local app-data injection), not from any random bot.

### F4 — Java gzip bomb on the same path

`p.m([B)` (`p.smali:2894`) inflates either a gzip or a raw deflate stream into a
`ByteArrayOutputStream` initialised to `payload.length * 4`, with no cap on the
output. A few hundred KiB of deflate expands to hundreds of MiB → Java OOM
(`OutOfMemoryError`), killing the app on render. Java-side, but reachable from
the same widget payload and cheaper than F1/F3.

---

## 8. Findings, ranked

| id | class | severity | confidence | native? | summary |
|---|---|---|---|---|---|
| F1 | DoS (hang/ANR) | high | high (code + arithmetic replica) | yes | unbounded `blur()` radius → 6 × (2R+1) ops/pixel in `sub_9805E4` |
| F2 | DoS (OOM) | medium | high | yes | 16 B/px scratch per filter pass, second buffer for drop-shadow; layer cap 16.7 M px ⇒ ~244 MiB each |
| F3 | DoS (SIGSEGV) | medium | medium (hypothesis) | yes | deep HTML/CSS nesting → recursive litehtml DOM/CSS/layout; no depth limit |
| F4 | DoS (OOM) | medium | high (Java) | no | unbounded gunzip of widget payload |
| — | memory corruption | — | — | — | none found in reviewed code (JSON, filters, ops, data/theme) |
| G1 | possible OOB read | unknown | low (unverified) | yes? | `canvasRead` byte[] consumer not located |
| G2 | possible corruption | unknown | low (unverified) | yes | `canvasRun` `int[]` encoder not located |

---

## 9. Negative results (checked and rejected)

1. **JSON parser**: depth cap 128; every string/number read bounds-checked;
   lexer cannot run past `len`; `\u` surrogate handling bounded; no allocation
   size overflow (`(len|15)+1`, `len+1` store).
2. **`filterPixels` bounds**: convert/apply/writeback stay in the bitmap and in
   the `16*w*h` scratch; drop-shadow's signed offsets are guarded by the same
   coordinate checks that make the algebra correct; blur pass indexes with
   clamps. Values are not clamped, but only cost, not memory, is affected.
3. **Canvas op argument handling**: `apply_ops` rejects malformed ops; resize
   clamps to 8192; line dash caps at 64 entries and rejects NaN/Inf; property
   setters clamp alpha/blur; no unchecked `args[i]` found in the reviewed
   handlers.
4. **`attackScan`/`conformance`/`limits`**: exported JNI but unreachable from
   the Dex; they only set global debug flags / a limits string, so a widget
   cannot enable the conformance instrumentation or relax limits.
5. **No sandbox escape via native file I/O**: see §7; no `open`/`fopen`/`dlopen`/
   `AAsset*`/`gz*`/`inflate` callers in the twidget range.
6. **Fonts**: no TTF parser in `libtmessages`; family names go to the platform.
7. **Images**: data-URI bytes go to `BitmapFactory` (platform), not to
   Telegram's decoder (there is none linked).

---

## 10. Gaps / recommended next steps

* **G1 (`canvasRead`)**: locate the native consumer of
  `WidgetSandboxBackend.canvasRead(IIIII)[B`. Search for the cached
  `jmethodID` (slot 16 of the method table built by `create`, byte offset
  `0x80`) and the `CallObjectMethod` site; if the returned `byte[]` is indexed
  with JS `w/h/x/y` without checking `GetArrayLength`, it is a JS-visible OOB
  read (info leak) and worth a full report.
* **G2 (`canvasRun` encoder)**: locate the `NewIntArray`/`SetIntArrayRegion`
  site that builds the `int[]` op stream (Java interpreter in
  `org.telegram.utils.twidget.d`). Verify the encoder's length arithmetic
  against the Java decoder's `(len+3)/4` stepping — that is the one place where
  a native heap overflow could still exist.
* **G3 (F3)**: confirm deep nesting with a host-side litehtml+gumbo harness
  (the vendored sources are public) or on a test device; measure the depth
  threshold. If confirmed, it is a 1-file DoS payload.
* **G4**: check whether the twlite CSS parser clamps lengths elsewhere
  (`0x7C7E58` unclamped on the `blur` path) to see whether F1 can be triggered
  with a smaller/less suspicious value (e.g. `blur(2e4px)` is enough for a
  full-screen ANR).
* **G5 (HTML ingest)**: pin the call that passes the `create`-time HTML string
  into litehtml/gumbo (`litehtml::document::createFromString` equivalent;
  candidates around `0x7E6D60`/`0x7E9014`/`0x7F7324`, called from the twlite
  renderer at `0x8F0554`). Needed to state the exact no-JS parse instant.

---

## 11. Reproduction / artifacts

`lab/twidget_native_audit/`:

| file | content |
|---|---|
| `functions_index.json` | address/size/dump map of every audited function |
| `fn_*.c` | Hex-Rays dumps of `create`, `theme`, `data`, `safeArea`, `filterPixels`, JSON parser/lexer, filter apply/blur/matrix, ops dispatch/handlers, twlite renderer vtables, `tw-canvas` serialisers |
| `canvas_op_table.tsv` | 17 canvas properties + 31 commands with ids and table addresses |
| `f1_blur_cost.c` / `.out` / binary | host replica of the blur-radius arithmetic + cost table |
| `make_payloads.py`, `payloads/` | candidate widget payloads (compressed) for F1/F3/F4, generated and re-inflated on the host for sanity |

`f1_blur_cost` build/run:

```
cc -O2 -o f1_blur_cost f1_blur_cost.c -lm && ./f1_blur_cost
./make_payloads.py --outdir payloads          # f1/f3/f4 payload candidates
```

The payloads are wire-format candidates for `messageMediaWidget.payload`
(gzip or raw deflate of the widget document); they were generated and
re-inflated on the host but **not** delivered to a device in this pass.
`payloads/f1_blur.html.gz` is 121 bytes and decompresses to a 1000×1000 div
with `filter:blur(1000000px)`; `payloads/f3_nesting.html.gz` is 3.2 KiB and
decompresses to 2.2 MB with 200k nested `<div>`s; `payloads/f4_bomb.bin` is
64 KiB and decompresses to 64 MiB of zeros.

IDB: `/tmp/opencode/tg49_twidget.so.i64` (saved in place); durable copy
`<HOME>/ailocal/voda/.opencode/idbs/libtmessages_49_twidget_audit.i64`.
The live `tg49_72799.so` database was not modified.

---

## Appendix A — exact addresses

| item | address |
|---|---|
| `WidgetSandboxNative_create` | `0x980858` (13 652 B) |
| `theme` / `safeArea` / `data` | `0x98623c` / `0x9866d0` / `0x9868a8` |
| `filterPixels` | `0x987790` → `sub_97FA68` `0x97FA68` |
| blur radius/pass | `sub_980434` `0x980434`, `sub_9805E4` `0x9805E4` |
| colour matrix | `sub_97F678` `0x97F678` |
| JSON wrapper / parser / string / number | `0x78EB30` / `0x79083C` / `0x791430` / `0x7916A4` |
| `\u` hex4 / UTF-8 append | `0x7919E4` / `0x791B98` |
| ops apply / table / lookup | `0x969F44` / `0x18C6A10`,`0x18C6C78` / `0x9706F0` |
| ops handlers | `0x96AE60` (state/geometry), `0x96C3CC` (props), `0x966928` (path/fill/text/image), `0x969A90` (resize) |
| CSS filter value parser | `0x7BF8EC`; name→id table `0x18BA4D8`–`0x18BA540` |
| CSS length parser | `0x7C7E58` |
| litehtml document vtable | `0x18BAF00` (holds typeinfo ptr; entries from `0x18BAF08`, name `0x2ABF70`) |
| twlite::Container typeinfo | object `0x18C5B30`, name `0x2B1CF9` (vtable not located) |
| twlite::Renderer vtable | entries from `0x18C5040` (typeinfo `0x18C5138`, name `0x2B11AC`) |
| twidget::Backend factory `__func` | vtable `0x18C7460` (typeinfo `0x18C74B0`); builds renderer in `0x98BC8C` |
| `AndroidRenderer` vtable | entries from `0x18C74D8` (typeinfo object `0x18C74D0`) |
| `AndroidRenderer::message` | `0x98C210` |
| gumbo (HTML5) | `0x17B...`–`0x17D...`; strings `0x22746b`, `0x29902e`, `0x21d998` |

## Appendix B — attacker-controlled native inputs (one line each)

* **HTML**: `create` arg1 ← `k0.d` ← `w.b` ← `m.t` ← gunzip(payload).
* **data JSON**: `data()` ← `w.v` ← `p.g(chatData, publicData)` (Java-built JSON,
  attacker strings).
* **canvas ops JSON**: `AndroidRenderer::message` (0x98C210) ← renderer JS
  `{"type":"ops",...}` ← sandbox JS canvas calls.
* **CSS filter list**: CSS `filter:` text (litehtml) → layer `"fl"` JSON →
  `filterPixels`.
* **images**: `data:` URI string (capped 2 MiB) → Java Base64 + BitmapFactory.
* **fonts**: family-name string → Java `Typeface.create` (no TTF bytes).
