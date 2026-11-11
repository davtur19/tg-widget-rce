# Widget SVG memory-safety hunt — 2026-11-08 (host-only)

Scope: the Telegram widget SVG path only. Android
`libtmessages.49.so` 72889 / 72929; iOS `TelegramUIFramework` 36535
(litehtml). No device, Frida, bot, or target/network access was used for
the lab work; only public CVE/advisory pages were fetched for research.
The Pixel remains crash-log-only; the iPhone and Sony were not touched.

Companion: `lab/lib_hunt_svg/` (harness, seeds, raw logs, ASan/OOM
artifacts), `notes/LEMMALOG_FACTS_svg_20261108.txt`.

---

## 0. Verdict

**No OOB write, UAF, type confusion, or length/pointer corruption was
found in the widget SVG parser or painter.** The source-level audit and
the focused ASan fuzz passes did not produce a controllable memory
primitive.

Three memory-safety-adjacent findings plus one UB finding were produced and
are logged:

| id | class | widget reach | status |
|---|---|---|---|
| **SVG-01** | native infinite loop → unbounded `vector<op_t>` growth (DoS; CWE-835/400) | **yes** (inline `<svg xmlns="http://www.w3.org/2000/svg"><path d="Z0"/></svg>`) | unreported native DoS |
| **SVG-02** | `<use>` exponential fan-out, no document budget on Android (DoS) | **yes** (profile-valid `use`) | unreported Android DoS; iOS fork has edit 38's budget |
| **SVG-03** | heap OOB **read** in bundled iOS nanosvg `nsvg__curveBounds` | **no** (trusted profile SVGs only) | n-day, nanosvg #184 / e7f5981 |
| **SVG-04** | non-finite arc radii → `dtheta=NaN` → float-to-int UB in `path_builder::arc` | **yes** (`path d="A 1e999…"`) | UB only; `segments` collapses to 1, no OOB |

`SVG-01` and `SVG-02` are memory-exhaustion/work-amplification bugs, not
corruption. `SVG-03` is a read-only n-day outside the widget path.
`SVG-04` is undefined behavior with no demonstrated memory primitive.
The honest answer to the primary question — an unreported **controllable
memory corruption** reachable from widget SVG — is **negative**.

One out-of-scope memory bug found by the update harness is logged as
`HTML-01` for handoff: a stack-use-after-return read in litehtml's
`element_name()` during structural document patching. It is not
SVG-specific (unknown HTML tag `<sv-g>`); unknown tags inside `<svg>` did
not reproduce it.

---

## 1. Exact source/binary baseline

### 1.1 Android

* `apks/Android_Beta_13.2.1_(72889).apk` ->
  `lib/arm64-v8a/libtmessages.49.so`
  sha256 `f12c3cb8b5e0345f51b543887b923001c8a8e04cda5cd38aed513d2d365f5f13`.
* 72929: `lab/qjs_fork_audit/zeroday_hunt_parser/device/updates/72929/lib/libtmessages.49.so`
  sha256 `f2178927433b9faf9de6831d1a0b5cd9341e106d506a642debd14fa9df707534`.
* The two builds share the SVG code. Example: `el_svg::draw`'s
  `getenv("LH_SVG_LATE_CACHE")` xref is `0x83a9e0` in both, in function
  `0x83a5ac..0x83aa58`; only data/PLT addresses differ.
  Evidence: `lab/lib_hunt_svg/evidence/android_el_svg_draw_xref.txt`.
* `draw_use` is `0x83e568..0x83f0a8`; it contains
  `cmp w21,#0x8` at `0x83e5ec` (the old depth check) and no `8192`
  budget immediate. Evidence:
  `evidence/android_72929_draw_use_depth_check.txt`,
  `evidence/android_72889_draw_use.asm`.
* Canonical Android source: `lab/rce_candidates/lt/src/litehtml_telegram`
  (`el_svg.cpp` md5 `a0eba3d7ddeb5fdd961c97f85170da5e`), identical to
  `lab/qjs_fork_audit/twidget-canonical/litehtml` at `759fcaf` (2026-11-05).
  This is the 1,834-line `el_svg.cpp`.

### 1.2 iOS

* `ios_sideload/Telegram_13.2.0_decrypted.ipa` ->
  `TelegramUIFramework` 36535; source:
  `lab/qjs_fork_audit/tgwidget-src/third-party/twidget/LiteHTML/litehtml`.
* This is the 2,161-line `el_svg.cpp` with the Telegram edits 38 (`<use>`
  budget + text runs), 58 (instance inheritance) and 72
  (`svg_path_bounds` / `transform-box: fill-box`).
* `TelegramUIFramework` contains `LH_SVG_LATE_CACHE` and
  `LH_NO_SVG_GROUP_CACHE`, matching this litehtml fork.
* The separate iOS `Svg` module (`iOS/submodules/Svg/LegacyImpl`) bundles
  **nanosvg**, but it is used by `PeerInfoRatingComponent` with bundled
  `profile_level*_{outer,inner}.svg` only; it is not the widget SVG path.

### 1.3 What the widget validator actually allows

`lab/qjs_fork_audit/widget-sandbox/docs/profile-v1.md`:
`svg.shapes`, `svg.structure` (`g, defs, symbol, use`, `transform`,
`viewBox`/`preserveAspectRatio`), `svg.text`, `svg.gradients` are **in**.
`clipPath`, `mask`, `pattern`, `marker`, SVG filter primitives, SMIL,
`foreignObject`, and `<image href="data:…">` inside SVG are **out**
(`docs/profile-v1.md:93-110`). `<img src="data:image/svg+xml">` is out
in profile v1, but the **iOS client diverges**: its sanitizer's
`imageMIMETypes` includes `image/svg+xml` and `LHCreateSVGImage` passes
SVG through (VENDOR.md edit 5; `widget-profile-draft.md:62` marks
`img-svg` OK on iOS). Android's `loadImage` rejects a media type
containing case-sensitive "svg", and `BitmapFactory` cannot decode SVG,
so Android has no data-URI SVG path. See
`evidence/data_svg_ios_policy.txt`.

So the live widget surface is inline `<svg>` with shapes/path, `g`,
`defs`, `symbol`, `use`, `text`/`tspan`, gradients, and `transform`;
on iOS, the same `el_svg` parser is also reached by an
`<img src="data:image/svg+xml,…">` whose payload bypasses the widget
HTML sanitizer entirely (2 MiB markup cap, 4096² bitmap cap).

`d` is the path-data attribute of `path` (profile `svg.shapes`), and the
validator does not parse path syntax; `Z0` passes.

---

## 2. SVG-01 — `Z` followed by an invalid byte never advances; native hangs and OOMs

### 2.1 Root cause

`path_builder::parse()` in `el_svg.cpp` (canonical lines 307-427; iOS line
423) loops over the `d` string. `Z`/`z` is the only command that consumes
no number:

```cpp
while(s && *s) {
    skip_separators(s);
    if(!*s) break;
    if(isalpha(*s)) { cmd = *s++; }
    else if(!cmd) { return; }
    ...
    switch(upper) {
      ...
      case 'Z': close(); break;
      ...
    }
    last = upper;
}
```

After `Z`, `s` points at the next byte. If that byte is a digit, `-`,
`.`, `+`, `%`, `)`, `[`, `#`, etc. — not alpha and not a
space/comma — the next iteration takes the `else if(!cmd)` branch
(`cmd` is still `Z`), executes `close()` again, and does not advance `s`.
`close()` calls `path.ops.push_back(op_t)` every time. The loop is
unbounded.

Evidence: `evidence/svg1_z0_source.txt`.

### 2.2 Minimal payload and host PoC

```html
<svg xmlns="http://www.w3.org/2000/svg"><path d="Z0"/></svg>
```

`evidence/min_z0.html` (60 bytes). With the canonical ASan harness:

```text
./harness/fuzz_svg_canon_asan -runs=1 -rss_limit_mb=256 evidence/min_z0.html
ERROR: libFuzzer: out-of-memory (used: 262Mb; limit: 256Mb)
Live Heap Allocations: 158828377 bytes in 1640 chunks
134217728 byte(s) (84%) in 1 allocation(s)
```

The 128 MiB allocation is the `std::vector<path::op_t>` doubling in
`path_builder::add()` (`el_svg.cpp:155` canonical / `157` iOS); it then
tries 256 MiB and fails. Raw log: `logs/min_z0_oom.log`.

Against the iOS vendored source the same input OOMs and the stack shows
`path_builder::add -> close -> parse -> svg_painter::draw_children ->
el_svg::draw` (`logs/min_z0_ios.log`). So the bug is present in both
the Android branch and the newer iOS fork.

### 2.3 Reachability

* **Render path:** any visible SVG child is painted through
  `el_svg::draw -> svg_painter::draw_children -> draw_child -> builder.parse`.
  `Z0` enters the loop before `paint()`.
* **Query path:** the widget JS bundle exposes `getTotalLength`,
  `getPointAtLength`, `getBBox`, `getComputedTextLength`, `getCTM`,
  `getScreenCTM` (`bundle_72889/WidgetJS/renderer-bundle.js`, `An`/`svg`).
  These call `svg_geometry()` on the element; `path d="Z0"` loops there
  before any length is returned. This is a synchronous native call, so the
  300 ms JS quota is not a guard.
* **Android:** inline `<svg>` is profile-in; `loadImage` is not involved.
* **iOS:** the same litehtml `el_svg` draws inline SVG. In addition,
  `LHCreateSVGImage` (LHDocument/LHContainer) parses `data:image/svg+xml`
  markup through litehtml. The profile marks `<img data:image/svg+xml>`
  out, so that route is only conditional on a client/validator that
  allows it; if allowed, the same `Z0` hangs the image load.
* **Sibling vector (from the same root cause):** `Z-`, `Z.`, `Z+`,
  `Z%`, `Z)`, `Z[`, `Z#` all hang. `Z `, `Z,`, `Z\n` and `Z` at end do
  not (separators/NUL are consumed or the loop exits).

### 2.4 Impact and limits

App-process OOM/ANR (the native renderer allocates until `bad_alloc`, and
the allocation is not under the 8 MiB QuickJS heap limit). The 30-byte
payload amplifies to hundreds of MiB. There is **no OOB write and no
pointer corruption**; this is CWE-835/CWE-400, not a code-execution
primitive. It is **unreported** in this project's inventory and no public
CVE/advisory was found.

### 2.5 Fix direction

After a `Z`/`z`, consume the next byte if the loop made no progress and
`*s != 0`; or return when `s == before_token && *s` (the lab guard in
`evidence/el_svg_zguard_lab.patch`). A defensive `d` length/ops cap in
`path_builder` is also reasonable.

---

## 3. SVG-02 — Android `<use>` fan-out has no document budget

### 3.1 Code and binary evidence

Canonical `draw_use()` (lines 1057-1104) resolves `href`/`xlink:href` to a
target with `select_one("#" + id)` and draws the target/subtree. It has a
depth cap (`depth > 8`) but **no element budget**: a document whose groups
each contain N `<use>` elements of the next group costs `N^depth` draws and
display-list commands.

The iOS vendored fork added exactly this defense (edit 38):
`kMaxUseDepth = 8`, `kMaxUseElements = 8192`, a document-wide
`use_instanced()` budget, and `testUseBudgetIsTheDocuments`. The Android
binary `draw_use` has `cmp w21,#0x8` at `0x83e5ec` and no `8192` budget
immediate (`evidence/android_72929_draw_use_depth_check.txt`). The
canonical 1,834-line `el_svg.cpp` has no `m_use_elements`/`use_budget`.
So the fan-out is live on 72889/72929 and fixed on the iOS fork.

### 3.2 Host measurement

`evidence/fanout7x8.html` (1,201 bytes) is a profile-valid 7-level
fan-out, 8 uses per level: 8^7 = 2,097,152 `<rect>` draws. With the
canonical ASan harness it completes in **2.38 s** on the host
(`logs/fanout7x8.log`). 9 levels = 8^9 = 134,217,728 draws (minutes);
10 levels = 1.07 B draws (hours), payload still ~1.4 KiB. The fuzz pass
also produced a 13 s timeout on a mutated nested-use seed
(`crash_patch_timeout-...`, `logs/fuzz_patch_190s.log`), which is the
same class. The iOS fork on the same seed takes 1.56 s
(`logs/fanout7x8_ios.log`) but draws only the 8,192-element budget (the
traversal is still O(2M)); it does not record 2M paths, which is the
memory difference that matters.

### 3.3 Reachability and impact

`svg.structure` includes `use` and `symbol`, so the payload passes the
widget profile; 4 KB compressed is enough. The native renderer records
one display-list `Path`/command per rect; this grows the C++ heap and the
JSON display list until OOM/ANR. No OOB, UAF, or type confusion.

This is **unreported** as an Android widget bug. It is a **fix-diff
finding**: the iOS fork already solved it; Android did not get that
edit.

### 3.4 Fix direction

Port edit 38's document-wide `kMaxUseElements` budget (or cap the display
list/instance count) into the Android branch. A 1,000-element per-paint
budget would still be far above real widgets.

---

## 4. SVG-03 — iOS bundled nanosvg is pre-e7f5981: heap OOB read

### 4.1 Findings

`iOS/submodules/Svg/LegacyImpl/Sources/nanosvg.h` is the pre-fix
nanosvg. `nsvg__addPath()` (line 1029) has only `if (p->npts < 4) return;`
and loops `for (i = 0; i < npts-1; i += 3)` calling `nsvg__curveBounds()`,
which reads eight floats at `&path->pts[i*2]`. It lacks both fixes from
nanosvg commit `e7f5981` (2020-09-28):

* `if (closed) nsvg__lineTo(...)` (commented out in the bundled copy), and
* `if ((p->npts % 3) != 1) return;`
* plus the `nsvg__cubicBezTo()` guard and `initPoint`/`rargs==-1` parser
  changes.

`nsvg__cubicBezTo()` in the bundled copy adds three points even when
`npts == 0`. `d="C1 2 3 4 5 6 C7 8 9 10 11 12"` therefore leaves
`npts = 6` (not 1 mod 3); `nsvg__addPath` allocates `12*sizeof(float)=48`
bytes and the bounds loop at `i=3` reads `path->pts[12..13]` — 8 bytes
past the allocation.

### 4.2 Host PoC

`harness/poc_nanosvg.c` parses that SVG with the bundled header. ASan:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 ... in nsvg__curveBounds nanosvg.h:578:32
#1 nsvg__addPath nanosvg.h:1059
0x... is located 0 bytes after 48-byte region
```

Raw log: `logs/nanosvg_oob.log`. This is a read-only OOB; the values are
consumed as path bounds (`shape->bounds`), so it can perturb rendering but
does not itself write or disclose bytes to script.

### 4.3 Reachability

Not widget-reachable: `drawSvgImage(data:...)` is called only by
`PeerInfoRatingComponent` with bundled `profile_level*_outer/inner.svg`
resources (`iOS/submodules/TelegramUI/.../PeerInfoRatingComponent.swift:368,398`).
The widget's SVG data images use `LHCreateSVGImage` (litehtml), not
nanosvg. Logged as an n-day for the iOS `Svg` module owner, not as a
widget finding.

### 4.4 Fix

Update `nanosvg.h` to current upstream (contains the `%3` guard,
`cubicBezTo` guard, and `initPoint` parser fix), or cherry-pick
`e7f5981`. The bundled header also has the older parser laxness that
allows commands before `M`; the `%3` guard alone stops the OOB.

---

## 5. HTML-01 — out-of-scope stack-use-after-return in the update path

The two-frame update harness (`harness/fuzz_svg_update`) found a
reproducible ASan `stack-use-after-return` read in
`litehtml::(anonymous namespace)::element_name(GumboNode const*)` at
`document.cpp:173`, reached from `same_element_kind()` /
`update_structure()` (`document.cpp:2039,2066`). Artifact:
`crash_upd_crash-05d6b5d942b888661cf9d83b411f8b1f77a11dfa` (56 bytes):
`<sv-g x}l</svg>\n<!--SPLIT-->\n<sv>ag" g xml x="0"ns="http`.
Log: `logs/fuzz_update_120s.log`.

This is a **generic HTML structural-patch** bug (unknown tag `<sv-g>`);
SVG-shaped unknown tags (`<svg><foo x}l</svg>`) and normal SVG updates
did not reproduce it in my tests. It is handed to the update/HTML owner.
It is read-only (`original_tag` points at a parser stack buffer), not a
write primitive.

---

## 6. Negative results (what was checked and did not yield a bug)

### 6.1 Path arrays and `svg_path_length`

`vector_path` has parallel `ops` and `points`; every producer keeps the
contract:

* `path_builder` `add()` pushes an op and exactly 2/4/6/0 points;
* `clip_path_shape::resolve()` produces 10 ops with 2/4/6-point segments
  for inset/circle/ellipse and pairs for polygon (parse requires ≥3
  pairs);
* `el_form` stroke paths push move/line + pair.

`svg_path_length()` indexes `points[k]` directly, so a caller that passes
an inconsistent `vector_path` would get an OOB read; I confirmed the
contract in every producer and found no attacker-controlled mismatch.
The same holds for the iOS `svg_path_bounds()` in edit 72 (it indexes
`p[k]` directly). This is a latent API hazard, not a reachable bug.

### 6.2 Gradients

`svg_gradient_paint()` validates the id (alnum/-/_, ≤128), looks up
`#id` through the document, accepts only `linearGradient`/`radialGradient`,
checks `g.stops.empty()` before `stops.back()` in the painter, and
`Writer::svg_path` only emits a gradient with `stops.size() >= 2`.
No empty-vector or target-lifetime bug.

### 6.3 Text/tspan

`svg_text_runs()` has a `parts` vector with a seed element before
recursion, guards `parts.back()`, skips empty text/no font, and computes
the box after the runs. 2,000 nested `<tspan>` and NaN/huge
`x/y/dx/dy` did not crash (host 1 MiB stack, ASan). No lifetime issue:
`element::ptr` owns each style element and the DOM outlives the painter.

### 6.4 `<use>`, `use_hosts`, cycles

Old `use_hosts` is a `thread_local vector<pair<const element*, element::ptr>>`;
the raw `element*` is only compared, never dereferenced, and the
`element::ptr` keeps the use alive. Self/ancestor/sibling cycles are
capped by `depth > 8`; no dangling pointer. Only the fan-out work is a
problem (SVG-02). The namespace-scope `thread_local` was later changed to
a function-local in `9af7d02` for a Desktop TLS-callback crash; that is a
startup issue, not an attacker memory bug, and does not affect Android's
SVG data path.

### 6.5 Group/paint cache

`svg_group_key`/`cacheable_paint_key` exclude `use`, images,
foreignObject, canvas and `url()` paints; they hash attribute/paint
signatures and cap the walk at 4,000. `draw_cached` stores only value
commands (`Path` shared_ptr, colors, matrices), no element pointers, and
copies them into the display list. A key collision can reuse stale pixels;
it cannot create a native pointer/lifetime bug.

### 6.6 Deep nesting and recursion

4,000 nested `<g>` and 2,000 nested `<tspan>` rendered through the ASan
harness with a 1 MiB host stack without a crash (57 ms / 38 ms). The
widget's 32 KiB HTML cap bounds nesting to ~4,000 `<g>`; the Android
render-thread stack was not tested on device (host-only). No stack
overflow was demonstrated; it remains a theoretical DoS, not corruption.

### 6.7 In-place SVG attribute patches

`document.cpp` records SVG geometry attributes (`d`, `points`, `transform`,
`x/y`, fill/stroke, ...) as template holes. The offset arithmetic checks
`v.data`/`v.length` against the input range, requires `length >= 2`,
clamps `s.start <= s.end`, rejects overlapping spans, and
`apply_template_values` only calls `set_attr` on the recorded owner.
120 s of two-frame SVG update fuzzing (80 hand seeds plus mutations)
produced only the out-of-scope HTML-01; no SVG hole UAF/OOB.

### 6.8 What would change the verdict

The negative is sensitive to four concrete assumptions; each is a
worthwhile next probe:

1. a producer that builds `vector_path` with fewer points than its ops
   (would make `svg_path_length` / `svg_path_bounds` OOB immediately);
2. a paint-time DOM mutation that frees an element held only by
   `use_hosts` or by a cached command (the current cache stores no
   element pointers, and the DOM is static during paint);
3. a new `el_svg` edit after 759fcaf/2161-line that adds a path or
   transform array without the same invariant;
4. a client whose validator/sanitizer allows a different SVG profile
   (e.g. data-URI SVG or clip/mask) than v1.

### 6.9 Android Java `SvgHelper` (the local `.svg` document path)

Two UBSan reports from the harness are explicitly not counted as
memory bugs: an invalid `string_id` load in `html_tag.cpp:436`
(`logs/fuzz_canon_110s.log`, malformed `<rec{` tag) and one in
`html_tag.cpp:941` from the harness's earlier comma selector list
(`logs/replay_canon.log`); both are enum-UB reads, not OOB/UAF, and the
second disappeared after the harness stopped using a selector list.

`SvgHelper` is a SAX/`android.graphics.Path` parser, not native litehtml.
`doPath()` advances on unknown characters (`default: ph.advance()`), so
the `Z0` loop does not apply; `parseNumbers`/`doPath` use Java arrays
(bounds-checked), and `Bitmap.createBitmap`/`Canvas` are platform code.
The only published issue (AndroidSVG XXE) is already covered by
`notes/appdata_code_formats.md` §13 and is blocked by Android's
ExpatReader. No new native memory bug was found there.

### 6.10 SVG-04 — non-finite arc radii: float-to-int UB, no memory primitive

The path parser accepts `1e999` because it is a numeric token. In
`path_builder::arc()`:

```cpp
int segments = std::max(1, static_cast<int>(std::ceil(std::fabs(dtheta) / (pi / 2) - 0.001f)));
```

`1e999` becomes `inf`; the arc center parameterization then produces
`dtheta = NaN`, and the float-to-int cast is undefined. UBSan:

```text
el_svg.cpp:242:63: runtime error: nan is outside the range of representable values of type 'int'
SUMMARY: UndefinedBehaviorSanitizer
```

Payload: `evidence/arc_inf.html`, log `logs/arc_inf_ubsan.log`.
On the tested targets the hardware cast yields `INT_MIN`/0 and
`std::max(1, …)` makes `segments = 1`; the loop then emits one cubic, so
this is **not** an OOB. `dtheta` is bounded by `atan2` (±2π), so a finite
value cannot make `segments` large. It is a robustness/UB bug worth fixing
with `std::isfinite(dtheta)`/clamping, not a write primitive.

### 6.11 Latent contract: `svg_path_length` trusts op/point counts

`svg_path_length()` indexes `path.points[k]` and `path.points[k+1]`
directly. A deliberately inconsistent `vector_path`
(`ops = {line}`, `points = {0}`) produces a 4-byte heap OOB read at
`el_svg.cpp:1499`:

```text
harness/poc_path_contract.cpp
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 ... svg_path_length el_svg.cpp:1499
log: logs/path_contract_oob.log
```

**This is not reachable from attacker input.** Every producer keeps the
invariant:

| producer | ops | points |
|---|---|---|
| `path_builder::move/line` | 1 | 2 |
| `path_builder::quad` | 1 | 4 |
| `path_builder::cubic` | 1 | 6 |
| `path_builder::close` | 1 | 0 |
| `path_builder::arc/ellipse/rect` | only move/line/cubic/close | matching |
| `clip_path_shape::resolve` | 10 / polygon pairs | matching |
| `el_form.cpp` paths | move/line/cubic/close | matching |

`svg_path_bounds()` (iOS edit 72) has the same direct-index shape and the
same invariant. The defensive fix is cheap: before indexing, compute the
required point count for each op and return/skip on shortage. That would
turn any future producer regression into a safe failure rather than an
OOB.

### 6.12 Data-URI SVG parser bypass — reachability, not a new parser

The iOS data-URI route (below) bypasses the **HTML** sanitizer, so the
payload can contain `clipPath`, `mask`, `pattern`, `marker`, SMIL,
`foreignObject`, `<image>`, and CSS that profile v1 drops. The litehtml
painter still skips `clippath`, `mask`, `pattern`, `marker`, `filter`,
`script`, `metadata`, `foreignobject`, and `image` children in
`svg_painter::draw_child()` (defs/style/title/desc/gradients/clipPath/
mask/pattern/symbol/marker/filter/script/metadata are skipped;
foreignObject/image/canvas have no drawing branch); no new SVG drawing
code is reached. The extra elements matter only to layout/CSS parsing
and to `<use>` target resolution, not to a new memory primitive. `LHCreateSVGImage` caps
markup at 2 MiB, box at 16384 pt, bitmap at 4096², and blocks nested
SVG with a thread-local depth guard. The reachability gap itself is logged
as `OBS-01` (iOS data-URI payload bypasses the HTML sanitizer); no memory
primitive was found in the audited painter, and the CSS/layout subset is
handed to the litehtml/CSS owner.

---

## 7. Tag domain, MTE, and endgame

* All SVG parser/painter allocations in `libtmessages` are C++ heap:
  `std::vector<op_t>`, `std::vector<float>`, `std::string`,
  `std::unordered_map`, `std::shared_ptr` control blocks. They are **not**
  in the QuickJS custom arena (tag 0); on Android they are Scudo
  allocations and receive Scudo/MTE tags when the process enables MTE.
* `SVG-01`'s 128 MiB allocation is exactly the `vector<op_t>` from
  `path_builder::add`; it is an allocation-size failure, not a tag
  violation. MTE-on does not mitigate it.
* If a future bug gives an OOB *within* one of these Scudo chunks (same
  granule), MTE checks the pointer tag (unchanged) and does not fault; a
  UAF would only fault if the chunk is reused with a different tag. So
  MTE-on is **not** a general mitigation for this heap class.
* No write primitive was found, so there is no heap-groom / tag-leak /
  endgame chain to propose. The two reachable findings end at app OOM/ANR.
* Do **not** run `SVG-01`/`SVG-02` on the Pixel except as crash-log-only,
  and not at all on iPhone/Sony. They are not memory-corruption proofs and
  could kill the app; device time is better spent on a write bug.

---

## 8. Payloads and device handoff (if the orchestrator wants them)

### 8.1 Smallest `Z0` widget body

```html
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16"><path d="Z0"/></svg>
```

Expected on a vulnerable client: render thread never returns; native heap
grows (observed 128 MiB `vector<op_t>` doubling, then a 256 MiB request)
until app OOM/ANR. No crash signature is guaranteed; logcat may show
`lowmemorykiller`/`OutOfMemoryError` or a native abort on `bad_alloc`.

### 8.2 `<use>` fan-out

`evidence/fanout7x8.html` is 1,201 bytes and does 2.1M rect draws on the
host in 2.38 s. Nine levels (134M draws) is >4 minutes at the same rate;
ten levels (1.07B) is hours. All levels are profile-valid and under 4 KB
compressed.

### 8.3 iOS data-URI SVG (client divergence, live on iOS)

The iOS client allows `data:image/svg+xml` (VENDOR.md edit 5; the draft
profile marks `img-svg` OK on iOS), while `profile-v1.md` marks it out.
On iOS:

```html
<img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><path d='Z0'/></svg>">
```

reaches `LHCreateSVGImage` -> `LHDocument` (litehtml) -> the same
`el_svg` loop. The payload is not passed through the HTML sanitizer, but
`LHCreateSVGImage` caps the markup at 2 MiB, the box at 16384 pt, and the
bitmap at 4096². This is a real iOS DoS route and also feeds the queued
SVG fuzz corpus. Android is not affected by this route.

---

## 9. Heavy fuzzing plan — approved but reduced and queued (not started)

The quick passes were: canonical unpatched replay + 150 s ASan; patched
canonical 190 s; iOS replay 316 runs; update 120 s. They are enough to
find the obvious DoS but not enough for a deep OOB/UAF search. No heavy
SVG fuzz has been started.

The reduced plan is queued, not running. Current worker allocation from
the orchestrator: **litehtml 2 + CSS 1 = 3 total**; the QuickJS run gets
2 slots after the litehtml 4 h run; the SVG targets will be scheduled
later with **max 2 workers**, `-rss_limit_mb=1536`, and
**first-ASan-crash stop**. **No new workers were started by this SVG
subagent.**

Queued targets (in order, later):

1. `harness/fuzz_svg_patch` — canonical with the lab `Z0` guard, so the
   run does not spend its budget on the known infinite loop.
2. `harness/fuzz_svg_ios` — the 2,161-line iOS fork.
3. `harness/fuzz_svg_update` — two-frame in-place patches.

Run shape when the slot arrives: **max 2 workers**, one target at a time,
`-rss_limit_mb=1536`, `-timeout=10`, first ASan report saved and the run
stopped. No `-fork=4`, no 12 h block, and no new worker while the current
3-slot allocation is active. Corpus: `seeds/` and `seeds_update/`, plus
the SVG token dictionary and the arithmetic edge seeds
(`evidence/arc_inf.html`, `evidence/inf_coords.html`,
`evidence/inf_viewbox.html`); the known `Z0`/fan-out seeds stay out of the
patched target. The iOS `LHCreateSVGImage` data-URI route is not covered
by the Linux litehtml harness (it needs the Objective-C host); that route
is analyzed statically in §6.12/§8.3.

Success criterion: any ASan `heap-buffer-overflow`,
`heap-use-after-free`, `stack-use-after-return` in an `el_svg` /
`svg_*` frame with a minimal HTML input; otherwise the negative stands.

`HTML-01` has been handed to the litehtml/HTML owner; it is not part of
this queued SVG run.

---

## 10. Method / prior-art notes

Methods used and recommended for the next pass:

* **Source-first audit** of `el_svg.cpp`, `document.cpp` SVG holes,
  `css_effects.cpp` path producers, and the C++ display-list consumers.
* **Differential source analysis**: Android canonical `759fcaf` vs iOS
  vendored 2,161-line copy; `VENDOR.md` edits 38/58/72 and commit
  `9af7d02` are an explicit patch log. This is how SVG-02 was found
  (Android lacks the iOS use budget).
* **Binary/source binding**: xref of the `LH_SVG_LATE_CACHE` string to
  `el_svg::draw` and the `cmp w21,#8` in `draw_use`; avoids auditing the
  wrong fork.
* **Focused libFuzzer/ASan**: raw inline-SVG HTML, direct DOM walk, every
  public SVG query, hit testing, paint; plus a two-frame update harness.
* **Known-CVE analog mapping** (used as hypotheses, not as findings):
  * nanosvg #184 / #178 (`nsvg__curveBounds` / point-count mismatch):
    exactly matched the bundled iOS copy → SVG-03.
  * Qt CVE-2026-79616 (path string OOB read): the same class as a
    path-parser length bug; our parser is NUL-terminated and bounds-safe.
  * Qt CVE-2026-6210 (marker/mask type confusion + heap overflow):
    markers/masks are profile-out and not implemented by `el_svg`.
  * librsvg CVE-2026-96889 (XInclude duplicate entity UAF): litehtml
    uses Gumbo, no XInclude/XML entity layer; not applicable.
  * WebKit SVG `<use>`/clip UAFs: our `use_hosts` holds strong
    `element::ptr` for each use; only fan-out is unbounded.
  * litehtml issue #423 / the existing LT table bug: already covered by
    `notes/rce_candidate_lt_20261108.md`; not SVG.
* **OSS-Fuzz/OSV**: no litehtml OSV entry or SVG-specific litehtml
  advisory was found; the widget fork is not in OSS-Fuzz. The nanosvg
  corpus is the one directly reusable known-bug corpus.
* **Patch analysis** of nanosvg `e7f5981` is the highest-value next
  source-level step for the iOS `Svg` module; for the widget path, the
  next value is a deeper `use`/cache/update fuzz with the guard applied.

---

## 11. Reproduction commands (host)

```bash
# canonical Android branch
cmake -G Ninja lab/rce_candidates/lt/src/litehtml_telegram \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_FLAGS='-g -O1 -fsanitize=address' \
  -DCMAKE_C_FLAGS='-g -O1 -fsanitize=address'
ninja -C <build> litehtml
clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address \
  -I<src>/include -I<src>/include/litehtml -I<src>/gumbo-include \
  lab/lib_hunt_svg/harness/fuzz_svg.cpp <build>/liblitehtml.a -lm \
  -o lab/lib_hunt_svg/harness/fuzz_svg_canon_asan

# SVG-01
ASAN_OPTIONS=detect_leaks=0 lab/lib_hunt_svg/harness/fuzz_svg_canon_asan \
  -runs=1 -rss_limit_mb=256 lab/lib_hunt_svg/evidence/min_z0.html

# SVG-02 (host timing)
ASAN_OPTIONS=detect_leaks=0 lab/lib_hunt_svg/harness/fuzz_svg_canon_asan \
  -runs=1 -timeout=10 lab/lib_hunt_svg/evidence/fanout7x8.html

# SVG-03
clang -fsanitize=address -g -O1 \
  -I iOS/submodules/Svg/LegacyImpl/Sources \
  lab/lib_hunt_svg/harness/poc_nanosvg.c \
  iOS/submodules/Svg/LegacyImpl/Sources/nanosvg.c -lm \
  -o lab/lib_hunt_svg/harness/poc_nanosvg
ASAN_OPTIONS=detect_leaks=0 lab/lib_hunt_svg/harness/poc_nanosvg

# SVG-04 (UB, no memory primitive)
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
  lab/lib_hunt_svg/harness/fuzz_svg_canon -runs=1 \
  lab/lib_hunt_svg/evidence/arc_inf.html

# Latent contract (not reachable; documents the primitive)
ASAN_OPTIONS=detect_leaks=0 lab/lib_hunt_svg/harness/poc_path_contract
```

All work is host-only. No device operations were performed for this note.
