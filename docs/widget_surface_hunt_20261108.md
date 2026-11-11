# Widget surface hunt — litehtml HTML/layout (2026-11-08, host-only)

Subagent scope (final): **litehtml HTML tag handling / document–element tree /
box-model and layout algorithms only** — tables, rows/cells, floats/clear,
positioned boxes and containing blocks, inline/block/flex/grid layout,
background/box geometry at the layout level, layout recursion, and the tag
handlers (`el_table`, `el_div`, `el_img` geometry, `el_td`, `el_tr`, …).

Deliberately **not** covered here (separate agents own them; not duplicated):
CSS parser / property layer, SVG painting, images/data-URI decoders,
canvas/DOM/bridge/JNI, Lottie/TGS, fonts/FreeType.

Targets: Android `libtmessages.49.so` 72889/72929 (the litehtml strings match
the canonical `TelegramMessenger/twidget` fork, and the layout-cache/template
`getenv` strings below prove the analysed code is shipped), iOS
`TelegramUIFramework` 13.2 (36535) LiteHTML.

Constraints honoured: host-only; no device, Frida, bot or payload delivery;
Pixel crash-log-only; iPhone/Sony untouched; no shared notes edited; own note,
lab dir and facts file.

Lemmalog handoff: `notes/LEMMALOG_FACTS_widget_surface_20261108.txt`.
Lab artefacts: `lab/widget_surface_hunt/`.

---

## 0. Verdict (short)

**No unreported memory corruption was found in the widget-reachable surface.**
After a source audit of the layout/tree code, a 495-document semantic-extreme
matrix, 10,594 single-edit document-update pairs, and 718 grammar-generated
layout-stress documents, all under ASan+UBSan — and the corpora again under a
`_GLIBCXX_ASSERTIONS` build that aborts on any
`std::vector`/`std::list`/`std::map` `operator[]` or iterator misuse — there is
**no OOB, UAF, type confusion or length/pointer bug reachable from widget
HTML**.

The approved fuzz did find one genuine memory-safety defect in the litehtml
fork — **HTML-01**, a stack-use-after-return *read* in the updatable-document
API — but it is **not reachable from the shipped widget engine** (the renderer
always serialises a ≥54-byte document, above the SSO capacity) and **not
present on iOS**; analysis in §4.5. It is read-only and has no primitive.

What the campaign produced, all logged below:

| id | finding | class | novelty | carrier? |
|---|---|---|---|---|
| **HTML-01** | `update_structure()` parses from a stack-local string and swaps it into `m_text`; for SSO documents the Gumbo `original_tag` pointers dangle and a later diff reads them in `element_name()` | stack OOB read (UAR), read-only | **new/unreported**; not widget-reachable, not iOS | no |
| **LH-D1** | Nested-table layout is exponential (ASan): 5 levels 42 ms, 10 levels 758 ms, 15 levels **>15 s**; release: 15 levels **7.96 s**, 16 levels **>20 s**, from a **522-byte** widget document, no JS | CPU DoS (UI-thread ANR) | new minimal characterisation of the known F3 nesting class (exact scaling measured) | no |
| **LH-D2** | Nested-flex layout: ASan 10 levels **10.1 s**; release 12 levels **17.4 s**, 13 levels **>20 s**, from a **347-byte** document | CPU DoS | same class as the prior flex-recursion timeouts, now minimal | no |
| **LH-N1** | `line_box::new_width()` never advances the removal iterator → infinite loop + unbounded `ret_items` growth (upstream fix `7ea29569` absent) | DoS (source-level) | **n-day**; reachability analysis says the caller is effectively dead in this fork → no host reproducer | no |
| **LH-N2** | `repeat_color_points()` loops on zero/tiny gradient period → 1.25 GiB+ allocation (upstream fix `ead904b7` absent) | OOM/DoS (paint-adjacent) | **n-day** | no |

Two UBSan diagnostics were observed in **CSS-property** code (out of this
scope, handed to the CSS owner): custom-property `string_id` values outside
the enum range (benign by design — ids are indices into a global name table)
and `z-index: 2147483647` float→int overflow (benign UB). Neither is memory
corruption; see §5.5.

**Honest overall answer to the 0day goal:** the layout surface of this fork is
memory-safety clean for the tested space, and the two DoS classes are not
carriers (no write, no controlled data). A layout 0day was **not** found here.

---

## 1. What was audited (code-level)

Canonical source: `lab/qjs_fork_audit/twidget-canonical` (commit
`759fcafe90fc6c5ffac400b3bab451b4cc8b4947`, 2026-11-05), litehtml under
`litehtml/`. The fork is **not** a thin upstream copy: of the layout files
checked, only `formatting_context.cpp` is byte-identical to an upstream blob;
`render_item.cpp`, `line_box.cpp`, `render_table.cpp`, `document.cpp`,
`html_tag.cpp`, `render_block.cpp` all carry Telegram modifications. The
unique fork code is exactly where the risk is, so it got the deepest reading:

* **Document/element tree**: `document::createFromString`,
  `createUpdatableFromString`, `update_from_string` → `update_from_template` /
  `apply_template_values` / `update_styles` / `update_holes` /
  `update_structure`, `build_template`, `restyle_after_patch`,
  `replace_text_renderers`, `fix_tables_layout`, `fix_table_parent`,
  `fix_table_children`, `create_node`, `build_render_tree`.
* **Layout core**: `render_item::render/measure/relayout/mark_layout_dirty`,
  `layout_entry` cache (`m_last_layout`, `m_measured[2]`),
  `relayout_boundary`, layout epoch/dirty tracking, `m_layout_marked`,
  `m_relayout_roots`, `m_layout_before` snapshots,
  `render_item_block::place_float`, `render_block_context`, `split_inlines`,
  inline splitting into anonymous blocks, `line_box::{finish,new_width,
  reorder_bidi,place_inline,apply_vertical_align}`, `formatting_context`
  float lists, `render_item_table::{init,resolve_collapsed_borders,_render}`,
  `table_grid::{add_cell,begin_row,is_rowspanned,finish,distribute_width,
  calc_table_width,calc_fixed_table_width,calc_horizontal_positions,
  calc_vertical_positions}`, `render_item_grid` (tracks, placement,
  occupancy), `render_item_flex`/`flex_line`/`flex_item`, tag handlers
  `el_table`, `el_td`, `el_tr`, `el_div`, `el_body`, `el_image` (geometry
  only), anonymous table-box construction, sibling-index selector cache.

Binary proof that this code ships (Android 72929 lib, SHA-256
`f2178927…707534`): `LH_NO_LAYOUT_CACHE`, `LH_LAYOUT_CACHE_CHECK`,
`LH_NO_TEMPLATE`, `LH_NO_STRUCTURE`, `LH_NO_PATCH_REGIONS`,
`LH_NO_KEEP_TREE`, `LH_NO_INPLACE_TEXT`, `LH_NO_SAME_SIZE_TEXT`,
`LH_NO_SHALLOW_WIDTH_PATCH`, `LH_NO_SIBLING_INDEX`, `LH_NO_SVG_GROUP_CACHE`
are present exactly once each. iOS 13.2 `TelegramUIFramework` has
`LH_NO_LAYOUT_CACHE` and `LH_LAYOUT_CACHE_CHECK` but **not** the
template/patch strings (see §7).

---

## 2. Builds and harnesses (all in `lab/widget_surface_hunt/`)

```
build_litehtml.sh          canonical fork, clang 19, ASan+UBSan (recover on UB)
build_litehtml_stl.sh      same + -D_GLIBCXX_ASSERTIONS (libstdc++ hard checks)
build_litehtml_rel.sh      -O2 release (timing)
src/render_harness.cpp     file or NUL-separated batch; createFromString,
                           render(800), draw, render(320), draw; TW_DEBUG dumps
                           the element tree; TW_DOC_TRACE prints "doc N" before
                           each batch item so a crash names its input
src/update_harness.cpp     A \x01 B pairs: createUpdatableFromString(A),
                           render, update_from_string(B), render/draw ×3
gen_corpus.py              495 semantic-extreme docs in 94 groups
gen_update_pairs.py        10,594 single-edit DOM-update pairs over 13 bases
gen_layout_stress.py       grammar-generated valid box/table/float/flex/grid trees
```

All runs used `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:
hard_rss_limit_mb=5000..6000` and `UBSAN_OPTIONS=halt_on_error=0`.

### 2.1 Method notes from public research (what was used)

* **litehtml has no public memory-safety CVE.** The GitHub tracker (54 issues)
  has two crash reports: #454 `prescan_a_byte_stream_to_determine_its_encoding`
  (fixed 2026-06-11, before the vendored snapshot; encoding layer, not layout)
  and #463 (Windows/mingw build). #451 is a layout-performance report. So
  there is no n-day list to diff against; the fork's own code has to be read.
* **Browser layout CVEs are bug-*class* guidance, not code to port.** The
  recurring classes are: exponential/quadratic table layout passes (the
  LH-D1 class), float-list mutation and stale float boxes, anonymous
  inline/block box splitting around block children, containing-block
  re-resolution during positioned layout, and stale layout/damage caches.
  Every one of those was mapped to its litehtml function and exercised with a
  valid-structure generator rather than byte mutation (byte fuzzers rarely
  build coherent table/float/inline trees).
* **Fuzzing-method lessons applied:** (a) semantic-extreme value corpora
  instead of byte mutation (INT_MAX/±1/1e38/0/negative/percent/calc for every
  layout-active property); (b) valid-pair differential input for the in-place
  patch path (A→B differs by one edit, as the widget's DOM does); (c)
  `_GLIBCXX_ASSERTIONS` as a second oracle because ASan misses
  `operator[]`-past-`size`-but-inside-`capacity` bugs, a normal shape in
  vector-based layout code; (d) libFuzzer/OSS-Fuzz style is reserved for the
  approval-gated plan (§7), not run in-session.


---

## 3. Campaign results (numbers)

| campaign | input | result |
|---|---|---|
| Semantic-extreme matrix | 495 docs / 94 groups (table spans 0/±1/1000/1001/INT_MAX/1e38, percentage/negative/calc widths, `repeat(1000)`, grid spans/lines, floats, absolute/fixed offsets, margins/padding/indent INT_MAX, line-height 0/huge, border radii, transform/filter extremes, `var()` cycles/depth, long/rtl/emoji text) — **ASan+UBSan** | `logs/run_*.err`: **0 ASan reports, 0 memory UBSan**. Non-memory UBSan diagnostics in 5 groups, all enum-range/float→int in CSS parsing (§5.5). Terminal conditions only: the known gradient repeat OOM (3 groups) and two layout CPU timeouts (`table_nested`, `flex_nested`, see §4). |
| Same matrix, **`_GLIBCXX_ASSERTIONS`** build | 58 groups | **0 assertion failures**. 53 groups rc=0; 3 groups hit the gradient OOM RSS cap; `table_nested`, `flex_nested` timed out at 60 s. `logs/stl_*.err`. |
| In-place document patch | 10,594 A→B pairs (text, style add/remove/replace, class, SVG geometry attr, child append/remove, 2-edit pairs), create+3 update rounds each — **ASan+UBSan** and **STL-assert** builds | **0 reports**, `batch pairs=10594` both builds (`logs/update_pairs.err`, `logs/stl_update.err`). |
| Grammar layout stress | 4,000 generated docs; the run was stopped by the operator at doc 718/4000 | **0 ASan/UBSan reports in 718 docs** (`logs/layout_stress1.err`, saved as `evidence/layout_stress_partial_718docs.err`). Not restarted per the instruction that cancelled it; the remaining 3,282 are in the heavy-fuzz plan (§8). |
| Approved libFuzzer, **worker A** (raw HTML, ASan) | 676 seeds, `-fork=1`, 4 h budget; **stopped by the operator at 03:23** after ~10 min of child time | max coverage **35,172** edges / 206,965 features, corpus **3,178**, 23,175 units in the last job, **0 artefacts** (`logs/fuzz_paint.log`) |
| Approved libFuzzer, **worker B** (in-place update, STL-assert) | 3,000 seeds, `-fork=1`; run 1 155 s, run 2 67 s; **stopped by the operator at 03:23** (not restarted) | found **HTML-01** (`crash-ccd81be40f9fe891b76407aae98f2170b9492235`); 1 OOM + 1 timeout artefact; max cov 33,645, corpus 2,850 (`logs/fuzz_update_run1_crash.log`, `logs/fuzz_update.log`) |

The negative is consistent with the earlier canonical campaigns (raw HTML,
paint, update, SVG/effects, debug-STL replay) recorded in
`lab/qjs_fork_audit/TRIAGE_20261107.md`; this campaign adds the semantic
number-space and the patch-pair corpus those runs did not generate.

---

## 4. Bugs logged

### 4.1 LH-D1 — nested tables: exponential layout work, UI-thread DoS

Minimal trigger (`html/dos_nested_tables_15.html`, **522 bytes raw / 52 bytes
zlib-9**, ~1.4 KiB raw for 40 levels — both far below the widget's 32,768-byte
raw HTML limit and the 4,096-byte zlib-9 payload limit):

```html
<html><body>
<table><tr><td><table><tr><td>… x15 …</td></tr></table></td></tr></table> …
</body></html>
```

Measured on the canonical fork, ASan+UBSan `-O1` (`logs/dos_scaling_tables_flex.txt`):

```
ASan table n=5   rc=0      42 ms
ASan table n=10  rc=0     758 ms
ASan table n=15  rc=124 15048 ms (15 s timeout)
ASan table n=20  rc=124 15111 ms
ASan table n=25  rc=124 15119 ms
ASan table n=30  rc=124 15108 ms
```

and on the `-O2` release build (no sanitizer overhead):

```
REL  table n=11  rc=0     140 ms
REL  table n=12  rc=0     451 ms
REL  table n=13  rc=0     664 ms
REL  table n=14  rc=0    1621 ms
REL  table n=15  rc=0    7962 ms     <- 522-byte document
REL  table n=16  rc=124 20007 ms (20 s timeout)
```

Growth is exponential, not polynomial: 5→10 levels is ~18× (ASan) and each
added level after 12 multiplies the time ~2-4× in release. Cause: each nested
table is measured and re-rendered through the parent cell's min/max-content
passes (`render_item_table::_render` → cell `render()` twice, `render_table`
row/column distribution over the grid), so nesting multiplies the passes. The
table-cell budget (`max_table_cells = 200000`, `document.h:154`) does not bound
this: the cost is per-pass, not per-cell.

Impact: plain HTML/CSS (no `<script>`) inside a widget makes layout run for tens of seconds to minutes. `JniBackend`/`Renderer` calls happen on the Android main thread
("every call happens on the Android main thread" — `platforms/android/jni.cpp`),
so this is a UI-thread ANR/watchdog kill, and on iOS the same layout runs on
the main thread. Widget-level DoS only: it writes nothing, and the widget
engine's own CPU/wall limits gate **JS**, not native layout. Novelty: this is
the "F3 deep nesting" hypothesis from `notes/twidget_native_audit.md` with the
first exact scaling and a minimal in-profile trigger; not a memory bug, not an
RCE carrier.

### 4.2 LH-D2 — nested flex: >10 s from a 347-byte document

Trigger `html/dos_nested_flex_10.html` (347 bytes raw / 61 bytes zlib-9): ten
nested `<div style="display:flex">` around one text node. Measurements:

```
ASan flex n=5   rc=0      71 ms
ASan flex n=10  rc=0   10079 ms      (10 s cap was just met)
REL  flex n=10  rc=0     562 ms
REL  flex n=11  rc=0    4929 ms
REL  flex n=12  rc=0   17397 ms
REL  flex n=13  rc=124 20004 ms (20 s timeout)
```

Same class as LH-D1: `render_item_flex::_render_content` → `flex_line::init`
→ `render_item::render` recursion re-measures every nested flex container.
Prior campaigns saw this only as fuzzer timeouts
(`artifacts_canon_update` backtraces); this is the minimal reproducer. DoS
only.

### 4.3 LH-N1 — `line_box::new_width()` non-advancing removal loop (n-day)

`line_box.cpp:1001-1008` still has:

```cpp
while(remove_begin != m_items.end())
{
    ret_items.emplace_back(std::move(*remove_begin));   // never ++remove_begin
}
m_items.erase(remove_begin, m_items.end());             // never reached
```

Upstream fixed this in `7ea29569` ("Fix item removal loop in
`line_box::new_width`", 2026-10-26); the shipped vendored snapshot predates it.
Consequence: infinite loop, `ret_items` grows without bound (the moved-from
`unique_ptr`s are null) → unbounded allocation/OOM. **n-day DoS.**

**Reachability note (new, important):** a host reproducer was *not* obtained,
and the call graph explains why. The only caller is
`render_item_inline_context::fix_line_width()` (`render_inline_context.cpp:313`),
reached from `render_block.cpp:50` as `fix_line_width(...)` on the **block that
places a float** (`this`), not on the float. `render_item_inline_context`
overrides it, but an inline context does not place block-level floats; an
inline float takes `render_inline_context::new_box()` →
`formatting_context::place_to_left()` and never re-wraps the previous line.
Four float/line constructions were tried with an 8 s cap (`/tmp/f1..f4.html`,
all rc=0). So the known source-level DoS is most likely **dead code in this
fork**, which matches the earlier campaign's "standalone reproducer was not
obtained". Keep it as an n-day to re-check if a future build changes the
`fix_line_width` dispatch.

### 4.4 LH-N2 — `repeat_color_points()` zero/tiny period OOM (n-day)

`background.cpp:760-780` (background-layer creation at paint time; listed here
because it is reached from the same widget HTML/CSS document and was hit by the
layout corpus):
`gd_size ≈ 0` or a tiny positive period makes the stop-expansion loop append
colour points without bound. Upstream fixed the zero/negative/non-finite case
in `ead904b7`; the shipped fork predates it, and the tiny-positive case is not
covered by the upstream fix either. Host evidence in this campaign: the
`bg_known_oom`, `bg_gradient_period`, `bg_radial` groups each abort at the
5–6 GiB RSS cap in ASan (`logs/run_bg_*.err`, `logs/stl_bg_*.err`); the earlier
canonical campaign minimised it to
`<div style="width:1000000000px;height:10px;background:repeating-linear-gradient(45deg,red 0 10px,blue 10px 20px)">`
with `malloc(1342177280)`. **n-day DoS**, no memory write.

### 4.5 HTML-01 — stack-use-after-return read in `element_name()` during structural patching

Found by the approved fuzz worker B after 231 executed units / 155 s
(`artifacts_update/crash-ccd81be40f9fe891b76407aae98f2170b9492235`); the SVG
agent independently reported the same defect (`lab/lib_hunt_svg/`,
`crash_upd_crash-*`, `logs/fuzz_update_120s.log`). It is not SVG-specific.

| field | value |
|---|---|
| **class** | stack-use-after-return **read** (OOB read of a dead stack frame), read-only |
| **root cause** | `document::update_structure()` copies the new HTML into a stack-local `std::string text = html;` (`document.cpp:1848`) and parses gumbo from `text.data()`. Gumbo stores `GumboStringPiece original_tag`/`original_text` pointers into that buffer. At the end it does `m_text.swap(text)` (`document.cpp:2316`). For documents that fit std::string's small-string buffer (libstdc++ ≤15 B; libc++/NDK ≤22 B), `swap` exchanges the *contents* of the two inline buffers, not the buffer pointers, so the `GumboOutput` keeps pointers into the stack frame that dies on return. |
| **trigger** | create + two updates with unknown tags: `create <div>a</div>` (12 B) → `update <x>a</x>` (8 B) → `update <y>a</y>` (8 B). The second update's diff compares the previous update's `<x>` node with the new `<y>` node; both are `GUMBO_TAG_UNKNOWN`, so `same_element_kind()` calls `element_name(a)`, which reads `original_tag.data[0]`/`[len-1]` from the dead frame (`document.cpp:173`, inside the `same_element_kind` comparison at `document.cpp:186`, reached from the diff at `document.cpp:2024/2039`). |
| **ASan** | `READ of size 1 ... stack-use-after-return`, address inside the dead `update_structure` frame's `text` SSO buffer, stack `same_element_kind (document.cpp:186) -> diff (2024/2039)`; `element_name` is inlined in this build (the SVG agent's log shows it as the symbol at `:173`). Evidence `evidence/html01_asan.log` and `evidence/html01_asan_gcc.log`. Deterministic with `ASAN_OPTIONS=detect_leaks=0:detect_stack_use_after_return=1 ./build/uar_repro '<div>a</div>' '<x>a</x>' '<y>a</y>'`. |
| **release effect** | no fault (the same thread's stack stays mapped). Step 3 reports `changed=0`: the `<x>`→`<y>` tag change is silently ignored because the stale bytes compare equal. Functional consequence only, and only for unknown tags. |
| **primitive** | **none**. Read-only; 1–2 bytes plus a `string_view` compare bounded by the old tag length; the value only decides an equality between two unknown tag names. No pointer or length is derived from it, and there is no attacker-visible output channel. |
| **tag domain** | **stack**, not heap. Scudo/MTE tags do not cover the stack, so MTE-on neither detects nor prevents it; detection is ASan-only. |
| **widget reachability** | **none** (verified). `update_from_string` is called only by `Container::build`; `html_` is assigned only by `Renderer::serialize()` (`core/src/renderer.cpp:3171`), which always begins `<!DOCTYPE html><html…` and always emits head and body → minimum 54 B, above the NDK libc++ SSO capacity 22 → heap string → the swap moves pointers → Gumbo stays valid. The Android JNI `create()` takes only width/dpr/theme/backend (`platforms/android/jni.cpp:258`); widget HTML arrives as JSON ops via `receive()`. |
| **iOS** | **not applicable**: iOS 13.2 LiteHTML has no `update_from_string`/`update_structure` (grep empty in `tgwidget-src`) and the `TelegramUIFramework` binary has no `LH_NO_TEMPLATE`/`LH_NO_STRUCTURE` strings; it parses from `m_text.data()` directly (`document.cpp:2127`). |
| **unknown tags** | Custom elements, and most SVG tags: vendored gumbo 0.10.1 has 153 tag enums; a probe shows `<g/>` inside `<svg>` = tag 153 (`GUMBO_TAG_UNKNOWN`, SVG namespace) and `<x>` = tag 153 (HTML namespace). The reliable PoC uses custom elements; in the tested SVG sequence the diff rebuilt the svg subtree before comparing g/u, so it did not reach `element_name`. |
| **evidence** | `evidence/html01_{asan.log,asan_gcc.log,release.log,trigger.txt,reachability.txt,fuzz_artifact.bin,fuzz_asan_excerpt.log}`, `src/uar_repro.cpp`, `artifacts_update/crash-ccd81be4…`, `logs/fuzz_update_run1_crash.log`. |
| **status** | new/unreported litehtml library bug; host PoC; **not** a widget 0day; logged per instructions. |

---

## 5. Dead ends (valuable negatives — do not re-spend time)

### 5.1 `fix_table_parent()` null-parent dereference is unreachable

`document.cpp:3694-3700` does `auto parent = el_ptr->parent();` then
`parent->src_el()` with no null check, and `parent()` returns
`m_parent.lock()` (a **weak_ptr**), so a parentless table-part render item
would be a null dereference. The only parentless render item is the root
(`create_render_item(nullptr)`). However CSS 2.2 §9.7 rule 4 is implemented in
`css_properties.cpp:143-155`: the root element's display is **blockified**
(`table-row`/`table-cell`/`table-row-group`/`table-caption`/`inline-block`/
`list-item`/… → `block`). Host check: `<html style="display:table-row">`,
`…table-cell`, `…table-row-group`, `…table` and the `<style>html{…}</style>`
variants all render rc=0 with root `display=1 (block)` for every table-part
value (root `table` stays `display=6`, whose fix-up path never uses the
parent); transcript `evidence/root_blockification.txt`, files
`html/root_*.html`. So the null-parent path cannot be reached from HTML.
**Dead end, not a bug.**

### 5.2 `m_relayout_roots` raw pointers vs `replace_text_renderers`

`document::m_relayout_roots` is a `std::vector<render_item*>` filled by
`render_item::mark_layout_dirty()` when an ancestor satisfies
`relayout_boundary()` (`contain:size` + BFC, `render_item.cpp:156-168`) and
consumed in `document::render()` (`document.cpp:3141-3143`). The in-place text
patch destroys render items in `replace_text_renderers()`
(`document.cpp:1503-1539`): it purges `m_layout_marked` for the destroyed
children but **not** `m_relayout_roots` — a stale raw pointer there would be a
UAF with a virtual `relayout()` call. Reachability: the destroyed children are
the `el_text`/`el_space` render items of one inline context; a relayout root is
always an *ancestor* of the dirtied item (the code skips `item == this`), and
the only destroyable children are text render items, which cannot own
`contain:size`. The root therefore outlives the replacement in every
construction tried (text inside `contain:size` inline-blocks, nested inline
spans, sibling text edits; 10,594 update pairs + a dedicated reasoning pass).
**No UAF, but the invariant is fragile** — if a future patch ever destroys a
non-text child here, `m_relayout_roots` must be purged too. Recorded as a
hardening note.

### 5.3 Table/grid index arithmetic re-verified

* `table_grid::add_cell` clamps `colspan`/`rowspan` to `[1,1000]` after
  `atoi` (`table.cpp:11-24`) — the known LT fix is present (independently
  re-read).
* `row_count`/`column_count` derivation, `place_cells` occupancy, and the
  `columns[c]`/`rows[r]` loops in `render_grid.cpp` (lines 600-720) stay in
  bounds because `placement.start/end` are clamped to ±1000 and
  `repeat()` count to 1000 (`css_effects.cpp:1232`,
  `render_grid.cpp:88`). Host: `grid_span`, `grid_line`, `grid_rows_huge`,
  `table_*` groups, all clean under ASan and STL assertions.
* `table_grid::finish` pads every row to `m_cols_count` before the
  `cell(col,row)` double loop; `cell()` bounds-checks; `calc_*` vectors are
  sized `n = m_cols_count`; `last_auto` is always set when used.
* `is_rowspanned` bounds-checks `c < m_cells[row].size()`; the filler loop is
  bounded by ≤1000 per cell; `max_table_cells = 200000` caps the grid.

### 5.4 Selector sibling-index cache

`html_tag.cpp:1937-1965` caches per-parent child indexes keyed by
`element*`; entries are invalidated by `g_apply_pass` and the map is cleared
when a style-application scope starts (`apply_scope`, `html_tag.cpp:220-227`),
so no stale pointer survives a pass. Dead end.

### 5.5 UBSan diagnostics observed (CSS-property/selector domain, out of scope)

* `style.cpp:428/433`, `css_selector.cpp:13/691/696`, `html_tag.cpp:436`:
  `load of value 512, which is not a valid value for type 'string_id'` for a
  200-deep `--vN: var(--vN+1)` document and for 5,000 generated rules. Custom
  property ids are indices into the global `_id` deque and legitimately exceed
  the enum (`string_id.cpp:49`); the code only uses them as map/set keys and
  for `_s()` on ids it created. Benign. Side observation (CSS owner): the
  global `_id` map/deque and the 50,000-entry declaration cache are never
  trimmed, so many unique custom-property names grow process-wide memory
  across widgets — a slow DoS, not memory corruption.
* `css_properties.h:457` (`z-index: 2147483647`) and `css_effects.cpp:1232`
  (grid line/span `2147483647`, clamped to ±1000 on the next statement):
  float→int UB. Benign; no index or length follows the conversion before the
  clamp.

---

## 6. Tag domain / MTE / iOS applicability

Every bug in scope lives in the **litehtml C++ heap**, never in the QuickJS
arena:

* Small objects (`render_item`, `table_row` 56 B, `table_column` 36 B,
  `pixel_t` vectors, `html_tag`) are Scudo **primary** allocations
  (< 64 KiB) → **tagged** under MTE, adjacent chunks get different tags
  (odd/even tuning) → a cross-allocation OOB/UAF faults (`SEGV_MTESERR`).
* Large vectors (`m_rows` = 56·N, `m_columns` = 36·M, line-item arrays over
  ~64 KiB) become Scudo **secondary** (mmap) allocations; on the measured
  Pixel 9 Android 17 smaps most secondaries are untagged (11/106 carry an
  8 KiB `PROT_MTE` prefix), so a pointer with tag 0 into them is not checked —
  but the target is then allocator data, not a controllable field.
* There is **no tag-0 arena equivalent** for litehtml (the v7/N1 tag-safe
  domain is QuickJS-only), so a litehtml bug is **MTE-off by construction**,
  exactly like the parser 0day (`b->vardefs`): it needs a non-MTE target or a
  same-chunk primitive. A same-chunk field overwrite (write inside the same
  `render_item`/`table_column` allocation) is the only shape that could be
  MTE-safe, and no such bug was found.
* iOS: stock Telegram 13.2 has no
  `com.apple.security.cs.checked_allocations`/MIE entitlements (evidence in
  `notes/MTE_safe_hunt_20261107.md` §5.2), so Apple malloc is not tag-checked
  and a C++ heap bug would apply to the iPhone *if* one existed. The layout
  engine is present in `TelegramUIFramework` 13.2 (36535) and carries the
  **layout cache** (`LH_NO_LAYOUT_CACHE`, `LH_LAYOUT_CACHE_CHECK`), but the
  string set shows **no template/in-place patch machinery**
  (`LH_NO_TEMPLATE`, `LH_NO_STRUCTURE`, `LH_NO_KEEP_TREE`,
  `LH_NO_INPLACE_TEXT`, `LH_NO_PATCH_REGIONS` absent), so §5.2 is an
  Android-72889/72929-only path; the layout/table/float analysis applies to
  both.

The DoS bugs (LH-D1/D2/N1/N2) have no write primitive: D1/D2 are pure CPU,
N1 is an unbounded `std::list` growth of null `unique_ptr`s until OOM, N2 is
an unbounded vector of small `color_point` records until OOM. None yields a
controllable length/pointer.

---

## 7. Payload / endgame assessment, and the approved fuzz run

**What a layout bug would need to become an endgame.** A widget-reachable
layout memory bug must (a) be reachable before any JS/CPU limit, (b) give a
write or a forged length/pointer, (c) survive/avoid the engine's own fatal
allocation policy, and (d) be same-chunk (MTE) or accept MTE-off/iOS-only
targets. A cross-allocation OOB from litehtml satisfies none of (c)/(d) on
MTE-on Android: the renderer's C++ allocations are Scudo-tagged and the
process has no tag-0 arena. The realistic endgame for a *found* such bug is
the MTE-off path already used for the parser 0day: corrupt a C++ object to
build an arbitrary read/write in the app process, then reach the JNI/Java
side; on iOS (no MIE) the same primitive would apply directly. For the DoS
bugs above there is no payload: they only deny service; the widget engine's
CPU budget gates JS, not native layout, and no state is corrupted.

**Heavy fuzzing plan — APPROVED and RUNNING with 2 workers** (orchestrator
auto-approval; hard cap 2 litehtml workers + 1 CSS worker = 3 total). The
earlier 4,000-doc grammar run was cancelled at 718 docs and is not restarted as
a corpus run; the approved libFuzzer campaign below replaces it.

### 7.1 Approved run (started 2026-11-08 ~03:13 CET; stopped by the operator 03:23, not restarted)

Both workers ran as one libFuzzer process each in `-fork=1` mode (one child at
a time), with `-timeout=5 -max_len=32768 -rss_limit_mb=2048
-malloc_limit_mb=1024 -ignore_timeouts=1 -ignore_ooms=1 -use_value_profile=1`,
dictionary `layout.dict`, seeds from the campaign corpora. Worker B was
restarted once with `-ignore_crashes=1` after it stopped on HTML-01; both were
then stopped by the operator at 03:23 and were **not** restarted.

| worker | binary / build | harness | seed corpus | result |
|---|---|---|---|---|
| A | `build/fuzz_asan` — canonical litehtml, clang 19, **ASan+UBSan**, coverage (`fuzzer-no-link`) | `lab/qjs_fork_audit/fuzz_litehtml_paint.cpp` (raw HTML parse+render+paint) | `corpus_fuzz/seeds_paint` — 676 docs: all semantic-extreme groups except the 5 known DoS groups, plus 200 grammar-stress docs | ~10 min child time; max cov **35,172** edges / 206,965 features; corpus **3,178**; 23,175 units in the last job; **0 artefacts** |
| B | `build/fuzz_stl` — same + **`_GLIBCXX_ASSERTIONS`** | `src/fuzz_update_pairs.cpp` (A\x01B → `createUpdatableFromString` + `update_from_string` + render/draw, both directions) | `corpus_fuzz/seeds_update` — 3,000 sampled records from the 10,594 single-edit pairs | run 1 155 s → **HTML-01 crash**; run 2 67 s (merge); max cov 33,645, corpus 2,850; 1 crash + 1 OOM + 1 timeout artefact |

Measured memory: parent+child RSS ≈ 0.93–1.5 GB per worker, below the 2 GiB
cap; no host OOM. The two non-crash artefacts were triaged host-side: the
**OOM** record (`oom-80a49076…`, 296 B) aborts at a 3 GB ASan cap after 11.3 s
(unbounded allocation, update path, malformed `float:` style — DoS only, owner
to be decided with the CSS agent); the **timeout** record
(`timeout-eb73d403…`, 223 B) is >10 s CPU in the SVG-path document (DoS only,
SVG owner). Neither yields a write.

Scripts: `run_fuzz_paint.sh`, `run_fuzz_update.sh`, `build_litehtml_fuzz.sh`,
`split_seeds.py`, `layout.dict`.

* Success criterion met by worker B: one genuine ASan artefact (HTML-01, §4.5).
* Final stats above come from `logs/fuzz_paint.log`,
  `logs/fuzz_update_run1_crash.log` and `logs/fuzz_update.log`; the fork-mode
  parent reports zero units of its own, so the counters are those of the last
  child job.

Small/quick runs already done in-session (allowed): the 495-doc matrix,
10,594 update pairs, 718 stress docs, the DoS scaling series, and the dead-end
checks.

---

## 8. Reproduction

```bash
cd lab/widget_surface_hunt
./build_litehtml.sh src/render_harness.cpp src/update_harness.cpp   # ASan+UBSan
OUT=build/litehtml_stl ./build_litehtml_stl.sh src/render_harness.cpp src/update_harness.cpp
OUT=build/litehtml_rel ./build_litehtml_rel.sh src/render_harness.cpp

# DoS scaling (LH-D1/D2)
timeout 15 ./build/litehtml_asan/render_harness html/dos_nested_tables_15.html
timeout 10 ./build/litehtml_asan/render_harness html/dos_nested_flex_10.html

# memory campaigns
ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:hard_rss_limit_mb=5000 \
  ./build/litehtml_asan/render_harness -batch corpus/table_rowspan.bin
ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 \
  ./build/litehtml_stl/update_harness -batch corpus/update_pairs.bin

# dead end: root blockification blocks fix_table_parent null deref
TW_DEBUG=1 ./build/litehtml_asan/render_harness html/root_row.html

# HTML-01: stack-use-after-return read in the updatable-document API
ASAN_OPTIONS=detect_leaks=0:detect_stack_use_after_return=1 \
  ./build/uar_repro '<div>a</div>' '<x>a</x>' '<y>a</y>'

# approved fuzz workers (stopped by the operator; flags as run)
./run_fuzz_paint.sh          # worker A
./run_fuzz_update.sh         # worker B
```

Key artefacts: `logs/dos_scaling_tables_flex.txt`,
`evidence/layout_stress_partial_718docs.err`, `evidence/update_pairs.err`,
`evidence/stl_update.err`, `evidence/html01_*` (HTML-01 ASan/release logs,
trigger, reachability proof, fuzz artefact), `logs/fuzz_*.log` (approved fuzz),
`logs/run_*.err` (matrix), `logs/stl_*.err` (assertion build),
`html/root_*.html` (dead-end proof), `html/dos_nested_*` (DoS repros),
`corpus/` and `corpus_fuzz/` (all inputs).

## 9. Limitations / honesty

* The grammar stress run covers 718/4,000 docs (operator stop). The semantic
  matrix is 495 docs, not an exhaustive value-space sweep; 64-bit fixed-point
  edge cases and combinations deeper than 5 nested layout levels are only
  partially covered.
* No device or MTE hardware was used; the tag-domain statements reuse the
  measured Pixel 9 smaps from `notes/MTE_safe_hunt_20261107.md` and public
  Scudo design, not a new measurement.
* The shipped-binary check is a `getenv`-string fingerprint that the layout
  cache/template code is compiled in, not a byte-for-byte match of every
  layout function (the canonical↔shipped chain is in
  `lab/qjs_fork_audit/REPORT_canonical_chain_20261107.md`).
* The two DoS classes are not new root causes; they are the previously
  hypothesised F3/flex-recursion and the two missing upstream DoS fixes. They
  are logged with exact measurements because the task asks for every bug, but
  they must not be presented as memory corruption or as an RCE.
* The approved fuzz was stopped by the operator at 03:23, well before the 4 h
  budget: worker A after ~10 min of child time, worker B after 155 s + 67 s.
  The coverage/corpus numbers are from the last fork child, not cumulative.
  The campaign therefore extends, but does not exhaust, the mutational space.
* HTML-01 is logged as a memory-safety defect because it is one, but its
  reachability is **none** through the shipped widget renderer (serialized
  document ≥54 B vs SSO ≤22 B on the NDK libc++ build) and it is absent from
  iOS. Do not present it as a widget 0day or an RCE candidate.
