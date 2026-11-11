# NON_RCE.md: non-RCE findings, one line each

The repository is an RCE archive. This page is the one-line index of everything
that is **not** an RCE: DoS, read-only, public n-day references, and rejected
carriers. Single fixtures are in `non-rce/`. The full labs remain in the source archive
named in the pointer.

**WEAKMAP-1835; public n-day, fixed `ebd139b`; DoS only; possible chaining entrypoint (UAF/null deref), no known RCE variant.**

| id | Finding | Class / status | Evidence pointer |
|---|---|---|---|
| WEAKMAP-1835 | WeakMap symbol-value UAF; fixed `ebd139b`; possible chaining entrypoint (UAF/null deref), no known RCE variant | DoS only | `telegramandroidwidget/lab/membug_ledger_20261107/`, `evidence/evidence_20261101/tombstone_13.txt` |
| CSS-01 | root `font-weight:bolder` null deref (`null+0x335`) | new DoS, host-only | `non-rce/css-01-root-font-weight.html` |
| CSS-02 | negative shift in text-decoration parsing | UB only | `lab/lib_hunt_css/` |
| CSS-03 | repeating-gradient OOM (`repeat_color_points`) | n-day DoS | `non-rce/css-03-gradient-oom.html` |
| SVG-01 | `path d="Z0"` infinite loop / vector growth | new DoS, host-only | `non-rce/svg-01-path-z0.html` |
| SVG-02 | `<use>` exponential fan-out, no Android budget | new DoS, host-only | `non-rce/svg-02-use-fanout.html` |
| SVG-03 | nanosvg `nsvg__curveBounds` OOB read, profile only | n-day read-only | `lab/lib_hunt_svg/` |
| SVG-04 | non-finite arc radii float-to-int UB | UB only | `non-rce/svg-04-arc-inf.html` |
| LH-D1 | 15 nested tables, UI-thread ANR | new minimal characterisation | `lab/widget_surface_hunt/html/dos_nested_tables_15.html` |
| LH-D2 | nested-flex layout ANR | DoS | `lab/widget_surface_hunt/html/dos_nested_flex_10.html` |
| WC-1 | `ton_core 0.1.4` BoC underflow, `isValidCellBoc` rejects | n-day, not reachable | `non-rce/wc-1-blocked.log` |
| WC-2 | `HashmapE` dictionary bomb in `StateInit::from_boc` | new DoS, widget tap | `non-rce/wc-2-hashmap-dictbomb.html` |
| WC-2b | `HashmapE` label shift → 2^61-byte allocation | new DoS, widget tap | `non-rce/wc-2b-hashmap-shiftbomb.html` |
| QNH-01 | array length invariant violation | semantic, no memory | `lab/quickjs_new_hunt/`, `notes/quickjs_new_hunt_20261108.md` |
| QNH-06 | `Array.join` CPU-quota bypass (#1753) | public DoS | `lab/quickjs_new_hunt/logs/join_dos_1753.log` |
| QNH-07 | parser native-stack overflow; widget thread is 8 MiB | closed | `lab/quickjs_new_hunt/parser/` |
| D-1 | `textarea.value` parent UAF; validator drops form controls | latent, not shipped | `non-rce/d-1-textarea-uaf.cpp` |
| D-2 | deep shadow-tree recursive stack exhaustion | conditional DoS | `non-rce/d-2-deep-stack.cpp` |
| HTML-01 | stack-use-after-return read in `element_name()`; not widget-reachable | new read-only | `non-rce/html-01-asan.log` |
| F1 | `lre_get_groupnames` UAF read; OOM-poisoned on shipped fork | read-only, not reachable | `lab/rce_candidates/f1/`, `notes/rce_candidate_f1_20261108.md` |
| C1 | `cpool[-1]` 16-byte write; cross-tag, wild free | rejected carrier | `notes/rce_candidate_c1_20261108.md` |
| C2 (bug) | `update_var_htab` mask; 4-byte store, no capability | rejected carrier | `notes/rce_candidate_c2_20261108.md` |
| FR | `FinalizationRegistry.unregister` UAF; no class-96 reclaim | DoS only | `notes/rce_candidate_fr_20261108.md` |
| LT | litehtml table span; clamped `[1,1000]` in shipped builds | negative | `notes/rce_candidate_lt_20261108.md` |
| N2 | `get_closure_var` −1 → `var_refs[65535]`; OOM-unreachable | DoS only | `notes/rce_candidate_n2_20261108.md` |
| #1792/#1826 | `Array.find` double free; teardown SIGABRT | n-day DoS | `notes/bug_inventory_20261105.md` |
| #1855 | lazy prototype OOM null deref | n-day DoS | `notes/audit_fuzz.md` |
| #1852 | `JS_SetPropertyInternal2` OOM value loss | n-day DoS | `notes/audit_parser.md` |
| #1570 | async iterator GC UAF; state reached, no repro | n-day, host-only | `notes/quickjs_new_hunt_20261108.md` |
| #1787 | compiler label leak; debug abort / release throw | n-day DoS | `notes/quickjs_new_hunt_20261108.md` |
| #1518 | deserializer cleanup OOB read; no widget bytecode loader | n-day, host-only | `notes/quickjs_new_hunt_20261108.md` |
| Images | data-URI decode uses platform Skia/ImageIO | negative | `notes/lib_hunt_images_20261108.md` |
| DOM | validator + shadow DOM enforce invariants | negative | `notes/lib_hunt_dom_20261108.md` |
| litehtml fork-only | no controllable write/type confusion | negative | `notes/lib_hunt_fork0day_20261108.md` |
| iOS `wr::` | native C++ DOM/bridge; no concrete bug | negative | `notes/ios_uiframework_hunt_20261108.md` |
| Canvas | Java/Kotlin bounds checks + iOS guards | negative | `notes/lib_hunt_canvas_20261108.md` |
| CSS | no memory corruption; only CSS-01/02/03 | negative | `notes/lib_hunt_css_20261108.md` |
| SVG write | no OOB write/UAF/type confusion | negative | `notes/lib_hunt_svg_20261108.md` |
| QJS-5FIX | five QuickJS-ng fixes missing in 73029/73039 (`3e236cb`, `8f0d3b6`, `3ad65ad`, `7ca4ac5`, `45c5b9b`) | engine bugs; eval OOB is a real OOB pointer read/JSValue write | `lab/g1_hunt_parallel/js_html.md` |

The source archive paths are relative to
`<HOME>/ailocal/Telegram/telegramandroidwidget/` (or
`<HOME>/ailocal/Telegram/` for `notes/`). They are not shipped in this
RCE repository.
