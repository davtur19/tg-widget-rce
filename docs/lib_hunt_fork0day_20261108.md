# Fork-only litehtml hunt — same-allocation write / type confusion (widget HTML/CSS)

Date: 2026-11-08. **Host-only.** No device, Frida, bot or network was used for
the work below. Target scope (per correction): the **widget HTML/CSS rendering
path only** — the Telegram `twidget` litehtml fork (canonical Android source
`TelegramMessenger/twidget@759fcaf`, 2026-11-05) and the iOS vendored fork
(`tgwidget-src` `24638bc`, release-13.2). No media, no app UI, no
non-widget renderer entry, no canvas/JS-bridge.

Companion artifacts: `lab/widget_surface_hunt/newfeat_20261108/`.
Facts: `notes/LEMMALOG_FACTS_fork0day_20261108.txt`.

---

## 0. Verdict (honest)

**No new memory-corruption primitive was found in the reviewed fork-only /
modified litehtml code.** The candidates that were checked and proven
consistent (same-allocation `operator[]` writes, span/line indices, filter
buffers, form-control state, template-hole indices) are listed in §2 with the
exact invariant that holds. There is **no controllable write and no
deterministic type confusion** to hand to a device test from this pass.

The one real delta found is **platform divergence, not memory corruption**:
the iOS internal fork carries hardening budgets/caps that the Android
canonical (and the shipped Android binary, verified in §3) **does not**.
Those differences are DoS/work-amplification class and are explicitly not
promoted as the requested 0day.

This note therefore closes the fork-only-code question as **negative**, with
the reviewed-function list and the reproducible evidence that the shipped
Android `libtmessages.49.so` 72929 contains the canonical template-update
code (`LH_NO_TEMPLATE`, `LH_NO_KEEP_TREE`, … env strings) and not the iOS
internal implementation.

---

## 1. What was compared and executed

Source trees:

| tree | role | identity |
|---|---|---|
| `lab/qjs_fork_audit/twidget-canonical` | canonical Android fork (public) | `759fcafe` (2026-11-05) |
| `lab/qjs_fork_audit/litehtml` | upstream, d2e55e80 extracted to `/tmp/opencode/html01` | `d2e55e80` (2026-10-23) |
| `lab/qjs_fork_audit/tgwidget-src` | iOS app vendored fork | `24638bc` (release-13.2) |

Diffs produced for this audit (kept in the artifact dir):

- `fork_src.diff` — canonical fork vs upstream d2e55e80, 10,470 lines,
  30 changed `.cpp` files (`document.cpp` 2,616 changed lines, `render_item.cpp`
  919, `html_tag.cpp` 758, `style.cpp` 704, …).
- `ios_vs_android.diff` — iOS vendored fork vs canonical, 12,122 lines.

Execution (existing harnesses, canonical fork, no new workers):

```bash
# ASan+UBSan build, 76 fresh render docs
./build/litehtml_asan/render_harness -batch newfeat_20261108/render.bin   # exit 0
./build/litehtml_stl/render_harness  -batch newfeat_20261108/render.bin   # exit 0
# in-place update path, 9 focused pairs + 65 single-edit pairs
./build/litehtml_asan/update_harness -batch newfeat_20261108/update.bin   # exit 0
./build/litehtml_stl/update_harness  -batch newfeat_20261108/update.bin   # exit 0
./build/litehtml_stl/update_harness  -batch newfeat_20261108/update_pairs2.bin  # exit 0
```

The fresh corpus (`gen_newfeat.py`) is aimed at features the earlier corpora
do not cover: `text-overflow: ellipsis` + fragments, `overflow-wrap/word-break`
fragmenting, bidi reordering, `quotes`/`open-quote`/`close-quote`,
`content: attr()/counter`, `clip-path` polygon/inset/circle/ellipse,
filters/transforms, grid spans, and form controls (`input/select/textarea/
meter/progress/fieldset`), plus update pairs changing text/style/attributes
and structure. `gen_update2.py` generates 65 single-edit pairs over those
bases. All logs in the artifact dir are the unedited harness output.

---

## 2. Fork-only / modified code reviewed and the invariants that hold

### 2.1 Fork-only files (`el_form.cpp`, `css_effects.{h,cpp}`, `render_grid.{h,cpp}`; `el_svg.{h,cpp}` is covered by SVG-01/02/03 and not re-audited)

**`css_effects.cpp` (1,250 lines) — all functions read.**
`parse_clip_path`, `clip_path_shape::resolve`, `parse_box_shadow`,
`function_args`, `calc_atom/calc_operator/calc_product/calc_sum/fold_calc`,
`fold_env`, `mix_part/fold_color_mix`, `viewport_axis/fold_math/
has_foldable_math/has_viewport_units(string)`, `filter_reach`, `parse_filter`,
`fast_transform_tokens`, `parse_transform`, `parse_transform_origin`,
`parse_track_breadth/parse_track_size/parse_grid_track_list/
parse_grid_placement`.

- `clip_path_shape::resolve` indexes `values[3]` (inset), `values[radii]`,
  `values[radii+1]` (circle/ellipse) and `values[i/i+1]` (polygon). The only
  producer `parse_clip_path` forces exactly 4 (+optional 5th radius) values
  for inset, exactly 3 for circle, exactly 4 for ellipse and an even
  `size() >= 6` for polygon; every failure path returns `false` and leaves
  `kind == none`. **No under-sized `values` can reach `resolve`.**
- `parse_filter` caps the function list at 32 and drop-shadow at 4 args with
  a 3-slot length array (`x,y,radius`); `parse_box_shadow` uses a 4-slot
  pointer array with `lengths < 4`.
- `calc_*` keep depth ≤ 16 and args ≤ 32; `clamp` requires exactly 3 args;
  `calc_evaluate(index)` bounds-checks the global intern table (index < 0 or
  ≥ `calc_table().size()` → 0). `MAX_EXPRESSIONS = 4096` is a hard stop.
- `fast_transform_tokens` is a hand-written parser over ≤ 512 bytes with a
  32-function / 6-arg cap; it always advances `i` or returns false.
- `parse_grid_track_list` clamps `repeat()` to 1,000 iterations and
  `parse_grid_placement` clamps start/end/span to ±1,000 (span ≥ 0).

**`render_grid.cpp` (943 lines) — all functions read.**
`make_tracks`, `resolve_line`, `resolve_placement`, `occupancy::fits/mark`,
`place_cells`, `size_columns`, `distribute_content`, `is_stretch`,
`align_offset`, `render_item_grid::_render_content`.

The span soundness argument that matters for a same-allocation write:

1. `column_count = max(explicit_columns, 1, max_cell((col≥0?col:0)+col_span))`
   is computed **before** `place_cells` and `columns` is resized to it.
   Therefore for every cell, `col + col_span <= column_count == columns.size()`.
2. `place_cells` only assigns `col` either to its explicit value (bound 1),
   or to a scanned `col` with `col+span <= cols` (bound 1), or to `0` when the
   scan fails (still `0+span <= cols` by the `column_count` bound). So every
   `grid.mark(row, col, row_span, col_span)` writes `m_rows[r][c]` with
   `c < m_cols`; **the bit-packed `std::vector<bool>` write is in bounds**.
3. `size_columns` indexes `tracks[cell.col]` / `tracks[c]` with `c < col+span
   <= columns.size()`; `_render_content`'s `area_width` uses
   `column_x[col+span-1]` with `column_x.size() == columns.size()+1`.
4. `row_count = max(explicit_rows, max_cell(row+row_span))` after placement,
   `std::vector<grid_track> rows(row_count)`, and every `rows[...]` /
   `row_y[...]` index is `< row_count` (`row_y` has `rows.size()+1`).
5. Numeric extremes only reach float pixel math; `static_cast<int>` of a
   non-finite `room/step` is clamped back to `count ∈ [1,1000]`.

**`el_form.cpp` (1,165 lines) — all functions read.**
`date_pattern/format_date`, `append_content/has_generated/textarea_text/
remove_generated`, `colors`, `fill_box/add_rounded/stroke_box/stroke_lines/
draw_chevrons`, `attr_number`, `authored_box/resolve_box/resolve_text/
add_padding/ua_padding/button_padding/field_padding/refresh_active`,
`border_box/inset/draw_bezel/draw_field`, and every `el_input::*`,
`el_select::*`, `el_button::*`, `el_textarea::*`, `el_meter::*`,
`el_fieldset::*` override.

- `format_date` only formats after `value.size() == 10` and
  `sscanf("%4d-%2d-%2d%c") == 3` with month/day/year range checks; the two
  `snprintf` targets (`char number[8]`, `char percent[32]`) cannot overflow
  (year ≤ 9999, month/day ≤ 31, `%g` of a 0..100 fraction).
- `append_content` always appends before `m_children.back()` is used
  (`el_textarea::parse_attributes`).
- `el_input::parse_attributes` re-generates its `lh-*` parts only after
  `remove_generated(this)`; the generated children are `html_tag`/`el_text`,
  never form subclasses, so the `static_pointer_cast<el_text>` in the update
  code is an upcast (`el_space : el_text`).
- `el_fieldset::draw`'s `for(int i = get_layers_number()-1; i >= 0; i--)` is
  safe for a zero layer count (int loop), and `bg->get_layer(i, …)` re-checks
  the index.
- Form state (`m_checked`, `m_type`, `m_fraction`, `m_swatch`) is derived
  from attributes only; no attacker index selects a buffer.

**iOS-only fork file `el_table.cpp` / `el_style` edit 83** (`accepts_child`)
was compared: it is a refactor of the same `tbody/thead/tfoot/caption` test
and does not alter bounds (see §3).

### 2.2 Modified files — memory-relevant hunks read line-by-line

`document.cpp` (2,616 changed lines): `createUpdatableFromString`,
`build_template`, `update_from_string`, `update_from_template`,
`update_structure`, `update_styles`, `update_holes`, `apply_template_values`,
`template_html`, `class_change_allowed`, `retag_allowed`, `apply_retag`,
`restyle_after_patch`, `retext_in_place`, `replace_text_renderers`,
`create_node`, `create_element`, `finalize_from_external_root`,
`selector_scope`, `style_attributes_selectable`, `ids_selectable`,
`layout_dirty_regions`, `snapshot_layout`, `media_changed`,
`take_table_cells`, `forget_positions`.

Key checks:

- `update_from_template`'s `pos` only advances over literals found in the new
  string; `html.compare(pos, …)` is never called with `pos > html.size()`.
- `apply_template_values` rejects empty/space-only text values before `v[0]`,
  rejects `<`, NUL, `&`, `\r`, and non-local style changes; every
  `hole.text_elements.front()` is reached only after a `retext_in_place`
  (`!current.empty()`) or an explicit `.empty()` check.
- `changes`/`property_patches`/`background_changes`/`width_changes` are all
  indexed by `&change - changes.data()` and sized to `changes.size()`.
- `retag_allowed` requires the element type to be exactly
  `html_tag/el_div/el_para/el_td/el_tr/el_body` (`restylable_in_place`) and
  **requires the new tag name to equal the old one**, so no element subclass
  can be retagged into another (`input`→`div` etc.); form/table/SVG types
  are rebuilt, never patched.
- `forget_matched_styles` erases the old `::before/::after` children and
  clears used selectors before `apply_matching`, so pseudo elements are not
  duplicated by repeated retags (verified with a probe, §4.3).
- `m_node_elements`/`m_node_holes` values are `shared_ptr` holders, not
  dangling raw pointers; `m_layout_marked`/`m_relayout_roots` are cleared on
  every render-tree rebuild (`restyle_after_patch`, `media_changed`,
  `render`).

`html_tag.cpp`: `apply_stylesheet`, `apply_selector`, `apply_matching`,
`flip_class`, `note_flip`, `patch_inline_properties`,
`can_restyle_width_shallow`, `compute_styles`, `compute_background_style`,
`select`/`select_pseudoclass`/`select_attribute`, `find_ancestor`,
`get_element_before/after`, `add_style`, `refresh_styles`,
`reset_attributes`, `restore_base_style`, `forget_matched_styles`.
The only raw index in `flip_class` (`saved->kids[i]`) is reached only after a
target state with `state.kids.size() == m_children.size()` was found and both
vectors were swapped, so the written vector has exactly `m_children.size()`
entries; snapshots are refreshed on every miss.

`render_item.cpp`: `render`, `measure`, `measure_height`, layout cache
(`layout_cacheable`, `layout_reusable`, `relayout_boundary`, `relayout`,
`mark_layout_dirty`, `same_layout_input`, `same_resolved_layout_input`),
`fetch_positioned`, `render_positioned`, `render_out_of_flow`,
`calc_document_size`, `paint_ink`/`ink`/`add_self_ink`/`add_children_ink`,
`group_transform`, `draw_group`, `draw_children`, `draw_borders`.
`paint_ink::add` ignores NaN; culling is disabled for unbounded ink; the
layout-cache *comparison* path is env-gated (`LH_LAYOUT_CACHE_CHECK`) and
therefore cannot itself index anything in production.

`style.cpp`: `add(string)`, declaration cache (`style_op`, `split_declarations`,
`declaration_cache`), `add(tokens)`, `add_property`, `keyword_property`,
`replace_properties`, `parse_grid_shorthand`, `add_parsed_property`,
`remove_property`, `combine`, `get_property`, `subst_vars`, `resolve_vars`,
`parse_font_family`, `parse_font_variant_numeric`,
`parse_font_feature_settings`. `parse_font_family`'s `result.resize(size-1)`
is reached only after at least one `,`-terminated item was appended;
`resolve_vars` inserts then skips the inserted tokens (`i += value.size()`).

`css_properties.cpp`: `compute`, `compute_background_color`,
`compute_opacity`, `compute_transform`, `compute_background`, `compute_flex`,
`compute_grid`, `compute_effects`, `snap_border_width`, `compute_font` and
the spacing/`font-variant-numeric`/`text-shadow` additions. Every
`get_property<T>(..., offset(member))` uses the member's own `offsetof` and
matching `T` (enums are int-sized; checked against `css_properties.h`).

`css_length.cpp`: `calc_node` intern table, `parse_list/parse_atom/
parse_product/parse_sum`, `evaluate`, `has_percent`, `convert_leaves`,
`calc_evaluate` (bounds-checked), `calc_resolve_units`, `css_length::from_token`
(calc branch). `key_of` recursion only follows parse depth ≤ 16.

`background.cpp`: `prepare_color_points`, `repeat_color_points`,
`color_points_transparent_fix`, `get_layer`, `get_image_layer`,
`get_color_layer`, `get_layer_type`, `EndPointsFromAngle`, gradient layer
getters. `given` has exactly one entry per `color_points` entry (the
`is_color_hint` branch `continue`s before `given.push_back`); `given.back()`
is forced true before the gap-filling loop, so `while(!given[j]) j++` cannot
run past the end.

`render_table.cpp` / `table.cpp`: `add_cell` clamp (`colspan/rowspan ∈
[1,1000]`, then `take_table_cells` with a 200,000 budget), `is_rowspanned`,
`finish`, `cell/column/row` domains, `calc_table_width`,
`calc_fixed_table_width`, `distribute_width`, `resolve_collapsed_borders`,
`_render`. Every `m_grid->column(c)`/`row(r)` call was checked: `c` comes
from a `cols_count` loop, from `col+colspan` (row length ≥ that by
construction), or from `span_col`/`span_row` clamped to `count-1`;
`cell(col,row)` is itself bounds-checked; `distribute_width` validates
`start/end` and `distribute_columns.front()` is only used on a non-empty
vector.

`render_inline_context.cpp` / `line_box.cpp` / `el_text.cpp` /
`el_before_after.cpp`: the wrapped-text fragment machinery
(`place_inline`, `wrapped_text_item`, `apply_ellipsis`, `text_content_size`,
`reorder_bidi`, `update_fragment_bounds`, `set_text`, `strong_direction`,
`draw`), `add_quote`, `add_text`, `add_function`, `add_image`.
`breaker->fit` returns a boundary `> start` or `start`; the loop breaks on
`end <= start || end > content.size()` and always advances. `el_text::draw`
uses `shown.substr(0, cut)` (clamped) and the fragment draw is guarded by
`!fragments.empty()`. `add_quote` forces `marks.size() >= 2` before
`marks.size()/2 - 1`, and `pair*2+1 <= marks.size()-1` for both even and odd
sizes.

`css_selector.cpp` (`generated_part_selector`), `stylesheet.cpp`
(`sanitize_at_rule`, layer depth), `css_parser.cpp` (`filter_code_points`:
`result` is sized `size + 2*null_count`, exactly the 3-byte replacement
budget), `document_container.cpp` (`split_text`), `element.cpp`
(`create_render_item`, `replace_children`, `_add_before_after`,
`mark_layout_dirty`), `flex_*`/`render_flex`, `render_block*`,
`el_image` (object-fit/object-position), `web_color`, `num_cvt`, `string_id`,
`iterators`, `render_image` — read; no attacker index or length on a buffer.

### 2.3 What is *not* claimed

- `el_svg.{h,cpp}` was not re-audited here (covered by SVG-01/02/03; the iOS
  copy is 2,161 lines per that note). `el_form.h` was not read (the `.cpp`
  defines all reviewed behaviour); the other two headers were read.
- The iOS internal update layer `telegram_external.cpp` (3,182 lines) is not
  the Android code path and was not audited as part of the requested
  same-allocation C++ heap target (it is iOS-only; see §3).
- The layout-cache *correctness* validation (`LH_LAYOUT_CACHE_CHECK`) is
  debug-only; a wrong cache reuse would be silent, but no path in the
  reviewed code turns a cached size into an index.

---

## 3. Platform divergence (found, but DoS-hardening, not memory corruption)

The iOS vendored fork is not the same fork as the Android canonical — it is
an internal fork of `twidget b5878f9` with Telegram "VENDOR.md" edits, while
the shipped Android library matches the public canonical code. Evidence
(`newfeat_20261108/android_binary_source_identity.txt` and
`ios_android_divergence.txt`):

- Android 72929 `libtmessages.49.so`
  (`sha256 f2178927…f707534`) contains the canonical template-update env
  strings `LH_NO_TEMPLATE`, `LH_NO_KEEP_TREE`, `LH_NO_STYLE_SHARING`,
  `LH_NO_LAYOUT_CACHE`, `LH_NO_INPLACE_TEXT`, `LH_NO_CLASS_FLIP`,
  `LH_NO_TRANSFORMED_CULLING`, `LH_NO_SAME_SIZE_TEXT` (1 hit each) and
  contains **none** of the iOS `telegram_external.cpp` markers
  (`not a rendered element`, `text: pieces not placeable`,
  `a parent whose children an element reads` — 0 hits).
- iOS (`tgwidget-src`) has, and Android canonical lacks:
  `generated_scope` + `max_text_elements = 10000` + `pseudo_element_allowed`
  (edits 84/19), `max_css_list` caps for `content:` items (edit 19),
  gradient stops (edit 15) and `clip-path` points (2×`max_css_list`),
  `el_table::accepts_child` (edit 83) and a completely different update layer
  (`telegram_external.cpp`, 3,182 lines).

Interpretation: the iOS build has explicit budgets against generated-content /
pseudo-element / stop-list growth; the Android canonical does not. That is a
**DoS/work-amplification delta** (content items, stops, clip-path points are
capped only by the 32 KiB serialized-HTML limit on Android), not a memory
corruption delta, and per the directive it is not promoted as the 0day. It is
recorded because the next Android widget DoS review should treat it as a
known gap.

Also observed on the iOS path only (not reported as a bug): the global
`style.cpp` `declaration_cache` replays cached `style_op`s **without calling
`container->sanitize_declaration`** on a cache hit (`style.cpp:add(string)`).
The iOS `LHContainer` is the only container implementing that hook with a
`m_trusted_styles` bypass; a declaration whose exact text was first parsed
while parsing master/user styles would be replayed for author CSS. The UA
master stylesheet (`master_css.h`) contains no `url(` and no
`behavior`/`-moz-binding`, so no bypass is demonstrated with the current
master CSS; a host-provided user stylesheet with URL declarations would make
it reachable. Not memory corruption; flagged for the iOS owners.

---

## 4. Reproducible host evidence

### 4.1 Fresh-feature render corpus

`gen_newfeat.py` → 76 documents (ellipsis/fragments, bidi, quotes,
counters/content, clip-path, filters/transforms, grid spans, form controls,
table forms). ASan+UBSan and ASan+UBSan+`_GLIBCXX_ASSERTIONS`: **exit 0**,
no report (`render_asan.log`, `render_stl.log`).

### 4.2 Update/template pairs

- 9 focused pairs (`update.bin`): ellipsis text/width, quotes text/CSS,
  grid structure/text, form attribute, clip-path CSS, UTF-8 text.
- 65 single-edit pairs (`update_pairs2.bin`, `gen_update2.py`) over the same
  feature bases (text, style add/remove/replace, attributes, child insert).
  ASan and `_GLIBCXX_ASSERTIONS`: **exit 0** (`update_asan.log`,
  `update_stl.log`, `upd2_stl.log`). No `_GLIBCXX_ASSERTIONS` abort, no ASan
  report, no timeout.

### 4.3 Pseudo-element duplication probe (negative)

`pseudo_growth.cpp` creates `#d::after{content:'X'}` and alternates the
`class` of `#d` through `update_from_string` 8 times (both template and
`LH_NO_TEMPLATE=1` structure paths). `div_children` stays 2 (text + one
`-tag-after`); the `forget_matched_styles` erase prevents accumulation.
Log: `pseudo_growth_probe.log`.

---

## 5. Honest confidence

| Claim | Confidence | Basis |
|---|---|---|
| no memory-corruption primitive in the reviewed fork-only/modified code | medium-high | full read of the 6 available fork-only files + all memory-relevant hunks; invariants above |
| shipped Android lib contains canonical template code, not iOS internal code | high | env strings / iOS markers in 72929 binary |
| iOS/Android divergence is budget/DoS hardening, not memory | high for the listed edits | source diff; no memory sink in the added guards |
| `clause`-level bounds (grid/table spans, clip-path arity, color points) | high | code + corpus, ASan/assertions clean |
| a different bug may exist outside this scope | plausible | `el_svg`, iOS `telegram_external.cpp`, paint backends, canvas/JS not re-audited here |

No device result is claimed. If the divergence is later promoted as a DoS
test, the Sony payload is a widget HTML with a `content:` list or gradient
stop list repeated near the 32 KiB limit; that is a denial-of-service check,
not the requested memory-corruption 0day.
