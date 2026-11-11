# LT (litehtml table `rowspan`/`colspan` negative index) — RCE assessment

Date: 2026-11-08. **Host-only** (no device, no Frida, no bot, no network).
Workdir: `<HOME>/ailocal/Telegram/telegramandroidwidget`.
Scope: decide whether the litehtml table-span negative index ("LT") can be a
second widget RCE that is **MTE-safe and universal** (Android builds + iOS,
without per-build/per-device hardcodes). A negative result is acceptable; no
RCE is claimed. Lemmalog handoff:
`notes/LEMMALOG_FACTS_lt_20261108.txt`.

---

## 0. Verdict (short)

1. **LT is not reachable in any target Telegram build.** The shipped
   `table_grid::add_cell` clamps **both** spans to `[1,1000]` immediately after
   `atoi()`, before any grid/vector use. This is present in the Android
   `libtmessages.49.so` builds 72789/72889/72929 (and two further lab libs) and
   in the iOS 13.2 (36535) `TelegramUIFramework`. The public Telegram fork
   source has the same clamp. The only unclamped implementation is **upstream
   litehtml** (the lab clone), not the widget engine.
2. **Even without the clamp, LT is not same-tag.** The negative index always
   addresses *before* `m_rows.data()` / `m_columns.data()`, i.e. outside the
   vector's own allocation. `std::vector` keeps `begin/end/cap` in the separate
   `table_grid` object, not in the data allocation. A negative index can reach
   that object only as a **cross-allocation** write (if the allocator happens to
   place the object before the data), and under Scudo MTE the data pointer and
   the object/previous chunk carry different tags -> `SEGV_MTESERR`.
3. **The nearest target is cross-tag by construction.** `data-56` is the
   previous chunk (or a tag-0 chunk header); `data-4` (colspan read) is the
   previous 16-byte granule. Scudo primary chunks are tagged and adjacent chunks
   differ under the default buffer-overflow tuning; the vector data pointer's
   tag does not match them.
4. **A 4-byte float add cannot be turned into a controlled length/pointer write
   from this primitive.** It can corrupt a `table_grid` metadata field in a
   lab bump model (we hit `m_rows_count` and `m_rows.end` addresses), but the
   write is an IEEE-754 add, the object placement/phase is allocator-dependent,
   and the target is cross-allocation. This is a crash/DoS path at best; no RCE
   was built.
5. **LT is not easier than N1 and not a substitute for c2560s.** N1 is
   same-tag (QuickJS arena) but OOM-gated; c2560s is the cross-tag parser 0day.
   LT is fixed in the target, and its hypothetical upstream form is cross-tag
   and non-universal. Recommendation: remove LT as a Telegram 0day from the
   RCE matrix (keep the upstream litehtml finding as upstream-only) and do not
   spend device runs on it.

Confidence: clamp presence **1.0**; same-allocation impossibility **1.0**;
cross-tag if unclamped **1.0** (Scudo model); `table_grid`-object metadata
reachability in a bump model **1.0** (host); real-target metadata reachability
**0.3** (unproven, and irrelevant because of the clamp); untagged-primary groom
hypothesis **0.2**; RCE **0.0** (not demonstrated).

**Delta vs the prior notes.** `REPORT_litehtml_rowspan_20261106.md` remains a
valid **upstream** host finding (its PoC was upstream litehtml, not the
Telegram fork). `REPORT_litehtml_span_patched_20261107.md` first reported the
shipped clamp for 72889/72801/7279; this note independently verifies it for
72789/72889/72929 and iOS 13.2, proves there is one `add_cell` implementation per
binary, and answers the same-tag/universality question. The MTE matrix row 18
in `MTE_safe_hunt_20261107.md` should be read with this correction: LT is not a
reachable Telegram 0day; as an upstream-only bug it is cross-tag.

---

## 1. Sources, binaries and method

### 1.1 Notes read

* `notes/bug_inventory_20261105.md` (18-row inventory; LT is not a row there,
  but the MTE matrix discussion treats it as candidate 18).
* `notes/MTE_safe_hunt_20261107.md` §6 row 18 and §7.4 (LT classified
  cross-tag, C++ heap previous chunk).
* `notes/twidget_native_audit.md` §5 (litehtml + gumbo is the native document
  engine; tables reachable from widget HTML without JS).
* `lab/qjs_fork_audit/REPORT_litehtml_rowspan_20261106.md` (upstream host OOB
  read/write finding).
* `lab/qjs_fork_audit/REPORT_litehtml_span_patched_20261107.md` (the shipped
  clamp; initial target-build correction).
* `lab/qjs_fork_audit/REPORT_canonical_chain_20261107.md` and
  `LEMMALOG_FACTS_20261107.md` (canonical source -> shipped bytes).
* `notes/new_0day_mte_specs_20261107.md` §2 (LT rejected as C++ heap previous
  chunk).
* `notes/universal_scudo_ladder_20261107.md` (Scudo class/MTE context).
* `lab/qjs_fork_audit/widget-sandbox/docs/{tgw-format.md,widget-runtime-profile.md}`
  (32,768-byte HTML / 4,096-byte zlib-9 limits; tables in the profile).

### 1.2 Source snapshots

| tree | role | identity |
|---|---|---|
| `lab/qjs_fork_audit/litehtml` | upstream litehtml, **unclamped** | clone at `ab7caef1d54f2265f919c299d29c135863675d96` (2026-11-02), only `render_table.cpp` trace-modified |
| `lab/qjs_fork_audit/twidget-canonical` | Telegram fork, Android-shaped | `759fcafe90fc6c5ffac400b3bab451b4cc8b4947` (2026-11-05) |
| `lab/qjs_fork_audit/tgwidget-src` | Telegram fork, iOS vendor copy | tag `release-13.2`, `24638bc69bd083981b178dd1e7f921eebbf7fc46` |
| `lab/rce_candidates/lt/src/litehtml_upstream` | lab copy of the unclamped upstream | this note |
| `lab/rce_candidates/lt/src/litehtml_telegram` | lab copy of the clamped canonical fork | this note |

The lab copies add only `LT_GEOM`/`LITE_SPAN_TRACE` instrumentation (vector
geometry prints, span trace, bump-allocator harness). They do not change the
vulnerable expressions or the clamp.

### 1.3 Binaries

| build | file | SHA-256 |
|---|---|---|
| Android 13.2.0 beta 72789 | `lib/arm64-v8a/libtmessages.49.so` (from `Android_Beta_13.2.0_(72789).apk`) | `7d54541a7d03104c11f45a6bd4caf496feae0c4e48bf5223cb7444e66542876f` |
| Android 13.2.1 beta 72889 | `lib/arm64-v8a/libtmessages.49.so` (from `apks/Android_Beta_13.2.1_(72889).apk`) | `f12c3cb8b5e0345f51b543887b923001c8a8e04cda5cd38aed513d2d365f5f13` |
| Android 72929 | `lib/arm64-v8a/libtmessages.49.so` (device update APK) | `f2178927433b9faf9de6831d1a0b5cd9341e106d506a642debd14fa9df707534` |
| iOS 13.2 (36535), stock `ph.telegra.Telegraph` | `ios_sideload/Telegram_13.2.0_decrypted.ipa` -> `Payload/Telegram.app/Frameworks/TelegramUIFramework.framework/TelegramUIFramework` | `577d3c7e1b1edec3350264f2bb66340933950686d4c1543ac52f75d5c3059f74` |

Two further lab `libtmessages.49.so` builds (`lab/bridge_t2`, and the
`telegramandroidwidget/evidence/release_updated/arm64.apk` lib) contain the same
clamp pattern; the
old `release_72371` lib has **no** `colspan`/`rowspan` strings and no litehtml
(the widget engine is absent), so it is not an LT target.

Method: Capstone disassembly of the exact `table_grid::add_cell`; xref scans
for the `colspan`/`rowspan` strings (to prove there is one implementation per
binary); host ASan/UBSan and release builds of upstream and the Telegram fork;
gdb layout; a lab bump-allocator harness to answer the address-arithmetic
question. No binary was executed on a device.

---

## 2. LT in upstream litehtml (the only vulnerable version)

### 2.1 The source

`litehtml/src/table.cpp` (upstream lab clone, unclamped):

```cpp
void litehtml::table_grid::add_cell(const std::shared_ptr<render_item>& el)
{
    table_cell cell;
    cell.el      = el;
    cell.colspan = atoi(el->src_el()->get_attr("colspan", "1"));
    cell.rowspan = atoi(el->src_el()->get_attr("rowspan", "1"));
    // no clamp to >= 1
    ...
}
```

`litehtml/src/render_table.cpp` clamps only the **upper** bound:

```cpp
int span_col = col + cell->colspan - 1;
if(span_col >= m_grid->cols_count()) span_col = m_grid->cols_count() - 1;
pixel_t cell_width = m_grid->column(span_col).right - m_grid->column(col).left;

int span_row = row + cell->rowspan - 1;
if(span_row >= m_grid->rows_count()) span_row = m_grid->rows_count() - 1;
...
m_grid->row(span_row).height += cell->el->height() - h;
```

A zero or negative span therefore produces a negative `span_row`/`span_col`.
With `rowspan = 1-k` in row 0, `span_row = -k`; the store is

```
m_rows[span_row].height += delta
= *(float*)(m_rows.data() - 56*k) += delta
```

with `table_row = 56 bytes`, `height` at offset 0. With `colspan = 1-k` in
column 0, the read is

```
m_columns[span_col].right
= *(float*)(m_columns.data() - 36*k + 32)
```

with `table_column = 36 bytes`, `right` at offset 32. The upper clamp is real
and prevents positive OOB (we verified `rowspan=1000` with 2 rows writes row 1,
offset `+56`, in-bounds).

### 2.2 Host reproduction (upstream, unclamped)

Reproducers (tiny; all under the widget limits):

```
html/rs0w.html:  <table><tr><td rowspan=2>A</td><td rowspan=0><div style="height:100px"></div></td></tr><tr><td>C</td></tr></table>
html/rsneg.html: same with rowspan=-1
html/cs0.html:   <table><tr><td colspan=0>X</td></tr></table>
```

ASan/UBSan build (`build/upstream_asan/lt_harness`, source
`src/litehtml_upstream`, `-fsanitize=address,undefined`):

* `evidence/host_upstream_rs0w_asan.log`:
  `rows data=0x50b000025df0 size=2 cap=2 obj=0x50d000001328`;
  `target=0x50b000025db8 offset_from_data=-56`;
  ASan `heap-buffer-overflow`, `READ of size 4`, "located 56 bytes before
  112-byte region [0x50b000025df0,0x50b000025e60)"; summary
  `pixel_float_t::operator+=` (the RMW at `render_table.cpp`).
* `evidence/host_upstream_rsneg_asan.log`: `span_row=-2`, target `data-112`;
  ASan `heap-use-after-free` (the target block is the freed previous vector
  allocation).
* `evidence/host_upstream_cs0_asan.log`: `cols data=0x504000002890 size=1
  cap=1`; `cols_target=data-36`; the actual 4-byte read is at `data-4`
  (`right` at +32); ASan "4 bytes before 36-byte region
  [0x504000002890,0x5040000028b4)".
* `evidence/host_upstream_rows2500_asan.log`: 2,500 rows, `rows data=...
  size=2500 cap=4096`, allocation 229,376 bytes, target `data-56`;
  ASan reports the same 56-bytes-before-region read. This is the
  >64 KiB/secondary-vector variant.
* `evidence/host_upstream_cols3000_asan.log`: 3,000 columns,
  `cols data=... size=3000 cap=4096`, allocation 147,456 bytes,
  `cols_target=data-36`, read at `data-4`; ASan `heap-buffer-overflow`.
* `evidence/host_upstream_rs_pos_clamped_asan.log`: `rowspan=1000`, 2 rows,
  `span_row=1`, target `data+56`, no ASan report.

Release build (`build/upstream_rel/lt_harness`):

* `evidence/host_upstream_rs0w_release.log`: `write_delta=102 cell_h=102
  accumulated_h=0`; `rowspan_write row=0 span_row=-1`; `target=data-56`.
  The RMW executes; the added value is the rendered cell height (100 + 2 px
  padding in this layout), i.e. CSS-controlled. The process does not crash
  immediately because the target happens to be nonzero glibc heap data; this
  is not a reliable exploit.

The minimal reproducers are **115/116 B raw, 86/87 B zlib-9**; the large
2,500-row variant is **20,087 B raw, 135 B zlib-9**; the 3,000-column variant is
**12,040 B raw, 78 B zlib-9**. All are inside the 32,768-byte HTML / 4,096-byte
zlib-9 widget limits. Trigger size is therefore **not** the blocker.

### 2.3 What the write can and cannot be

`pixel_float_t::operator+=` reads the 4 bytes at the target as an IEEE-754
`float`, adds the cell height, and stores the float. It is not an integer add.
Consequences:

* If the target is zero, the result is the float encoding of the cell height
  (e.g. 102.0f = `0x42CC0000`), not the integer 102. A 4-byte length field would
  become ~1.12e9, not 102.
* If the target is an existing pointer's low 32 bits, those bits are interpreted
  as a float; a small delta is often rounded away (ULP at ~1e9 is 64), and a
  large delta moves the pointer by an uncontrolled amount. It cannot set an
  arbitrary pointer.
* The store is 4 bytes at `height` offset 0 of a 56-byte-grid slot. It cannot
  reach `table_row::el_row` (offset 16) of a real row because that would require
  an address that is not on the 56-byte grid.

This is a controlled **heap increment**, as the earlier report said, but not a
controlled length/pointer write.

---

## 3. The decisive fact: the target builds already clamp

### 3.1 Android `table_grid::add_cell`

72889 (13.2.1 beta), `lib/arm64-v8a/libtmessages.49.so`:

```
0x8b6b58  table_grid::add_cell
0x8b6bc4  adrp/add -> "colspan" string 0x22df30
0x8b6bd4  bl atoi (0x18bec60)
0x8b6bf0  adrp/add -> "rowspan" string 0x228d32
0x8b6c04  bl atoi
0x8b6c14  cmp w23, #1
0x8b6c18  b.lt  0x8b6c2c        ; colspan < 1 -> 1
0x8b6c1c  cmp w23, #0x3e9
0x8b6c20  b.lo  0x8b6c34        ; colspan <= 1000 -> keep
0x8b6c24  mov  w23, #1000
0x8b6c30  str  w23, [sp,#0x60]
0x8b6c34  cmp w21, #1
0x8b6c38  b.lt  0x8b6c4c        ; rowspan < 1 -> 1
0x8b6c3c  cmp w21, #0x3e9
0x8b6c40  b.lo  0x8b6c54
0x8b6c44  mov  w21, #1000
0x8b6c50  str  w21, [sp,#0x64]
0x8b6c54  ... take_table_cells ...
```

The clamp is applied **before** `take_table_cells` and before any vector use.
The `b.lt` is signed, so `INT_MIN`, all negative values and zero are caught.
The `b.lo` after `cmp #1001` is the unsigned upper clamp. `atoi` overflow is technically UB, but the binary clamp covers every `int`
outside `[1,1000]`; host runs with `4294967296`, `-2147483649`,
`99999999999999999999`, `2147483648`, `-2147483648` all clamp to 1 or 1000 and
produce no ASan report (`evidence/host_atoi_overflow_tests.txt`). A hypothetical
`atoi` result in `[1,1000]` is safe; there is no negative result that escapes
`cmp #1; b.lt`.

Per build (full disassembly in `evidence/android_*_add_cell_disasm.txt`):

| build | `add_cell` | `colspan` atoi / clamp | `rowspan` atoi / clamp |
|---|---|---|---|
| 72789 (13.2.0 beta) | `0x8ae058` | `0x8ae0d4` / `0x8ae114-0x8ae150` | `0x8ae104` / `0x8ae134-0x8ae150` |
| 72889 (13.2.1 beta) | `0x8b6b58` | `0x8b6bd4` / `0x8b6c14-0x8b6c50` | `0x8b6c04` / `0x8b6c34-0x8b6c50` |
| 72929 | `0x8b6b58` | `0x8b6bd4` / `0x8b6c14-0x8b6c50` | `0x8b6c04` / `0x8b6c34-0x8b6c50` |
| `release_updated` lab lib | pattern | clamp `0x8b2c90` | clamp `0x8b2cb0` |
| `bridge_t2` lab lib | pattern | clamp `0x8b4c1c` | clamp `0x8b4c3c` |

There is **one** implementation per binary: an xref scan of all `adrp/add`
pairs in `.text` finds exactly one reference to the `colspan` string and one to
`rowspan`, both inside `add_cell` (`evidence/xrefs_summary.txt`). 72889 has one
direct call to `add_cell` at `0x897bd0` (the `render_item_table::init` lambda),
so the clamped path is the table path that the widget renderer uses
(`evidence/call_sites.txt`).

The clamp bytes in 72889 are also the same shape as the annotated 72879 IDB and
the public canonical source; there is no second, unclamped litehtml copy in
`libtmessages.49.so`.

### 3.2 iOS 13.2 (36535) `TelegramUIFramework`

The iOS binary contains the same `table_grid::add_cell` at `0x410a064`:

```
0x410a0d8  adrp/add -> "colspan" 0x5a935eb
0x410a0ec  bl atoi (0x557ab10)
0x410a104  adrp/add -> "rowspan" 0x5a935f3
0x410a118  bl atoi
0x410a124  ldr w24, [sp,#0x60]      ; colspan
0x410a128  cmp w24, #1
0x410a12c  b.lt  0x410a140           ; <1 -> 1
0x410a130  cmp w24, #0x3e9
0x410a134  b.lo  0x410a148
0x410a138  mov  w24, #1000
0x410a144  str  w24, [sp,#0x60]
0x410a148  cmp w22, #1               ; rowspan
0x410a14c  b.lt  0x410a160
0x410a150  cmp w22, #0x3e9
0x410a154  b.lo  0x410a168
0x410a158  mov  w22, #1000
0x410a164  str  w22, [sp,#0x64]
0x410a1a0  mul w1, w22, w24           ; take_table_cells
```

The object offsets confirm the iOS `table_grid` variant: `str w8,[x19,#0x70]`
is the iOS-only `m_cells_taken` at offset 112. The Telegram **Android**
canonical `table_grid` ends at 112 bytes (no extra member after `m_captions`);
the **upstream** litehtml object has an additional 24-byte `m_column_widths`
at 112 (136 bytes total). The main vector headers (0..111) have the same
offsets on all three variants; see `evidence/table_grid_layouts.txt` and
`evidence/host_gdb_layout.txt`.

There is one `add_cell` and one call site (`0x40ec938`, the
`render_item_table::init` lambda). The other `colspan`/`rowspan` xrefs at
`0x411f8d8/0x411f900/0x412101c` are `telegram_external.cpp` attribute/shape
accounting; they do not build a `table_grid`. That code has its own clamp:
`span_of()` returns `n < 1 ? 1 : (n > 1000 ? 1000 : n)` (source
`tgwidget-src/.../telegram_external.cpp:756-761`; binary clamp visible at
`0x411fd90-0x411fda4`). No second `add_cell`/table-grid implementation was
found in the UI framework; the `TelegramCoreFramework` contains `colspan`
attribute-name strings but no litehtml marker or clamp pattern, so it is not a
second renderer.

`evidence/ios_add_cell_disasm.txt` contains the full disassembly;
`evidence/xrefs_summary.txt` lists all xrefs.

### 3.3 Public Telegram source

`tgwidget-src/third-party/twidget/LiteHTML/litehtml/src/table.cpp` (tag
`release-13.2`):

```cpp
cell.colspan = atoi(el->src_el()->get_attr("colspan", "1"));
cell.rowspan = atoi(el->src_el()->get_attr("rowspan", "1"));
if(cell.colspan < 1) cell.colspan = 1;
if(cell.colspan > 1000) cell.colspan = 1000;
if(cell.rowspan < 1) cell.rowspan = 1;
if(cell.rowspan > 1000) cell.rowspan = 1000;
```

The canonical Android fork `twidget-canonical/litehtml/src/table.cpp` has the
same clamp. The iOS vendor copy also has `m_cells_taken`; the clamp is identical.

### 3.4 Host reproduction of the clamp (Telegram fork)

Built from `src/litehtml_telegram` with ASan/UBSan
(`build/telegram_asan/lt_harness`), same inputs:

```
rs0w:  LT_CELL attr colspan=1 rowspan=2 -> colspan=1 rowspan=2
       LT_CELL attr colspan=1 rowspan=0 -> colspan=1 rowspan=1
       LT_CELL attr colspan=1 rowspan=1 -> colspan=1 rowspan=1
       LT_RENDER done (rc=0; no ASan)
rsneg: rowspan=-1 -> 1; no ASan
cs0:   colspan=0 -> 1; no ASan
csneg: colspan=-1 -> 1; no ASan
rs_pos_clamped: rowspan=1000 -> 1000; write at row 1 (+56), in-bounds
rs_1001: rowspan=1001 -> 1000
```

`evidence/host_telegram_clamp_*` and `evidence/host_telegram_clamp_cs0.log`.
This is the direct target-source demonstration: the same HTML that is an
ASan OOB in upstream is a normal layout in the Telegram fork.

### 3.5 Bypass audit

We looked for a way to obtain a negative span despite the clamp; none exists:

* `cell.colspan`/`cell.rowspan` are assigned only in `table_grid::add_cell`
  (`grep` over both forks: `src/table.cpp:12-17`; no other assignment).
* `atoi` overflow/`INT_MIN`/zero/all negatives are caught by the signed
  `b.lt`; values >1000 by `b.lo`. `atoi` cannot produce a negative value that
  bypasses `cmp #1; b.lt`.
* `take_table_cells` failure sets both spans to 1; it cannot set a negative.
* `table_cell` default/copy/move constructors initialize spans to 1; the empty
  filler cells in `finish()` are default `1` and have `el == nullptr`.
* There is no CSS property, DOM mutation, `attr()` or custom element path that
  writes `table_cell::colspan`/`rowspan` after `add_cell`.
* The only index expressions are `span_col`/`span_row`; both are upper-clamped.
  Positive values cannot exceed `rows_count-1`/`cols_count-1`; the vector
  capacity slack after `size()` is not reachable.
* `m_rows_count` is `m_cells.size()`; `begin_row` pushes both vectors; no
  mismatch except an allocation exception, which aborts the render rather than
  producing a silent negative index.
* `table_grid::cell()` bounds-checks both indices; `distribute_width()` checks
  `start/end`; `is_rowspanned()` checks `c < m_cells[row].size()`.

The malformed `<table><td rowspan=0>` case also goes through an implied row in
gumbo and is clamped in the target build; no separate pre-`begin_row` path was
found.

---

## 4. Same-allocation / same-tag analysis

### 4.1 Vector data has no metadata

`std::vector<table_row>` layout is three pointers (`begin`, `end`, `cap`) in
the `table_grid` object, plus a separate allocation for the elements. `data()`
returns the first element pointer, which is the start of that allocation
(`std::allocator` -> `operator new`; no header in the user allocation). The
data allocation contains only `table_row` objects:

```
table_row (56 B):
  +0  height (float, 4)
  +4  border_top
  +8  border_bottom
  +16 shared_ptr<render_item> el_row (16)
  +32 top
  +36 bottom
  +40 css_length css_height (8)
  +48 min_height
```

`table_column` (36 B) has `right` at +32. The vector `size`/`capacity`/`begin`
are **not** in this allocation.

### 4.2 Negative index is always outside the data allocation

`m_rows[r]` with `r = -k` computes `data + (size_t)(-k) * 56`, which wraps to
`data - 56*k`. Since `data` is the allocation start, every `k >= 1` is before
the allocation. There is no `k` that lands in `[data, data + capacity*56)`.
The same holds for `m_columns`: `data - 36*k + 32 <= data - 4` for `k >= 1`.

Host gdb (`evidence/host_gdb_layout.txt`) and the ASan allocation bounds
(`evidence/host_upstream_rs0w_asan.log`: target is 56 bytes before a 112-byte
region; `cs0`: read 4 bytes before a 36/72-byte region) confirm the arithmetic.
The 2,500-row variant is a 229,376-byte allocation and the target is still
56 bytes before it.

**Strict same-allocation is impossible for a negative index.** The vector's
own `size`/`capacity`/pointer fields are in the `table_grid` object, not in the
data allocation.

### 4.3 The vector metadata *is* reachable — but cross-allocation

The `table_grid` object layout (upstream 136 B; Telegram Android canonical
112 B; iOS 120 B; main offsets 0..111 identical):

| offset | field |
|---:|---|
| 0 | `m_rows_count` (int) |
| 4 | `m_cols_count` (int) |
| 8 | `m_cells` begin/end/cap |
| 32 | `m_columns` begin/end/cap |
| 56 | `m_rows` begin/end/cap |
| 80/84 | caption heights |
| 88 | `m_captions` begin/end/cap |
| 112 | upstream `m_column_widths` begin/end/cap; Telegram Android ends at 112; iOS `m_cells_taken` (int) |

If the allocator happens to place the `table_grid` object **before** the
`m_rows` data by `D = data - obj`, the 56-byte grid hits object offsets
`r = D mod 56`, `r+56`, `r+112` where each offset is within the object (both
addresses are 16-byte aligned, so `r` is a multiple of 8). That can be:
`m_rows_count` (r=0), `m_cells/m_columns/m_rows` begin/end/cap, caption
vector, etc. This is a **cross-allocation write**, not same-allocation. It can
corrupt a length/pointer field of a vector header if the phase is right, but:

* the object and data are separate allocations with different Scudo tags under
  MTE (see §5); the write faults before it can be observed;
* the object may just as well be after the data (host release/ASan show
  `obj > data`), in which case no negative index can reach it;
* the write is an IEEE-754 float add, not a controlled length/pointer set
  (§2.3);
* `m_rows_count` at offset 0 is an `int`; if hit, the 4 bytes are read as a
  float and replaced by the float encoding of `delta` (e.g. 102.0f =
  `0x42CC0000` = 1,120,665,600 as an int), which is a wild length, not a
  controlled small value. The subsequent loops can run away and crash (DoS);
  the direct bump run did SIGSEGV, but the gdb run did not (UB/optimization
  nondeterminism), so this is not a reliable primitive.
* `m_cols_count` at offset 4 is not reachable by the 8-byte-aligned grid; the
  other fields are pointers whose low 32 bits are usually huge floats, so a
  small delta is often a no-op.

#### Lab bump-model evidence (address arithmetic only)

`src/harness_bump.cpp` overrides `operator new` with a 256 MiB bump arena; the
`table_grid` object is allocated before the vector data, so `D > 0` is forced.
This is **not** Scudo and has no tags; it only answers "can the index reach the
object if it is before the data?".

* `evidence/host_bump_hit_m_rows_end.log`: `D=1464`, `span_row=-25`,
  `target=obj+64` (`m_rows.end` low 32 bits) — reachable, process exits 0.
* `evidence/host_bump_hit_m_rows_count.log`: `D=2856`, `span_row=-51`,
  `target=obj+0`, `TARGET_IN_TABLE_GRID_OBJECT offset=0 field_region=counts`
  — reachable. The direct run then SIGSEGV'd (rc 139); a gdb run exited normally
  (UB/optimization nondeterminism). The address proof is the point, not the
  crash.
* `evidence/host_bump_hit_m_rows_count_gdb.txt` is the gdb transcript; it shows
  the target `obj+0` and that the write is not a deterministic crash.

**Conclusion:** the only way to reach the vector's own `size`/`capacity`/
`pointer` fields is a cross-allocation negative offset into the `table_grid`
object, which is tag-checked under MTE and is not the same allocation. The
"same-tag target" the task asks about does not exist for this primitive.

---

## 5. Allocation / tag domain: Android and iOS

### 5.1 Android (Scudo)

The litehtml C++ heap is **not** the QuickJS arena. `std::vector` and
`table_grid` use `operator new` -> Bionic `malloc` -> Scudo:

* `table_grid` object: 112 B (Telegram Android canonical), 120 B (iOS), or
  136 B (upstream) -> Scudo/Apple **primary** (<64 KiB), tagged. The object
  lives in a primary size-class region; its `begin/end/cap` fields are in a
  tagged chunk.
* `m_rows` data: `56*N` bytes. Small N -> primary (tagged); N >= ~1170 ->
  >64 KiB -> **secondary** (`mmap`, usually untagged on Android; Android 17
  may have an 8 KiB `PROT_MTE` prefix, but the data is untagged).
* `m_columns` data: `36*M`; same primary/secondary rule.

A negative access uses the vector's `begin` pointer, including its top-byte
tag. The target is in a different allocation:

* nearest write target `data-56`: previous chunk user data or the current
  chunk's header (Scudo metadata is tag 0). The `begin` tag is the data chunk's
  tag (nonzero for primary). Tag check fails -> `SEGV_MTESERR` (sync).
* `colspan` read `data-4`: previous 16-byte granule; same mismatch.
* if the target is the `table_grid` object (cross-allocation), its chunk has
  its own tag; the data pointer's tag does not match (unless a 1/16 random
  collision, or both allocations are untagged).
* Scudo's default `M_MEMTAG_TUNING_BUFFER_OVERFLOW` makes adjacent chunks
  differ (odd/even tags), so a linear overflow from a tagged primary is
  detected with high probability; the nearest `data-56` is exactly that case.
* chunk headers are tag 0; a tagged pointer into a header faults.
* reclaiming the previous chunk with attacker-controlled data does **not** make
  it same-tag: Scudo retags on free and gives the reused chunk its own tag;
  it matches the vector-data tag only by a 1/16 collision, and the default
  odd/even tuning makes adjacent chunks differ in parity. Reclaim turns the
  target into controlled bytes but not into a tag-safe access.

Measured MTE coverage on the Pixel 9 debug run (`MTE_safe_hunt` §2.4): 44
`mt` mappings = 33 primary + 11 secondary; 66 primary mappings total (33
tagged/33 untagged). The untagged primaries are a growth path; the v7 chain's
`ctx`/`rt` were in untagged primary mappings. This matters for the one
MTE-safe hypothesis below.

### 5.2 The only MTE-safe hypothesis: untagged primary growth

If **both** the vector data and the target `table_grid` object are served from
**untagged** Scudo primary growth mappings, the pointers are tag 0 and the
negative access is not checked. This is the only way LT could be "MTE-safe" in
the tag-domain sense, and it is:

* **not same-allocation** (the object is still a separate allocation);
* **not universal**: it depends on the Scudo region state/size class and the
  device's mapping layout; the attacker would have to fill the tagged region
  for both classes to force the growth mapping, and the object/data phase must
  still line up; on some devices/builds the growth mapping may be tagged or the
  classes/regions differ;
* **unproven**: no host Scudo or device run was done for the table allocations
  in this task; the measured 33/33 split is from the v7 debug app, not from a
  table groom;
* **irrelevant to the target**: the clamp removes the negative span in
  every Telegram build checked.

If the data is a **secondary** allocation (>64 KiB), the data pointer is tag 0,
but the `table_grid` object is still a tagged primary; a negative index that
reaches the object faults (0 vs nonzero tag), and the nearest `data-56` is a
secondary header/guard page, not a controlled field. A large vector can make the
nearest access unchecked (tag 0), but it targets allocator metadata/guard, not
the vector's size/capacity/pointer; it does not give a same-tag control field.

### 5.3 iOS (MIE)

Stock Telegram 13.2 has no `com.apple.security.cs.checked_allocations` /
`enhanced_security` entitlement (MTE note §5.2), so MIE tag checks are **off**
for the app; `operator new` -> Apple `malloc` is not tag-checked. If an app
opts into MIE, Apple malloc tags allocations and the same cross-tag argument
applies. The clamp is platform-independent source and is present in the iOS
binary; LT is not reachable on iOS either.

On iOS/no-MIE, an unclamped LT would be "MTE-safe" only by absence of checks,
not by a same-tag property; it would still be cross-allocation, need a heap
groom/leak, and would not be universal (Android MTE-on fails). The stock iOS
app is not a target for a universal payload.

### 5.4 Why v7 does not help

v7's safety comes from the QuickJS **arena**: all blocks are in 64 KiB
`mmap` slabs, tag 0, never `PROT_MTE`. litehtml's `std::vector`/`table_grid`
never use `js_malloc`/the arena; they use the platform C++ heap. There is no
v7-style tag-0 domain to inherit. This is the same reason the MTE note rejected
LT as C++ heap previous chunk.

---

## 6. Universality and trigger size

### 6.1 Clamp coverage

| target | litehtml | clamp |
|---|---|---|
| Android 72789 (13.2.0 beta) | yes | yes (`0x8ae114`) |
| Android 72889 (13.2.1 beta) | yes | yes (`0x8b6c14`) |
| Android 72929 | yes | yes (`0x8b6c14`) |
| Android `release_updated` lab lib | yes | yes (`0x8b2c90`) |
| Android `bridge_t2` lab lib | yes | yes (`0x8b4c1c`) |
| Android 72371 | **no** litehtml | n/a (no widget table path) |
| iOS 13.2 (36535) `TelegramUIFramework` | yes | yes (`0x410a130`) |
| iOS public source tag `release-13.2` | yes | yes (source) |
| Android canonical source `759fcaf` | yes | yes (source) |
| upstream litehtml (lab) | yes | **no** |

There is no target build in the tree without the clamp. The clamp is
unconditional source code, not a per-device mitigation; the attacker cannot
turn it off. Therefore LT is not a **universal** Telegram bug; it is not a
Telegram bug at all in these builds. The only unclamped code is upstream
litehtml, which is a different product (and where the host finding remains
valid as an upstream issue).

### 6.2 Trigger size, if it were present

* Minimal row span: 115 B raw / 86 B zlib-9.
* Minimal col span: 45 B raw / 44 B zlib-9.
* Large-vector row span (2,500 rows, >64 KiB `m_rows`): 20,087 B raw /
  135 B zlib-9.
* Large-column read (3,000 columns, >64 KiB `m_columns`): 12,040 B raw /
  78 B zlib-9.

All are within the widget's 32,768-byte raw HTML and 4,096-byte zlib-9 limits;
tables are in the runtime profile; no JavaScript is needed. So **delivery size
is not a blocker**; the clamp is. If a future Telegram build removed the clamp,
the trigger would be trivial to deliver, but the MTE/cross-tag problem would
remain.

### 6.3 No per-build/per-device hardcode can make it universal

Even in the hypothetical unclamped case, an exploit would need:

1. the `table_grid` object to be **before** `m_rows.data()` (allocator
   dependent, per build/device/process);
2. the 56-byte phase `D mod 56` to hit a useful metadata field (per heap
   layout; object sizes differ: upstream 136 B, Telegram Android 112 B,
   iOS 120 B);
3. the target allocation to be in the same tag domain as the data (untagged
   primary growth or a 1/16 tag collision; per device/Scudo state);
4. a float-add value that changes the target field in a useful way (the field
   is a pointer/count, not a float length);
5. a way to survive the resulting wild loops or to use the corruption before
   the crash (not built).

These are exactly the per-build/per-device hardcodes the task excludes. The
only universal statement is the clamp.

---

## 7. Difficulty vs N1 and c2560s

| | N1 (QuickJS `push_scope`) | c2560s (parser `ARG_SCOPE_END`) | LT (litehtml span) |
|---|---|---|---|
| target-build reachable | yes (app snapshot) | yes | **no (clamp)** |
| trigger | refused `js_realloc(scopes,180)` at 6 MiB | parser OOB, 1.31 MB displacement | negative span (removed by clamp) |
| memory domain | QuickJS arena, **same-tag** | `b->vardefs` Scudo primary, **cross-tag** | C++ Scudo heap, **cross-tag** |
| MTE-on | safe by tag domain (real-ABUF) | faults | faults (nearest/object) |
| host RCE | 5/5 (real-ABUF) | stage-A forge/device-proven pieces | none; only OOB read/write/DoS |
| missing piece | non-OOM trigger (device-closed) | MTE-off target / class | clamp removal + tag bypass + heap phase + float primitive |
| difficulty | high but concrete | high | **highest; not a candidate** |

N1 remains the best same-tag carrier if a non-OOM trigger can be found; its
blocker is the widget engine's fatal OOM policy, not a missing memory
primitive. c2560s is the cross-tag parser 0day. LT is fixed, and its
hypothetical upstream form is cross-tag, non-universal, and has no demonstrated
RCE primitive. It is **not easier than N1** and is not a second RCE candidate.

---

## 8. Recommendation to the orchestrator

1. **Remove LT as a Telegram 0day** from the RCE matrix (the "18-bug" row 18
   should be marked: *upstream litehtml only; clamp in 72789/72889/72929 and
   iOS 13.2; not reachable in the widget engine*). Do not spend device runs on
   it.
2. Keep the upstream litehtml host finding as an **upstream-only** issue:
   `colspan<1` OOB read (public issue #358, read-only) and the `rowspan<1`
   OOB float RMW (host-only, upstream; not Telegram). The Telegram fork already
   has the clamp.
3. If a future build drops the clamp, re-open only as a **research** item:
   first measure whether the table allocations can be forced into untagged
   Scudo primary growth mappings and whether the `table_grid` object can be
   placed before the data; without both, MTE-on is a hard stop. Do not claim a
   universal payload.
4. For a second MTE-safe RCE, continue the same-tag, non-OOM QuickJS/native
   hunt; LT does not change the matrix.

---

## 9. Evidence and reproduction

All artifacts are under `lab/rce_candidates/lt/`:

```
src/litehtml_upstream/        upstream litehtml copy (unclamped; LT_GEOM trace)
src/litehtml_telegram/        Telegram canonical litehtml copy (clamped; LT_GEOM/LT_CELL trace)
src/harness.cpp               litehtml document + render harness
src/harness_bump.cpp          same harness with a 256 MiB bump operator new
html/                         reproducers and large-vector variants
scripts/                      dump_add_cell.py, probe_phase*.py, xref scanners,
                              extract_binaries.sh (exact APK/IPA extraction)
logs/                         full build/run logs
evidence/                     selected logs, disassembly, hashes, manifests
```

Key evidence:

| file | content |
|---|---|
| `evidence/android_72889_add_cell_disasm.txt` | clamp disassembly 0x8b6b58-0x8b6d20 |
| `evidence/android_72789_add_cell_disasm.txt` | clamp disassembly 0x8ae058-0x8ae220 |
| `evidence/android_72929_add_cell_disasm.txt` | clamp disassembly |
| `evidence/ios_add_cell_disasm.txt` | clamp disassembly 0x410a064-0x410a1e0 |
| `evidence/android_clamp_hits.txt` | byte-pattern clamp hits in five Android libs |
| `evidence/xrefs_summary.txt` | one `colspan`/`rowspan` xref pair per binary; iOS extra extern accounting |
| `evidence/ios_second_copy_check.txt` | no second litehtml/table-grid copy in the IPA |
| `evidence/call_sites.txt` | one `add_cell` call site per platform |
| `evidence/table_grid_layouts.txt` | upstream 136-B vs Telegram Android 112-B vs iOS 120-B `table_grid` |
| `evidence/host_gdb_layout.txt` | gdb `ptype /o` for table_grid/table_row/table_column |
| `evidence/same_tag_proof.txt` | arithmetic proof and phase table |
| `evidence/host_upstream_rs0w_asan.log` | upstream OOB write at data-56 |
| `evidence/host_upstream_rsneg_asan.log` | upstream OOB at data-112 |
| `evidence/host_upstream_cs0_asan.log` | upstream OOB read at columns_data-4 |
| `evidence/host_upstream_rows2500_asan.log` | 229,376-B vector, target data-56 |
| `evidence/host_upstream_cols3000_asan.log` | 147,456-B column vector, read data-4 |
| `evidence/host_upstream_rs0w_release.log` | delta=102, write executes |
| `evidence/host_telegram_clamp_*.log` | fork clamps 0/-1 -> 1, no ASan |
| `evidence/host_atoi_overflow_tests.txt` | `atoi` overflow/INT_MIN host cases all clamped |
| `evidence/host_bump_hit_m_rows_count.log` | bump model target obj+0 (m_rows_count) |
| `evidence/host_bump_hit_m_rows_end.log` | bump model target obj+64 (m_rows.end) |
| `evidence/binary_sha256.txt` | exact binaries used |
| `evidence/binary_sources.md` / `evidence/binary_extract_check.txt` | APK/IPA -> extracted binary mapping and re-extraction hashes |

### 9.1 Rebuild commands

```bash
cd lab/rce_candidates/lt

# upstream litehtml, ASan/UBSan, LT geometry + span trace
cmake -S src/litehtml_upstream -B build/upstream_asan -DCMAKE_BUILD_TYPE=Debug \
  -DLITEHTML_BUILD_TESTING=OFF -DLITEHTML_ENABLE_LINT=OFF \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -DLT_GEOM -DLT_GEOM_ASAN -DLITE_SPAN_TRACE"
cmake --build build/upstream_asan -j"$(nproc)"
g++ -std=c++20 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
  -DLT_GEOM -DLT_GEOM_ASAN -DLITE_SPAN_TRACE \
  -Isrc/litehtml_upstream/include -Isrc/litehtml_upstream/include/litehtml \
  src/harness.cpp build/upstream_asan/liblitehtml.a build/upstream_asan/src/gumbo/libgumbo.a \
  -o build/upstream_asan/lt_harness

# Telegram canonical fork, ASan/UBSan, clamp trace
cmake -S src/litehtml_telegram -B build/telegram_asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -DLT_GEOM -DLT_GEOM_ASAN -DLITE_SPAN_TRACE"
cmake --build build/telegram_asan -j"$(nproc)"
g++ -std=c++20 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
  -DLT_GEOM -DLT_GEOM_ASAN -DLITE_SPAN_TRACE \
  -Isrc/litehtml_telegram/include -Isrc/litehtml_telegram/include/litehtml \
  src/harness.cpp build/telegram_asan/liblitehtml.a -o build/telegram_asan/lt_harness

# run
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./build/upstream_asan/lt_harness html/rs0w.html
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./build/telegram_asan/lt_harness html/rs0w.html
```

The bump model and phase probes:

```bash
# release library (no ASan)
cmake -S src/litehtml_upstream -B build/upstream_rel -DCMAKE_BUILD_TYPE=Release \
  -DLITEHTML_BUILD_TESTING=OFF -DLITEHTML_ENABLE_LINT=OFF \
  -DCMAKE_C_FLAGS="-O2 -g" -DCMAKE_CXX_FLAGS="-O2 -g -DLT_GEOM -DLITE_SPAN_TRACE"
cmake --build build/upstream_rel -j"$(nproc)"
g++ -std=c++20 -O2 -g -DLT_GEOM -DLITE_SPAN_TRACE \
  -Isrc/litehtml_upstream/include -Isrc/litehtml_upstream/include/litehtml \
  src/harness_bump.cpp build/upstream_rel/liblitehtml.a build/upstream_rel/src/gumbo/libgumbo.a \
  -o build/upstream_rel/lt_harness_bump
python3 scripts/probe_phase2.py     # finds a shape with D%56==0, k=D/56
./build/upstream_rel/lt_harness_bump html/bump_hit_count2.html
```

Binary verification (Capstone, host):

```bash
python3 scripts/dump_add_cell.py <libtmessages.49.so> 0x8b6b58 0x8b6d20 evidence/...
python3 scripts/dump_add_cell.py <TelegramUIFramework> 0x410a064 0x410a1e0 evidence/ios_add_cell_disasm.txt
```

The build directories are reproducible and were not committed as large
binaries; the logs and source needed to rebuild are preserved.

---

## 10. Honest limitations

* No device execution, no Scudo host binary, no MTE hardware. The MTE argument
  is the public Scudo design plus the measured Pixel 9 smaps in
  `MTE_safe_hunt_20261107.md`; it is not a new measurement.
* The bump model is not a target allocator; it only proves that the negative
  address arithmetic can land on `table_grid` fields if the object is before
  the data. It does not prove the real heap does that.
* The exact `table_grid` tail differs upstream (136 B, `m_column_widths`),
  Telegram Android (112 B, no extra member) and iOS (120 B, `m_cells_taken`);
  the main vector offsets 0..111 are the same. Any
  hypothetical metadata exploit would need per-platform/per-build layout
  handling, another reason it is not universal.
* The iOS MIE-off statement is from the entitlements evidence in
  `MTE_safe_hunt` §5.2; the iOS binary was not re-signed/entitlement-checked in
  this task.
* We did not build an RCE chain; the only host evidence is the OOB read/write
  and the address-reachability model. No RCE claim is made.

---

## 11. Final one-line answer

**LT cannot be made same-tag or universal: the shipped Telegram builds clamp
`rowspan`/`colspan` to [1,1000] before the grid is built (Android
72789/72889/72929 and iOS 13.2), and even unclamped the negative index addresses
outside the vector allocation; the vector's metadata is a separate,
cross-tag-checked `table_grid` allocation. LT is an upstream litehtml host
finding, not a second Telegram RCE; it is harder than N1, not easier.**
