# Static lib hunt — widget / QuickJS surfaces (libtmessages.49.so 72889/72929)

Date: 2026-11-08
Target: `Android_Beta_13.2.1_(72889).apk` / update build 72929,
`lib/arm64-v8a/libtmessages.49.so`
- 72889: 27,069,808 B, md5 `380c27db025a0b10f7ea5d6fd304bc8e`,
  BuildId `21ec5d5d81f69a9722cf60824e4c296e373bd87b`
- 72929: 27,070,032 B, md5 `f832021b2b3d6312e059602f4ecfdcc9`,
  BuildId `f0a1d2f382fc7c7b69241c1715785e28227d665b`
- ELF64 AArch64, stripped, NDK r27c (12479018), clang 18.0.3 (+pgo, +lto),
  LLD 18.0.3. 72889→72929 is a rebuild: `.text` +0xE4, all meaningful strings
  identical, same component versions → one target.

Scope (per 2026-11-08 directive): the uncovered **widget** surfaces of the
Telegram fork and QuickJS — wallet/TON, `answerRequest`, selection/text_runs,
Web Animations, compositor, QuickJS C API/bridge. **FFmpeg, libvpx, dav1d,
WebRTC, BoringSSL and other big/freshly-updated library differentials were
dropped**; their files are retained only as `evidence/out_of_scope_*` for
provenance and are not part of the conclusions.

Host-only. The Android library was **not executed**; the only execution is
x86_64 host Rust: a replica of `ton_core 0.1.4` (plus the bounded single-worker
T1 fuzz), the T5 wallet probe built against the pinned
`wallet-engine`/`ton-connect-core` crates (`wallet_tlb_repro`), and the WC-2
deterministic probe. No device, no Frida, no bot, no payload delivery. Pixel
stayed crash-log-only; iPhone/Sony untouched. No new workers: every run below
uses one process/one thread; the tree's other agents (litehtml 2, CSS 1) were
not started or disturbed. The 1.5 GiB `ulimit -v` on the WC-2 probe is an
address-space rlimit, not a fuzz worker.

**Scope correction (2026-11-08, later directive): widget-only.** Only the path
widget HTML/JS `wallet.sendTransaction` `payload`/`stateInit` (or
`wallet.signData` `cell`) -> `WidgetMedia.wallet` -> `GramWalletWidget` ->
`Wallet.d2.<init>` -> `WalletEngine2.isValidCellBoc` / wallet-engine TLB
readers is in scope. Wallet UI, deep links (`parse_ton_transfer_link`),
`messageBodyHash`, dApp TON Connect sessions and every other non-widget entry
were dropped and must not be used as the final payload. The WC-1 correction and
WC-2 below obey this: both are reached through the widget send request only.

**Scope correction for the litehtml HTML/CSS pass (2026-11-08):** that pass is
**widget HTML/CSS rendering path only** — litehtml/gumbo/`el_*` as used by the
widget sandbox, no media, no app UI, no non-widget renderer entry. Its PoC, if
one existed, must be a widget HTML/CSS payload rendered by the widget engine
and reproduced through the same harness entry; anything needing a non-widget
path is out of scope and dropped. Result: `notes/lib_hunt_fork0day_20261108.md`
(negative for a new memory-corruption primitive; the iOS/Android divergence it
found is DoS-hardening only).

---

## 0. Verdict

1. **WC-1 correction (supersedes note v1; widget scope).** `ton_core 0.1.4`
   really does index the BoC cell/root arrays unchecked (`raw_boc.rs:163/170`)
   and really is built `panic=abort`. But the widget entry never hands raw
   bytes to `ton_core`: `WalletEngine2.isValidCellBoc` ->
   `gram_adapter::is_valid_cell_boc` -> `gram_wallet::is_valid_cell_boc` ->
   `ton_connect_core::CellBoc::try_from`, and `CellBoc::try_from` runs
   `validate_single_root_boc` first (`GENERIC_BOC_MAGIC`, header flags,
   `cells == 0 || roots != 1 || absent != 0 || cells > cell_bytes/2` at
   `cell_boc.rs:146/166`, `root >= cells` at :153/173, and per-ref
   `reference <= cell_index || reference >= cells` at :242/289). That validator
   exists in `cell_boc.rs` at the **initial** TON Connect commit `62a75cb`
   (2026-08-17), i.e. before any wallet-engine version that can have shipped in
   13.2.1. The later `20adadc` (2026-09-27) added the depth/exotic hardening to
   `CellBoc` and also moved the wallet's own `types::boc::Boc` onto the same
   validator (`types/boc.rs` at `62a75cb` still called `TonCell::from_boc`
   directly). Both the app wrapper (uses `CellBoc`) and the shipped pin
   (`5c65e47`, 2026-10-02) are past that point. Host test against the pinned crate (`ton-connect-core 0.0.7` @
   `5c65e47`): the two WC-1 payloads **and** the 23-byte huge-cells payload all
   return `Err(...)` at `CellBoc::try_from` with **no panic**; only the raw
   `ton_core::cell::boc::BoC::from_bytes` call used by the note-v1 harness
   panics. **WC-1 is an n-day in `ton_core`, not a widget-reachable bug as
   shipped.** It remains live only for callers that bypass the validator
   (`message_body_hash` -> `Msg::from_boc` does, but it is not on the widget
   path; out of scope).
2. **WC-2 (new, widget-reachable, DoS): exponential `HashmapE` expansion in
   the wallet's TLB reader.** `StateInit::from_boc` (vendor/ton) parses
   `library: HashmapE 256 SimpleLib` with `DictDataParser`, which recurses into
   both refs of every node. A valid single-root BoC (accepted by
   `isValidCellBoc`) can encode a shared-ref DAG where every level branches to
   the *same* next cell and the final leaf completes the 256-bit key; the
   parser then materialises 2^depth distinct keys. 157-byte BOC -> 65,536
   entries / 89 ms; 175-byte -> 1,048,576 entries / 557 MB / 1.8 s; 184-byte
   under a 1.5 GiB cap -> `memory allocation of 813694992 bytes failed` ->
   abort (exit 134). On a phone this is an ANR/OOM kill from a ~250-char
   `wallet.sendTransaction` `stateInit`
   (`payloads/widget_wallet_send_stateinit_dictbomb.html`). A sibling in the
   same parser is *instant*: a 106-byte BoC makes a label-length underflow feed
   `usize::MAX` into `BigUint <<=`, requesting a 2^61-byte allocation and
   aborting immediately (`payloads/widget_wallet_send_stateinit_shiftbomb.html`,
   §4A.6). Both are **DoS, not memory corruption**, and do not meet the
   memory-corruption bar.
3. **No memory-corruption primitive was found on the widget wallet path.**
   `ton-connect-core` and `ton-connect-client` are `#![forbid(unsafe_code)]`;
   `wallet-engine/src`, `vendor/ton/src` and `ton_core-0.1.4/src` contain no
   `unsafe` token (grep). The only unsafe code on the path is generated uniffi
   scaffolding plus the hand-written JNI bridge, whose conversions are
   length-checked (`java_string`: `GetStringUTFChars` + `std::string`;
   `SensitiveString`: sized by `GetArrayLength`; RustBuffer lowering copies
   `std::string::data()/length()`; the C++ `FfiConverterString` pair is a
   1:1 copy). No controllable write, no deterministic type confusion and no
   length/offset mismatch was found. Exact reviewed sites are in §4B.
4. **`answerRequest`, selection/text_runs, Web Animations, compositor and the
   QuickJS C API/bridge were reviewed against the exact app source
   (`drklo/TMessagesProj/jni/twidget`, 13.2.1/7291) and are negative** for a
   new memory-safety bug. Details and the specific checks are in §3.
5. **The litehtml fork still carries the two known DoS n-days** (line-box
   loop, zero-period repeating gradient). They are renderer/DoS bugs already
   reported in the prior campaign; no new memory-corruption delta exists
   upstream after the fork point (upstream Nov 7–8 = docs/tests/cleanup/table
   layout).
6. **T1 fuzz is re-scoped.** It fuzzed `ton_core::BoC::from_bytes` directly
   (1.59×10^9 mutations, 2 unique panic sites). That is upstream-parser
   evidence, not app-reachability evidence; the widget entry rejects the same
   inputs before `ton_core` runs.

### 0.1 Bug log

| id | surface | class | evidence | status |
|---|---|---|---|---|
| **WC-1** | `ton_core 0.1.4` BoC parser (upstream) | DoS (Rust panic → SIGABRT); 75 GB allocation abort | host repro on raw `BoC::from_bytes` exit 101/134; T1 fuzz 2 sites; **widget entry returns `Err`** (`CellBoc::try_from`) | **n-day (fixed 0.3.5); NOT reachable via the widget `isValidCellBoc` entry** — corrected in §4 |
| **WC-2** | widget wallet `stateInit` → `StateInit::from_boc` `HashmapE` TLB reader | algorithmic: 2^depth dict expansion → ANR / OOM / allocator abort | host repro: 65,536 keys/89 ms (157 B BOC), 1,048,576 keys/557 MB/1.8 s (175 B), 813 MB alloc fail→exit 134 (184 B, 1.5 GiB cap); `CellBoc` accepts | **new, widget-reachable, DoS only** (not memory corruption) |
| **WC-2b** | same reader, `DictDataParser::remain_suffix_bit_len` | allocation-size mismatch: label-length underflow → unchecked `BigUint <<= usize::MAX` → 2^61-byte alloc → abort | 106 B BOC / 144 chars, `CellBoc=Ok`, `memory allocation of 2305843009213693992 bytes failed`, exit 134 | **new, widget-reachable, DoS only, instant** |
| LIT-1 | litehtml fork `line_box::new_width` | infinite loop / unbounded alloc (DoS) | prior renderer campaign | known, reported (n-day `7ea29569`) |
| LIT-2 | litehtml fork `repeat_color_points` | zero/tiny-period gradient loop/OOM (DoS) | prior `poc_gradient_repeat_oom_20261107.html` | known, reported (n-day `ead904b7`) |

No other new bug was logged for `answerRequest`, selection, Web Animations,
compositor or the QuickJS C API/bridge; the checks are in §3. No
memory-corruption primitive (controllable write / type confusion) was found on
the widget wallet surface; §4B lists every reader reviewed.

---

## 1. Widget-relevant component inventory

Exact evidence: `lab/lib_hunt_static/evidence/versions_and_build.txt`,
`jni_and_panic_runtime.txt`, `litehtml_fork_diff.txt`.

The APK ships only three distinct native libraries
(`libdatastore_shared_counter.so`, `liblanguage_id_l2c_jni.so`,
`libtmessages.49.so`); all of the following is statically linked into
`libtmessages.49.so`.

| Component | Version | Evidence |
|---|---|---|
| litehtml | Telegram in-tree fork `TelegramMessenger/twidget@759fcaf` (2026-11-05) | VENDOR.md "litehtml (modified)"; 73/138 shared source files byte-identical with upstream `d2e55e80`, 57 modified (+9,356 lines), 8 fork-only files (`css_effects`, `el_form`, `el_svg`, `render_grid`) |
| gumbo-parser | **0.10.1** layout (`src/gumbo/*.c`) | upstream litehtml `67a50fec`; upstream switched to 0.14.1 in `4d7f0bed` (2026-10-11) |
| QuickJS / widget-sandbox | app snapshot **2dfeee3e**, bundle **0.6.0** (0.17-era quickjs-ng) | prior `REPORT_upstream_diff_20261107.md`; no quickjs version literal in lib |
| **ton_core (Rust)** | **0.1.4** (2026-07-21) | `/cargo-home/.../ton_core-0.1.4/src/cell/boc/*` strings; `wallet_engine::types::boc::Boc` |
| uniffi_core | 0.32.0 | cargo path |
| serde_json | 1.0.151 | cargo path |
| wallet engine | **0.0.7**, pinned submodule `dkaraush/wallet-engine@5c65e47` (2026-10-02); `ton-connect-core 0.0.7`, `vendor/ton 0.1.3` | `gram-wallet/Cargo.lock` + source paths and error strings |
| BoringSSL/WebRTC/FFmpeg/etc. | present but **out of scope** | archived evidence only |

72889 vs 72929: `.text` 0x118702C → 0x1187110 (+0xE4); `.rodata` same size;
meaningful string tables identical (only two junk byte-strings differ). No
security-relevant diff visible at string/section level; the vulnerable
`ton_core 0.1.4`, QuickJS snapshot and litehtml fork are still present in both.

### 1.1 litehtml fork — missing upstream fixes

Two upstream fixes after the fork point are absent and both are **DoS only**:

- `7ea29569` (2026-10-26) "Fix item removal loop in `line_box::new_width`" —
  infinite loop / unbounded allocation;
- `ead904b7` (2026-10-31) "Infinite loop/OOM in `repeat_color_points` for
  repeating gradients with zero period" — the fork additionally has the
  tiny-positive-period gradient OOM.

Both were reproduced by the earlier renderer campaign
(`REPORT_upstream_diff_20261107.md`, `poc_gradient_repeat_oom_20261107.html`).
Upstream commits after 2026-11-02 (fetched 2026-11-08) are `f358a56a` cleanup,
`aa29c111` collapsed table-row layout, `6293d441` tests — no security fix.
Gumbo 0.12.2/0.14.1 hardening is not reachable: the serializer escapes
`& < > "` (`escape_text`/`escape_attr`) and tag/attribute names are restricted
to `[A-Za-z0-9:-]`, so no raw `&#…;` entity or zero-length tag reaches gumbo.

---

## 2. Coverage map (widget surfaces)

Full CSV: `lab/lib_hunt_static/coverage_map.csv`. "Reviewed" means the exact
app/canonical source was read in this pass; "covered" means an existing
host harness + report exists.

| Surface | Entry (72889) | Status | Note |
|---|---|---|---|
| HTML payload | `create @0x98d56c` | covered | JS bundle → ops → serialized HTML → litehtml |
| data/theme/safeArea JSON | `data @0x9935bc` | covered | `fuzz_json_parser` 10.99M |
| **answerRequest** | `0x9938d8` | **reviewed negative** | bot answer result: UTF-8/NUL/len checked |
| RenderOps | `AndroidRenderer::message` | covered | `fuzz_renderer_ops` 977k |
| canvas ops / producer / read | `0x9944a4` etc. | covered | 4.02M canvas fuzz; Java bounds |
| CSS/DOM/layout/paint/SVG | — | covered | `fuzz_css*`, `fuzz_litehtml*`, SVG corpus |
| incremental update | — | covered | `fuzz_litehtml_update` |
| hit test / touch | — | covered | `fuzz_hit_test` |
| **selection / text_runs** | — | **reviewed negative** | §3.2 |
| **Web Animations** | — | **reviewed negative** | §3.3 |
| **compositor / layers** | — | **reviewed negative** | §3.4 |
| **QuickJS C API / bridge** | — | **reviewed negative** | §3.5 |
| bridge SDK policy | — | covered + reviewed | `fuzz_bridge_sdk`; links/UTF-8/base64 |
| Intl | — | covered | `fuzz_intl` |
| **wallet / TON (widget-only)** | `isValidCellBoc @0x738454` | **WC-1 corrected; WC-2 new DoS** | §4, §4A |
| media/RLottie/SQLite | — | **out of scope** | dropped per directive |

Ranking of remaining un-fuzzed widget work: wallet/TON (confirmed) >
`answerRequest` (reviewed; a small JSON harness would still be useful) >
selection > Web Animations > compositor. The renderer/CSS/SVG/canvas grid is
saturated and negative except for the known DoS cases.

---

## 3. Surface reviews (exact source, negative results)

Source tree used: `drklo/TMessagesProj/jni/twidget` commit `7be672e`
(13.2.1/7291); line numbers below are from that tree. Excerpts:
`lab/lib_hunt_static/evidence/widget_surface_review_20261108.txt`.

### 3.1 `answerRequest` — `twidget-bridge.cpp:1145`, `sandbox_engine.cpp:771`, `sdk_policy.cpp:562`

Chain: JNI `answerRequest(JJI[B)` → look up the responder under
`requestsMutex`, erase, map `failure` 1..5 to `Timeout/RateLimited/Failed/
Rejected/BadRequest` (anything else → `None`), copy `result` bytes only when
`failure == None` and the array is non-null, call the engine responder. On the
engine thread:

- `checkRequestAnswer` rejects non-well-formed UTF-8, embedded NUL, and
  results longer than `MAX_REQUEST_RESULT_BYTES`; invalid gets
  `INVALID_ANSWER` and a diag, never a crash.
- Unknown/answered request ids are ignored (`requests.find` under lock).
- The JNI `bytes()` helper gets `GetArrayLength`, allocates exactly that
  `std::string`, `GetByteArrayRegion`; null arrays become empty.
- No unchecked length is used as an index; no fixed buffer.

**Negative.** A dedicated harness is still absent (the JSON parser itself is
covered by `fuzz_json_parser`), but the answer path is bounds- and
UTF-8-checked.

### 3.2 Selection / `text_runs` — `renderer.cpp:5489-5760`

- `text_runs()` walks the litehtml tree, stores `owner/offset/block/text` with
  `lengths[owner] += text.size()`; offsets are cumulative and bounded by the
  document text.
- `locate()` only matches `p.offset` inside `[r.offset, r.offset + text.size()]`;
  no subtraction that can underflow.
- `selected_text()` guards `from >= to`, `!out.empty()`, and `r.text[from]`
  with `from < to <= r.text.size()`.
- `point_at()` computes byte boundaries with `inside_sequence(i)` that checks
  `i < text.size()` before indexing.
- `run_advance()` caches advances per byte offset; `substr(0, bytes)` clamps.

One **logical** edge: if a text run starts with a UTF-8 continuation byte
(invalid UTF-8 from a malformed document), `point_at`'s `while
(inside_sequence(bytes)) bytes--;` can underflow `bytes` to `SIZE_MAX`, and
`offset + bytes` wraps to `offset-1`. It is not an OOB read (`inside_sequence`
checks the bound first) and only shifts the selection anchor by one byte in
invalid-UTF-8 text; not reported as a bug. Selection is client/touch-driven,
not attacker-triggered.

**Negative** for memory safety.

### 3.3 Web Animations — `animations.cpp:820-1280`

- `WebAnimation::parse` requires `aid`/`target` numbers, `frames` ≤64, timing
  fields finite and |value| ≤ 86400 s, iterations/iterationStart ≤1e9,
  direction/fill enums, easing ≤256 points, composite enums, start/hold
  finite, playbackRate finite and |rate| ≤1000. `frames` offsets are checked
  `offset >= previous && <= 1`; a NaN offset passes the comparisons, but
  downstream `web_value`/`compute` use comparisons that are false for NaN and
  fall to defaults; no index is derived from the NaN.
- `web_value` inserts 0/1 endpoints, so `frames.size() >= 2` before
  `frames.size() - 2`; `start/end` are clamped.
- `sample_web` maps by target/aid and calls `compute`, which rejects
  non-finite local time; `web_add`/`interpolate` are string/number only.

No OOB/overflow. **Negative**; no dedicated fuzz (the renderer animation
corpus exercises it indirectly).

### 3.4 Compositor — `compositor.cpp:475`

- `resume_track` requires `keys.size() >= 2`, clamps the phase, and only reads
  `keys[i+1]` while `i+2 < size`.
- `damage_between` derives `head/tail` only within both sizes; `MAX_KEYS`,
  `MAX_DAMAGE_RECTS`, `MAX_DEPTH` bound the work.
- `ink_of`/`transformed` operate on floats and clamp/expand rects; no array
  indexing from unvalidated counts.
- Layer keys are value types; no raw node pointers in the key/digest.

**Negative** for memory safety; the paint/damage paths are exercised by
`fuzz_twidget_renderer`.

### 3.5 QuickJS C API / bridge — `quickjs_context.cpp`, `qjs_shim.c`, `sandbox_engine.cpp:150-670`

- `QuickJSTrampoline::call` checks `magic < functions_.size()`, converts
  string/number args, and returns `HostReturn` via `qjs_new_string_len` /
  `qjs_new_array_buffer_copy`; `qjs_typed_array_bytes` checks
  `offset <= size && length <= size - offset` (and is only used by the iOS
  Swift bridge, not Android).
- `QuickJSContext::call/evaluate/readResult` pass explicit lengths and free
  every `JSValue`; `evaluateBytecode` verifies the TWQB header/source hash and
  is never used for widget code.
- The host functions are `__host`/`__hostBinary` only on Android; after boot
  the engine evaluates
  `delete globalThis['__host','__hostBinary','__hostCanvas','__hostOps','__twDispatch']`
  and captures `__twDispatch` privately, so widget JS cannot reach the raw
  host functions. It can only use the bundle's validated API.
- `hostCall` dispatches a fixed set of kinds; bridge JSON is parsed with depth
  128 and `checkBridgeCall` re-validates method/args; storage commits are
  size-checked; `random` is clamped to 65536; timers are capped by
  `maxTimers`; `intl` returns a formatted string.
- `qjs_take_exception_description` builds `name + message + stack` with
  `strlen`/`snprintf` and frees the C strings; no unchecked copy.
- `JSThread::after` clamps timer delays (`NaN`→0, `inf`→cap), sweeps
  cancelled timers once the queue doubles, and `run` cancels/clears timers on
  stop; `join` cannot self-join. `TrustedValidator` catches `JSError` per call
  and keeps a 256 MB runtime; `WidgetHost` thread handoff is the already
  audited lifetime path (`REPORT_create_destroy_lifetime_20261107.md`).

**Negative** for memory safety. One benign semantic quirk: host string args are
copied with `std::string(c)` after `JS_ToCString`, so an embedded NUL truncates
the C++ argument; the bundle's own policy checks run on the same truncated
string and the host revalidates, so this is not a bypass of the link/request
checks (no path where the truncated prefix is more permissive than the full
string in a security-relevant way). Not reported as a bug.

---

## 4. WC-1 revisited (widget scope) — `ton_core 0.1.4` BoC index underflow is NOT reachable through `isValidCellBoc`

**Correction to note v1.** The `ton_core` defect and the `panic=abort` runtime
are real (4.1, 4.4), but the widget entry validates the BoC envelope before
`ton_core` sees a single cell (4.2, 4.3). v1's reachability claim rested on a
host harness that called `ton_core::cell::boc::BoC::from_bytes` directly — not
the app entry. The corrected status is in 4.6; the evidence is
`evidence/wallet_entry_wc1_blocked_20261108.log`.

### 4.1 Root cause

`ton_core 0.1.4` (`raw_boc.rs:153-173`) builds cells bottom-up:

```rust
for (cell_index, cell_raw) in self.raw_cells.into_iter().enumerate().rev() {
    for ref_index in &cell_raw.refs_pos {
        if *ref_index <= cell_index { bail!("ref to parent cell"); }
        refs.push(cells[cells_len - 1 - ref_index].clone());   // line 163
    }
    cells.push(cell_raw.into_ton_cell(refs));
}
for root_index in self.roots_pos {
    roots.push(cells[cells_len - 1 - root_index].clone());     // line 170
}
```

`ref_index`/`root_index` are read from the untrusted BOC and are **not checked
against `cells_len`**. If `index >= cells_len`, the `usize` subtraction wraps
and the slice index panics:
`index out of bounds: the len is 1 but the index is 18446744073709551611`.
`RawBoC::from_bytes` also does `Vec::with_capacity(cells_cnt)` before reading
any cell, so a 23-byte BOC with `cells=0x10000000` tries to allocate
75,161,927,680 bytes and aborts.

Upstream fixed this in **0.3.5** (2026-09-28): the header is validated before
allocation, and `build_ton_cells` adds
`if ref_index >= cells_len { bail }` / `if root_index >= cells_len { bail }`
(plus a header-level `root_pos >= cells_cnt` check). 0.1.4 is the newest
0.1.x; no backport. `evidence/ton_core_boc_diff.txt`.

### 4.1.1 Runtime is panic=abort (what an abort would look like)

The binary embeds `ton_core-0.1.4/src/cell/boc/*` paths and the Rust runtime is
`panic_abort`:

```
/cargo-home/.../ton_core-0.1.4/src/cell/boc/raw_boc.rs
/rustc/31fca3a.../library/panic_abort/src/lib.rs
```

No `panic_unwind`/`catch_unwind` path is present. A Rust panic therefore
calls `abort()`; the app process gets SIGABRT (host `-C panic=abort` build:
exit 134). Cross-check: a locally built `-C panic=unwind` binary contains
`library/panic_unwind/...` and **no** `panic_abort` path; a `-C panic=abort`
binary contains only `panic_abort` — exactly the shipped pattern
(`evidence/panic_runtime_test.txt`). This part of v1 stands.

### 4.2 Why the widget entry does not reach the panic

`App` source (13.1.1 tree, same entry as the 13.2.1 binary):

- `Android/TMessagesProj/jni/wallet/WalletEngineBridge.cpp:575` —
  `Java_..._isValidCellBoc` calls `gram_adapter::is_valid_cell_boc(java_string(...))`.
- `Android/TMessagesProj/jni/wallet/GramWalletAdapter.cpp:15` — forwards to
  `gram_wallet::is_valid_cell_boc`.
- `Android/TMessagesProj/jni/gram-wallet/src/lib.rs:34` —
  `ton_connect_core::CellBoc::try_from(boc).is_ok()`.
- `ton-connect-core/src/cell_boc.rs:120-123` — `parse_single_root` calls
  `validate_single_root_boc(bytes)?` **before** `TonCell::from_boc`.

`validate_single_root_boc` closes exactly the two WC-1 holes plus the
allocation-amplification one:

| check | line (current / initial 62a75cb) | WC-1 site blocked |
|---|---|---|
| `cells == 0 \|\| roots != 1 \|\| absent != 0 \|\| cells > cell_bytes/2` | 166 / 146 | 75 GB `Vec::with_capacity(cells_cnt)` |
| `root >= cells` | 173 / 153 | `raw_boc.rs:170` root index |
| `reference <= cell_index \|\| reference >= cells` (per ref) | 289 / 242 | `raw_boc.rs:163` ref index |
| `MAX_CELL_DEPTH = 1024` + exotic layout | 22, 242-311 / absent in initial, added 2026-09-27 | stack-overflow / exotic-hash panics |

The first three checks are in the **initial** `cell_boc.rs` commit `62a75cb`
(2026-08-17), so no wallet-engine version that can have shipped in the
November 2026 APK lacks them. The 2026-09-27 commit `20adadc` (the one that
also adds the signData strings present in the binary) adds the depth/exotic
hardening on top.

Host evidence (`wallet_tlb_repro`, crate `ton-connect-core 0.0.7` @ pinned
`5c65e47`, `ton_core 0.1.4` path):

```
CellBoc::try_from(te6ccgEBAQEAAgUAAA==)  = Err(...)  [no panic]   # root index 5
CellBoc::try_from(te6ccgEBAQEAAwABAAU=)  = Err(...)  [no panic]   # ref past end
CellBoc::try_from(te6ccgQBEAAAAAAAAAEAAAAAAAAAAAA=) = Err(...)  # cells=0x10000000
CellBoc::try_from(te6ccgEBAQEAAgAAAA==)  = Ok
raw BoC::from_bytes(te6ccgEBAQEAAgUAAA==) = PANIC (index 18446744073709551611)
```

Residual uncertainty: the app tree on disk is 13.1.1 (2026-10-25); the APK is
13.2.1. A device check is still the cheapest falsification: on a wallet-enabled
account, the WC-1 payload should be rejected at parse time (invalid-cell error)
and must not abort. Until that runs, the correction is **high-confidence
static**, not device-verified.

### 4.3 Reachability chain (widget → native)

1. Widget JS: `TelegramWidget.wallet.sendTransaction(tx, data)` (or
   `wallet.signData`) → bundle `N1`/`a1` validation. JS checks only shape,
   base64 charset and lengths: `payload`/`stateInit` ≤8192 chars, `cell`
   ≤4096, `messages` 1..255, total ≤65536. **No BOC structure check**
   (`evidence/js_wallet_validation.txt`).
2. Host tap/wallet gate: wallet actions require a user gesture and
   `wallet===true`. Java: `WidgetSandboxSession` reads signal 19
   (`WidgetSandboxSession.java:507`) and calls `listener.onWallet(id, call)`;
   `WidgetMedia.wallet` (`WidgetMedia.java:971`) checks `walletAvailable`
   (`canQuery && !preview && config.walletAvailable`), the bot peer and a live
   fragment, then calls `GramWalletWidget.open(context, account, bot, call,
   ...)` with the widget-provided TON Connect call. The obfuscated
   `org.telegram.utils.twidget.u.i` smali is the same handler
   (`evidence/java_widget_wallet_u_i.txt`).
3. `GramWalletWidget.open` parses the request and calls
   `Wallet/f2.G` / `Wallet/f2.I` → `Wallet/d2.<init>(JSONObject)`
   (`evidence/java_wallet_boc_path.txt`). `d2` checks address/amount, then for
   each non-null `payload`/`stateInit` calls
   `WalletEngine2.isValidCellBoc(String)`; `f2.G` does the same for the
   signData `cell`.
4. `Java_..._WalletEngine2_isValidCellBoc` at **0x738454** converts the
   jstring (verified in the shipped lib: `GetStringUTFChars` + `strlen` +
   `std::string`, then a `bl` to the uniffi C++ `gram_wallet::is_valid_cell_boc`
   wrapper, which lowers the string and calls the Rust
   `uniffi_gram_wallet_fn_func_is_valid_cell_boc`). In the app source that Rust
   function is `gram_wallet::is_valid_cell_boc` →
   `ton_connect_core::CellBoc::try_from` (§4.2).
   v1 claimed this calls raw `ton_core::cell::boc::BoC::from_base64`; that is
   wrong for this entry. The `ton_core-0.1.4/src/cell/boc*` strings in the
   binary come from the downstream `TonCell::from_boc` that runs **after**
   validation.
5. Corrected chain: `CellBoc::try_from` → `validate_single_root_boc` →
   `Err(InvalidBoc)` for every WC-1 shape; `ton_core::RawBoC::into_ton_cells`
   is never reached with an out-of-range index. The panic path in 4.1 is live
   only for a caller that skips the validator (none on the widget path).

`wallet.signData({type:"cell", schema, cell})` reaches the same validator via
`f2.G` / `parse_single_root`; same result.

### 4.4 Host reproduction (exact)

**v1 harness = raw parser, not the app entry.** `lab/lib_hunt_static/ton_repro`
is a Cargo project against `ton_core 0.1.4` (crate tarball in
`ton_core_crate/`); it calls `BoC::from_bytes` directly. This reproduces the
upstream defect only. The app entry is reproduced by
`lab/lib_hunt_static/wallet_tlb_repro` (§4.2, log
`evidence/wallet_entry_wc1_blocked_20261108.log`).

```
# root index 5 with 1 cell
echo te6ccgEBAQEAAgUAAA== | base64 -d | xxd
b5ee9c72 01 01 01 01 00 02 05 00 00

cargo build --release
./target/release/ton_repro te6ccgEBAQEAAgUAAA==
  panicked at .../raw_boc.rs:170:29:
  index out of bounds: the len is 1 but the index is 18446744073709551611
  exit=101

RUSTFLAGS="-C panic=abort" cargo build --release --target-dir target_abort
./target_abort/release/ton_repro te6ccgEBAQEAAgUAAA==
  ... Aborted ... exit=134        # SIGABRT
```

- ref-index variant: `te6ccgEBAQEAAwABAAU=` → panic at `raw_boc.rs:163`.
- valid control: `te6ccgEBAQEAAgAAAA==` → `OK roots=1`.
- huge-cells variant: 23-byte BOC `cells=0x10000000` → 75,161,927,680-byte
  allocation failure → abort (`(ulimit -v 524288;
  cargo run --release --bin huge_cells)`).

Logs: `evidence/ton_repro_unwind.log`, `ton_repro_abort.log`,
`ton_repro_huge_cells.log`.

### 4.5 PoC payloads

- `payloads/widget_wallet_send_payload.html` — tap →
  `wallet.sendTransaction({messages:[{address:<valid 48-char TON address>,
  amount:"1", payload:"te6ccgEBAQEAAgUAAA=="}]}, "claim")`.
- `payloads/widget_wallet_send_stateinit.html` — same via `stateInit`.
- `payloads/widget_wallet_sign_data_cell.html` — `wallet.signData({type:
  "cell", schema:"test", cell:"te6ccgEBAQEAAwABAAU="}, "sign")`.
- `payloads/boc_root_oob.b64`, `boc_ref_oob.b64`, `boc_valid.b64`,
  `boc_huge_cells.b64`.

### 4.6 Status / severity / honest unknowns

- **Corrected status:** `ton_core 0.1.4` n-day (fixed 0.3.5, 2026-09-28, no
  CVE found) — **not reachable through the widget `isValidCellBoc` entry**.
  The v1 claim "new, unreported widget DoS" is withdrawn. `/ton_repro` remains
  valid as an upstream-parser repro only; the app-entry repro is
  `wallet_tlb_repro` and returns `Err`.
- **Why v1 was wrong:** it tested `BoC::from_bytes` and inferred the entry from
  binary path strings (`ton_core::cell::boc`, `wallet_engine::types::boc::Boc`)
  without checking `CellBoc::try_from`/`Boc::try_from`, both of which call the
  validator first. The validator was present in the initial TON Connect commit.
- **Class if it were reachable:** DoS (process abort); safe Rust, no memory
  corruption, no RCE.
- **Not device-verified either way.** Cheap device check: send the WC-1 payload
  from *any* wallet-enabled widget; expected = invalid-cell rejection, not a
  crash. If it does abort, the app's gram-wallet/`CellBoc` wiring differs from
  the 13.1.1 source and this correction must be re-opened.
- **Side note:** `WalletEngine2.nativeMessageBodyHash` *does* call
  `Msg::<TonCell>::from_boc` on a raw base64 string without the validator
  (`gram-wallet/src/lib.rs:43`); it is called only on wallet-engine-produced
  BOCs (`WalletEngine2.java:1351-1354`), not on widget input, so it is out of
  the widget scope. If a future caller ever feeds it a widget string, WC-1
  becomes live again through that call site.

---

## 4A. WC-2 — exponential `HashmapE` expansion in `StateInit::from_boc` (new, widget-reachable, DoS)

### 4A.1 Root cause

`build_internal_message` (`wallet-engine/src/wallet/transfer.rs:366`)
deserializes the widget `stateInit` BoC as a TLB `StateInit`:

```rust
let state_init = StateInit::from_boc(state_init.as_bytes().to_vec())
    .map_err(TransferError::InternalMessage)?;
```

`StateInit` (`vendor/ton/src/block_tlb/state_init.rs:15-25`) contains
`library: HashmapE 256 SimpleLib`, parsed by
`TLBHashMapE::read` -> `DictDataParser::parse_impl`
(`vendor/ton/src/tlb_adapters/dict/data_parser.rs:37-91`). At every internal
node `parse_impl` reads a label and then **recurses into both refs**. Nothing
caps the number of *paths*: a cell may be referenced twice, so a `depth`-level
DAG where both refs of every node point at the same child is a valid BoC and
yields 2^depth leaf visits and 2^depth distinct keys in the returned `HashMap`.

The wallet's BoC validator does not stop it: the envelope is a legitimate
single-root BoC (magic, one root, forward refs, depth 1024 max, ordinary cells)
— only the *content* is adversarial. `CellBoc::try_from` returns `Ok`, so this
is not a validator bypass in the WC-1 sense; the validator simply does not
police TLB shape.

### 4A.2 Reachability (widget-only)

1. Widget JS `wallet.sendTransaction({messages:[{address, amount,
   stateInit: <bomb>}]})`. Bundle `u1` accepts `stateInit` as base64
   `[A-Za-z0-9+/_-]+={0,2}` with length ≤8192 (`evidence/js_wallet_validation.txt`);
   the crafted BOC is 157-193 bytes / 212-260 base64 chars for depths 16-24
   (depth 26 = 272 chars), far below the 8192-char limit.
2. `Wallet.d2.<init>` -> `WalletEngine2.isValidCellBoc(stateInit)` -> `Ok`.
3. `GramWalletTonConnect.Transaction.Message` stores the string; the wallet
   sheet calls `WalletEngine2.previewTonConnect(request, ...)`
   (`WalletEngine2.java:164`) -> JNI `nativePreviewTonConnect` (0x73dcf8) ->
   `wallet->preview_ton_connect` -> `preview_send` ->
   `prepare_transfer_emulation` -> `build_internal_messages` ->
   `StateInit::from_boc` (`src/engine/preview.rs:187`,
   `src/wallet/transfer.rs:189,273,366`).
4. The dict expansion runs on the wallet engine thread, before the user
   confirms anything (the preview is what the sheet displays).

Preconditions match WC-1: wallet-enabled account, widget host accepts the
request, one tap.

### 4A.3 Host reproduction (exact)

`lab/lib_hunt_static/wallet_tlb_repro` (same `ton-connect-core` crate + local
`ton_core 0.1.4`; `dictbomb` builds `<depth>` branching levels, both refs of
each node to the same child, and a leaf whose label completes the 256-bit key
so every path terminates in a `SimpleLib` value).

```
cargo build --release
./wallet_tlb_probe dictbomb 16
  depth=16 boc_bytes=157 CellBoc=Ok
  StateInit::from_boc = Ok(library=65536) in 89 ms rss=42 MB
./wallet_tlb_probe dictbomb 20
  depth=20 boc_bytes=175 CellBoc=Ok
  StateInit::from_boc = Ok(library=1048576) in 1.81 s rss=557 MB
(ulimit -v 1572864; ./wallet_tlb_probe dictbomb 22)
  depth=22 boc_bytes=184 CellBoc=Ok
  memory allocation of 813694992 bytes failed
  Aborted (SIGABRT), exit=134
(ulimit -v 1572864; ./wallet_tlb_probe dictbomb 24)   # the shipped widget payload
  depth=24 boc_bytes=193 CellBoc=Ok
  memory allocation of 1358954512 bytes failed
  Aborted (SIGABRT), exit=134
```

Scaling is ~4x per +1 level in both time and memory (2^depth keys held in a
`HashMap<BigUint, SimpleLib>`). On a phone, depth 22-26 (~210-272 base64 chars)
is an ANR followed by OOM/allocator abort; the exact kill point depends on the
device heap limit. Log:
`evidence/wallet_tlb_stateinit_dictbomb_20261108.log`.

### 4A.4 Widget payload

`payloads/widget_wallet_send_stateinit_dictbomb.html` (depth 24,
`payloads/boc_stateinit_dictbomb_d24.b64`; also d22/d26). The payload passes
the bundle schema and `isValidCellBoc`; no other field is unusual.

### 4A.5 Status / classification

- **New and deterministic** (no parser panic involved; pure algorithmic
  expansion), widget-reachable, cross-platform by construction: the wallet
  engine and `vendor/ton` are shared Rust, so the same `stateInit` reaches the
  same reader on iOS/desktop clients that use wallet-engine. Not device-tested
  here (host-only; no wallet account).
- **DoS only** (ANR/OOM/abort). It is **not** the requested memory-corruption
  primitive: safe Rust, no write outside an allocation, no type confusion.
- Severity: a bot can freeze/kill the client of any user who taps a widget
  control once. Same one-tap bar as WC-1, but this one is actually reachable.
- Possible hardening for upstream: cap dict node/path count or reject shared
  refs inside a dict; `TLBHashMapE` currently has no path budget.

### 4A.6 WC-2b — the same reader also has an instant allocation-size bug

`DictDataParser::remain_suffix_bit_len`
(`data_parser.rs:94-97`) computes

```rust
let prefix_len_left = self.key_bits_len - self.cur_key_prefix.bits() as usize + 2;
(prefix_len_left as f32).log2().ceil() as usize
```

with unchecked `usize` arithmetic. A Short label longer than the remaining key
(300 bits on the first dict node is enough) makes the running prefix exceed
`key_bits_len + 2`; on the next node the subtraction wraps, the computed
suffix length becomes ~64, and a `Same` label reads a 64-bit `prefix_len` that
is used directly:

```rust
let prefix_len = parser.read_num::<usize>(prefix_len_len)?;  // 64 bits here
...
self.cur_key_prefix <<= prefix_len;                          // no bound
```

With `prefix_len = usize::MAX`, `BigUint::shl` requests a 2^61-byte allocation
and Rust aborts. 106-byte BoC / 144-char base64, accepted by `CellBoc`:

```
boc_bytes=106 CellBoc=Ok
StateInit::from_boc = memory allocation of 2305843009213693992 bytes failed
Aborted (SIGABRT), exit=134
```

Payload: `payloads/widget_wallet_send_stateinit_shiftbomb.html`; log
`evidence/wallet_tlb_hashmap_shiftbomb_20261108.log`. This is an instant
process abort (no freeze), same widget entry and preconditions as WC-2. It is
still **DoS only** — an allocation-size mismatch in safe Rust, not an
out-of-bounds write. (In a debug/overflow-checks build the same input panics at
the subtraction; the shipped release profile has overflow checks off.)

## 4B. TLB/FFI call sites reviewed (widget scope, negative for memory corruption)

Reviewed against the pinned wallet-engine `5c65e47`, `ton_core 0.1.4`,
`vendor/ton 0.1.3` and the app JNI (13.1.1 tree):

| site | input | result |
|---|---|---|
| `gram-wallet/src/lib.rs:34` `is_valid_cell_boc` -> `CellBoc::try_from` | widget `payload`/`stateInit`/signData `cell` | envelope validated; no panic on WC-1 shapes |
| `ton-connect-core/src/cell_boc.rs:134-311` `validate_single_root_boc`/`validate_cells` | same | checked arithmetic + `get`, linear, allocation ≤ input; no panic found |
| `ton-connect-core/src/cell_boc.rs:120` `parse_single_root` -> `TonCell::from_boc` | validated bytes | `RawBoC::into_ton_cells` indices are in range; `Vec::with_capacity` bounded by `cells <= cell_bytes/2` |
| `src/types/boc.rs:45-56` `Boc::try_from(Vec<u8>)` (SendIntent lift) | widget `stateInit`/`payload` strings | same validator, then `TonCell::from_boc`; uniffi `TryFrom` failure is a normal error |
| `vendor/ton/src/block_tlb/state_init.rs:15` `StateInit::from_boc` | widget `stateInit` | TLB fields fixed-size; `library` `HashmapE` is the WC-2 bomb (DoS), no OOB/UB |
| `vendor/ton/src/tlb_adapters/dict/data_parser.rs:37-91` + `tlb_hash_map*.rs` | dict cells | recursion bounded by BoC depth (≤1024); label shifts are unbounded after the WC-2b underflow; exponential *work* (WC-2) but memory-safe |
| `vendor/ton/src/block_tlb/msg_types/msg.rs` `Msg::from_cell` | wallet-built messages only | not fed widget cells in the widget flow; no issue found |
| `ton-connect-core/src/signing.rs:337-421` `cell_signing_hash` (signData `cell`) | widget signData cell | `parse_single_root` (`:392`) + builder; no TLB parse of content |
| `ton_core-0.1.4/src/cell/cell_parser.rs` | all TLB readers | length-checked; `read_bits` allocates before `ensure_enough_bits`, but callers on this path use schema-fixed lengths (dict labels are normally ≤9 bits, but see WC-2b) |
| `ton_core-0.1.4/src/cell/cell_meta_builder.rs` hash/depth | any validated cell | `LevelMask` up to 7 handled; hashes `SmallVec` indexed ≤3; no OOB in hash/depth paths; mask-7 ordinary cell hashes OK on host |
| JNI `WalletEngineBridge.cpp:575` `isValidCellBoc`, `:1020` `nativePreviewTonConnect`, `:1048` `nativeSignMessage`, `:1071` `nativePrepareTonConnectTransfer` | widget strings/arrays | `java_string` (GetStringUTFChars + `std::string`), `SensitiveString` sized by `GetArrayLength`, the `fields` array stride fixed at 5, handle lookup under mutex + `shared_ptr` copy |
| `prebuild/include/wallet-engine/gram_wallet.cpp` / `wallet_engine.cpp` (uniffi C++) | RustBuffer <-> `std::string` | 1:1 copies `(data,len)`; lower casts `size_t` to `int32_t` but widget strings are ≤8192; no mismatch reachable |
| Java `WalletEngine2.textCommentFromBody` (`WalletEngine2.java:849-935`) | widget `payload` (already envelope-validated) | hand-rolled BoC reader with `ByteBuffer` bounds checks and `readBocInt`; exceptions are Java-level, no native memory access |

No `unsafe` block exists in `wallet-engine/src`, `vendor/ton/src` or
`ton_core-0.1.4/src`; `ton-connect-core`/`-client` are
`#![forbid(unsafe_code)]`. That is why the negative is structural rather than
"we did not find it": a controllable write would have to live in the generated
uniffi C++ or the JNI bridge, and both were reviewed above.

---

## 5. T1 fuzz — `ton_core` BoC parser (approved, small)

Run: `lab/lib_hunt_static/ton_repro/src/bin/boc_fuzz.rs`, 1 process, `taskset
-c 0` (1 worker), `ulimit -v 524288` (512 MB), `FUZZ_SECS=600`. Inputs with
`cells_cnt > 256` are filtered by the fuzzer guard so the fuzzer itself cannot
hit the known 75 GB allocation; the unguarded path is the deterministic
huge-cells repro. Parser: `BoC::from_bytes` (identical to the wallet's
`from_base64` after decoding); panics are caught with `catch_unwind`
(panic=unwind build) so one panic does not end the run.

```
cargo build --release --bin boc_fuzz
(ulimit -v 524288; FUZZ_SECS=600 taskset -c 0 \
  ./target/release/boc_fuzz ../evidence/boc_fuzz_findings_600s.log)
```

Result (see `evidence/boc_fuzz_run_600s.log` and
`boc_fuzz_findings_600s.log`):

- **1,591,234,668** mutations, **721,866,591** accepted inputs
  (header-filtered);
- **85,679,753** caught panics;
- **unique panic sites: 2** — `raw_boc.rs:163` (ref index,
  63,859,816 hits) and `raw_boc.rs:170` (root index, 21,819,937 hits). The
  log contains one sample per site; the counts are in the run summary.
- run exit 0 (`catch_unwind` caught all panics; no abort).
- **No third parser panic site** (no `read_var_size`, `RawCell::read`,
  base64, or cell-parser crash).

Interpretation: the two sites are the same root cause as WC-1 (missing
`index < cells_len` checks), not two separate bugs. The fuzzer's deterministic
sibling (huge `cells_cnt`) is the second consequence of the same missing
header validation. **Caveat added in the 2026-11-08 T5 pass:** this fuzzer
calls `BoC::from_bytes` directly. It is not evidence that the widget entry
reaches those panics; `CellBoc::try_from` rejects the same inputs (§4.2). T1
therefore remains useful only as upstream-parser coverage.

The T5 follow-up (this pass) audited the actual widget-reachable readers:
negative for memory corruption, one new DoS (WC-2, §4A).

---

## 6. Remaining widget/QuickJS audit targets (small only)

No heavy fuzz was started beyond T1. Proposed, all 1-worker and ≤512 MB:

1. **T2 `answerRequest` JSON harness** (30 min): call the native path /
   `SandboxEngine::answerRequest` with arbitrary bot result bytes; expect the
   existing UTF-8/NUL/length checks to hold. Low value after §3.1; only if a
   harness is cheap.
2. **T3 selection** (10 min): text runs + touch/selection ranges, including
   invalid UTF-8 runs (the `bytes--` edge) and huge/astral text. ASan.
3. **T4 Web Animations** (20 min): extend `fuzz_renderer_ops` seeds with
   `element.animate()`/`@keyframes`, NaN offsets, `Infinity`, huge iteration
   start/rate; the parser is already bounded, so this is confirmation.
4. **T5 wallet TLB/serde audit — DONE 2026-11-08 (this pass), widget-only.**
   Reviewed `wallet-engine/src/**`, `vendor/ton` readers, `ton_core 0.1.4`,
   the uniffi C++/JNI bridge and the Java comment reader (§4B). Result:
   **negative for memory corruption** (safe Rust, no `unsafe` in the audited
   crates; FFI copies are length-checked). Two by-products: (a) WC-1's widget
   reachability is disproven (the wallet validator blocks it, §4); (b) new
   WC-2 DoS, exponential `HashmapE` in `StateInit::from_boc`, host-reproduced
   (§4A). No further broad fuzz was run; the 1-worker T1 result is
   upstream-parser-only.
5. **T6 QuickJS bridge** (static + targeted JS): `__host` isolation is
   verified by the boot `delete`; check `__hostBinary`/`__hostOps` absent on
   Android, `args`/NUL truncation semantics, and the `intl`/`random` bounds.
   No broad fuzz — the validator/bridge harnesses already cover the JS side.

Do not re-fuzz litehtml/CSS/SVG/canvas/filters/JSON: those campaigns are
negative except the known DoS cases. Do not start FFmpeg/media work (dropped).

---

## 7. Artifacts

```
lab/lib_hunt_static/
  README.md
  evidence/
    versions_and_build.txt        hashes/build IDs, widget component versions
    jni_and_panic_runtime.txt     exact JNI addresses + panic_abort evidence
    litehtml_fork_diff.txt        fork-vs-upstream counts + missing DoS fixes
    widget_surface_review_20261108.txt  answerRequest/QuickJS host/bridge excerpts
    java_widget_wallet_u_i.txt    widget wallet handler (smali)
    java_wallet_boc_path.txt      d2/f2 parsers -> isValidCellBoc
    js_wallet_validation.txt      JS wallet schema/length/base64 checks
    ton_core_boc_diff.txt         0.1.4 vulnerable code vs 0.3.5 bounds checks
    panic_runtime_test.txt        unwind vs abort string cross-check
    ton_repro_unwind.log          root/ref panic (exit 101) + valid control
    ton_repro_abort.log           panic=abort -> SIGABRT (exit 134)
    ton_repro_huge_cells.log      75 GB allocation -> abort
    boc_fuzz_run_600s.log         T1 run summary (1 worker, 600 s, 512 MB)
    boc_fuzz_findings_600s.log    T1 unique sites + samples
    wallet_entry_wc1_blocked_20261108.log   WC-1 through the real widget entry: Err, no panic
    wallet_tlb_stateinit_dictbomb_20261108.log  WC-2 scaling + allocator abort
    wallet_tlb_hashmap_shiftbomb_20261108.log  WC-2b instant 2^61-byte alloc abort
    note_20261108_v1_with_biglibs.md   archived pre-directive draft
    out_of_scope_biglib_cve_matrix.md  archived big-lib matrix (not in scope)
    coverage_map_with_media_20261108.csv archived pre-directive CSV
  payloads/
    boc_root_oob.b64, boc_ref_oob.b64, boc_valid.b64, boc_huge_cells.b64
    boc_stateinit_dictbomb_d22.b64, _d24.b64, _d26.b64   WC-2 BoCs
    boc_stateinit_shiftbomb.b64                          WC-2b BoC (106 bytes)
    widget_wallet_send_payload.html
    widget_wallet_send_stateinit.html
    widget_wallet_send_stateinit_dictbomb.html   WC-2 widget payload
    widget_wallet_send_stateinit_shiftbomb.html  WC-2b widget payload
    widget_wallet_sign_data_cell.html
  coverage_map.csv                widget-only surface/entry/status
  ton_repro/                      Cargo repro + boc_fuzz + huge_cells bins (raw ton_core)
  wallet_tlb_repro/               Cargo probe at the widget entry + StateInit TLB reader
  wallet_engine_src/              wallet-engine @ 5c65e47 (submodule commit), harness dep
  ton_core-0.1.4/                 crate source
  ton_core_crate/ton_core.crate   downloaded tarball (0.1.4)
```

Wallet-engine source used for T5: upstream `dkaraush/wallet-engine` at the
Android submodule commit `5c65e47` (2026-10-02), vendored under
`lab/lib_hunt_static/wallet_engine_src/`; `crates/ton-connect-core` and
`vendor/ton` are the audited sources. The `62a75cb`/`20adadc` history checks
used the GitHub raw files (not kept).

Facts: `notes/LEMMALOG_FACTS_libhunt_20261108.txt`.

---

## 8. Confidence

| Claim | Confidence | Basis |
|---|---|---|
| litehtml fork identity / missing DoS fixes | high | source diff, VENDOR, upstream git |
| ton_core 0.1.4 raw-parser panic | high | host repro + source |
| shipped lib uses ton_core 0.1.4 + panic=abort | high | source paths + panic_abort |
| **WC-1 not reachable via `CellBoc::try_from`** | **high (static)** | validator in initial 62a75cb; host entry test Err; app source chain |
| WC-1 still live via `messageBodyHash` (non-widget) | medium-high | source: `Msg::from_boc` without validator; caller analysis |
| widget→isValidCellBoc chain | high static, live unverified | smali + JNI + JS bundle + JNI disasm |
| WC-2 exponential dict (host) | high | deterministic host repro, 4x/level |
| WC-2 on device (ANR/OOM) | medium-high | host scaling + Android memory limits; not device-run |
| no memory-corruption primitive on widget wallet path | high (structural) | no `unsafe` in audited crates; FFI/JNI review |
| answerRequest/selection/animations/compositor/QuickJS bridge negative | medium-high | exact source review, partial fuzz |
| T1 fuzz found only two raw-parser sites | high | 600 s, 1 worker, 2 unique sites |
