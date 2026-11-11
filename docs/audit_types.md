# Types audit — quickjs-ng latest (typed arrays / ArrayBuffer / BigInt / strings / JSON / Map-Set / Proxy)

Date: 2026-11-05. Host-only: no phone, no bot, no device operations.

Target: quickjs-ng `e22ce4d` (`/tmp/opencode/qjs_now`, then re-cloned to
`lab/qjs_types_audit/src` because `/tmp/opencode` was wiped mid-run by an
external cleanup). App comparison: `7a23d8e` (Telegram 13.2.0 beta, 0.17.0+
snapshot). The `7a23d8e..e22ce4d` delta for `quickjs.c` is 101/19 lines
(Array.find ownership, RegExp delete bytecode, BJSON RegExp); it touches
neither `JS_FreeAtomStruct`/`js_sub_string` (T1) nor the typed-array C API
(T2) nor the Atomics paths (T3), so all three are shared with the app build.

Widget model: source-only JS, 6 MiB JS heap, 300 ms CPU / 500 ms ceiling,
no host APIs, no modules, no BJSON.

Artifacts: `lab/qjs_types_audit/` (`poc/`, `harness/`, `logs/`,
`t262logs/`, fuzz corpora and generators, `build.sh`).

## 1. Result

**No new JS-reachable OOB/UAF/type-confusion primitive was found** in the
requested areas in `e22ce4d`. Three novel, previously unreported issues were
found; only one is a memory-safety bug, and it is C-API-only:

| ID | Area | Type | JS-reachable in widget | Novel |
|---|---|---|---|---|
| T1 | strings / atoms / Map-Set keys | permanent heap leak (parent of a slice-string atom) | yes (heap exhaustion; no corruption) | yes |
| T2 | typed arrays / resizable ArrayBuffer | stale byte length returned by `JS_GetTypedArrayBuffer` / `JS_GetUint8Array`; ASan OOB read in a trusting embedder | no (needs a host that consumes typed arrays through the C API; the widget bridge is JSON-string only) | yes |
| T3 | Atomics / immutable ArrayBuffer | write to an immutable ArrayBuffer through `Atomics.store` (and other RMW ops) | yes, but no engine memory corruption | yes |

T1 and T2 are not in the upstream tracker (checked issue titles/bodies up to
#1892 and web search; `JS_GetTypedArrayBuffer`, `pbyte_length`, atom-slice
parent, `Atomics` + immutable return no matches). T1 must not be confused with
#1892 (signed refcount overflow): T1 is a missing release (leak), and its
refcount amplification is only an impractical way to reach the #1892 overflow
at 2^31 atomisations.

## 2. Candidate table

| ID | Trigger | Primitive | Evidence | Blocker |
|---|---|---|---|---|
| T1 | `s = 'A'.repeat(N); k = s.slice(a,b)` (>1 KiB), use `k` as a property key or symbol description, drop `k`; atom path frees only the slice header (`JS_FreeAtomStruct`) and never releases `parent` (`js_free_string0` would) | heap permanently consumed; survives `JS_FreeContext`; OOM of later widget code | LSan direct leak of 4,194,353 B; `malloc_size` 4.3 MB after `JS_FreeContext`, ctx2 cannot allocate 4 MiB; release arena build reproduces | leak only: leaked block is unreachable but refcounted; no dangling dereference |
| T2 | `b = new ArrayBuffer(1024,{maxByteLength:4096}); v = new Uint8Array(b); b.resize(16);` then embedder calls `JS_GetTypedArrayBuffer`/`JS_GetUint8Array` on `v` | C API reports `pbyte_length=1024` while `v.byteLength===16`; host reading that length reads 1007 bytes past a 16-byte allocation (ASan heap-buffer-overflow read) | `harness/stale_length.c`, `logs/stale_length*.txt` | the only native call that receives a typed array is `__hostCanvas` with an engine-created fixed `Float64Array.subarray`; `__hostBinary` is captured but unused; no widget-controlled RAB view reaches the C API. Pure-JS paths are bounded by `p->u.array.count` / the species length check |
| T3 | `im = (new ArrayBuffer(16)).transferToImmutable(); v = new Int32Array(im); Atomics.store(v,0,42)` | violates the read-only guarantee (`v[0]` and `DataView.setInt32` are blocked; Atomics writes anyway) | `poc/atomics_immutable.js`, `logs/atomics_immutable.txt` | semantics only: QuickJS does not base any memory invariant on `immutable`; no corruption |

## 3. T1 — slice-string atom leaks its parent (heap exhaustion)

### Root cause

* `js_sub_string()` (`quickjs.c:4310`) creates `JS_STRING_KIND_SLICE` strings
  for substrings > 1 KiB; it takes a reference on the parent:
  `JS_REF_COUNT(p)++` (`quickjs.c:4340`), and normal frees release it in
  `js_free_string0()` (`quickjs.c:2616`).
* `__JS_NewAtom()` takes ownership of a non-atom string instead of copying it
  (`quickjs.c:3543`). A slice used as a property key or `Symbol` description
  therefore becomes the atom itself.
* Atom destruction goes through `JS_FreeAtomStruct()` (`quickjs.c:3648`),
  which `js_free_rt(rt, p)` frees the slice header directly and never calls
  `js_free_string0(p)`. The slice's parent reference is never dropped.

Consequences: every distinct >1 KiB slice ever atomised keeps its parent
string alive forever, even after the atom and the slice value are gone, and
even after `JS_FreeContext()` (atoms/strings are runtime-scoped). The parent
stays accounted in `rt->malloc_state.malloc_size`.

This is a one-line-family omission, not a refcount overflow: the parent
refcount is simply never decremented. The same applies to
`JS_STRING_KIND_INDIRECT` strings (BJSON/ROM only, out of app scope).

### PoCs

* `poc/leak_slice_atom.js` — 4 MiB parent, 64 distinct slice keys, drop all
  references, then try `new ArrayBuffer(2 MiB)` under `--memory-limit 6144`:
  leak version dies with `InternalError: out of memory`;
  `poc/leak_slice_atom_control.js` (same loop without `o[k]=1`) prints
  `ALLOC_OK`.
* `poc/leak_slice_atom_stats.js` — same without the probe; `qjs -d` shows
  `memory allocated 4,318,293` vs `memory used 112,646` (live objects).
* `poc/leak_symbol_description.js` — `Symbol(s.slice(0, 2 MiB))` alone:
  after `sym=null; s=null`, 3,269,439 B stay allocated while live data is
  112,512 B.
* `harness/leak_ctx.c` — creates ctx1, leaks, `JS_FreeContext(ctx1)`, then
  ctx2 tries a 4 MiB allocation: `malloc_size=4,299,302` after ctx1 free and
  ctx2 gets OOM. The no-atom control (identical loop, `o.x=1`) leaves only
  `malloc_size=104,949` after ctx1 free and ctx2's 4 MiB probe succeeds. This
  proves the leak crosses context resets; only a new `JSRuntime` reclaims it.
* LSan on the 4 MiB PoC: `Direct leak of 4,194,353 byte(s) in 1 object(s)`.

App-like release build (`Clang -O2 -fsanitize=scudo`, arena enabled, 6 MiB)
reproduces the OOM split (leak vs control) in
`logs/leak_slice_atom_arena.txt`.

### Impact / limits

Within one widget script: up to ~the whole 6 MiB heap can be made
unreclaimable; if the host keeps the runtime across widget updates, the
widget runtime is permanently poisoned (later updates OOM). It is a DoS, not
memory corruption. No dangling pointer arises: the parent block is
unreachable but its refcount is positive and the accounting matches.

Fix sketch: route atom destruction through the `kind`-aware release path
(e.g. change `JS_FreeAtomStruct` to call `js_free_string0`-equivalent for
non-NORMAL kinds, or have `js_sub_string` not use slices for interned atoms /
copy the parent reference bookkeeping into `JS_FreeAtomStruct`).

## 4. T2 — stale byte length from the typed-array C API

### Root cause

`js_array_buffer_update_typed_arrays()` (`quickjs.c:59604`) updates
`p->u.array.count` and `p->u.array.u.ptr` on RAB resize, but for a
length-tracking view (`track_rab`) it deliberately does **not** update
`ta->length` (it only updates `ta->length` for DataViews). `ta->length` is
the construction-time byte length.

`JS_GetTypedArrayBuffer()` (`quickjs.c:60047`) returns `ta->length` as
`pbyte_length`, and `JS_GetUint8Array()` (`quickjs.c:60072`) returns
`ta->length` as `psize`, while the JS-visible `byteLength` uses
`p->u.array.count`/`ta->length` differently (`js_typed_array_get_byteLength`
returns `count << shift` for `track_rab`).

So after `b.resize(smaller)` the engine reports two different lengths: the JS
property is current, the C API is the old one.

### PoC / evidence

`harness/stale_length.c`:

```
JS byteLength=16  API pbyte_length=1024  buffer.byteLength=16 offset=0 bpe=1
ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
0x... is located 1007 bytes after 24-byte region
```

(24 bytes is the ASan/glibc usable size of the 16-byte realloc; either way the
read is ~1 KiB past the backing store.) GCC ASan and Clang ASan large-only
both reproduce (`logs/stale_length.txt`, `logs/stale_length_clang.txt`).

Note: `JS_GetTypedArrayBuffer` calls `typed_array_is_oob()`, so it refuses
views that are fully out of bounds or detached; the bug needs a view that
remains valid after a shrink, exactly the length-tracking case.

### Reachability / blocker

The engine's own JS paths are safe: `typed_array_length()` is used only by
`js_typed_array_slice` (bounded by the species length check on the *current*
count) and by `js_typed_array_indexOf`'s `includes(undefined)` shortcut (no
dereference). The Telegram widget sandbox's native bridge mostly carries strings/JSON
(`crypto.getRandomValues` passes a length string; `openLink` etc. pass
strings). The one exception, canvas packing, passes an engine-created fixed
`Float64Array.subarray` to `__hostCanvas`, which the widget cannot turn into
a resizable/length-tracking view; `__hostBinary` is captured but never called
by the bundle. So no widget-controlled RAB view reaches the C API today. An embedder using `JS_GetTypedArrayBuffer`/`JS_GetUint8Array` on a
JS-provided RAB view is exposed to an OOB read (info leak) and, if it writes
based on the reported length, an OOB write.

Relevant latent surface: the Android sandbox bundle captures
`__hostBinary` (`u5 = __hostBinary`, sandbox-bundle.js) but never calls it in
this build (`u5(` has zero uses); `hide-host.js` removes the global. The native
`__hostBinary` implementation therefore exists but is not reachable from
widget JS today. If any host binary command starts consuming a JS typed
array/ArrayBuffer (or if another client build wires it), T2 becomes
widget-reachable. Verify `__hostBinary`'s native implementation before
assigning app impact.

**Resolved (2026-11-05):** see `notes/audit_bridge_t2.md`. On build 72879 the
`__hostBinary` native implementation is `tw_hostBinary_op` (0x78AF30), which
**ignores its arguments** and returns a staged byte blob; the only JS→native
boundary (`tw_host_trampoline`, 0x77D89C) marshals every argument to
`std::string` (objects → `""`), and `__hostCanvas`/`__hostOps` are not
registered at all. T2 is **not** widget-reachable in this build; the "canvas
packing passes a Float64Array" statement above is wrong for 7287 (the encoder
is disabled by `Jo === null`).

Fix sketch: for `track_rab`, return `p->u.array.count << size_log2`; for
`JS_GetUint8Array` compute the same. Alternatively update `ta->length` in
`js_array_buffer_update_typed_arrays` for tracking views (but then
`typed_array_length()`'s use in slice fast path must be rechecked; current
`count`-based code is the safer source).

## 5. T3 — Atomics writes through immutable ArrayBuffers

`typed_array_is_immutable()` is enforced by `JS_SetPropertyValue` (indexed
writes), `js_typed_array_set_internal`, `copyWithin`, `fill`, `sort`,
`reverse`, `setFromBase64/Hex`, and `js_dataview_setValue`. The Atomics paths
(`js_atomics_get_buf`, `js_atomics_op`, `js_atomics_store`,
`js_atomics_wait/notify`) never test `abuf->immutable`. (The TC39 immutable
ArrayBuffer proposal passes a `write` flag to
`ValidateAtomicAccessOnIntegerTypedArray` and rejects writes.)

PoC output (`poc/atomics_immutable.js`):

```
plain_write_blocked dataview_throw atomics_wrote=42 immutable=true
```

Both the GCC ASan and the app-like Scudo arena builds agree. No
memory-safety impact inside QuickJS: `immutable` is a JS-facing flag with no
engine invariants attached; the host would have to use an immutable buffer as
trusted read-only storage for this to matter.

## 6. Coverage and negative results

### Builds / sanitizers

| Build | Purpose |
|---|---|
| GCC `-fsanitize=address,undefined` | per-allocation ASan; GCC defines `__SANITIZE_ADDRESS__`, so `JS_ARENA_LARGE_BLOCKS_ONLY=1` and intra-arena writes are visible |
| Clang `-fsanitize=address,undefined -D__SANITIZE_ADDRESS__=1` (also `-fno-sanitize=function`) | second compiler; the explicit define is required because Clang does not define `__SANITIZE_ADDRESS__` (FYI from the fuzz worker) |
| Clang `-fsanitize=address -DFORCE_GC_AT_MALLOC=1` | aggressive GC at every allocation, large-only |
| Clang `-O2 -fsanitize=scudo`, arena enabled (no define) | app-like release/arena geometry, Android allocator |
| Clang `-fsanitize=memory` (MSan) | uninitialized reads (no findings in corpus) |

### test262 (latest checkout, 2026-11-05)

| Suite | Result |
|---|---|
| `built-ins/TypedArray` | 4/1453 errors — all the known #1878 `with` shrink cases (no crash) |
| `built-ins/ArrayBuffer` | 0/221 |
| `built-ins/DataView` | 6/560 — spec deviation: `byteLength`/`byteOffset` throw `TypeErrorArrayBufferOOB` after the RAB shrinks where test262 expects 0/old length; fail-closed, no memory issue |
| `built-ins/BigInt` | 0/77 |
| `built-ins/JSON` | 0/166 |
| `built-ins/Map` | 0/204 |
| `built-ins/Set` | 0/383 |
| `built-ins/Proxy` | 0/310 (1 skipped) |
| `built-ins/String` | 0/1223 |
| `built-ins/Array` | 0/3083 |

No ASan/UBSan report in any suite. `run-test262` was linked against the GCC
ASan build; logs in `t262logs/`.

### Structured adversarial corpora

* `gen_fuzz.py` (400 scripts × 10 cases): RAB/SAB resize/detach/transfer
  during `at/with/toSorted/slice/subarray/set/copyWithin/fill/sort/join/
  indexOf/map/filter/reduce`, species constructors, DataView, ArrayBuffer
  slice/transfer (incl. immutable), JSON source records/reviver, ropes,
  Map/Set iterators, Proxy.
* `gen_fuzz2.py` (500 scripts × 10 cases): typed-array/ArrayBuffer
  subclasses, species re-entrancy before/after `super()`, base64/hex
  (`fromBase64`, `setFromBase64`, `toBase64`, `toHex`, options Proxies),
  `Object.freeze/seal/preventExtensions` on RAB/detached views, Atomics with
  growable SABs and evil `valueOf`, rope/atom/JSON stress, BigInt
  asUintN/asIntN/shifts/pow/radix, Map `getOrInsertComputed` and Set
  operations with callbacks that mutate/clear/delete.
* All of the above under GCC ASan, Clang ASan (forced large-only), Scudo
  (large-only and arena release) and a 120-script subset under
  FORCE_GC_AT_MALLOC. No ASan/MSan/Scudo/assert hits; only timeouts from the
  deliberately expensive BigInt/rope cases.
* OOM-path sweeps (`oom_sweep.py`, `oom_fine.py`): the T1 leak is used as an
  exactly-accounted heap filler, leaving 0–128 KiB of headroom in 32/64-byte
  steps (≈25 k + 9 k + 0.9 k runs) and then exercising typed-array
  constructors/species/slice/set, JSON parse (with reviver), stringify, Map
  fill, Set union, base64/hex, `Object.keys`, `join`, `toSorted`, DataView.
  No double free, UAF or OOB on the OOM paths.

### Source-audit hypotheses ruled out

| Hypothesis | Result |
|---|---|
| TypedArray species/detach TOCTOU (`slice`, `subarray`, `with`, `at`, `set`, `fill`, `copyWithin`, `sort`, `join`) | `js_typed_array_create` enforces the species length against the **current** internal count for `slice/map/filter`; `with/at/fill/copyWithin/indexOf` re-read `count` and `ptr` after every coercion; the slice fast path copy is bounded by the current count, not by the stale `ta->length` |
| ArrayBuffer `slice`/`transfer`/`resize` vs evil `valueOf`/species | every path re-checks `detached`, `byte_length`, `immutable`, `js_same_value` and destination bounds after user code; `js_array_buffer_update_typed_arrays` invalidates views before the transferred data is handed to the new buffer |
| `subarray` species called with 2 args and `argv[2]` | internal direct call can see the caller's `args[3]`; only a length-tracking semantic difference, always validated against the current buffer |
| base64/hex capacity math | `from_base64`'s “remaining == 1 && seen == 2 / remaining == 2 && seen == 3” guard is sufficient; `remaining == 1 && seen == 3` is unreachable because the previous character would have stopped; exhaustively swept capacities 0–40 × input lengths 0–40 plus fuzz |
| JSON.parse source records / duplicate keys / reviver | parse-record tree is private to the parser and not reachable from the reviver; duplicate-key wrong-record is the open #1851 (correctness only), no UAF. `JSON.stringify` gap/indent/rawJSON values are held by refcount |
| Map/Set iterator + finalizer | iterators hold `cur_record` refcounts (zombie records), the two-pass WeakMap finalizer (#1844) removes weak refs before freeing values; cross-map symbol value/key cases remain safe because of the refcounts; no new variant found |
| Proxy traps / descriptor reentrancy | revocation keeps `target`/`handler` alive, every trap re-fetches the target state and uses `JS_IsExtensible`; no stale descriptor or invalid free |
| ropes / slices / string buffers | rope depth is capped and rebalanced at 60; rebalance and linearisation ownership checked; slice parent refs are correct on the normal free path (the only defect is the atom free path, T1) |
| BigInt limb arithmetic / asUintN / pow / shifts / toString | size caps and normalization checked; huge shifts are saturated to ±INT32_MAX; no OOB; `js_bigint_from_string` binary writes stay within `n_limbs` |
| interpreter interrupt polls (Array.find class) | each of the 24 `js_poll_interrupts` sites audited for value ownership; the #1792 pattern (`val` freed then freed again on the next loop-top poll) is fixed in `js_array_find`; `js_array_every/reduce` clear `val`; the other sites do not free a live value before the poll |
| arena allocator / refcount-in-header merge | all GC/string/bigint/shape constructors set `ref_count` and GC header bits; `js_realloc` carries the header fields across classes; `js_free_rt` accounting is balanced; no arena-only crash in the release+Scudo corpus |

## 7. Reproduction

```bash
cd lab/qjs_types_audit
./build.sh                                  # src is e22ce4d
# T1
ASAN_OPTIONS=detect_leaks=0 builds/gccasan/qjs --memory-limit 6144 poc/leak_slice_atom.js
ASAN_OPTIONS=detect_leaks=0 builds/gccasan/qjs --memory-limit 6144 poc/leak_slice_atom_control.js
ASAN_OPTIONS=detect_leaks=1 builds/gccasan/qjs --memory-limit 6144 poc/leak_slice_atom_stats.js
./harness/leak_ctx
# T2
./harness/stale_length
# T3
builds/gccasan/qjs poc/atomics_immutable.js
# test262 (needs a test262 checkout; harnessdir is in t262.conf)
./run_t262b.sh TypedArray ArrayBuffer DataView BigInt JSON Map Set Proxy String Array
```

Limitations: T1's default PoC sizes use the 6 MiB limit; T2's OOB read is in
the harness (a stand-in for an embedder that trusts `pbyte_length`), and the
widget sandbox does not currently pass typed arrays to native code; T3 is a
semantic/invariant bug with no engine memory corruption.

## 8. Dedup

Explicitly not re-reported: #1878, #1890, #1882, #1892, #1858/#1859,
#1847/#1770, #1800, #1799, #1798, #1797, #1796, #1794, #1844/#1835,
#1852/#1855, #1853. The three findings above do not appear in the upstream
issue list (checked through #1892) nor in the repository's existing types /
core / fuzz reports.
