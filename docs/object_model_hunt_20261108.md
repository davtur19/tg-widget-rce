# Object-model hunt — new 0day attempt, Android fork + iOS engine

Date: 2026-11-08. **Host-only**: no device, no Frida, no bot, no network.
Author role: *new object-model bug hunter* (a follow-up to the allocator/slab
and 18-bug-inventory campaigns).

Targets:

| tag | engine | source | role |
|---|---|---|---|
| shipped | quickjs fork `2dfeee3e` (0.17.0 + fork perf/cache commits), APKs 72889/72929 | `lab/qjs_fork_audit/zeroday_hunt_parser/src` | Android target, `JS_ARENA_SLABS` |
| ios | quickjs-ng `7a23d8e` (0.17.0 + `JS_ReadBigInt` fix) | `lab/qjs_src_7a23` | iOS-era engine, malloc arenas |
| upstream | quickjs-ng `e22ce4d` (v0.18.0+3) | `lab/qjs_src`, `lab/fork_fuzz/src_master` (`1a402cb`) | novelty reference |

All three were built here with the same harness: ASan+UBSan with
`-D__SANITIZE_ADDRESS__` (arena off, one malloc per object, ASan can see
every block), plus an arena-on asserts build of the shipped fork (device
allocation model).

---

## 0. Verdict (short, honest)

**No new memory-safety bug was found.** No unreported UAF, type confusion,
length corruption or pointer corruption with a controllable reclaim/overlap/
leak/write was demonstrated in the audited object-model surfaces, on either
engine.

What the session did produce:

1. Two **new cross-engine proofs of known n-days** and one **fresh proof that
   an unreported lab bug is still in the local upstream reference**:
   - `#1827` (`JS_RegExpDelete` stale bytecode): the **iOS 0.17.0 engine is
     vulnerable with no cache eviction at all** (the fork's 16-slot pattern
     cache is what hides the UAF on the shipped build). Shipped needs 16+
     distinct `new RegExp` to evict; upstream `e22ce4d` is fixed.
   - `#1835` (WeakMap symbol finalizer UAF): shipped **and** iOS vulnerable,
     upstream fixed.
   - **MB-02** (`js_finrec_unregister` FR entry UAF): still present in the
     upstream reference `e22ce4d`/`1a402cb`, on all three engines. DoS-only
     (no class-96 allocation in the free→use gap; re-verified).
2. A **new negative result of a new bug class**: builtin *arity/`.length`* vs
   the interpreter's `argv[]` padding (`JS_CFUNC_*_DEF` length N pads
   `arg_buf` to N with `JS_UNDEFINED`, so any function that reads
   `argv[i≥N]` without an `argc` guard is a stale-JSValue hazard). Every
   `JS_CFUNC_DEF` / `JS_CFUNC_MAGIC_DEF` / `JS_ITERATOR_NEXT_DEF`
   registration was scanned mechanically (42 candidates read past their
   declared length) and the `JS_CFUNC_SPECIAL_DEF` (`f_f`/`f_f_f`) family
   was checked by hand; every candidate is protected by an `argc` test or a
   short-circuit. No stale argument read exists today. The scanner and the
   reasoning are kept so a future `.length` change cannot silently
   reintroduce the class.
3. A **systematic audit of the fork-only object-model optimizations** that
   the previous campaigns touched only at the allocator level: inline
   property arrays (`ee1ef12`), zombie shapes (`e65afb8`), direct
   `put_field` (`b989db6`), inline `get_length`/`get_field` walks
   (`7de45b9`/`aa443fe`), atom-valued literal push (`f9bf3e3`), JSON direct
   writes (`286a561`/`9383ba4`), RegExp bytecode cache (`6b6c1f2`). The
   lifetime invariants are written out in §3.2 and hold under targeted
   stress; the residual risk is interleaving coverage, not a known defect.
4. 1760 coercion/mutation cases × 2 builds, 800 random object-model
   sequences × 2 builds, and the quickjs-ng test corpus × 3 builds:
   **zero sanitizer reports** (outside the intentionally-live runtime leak).

Consequence for the v7 BigInt endgame: none of these surfaces adds a
primitive. The only confirmed carriers remain the known `#1827` (v7) and
`#1865` routes.

---

## 1. Model and tools

### 1.1 Harness

`src/run.c` — app-model runtime, one `JSRuntime`/`JSContext` reused across
scripts, 6 MiB default limit, optional CPU deadline, `__gc()`, `__mem()`,
`__drain()`; microtasks drained after every eval; **no teardown** (a corrupt
state must not be masked by `JS_FreeRuntime`). Same harness compiled against
the three engines (`scripts/build.sh`).

Builds in `build/`:

| binary | engine | flags |
|---|---|---|
| `run_asan_shipped` | 2dfeee3e | clang ASan+UBSan, `-D__SANITIZE_ADDRESS__` → `JS_ARENA_LARGE_BLOCKS_ONLY=1` |
| `run_arena_shipped` | 2dfeee3e | gcc -O1, arena + slab allocator, assertions on (device model) |
| `run_asan_ios` | 7a23d8e | ASan+UBSan |
| `run_asan_upstream` | e22ce4d | ASan+UBSan |

`JS_ARENA_LARGE_BLOCKS_ONLY` matters: without it ASan cannot see inside the
16×4 KiB arena slabs. The earlier ledger build used it; this campaign
reproduced the flag explicitly.

### 1.2 Tag domains (measured model from `notes/MTE_safe_hunt_20261107.md`)

* Android shipped: every request ≤ 512 B comes from `mmap(PROT_READ|WRITE)`
  64 KiB slabs → **tag 0, never MTE-checked**. `JSObject` (~96–230 B with
  inline props), `JSMapRecord` (88 B), `JSFinRecEntry` (88 B), small
  `JSString`, small typed-array data all live there.
* iOS: no MTE; glibc-free/malloc arenas. Object-model bugs are allocator
  independent; only the *reclaim geometry* differs.
* Blocks > 512 B go to Scudo (tagged primaries, secondaries ≥ 64 KiB).
  A same-tag bug must therefore keep the corrupted object in the ≤ 512 B
  arena domain, as v7 does.

### 1.3 What was run

| sweep | volume | result |
|---|---|---|
| builtin corpus (`lab/qjs_src/tests/*.js`) | 109 files × 3 engines | 0 sanitizer hits |
| coercion/mutation matrix (`cases/`) | 1760 cases × 2 builds | 0 hits |
| random sequences (`seq1/`, `seq2/`) | 800 scripts × 2 builds | 0 hits |
| shape/put_field/zombie stress | 300 rounds × 40 objects + edge cases | 0 hits |
| `using`/`await using`/`for await` control-flow stress | 20 scenarios | 0 hits, semantics match V8 for the tested cases |
| forced-GC build (`-DFORCE_GC_AT_MALLOC`, ASan) | 103 tests + 400 sequences + all 1760 cases + async/generator stress | 0 hits, no premature-free exposed |
| arity/argv scanner | all `JS_CFUNC*_DEF` + `JS_ITERATOR_NEXT_DEF` | 0 unguarded reads |

Logs: `logs/corpus/`, `logs/cases/`, `logs/seq1/`, `logs/seq2/`,
`logs/forcegc/`, `logs/forcegc_seq1/`, `logs/forcegc_cases/`,
`logs/sweeps_summary.txt`, `logs/nday/`.

---

## 2. New ledger rows (memory bugs confirmed this session)

These are **not** new 0days; they are the cross-engine confirmations the
campaign needed, recorded in the same ledger style as
`notes/memory_bug_log_20261107.md`.

### OM-01 — `#1827` `JS_RegExpDelete` stale bytecode: iOS engine trivially reachable (n-day)

| field | value |
|---|---|
| id | OM-01 (dedup `#1827`, MB-05) |
| root cause | `JS_RegExpDelete` takes `re_bytecode = str8(re->bytecode)` **before** the `lastIndex` coercion. `valueOf()` calls `re.compile(...)`; the stale pointer is then used by `lre_get_alloc_count` / `lre_exec`. Fixed upstream by `2b62af1` / `3d5cb14`; the fix moves the read after the coercion. |
| class | UAF read of the freed RegExp bytecode buffer |
| exact trigger | `re = /a/g; Object.defineProperty(re,"constructor",{get(){ re.lastIndex={valueOf(){ re.compile("b","g"); /* evict */ for(i=0;i<64;i++) new RegExp("x"+i,"g"); return 0; }}; return RegExp; }}); "aaa".replace(re,"")` |
| tag domain | bytecode string: `JSString` (arena class 32/64, tag 0) + `lre_compile` buffer via `js_malloc` (tag 0 arena when ≤512 B; Scudo when larger). iOS: malloc. |
| OOM? | **no**; no near-cap heap |
| novelty | **n-day** (fixed upstream, merged) |
| host repro (shipped) | `poc/poc_regexp_delete_1827_evict.js` → ASan `heap-use-after-free ... in lre_get_alloc_count libregexp.c:3428`, caller `JS_RegExpDelete quickjs.c:50809` (`logs/nday/1827_shipped_evict.log`) |
| host repro (iOS) | `poc/poc_regexp_delete_1827.js` → same UAF **without any eviction loop** (`logs/nday/1827_ios_nocache.log`, `quickjs.c:49982`). The fork's 16-slot cache (`6b6c1f2`) is the only reason the shipped build needs eviction. |
| shipped without eviction | no crash, but the result is **wrong** (`"aaa".replace(re,"")` returns `""`, `re.source === "b"`), proving the stale bytecode was executed — this is the mechanism the fork's own test `1a402cb` documents |
| upstream `e22ce4d` | clean, returns `"aaa"` (`logs/nday/1827_upstream_evict.log`) |
| payload | raw 861 B / zlib9 **459 B** (`poc/`) |
| exploitability | the v7 reference; not recounted as a 0day. **New operational note:** a shipped-engine payload must force cache eviction (`>16` distinct compiled patterns, or patterns > 1024 chars) or the old bytecode stays alive and there is no UAF. |

### OM-02 — `#1835` WeakMap symbol finalizer UAF, cross-engine (n-day)

| field | value |
|---|---|
| id | OM-02 (dedup `#1835`, MB-01) |
| root cause | `js_map_finalizer` frees each record's value inside `list_for_each_safe`; a symbol value that is also a later record's key frees that record through `reset_weak_ref`, under the saved cursor. Fixed upstream `25a005b` / fork `ebd139b`; missing in shipped. |
| class | UAF read of a class-96 arena record |
| exact trigger | `wm=new WeakMap(); A={}; S=Symbol(); wm.set(A,S); wm.set(S,1); S=null; wm=null; __gc()` |
| tag domain | `JSMapRecord` 88 B → arena class 96, tag 0 (Android); malloc (iOS) |
| OOM? | no |
| novelty | n-day |
| host repro | shipped `quickjs.c:54778` (`logs/nday/1835_shipped.log`); iOS `quickjs.c:53871` (`logs/nday/1835_ios.log`); upstream **clean** (`logs/nday/1835_upstream.log`) |
| payload | raw 344 B / zlib9 **241 B** |
| exploitability | DoS only (no class-96 allocation between the free and the second visit); re-confirmed on all three |

### OM-03 — `js_finrec_unregister` FR entry UAF still in upstream reference (unreported, DoS-only)

| field | value |
|---|---|
| id | OM-03 (dedup MB-02) |
| root cause | `js_finrec_unregister` frees entry 1's held value while iterating; if that value is entry 2's target, `reset_weak_ref` unlinks **and frees** entry 2 under the loop cursor. The registry *finalizer* was fixed with a two-pass unlink; `unregister` was not. |
| class | UAF read of a class-96 `JSFinRecEntry` |
| exact trigger | `reg=new FinalizationRegistry(()=>{}); T={}; tok={}; k={}; reg.register(k,T,tok); reg.register(T,2); T=null; reg.unregister(tok)` |
| tag domain | `JSFinRecEntry` 88 B → arena class 96, tag 0; iOS malloc |
| OOM? | no |
| novelty | **unreported**; present in the newest local reference `e22ce4d`/`1a402cb` |
| host repro | shipped `quickjs.c:64251` (`logs/nday/fr_shipped.log`), iOS `63295` (`logs/nday/fr_ios.log`), **upstream `63377` (`logs/nday/fr_upstream.log`)** |
| payload | raw 342 B / zlib9 **227 B** |
| exploitability | DoS only: the only allocation in the gap is the class-64 `JSJobEntry` from `reset_weak_ref`'s FR enqueue, so the class-96 entry cannot be reclaimed with attacker bytes. On 32-bit ARM the classes are 48 vs 40 — still disjoint. |

---

## 3. Audited surfaces and why they held

### 3.1 Builtin arity vs `argv[]` (new bug class, negative)

`js_call_c_function` / `js_call_c_function_data` copy/pad arguments up to the
**registered `.length`** (`p->u.cfunc.length`, i.e. the JS `fn.length`), not up
to the number the C function reads. A builtin that declares `length = N` but
reads `argv[i≥N]` with fewer arguments reads a **stale interpreter stack
slot** — an unrooted JSValue; `js_dup` of it is a refcount write into a
possibly-freed block. This is a genuine object-model hazard that no previous
campaign named.

`scripts/scan_argv2.py` scans every `JS_CFUNC_DEF` / `JS_CFUNC_MAGIC_DEF` /
`JS_CFUNC_SPECIAL_DEF` / `JS_ITERATOR_NEXT_DEF` registration against its
function body. 42 registrations read past their declared length; every one is
protected:

* explicit `argc` tests: `join`, `flat`, `flatMap`, `fill`, `copyWithin`,
  `indexOf`, `reduce`, `find`, `padStart`, `includes`, `every`, `map`,
  `set`, `dataview_*`, `reflect_*`, `atomics_op`, …;
* short-circuit on `magic`: `Number.prototype.toLocaleString` (`magic`
  first), `Array/TypedArray.prototype.toLocaleString`;
* `attr == NULL` for `String.prototype.big/blink/…`;
* `argc > 0 ? argv[0] : undefined` in `Uint8Array.prototype.toBase64`;
* `argc < 1 ||` in `ArrayBuffer.prototype.transfer`.

`js_generator_next` / `js_async_generator_next` are the load-bearing case:
they read `argv[0]` for the value sent into a `yield`, and are registered
with length **1**, so a zero-argument `g.next()` gets a padded `undefined`,
not a stale slot. A regression here would be a strong primitive (dupping an
arbitrary stale value into a generator frame), so this is worth a permanent
test: `poc/../scripts/cases/t_genarg*.js`.

### 3.2 Fork-only shapes: inline property arrays, zombie shapes, `put_field`

The shipped fork adds ~20 object-model/perf commits (author `macosswift`)
that upstream does not have. Their lifetime invariants were written down and
tested:

* **Inline property array** (`ee1ef12`): `JSObject` and up to
  `JS_OBJECT_INLINE_PROP_MAX = 16` `JSProperty` slots are one block;
  `js_realloc_object_prop()` keeps the inline array while
  `new_size <= p->shape->prop_size`. Invariant: for an inline object,
  `p->shape->prop_size <= capacity`, because every shape installation is
  preceded by a `js_realloc_object_prop` with the new `prop_size`, and both
  `add_property` paths (`find_hashed_shape_prop` + `resize_properties`) obey
  it. `free_object` compares `p->prop != js_object_inline_prop(p)` to decide
  the free; `compact_properties` installs the compacted shape *before*
  calling `js_realloc_object_prop`, and its shrink path returns the inline
  array without a `memcpy`, so the shape/count mismatch window is empty.
* **Zombie shapes** (`e65afb8`): a hashed shape whose refcount hits 0 is
  moved from `gc_obj_list` to `shape_zombie_list` (max 64) and revived by
  `js_revive_shape()` (detect refcount 0 → `add_gc_object` → `js_dup_shape`).
  Both hash-table lookup users call `js_revive_shape`; `JS_RunGC` frees the
  zombies before `gc_decref`; shapes freed during GC (`gc_phase != NONE`) or
  runtime teardown (`in_free`) are freed immediately. The dangerous case
  would be an object still pointing at a shape that became a zombie —
  requires a refcount accounting error, which I did not find.
* **Direct `put_field`** (`b989db6`): `js_put_field_add` walks the prototype
  chain and bails on any exotic link, setter, read-only or autoinit
  property; only an all-plain chain with a writable data property (or no
  property) takes the fast add. Tested with prototype setters, read-only
  inherited data, `__proto__`, `preventExtensions`, array prototypes: all
  match V8 semantics.
* **Inline `get_length` / `get_field` walks** (`7de45b9`, `aa443fe`): the
  `js_exotic_skip_for_key()` exemption is limited to arrays/arguments/
  strings and non-index atoms; proxies, typed arrays, module namespaces stay
  on the slow path. `new String("abc").length`, proxy `length`, getter
  `length` all verified.
* **Atom-valued literal push** (`f9bf3e3`): only `JS_ATOM_TYPE_STRING`
  atoms are `js_dup`'d directly; tagged ints and symbols take the old path.

Stress: `scripts/cases/t_shapes.js` (300 rounds × 40 objects, add/delete/
compact/revive, GC every 8 objects, 20-property boundary) on all three
engines → 0 sanitizer reports.

### 3.3 `using` / `await using` / `for await` (fork-only ops, negative)

New opcodes `OP_using_dispose{,_async,_merge,_end}`, `OP_using_check` and the
hidden `JS_VAR_USING_METHOD` local, plus `js_iterator_get_value_done()`'s
`sp[-4]` stack-layout assumption. Tested: captured `using` variables (the
hidden method is a paired local; capture must not alias it), nested blocks,
loops, exceptions, `SuppressedError` chains, async stacks with `await`
between declarations, `await using` sync-fallback wrapping, `for await`
break/throw/return, custom `return()` throwing, rejecting `next`, `yield*`
delegation. Semantics match V8 (Node 24) for the tested cases; no
double-free/OOB. The captured-`using` case in particular proves the compiler
does not hand `OP_using_dispose` a raw `JSVarRef` as `this`.

### 3.4 RAB / typed arrays / DataView coercion matrix (negative)

`scripts/gen_cases.py` builds 1760 self-contained cases: every API in
`T.set/fill/copyWithin/slice/subarray/sort/toSorted/toReversed/with/join/
indexOf/lastIndexOf/includes/find/findIndex/map/filter/reduce/forEach/every/
some/at`, `DataView.get*/set*`, `ArrayBuffer.slice/transfer/
transferToFixedLength/transferToImmutable/resize`, array
`sort/toSorted/toSpliced/with/splice/fill/copyWithin/...`, string
`replace/replaceAll/split/match/matchAll/search/padStart/repeat/at/...`,
RegExp `exec/test/compile`, Map/Set/JSON/Proxy — each called with
`valueOf`/`toString`/`Symbol.toPrimitive` hooks that detach, transfer,
resize (0/8/128), slice-to-immutable, GC, clear/delete/add map entries,
mutate arrays, or evict/recompile the RegExp. 3520 runs across the ASan and
arena builds: **0 sanitizer reports**.

The guarded patterns found by reading: `js_typed_array_fill` re-clamps
`final` to the post-coercion count; `indexOf` re-reads `count` after
coercion; `with` re-validates and uses `min(orig, current)`; `slice`
falls back to a slow path when the length changed; `join` computes separators
for the old length; `DataView` re-checks `detached`/`offset+length` after
each coercion; `ArrayBuffer.transfer`/`slice` re-check detach/size after
`valueOf` and species calls.

### 3.5 RegExp lifetime beyond `#1827`

Every `str8(re->bytecode)` site was ordered:

* `js_regexp_exec`: read **after** `JS_ToString` and the `lastIndex`
  coercion — safe. The post-match `JS_SetProperty(lastIndex)` cannot run
  user code (own non-configurable writable data property; a subclass'
  prototype accessor is shadowed), so the `lre_get_groupnames(re_bytecode)`
  read after it is safe.
* `JS_RegExpDelete`: **the n-day** (OM-01).
* `js_regexp_get_flag/source`, `constructor_internal`, `compile`: no
  intervening user code that can free the bytecode.
* The fork-only cache (`6b6c1f2`, 16 slots, patterns ≤ 1024) only delays
  the free; it cannot make a stale read safe. Its eviction path frees the
  old pattern+bytecode and installs dups; both refcounted.
* `Symbol.split/match/matchAll/search`: only strings from `JS_ToString`
  (always linearized) feed `string_get`; `strp`/`sp` are held by the owning
  JSValue for the whole function.

### 3.6 JSON direct writes

`string_buffer_put_quoted` (fork) copies 8-bit runs and uses
`string_getc`/`string_buffer_putc` for escapes; slices go through
`strv()` which applies `slice->start` in bytes; wide slices use `str16`.
`json_write_number` keeps `char buf[128]` outside the recursion frame;
`js_dtoa_max_len > 127` falls back to a string. The recursion guard uses
the `stack` array with `js_array_includes`/push/pop; an exception aborts the
whole stringify and the array is freed by `JS_JSONStringify`. No OOB in
reading or in the direct writes.

### 3.7 Iterators / proxies / classes / Map-Set / DisposableStack

* `Iterator.concat` guards re-entry with `running`; `values[]`/`iter`/`next`
  are cleared before the pair is freed; `return()` frees the remaining
  pairs after closing the current iterator; the object is rooted by
  `this_val`.
* `Iterator` helpers use `executing`, clear `buf` on completion, and transfer
  ownership to `JS_NewArrayFrom`.
* `Map` iterators lock the current record (`ref_count++`), deleted records
  become zombies still linked in `records`, `map_decref_record` unlinks on
  the last reference; `forEach` reads `el->next` before decref.
* `DisposableStack`: `disposed` is set before any disposer runs, so
  `use/defer/adopt` throw (`ReferenceError`) during disposal and cannot
  `realloc` the `resources` array under the loop.
* `Proxy` revoke only frees the revoke function's own reference and keeps
  target/handler alive; `s` is owned by the proxy object which the caller
  roots. Every trap site re-checks `s->is_revoked` after user code.
* Private fields/brands are ordinary private-symbol properties; the
  add/get/set paths re-find the property and own the value.

### 3.8 async / generators / promise jobs

`JSJobEntry` copies+dups args, is unlinked before the job runs, and frees
args with the entry context. Async generator requests are strong refs in the
queue; `AWAITING_RETURN` skips `async_func_free` exactly once. The known
OOM bugs (#1867/#1873) remain OOM-gated; no non-OOM ownership defect was
found in `js_async_function_resume` / `js_async_generator_resume_next`.

### 3.9 atoms / slice strings / in-place concat

`JS_ConcatString2` appends in place only when `JS_REF_COUNT(p1)==1`,
`atom_type==0`, same width, and `js_malloc_usable_size` proves the slack;
it drops the cached Map hash. A string that is a Map key or a slice parent
always has refcount > 1, so it cannot be mutated under a key. `js_sub_string`
dups the parent for slices; `js_free_string0` releases it. (T1, the
missing release for atomised slice parents, is a known leak.)

---

## 4. Why this is a negative, and what the remaining gap is

The object model is unusually well guarded in this codebase: every user
callback is bracketed by a re-validation of the pointer/length it could
invalidate, containers use zombie records or executing flags, and the
fork's shape/storage optimizations preserve the shape→capacity invariant.
The engine has also been through several campaigns (18-bug inventory,
allocator/slab, state-coverage fuzzing, FR/WeakMap, parser).

The realistic ways to a new same-tag primitive remain:

1. **A refcount accounting error in the fork-only shape zombie / inline
   property storage** that leaves an object pointing at a refcount-0 shape
   (→ GC frees the shape, later use is UAF). I proved the current
   transitions preserve the invariant; a model-checking pass over
   `add_property`/`resize_properties`/`compact_properties`/`js_free_shape`/
   `js_revive_shape`/`js_shape_prepare_update` (including hash resize) is
   the next step, not more fuzzing.
2. **A stale-cache read of a pointer that is not a JSValue** (bytecode,
   shape, property array) across a callback that reallocates it. All
   currently visible sites were ordered correctly; the `#1827` family has
   exactly one member left, and it is the n-day.
3. **A `.length`/arity change** to a builtin reintroducing the
   stale-`argv[]` class. The scanner in `scripts/scan_argv2.py` should be
   part of any future builtin-table review.

I did not find (1) or (2), and (3) is currently clean.

---

## 5. Artifacts

```
lab/object_model_hunt_20261108/
  src/run.c                     harness (ASan / arena builds, __gc/__mem/__drain)
  scripts/build.sh              builds the four engines
  scripts/build_forcegc.sh      ASan + FORCE_GC_AT_MALLOC build (premature-free oracle)
  scripts/run_corpus.sh         quickjs tests × 3 engines
  scripts/gen_cases.py          coercion/mutation matrix generator (1760 cases)
  scripts/run_cases.sh          matrix × asan/arena
  scripts/gen_seq.py            random object-model sequence generator
  scripts/run_seq.sh            sequences × asan/arena
  scripts/run_forcegc_seq.sh    sequences under the forced-GC build
  scripts/scan_argv.py           arity/argv scanner (v1, heuristic)
  scripts/scan_argv2.py          arity/argv scanner (v2, per-registration)
  scripts/cases/                hand-written using/for-await/shape/argv/async tests
  cases/                        1760 generated cases + index.tsv
  seq1/ seq2/                   800 generated sequences
  poc/                          OM-01/02/03 reproducers (+ sizes)
  logs/                         builds, sweeps, corpus, per-case logs
  logs/nday/                    cross-engine UAF logs
  build/                        run_asan_{shipped,ios,upstream}, run_arena_shipped
```

## 6. Reproduce

```bash
cd lab/object_model_hunt_20261108
bash scripts/build.sh
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./build/run_asan_shipped poc/poc_regexp_delete_1827_evict.js
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./build/run_asan_ios     poc/poc_regexp_delete_1827.js
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./build/run_asan_upstream poc/poc_finrec_unregister.js
python3 scripts/scan_argv2.py | head
bash scripts/run_cases.sh   # expect 0 hits
```
