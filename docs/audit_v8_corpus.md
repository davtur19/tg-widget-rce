# V8/Chrome non-JIT mjsunit corpus against quickjs-ng

Date: 2026-11-05. Host-only (no phone, no emulator, no bot).

Targets:

| | commit | version | role |
|---|---|---|---|
| App 72799 engine | `7a23d8e3fedb010070ef1a03873c55500c7aa1a9` | 0.17.0 | what Telegram ships |
| Upstream HEAD | `e22ce4de4362dc5fd4794cfa3c03fc7fdba5f015` | v0.18.0+3 (2026-11-02) | current quickjs-ng |
| V8 corpus | `7e76d90` (sparse `test/mjsunit`, `test/test262`) | 2026-11 | Chrome/V8 regression tests |

Artifacts: `lab/v8_corpus/` (clone, harness, selections, logs, PoCs).

---

## 0. TL;DR

* **4,869 V8 mjsunit tests** were run on both engines (2,447 without
  intrinsics, then 4,869 with `%Intrinsic(...)` rewritten to JS shims), plus
  **GC-stress**, **Scudo**, and **memory-limit sweeps** from 512 KiB to
  6.4 MiB.
* **Two new OOM-gated NULL dereferences** were found. Both are source-only,
  need no host API, run in < 20 ms, and **SIGSEGV the release engine at the
  app's 6 MiB limit**, on both `7a23d8e` and `e22ce4d`:
  * **F1** — `resize_properties()` unlinks a shape from `gc_obj_list`
    before a fallible `js_realloc`; constructing the OOM Error triggers GC,
    which resurrects the unlinked shape and calls `list_del()` on a zeroed
    link: **fixed 8-byte zero write at address 0x8**.
  * **F2** — `js_function_bind()` frees a half-constructed bound-function
    object after the `JSBoundFunction` allocation fails;
    `js_bound_function_finalizer()` dereferences the still-NULL
    `p->u.bound_function`: **fixed NULL read at 0x8**.
  * No matching quickjs-ng issue/PR was found (GitHub search API,
    2026-11-05). Both are distinct from #1855, #1852 and #1833.
* **One known OOM bug reproduced by the corpus**: #1782 (truncated parser
  bytecode read in `resolve_variables`), via
  `regress/regress-539350801-long-chain.js` at 512 KiB. Dedup, PR open.
* **Six semantic deviations** were isolated and minimised. Five are
  wrong-value only; one (`Object.defineProperties` partial application) is
  already tracked as #1794 / PR #1834. None gave a memory-safety
  primitive.
* No ASan UAF/OOB was found in 4,869 tests at the 6 MiB model without a
  tuned OOM alignment. The non-OOM builtins surface is in good shape.

---

## 1. Corpus and harness

### 1.1 Acquisition

```bash
git clone --depth 1 --filter=blob:none --sparse \
  https://chromium.googlesource.com/v8/v8.git lab/v8_corpus/v8
cd lab/v8_corpus/v8
git sparse-checkout set test/mjsunit test/test262
```

* 63 MB on disk, 9,659 `.js` files under `test/mjsunit`.
* `test/test262` in the V8 tree is only V8's **runner infrastructure**; the
  actual test262 data is not in the V8 repo. No local test262 checkout exists
  on this host (`find <HOME> -maxdepth 5 -type d -name test262` found
  only unrelated projects), so test262 was **not** run — this also avoids
  duplicating the prior async/types test262 campaigns.

### 1.2 Selection

`select_tests.py` applies static filters:

* skipped directories: `wasm`, `compiler`, `maglev`, `turbolev`,
  `turboshaft`, `ignition`, `lithium`, `baseline`, `sandbox`, `d8`, `tools`,
  `async-hooks`, `shared-memory`, `lower_limits_mode`, `math-sum-precise`,
  `opt-proto-seq`, `type-profile`, `protector-cell`;
* skipped content: `%CamelCase` natives syntax, `--allow-natives-syntax`,
  WebAssembly/Wasm, `Intl`, `d8.`/`os.`/`readline`/`readbuffer`,
  `Worker`/`Realm`/`ShadowRealm`, modules (`import`/`export`), top-level
  `await`, `assertOptimized`/`assertMaglevved`, V8-only flags, `debugger`.

Result: **2,447 clean tests**.

For the second pass, the selector was relaxed (same directory and host-API
filters only) and the runner rewrote every `%Intrinsic(...)` and bare
`%Intrinsic` to `__intr.Intrinsic` with a JS shim:

* semantic: `%ArrayBufferDetach` → `transfer()`, `%ArrayBufferMaxByteLength`,
  `%ArrayBufferGetByteLength/GetMaxByteLength/GetResizable`,
  `%ConstructConsString`, `%CreatePrivateSymbol`, `%Equal`, `%NotEqual`, …
* JIT-control: no-ops (`%PrepareFunctionForOptimization`,
  `%OptimizeFunctionOnNextCall`, `%GetOptimizationStatus` → 0, …), so the
  builtin body still executes without a JIT.

Result: **4,869 tests**.

Each test is wrapped as
`mjsunit.js` + shims + `;(function(){ <test> })();` and run in a fresh
process:

```bash
qjs --script --memory-limit 6144 --stack-size 512 <wrapped.js>
```

(`--script` is required: qjs defaults to autodetect and implicit globals
fail in module mode.)

### 1.3 Builds

| build | compiler/flags | purpose |
|---|---|---|
| `build-asan` | GCC, `-fsanitize=address,undefined -g -O1`, Debug | per-allocation ASan/UBSan, arena disabled by GCC's `__SANITIZE_ADDRESS__`, 6 MiB heap |
| `build-asan-7a23` | same, app worktree | app-version comparison |
| `build-gcstress` | GCC ASan + `-DFORCE_GC_AT_MALLOC=1` | lifetime bugs exposed by GC at every allocation |
| `build-rel` | GCC `-O2 -g`, Release, arena enabled | production-like crash reproduction |
| `build-rel-7a23` | same, app worktree | app-version crash reproduction |
| `build-scudo` | clang `-fsanitize=scudo -O2`, arena enabled | Android-like allocator |

The app worktree is `lab/qjs_src_7a23` (git worktree of `lab/qjs_src` at
`7a23d8e`).

---

## 2. Execution matrix

### 2.1 Main runs

| run | selection | build | mem | tests | pass | result file |
|---|---|---|---:|---:|---:|---|
| clean | 2,447 | asan e22 | 6 MiB | 2,447 | 1,995 | `results_mjsunit_e22.jsonl` |
| intrinsics | 4,869 | asan e22 | 6 MiB | 4,869 | 3,686 | `results_intr4_e22.jsonl` |
| intrinsics | 4,869 | asan **7a23** | 6 MiB | 4,869 | 3,679* | `results_intr_7a23.jsonl` |
| intrinsics | 4,869 | gcstress e22 | 6 MiB | 4,869 | 3,638 | `results_intr_gcstress_e22.jsonl` |
| intrinsics | 4,869 | release e22 | 6 MiB | 4,869 | 3,700 | `results_rel_6144.jsonl` |

\* run before the final shim fixes; per-test diff against the e22 run of the
same shim generation shows only timing/random/stack-text noise (13 rows, no
class flip). The app and upstream engines behaved identically on the corpus.

### 2.2 Memory-limit sweeps

The corpus itself rarely lands the OOM exactly on a vulnerable allocation
window, so the same 4,869 tests were replayed at several limits.

ASan/UBSan build (`class` values from `results_oom_<mem>.jsonl`):

| mem | crash rows | root cause |
|---:|---|---|
| 512 KiB | 5 | **#1782** parser truncated-bytecode OOB (ASan) + 4 × **F1** (UBSan) |
| 768 KiB | 0 | — |
| 1024 KiB | 0 | — |
| 1536 KiB | 3 | **F2** (`js_bound_function_finalizer`) |
| 2048 KiB | 2 | **F2** + **F1** (`unbox-double-arrays.js`) |
| 3072 KiB | 4 | **F2** |
| 4096, 5000, 5500, 6000, 6200, 6400 KiB | 0 | — |

Release build (SIGSEGV/ASan class):

| mem | crash rows | root cause |
|---:|---|---|
| 512 KiB | 5 | **F1** (`regress-430201`, `430201b`, `regress-crbug-731193`, `dictionary-to-fast-arguments`, `set-flags-stress-compact`) |
| 768, 1024, 1280 KiB | 0 | — |
| 1536, 1792 KiB | 3 each | **F2** |
| 2048 KiB | 2 | **F1** (`unbox-double-arrays`) + **F2** |
| 3072 KiB | 4 | **F2** |
| 4096, 5120, 6144 KiB | 0 | — |

The V8 tests that hit the two bugs are seeds, not the final PoCs:

| finding | V8 seed tests |
|---|---|
| F1 | `regress/regress-430201.js`, `regress-430201b.js`, `regress/regress-crbug-731193.js`, `regress/regress-dictionary-to-fast-arguments.js`, `regress/regress-set-flags-stress-compact.js`, `unbox-double-arrays.js` |
| F2 | `regress/regress-479872236.js`, `regress/regress-1098565.js`, `regress/regress-1105746.js`, `regress/regress-344664770.js`, `regress/regress-346876227.js`, `regress/regress-388905056.js`, `regress/v8-6716.js` |
| #1782 | `regress/regress-539350801-long-chain.js` |

Seed hit log: `logs_findings/corpus_seed_hits.txt`.

---

## 3. New findings

### F1 — shape unlinked before fallible shape realloc; GC NULL write (SIGSEGV)

**Status:** new, no matching GitHub issue found. Present in `7a23d8e` and
`e22ce4d` (upstream HEAD).

**Location:** `quickjs.c`, `resize_properties()`, "only resize the
properties" branch, lines 5904–5910; crash in `gc_scan_incref_child()` /
`list_del()` at `quickjs.c:7403` / `list.h:78`.

**Root cause:**

```c
/* resize_properties(), quickjs.c:5903 */
list_del(&sh->header.link);                 /* shape leaves gc_obj_list */
sh_alloc = js_realloc(ctx, get_alloc_from_shape(sh), ...);  /* can fail */
if (!sh_alloc) {
    list_add_tail(&sh->header.link, &ctx->rt->gc_obj_list);
    return -1;
}
```

`js_realloc()` on the memory-limit check calls `JS_ThrowOutOfMemory()`.
Constructing the uncatchable InternalError allocates a JSObject, and
`JS_NewObjectFromShape()` calls `js_trigger_gc()`. At this point:

1. the live array/object still points at the shape (`p->shape == sh`), but
   the shape is not in `gc_obj_list` and its link is `{NULL, NULL}`;
2. the GC decref pass still visits the shape as a child of the live owner
   and decrements its refcount 1 → 0;
3. `gc_scan()` then treats it as a zero-ref child to resurrect, increments
   it 0 → 1, and calls `list_del(&p->link)`;
4. `list_del()` computes `prev = el->prev = NULL` and executes
   `prev->next = next`, a fixed 8-byte zero write at address `0x8`.

So the failure path that would reinsert the shape is never reached: the GC
aborts first. (If the write were tolerated, the subsequent
`list_add_tail()` would insert the same link twice.)

**Evidence:**

* UBSan 6 MiB (`logs_findings/shape_gc_oom_asan_6m.txt`):

  ```
  list.h:78:16: runtime error: member access within null pointer
    #0 list_del
    #1 gc_scan_incref_child            quickjs.c:7403
    #2 mark_children                   quickjs.c:7268
    #3 gc_scan                         quickjs.c:7424
    #4 JS_RunGC                        quickjs.c:7492
    #5 js_trigger_gc                   quickjs.c:1696
    #6 JS_NewObjectFromShape           quickjs.c:6144
    #7 JS_NewObjectProtoClass          quickjs.c:6273
    #8 JS_MakeError2 / JS_ThrowError2  quickjs.c:8417/8451
    #9 JS_ThrowOutOfMemory             quickjs.c:8570
    #10 js_realloc                     quickjs.c:2139
    #11 resize_properties              quickjs.c:5905
  ```

* Release gdb 6 MiB (`logs_findings/shape_gc_oom_release_gdb.txt`):
  `SIGSEGV` at `mov %rax,0x8(%rcx)` with `rax=0, rcx=0`; `sh` in the still
  live `resize_properties` frame equals `p` in `gc_scan_incref_child`, and
  `sh->header.link == {NULL, NULL}`.

**PoC** (`poc/shape_gc_oom_6m.js`, 3 lines, source-only):

```js
var fill = new ArrayBuffer(148000);
var a = [];
for (var i = 0; i < 500000; i++) { a[i * 100] = 0; }
```

* glibc release, 6 MiB: SIGSEGV (rc 139) in 3/3 runs, ~15 ms.
* Scudo release, 6 MiB: SIGSEGV in the same shape; the crash band is
  **broad**, not a knife-edge: every 4 KiB step from **148 KB to 540 KB**
  crashed under glibc (the sweep ran 0–2,000 KB), and every 10 KiB step
  from **160 KB to 550 KB** crashed under Scudo (sweep 100–800 KB).
* String-valued sparse arrays (`a[i*100] = "xyz"`) show the same band at
  160–520 KB; the exact filler value is not critical inside the band.
* ASan/UBSan, 6 MiB: UBSan null member access, deterministic 3/3.

A payload family over filler sizes is enough to absorb the widget's own
baseline heap (sandbox bundle + DOM shims). If the widget baseline already
exceeds ~550 KB, use a smaller sparse-array count/spacing or a different
growth shape to move the capacity phase (see §7). `ArrayBuffer` is the only
"special" object used; no host API, no `os`/`std`/module.

**Impact:** reliable engine SIGSEGV → app-process DoS from a bot widget
(scripts run on bind, no tap). The primitive is a **fixed** NULL write
(address `0x8`, value `0`); page 0 is unmapped on Android/Linux, so it is
not an arbitrary write and no corruption/RCE follows the fault. The
underlying GC-list invariant violation would be list corruption if the
fault were somehow survivable; no such variant was demonstrated.

**Fix sketch:** never delink a GC object across a fallible allocation.
Either allocate/copy the new shape first (as the hash-growth branch does),
or use the non-throwing `js_realloc_rt()`, reinsert the link on failure,
and only then call `JS_ThrowOutOfMemory()`.

**Dedup:** GitHub issue search (`resize_properties`, `list_del`,
`gc_obj_list`) on 2026-11-05 found no match; no matching entry exists in the
project `notes/` either (the prior OOM notes cover #1782/#1852/#1855 but not
this delink window). Distinct from: #1833 (module-link orphan var_refs),
#1852 (`JS_SetPropertyInternal2` value loss), #1855 (`add_property` NULL
write for array `length`).

---

### F2 — bound-function finalizer dereferences NULL after bind OOM (SIGSEGV)

**Status:** new, no matching GitHub issue found. Present in `7a23d8e` and
`e22ce4d`.

**Location:** `quickjs.c`, `js_function_bind()` exception path
(line 42714) and `js_bound_function_finalizer()` line 7015.

**Root cause:**

```c
func_obj = JS_NewObjectProtoClass(ctx, prototype, JS_CLASS_BOUND_FUNCTION);
...
bf = js_malloc(ctx, sizeof(*bf) + arg_count * sizeof(JSValue));
if (!bf)
    goto exception;                 /* p->u.bound_function still NULL */
...
exception:
    JS_FreeValue(ctx, func_obj);    /* runs the finalizer */
```

`js_bound_function_finalizer()` does:

```c
JSBoundFunction *bf = p->u.bound_function;
JS_FreeValueRT(rt, bf->func_obj);   /* bf == NULL */
```

The object is zero-initialised, so the finalizer reads `bf->func_obj`'s tag
at address `0x8` and faults.

**Evidence:**

* UBSan 6 MiB (`logs_findings/bound_finalizer_asan_6m.txt`):
  `quickjs.c:7015:5: runtime error: member access within null pointer of
  type 'struct JSBoundFunction'`, with the full
  `js_function_bind` → `JS_FreeValue` → `free_object` →
  `js_bound_function_finalizer` stack.
* Release gdb (`logs_findings/bound_finalizer_release_gdb.txt`):
  `bf = 0x0`, `p->u.bound_function = 0x0`, `arg_count = 65524`;
  SIGSEGV at `js_bound_function_finalizer`.

**PoC** (`poc/bound_finalizer_oom_6m.js`, source-only):

```js
var fill = new ArrayBuffer(4200000);
var foo = function () {};
var args = new Array(65525);
try { Function.prototype.bind.apply(foo, args); } catch (e) { }
```

* glibc release, 6 MiB: SIGSEGV 3/3, ~2 ms.
* Scudo release, 6 MiB: SIGSEGV 2/2 (same filler).
* The OOM is thrown as an uncatchable InternalError, but the crash happens
  while the error is being constructed, before any `catch` can matter.

**Impact:** engine SIGSEGV → app DoS. Fixed NULL read at `0x8`; no
attacker-controlled read/write or RCE. Same severity class as #1855: a
remote, no-interaction engine crash.

**Fix sketch:** make the finalizer NULL-safe (`if (!bf) return;`), or do
not publish a `JS_CLASS_BOUND_FUNCTION` object until `bf` is installed; a
temporary safe class or an explicit zero state is sufficient.

**Dedup:** GitHub search (`JSBoundFunction`, `bound function OOM`,
`bound_function`) on 2026-11-05 found no match, and no project note mentions
the bound-function finalizer. Distinct from #1852/#1855 (different
functions and failure paths).

---

## 4. Deduped / already known

| item | how the corpus hit it | verdict |
|---|---|---|
| **#1782** truncated parser `byte_code` read in `resolve_variables()` | `regress/regress-539350801-long-chain.js` at 512 KiB, ASan heap-buffer-overflow read of 4 bytes past an 88,266-byte Dbuf | known, PR open; already deduped in `notes/audit_parser.md`; log `logs_findings/parser_1782_asan_512.txt` |
| **#1827** RegExp deletion bytecode UAF | not from mjsunit: qjs upstream test `tests/regexp-delete-lastindex-recompile.js` run on the app worktree | known, fixed in `e22ce4d`; `7a23d8e` ASan UAF confirmed; prior campaign owns it, not re-reported |
| **#1794 / #1834** `Object.defineProperties` evaluation order | `object-define-properties.js`: invalid second descriptor leaves `object.foo === 1` (partial application) | known open issue/PR; semantic only |
| **#1855 / #1852** OOM family | not re-triggered by this corpus in these sweeps | known open; F1/F2 are distinct sites |

Not observed in this corpus: #1865 (needs >65k captured variables, not
reachable at 6 MiB), #1878, #1882, #1890, #1892.

---

## 5. Semantic deviations (wrong-value only)

Reproduced directly on `build-asan` at 6 MiB; all are pure JS and
memory-safe in the tested shapes. Machine-readable evidence:
`lab/v8_corpus/poc/semantic_diffs.js` and
`lab/v8_corpus/logs_findings/semantic_diffs.txt`.

| # | test / probe | expected (V8/spec) | quickjs-ng | root cause | memory relevance |
|---|---|---|---|---|---|
| S1 | `es9/object-spread-basic`: `{...'foo'}` | `{0:'f',1:'o',2:'o'}` | `{}` | `JS_CopyDataProperties()` (`quickjs.c:17427`) returns 0 for any non-object source; spec does `ToObject(source)` except null/undefined. Object *rest* (`let {...r} = "ab"`) works, so only the spread entry point is affected. | none (early return) |
| S2 | `harmony/set-union.js` `TestUnionAfterClearingTheReceiver` | union copies receiver after `other.size` getter runs; clearing receiver via the getter yields only other's elements | getter never runs; union returns the old receiver elements | `js_setlike_get_props()` (`quickjs.c:54204`, fast path `54214`) uses `s->record_count` for real Set/Map instances and never `Get(other, "size")`; observable side-effect/order violation | none (fast path is bounded) |
| S3 | `es7/array-includes.js` | `a.includes(4, {toString(){a.push(4);return 0}})` is `false` (length captured before ToInteger) | `true` | `js_array_includes()` uses the post-side-effect fast-array `count` instead of the captured `len` | none: `js_get_fast_array()` re-fetches pointer/count, no OOB |
| S4 | `regexp.js` Annex B class `[\s-0-9]` | range `\s..'0'` plus literal `9`; `'1'` does not match | `'1'` matches (`\s`, `-`, `0-9` set interpretation) | `libregexp.c` character-class range parsing | none (parser) |
| S5 | `number-tostring-big-integer.js` | `(1.2345e27).toString(5) == "314404114120101444444424000000000000000"` | `"314404114120102000000000000000000000000"` | radix ≠ 10 conversion precision for large doubles (`dtoa.c` / `js_dtoa`) | none (string output) |
| S6 | `object-define-properties.js` | invalid second descriptor leaves the target untouched | first property already defined (`foo === 1`) | `JS_DefineProperties` defines incrementally (#1794/#1834) | none |

Fixed/probable harness artifacts (not qjs bugs):

* `es8/object-values.js`, `harmony/string-replaceAll.js`,
  `es9/object-spread-basic.js` initial failures were caused by generic
  no-op stubs for `%CreatePrivateSymbol` / `%ConstructConsString`; after
  adding those shims the first two pass (the remaining S1 spread case is
  genuine).
* `typedarray-every/foreach/map` failures were caused by a non-idempotent
  `%ArrayBufferDetach` shim; V8's intrinsic is idempotent, qjs `transfer()`
  throws on an already-detached buffer. After making the shim idempotent
  those tests pass.
* RegExp `$&`/`$1` statics, `Error.stack` formatting,
  `Function.prototype.toString` whitespace, `assertOptimized`,
  `Date`/timezone/locale, `Realm`/`d8`/`setTimeout` are V8/environment
  specific and were filtered or ignored.

Other observations, not claimed as bugs:

* `array-concat.js` with `new Array(4_000_000_000)` runs a 4-billion-step
  loop in qjs (concat walks the holey array); it is a timeout/perf
  difference, not memory unsafety.
* `Set.prototype.union` with a cleared receiver returns stale **current**
  elements (S2) but does not read freed records; ASan clean.
* BigInt size limits (`RangeError: BigInt is too large` below V8's limits)
  and iterator-helper prototype symbol counts differ; semantic only.

---

## 6. Reproduction

Build (already present in `lab/v8_corpus/`):

```bash
cd lab/v8_corpus
cmake -S ../qjs_src -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
make -C build-asan -j8 qjs_exe
cmake -S ../qjs_src -B build-rel -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-O2 -g"
make -C build-rel -j8 qjs_exe
```

Corpus:

```bash
python3 select_tests.py
python3 run_corpus.py --list selected_tests.json --mem 6144 --jobs 8 \
  --out results_mjsunit_e22.jsonl
python3 run_corpus.py --list all_tests.json --rewrite all --mem 6144 \
  --jobs 8 --out results_intr4_e22.jsonl
# OOM sweep example
python3 run_corpus.py --list all_tests.json --rewrite all --mem 1536 \
  --jobs 8 --out results_oom_1536.jsonl
```

Crashes:

```bash
./build-rel/qjs  --script --memory-limit 6144 poc/shape_gc_oom_6m.js ; echo $?  # 139
./build-rel/qjs  --script --memory-limit 6144 poc/bound_finalizer_oom_6m.js ; echo $?  # 139
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
  ./build-asan/qjs --script --memory-limit 6144 poc/shape_gc_oom_6m.js
```

Single test with full output:

```bash
python3 single_test.py regress/regress-430201.js "$PWD/build-asan/qjs" 512 512
```

---

## 7. Limitations and next steps

* Both new findings are **OOM-gated** and crash before returning to JS; the
  widget impact is a deterministic app-process DoS, not RCE. Do not
  advertise more than that.
* The 6 MiB PoCs are tuned for the local builds. The widget's baseline heap
  (sandbox bundle, DOM shims, host wrappers) differs by an unknown amount;
  deliver a filler family (e.g. 100–550 KB for F1, 3.8–4.5 MB for F2 in
  2–4 KB steps) and let the first crashing member win. F1's tested band is
  broad but bounded by the point where the property array realloc fails
  first; if the widget baseline already exceeds ~550 KB, vary the
  sparse-array count (`500k` → `300k`/`700k`), spacing (`i*100` →
  `i*64`/`i*128`) or value kind (string values shift the per-property
  cost) to move the capacity boundaries instead of relying on a negative
  filler.
* Confirm on the app binary (`libtmessages.49.so`, 72799) on a disposable
  install before any external report; source identity is already proven
  (`notes/qjs_latest_audit.md`).
* Re-run F1/F2 after upstream merges #1782/#1794/#1834 and after any
  allocator/GC refactor; both are currently reproducible on upstream HEAD
  `e22ce4d`.
* If test262 data is wanted later, clone `tc39/test262` separately and run
  only the detach/Proxy/RegExp-annex-B directories; do not repeat the
  async/types campaigns already in `notes/audit_async.md` and
  `notes/audit_types.md`.

---

## Appendix — artifact index

| path | contents |
|---|---|
| `lab/v8_corpus/v8/` | V8 sparse clone (`test/mjsunit`, `test/test262`), HEAD `7e76d90` |
| `lab/v8_corpus/select_tests.py` | static selector (`selected_tests.json`, `all_tests.json`) |
| `lab/v8_corpus/run_corpus.py` | parallel harness, intrinsic rewriter, classifier |
| `lab/v8_corpus/single_test.py` | one-test runner with full output |
| `lab/v8_corpus/build-asan`, `build-asan-7a23`, `build-rel`, `build-rel-7a23`, `build-gcstress`, `build-scudo` | engine builds |
| `lab/v8_corpus/results_*.jsonl` | per-test classification (class, rc, ms, first line) |
| `lab/v8_corpus/logs_*/` | full output for crash rows |
| `lab/v8_corpus/poc/shape_gc_oom_6m.js` | F1 source-only PoC |
| `lab/v8_corpus/poc/bound_finalizer_oom_6m.js` | F2 source-only PoC |
| `lab/v8_corpus/poc/semantic_diffs.js` | S1–S6 reproducer (OK/DIFF lines) |
| `lab/v8_corpus/logs_findings/` | UBSan stacks, gdb traces, corpus seed hits, #1782 log, semantic output |
