# Memory-bug ledger — Telegram QuickJS widget engine (2026-11-07/08)

Host-only campaign. No device, no Frida, no bot, no network payload delivery.
Target: the shipped Telegram QuickJS fork **2dfeee3e** (`libtmessages.49.so`,
APKs 72889/72929); reference upstream: the fork's `origin/master` (6 commits
ahead) and quickjs-ng `e22ce4d` copies in the tree.

Purpose of this note: **one durable ledger for every memory bug found or
confirmed in this campaign**, including n-days, DoS-only bugs, read-only bugs
and leaks. It complements — and does not replace — the existing
`notes/bug_inventory_20261105.md` (18-row root-cause matrix),
`notes/MTE_safe_hunt_20261107.md` (18-bug matrix + MTE model) and
`notes/new_0day_mte_specs_20261107.md` (§11 N1 closure, §12 same-tag negative).
Existing evidence was not deleted or overwritten.

All host artifacts for this campaign are under
`lab/membug_ledger_20261107/`:

```
build.sh                              builds the three harnesses + run_gc/run_int
scripts/instrument_arena2.py          A1-A4 slab/page invariants
scripts/instrument_realloc.py         R1 "no realloc of a gc-linked object"
scripts/run_gc.c                      harness with __gc()/__mem()
scripts/run_int.c / run_int2.c        interrupt-injecting harnesses
scripts/t_*.js                        fork-code stress corpus
poc/poc_*.js                          minimal triggers
logs/*                                build + run logs
```

## 0. Result of the primary objective (honest)

**No new 0day with a v7-like same-allocation primitive was found.** The
fork-specific code that was the primary target — the `JS_ARENA_SLABS`
allocator, the GC/refcount-in-block-header merge, and the 2026-10 perf
commits — held under review, three instrumented builds and targeted stress
(§4). What the campaign *did* produce is a verified ledger of memory bugs that
the shipped engine still contains, three of them with fresh host repros
(§1: MB-01, MB-02, MB-03), all in the same tag-0 arena domain the v7 pattern
uses.

## 1. Ledger (new / confirmed with host evidence)

Legend: **class** = OOB read/write, UAF, double free, type confusion, stale
pointer, leak/DoS. **OOM?** = needs an allocation failure or near-cap heap.
**Novelty**: `new` = not in any upstream fix and not in the inventory;
`n-day` = fixed upstream on `origin/master` but present in the shipped
snapshot; `known` = already in `bug_inventory_20261105.md`.

### MB-01 — `js_map_finalizer` WeakMap record UAF (n-day #1835)

| field | value |
|---|---|
| id | MB-01 (dedup: #1835 / GHSA-family WeakMap symbol UAF) |
| root cause | `js_map_finalizer` iterates `s->records` with `list_for_each_safe` and, per record, calls `delete_map_weak_ref()` then `JS_FreeValueRT(mr->value)`. Freeing a value that is a **symbol also used as a key of a later record in the same map** runs `reset_weak_ref()`, whose second pass unlinks **and frees** that later record (`js_free_rt(rt, mr)`). The finalizer's saved cursor `el1` then points at freed memory. |
| class | UAF (read of a freed class-96 record; second visit re-enters `delete_map_weak_ref` on the freed record and dereferences a NULL weak-ref head) |
| exact trigger | `wm = new WeakMap(); A = {}; S = Symbol("s"); wm.set(A, S); wm.set(S, 1); S = null; wm = null;` (A kept alive). Record order must be [A→S] before [S→1]; the map must die while A is alive and S's only strong ref is record 1's value. |
| tag domain | QuickJS arena slab, `JSMapRecord` = 88 B request → **class 96**, tag 0, never MTE-checked |
| OOM? | **no**; no near-cap heap; no explicit GC needed (the map hits refcount 0 at `wm = null`) |
| novelty | **n-day**: fixed upstream by `ebd139b Detach WeakMap references before freeing values`; the shipped snapshot `2dfeee3e` is 6 commits behind and has the unfixed loop. Already listed as "#1835 WeakMap symbol UAF fixed in latest" in the inventory — this row adds the exact corrected trigger and the release behaviour. |
| host repro | `poc/poc_weakmap_finalizer2.js` — ASan `heap-use-after-free ... in js_map_finalizer quickjs.c:54778` (read of 8 at offset 32 of the freed 88-byte record), log `logs/mb01_weakmap_asan.log`; release/arena build **SIGSEGV in `delete_map_weak_ref` quickjs.c:54450** (`logs/mb01_weakmap_release.log`, gdb backtrace in `logs/mb01_weakmap_gdb.log`). |
| widget payload | `poc/widget_mb01_weakmap.html`: **158 B raw / 143 B zlib9** (7-line trigger). Marker before the trigger survives only in the JS log, not on screen. **Destructive**: native SIGSEGV in the widget thread kills the app process → DB/probe only, do **not** send to a device under the current rules. |
| exploitability | DoS as written. No JS runs and no allocation happens between the free and the second visit (only frees), so the freed class-96 record cannot be reclaimed with attacker bytes; the second visit sees `mr->empty == 0`, `mr->key == S` (freed atom, `first_weak_ref == NULL`) and crashes in `delete_map_weak_ref`. Turning it into a write would need a class-96 allocation inside `reset_weak_ref`'s gap — same blocker as the FR bug (§12.3.5). |
| status | reproduced (ASan + release); n-day; not a carrier. |

### MB-02 — `js_finrec_unregister` FinalizationRegistry UAF (unreported lab bug)

| field | value |
|---|---|
| id | MB-02 (same root cause as the inventory's "FR unregister UAF"; kept as its own row) |
| root cause | `js_finrec_unregister` walks the registry's entry list and frees entry 1's held value while still iterating. If that held value is the **target of another entry in the same registry**, its refcount hits 0 inside the loop and `reset_weak_ref()` unlinks **and frees** the other entry (`js_finrec_free`), leaving the loop cursor dangling. |
| class | UAF (read of freed class-96 `JSFinRecEntry`), NULL-derived crash |
| exact trigger | `reg = new FinalizationRegistry(()=>{}); T={}; tok={}; k={}; reg.register(k, T, tok); reg.register(T, 2); T=null; reg.unregister(tok);` |
| tag domain | arena class 96, tag 0 |
| OOM? | no |
| novelty | **new/unreported** (not fixed upstream at `origin/master`; the registry *finalizer* has the two-pass fix, `js_finrec_unregister` does not) |
| host repro | `poc/poc_finrec_unregister.js` — ASan `heap-use-after-free ... in js_finrec_unregister quickjs.c:64251` (`logs/mb02_finrec_asan.log`); release build SIGSEGV (`logs/mb02_finrec_release.log`) |
| widget payload | `poc/widget_mb02_finrec.html`: **185 B raw / 153 B zlib9**; destructive (native crash) → DB-only, no device probe |
| exploitability | DoS only, for the reason already recorded in `new_0day_mte_specs_20261107.md` §12.3.5: the free→read gap contains no class-96 allocation (the only allocation is the class-64 `JSJobEntry` from `reset_weak_ref`'s FR enqueue), so no reclaim. |
| status | reproduced (ASan + release); unreported but not a carrier. |

### MB-03 — `js_array_find` double free on the interrupt path (n-day #1826)

| field | value |
|---|---|
| id | MB-03 (dedup: #1826/#1792 Array.find ownership) |
| root cause | `js_array_find` frees the loop-carried `val` at the end of every iteration but does not clear it (`val = JS_UNDEFINED` is missing). The next iteration's `js_poll_interrupts()` failure jumps to `exception`, which frees `val` again. (The same file already clears `val` in `js_array_reduce` and `js_array_map/filter/every/some`; find was the only one left.) |
| class | double free / refcount underflow (previous element value) |
| exact trigger | a `find`/`findLast` whose callback returns false for ≥ 2 iterations, with a pending interrupt at the top of a later iteration (widget: the 300 ms CPU quota). Host: `run_int2` + `__arm()`; a 22000-element String object makes every element a fresh refcount-1 1-char string. |
| tag domain | arena (element value). For a plain array the first free only drops the array's own reference (double **decrement**, premature free); for a value not otherwise referenced it is a true double free. |
| OOM? | no, but it requires the interrupt (timeout) path |
| novelty | **n-day**: fixed upstream by `e22ce4d` / cherry-picked `f4dd164 Clear Array.find value ownership after release`; the shipped snapshot lacks it. Listed as "#1826/#1792 Array.find ownership (merged e22ce4d)" in the inventory. |
| host repro | **confirmed**: `poc/poc_array_find_doublefree4.js` + `build/run_int2_asan` → ASan `heap-use-after-free ... READ of size 4 ... JS_FreeValueRT quickjs.c:7533` called from `js_array_find quickjs.c:44832` (the exception label); the ASan "freed by" stack shows the first free at `js_array_find quickjs.c:44821` (the normal end-of-iteration free) — the exact double-free cycle — on a 34 B 1-char `JSString` block (`logs/mb03_find_asan.log`). In the release/arena build the second free lands on a block that `JS_ThrowInterrupted` has already reclaimed, so `js_free_string0` sees a stale `atom_type` and enters `JS_FreeAtomStruct`; the process **hangs** in the atom free-list manipulation (gdb SIGINT backtrace `#0 JS_FreeAtomStruct quickjs.c:3924`, `logs/mb03_find_gdb.log`; 20 s timeout rc=124, `logs/mb03_find_release.log`). Deterministic host driver: `scripts/run_int2.c` (`__arm()` + `JS_SetInterruptHandler` counter reset). |
| widget payload | `poc/widget_mb03_find.html`: **176 B raw / 158 B zlib9**. It only fires when the widget is already being killed by the 300 ms quota (InternalError uncatchable), so it is not a controllable carrier — but the double free is a real free-list corruption (hang/crash, i.e. app-level DoS). The poll parity decides whether the quota lands on the loop-top poll (double free) or the callback-entry poll (no double free); either way the widget is already dead. The reclaim by `JS_ThrowInterrupted`'s own error/message allocations is what turns it from a plain double free into atom-free-list corruption. |
| status | reproduced (ASan UAF + release hang); n-day; interrupt-gated, not a carrier. |

### MB-04 — `JS_ReadRegExp` does not register the deserialized object (n-day, not widget-reachable)

| field | value |
|---|---|
| id | MB-04 |
| root cause | `JS_ReadRegExp` constructs the RegExp object without `BC_add_object_ref()`, so a later reference to the same object in the serialized graph re-creates it (or leaves the bytecode string without an owning object reference). Fixed upstream by `f4fe478 Register deserialized RegExp object references`. |
| class | UAF / lifetime (bytecode deserialization) |
| tag domain | Scudo/arena depending on allocation size (bytecode strings > 504 B are large blocks) |
| OOM? | no |
| novelty | **n-day** (fixed `f4fe478`, missing in 2dfeee3e) |
| widget reachability | **not reachable**: only the host's own precompiled bundles go through `JS_ReadObject` (`lab/qjs_fork_audit/widget-sandbox/docs/native-port-notes.md`); widget JS never sees `JS_ReadObject`. |
| host repro | none attempted (unreachable); source diff is the evidence (`git show f4fe478`) |
| status | n-day, unreachable → ledger only. |

### MB-05 — `JS_RegExpDelete` stale bytecode (n-day #1827, the v7 technique reference)

| field | value |
|---|---|
| id | MB-05 (v7) |
| root cause | `JS_RegExpDelete` takes `re_bytecode = str8(re->bytecode)` **before** the `lastIndex` coercion; user code (`valueOf`) can call `RegExp.prototype.compile`, dropping the last reference to the bytecode string, and the stale pointer is then executed. Fixed upstream by `2b62af1`; the shipped snapshot has the vulnerable order. |
| class | UAF / stale pointer (RegExp bytecode) |
| tag domain | arena (bytecode ≤ 504 B → small class; the v7 fake program lives in class 480/512), tag 0. Proven MTE-on on the Pixel 9 (C2 `tg-10290-Pixel_9`). |
| OOM? | no |
| novelty | **n-day** (merged upstream). It is the same-view technique reference, not a 0day. |
| host repro | already in the tree (`lab/qjs_n1/poc/trigger_re.js`, `poc/loader_v7_plain_text_cec.html`, proofs 5489/5492/5493) |
| widget payload | 3,056 B zlib9 (v7 cec), MTE-on proven |
| status | known n-day, working. Not counted as a 0day. |

### MB-06 — `JS_ArrayFind`-family ownership review (no new bug)

The interrupt-path audit of every `js_poll_interrupts` loop with a loop-carried
freed value (23 poll sites) found exactly one unfixed instance (MB-03):
`indexOf`/`lastIndexOf`/`includes` free `val` per iteration but their exception
labels only free `obj` (a leak at worst on interrupt, not a double free);
`reduce` and `map/filter/every/some` already carry the `val = JS_UNDEFINED`
clear; `Object.isPrototypeOf`/`getPrototypeOf` do not free the loop value in
the exception path. No additional double free.

### Non-memory delta (for completeness, not a memory bug)

* `b06baf9 Use internal calls for Array.fromAsync callbacks` — spec conformance
  (a user-supplied `.call` property must not hijack `fromAsync`), no memory
  impact. `tests/bug1795.js`.
* `1a402cb` — test only.
* `ebd139b` → MB-01, `2b62af1` → MB-05, `f4dd164` → MB-03, `f4fe478` → MB-04.

## 2. Shipped fork vs `origin/master` (the exact missing-fix set)

`git log --oneline app-snapshot..origin/master` gives the six commits the
shipped `2dfeee3e` lacks. Widget reachability:

| commit | what | memory? | widget reachable? |
|---|---|---|---|
| `ebd139b` | detach WeakMap refs before freeing values | **yes — UAF** | **yes (MB-01)** |
| `f4dd164` | clear Array.find value ownership | **yes — double free** | **yes, interrupt-gated (MB-03)** |
| `2b62af1` | keep RegExp bytecode valid after lastIndex coercion | **yes — UAF (#1827)** | **yes (MB-05, v7)** |
| `f4fe478` | register deserialized RegExp object refs | **yes — UAF** | no (`JS_ReadObject` host-only) |
| `b06baf9` | Array.fromAsync internal calls | no (spec) | yes, no memory impact |
| `1a402cb` | RegExp replace test | no | — |

So the shipped engine contains **four** missing memory fixes; three are
widget-reachable, and all three reachable ones are already known n-days. This
is the whole delta; there is no *unfixed* fork-only memory fix in the delta.

## 3. Existing inventory (index — not re-verified here)

These rows remain as recorded in `notes/bug_inventory_20261105.md` and
`notes/MTE_safe_hunt_20261107.md` §6; this campaign did not change their
status: N1 (OOM-gated, device-closed), C1, C2, F1, F2, T1, T2, T3, F-A, S1,
V1, V2, R1, R2, FR-unregister (=MB-02), async-frame leak, symbol-FR teardown
leak, #1827 (=MB-05), #1835 (=MB-01), #1826 (=MB-03), #1865/#1869, #1867/#1873,
#1874, #1844, #1828/#1829, #1852/#1855, #1892.

## 4. New-code negative results (fork-specific surfaces)

Built and run (host):

* `build/run_dbg` — arena ON, asserts, shipped source.
* `build/run_inst2` — arena ON + **A1–A4** invariants (block class matches its
  arena; no page double-ownership across live arenas; `js_arena_free` derives a
  live slab slot of the same class; free-list index in range) + **R1**
  (`js_realloc_rt` must never move a block that is linked in `gc_obj_list`).
* `build/run_asan2` — ASan+UBSan, arena off.
* `build/run_gc*`, `build/run_int2*` — GC and interrupt drivers.

| surface (fork commit) | what was tested | result |
|---|---|---|
| `JS_ARENA_SLABS` + `7004444` keep-empty-arena (`quickjs.c:1851-2110`) | 24 size classes × 800 objects, 4 000 interleaved ArrayBuffers, free-half → `__gc()` → 20 000 reallocs → verify all survivors → free all → GC → 20 000 mixed-class allocations (`t_slab_churn.js`) | **clean** under A1–A4; no cross-class page reuse, no header corruption, no free-list anomaly |
| GC-header merge (`JSMallocBlockHeader`) + `js_realloc` | R1 active over the whole corpus + slab churn + all existing `sametag_hunt` scripts | **clean**: no realloc of a GC-linked object (this closes the §12.6(4) open invariant) |
| typed-array inline store `4b387c6` | RAB grow/shrink to 0, fixed and length-tracking views, detach, `transferToImmutable`, all element classes, negative/huge indices, subclass, BigInt64/Float16 (`t_rab_fast.js`) | **clean**; the OOB-view fast path is blocked by `count == 0` after `js_array_buffer_update_typed_arrays`, and `idx` is an int32 before the uint32 bound check |
| string hash cache `7ead61a` | 500 Map keys + atomization + in-place `+=` after map drop, 100 slice keys (> 1024), Set, mixed widths, indexOf/includes vs a reference implementation (`t_strhash.js`) | **clean**; hashes are content-consistent across plain/slice/atom; in-place concat clears `hash_next`; slices never take the in-place path (the 1024-byte slice threshold makes `js_malloc_usable_size` fail the check) |
| inline property array `ee1ef12` | grow 0→40, delete/compact, defineProperty, setPrototypeOf, preventExtensions (`t_inlineprop.js`) | **clean**; no larger shape is ever assigned without an external array |
| `put_field` add `b989db6` | prototype writable data prop, setter, read-only, Proxy in chain, non-extensible (`t_inlineprop.js`) | **clean**; fast path defers to the generic path in every shadowing case |
| RegExp bytecode cache `6b6c1f2`/`9383ba4` | 200 cached patterns + eviction, 400 long patterns, `compile` inside `lastIndex` coercion, split/replace sticky copies, flags as key (`t_regcache.js`) | **clean**; the cache adds a second strong ref to the bytecode, so it only *narrows* the #1827 window; no new lifetime hole |
| JSON fast paths `286a561`/`ddcd8e5`/`9383ba4` | source audit + quoting/number paths exercised | **clean**; `nbuf[128]` is guarded by `js_dtoa_max_len`, `nbuf[16]` holds any int32, and `JS_DTOA_EXP_AUTO` is 0 so tiny exponents take the exponent branch |
| arena `js_arena_realloc` header transfer | reviewed; fields transferred on move; R1 active | **clean** |

Non-memory observation from the same corpus (recorded so it is not lost, and
so it is not mistaken for a new bug): **an assignment to an element of a typed
array over an immutable ArrayBuffer is a silent no-op through the inline fast
path** (`v[i] = x` neither writes nor throws), while `v.set()`, `fill()`,
`copyWithin()` and `DataView.set*` throw `TypeError`. The `ta_immutable` label
in `JS_SetPropertyValue` lives inside the `JS_CLASS_FLOAT64_ARRAY` case and
does `return false` for every class (`quickjs.c:11407`), which the callers read
as success. This is **identical in upstream quickjs-ng `e22ce4d`** (not a fork
regression), it is **fail-closed** (the bytes never change), and it is a spec
deviation, not a memory-safety issue. Widget impact: none (no write).

No ASan/UBSan report, no invariant abort, no assertion failure in any of the
above.

## 5. Next leads (in priority order)

1. **Interrupt-gated ownership bugs (MB-03 class).** The widget always has a
   300 ms interrupt, and every `js_poll_interrupts` loop is a potential
   double-free site when its exception label frees loop-carried state. A
   mechanical pass over the 23 poll sites with a "is every refcounted local
   either cleared after its free or re-assigned before the next poll" rule is
   cheap; find was the last unfixed instance in the array builtins but the
   fork's own loops (JSON, regexp, iterator helpers) were not audited this way.
2. **Finalizer-order class (MB-01/MB-02 class).** Any finalizer that iterates
   a container and frees values which can re-enter `reset_weak_ref` or another
   container. The map finalizer and the FR finalizer have the two-pass fix;
   `js_finrec_unregister` does not. Check `js_map_clear`/`map_delete_record`
   for a weak-map path (none is spec-reachable today: WeakMap has no
   clear/forEach).
3. **Arena slab under a long GC-stress run.** The A1–A4/R1 build is ready;
   a multi-hour libFuzzer run with `-DFORCE_GC_AT_MALLOC` plus the slab-churn
   generator is the natural next step (the earlier 55 k-exec campaign did not
   have A1–A4/R1 and did not force the trim path).
4. **Test262 under the instrumented build** (`build/qjs_inst2`, R1 active):
   build failed on a missing `cutils.c` in the copy; rebuild from the full
   source tree and run the engine's own `tests/*.js` with
   `MB_CHECK_GC_REALLOC=1`.

## 6. Files

```
notes/memory_bug_log_20261107.md          this ledger
notes/bug_inventory_20261105.md           new rows MB-01..MB-04 appended
notes/new_0day_mte_specs_20261107.md      §13 pointer to this ledger
notes/LEMMALOG_FACTS_membug_20261107.txt  facts for the orchestrator
lab/membug_ledger_20261107/               build.sh, scripts/, poc/, logs/
```

No device, Frida, bot or network was used. No existing file or evidence was
deleted.
