# quickjs-ng v0.17.0 memory-safety fuzzing — Telegram 13.2.0 widget sandbox

Date: 2026-11-01
Author: fuzzing subagent
Scope: novel memory-safety bugs reachable from attacker-controlled widget JS.
Verdict up front: **no new memory-safety bug (UAF / OOB / type confusion) was found.**
One new *non*-memory-safety defect (a leak that trips a debug assertion) was found,
is reproducible on stock `qjs`, and is still present on quickjs-ng master.

Findings ranked:

| # | finding | class | severity | memory-safe? | reachable in sandbox |
|---|---|---|---|---|---|
| F1 | WeakMap value leaked when the key is a Symbol (`§5`) | resource leak / debug assertion | P4 low | yes — no corruption | yes, plain JS, deterministic |

No P1/P2/P3 finding. The remainder of this document is the evidence: what was
fuzzed, for how long, what was triaged out, and which escalation paths were
checked and rejected.


---

## 1. Target

| | |
|---|---|
| Commit | `7a23d8e` "Fix leak in JS_ReadBigInt on truncated input", 2026-10-23 |
| Version | `QJS_VERSION 0.17.0` |
| Tree | https://github.com/quickjs-ng/quickjs (fresh clone, `src/`) |
| Why this commit | inside the app's snapshot window `[2026-10-08, 2026-10-30)`, latest commit before 2026-10-30, and still 0.17.0 |
| Cross-checked against | tag `v0.17.0` = `6d46d07`; master `d7215b0` (0.18.0, 2026-11-01) |

Known/owned bugs (#1792, #1835/#1844, #1570, PR #1827) are present in this
commit and were **not** re-reported. #1792 and #1827 are still unfixed here;
the #1835 fix (`25a005b`) is also after this commit.

App model used everywhere: fresh `JSRuntime`, `JS_SetMemoryLimit(6 MiB)`,
`JS_SetMaxStackSize(512 KiB)`, 300 ms `JSInterruptHandler` deadline, global-mode
`JS_Eval`, no host APIs, no `std`/`os` module, no GC stress, no `-OOM` fuzzing.

---

## 2. Build

`build.sh` produces two object sets and six binaries:

```
build/fuzz_src      build/run_src      # source eval
build/fuzz_regexp   build/run_regexp   # RegExp compile/exec
build/fuzz_api      build/run_api      # structured API sequences
build/fuzz_weak     build/run_weak     # WeakMap/WeakRef/FinalizationRegistry graphs
```

Flags: `clang -g -O1 -fsanitize=fuzzer-no-link,address,undefined` for the
libFuzzer builds, plain `address,undefined` for the standalone reproducers.
`-fno-sanitize=function` suppresses a benign `js_realloc` function-pointer-type
UBSan report that floods the log. `-fno-sanitize-recover` is set for the
memory-relevant UBSan checks only. Leak detection is off
(`ASAN_OPTIONS=detect_leaks=0`) except where explicitly measured.

Reproduce:

```bash
cd /tmp/opencode/qjs_fuzz
./build.sh            # ~55 s on 8 cores
ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 \
  ./build/run_src pocs/f1_weakmap_symbol_leak.js
```

---

## 3. Harnesses

### 3.1 `fuzz_src` — raw source eval
Bytes are fed to `JS_Eval(..., JS_EVAL_TYPE_GLOBAL)` as a UTF-8 script.
`JS_Eval` requires `input[len] == '\0'` (documented in `quickjs.h`), so the
input is copied into a NUL-terminated buffer. Pending jobs are drained after
eval (promises / async / generators). Runtime and context are freed per input,
so teardown bugs are also visible (triaged separately from live bugs).
Rejects NUL-containing inputs and inputs > 1 MiB.

### 3.2 `fuzz_regexp` — RegExp
Input = `[flags byte][mode byte][pattern]\0[subject]`. A persistent
runtime/context calls a JS driver that runs `exec/test/Symbol.match/replace/
split/search/matchAll (bounded to 16)/compile/to_string`, each in its own
`try/catch`, with a 100 ms interrupt deadline to cap catastrophic backtracking.

### 3.3 `fuzz_api` — structured API sequences
Instead of mutating text (which mostly yields `SyntaxError`), each input byte
*selects an operation* from a 34-entry menu and parameterises it. 48–60
statements are emitted, each wrapped in `try/catch`, over a 12-variable pool.
Menu covers: typed arrays (all 12 element types incl. Float16/BigInt),
ArrayBuffer/RAB resize + detach, DataView, all Array/TypedArray methods,
Map/Set/WeakMap/WeakSet with mutation during iteration, Proxy traps,
`Object.defineProperty` getters that mutate during access, JSON, RegExp,
generators, iterator helpers, `Array.fromAsync`, private class fields,
`using`/dispose, spread/destructuring, SharedArrayBuffer + Atomics, `eval`/
`Function`. This is the harness that reaches state-machine code rather than
parser code.

### 3.4 `fuzz_weak` — weak-reference graph fuzzer
Targets the area that produced #1835/#1844. 18 operations over a 16-variable
pool: create Symbol/object/function/WeakMap/WeakSet/WeakRef/
FinalizationRegistry; `set`/`add`/`register` with arbitrary cross-edges
(including symbol-as-key-and-value, registry-held-value-is-the-registry);
drop references; observe (`get`/`has`/`deref`); delete; allocation churn to
force natural GC inside the 6 MiB budget.

### 3.5 Corpus
`corpus/src` — the 100 files of `src/tests/*.js` plus 17 hand-written seeds for
modern features (iterator helpers, `Iterator.zip`/`zipKeyed`, `Array.fromAsync`,
private fields, `using`, RAB/GSAB typed arrays, proxies, weak refs, RegExp
`v`-flag/modifiers/`d`-flag, JSON, typed arrays, promises, classes, strings,
destructuring).
`corpus/api`, `corpus/weak`, `corpus/regexp` — random/structure seeds.

---

## 4. Campaign

All runs: 8 vCPU, ASan+UBSan, `-rss_limit_mb=2200`, `-timeout=10`.

| target | workers | wall time | execs | edges | corpus | result |
|---|---|---|---|---|---|---|
| `fuzz_src` | 4 | ~13 min | 1 171 805 | 11 343 | 5 430 | 2 artifacts, both F1 |
| `fuzz_api` | 2 | ~22 min | 424 194 | 7 116 | ~2 350 | 2 timeouts only |
| `fuzz_weak` | 2 | ~22 min | ~58 000 | 2 886 | ~760 | 2 artifacts, both F1 |
| `fuzz_regexp` | 2 | ~16 min | ~1 070 000 | 4 781 | 3 422 | 0 |

Total ≈ 2.7 M executions, ≈ 45 CPU-minutes of fuzzing, no memory-safety
sanitizer report.

Notes:
- `fuzz_src` is slow per input because a whole runtime is built and torn down
  per test case (~500–680 exec/s/worker). That is the price of teardown
  coverage and of the 6 MiB limit.
- `fuzz_api` and `fuzz_weak` initially lost their workers to `-timeout` aborts
  (a single input exceeding 10 s). Re-run with `-ignore_timeouts=1
  -ignore_crashes=1`; the timeouts are harness-level (very long generated
  programs hitting the 6 MiB limit/GC churn), not quickjs hangs, and DoS is
  out of scope here.
- `fuzz_regexp` reaches very high exec rates (~1 000/s/worker) because it keeps
  one runtime alive; it is the only target where the persistent-runtime model
  is used, so teardown bugs are invisible there by design (`fuzz_src` covers
  teardown).

### 4.1 Crash triage
Every artifact was replayed with the standalone ASan build
(`build/run_*`), then minimised. Dedup by top frame / assertion site:

| artifact | class | verdict |
|---|---|---|
| `src-crash-ed0142…`, `src-crash-8787a9…` | `assert(list_empty(&rt->gc_obj_list))` in `JS_FreeRuntime` | F1 |
| `weak-crash-7622e6…`, `weak-crash-cb5c84…` | same assertion | F1 (fuzzer independently rediscovered it) |
| `api-timeout-*`, `weak-timeout-*`, `weak-slow-unit-*` | libFuzzer timeout | discarded: generated program too large for the 6 MiB budget; DoS, out of scope |

No ASan report of any kind (no `heap-use-after-free`, `heap-buffer-overflow`,
`stack-buffer-overflow`, `SEGV`, type-confusion, or UBSan memory check) was
produced in any run.

---

## 5. Finding F1 — WeakMap value is leaked when the key is a Symbol

**Severity: low (memory leak; debug-build abort). Not memory corruption.**

### Reproducer (minimal, no harness needed)

```js
// pocs/f1_weakmap_symbol_leak.js
let key = Symbol("k")
let wm = new WeakMap()
wm.set(key, { payload: new Array(16).fill(0x41) })
```

Stock `qjs`, assertions enabled:

```
$ qjs f1_weakmap_symbol_leak.js
qjs: quickjs.c:2699: JS_FreeRuntime: Assertion `list_empty(&rt->gc_obj_list)' failed.
Aborted
```

Same result on tag `v0.17.0` (`6d46d07`) and on master `d7215b0` (0.18.0,
2026-11-01). No open issue matches this reproducer (checked all issues created
since 2026-09-01 plus a `crash` search; the only `gc_obj_list` report, #1833,
is about failed module links and needs no WeakMap).

With `-DNDEBUG` (what Android release builds use) the assertion disappears and
the object is simply never freed. Measured with LeakSanitizer, one runtime:

```
$ ASAN_OPTIONS=detect_leaks=1 qjs f1_weakmap_symbol_leak.js
SUMMARY: AddressSanitizer: 11968 byte(s) leaked in 14 allocation(s).
```

A control script (`let a = 1`) leaks 0 bytes.

### Conditions (measured, 10/10 deterministic)

| variant | leaks? |
|---|---|
| `wm.set(Symbol(), {})` | yes |
| `wm.set(Symbol(), 1)` (primitive value) | no |
| `wm.set({}, {})` (object key) | no |
| `wm.set(sym, {})` + `FinalizationRegistry.register(sym, …)` | yes (not required) |
| `fr.register(Symbol(), 42)` alone | no |
| two symbol keys | yes, both values |

So the trigger is exactly: **a `WeakMap`/`WeakSet` record whose key is a
`Symbol` and whose value is a GC object, still present when the runtime is
destroyed**.

### What it is not

I explicitly tested the escalation paths and they do **not** fire:

- The value is *not* collectable while the record exists. `WeakRef` on the
  value still dereferences after a forced full GC (`cyc_collected=true,
  val_collected=false`), including when the value is a cycle
  (`v.self = v`) — the record's reference is treated as external by
  `gc_free_cycles`, so no dangling record, no UAF.
- The value is not freed twice: the record's reference is never released, so
  the reference count never reaches zero.
- No `reset_weak_ref` / `js_map_finalizer` mis-ordering is involved. An
  instrumented build (`free_object` / `js_map_finalizer` / `reset_weak_ref`
  tracing) shows that with an **object** key the ordinary finalisation path
  runs to completion (`reset_weak_ref` then `js_map_finalizer weak=1 n=0`),
  while with a **symbol** key neither finalizer is reached for this object
  graph at all — that is precisely why the value keeps its reference.

So the effect is a missed free in the symbol-keyed WeakMap teardown path, not
a lifetime inversion. The exact ordering that skips the finalizer was not
fully pinned down; what *is* established is that the value stays reachable and
is never double-freed. In the Telegram sandbox (release build, one runtime per
widget) the practical effect is a one-off leak bounded by the number of
symbol-keyed WeakMap entries live at teardown (≈12 KB in the test above),
inside a heap that is about to be destroyed anyway. It is reported because it
is new, deterministic, present on master, and cheap to fix — not because it is
exploitable.

### Reachability and survival under the app model

The script executes normally and returns; nothing happens during execution, no
exception is raised, no GC behaviour changes. The effect is observed only when
the `JSRuntime` is torn down (release: silent leak; debug: assertion abort).
There is no object primitive to control — no freed object is ever reachable
from JS afterwards, and no attacker-controlled data is involved. Reaching it
needs three lines of plain JS with no host APIs, so the *reachability* is
trivial; the *impact* is a bounded leak.

### Suggested direction for upstream
`reset_weak_ref()` only walks `JSWeakRefRecord`s hung off a *symbol's*
`first_weak_ref`, and `mark_weak_map_value()` is only called from
`mark_children()` for `JS_GC_OBJ_TYPE_JS_OBJECT`. Symbol keys have no
`mark_children` equivalent and the record's strong reference to the value is
never dropped on the teardown path, so the value outlives the runtime's
final GC and trips the `gc_obj_list` assertion.

---

## 6. Leads investigated and rejected (negative results worth recording)

These were checked because they are recent code or recent-fix neighbours; none
produced a memory-safety defect.

1. **WeakMap / FinalizationRegistry / Symbol cross-graphs.** Full graph
   fuzzing plus hand-built cases (symbol as key and value, registry held value
   is the registry, token = target, held value = key of another map). Only F1.
   The #1835 two-pass pattern is correctly applied in `js_map_finalizer`,
   `js_finrec_finalizer` and `reset_weak_ref` in this commit.
2. **`reset_weak_ref` second-pass reentrancy.** Considered the case where
   freeing `mr->value` runs a finalizer that calls `delete_map_weak_ref` /
   `delete_finrec_weakref` on a node the outer loop still owns. Both reachable
   finalizers are protected: the outer first pass `list_del`s the registry
   entry / map record before the second pass runs, so the inner walker never
   sees them. No UAF reachable.
3. **Typed arrays over resizable ArrayBuffers.** `grow-from-zero` (count 0,
   pointer possibly NULL, then `resize(100)`), shrink/grow with byteOffset,
   DataView over RAB, `indexOf`/`copyWithin`/`fill` with `valueOf` hooks that
   resize mid-coercion, `sort` with a comparator that resizes/detaches. All
   correct; the functions already re-clamp `p->u.array.count` after user code
   and `typed_array_is_oob()` guards the rest.
4. **`#1792` double-free pattern search.** The bug is "free a `JSValue` in the
   loop, then `goto exception` frees it again". Audited every
   `js_poll_interrupts()` site (24) and the Array/String/Object loops that free
   temporaries. `js_array_every`/`filter`/`map` and `js_array_reduce` reset
   `val = JS_UNDEFINED` after freeing; `js_array_find` is the only offender.
   No sibling bug.
5. **Private symbols / private class fields (#1725).** `Object.getOwnPropertySymbols`,
   `Reflect.ownKeys`, `getOwnPropertyNames`, descriptors and spread all hide
   them (`syms=0 keys=0`). No embedder-state disclosure from JS.
6. **`using` / `DisposableStack` / `SuppressedError`.** 13 abrupt-completion
   combinations (dispose throws during throw, multiple resources, generators
   with `return()`, async dispose, `adopt` callback throwing, re-entrant
   `move`+`dispose`). No crash.
7. **`for-in` mutation.** Deleting/adding properties, swapping the prototype
   and inserting a `Proxy` with an `ownKeys` trap that mutates the target
   during enumeration. No crash.
8. **`Array.prototype.sort` slot/string lifetime.** `ValueSlot.str` holds a
   leaked `JSString*` reference on purpose; comparators that mutate the array
   or force GC do not invalidate it. No bug found.

---

## 7. Why the yield is low, and what would raise it

- quickjs-ng is continuously fuzzed upstream (OSS-Fuzz bytecode target plus
  test262), and this snapshot is 6 weeks old. Parser/interpreter crashes are
  largely already harvested; the recent bugs (#1792, #1835, #1827, #1865) sit
  in *semantic* corners that raw byte fuzzing reaches poorly.
- `fuzz_src` reached ~11.3 k coverage edges; `fuzz_api` ~7 k. The structured
  generator is the limiting factor: it emits at most 60 statements and its
  menu covers maybe a third of the builtin surface.
- Highest-value next steps, in order:
  1. a grammar-based JS generator (or `-use_value_profile=1` plus a
     differential oracle against V8/Node) for the interpreter;
  2. fork-mode (`-fork=8`) with `-ignore_crashes=1` for much longer runs;
  3. a dedicated generator for `Array`/`TypedArray` methods taking callbacks
     that mutate the receiver — that family has produced #1792 and is not
     exhausted;
  4. targeted differential testing of `Array.fromAsync`, iterator helpers and
     `using` against a spec-conformant engine (semantic bugs, not memory
     safety, but they are what this snapshot gets wrong).

---

## 8. Artifacts

```
/tmp/opencode/qjs_fuzz/
  REPORT.md                  this file
  build.sh                   build script (two sanitizer object sets, 8 binaries)
  harness/common.h           app-model runtime setup (6 MiB, 300 ms, leak dump)
  harness/fuzz_src.c         §3.1
  harness/fuzz_regexp.c      §3.2
  harness/fuzz_api.c         §3.3
  harness/fuzz_weak.c        §3.4
  corpus/{src,api,weak,regexp}/
  crashes/                   raw libFuzzer artifacts (2 F1 + 5 timeouts)
  pocs/f1_weakmap_symbol_leak.js
  logs/                      per-target supervisor logs
  run/{src,api,weak,regexp}/ per-worker libFuzzer logs
  src/                       quickjs-ng @ 7a23d8e (clone)
  master/                    quickjs-ng @ d7215b0 (worktree, cross-check)
```

Copied to:
- `telegramandroidwidget/notes/qjs_fuzz_report_20261101.md`
- `telegramandroidwidget/lab/qjs_fuzz/` (harnesses, build script, corpus, pocs, crashes)
