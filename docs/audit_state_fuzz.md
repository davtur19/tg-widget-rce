# quickjs-ng 7a23d8e — state-coverage fuzzing (StateLens/Fuzzilli-inspired)

Date: 2026-11-05
Target: quickjs-ng `7a23d8e3fedb010070ef1a03873c55500c7aa1a9`
(Telegram 13.2.0 beta 72799 widget engine; 0.17.0 + `JS_ReadBigInt` fix).
Scope: host-only research harness. No phone, emulator, bot, modules or BJSON
were used.

## 0. Verdict

* State-coverage campaign: **no new memory-safety bug** (UAF/OOB/type
  confusion) with a controllable primitive was demonstrated in this
  time-box. No GitHub issue was filed. The state signal did measurably
  improve exploration: in a controlled pair (same binary, corpus and
  mutation seed) it reached **+18.8 % structural edges** (7,630 vs 6,423)
  and +18.2 % new corpus units (786 vs 665).
* Known-bug calibration: quickjs-ng **#1835** (WeakMap/symbol finalizer UAF)
  reproduces on `7a23d8e` and is retained by the instrumented build; it is
  post-snapshot upstream (fixed in `25a005b`, 2026-10-30) and is reported only
  as dedup/validation.
* Instrumentation itself produced two ASan false positives during bring-up
  (probe after `free_gc_object`; stale `sh` in `JS_NewObjectFromShape`); both
  were removed. This is evidence the probe corpus must be validated against
  a known crash and against replay of clean inputs.

## 1. Method

### 1.1 Inspiration

* **StateLens** (arXiv 2609.24550, SOSP'26): state coverage as a second
  feedback signal; probes are side-effect-free expressions paired pre/post
  at a transition, hashed into a bitmap; dual feedback with edge coverage.
  The paper's QuickJS case study is a Worker/`onmessage` accessor UAF that
  needs host APIs; it is not reachable in the widget sandbox.
* **Fuzzilli QJS target**: only the host-shell REPRL/instrumentation pattern
  was borrowed; no Swift was built. The generator is a byte-driven
  FuzzIL-lite: each selector chooses an operation and its parameters, and
  every statement is wrapped in a try/catch and optionally in a re-entrancy
  context (direct, microtask, getter, generator, async finally, proxy trap).

### 1.2 App model

Same as `notes/audit_fuzz.md`:

| parameter | value |
|---|---|
| runtime | fresh `JSRuntime`/`JSContext` per input |
| heap | 6 MiB (`JS_SetMemoryLimit`) |
| stack | 512 KiB |
| CPU | 300 ms interrupt deadline |
| eval | `JS_EVAL_TYPE_GLOBAL`, raw script, no host functions |
| jobs | `JS_ExecutePendingJob` drained after eval (bounded) |

### 1.3 State probes

All probes are in `lab/qjs_state_fuzz/src/quickjs.c`, inserted by
`instrument.py` with `/*QJS_SP:name*/` markers. Each probe computes
`hash(kind, pre_state, post_state/receiver)` and sets one byte in a 64 KiB
counter array. In the libFuzzer build that array is registered with
`__sanitizer_cov_8bit_counters_init` + a synthetic PC table, so libFuzzer
retains an input when it reaches a novel state even if edge coverage is
unchanged. `qjs_state_seen` (cumulative) and per-kind hit counts are only for
reporting.

| kind | site | captured state |
|---|---|---|
| DEFINE | `JS_DefineProperty` entry/conversions | old property type (normal/getset/varref/autoinit) → requested/new type; class_id; shape prop-count bucket |
| SETPROP | `JS_SetPropertyInternal2`, `JS_SetPropertyValue` | class_id, existing property type, old/new value tag, fast-array count bucket; `retry2` lazy-prototype path |
| ADDPROP | `add_property`, `js_shape_prepare_update` | class_id, old/new shape prop-count bucket, is_hashed, shape refcount bucket; shape clone/unhash |
| DELPROP | `delete_property` | class_id, old/new prop-count bucket; found vs missing |
| FAST2SLOW | `convert_fast_array_to_array` | class_id, length bucket, new shape count |
| EXPAND | `expand_fast_array` | old/new backing-store size |
| ARRLEN | `set_array_length`, `add_fast_array_element` | old/new count and size, fast flag |
| ACCESSOR | getter/setter/autoinit call | holder class_id, property type, **receiver class_id** (StateLens lookup-holder vs receiver mismatch) |
| GET | `JS_GetPropertyInternal` special-property read | holder class_id, property type, flags, receiver class_id |
| NEWOBJ | `JS_NewObjectFromShape` | class_id, shape prop-count/size bucket, hashed, shape refcount bucket |
| PROTO | `JS_SetPrototypeInternal` | class_id, new proto class_id, shape hashed/count |
| GC | `js_trigger_gc`, `JS_RunGC`, `gc_free_cycles` | malloc size/threshold buckets, phase pass, freed GC object type |
| REF | `free_zero_refcount`, `js_free_value_rt`, `gc_scan_incref_child`, `free_object` | zero-ref free, cycle resurrection, finalizer class_id |
| JOB | `JS_EnqueueJob`, `JS_ExecutePendingJob`, async resume/call | job function identity, argc bucket, result, async active/rooted flags |
| GEN / AGEN | generator and async-generator state machines | state enum transitions and queue-driven return/throw paths |
| PROMISE | `fulfill_or_reject_promise` | pending → fulfilled/rejected |
| TYPED | `JS_DetachArrayBuffer`, typed-array view detach, buffer construction | byte/max length buckets, shared flag, view class/count before detach |
| PROXY | get/set/defineProperty/deleteProperty/gOPD/ownKeys traps | trap id, target class, revoked flag, trap-present flag |
| WEAK | `reset_weak_ref` | weak record kind being reset (WeakMap/WeakRef/FinalizationRegistry) |
| RUNTIME | `JS_NewRuntime` | runtime lifecycle |

Important instrumentation constraints learned:

* Never probe an object after `free_gc_object()`/`js_free()`; probe before
  the free (first version read `JS_GC_TYPE(p)` after the free and produced a
  false UAF).
* In `JS_NewObjectFromShape`, the incoming `sh` can be freed by
  `add_property()` during array length initialization; probe `p->shape`, not
  `sh`.
* `qjs_sp` must not allocate, lock, call JS, or call an observation function
  with side effects; it runs from GC, finalizers and property-transition
  paths.

### 1.4 Generator

`harness/fuzz_state.c`, 48 operations, byte-selected; 8–63 statements per
input, each in a re-entrancy wrapper. Operations cover:

* data ↔ accessor transitions, bulk descriptors, alternation via
  `redef()`, non-configurable/extensible errors, `__proto__`, `with`, eval;
* fast array growth/shrink/holes, fast→dictionary via element accessor,
  length descriptors, species constructors, sealed/frozen arrays;
* typed arrays/DataView over a shared buffer, transfer/detach during
  `ToNumber` coercion, resizable ArrayBuffer resize/transfer;
* mapped `arguments` and accessor conversion;
* proxy traps that mutate/delete/redefine the target, revocable proxies,
  re-entrant `defineProperty`/`set`/`ownKeys`/`gOPD`;
* WeakMap/WeakSet/WeakRef/FinalizationRegistry plus cycle collection and
  allocation pressure;
* generators and async generators with interleaved next/return/throw;
  promise combinators, thenables, nested microtasks, async finally;
* object/shape resets every so often so long sequences keep exploring new
  shapes instead of a frozen object.

## 2. Build

```bash
cd lab/qjs_state_fuzz
python3 instrument.py
./build.sh
```

Flags: clang 19.1.7, `-g -O1 -fno-omit-frame-pointer`, ASan+UBSan,
`-D__SANITIZE_ADDRESS__`, `-DQJS_STATE_PROBE`, libFuzzer. Standalone replay
binaries use assertions on; libFuzzer objects use `-DNDEBUG`.

### 2.1 Probe validation

Two ASan reports during bring-up were **instrumentation bugs**, not engine
bugs, and are recorded here so later users do not repeat them:

1. `free_zero_refcount`: the probe read `JS_GC_TYPE(p)` *after*
   `free_gc_object(rt, p)`, producing a heap-use-after-free of the freed
   `JSObject`. Fix: probe before the free.
2. `JS_NewObjectFromShape`: the probe read the incoming `sh` after
   `add_property()` had already freed it while initializing an array's
   `length`. Fix: probe `p->shape`, which is the live shape.

After the fixes, 300 inputs from the A corpus and all targeted seeds replay
cleanly on the instrumented build. The pristine replay binary
(`build/run_js_pristine`, linked against `7a23d8e` + ASan without probes)
reproduces the known `#1835` UAF, which validates both the ASan
configuration and the triage path.

## 3. Campaigns

### 3.1 Runs

Primary state campaign (C) started from `corpus/seed` + `corpus/targeted` +
the 2.7 k inputs retained by the earlier probe revision (A). C2 resumed from
C's corpus with `-seed=99`.

The controlled pair (`fair_control` / `fair_state`) used the **same binary**,
the **same initial corpus** (`corpus/fair_seed`, 2.9 k selector files), and
the **same libFuzzer seed** (`-seed=424242`); the only difference is
`QJS_STATE_NOFB=1`, which skips registration of the 64 KiB state bitmap so
only edge coverage guides mutations (the probes still run, so runtime cost is
comparable).

| run | probes / feedback | time | runs | edge cov | ft | corpus | state hashes | artifact |
|---|---|---|---|---|---|---|---|---|
| A | first revision: missing NEWOBJ/ADDPROP/DELPROP + no receiver class; edge+state | 20 min | 67,642 | 7,255 | 33,913 | 2,735 | n/a (no dtor) | none |
| B | A + `-use_value_profile=1`; edge+state+value profile | aborted (SIGPIPE) | 5,256 | 6,805 | 48,781 | 1,607 | n/a | none |
| C | corrected probes (NEWOBJ, shape add/delete, GET receiver class, retry2) + longer generator; edge+state | 13,482 runs before a scheduling timeout artifact | 13,482 | 7,636 | 33,970 | 2,354 | n/a (aborted) | scheduling timeout, replays 63 ms |
| C2 | C's corpus, `-seed=99`, `-timeout=60`; edge+state | 10 min | 18,151 | 7,682 | 35,060 | 2,662 | 1,241 | none |
| fair_control | corrected probes, **state bitmap not registered**; edge only | 10 min | 20,880 | 6,423 | 33,318 | 2,418 | 1,228 (probes run) | none |
| fair_state | corrected probes; edge+state | 10 min | 20,809 | 7,630 | 34,451 | 2,635 | 1,216 | none |
| D | final probes (+ shape refcount), shared-shape generator, `-seed=777`; edge+state | 10 min | 36,340 | 7,953 | 36,495 | 3,038 | 1,475 | none |

At 2,048 executions (before either fair run plateaus):

| run | edge cov | corpus | 
|---|---|---|
| fair_control (edge only) | 6,226 | 1,351 |
| fair_state (edge + state) | 7,180 | 1,398 |

Final, same budget and same mutation seed:

| run | runs | edge cov | corpus | new units |
|---|---|---|---|---|
| fair_control | 20,880 | 6,423 | 2,418 | 665 |
| fair_state | 20,809 | 7,630 | 2,635 | 786 |

The state signal reaches **+18.8 % structural edges** (+1,207 edges) and
+18.2 % new corpus units (786 vs 665; final corpus 2,635 vs 2,418, +9.0 %)
on the same mutation budget and initial corpus. The
effect is not a mere corpus-size artifact; the extra edges are in the same
`quickjs.c` binary. The state bitmap was sparse (1,216-1,241 distinct hashed
indices out of 65,536) but all 21 probe kinds were exercised during
`fair_state` (per-kind counters at exit). RSS is ~1.6 % higher with the state
array registered (581 vs 572 MB) and throughput is identical at 34 exec/s.

### 3.1b Long enriched campaign (120 min)

After the short campaigns, the generator was extended with ops 48-57 (class
fields/private fields/static blocks, RegExp compile/exec/lastIndex/replace,
iterator helpers, async iterator helpers/Array.fromAsync, Map/Set mutation,
resizable ArrayBuffer/typed-array shrink/detach, Proxy over arrays,
private-field coroutines, Promise.try/withResolvers) and a raw-source
harness (`fuzz_src_state`) was added.  The raw seed corpus was curated from
the existing labs: 400 async/generator programs, 400 typed-array/RAB
programs, RegExp cases, quickjs engine tests and iterator-helper tests, 858
clean scripts after replay, plus fuzzer-discovered units (1,165 files total,
1.7 MiB).  Known-bug PoC seeds (#1827, #1835, OOM/crash regressions) are
excluded.

Three processes ran for 120 minutes each:

| run | harness / corpus | seed | max_len | timeout | status |
|---|---|---|---|---|---|
| long_struct | `fuzz_state`, 4.4 k selector seeds | 20261105 | 4096 | 60 | RUNNING |
| long_raw | `fuzz_src_state`, 1.2 k raw-JS seeds + qjs.dict | 20261106 | 4096 | 60 | RUNNING |
| long_raw_vp | same raw corpus + `-use_value_profile=1` | 20261107 | 4096 | 60 | RUNNING |

### 3.2 What the state signal bought

All 21 probe kinds were exercised by the pooled corpus: DEFINE, SETPROP,
ADDPROP, DELPROP, FAST2SLOW, EXPAND, ARRLEN, ACCESSOR, NEWOBJ, PROTO, GC,
REF, JOB, GEN, AGEN, PROMISE, TYPED, PROXY, WEAK, RUNTIME and GET.  The
strongest early gains appear in the property/shape and slow-path code
(`JS_DefineProperty`, `add_property`, `delete_property`,
`convert_fast_array_to_array`, `JS_SetPropertyInternal2`), which is exactly
where the state probes carry pre/post type, class and shape information that
edge coverage cannot distinguish.

No ASan or UBSan report was produced by A, B, C, C2, D or either fair run.
The only ASan reproduction in this lab is the known post-snapshot **#1835**
finalizer UAF, which is kept as calibration/dedup.  D (final probe set plus
shared-shape objects, run alone so it got 60 exec/s) reached the highest
structural coverage of the session: 7,953 edges and 3,038 retained inputs.

### 3.3 Scheduling timeouts

The first C/C-control runs used `-timeout=10`. All three concurrent ASan
workers produced one timeout artifact each when the host was loaded; each
replays in **25–112 ms** under the standalone app model and none loops. They
are scheduling artifacts, not hangs (same class as `notes/audit_fuzz.md`'s
slow units). The resumed runs use `-timeout=60`; the JS interrupt handler
still enforces the 300 ms app deadline.

A/B results are retained for methodology (they show the cost of a probe gap
and of value-profile noise), but C/C2, D and the fair pair are the
state-complete evidence.

## 4. Triage and dedup

Known/suppressed:

* **#1835** WeakMap symbol finalizer UAF — reproduced on 7a23d8e with the
  pristine ASan build and with the instrumented state build; fixed upstream
  by `25a005b` after the app snapshot. `pocs/known_1835.js`;
  logs: `logs/known_1835_pristine.err` and `logs/known_1835_instr.err`.
  Not a new bug.
* **#1827** RegExp deletion bytecode lifetime UAF — found while curating the
  raw-JS seed corpus (`qjs_regexp_audit/cases/case01.js`: `lastIndex.valueOf`
  calls `regexp.compile` from the `constructor` getter during
  `String.prototype.replace`). Reproduces on pristine 7a23d8e at
  `lre_get_alloc_count` via `JS_RegExpDelete`; fixed upstream by `3d5cb14`
  after the app snapshot. `pocs/known_1827.js`;
  logs: `logs/known_1827_pristine.err` and `logs/known_1827_instr.err`.
  The seed is excluded from the fuzz corpus so the campaign does not abort
  immediately on a known bug. Not a new bug.
* **#1852**, **#1855**, **#1865**, **#1570**, **#1792**,
  **#1894**, **#1878** — known upstream; see `notes/audit_fuzz.md` and
  `notes/audit_async*.md`. The generator does not intentionally target them;
  an artifact matching them would be dedup only.
* U1 (`&NULL[0]` in `js_array_buffer_update_typed_arrays`) — known benign
  UBSan class; not claimed.

Any new artifact must be replayed on the **pristine** `7a23d8e` ASan build
without `QJS_STATE_PROBE`, with the generated JS extracted via
`QJS_DUMP_PROG=1`, and minimized before reporting.

## 5. Reproduction

```bash
# state campaign
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./build/fuzz_state -max_total_time=1200 -max_len=2048 -timeout=60 \
  -artifact_prefix=artifacts/ corpus/seed

# inspect a selector artifact
QJS_DUMP_PROG=1 QJS_STATE_REPORT=1 \
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./build/run_state artifacts/<file>

# raw JS under the app model
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./build/run_js poc.js

# known-bug calibration (instrumented and pristine replay)
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./build/run_js pocs/known_1835.js
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./build/run_js_pristine pocs/known_1835.js
```

## 6. Limits

* The widget sandbox exposes no host APIs, so StateLens's QuickJS Worker
  case study is out of scope; no `os.Worker`/module paths were fuzzed.
* Fresh runtime per input means cross-input heap history is not explored;
  within-input GC/refcount state is.
* State hashing is lossy (64 KiB); collisions are accepted.
* The state counter array is registered as sanitizer coverage, so libFuzzer
  reports edge and state features together; no separate state-only instance
  was run. A phased switch (StateLens switches after 100 edge-stall
  iterations) was not implemented.
