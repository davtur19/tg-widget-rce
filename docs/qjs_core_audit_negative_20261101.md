# quickjs-ng core audit — negative result (no new distinct bug)

Date: 2026-11-01
Scope: `quickjs.c` interpreter / object / GC core of quickjs-ng v0.17.0
(app snapshot [2026-10-08, 2026-10-30), 6 MiB JS heap, 500 ms/script CPU,
attacker-controlled widget JS, no host APIs).

Owned / excluded up front: **#1792** (`js_array_find`), **#1835/#1844**
(WeakMap symbol value), **#1570** (async-generator cycle GC), **PR #1827**
(`JS_RegExpDelete` stale bytecode), and **#1865** (`var_ref_count`
truncation, now owned by the #1865 agent).

## Result

**No new distinct memory-safety bug was found in the audited scope beyond the
five listed above.**

All positive memory-safety results obtained in this session were variants of
**#1865** (the `uint16_t` captured-variable count/index truncation). I am not
claiming them as a new bug, and I stopped the #1865 endgame/exploit work once
that bug was assigned to its owner.

For the #1865 owner only, as a hand-off note (not a new finding): the same
truncated OOB slot can be used with a `Float64Array` backing store to obtain a
full 64-bit `JSVarRef *` heap pointer in a surviving script, and a
`String.fromCharCode`/`Array.prototype.with` layout can read a frame pointer
from the referenced `JSVarRef`. Those are #1865 impact, not a separate bug.
Artifacts are in `/tmp/opencode/qjs_core_audit/poc/` if useful; no RCE was
demonstrated here.

## Coverage

### Refcount / list / lifetime

- `JS_FreeValueRT`, `free_var_ref`, `close_var_ref(s)`, `js_release_coro`,
  coroutine `var_ref` (`is_coro`, `stack_frame`, `cur_gc_obj`) and generator /
  async-function / async-generator frames. **No distinct bug found**; the
  truncation path is #1865.
- `Map`/`Set` records, iterators (`cur_record` locking, delete/clear during
  `forEach`), `WeakMap`/`WeakSet` and `reset_weak_ref`, `WeakRef`,
  `FinalizationRegistry` register/unregister/finalizer. **No distinct bug**;
  #1835 excluded.
- `using` / `DisposableStack` / `AsyncDisposableStack`: dispose reentrancy
  (`dispose()`/`move()`/`use()` from a disposer), LIFO/exception-suppression,
  `using` in blocks, loops, `switch`, `catch`, generators, async functions;
  abrupt completion and double-close shapes. **No memory-safety failure**.
- Promises: resolving-function single-shot check, thenable assimilation job,
  reaction lists, `Promise.all/any/allSettled` closures, await continuation.
  **No distinct bug**.

### Objects / arrays / properties

- `Array.prototype` sort (comparator and `toString` reentrancy, cached
  `JSString *` in `ValueSlot`, write-back), splice, slice, concat, flat /
  flatMap, from, toSorted, toSpliced, toReversed, with, copyWithin, fill.
- Fast-array growth/shrink, `length` assignment, sparse transitions,
  `add_fast_array_element`, `expand_fast_array`, `JS_CopySubArray`.
- Property definition/`add_property`/shape reallocation, lazy `AUTOINIT`,
  `JS_PROP_VARREF`, prototype-chain walks, `object_data`.
- Proxy exotic methods and Reflect traps (`get`/`set`/`defineProperty`/
  `deleteProperty`/`ownKeys`/`getOwnPropertyDescriptor`/`construct`),
  revocable proxies, target/handler reentrancy and invariant checks.
  **No distinct memory-safety bug reproduced.**

### Strings / atoms / ropes

- `JS_ConcatString{1,2,3}`, rope creation/rebalance/linearize/iteration,
  in-place append refcount guard, `JS_TAG_STRING_ROPE` handling in property
  get, hashing, JSON, BigInt conversion and equality.
- Substring/slice/repeat/pad, UTF-8/UTF-16 conversion, atom table/refcounts
  (source-level). **No distinct bug found.** (Rope length arithmetic is
  bounded by `JS_STRING_LEN_MAX`; app heap limit prevents overflow-scale
  strings.)

### JSON / BigInt / Date / errors

- `JSON.stringify` toJSON/replacer/array-index conversions, cycle stack,
  `JSON.parse` with reviver and source records, duplicate keys.
- BigInt shifts/pow/division/asUintN/toString and parse paths; Date setters;
  `Error`/`AggregateError`/`SuppressedError`, `Error.captureStackTrace`,
  `prepareStackTrace`, CallSite array bounds (`csd[64]` capped by
  `stack_trace_limit`). **No distinct bug found.**

### Typed arrays / ArrayBuffer / DataView

- `%TypedArray%.prototype` set/slice/sort/with/toSorted/toReversed/subarray/
  indexOf/fill/copyWithin/join; species constructor and detach/resize
  TOCTOU; `ArrayBuffer.prototype.transfer`/`resize`/`slice`; DataView
  get/set. **No distinct bug reproduced**; the known TOCTOU classes are
  guarded or revalidated.

### Parser / bytecode

- Variable capture counts (the #1865 truncation), lexical scopes,
  destructuring, class fields/static blocks/private names, generators/async,
  direct eval/Function, labels, `using` codegen. **No distinct bug** beyond
  #1865.

### Explicitly out of reach under the task constraints

- OOM-only: #1852, #1855, #1782, `JS_NewContext` OOM UAF.
- Bytecode/BJSON-only (widget JS is source, never `JS_ReadObject`): #1853,
  #1771, #1809.
- Modules/raw context: #1833, #1762.
- Interrupt-only DoS / missing interrupt polls: #1856, #1753, #1791, etc.
- Native-stack-only: #1790 (needs ~30k nested iterators, OOM at 6 MiB).
- CPU/heap-limit semantics, GC-on-allocation heuristics: not memory-safety
  bugs in the app model.

## Verification setup

- quickjs-ng **v0.17.0** at `/tmp/opencode/qjsng` (tag `v0.17.0`, commit
  `6d46d07`), ASan/UBSan and release builds.
- App-model harness: one `JSRuntime`/`JSContext`, 6 MiB `JS_SetMemoryLimit`,
  per-script CPU deadline, no teardown
  (`/tmp/opencode/qjs_core_audit/harness/appmodel2.c`, built
  `/tmp/opencode/qjs_core_audit/build/appmodel_rel`).
- ASan-only and ASan+UBSan builds used for the #1865 crash; no distinct
  sanitizer finding outside #1865.
- Tests run: targeted `using`/generator/async matrix, array-method callback
  reentrancy, typed-array detach/resize races, Proxy invariants, JSON
  toJSON/reviver, rope stress, and source-level review of the paths listed
  above.

## Artifacts

- `/tmp/opencode/qjs_core_audit/REPORT.md` — this report.
- `/tmp/opencode/qjs_core_audit/harness/` — app-model harness and inspect
  tools.
- `/tmp/opencode/qjs_core_audit/poc/` — #1865 crash/leak variants (owned;
  hand-off only, not claimed as new).
- `/tmp/opencode/qjs_core_audit/logs/` — app-model, ASan, gdb and allocator
  layout logs.

## Limitations

This was a time-boxed source audit with targeted dynamic checks, not an
exhaustive proof. The absence of a new bug here does not prove absence; it
means no deterministic, plain-JS, non-OOM, non-interrupt memory-safety bug
was found outside the five owned issues in the paths above.
