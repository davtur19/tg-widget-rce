# quickjs-ng HEAD e22ce4d — targeted widget-sandbox fuzzing

Date: 2026-11-05
Scope: find *new* memory-safety bugs in quickjs-ng HEAD `e22ce4d`
("Clear Array.find value ownership after release (#1826)", 2026-11-02) that are
reachable from ordinary Telegram widget JavaScript: source-only engine, 6 MiB
heap, 300 ms CPU per script (500 ms ceiling), no host APIs, no modules/BJSON.
Host-only work: no phone, emulator or bot was used.

Verdict up front: **no new memory-safety bug was demonstrated in this
campaign window.** Two known/benign issues were reproduced and are reported
for dedup only:

1. **K-1855** (known, upstream PR #1855, open): allocation failure inside
   `JS_NewObjectFromShape()` → `add_property()` returns NULL and is
   dereferenced. Reproduced with the new allocation-failure injector at
   `Array.from({length:143}, ...)` inside a Proxy getter. DoS NULL deref,
   not claimed as new.
2. **U1** (UBSan-only, known UB class #1432/#1437): `ArrayBuffer.prototype
   .transfer()` on a buffer with a zero-length view computes `&NULL[0]` in
   `js_array_buffer_update_typed_arrays()`. Harmless: no ASan report, and a
   release build emits nothing; no memory-safety impact.

The most important methodological result is that the standard clang
ASan build of quickjs-ng **does not see small-object overflows**: clang does
not define `__SANITIZE_ADDRESS__`, so `JS_ARENA_LARGE_BLOCKS_ONLY` stays 0 and
objects up to 512 B live inside 4 KiB arenas. An ASan fuzz build must add
`-D__SANITIZE_ADDRESS__` (or `FORCE_GC_AT_MALLOC`) or intra-arena overflows are
invisible. All "precise" campaigns below use that flag.

---

## 1. Target, app model and source tree

| item | value |
|---|---|
| engine | quickjs-ng `e22ce4d` (`v0.18.0` + #1809/#1826/#1827) |
| pristine source | `/tmp/opencode/qjs_now` (read-only input) |
| diagnostic source | `/tmp/opencode/qjs_fuzz_new/src-n1fix` (known-bug suppressions, see §5) |
| app snapshot | `7a23d8e` (Telegram 13.2.0 Beta engine; checked for U1 only) |
| runtime model | fresh `JSRuntime` + `JSContext` per input, `JS_SetMemoryLimit(6 MiB)`, `JS_SetMaxStackSize(512 KiB)`, 300 ms interrupt deadline, `JS_EVAL_TYPE_GLOBAL`, no host functions |
| re-entrancy | callbacks, getters, `valueOf`/`toString`, thenables, Proxy traps, species constructors, iterator `next/return/throw`, async finally |
| job queue | `JS_ExecutePendingJob` drained after each eval (bounded 5 000) |
| CPU budget | one to four campaign processes at a time, all `nice -n 19`; the host was heavily shared with other workers (load 20–35 during the runs) |

The app model follows `notes/widget_js_api_audit.md`: inline `<script>` bodies
are evaluated in global mode, `eval`/`Function` are available, the runtime is
capped at 6 MiB on the UI thread with a 300 ms budget and a 500 ms ceiling.

## 2. Builds and harnesses

All builds: clang 19.1.7, `-g -O1 -fno-omit-frame-pointer`, ASan + UBSan,
`-fno-sanitize=function`, asserts off in libFuzzer objects (`-DNDEBUG`),
asserts on in standalone replay objects.

| build | flags | purpose |
|---|---|---|
| `build/` (initial) | `-fsanitize=fuzzer-no-link,address,undefined` | arena layer **enabled** (clang does not define `__SANITIZE_ADDRESS__`) |
| `build/` (precise) | same **+ `-D__SANITIZE_ADDRESS__`** | every allocation through malloc, ASan sees each object |
| `build-n1fix/` | precise + N1/#1782/#1855 suppressions on `src-n1fix` | parser/runtime OOM fuzzing past known bugs |
| `build/` standalone | `-fsanitize=address,undefined -D__SANITIZE_ADDRESS__` | `run_*` replay with 6 MiB model |

Harnesses (source in `lab/qjs_fuzz_new/harness/`):

| harness | input | coverage focus |
|---|---|---|
| `fuzz_src2` | raw bytes as JS source | parser/compiler/runtime, OOM via `QJS_FUZZ_OOM` |
| `fuzz_async` | bytes select ops | async/await, promises, generators, async iterators, Iterator helpers |
| `fuzz_typed` | bytes select ops | TypedArray/ArrayBuffer/RAB/DataView/SAB, transfer/detach, species, base64/hex |
| `fuzz_strjson` | bytes select ops | strings/ropes, JSON parse/stringify (reviver/replacer/toJSON), templates, unicode |
| `fuzz_regexp2` | bytes build pattern/flags/subject | RegExp compile/exec/replace/split/matchAll, `compile()` during conversions, `d`/`u`/`v` |
| `fuzz_fillramp` | bytes select op + heap ramp | app-reachable runtime OOM: `ArrayBuffer` filler walks the 6 MiB boundary inside one input, op repeated 8–25 times |
| `fuzz_inject` | bytes select op | **precise allocation failure**: custom `JSMallocFunctions` fails the N-th allocation; program is compiled first (`JS_EVAL_FLAG_COMPILE_ONLY`) and injection is enabled only for `JS_EvalFunction` + job drain |

`fuzz_inject` runs each input twice: phase A counts the allocations inside
execution, phase B fails one of them (`fail_at = 8 + u16 % (total-8)`). Any
injected failure is reachable under the 6 MiB cap by filling the heap so that
allocation N is the first that does not fit; when execution is compiled before
injection, the failure is in builtins/bytecode, not in the parser.

Measured effect of the arena flag on the same 12-byte input (`fuzz_inject`
phase A, WeakMap + promise job): **3 counted allocations with the default
clang ASan build vs 1 666 with `-D__SANITIZE_ADDRESS__`**. In the default build
almost every JS object lives inside a 4 KiB arena block, so an overflow that
stays inside the block is invisible to ASan; with the flag each object gets its
own redzones.

## 3. Campaigns

All campaigns: libFuzzer, `-rss_limit_mb=900..1200`, `-timeout=20/30`,
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`, `UBSAN_OPTIONS=halt_on_error=0`,
`nice -n 19`, one process per campaign unless stated.

| # | target | build / env | wall | execs | coverage | result |
|---|---|---|---|---|---|---|
| C1 | `fuzz_async` 6 MiB | initial (arenas on) | 12 min | 35 293 | 4 534 | 0 crashes; 1 timeout artifact (replays in 49 ms, scheduling) |
| C2 | `fuzz_typed` 6 MiB | initial (arenas on, detach was a no-op) | 12 min | 19 404 | 5 953 | 0 memory crashes; **U1** UBSan abort at 1 281 execs |
| C3 | `fuzz_strjson` 6 MiB | initial | 12 min | 59 739 | 6 723 | 0 crashes (1 slow-unit, 11 s, scheduling) |
| C4 | `fuzz_fillramp` 6 MiB | initial | 15 min | 9 118 inputs × ~25 states | 6 949 | 0 crashes; only slow-unit/noise |
| C5 | `fuzz_src2` OOM (`QJS_FUZZ_OOM`, 48 KiB–5 MiB per input) | n1fix, precise | 10 min | 119 462 | 12 340 | 0 crashes |
| C6 | `fuzz_regexp2` 6 MiB | initial | 12 min (attempt) | — | — | failed to start (missing artifact dir); re-run precise 64 execs, starved |
| C7 | `fuzz_typed` 6 MiB | **precise** (arena off, real `transfer()` detach) | 6 min | 5 989 | 5 888 | 0 memory crashes; U1 UBSan only |
| C8 | `fuzz_strjson` 6 MiB | **precise** (unicode/rope ops) | 6 min | 3 635 | 6 887 | 0 crashes; 1 slow-unit (replays 167 ms) |
| C9 | `fuzz_inject` precise OOM | n1fix, precise | 4.5 min | 5 986 | 7 046 | **#1855** at exec 321 before suppression; 0 crashes after |
| C10 | `fuzz_regexp2` 6 MiB | precise | <1 min | 64 | 4 892 | starved by host load, stopped to free CPU |

Host load from other workers reached 20–35 during C7–C10; the nice-19
processes received 1–10 % CPU, so the precise campaigns are small. C1–C5 ran
before the arena fix and are therefore only useful as a negative baseline for
large (>512 B) allocations.

## 4. Findings

### 4.1 K-1855 — OOM NULL dereference in `JS_NewObjectFromShape` (KNOWN, dedup)

Found by C9 at 321 execs, before the #1855 fix was applied to the diagnostic
tree. Input: 12 bytes, generated program:

```js
try{new Proxy({},{get:function(t,p){
  a13=Promise.all(Array.from({length:143},function(_,i){return thenable(i,1)}));
  a13.then(function(){},function(){});
  return 1}}).x}catch(e){}
```

Injection: `fail_at=67` (the 67th allocation after `JS_EvalFunction` starts),
which fails the `add_property()` realloc while `Array.from` builds its result
array. Stack:

```
runtime error: member access within null pointer of type 'JSProperty'
 #0 JS_NewObjectFromShape      quickjs.c:6198
 #1 JS_NewObjectProtoClass     quickjs.c:6273
 #2 js_create_from_ctor        quickjs.c:21075
 #3 js_array_constructor       quickjs.c:43163
 #4 js_call_c_function         quickjs.c:17921
 #5 JS_CallConstructorInternal quickjs.c:21105
 #6 JS_CallConstructor         quickjs.c:21142
 #7 js_array_from              quickjs.c:43255
 ... Proxy get trap ...
```

This is exactly upstream **PR #1855** ("Fix NULL dereference when adding the
length property of an array fails", open): `add_property()` is documented as
"cannot fail" in the array branch of `JS_NewObjectFromShape()`. It can, and the
NULL is written through. Dedup verdict: known, not claimed. The crash log is
saved as `logs/known_1855_inject.log`; the exact input is
`pocs/known_1855_inject_input.bin`. Re-verified on pristine `e22ce4d` with
`build/run_inject_head` (same frame, `quickjs.c:6198`).

Reachability: plain widget JS (`Array.from`/`map`/species inside a callback);
under the 6 MiB cap, a filler string plus an allocation-failure point yields
the same NULL deref. DoS only (NULL store at a fixed offset; no controllable
value).

### 4.2 U1 — UBSan null-pointer arithmetic on ArrayBuffer transfer (benign)

First seen in C2, `fuzz_typed`, reproducible at will:

```js
var b = new ArrayBuffer(0);
var v = new Uint8Array(b);
b.transfer();          /* detaches b; v is a zero-length view */
```

`js_array_buffer_transfer()` sets `abuf->data = NULL` and calls
`js_array_buffer_update_typed_arrays()`; for a zero-length view with offset 0
the function executes `p->u.array.u.ptr = &data[ta->offset]`, i.e. `&NULL[0]`.

```
quickjs.c:59635:37: runtime error: applying zero offset to null pointer
 #0 js_array_buffer_update_typed_arrays quickjs.c:59635
 #1 js_array_buffer_transfer            quickjs.c:59715
```

Classification: UB only, not memory corruption. The view keeps `count = 0` and
the buffer is detached, so every later typed-array entry point returns
`TypeError: array buffer is detached` before dereferencing the pointer. A
release build emits no diagnostic. Upstream already has the same class of
report and hardening in #1432 / #1427 / #1437; this is a **new site of a known
benign class**, not a new memory-safety bug. Present in both `e22ce4d` and the
app snapshot `7a23d8e` (same code path).

### 4.3 C7–C10 results

All precise-build campaigns ran on a host shared with other workers (load
20–35); the nice-19 fuzzers received 1–10 % CPU, so these numbers are a
sensitivity run, not a coverage-equivalent campaign.

| campaign | execs | outcome |
|---|---|---|
| C7 `fuzz_typed` precise (arena off, real `transfer()` detach) | 5 989 | U1 UBSan again; no memory-safety crash |
| C8 `fuzz_strjson` precise (unicode + rope ops) | 3 635 | no crash; one 11 s slow-unit that replays in 167 ms (load artifact) |
| C9 `fuzz_inject` precise | 5 986 | no crash after #1855 suppression; the pre-suppression run found #1855 at exec 321 |
| C10 `fuzz_regexp2` precise | 64 | stopped to free CPU for C7–C9 |

No memory-safety crash, no UAF, no double free, no OOB, no type confusion was
produced by these campaigns under either allocator configuration.

## 5. Dedup

Upstream state used: issue/PR list `state=all` (100 most recent) fetched
2026-11-05, plus GitHub issue search and the explicitly requested list.

Explicitly compared against:

| id | subject | relation to this work |
|---|---|---|
| N1 | unchecked `push_scope` OOM | suppressed in `src-n1fix`; not re-reported |
| #1865 | captured variable count truncation, OOB + generator UAF | different subsystem; not seen |
| #1827 | RegExp deletion bytecode lifetime | fixed in HEAD; post-fix regexp harness found nothing |
| #1792 | Array.find double free on interrupt | fixed in HEAD (`#1826`); not seen |
| #1878 | TypedArray.prototype.with on shrink/detach | different bug (result/error, not memory safety); not seen |
| #1890 | ToUint32 vs ToLength in iterators/ownKeys/@@replace | semantics, not memory safety |
| #1882 | non-extensible array length update on failed define | semantics; not seen |
| #1892 | refcount int overflow | requires ~2^31 references; not reachable under 6 MiB |
| #1852 | lazy prototype property OOM | not triggered in the injector window (would be patched like #1855 if it were) |
| #1855 | NULL deref adding array length under OOM | **reproduced** (K-1855), dedup |
| #1782 | truncated parser bytecode OOB read under OOM | suppressed in `src-n1fix` |
| #1432 / #1427 / #1437 | UBSan zero-offset / NULL ArrayBuffer data | U1 belongs to this known benign class |

GitHub searches performed (all on `repo:quickjs-ng/quickjs`):

* `"applying zero offset to null pointer"` → 5 hits (#1432, #1427, #1411, #641, #617)
* `js_array_buffer_update_typed_arrays` → 0 hits
* `"null pointer" ArrayBuffer` → 4 hits (#1437, #1321, #85, #323)
* issue-number checks for #1782 #1792 #1827 #1852 #1855 #1865 #1878 #1882 #1890 #1892
* full recent issue/PR listing (up to #1892) for `OOM`, `use-after-free`,
  `double free`, `heap-buffer-overflow`, `NULL dereference`

No crash from the campaigns matched an *open new* signature: the only ASan/UBSan
crash produced is #1855 (known) or the U1 benign UB.

## 6. Primitive and reachability assessment

* **#1855 (known)**: NULL write to a fixed address during object creation;
  deterministic DoS if the heap is groomed so that `add_property()`'s realloc
  fails. Value written is `js_int32(0)` at offset 0 of a NULL `JSProperty *`;
  no controlled pointer, no info leak. App-reachable with `Array.from`/`map`
  plus a filler string; ranking DoS only.
* **U1**: no primitive. The null+0 pointer is stored into a zero-length view
  whose buffer is detached; all accessors check `detached`/`oob` first.
* **Campaigns**: no OOB/UAF/double-free/type-confusion primitive was found,
  so there is no new RCE/ACE candidate from this work.

## 7. Next steps

1. **Always build ASan fuzzers with `-D__SANITIZE_ADDRESS__`.** Without it,
   small-object intra-arena overflows are invisible. Re-run C1–C4 with the
   precise build on an idle host; the current precise runs were starved.
2. **Continue allocation-failure injection past the known OOM bugs.** #1855 is
   suppressed in `src-n1fix`; the next candidates to suppress if hit are #1852
   and #1855's review variants. The injector found #1855 in 321 execs, so a
   10–30 min run with a real CPU budget should reach further allocation points.
3. **Extend injection to `realloc`/`calloc` failure separately.** The current
   injector fails every allocation kind at the same index; splitting them
   covers failure paths that only exercise `js_realloc` (e.g. string buffers).
4. **Parser OOM beyond N1.** The diagnostic tree only patches the three
   `push_scope` sites used by N1 plus #1782. The other ~11 unchecked
   `push_scope(s)` call sites (class/block/for/if/with/body scopes) are the next
   parser-OOM surface; patch them all, then re-run `fuzz_src2` with
   `QJS_FUZZ_OOM` to see whether anything distinct remains.
5. **RegExp post-#1827.** The user-level harness was starved; the direct
   `libregexp` fuzzer run by the regexp worker covers the executor. Re-run
   `fuzz_regexp2` precise on an idle host, especially patterns with lookbehind
   captures, backrefs, `v`-mode `\q{}` classes and duplicate named groups.
6. **Replay any candidate on the app snapshot** with `src-app` (`7a23d8e`) and
   then on-device only through the orchestrator; U1 already reproduces on
   `7a23d8e` by code inspection.

## 8. Artifacts

```
lab/qjs_fuzz_new/
  README.md                     reproduction instructions and artifact map
  build.sh                      libFuzzer/ASan/UBSan build (adds __SANITIZE_ADDRESS__)
  harness/                      common.h, gen_common.h, all fuzz_*.c
  scripts/                      dump_prog.sh, triage.sh
  qjs.dict                      libFuzzer JS dictionary
  pocs/known_oom_suppressions.diff   N1 + #1782 + #1855 diagnostic patches
  pocs/known_1855_inject_input.bin   #1855 reproducer (selector bytes)
  pocs/ubsan_null_offset_transfer.js U1 reproducer
  logs/known_1855_inject.log         ASan/UBSan stack for #1855
  logs/                              campaign logs (final stats + crash logs)
  artifacts/                         libFuzzer timeout/slow-unit inputs
```

This report lives at `notes/audit_fuzz.md`.  Working trees and large build
outputs stay in `/tmp/opencode/qjs_fuzz_new/` (`corpus/` 44 MB, well under the
500 MB budget).
