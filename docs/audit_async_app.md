# App-snapshot async audit — 7a23d8e + real WidgetJS bundle + F2

Date: 2026-11-05. Host-only: no phone, emulator or bot.
Target: Telegram Android 13.2.0 widget sandbox, quickjs-ng **7a23d8e**
(2026-10-23, v0.17.0-era), with the **real Android
`assets/WidgetSandbox/WidgetJS/sandbox-bundle.js`** from
`apks/13.2.0 (7279).apk` and `(7287).apk`.
Lab: `lab/qjs_async_app/`.

This continues `notes/audit_async.md` (HEAD e22ce4d, generic qjs harness).
The previous work did not run the app snapshot, the real bundle, or F2.
This run does all three.

## 0. TL;DR

**No new UAF / double free / frame confusion / pointer primitive was found.**
The app snapshot + real sandbox bundle + F2 produced one new policy finding
(F-A) and reproduced two known open-PR bugs in the actual bundle:

1. **F-A** (new, `notes/audit_async_iter.md` §4): `Iterator.prototype.flatMap`
   calls a completed inner iterator's `return()` and ignores the
   `JS_IteratorClose()` result.  Under F2 an uncatchable OOM raised there is
   swallowed; the script continues.  In the real bundle a top-level F-A
   script is reported by the native eval wrapper (`JS_HasException` check),
   but F-A inside a **timer/event callback** survives the native dispatch
   (which checks only `JS_IsException(result)`) and can abort a later
   callback's catch/finally.  Policy/DoS only; ASan clean, including
   teardown with the error pending.  §3.6.
2. **#1867** (`report settled Promise subscription enqueue failure`): an
   async-generator `yield` under an exact-headroom OOM leaves the generator
   in `EXECUTING` with a queued request and no continuation.  App/bundle
   reproduction works; subsequent `next/return` or GC does not corrupt
   memory — it is a stuck/poisoned promise, not a UAF.
3. **#1873** (`report async-generator delivery allocation failures`): a
   failed `js_create_iterator_result()` is passed to the request resolver
   as the internal **`JS_EXCEPTION` sentinel**.  It is delivered as a
   *fulfilled* promise value to user JS.  We captured it and measured it:
   tag `6`, pointer `0`, non-reflexive, reads/`String`/`JSON` throw a
   catchable `null`, sloppy-mode property writes silently no-op, strict
   operations throw.  No ASan/UBSan even with GC after every job.  This is
   a JS-level poison/type confusion; it gives **no pointer, length or
   arbitrary read/write control**.

`Array.fromAsync` under F2 on the app snapshot (the old
`.call`-lookup builtin, pre-#1832) did **not** reproduce the C2
`JS_FreeRuntime` teardown leak of the HEAD report; 810 F2 variants were
clean under ASan.  The pre-fix async-OOM stack (#1866/#1870/#1872) was
exercised; no memory error, only the #1867 hang and #1873 sentinel.

The only value with a controllable-looking shape is the `JS_EXCEPTION`
sentinel, and it is hard-wired to pointer zero.  The rest of the
candidates are hangs, leaks or JS-level wrong values.

## 1. App snapshot and real bundle

### 1.1 Source

`lab/qjs_async_app/src` is the 7a23d8e codeload tree (same one used for
the prior F2 verification).  It reports quickjs-ng 0.17.0 and contains the
pre-#1827/#1844/#1860/#1832 code.  The async/promise/generator C code is
essentially the same as HEAD in the e22ce4d tree: the app↔HEAD `quickjs.c`
diff is 235 lines and touches dynamic import, `Array.fromAsync` builtin
arguments (the `call` function), regexp bytecode/lastIndex, WeakMap
finalization and one Array.find ownership fix — no async-generator or
promise ownership fix.

### 1.2 Android assets

Extracted from both APKs:

| APK | sandbox-bundle.js | sandbox-bundle.qbc | manifest |
|---|---|---|---|
| 13.2.0 (7279) | 596053 B, sha256 `946e1d…e8db` | 684758 B, sha256 `090db7…039b` | `TWQB` assets |
| 13.2.0 (7287) | 596965 B, sha256 `282dcf…d470` | 686229 B, sha256 `ce1250…4270` | `TWQB` assets |

The bundle banner is `widget-sandbox version=0.6.0 protocol=1 profile=1
sdk=1`.  The qbc is a **`TWQB` container**: magic, version, source length,
32-byte digest, then what appears to be the QuickJS bytecode stream
(`BC_VERSION`/atom table layout); it is not a plain `.qbc` readable by the
stock qjs CLI.  Per the task, the **JS bundle** was used; its hash matches
the manifest.  Both 7279 and 7287 were extracted and spot-checked; 7287 is
the bundle matching the 7a23d8e engine and carries all campaign work.

### 1.3 Fidelity harness

`sandbox_harness.c` boots the real bundle and drives the native protocol:

```
boot(html,config) -> nextScript/JS_Eval/scriptDone until empty
                  -> endTick; if "1" tick again
                  -> host __host("timer",[id,delay]) / clearTimer
                  -> __twDispatch("timer", id); raf/frame
                  -> JS_ExecutePendingJob after each eval/dispatch
```

The host stub returns:
`now` (virtual ms), `random` (zero bytes), `query` (`{}`), empty strings
for diag/log/storage/stat/pd, and records timer/clearTimer/raf.  DOM,
canvas and animations are not rendered (no native backend), but the real
bundle parses the HTML, queues its `<script>` elements, runs `endTick`,
and manages its own timer map.  This is more than a generic
`JS_ExecutePendingJob` loop: the script queue, bundle timer table and
`endTick` are the app's own code.

Test helpers: `mem()`, `gc()`, `__diag`, `__tag(v)`, `__ptrv(v)`;
`CPU_MS=500` arms the app-like interrupt deadline after boot;
`GC_EVERY_JOB=1` runs `JS_RunGC` after each job.
The bundle overrides `print`, so tests use `__diag`/`globalThis.print=__diag`.

## 2. F2 in the real bundle

`f2_helper.js` fills the heap with `{}` until OOM; when the error object
cannot be allocated, `JS_ThrowError2()` substitutes `JS_NULL` and
`js_set_uncatchable_error()` ignores it, so the OOM is a **catchable
`null`** (F2, `notes/audit_regexp_postfix.md` §6).  On both real bundles:

```
7279: once=true cycles=20 nulls=20 objerr=0 ok=20 ms=1128
7287: once=true cycles=20 nulls=20 objerr=0 ok=20 ms=1139
      sweep m=64 first_ok=2 nulls=1 objerr=0
```

The sandbox itself already consumed ~3.0 MiB of the 6 MiB cap (bundle,
DOM, CSS, timers, globals); F2 leaves ~3.0 MiB of filler.  The helper
still works because the failing filler allocation is small.

F2 gives the lab a deterministic **continue-after-OOM** primitive: fill,
free K small objects, run the operation, catch `null`, free the filler,
and keep using the same JS values.  With `new ArrayBuffer(S)` fillers,
freeing K buffers exposes K*S bytes; sweeping S and K moves the failure
through different allocations.

## 3. App/bundle async campaign

### 3.1 What was run

| matrix | scope | runs | result |
|---|---|---|---|
| `fm_*` | 12 async templates × K=0..48 × fillers `{a,b,c,d}` and 64-byte AB | 1176 | 0 ASan/assert |
| `fam_*` | 5 `Array.fromAsync` variants × K=0..80 × both fillers | 810 | 0 ASan/assert |
| `agt_*` | ArrayBuffer filler sizes 64…512 × K=0…8 for async-generator yield | 77 | 0 ASan/assert; found #1867 window |
| `sd_*` | 23 direct operations on the captured sentinel value | 23 | 0 ASan/assert |
| `cmp_*` | completed-generator next/return under K sweep, sentinel capture | 60+ | 0 ASan/assert |
| `stuck_*` | post-#1867 next/return/drop/closure/GC modes | 6 | 0 ASan/assert |
| F2 helper | 7279 + 7287 real bundles | 2 | catchable-null confirmed |
| CPU_MS=500 | representative F2/sentinel/stuck pages | 6 | 0 ASan/assert |

All on the 7a23d8e ASan build with `-D__SANITIZE_ADDRESS__` (GCC defines
it; the 4 KiB arena is off), 6 MiB heap, real bundle, ASan/UBSan-capable
harness, assertions on.  The app snapshot/runtime is torn down after every
page; `gc_obj_list` assertions would fire on leaks.

Templates cover: async function await/return/finally; thenable adoption;
async-generator next/return/throw/yield*; completed-generator next/return;
Promise.all/any/settled subscription; for-await; Array.fromAsync array-like,
sync iterator, async iterator, mapFn `.call`, custom constructor.

### 3.2 #1867 — settled-subscription enqueue failure in app/bundle

The exact window: fill with `ArrayBuffer(96)` and free 4 buffers; run
`it.next()` on `async function* g(){ yield 1; }`.  The request/promise and
the await continuation are created, but the job for the already-settled
`Promise.resolve(1)` reaction cannot be enqueued.  Trace
(`logs/app_1867_stuck.txt`):

```
next entry state=0 magic=0
next before res state=0 queue_empty=0
resume_next enter state=0 empty=0
next after res state=3 queue_empty=0       <- EXECUTING, request still queued
AGT S=96 K=4 full=1 ERR=0 P=1 M=6290787 LOG=
PUMPS 2 fired 2 jobs 1 joberr 0 null 0 obj 0 uncatch 0 mem 3049836
```

No `ror` line: `js_async_generator_resolve_or_reject()` was never reached.
The request is pending, the generator frame is suspended in `EXECUTING`
with no continuation installed.  This is precisely the open #1867
("report settled Promise subscription enqueue failure") / the async-OOM
stack #1870.

Abuse after the stuck state (same page, `stuck_*` modes): a second
`next()`, `return(7)`, `throw(8)`, `gc()` with/without filler alive,
dropping `IT`, a closure over a generator local, and GC after every job.
Results are hangs/wrong values, never ASan or an assertion:

```
plain:        fin|p1:rej:null|p2:ok:undefined|p3:ok:7
gc_before:    same
drop:         same
closure_drop: fin|cl=7|p1:rej:null|p2:ok:undefined|p3:ok:7
```

So the stuck state can later be drained by another request or finalized;
the frame/queue ownership stays intact.  Impact: a request promise can be
left pending forever (DoS/hang), not memory corruption.

### 3.3 #1873 — `JS_EXCEPTION` sentinel as a fulfilled value

When the generator is already `COMPLETED`, `js_async_generator_resolve()`
creates the iterator result immediately (no await).  Under exact headroom,
`js_create_iterator_result()` fails, returns `JS_EXCEPTION`; app 7a23d8e
passes that sentinel to the request resolver without checking:

```
LAB_TRACE ag_result_oom
LAB_TRACE ror ret_exc=0 state=1
CMP K=5 F=obj full=1 ERR=0 P=1 TP=object LOG=ok strerr:null
```

`state=1` is `JS_PROMISE_FULFILLED`: the request promise **fulfills with
the internal sentinel**.  The `.then` handler receives it.  `__tag(v)` on
the handler argument, and `__ptrv(v)`:

```
SD 100 RES=ok:tag=6 ptr=0
```

`JS_TAG_EXCEPTION = 6`, pointer 0, no refcount.  Direct operation matrix
on the handler value `v` (not via a global, because global reads already
throw):

| operation | result |
|---|---|
| `typeof v` | `"unknown"` (no crash) |
| `v === v` | `false` (non-reflexive) |
| `v.foo`, `v[0]` | catchable `null` |
| `v.foo = 1`, `v[0] = 1`, `v.__proto__ = {}` | sloppy mode: silently succeeds/no-op (`RES=1`) |
| `String(v)`, `` `${v}` ``, `v + 1`, `v \| 0` | catchable `null` |
| `JSON.stringify(v)`, `Object.keys(v)`, `Object.assign({},v)` | catchable `null` |
| `Reflect.set(v,...)`, `Object.defineProperty(v,...)`, `v()`, `new v()`, `new WeakRef(v)` | `TypeError` object |
| `Array.prototype.push.call([],v); gc()` | sentinel stored; GC clean |
| `v instanceof Object` | `false` |

Further checks: the caught value from a sentinel read is **`JS_NULL`
(tag 2, pointer 0)**, not an object or uninitialized value; `String(v)`
throws the same catchable null.  No operation produced ASan/UBSan, even
with `GC_EVERY_JOB=1`.  The sentinel is inert: tag 6 with pointer 0, and
all property/string/number/call paths either throw or no-op.  It is a
**JS-level poison value**, not a pointer/length primitive.

This is exactly the bug fixed by open PR #1873 ("failed iterator-result
allocation is passed to that resolver as a guest value").  The app/bundle
reproduction and the tag/pointer/operation matrix are new evidence; the
bug itself is not new.

### 3.4 C2 — `Array.fromAsync` with F2 on the app snapshot

The app snapshot has the older builtin (pre-#1832): it looks up
`mapFn.call` and `method.call` and closes the iterator in `finally`.
F2 variants:

* array-like path `{length,0,1,2}` + mapFn;
* sync iterator via `Symbol.iterator`;
* async iterator with `next`/`return`;
* mapFn with a throwing `call` getter;
* custom constructor via `FA.call(C,...)`;
* K=0..80, filler `{a,b,c,d}` and 64-byte AB.

810 pages, 0 ASan/assert, no `gc_obj_list` teardown assertion.  The HEAD
C2 leak (`Array.fromAsync` exact-headroom → captured builtin C functions
leak under debug teardown, §4.2 of `notes/audit_async.md`) **did not
reproduce** on the app snapshot in the F2 flow.  Possible reasons:
different builtin (pre-#1832 `call` lookup), and F2 catches the OOM and
frees filler before the frame/teardown, unlike the fixed-headroom hook.
We do not claim C2 as app-reachable; the app/F2 result is negative.

### 3.5 #1866 metadata and the rest of the OOM stack

Under F2, creating normal/async/generator/async-generator/arrow functions
and object methods can throw a catchable null at function creation
(K=1..10); the functions created before the throw are usable (`name`,
`length`, call/next), no assertion or UAF.  This is the #1866 metadata
failure path; the app lacks the PR #1866 fix but the path is catchable and
does not free the function twice in our runs.

`Promise.all`, `Promise.any`, settled `.then`, thenable adoption
(`new Promise(r => r(thenable))`) and `for await` under F2 are covered by
the 12-template matrix; failures become rejections/null or pending
promises, not ASan reports.  #1870/#1872 are therefore exercised only as
known lost-observer/allocation-failure behavior.

### 3.6 F-A — `flatMap` uncatchable-OOM swallow (new, app-verified)

F-A from `notes/audit_async_iter.md` §4 was verified in the real 7287
bundle with the same pure-JS trigger (F2 fill, free K, `flatMap` whose
completed inner iterator's `return()` asks for 1 MiB).  The harness gained
`__hasexc()`, `__excinfo()`, `PENDING_TRACE=1` and `APP_EVAL_CHECK=1`; the
latter mimics the native `SandboxEngine_evalScript` check
(`if (JS_HasException(ctx)) throw JSError`) and clears the pending error as
the JSError constructor does.

| scenario | result |
|---|---|
| F-A in a top-level `<script>` | `survived=true`; `JS_HasException` true; `APP_EVAL_HASEXC <script 1>: InternalError: out of memory`; next script `hasexc=0` and fully functional (`logs/fa_top_script_appcheck.txt`) |
| F-A in timer A, sentinel used in timer B | timer A returns normally with the error pending; the native dispatch helper checks only `JS_IsException(result)` (IDA: `tw_dispatch_to_js` 0x7893EC → `sub_77D230` → `sub_17BF33C(tag)==6`), so the error survives; timer B's `try/catch` is skipped and it returns `JS_EXCEPTION`; `DISPATCH timer EXC: InternalError: out of memory`; timer C is clean (`logs/fa_cbtimer_fa.txt`; control without F-A catches tag 4 in `logs/fa_cbtimer_nofa.txt`) |
| F-A only in a timer, no later exception | pending `InternalError` survives the dispatch, `endTick` and reaches `JS_FreeContext`/`JS_FreeRuntime`; `GC_EVERY_JOB=1`; ASan clean (`logs/fa_timer_pending.txt`) |
| F-A in a promise job (generic/sandbox model) | pending survives into the next script; a queued microtask/promise that uses the sentinel is aborted and the job pump consumes the error (`joberr=1`); the real native job-pump check is not confirmed (`logs/fa3_micro.txt`, `logs/fa3_promise.txt`) |
| string/number/host bridge with the error pending | `__host("now")`, `String`/`Number`/`JSON`, `document.createElement` all normal; no corruption (`logs/fa3_timer.txt` script 3) |

App-faithful impact: a **policy/DoS** issue.  A top-level F-A script is
reported as a failed script (the native eval wrapper sees
`JS_HasException`); F-A inside a timer/event callback can survive the native
dispatch and abort a later callback's catch/finally, with the host
attributing the stale `InternalError` to that later callback.  No ASan
or assertion in any sequence, including GC after every job and teardown with
the error still pending.

The Promise channel adds a policy leak: in `fa/fa3_agen.html` the stale
error, raised inside an async generator's `for await` body, is converted by
`js_async_generator_reject` into a promise rejection (`AGEN REJ object`);
the generator `finally` is skipped and a user rejection handler can observe
the uncatchable error.  This is the known #1777/#1871 class, not a new bug
and not memory-unsafe.

**Secondary: `JS_UNINITIALIZED` (tag 4) in a catch.**  When the eval-boundary
check clears the sentinel's pending OOM and a later no-throw `JS_EXCEPTION`
is raised by `String(SENT)`, the catch block receives
`rt->current_exception == JS_UNINITIALIZED`: `tag=4 ptr=0 typeof=unknown`,
`e === e` false, `String(e)` `[uninitialized]`, `+1` `NaN`, `|0` `0`,
`JSON.stringify` `undefined`, property reads `undefined`, sloppy writes
no-op, `Object.keys/Object/call/new/WeakMap/spread/for-of/toString` throw
TypeError, `Map` lookup `undefined`, `JSON.stringify([e])` `null`, host
calls normal.  36-operation matrix, ASan clean (`logs/fa_tag4_ext.txt`).
This is an inert JS-level poison in the same family as the #1873 tag-6
sentinel, not a pointer/length primitive; it is not specific to F-A.

## 4. Controllability / possible arbitrary R/W

| candidate | value shape | control | memory impact |
|---|---|---|---|
| #1867 stuck generator | state `EXECUTING`, queued request, lost continuation | request/frame are valid owned objects; no user pointer | hang only; later next/return/finalize clean |
| #1873 sentinel | tag 6, ptr 0, non-reflexive | no pointer or length; property writes no-op/TypeError | poison JS value; no ASan/UBSan |
| #1866 metadata | partial function object / pending null | no freed pointer observed | none in tests |
| C2 (HEAD only) | captured builtin C functions at teardown | leak, no deref | leak/debug assert, not app-reproduced |

No primitive in this campaign gives a controllable frame pointer, request
pointer, property key or length.  The only pointer-bearing object involved
is the normal generator frame, and its state/ownership invariants held in
all F2/stuck/sentinel sequences.

## 5. Dedup and novelty

GitHub search (2026-11-05; open issues/PRs up to #1892, plus issue search
for async/promise/fromAsync/gc_obj_list):

* **#1867** — open PR, settled Promise subscription enqueue failure.  Our
  app/bundle F2 stuck generator is this bug; not claimed new.
* **#1873** — open PR, async-generator delivery allocation failures; the
  app/bundle sentinel delivery is this bug; not claimed new.
* **#1866** — open PR, function metadata; exercised, no memory issue.
* **#1870/#1872** — open PRs, reaction reserve and thenable adoption; the
  F2 paths are consistent with these known failures.
* **#1874** — open PR, async-generator resolver reentry; the HEAD report
  already covers it; app code has the same `EXECUTING`/resume loop.
* **#1570**, **#1763**, **#1838**, **#1757**, **#1747**, **#1777** — known;
  no new claim.
* No new app-specific async issue was found in the tracker.

The app/bundle reproduction of #1867 and #1873 is new evidence (previous
work was HEAD/generic harness), but the bug reports are prior art.  The
sentinel operation matrix is a new exploitability assessment and concludes
"no pointer/length/RW primitive".

## 6. Limitations

* Host-only; no device/bot.  The Android 7287 JS bundle is real; the qbc is
  extracted but not executed.  7279 spot checks match 7287 behavior.
* The host bridge is a stub: `query` returns `{}`, no canvas/animation
  backend, no native timer delay scheduling (timers fire in virtual time).
  This exercises the bundle's scheduler/script/timer code, not the native
  engine's exact batching or the Java DOM.
* `FORCE_GC_AT_MALLOC` on the full bundle is too slow/hangs under ASan
  (GC before every allocation); GC-after-every-job was used instead.
  Precise interrupt was tested on HEAD (`notes/audit_async.md`) and with
  `CPU_MS=500` on representative app pages here; a full app CPU-armed
  matrix was not run.
* Exact-headroom F2 placement is a lab technique; a real widget can fill
  its own heap to the same region, but F2's null is only catchable while
  the error object cannot be allocated, so the exact K/S window is
  allocator-dependent.
* F-A app verification: `APP_EVAL_CHECK=1` models the native
  `SandboxEngine_evalScript` `JS_HasException` check from the prior RE
  notes (`twidget_interrupt_re.md` §A.1); the dispatch path was verified
  in the 72879 IDB (`tw_dispatch_to_js` → `sub_77D230` checks only
  `tag == 6`).  The native **job pump** check was not verified; the
  microtask/Promise variant is therefore model-dependent, while the
  timer/event variant is backed by the IDB.
* The app snapshot 7a23d8e is the 72879 engine; 7279 may be a slightly
  different build, but the bundle behavior and F2 spot checks matched.

## 7. Artifacts

Under `lab/qjs_async_app/`:

* `README.md` — source/assets/build/harness index.
* `src/`, `src_trace/` — app snapshot and trace copy.
* `assets/7279/`, `assets/7287/` — extracted bundle JS/qbc/manifest.
* `sandbox_harness.c`, `sandbox_harness`, `sandbox_harness_trace`,
  `build-asan/`, `build-trace/`.
* `f2tests/` — all generated pages (`fm_*`, `fam_*`, `agt_*`, `cmp_*`,
  `sd_*`, `stuck_*`, `ags*`).
* `fa/` — F-A pages: `fa_two_scripts.html`, `fa3_*.html`, `fa_x_*.html`,
  `fa_sentinel_combined.html`, `cbtimer.html`, `fa_timer_pending.html`,
  `tag4.html` and their generators (`gen_fa_x*.py`, `gen_cbtimer.py`,
  `gen_tag4.py`).
* `logs/app_1867_stuck.txt`, `logs/app_1873_sentinel.txt`,
  `logs/app_1873_tagptr.txt`,
  `logs/f2matrix/app_obj4.log`, `logs/f2matrix/app_ab64.log`,
  `logs/f2matrix/app_fa.log`, `logs/fa_top_script_appcheck.txt`,
  `logs/fa_cbtimer_fa.txt`, `logs/fa_cbtimer_nofa.txt`,
  `logs/fa_timer_pending.txt`, `logs/fa_tag4.txt`,
  `logs/fa_tag4_ext.txt`, `logs/fa3_*.txt`, `logs/fa_x_*.txt`,
  `logs/fa_app_summary.txt`.
* Reference F2 helper: `../qjs_regexp_audit/f2_helper.js`.

No phone, emulator, bot or network service was used.
