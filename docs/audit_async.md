# Async / generators / promises / job queue — quickjs-ng HEAD e22ce4d

Date: 2026-11-05. Host-only: no phone, emulator or bot.
Target: quickjs-ng `e22ce4de4362dc5fd4794cfa3c03fc7fdba5f015`
("Clear Array.find value ownership after release (#1826)", 2026-11-02),
i.e. v0.18.0 + #1809/#1826/#1827.

Lab: `lab/qjs_async_audit/`. Source clone used by the final builds:
`lab/qjs_src` (same commit; `/tmp/opencode/qjs_now` was deleted by a tmp
cleaner during the run and restored from GitHub).

## 0. TL;DR

**No new memory-safety bug (UAF, double free, frame confusion) was
demonstrated in the async/generator/promise/job-queue area.**

* The known open-PR correctness bug **#1874** (async-generator resolver
  reentry loses an await value) was reproduced and subjected to precise
  ASan, GC-per-job, `FORCE_GC_AT_MALLOC` and CPU-interrupt stress.  It stays
  a wrong-result bug: the early resume writes `undefined` into an
  already-cleared `cur_sp[-1]` slot.  No stale frame/request pointer is
  reachable and no arbitrary R/W primitive follows from it.
* One **new observation** is an OOM-path teardown leak in
  `Array.fromAsync`: under a test-only exact headroom, a debug build hits
  `JS_FreeRuntime: Assertion 'list_empty(&rt->gc_obj_list)'` and
  `JS_DUMP_LEAKS` shows a few captured builtin C functions.  It is a leak /
  debug assertion, **not** UAF or corruption; it was not found in the
  upstream tracker.  It survives a local implementation of PR #1866, so it is
  not simply that known bug; it may belong to the open async-OOM stack
  (#1867/#1870/#1872), so novelty is not claimed.
* The clang static-analyzer `list_del` null-deref warning on
  `js_async_generator_resolve_or_reject()` is a false positive (see §4).
* No primitive with a controllable pointer, length or frame index was found.
  The concrete impact of everything below is JS-level wrong behaviour or a
  small leak; not RCE and not an arbitrary R/W stepping stone.

The rest of this note is the negative evidence, the dedup search, and the
candidate table.

## 1. App / sandbox model used

| item | value | source |
|---|---|---|
| engine | quickjs-ng `e22ce4d` (latest on origin/master on 2026-11-05) | `lab/qjs_src` |
| heap | 6 MiB (`JS_SetMemoryLimit`) | `notes/widget_js_api_audit.md`, `twidget_interrupt_re.md` |
| CPU | 300 ms per script, 500 ms ceiling, uncatchable `InternalError` | same |
| host API | none; classic global scripts; `eval`/`Function` yes; modules/BJSON no | same |
| async surface | `Promise`, `queueMicrotask`, `async`/`await`, generators, async generators, `for await`, `Array.fromAsync`, async iterator helpers as implemented | source/tests |
| timers | `setTimeout`/`setInterval`/`requestAnimationFrame` exist in `sandbox-bundle.js` (host bridge `fe(...)`, `maxTimers = 64`) | macOS widget asset in `lab/macos_beta/.../sandbox-bundle.js`; Android `maxTimers` in `twidget_interrupt_re.md` |
| job pump | the widget bundle relies on Promise/microtask jobs; q1570 report notes the engine must pump `JS_ExecutePendingJob` | `notes/q1570_report.md:77` |

Every PoC here needs only **synchronous eval plus job drain**; none needs a
timer, module, BJSON, native call or `std`.  The timer note is included only
to close the "is async reachable at all?" question: microtasks are enough.

The Android 72799 sandbox bundle was not re-extracted in this time-box; the
shared macOS 13.x widget bundle was used for the timer/queueMicrotask
inventory, with the Android-specific interrupt/limit facts taken from the
existing RE notes.

## 2. Builds and harness

All ASan builds are **precise**: GCC defines `__SANITIZE_ADDRESS__` for
`-fsanitize=address`, so QuickJS's 4 KiB small-block arena is disabled
(`JS_ARENA_LARGE_BLOCKS_ONLY = 1`) and every allocation gets an ASan redzone.
The clang libFuzzer build adds `-D__SANITIZE_ADDRESS__` explicitly.  (This is
the point raised by `notes/audit_fuzz.md` §2: the earlier C1 async campaign
used an arena-on build and was blind to sub-512 B overflows.)

| build | flags | use |
|---|---|---|
| `harness/harness` | GCC ASan, assertions on, dumps on | precise ASan replay, leak dumps, matrices |
| `build-ubsan/harness` | ASan+UBSan, `-fno-sanitize-recover=all` | UBSan replay |
| `build-force/harness` | ASan + `-DFORCE_GC_AT_MALLOC` | GC before every allocation |
| `build-dbg/harness` | ASan + `quickjs_lab.c` hook | precise CPU-interrupt arming (`__arm(n)` sets `ctx->interrupt_counter = n`) |
| `build-1866/harness` | ASan, lab source + local PR #1866 patch | check whether the fromAsync leak is #1866 |

Harness details and rebuild commands: `lab/qjs_async_audit/README.md`.
Test-only helpers: `__gc`, `__drain`, `__mem`, `__limit`, `__arm`,
`HEADROOM`, `GC_EVERY_JOB`, `DUMP_LEAKS`.  The app path itself has no such
helpers; they only let the lab place a GC/OOM/interrupt at a precise state.

## 3. Candidates

| id | area | class | status | app reach | novel? |
|---|---|---|---|---|---|
| C1 | async-generator resolver reentry (#1874) | wrong value / frame-continuation confusion | reproduced on HEAD; ASan/GC/force/interrupt clean; no memory primitive | yes (pure JS, `Object.prototype.then` getter) | **no**, open PR #1874 |
| C2 | `Array.fromAsync` OOM teardown | leak / debug assertion | reproducible with exact-headroom hook; small builtin-function leak; no ASan UAF | only after OOM; OOM is uncatchable and the app engine dies; impact is a small leak until context teardown | not in tracker; may be covered by open async-OOM stack (#1867/#1870/#1872); not claimed |
| C3 | clang analyzer `list_del` in `js_async_generator_resolve_or_reject()` | false positive | analyzer path requires an already-removed queue head; code always dequeues the head first | n/a | n/a |
| C4 | uncatchable exception kept pending by an async-generator resolve failure | policy / interrupt-budget | consistent with #1777; no memory error | engine dies on interrupt/OOM; no post-die JS | **no**, #1777 |

No candidate has a controllable primitive.  Details follow.

## 4. What was actually tested, and what holds

### 4.1 C1 — #1874 resolver reentry (known)

Minimal PoC `pocs/known_1874_reentry_value.js`:

```js
let it, second, entered = false, logs = [];
const gate = Promise.withResolvers();
async function* g() { yield 1; yield await gate.promise; }
Object.defineProperty(Object.prototype, "then", {
  configurable: true,
  get() { if (!entered) { entered = true; second = it.next(); } return undefined; }
});
(async () => {
  it = g();
  const first = await it.next();
  logs.push(["first", first.value, first.done]);
  await 0; await 0;
  gate.resolve(2);
  const r = await second;
  logs.push(["second", r.value, r.done]);   // HEAD: undefined, fixed: 2
  print(JSON.stringify(logs));
})();
```

Output on `e22ce4d`: `[["first",1,false],["second",null,false]]`
(`r.value === undefined`, JSON renders it as `null`).  With PR #1874 the
second value is `2`.  The same result is obtained under `GC_EVERY_JOB=1`
and under `build-force/harness` (force GC before every allocation), and the
process never trips ASan.

Why this does not become memory unsafety at HEAD:

* `js_async_generator_resolve_or_reject()` (`quickjs.c:21794`) removes the
  request from the queue **before** it calls the request resolver, and frees
  the request afterwards.  A resolver-driven reentry therefore cannot see or
  free the request that is currently being delivered.
* `js_async_generator_resume_next()` (`quickjs.c:21880`) only resumes a
  frame in `EXECUTING` state; the await slot `cur_sp[-1]` was set to
  `JS_UNDEFINED` when the `FUNC_RET_AWAIT` was observed (same function,
  `FUNC_RET_AWAIT` case).  The #1874 early resume therefore resumes with
  `undefined`, not with a stale pointer or a stale JSValue.
* A frame is freed by `js_async_generator_complete()`
  (`quickjs.c:21833`) only after setting `state = COMPLETED`; every later
  await callback checks `state == EXECUTING`
  (`js_async_generator_resolve_function`, `quickjs.c:21982`) before touching
  `cur_sp`.  A stale callback cannot write into a freed frame.
* `AWAITING_RETURN` is entered only from the `COMPLETED` branch of
  `js_async_generator_resume_next()`, after the frame was already freed;
  `js_async_generator_free()` (`quickjs.c:21680`) explicitly skips
  `async_func_free()` for that state, avoiding a second free.
* Requests are owned by the queue and by `JSAsyncGeneratorRequest` C refs
  (`req->result`, `req->promise`, `req->resolving_funcs[2]`); the queue is
  marked by `js_async_generator_mark()`.  We did not find a path that
  leaves a dangling request at the queue head, including under nested
  `next/return/throw` from `then` getters (see the matrices below).

The 2400-program arm matrix and 2448-program reentry matrix specifically
cover direct/delegated `next/return/throw`, `for await` break/return,
`yield*`, try/finally with awaits, zero-argument handlers, and GC at the
getter.  No ASan/UBSan/assert hit.

### 4.2 C2 — `Array.fromAsync` exact-headroom OOM leak (new observation)

PoC `pocs/oom/fromasync_one.js`:

```js
function go() { Array.fromAsync([1]).then(() => {}, () => {}); }
```

Run with the test-only headroom hook:

```bash
HEADROOM=512 GC_EVERY_JOB=1 DUMP_LEAKS=1 \
  ./harness/harness pocs/oom/fromasync_one.js
```

Result (log `logs/leak_fromasync_512.txt`):

```
jobs=0
Object leaks:
       ADDRESS REFS SHRF          PROTO      CLASS PROPS
0x507000008a68    1   0* 0x507000000bf8   Function { length: 0, name: 3"Array" }
0x507000008ad8    1   0* 0x507000000bf8   Function { length: 1, name: 4"TypeError" }
0x507000008bb8    1   0* 0x507000000bf8   Function { length: 2, name: 2"call" }
harness: quickjs.c:2700: JS_FreeRuntime:
         Assertion `list_empty(&rt->gc_obj_list)' failed.
```

`HEADROOM` sets `JS_SetMemoryLimit(malloc_size + h)` after the script has
been parsed, calls `go()`, drains jobs under that cap, restores 6 MiB, then
tears the context/runtime down.  The assertion appears for
`h ∈ {256, 384, 512, 768, 1024, 1536, 2048, 3072}` bytes; the leaked object
set grows with h (one to four captured builtin functions:
`Array`, `TypeError`, `Object.defineProperty`, `call`).  The same happens
with a plain `Array.fromAsync([1])` and with three concurrent calls.

Controls that do **not** reproduce it under the same sweep:

* a plain `async function` that awaits;
* an async function that captures `Array`, `TypeError`,
  `Object.defineProperty` and returns them;
* `Promise.all/allSettled/any/race`, async generators, async iteration;
* user-written replicas of the `Array.fromAsync` body
  (`pocs/oom/fa_replica.js`, `fa_replica2.js`).

A local implementation of PR #1866 (`js_function_set_properties` returns
`-1` and callers free the function; includes the
`js_create_resolving_functions()` call site) still leaks at the same
headrooms (`build-1866/harness`), so C2 is not simply #1866.  It may be
covered by the other open async-OOM PRs; we did not prove that either.

Impact and blockers:

* It is a **leak + debug-only assertion**, not a dangling-pointer use.  No
  ASan report in normal, GC-per-job, or `FORCE_GC_AT_MALLOC` builds.
* OOM in the real sandbox is an uncatchable `InternalError` (#1810).  The
  widget engine kills the engine (`die()`), and the context is only freed at
  host teardown; a few hundred bytes leak until then.  No controllable
  pointer/length, no R/W primitive.
* We did not find a pure-JS way to leave exactly this headroom without
  aborting the script with the uncatchable OOM itself.  A real widget would
  need to fill its 6 MiB heap to within a few hundred bytes of the
  `Array.fromAsync` working set; the OOM would then kill the script.  That
  is the main reason it is not ranked as a serious finding.

### 4.3 C3 — clang analyzer `list_del` warning is a false positive

`clang --analyze -analyzer-checker=core,unix.Malloc` reports a null deref in
`list.h:78` reached from `js_async_generator_resolve_or_reject()`
(`logs/clang_analyze.txt:453`).  The analyzer path assumes the queue head can
still point at a request whose `link` was already `list_del`'d.  In the code,
`next = list_entry(s->queue.next, ...)` is taken immediately before
`list_del(&next->link)`, and the queue head is updated by `list_del`; the
only reentry points happen after that removal.  The warning could not be
turned into a test: all attempts to make a request survive in the queue
after `list_del` rely on calling `js_async_generator_resolve_or_reject()`
directly, which is not exposed to JS.

### 4.4 Job queue ownership

`JS_EnqueueJob()` (`quickjs.c:2490`) duplicates every argument into the
`JSJobEntry`; `JS_ExecutePendingJob()` (`quickjs.c:2527`) removes the entry,
runs it, then frees the duplicated arguments, and `JS_FreeRuntime()` frees
whatever jobs remain.  No JS-held path can make a job argument a borrowed
value, and the widget sandbox has a single context, so the `e->ctx` pointer
is never observed after its context is freed.

The deliberate failure mode here is OOM on enqueue: `js_promise_resolve` /
`fulfill_or_reject_promise` / `js_promise_resolve_thenable_job` ignore the
return value in the current tree, so a reaction/finally handler can be
dropped and a derived promise left pending.  That is the open async-OOM
stack (#1867/#1870/#1872), not a UAF: the dropped reaction data and its
JSValues are freed normally, and no dangling pointer is stored in a promise
or job.  We exercised these paths with exact headroom and with GC between
jobs; ASan stayed clean and the only observable was a pending promise (and
the C2 leak for `Array.fromAsync`).

`queueMicrotask()` (`quickjs.c:41127`) checks that the argument is a
function and enqueues one duplicated argument; the microtask runner calls it
with `globalThis` as `this`.  A throwing microtask is handled by the job
runner (`JS_ExecutePendingJob` returns -1) and the harness/host clears it;
no job-queue corruption was found.

### 4.5 C4 — uncatchable exceptions and the CPU interrupt

The widget CPU limit throws an uncatchable `InternalError` from
`js_poll_interrupts()`.  We armed it precisely (`__arm(n)` sets
`ctx->interrupt_counter = n`; the handler fires on the n-th poll) inside:

* `Object.prototype.then` getters that call `it.next/return/throw`;
* an awaited object's `then` getter;
* async-generator `return(value)` where `value.then` is a getter;
* a `for await` iterator's `done` getter;
* `Promise.all` element handlers and async-function await preparation.

2400 programs × N = 1…400 polls, run twice (normal and GC after every job),
all clean under ASan.  The harness verifies that the interrupt really fired
(`fired=1` at low N).

Some paths do leave the uncatchable exception pending while returning a
normal value from a promise-resolution helper (the async-generator request
is dequeued and its promise is not settled).  This matches open policy work
#1777 and is not a memory error.  The app's engine calls `die()` after the
interrupt and does not execute further JS, so it has no post-die primitive.

## 5. Campaigns and negative evidence

| campaign | inputs | build | result |
|---|---|---|---|
| test262 async corpus (await, async-function, for-await-of, generators, Promise, AsyncGeneratorPrototype) | 2376 combined programs | precise ASan + GC every job | 0 hits (`logs/t262_replay_gc.log`) |
| same | 2376 | ASan+UBSan | 0 hits (`logs/t262_replay_ubsan.log`) |
| enumerated async-generator reentry matrix | 2448 | precise ASan | 0 hits (`logs/matrix_default.log`) |
| same | 2448 | precise ASan + GC every job | 0 hits (`logs/matrix_gc.log`) |
| same, every third input | 816 | ASan + `FORCE_GC_AT_MALLOC` | 0 hits (`logs/matrix_force.log`) |
| same | 2448 | ASan+UBSan | 0 hits (`logs/matrix_ubsan.log`) |
| random reentry corpus | 700 | precise ASan / force GC | 0 hits |
| precise CPU-interrupt matrix | 2400 × 2 | precise ASan, ±GC per job | 0 hits (`logs/arm_int_precise*.log`) |
| libFuzzer `fuzz_async` (stock) | 2885 execs, 12 min | precise ASan+UBSan, 6 MiB, 300 ms | 0 crashes |
| libFuzzer `fuzz_async2` (stock + inherited `then` reentry, 36 ops) | 6377 execs (slow build) / 5666 (fast build) | precise ASan (+UBSan) | 0 ASan; both runs stopped by a host-load timeout in `JS_NewContext` |
| corpus replay of all fuzzer inputs with assertions on | all corpus inputs | precise ASan+UBSan, assert build | 0 assertions |

The two libFuzzer timeouts are **scheduling artifacts**, not bugs: their
artifacts replay in 22 ms and 81 ms with a standalone ASan build
(`logs/timeout-*`, `fuzz_async2*.log`).  The alarm stack is in
`hash_string8/__JS_FindAtom` during `JS_NewContext`, before any input is
evaluated; host load was 20–35 from other workers.

`fuzz_async2` is `lab/qjs_fuzz_new/harness/fuzz_async2.c`: a copy of the
existing structured async harness with `Object.prototype.then` reentry
(cases 29–35) and a `var IT,RE,HIT,IND` guard.  This closes the gap left by
the earlier C1 campaign, which used an arena-on ASan build and did not model
the inherited `then` getter.

## 6. GitHub / tracker dedup search (2026-11-05)

Fetched the 100 newest open issues/PRs from
`api.github.com/repos/quickjs-ng/quickjs/issues?state=open&sort=created`
(latest open: #1892, 2026-11-05) and checked the issue search for
`fromAsync leak` and `gc_obj_list assert`.  Async-related open items found:

| # | title | relation |
|---|---|---|
| #1865 | Captured variable count truncation → OOB r/w + generator UAF | excluded (other worker / prior report) |
| #1866 | function metadata init failures | tested as a control for C2; C2 survives the patch |
| #1867 | settled Promise subscription enqueue failure | async-OOM stack, may cover C2 mechanism |
| #1870 | reserve Promise reaction jobs before settlement | async-OOM stack |
| #1872 | propagate thenable adoption allocation failures | async-OOM stack |
| #1873 | async-generator delivery allocation failures | async-OOM stack, generator delivery |
| #1874 | preserve async-generator await results during resolver reentry | **C1**, explicitly excluded / used as control |
| #1877 | module use-after-free with pending top-level await | not reachable (no modules) |
| #1838 | drain async generator queue after completion | known hang, not memory |
| #1757 | await bypasses catch when PromiseResolve throws | known correctness, no memory |
| #1747 | for-await closes iterator at wrong times | known semantics |
| #1777 | uncatchable exceptions out of async generator results | known policy (C4) |
| #1763 | async function leak without Promise intrinsic | different context; not app |
| #1890 | Array iterator/Proxy/RegExp ToUint32 vs ToLength | not async |
| #1892 | JS_DupValue/JS_DupAtom refcount overflow | new, not async, requires ~2^31 increments; not app-time-reachable |

No async memory bug newer than the list above was found.  C2 is not in the
tracker and is the only candidate we would consider reporting, with the
caveat that it is a leak/assertion and may be subsumed by the open OOM
stack.

Prior local reports checked before starting:
`notes/qjs_latest_audit.md`, `notes/qjs_latest_bughunt.md`,
`notes/qjs_novel_audit.md`, `notes/qjs_postsnapshot_f1865_report.md`,
`notes/weakmap1835_report.md`, `notes/audit_fuzz.md`.  In particular
`audit_fuzz.md` C1 ran `fuzz_async` with the arena-on clang build; the
precise ASan campaigns here are new evidence, not a rerun.

## 7. Controllability / path to arbitrary R/W

No candidate provides one.

* C1 writes `JS_UNDEFINED` into `cur_sp[-1]`, a slot that is already inside
  the owned coroutine frame and whose offset is fixed by the bytecode.  The
  nested caller cannot choose the slot, the frame address, or the written
  JSValue.  The frame pointer and the queue links remain valid; ASan with
  forced GC and precise interrupts found no dangling access.
* C2 leaks a fixed handful of C function objects.  There is no read of the
  leaked value, no free of it, and no length/pointer transfer to JS.
* The analyzer path (C3) is not reachable from JS.
* For a UAF-to-R/W chain one would need a queued `JSAsyncGeneratorRequest *`
  or a suspended `JSStackFrame *` that is freed while a resolver still has
  it.  The ownership rules above (dequeue before resolver call; frame free
  gated by `COMPLETED`; `AWAITING_RETURN` skips a second free; `is_active`
  and refcounts for async functions; `cur_gc_obj`/`is_coro` rooting from
  7955cfd) close those routes in every path we could exercise.

## 8. Blockers and limitations

* Host-only; no device/emulator.  The Android 72799 sandbox bundle was not
  re-extracted in this window; the shared macOS 13.x bundle was used for
  the timer/`queueMicrotask` inventory and prior Android RE notes for limits.
* Exact-headroom OOM is a test-only placement.  A real 6 MiB widget can
  reach OOM, but the uncatchable OOM aborts the script and the engine dies,
  so C2's practical impact is limited to a small leak until context
  teardown.
* Interrupt tests continue draining jobs after the first uncatchable
  interrupt, which is more permissive than the app (the app kills the
  engine).  This can only find extra bugs, not hide app-reachable ones in
  the unwinding path; the reverse (app executes something the harness does
  not) does not apply.
* libFuzzer campaigns were starved by host load (2–23 exec/s).  The
  structured matrices and test262 replay carry most of the coverage;
  fuzzing is supporting evidence.
* No binary/device check was done for the app snapshot; the task target was
  source HEAD.  App snapshot 7a23d8e is older than HEAD.  #1874 is present
  there too (the async-generator code did not change in the 7a23d8e..HEAD
  window).  C2 was only tested on HEAD: the app snapshot has the older
  `Array.fromAsync` builtin (PR #1832 changed it after 7a23d8e), so C2 app
  reachability is not claimed.

## 9. Artifacts

All under `lab/qjs_async_audit/`:

* `README.md` — harness build/reproduce commands, full artifact index.
* `harness/harness.c`, `quickjs_lab.c` — app-model harness and interrupt hook.
* `pocs/known_1874_reentry_value.js` — C1 control.
* `pocs/t_reentry1.js`, `pocs/t_deep_reentry2.js`,
  `pocs/t_all_handlers0.js` — reentry/handler stress.
* `pocs/oom/` — C2 PoC, controls, user replicas.
* `fuzz/matrix/`, `fuzz/arm/`, `fuzz/t262/`, `fuzz/seeds*/` — generated corpora.
* `logs/` — the logs cited above, including `t262_replay_gc.log`,
  `t262_replay_ubsan.log`, `matrix_*.log`, `arm_int_precise*.log`,
  `fuzz_async*.log`, `leak_fromasync_512.txt`, `gcobjs_detail.txt`,
  `clang_analyze.txt`.
* `../qjs_fuzz_new/harness/fuzz_async2.c` and
  `../qjs_fuzz_new/logs/fuzz_async2*.log` — extended libFuzzer harness and
  campaign logs.

No files in the original `qjs_now` were modified; `/tmp/opencode/qjs_now`
was restored from GitHub after the tmp cleaner removed it, and final builds
use `lab/qjs_src` at the same commit.
