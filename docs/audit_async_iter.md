# Async iterators / for-await / async generators / then-reentrancy — quickjs-ng audit

Target: `quickjs-ng` **e22ce4d** (`Clear Array.find value ownership after release
(#1826)`, 2026-11-02) and the app snapshot **7a23d8e** (2026-10-23).  Both
trees have **identical** iterator/async code: the full `quickjs.c` diff between
the two is 235 lines and has no hunk in the iterator helpers
(45.1k–46.5k), async generator (21.2k–22.1k), async-from-sync (56.7k–57.0k),
promise or job-queue regions.  Every finding below therefore applies to both.

Date: 2026-11-05.  Host-only lab; no device, no bot, no network target.
Lab: `lab/qjs_async_iter/` (source clones, ASan/gcstress/release harnesses,
5 000+ generated programs, PoCs, logs).

---

## 1. Verdict

**No new memory-safety bug** (UAF, double free, frame confusion, type
confusion, controllable pointer/length/frame index) was found in the async
iterator / for-await / async generator / thenable surface.  The negative
evidence is in §7; the ownership review is in §3.

**One new non-memory finding (F-A) was found and reproduced on both targets:**

`Iterator.prototype.flatMap` calls the *inner* iterator's `return()` even when
the inner iterator has already reported `{done:true}`.  That call is forbidden
by the spec (`Iterator.prototype.flatMap`: “If innerValue is done, then set
innerAlive to false”, with no `IteratorClose(innerIterator)`), and its result
is **ignored**:

```c
/* quickjs.c:46359-46365 (e22ce4d) */
if (*pdone) {
    *pdone = false; // The outer iterator must continue.
    JS_IteratorClose(ctx, it->inner, false);   /* <-- result ignored */
    JS_FreeValue(ctx, it->inner);
    it->inner = JS_UNDEFINED;
    goto flat_map_again;
}
```

If that `return()` throws an **uncatchable** OOM (or an uncatchable
interrupt/InternalError), `JS_IteratorClose()` returns `-1` with the
uncatchable error pending; `flatMap` keeps running the outer iterator and
`helper.next()` returns normally.  The script therefore survives an exception
that #1810 made uncatchable, continues after releasing the heap filler, and
leaves `InternalError: out of memory` pending in the runtime.

This is a **different route** from the previous report's F2 (bare-null OOM
when the error object cannot be allocated): F-A fires with a *proper*
uncatchable `InternalError` object, needs only a few hundred bytes of
headroom, and does not require catching anything in JS.  It is also **not
fixed by open PR #1871** (“Route uncatchable exceptions through one helper”):
I built the PR head (`cbyrd01/quickjs@487b5e88`, all three commits) and the PoC
still reports `survived=true` with `PENDING_EXC: InternalError: out of
memory`; the PR routes uncatchable errors through promise/async paths and the
pending-close arm of `JS_IteratorClose()`, but it does not change the
`is_exception_pending == false` close whose result `flatMap` drops.

Impact: sandbox policy bypass / robustness (`#1810` says OOM must be terminal
for JS), not memory corruption.  The stale error also makes `JS_Eval` return a
normal value while `JS_HasException()` is true.  Later catchable errors remain
catchable (verified).  With a one-shot interrupt handler the same path can
swallow the CPU-budget interrupt; the app's deadline-based handler re-fires at
the next poll, so that variant is bounded.

App verification (real 7a23d8e WidgetJS bundle, §4.7): the native
`SandboxEngine_evalScript` checks `JS_HasException` after every `JS_Eval`, so
a **top-level** F-A script is reported as a failed script and the pending
error is cleared at the eval boundary; the next script is clean.  The
reachable in-app variant is F-A inside a **timer/event callback**: the native
dispatch helper checks only `JS_IsException(result)`, not `JS_HasException`,
so the uncatchable error survives the dispatch and aborts a later callback's
catch/finally (the host reports the stale `InternalError` there).  All
app-faithful sequences are ASan clean (the app harness is ASan-only), including GC after every job and
teardown with the error still pending.  A secondary JS-level poison
(`JS_UNINITIALIZED`, tag 4) is reachable when the eval-boundary check clears
the pending error before the #1873 sentinel is used; its operation matrix is
inert and non-memory.

---

## 2. App model and builds

The app model is the same as the previous audit: one `JSRuntime` with a
**6 MiB** memory limit, 1 MiB JS stack, cooperative interrupt, no host API
beyond `print`/`trace`/`mem`-style helpers.

| build | flags | use |
|---|---|---|
| `harness/asan` | gcc `-O1 -fsanitize=address,undefined -fno-sanitize-recover=all`, 6 MiB | precise ASan: gcc defines `__SANITIZE_ADDRESS__`, so quickjs's 4 KiB arena is disabled (`JS_ARENA_LARGE_BLOCKS_ONLY`) |
| `harness/gcstress` | same + `-DFORCE_GC_AT_MALLOC` | GC before every allocation |
| `harness/rel` | gcc `-O2`, arena active, 6 MiB | app-like allocator/reclaim |
| `harness/snap_rel` | gcc `-O2`, arena active, built from `src_7a23d8e` | app snapshot, app-like allocator |
| `harness/asan_1871` | PR #1871 head `487b5e88` | dedup check for F-A |

(`./build.sh snap` rebuilds the ASan build of the snapshot on demand; the
release snapshot binary `snap_rel` is kept because it is the app-like one.)

Harness helpers (test-only): `__gc()`, `__drain()`, `__mem()`,
`__limit(h)` (limit = current usage + h), `__arm(n)` (precise interrupt via
`quickjs_lab.c`, debug build), `HEADROOM=h` + `AFTER=1` (run `globalThis.go()`
under an exact cap, drain, restore, call `globalThis.after()`), `ARG`.

All ASan builds are **precise**: the 4 KiB arena is off, so sub-512-byte
overflows/UAFs are visible.  The `rel`/`snap_rel` builds keep the arena to
model the app's allocator and to exercise the OOM grooming used by F-A.

---

## 3. Surface map and ownership review

`Callback` = arbitrary JS can run (getter, `valueOf`, user `next`/`return`,
species constructor, thenable `then`).

### 3.1 Iterator helpers (sync; the async variants listed in the task do not exist at HEAD)

`Iterator.from`, `concat`, `chunks`, `windows`, `map`, `filter`, `take`,
`drop`, `flatMap`, `every`, `find`, `forEach`, `some`, `includes`, `join`,
`reduce`, `toArray`, `[Symbol.dispose]`, `zip`, `zipKeyed`.

`Iterator.zip`/`zipKeyed` are JS source compiled into bytecode
(`builtin-iterator-zip{,-keyed}.js`); `concat` and the helper cores are C.

| site | ownership across callbacks | verdict |
|---|---|---|
| `js_iterator_helper_next` 46149 (`obj`, `next`, `func`, `inner`, `buf` all owned/duped; `executing` guard) | callback can only re-enter the same helper through `next/return/dispose`, all rejected by `executing`; `buf` values are owned and marked (`js_iterator_helper_mark`) | safe; the only defect is the ignored close in `flatMap` (F-A) |
| `chunks`/`windows` buffer | `JS_NewArrayFrom()` takes ownership of `buf[0..buf_count)` and frees them itself on OOM; `js_create_array()` dups for windows; `buf_count = 0` is executed on both success and failure; slide path frees `buf[0]` then `memmove` | safe; no double free, no stale mark |
| `js_iterator_concat_next` 45253 / `_return` 45336 / finalizer 45227 / mark 45240 | `values[]` holds `(iterable, Symbol.iterator)` pairs; `index`/`count` are 31-bit; consumed slots are skipped by mark/finalizer; `running` guard is set before any user call (fix 25b5e709) and consumed slots are cleared to `JS_UNDEFINED` before reentry (fix daab4ad4) | safe; `fail:` marks done without closing the inner iterator (resource retention only; matches the “step threw, do not close” rule) |
| `js_iterator_from` 45424 / `js_iterator_wrap_next` 45142 | wrapper owns `wrapped_iter` + `wrapped_next`; no `running` guard, so user `return()` can run during `next()` | only user-visible reentrancy; the engine stores nothing transient between the two calls |
| `js_iterator_proto_func` 45634 (`every/find/forEach/some`), `includes` 45792, `reduce` 45857, `toArray` 45927, `join` 45963 | `func`/`method`/`item`/`acc` are owned locals across `JS_Call`; refcounts keep them alive; close results are checked in `every/find/some/includes/join/reduce` | safe; `reduce`/`toArray` do not close on a step failure (test262/spec behavior) |
| `IteratorHelperPrototype.next/return` dispatch via `JS_ITERATOR_NEXT_DEF` | fast path `JS_IteratorNext2` calls `js_iterator_helper_next`/`js_iterator_concat_next` directly; `*pdone` is initialized on every path; exceptions are checked before the result is wrapped | safe; missing stack check is known #1790 (§6) |
| `Iterator.zip`/`zipKeyed` JS | plain objects with own `next`/`return` and `__proto__: %IteratorHelperPrototype%`; state is a JS closure, reentry guarded by `state == 2` | memory-safe by construction; the helper C core rejects the plain object (`JS_GetOpaque2`) |

### 3.2 for-await and async generators

| site | what was checked | verdict |
|---|---|---|
| for-await codegen 29340 | `iter_obj,next,catch_offset` + `dup3/drop/call_method/await`; `js_iterator_get_value_done` 17242 frees `sp[-4]` only on `{done:true}` and nulls it; `emit_iterator_close` 28574 handles undefined iterator, missing `return`, non-object result and `await` | layout is fixed at the only emit site; no frame index is user-influenced; no OOB frame access found |
| exception unwinding 20944 | catch offset `pos==0` drops `next`, calls `JS_IteratorClose(iter, true)` synchronously, then rethrows the original | matches the pre-#1649 engine; semantic deviations are known #1747/#1649 |
| `js_async_generator_next` 21950 / `_resume_next` 21880 / `_resolve_or_reject` 21794 / `_resolve_function` 21982 | request dequeued **before** the resolver call; frame freed only on `COMPLETED`/exception; `AWAITING_RETURN` skips a second `async_func_free`; reentry writes only the cleared `cur_sp[-1]` await slot | no UAF/double free in 2 000 generated async programs + 300 GC-stress; #1874 value loss reproduced, not memory |
| `js_async_generator_completed_return` / `_await` OOM | failed result/continuation setup leaves a pending OOM and an unsettled promise | known open async-OOM stack #1867/#1870/#1872/#1873; our 6 MiB trace shows the `yield` operand's `await` reaction enqueue failing first (§5.2) |
| `JS_CreateAsyncFromSyncIterator` 56784 / `js_async_from_sync_iterator_next` 56838 | sync iterator + `next_method` owned/marked; promise capability always settled; missing `return`/`throw` handled with `JS_IteratorClose` | safe; the failed `js_create_iterator_result()` passes `JS_EXCEPTION` to the resolver in one return path (same class as #1873, no new primitive) |
| `Promise`/job queue (`JS_EnqueueJob` 2490, `JS_ExecutePendingJob` 2527, `queueMicrotask` 41127) | arguments duplicated into the job; job removed, run, then freed; `queueMicrotask` checks callability | no ownership bug; failed enqueues drop reactions (known #1867/#1870/#1872) |
| `Promise.prototype.then/finally`, species | owned locals across species/`then` getters; refcounts root them | safe |

---

## 4. F-A — `flatMap` closes a completed inner iterator and drops an uncatchable exception

### 4.1 Spec and code

ECMA-262 `Iterator.prototype.flatMap` (27.1.3.3.7) inner loop:

```
Repeat, while innerAlive is true,
  Let innerValue be Completion(IteratorStepValue(innerIterator)).
  IfAbruptCloseIterator(innerValue, iterated).
  If innerValue is done, then
    Set innerAlive to false.
  Else,
    Let completion be Completion(Yield(innerValue)).
    ...
```

There is **no** `IteratorClose(innerIterator)` on the done branch.  QuickJS
does call it (quickjs.c:46361 at e22ce4d, `quickjs.c:46286` at 7a23d8e), and,
unlike every other close site in the same file, does not inspect the result.

Two consequences:

1. **Conformance:** the inner iterator's `return()` is invoked after it has
   already completed.  test262 `mapper-returns-closed-iterator.js` expects the
   engine *not* to call it; the test still passes on QuickJS only because the
   resulting exception is swallowed (the test only checks the result value).
2. **Policy bypass:** if that `return()` raises an uncatchable OOM (or an
   uncatchable interrupt/InternalError), `JS_IteratorClose(...false)` returns
   `-1` with `rt->current_exception` set to the uncatchable error; `flatMap`
   ignores it and continues with the outer iterator.  The interpreter never
   takes its own exception path for this error, so the uncatchable check
   (`JS_IsUncatchableError`, #1810) never runs.  The script survives.

### 4.2 Trigger

`pocs/flatmap_uncatchable_oom_purejs.js` (pure JS, both targets):

```js
const DONE = { done: true, value: undefined };
const ONE  = { done: false, value: 1 };
const inner = {
    next() { return DONE; },
    return() { return { value: new ArrayBuffer(1 << 20), done: true }; },
    [Symbol.iterator]() { return this; },
};
let oi = 0;
const outer = { next() { return oi++ ? DONE : ONE; }, [Symbol.iterator]() { return this; } };
const helper = Iterator.from(outer).flatMap(() => inner);

let FILL = [];                       // F2-style grooming: fill to OOM
try { for (;;) FILL.push({}); } catch (e) {}
FILL.length -= K;                    // room for the InternalError object
let r = helper.next();               // survives, r.done === true
FILL.length = 0;                     // heap usable again
```

The `1 MiB` allocation always fails under the 6 MiB limit; `K` only has to be
large enough for the `InternalError` object (a few hundred bytes).  When `K`
is too small the error object itself cannot be allocated and the older F2
bare-null behaviour occurs instead.

### 4.3 Evidence (6 MiB, release/arena and app snapshot)

`logs/fa_purejs_matrix.txt`:

```
## HEAD e22ce4d, release/arena 6MiB
K=8    fillOOM=null K=8 survived=true alloc=ok ... PENDING_EXC: InternalError: out of memory
K=16   ... survived=true ...
...
## app snapshot 7a23d8e, release/arena 6MiB
K=8    fillOOM=null K=8 survived=true alloc=ok ... PENDING_EXC: InternalError: out of memory
K=16   ... survived=true ...
```

Control (`pocs/flatmap_control_direct.js`, same heap state, `inner.return()`
called directly from JS): the uncatchable error is *not* catchable and aborts
the eval, no `print` is reached (`logs/fa_close_and_control.txt`):

```
EXC: InternalError: out of memory
```

The same file also shows the forbidden close (`flatmap_inner_return_throw.js`):

```
outer.next 0 | inner.next | inner.return | outer.next 1 | r1 {"done":true} | r2 {"done":true}
PENDING_EXC: Error: RET-THROW
```

i.e. the inner `next()` returned `done:true`, then `inner.return()` ran, and
its `Error` stayed pending while both `helper.next()` calls returned normally.
With a plain `Error` this is a silent exception loss; with the OOM it is the
#1810 bypass.

Built PR #1871 head (`harness/asan_1871`, `487b5e88`):

```
K=16 ... survived=true ... PENDING_EXC: InternalError: out of memory
K=32 ... survived=true ... PENDING_EXC: InternalError: out of memory
```

so F-A is **not** covered by that PR (the full head tree was built, not just
the last commit; it does not change the `is_exception_pending == false` close
nor the `flatMap` caller).

### 4.4 Relationship to the previous report and the tracker

| item | relation |
|---|---|
| F2 (previous report) | bare-`JS_NULL` OOM when the error object cannot be allocated; **used here only to fill the heap**.  F-A works with a proper uncatchable `InternalError`. |
| #1810 (closed) “Make OOM exceptions uncatchable” | F-A bypasses the policy: the error is uncatchable but the *control flow* never reaches the uncatchable check. |
| #1871 (open PR) “Route uncatchable exceptions through one helper” | covers `JS_IteratorClose` when an exception is already pending and the unwinder; does **not** cover an uncatchable exception raised by `JS_IteratorClose(..., false)` whose result the caller ignores.  Verified against the PR head. |
| #1873 / #1872 / #1867 / #1870 (open async-OOM stack) | async generator/promise delivery paths, different functions; none mentions `flatMap`. |
| #1622 / #1558 / #1557 (closed iterator-helper fixes) | the extra close was introduced/kept by the helper cleanup; no issue or PR describes the done-inner close. |

### 4.5 Impact

* **Not memory corruption.**  The pending error is a normal `Error` object;
  later `JS_Throw` calls free it normally; `JS_FreeContext`/`JS_FreeRuntime`
  with it pending is ASan-clean (including a self-referential thrown value and
  GC-stress, `pocs/flatmap_pending_cycle.js`).
* **Policy bypass / robustness.**  A script can make the heap fail by a few
  hundred bytes, survive the uncatchable OOM, drop its filler, and continue
  with full functionality.  This defeats the #1810 design (“OOM cannot be
  caught, so try/catch probing is blocked”) without needing the F2 bare-null
  fallback.
* **Stale runtime exception.**  `JS_Eval` returns a normal value while
  `JS_HasException()` is true.  A host that only checks `JS_IsException(ret)`
  will believe the script succeeded; the pending error is only visible at the
  next `JS_Throw`, at `JS_FreeRuntime`, or via an explicit `JS_HasException`.
* **Interrupt variant.**  The same C path swallows an uncatchable interrupt
  thrown inside `inner.return()`.  With the app's deadline-based handler the
  next `js_poll_interrupts` re-fires, so the CPU budget is extended by at most
  one poll interval; with a one-shot handler the interrupt is lost entirely.
* **Exception loss (conformance).**  Any exception from the forbidden close is
  discarded even when it is a normal JS error; the caller sees a normal
  `{done:true}` result.

### 4.6 Suggested fix

Delete the `JS_IteratorClose(ctx, it->inner, false)` call in the `*pdone`
branch (spec: set `innerAlive = false` and continue); the subsequent
`JS_FreeValue`/`it->inner = JS_UNDEFINED` is sufficient.  If the close is kept
for some debugging reason, it must check the return value and propagate
`JS_EXCEPTION` (and route uncatchable errors as in #1871).  Add a regression
test in the style of test262 `mapper-returns-closed-iterator.js` that replaces
a completed inner generator's `return` with a throwing function and asserts it
is **not** called, and a second test that a throwing `return` on a custom
inner that returns `{done:true}` does not leave a pending exception.

### 4.7 App-bundle verification (7a23d8e WidgetJS sandbox)

Follow-up requested by the orchestrator: run F-A inside the **real Android
`sandbox-bundle.js`** from `apks/13.2.0 (7287).apk` and drive the native
protocol (`boot` → `nextScript`/`JS_Eval`/`scriptDone` → `endTick` →
timers/frames → job pump) in `lab/qjs_async_app/`.  The harness was extended
(lab-only) with `__hasexc()`, `__excinfo()`, `PENDING_TRACE=1` (inspect and
restore the pending exception at every protocol step) and `APP_EVAL_CHECK=1`
(mimic `SandboxEngine_evalScript`: after `JS_Eval`, if `JS_HasException(ctx)`,
clear it via `JS_GetException` and treat the eval as failed).  6 MiB heap,
ASan build, assertions on.

**F-A reproduces in the real bundle** with the same pure-JS trigger
(`logs/fa_top_script_appcheck.txt`):

```
FA1 fill=null survived=true hasexc=1
FA1 end hasexc=1 info=tag=-1 cls=3 uncatch=1 msg=InternalError: out of memory
PEND <script 1> tag=-1 cls=3 uncatch=1 ...
APP_EVAL_HASEXC <script 1>: InternalError: out of memory
PEND after-scriptDone none
S2 start hasexc=0 info=none
S2 log=try|caught:object|host: hasexc=0
```

The native app checks `JS_HasException` after every `JS_Eval` (prior RE:
`notes/twidget_interrupt_re.md` §A.1: `SandboxEngine_evalScript` →
`if (JS_HasException(ctx)) throw JSError`; the JSError ctor calls
`JS_GetException`, clearing the pending error).  `APP_EVAL_CHECK=1` models
that check.  Therefore:

* A **top-level `<script>`** that runs F-A is *reported as a failed script*
  (`JSError: InternalError: out of memory`) even though `JS_Eval` returned a
  normal value; the pending error is cleared at the eval boundary and the next
  script starts clean.  The F-A script's code *after* the swallow still ran
  before the boundary, so OOM is still not terminal for that execution, but
  the host sees the error.
* The pending error does **survive** `scriptDone`, the job drain,
  `nextScript`, `endTick` and a timer dispatch
  (`PENDING_TRACE` in `logs/fa_x_timer.txt`, `logs/fa3_timer.txt`).  The real
  engine's script eval check is what stops it at the next `<script>`; it does
  not run between callbacks.

**Dispatch boundary (verified in the IDB).**  The native `__twDispatch` call
helper (`libmessages_49_arm64_72879_f2_annotated.i64`, 0x7893EC
`tw_dispatch_to_js` → 0x77D230) calls the JS dispatch through
`sub_17BFDE8` and then checks only `sub_17BF33C(result)`, which is
`tag == 6` (`JS_IsException`).  It does **not** consult
`rt->current_exception` (`JS_HasException`).  A callback that returns normally
while an uncatchable error is pending (the F-A swallow) is therefore *not*
detected by the dispatcher; a callback that returns `JS_EXCEPTION` *is*
detected and converted to a JSError.  The bundle's own
`__twDispatch` wrapper (`try { ... } catch (e) { report }`) cannot catch an
uncatchable error, so it does not help either.

**Cross-callback poisoning, app-faithful** (`fa/cbtimer.html`,
`logs/fa_cbtimer_fa.txt`): timer A runs F-A and returns normally with
`InternalError` pending; timer B does `String(SENT)` on the #1873
`JS_EXCEPTION` sentinel (a no-throw `JS_EXCEPTION`); the pending uncatchable
error makes the interpreter skip timer B's `try/catch`, so its catch and the
following `__diag` calls do not run; the callback returns `JS_EXCEPTION`, the
dispatcher reports it, and the stale error is attributed to timer B:

```
CB TA survived=true hasexc=1
PEND after-pump-jobs tag=-1 cls=3 uncatch=1 msg=InternalError: out of memory
DISPATCH timer EXC: InternalError: out of memory
CB TC OK hasexc=0
```

Control without F-A (same sentinel; `logs/fa_cbtimer_nofa.txt`): timer B
catches the value (`CB TB CAUGHT unknown tag=4`) and continues
(`CB TB AFTER`), timer C runs, no dispatch error.  The same sequence is
stable 3/3 under `GC_EVERY_JOB=1` and ASan.

**Microtask/Promise.**  `fa/fa3_micro.html` and `fa/fa3_promise.html`: a
queued microtask/promise reaction that does `String(SENT)` runs after the
script and is aborted by the stale error; the harness job pump then consumes
it (`PUMPS ... joberr=1 ... obj=1`) and the catch/following markers do not
run.  Whether the *real* native job pump checks `JS_HasException` between
jobs is not confirmed in the RE notes or this IDB pass; `JS_ExecutePendingJob`
returns -1 only when the job's return value is an exception, so a job that
returns normally with a pending error behaves like the timer case.  Treat the
job-boundary variant as model-dependent, not as a confirmed app path.

`fa/fa3_agen.html` shows the Promise-channel variant: the same stale error,
raised inside an async generator's `for await` body, is converted by
`js_async_generator_reject` into a **promise rejection** (`AGEN REJ object`);
the generator's `finally` does not run and a user
`.then(undefined, handler)` observes/catches the uncatchable error.  This is
the known #1777/#1871 class (uncatchable exceptions leaking into promise
results), not a new bug and not memory-unsafe.

**GC / teardown.**  `fa/fa_timer_pending.html`: F-A runs only in a timer; no
later exception occurs, so the uncatchable error is still pending at
`endTick` and at `JS_FreeContext`/`JS_FreeRuntime`, with `GC_EVERY_JOB=1` and
explicit `gc()` after the swallow (`logs/fa_timer_pending.txt`).  ASan
clean, no `gc_obj_list` assertion, no double free, no UAF.  The same holds
when the pending error survives across a whole extra script and endTick
until the timer consumes it (`logs/fa_x_timer.txt`).

**String/number/host bridge.**  Script 3 in `fa/fa3_*.html` runs
`__host("now")`, `String`/`Number`/`JSON.stringify` and
`document.createElement`/`textContent` while the F-A error is pending
(the `timer` mode: `S3 start hasexc=1`, `S3 bridge now=0 txt=n=123 m=7
j={"a":1}`, `S3 end hasexc=1`) and after a script abort; all conversions and
host returns are normal, and no ASan/assert appeared.  The pending state does
not corrupt the bridge.

**Secondary observation — `JS_UNINITIALIZED` (tag 4) leaking into JS.**  When
the host eval check clears the pending exception and a later no-throw
`JS_EXCEPTION` is raised (again via the #1873 sentinel), the interpreter
delivers `rt->current_exception == JS_UNINITIALIZED` to the catch block.
`fa/tag4.html` (`logs/fa_tag4_ext.txt`): the catch value is
`tag=4 ptr=0 typeof=unknown`, `e === e` is **false**, `String(e)` is
`[uninitialized]`, `e + 1` is `NaN`, `e | 0` is `0`, `JSON.stringify(e)` is
`undefined`, property read is `undefined`, sloppy write is a no-op,
`Object.keys/Object/call/new/WeakMap/spread/for-of/toString` throw
`TypeError`, a `Map` key lookup returns `undefined`, `JSON.stringify([e])` is
`null`, and `__host` calls return normal strings.  No ASan/assert in
any operation.  This is another inert JS-level poison (like the tag-6
sentinel), reachable when the pending exception is cleared between sentinel
capture and use; it gives no pointer or length control.  It is *not* specific
to F-A (the #1873 sentinel is the source of the no-throw `JS_EXCEPTION`), and
it is recorded here because the app eval-boundary check makes it reachable.

**Net app-level impact.**  F-A is a **policy/DoS** issue: an uncatchable OOM
inside `flatMap`'s bogus close does not terminate the execution; the rest of
the script/callback runs, and in a timer/event callback the pending error can
survive the native dispatch and abort a later callback's `catch`/`finally`
with the host attributing the stale `InternalError` to that later callback.
It is **not memory corruption**: all app-faithful sequences (top-level script,
timer A/B/C, timer-only to teardown, GC after every job) are ASan clean
and show no assertion or type confusion.  The generic-harness "second script
sees the pending error" result is *not* app-reachable for a top-level script
because the native eval wrapper checks `JS_HasException`; it remains
model-dependent for jobs and is real for the dispatch/timer path
(dispatcher checks only `JS_IsException`).

---

## 5. Secondary observations

### 5.1 Stale exception at the eval boundary (same root, non-memory)

`js_iterator_helper_next`'s `flatMap` branch is the only place where
`JS_IteratorClose`'s return value is ignored: every other close site
(`concat_return`, helper `close:`, `every/find/some/includes/join/reduce`,
`js_create_iterator_helper`) checks it.  Consequently F-A also explains the
generic “exception lost” case.  There is no read of the stale exception by JS
and no ownership transfer, so this is a correctness/policy issue, not a UAF.

### 5.2 Async generator OOM during `yield` (known #1873; negative for memory)

In an async generator, `yield expr` compiles to `await expr; yield` (bytecode
at `pocs/oom_trace.js`).  Under an exact 6 MiB headroom (harness `HEADROOM`),
a temporary instrumented build showed that the first failure is the microtask
enqueue for that await:

```
TRACE resume ret tag=0 int=0        (first next -> await gate)
TRACE resolve_fn magic=0 state=3    (gate resolved)
TRACE resume ret tag=0 int=0        (await of the yield operand)
... PENDING_EXC: null
```

With `h <= 600` the await reaction enqueue fails; `perform_promise_then()`
ignores `JS_EnqueueJob()`'s return, `js_async_generator_await()` reports
success, the generator is left suspended with an OOM pending and no
continuation installed.  With `h >= 604` the same run completes normally and
the iterator result is created successfully, so the pure delivery-OOM window
(“failed iterator-result allocation passed to the resolver”, #1873) was not
reachable in this configuration at 6 MiB.  This matches the open PR #1873,
which describes exactly the “report success with a native exception still
pending” behaviour; no new memory primitive was found around it.

### 5.3 `JS_IteratorNext2` fast path lacks the stack check (known #1790)

`pocs/stack1790.js`: 17 500 nested `.map(x => x)` helpers fit in the 6 MiB
heap but `it.next()` throws `RangeError: Maximum call stack size exceeded` at
the innermost callback; no segfault at 6 MiB with an 8 MiB OS stack because
the heap limit is reached before the native stack.  At 18 000 helpers the
construction itself OOMs (catchable null).  This is the open PR #1790; on a
host with a smaller thread stack (Android worker threads are often 1 MiB) the
crash margin may differ, but it is known and out of scope here.

### 5.4 `for await` close semantics (known #1747 / #1649)

The for-await unwinder closes the iterator on a rejected `next()`, and the
async close does not await `return()`; the trailing `OP_iterator_close` also
runs `return()` for a synchronous `return` that throws.  These are the known
semantic deviations; no memory-safety consequence was found (the iterator is
always a live, counted value at the close site, and the sync close only frees
the returned promise).

---

## 6. Dedup / tracker search (2026-11-05)

Open/closed items checked via the GitHub API (100 newest + targeted searches
for `Iterator flatMap`, `iterator close`, `for await`, `async generator`,
`uncatchable OOM`, `OOM catch`):

| # | state | relation |
|---|---|---|
| #1871 | open PR | uncatchable routing through one helper; **does not fix F-A** (built and tested) |
| #1873 | open PR | async-generator delivery allocation failures; §5.2, not F-A |
| #1874 | open PR | async-generator resolver reentry value loss; reproduced as control, not memory |
| #1838 | open PR | drain async generator queue after completion; reproduced (pending promises), not memory |
| #1747 | open issue | for-await closes read-only/at wrong times; §5.4 |
| #1649 | open PR | for-await / async-from-sync close semantics; §5.4 |
| #1790 | open PR | missing stack check in `JS_IteratorNext2` fast path; §5.3 |
| #1865 | open | captured variable count truncation / generator UAF; excluded (prior report/other worker) |
| #1867 #1870 #1872 | open PRs | async-OOM stack (promise reactions / thenable adoption); different functions |
| #1776 #1777 #1778 | closed | uncatchable exceptions in promise/module/async generator; superseded by #1871 |
| #1810 | closed | uncatchable OOM policy; F-A bypasses it |
| #1622 #1558 #1557 | closed | iterator-helper fixes; no done-inner close issue |
| #1890 | open | Array/Proxy/RegExp ToUint32 vs ToLength; not async |
| #1892 | open | JS_DupValue/JS_DupAtom refcount overflow; not async |

No issue, PR or test262 file describes the `flatMap` done-inner close or the
resulting uncatchable swallow.  test262
`Iterator/prototype/flatMap/mapper-returns-closed-iterator.js` expects no
close and passes only because the exception is dropped.

Prior local reports checked before starting: `notes/audit_async.md` (C1
#1874, C2 fromAsync OOM leak, C4 policy), `notes/audit_regexp_postfix.md` (F2
bare-null OOM), `notes/audit_fuzz.md`, `notes/qjs_latest_audit.md`,
`notes/qjs_latest_bughunt.md`, `notes/qjs_novel_audit.md`.  The 2 448-program
async-generator matrix, 2 400-program interrupt matrix and 2 376-program
test262 replay from `notes/audit_async.md` target the same source revision for
the async-generator code and were not repeated; the campaigns here add the
iterator-helper and async-from-sync surface.

---

## 7. Campaigns and negative evidence

| campaign | inputs | build | result |
|---|---|---|---|
| `fuzz/gen_matrix.py` helper state machine | 5 000 programs | precise ASan+UBSan, 6 MiB | 0 sanitizer/assert hits; 2 host-scheduling timeouts replayed clean in 16–19 ms (`logs/fuzz_matrix_asan.txt`) |
| same, GC stress | 600 (every 4th) | `-DFORCE_GC_AT_MALLOC` + ASan | 0 hits (`logs/fuzz_gcstress.txt`) |
| same, app snapshot | 1 500 | `src_7a23d8e` ASan+UBSan | 0 hits (`logs/fuzz_matrix_snap.txt`) |
| `fuzz/gen_async.py` async state machine (for-await break/throw/return, `yield*`, async-from-sync, manual next/return/throw) | 2 000 programs | precise ASan+UBSan | 0 hits (`logs/fuzz_async_asan.txt`) |
| same, GC stress | 300 | ASan + GC per allocation | 0 hits (`logs/fuzz_async_gcstress.txt`) |
| OOM paths of the helper API (`__limit` sweep) | 20 operations × 16 headrooms (0…6 144 B) | precise ASan+UBSan, `AFTER` hook | 0 hits |
| flatMap uncatchable-OOM PoC | K ∈ {0,8,16,32,64,128} | HEAD rel/arena + 7a23d8e rel/arena + ASan | **F-A** (`logs/fa_purejs_matrix.txt`) |
| flatMap pending-exception teardown | cycle-valued throw + `__gc` | ASan + GC stress | clean (`pocs/flatmap_pending_cycle.js`) |
| F-A in real WidgetJS bundle (`lab/qjs_async_app`) | 9 callback/script modes + controls | 7a23d8e ASan, 6 MiB, real `sandbox-bundle.js` | F-A reproduces; policy effects, 0 ASan/assert (`logs/fa_*`, `logs/fa3_*`) |
| F-A timer A → sentinel timer B (app-faithful, `APP_EVAL_CHECK=1`) | 3 reps + no-F-A control | ASan + `GC_EVERY_JOB=1` | B's catch/finally skipped + `DISPATCH timer EXC`; control catches tag 4; 0 ASan/assert (`logs/fa_cbtimer_*.txt`) |
| F-A timer-only to teardown | pending at `JS_FreeContext` | ASan + `GC_EVERY_JOB=1` | clean (`logs/fa_timer_pending.txt`) |
| tag4 matrix (`JS_UNINITIALIZED` catch value) | 36 operations | 7a23d8e ASan, real bundle | inert, 0 ASan/assert (`logs/fa_tag4_ext.txt`) |
| known #1790 repro | 5 000…17 500 helpers | HEAD rel, 6 MiB | RangeError, no segfault (§5.3) |
| known #1874 control | reentry PoC | ASan | wrong value, no memory error (prior report) |
| clang static analyzer | whole `quickjs.c` | `core,unix.Malloc,deadcode` | warnings reviewed; the list.h:78 one is the known #1874 false positive; the rest are pre-existing false positives/dead stores (log `logs/clang_analyze_text.txt`) |

The generator emits only programs that run to completion in a few ms; each
program combines 1–3 iterators with trapping `next`/`get`/`return` getters,
helper chains, `for await`, `yield*`, spread, `toArray/reduce/join/...` and
`__gc()`.  The helper corpus never hit ASan/UBSan; the async corpus is the
supplement for the for-await/async-generator part of the surface.

---

## 8. Limitations

* Host-only; no device/emulator/browser.  The app snapshot is checked by
  source build (`7a23d8e`) and by the 72879 binary only indirectly (the async
  code is unchanged between the two source snapshots; no symbol-level check
  was needed for F-A because it is pure JS and allocator behavior is modeled
  by the 6 MiB arena build).
* F-A needs the heap to be nearly exhausted (F2 fill) and a few hundred bytes
  of headroom.  The PoC uses only JS (`{}` filler, `FILL.length -= K`) and was
  reproduced with K = 8…128 on the app-snapshot release build; the exact K is
  allocator/build dependent, like the previous F2/F1 thresholds.
* The interrupt variant of F-A was reasoned from the code path and the
  one-shot `__arm` behavior; it was not run with the widget's exact handler.
  The deadline-based handler re-fires at the next poll, so the practical
  extension is small.
* The async iterator **helper** proposal (async `map/filter/take/drop/...`,
  `AsyncIterator.zip`, etc.) is not implemented at HEAD e22ce4d: the only
  async iterator surface is `%AsyncIteratorPrototype%[@@asyncIterator]`,
  `[@@asyncDispose]`, `for await`, async generators, async-from-sync and
  `Array.fromAsync`.  The “async variants” in the task therefore could not be
  audited as separate code paths; they do not exist in either target.
* No memory primitive was found; F-A is a policy/robustness finding.  If the
  goal is an R/W primitive, the stronger local candidates remain the
  regexp/arena/UAF work in the other notes, not this surface.

---

## 9. Artifacts and reproduction

All under `lab/qjs_async_iter/`:

| file | purpose |
|---|---|
| `src/`, `src_7a23d8e/` | hard-linked source trees at e22ce4d and 7a23d8e |
| `src_1871/` | PR #1871 head `487b5e88` (dedup check) |
| `harness/harness.c` | 6 MiB runner; `__gc`, `__drain`, `__mem`, `__limit`, `__arm`, `HEADROOM`/`AFTER`, `ARG` |
| `build.sh` | `asan`, `gcstress`, `dbg`, `rel`, `snap`, `snaprel` builds |
| `pocs/flatmap_uncatchable_oom_purejs.js` | **F-A**, pure JS, both targets |
| `pocs/flatmap_uncatchable_oom.js` | **F-A** with exact `HEADROOM` (ASan) |
| `pocs/flatmap_oom_f2.js` | F-A with the F2 fill/`K` sweep |
| `pocs/flatmap_control_direct.js` | control: direct `inner.return()` aborts with the uncatchable OOM |
| `pocs/flatmap_inner_return_throw.js` | spec deviation / silent exception loss |
| `pocs/flatmap_pending_cycle.js` | teardown/GC stress with a pending exception |
| `pocs/oom_helper_ops.js` | 20 helper ops under `HEADROOM` |
| `pocs/oom_delivery_guest.js`, `pocs/oom_trace.js`, `pocs/oom_delivery2.js` | §5.2 async-generator OOM traces |
| `pocs/known_1790_stack.js`, `pocs/stack1790.js` | §5.3 |
| `fuzz/gen_matrix.py`, `fuzz/gen_async.py`, `fuzz/run_corpus.sh` | generators and runner |
| `fuzz/matrix/`, `fuzz/async/` | retained 1 000 + 500 programs (the full 5 000 + 2 000 corpora are regenerated by the two scripts; the campaign logs cover the full runs) |
| `logs/` | build logs, campaign logs, F-A matrices, clang analyzer |

App-bundle verification (real 7a23d8e WidgetJS bundle, §4.7) is under
`lab/qjs_async_app/`:

| file | purpose |
|---|---|
| `fa/fa_two_scripts.html` | direct F-A script + second script (top-level eval-boundary case) |
| `fa/fa3_*.html`, `fa/fa_x_*.html` | 2/3-script modes: plain, micro, promise, timer, gen, agen, forof, mapcb, flatcb |
| `fa/fa_sentinel_combined.html`, `fa/gen_fa_x3.py` | #1873 sentinel capture + F-A + probe scripts |
| `fa/cbtimer.html`, `fa/gen_cbtimer.py` | app-faithful timer A (F-A) → timer B (sentinel) sequence |
| `fa/fa_timer_pending.html` | F-A only in a timer, pending error to teardown |
| `fa/tag4.html`, `fa/gen_tag4.py` | `JS_UNINITIALIZED` (tag 4) catch-value matrix |
| `sandbox_harness.c` | real-bundle harness, now with `__hasexc`, `__excinfo`, `PENDING_TRACE`, `APP_EVAL_CHECK` |
| `logs/fa_top_script_appcheck.txt`, `logs/fa_cbtimer_fa.txt`, `logs/fa_cbtimer_nofa.txt`, `logs/fa_timer_pending.txt`, `logs/fa_tag4_ext.txt`, `logs/fa3_*.txt`, `logs/fa_x_*.txt`, `logs/fa_app_summary.txt` | app evidence |

Reproduce F-A:

```sh
cd lab/qjs_async_iter
./build.sh rel
ARG=32 ./harness/rel pocs/flatmap_uncatchable_oom_purejs.js
# fillOOM=null K=32 survived=true alloc=ok
# ... PENDING_EXC: InternalError: out of memory

./build.sh snaprel
ARG=16 ./harness/snap_rel pocs/flatmap_uncatchable_oom_purejs.js
# same on 7a23d8e

ARG=32 ./harness/rel pocs/flatmap_control_direct.js
# EXC: InternalError: out of memory   (no print: control aborts)

# F-A survives PR #1871:
gcc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I src_1871 -Iharness -o harness/asan_1871 harness/harness.c \
    src_1871/{quickjs,libregexp,libunicode,dtoa}.c -lm -ldl -lpthread
ARG=32 ./harness/asan_1871 pocs/flatmap_oom_f2.js   # survived=true, same PENDING_EXC
```

App bundle (real 7a23d8e `sandbox-bundle.js`; build as in
`lab/qjs_async_app/README.md`):

```sh
cd lab/qjs_async_app
# top-level F-A, native eval-boundary check modeled
APP_EVAL_CHECK=1 PENDING_TRACE=1 ./sandbox_harness \
    assets/7287/sandbox-bundle.js fa/fa_two_scripts.html
# FA1 survived=true; APP_EVAL_HASEXC <script 1>; S2 starts hasexc=0

# app-faithful cross-callback: timer A = F-A, timer B = sentinel
python3 fa/gen_cbtimer.py 5 0
APP_EVAL_CHECK=1 GC_EVERY_JOB=1 ./sandbox_harness \
    assets/7287/sandbox-bundle.js fa/cbtimer.html
# DISPATCH timer EXC: InternalError: out of memory; CB TC OK hasexc=0
# control (no F-A): python3 fa/gen_cbtimer.py 5 1 -> CB TB CAUGHT unknown tag=4

# F-A only in a timer: pending reaches teardown
APP_EVAL_CHECK=1 GC_EVERY_JOB=1 ./sandbox_harness \
    assets/7287/sandbox-bundle.js fa/fa_timer_pending.html
# PEND before-teardown ... uncatch=1; PUMPS 1; ASan clean

# tag-4 catch value matrix
APP_EVAL_CHECK=1 ./sandbox_harness assets/7287/sandbox-bundle.js fa/tag4.html
```

Key logs: `logs/fa_purejs_matrix.txt`, `logs/fa_close_and_control.txt`,
`logs/fuzz_matrix_asan.txt`, `logs/fuzz_gcstress.txt`,
`logs/fuzz_async_asan.txt`, `logs/fuzz_async_gcstress.txt`,
`logs/fuzz_matrix_snap.txt`, `logs/oom_helpers.txt`,
`logs/clang_analyze_text.txt`.
