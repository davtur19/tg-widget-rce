# quickjs-ng issue #1570 vs Telegram 13.2.0 beta — offline reachability assessment

Date: 2026-11-01. Target: Telegram Android 13.2.0 beta (`Android_Beta_13.2.0_(72789).apk`),
widget sandbox `libtmessages.49.so`, quickjs-ng >= v0.17.0 (6 MiB JS heap, 300 ms
CPU per task / 500 ms ceiling, no teardown when a script ends).
Everything below is local x86-64, no phone, no app modification.

## 0. Verdict (plain)

**#1570 is not a demonstrated app-reachable RCE candidate for Telegram 13.2.0 as
shipped.**

* On quickjs-ng **v0.17.0** (the app baseline) the public reproducer `min1570b.js`
  does **not** crash in any configuration tested: release, ASan, arena on/off,
  GC stress on/off. Stress runs: **0/5 crashes**; six-config baseline: **0 crashes in 12 runs** (`poc1570` spins in all of them).
* The commit that neutralizes the reproducer is **7955cfd** (“Fix use-after-free of a
  suspended coroutine reachable only via a closure”, 2026-07-23), which is included
  in v0.17.0. Earlier commits (`d950d55`, `f2da139`, `d5a59c3`) crash under
  ASan+GC stress; `7955cfd` and later do not.
* Current master (`d7215b0`, v0.18.0-dev) also does **not** crash under
  ASan+GC stress. `async_func_mark` still skips a running coroutine's stack, so the
  root-cause assumption is still in the source, but no v0.17/v0.18 trigger was found.
* The public schematic `poc1570.js` is a spinner (unbounded thenable microtask
  chain), exactly as the reporter later admitted; it never reaches the vulnerable GC.
* GC stress is **not** inherently required for the bug class: on pre-fix master a
  normal GC policy (no `FORCE_GC`) can be placed at the vulnerable allocation by heap
  grooming across timer callbacks (ASan UAF, 5/5, peak 1.33 MB, ~32 ms CPU). But that
  is pre-fix code the app does not ship; on v0.17.0 the same normal-GC chain does not
  crash, even when the GC is confirmed to run inside the vulnerable job.
* On pre-fix master in a **release** build (no ASan) the same chain did **not**
  abort: the UAF stayed latent (freed 80-byte block recycled). A lab UAF is not an
  RCE, and here the release build does not even turn it into a crash.

If the app were built from pre-7955cfd master, #1570 would be a real (lab-detected)
UAF reachable under ordinary GC with heap grooming; even then, turning it into RCE is unproven.
For the shipped v0.17.0 baseline, the answer is no.

## 1. Builds

Source: `quickjs-ng` tag **v0.17.0** (`6d46d07d04041b40f4f49eaa7fdebe44c314c699`).
Reference pre-fix build: **d950d55e950dd7994a96c669c31efa967b8b79f3** (master at the
issue report, v0.15.1), plus bisect commits and current master `d7215b0`.

| build | flags | purpose |
|---|---|---|
| `rel` | `-O3 -DNDEBUG` | app-like release, upstream arena ON |
| `rel_stress` | `-O3 -DNDEBUG -DFORCE_GC_AT_MALLOC` | stress without ASan |
| `asan_noarena` | `-O1 -g -fsanitize=address` | ASan, GCC auto-disables arena |
| `asan_noarena_stress` | + `-DFORCE_GC_AT_MALLOC` | public reproducer config |
| `asan_arena` | ASan + `JS_ARENA_LARGE_BLOCKS_ONLY 0` forced | arena kept ON under ASan |
| `asan_arena_stress` | ASan + forced arena + `FORCE_GC` | arena + stress |

Note on compilers: GCC defines `__SANITIZE_ADDRESS__`, clang does not; with clang an
ASan build keeps the arena ON. We therefore built both arena variants explicitly.
A clang-19 cross-check gave the same result: master stress crashes, v0.17.0 stress
does not.

Build command (in `/tmp/opencode/q1570`):

```sh
git clone --branch v0.17.0 --depth 1 https://github.com/quickjs-ng/quickjs.git src
cp -a src src_arena   # then replace the ASAN/FORCE_GC block with:
                      #   #define JS_ARENA_LARGE_BLOCKS_ONLY 0
./build.sh
```

`build.sh` compiles `ev1570.c` (single eval) and `ev1570_timer.c` (multi-task) with
each config. Harness sources and a portable builder are in the lab directory (§8).

## 2. Harness model

`ev1570 <file.js>`:

* `JS_NewRuntime`, `JS_SetMemoryLimit(6 MiB)`, `JS_NewContext`.
* CPU interrupt handler on `CLOCK_THREAD_CPUTIME_ID`, budget **5000 ms** (generous,
  so the 300/500 ms sandbox budget does not mask the bug), plus a 30 s wall timeout.
* `JS_Eval` the file, then drain `JS_ExecutePendingJob` (the widget bundle uses
  Promise/queueMicrotask and timers, so the engine must pump jobs).
* **No `JS_FreeContext` / `JS_FreeRuntime`**; `_exit(0)` after printing the result.
* Lab-only diagnostics `__gc`, `__mem`, `__peak`, `__cpu`, `__log` are available but
  are **not used by the app-shaped timer chain** (the app exposes no `gc()`).

`ev1570_timer <file1.js> ...`:

* One runtime/context for all files, no teardown.
* Each file is a task with a fresh **300 ms CPU deadline** and **5000 ms wall
  backstop**; jobs are drained inside the task.
* Real `nanosleep` between tasks (default 1000 ms) models `setTimeout`; sleeps do
  not consume CPU, so the 300 ms/1000 ms sliding quota refills.
* No diagnostic globals: the timer scripts are ordinary JS.

The app's `<script>`s are 1000 max, timers 64 max; timers are dispatched as tasks
with fresh deadlines (RE notes). The harness uses separate top-level evals rather
than the bundle's native timer host; the task semantics (same context, fresh CPU
deadline, no teardown) are the same.

## 3. Baseline matrix (issue reproducers)

`min1570b.js` matches the code block in issue comment 4982132700 (the only
difference is a leading blank line).
`poc1570.js` is the schematic from the issue body.

| build | GC stress | min1570b | poc1570 | peak malloc |
|---|---|---|---|---|
| v0.17.0 release | off | ok, 0.8 ms | spins (1M-job cap, 1.28 s CPU) | 156 KB |
| v0.17.0 release | on | ok, 2.9 ms | spins (CPU budget fires) | 160 KB |
| v0.17.0 ASan (arena off) | off | ok, 8.3 ms | spins | 164 KB |
| v0.17.0 ASan (arena off) | on | ok, 21.7 ms | spins | 163 KB |
| v0.17.0 ASan (arena forced ON) | off | ok, 4.6 ms | spins | 168 KB |
| v0.17.0 ASan (arena forced ON) | on | **ok, 18.1 ms (0/5)** | spins | 167 KB |
| master d950d55 release | off | ok, 0.7 ms | spins (1M-job cap) | 154 KB |
| master d950d55 ASan | off | ok, 8.6 ms | — | 162 KB |
| master d950d55 ASan | **on** | **ASan heap-use-after-free, 5/5** | spins | ~160 KB |
| master latest d7215b0 ASan | on | ok, 21.3 ms | — | 163 KB |

clang `-O2 -DNDEBUG` v0.17.0 release (closer to the Android NDK): `min1570b`
0.45 ms, timer chain 6.0 ms CPU / 3.0 s wall, peak 2.9 MB, no crash.

`min1570b` alone peaks at ~160 KB, i.e. below the 256 KB initial GC threshold:
without stress it runs **zero GCs** (GC diag count 0). That is why a plain
release/ASan run cannot trigger #1570 at all, in any version.

## 4. Which commit neutralizes the reproducer

All runs: ASan + `FORCE_GC_AT_MALLOC`, `min1570b.js`, same harness.

| commit | date | result |
|---|---|---|
| d950d55 (master at report) | 2026-07-12 | ASan UAF 5/5 |
| 4369dd6 (parent of f2da139) | 2026-07-17 | ASan UAF |
| f2da139 “for-await normal completion” | 2026-07-17 | ASan UAF |
| d5a59c3 “await iterator return on break” | 2026-07-17 | ASan UAF |
| **7955cfd “suspended coroutine via closure”** | **2026-07-23** | **no crash** |
| 05b2db9 “AsyncDisposableStack UAF” | 2026-08-21 | no crash |
| v0.17.0 tag | 2026-09-18 | no crash (0/5) |
| d7215b0 current master (v0.18.0-dev) | 2026-11-01 | no crash |

7955cfd adds `JSStackFrame.cur_gc_obj` and `JSVarRef.is_coro`, makes an open var_ref
capturing a coroutine local a GC object with a counted reference to the owning
coroutine, and traces that edge from every var_ref holder. In `min1570b` this keeps
the async generator/coroutine reachable through the closure chain, so the cycle
collector no longer frees the object that the running frame holds. It is a real fix
for a neighbouring coroutine-liveness bug, and it incidentally removes the #1570
reproducer. `async_func_mark` still has the `if (sf->cur_sp)` skip in v0.17.0 and
latest, so the comment’s assumption is still there; we found no new trigger.
Note that 7955cfd is a fix for a *neighbouring* coroutine-liveness bug, so the
reproducer may have been exercising that bug (a suspended coroutine reachable only
through a closure) rather than the running-operand-stack skip described in #1570.
The reproducer alone does not distinguish the two; either way, v0.17.0 is clean.

## 5. Normal GC vs GC stress (important nuance)

GC stress is not the only way to reach #1570 on pre-fix master. `js_trigger_gc` is
called only from `JS_NewObjectFromShape` when `malloc_size + sizeof(JSObject) >
malloc_gc_threshold`; strings do not call it. Therefore the threshold can be
positioned with strings and timer-separated tasks.

Measured on master (diag build, no stress):

```
initial threshold 262144
GC at 262139 -> 393148 -> 589676 -> 884556
after last GC: threshold = 1.5 * 884556 = 1,326,834
```

4-task chain, all plain JS, 1 s between tasks:

1. task 1: define `explore`/`F10` (4.4 ms CPU, 148 KB)
2. task 2: 4000 live objects + `"x".repeat(377500)` (13.4 ms CPU, 1.315 MB)
3. task 3: `new F10()` (0.2 ms eval + 1.24 ms jobs)
4. task 4: allocate 9000 objects -> next GC

With K=377500 the task-3 GC fires at `malloc_size=1,326,891` **inside
`JS_NewPromiseCapability` in `js_async_from_sync_iterator_next`**, while async
frames are running (`MARK-RUNNING` diag). Task 4 then runs two GCs: the first
(1.99 MB) frees the object, the second (2.98 MB) marks it and hits the UAF:

```
ERROR: AddressSanitizer: heap-use-after-free
  #0 gc_decref_child   quickjs.c
  #1 JS_MarkValue
  #2 mark_children
  #3 gc_decref
  #4 JS_RunGC
  #5 js_trigger_gc
  #6 JS_NewObjectFromShape
```

5/5 deterministic at K=377500; K 377300–377700 also put the GC on the promise
allocation. Peak before task 4 is 1.33 MB; task 4 reaches ~2.98 MB before the
second GC aborts. Total CPU is under ~32 ms, wall 3 s with 1 s sleeps. No `gc()`, no
stress flag, no diagnostic hooks in the chain.

**v0.17.0, same chain:** no crash. 4 tasks complete in 6.5–47 ms CPU (release 6.5 ms, ASan 34–47 ms), 3.0 s wall,
peak 3.1 MB. Diag run:

```
[TASK 3] start malloc=1,317,229
[AFSI] entry
[AFSI] promise=ok
[DIAG GC] size=1,327,578 threshold=1,327,630
[MARK-RUNNING] [MARK-RUNNING]      <- GC inside job execution, async frames running
... later GCs at 1,990,852 and 2,984,978
```

A normal GC *does* run while coroutines are running, and later GCs run again; still
no UAF. Under `FORCE_GC_AT_MALLOC` v0.17.0 also does not crash, which is the
exhaustive case (GC before every allocation): if stress cannot hit it, no
normal-GC placement can.

The 6-task v0.17 chain (definitions + groom + trigger + three post tasks) reaches
the 6 MiB cap (6.29 MB) and gets `InternalError: out of memory` at task 6 without
crashing; the 4-task chain peaks at ~3.1 MB, well under the cap.

## 6. Timer-chunked arm (requested refinement)

**Split of `min1570b` across evals/tasks:** task 1 = everything except the final
`new F10();`, task 2 = `new F10();`, 1 s apart, same context.

* master d950d55 ASan+stress: **crashes in task 2 jobs** (same `gc_decref_child` UAF).
* v0.17.0 ASan+arena+stress: both tasks complete, 18.3 ms CPU, 1.02 s wall,
  peak 166 KB. 0 crashes.

So the program *can* be split across `<script>`/timer chunks: definitions in one
task, trigger + job pump in the next. The UAF window itself cannot span tasks: while
the coroutine is suspended at `await`, `cur_sp` is restored and the stack is marked
normally; the vulnerable state exists only while a task is executing synchronously
inside a job. What persists across tasks is the heap and the GC threshold, which is
what enables the normal-GC chain above.

**Timer limit:** the sandbox bundle throws `RangeError` above `maxTimers` (64).
The split uses 2 tasks, the groom chain 4; even a 64-attempt sweep is 64 timers.
Total CPU is 6.5–47 ms across all tasks (each task ≤23 ms, far below 300 ms); the
1 s spacing refills the 300 ms/1000 ms quota; the 5 s wall backstop is per task and
unused. **The 64-timer limit is not a blocker.**

Caveat for the pre-fix hypothetical: the K value is build/heap-layout specific
(a ~400-byte window in our run; the widget bundle/DOM shifts the baseline), and the
attacker would have to sweep K across timers. On v0.17.0 this is moot because no K
crashes.

## 7. What the UAF frees (primitive), and what it is not

From the ASan report of the normal-GC master chain:

* Freed region: **80 bytes**, `[0x…730, 0x…780)`, allocated by `js_def_malloc` from
  `JS_NewObjectFromShape` **inside `async_func_resume`** (a JSObject created while an
  async function was running).
* Freed by `js_def_free` from `gc_free_cycles` → `JS_RunGC` — i.e. the object’s
  `JSProperty` array. The freeing GC is task 4’s first GC (1.99 MB); the read is in
  task 4’s second GC (2.98 MB).
* The read at +4 in `gc_decref_child` marks the stale object’s children
  (`JS_MarkValue` ← `mark_children`).

Primitive: a **stale JSObject / freed 80-byte JSProperty array** referenced from a
suspended coroutine frame. In release, that block can be recycled by later JS
allocations, giving a potential stale-property-array/type-confusion primitive in the
GC marker. We did **not** attempt reclaim/control, and on the vulnerable master the
plain release build did not abort (3/3 six-task and 1/1 four-task runs exited 0).
No RCE chain is claimed; a lab UAF is not an RCE.

## 8. Raw logs, matrix, harness

* Full matrix: `/tmp/opencode/q1570/q1570_matrix.csv` (and in `notes/`).
* Raw stdout/stderr per run: `/tmp/opencode/q1570/logs/base/` (names are referenced
  in the matrix builder `make_matrix.py`; archive `q1570_logs.tar.gz`).
* Harness sources: `/tmp/opencode/q1570/ev1570.c`, `ev1570_timer.c`, `build.sh`,
  `make_matrix.py`; copies in `lab/` as `ev1570.c`, `ev1570_timer.c`,
  `build_q1570.sh`, `make_matrix.py`, plus the `chunks/` chain files.
* Key logs:
  * `base/ms_1..5.err` — master d950d55 stress UAF 5/5.
  * `base/a_1..5.out` — v0.17.0 stress 0/5.
  * `base/pre_f2.err`, `base/f2_stress.err`, `base/d5a59c3_stress.err` — pre-fix crashes.
  * `base/7955cfd_stress.out`, `base/latest_stress.out` — no crash.
  * `base/final_master_asan.err` — normal-GC master chain UAF (task 4).
  * `base/final_master_rel.out`, `base/final_v017_*.out` — no release crash.
  * `base/v017_diag.err` — GC inside job execution + later GCs, no UAF.
  * `base/timer_master_stress_split.err`, `base/timer_asan_arena_stress_split.out`.

Reproduce the key runs:

```sh
cd /tmp/opencode/q1570

# 1. issue reproducer on v0.17.0 release and ASan+stress
./bin/ev1570_rel /tmp/opencode/min1570b.js rel/min1570b
ASAN_OPTIONS=detect_leaks=0 ./bin/ev1570_asan_arena_stress /tmp/opencode/min1570b.js v17/stress

# 2. master at the issue commit, ASan+stress (crashes)
ASAN_OPTIONS=detect_leaks=0 ./bin/ev1570_master_stress /tmp/opencode/min1570b.js master/stress

# 3. timer-chunked normal-GC chain (master ASan crashes in task 4)
ASAN_OPTIONS=detect_leaks=0 SLEEP_MS=1000 \
  ./bin/ev1570_timer_master_asan \
  chunks/min1570b_A_defs.js chunks/groom/g4000_k377500.js \
  chunks/min1570b_B_trigger.js chunks/post/g1.js

# 4. same chain on v0.17.0 (no crash)
SLEEP_MS=1000 ./bin/ev1570_timer_asan_arena \
  chunks/min1570b_A_defs.js chunks/groom/g4000_k377500.js \
  chunks/min1570b_B_trigger.js chunks/post/g1.js
```

## 9. Limits of this evidence

* Offline x86-64 source build, not the arm64 app binary. The app binary’s arena table
  matches v0.17.0 (prior RE; the version is inferred, not read from a version string);
  current master (v0.18.0-dev) also does not crash, so a newer snapshot does not change
  the verdict.
* ASan with the arena forced ON cannot detect intra-slab UAF by itself; the sensitive
  negative is the arena-off ASan+stress build, and the release/arena-on build also
  does not crash.
* The app’s real heap baseline includes the sandbox bundle/DOM, which shifts the GC
  threshold; the timer chain was tuned on a bare runtime. This is an additional
  practical barrier for the pre-fix hypothetical, not a rescue for v0.17.0.
* No device test, no widget DB/phone access, no RCE/reclaim experiment.
