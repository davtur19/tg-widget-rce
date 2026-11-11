# Telegram 13.2.0 beta — twidget sandbox: CPU/interrupt policy and
# on-device fatality of the QuickJS `Array.prototype.find` double free

Target: `lib/arm64-v8a/libtmessages.49.so` from
`Android_Beta_13.2.0_(72789).apk` (sha256
`23727eb4208488faf50d96ab8b9cd2574b6cb01ee5e33e4de05a1aee1aeee861`).
IDB: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_widget_annotated.i64`
(annotated + saved by this session: 24 renames, 9 comments).

Method: Hex-Rays + raw AArch64 on the .so; the Java-side defaults were read
from the same APK with jadx (read-only, no device, no app modification).

---

## 0. TL;DR (verdict)

* The widget engine installs a QuickJS interrupt handler
  (`JS_SetInterruptHandler` at **0x1739B0C**, handler **`twidget_interrupt_handler`
  = 0x777CE4**) whose whole job is: *return 1 when the current task has burned
  its CPU budget*.
* The budget is **300 ms of `CLOCK_THREAD_CPUTIME_ID` per 1000 ms window**
  (`cpuQuotaMs=300`, `cpuQuotaWindowMs=1000`), clamped per task to
  `[50 ms … 500 ms]` (`cpuLimitMs=500` is the per-task ceiling / boot budget),
  with a 5 s wall-clock backstop. `cpuKillAfterMs=0` → the widget is never
  "killed" by the quota, only interrupted. Values are **hard-coded in the JNI
  `create`** (`0x97ead0…0x97eb40`) and multiplied by a Java "CPU multiplier"
  that is a `final int = 1` in this build.
* When the handler returns 1, `js_poll_interrupts` (**0x17082F0**) throws an
  **uncatchable** `InternalError("interrupted")`, sets `rt+0x518` (runtime
  wedged), the script eval is turned into a C++ `twidget::JSError`, and the
  engine kills itself (`SandboxEngine_die` = **0x77E044**, message
  `"CPU limit exceeded: more than %d ms of continuous execution (<task>)"`).
  The JS context is **not** freed at that point (only in the runtime wrapper
  destructor 0x776CEC → `JS_FreeContext`+`JS_FreeRuntime`).
* `js_array_find` (**0x17955A8**) polls **once per loop iteration, at the loop
  top**, i.e. *after* the previous element has already been released
  (0x1795808‑0x1795834) and *without* clearing the register pair. The interrupt
  branch (0x1795844‑0x1795870) releases that same pointer again with
  `__JS_FreeValueRT` → **`js_free_rt` → `rt->free` → libc `free()`**.
  Tag for strings in this build is **-7** (verified at the return of
  `JS_NewStringLen` 0x17190BC: `MOV X1,#0xFFFFFFFFFFFFFFF9`), which is inside
  the ref-counted range, so a freshly built 1‑char string (refcount 1) is
  really `free()`d the first time and `free()`d **again** the second time.
* The default allocator path is `JS_NewRuntime` with the *default*
  `JSMallocFunctions` (`sub_17395B8` → `js_free_default` → libc `free`), i.e.
  **scudo** on Android. A second `free()` of a chunk still in the scudo
  quarantine is a `DoubleFreeOrCorruption` → `die()` → **SIGABRT**.
  A secondary abort also exists inside QuickJS itself
  (`"js_free_rt: malloc_size underflow"`, 0x16FA4FC) if the tracked byte
  counter underflows first.

**Conclusion:** a widget script that keeps `Array.prototype.find` running
longer than the CPU budget **is interrupted inside the find loop**, and the
interrupt lands on the only poll site that exists there (the loop top), so the
stale element is freed twice. On device this is expected to be a **fatal
SIGABRT in the Telegram process** (double free detected by scudo), not a
silent corruption. Payload can stay tiny (a few hundred bytes) because the
long string is built at runtime with `String.prototype.repeat`; the binding
constraint is *CPU time*, not HTML size.

---

## 1. The interrupt handler and the exact deadline semantics

### 1.1 Installation

`JS_SetInterruptHandler(rt, cb, opaque)` — 0x1739B0C:

```c
__int64 __fastcall sub_1739B0C(__int64 rt, __int64 cb, __int64 opaque)
{
  *(_QWORD *)(rt + 1320) = cb;        /* rt+0x528 */
  *(_QWORD *)(rt + 1328) = opaque;    /* rt+0x530 */
  return rt;
}
```

Only caller: the runtime wrapper constructor **0x776C30**
(`twidget_JSInterruptRuntime_ctor`) used by the sandbox engine:

```c
*(this+24) = JS_NewRuntime();          // sub_17395B8 (default malloc fns)
JS_SetMemoryLimit(this->rt, 6291456);  // 6 MiB JS heap
this->ctx  = JS_NewContext(rt);        // sub_173A0B4
JS_SetInterruptHandler(rt, twidget_interrupt_handler /*0x777CE4*/, this);
```

The wrapper layout is the "opaque" handed to the handler:

| off | type | meaning |
|----|------|---------|
| +0x00 | double | wall deadline, `CLOCK_MONOTONIC` seconds |
| +0x08 | u8 | "interrupt fired" flag (set by the handler) |
| +0x10 | double | CPU deadline, `CLOCK_THREAD_CPUTIME_ID` seconds (`INF` = disabled) |
| +0x18 | ptr | `JSRuntime*` |
| +0x20 | ptr | `JSContext*` |

### 1.2 The handler (0x777CE4) — decompiled verbatim

```c
__int64 __fastcall twidget_interrupt_handler(__int64 rt_or_ctx, __int64 opaque)
{
  if ( opaque == 0 ) return 0;
  if ( (double)now_monotonic_ns()/1e9 <= *(double *)opaque )      /* wall not expired */
  {
      if ( *(double *)(opaque + 16) == INFINITY ) return 0;       /* CPU cap disabled */
      clock_gettime(CLOCK_THREAD_CPUTIME_ID /*3*/, &ts);
      if ( (double)ts.nsec/1e9 + (double)ts.sec <= *(double *)(opaque + 16) )
          return 0;                                               /* still inside budget */
  }
  *(_BYTE *)(opaque + 8) = 1;                                     /* mark fired */
  return 1;                                                       /* -> INTERRUPT */
}
```

So the predicate is literally:

```
interrupt  ⇔  mono_now > wall_deadline  OR  thread_cpu_now > cpu_deadline
```

(`sub_169E17C` = CLOCK_MONOTONIC ns, `sub_776BBC` = seconds, `sub_776BE4` =
CLOCK_THREAD_CPUTIME_ID seconds — same clocks on both sides of the
comparison, verified.)

The handler ignores its first argument (the disassembly passes `ctx` in X0 and
`opaque` in X1: `LDR X9,[X8,#0x528]; LDR X1,[X8,#0x530]; BLR X9`).

### 1.3 How the deadlines are armed

Three sites write `rt_wrapper[+0]` / `rt_wrapper[+16]`, always the same form:

**(a) `SandboxEngine_start` (0x785AD0), boot phase** (pseudocode, ~line 803):

```c
v4 = engine->cpuLimitMs; if (v4 < 5000.0) v4 = 5000.0;
rt->wall_deadline = mono_now + v4/1000.0;      /* 5 s */
rt->cpu_deadline  = INFINITY;                  /* no CPU cap while booting  */
```

**(b) `SandboxEngine_runTask` (0x77AB3C)** — every dispatched job:

```c
void runTask(engine, name, delegate, double budget_ms)
{
  engine->budget_ms = budget_ms;              /* engine+0x5A8 */
  rt->fired = 0;
  rt->cpu_deadline  = thread_cpu_now() + budget_ms/1000.0;
  w = budget_ms * 10.0; if (w < 5000.0) w = 5000.0;
  rt->wall_deadline = mono_now + w/1000.0;
  ... delegate(); layout(); runScripts();  ...
}
```

**(c) `SandboxEngine_runScripts` (0x7849AC)** — re-armed *before every single
`<script>`* with the same `engine->budget_ms`:

```c
*(u8*)(rt+8) = 0;
*(double*)(rt+16) = thread_cpu_now() + engine->budget_ms/1000.0;
w = engine->budget_ms*10.0; if (w < 5000.0) w = 5000.0;
*(double*)rt = mono_now + w/1000.0;
... JS_Eval(script) ...
```

⇒ **Per script**: `budget_ms` of thread CPU, and a wall backstop of
`max(10*budget_ms, 5000) ms`.

### 1.4 Where `budget_ms` comes from (the quota)

`Budget_admit` (**0x75ADC8**) is called by `runJob` (0x77AF4C) for the
JS-thread budget (engine+0x3F8) and the main-thread budget (engine+0x4D0):

```c
remaining = obj[1] - used_in_window(now);          /* obj[1] = quota (ms) = cpuQuotaMs */
if (is_exempt_task(name) || remaining > 0.0) {
    *allowed = 1;
    budget = max(remaining, 50.0ms);               /* floor 50 ms */
    if (budget > obj[0]) budget = obj[0];          /* ceiling = per-task max */
    *out_ms = budget;
} else {
    *allowed = 0;                                  /* throttled, job skipped */
    /* computes retryAt from the 10-slot sliding window */
}
```

`obj[0]` is the per-task ceiling: the `"boot"` path is exempt and returns
`obj[0]` directly, and `SandboxEngine_boot` dispatches `"boot"` with
`cpuLimitMs` — hence `obj[0] == cpuLimitMs == 500 ms`. `obj[2]` = window
(1000 ms), `obj[3]` = `cpuKillAfterMs` (0).

`name == "boot"` is special-cased: it always returns `obj[0]` (the per-task
ceiling) and `allowed = 1`.

Sliding-window accounting, `Budget_addSample` (0x75AC38) / `usedInWindow`
(0x75ACF8): the window is split into 10 slots (`slot = obj[4]`, presumably
`window/10`); each slot stores its start time (`obj[5..14]`) and the ms burned
in it (`obj[15..24]`); `used` = sum of the slots still inside
`[now-window, now]`.

Throttle/kill: `Budget_throttleRemaining` (0x75B0AC), `Budget_shouldKill`
(0x75B0DC) → `kill` requires `obj[3] > 0`; with the shipped default
`cpuKillAfterMs = 0` **the widget is never killed**, it is only throttled and
its jobs are skipped. The skip branch logs:

```
"CPU quota: throttled for %.1f s (%d ms per %d ms, cpuKillAfterMs=%d)"
```
(0x782E78 region / 0x77AF4C).

### 1.5 Defaults — hard-coded in JNI `create`, not from Java

`WidgetSandboxNative.create(...)` (`0x97e6d8`) builds `WidgetHostOptions` on
the stack at `SP+var_5A0`; the store sequence at **0x97ead0..0x97eb40** is
unconditional:

```
0x97ead0  STR  X8(=0x800000)          -> opt+0x00 memoryLimitBytes = 8 MiB
0x97eaf8  STUR Q0(xmmword_1F9480)     -> opt+0x08 cpuLimitMs       = 500.0
                                         opt+0x10 cpuQuotaMs       = 300.0
0x97eb14  STUR Q0(xmmword_1F5B30)     -> opt+0x18 cpuQuotaWindowMs = 1000.0
                                         opt+0x20 cpuKillAfterMs   = 0.0
0x97eb28  STR  X10(=0x4059000000000000)-> opt+0x28 mainThreadQuotaMs = 100.0
0x97eadc  STR  W8(=0x40)              -> opt+0x30 maxTimers          = 64
0x97eae8/0x97eb20/0x97eb2c            -> mode = "strict", locale = "en-US",
                                         policy feature "webAnimations"
```

Field offsets confirmed independently by `SandboxEngine_start` (0x785AD0,
`sub_785AD0`) which formats those exact fields into the `"limits"` JSON
(`"memoryLimitBytes"`, `"cpuLimitMs"`, `"cpuQuotaMs"`, `"cpuQuotaWindowMs"`,
`"cpuKillAfterMs"`, `"mainThreadQuotaMs"`, `"maxTimers"` at 0x78609c, 0x7861dc,
0x786310, 0x786450, 0x7357… strings).

**Java "CPU multiplier"**: `create`'s 8th parameter is `int a8`, and

```c
/* just before the limits are handed to the engine (decompiled `create`) */
v581 = vmulq_n_f64(v581, (double)a8);   /* cpuLimitMs(500), cpuQuotaMs(300) */
v583 = v583 * (double)a8;               /* mainThreadQuotaMs(100) */
```

Java side (`org/telegram/utils/twidget/k0.java`):

```java
if (i10 < 1 || i10 > 4) throw new IllegalArgumentException("CPU multiplier must be 1..4");
...
this.e = i10;   // passed to create()
```
and `w.java:76  public final int d = 1;` — in the shipped beta the multiplier
is **always 1**, so the effective defaults are exactly the numbers above.

The dormant `WidgetSandboxNative.limits(byte[])` hook (sets a global JSON
string, 0x19E7400) is **never called from Java** in this APK (verified by
grepping the whole decompiled tree), so it cannot override them.

**Effective budget for the first widget script:**

```
budget = clamp(cpuQuotaMs - used_in_window, 50, cpuLimitMs) = clamp(300-0,50,500) = 300 ms
wall   = max(10*300, 5000) = 5000 ms
```
(If the script happens to run from the `"boot"` dispatch itself, the value
handed to `runTask` is `cpuLimitMs` = 500 ms instead; either way ≤ 500 ms.)

`js_poll_interrupts` (0x17082F0) resets `ctx->interrupt_counter` to **10000**
on every slow-path call, and the fast path is `if (--counter <= 0) slow()` —
so the handler is consulted every 10000 loop iterations (or sooner if some
other JS op consumes the counter).

---

## 2. What the engine does with the interrupt

`js_poll_interrupts` (0x17082F0), verbatim structure:

```c
if (rt->interrupt_blocked /*rt+0x518*/) { ctx->counter = 1; return -1; }
ctx->counter = 10000;
if (!rt->interrupt_handler) return 0;
if (rt->interrupt_handler(ctx, rt->interrupt_opaque) != 0) {
    rt->interrupt_blocked = 1;
    for (all contexts) ctx->interrupt_pending /*+0x20C*/ = 1;
    cur_exception_saved = rt->current_exception; rt->current_exception = NULL;
    JS_ThrowError(ctx, ..., "interrupted");       /* sub_16FAD90 */
    rt->current_exception = cur_exception_saved;
    return -1;
}
```

* The thrown value is an `Error` object and it is **flagged uncatchable**:
  0x16FAD90 does `*(u16*)(err+16) |= 0x40` on the freshly created exception
  (the `is_uncatchable_error` bit). Widget `try/catch` **cannot** swallow it.
* `rt+0x518` stays 1 afterwards ⇒ every later poll returns -1, the runtime is
  effectively dead. It is only reset by a full runtime teardown.
* The exception surfaces out of `JS_Eval`: `SandboxEngine_evalScript`
  (0x7848D8) → `JS_Eval_wrapper_throwJSError` (0x776FF0):

```c
val = JS_Eval(ctx, src, len, filename, is_module);
if (JS_HasException(ctx))                       /* sub_17AFBBC */
    __cxa_throw(new twidget::JSError(...), &typeinfo for twidget::JSError, dtor);
```

* On the way out, `SandboxEngine_afterRun_report` (0x782E78) sees
  `rt->fired != 0` and calls `SandboxEngine_die` (0x77E044) with

```
"CPU limit exceeded: more than %d ms of continuous execution (<task>)"   (0x22c12c)
```
  (layout-query variant: `"Layout query limit exceeded: host queries blocked
  the renderer for more than %d ms ..."`, 0x25f8cb, driven by `engine+1504`).

* `die()` sets `engine+808 = 1`, clears the job/timer queues, notifies the host
  (`onDied` → Java logs `"widget <id> stopped (n): <msg>"`), and **does not
  touch the JS context**. The `JSContext`/`JSRuntime` are destroyed only by
  `twidget_JSInterruptRuntime_dtor` (0x776CEC: `JS_FreeContext(ctx)` →
  `JS_FreeRuntime(rt)`), i.e. when the engine object is destroyed
  (`WidgetSandboxNative.destroy`, host teardown).

Consequence: after an interrupt the sandbox is dead but the **JS heap stays
allocated for the lifetime of the widget host**, and it is freed later
(GC + `JS_FreeContext`) on a heap that the double free may already have
corrupted.

---

## 3. Script execution policy (`<script>`), size and count

Boot chain (native): `JNI create` → `WidgetHost` ctor → `SandboxEngine_boot`
(0x77A6C8) → creates the runtime (0x776C30), defines `__host`,
`__hostBinary`, … → `runTask("boot", …)` (0x77AB3C):
delegate (loads `sandbox-bundle.js`, runs `hide-host.js`) → `layout` →
`SandboxEngine_runScripts` (0x7849AC).

`runScripts` (0x7849AC) verbatim structure:

```c
for (n = 0; ; ) {
    if (engine->dead) break;
    host_call("nextScript", &json);                 /* sub_7840C8 */
    if (!ok || json_length == 0) break;
    parse json -> { id, type, code, src }
    if ("src" present) { log("external script not available: %s"); continue; }
    if (type == "module") module = 1;
    /* re-arm deadlines from engine->budget_ms */
    eval(script, "inline-script-<id>.js", module);  /* sub_7848D8 */
    host_call("scriptDone", "[<id>,true|false]");
    layout();
    if (!ok_now) break;
    if (++n == 1000) break;                         /* hard cap: 1000 scripts */
}
```

Findings relevant to a PoC payload:

* **No per-script or per-HTML byte-size limit in native code.** The only cap
  is the JS heap: `JS_SetMemoryLimit(rt, 6291456)` (6 MiB) in 0x776C30, and
  `memoryLimitBytes = 8 MiB` in the options. Exceeding it throws the
  uncatchable `"out of memory"` (same wedge).
* **1000-script cap** per run (the `++v2 != 1000` counter).
* Scripts with `src` are skipped (`"script-skipped"` / `"external script not
  available: %s"`); only *inline* text runs.
* The JS side (`sandbox-bundle.js`, dispatch table `__twDispatch`) collects
  scripts during HTML parse:
  `Rd(el)`: `if (el[executed] || !el.isConnected) return;` — type must be in
  `{text/javascript, application/javascript, …, module}`, `nomodule` is
  skipped, empty inline bodies are skipped, and the entry pushed is
  `{id, type:"global"|"module", code:<textContent>}` — **no length check**.
  `nextScript()` returns them one by one.
* The bundle does **not** patch or freeze `Array.prototype` (no
  `Array.prototype.*=` assignments anywhere in sandbox-bundle.js), so
  `Array.prototype.find` is stock QuickJS.
* **`is_copy` never gates execution**: Java only exposes it as
  `profile.isCopy` (`p.java:190`), and the engine starts from the view/render
  path (`p.y(mVar)` from `p.o()` / `p.s(w)`, i.e. when the widget view is
  bound/measured), not on message receipt.
* **`visible` never gates execution**: the boolean is passed into `create`
  (a13) and forwarded to the bundle as `config.visible`
  (`Td(r.visible===!1)`), which only affects rendering/`visibilitychange`.
  `runScripts` only checks `engine->dead` (engine+808).

⇒ An invisible-but-bound widget (and any `is_copy` widget) still evaluates its
`<script>`s, and the natural place to run the payload is the very first
script, which gets the full fresh quota.

---

## 4. `js_array_find` — the double free, instruction by instruction

Registered at `0x194cc88` — `{"find", JS_PROP_WRITABLE|ENUMERABLE, JS_DEF_CFUNC,
magic 0, func 0x17955A8}`; `findIndex`/`findLast`/`findLastIndex`
(0x194cca8/0x194ccc8/0x194cce8) are the same function with magic 1/2/3.

Relevant part of `js_array_find` (0x17955A8, 952 bytes):

```
0x17955e0  BL  sub_1709050                 ; ToObject(this_val): a string primitive is boxed
                                           ; (the primitive is kept in the new object at +0x30)
0x17955fc  BL  js_get_length64(ctx,&len,obj);   ; sub_172FFCC -> length of the (boxed) string
...
0x1795748  B   0x179575C                   ; first iteration
0x179574C  LDR X8,[SP,#var_68]             ; <-- back-edge
0x1795750  ADD X19,X19,X8                  ; k += dir
0x1795754  CMP X26,X19 ; B.EQ 0x17956F0    ; loop finished
0x179575C  LDR W8,[X22,#0x224]             ; <-- LOOP-TOP POLL (ctx->interrupt_counter)
0x1795760  SUBS W8,W8,#1
0x1795764  STR  W8,[X22,#0x224]
0x1795768  B.LE 0x1795838                  ; counter hit 0 -> slow path
0x179576C  ... build index JSValue ...
0x17957A0  BL  sub_171252C                 ; JS_GetPropertyUint32(ctx,obj,k) -> (X0=ptr,X1=tag)
0x17957A4  MOV X21,X1                      ; tag
0x17957A8  MOV X25,X0                      ; ptr        <-- "val"
0x17957AC  CMP W21,#6 ; B.EQ 0x1795844     ; element getter threw
0x17957D4  ... JS_CallInternal(predicate, val, k, obj) ...   ; sub_16FD168
0x17957EC  MOV X2,X1 ; CMP W2,#6 ; B.EQ 0x1795844           ; predicate threw
0x1795800  BL  sub_171053C                 ; ToBoolean(result)
0x1795804  CBNZ W0, 0x17958B8             ; -> match: free val, return it
0x1795808  CMN W21,#9 ; B.CC 0x179574C    ; not refcounted -> next iteration
0x1795810  LDR  X9,[SP,#var_70]            ; rt
0x1795814  LDUR W8,[X25,#-4]               ; ref_count
0x1795818  LDR  X0,[X9]
0x179581C  SUBS W8,W8,#1
0x1795820  STUR W8,[X25,#-4]
0x1795824  B.GT 0x179574C                  ; still alive -> next iteration
0x1795828  MOV  X1,X25 ; MOV X2,X21
0x1795830  BL   __JS_FreeValueRT           ; <-- FIRST free (val), X25/X21 NOT cleared
0x1795834  B    0x179574C
0x1795838  MOV  X0,X22 ; BL js_poll_interrupts   ; <-- slow path
0x1795840  CBZ  W0, 0x179576C              ; handler said "carry on"
0x1795844  CMN  W21,#9 ; B.CC 0x17958B0    ; <-- INTERRUPT / EXCEPTION PATH
0x179584C  LDR  X19,[SP,#var_70]
0x1795850  LDUR W8,[X25,#-4]               ; ref_count read from FREED memory
0x1795854  LDR  X0,[X19]
0x1795858  SUBS W8,W8,#1
0x179585C  STUR W8,[X25,#-4]
0x1795860  B.GT 0x1795608                  ; (won't be taken for a freed 0)
0x1795864  MOV  X1,X25 ; MOV X2,X21
0x179586C  BL   __JS_FreeValueRT           ; <-- SECOND free of the SAME pointer
```

Why the second free is not a benign refcount decrement:

* The value is a **string** (tag **-7**, see §4.1) and comes from
  `JS_GetPropertyUint32` on a String object, i.e. it is a freshly allocated
  `JSString` with `ref_count == 1` — the first `free` takes it to 0 and calls
  `__JS_FreeValueRT`, which actually releases the allocation.
* Therefore at the loop top the register pair `(X25, X21)` already points to
  memory that has been returned to the allocator, and the exception path
  decrements `[ptr-4]` of freed memory and then calls `__JS_FreeValueRT`
  again on the same pointer.

`__JS_FreeValueRT` (0x16FB170) → `js_free_rt` (0x16FA4FC) → `rt->free`
(`*(rt+16)`) with `(rt->malloc_opaque, ptr-8)`. `sub_17395B8` created the
runtime with the **default** `JSMallocFunctions`, whose free is libc
`free()` (→ scudo on Android).

Note the *other* two exits are correct: an exception raised by the element
getter or inside the predicate jumps to the same 0x1795844 block **before**
the per-iteration free, so those free the current value exactly once.

### 4.1 String tag check (this is not stock-Tag -5 QuickJS)

`JS_NewStringLen` = **0x17190BC**; its success return is:

```
0x17197e0  MOV  X1, #0xFFFFFFFFFFFFFFF9      ; tag = -7
0x17197e4  MOV  X0, X23                     ; JSString*
0x17197e8  ... epilogue ... RET
```

`__JS_FreeValueRT` (0x16FB170) dispatches on: `tag <= -7` → the string/big
number block, where **-7** falls into the string release path
(`sub_16FA4FC(rt, str)` = `free`), -3 = module → `abort()`, and -5/-4 are
"unknown tag" → `printf("js_free_value_rt: unknown tag=%d"); abort()`. So the
build is a recent quickjs-ng where **`JS_TAG_STRING == -7`**, and everything
downstream (refcount at `ptr-4`, GC-object list) matches the code above.

### 4.2 The allocator will notice

* `sandbox-bundle.js` never touches `Array.prototype` (grep-verified), so the
  stock function is reachable.
* Default `JS_NewRuntime` ⇒ `malloc`/`free` from bionic ⇒ **scudo**. Android
  (11+) enables the `DoubleFreeOrCorruption` check by default: freeing a chunk
  whose state is "Available"/quarantined calls `reportDoubleFree()` → `die()`
  → `abort()`.
* Even if that check were compiled out, QuickJS's own accounting aborts first
  in many cases: `js_free_rt` does
  `if (rt->tracked_bytes < chunk_size) { printf("js_free_rt: malloc_size
  underflow: freeing %zu but only %zu tracked\n"); abort(); }` (0x16FA4FC).

So the realistic on-device outcome of the double free is **SIGABRT**, not a
quiet corruption. (The "shared object → refcount undercount → later UAF"
variant described in the earlier report also exists, but with a *fresh*
per-element string the immediate double free dominates.)

---

## 5. Does a long `find` get interrupted inside the loop? — yes, deterministically

Interrupt polls inside `js_array_find`:

* the loop-top poll at 0x179575C (one per iteration), and
* no other poll, **provided the predicate is a C function** (`Number`): a JS
  predicate would run `JS_CallInternal`'s own polls, which fire *inside* the
  predicate — in that case the exception path is entered with the current
  element still live, i.e. only one free. That would waste the bug.

Timeline for `Array.prototype.find.call(s, Number)` as the first widget
script, `s` long enough:

```
t=0        runScripts arms: cpu_deadline = thread_cpu + 300 ms, wall = +5 s
t≈0…300ms  10 000-iteration polls return 0 (handler says "carry on")
t≈300ms    first loop-top poll after the deadline returns 1
           -> js_poll_interrupts throws uncatchable "interrupted"
           -> 0x1795844: free X25 (already freed at 0x1795830)  == DOUBLE FREE
           -> scudo abort  (or JS tracked-size abort)
```

`Number` returns `NaN` for every 1-char string, so the predicate never
matches and the loop always runs to the end of the string (or to the
interrupt).

**Required string length.** The loop must still be running when the 300 ms
budget expires; there is no way to fire earlier (the counter floor is 10000
iterations, and the min budget is 50 ms). Per iteration the engine does
`JS_GetPropertyUint32` on a String object (allocates a 1-char `JSString`),
`JS_CallInternal` of a C builtin, a ToBoolean, and `free()` of the string —
i.e. one malloc + one free per character. Estimated cost **≈250–600 ns per
iteration** on a mid-range arm64 device ⇒ 300 ms ≈ **0.5–1.2 M iterations**.

Recommendation (with margin, still inside the 6 MiB JS heap):

```js
const s = "A".repeat(2000000);            // 2 MB string ≈ 0.5–1.5 s of CPU
Array.prototype.find.call(s, Number);     // never matches -> full traversal
```

* 2 000 000 chars gives ~1.7–4× the needed iterations; keep the HTML itself
  tiny (a few hundred bytes) — **do not** ship a 2 MB HTML: the HTML text is
  itself a JS string in the same 6 MiB heap, and the sandbox bundle also
  materialises DOM/text nodes for it.
* `String.prototype.repeat` is native and cheap; `"A".repeat(3e6)` is still
  under the heap limit and gives more margin, but 2e6 is the safer default.
* Fallback if a build ever interns 1-char strings (not the case here, verified
  by the tag path): use heap objects instead —
  `Array.prototype.find.call(Array.from({length:120000},()=>({})),Number)`
  (a fast array of 120 k object references stays under the memory limit).
* Second-script trick: a first script that burns ~250 ms of CPU leaves
  `remaining ≈ 50 ms`, so a *following* script's `find` needs only ~50 ms
  (≈100–250 k chars). Not required, but useful if heap pressure is a concern.

---

## 6. Address table (all verified in this IDB, names persisted)

| Address | Name | Role |
|---|---|---|
| 0x97e6d8 | `Java_..._WidgetSandboxNative_create` | builds the fixed limits at 0x97ead0…0x97eb40 |
| 0x985a60 | `Java_..._limits` | dormant limits override (never called from Java) |
| 0x776c30 | `twidget_JSInterruptRuntime_ctor` | `JS_NewRuntime` + 6 MiB + `JS_SetInterruptHandler(0x777CE4)` |
| 0x776cec | `twidget_JSInterruptRuntime_dtor` | `JS_FreeContext` + `JS_FreeRuntime` (only place) |
| 0x1739b0c | `JS_SetInterruptHandler` | `rt+0x528`/`rt+0x530` |
| 0x777ce4 | `twidget_interrupt_handler` | returns 1 when wall/CPU deadline exceeded |
| 0x17082f0 | `js_poll_interrupts` | counter=10000, calls handler, throws uncatchable "interrupted" |
| 0x77a6c8 | `SandboxEngine_boot` | creates runtime, dispatch "boot" with `cpuLimitMs` |
| 0x785ad0 | `SandboxEngine_start` | loads bundle, arms deadlines |
| 0x77ab3c | `SandboxEngine_runTask` | sets `engine+0x5A8 = budget_ms`, arms deadlines, runs delegate/layout/scripts |
| 0x77af4c | `SandboxEngine_runJob` | quota admission via 0x75ADC8, throttle logging |
| 0x7849ac | `SandboxEngine_runScripts` | ≤1000 scripts, re-arms deadlines per script |
| 0x7848d8 | `SandboxEngine_evalScript` | wraps `JS_Eval` |
| 0x776ff0 | `JS_Eval_wrapper_throwJSError` | converts a JS exception into C++ `twidget::JSError` |
| 0x77e044 | `SandboxEngine_die` | marks engine dead + `onDied`; keeps the JS context |
| 0x782e78 | `SandboxEngine_afterRun_report` | `"CPU limit exceeded: more than %d ms…"` → die |
| 0x75adc8 | `Budget_admit` | `clamp(remaining,50,max)` admission |
| 0x75ac38 / 0x75acf8 | `Budget_addSample` / `Budget_usedInWindow` | 10-slot sliding window |
| 0x75b0ac / 0x75b0dc | `Budget_throttleRemaining` / `Budget_shouldKill` | kill only if `cpuKillAfterMs>0` |
| 0x17955a8 | `js_array_find` | the double free (0x1795808…0x1795870) |
| 0x17082f0 slow path ⇄ 0x179575c | | loop-top poll |
| 0x16fb170 / 0x16fa4fc | `__JS_FreeValueRT` / `js_free_rt` | final `free()` |
| 0x17190bc | `JS_NewStringLen` | returns tag -7 |
| 0x194cc88 | Array.prototype table entry | `find` → 0x17955A8 (magic 0) |

---

## 7. On-device signals (for a later verification run)

* Java log (`org.telegram.messenger.f8`): `widget <key> stopped (n): CPU limit
  exceeded: more than 300 ms of continuous execution (inline-script-N.js)` —
  emitted from the `onDied` diag right before/around the crash.
* Tombstone: `SIGABRT` in `libc.so` (scudo `die`), stack roughly
  `free → js_free_rt → __JS_FreeValueRT → js_array_find → JS_CallInternal →
  JS_Eval → SandboxEngine_evalScript → SandboxEngine_runScripts →
  SandboxEngine_runTask → twidget-host thread`.
* If instead the tombstone shows `abort` inside `js_free_rt` with
  `"js_free_rt: malloc_size underflow"` in the log, the same bug fired but
  QuickJS's own accounting tripped first — still fatal.
* If the widget dies with `CPU limit exceeded` and no crash, the string was
  too short (loop finished before the deadline) or the predicate was a JS
  function (poll landed inside the predicate).

---

## 8. Confidence / open items

High confidence (direct evidence): handler semantics and its two clocks;
installation; hard-coded limits and the `×cpuMultiplier` (=1) scaling; the
per-script re-arming; uncatchable error + engine death + context retention;
`js_array_find` free/poll ordering; string tag -7 and the `free()` chain;
script count cap, no size cap, no `is_copy`/`visible` gating in the engine.

Medium (estimate, not measured on device): the per-iteration cost used to size
the string (0.5–1.2 M iterations for 300 ms) — hence the recommend 2 M chars
(≈2–4× margin). Everything else about the trigger is deterministic.

Not covered here: Java-side reachability details of `p.y()` beyond "engine
starts from the view/render scheduling path" (the earlier report covers that),
and the exact scudo configuration of a specific OEM ROM (AOSP defaults assume
the double-free check is on).

---

# Addendum A — follow-up: what the engine does *after* the interrupted eval

## A.1 The JSError is caught **inside** `SandboxEngine_evalScript`

`SandboxEngine_evalScript` (0x7848D8) is a tiny function (body 0x7848D8‑0x784928)
that calls `JS_Eval_wrapper_throwJSError` (0x776FF0). Its GCC landing pad is
placed right after the body, at **0x78492C‑0x7849A8** (not part of any
function in IDA):

```
0x78492c  CMP  W1, #1                  ; EH selector: 1 = twidget::JSError
0x784930  MOV  X21, X0                 ; exception object
0x784934  B.NE 0x7849A0                ; anything else -> cleanup/rethrow
0x784938  MOV  X0, X21
0x78493c  BL   sub_16E4D60             ; __cxa_begin_catch
0x784940  LDR  X8, [X0]
0x784944  LDR  X8, [X8, #0x10]         ; vtable slot 2 = std::exception::what()
0x784948  BLR  X8
0x78494c  ...  sub_740BF8               ; build std::string
0x784958  ADD  X1, SP, #8              ; msg
0x78495c  MOV  X0, X20                 ; engine
0x784960  MOV  X2, X19                 ; task name
0x784964  BL   SandboxEngine_afterRun_report   ; 0x782E78  -> die() if interrupted
0x784968  ... string cleanup ...
0x784978  BL   sub_16E4F40             ; __cxa_end_catch
0x78497c  B    0x784918                ; epilogue -> normal return (no rethrow)
...
0x7849a0  MOV  X0, X21 ; BL sub_16E667C  ; _Unwind_Resume (only for non-JSError)
```

So the C++ exception never unwinds into `runScripts`: the catch is per‑eval,
`afterRun_report()` (and therefore `die()`) runs, and `evalScript` **returns
normally**.

## A.2 `afterRun_report` dies whenever the interrupt flag is set

`SandboxEngine_afterRun_report` (0x782E78):

```c
rt_wrapper = engine->rt;                       // engine+0x320
if (rt_wrapper) {
    fired = rt_wrapper->fired;                 // rt+0x08 (set by the handler)
    if (fired && engine->[0x5E0]) { ... "Layout query limit exceeded: ..." -> die }
    if (fired) {
        if (engine->budget_ms /*+0x5A8*/ >= engine->cpuLimitMs /*+0x100*/)
             goto cpu_die;
        /* else format "CPU quota: %d ms of %d ms in %d ms window" */
cpu_die:
        msg = "CPU limit exceeded: more than <budget_ms> ms of continuous execution (<task>)";
        SandboxEngine_die(engine, msg);        // 0x783000 / 0x783488 / 0x78392c
        return;
    }
}
/* not fired -> just format the JS error text and forward it to the host diag
   callback (delegate vtable+64); engine keeps running                     */
```

Ordinary JS errors (TypeError, …) therefore do **not** kill the widget; an
interrupt always does.

## A.3 `runScripts` **breaks** after the eval when the engine died

Right after the eval call (0x784EDC) in `SandboxEngine_runScripts`:

```
0x784edc  BL   SandboxEngine_evalScript
0x784ee0  ... cleanup of the temp strings ...
0x784f00  ADRL X28, "true"               ; "scriptDone" success flag
0x784f08  LDRB W8, [X19, #0x328]         ; engine->dead == engine+808
0x784f0c  CBZ  W8, 0x784FCC              ; still alive -> layout + scriptDone
0x784f10  MOV  W21, #1                   ; v6 = 1  (loop result = "stop")
0x784f14  B    0x78512C                  ; -> loop tail
    ...
0x784fcc  MOV  X0, X19 ; BL sub_784380   ; layout
0x784fd4  ...  "scriptDone" host call ...
0x785120  MOV  X0, X19 ; BL sub_784380
0x785128  MOV  W21, WZR                  ; v6 = 0  (continue)
0x78512c  ... free the nextScript JSON ...
0x78514c  CBNZ W21, 0x7851D8            ; v6 != 0 -> RETURN
0x785150  ADD  W22, W22, #1              ; script counter
0x785154  CMP  W22, #1000
0x785158  B.NE 0x784A0C                  ; -> next <script>
0x78515c  B    0x7851D8                  ; cap reached -> return
```

**Answer: BREAK.** After an interrupt the loop returns immediately, does not
touch the remaining `<script>` elements, and notably **skips the host
`scriptDone` call** (so the sandbox bundle's script map entry is never
released). For a plain (non-interrupt) JS error the engine stays alive and the
loop *does* continue with the next script.

## A.4 `die()` — what it sets, what it doesn't free

`SandboxEngine_die` (0x77E044), disassembly:

```
0x77e058  LDRB W8, [X0, #0x328]   ; already dead? -> return (idempotent)
0x77e05c  CBZ  W8, 0x77E074
0x77e084  STRB W9(=1), [X0, #0x328]    ; engine->dead = 1
   ... clears engine+0x6F0 string, queue map engine+0x370/0x378,
       vector engine+0x3C0/0x3C8, shared_ptr engine+0x3D8/0x3E0,
       wake shared_ptr engine+0x620/0x628 ...
   ... delegate = engine+0xD8; (*(*delegate + 152))(delegate, engine, msg)   ; onDied
```

* marks the session dead at **engine+0x328 (= +808)** — the same byte every
  entry point tests;
* notifies the host through delegate slot **+152** (`onDied`), which is what
  produces the Java log line `widget <id> stopped (n): <msg>`;
* does **not** call `JS_FreeContext` / `JS_FreeRuntime` and does not touch the
  runtime wrapper.

`JS_FreeContext` (0x16FC2DC) / `JS_FreeRuntime` (0x173789C) are called from
exactly one engine function, `twidget_JSInterruptRuntime_dtor` (0x776CEC), whose
callers are all teardown/replacement paths:
`0x77A0C4`, `0x79F12C` (host/view teardown, reached from the WidgetHost object
destroy path), `0x78C1C0` (validator context), `0x7A02E0` (validator
setup/teardown), `0x7A0BA4` (vtable slot), and `0x77A718` (boot-time runtime
replacement). **None is reachable from `die()` or from the catch path.**

## A.5 Post-`die()` host callbacks cannot run JS

Every path from the JNI entry points back into the sandbox context passes
through one of these gates:

| gate | address | behaviour when engine+808 != 0 |
|---|---|---|
| `SandboxEngine_runTask` | 0x77AB3C, check at 0x77AB50/54 | returns immediately |
| `SandboxEngine_runJob` | 0x77AF4C, check at 0x77AF70/74 | returns 1 (failure) |
| `SandboxEngine_runScripts` | 0x7849AC, `while (engine+808 == 0)` | loop never entered |
| host bridge to `__twDispatch` (`sub_7840C8`) | 0x7840C8, first insn | returns an empty result, performs **no** JS call |
| visibility callback (`sub_78A788`) | 0x78A788, whole body inside `if (engine+808 == 0)` | no-op |
| `SandboxEngine_die` | 0x77E044 | idempotent |

`JS_Eval` (0x17AFDDC) has exactly **one** caller in the whole binary
(`JS_Eval_wrapper_throwJSError`, 0x776FF0), and the only engine callers of that
wrapper are `SandboxEngine_evalScript` (0x7848D8), `SandboxEngine_start`
(0x785AD0, boot), and the validator bundle loaders (0x784578, 0x78AA9C,
0x7A02E0 — separate validator runtime/context). All `JS_Call`-style traffic
(`__twDispatch`) goes through `sub_7840C8`, which is gated.

⇒ after `die()`, **no host callback (tick / event / theme / safeArea / data /
visible / touch / hover / width / repaint / answerRequest) can evaluate any
JavaScript in the sandbox context.**

## A.6 Q4 — the "interrupted" state *is* cleared, but only after the engine is dead

This is the one non-obvious point, and it corrects the naive reading of
`js_poll_interrupts`.

`JS_GetException` is **inlined** at the top of `sub_17B08A0` (the function that
builds the JSError message, called from the JSError constructor `sub_776ED8`):

```
0x17b08bc  LDR  X8, [X0, #0x10]     ; rt = ctx->rt
0x17b08cc  LDR  X9, [X8, #0x520]    ; rt->current_stack_frame
0x17b08d0  LDR  X20, [X8, #0x508]   ; pending exception (ptr)
0x17b08d4  LDR  X21, [X8, #0x510]   ; pending exception (tag)
0x17b08dc  STR  Q0, [X10]           ; clear rt+0x508 (pending exception)
0x17b08e0  CBZ  X9, 0x17B0994       ; no JS frame -> unblock path
    ...
0x17b0994  LDRB W9, [X8, #0x518]    ; rt->fatal_latch (set by the interrupt)
0x17b0998  CBZ  W9, 0x17B08E4
0x17b099c  LDR  X9, [X8, #0x490]    ; context list
0x17b09a4  STRB WZR, [X8, #0x518]   ; <<< LATCH CLEARED
0x17b09b0  MOV  W8, #0x2710         ; 10000
0x17b09b4  STR  W8, [X9, #0x20C]    ; <<< interrupt_counter re-armed, all contexts
```

`rt+0x520` is the current JS stack-frame pointer (pushed in `JS_CallInternal`
at 0x16FD33C‑0x16FD340), so the unblock happens exactly when the embedder
retrieves the exception at top level — which is what the JSError constructor
does right after `JS_Eval` returned.

So, strictly: **yes, there is a path that clears the uncatchable "interrupted"
state** — `JS_Eval` returns → `JSError` ctor → `JS_GetException` (0x17B0994) →
latch off, counters re-armed, pending exception consumed. The runtime and the
context are left **healthy and reusable**, not wedged and not freed.

But that same unwinding continues into `afterRun_report` → `die()` (because
`rt+0x08` is still 1), so the engine never issues another eval.

## A.7 Net effect on exploitability

* Same session: no attacker JS after the double free — the engine side is dead
  (A.5) even though the QuickJS context is technically fine (A.6). There is no
  in-session heap-grooming primitive through widget JS.
* The double free therefore has to be exploitable **at the moment it happens**
  (scudo double-free check → SIGABRT; or, if that check does not fire, silent
  chunk-state corruption).
* Residual, uncontrolled activity on the corrupted heap: `JS_FreeContext` +
  `JS_FreeRuntime` at host teardown (`twidget_JSInterruptRuntime_dtor`), which
  runs the cycle collector over whatever state the double free left behind —
  not attacker-steerable.
* A cross-session angle exists only if scudo does not abort: each new widget
  session builds a fresh `JSRuntime` from the same process allocator, and the
  widget HTML/JS strings are attacker-controlled allocations. That is a
  multi-session heap-grooming scenario, far less deterministic than the
  immediate abort.

# Addendum B — device confirmation and final impact (2026-11-01 14:27)

The decisive M1 test confirms A.3 on the handset. Payload:

```html
<div id="t">start</div>
<script>globalThis.M1=1; const s='A'.repeat(4000000);
        Array.prototype.find.call(s, Number);</script>
<script>document.getElementById('t').textContent =
        (typeof M1 !== 'undefined') ? 'SAME_CTX' : 'NEW_CTX';</script>
```

Log: `14:27:11.383 ... stopped (1): CPU limit exceeded: more than 500 ms of
continuous execution (inline-script-1.js)`, widget `on screen ... running
1822 ms, session 1`. The box stayed **"start"** at 14:27:13 and 14:27:31: no
`SAME_CTX`, no `NEW_CTX`, no payload reload, no `session 2`. Script 2 never
ran. The earlier `survB` `AFTER_INTERRUPT` observation is an unreproducible
outlier and is superseded.

Correction to A.7: the double-freed block is ≤512 B, so it is a block in
QuickJS's **small-block arena** (double push on the free list), not a Scudo
`free()` — there is no Scudo double-free abort. `die()` does not free the
runtime, so the corrupted arena stays alive but no attacker JS can reach it;
new widget sessions build fresh runtime arenas. Neither in-session nor
cross-session grooming is reachable through widget JS.

Final impact: remote DoS (widget stops with "CPU limit exceeded") plus latent
arena corruption whose only crash point is host teardown/GC (lab: 3/3 SIGSEGV
in `JS_FreeRuntime → GC → js_free_shape0`; not observed on device). RCE is
not demonstrated and this bug is not an RCE path.
