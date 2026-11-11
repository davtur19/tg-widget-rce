# Widget memory limits — size / heap / limit engineering for the existing carriers

Date: 2026-11-08. Host-only (no device, no Frida, no bot, no network). Target engine:
quickjs fork **2dfeee3e** (`libtmessages.49.so`, 72889/72929) and the upstream twin
`e22ce4d`; widget model 6 MiB JS heap (`twidget_JSInterruptRuntime_ctor` →
`JS_SetMemoryLimit(rt, 6291456)`), 8 MB option field, 300 ms CPU quota.

This note is the deliverable of the `widget memory limits` subtask. It does not repeat
the new-0day hunt or the Sony/iOS device runs; it records the measured allocator/limit
model, the OOM-kill bypass, the self-calibrating fill prototype, the delivery-size
analysis, and the honest remaining gap (fake-chain layout).

---

## 0. Verdict (short)

1. **The N1 gate can be reached without any fixed big filler and without per-device
   heap constants.** A class-48 string fill discovers the limit at runtime (exact arena
   charges), and a promise job — compiled before the fill, run by the engine's job model
   after the OOM-aborted fill script — frees the measured parse cost and evaluates the N1
   source. Host: the scoped-realloc gate fires at **6 MiB** (`PUSHFAIL_HEAP
   used=6,291,656`, check free −201) and at **8 MiB** (`used=8,388,824`, check free −217)
   with the **same payload** (`n1_sc_gate_leak.html`, 2,872 raw / 1,280 zlib9).
2. **The gate alone is not the carrier.** After the failed grow the parser continues and
   pops `scopes[-1]`; the fake-parent chain only works if the FK block is the block
   immediately before the scopes block. In the sibling-script host harness the FK is not
   there, the walk reads garbage (`level=-1` then a wild level) and the process segfaults.
   The heap/limit half is solved; the same-slab FK/TD1/TD2 groom remains the open item.
3. **F2 (bare-null OOM) is dead on 2dfeee3e**, contrary to the earlier plan that used it in
   `gen_ab_only.py`. `js_throw_uncatchable()` sets `malloc_limit = 0` while it builds the
   `InternalError`, so the error object always allocates; the catchable bare-null exists
   only in upstream quickjs-ng (`e22ce4d`/`7a23d8e`). On the device every OOM is an
   `InternalError`, and the `InternalError.prototype.name` getter is the only lever.
4. **The getter bypass is verified on the host exactly as on the device**: with the getter
   the engine logs and continues (`name=x`), without it the same refused allocation kills
   (`Memory limit exceeded`). It changes the post-script decision, not the aborted
   script's control flow; a promise job scheduled before the abort still runs afterwards.
5. **Size:** the gate-reach payload is **2,588 raw / 1,270 zlib9**, i.e. inside the bot
   `sendWidget` envelope (32,768 raw, 4,096 zlib9) with 2,826 B zlib margin. The full N1
   carrier (6,618 zlib9) still needs staged delivery; the full-widget gap is now a
   delivery/endgame problem, not a heap problem.
6. **Delivery analysis:** `TelegramWidget.request` gives ≤1024 B per answer, one in
   flight, one per tap or one per 5 s in the background; `chatData`/`publicData` are
   ≤1024 B each and bot-written. 17 chunks for the 17,096 B full N1 (8 for the 7,454 B
   stage 1); the fetched strings are heap, but the self-calibrating fill runs after the
   fetch and absorbs them. This is a design option only (policy: no payload over the bot
   without explicit approval).
7. No new memory bug was needed and none was used.

### Ranked techniques

| rank | technique | size / heap numbers | universality | feasibility | risks |
|---:|---|---|---|---|---|
| 1 | **Runtime self-calibrating fill (class-48) + pre-compiled gate job + getter** | 2,588 raw / 1,270 zlib9; gate at 6 MiB and 8 MiB with the same payload; terminal free f0 ∈ (−8, 39] | no heap/device constants; limit discovered at runtime; only P/Δ source constants | host-proven up to the gate; job drain host-proven | fake-chain layout (TD1) unproven in sibling model; job drain after OOM unproven on device |
| 2 | **Two-phase fill (512 bulk + 40 fine) + gate job** | ~2,989 raw / ~1.3 KB; same gate mechanism | same | same; more moving parts | more job/script transitions → larger Δ sensitivity |
| 3 | **Staged delivery via `TelegramWidget.request`** | ≤1024 B/answer; 17 answers for 17,096 B, 8 for 7,454 B; 5 s background pacing → 40–85 s; 17 taps otherwise | payload chunks are device-agnostic; the fill absorbs the fetched heap | design only (bot policy) | one in flight; 15 s timeout; answer <1024 B; needs a cooperative bot; policy approval |
| 4 | **`chatData`/`publicData` chunks** | ≤1024 B each; bot edits the message; 2 KB per edit round | device-agnostic | design only | bot must edit; slower than requests; state visible in the chat |
| 5 | **Web Storage cache (16 KB)** | 16 KB quota (strict limits); per-widget storage | device-agnostic | design only | bot cannot write it; only a loader can persist fetched chunks |
| 6 | Fixed big filler (current N1 carriers) | 17,096/6,618 (6 MiB), 17,147/6,637 (8 MiB) | **not universal**: the same 6,074,000 filler is refused on the Sony (big1 aborts the stage) | device-proven to fail at 6 MiB | per-profile tuning, huge zlib, kills the stage before the gate |
| 7 | `gen_ab_only.py` F2 bare-null retry | 1,498 B stage | broken on 2dfeee3e | **dead** | `js_throw_uncatchable` lifts the limit; no bare null |

---

## 1. The engine/allocator model (measured)

### 1.1 The limit and the kill policy

* `JS_SetMemoryLimit(rt, 6291456)` on Android (6 MiB); the 8 MB field in the JNI options
  is the renderer/options value, not the JS heap (§10.3 of
  `new_0day_mte_specs_20261107`).
* Every allocation goes through `js_malloc_rt`:
  `if (malloc_state.malloc_size + size > malloc_limit - 1) return NULL;` then the charge
  is `js_arena_usable_size(ptr) + MALLOC_OVERHEAD`.
* A refused allocation calls `JS_ThrowOutOfMemory` → `js_throw_uncatchable` → the widget
  engine's `handleError` decides kill vs log. Without the getter it kills with
  `Memory limit exceeded (8 MB)` and freezes the last render; the canonical sandbox tests
  say the stop is caused by the refused allocation itself, not a post-eval check.

### 1.2 Allocator accounting (the part that matters for tuning)

`JS_ARENA_SLABS` (fork 2dfeee3e):

| allocation | backing | charge to `malloc_size` |
|---|---|---|
| ≤512 B small block | 64 KiB `mmap` slab, 4 KiB class pages | **exact class size** (16,24,…,512) — identical on Android/iOS/host |
| >512 B large block | `js_malloc` (Scudo primary/secondary; glibc) | allocator usable size — **rounded by the allocator** (glibc mmap ≥128 KiB → 4 KiB pages; Scudo secondary → pages) |
| `JSArenaSlab` metadata | raw `rt->mf.js_malloc` | not charged (bypasses the JS check) |
| 64 KiB slab mapping | `mmap` | not charged |

Consequences measured on the host:

* a class-48 string (`'x'.repeat(15)`, size ~40) charges exactly 48; a class-40 string
  (`'x'.repeat(7)`) charges exactly 40; class 56 (`repeat(23)`) 56; class 512
  (`repeat(479)`) 512;
* a 1,000,000-char string charges 1,003,504 on glibc (page-rounded), i.e. the large-block
  charge is not the requested size and must not be used as a fine knob.

### 1.3 The gate condition

`js_realloc_rt` fails iff

```
malloc_size + new_requested - old_usable > malloc_limit - 1
```

For the `fd->scopes` growth (`push_scope`, `JSVarScope` = 20 B, `new_size = max(count+1,
size*3/2)`):

| grow | new request | old class / usable | check delta (window) |
|---|---:|---:|---:|
| 4→6 | 120 | inline `def_scope_array` (first) | n/a (malloc) |
| 6→9 | 180 | 128 / 120 | **60** |
| 9→13 | 260 | 192 / 184 | **76** |
| 13→19 | 380 | 256?/… → class 288 / 280 | **100** |
| 19→28 | 560 | 416 / 408 | **152** |
| 28→42 and later | >512 | large block, allocator-rounded usable | ≥~250, allocator-dependent |

The window is the byte range of free heap at the grow for which the realloc fails. It is
*not* 20 B in general; the earlier "20-byte window" was the free window at the specific
6 MiB tuning (used 6,291,440 vs limit 6,291,456), not the gate's structural window.

### 1.4 F2 is dead on the shipped fork (correction)

```c
static void js_throw_uncatchable(JSContext *ctx, const char *msg)
{
    ...
    rt->malloc_state.malloc_limit = 0;      /* limit lifted */
    JS_ThrowInternalError(ctx, "%s", msg);
    rt->malloc_state.malloc_limit = limit;
}
```

The limit is lifted while the `InternalError` is created, so the error object always
allocates and the JS exception is a real `InternalError`, never `JS_NULL`. The bare-null
F2 path (`f2_helper.js`, `oom_regexp_probe3.js`, `gen_ab_only.py`'s `ERRNULL`) was
measured on upstream `e22ce4d`/`7a23d8e`, which do not lift the limit. On the device the
`gen_ab_only` retry loop will never see `ERRNULL`; its `fill()` catch will not run and the
eval will abort uncatchably. Do not ship F2-based stages for 2dfeee3e.

Host verification of the getter (the engine's policy emulated in `memprobe.c` — take the
exception, read `name`/`message`, kill on "out of memory"):

```
# lab/qjs_n1/logs/widget_limits_20261108/getter_bypass_host.txt
[<s0>] EXC name=x message=x -> LOG(continue)
[<s1>] EXC name=ReferenceError message=document is not defined -> LOG(continue)
[<s2>] EXC name=Error message=MARK ... -> LOG(continue)
# getter_control_host.txt
[<s0>] EXC name=InternalError message=out of memory -> KILL(Memory limit exceeded)
```

The Sony subagent verified the same on the device (23:41 bypass vs 23:42 control).

---

## 2. Reaching the N1 gate without a fixed filler

### 2.1 Why the 6,074,000 filler fails on the device

The device stage dies at `big1='x'.repeat(6074000)` (`S0 START`, no `S1PRE`). The charge
of a 6,074,000-char string plus the app baseline and the stage prefill exceeds 6 MiB; the
refused allocation is the filler itself, before `eval(src1)`. On the host the same filler
works because the host baseline is ~100 KB. The failure is a *baseline* mismatch, not a
bug in the chain.

### 2.2 Self-calibrating fill

Pick a filler class whose charge is exact and whose terminal *request* is small. Class 48
(`'x'.repeat(15)`: body 40, charge 48) gives, after a fill loop that allocates until the
next string is refused:

```
free after fill f0 ∈ (−8, 39]     (the refused request is 40, charge overshoot ≤ 8)
```

independent of the runtime baseline, the heap limit (6 or 8 MiB) and the platform, because
the charge is the arena class and the limit check uses the request. Container: one
pre-allocated fast array (`Array(160000).fill(0)`, 2.56 MB) — `new Array(N)` does **not**
preallocate the elements buffer in this engine; the `push`/index growth would add
page-rounded large blocks and ruin the terminal bound.

Why one array of 160k slots fits both profiles: setup ≈ 2.56 MB (array) + 0.6 MB
(O/coins/groom); at 6 MiB the fill has ~3.1 MB → aborts at ~65k strings; at 8 MiB ~5.2 MB
→ aborts at ~109k strings; both < 160k, so the fill always aborts in the same script.
A 120k array fills *completely* at 8 MiB (the gate then misses), which is why the first
8 MiB run failed.

### 2.3 The gate cannot run in the aborted script

The fill script aborts on the refused string (uncatchable), so it cannot call `eval`.
The gate must run from a *job* that was compiled before the fill:

```js
// s0 (compiled/set up before the fill)
function TAKE(k){ /* free k bytes of exact-class coins, see below */ }
function J2(){ TAKE(F); /* optional K filler */ try{eval(SRC);}catch(e){} }
// s1
Promise.resolve().then(J2);
for (var i=0;i<160000;i++) Q.A[0][i]='x'.repeat(15);   // aborts at the limit
```

Host-verified: after an OOM-aborted script the runtime's job list survives
(`JS_ExecutePendingJob` returns −1 for the aborted job, the next job runs); after an
OOM-aborted job the drain continues. This is the engine's job model, the same drain the
widget uses.

The `eval(SRC)` inside `J2` is a C-level `__JS_EvalInternal` on a pre-existing string; it
does not need a script compile at the tight heap. **Scripts cannot be used for the gate**:
a 236-byte marker script needs ~1 KB of compile space, and the fill leaves <40 B.

### 2.4 Freeing exactly P + w

The eval's parse consumes `P` bytes up to the gate. `P` is deterministic for a given
source + engine build and is measured with the `N1_TRACE` build (`P = used_at_gate −
used_at_eval_start`):

| source | bytes | P up to the 6→9 gate |
|---|---:|---:|
| `src1` (133-var leak, `poc_n1_ab_len.js`'s first source) | 638 | **6,552** |
| `src2` (1024-var AB source) | 5,098 | **97,160** (measured in the ref harness; same class sum) |

`TAKE(k)` frees `k` bytes as a combination of exact-class coins (48 from the fill array,
40/48/56 pools) — the combination exists for every multiple of 8 except a small set
(checked by brute force in the payload; 6,864 = 143×48, 6,568 = 136×48+40, 6,832 =
139×48+4×40, 7,408 = 152×48+2×56).

The free at the eval start is `f0 + F − Δ`, where `Δ` is the net heap change of the
script→job transition (the aborted script's bytecode/frame is freed; the job's frame is
allocated). On this host the clean one-phase payload has `Δ ≈ −288` (the job is *richer*
by ~288 B than the aborted script). `Δ` is source/engine-defined, not device-defined. The
`K` filler in `J2` consumes the `−Δ` slack so that

```
free_at_gate = f0 + w            (w chosen 8..20; f0 ∈ (−8,39]  ⇒  free_at_gate ∈ (0,59])
```

and the 6→9 realloc fails. Anything that changes the *code* of the scripts (adding
`__print`, `Q.i=…`, a new global in a sibling script) shifts `Δ` by hundreds of bytes and
must be re-measured — this is why the first tuned variants missed after a debug edit.

### 2.5 Host result (same payload, both profiles)

`lab/qjs_n1/widget/n1_sc_gate_leak.html` — 2,872 raw / **1,280 zlib9** (F=7000):

```
# 6 MiB
N1EVAL_START file=<input> len=638 used=6285216 lim=6291456
N1PUSH ... count=5 size=6 scope=5 used=6291400 lim=6291456
N1PUSHFAIL_HEAP ... count=6 size=6 scope=6 new_size=9 used=6291656 lim=6291456   # gate
N1POP ... level=-1 count=6 size=6 scope=0 ...                                     # fake chain read
# 8 MiB
N1EVAL_START file=<input> len=638 used=8382016 lim=8388608
N1PUSHFAIL_HEAP ... count=6 size=6 scope=6 new_size=9 used=8388824 lim=8388608   # gate
N1POP ... level=-1 ... ; N1POP ... level=-2029057543 scope=32555 ...              # wild: layout miss
```

Both runs segfault *after* the gate, in the fake-scope read: the class-128 block before
the scopes array is not the FK in this harness, so the parent chain is garbage. The heap
half is done; **the layout half is solved in §9**: create the FK in the gate job J2 right
before `eval`, tune T to `scopes_block − 7`; the same payload then hits `TLEN=134` at
both 6 and 8 MiB with no segfault.

Baseline matrix (earlier tuned variant, exact 56-B baseline blocks, 6 MiB):

```
Nb baseline blocks: 0 1 2 3 4 5 20 40 80
free at eval start: 6607 6567 6591 6567 6591 6599 6583 6607 6607
gate free:            55   15   39   15   39   47   31   55   55     (all in (0,60))
```

A *separate sibling script* adding one global (`var BASE=...`) shifted the gate by ~296 B
(global-object shape/property growth and an extra eval task). The payload must keep its
script/global structure fixed; device-side baseline allocations are absorbed by the fill.

---

## 3. Size and staged delivery

### 3.1 Carrier sizes (measured)

| payload | raw | zlib9 | 4 KiB bot limit |
|---|---:|---:|---|
| N1 sibling full (6 MiB) | 17,096 | 6,618 | no |
| N1 sibling full + getter (6 MiB) | 17,481 | 6,851 | no |
| N1 probe (6 MiB) | 7,679 | 2,966 | yes |
| N1 probe (8 MiB) | 7,732 | 2,987 | yes |
| parser c2560s final (72929) | 9,946 | 4,023 | yes (73 B margin) |
| v7 plaintext CEC | 7,460 | 3,056 | yes |
| **self-calibrating leak gate (this note)** | **2,588** | **1,270** | **yes (2,826 B margin)** |
| self-calibrating AB gate (experimental) | 6,960 | 3,094 | yes (1,002 B margin) |

The self-calibrating gate replaces the 6,074,000-byte filler and its profile constants;
the 6,618 zlib full N1 could shrink by roughly the filler/duplicate-stage difference once
the AB layout is fixed — the gate-reach payload alone is 1,270 zlib.

### 3.2 Externalizing the bulk (design analysis only)

Bot answer channel (`TelegramWidget.request`):

* `data` 1–64 B; the bot's answer `result` ≤1024 B (UTF-8, no NUL); `null` allowed.
* one request in flight; a second rejects `BUSY`; one request per tap (shared with
  `openLink`/`copyText`), or one per 5 s in the background while the widget is visible;
  15 s timeout; `INVALID_ANSWER` if the answer breaks the limits.
* chunks needed: 17,096 B → 17 answers; stage 1 (7,454 B) → 8; the 5,098 B AB source → 5.
* pacing: background 5 s → 85 s for 17, 40 s for 8; taps otherwise.
* heap: each answer is a JS string; the concatenated source is live at the eval
  (~17 KB), plus the eval reads it as a source string. The self-calibrating fill runs
  *after* the fetch, so the added heap is absorbed exactly; only `P` grows with the
  source length (re-measure it).
* universality: chunk contents are device-agnostic; the loader is a fixed small payload;
  the bot is the only variable.

`chatData`/`publicData` channel:

* ≤1024 B each (UTF-8, no NUL), bot-written by editing the message; updates arrive as
  `chatDataChanged`/`publicDataChanged` without restarting the page; forwards do not
  carry `chatData`.
* 2 KB per edit round (both fields), so 17 KB needs ≥9 bot edits (or more if edits lag);
  slower than requests, but no tap requirements and works in groups.
* the state is visible in the message; no secrets.

Web Storage: 16 KB per widget (strict limits), per-origin/per-forward; the bot cannot
write it; only a loader can cache fetched chunks there across re-renders. Useful for a
retry/patience design, not as the primary channel.

### 3.3 Recommendation

The small universal loader = getter + self-calibrating fill + gate job (this prototype).
If the endgame must be fetched, use `request` chunks with 1024 B answers (8 chunks for the
N1 stage 1) or `publicData` chunks; fetch *before* the fill so the fill absorbs the heap.
None of this is executed on the device without the orchestrator's approval.

---

## 4. Universality assessment

| element | device-independent? | notes |
|---|---|---|
| getter bypass | yes | `InternalError.prototype.name` getter + the engine's name/message read; verified on Sony 72929 and host |
| fill accounting | yes | class charges are the arena table, identical on Android/iOS; large-block rounding is bypassed by the class-48 fill |
| heap limit discovery | yes | the fill terminates at the actual limit; 6/8 MiB and any baseline |
| gate free window | yes (window), **no** (the exact Δ/P constants) | `P` and `Δ` depend on the source + engine build; measure per source and per fork snapshot |
| fake-chain layout (TD1/TD2) | **no** | needs the FK block immediately before the scopes class block; same-slab grooming is the open item (host harness currently misses) |
| parser c2560s Scudo geometry | no | Scudo class map per allocator/page size (existing knowledge) |
| v7 resolver | yes | runtime ELF/GNU-hash resolution (existing knowledge) |

The self-calibrating fill removes the *heap* universality problem entirely. The remaining
non-universal parts are the source-derived `P`/`Δ` (same for 72889/72929; re-measure for a
different fork snapshot such as iOS quickjs-ng) and the fake-chain layout.

---

## 5. Device probe plan (non-destructive first)

The orchestrator owns the device; these are host-built payloads and expectations.

1. **Calibration probe (no exploit):** fill + job that frees `P_trivial + w` and evals
   `Q.r=1;`, marker `R=0/1` in `#v`. Host expectation: `R=1` when the free at the eval
   start ≥ the trivial parse's P. On the device this proves the fill, the job drain after
   an OOM and the getter with zero memory-safety risk. If `R=0`, the job drain after an
   aborted script does not happen on the device; stop and re-plan.
2. **Gate probe (this prototype):** `n1_sc_gate_leak.html` via the DB harness. Expect:
   * `TLEN=134 LEAK=<16 hex>` — gate + layout hit (the T.len write landed);
   * `TLEN=95 LEAK=NaN…` — gate fired but the FK layout missed (heap half confirmed, layout
     retune next);
   * a `Widget stopped`/kill line — the getter or the job model differs; the payload kills
     the stage before the gate.
   * **Risk:** the fake-chain walk on a layout miss writes at a garbage level; the host
     run segfaulted after the gate. Treat this probe as potentially destructive to the
     widget thread (not the app process on Android; the widget runs in a worker).
3. Only after a `TLEN=134` or a controlled `ABLEN=1024` should the trigger/endgame be
   appended; the endgame needs the app-specific `JS_DEF_FREE`/`free` resolution (v7
   runtime ELF resolver is the universal choice).

---

## 6. Files

```
notes/widget_memory_limits_20261108.md                  this note
notes/LEMMALOG_FACTS_widget_memory_limits_20261108.txt  facts for the orchestrator
lab/qjs_n1/widget/n1_sc_gate_leak.html                  2,872 raw / 1,280 zlib9 (leak gate, TLEN=134 at 6/8 MiB)
lab/qjs_n1/widget/n1_sc_gate_ab_experimental.html       6,960 raw / 3,094 zlib9 (AB gate, host crash)
lab/qjs_n1/lab/gen_sc_gate.py                           one-phase generator (leak/ab)
lab/qjs_n1/lab/gen_sc_job.py                            two-phase generator (bulk 512 + fine 40)
lab/qjs_n1/lab/gen_sc_one.py                            one-phase experiment generator + baselines
lab/qjs_n1/lab/gen_sc_fill.py                           earlier ref/fill sweep generator
lab/qjs_n1/lab/memprobe.c                               sibling harness + engine policy + job drain + __used/__print
lab/qjs_n1/build/memprobe[_trace]                       host builds (2dfeee3e and n1_fork trace src)
lab/qjs_n1/logs/widget_limits_20261108/gate_6m_trace.txt  gate at 6 MiB + fake-chain read
lab/qjs_n1/logs/widget_limits_20261108/gate_8m_trace.txt  gate at 8 MiB
lab/qjs_n1/logs/widget_limits_20261108/getter_bypass_host.txt / getter_control_host.txt
```

Existing evidence was not deleted. The n1_fork trace source was patched with an
`N1EVAL_START` line (print at `__JS_EvalInternal` entry) to measure `P`; the patch is
cosmetic (fprintf, no heap allocations).

## 7. Honest negatives

* The gate-reach payload is **not** a full carrier: the fake-chain layout (FK immediately
  before the scopes class-128 block) is still missing in the sibling model; the host
  segfaults after the gate. Do not claim a device hit until `TLEN=134`/`ABLEN=1024`.
* The AB variant (`n1_sc_gate_ab_experimental.html`) crashes in the host parse at
  ~6,195,184 used (97 KB below the limit) before the gate; it is parked, not delivered.
* `P`/`Δ` are source/engine constants; a different fork snapshot (iOS quickjs-ng) must be
  re-measured. The getter itself is shim-dependent (the iOS `qjs_take_exception_description`
  path is the same shape; not device-verified here).
* The class-48 fill needs a 2.56 MB pre-allocated array; on a device whose widget-runtime
  baseline is >3.5 MB the array allocation itself would fail. The widget baseline observed
  on the Sony is ≪1 MB (the big filler failed only because of the stage prefill), but this
  bound is inferred, not measured on the device.
* One 1 MiB *sibling script* baseline shifted the gate by ~296 B (global-object shape);
  a device whose sandbox pre-populates globals differently can shift the same constants.
  If the first device run misses, the remedy is a later (wider) gate or a small F sweep,
  not a blind big filler.
* No payload was sent to the bot; the staged-delivery option is analysis only.

---

## 8. Same-payload N1 ≤4,096 zlib9 with the v7 universal endgame (2026-11-08 late)

The task: one HTML for Sony 72929 (6 MiB, MTE off, DB delivery) and Pixel 9 (8 MB
option, MTE on, bot `sendWidget` ⇒ zlib9 ≤4,096), carrying stage A + trigger + v7-style
universal endgame + getter, with the self-calibrating gate.

### 8.1 Measured sizes of the components

| component | raw | zlib9 | notes |
|---|---:|---:|---|
| self-calibrating **gate** (leak target, this note) | 2,872 | 1,280 | gate+layout hit at 6/8 MiB (`TLEN=134`); §9 |
| self-calibrating **AB stage A** (experimental) | 6,960 | 3,094 | of which the 5,098-B 1024-var source alone is **1,997** zlib |
| N1 **trigger** (`poc/trigger_re.js`, #1827 fake bytecode) | 1,899 | 939 | the same primitive v7 uses |
| N1 host **endgame** (`endg_sib.js`, build constants) | 7,659 | 2,820 | `JS_DEF_FREE=0x45940`, `FREE_GOT=0x109008`, `SYSTEM_DELTA=-0x4ff30` |
| **v7 whole minimal payload** (`device_payload_v7_cec.min.js`) | 7,299 | **2,945** | includes its own primitive + trigger + universal ELF resolver |
| v7 whole loader HTML (`loader_v7_plain_text_cec.html`) | 7,460 | 3,056 | proven Sony 72889/72929 and Pixel 5511 |

Arithmetic for the text-source N1+v7-endgame combination:

```
AB stage A (3,094) + trigger (939) + universal endgame (≈1,500–2,820)
    ≈ 5,533–6,853 zlib9   >  4,096
```

The universal endgame replaces the 2,820-zlib host endgame's constants with the v7
PLT/GOT + ELF-dynsym resolver (the v7 payload's whole resolver section is smaller than the
host endgame because the latter carries diagnostics and fixed-address fallbacks; the
resolver alone is ≈1.2–1.6 KB zlib). Even at the optimistic 1,500, the sum is ~5.5 KB.

**Verdict on the literal request: not achievable in one HTML with the text-source AB
stage A.** The dominant cost is the N1 stage A source text (1,997 zlib for the 1024-var
catch source alone).

### 8.2 The nearest feasible form (still host-only)

1. **Runtime-built stage A source.** `gen_ab_only.py` builds the 1024-name source from a
   name table at runtime: the generated stage is **1,499 raw / 723 zlib9** (measured
   today). Replacing the 1,997-zlib text source with this builder inside the
   self-calibrating harness gives `stage A ≈ 723 + 1,097 (harness) = ≈1,820 zlib9`
   (the harness share is the AB payload 3,094 minus the 1,997-zlib source). Combination:
   `stage A ≈1,820 + trigger 939 + universal resolver 1,200–1,600 = 3,959–4,359 zlib9`
   → **fits 4,096 only if the resolver is ≤1,337 zlib and a little compaction is done**.
   The self-calibrating fill absorbs the builder's table/atoms/parse heap; `P` must be
   re-measured. This is the only N1 path that can fit the bot limit; it is not built yet
   because the fake-chain layout (TD1/TD2) is still open (see §2.5).
2. **v7 as the single universal payload.** `poc/loader_v7_plain_text_cec.html` is 3,056
   zlib9, already proven cross-build on the Sony (proofs 5489/5492/5493) and MTE-on on
   the Pixel (message 5511). It is the reference and the safest answer to "one payload
   for both devices" *today*: its ctx/arena primitive is same-tag (tag-0 arena), and its
   endgame is the universal ELF resolver. The N1 same-tag variant adds no proven device
   capability that v7 lacks; it is a parallel carrier.
3. **Staged loader ≤4,096.** A 1.2–2.0 KB loader (getter + self-calibrating fill + gate)
   fetches the trigger/endgame via `TelegramWidget.request` (1024 B answers) at runtime.
   The fetched strings are absorbed by the fill; the bot limit is met; policy approval is
   required. This preserves the "same payload" property because the loader is the HTML.

### 8.3 What is build/device-specific and cannot be made universal

| constant | where | why |
|---|---|---|
| `TD1`/`TD2` (fake-parent level) | stage A | depends on the physical distance `scopes − target`; the host uses a cross-slab −11449, the device deltas are 10²–10⁸ B. Needs same-64 KiB-slab grooming (FK in the block before the scopes, victim page after) — designed in §10.5 of `new_0day_mte_specs_20261107`, not yet host-proven. |
| `P`, `Δ` | stage A gate | source + engine-build constants (same for 72889/72929; re-measure for another fork snapshot / iOS quickjs-ng) |
| endgame `js_free` location | endgame | **solved** by the v7 runtime PLT/GOT + ELF dynsym resolver; the old `JS_DEF_FREE`/`FREE_GOT`/`SYSTEM_DELTA` constants must be removed |
| `system` address | endgame | solved by the libc GNU/SysV ELF resolver (same v7 code) |
| MTE | whole chain | the N1 write and the AB view are tag-0 arena; the endgame must keep 64-bit pointers whole (v7 rule) and never tag-strip a live pointer. v7 is the MTE-on-proven reference on the Pixel. |

### 8.4 Device plan for the same-payload requirement

1. Sony DB: deliver `n1_sc_gate_leak.html` (1,270 zlib) → gate/layout datum
   (`TLEN=134` or `TLEN=95`); then the compact stage A + trigger + v7 endgame if/when the
   layout is fixed. The Sony path can carry the DB-only sizes.
2. Pixel bot: the same HTML must be ≤4,096 zlib. If the final N1 combination is over
   (as the text-source form is), the bot carries either the v7 loader (3,056) or the
   staged loader; the orchestrator decides with the policy owner.
3. Do not send any payload to the bot without explicit approval.

### 8.5 Honest status

* The heap half (6/8 MiB, self-calibrating, getter, job drain) is host-proven up to the
  gate.
* The fake-chain layout (TD1/TD2) is **not** solved; the host currently segfaults after
  the gate. No device claim.
* The one-HTML N1 + trigger + universal endgame at ≤4,096 zlib is **not feasible with the
  text-source stage A** (≈5.5–6.9 KB). The nearest fits are the runtime-built compact
  stage A (≈3.4 KB estimated, needs the layout fix) and the already-proven v7 loader
  (3,056 zlib).

---

## 9. Fake-chain layout solved for the leak gate (2026-11-08 late)

### 9.1 The fix

The scopes block is allocated by the *eval's* 4→6 grow; the class-128 arena is shared with
the groom. The decisive observation from the `n1_slot_of`/`N1C128` trace: the *fill script's
compile* allocates a 6-entry scopes array (req 120) in the same class-128 arena, and the
eval's own pre-FK allocations (one req-120 block) sit between the old FK and the scopes.
The fix is not more fillers, it is **allocating the FK in the gate job J2, after TAKE and
immediately before `eval(SRC)`**:

```js
function J2(){
  TAKE(F);
  for(var i=0;i<6;i++)Q.K[i]='x'.repeat(15);   // delta (script-bytecode) filler
  G.push(String.fromCharCode(19200,...,19246)); // the FK, last class-128 alloc
  try{eval(SRC);}catch(e){}
}
```

The FK then takes the block the aborted fill script just freed (or the next free block),
and the eval's 4→6 grow takes the next one: **FK and scopes are adjacent by
construction**. The only remaining condition is the physical block distance to T:
`target(level −45) = scopes − 896 = 7 blocks before the scopes block`, so T must be at
`scopes_block − 7`. With the 60-string groom (31 + 23 + T + Symbol + 2 'c' fillers) and
the FK moved to J2, the measured map is:

```
T           block 7   (arena A2, slot 5 of the 64 KiB slab)
fill compile block 11
J2 req120   block 12
FK          block 13
scopes      block 14    (4->6 grow)
next grow   block 15
=> target = block 7 = T.len      hit
```

The 2 remaining 'c' fillers (instead of 4) are what shift the fill compile and the FK
down by two blocks so that `scopes − 7 = T`. The old 4-filler groom missed by two blocks.

### 9.2 Result (same payload, both profiles)

`lab/qjs_n1/widget/n1_sc_gate_leak.html` — **2,872 raw / 1,280 zlib9**:

```
6 MiB: N1PUSHFAIL_HEAP ... level=-45 count=6 size=6 scope=6 new_size=9 used=6291576
       N1ADD ... level=-45 idx=134 target=0x...23b8
       TLEN=134 LEAK=58602a49717f0000      (no segfault)
8 MiB: N1PUSHFAIL_HEAP ... level=-45 ... used=8388744
       N1ADD ... level=-45 idx=134 target=0x...83b8
       TLEN=134 LEAK=58c0d98fe37f0000      (no segfault)
```

Logs: `lab/qjs_n1/logs/widget_limits_20261108/gate_6m_trace.txt` / `gate_8m_trace.txt`.
The gate+layout is now host-proven on both profiles with one payload. `F = 7000`
(`TAKE` frees 145×48 + 40 = 7000; `P(src1)=6,552`, `w` and the Δ filler as above).

### 9.3 AB stage status (the next blocker, measured)

The same J2-FK technique was applied to the AB variant (`gen_ab_gate.py`, src2, ND=1).
The AB struct and the eval scopes land in **different 64 KiB slabs**:

```
AB struct 0x7f3db41a0238 bs=64  idx=8 ar=0x7f3db41a0000 slab=0x563cdbc17a80 slot=4
scopes    0x7f3db3e89838 bs=128 idx=16 ar=0x7f3db3e89000 slab=0x563cdbc18450 slot=5
delta = 3,238,400 (0x316a00); (delta-4) % 20 = 16, TD2 = 161,919 after ND=2
```

That is a cross-slab distance, i.e. exactly the host-layout-specific TD2 the old chain
had (and the device deltas were 10²–10⁸ B). For a universal AB stage the class-64 page and
the class-128 page must be forced into the **same 64 KiB slab** so that
`TD2 = (AB − scopes − 4)/20` is a small constant (the §10.5 target: victim block 10,
scopes block 15, TD2 = −269). That groom is the remaining work; it needs the class-page
slots of one slab controlled (fill the 16 slots with class pages, put the class-64 victim
page before the class-128 page, choose the AB block with ND for the 20-byte grid).

The same-payload ≤4,096 arithmetic of §8 is unchanged: the leak gate (1,280 zlib) is
functional; the AB text stage (3,094) + trigger (939) + universal resolver (1.2–1.6 KB) is
5.2–5.6 KB; only the runtime-built compact stage A (≈1.8 KB) can fit, and it needs the
same-slab AB groom.

---

## 10. Device result: the J2-FK host layout does not transfer (Sony, 2026-11-08)

### 10.1 What happened

`n1_sc_gate_leak.html` (2,872 / 1,280, F=7000) was delivered on the Sony via DB. The app
died:

```
F libc: Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x6cde3efe38
        in tid ... (widget.sandbox), process org.telegram.messenger.beta
```

No `TLEN=134`. The earlier 2,588/1,270 probe was safe: gate fired, `TLEN=95 LEAK=NaN…`,
app alive. So on the device: getter + fill + job + gate are proven; the **write target**
is what differs.

### 10.2 Why it crashed (fault-address analysis)

The fake chain's write is `scopes + 20*L + 4`; for the leak chain `L = −45` →
`target = scopes − 896`. The fault `0x6cde3efe38` is consistent with `scopes ≈
0x6cde3f01b8`, i.e. `scopes − 896` fell ~0x1c8 bytes **before** the slab/page mapping
(`0x6cde3f0000`). That means on the Sony the scopes block sat at a **low block of the
first 4 KiB slot of its 64 KiB slab** (block ≲ 6), while the host run had it at block 14
of slot 5. The host's `T = scopes_block − 7` arithmetic only holds when the scopes block
is ≥ 7; when it is 0..6, `scopes − 896` leaves the slab and the write is unmapped.

The crash also shows the J2-FK adjacency *did* happen on the device (otherwise the walk
would have read garbage and either missed with `LEAK=NaN` like the old probe, or faulted at
a different level); the failure is the **slab slot / block index**, not the FK order.

### 10.3 Safe calibration design (no wild write on any miss)

1. **Gate-only safe probe (no fake chain).** Use a *valid* catch source with the same
   133-var shape and sweep `F` across sibling jobs; each job TAKEs `F_i` and evals the
   source, setting `Q.ok=1` if the eval returns. A miss completes (`Q.ok=1`); the gate
   (failed scoped realloc) aborts the eval (`Q.ok=0`) like an early OOM. The first `F`
   where `Q.ok` flips 0→1 is the device gate boundary; the attempt just below it is the
   gate. No `scopes[-1]` walk, no write.
2. **Level −1 read-back probe.** Fill the whole class-128 arena with controlled marker
   strings (all G fillers carry a known 4-byte tag at block offset 108); chain the fake
   parents to stay at −1; the add writes `idx` at `scopes − 16` = the previous block's
   tail (or the arena header). Read every G string back in JS and report which one changed
   and at which char → identifies the block before the scopes and therefore the scopes
   block index (safe: the target is inside the same page/header for any k).
   Do **not** run this if the block before the scopes is not one of the G strings (the
   read at `scopes[-1].parent` would be an arena-header fragment); the probe's design must
   make the arena full of G strings first (the fill already allocates class-128 strings
   in the same arena only if the groom is sized to it — verify with a slot trace first).
3. **Guarded −45 leak only after (1)+(2):** push the scopes page to a **later slot of the
   slab** by allocating class-page fillers before the eval (the §10.5 recipe) so
   `scopes − 896` stays inside the 64 KiB slab for every block index; then the −45 chain
   is safe and `TLEN=134` is the hit.

### 10.4 Status

* Device: gate/getter/job proven; the host J2-FK layout is **not** device-portable.
* No Pixel run until the Sony safe probe reports the layout and a safe hit.
* The AB same-slab class-page groom (§9.3) and the compact stage A + trigger + v7
  resolver ≤4,096 plan are unchanged; the class-page placement is now the single blocker
  for both the leak and the AB target.

---

## 11. Safe-probe ladder: probe 1 host result (negative) and the corrected design

Probe 1 was built (`lab/qjs_n1/lab/gen_gate_safe.py`, 3,009 raw / 1,100 zlib9): the
133-var source with the final `catch(e` closed to `catch(e){}`, the self-calibrating fill,
and 31 jobs (J0 frees 6000, then 30 jobs free 40 each, each `eval` sets `Q.ok=1` on
return; marker `OK/K/F`).

**Host result: the probe is NOT safe.** 6 MiB, F0=6000:

```
[<s1>] used_before=3659448 used_after=6289984
[<s1>] EXC name=x message=x -> LOG(continue)
Segmentation fault (rc=139)
```

The valid source still crashes: the failed `push_scope` leaves the scope bookkeeping
inconsistent, and the parser's error path (`close_scopes`/`pop_scope`) walks into
`scopes[-1]` regardless of whether the final catch is terminated. "Make the source
valid" does not remove the fake-chain walk; it only changes when the parse fails.

**Consequence:** probe 1 in the "no walk" form cannot be made safe with this bug. The
safe ladder must instead guarantee that the *parent values are controlled and the target
is mapped*, i.e.:
* probe 2 (level −1/−2 chain + read-back of the class-128 fillers) is the correct first
  device step: keep the level inside the same page/arena header;
* probe 3 (−45 leak) only after probe 2 reports the block index and the class-page slot,
  with the scopes page pushed to a later slab slot so `scopes − 896` is mapped.

Do not deliver probe 1 to the Sony in this form. `gen_gate_safe.py` is kept as the
negative artifact. The old 2,588/1,270 probe remains the only empirically safe gate
datum on the Sony (`TLEN=95 LEAK=NaN`).

---

## 12. Probe 2 — level −1 self-loop write-back (host-validated, 2026-11-08 late)

### 12.1 Construction

`lab/qjs_n1/widget/n1_p2_marker_selfloop.html` — **2,695 raw / 1,261 zlib9**,
generated by `lab/qjs_n1/lab/gen_p23.py p2 6720 200 2 0 0 <out> /tmp/opencode/src1.js 1`.

The whole class-128 arena is filled with **wide marker strings** (47 code units,
`String.fromCharCode`, request 118 → class 128). Each marker carries, at the
object offsets the negative scope walk reads:

| block off | object off | chars | content |
|---:|---:|---|---|
| 32 | 24 | 0.. | id magic `0xF1xx,0xF1FF` |
| 108 | 100 | 38,39 | 4-byte TAG `0x7Axx,0x7AFF` |
| 116 | 108 | 42,43 | `scopes[-1].parent = -1` (`0xFFFF,0xFFFF`) |
| 120 | 112 | 44,45 | write watch `0x5A5A,0x5A5A` |

J2 TAKEs `F=6720` bytes of exact-class coins (48/40/56), pops the **last two
markers** (creating a two-block consecutive free run), then allocates **one
guard marker**, then evals the 133-var N1 source.

Because the free list after the two pops is `b-1 -> b`, the guard takes `b-1`
and the eval's 4→6 scopes grow takes `b`; the block before the scopes is the
guard (or a marker) in every layout where `b != 0`. The self-loop chain
(`scopes[-1].parent = -1` in every marker and in the guard) keeps *all*
negative pops at level −1, so the final `add_scope_var` writes `idx=134` at
`&scopes[-1].first = scopes − 16` = the predecessor block offset 120 = the
predecessor object offset 112 = chars 44..45. No wild address is ever formed.

### 12.2 Host result (6 and 8 MiB, same payload)

```
6 MiB: N1PUSHFAIL_HEAP ... level=-1 count=6 size=6 scope=6 new_size=9 used=6291592
       N1POP ... level=-1 ... scope=-1    (x5, stays at -1)
       N1ADD ... level=-1 idx=134 target=0x...4e28   (== scopes-16)
       P2 NB=1 BAD=198:86, N=199
8 MiB: identical marker report
```

Repetitions: 30/30 hits at 6 MiB and 30/30 at 8 MiB with ASLR enabled;
40/40 + 40/40 with `setarch -R` (ASLR off). The changed marker is the guard
(`G[198]`), i.e. *the block immediately before the scopes*. Slot trace:
`scopes ... bs=128 idx=28 ar=0x...4000 slot=9` (27/28 depending on run);
the predecessor block is index 27 → the scopes block index is **28** in this
layout (the trace in an earlier run had 27/26; the block index is run-dependent
by one but the predecessor is always the guard). Logs: `logs/widget_limits_20261108/p2_6m_trace.txt`, `p2_8m_trace.txt`.

### 12.3 Block-index sweep and the one residual hazard

With the guard, sweeping `N = 180..220` (three runs each, trace build) gives a
hit for every N except **N=203**, which crashes 3/3: the guard is allocated at
block 30 of a page, the scopes is therefore block 0 of the next 4 KiB page,
and the first negative pop reads the *arena header* (`ar+36` = `link.prev`
high half) instead of a marker. This is the **only** unsafe configuration:
`b = 0` (the marker run ends exactly at a page boundary).

The residual is structural: any fixed scheme that frees a run ending at block
`b` puts the scopes at block `b`, so a residue `b = 0 (mod 31)` always exists.
It is ~1/31 under a uniform residue; 1 crash was observed in ~70 ASLR-enabled
runs of the delivered N=200, 0/80 with ASLR off. The delivered N=200 is in the
safe residue on the host. **The device residue is not measurable from JS**;
if the Sony run crashes, retry with `N+1` (the residue shifts by one block).

## 13. Probe 3 — guarded −45 leak (host-validated, 2026-11-08 late)

### 13.1 Construction

`lab/qjs_n1/widget/n1_p3_marker_leak.html` — **2,660 raw / 1,253 zlib9**, the
*identical* construction as probe 2 (`gen_p23.py p3 6720 200 2 0 0 ... 1`) with
only the four encoded parents changed to the leak chain:

```
object 108 (block 116) -> -2      scopes[-1].parent
object  88 (block  96) -> -3      scopes[-2].parent
object  68 (block  76) -> -4      scopes[-3].parent
object  48 (block  56) -> -45     scopes[-4].parent
```

The chain is walked by the same five pops; the final add writes `idx=134` at
`scopes − 896` = the `JSString.len` (object offset 0) of the block **7 before
the scopes**. For a scopes block index ≥ 7 the target is a marker in the same
4 KiB page; for index < 7 it is the user pointer of block `s+25` in the next
4 KiB slot (mapped inside the same 64 KiB slab when the page is at slot ≥ 1).

### 13.2 Host result (6 and 8 MiB, same payload)

```
6 MiB: N1POP level=-1,-2,-3,-4,-45 (chain controlled)
       N1ADD level=-45 idx=134 target=0x...3ab8
       P3 NB=1 BAD=192:134, N=199
8 MiB: identical marker report
```

`G[192]` is `G[198] − 6`, i.e. exactly seven 128-byte blocks before the scopes.
Because probe 2 and probe 3 use the same prefix, F, N, KF and guard, the
predecessor measured by probe 2 transfers: probe 2's changed marker is the
guard; probe 3's changed marker is six positions earlier. Repetitions: 6/6 +
6/6, no crash. Logs: `p3_6m_trace.txt`, `p3_8m_trace.txt`.

Slot trace for the delivered construction: the class-128 marker pages occupy
slots 4..9 of one 64 KiB slab (`N1NEWARENA cls=14 slab=0x...2450 slot=4..9`),
the scopes page is slot 9 (the last page of the run), so its previous slot 8 is
itself a full marker page. If the scopes block index were < 7 the target would
land on a marker at block `s+25` of slot 8 — a hit as well.

### 13.3 Device sequence (Sony 72929, DB delivery)

1. Run `n1_p2_marker_selfloop.html` (1,261 zlib). Expected: `P2 NB=1
   BAD=<guard index>:86` in the widget text and in the thrown marker, app
   alive. This proves the guard/scopes adjacency and the −1 containment.
2. If and only if that is safe, run `n1_p3_marker_leak.html` (1,253 zlib).
   Expected: `P3 NB=1 BAD=<index>:134`, i.e. `TLEN=134` on a marker, app
   alive. A `NB=0` (no marker changed, no crash) is a mapped miss: the target
   fell into the previous 4 KiB slot that was not a marker page — report it
   and do not retry blind.
3. Only after a safe Sony `TLEN=134` does the Pixel (MTE-on, bot) run happen
   with the same HTML. Both payloads are below the 4,096 zlib bot limit
   (1,261 and 1,253).

### 13.4 What is still open

* The AB same-slab class-page groom (§9.3/§14) is still not host-proven.
* The k=0 residual (§12.3) applies to probe 2; probe 3 inherits it (the same
  free-run construction).
* No device claim is made here. The Sony sequence above is the first device
  validation of the guard construction.

---

## 14. AB same-slab groom — measured geometry and the exact TD2 recipe (2026-11-08 late)

### 14.1 Measured geometry (today, host trace, old cross-slab groom)

`gen_ab_gate.py -269 97200 1` under the trace build:

```
N1ABUF abuf=0x7f7294a8d238 data=0x7f7294791308 len=64
N1ABUF_STRUCT ... bs=64 idx=8 ar=0x7f7294a8d000 slab=0x565369808a80 slot=4
N1SCOPES 0x7f7294776838 bs=128 idx=16 ar=0x7f7294776000 slab=0x565369809450 slot=5
ABLEN=64 VIEW=64        (miss, as expected: different slabs)
```

The AB struct is a **class-64** block (`idx=8`, user = `ar+56+64*8 = ar+568`), the
scopes a **class-128** block (`idx=16`, user = `ar+56+128*16 = ar+2104`). The
two pages are in different 64 KiB slabs (0x...8a80 vs 0x...9450), distance
0x317000 (3.2 MB) — the old cross-slab layout.

### 14.2 Same-slab TD2 = −269 recipe (arithmetic)

Put the class-64 victim page at slab slot `j` and the class-128 scopes page at
slot `j+1` of the same 64 KiB slab, victim page **before** the scopes page:

```
AB      = P + 56 + 64*a          (class-64 block a)
scopes  = P + 4096 + 56 + 128*s  (class-128 block s, next slot)
AB - scopes = 64*a - 128*s - 4096
TD2 = (AB - scopes - 4)/20
```

The 20-byte grid requires `a - 2s ≡ 0 (mod 5)`, and `TD2 = -269` gives
`a - 2s = -20`. Choose **s = 16, a = 12**: TD2 = (768 - 2048 - 4100)/20 =
**-269** exactly. That is the §10.5 target (victim block 12 of the class-64
page, scopes block 16 of the class-128 page immediately above it).

So the same-slab groom must:
1. allocate the class-64 page immediately before the class-128 scopes page so
   they take consecutive slots of one slab (the probe-3 trace already shows the
   slab allocator handing out consecutive slots to a page run: class-128 pages
   at slots 4..9 of `slab=0x...2450`);
2. place `AB` at **class-64 block 12** (7 dummies after an 5-block prefill, or
   the equivalent trace-tuned count; the exact dummy count must be read from
   the slot trace);
3. place the scopes at **class-128 block 16** with the guard construction
   (TAKE/pop-run/guard);
4. use `TD2=-269`.

This is **not host-validated yet** (no `ABLEN=1024` with TD2=-269 in this
session). The next experiment is a J2 that allocates the class-64 page + AB at
block 12 *immediately before* the class-128 guard/eval, then reads
`N1ABUF_STRUCT`/`N1SCOPES` from the trace and checks
`(AB - scopes - 4)/20 == -269`.

### 14.3 Size arithmetic for the same-payload ≤4,096 zlib9 target

| component | raw | zlib9 | status |
|---|---:|---:|---|
| marker gate harness (probe 3, measured today) | 2,660 | 1,253 | host-proven |
| compact AB stage A (`gen_ab_only` runtime builder) | 1,499 | 723 | generator exists, F2 path dead -> needs the gate job |
| N1 trigger (`trigger_re.js`) | 1,899 | 939 | host-proven (old endgame) |
| v7 universal ELF dynsym endgame | ~2.0-2.6 K | ~1.0-1.4 K | proven in v7 loader (3,056 zlib total) |

`1,253 + 723 + 939 + 1,000..1,400 = 3,915..4,315` zlib9. The sum crosses
4,096 at the upper end of the endgame; the fit needs the endgame at ≤1,180
zlib *and* the marker harness trimmed by ~100 zlib (the AB groom replaces the
marker chain, so the harness share shrinks). This is the same arithmetic as F10
with the measured probe-3 harness; it is a plan, not a delivered payload.

### 14.4 First same-slab experiment (negative, measured)

`lab/qjs_n1/lab/gen_ab_same.py 6720 200 12 16 -269` (ABF=12 class-64 dummies,
GM=16 class-128 guard markers) under the trace build:

```
N1ABUF_STRUCT ... bs=64 idx=19 ar=0x7f3feb6c1000 slab=0x561d8d7dca80 slot=4
N1SCOPES      ... bs=128 idx=29 ar=0x7f3feb3ae000 slab=0x561d8d7dd450 slot=9
ABLEN=64 VIEW=64
```

The 16 guards did **not** create a new class-128 page: they filled the free
tail of the last marker page (the scopes landed at idx=29 of that page), so the
victim page (slot 4 of slab `...ca80`) and the scopes page (slot 9 of slab
`...d450`) stayed in different slabs. The same-slab geometry therefore needs
GM large enough to exhaust every non-full class-128 page (≤31 blocks) and the
scopes block placed at 16 in the *fresh* page, i.e. `GM ≡ 16 - start (mod 31)`.
`start` is exactly the residue probe 3 measures, so the AB payload must be
built after the Sony probe 3 result, not before. This is the concrete reason
the AB stage is sequenced last.

The closest host-validated AB result remains the old cross-slab `ABLEN=1024`
(TD2=-11449) from the earlier sessions; the same-slab TD2=-269 payload is a
plan with the arithmetic fixed (14.2) and the page-placement experiment still
negative (14.4).
