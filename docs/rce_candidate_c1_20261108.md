# RCE candidate C1 — `cpool[-1]` 16-byte OOB write: MTE-safety and universality assessment

Date: 2026-11-08. **Host-only** (no device, no Frida, no bot, no network).
Scope: decide whether C1 (`cpool_add()` failure → `parent_cpool_idx = -1` →
`fd->cpool[-1] = func_obj`) can be a second RCE that is *easier* than N1 (dead
at the filler) and than the parser c2560s 0day (cross-tag, MTE-off), in
particular whether it can be **MTE-safe and universal** (Android builds + iOS,
no per-build / per-device hardcodes), and whether the verified OOM-kill-bypass
getter changes that.

Inputs read: `notes/bug_inventory_20261105.md` (C1 row),
`notes/MTE_safe_hunt_20261107.md` §6/§7, `notes/audit_parser.md` §3,
`notes/audit_class_fields.md` §3, `notes/new_0day_mte_specs_20261107.md` §14
(getter), and the shipped fork source
`lab/qjs_fork_audit/n1_hookfree/src` (app snapshot `2dfeee3e`, announces
quickjs-ng 0.17.0).

All new artifacts: `lab/rce_candidates/c1/` (instrumented build, PoCs, logs,
binary scan). Reproduce with `lab/rce_candidates/c1/README.md`.

---

## 0. Verdict (short)

1. **C1 is not an RCE and is not an MTE-safe carrier.** Every reachable
   instance of the write lands in the *constant pool's own allocator
   metadata*: the cpool is a large block (backing allocator = Scudo primary on
   device, **tagged**), and `cpool-16` is inside that block's own 16-byte Scudo
   chunk header (**tag 0**). The store is therefore **cross-tag**; it is *not*
   the same-tag arena write the MTE-on hunt is looking for.
2. **The same-tag (arena) variant is unreachable** (proved in §10.1: the
   refused grow always allocates a 256-byte uncatchable-OOM error object with
   the limit lifted, and the child needs ≈128–143 more; the arena deltas are
   160/200). The cpool can only be arena-resident if the failing grow is the
   19→28 or 28→42 transition, so a grow that fails at `free < 201` can never
   be followed by a successful child creation. Measured boundary: the class-field
   trigger reaches the store with delta 496, the function trigger with delta
   1680; the 28→42 attempt aborts on the next 16-byte allocation.
3. **The free path is unavoidable and is a build-constant wild pointer.**
   The store's tag half (`0xFFFFFFFFFFFFFFFE`) sets the cpool block's
   `block_idx = 0xFFFE, block_size_idx = 0xFF`; the block is freed inside the
   *same* `js_create_function()` call on every path (success → line 37887,
   failure → `js_free_function_def()` line 33851). `js_arena_free()` then
   computes `ar = b − arena_block_sizes[0xFF]·0xFFFE − 48`. On **every shipped
   arm64/armv7 Android build (72789, 72889) and on the iOS 13.2.0 arm64
   binary** `arena_block_sizes[0xFF] = 28261` →
   `ar = b − 1,852,056,422` (1.7 GiB below) → unmapped → **SIGSEGV at
   `b->u.free_next = ar->first_free_block`**. (Android x86_64 builds read 101
   → `b − 6,618,982`; the host reproduces that.)
4. **The OOM-kill-bypass getter does not chain with C1.** The getter changes
   the engine's *post-eval* policy (`handleError` logs instead of killing).
   C1's fault is native and happens inside `js_create_function()`, before
   `JS_Eval` returns; the engine never sees the exception. Measured in the
   sibling-script harness: with the getter installed, the C1 script still
   SIGSEGVs and the next `<script>` never runs, while the same harness runs
   the next script for a plain refused allocation.
5. **The write value is not attacker-controlled.** It is
   `{ child_JSFunctionBytecode *, JS_TAG_FUNCTION_BYTECODE (−2) }`: a genuine
   heap pointer (measured: a **tag-0 arena slab** pointer) plus a constant.
   The address is `cpool−16`, fixed relative to an allocation whose class and
   position the attacker only coarsely influences.
6. **Universality: the crash is universal, the exploit is not.** The table
   index that kills it is a `.rodata` OOB read (510 bytes past a 62-byte
   table), i.e. whatever string literal the linker placed next. It is 28261 on
   the three device-relevant binaries measured here and 101 on Android x86_64
   — a *per-build constant*, exactly what "no per-build hardcodes" forbids.
7. **Residual (latent, unreachable):** the failed `cpool_add()` also bakes
   `0xFFFFFFFF` into the bytecode (`OP_fclosure 0xffffffff` /
   `OP_push_const 0xffffffff`), which `resolve_labels()` rewrites to
   `OP_fclosure8 0xff` → a runtime `b->cpool[255]` read. It is never executed:
   the eval aborts with the pending OOM and the cpool free faults first.

C1 stays **DoS / heap-metadata corruption**. It is not a candidate for the
MTE-on, universal second RCE.

---

## 1. What C1 is, exactly (source recap)

`cpool_add()` (`quickjs.c:24903`) returns `-1` when the pool grow is refused.
Three call sites store that value unchecked into `parent_cpool_idx`
(`js_parse_function_decl2()`, `emit_class_init_end()`,
`js_parse_class_default_ctor()`), and `js_create_function()` later does:

```c
/* quickjs.c:37803-37810 (app snapshot 2dfeee3e) */
fd1 = list_entry(el, JSFunctionDef, link);
cpool_idx = fd1->parent_cpool_idx;      /* -1 when the grow was refused */
func_obj = js_create_function(ctx, fd1);
if (JS_IsException(func_obj)) goto fail;
assert(cpool_idx >= 0);                 /* compiled out with NDEBUG */
fd->cpool[cpool_idx] = func_obj;        /* fd->cpool[-1] : 16-byte OOB write */
```

`JSValue` is 16 bytes; the store writes
`{u = child JSFunctionBytecode *, tag = 0xFFFFFFFFFFFFFFFE}` at
`(uint8_t *)fd->cpool − 16`. The block is then freed in the same call:

* success path → `js_free(ctx, fd->cpool)` at `quickjs.c:37887`;
* any later failure → `js_free_function_def()` → `js_free(ctx, fd->cpool)` at
  `quickjs.c:33851`.

Both happen before `JS_Eval` returns to the engine.

---

## 2. Host reproduction (shipped source, app allocator model)

Build: app snapshot `2dfeee3e` + the instrumentation in
`lab/rce_candidates/c1/patch/quickjs_c1_trace.patch`, `gcc -O1 -DNDEBUG`
(the fork's own arena allocator is active: `JS_ARENA_LARGE_BLOCKS_ONLY=0`
because the build is neither ASan nor `FORCE_GC_AT_MALLOC`).

### 2.1 Function-declaration trigger (K = 211)

`poc/poc_large_k211.js`: `"x".repeat(6180000)` then
`eval("1e300;".repeat(211) + "function victim(){}")`.

```
[C1 realloc-fail] ptr=… req=5056 old_usable=3376 malloc_size=6290352 limit=6291456 free=1103
[C1 cpool-add-fail] fd=0x… count=211 size=211 cpool=0x…
[C1 create-child] … cpool_idx=-1 child_cost=-408 min_slack=854 malloc_size=6290064
[C1 store] cpool_idx=-1 cpool=0x… count=211 size=211 store_at=0x…c88 value=0x7f…1308 tag=-2
           in_slab=0 value_in_slab=1
[C1 store-old16] 410d000000000000 ffffff0000000000
[C1 freedef] fd=… cpool=0x…c98 count=211 size=211
[C1 free_rt] ptr=0x…c98 idx=65534 bsi=255 free_size=101 malloc_size=6286576
[C1 free]    ptr=0x…c98 hdr@0x…c90 idx=65534 bsi=255 refcnt=-1
[C1 free-arena] b=0x…c90 block_idx=65534 bsi=255 BS=101 ar=0x…ed2a (b-6618982)
SIGSEGV
```

* delta = 5056 − 3376 = **1680**; free at the grow = 1103 < 1681 → the grow
  fails; the child still fits (its peak cost is 141 bytes: allocations
  1,1,2,4,4,129 with `min_slack = 854`).
* `store-old16` shows what is overwritten: the first 8 bytes are the glibc
  chunk-size field of the cpool block (`0x0d41` = 3393 = 3392|PREV_INUSE for a
  3384-byte request), the second 8 bytes are the QuickJS block header
  (`idx=0xFFFF, bsi=0xFF, refcnt=0`).
* After the store the header is `idx=0xFFFE, bsi=0xFF, refcnt=-1`, and the
  free path walks into the wild `ar`. 5/5 runs SIGSEGV
  (`logs/03_release_k211_repeat5.txt`).

ASan build (`-DNDEBUG -fsanitize=address`; arena disabled by
`__SANITIZE_ADDRESS__`, same store):

```
ERROR: AddressSanitizer: heap-buffer-overflow … WRITE of size 16 at 0x51f000000e78
  #0 js_create_function quickjs.c:37916
0x51f000000e78 is located 8 bytes before 3384-byte region [0x51f000000e80,…)
allocated by … js_def_realloc ← cpool_add ← js_resize_array
```
(`logs/04_asan_k211.log`; the address matches `audit_parser.md` §3.3 exactly.)

### 2.2 Class-fields trigger (independent shape, K = 63)

The class-fields PoC of `audit_class_fields.md`
(`lab/qjs_class_audit/poc_cpool_oom.js`, TUNE tuned to 2600/2650 for this
build) reaches the same store with a **smaller delta**:

```
[C1 realloc-fail] req=1504 old_usable=1008 free=447        (delta = 496)
[C1 cpool-add-fail] count=63 size=63
[C1 store] cpool_idx=-1 cpool=… count=63 size=63 store_at=… in_slab=0 value_in_slab=1
[C1 store-old16] 0004000000000000 ffffff0000000000         (chunk size 1024)
malloc(): invalid next size (unsorted)                     (glibc detects the chunk-size corruption)
```

All 64 stores in that run are `in_slab=0` (large pool), and the process dies
with glibc's allocator check (`logs/11_class_fields_k63.log`).

### 2.3 The arena attempt (K = 28) — measured negative

`eval("1e300;".repeat(28) + "function victim(){}")`, heap tuned so that the
28→42 grow (delta 200) is refused:

```
[C1 cpool-add] count=28 size=28 free=191 bc_size=479 bc_cap=681 bc_slack=202
[C1 realloc-fail] req=672 old_usable=472 free=191           (delta = 200)
[C1 cpool-add-fail] count=28 size=28 cpool=0x7f…            ← 0x7f… = arena slab
[C1 malloc-fail] req=16 malloc_size=6291520 free=-65         ← next allocation already fails
```

The pool *is* an arena block here — the same pointer appears in the allocation
trace as `[C1 alloc] ptr=0x7f41306875d8 req=448 total=456 class=480 idx=3
ar=0x7f4130687000 slab=1` (`logs/05_k28_arena_growfail.log`) — i.e. this is
exactly the same-tag configuration. But the parse cannot continue:
the very next allocation (16 bytes) is refused, so `js_create_function()` is
never reached and no store happens. Sweeps over the filler at 8-byte steps and
over the memory limit at **1-byte steps** (`-b` option of the harness,
`logs/…`) found **no** configuration in which the 28→42 (or 19→28) failure is
followed by a successful child creation.

Why (and it is structural, not tuning):

* `js_resize_array(fd->cpool, …, 29)` fails when `free < delta+1`; for the
  arena capacities delta is 160 (19→28) or 200 (28→42);
* before that point the parser has already had to allocate the child's
  `JSFunctionDef` (`calloc(528)` measured), and after the failed grow it still
  has to (a) record the new function (`add_global_var` / class bookkeeping) and
  (b) build the child's `JSFunctionBytecode` (`calloc(129)` + 16 bytes of
  small buffers, measured);
* the measured post-grow costs are ≈ 48–256 bytes of parse bookkeeping plus
  141 bytes of child creation — always **> 201**, the entire budget.
  Confirmed by the reachable cases: delta 496 (class) and delta 1680
  (function) both work; delta 200 does not.

**Correction (2026-11-08 follow-up, §10.1):** the dominant post-grow cost is
not the parse bookkeeping measured here but a **256-byte uncatchable-OOM error
object** that `js_throw_uncatchable()` allocates with `malloc_limit` lifted;
the measured threshold is `free_at_grow ≳ 384`, which makes the arena deltas
(160/200) impossible by a wider margin than stated below.

**Consequence:** every cpool that can be in place at a *reachable* store is
≥ 42 entries (≥ 680 bytes, the first capacity above the 512-byte arena limit)
and in practice ≥ 63 entries (≥ 1008 bytes: the two measured reachable
triggers use 63 and 211) → a backing-allocator (Scudo) block, never the tag-0
arena. This closes the "same-tag C1" idea and matches `audit_parser.md` §3.7
with exact numbers.

---

## 3. What the 16 bytes actually hit (target controllability)

For a large cpool block the layout is
`[Scudo 16-byte chunk header][QuickJS 8-byte block header][cpool…]`, and
`fd->cpool = chunk + 24` — exactly the geometry already recorded in
`notes/universal_scudo_ladder_20261107.md` (“chunk+24 (Scudo 16-byte header +
QuickJS 8-byte block header)”). Therefore:

| bytes | address | content overwritten |
|---|---|---|
| `cpool−16 … cpool−9` | `chunk+8 … chunk+15` | upper 8 bytes of the **cpool's own** 16-byte Scudo chunk header (padding or header half, depending on Scudo's `getHeaderSize()` placement) — **never another object** |
| `cpool−8 … cpool−1` | `chunk+16 … chunk+23` | the cpool block's **own** QuickJS `JSMallocBlockHeader` |

The host shows the same for glibc: the first half overwrites the cpool chunk's
own `size` field (`0x0d41`), the second half its block header.

So the write **cannot target a JS object**: it is always *inside its own
allocation's metadata*. The only degrees of freedom are the cpool's size class
(chosen by the attacker: 63/94/211/316 entries…) and, indirectly, where the
allocator places it. There is no controllable header: the tag half is the
constant `0xFFFE/0xFF/0x7F|-1`, and the value `arena_block_sizes[0xFF]` is a
build constant (§4).

---

## 4. The free path: a build-constant wild pointer (measured on shipped binaries)

After the store, `js_arena_free()` (`quickjs.c:2076-2080`) runs

```c
block_size = arena_block_sizes[block_size_idx];   /* block_size_idx = 0xFF */
ar = (JSArena *)((uint8_t *)b - block_size * block_idx - sizeof(JSArena));
b->u.free_next = ar->first_free_block;            /* wild read -> SIGSEGV */
```

`block_idx = 0xFFFE`, `block_size_idx = 0xFF` are *forced* by the store, so
the outcome depends solely on `arena_block_sizes[0xFF]` — a 2-byte read 510
bytes past a 62-byte `static const` table, i.e. whatever the linker put after
it (here: the string literal pool `"null\0false\0true\0if\0else\0return…"`).

Measured with `poc/scan_arena_block_sizes.py` (`logs/10_…log`):

| binary | `arena_block_sizes[255]` | `ar` |
|---|---:|---|
| Android 13.2.0 (72789) arm64-v8a | **28261** | `b − 1,852,056,422` (1.73 GiB) |
| Android 13.2.0 (72789) armeabi-v7a | 28261 | `b − 1,852,056,422` |
| Android 13.2.0 (72789) x86 (32-bit) | 28261 | `b − 1,852,056,422` |
| Android 13.2.0 (72789) x86_64 | 101 | `b − 6,618,982` |
| Android 13.2.1 (72889) arm64-v8a | **28261** | `b − 1,852,056,422` |
| Android 13.2.1 (72889) armeabi-v7a / x86 | 28261 | `b − 1,852,056,422` |
| Android 13.2.1 (72889) x86_64 | 101 | `b − 6,618,982` |
| iOS 13.2.0 (`TelegramUIFramework`, arm64) | **28261** | `b − 1,852,056,422` |

Two consequences:

* On every device-relevant build (arm64/armv7 Android + iOS) the wild `ar` is
  **1.7 GiB below the cpool block** — no plausible heap layout maps that, so
  the crash is deterministic. There is no "if `ar` lands in mapped memory"
  route on these builds.
* The multiplier is a **.rodata adjacency artifact** and differs per ABI
  (101 on x86_64). A payload that wanted to survive the free would need
  per-build calibration of exactly the kind the task excludes — and even then
  the fake `JSArena` it would need at `ar` is not attacker-controlled.

Before the fault, `js_free_rt()` also does
`free_size = arena_block_sizes[0xFF] − 8` and subtracts it from `malloc_size`
(a ~28 KB under-accounting, i.e. a tiny heap-limit artefact). It is moot: the
underflow check does not fire (`free_size ≪ malloc_size`) and the fault follows
immediately.

---

## 5. The OOM-kill-bypass getter does not chain

The getter

```js
Object.defineProperty(InternalError.prototype, 'name',
  { configurable: true, get(){ this.message='x'; return 'x'; } });
```

makes `qjs_take_exception_description()`/`handleError` log instead of
`kill("Memory limit exceeded")`, so the *engine* survives a refused allocation
(`new_0day_mte_specs_20261107.md` §14). It changes nothing for C1 because the
C1 fault is not an exception seen by the engine: it is a SIGSEGV inside
`js_create_function()` → `js_free_rt()` → `js_arena_free()`, which runs *before*
`JS_Eval` returns.

Measured with the widget sibling-script model (`harness/memprobe.c`,
one `JS_Eval` per `<script>`, same `JSRuntime`/`JSContext`, engine policy
emulated; `logs/07…09`):

| payload | result |
|---|---|
| `poc/c1_getter_sibling.html` (getter in s0, C1 in s1, marker in s2) | s0 runs; s1 does the C1 store; **SIGSEGV** in the wild free; s2 never runs |
| `poc/c1_nogetter_sibling.html` (same, no getter) | same SIGSEGV |
| `poc/c1_getter_oom_only.html` (getter + plain 7 MB allocation) | s1 exception logged as `x: x`, **s2 runs**, `SIB_DONE scripts=3` |

The third row proves the harness models the bypass correctly; the first two
prove the bypass is irrelevant to C1. The only thing a survivor script could
have used is the leaked child-bytecode pointer — and there is no survivor.

---

## 6. Value controllability and the residual second stage

* The **value** is `{child_JSFunctionBytecode*, JS_TAG_FUNCTION_BYTECODE}`.
  Measured `value_in_slab=1`: the child's bytecode object (129-byte request →
  class 144) is an **arena** block, so the pointer written is a **tag-0**
  pointer into an untagged slab. It is a real heap address (a leak in
  principle) but not attacker-chosen, and it is written into *allocator
  metadata*, which the free destroys before any JS can read it.
* The failed `cpool_add()` also emits `OP_fclosure 0xffffffff` (function
  declaration/fields-init) / `OP_push_const 0xffffffff` (default ctor) into the
  bytecode. `resolve_labels()` rewrites the operand to `OP_fclosure8 0xff`
  (`idx < 256`), which would be a runtime `b->cpool[255]` read with **no bounds
  check** — a latent type-confusion/read stage. It never executes: the eval
  aborts with the pending OOM and the corrupted cpool is freed (and faults)
  first. Worth fixing, not worth counting as a route.

---

## 7. Answers to the specific questions

| question | answer | evidence |
|---|---|---|
| Can C1 be chained with the OOM getter? | **No.** Native fault inside `js_create_function`, before the engine sees the exception. | §5, `logs/07/08/09` |
| Can the 16-byte write target a same-tag/arena object? | **No.** The arena-pool (tag-0) variants require delta 160/200 and are unreachable; every reachable store has a ≥ 680-byte (large, tagged) pool — 1008/3384 bytes measured. | §2.3, §3 |
| Can it target a controllable header? | **No.** It always hits its own chunk header + its own QuickJS block header; the tag half is a constant and the multiplier is a `.rodata` constant. | §3, §4 |
| Is the value/contents attacker-controlled? | **No.** `{valid heap pointer, −2}`; the pointer is the child bytecode (tag 0 arena) and is not chosen. | §6 |
| MTE-safe? | **No.** Tagged cpool pointer → tag-0 chunk-header granule = sync `SEGV_MTESERR` at the store itself (and the free would fault on any build anyway). | §3, `MTE_safe_hunt` §6 row 2 confirmed |
| Universal (Android + iOS, no hardcodes)? | **The DoS is universal** (all arm64/armv7 builds and iOS read 28261 → 1.7 GiB wild pointer). **An exploit is not**: the multiplier is per-ABI, and the primitive ends in the allocator. | §4 |
| Easier than N1 / c2560s? | **No.** N1 at least has a same-tag write and only dies at the 6 MiB gate; C1 dies in the allocator before any controllable consequence. | — |

---

## 8. Limits of this assessment

* All new measurements are x86-64 host builds of the shipped source; the tag
  statements are *reasoned* from the measured allocator domain
  (`in_slab` = arena vs backing allocator) plus the established Scudo model
  (`MTE_safe_hunt_20261107.md` §2), not measured on an MTE device. The claim
  that the reachable C1 store is cross-tag follows from (a) the cpool being a
  large block, (b) the established 16-byte Scudo header at `chunk+0..15`, and
  (c) `cpool = chunk+24`.
* The wild-`ar` multipliers are read from the shipped binaries' `.rodata`
  (exact file offsets in `logs/10_…log`); the *mapping* outcome is inferred
  from the magnitude (1.7 GiB below a heap block) — no device run, by design.
* The arena-unreachability result is empirical over three trigger shapes plus
  one-byte-step limit sweeps, with the analytic reason (post-grow cost >
  delta) stated in §2.3. It does not exclude a hypothetical fourth call site
  with a cheaper child, but no such site exists in this source (only the three
  `parent_cpool_idx` stores).
* No device, no Frida, no bot, no network were used. Nothing destructive was
  run.

---

## 9. Artifacts

```
lab/rce_candidates/c1/
  README.md                    build + repro commands
  patch/quickjs_c1_trace.patch instrumentation (C1_TRACE=1/2), applies -p1
  harness/c1run.c              single-eval runner (-l MiB | -b bytes)
  harness/memprobe.c           sibling-<script> + engine-policy harness
  harness/sweep*.py
  poc/poc_large_k211.js        function-decl trigger (delta 1680)
  poc/poc_class_fields_k63.js  class-fields trigger (delta 496, audit original)
  poc/c1_getter_sibling.html   getter + C1 + marker
  poc/c1_nogetter_sibling.html control
  poc/c1_getter_oom_only.html  getter + plain OOM (bypass works)
  poc/scan_arena_block_sizes.py  shipped-binary .rodata scan
  logs/01..11                  traces, ASan report, memprobe logs, binary scan, class trigger
```

Key log lines quoted above are verbatim from `logs/01_release_k211_trace.log`,
`logs/04_asan_k211.log`, `logs/05_k28_arena_growfail.log`, `logs/07…09`,
`logs/10_shipped_binaries_arena_block_sizes.log` and `logs/11_class_fields_k63.log`.

Lemmalog handoff: `notes/LEMMALOG_FACTS_c1_20261108.txt`.

---

# 10. Delegated follow-up (2026-11-08): "make it work" — every route, and the exact blocker

Task: treat the negative as the starting point; either turn C1 into a usable
primitive or give an impossibility proof with the exact blocker.

**Result: no usable primitive exists on the shipped builds.** The blocker is no
longer "the post-grow cost is large": it is a specific, measured mechanism —
**a refused cpool grow allocates a ~256-byte uncatchable-OOM error object with
`malloc_limit` temporarily lifted**, so the tracked heap is *over* the limit
immediately after the failure and the child's `JSFunctionBytecode` can never be
built unless the realloc delta exceeds ~398 bytes. All arena-resident pool
capacities have delta ≤ 200, so the same-tag store is **impossible**; the only
reachable stores have large (Scudo) pools, are cross-tag, and their block is
freed in the same `js_create_function()` call with the build-constant 1.7 GiB
wild pointer.

## 10.1 Route 1 — make the failing cpool arena-resident (same-tag): impossible

### 10.1.1 The mechanism (new, measured)

`js_realloc()` calls `JS_ThrowOutOfMemory()` when the gate refuses the grow,
which calls `js_throw_uncatchable()`:

```c
/* quickjs.c:8989 */
static void js_throw_uncatchable(JSContext *ctx, const char *msg)
{
    JSRuntime *rt = ctx->rt;
    size_t limit = rt->malloc_state.malloc_limit;
    js_set_uncatchable_pending(rt);
    rt->malloc_state.malloc_limit = 0;      /* <-- limit lifted */
    JS_ThrowInternalError(ctx, "%s", msg);  /* builds the Error object anyway */
    rt->malloc_state.malloc_limit = limit;
}
```

So the OOM error object is **always allocated, even though the heap is at the
cap**, and its bytes are counted in `malloc_size`:

```
[C1 cpool-add] fd=… count=28 size=28 free=199
[C1 realloc-fail] ptr=… req=672 old_usable=472 malloc_size=103520 limit=103720 free=199
[C1 throw-uncatchable] msg=out of memory limit=103720 used_before=103520 used_after=103776 cost=256
[C1 malloc-fail] req=1 malloc_size=103776 limit=103720 free=-57
```

(`logs/12_error_object_cost.log`; the three allocations are 88 + 104 + 38 bytes,
classes 96 + 112 + 48 = 256 accounted.)

After the throw the limit is restored, but `malloc_size` is now **above** it:
`free = -57`. Every later allocation is refused — including the child's
`JSFunctionBytecode`.

### 10.1.2 The reachability threshold (measured, 1-byte control)

Sweeping the class-fields trigger (delta 496) with the byte-precise limit knob:

| free at the failed grow | error object | free after it | child creation | store |
|---:|---:|---:|---|---|
| 415 | 256 | 159 | ok | **yes** |
| 399 | 256 | 143 | ok (tightest allocation slack 14) | **yes** |
| 383 | 256 | 127 | **refused** (`calloc(129)`) | no |
| 351 | 256 | 95 | refused | no |

(`logs/13_threshold_sweep.csv`; the tightest-child trace at free 399 is in
`logs/12…`.)

**Measured threshold: `free_at_grow ∈ (383, 399]`, consistent with the
computed 386 (256 + 130).**

### 10.1.3 The theorem

> **C1 cannot store into an arena-resident (tag-0) cpool.**
>
> 1. The store needs a child `js_create_function()`, whose allocations after
>    the failed grow include `js_mallocz(function_size)` with
>    `function_size ≥ sizeof(JSFunctionBytecode) ≈ 129`. The measured tightest
>    allocation is that 129-byte block, taken at free 143 with slack 14
>    (`logs/12…`); it is refused at free 127. The child therefore needs
>    ≈ 130 bytes (plus a transient 32).
> 2. The refused grow costs 256 accounted bytes *unconditionally* (10.1.1).
> 3. The grow is refused iff `free_at_grow < delta`, where
>    `delta = usable(1.5·K) − usable(K)`.
> 4. The child needs `free_at_grow − 256 ≥ 130`, i.e. `free_at_grow ≥ 386`.
> 5. Hence a reachable store requires `delta > 386`.
> 6. An arena-resident cpool requires `K ≤ 28` entries (448 B → class 480 ≤
>    512; the next capacity, 42 entries = 680 B, is already a large block).
>    The only grow out of a ≤ 28-entry pool is 19→28 (delta **160**) or 28→42
>    (delta **200**).
> 7. 200 < 386 → contradiction. ∎

Empirically confirmed on all three inventory triggers: the 28→42 attempt with
free 159…199 always fails the grow and then aborts on the next 1-byte
allocation, never reaching `js_create_function` (`logs/14_arena_impossibility.log`);
the default-ctor and class-field triggers behave identically; only deltas
≥ 496 are reachable, and those pools are ≥ 1008 bytes (large blocks).

**This supersedes the "post-grow cost 48–256 + 141" estimate in §2.3: the
dominant term is the OOM error object (exactly 256), and it is unavoidable.**

## 10.2 Route 2 — the store target and value: structurally fixed

* **Destination.** `fd->cpool` is always a js_malloc base, so `cpool−16` is
  always (a) the 8 bytes before the block's own QuickJS header for a large
  block — its own 16-byte Scudo chunk header granule — or (b) the last 8 user
  bytes of the *previous* block plus its own header for an arena block (case
  (b) is impossible, §10.1). No trigger, capacity, or groom moves the offset.
* **Value.** Always `{child_JSFunctionBytecode*, JS_TAG_FUNCTION_BYTECODE}`.
  The pointer is a *valid* bytecode object (tag 0 arena slab), so even if it
  landed on a JSValue slot it would be a legitimate `OP_fclosure` operand, not
  a type confusion; the tag is a constant and is what poisons the header.
* **Consumption by a later allocation / GC / free.** None. The block is not on
  any free list (its header is not a free-list link), QuickJS GC never scans
  arena block headers (it walks the GC object list), and the only consumer is
  `js_free_rt()` in the same call. A second `-1` child only overwrites the same
  16 bytes with another valid pointer.
* **Controlled free slot.** There is no free list the payload can seed at
  `cpool−16`: the slot is the block's own header.

## 10.3 Route 3 — defer the free / benign build

* **Every path frees the cpool inside the same `js_create_function()`**:
  success → `js_free(ctx, fd->cpool)` (quickjs.c:37887), failure →
  `js_free_function_def()` (quickjs.c:33851). The fd can never *succeed* anyway:
  its `function_size` includes the full pool (`16·K`) while the refused grow's
  delta was `8·K`; even with many pre-created children freeing ~408 B each, the
  success path still frees the corrupted block.
* **No GC/refcount indirection**: the cpool is a plain malloc block, not a GC
  object; `JS_FreeValue` is never called on the OOB slot (index −1).
* **No benign build.** `arena_block_sizes[255]` measured on every shipped
  binary available: **28261** on Android 13.2.0 (72789), 13.2.1 (72889),
  13.2.2 beta (72929) and the release_updated arm64 build — for arm64, armv7
  and x86 — and on iOS 13.2.0 arm64; **101** only on x86_64 (→ 6.6 MB, still
  beyond the 6 MiB widget heap). `arena_block_sizes` is `static const`, so it
  cannot be changed at runtime.
* **Device-data check of the wild address** (Pixel 9, Android 17, MTE-on,
  `evidence/evidence_20261102/pixel_mte/app_smaps_mte.txt`, 4,534 mappings):
  sampling every scudo primary/secondary mapping at 5 positions, `ar =
  b − 28261·0xFFFE − 48` lands in a **PROT_NONE** reservation (scudo
  primary_reserve, libwebview reservation, CFI shadow) or unmapped memory in
  ~97 % of positions, in read-only file mappings in ~0 %, and in a **writable**
  mapping in **3.2 %** (`dalvik-main space`, jit-cache, anon rw-p) — never in
  memory the payload can place or read (`logs/15_pixel_smaps_ar_analysis.log`).
  Even in the writable 3.2 % the free only performs fixed 2-byte writes at
  `ar+46`/`ar+42` and possibly a `list_add` into `free_arena_list[255]`, all at
  addresses and values the attacker does not control.

## 10.4 Route 4 — getter / engine loop: no

The fault is a native SIGSEGV inside `JS_Eval` → `js_create_function` →
`js_free_rt` → `js_arena_free`. `handleError`/`qjs_take_exception_description`
run only after `JS_Eval` returns an exception; C1 never returns one. Measured
in §5 (`logs/07…09`) and unchanged by any of the new shapes.

## 10.5 Route 5 — the other C1 triggers: same blocker

All three `parent_cpool_idx` sites converge on the same `js_create_function`
store with the same OOM-error-object cost. The pool capacity (hence delta) is
the only variable, and the arena capacities are all below the 398-byte
threshold. The default-ctor trigger was re-measured: at free 175/195 the grow
fails, the error object costs 256, and the next 11-byte allocation is refused
(`logs/14…`).

## 10.6 The closest partial primitive (what C1 actually gives)

For the reachable large-pool triggers, C1 gives exactly one 16-byte write of
`{valid JSFunctionBytecode*, −2}` into the cpool block's **own** Scudo chunk
header granule plus its own QuickJS block header, immediately followed by a
free that computes `ar = b − 1,852,056,422` and faults.
The only attacker-influenced choices are the cpool capacity (63/94/211/…, all
large) and the heap position (which shifts `ar` between PROT_NONE, unmapped,
read-only and — 3.2 % of the time — an unrelated writable mapping). There is no
leak channel (the free precedes any JS observation), no second-stage execution
(the eval aborts with the pending uncatchable OOM), and no controllable write.

**This cannot beat N1**: N1 has a *reachable* same-tag write and only fails at
the 6 MiB allocation gate; C1's same-tag write is provably unreachable and its
reachable variant is a deterministic crash on every shipped build.

## 10.7 What would change the verdict

1. A build where `arena_block_sizes[0xFF]` is 0 or small enough that
   `b − BS·0xFFFE` lands in a mapping the payload can place. None exists in the
   measured binaries (28261 on all device ABIs); the table is `.rodata`.
2. A way to skip the free in `js_create_function` — none in this source.
3. A way to suppress the OOM error object (needs `rt->in_out_of_memory` set
   across the parser; it is only true inside the throw itself) — none.
4. A fourth unchecked cpool index with a *positive* out-of-range value — the
   source has exactly three `parent_cpool_idx` stores, all set from
   `cpool_add()`.

## 10.8 New artifacts (this follow-up)

```
lab/rce_candidates/c1/logs/12_error_object_cost.log       the 256-byte mechanism
lab/rce_candidates/c1/logs/13_threshold_sweep.csv         reachability threshold 398
lab/rce_candidates/c1/logs/14_arena_impossibility.log     28->42 sweeps, no store
lab/rce_candidates/c1/logs/15_pixel_smaps_ar_analysis.log Pixel 9 ar placement
lab/rce_candidates/c1/logs/16_multiplier_all_builds.log   all shipped binaries
```

Lemmalog handoff updated: `notes/LEMMALOG_FACTS_c1_20261108.txt`.
