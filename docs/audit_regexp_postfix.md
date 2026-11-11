# quickjs-ng regexp memory-safety audit after #1827 / #1826

Target: `quickjs-ng` master at **e22ce4d** ("Clear Array.find value ownership
after release (#1826)"; parent 3d5cb14 = #1827). The provided tree
`/tmp/opencode/qjs_now` was left untouched; the environment's temp cleaner
removed it mid-session, so the evidence and the reproduction use a fresh
shallow clone pinned to e22ce4d (`git ls-remote` confirmed master == e22ce4d)
under `lab/qjs_regexp_audit/src/`.

App model (same shape as the Telegram widget sandbox): one `JSRuntime` with a
**6 MiB memory limit**, 1 MiB stack, 500 ms cooperative interrupt, no host APIs
other than `print`/`trace`/`mem` used for output and accounting probes.

Date: 2026-11-05. Local lab only; no device, no bot.

---

## 1. Verdict

**A new, source-only UAF/OOB-read variant of #1827 was found and reproduced.**
It is a different trigger from the one #1827 fixed, and it is not in the
known/reported list (#1827, #1826, #1792, #1828, #1829, #1853).

* #1827 fixed the case where `lastIndex` *exists* and its `valueOf` recompiles
  the same `RegExp` before `JS_RegExpDelete`/`js_regexp_exec` snapshot the
  bytecode. That specific route is fixed and verified (§3); the new variant
  does not need it.
* The new variant creates a `RegExp` instance **without its own `lastIndex`**
  property. `js_regexp_constructor_internal()` ignores the return value of
  `JS_DefinePropertyValue(obj, JS_ATOM_lastIndex, ...)` (quickjs.c:49383).
  For the base class that define cannot fail (shared `ctx->regexp_shape` hit +
  pure shrink, §4). For an instance created with a **different prototype**
  (`class R extends RegExp`, or `Reflect.construct(RegExp, args, F)` with a
  fresh `F.prototype`), the define has to clone/resize the shape, which *can*
  fail when the 6 MiB heap is exhausted. The constructor still returns the
  instance. An accessor for `lastIndex` placed on that prototype is then live.
* `js_regexp_exec()` reads `lastIndex` through the accessor, executes, caches
  `re_bytecode`, then calls `JS_SetProperty(this_val, lastIndex, end)`
  (quickjs.c:49879) — which runs the accessor's setter *after* the snapshot.
  The setter calls `compile()`, which frees the bytecode buffer; the next
  statement, `lre_get_groupnames(re_bytecode)` (quickjs.c:49883), reads the
  freed buffer. ASan: `heap-use-after-free` in `lre_get_flags` ←
  `lre_get_groupnames` ← `js_regexp_exec`.

The freed bytecode buffer is reclaimable with attacker-controlled bytes on the
arena/Scudo-style allocator (demonstrated with a same-size `ArrayBuffer`): the
fake header's `flags` field decides whether `lre_get_groupnames()` returns a
trailer pointer, and `bytecode_len` (u32 at offset 4) makes that pointer land
anywhere up to ~4 GiB forward of the block. `JS_NewAtom()` then `strlen()`s from there and
the bytes become an atom / property name in `m.groups` — a controlled heap
**read** and potential info leak. No write or execute primitive was found:
`lre_exec()` never runs on the stale bytecode (the setter runs after the
match), and in `JS_RegExpDelete` every `SetProperty(lastIndex)` is immediately
followed by `break`.

GitHub issue/PR search (2026-11-05) for regexp + UAF/OOB/overflow returned
only #1827, #1828/#1829, #1792 and #1853 (all known), plus the non-memory
spec issues #1796/#1805/#1890. No report describes the subclass /
failed-`lastIndex`-define path.

Two secondary, non-memory findings are in §6:
* **F2**: when the heap is exhausted by small live objects, the OOM error
  object cannot be allocated, `JS_ThrowError2()` falls back to `JS_NULL`, and
  `js_set_uncatchable_error()` ignores non-objects — the OOM is thrown as a
  **catchable bare `null`**, bypassing #1810. Demonstrated at 6 MiB.
* **F3** (observation only): a lying `flags` getter makes `@@match` /
  `@@replace` loop without progress (bounded by the 500 ms interrupt).

Follow-up verifications (this session): F2 is confirmed on the app snapshot
**7a23d8e** (source build, 6 MiB) and on the **72879** binary (static IDA:
`JS_ThrowError2` maps `JS_TAG_EXCEPTION` to `JS_NULL`, and the uncatchable
marking is gated on `tag == JS_TAG_OBJECT`), and it is usable for single-eval
probe/sweep (~5–16 ms per fill/catch/free/probe cycle, small headroom sweeps
in ~1 ms).  **F1's UAF was also reproduced on the 7a23d8e ASan build**
(read `js_regexp_exec:49808`, free `js_regexp_compile:49460` via the setter;
`logs/poc_uaf_7a_asan.txt`).  F1's read is **forward-only from the reclaimed
heap block** and its group name is UTF-8-decoded, so invalid bytes (most
pointer bytes) become U+FFFD: it leaks no libc/app/heap pointer in any usable
form, and N1 adds nothing to gain from it (N1's OOB RW/leak is stronger).
Details in §4.5 and §6.

---

## 2. Call-site table (HEAD e22ce4d)

`Callback` = arbitrary JS can run (accessor, `valueOf`/`toString`, species
constructor, user `exec`).

| # | Site | `re->bytecode` / `re->pattern` read | Callback between read and last use | Verdict |
|---|------|-------------------------------------|------------------------------------|---------|
| 1 | `js_regexp_exec` 49793 | `str8(re->bytecode)` **49827** after `lastIndex` get + `JS_ToLengthFree` 49823–49825 | `JS_SetProperty(lastIndex)` 49857/49879 **can run a prototype setter when the instance has no own `lastIndex`** (§4/F1); `lre_get_groupnames` 49883 then reads the freed buffer | **unsafe for subclass instances whose define failed (F1)**; safe for base/literal RegExps |
| 2 | `JS_RegExpDelete` 50023 | `str8(re->bytecode)` **50049** after `lastIndex` get 50046–50048 | `JS_SetProperty(lastIndex)` 50074/50105 are followed by `break`; a setter that recompiles cannot be followed by another `lre_exec` | safe (even with a missing `lastIndex`) |
| 3 | `js_regexp_compile` 49504 | frees/reassigns 49534–49537 | `pattern1`/`flags1` `toString` callbacks run before the frees; pattern/bc dupped first (49520–49521) | safe |
| 4 | `js_regexp_constructor` 49426 | `js_dup(re->pattern/bytecode)` 49456/49458 before any flags callback | — | safe |
| 5 | `js_regexp_constructor_internal` 49359 | assignment 49388–49389 | `js_create_from_ctor()` may run `ctor.prototype` getter before the assignment; parameters are owned | safe, **except the ignored `JS_DefinePropertyValue` at 49383** (F1) |
| 6 | `js_regexp_get_source` 49548 | `p = re->pattern` 49565 | none (StringBuffer only) | safe |
| 7 | `js_regexp_get_flag(s)` 49614/49634 | `lre_get_flags(str8(re->bytecode))` 49630 | none between read and use | safe |
| 8 | `js_regexp_toString` 49690 | via `source` property | flags getter runs after `source` was materialised | safe |
| 9 | `Symbol.match` 50166 | none | only counted string refs; no `re` pointer | safe |
| 10 | `Symbol.matchAll` 50334 + iterator 50281 | none | iterator holds counted JSValues (mark + finalizer) | safe |
| 11 | `Symbol.replace` 50480 (+ `JS_RegExpDelete` fast path) | none in the slow path | `js_is_standard_regexp` getters run before the delete; `sp`/`rp` are counted strings | safe |
| 12 | `Symbol.search` 50672 | none | live refs; `JS_SetProperty` consumes correctly | safe |
| 13 | `Symbol.split` 50730 | none | `strp` points into counted `str`; species cannot invalidate it | safe |
| 14 | `lre_exec` 3386 | engine runs no JS; only host interrupt + `lre_realloc` (GC) | GC roots keep `this_val`'s bytecode string alive | safe |
| 15 | capture sizing | `lre_get_alloc_count()` = 2·cc + rc (49839/50056); runtime writes `2·cc + pc[0]`, `pc[0] < rc` by `compute_register_count` | — | safe for compiler bytecode; 8.2 M random cases (§5) |

`re->pattern` is never read across a callback: the only non-constructor reads
are the pure-C loop in `js_regexp_get_source` and `lre_get_groupnames`
(bytecode, not pattern).

---

## 3. #1827 is fixed (regression check)

Pre-fix `JS_RegExpDelete` cached `re_bytecode` **before** reading
`lastIndex`; an object-valued `lastIndex` whose `valueOf` calls
`regExp.compile()` freed the bytecode under the cached pointer. The fix moves
the `lastIndex` read/ToLength before the snapshot (50046–50049), and
`js_regexp_exec` already had the correct order (49823 then 49827).
`tests/regexp-delete-lastindex-recompile.js` passes at HEAD:

```
$ ./appmodel_asan t1827.js 6 500
ccc
b c
```

All 20 `cases/` scenarios (lastIndex `valueOf`, `exec` getter, species,
flags/source getters, `Symbol.*` getters, reentrant exec/next, named groups,
`d` flags, wide/rope/sliced inputs, `replace`/`replaceAll`/`split`/`match`/
`matchAll`/`search`) run clean under ASan, GC-stress, clang-ASan and Scudo.

---

## 4. F1 — subclass + failed `lastIndex` define → UAF in `js_regexp_exec`

### 4.1 Why the base class is safe and the subclass is not

**Base class.** `new RegExp(...)` reaches
`js_regexp_constructor_internal(ctx, RegExp, ...)`; `js_create_from_ctor()`
uses `RegExp.prototype`, so the fresh object has the empty hashed shape for
that prototype. `add_property()` (10156) finds the cached `ctx->regexp_shape`
by hash and takes the "matching shape found" branch (10171–10187): it only
*shrinks* `p->prop` from `JS_PROP_INITIAL_SIZE` (=2, 32 B) to one slot (16 B)
and dups the shape. A shrink cannot fail: `js_arena_realloc()` returns the same
block when the new total size fits the current class (1924), and
`js_realloc_rt()`'s limit check uses `malloc_size + size - old_size`, which
decreases for a shrink (2047–2075). The same holds for regexp literals
(`OP_regexp` → the `ctx->regexp_shape` path, 49374–49378).

**Subclass / custom prototype.** `class R extends RegExp {}` (or
`Reflect.construct(RegExp, args, F)` with `F.prototype =
Object.create(RegExp.prototype)`) makes `js_create_from_ctor()` use a
*different* prototype object. `find_hashed_shape_prop()` (6060) cannot match
`ctx->regexp_shape` (the prototype pointer differs), so `add_property()`
clones the shape and `add_shape_property()` may resize the property array.
That allocation can fail when the heap is at the 6 MiB limit.

**Ignored result.** `js_regexp_constructor_internal()` does not check the
return of:

```c
JS_DefinePropertyValue(ctx, obj, JS_ATOM_lastIndex, prop.u.value,
                       JS_PROP_WRITABLE);      /* quickjs.c:49383 */
```

On failure the exception is set but the object is still returned (with
pattern/bytecode assigned). The instance has **no own `lastIndex`**; the
prototype accessor is now consulted by `JS_GetProperty`/`JS_SetProperty`. The
pending OOM exception is latent: the constructor returns a value, so no
exception propagates; the next `JS_Throw` frees it. The script keeps running
(verified in the PoC).

### 4.2 Trigger

`poc_sweep_inprocess.js` (class form) and `poc_reflect.js`
(`Reflect.construct`, no class syntax):

1. install `get/set lastIndex` on the fresh prototype (get returns a stored
   value, set runs `this.compile("(?<y>b)", "g")` on the first call);
2. warm the empty shape with `Object.create(R.prototype)`;
3. search the fill size: allocate an `ArrayBuffer(FILL)` and construct
   `new R("(?<x>a)", "g")`; increase FILL by one byte per attempt. The first
   attempt for which the instance exists but
   `hasOwnProperty(r, "lastIndex")` is false is the window (the define failed,
   everything else succeeded). Increasing FILL, the first non-OWN outcome is
   the malformed instance itself (the define fails but the constructor returns
   normally); constructor-throwing fills only appear *above* the window, so
   the search stops before them. F2 matters for tuning variants that overshoot
   or fill to OOM;
4. free the fill, call `r.exec("a")`.

`js_regexp_exec` then: prototype getter → 0; `lre_exec` matches "a" and fills
`capture`; `JS_SetProperty(lastIndex, 1)` → setter → `compile()` frees the old
bytecode; `lre_get_groupnames(re_bytecode)` reads freed memory.

The search fits the widget's 500 ms budget if the fill step is coarse: on the
release/arena build a **16-byte strided** search from 6 170 000 reaches the
window in under 500 ms (3/3 runs, `logs/poc_stride16_rel.txt`,
`poc_sweep_stride16.js`). The window is ~100 bytes wide, wider than the stride,
so the stride cannot jump over it; the exact fill depends on the build and even
on the script path length (the filename is part of the runtime heap).

The same UAF is reachable through `r.exec()`, `r.test()`,
`String.prototype.match/search`, `replace` (slow path, non-empty replacement)
and the `matchAll` iterator, because all of them funnel into
`js_regexp_exec()`; a species constructor that returns a malformed subclass
instance can also plant it in a `matchAll` iterator.

### 4.3 Evidence (ASan, 6 MiB)

`logs/poc_uaf_inproc.txt` (gcc ASan, arena off; the fill value is
build/path-dependent, the window is ~100 bytes wide):

```
FOUND 6180293
==...==ERROR: AddressSanitizer: heap-use-after-free on address 0x...
READ of size 2 at 0x... thread T0
    #0 get_u16                       src/cutils.h:328
    #1 lre_get_flags                 src/libregexp.c:3453
    #2 lre_get_groupnames            src/libregexp.c:3461
    #3 js_regexp_exec                src/quickjs.c:49883
...
0x... is located 8 bytes inside of a 48-byte region
freed by thread T0 here:
    #0 free
    #1 js_def_free                   src/quickjs.c:2416
    #2 js_arena_free                 src/quickjs.c:1854
    #3 js_free_rt                    src/quickjs.c:2044
    #4 js_free_string0               src/quickjs.c:2627
    #5 js_free_value_rt              src/quickjs.c:7153
    #6 JS_FreeValueRT / JS_FreeValue
    #8 js_regexp_compile             src/quickjs.c:49535   <-- via the setter
    #13 call_setter                  src/quickjs.c:10345
    #14 JS_SetPropertyInternal2      src/quickjs.c:10730
    #16 JS_SetProperty               src/quickjs.c:10829
    #17 js_regexp_exec               src/quickjs.c:49879   <-- SetProperty after the snapshot
```

Same report with **clang ASan** (`-D__SANITIZE_ADDRESS__`, arena off):
`logs/poc_uaf_clang.txt`. The same PoC under **Scudo** (Android-like,
`-fsanitize=scudo -D__SANITIZE_ADDRESS__`) runs to completion silently
(`logs/poc_uaf_scudo.txt`, `FOUND … exec index=0 hits=2`) because Scudo has no
UAF-read shadow; the freed buffer is still intact, so the walk reads the old
trailer — the bug is present but invisible there.

### 4.4 Reclaim and control (release / arena build)

`poc_reclaim_groups.js` runs the same search on a `-O2` build with the 4 KiB
arena enabled and, in the setter, after `compile()` allocates same-size
`ArrayBuffer`s whose bytes are a fake regexp header:

```
+0  u16 flags        (0x0080 = LRE_FLAG_NAMED_GROUPS)
+2  u8  capture_count
+3  u8  register_count
+4  u32 bytecode_len  (trailer pointer = block + 8 + len)
+8  group-name trailer (name NUL scope)
```

The freed bytecode block is reused (arena LIFO), and:

* with `flags = 0` (`poc_reclaim_off.js`, `logs/poc_reclaim_off.txt`), the
  original group disappears: `groups=<undefined>` — proof that the fake
  header was read (reclaim succeeded);
* with `flags = NAMED_GROUPS` and `bytecode_len = 0`, a fake trailer
  `"EVIL\0\0"` at +8 produces:

```
FOUND 6185024
exec index=0 hits=2 groups=EVIL
CONTROLLED group EVIL=a
```

The result's `groups` object now has an attacker-chosen property name and the
captured value. `bytecode_len` is a full u32: any value moves the trailer
pointer (`bc + 8 + len`) anywhere in the 32-bit range; `JS_NewAtom` then
`strlen()`s from there, and the bytes become an atom / property name — a
controlled-offset OOB **read**.  The read is decoded as UTF-8, so only ASCII
bytes survive; pointer leakage is ruled out in §4.5 (the flags/trailer control
above is proven, an end-to-end pointer leak is not possible).

### 4.5 Read range and leak limits (verified)

The fake trailer pointer is `reclaimed_block + 8 + (uint32_t)bytecode_len`:
**forward only**, 0..0xFFFFFFFF bytes from the reclaimed block, no backward
and no sign.  Measured on the release/arena build (`f1_addrs.js`,
`logs/f1_addrs_head.txt`, `logs/f1_addrs_7a.txt`):

| object | relation to the reclaimed block |
|---|---|
| harness/app text (`&JS_NewRuntime`) | **below** (negative; ~0.24–1.0 GB in measured runs) |
| `JSRuntime` (`rtaddr()`) | **~167 KB below** (negative) |
| libc `free` / `malloc` / `system` | **+45–46 TiB above** (far outside +4 GiB) |

So the runtime (which stores `mf.js_free`), the app text and libc are all
outside the reachable forward window on this platform.  The mapped forward
window is only the JS heap itself: a read at +6 MiB is still mapped (the key
came out empty, i.e. it hit a NUL), +8 MiB is SIGSEGV (`f1_range.js`,
`logs/f1_range*.txt`; no fault recovery in JS).

The group name is built by `JS_NewAtom`, i.e. a **UTF-8 decode**: invalid bytes
become U+FFFD (verified by injecting `41 80 81 82 FE FF 42 00` — the key is
`A <5 × U+FFFD> B`, `f1_bytes.js` / `logs/f1_bytes_*.txt`).  A 64-bit pointer's
bytes are mostly ≥ 0x80, so they are destroyed by the decode; only ASCII bytes
survive.  The decoded length still reveals the position of the first NUL, but
not the pointer value.

**Conclusion:** F1 is a **heap-forward, lossy ASCII read**, not a pointer-leak
primitive.  It cannot leak a libc/app pointer, the runtime, or even a raw heap
pointer; no write/execute either.  For N1 (which already has OOB RW and a heap
leak) it adds nothing for ASLR or pointer acquisition: N1's existing
`JSWeakRefRecord*` leak and oversized-view read are strictly stronger.  The
only plausible joint use is a lab-side layout check (place an ASCII marker
after the block and verify it with `m.groups`), which is redundant in the
chain.  If a heap pointer is needed, use N1's leak; if a libc/app base is
needed, use N1's `rt->mf.js_free` → PIE GOT path.

### 4.6 Severity / primitive

* **Read-only.** No path executes the stale bytecode a second time: the setter
  runs after `lre_exec` in `js_regexp_exec`, and `JS_RegExpDelete`'s
  `SetProperty` is followed by `break`. The only post-free uses are
  `lre_get_flags`/`lre_get_groupnames` (header + `strlen`) and `JS_NewAtom`
  (allocation). No write to the freed block, no control-flow hijack.
* **Impact**: deterministic heap UAF read in a 6 MiB sandbox; attacker-
  controlled metadata (flags, trailer pointer, group name) exposed to JS via
  `m.groups`; OOB read/info leak; possible crash if the trailer pointer lands
  in unmapped memory. Also an attacker-chosen property name on the result
  object (potential gadget for host code that merges `groups` into app
  objects).
* **Trigger**: heap exhaustion (the app's 6 MiB runtime limit) at the
  subclass `lastIndex` define; the malformed instance survives. This is
  OOM-gated, but the OOM does not propagate (ignored return) and the UAF is a
  separate, controllable primitive.
* **Not #1827's test**: the added regression test only covers an existing
  `lastIndex` whose `valueOf` recompiles; it never constructs a subclass under
  heap pressure.

### 4.7 Suggested fix

Check the `JS_DefinePropertyValue` result in
`js_regexp_constructor_internal()` and `goto fail` (free `obj`); optionally
make the property definition infallible (reuse a pre-built shape for the
subclass prototype too, or fall back to the `ctx->regexp_shape` path and set
the prototype afterwards). Add a regression test that constructs a subclass
under a tight `JS_SetMemoryLimit` and asserts `hasOwnProperty(lastIndex)`.

---

## 5. Dynamic evidence

### 5.0 Sanitizer / allocator configuration (important)

quickjs's small-block allocator is a 4 KiB arena whose blocks are invisible to
ASan: an overflow into the next block, or a read of a freed block recycled
inside the arena, is not a poisoned access. The arena is disabled by
`JS_ARENA_LARGE_BLOCKS_ONLY` only when `__SANITIZE_ADDRESS__` **or**
`FORCE_GC_AT_MALLOC` is defined (quickjs.c:272).

`__SANITIZE_ADDRESS__` is a **GCC** macro; **clang does not define it**
(verified: `clang -fsanitize=address -dM -E` has no such macro). A naive
clang ASan build keeps the arena active and hides intra-arena hits. All
numbers below use configurations that disable it:

* primary: **gcc** + `-fsanitize=address` (macro defined); confirmed by
  disassembling `js_arena_malloc()` — only `arena_malloc_large`
  (`logs/arena_check.txt`: `89ff: call 878a <arena_malloc_large>`);
* GC-stress: `-DQJS_ENABLE_GC_STRESS=ON` (`FORCE_GC_AT_MALLOC`);
* clang ASan cross-check: `-D__SANITIZE_ADDRESS__` explicit;
* clang Scudo cross-check: `-fsanitize=scudo` + `-D__SANITIZE_ADDRESS__`;
* release (`-O2`, arena active) for the reclaim experiment.

### 5.1 Results

| Harness | Cases | Configuration | Result |
|---|---|---|---|
| `cases/case01..20.js` | 20 | gcc ASan, GC-stress, clang ASan, Scudo (arena off) | no hit |
| `fuzz_regexp2.js` full campaign | 8 × 300 000 = 2.4 M | gcc ASan, 6 MiB | no hit (`logs/status.txt`) |
| `fuzz_regexp2.js` reproducible subset | 4 × 300 k + 300 k clang + 300 k Scudo | arena off | no sanitizer hit, all 8 runs `rc=0` (`logs/verify_run.txt`: "fuzz clean") |
| `fuzz_regexp2.js` GC-stress | 4 × 4 000 + 2 × 2 000 | GC per allocation | no hit |
| `lre_regfuzz.c` | 8 × 1 000 000 (+250 k) | clang ASan, exact capture sizing | no hit (`logs/lre_status.txt`) |
| `tests/*.js` (109 files) | 109 | GC-stress ASan | no hit; `microbench.js` timed out by design |
| `t1827.js` | 1 | gcc ASan | pass |
| `poc_sweep_inprocess.js` (F1) | 1 | gcc ASan / clang ASan / Scudo, 6 MiB | **UAF reproduced** (ASan ×2; silent under Scudo) |
| `poc_sweep_stride16.js` (F1) | 3 | release/arena, **500 ms budget** | **MALFORMED + exec** 3/3 |
| `poc_reflect.js` (F1, no class) | 1 | gcc ASan | **UAF reproduced** |
| `poc_sweep_stride16.js` (F1 on app snapshot) | 1 | 7a23d8e ASan, 6 MiB | **UAF reproduced** (`logs/poc_uaf_7a_asan.txt`) |
| `poc_reclaim_groups.js` (F1 reclaim) | 1 | release, arena | **controlled group name `EVIL`** |
| `oom_regexp_probe3.js` (F2) | 1 | gcc ASan, 6 MiB | OOM caught as `null`, runtime recovered (`11`) |
| `f2_helper.js` (F2) | 20 cycles | 7a23d8e / HEAD release, 6 MiB | 20/20 nulls + recovery; `sweep` first_ok=2–3; 16 cycles in 76–105 ms @300 ms |
| `f2_fillsize.js` (F2) | 10 sizes | release, 6 MiB | 8/32–512 B catchable; 16/1024/4096/16384 B uncatchable (filler-size caveat) |
| `f1_addrs.js`, `f1_bytes.js`, `f1_range.js` (F1) | 3 probes | release, 6 MiB | forward-only; app/rt below, libc +42–46 TiB; mapped ~6–7 MiB; UTF-8 lossy, no pointer |
| 72879 IDA | 4 functions | static arm64 libtmessages 72879 | `JS_NULL` fallback + tag-gated uncatchable marking confirmed |

---

## 6. Secondary findings (non-memory)

### F2 — bare-null OOM bypasses #1810's "uncatchable" policy (new)

`JS_ThrowOutOfMemory()` → `JS_ThrowInternalError()` → `JS_ThrowError2()`.
If the error object cannot be allocated, `JS_MakeError()` fails and the code
substitutes `JS_NULL` ("out of memory: throw JS_NULL to avoid recursing",
8449–8456). `JS_ThrowError()` then calls `js_set_uncatchable_error(
current_exception, true)`, but the helper returns early for non-object values
(12078–12086). The thrown value is a plain catchable `null`.

PoC `oom_regexp_probe3.js` (6 MiB): fill the heap with live `RegExp` objects
until the OOM; `catch (e)` sees `null`; drop the fill and continue
(`got + (ok ? 10 : 0)` → `11`). The control case (`new ArrayBuffer(1 << 30)`,
where the error object still fits) remains uncatchable
(`EXCEPTION: InternalError: out of memory`).

Impact: #1810's design ("OOM cannot be caught, so try/catch probing is
blocked") is not enforced when the heap is exhausted by small objects. This
gives pure JS a deterministic OOM-injection-and-recovery primitive — directly
relevant to the OOM-gated bug class (#1855, #1852, …) and to fill-to-OOM
tuning for F1 (constructor OOMs above the window arrive as catchable nulls if
the search overshoots). Not a memory-corruption primitive by itself and it does
not resurrect
#1827's original route (the base-class `lastIndex` define is still
infallible).

Related upstream work (checked): #1810 (closed, this bypasses it), #1776–
#1778 (open, uncatchable exceptions leaking into promise/module/async
generator results), #1773/#1779 (opt-in terminal memory-limit semantics).
This specific `JS_NULL` fallback escape was not found in the issue tracker.

#### F2 on the app snapshot 7a23d8e and the 72879 binary (verified)

The app snapshot is quickjs-ng master at **7a23d8e** (2026-10-23), i.e. after
#1810 and before #1827.  It has the same code: the `JS_NULL` fallback at
7a23d8e:`quickjs.c:8451-8452` and the tag check in `js_set_uncatchable_error`
at 12078-12086.  Built from the codeload tarball (`lab/.../src_7a23d8e`,
`verify_snapshot.sh`) and run under the 6 MiB app model:

```
once=true
cycles=20 nulls=20 objerr=0 ok=20 ms=98        # all 20 OOMs caught as null
sweep m=64 first_ok=2 nulls=1 objerr=0 ms=0    # small-object headroom probe
```

The control (one oversized `new ArrayBuffer(1<<30)`, error object still fits)
remains **uncatchable** (`EXCEPTION: InternalError: out of memory`), so the
#1810 flag is active and the null is a genuine bypass, not a missing feature.

The **72879 binary** was verified statically in IDA (no device; 27 MB arm64
`libtmessages.49.so` from `apks/13.2.0 (7287).apk`):

* `JS_ThrowError2` @ **0x170A658**: when `JS_MakeError` returns tag 6
  (`JS_TAG_EXCEPTION`), the code sets the value to `JS_NULL` (tag 2) and stores
  it in `rt->current_exception` (rt+1288/rt+1296) — the exact fallback.
* `JS_ThrowInternalError` @ **0x170A510**: after throwing, it marks uncatchable
  only `if (*(rt+1296) == -1 /* JS_TAG_OBJECT */)`, the object's class_id is 3
  (`JS_CLASS_ERROR`) and does `*(uint16_t *)(obj+16) |= 0x40` (the
  `is_uncatchable_error` bit).  A `JS_NULL` (tag 2) never enters this branch.
* `JS_ThrowError2` has the same tag == -1 / class 3 / bit 0x40 gate for
  propagating the uncatchable state to the runtime/frames.
* `JS_ThrowOutOfMemory` @ **0x170A468** checks `in_out_of_memory` at
  `rt+1305`, calls `JS_ThrowInternalError` @ 0x170A510 with `"out of memory"`
  and resets it; 0x1718580 is a string-allocation site with the same inlined
  guard/throw (second fingerprint).
* `js_regexp_exec` @ **0x177494C** still references the string
  `"out of memory in regexp execution"` (0x1774e58), which HEAD replaced by
  `JS_ThrowOutOfMemory` — fingerprint that 72879 is the 7a23d8e-era snapshot.

IDB (saved): `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_72879_f2_annotated.i64`;
pseudocode dumps in `lab/qjs_regexp_audit/logs/ida_72879_*.txt`.  The ARM64
binary itself was not executed (no device); the behavior test is on the exact
source snapshot, and the binary check confirms the same fallback/marking code.

#### F2 single-eval probe/sweep usability

`f2_helper.js` is the compact helper: `fill()` exhausts the heap with small
objects and records `e === null` **without allocating in the catch** (a
`{e:e}` allocation there would itself OOM and escape); the caller then frees
`KEEP` and probes.  Measured (release, 6 MiB):

| operation | result |
|---|---|
| `once()` | true (null caught + 64-byte probe succeeds after freeing) |
| `cycles(20)` | 20/20 nulls, 20/20 probes OK, 98–326 ms → ~5–16 ms/cycle |
| `cycles(16)` under **300 ms** | 16/16, 76–105 ms |
| `sweep(64)` | `first_ok=2..3`, 1–2 catchable nulls, ~0–1 ms |
| under ASan (arena off) | same, 20/20, ~44 ms/cycle |

So a **full fill→catch→free→probe cycle costs ~5–16 ms** and a small-object
headroom sweep is essentially free; a 300–500 ms eval allows roughly 20–40
cycles/retries.  Rules learned:

* nothing may allocate between the OOM and freeing the filler;
* the filler must be made of **small** objects (`{}` or 32–512-byte
  allocations): with 8/32/64/128/256/512-byte `ArrayBuffer`s the OOM is a
  catchable null and recovery works; with 16/1024/4096/16384-byte fillers the
  failing request leaves room for the error object and the OOM is
  **uncatchable** (the eval aborts).  The 16-byte anomaly shows the exact
  boundary is arena-state dependent — always verify `e === null`.
* a failed **small** probe on a full heap is catchable; a failed **large**
  probe while headroom exists is not (the error object fits), so probes should
  run with the heap full and small requests.

This is the usable form for N1/C1/C2: deterministic OOM injection with
recovery and small headroom probing inside one eval (e.g. retry a groom that
failed, or bisect free headroom by freeing K small objects and probing).  It
does not make a full 6 MiB heap sweep cheap: each cycle refills the heap
(~5–16 ms) and only ~20–40 fit in the widget budget; for large sweeps the
fixed-fill/offline calibration approach is still needed.

### F3 — lying `flags` getter loops without progress (observation)

`RegExp.prototype[@@match]`/`[@@replace]` trust the `flags` getter. If it says
`"g"` for an actually non-global regexp, the native loop keeps calling
`RegExpExec`, which never advances `lastIndex`; the match array grows until
the heap is exhausted. The unicode/surrogate variant (`/(?:)/gu` + getter
returning `"g"`) regresses `lastIndex` across a surrogate pair. The loop is
bounded by the 500 ms budget because non-sticky bytecode polls via
`REOP_goto` (`libregexp.c:3037`), but at 6 MiB it can OOM before the first
poll (10 000 polls), yielding the F2 null. Not a memory bug; kept in
`poc_lying_flags_dos.js` for completeness.

---

## 7. Blockers / limitations

* No device run: source+lab only, as requested. The app snapshot is v0.17.0
  (pre-#1827); the device exposure of the *original* bug is the already-known
  #1827. **F1 is also present verbatim in v0.17.0 / 7a23d8e**: the ignored
  `JS_DefinePropertyValue(lastIndex)` is at `v0.17.0:quickjs.c:49304-49305`
  and the post-match `JS_SetProperty` before `lre_get_groupnames` at
  49800-49804. The 7a23d8e ASan build reproduces the UAF end-to-end
  (read `js_regexp_exec:49808`, free `js_regexp_compile:49460`;
  `logs/poc_uaf_7a_asan.txt`). So the app has two independent routes: the
  known #1827 and F1; fixing #1827 does not remove F1.
* F1's trigger needs heap exhaustion at the subclass `lastIndex` define. On
  the app's real allocator (Scudo + quickjs arena, 4 KiB chunks) the fill
  granularity differs from the lab: the lab proves the malformed object and
  the UAF end-to-end on gcc/clang ASan and the reclaim on the arena release
  build; on-device grooming/tuning was not attempted here (follow-up: fill to
  OOM as in F2, free a large ArrayBuffer, then re-allocate it with decreasing
  sizes to move the headroom in allocator size-class steps).
* The 500 ms widget budget bounds the fill/search loop: a 1-byte search is too
  slow (interrupted after ~2–3 k fill attempts on the release build), but a
  16-byte stride finds the ~100-byte window within the budget (3/3 runs,
  `logs/poc_stride16_rel.txt`). The device baseline still needs calibration
  (or the fixed-fill approach of the earlier #1827 work).
* #1828 (`unicode_script` fail loop) is fixed at HEAD by 081d50c; not
  re-reported. BJSON/`JS_ReadObject` regexp paths are not source-reachable
  from the widget and were excluded.
* F2's threshold and the F1 window are allocator/build dependent; the
  *mechanisms* are source-level.
* F1's read range was measured on x86-64 lab builds: app text **below** the
  block (~0.24–1.0 GB depending on ASLR), `JSRuntime` ~167 KB **below**,
  libc +45–46 TiB **above**, mapped forward window ~6–7 MB (SIGSEGV at
  +8 MB); the UTF-8
  decode also destroys non-ASCII pointer bytes.  On the Android/Scudo layout
  the relative order may differ, but the lossy decode and the lack of fault
  recovery keep it a heap-read primitive, not a pointer leak.
* The 72879 verification is static (IDA), not an execution of the ARM64 app
  binary: no device was used.  The behavior was measured on the exact source
  snapshot (7a23d8e) instead.

---

## 8. Artifacts and reproduction

`lab/qjs_regexp_audit/`:

| File | Purpose |
|---|---|
| `src/` | quickjs-ng e22ce4d shallow clone (tested revision) |
| `src_7a23d8e/` | app snapshot source (quickjs-ng 7a23d8e, 2026-10-23) |
| `verify.sh` | HEAD: asan/gcstress/clang/scudo/release, cases, fuzz, F1 PoCs |
| `verify_snapshot.sh` | 7a23d8e: F2 helper, filler matrix, F1 addresses/range/fidelity |
| `appmodel_run.c` | 6 MiB / 500 ms / no-host-API runner (`print`, `trace`, `mem`) |
| `poc_sweep_inprocess.js` | **F1**: in-process fill search + UAF (`r.exec`) |
| `poc_sweep_stride16.js` | **F1**: 16-byte strided search, fits the 500 ms budget |
| `poc_reflect.js` | **F1**: same via `Reflect.construct` (no class syntax) |
| `poc_reclaim_groups.js` | **F1 reclaim**: fake header, `groups=EVIL` on release/arena |
| `poc_reclaim_off.js` | **F1 reclaim check**: fake header with NAMED_GROUPS off → `groups=<undefined>` |
| `poc_lastindex_setter_dead.js` | base-class `lastIndex` setter is unreachable |
| `poc_subclass_lastindex.js` | single-fill subclass PoC (fixed fill) |
| `oom_regexp_probe3.js`, `oom_probe1.js` | **F2**: catchable bare-null OOM |
| `f2_helper.js` | **F2**: compact fill/catch/free/probe helper (`once`,`cycles`,`sweep`) |
| `f2_fillsize.js` | **F2**: filler-size matrix (small vs uncatchable large fills) |
| `f1_addrs.js` | **F1**: reclaimed-block vs app/rt/libc addresses |
| `f1_bytes.js` | **F1**: UTF-8 fidelity of the group-name read |
| `f1_range.js` | **F1**: forward read-range probe (mapped window / SIGSEGV) |
| `poc_lying_flags_dos.js` | F3 observation |
| `fuzz_regexp2.js`, `lre_regfuzz.c` | JS-API fuzzer / libregexp register fuzzer |
| `cases/`, `t1827.js`, `logs/` | 20 ordering scenarios, #1827 regression, raw logs |

Key logs: `logs/poc_uaf_inproc.txt` (gcc ASan UAF), `logs/poc_uaf_clang.txt`
(clang ASan UAF), `logs/poc_uaf_scudo.txt` (Scudo, silent),
`logs/poc_reclaim.txt` (`groups=EVIL`), `logs/poc_reclaim_off.txt`
(`groups=<undefined>`), `logs/poc_stride16_rel.txt`, `logs/arena_check.txt`
(arena-off proof), `logs/fuzz_*`, `logs/lre_status.txt`;
`logs/f2_helper_*.txt`, `logs/f2_fillsize_*.txt`, `logs/f2_control_7a.txt`,
`logs/f1_addrs_*.txt`, `logs/f1_bytes_*.txt`, `logs/f1_range*.txt`,
`logs/poc_uaf_7a_asan.txt`;
`logs/ida_72879_JS_ThrowInternalError.txt`, `..._JS_ThrowError2.txt`,
`..._JS_ThrowOutOfMemory.txt`, `..._js_alloc_string_oom.txt`,
`..._js_regexp_exec.txt`.

72879 static evidence: IDB
`<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_72879_f2_annotated.i64`
(`JS_ThrowInternalError` 0x170A510, `JS_ThrowError2` 0x170A658,
`JS_ThrowOutOfMemory` 0x170A468, `js_alloc_string_oom` 0x1718580,
`js_regexp_exec` 0x177494C).

```sh
cd lab/qjs_regexp_audit
git clone --depth 1 https://github.com/quickjs-ng/quickjs.git src   # e22ce4d

# primary ASan build (gcc => __SANITIZE_ADDRESS__ => arena off)
CC=gcc cmake -S src -B .build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"
cmake --build .build-asan -j
clang -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -I src \
  appmodel_run.c .build-asan/libqjs.a .build-asan/libqjs-libc.a \
  -lm -lpthread -o appmodel_asan

./appmodel_asan t1827.js 6 500                    # #1827 regression
./appmodel_asan poc_sweep_inprocess.js 6 120000   # F1 -> ASan UAF
./appmodel_asan poc_reflect.js 6 120000           # F1 via Reflect.construct
./appmodel_asan oom_regexp_probe3.js 6 5000       # F2 -> 11

# reclaim demo: release build with the 4 KiB arena active
CC=gcc cmake -S src -B .build-rel -DCMAKE_BUILD_TYPE=Release
cmake --build .build-rel -j
gcc -O2 -I src appmodel_run.c .build-rel/libqjs.a .build-rel/libqjs-libc.a \
  -lm -lpthread -o appmodel_rel
./appmodel_rel poc_reclaim_groups.js 6 280000     # FOUND + groups=EVIL

# app snapshot 7a23d8e: F1 UAF under ASan (arena off)
CC=gcc cmake -S src_7a23d8e -B .build-7a-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"
cmake --build .build-7a-asan -j
gcc -O1 -g -fsanitize=address -I src_7a23d8e appmodel_run.c \
  .build-7a-asan/libqjs.a .build-7a-asan/libqjs-libc.a -lm -lpthread -ldl \
  -o appmodel_7a_asan
ASAN_OPTIONS=detect_leaks=0 ./appmodel_7a_asan poc_sweep_stride16.js 6 150000

# clang ASan and Scudo (must pass -D__SANITIZE_ADDRESS__ to disable the arena)
CC=clang cmake -S src -B .build-clang -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -D__SANITIZE_ADDRESS__" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
CC=clang cmake -S src -B .build-scudo -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=scudo -D__SANITIZE_ADDRESS__" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=scudo"
```
