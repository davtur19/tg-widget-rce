# quickjs-ng class fields / private names / destructuring / iterator helpers

Target: `quickjs-ng` master **e22ce4d** ("Clear Array.find value ownership
after release (#1826)") and app snapshot **7a23d8e** ("Fix leak in
JS_ReadBigInt on truncated input"). Host-only lab; no device, no bot.

Date: 2026-11-05. Sources and all artifacts are durable under
`lab/qjs_class_audit/`.

---

## 1. Verdict

**F1 (new, memory corruption):** an OOM while parsing a class whose field
initializer needs a constant-pool slot is ignored by `emit_class_init_end()`.
The failed `cpool_add()` returns `-1`, and `js_create_function()` later stores
the child function at `fd->cpool[-1]` instead of failing. In release builds
the `assert(cpool_idx >= 0)` is compiled out, so this is a **16-byte
heap-buffer-overflow write before a `JSValue` array**. With the default
allocator it overwrites the backing chunk size and/or the QuickJS block header
and is reliably followed by glibc heap-metadata aborts
(`free(): invalid next size`, `corrupted size vs. prev_size`,
`malloc(): invalid next size (unsorted)`). ASan reports
`heap-buffer-overflow WRITE of size 16` at `js_create_function`.

The trigger is plain ECMAScript under the app model (6 MiB
`JS_SetMemoryLimit`, no host APIs): a large `ArrayBuffer` places the cap near
the parser's constant-pool growth, a `String.prototype.repeat` result tunes the
last ~4 KiB in 8-byte steps, and `eval()` compiles a class with 62 empty
methods plus two fields. The same structure crashes the *release* build and is
caught by ASan on both **e22ce4d** and **7a23d8e** (only the filler `TUNE`
differs between allocator configurations).

**S1 (secondary, OOM-only crash/OOB read):** `resolve_scope_var()`'s
eval-closure lookup does `goto has_idx` even when `get_closure_var()` returns
`-1` on OOM. `has_idx` immediately dereferences `s->closure_var[idx]` with
`idx == -1`. With no prior closure variable this is a null-pointer `-8` access
(UBSan). With one prior closure variable it is a read before the array; the
compile then embeds `OP_get_var_ref 0xffff`. In every tested configuration a
later allocation also failed, so the runtime `var_refs[65535]` read was not
reached. It is a distinct parser-OOM defect (the open #1782 dbuf check would
not catch it), but only a compile-time DoS was demonstrated.

No UAF, double-free, or controlled type confusion was found in the runtime
class-field/private-brand, destructuring, or iterator-helper state machines.
The negative coverage is documented in §6.

---

## 2. Builds and app model

All builds use `-D__SANITIZE_ADDRESS__` so QuickJS's 4 KiB arena is bypassed
and every block is visible to ASan. Two source trees are kept:

| tree | commit | purpose |
|---|---|---|
| `src/` | e22ce4d | latest |
| `src_7a/` | 7a23d8e | app 72799/72879 snapshot |

Build matrix (GCC; `Release` has `NDEBUG`, i.e. the app's assert behaviour):

| binary | flags | use |
|---|---|---|
| `appmodel_asan_ndebug` | Release + ASan + UBSan | ASan evidence (e22ce4d) |
| `appmodel_rel` | Release, default allocator | glibc evidence (e22ce4d) |
| `appmodel_7a_relasan` | Release + ASan + UBSan | ASan evidence (7a23d8e) |
| `appmodel_7a_rel` | Release, default allocator | glibc evidence (7a23d8e) |
| `appmodel_gcstress` | ASan + UBSan + `FORCE_GC_AT_MALLOC` | GC-stress fuzz |
| `appmodel_asan` | Debug + ASan + UBSan | fail-fast assert check |

Harness (`appmodel_run.c`): one runtime/context, `JS_SetMemoryLimit(6 MiB)`,
1 MiB stack, 500 ms cooperative interrupt, `print`, `trace`, `mem`, `gc`.
`mem()` returns `JS_ComputeMemoryUsage().malloc_size`; `limit(delta)` is a lab
hook that sets the hard limit to `malloc_size + delta`. The catchable-bare-null
OOM helper (called F2 in `notes/audit_regexp_postfix.md`) is kept as
`f2_helper.js` and was used for in-process OOM probing; F1 does not depend on
it because the bad store happens before the exception becomes observable.
**The final F1 PoC does not use any of these hooks** — that is only for the
diagnosis/sweeps.

Build logs: `logs/build_*.log`, `logs/cmake_*.log`.

---

## 3. F1 — class-field constant-pool OOM → `cpool[-1]` OOB write

### 3.1 Root cause

`cpool_add()` (`quickjs.c:24159`) is the only allocator for the per-function
`JSValue` constant pool:

```c
static int cpool_add(JSParseState *s, JSValue val)
{
    JSFunctionDef *fd = s->cur_func;
    if (js_resize_array(s->ctx, (void *)&fd->cpool, sizeof(fd->cpool[0]),
                        &fd->cpool_size, fd->cpool_count + 1))
        return -1;
    fd->cpool[fd->cpool_count++] = val;
    return fd->cpool_count - 1;
}
```

`emit_class_init_end()` (`quickjs.c:25492`) stores the result without
checking it and immediately bakes it into bytecode:

```c
cpool_idx = cpool_add(s, JS_NULL);
cf->fields_init_fd->parent_cpool_idx = cpool_idx;
emit_op(s, OP_fclosure);
emit_u32(s, cpool_idx);          /* 0xffffffff on failure */
```

The same unchecked pattern exists in:

* `js_parse_class_default_ctor()` (`quickjs.c:25567`: the constructor's cpool
  entry; the bad value is later patched into `OP_push_const` at
  `quickjs.c:25982`), and
* `js_parse_function_decl2()` (`quickjs.c:37939`, every function/method
  closure).

`js_create_function()` then walks the parent's child list
(`quickjs.c:37076-37086`):

```c
cpool_idx = fd1->parent_cpool_idx;
func_obj = js_create_function(ctx, fd1);
if (JS_IsException(func_obj))
    goto fail;
assert(cpool_idx >= 0);
fd->cpool[cpool_idx] = func_obj;
```

In Debug the assert fires. In Release (`NDEBUG`, the app binary) it is
removed, and `fd->cpool[-1] = func_obj` writes `sizeof(JSValue)` bytes before
the array.

### 3.2 Why it is reachable only near OOM

`js_resize_array()` grows the cpool by 1.5× (`max(req, size*3/2)`,
`quickjs.c:2167`). A normal parse has plenty of headroom, so `cpool_add()`
never fails. The bug needs an allocation failure at a cpool growth, followed
by enough headroom for the *child function* `js_create_function()` (which
allocates the `JSFunctionBytecode` + bytecode) to still succeed. Method
children compiled before the field-init child also free their `JSFunctionDef`
and bytecode buffers, which is what creates that headroom.

The PoC uses 62 empty methods so that, when the class-fields initializer is
appended, the parent cpool is at the worst point:

* 62 methods + 1 default constructor = 63 entries;
* cpool size is exactly 63 (`4,6,9,13,19,28,42,63`);
* the fields-init entry requests 64 → `js_resize_array()` allocates
  94 entries (94×16 = 1504 bytes; growth = **496 bytes**).

The fields-init child's `JSFunctionBytecode` then still fits in the leftover
(<496 B), so the child compiles and the child loop executes the bad store.
Empirically the usable accounting window is ~100 bytes wide; the filler PoC
tunes it with a string in 8-byte steps.

### 3.3 PoC

Two files, same source, different constant because ASan changes allocator
accounting:

* `lab/qjs_class_audit/poc_cpool_oom.js` — `TUNE = 2700`, release/default
  allocator (also the app-shaped run).
* `lab/qjs_class_audit/poc_cpool_oom_asan.js` — `TUNE = 6940`, ASan build.

```js
var TUNE = 2700;
var BIGB = 6143000;
var SRC = "(class C {";
for (var i = 0; i < 62; i++) SRC += "m" + i + "(){} ";
SRC += "a = 1; b = 2; })";
var AB = new ArrayBuffer(BIGB);   // coarse 4 KiB headroom step
var S = "y".repeat(TUNE);         // fine 8-byte step
try { var C = eval(SRC); } catch (e) { }
```

`BIGB` consumes 6,143,000 bytes of the 6,291,456-byte cap; `AB` accounting is
rounded to 4 KiB, `S` moves the residual by ~8 bytes per character. The
source string is ~700 bytes. No `mem()`/`limit()`/`gc()` is used.

### 3.4 Evidence

ASan, e22ce4d, `logs/final/poc_cpool_asan_e22.txt`:

```
ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 16
    #0 js_create_function quickjs.c:37083
0x...e78 is located 8 bytes before 1016-byte region [0x...e80,0x...e278)
allocated by ... cpool_add ... js_parse_function_decl2 ... js_parse_class
```

ASan, 7a23d8e, `logs/final/poc_cpool_asan_7a.txt`: same write at
`src_7a/quickjs.c:37017`; allocation stack through `cpool_add`.

Release (default allocator), e22ce4d `logs/final/poc_cpool_rel_e22.txt` and
7a23d8e `logs/final/poc_cpool_rel_7a.txt`:

```
free(): invalid next size (normal)
Aborted (core dumped)          # exit 134
```

Other allocator layouts in the sweeps produced
`corrupted size vs. prev_size` and `malloc(): invalid next size (unsorted)`.

Window sweep (release e22ce4d, hard-coded TUNE, one process per value):
TUNE **2664–2772** aborts; 7a23d8e: **2682–2790**. ASan e22ce4d:
**6882–6988**; 7a23d8e: **6900–7004**. The chosen 2700 / 6940 are inside all
four windows. Raw range files are under `logs/sweep_tpl_*`.

### 3.5 What the 16-byte write corrupts

On 64-bit non-NAN-boxing `JSValue` is `{union u; int64_t tag;}` (16 bytes).
With the default allocator the array user pointer is `malloc_ptr + 8`
(QuickJS's `JSMallocBlockHeader`), so `cpool[-1]` spans:

```
cpool-16 .. cpool-9   JSFunctionBytecode *b      (u.ptr)
cpool-8  .. cpool-1   JS_TAG_FUNCTION_BYTECODE (-2, 0xfffffffffffffffe)
```

* `cpool-16` is the backing allocator's chunk-size field for the cpool block
  (glibc `size`). Writing the pointer makes it enormous/unaligned; malloc/free
  detects it on the next relevant allocation.
* `cpool-8` is QuickJS's block header: `block_idx = 0xfffe` (not
  `JS_ARENA_FREE_NIL` = 0xffff), `block_size_idx = 0xff`. If free ever reaches
  `js_arena_free()` with this header, it indexes `arena_block_sizes[0xff]`
  (global OOB read) and computes an attacker-uncontrolled bogus `JSArena *`,
  then writes into it.
* If an allocator tolerated the chunk-size corruption, class evaluation would
  next execute the baked-in `cpool[-1]` operands: `OP_fclosure 0xffffffff`
  (field/static initializer) and `OP_push_const 0xffffffff` (default
  constructor). Those index `b->cpool[0xffffffff]` and feed the resulting
  arbitrary `JSValue` to `js_closure2()` / `OP_define_class` as a function
  bytecode pointer — a latent type-confusion/OOB-read stage.

### 3.6 Exploitability assessment

Demonstrated: deterministic heap-metadata corruption and abort from plain JS
under the 6 MiB app model. The write offset is fixed (`cpool[-1]`, i.e. −16
from the array) and the written value is a heap pointer to the
`JSFunctionBytecode` plus a fixed tag, so this is not a controlled-value
write. No read/write primitive or leak was obtained: the process aborts before
user JS runs again, and at exit the corrupted cpool is freed. The second-stage
`cpool[0xffffffff]` indices are real, but reaching them needs an allocator
that survives the first corruption, which glibc/Bionic-style allocators do
not. I am reporting F1 as a new memory-safety bug (CWE-787), not as a proven
RCE.

### 3.7 Suggested fix

1. `emit_class_init_end()` must return an error and `js_parse_class()` must
   propagate it when `cpool_add()` returns < 0.
2. Check `cpool_add()` in `js_parse_class_default_ctor()` and in
   `js_parse_function_decl2()` (or make `cpool_add()` set/keep the parser error
   state and make the callers abort).
3. Defensive backstop in `js_create_function()`: treat
   `fd1->parent_cpool_idx < 0` (or `>= fd->cpool_count`) as a failed parse and
   return `JS_EXCEPTION` instead of indexing the pool; debug assert alone is
   not enough because `NDEBUG` is the shipped configuration.
4. The open #1782 `dbuf_error` check is necessary but insufficient: the cpool
   failure here does not set the bytecode DynBuf error flag.

---

## 4. S1 — eval-closure OOM → `closure_var[-1]` (secondary)

`resolve_scope_var()` scans a direct eval's captured variables at
`quickjs.c:34201-34213`:

```c
if (fd != s) {
    idx = get_closure_var(ctx, s, fd, JS_CLOSURE_REF, idx1, ...);
} else {
    idx = idx1;
}
goto has_idx;                     /* no idx < 0 check */
...
has_idx:                          /* quickjs.c:34251 */
    if (...)
        s->closure_var[idx].is_const;   /* 34253 */
    ...
    if (s->closure_var[idx].is_lexical) /* 34322: idx == -1 */
```

`get_closure_var()`/`add_closure_var()` can fail on OOM and return `-1`. The
`has_idx` label is inside the normal `if (idx >= 0)` block, so this `goto`
bypasses the guard. `s->closure_var` is NULL when the child has no closure
variables yet → UBSan "applying non-zero offset ... to null pointer" at
`quickjs.c:34322` (7a23d8e: 34256). With a previous successful closure add the
array is live, the read is before it, and the compiler emits
`OP_get_var_ref 0xffff`; runtime would read `sf->var_refs[65535]`.

Trigger: class fields are a convenient child function inside a direct eval:

```js
function outer() {
  var a = 11, b = 22;
  var src = "(class C { #p = 1; x = a; y = b; z = this.#p; })";
  limit(delta);                    // lab hook; app: filler as in F1
  eval(src);
}
```

Sweeps hit the UBSan null access at deltas ~2286–2400 on both commits
(`logs/final/poc_evalclos_asan_e22.txt`,
`logs/final/poc_evalclos_asan_7a.txt`). In the release-instrumented build the same path
prints `EVALCLOSFAIL atom=602 cc=1` followed by `NEGVARREF idx=-1` (twice,
for the two captured vars) and emits the `0xffff` operand
(`logs/final/s1_negvarref_instr_e22.txt`); the remaining OOM then aborts
compilation before the function can run.

This is an OOM-only compile-time crash/OOB read. It is not #1865 (that is the
`uint16_t var_ref_idx` truncation at 65,536 captured variables); it is also not
covered by #1782's `dbuf_error` check because the bytecode buffer is fine.
Impact demonstrated: DoS. Fix: check `idx < 0` before `goto has_idx` and
propagate the OOM as a parse failure.

---

## 5. Deduplication (GitHub, 2026-11-05)

Queries against `quickjs-ng/quickjs` issues/PRs (open and closed):
`cpool`, `cpool_add`, `parent_cpool_idx`, `emit_class_init_end`,
`class field OOM`, `class fields out-of-bounds`, `parser heap write`,
`invalid next size`, `private brand crash`, `iterator helper leak`.

* No report matches F1. The nearest is open PR **#1782** ("Fix out-of-bounds
  read when the parser runs out of memory"): it is an OOB *read* in
  `resolve_variables()` caused by a truncated bytecode DynBuf, and its fix
  checks `dbuf_error()` in `js_create_function()`. F1 is an OOB *write* caused
  by an ignored `cpool_add()` return; the DynBuf error flag is not set.
* #1865/#1869 are the captured-variable count truncation; #1866 is function
  metadata OOM; #1852/#1855 are OOM property-definition bugs; #1892 is the
  known signed refcount overflow; #1798/#1651/#1652 are spec/evaluation-order
  issues. None covers F1 or S1.
* Project-local reports (`notes/audit_regexp_postfix.md`,
  `notes/qjs_core_audit_negative_20261101.md`, `qjs_latest_audit.md`,
  `qjs_novel_audit.md`) do not contain this class-field cpool path.

If the maintainers decide F1 is part of a general "parser OOM hardening"
campaign, the write and the negative cpools are still a distinct code path
from #1782 and must be fixed separately.

---

## 6. Negative coverage (no new memory-safety bug found)

Source review and dynamic checks, all under 6 MiB / ASan / GC-stress where
applicable:

### 6.1 Class fields, private names, brands, home object

* `JS_DefinePrivateField`, `JS_GetPrivateField`, `JS_SetPrivateField`,
  `JS_AddBrand`, `JS_CheckBrand`, `OP_define_private_field`,
  `OP_get_private_field`, `OP_put_private_field`, `OP_check_brand`,
  `OP_add_brand`, `OP_define_field`, `OP_set_home_object`.
* Fields before/after methods, use-before-declaration, getter/setter pairs,
  static private fields/methods, static blocks, computed names, fields named
  `get`/`set`/`static`, `extends null`, derived constructors, two `super()`
  calls, `super()` in arrows, `super.x` in static/instance field initializers,
  replaced `.prototype`, non-extensible objects returned from `super()`,
  proxies and revoked proxies as `this`, private field assignment targets in
  destructuring/for-of/for-in/compound assignment, nested classes and private
  name shadowing, `eval()` inside methods and field initializers, class
  declarations inside `with`, classes captured by generators/async functions,
  mapped/default/destructured/rest parameters and `arguments`.
* No ASan/UBSan hit. Private-named properties are data-only by construction;
  the filters in `JS_GetOwnPropertyNamesInternal()` exclude
  `JS_ATOM_KIND_PRIVATE`. The `JS_AddBrand` "borrow the atom from the symbol
  and `JS_FreeAtom`" pattern was checked for both home-object and instance
  paths; references balance.
* OOM sweep of class definition + construction with private fields/methods/
  static blocks (6,001 limit values: deltas 0..24,000 step 4, one process per
  value): no sanitizer hit.

### 6.2 Destructuring, rest/spread/default parameters

* Object/array patterns, nested patterns, computed keys, defaults that call
  getters/`gc()`/throw, object rest and `OP_copy_data_properties` mask
  offsets, exclude lists, iterator close on abrupt completion, array-like and
  iterator sources, `arguments`/eval interactions, spread of arrays and
  custom iterables.
* No ASan/UBSan hit in 48,000 randomized patterns plus the parameter matrix.
* OOM sweep (7,501 limit values: deltas 0..30,000 step 4): no sanitizer hit.

### 6.3 Sync iterator helpers

* `Iterator.concat`, `Iterator.from`, `Iterator.zip`, `Iterator.zipKeyed`,
  `map`/`filter`/`flatMap`/`take`/`drop`/`chunks`/`windows`, terminals
  `toArray`/`reduce`/`forEach`/`some`/`every`/`find`/`includes`/`join`.
* Buffer ownership in `JSIteratorHelperData` (`buf`, `buf_count`, `buf_size`),
  `JS_NewArrayFrom` ownership transfer, inner iterator teardown in
  `flatMap`, concat `running`/`done` reentrancy, extracted/`call`-ed methods,
  proxy-backed sources, callbacks that re-enter `next`/`return`/`gc`.
* No ASan/UBSan hit in 40,000 randomized chains (ASan) plus GC-stress runs.
* OOM sweep (10,001 limit values: deltas 0..40,000 step 4): no sanitizer hit.
* Observation (not claimed as memory-safety): `js_bytecode_eval()` leaks its
  `argv` when `JS_ReadObject()`/`JS_EvalFunction()` fails, and
  `js_bytecode_autoinit()` does not check builtin-argument allocations, so an
  OOM can pass a `JS_TAG_EXCEPTION` value as a normal argument to the lazy
  `Array.fromAsync`/`Iterator.zip(K)` builtins. Both are OOM-only; the
  exception-tag values are handled by the generic tag checks and no memory
  error was reproduced. Worth hardening while fixing OOM paths.

### 6.4 Proxy/Reflect

* Proxy `get`/`set`/`defineProperty`/`deleteProperty`/`ownKeys`/
  `getOwnPropertyDescriptor`/`construct` traps around private-field stamping,
  private brand checks, `Object.preventExtensions`/`seal`/`freeze`, revocable
  proxies, and `Reflect.construct` with custom `newTarget`.
* No UAF/OOB reproduced. The proxy object keeps its own `extensible` flag
  (private fields can be stamped onto proxies; documented in the source), and
  its shape properties are marked/freed by the generic object paths.

### 6.5 Fuzzer artifacts

* `fuzz_classes.js` (ASan, 4×20k iterations), `fuzz_destructuring.js`
  (4×12k), `fuzz_iter_helpers.js` (4×10k + GC-stress 2×40k):
  `logs/fuzz_*.log`, `logs/gc_fuzz_*.log`.

---

## 7. Reproduction

```sh
cd lab/qjs_class_audit

# F1: ASan evidence (both commits)
ASAN_OPTIONS=detect_leaks=0 ./appmodel_asan_ndebug poc_cpool_oom_asan.js 6 5000
ASAN_OPTIONS=detect_leaks=0 ./appmodel_7a_relasan poc_cpool_oom_asan.js 6 5000

# F1: release/default allocator (both commits)
./appmodel_rel    poc_cpool_oom.js 6 5000
./appmodel_7a_rel poc_cpool_oom.js 6 5000

# S1: compile-time eval-closure OOM (ASan/UBSan)
ASAN_OPTIONS=detect_leaks=0 ./appmodel_asan_ndebug oom_eval_class_probe2.js 6 5000 2286
ASAN_OPTIONS=detect_leaks=0 ./appmodel_7a_relasan oom_eval_class_probe2.js 6 5000 2286
```

A full rebuild is in `lab/qjs_class_audit/verify.sh`. The PoCs need only
`eval`, `ArrayBuffer` and `String.prototype.repeat`; the `TUNE` values are
allocator-accounting-specific and are documented per build.

---

## 8. Artifacts

```
lab/qjs_class_audit/
  poc_cpool_oom.js            F1 release PoC (TUNE=2700)
  poc_cpool_oom_asan.js       F1 ASan PoC (TUNE=6940)
  oom_eval_class_probe2.js    S1 trigger (limit() hook)
  logs/final/s1_negvarref_instr_e22.txt  S1 emitted 0xffff evidence
  oom_class_probe.js          F1 limit()-driven diagnosis
  fuzz_classes.js
  fuzz_destructuring.js
  fuzz_iter_helpers.js
  appmodel_run.c              harness
  verify.sh                   rebuild + reproduce + fuzz smoke
  README.md                   lab map and commands
  src/                        e22ce4d
  src_7a/                     7a23d8e
  logs/final/                 ASan + release PoC outputs
  logs/SWEEPS.txt              all sweep/fuzz counts
  logs/sweep_tpl_*/rc.txt     crash windows
  logs/fuzz_*.log, gc_fuzz_*.log
  logs/build_*.log, cmake_*.log
```

## 9. Limitations

* F1 was demonstrated on the source builds of both target commits, with the
  same app model (6 MiB, 500 ms, standard intrinsics). The exact filler `TUNE`
  is allocator-accounting-specific; a real widget payload may need a small
  sweep across sessions. No live device/emulator run was performed.
* F1 is a fixed-offset, fixed-value OOB write; no controlled read/write or
  RCE was demonstrated. The second-stage bad `cpool[0xffffffff]` operands are
  described as a latent risk, not a claim.
* S1 was only reachable as a compile-time crash/OOB read in the tested
  configurations; the runtime `var_refs[65535]` path was not reached because
  the remaining OOM aborts compilation.
* The negative results are time-boxed fuzzing/source review, not a proof of
  absence.

## 10. Dedup correction (2026-11-05)

**F1 is not a new root cause.** It is the same bug as **C1** in
`notes/audit_parser.md`: `emit_class_init_end()` ignores a failed
`cpool_add()` and stores `-1` in `parent_cpool_idx`, then
`js_create_function()` does `fd->cpool[-1] = func_obj`. The parser audit
already lists the three call sites (`js_parse_function_decl2`,
`emit_class_init_end`, `js_parse_class_default_ctor`). This class-field PoC
is a **new trigger** of C1, not a new bug; it is useful because it is pure
class syntax and reproduces on both `e22ce4d` and `7a23d8e`.

**S1 is also already known**: it is the prior project closure-OOM finding
(`get_closure_var()` returns -1, unchecked in `resolve_scope_var()`), listed
in `notes/audit_parser.md` §2 dedup. It is not a new root cause.

The negative coverage (private fields/brands/proxy, destructuring/rest/
spread/defaults, sync iterator helpers) remains valid and useful.
