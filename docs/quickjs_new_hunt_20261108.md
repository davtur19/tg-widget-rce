# QuickJS new-surface hunt — 2026-11-08 (host-only)

Follow-up campaign to the 18-bug inventory, the memory-bug ledger and the
object-model/MTE hunts. The task was to go after the **unchecked** surfaces
(interpreter/bytecode/stack, GC/refcount/finalizer order, parser/compiler,
async/generator/jobs, proxies/exotics, typed arrays/RAB, BigInt, atoms/shapes,
JSON, RegExp beyond #1827, serialization, C API) and produce a new unreported
0day or a controllable primitive.

Everything here is **host-only**: no device, no Frida, no bot, no payload
delivery. The Pixel was not touched; iPhone/Sony untouched. Network use was
limited to public advisory/tracker reading (allowed by the follow-up
instruction) — no payload infrastructure.

All artifacts are under `lab/quickjs_new_hunt/`.

---

## 0. Verdict (honest)

**No new RCE-capable 0day and no new memory-corruption primitive was found.**
The campaign produced:

1. **QNH-01 — a new-to-the-project array length invariant bug** (slow-array
   truncation leaves index properties above `length`). It is **unreported in
   quickjs-ng**, still present in the shipped fork `2dfeee3e`, in upstream
   `e22ce4d` and in the iOS engine `7a23d8e`; it is fixed only in
   bellard/quickjs (`3c4c6edc`, 2026-10-31, #585) and was not ported.
   A 55-method × 200-round ASan sweep found **no memory-safety consequence**:
   the bug is semantic (the array lies about its length). Details in §2.1.
2. **QNH-02 — a benign cross-engine number-formatting delta** (108 of
   1,097,348 targeted doubles print shorter strings than the 0.17.0 exact
   path; the shorter strings are the correct shortest round-trip forms). The
   fork commit's "output is unchanged" claim is false; the change is a fix.
3. **Two public open upstream bugs verified present in the shipped source**:
   - **#1570** (`async_func_mark` skips a *running* async frame's operand
     stack). The vulnerable state is reached in the shipped source under GC
     stress (instrumented proof in §2.3), but the upstream deterministic
     reproducer does **not** crash our harness. Public issue; not a 0day.
   - **#1787** (`resolve_labels` label leak): the shipped *debug* build
     aborts on `function f(){ for(;;) for(;;x) break; }`; release gives
     `InternalError: invalid opcode`. Compiler DoS only; public issue.
4. **#1518** (deserializer `free_function_bytecode` OOB read) confirmed in
   the shipped source; **not widget-reachable** (`JS_ReadObject` is host-only)
   and public/closed-not-planned.
5. **QNH-06 — the known public CPU-quota bypass (#1753) confirmed with a
   40-byte widget payload and measured.** `var a=[]; a.length=0xfffffffe;
   a.join('')` runs ~4.3 B iterations in C without an interrupt poll:
   20 M iterations take **1.05 s** even with a **100 ms** CPU deadline, so
   the full length is ~3.8 minutes in one call. The widget's 300 ms quota
   is only delivered at the *next* poll, i.e. after `join` returns. This is
   the existing open issue #1753 (public), not a 0day; recorded because the
   project's inventory did not have it and because it is the cheapest way
   to make the widget engine unresponsive after the memory limit has
   already been tripped (empty separator ⇒ no allocation per element).
6. **QNH-07 — parser nesting vs the JS stack limit: investigated, closed by
   evidence (not widget-reachable).** The widget engine never calls
   `JS_SetMaxStackSize` (RE: only `JS_NewRuntime` + 6 MiB + the interrupt
   handler), so it runs with the 1 MiB default. On a thread with ~1 MiB
   native stack, a 1.8 KB script of nested parentheses SIGSEGVs the process
   during parsing (measured at ulimit 1 MiB: n=900 crashes; ≥1.5 MiB throws a
   clean `RangeError: Maximum call stack size exceeded`). The widget's
   `twidget-host` thread has an **8 MiB** stack (armv7 tombstone mapping
   `7c830000-7d02ffff rw- 0 800000 [stack:6403]`), so the 7 MiB of headroom
   make it a clean RangeError — not a widget crash. Recorded because the
   configuration (default 1 MiB limit, no `JS_SetMaxStackSize`) would become
   fatal at a ≤1.5 MiB thread stack, and because the same measurement closes
   the "parser ignores the stack limit" hypothesis.
7. Four new **negatives** with fresh evidence:
   - interpreter stack invariant (`sp` inside `[stack_buf, stack_buf+stack_size]`)
     over **2,660 programs**: 0 violations;
   - interrupt-gated sweep of the fork's uncatchable-exception paths:
     **156 runs**, 0 sanitizer/assertion hits;
   - differential result comparison shipped-vs-0.17.0 over the **1,760**
     generated coercion/mutation cases: **0 divergences**;
   - dtoa Grisu3 under ASan/UBSan over **1,097,348** doubles: 0 reports;
   - the approved focused+long fuzz campaign (2 workers, 2 GB cap, `-DNDEBUG`,
     first-crash-stop) ran **1,891,616 execs** and produced **0 artifacts /
     0 sanitizer reports** (§5). The #1570 trigger was not found.

The most important structural result is a **recon correction** (§1): the
shipped engine is *not* v0.17.0. It contains essentially all of v0.18.0
(including the 0.18 security fixes) plus the post-0.18.0 master content, and
is missing **exactly the six known fork-master commits** (four memory fixes,
two non-memory). The n-day horizon of this target is therefore **closed and
known**; a new carrier must be an unreported bug in code that upstream also
ships today, or a fork-only bug in the perf/exception commits.

---

## 1. Shipped-engine baseline (recon, new and load-bearing)

### 1.1 Method

The fork source is `lab/fork_fuzz/src` (full git history, 1,267 commits,
HEAD `app-snapshot = 2dfeee3e`). The upstream range was fetched from the
public GitHub API and stored in
`lab/quickjs_new_hunt/recon/compare_v0170_v0180.json`.

For every commit in `v0.17.0..v0.18.0` (`6d46d07..d7215b0`) the ancestry of
`app-snapshot` was tested with `git merge-base --is-ancestor`.

### 1.2 Result

Every v0.18.0 commit is an ancestor of the shipped snapshot **except**:

| commit | what | memory? | shipped? |
|---|---|---|---|
| `5271a40b` | macOS CI runner | no | no |
| `081d50c2` | unicode_script() OOM infinite loop | DoS | fork has its own fix `53dd884` |
| `270b8c97`/`e6807861` | WASI exports | no | no |
| `7a23d8e3` | JS_ReadBigInt truncated-input leak | leak | fork has its own fix `2dfeee3` |
| `11e08c07`…`cea851c6` | Cosmopolitan libc | no | no |
| `d4cd8f40` | asynchronous dynamic import() | feature | no |
| `25a005b4` | **UAF freeing WeakMap with symbol values** | **UAF** | **no — MB-01** |
| `c1ed1943` | Array.fromAsync internal calls | no | fork has `b06baf9` |
| `7b5f588e` | CI temp dir | no | no |
| `d7215b0a` | version bump | no | no |

So the shipped engine already contains the 0.18.0 security fixes
(`19dbe852` String.repeat, `8e14a39f` JS_NewContext OOM UAF, `293ba089`
JSON.stringify leak, `6a9b5313` bound prototype, the uncatchable-exception
policy, …). The only *memory* fix it lacks from 0.18.0 is the WeakMap one
(already MB-01).

Post-0.18.0 upstream master (`d4187c7`, 2026-11-07) has exactly four commits:
BJSON RegExp refs (#1809), #1827, #1826 and the String `memchr/memcmp`
optimisation (#1897). The shipped snapshot is missing the three known memory
fixes (`f4fe478`, `2b62af1`, `f4dd164` in fork notation) and already contains
equivalent String indexOf/includes fast paths from the fork's own
`7ead61a` (2026-10-12) — i.e. it is *ahead* of 0.18.0 there.

**Consequence.** The "missing-fix set" of the shipped engine is exactly the
six fork-master commits from `memory_bug_log_20261107.md` §2. All are known
n-days (MB-01/03/04/05 + two non-memory). Any new finding has to be an
unreported bug in code that is also in upstream master, or fork-only code
(the perf commits and `9ddb1b8`).

### 1.3 Public knowledge used (read, not re-derived)

* **CVE-2026-0821/0822/1145/120438/120439/120440** — all "before 0.16.0"
  (TypedArray sort/constructor 32-bit overflow, Proxy ownKeys 32-bit
  overflow, Atomics.store leak). Shipped is 0.18-era → fixed.
* **v0.18.0 release notes / commit list** (§1.2).
* **100 open quickjs-ng issues** (stored in
  `recon/open_issues_20261108.json`). Security-relevant ones:
  #1570 async-frame GC UAF (open), #1865 var_ref_count truncation (open,
  known #1865), #1787 label leak (open), #1833 module-link var_refs (open),
  #1762 Promise-less context leak (open), #1518 vardefs OOB read (closed
  not-planned), #1856/#1753 missing interrupt polls (DoS), #1890 ToUint32
  vs ToLength (semantic), #1893/#1894 (= T1/T2), #1882 array length before
  extensibility (semantic, §2.1 family), #1770 TypedArray species content
  type (semantic; the non-empty-source copy throws, so no OOB).
* **bellard/quickjs 2026-09/11 commits** (public list): `3c4c6edc` slow
  array truncation (#585), `af2e2827`/`b25da592` JS_CreateProperty
  extensibility and add_fast_array_element OOM length (#593/#576),
  `092277ac` append_enumerate double iterator read, `f68db0e9` deserializer
  NULL refs, `cd97c2b4` build_backtrace OOM UAF, `552d5eba` ToCString leak,
  `5febaaa4` AutoInitProperty OOM, BigInt compare/decrement fixes.
  Checked against the shipped source where relevant (§2.5).

---

## 2. New results

### 2.1 QNH-01 — slow-array truncation breaks the array length invariant
**(new to the project; unreported in quickjs-ng; semantic — not memory-unsafe)**

| field | value |
|---|---|
| root cause | `set_array_length()` (quickjs.c:10814 shipped) second branch deletes every array-index property with `idx >= len` using `delete_property()`. `delete_property()` **compacts** the shape when `deleted_prop_count >= 8 && deleted_prop_count >= prop_count/2`, which moves the remaining properties down. The loop re-fetches `sh = p->shape; pr = &get_shape_prop(sh)[i];` and then continues with `i++`, so after a compaction it looks at the *next* entry of the compacted array and **skips** the entry that moved into slot `i`. Skipped configurable properties with index ≥ `len` survive, and the function then stores `cur_len = len` in the `length` property — below the surviving indices. |
| class | array length invariant violation (semantic). Not OOB: every fast-array consumer re-checks `count` vs `length`. |
| exact trigger | `let a=[0,1,2,3,4,5,6,7]; a[10]=1; a.length=0;` → `a.length === 0` but `a[10] === 1` and `Object.getOwnPropertyNames(a)` = `10,length`. Larger: 40 index props, delete every third, `b.length=5` leaves `14,16,17,19,20,…`. |
| tag domain | n/a (no memory violation) |
| OOM? | no |
| novelty | **not reported in quickjs-ng** (searched tracker: no array-truncation issue; #1882 is the neighbouring JS_CreateProperty extensibility ordering). Reported and fixed only in bellard/quickjs `3c4c6edc` (2026-10-31, #585); that fix is **not** in quickjs-ng `e22ce4d`/`1a402cb` nor in the shipped fork. |
| host repro | `lab/quickjs_new_hunt/interp/scripts/t_arrtrunc.js`; evidence `logs/arrtrunc_evidence.log`. Same output on `run_asan_shipped`, `run_asan_upstream` and `run_asan_ios` → shared by all three engines. |
| memory-safety sweep | `interp/scripts/t_arrinv.js`: builds the inconsistent state, then drives 55 array/JSON/typed-array/Object APIs × 200 rounds under ASan+UBSan (`run_spcheck`, arena off): 0 reports. The fast paths that could read `values[i]` all gate on `count32 == len` (`js_array_pop/join/push/splice/sort/append_enumerate/build_arg_list/…`), and the interpreter element opcodes gate on `idx < count`. |
| widget impact | none demonstrated. A widget can create arrays whose `length` lies, but `JSON.stringify` (the only bridge encoding) uses `length` and therefore drops the leftover elements. No memory primitive, no tag domain. |
| endgame | none (semantic). Recorded so it is not rediscovered as a bug and so a future array fast-path change that drops the `count == length` guard has a ready trigger. |

This is the only *new, unreported* defect found in the campaign. It is
honestly **not** an RCE carrier.

### 2.2 QNH-02 — dtoa Grisu3 output delta (benign; commit claim false)

| field | value |
|---|---|
| root cause | fork commit `74f2249` inserts a Grisu3 short-path into `js_dtoa()` (`dtoa.c`, 311 new lines). Its comment/commit message claims the output is unchanged versus the exact multi-precision path. |
| observed | On a 1,097,348-value targeted corpus (all powers of two ±6 ulp incl. subnormals ≈54k, all decimal powers ±6 ulp ≈16k, 200k integers, 200k random 64-bit patterns, 200k dense random in the fixed-format exponent window, 14k doubles near 2^53), **108 values produce a different string** than the 0.17.0 exact path (`lab/qjs_src_7a23/dtoa.c`). Every difference is a **shorter** output (16 digits vs 17) and every shorter string round-trips (glibc `strtod` → identical bits). Example: bits `0x0060000000000000`: shipped `7.120236347223045e-307`, 0.17.0 `7.1202363472230444e-307`; Python's shortest repr is the shipped string. |
| class | semantic (number formatting); the shipped output is the correct shortest round-trip form. |
| memory safety | ASan+UBSan build of the shipped `dtoa.c` over the same corpus: 0 reports; the `digits[20]` buffer is written at most 17 digits (`len >= 17` bail-out) and the returned length never exceeded `js_dtoa_max_len`. |
| novelty | not a bug; a cross-engine output difference. Recorded because it falsifies the commit's equivalence claim and because iOS/0.17.0 prints the longer form (any signature/hash over number strings differs between the Android fork and the iOS engine). |
| files | `lab/quickjs_new_hunt/dtoa/{dtoa_probe.c,out_shipped.tsv,out_old.tsv,asan.log}`, `logs/` |

### 2.3 QNH-03 — #1570 vulnerable state is reachable in the shipped source

| field | value |
|---|---|
| root cause (public) | `async_func_mark()` marks the operand stack only when `sf->cur_sp != NULL`; while an async function runs, `cur_sp` is NULL, so the frame's args/locals/stack are invisible to the cycle collector. Upstream issue #1570 (2026-07-15) has a fuzzer-generated program that crashes ASan in `gc_decref_child ← JS_MarkValue ← mark_children`. |
| shipped source | the exact code and the comment ("a running function cannot be part of a removable cycle") are still present at quickjs.c:21931 in `2dfeee3e`. |
| new evidence | instrumented build `gc/src_markdiag` (prints when `mark_children` reaches an *active* async frame with `cur_sp == NULL`) + `-DFORCE_GC_AT_MALLOC`: the upstream deterministic PoC `gc/min1570b.js` triggers the state **20+ times per run** (`logs/markdiag_1570.log`). |
| not reproduced | the same PoC does **not** crash under `run_asan_shipped`, `run_asan_ios`, `run_asan_upstream`, `run_forcegc_shipped` or `run_markdiag_force` in our harness (jobs=8, mem 164 KB). The upstream 8/8 crash depends on their exact allocation interleaving/heap layout; we could not reconstruct the free. My own `for await`+`using`+`__gc()` variants (poc_1570_gc*.js) also stay clean. |
| status | **public open issue, not a 0day.** If a trigger is found, the faulting operation is `JS_REF_COUNT(p)++` on an attacker-influenced `shape` pointer in `gc_scan_incref_child` — a potentially strong same-tag increment; but the free→use geometry is GC-timing-dependent and no release-build crash has been shown. Heavy-fuzz plan A targets it (§5). |
| widget relevance | `for await`/`using` are enabled in the widget engine; the widget GC runs on allocation thresholds under a 6 MiB limit, so the state is reachable in principle — but without a free/trigger there is no payload. |

### 2.4 QNH-04 — #1787 label leak: shipped debug build aborts

`interp/poc_1787.js` = `function f(){ for(;;) for(;;x) break; }`.

* shipped debug/ASan build: `Assertion 'label_slots[i].first_reloc == NULL' failed`
  in `resolve_labels` (quickjs.c:37359) — `logs/poc_1787_asan.log`, SIGABRT.
* The fork's peephole pass (`e69387d`) runs in the same function but is not
  involved: the assert also fires on the unpatched 0.17.0.
* Release (device) behaviour: `InternalError: invalid opcode (op=0, pc=3)` at
  compile time, catchable. No memory corruption. Public open issue, compiler
  DoS only; not a carrier.

### 2.5 #1518 — vardefs cleanup OOB read (present, not widget-reachable)

`free_function_bytecode()` walks `b->vardefs[]` for
`i < b->arg_count + b->var_count`, while the deserializer sized `vardefs`
by `local_count`; a malformed `JS_ReadObject(JS_READ_OBJ_BYTECODE)` blob can
make the cleanup read 4 bytes past the allocation. The shipped source has the
same loop. Public issue, closed `not_planned`; `JS_ReadObject` is only used by
the host's own pre-compiled bundles (`native-port-notes.md`: widget code is
always parsed from source) → **not widget-reachable**, ledger only.

### 2.6 QNH-06 — #1753 CPU-quota bypass, measured in the widget model (public known DoS)

| field | value |
|---|---|
| root cause (public) | the C loops of `join`, `reverse`, `slice`, `splice`, `concat`, `sort`, `flat`, `fill`, `Array.from` and `JS_CopySubArray` never call `js_poll_interrupts()`; with an array-like length up to 2^32-1 (or 2^53-1) they run for minutes and cannot be stopped by an embedder interrupt. |
| this campaign | reproduced the exact `join` case in the widget model (6 MiB limit, `JS_SetInterruptHandler` with a CPU deadline): `var a=[]; a.length=20000000; a.join('')` takes **1,052 ms** with a **100 ms** deadline (20M iterations), while a plain `for(;;)` under the same deadline dies with `InternalError: interrupted` at ~100 ms. Extrapolated: `a.length = 0xfffffffe; a.join('')` ≈ 3.8 minutes in one uninterruptible call; the empty separator means no allocation per element, so the memory limit is irrelevant. |
| payload | ~40 bytes of JS, no host API, no memory growth. |
| class | sandbox CPU-quota bypass / DoS (not memory safety). |
| novelty | **public open issue #1753** (2026-09-25) — explicitly lists `join` with an empty separator and "four to five minutes". Not a 0day; it is however missing from the project inventory and directly affects the widget's 300 ms budget. |
| host evidence | `interp/scripts/t_join_dos2.js`, `logs/join_dos_1753.log`. |
| widget caveat | the host thread is not blocked (the engine has its own thread), and a host-level wall-clock watchdog (if any) is outside the engine; but the engine itself cannot deliver its own stop. If the host frees the runtime while the JS thread is inside this loop, that cross-thread teardown is a host-side hazard not testable here. |
| endgame | none for RCE; relevant to the DoS matrix only. |

### 2.8 QNH-07 — parser nesting vs the 1 MiB default JS stack limit (closed: 8 MiB thread)

| field | value |
|---|---|
| fact (RE) | the widget engine's runtime constructor calls only `JS_NewRuntime`, `JS_SetMemoryLimit(rt, 6 MiB)`, `JS_NewContext`, `JS_SetInterruptHandler` (`notes/twidget_interrupt_re.md` §1.1). **No `JS_SetMaxStackSize`** → quickjs-ng's `JS_DEFAULT_STACK_SIZE` = 1 MiB (`quickjs.h:445`) applies. |
| host measurement | nested-paren source evaluated with the widget-model harness (release arena build, no `-S`): with a 1 MiB native stack, `n=900` parentheses (1,838-byte script) **SIGSEGVs** inside `js_atof ← next_token ← js_parse_skip_parens_token ← js_parse_assign_expr2 ← js_parse_expr_binary` (gdb backtrace captured); at 1.5–8 MiB the same input throws `RangeError: Maximum call stack size exceeded` cleanly. So the engine's own limit is present, but it needs ≈0.5 MiB of headroom above the 1 MiB budget. |
| device fact | the `twidget-host` thread is created with an **8 MiB** stack: armv7 tombstone `tombstone_00` line 771 `7c830000-7d02ffff rw- 0 800000 [stack:6403]`, tid 6403 named `twidget-host` (line 33322); the neighbouring `[stack:6398]` mapping is `7ff000` + a 4 KiB guard. The 64-bit build uses the same engine; 8 MiB is the design value (native-port notes: pool threads with 512 KiB are why a dedicated thread is used). |
| verdict | **not widget-reachable.** The 1 MiB default inside an 8 MiB thread is safe; the ~1.5 MiB minimum headroom is met with 7 MiB to spare. |
| residual | an embedder that hosts this engine on a ≤1.5 MiB thread without `JS_SetMaxStackSize` is crashable by a <2 KB nested-paren script (host contract, documented in `docs/developer-guide/intro.md`). The iOS sandbox prototype already sets 384 KiB explicitly (`QuickJS.swift:53`), so it is not affected. |
| payload / endgame | none for the widget (host-limited). No tag domain, no OOM, no interrupt involvement. |
| evidence | `lab/quickjs_new_hunt/parser/{paren_900.js, w_paren_*.html}`, gdb backtrace `logs/parser_stack_gdb.log`; tombstone path above. |

### 2.9 Candidate matrix (requested fields, one row per finding)

| id | class | trigger (short) | novelty | tag domain | OOM? | MTE / iOS | payload / endgame | host evidence |
|---|---|---|---|---|---|---|---|---|
| QNH-01 | array length invariant violation (semantic) | `a=[0..7]; a[10]=1; a.length=0` → `a[10]` survives, `length=0` | unreported in quickjs-ng; fixed only in bellard `3c4c6edc` | n/a (no memory access outside objects) | no | n/a (semantic) | none (not a carrier) | `logs/arrtrunc_evidence.log` |
| QNH-02 | number formatting delta (benign) | any of 108 subnormal/pow2 edges through `String(x)` | fork commit `74f2249` claim false; output is a fix | n/a | no | iOS prints the 17-digit form (output differs) | none | `dtoa/out_*.tsv` (108 diffs) |
| QNH-03 | GC UAF (public #1570) | `for await`+`using` over async iterator that allocates while the async frame runs | **public open issue**, not 0day | arena tag 0 if triggered | no | iOS/upstream share the source; no repro | if triggered: increment in `gc_scan_incref_child` on a shape pointer; same-tag endgame possible | `logs/markdiag_1570.log` (state reached, no free) |
| QNH-04 | compiler label leak (public #1787) | `function f(){ for(;;) for(;;x) break; }` | public open issue | n/a | no | shared by 0.17.0 | none (debug abort / release InternalError) | `logs/poc_1787_asan.log` |
| QNH-05 | OOB read in deserializer cleanup | malformed `JS_ReadObject(JS_READ_OBJ_BYTECODE)` | public #1518, closed not-planned | Scudo/arena by size | no | not iOS-reachable (host API) | none (host-only) | source `quickjs.c:37959` |
| QNH-06 | CPU-quota bypass / DoS (public #1753) | `a=[]; a.length=0xfffffffe; a.join('')` | public open issue, missing from project inventory | n/a | no (empty separator allocates nothing) | shared by iOS 0.17.0 | ~3.8 min uninterruptible per call; DoS only | `logs/join_dos_1753.log` |
| QNH-07 | parser native-stack overflow (host contract) | 900 nested parens (1.8 KB) at a ~1 MiB thread stack | **closed**: widget thread is 8 MiB (tombstone); not a 0day | n/a | no | iOS prototype sets 384 KiB explicitly | none for the widget | `logs/parser_stack_gdb.log`, tombstone_00:771 |

---

## 3. Negative results (new evidence)

### 3.1 Interpreter stack invariant — 2,660 programs, 0 violations

`interp/src_spcheck/quickjs.c` is the shipped source with a `SP_CHECK` macro
that aborts if `sp < stack_buf || sp > stack_buf + b->stack_size` at every
dispatch (both `BREAK` variants) and at the exception label. This is the
primitive-level check for the "compiler/opcode stack imbalance corrupts the
frame (var_refs live immediately after stack_buf)" class.

Corpus (`interp/run_corpus.sh`): 1,760 object-model coercion/mutation cases;
800 random object-model sequences; 109 engine tests; plus hand-written
`t_forawait.js`, `t_spread.js`, `t_class.js`, `t_exc.js`, `t_eval.js`,
`t_arrtrunc.js`, `t_arrdef.js`, `t_arrinv.js` (for-await/using/iterator-close,
spread/apply/eval, classes/private/super/static blocks, exception/finally/
gosub/generator throw, direct+indirect eval).

Result: `ran=2660`, `hit_count=0` (`interp/logs/spcheck_corpus.log`).
In particular `OP_apply_eval`, `OP_for_of_*`, spread `OP_append`, and the
`using` dispose stack layouts stay inside the declared frame.

### 3.2 Interrupt-gated sweep of the fork's uncatchable-exception code — 156 runs, 0 hits

The fork's `9ddb1b8` ("uncatchable exceptions are a runtime state") rewrites
ownership on many exception paths (using disposers, SuppressedError,
async-generator resume, promise jobs, backtrace). Scripts
`fuzz/intr/i01..i12` each spin/throw inside those constructs; each is run
with 13 CPU deadlines (1…70 ms) under `run_asan_shipped`, so the 300 ms-class
interrupt lands in different sub-paths. 156 runs, 0 sanitizer/assertion hits
(`logs/intr_hits.txt`, empty).

### 3.3 Differential shipped vs 0.17.0 over 1,760 cases — 0 divergences

Each generated case prints `RESULT <log>`; `run_arena_shipped` vs
`run_asan_ios` (0.17.0) produced **identical** output on all 1,760 cases
(`logs/diff_cases_result.txt`, empty). This is a new semantic-equivalence
check for the fork's ~24 perf commits (the previous campaign only checked
for sanitizer reports, not output equality).

### 3.4 dtoa — 1,097,348 values, 0 sanitizer reports

Covered in §2.2; the only finding is the benign output delta.

### 3.5b Teardown leak assertion cross-check (known family)

The assert-enabled fuzz build of `qz_gen_async` aborts at
`JS_FreeRuntime` on `assert(list_empty(&rt->gc_obj_list))`
(`quickjs.c:2952`) for generated async/using programs that leave a frame
alive at teardown — i.e. the known async-frame leak (and the symbol-FR
teardown leak) already recorded as upstream-shared DoS in
`new_0day_mte_specs_20261107.md` §12.8. Not a new bug; it is why the campaign
binaries are built with `-DNDEBUG` (ASan/UBSan remain on).

### 3.6 Deterministic GC-stress matrix — 17 surfaces × 2 builds, 0 hits

`gc/matrix/g01..g17` exercise async frames/captured locals, for-await +
using/await using, async-generator reentry/throw/return, var_refs/closures/
eval/with, finalizers + WeakMap/WeakSet/WeakRef + FR unregister, typed-array
views/RAB transfer, nested DisposableStack/AsyncDisposableStack suppression
chains, proxies (revoke in traps, proxy in prototype), JSON getters/revivers,
RegExp custom exec/lastIndex-compile, class fields/private/static blocks +
eval + using, generators/yield*, promise combinators/thenables, mapped
arguments, strings/atoms, BigInt, catch/finally/iterator-close. Each is run
under `run_forcegc_shipped` (ASan + a GC before every allocation) and
`run_asan_shipped`: **0 sanitizer/assertion hits, no timeouts**
(`gc/matrix/run_matrix.sh`).

### 3.7 Typed-array overlap / detach / RAB-during-copy — 0 hits

`typed/t_overlap.js` (500 rounds): overlapping `set`/`copyWithin`/`sort`
across all element sizes, exact overlap, `DataView`, RAB `resize(0)` and
`transfer()` inside array-like element getters and inside a sort comparator,
GC in the comparator. ASan+UBSan, 64 MiB: **0 reports**. The sort path
re-reads `typed_array_is_oob`/`count` after the comparator and the copy loop
guards `j < len`, so no stale-pointer write was reachable.

### 3.8 Parser nesting / native stack — measured, closed (QNH-07)

See §2.8: 1 MiB thread → crash at n=900; ≥1.5 MiB → clean RangeError; the
widget thread is 8 MiB.

### 3.5 Fork-only code, audited by inspection

| commit | result |
|---|---|
| `e142acb` frame setup + direct C getter | `js_call_c_function(ctx, func, this_obj, 0, NULL, 0)` is equivalent to the `JS_CallFree` path for `JS_CLASS_C_FUNCTION` (same poll, same arg padding to `u.cfunc.length`, same realm switch, same refcount release). Getter C functions have `length` 0 and cproto getter; setter objects have `length` 1 (`quickjs.c:41552`), so the setter branch never dereferences a NULL `arg_buf`. No new bug. |
| `2adec3f` C calls skip `JS_CallInternal` | identical dispatch for `class_id == JS_CLASS_C_FUNCTION` (`class_array[C_FUNCTION].call == js_call_c_function`); the `argc/argv` contract is unchanged; tail-call/exception labels unchanged. |
| `e69387d` `dup put_loc_check drop -> put_loc_check` and `post_inc put_loc_check drop -> inc put_loc_check` | stack effect preserved (-1), TDZ check order preserved (inc before check, as before); the SP_CHECK corpus (including TDZ loops) is clean. |
| `74f2249` Grisu3 | §2.2. |
| `7bff43c` map hash avalanche | distribution-only; hash still deterministic per key/value; the bucket mask path unchanged. |
| `9ddb1b8` uncatchable runtime state | reviewed hunk by hunk; ownership of `error_state`/`new_error`/`saved_exception` is correct on every `goto`; the `sp[-1] = JS_UNDEFINED` writes overwrite the already-freed slot; §3.2 finds no runtime hit. No memory defect found. |

---

## 4. Status of the requested unchecked surfaces

| surface | what this campaign added | residual |
|---|---|---|
| interpreter/bytecode/stack | SP_CHECK over 2,660 programs (§3.1); audit of `OP_eval`/`OP_apply_eval`/`OP_append`/`OP_for_of_*`/`using` opcodes; #1787; QNH-06 (#1753) measured | opcode-by-opcode *ownership* model (not just stack height) is still missing; interrupt polls in C loops |
| GC/refcount/cycle/finalizer | #1570 state-reached evidence + instrumented build (§2.3); dtoa/array sweeps | deterministic #1570 trigger; refcount-underflow oracle over async corpus |
| parser/compiler | #1787 shipped-abort; bellard #585 family found (QNH-01) | grammar-based parser fuzz (plan B) |
| async/generator/jobs | §3.2 sweep; #1570 lead | GC-timing fuzz (plan A) |
| proxies/exotics | #1770/#1890 re-checked: semantic only | — |
| typed arrays/RAB | `js_typed_array_slice` fast path re-proved safe (`class_id` equality + `length >= count`); species content-type issue semantic | — |
| BigInt | re-read `compute_register_count`/BigInt caps; no new | — |
| atoms/strings/shapes | bellard `092277ac` double `Symbol.iterator` read exists in quickjs-ng's `js_append_enumerate` but is memory-safe (classification uses the first result; fast path re-validates `js_get_fast_array`+`length==count`); string fast paths already in the fork (`7ead61a`) | — |
| JSON | no new (previous campaign clean; `json_write_number` bound check re-proved) | — |
| RegExp beyond #1827 | re-proved `capture[]` sizing invariant: `alloc_count = capture_count*2 + register_count`, `register_count` is capped by `REGISTER_COUNT_MAX` and stored in a byte, capture indices are capped by `CAPTURE_COUNT_MAX`; executor cannot exceed alloc_count for compiler-produced bytecode | lre_exec canary fuzz (plan C) |
| serialization | #1518 present, host-only | — |
| C API/bridge | no new; T2 still embedder-only | — |

---

## 5. Focused fuzz campaign — **run and completed** (2 workers, approved)

The campaign was approved with 2 workers, a 2 GB RSS cap each, `-DNDEBUG`,
first-crash-stop and host-only operation, and was run on 2026-11-08
03:37:53–06:09:19 (focused then long) with the CSS worker as the only other
fuzz process. It lives in `lab/quickjs_new_hunt/fuzz/campaign/`:

```
qz_gen_async.c     byte -> valid for-await/using/async-iterator program;
                   __gc() is called from iterator/dispose methods exactly
                   where the input selects; 6 MiB, 512 KiB stack, 300 ms
qz_gen_parser.c    byte -> valid program of nested parens/arrays/objects/
                   arrows/templates, classes/private/static, destructuring,
                   using, labels/loops (#1787 family), eval
qz_gen_regexp.c    byte -> pattern from a regexp token grammar + flags +
                   subject; exec/match/search/split/replace/matchAll +
                   lastIndex valueOf recompile
qz_eval_src.c      raw JS source with the widget model (the 507k-exec
                   campaign's harness, rebuilt with these limits)
run_campaign.sh    build / smoke / focused / long / parser / regexp
make_seeds.py      deterministic seed corpus (48 byte seeds per generator,
                   327 source seeds from this campaign + the object-model
                   corpus)
corpus/{async,parser,regexp,src}/   seeds + libFuzzer-grown corpus
                                   (final: async 2,916, parser 870,
                                   regexp 48, src 327)
corpus/async_gc/                   52 deterministic byte seeds (the FORCE_GC
                                   long-phase worker; kept small so a 180 s
                                   chunk is not dominated by corpus replay)
bin/                               qz_gen_async, qz_gen_async_gc, qz_gen_parser
                                   (validated; regexp/eval_src built on demand)
artifacts/                         empty; libFuzzer writes `<bin>-<hash>` here
```

Validation done now (small, deterministic): both variants of `qz_gen_async`
were built with ASan+UBSan and run on **300 seed inputs** each: the
`FORCE_GC_AT_MALLOC` build 16 s at 18 exec/s (11,276 edges), the fast build
2 s at 300 exec/s (11,243 edges), RSS ≤ 220 MB: **0 sanitizer hits**
(`corpus/async`, ~100 corpus units after each run). Two harness bugs found and
fixed during validation (input-length guard; the assert-enabled build aborts
at `JS_FreeRuntime` on `list_empty(&rt->gc_obj_list)` for the **known**
async-frame / symbol-FR teardown leak), which is why the campaign binaries
are built with `-DNDEBUG` (ASan/UBSan stay on). The other four binaries are
compiled by `run_campaign.sh build` when a slot frees (a compile, not a
worker).

### Phases and resource caps

| phase | command | workers | wall | RSS cap | target |
|---|---|---|---|---|---|
| 0 smoke | `./run_campaign.sh smoke` | 1 (sequential) | 3 × 60 s | 2 GB | **done (validation)** |
| 1 focused | `./run_campaign.sh focused` | 2 | 2 × 30 min | 2 GB each | **done 04:08:28, no artifact** |
| 2 long | `./run_campaign.sh long` | 2 | 2 × 2 h | 2 GB each | **done 06:09:19, no artifact**; `qz_gen_async` + `qz_gen_async_gc` |
| 3 regexp | `./run_campaign.sh regexp` | 1 | 20 min | 1 GB | lre_exec/capture |

Rules baked into the script: `-timeout=10 -rss_limit_mb=2048`, one libFuzzer
worker per process, `-artifact_prefix=artifacts/<binary>-`, first artifact
reviewed before continuing; no network, no device. Start only after the
orchestrator frees a slot; two slots are requested for phase 1/2 (phase 0/3
use one). Expected outputs: a reproducer in `artifacts/` for one of
(a) `gc_decref_child`/`gc_scan_incref_child`/`free_object` (the #1570 class),
(b) a parser/compiler ASan report (the ARG_SCOPE_END class),
(c) an lre_exec/capture canary hit.

### Live run (approved 2026-11-08, 2 workers, first-crash-stop)

**v1 launch (03:33:54, `supervise.sh` + `run_campaign.sh focused`)**:
- qz_gen_async PID 1258873 (616 MB at start), qz_gen_parser PID 1258874 (491 MB);
  supervisor 1258855, phase script 1258860; total fuzz workers = 3 (CSS 1239363
  + these two) — at the cap.
- The fast async harness hit the **2 GB RSS cap after ~2 min / 17,413 execs**
  (152 exec/s, 1,006 new corpus units, peak_rss 2048 MB) and was stopped by
  libFuzzer; **no artifact**. Cause: the **known abandoned-async-frame leak**
  (§3.5b/`new_0day_mte_specs_20261107.md` §12.8) accumulates ≈13 MB/s at this
  exec rate with a fresh runtime per input. Logs kept:
  `artifacts/qz_gen_async.1794105234.log`, `artifacts/qz_gen_parser.1794105234.log`
  (parser was stopped by the supervisor at 2 min, peak 497 MB). No artifact.

**v2 (03:36:12, `supervise2.sh`) — superseded after one chunk**: the
60 s chunking worked (first full chunk: 6,214 execs, 101 exec/s, peak RSS
**1,038 MB**, rc=0, no artifact), but the long phase's `FORCE_GC` worker runs
at ~18 exec/s, so replaying a ~1,000-file corpus would consume longer than a
60 s chunk. v3 keeps chunking for the fast worker and gives the GC worker a
180 s chunk with a 52-seed corpus.

**v3 launch (03:37:53, `supervise3.sh`) — the live run** — same modes, same
2 GB cap, same deterministic seeds. focused = async (60 s chunks,
`corpus/async`) + parser (single 30 min); long = async (60 s chunks) +
`qz_gen_async_gc` (180 s chunks, `corpus/async_gc` = 52 seeds). First-crash-stop
is the supervisor watcher (`artifacts/qz_gen_*-*` → `pkill -x` → phase stops,
supervisor exits).

| role | PID | command (argv) | RSS at +12 s |
|---|---|---|---|
| supervisor v3 | **1260623** | `bash supervise3.sh` | — |
| async chunk loop | **1260629** | `chunked qz_gen_async corpus/async 1800 60` | — |
| parser worker | **1260634** | `bin/qz_gen_parser corpus/parser -max_total_time=1800 -timeout=10 -rss_limit_mb=2048 -artifact_prefix=artifacts/qz_gen_parser- -print_final_stats=1` | **487 MB** |
| async worker (rotates each 60 s chunk) | **1260638** at +12 s | `bin/qz_gen_async corpus/async -max_total_time=60 -timeout=10 -rss_limit_mb=2048 -artifact_prefix=artifacts/qz_gen_async- -print_final_stats=1` | **680 MB** |

Total fuzz workers = **3** (CSS 1239363 + 2 QuickJS) — at the cap, no third
QuickJS worker. Parser rate 227 exec/s, RSS 473 MB. First full v3 async
chunk (03:38:54, PID 1260638's successor): **8,756 execs, 146 exec/s, peak
RSS 1,149 MB**, rc=0; the next chunk started at 03:38:54 (PID 1260896,
779 MB at +19 s). Artifacts at 03:39: **none**.
Logs: `artifacts/qz_gen_async.loop.log`, `artifacts/qz_gen_parser.loop.log`,
`campaign_run.log`. On an artifact the supervisor prints
`[supervisor v3] ARTIFACT ...`, stops both workers, and the full ASan report
is in the corresponding `artifacts/qz_gen_*-<hash>` + `.loop.log` tail.

### Campaign result (completed 2026-11-08T06:09:19+01:00)

The supervisor ran the full approved plan: focused **03:37:53 → 04:08:28**
(async + parser), long **04:08:28 → 06:09:19** (async fast + async FORCE_GC),
then exited `done`. **No artifact and no sanitizer/assert/OOM line in any
log.**

| worker | runs | execs | max peak RSS | corpus at end |
|---|---:|---:|---:|---:|
| `qz_gen_async` (focused + long, 60 s chunks) | 150 chunks | **1,378,080** | **1,227 MB** | 2,916 files |
| `qz_gen_async_gc` (long, 180 s chunks, FORCE_GC) | 40 chunks | **115,484** | **820 MB** | 1,391 files |
| `qz_gen_parser` (focused, single 30 min) | 1 | **383,274** | **492 MB** | 870 files |
| **total** | 191 runs | **1,891,616** | **1,227 MB** | — |

All chunk exit codes 0; no timeout, no `deadly signal`, no
`AddressSanitizer`, no `Assertion`, no `out-of-memory`. The 2 GB cap was
never reached (max 1,227 MB). Logs:
`artifacts/qz_gen_async.loop.log` (534 KB),
`artifacts/qz_gen_async_gc.loop.log` (263 KB),
`artifacts/qz_gen_parser.loop.log` (46 KB), plus the v1 logs at
`artifacts/qz_gen_{async,parser}.1794105234.log` (17,413 execs, peak 2,048 MB,
no artifact). The v1/v2/v3 commands, PIDs and RSS were reported live; the
final supervisor PID was 1260623.

**Honest reading:** the #1570 class is still not reproduced. The campaign
invested ~1.9 M executions in the async/GC and parser surfaces with
deterministic `__gc()` placement (fast worker) and a GC before every
allocation (FORCE_GC worker) and found no memory-safety report. The only
new finding remains QNH-01 (semantic) plus the measured/known QNH-06/07.

### Why these targets

The recon (§1) shows the shipped engine is current with upstream except the
six known fixes; the fork-only code was audited negative (§3.5). The only
unfixed memory-safety lead with a plausible same-tag primitive is #1570
(async frame vs cycle GC), and the only compile-time memory class known to
exist in this codebase is the parser (ARG_SCOPE_END). The campaign is sized
so the first slot produces a smoke result in minutes and the two-slot run is
a bounded 2 h, not an unbounded fuzz farm.


## 6. Reproduction

```bash
cd lab/quickjs_new_hunt

# QNH-01
cd interp && ASAN_OPTIONS=detect_leaks=0 ./run_spcheck scripts/t_arrtrunc.js
# QNH-02
cd ../dtoa && ./probe_rel_shipped 0 1 out_shipped.tsv && ./probe_rel_old 0 1 out_old.tsv
diff out_shipped.tsv out_old.tsv | head
# QNH-03
cd ../gc && ASAN_OPTIONS=detect_leaks=0 ./run_markdiag_force min1570b.js 2>&1 | grep -c markdiag
# QNH-04
cd ../interp && ASAN_OPTIONS=detect_leaks=0 ../../object_model_hunt_20261108/build/run_asan_shipped poc_1787.js
# §3.1
cd .. && bash interp/run_corpus.sh        # expect ran=2660 hit_count=0
# §3.2
bash fuzz/run_intr.sh                     # expect count 0
# §3.3
# (see logs/diff_cases_result.txt: empty)
# §3.6
bash gc/matrix/run_matrix.sh            # expect count 0
# §3.7
cd typed && ASAN_OPTIONS=detect_leaks=0 ../../object_model_hunt_20261108/build/run_asan_shipped -l 64 t_overlap.js
# QNH-06
cd ../interp && ASAN_OPTIONS=detect_leaks=0 ./run_spcheck -l 6 -t 100 scripts/t_join_dos2.js
# QNH-07 (host-limited; 1 MiB thread -> SIGSEGV at n=900)
cd ../parser && ( ulimit -s 1024; ../../object_model_hunt_20261108/build/run_arena_shipped -l 64 paren_900.js )
# campaign (only when a slot is free)
cd ../fuzz/campaign && ./run_campaign.sh smoke
```

(The object-model harnesses are reused from
`lab/object_model_hunt_20261108/build/`; their build scripts are unchanged.)

---

## 7. Limits and honest negative

* All measurements are x86-64 host builds. The device engine is AArch64
  with the arena allocator; ASan builds disable the arena. The SP_CHECK
  result is architecture-independent (interpreter stack), the GC result is
  not (heap layout).
* The dtoa and array-invariant sweeps are targeted, not exhaustive.
* #1570 remains **unreproduced**: the state is reachable, the free is not.
  Until a host crash exists it must not be treated as a carrier.
* No new memory bug was found in the fork's perf commits or in the
  uncatchable-exception rewrite under the sweeps above. The one new
  unreported bug (QNH-01) is semantic. QNH-07 was a real crash class but is
  closed by the 8 MiB thread evidence (host contract).
* No device, Frida, bot or payload was used; no existing note or evidence
  was modified.

## 8. Files

```
notes/quickjs_new_hunt_20261108.md              this note
notes/LEMMALOG_FACTS_quickjs_new_hunt_20261108.txt
lab/quickjs_new_hunt/recon/                     upstream compare JSON, open-issue dump
lab/quickjs_new_hunt/dtoa/                      probe harness, corpora, logs
lab/quickjs_new_hunt/interp/                    SP_CHECK source+build, corpus runner,
                                                scripts/, poc_1787.js
lab/quickjs_new_hunt/gc/                        #1570 PoCs, markdiag source/builds,
                                                matrix/g01..g17 + run_matrix.sh
lab/quickjs_new_hunt/typed/                     overlap/detach/RAB sweep
lab/quickjs_new_hunt/parser/                    nesting corpus + QNH-07 gdb log
lab/quickjs_new_hunt/fuzz/                      interrupt scripts + runner,
                                                campaign/{harnesses,seeds,runner,bin}
lab/quickjs_new_hunt/logs/                      collected evidence
```
