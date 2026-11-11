# quickjs-ng #1835 — WeakMap symbol-value UAF: offline characterization

Target: quickjs-ng v0.17.0 (Telegram 13.2.0 widget engine, binary-verified by the
parallel reverse agent: `js_map_finalizer` @ `0x173899c` pre-fix, `reset_weak_ref`
@ `0x16fb42c`). Everything here is local, x86-64, no phone; the device result is
included as corroboration and marked as such.

**Verdict (measured, not inferred):**

| question | answer |
|---|---|
| App-reachable crash? | **Yes** — synchronous during the first script (scope/callback drop of the map) |
| Crash class | deterministic **NULL dereference**, fault addr `0x0`, in `delete_map_weak_ref` (inlined) |
| Double free of the record? | **Unreachable in v0.17.0** — the NULL deref always precedes it |
| Controlled read / write / alias? | **No** in pristine v0.17.0 |
| RCE? | **Not demonstrated**; only a synthetic two-guard patch reaches an alias, and that path corrupts the allocator |
| Device match | pc `0x1738a80` = `js_map_finalizer+0xe4`, fault `0x0`, tombstone_13 — same branch |

The exploit plan that assumes "the finalizer returns and the script continues"
does not hold for this bug in v0.17.0. The reason is at the bottom of the
allocator, not in the JS heap: the byte the plan wants to flip (`mr->empty`, +0x04)
is never written by the free path, and the weak-ref head the loop needs is
unconditionally NULLed before the loop continues.

---

## 1. Environment

Source: `/tmp/opencode/qjs017/quickjs.c`
sha256 `9fd0e0e68856d165e2872140ac38889845b53eb1bc55150f8598a53eb86948f5`,
**byte-identical to upstream tag `v0.17.0`** (verified against
`raw.githubusercontent.com/quickjs-ng/quickjs/v0.17.0/quickjs.c`).
The vulnerable loop is `quickjs.c:53853-53879`; the fix (PR #1844) is absent.

| build | flags | purpose |
|---|---|---|
| `build_asan` | Debug, `QJS_ENABLE_ASAN=ON`, no GC stress | per-block poisoning (`__SANITIZE_ADDRESS__` forces `JS_ARENA_LARGE_BLOCKS_ONLY`) |
| `build_rel` | Release `-O2 -DNDEBUG`, arena enabled | production-like: arena allocator, no asserts |
| `build_dbg2` | RelWithDebInfo | release crash with source lines |
| `wm_inst` / `wm_inst_rel` | source-instrumented, asserts / `-DNDEBUG` | record & weak-ref sequencing |
| `wm_detect_rel` | `wm_inst_rel` + arena double-free detector + byte dumps | survival hunt |
| `wm_latent*` | synthetic guards only (see §6) | "what if it survived" |

Harness `wm_harness.c` models the app execution shape:

* one long-lived `JSRuntime`/`JSContext`; **no teardown until explicitly asked**
  (`--teardown none|ctx|rt`), so the script continues after the finalizer;
* `JS_SetMemoryLimit(6 MiB)` (`--mem 6144`), stack 512 KiB, **no GC stress**;
* `--defer` runs a function from C after the eval returns (timer/rAF model);
* `__gc()` and allocation-pressure loops cover collector-triggered finalization.

Build/run: `./build.sh`, `python3 run_matrix.py`, `python3 gen_survival.py`.
All logs under `logs/`.

---

## 2. Reproducers and crash matrix

Minimal app-reachable PoC (`js/repro_b.js`):

```js
var o = {};
function f() {
  var m = new WeakMap(), b = Symbol('b');
  m.set(o, b);
  m.set(b, 1);
  b = undefined;
  m = undefined;        // finalizer runs here, synchronously
}
f();
```

`js/repro_a.js` (the issue's global `const` variant) only dies at
`JS_FreeRuntime` → **not app-reachable** because the widget runtime is never
freed. The local-drop variant dies inside the first script.

19-case matrix (`logs/matrix.csv`, ASan + release): all shapes agree with the
model.

| shape | result |
|---|---|
| value symbol = key of the **immediately next** record | **SIGSEGV / ASan UAF** |
| value symbol = key of a later record with a live record between | survives |
| value symbol = key of the last record | survives |
| value symbol = key of an already-visited record | survives |
| value symbol also strongly referenced (global/array) | survives (no `reset_weak_ref`) |
| object value that is the next key | survives (deferred by `gc_zero_ref_count_list`) |
| string value | survives |
| WeakRef / FinalizationRegistry on the symbol | crashes (same site) |
| delete + re-add | crashes |
| map dropped in scope / returned then dropped / GC cycle / GC pressure / deferred callback / runtime teardown | crashes in every route |
| WeakSet only | survives |

Adjacency is **dynamic**: removing an earlier record can make a later
value→key pair adjacent (`p5_two_links_separated` crashes for exactly this
reason). The condition is "at the moment the value symbol dies, the record it
keys is the loop's saved `next`".

---

## 3. Exact crash site

ASan (`logs/asan_canonical_t02.txt`), canonical scope variant:

```
ERROR: AddressSanitizer: heap-use-after-free
READ of size 8 ... in js_map_finalizer quickjs.c:53865
0x... is located 32 bytes inside of 88-byte region
freed by: js_def_free <- js_arena_free <- js_free_rt <- reset_weak_ref:63393
          <- JS_FreeAtomStruct:3675 <- js_free_value_rt:7186
          <- JS_FreeValueRT:7200 <- js_map_finalizer:53872
allocated by: map_add_record:53496 <- js_map_set
```

Line 53865 is the `list_for_each_safe` update: it reads `el->next` from the
record that `reset_weak_ref` just freed. Offset 32 = `link.next` (record +0x18,
ASan region +0x20 including the 8-byte header).

Release (`build_dbg2`, gdb):

```
SIGSEGV
#0 delete_map_weak_ref (mr=0x...e78) at quickjs.c:53537   // if (wr->kind == ...)
#1 js_map_finalizer (val=...)        at quickjs.c:53869   // delete_map_weak_ref(rt, mr)
#2 free_object:7081 <- free_gc_object:7101 <- free_zero_refcount:7123
#3 js_free_value_rt:7169 <- JS_CallInternal:18951
```

Faulting instruction `mov (%rsi),%ecx` with `rsi = 0` — `wr->kind` on a NULL
`wr`. Device: pc `0x1738a80` (`js_map_finalizer` `0x173899c` + `0xe4`), fault
`0x0`, same inlined `delete_map_weak_ref`. Codegen offsets differ; branch is
identical.

Sequence with addresses (`logs/inst_repro_b.out`):

```
map s=0x...a178 records head=0x...a180
r1 mr=0x...1d98 key={}  value=Symbol b
r2 mr=0x...1df0 key=Symbol b value=1        <- saved el1
free r1.value (b): reset_weak_ref(b)
  pass1: unlink r2 (list_del hash_link/link, record_count 2->1)
  pass2: free r2.value (int), js_free r2      class 88, block_idx 8
  rw exit: b->first_weak_ref = NULL
back in loop: js_free r1                       class 88, block_idx 7
loop update: el = r2 (freed), el1 = r2->link.next = NULL
iteration 2: mr = r2 (freed), empty = 0 -> delete_map_weak_ref(r2)
  get_first_weak_ref(r2->key) -> b's freed atom -> first_weak_ref = NULL
  wr = NULL; wr->kind -> SIGSEGV at 0
```

---

## 4. Size classes (the plan's class-80 premise is off by one)

`JSMapRecord` (gdb `ptype /o`, identical in source and app per the binary report):

| offset | field |
|---|---|
| +0x00 | `int ref_count` |
| +0x04 | `bool empty` |
| +0x08 | `JSMapState *map` |
| +0x10 | `link` (prev +0x10, **next +0x18**) |
| +0x20 | `hash_link` |
| +0x30 | `key` (JSValue) |
| +0x40 | `value` (JSValue) |
| total | **0x50 = 80 bytes** |

`js_arena_malloc` adds an 8-byte `JSMallocBlockHeader` and selects the class from
`align(size)+8`:

| object | user size | block | class index | class |
|---|---|---|---|---|
| **JSMapRecord** | 80 | **88** | 9 | **88** |
| `{}` (JSObject) | 72 | 80 | 8 | 80 |
| 31-char ASCII string | 72 | 80 | 8 | 80 |
| 32..39-char ASCII string | 73..80 | 81..88 | 9 | **88** |
| 40-char ASCII string | 81 | 96 | 10 | 96 |
| symbol atom (JSAtomStruct) | 40 | 48 | 4 | 48 |
| JSWeakRefRecord | 24 | 32 | 2 | 32 |
| JSJobEntry (finrec, argc=2) | 72 | 80 | 8 | 80 |

So the record is **class 88**, not class 80. `{}` and 31-char strings (the
suggested groomers) are class 80 and cannot reuse it; the class-88 strings are
**32–39 chars**. The trace confirms it: `malloc size=80 total=88 class=88` for
the record, `size=72 total=80 class=80` for `{}`.

---

## 5. Why the survival variant does not exist

### 5.1 `empty` (+0x04) is never written by the free path

`JSMallocBlockHeader` is 8 bytes **before** `user_data`:

```
-8..-7  union { block_idx; free_next }   <-- js_arena_free writes free_next here
-6      block_size_idx
-5      gc_obj_type|mark
-4..-1  ref_count
 0..     user_data (record: ref_count, empty, ...)
```

Byte dump at the free (`logs/inst_t02...`, reproduced for free-list heads
`k = 0,1,2,7,31,63` in `js/groomh/`):

```
pre-free  mr[0..7]      : 01 00 00 00 00 00 00 00
pre-free  hdr[-8..-1]   : 08 00 09 00 00 00 00 00   (block_idx=8, class=9)
post-free mr[0..7]      : 01 00 00 00 00 00 00 00   <-- unchanged, empty=0
post-free hdr[-8..-1]   : 09 00 09 00 00 00 00 00   (free_next=9)
```

Every free-list head produces the same `+0x04 = 0`. Grooming cannot move the
free metadata: its offset is fixed at `-8`, 12 bytes below `+0x04`. And
`map_add_record` explicitly stores `empty = false` at allocation.

### 5.2 `first_weak_ref` is always NULL on the next iteration

`reset_weak_ref` walks the symbol's whole weak-ref chain in pass 1 and unlinks
**every kind** — MAP, WEAK_REF, FINALIZATION_REGISTRY_ENTRY. Trace with one
symbol referenced by two WeakMaps, a WeakSet, a WeakRef and a registry entry:

```
rw pass1 wr kind=2 (FINREC) next=...
rw pass1 wr kind=1 (WEAK_REF)
rw pass1 wr kind=0 (MAP) unlink mr=...1a0
rw pass1 wr kind=0 (MAP) unlink mr=...148
rw pass1 wr kind=0 (MAP) unlink mr=...0f0
rw pass2 ... frees all five ...
rw exit first=... -> NULL
mf iter el=(freed record) mr=...0f0 empty=0 ... -> delete_map_weak_ref -> NULL
```

No weak-ref kind survives to the second iteration, and no JS runs between the
reset and the read, so no new entry can be inserted.

### 5.3 No allocation window for reuse

The only allocation performed after the record free inside `reset_weak_ref` is
the FinalizationRegistry job enqueue (`JS_EnqueueJob`, argc=2): `size=72
total=80 class=80`, trace-confirmed. The record is class 88. The atom (class 48)
is freed after the reset and read again by `get_first_weak_ref` with no
allocation in between. Under the ASan build the arena is bypassed, so every
allocation is an individual block; under Release the free metadata is at `-8`.

### 5.4 Result of the 47-shape hunt (`logs/surv/survival.csv`)

* 31 finalizers returned: all are safe shapes (separated/previous/last key,
  held symbol, object/string value) and **none** printed a double free;
* 16 crashed: every shape where the value symbol's record is the saved next;
* **0 double frees**; the arena detector never fired.

Conclusion: in pristine v0.17.0 the second iteration always reaches
`delete_map_weak_ref` with `mr` = freed record and `mr->key` = freed atom whose
`first_weak_ref` is NULL. The finalizer cannot return. The device tombstone
(`fault 0x0`, `js_map_finalizer+0xe4`) confirms this exact branch.

---

## 6. The latent double free (synthetic only — NOT a v0.17.0 path)

To answer "what would happen if the loop skipped the frees", two guards were
patched into an instrumented copy (`wm_latent*`, clearly not upstream):

1. `delete_map_weak_ref`: `if (wr == NULL) return;`
2. loop condition stops when `el == NULL` (the value `list_del` wrote).

Result: the finalizer completes and the script continues, but the second
`js_free_rt(rt, mr)` is **not clean**:

* the first free overwrote `block_idx` (at `-8`) with `free_next`; the second
  free therefore computes the arena as `b - 88*index - sizeof(JSArena)` with the
  **wrong index**, i.e. 88 bytes before the real arena, and writes
  `ar->first_free_block` there;
* allocation tracing then shows the double-freed record handed out twice:
  `map_add_record mr=0x...a090` appears for two different live maps
  (`logs/latent_alias4.log`), i.e. a real record/record alias;
* the run then **hangs/spins** in the allocator because the class-88 free list
  and the mis-computed arena metadata are corrupted.

So even a partial fix of the "just check `wr != NULL`" kind converts the crash
into allocator corruption plus an overlapping-record condition — never a
controlled object/string alias. That path is not reachable in v0.17.0 anyway,
because the guards that create it do not exist in the shipped code.

---

## 7. App-model relevance

* The runtime is never torn down, so the issue's global-`const` reproducer
  (crash only at `JS_FreeRuntime`) does **not** fire in the app.
* The local-drop / callback / GC-cycle variants do fire synchronously during the
  first script. 6 MiB limit, no GC stress and no teardown do not change the
  crash; all were exercised above.
* The parallel agent's device result (pc `0x1738a80`, fault `0x0`,
  `thread widget.sandbox`, `SandboxEngine_evalScript` → `runScripts`,
  tombstone_13) matches the `delete_map_weak_ref` NULL branch exactly.

---

## 8. RCE assessment and recommendation

* **Primitive: deterministic NULL-pointer dereference / DoS.** Not a controlled
  read, not a controlled free, not a write.
* The record double free is gated behind an unconditional NULL deref; the
  `empty` byte cannot be influenced by heap grooming (free metadata is at `-8`,
  not `+0x04`), and no weak-ref composition keeps `first_weak_ref` non-NULL.
* The synthetic alias exists only after patching out the crash; it immediately
  corrupts the allocator, so it is not a stable type-confusion primitive.
* Recommendation: treat #1835 as a widget-engine kill switch (DoS), patch to
  PR #1844, and pivot the RCE search to a candidate with a surviving UAF
  (the arena/type-confusion class from `lab/arena_inst.c` or another
  finalizer/GC path), not this one.

---

## 9. Deliverables

```
/tmp/opencode/weakmap_poc/
  wm_harness.c              app-model harness (6 MiB, no early teardown, --defer)
  build.sh                  builds asan / release / instrumented / latent
  mk_instr.py               source instrumentation generator
  run_matrix.py             19-case ASan+release matrix
  gen_survival.py           47-shape survival hunt + arena double-free detector
  js/repro_a.js             issue variant A (teardown only)
  js/repro_b.js             issue variant B (app-reachable scope exit)
  js/t*.js                  19-case matrix corpus
  js/surv/, js/groomh/      generated hunt corpora
  logs/matrix_asan.log      full ASan reports for the matrix
  logs/matrix_rel.log       release crash results
  logs/asan_canonical_t02.txt
  logs/inst_repro_b.out     address-level finalizer trace
  logs/inst_t24_multi_weak.log  all weak-ref kinds unlinked + NULL head
  logs/surv/survival.csv    47 shapes, 0 double frees
  logs/latent_alias4.log    synthetic alias + allocator spin
```

Copied to the Telegram tree as `lab/weakmap1835_*` and
`notes/weakmap1835_report.md`.
