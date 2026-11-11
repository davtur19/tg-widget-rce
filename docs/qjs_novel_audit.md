# Novel quickjs-ng audit — FinalizationRegistry.unregister UAF

Date: 2026-11-02. Host-only, source-first; no phone/emulator, no fuzz campaign.

## Verdict

No novel RCE was found. One **novel, unreported memory-safety bug** was found
and reproduced on both `d7215b0` (v0.18.0) and `7a23d8e` (app 72799):

**`FinalizationRegistry.prototype.unregister()` iterates `frd->entries` with
`list_for_each_safe`; freeing one entry's held value can synchronously free the
saved next entry, and the loop continues through freed `JSFinRecEntry`
memory. This is confirmed with ASan (heap-use-after-free) and UBSan (null
`list_head` access). It is a deterministic plain-JS crash. RCE is not
demonstrated; the stale `list_del` would be a write-what-where only if the
freed 96-byte entry were reclaimed with controlled `link` fields, and no
allocation occurs in the gap on this path.**

The upstream tracker has no matching issue: searches for
`FinalizationRegistry`, `unregister`, and the exact code path returned only
#1318/#1352/#1366 (different FinalizationRegistry lifetime bugs, fixed in
February 2026) and older #432/#656/#494 reports. None covers the
`unregister` list iteration.

## 1. Versions

| | commit | date | version |
|---|---|---|---|
| App 72799 | `7a23d8e3fedb010070ef1a03873c55500c7aa1a9` | 2026-10-23 | 0.17.0 |
| Latest | `d7215b0ad3fc2c562e8317fd9bca058fd4863804` | 2026-11-01 | 0.18.0 |

`js_finrec_unregister`, `js_finrec_free`, `reset_weak_ref`, and
`js_finrec_finalizer` have **no delta** between these commits
(`git diff 7a23d8e..d7215b0 -- quickjs.c` has no hunk touching them), so the
bug is shared.

## 2. The bug

`quickjs.c:63357..63380`:

```c
static JSValue js_finrec_unregister(...)
{
    ...
    list_for_each_safe(el, el1, &frd->entries) {
        JSFinRecEntry *fre = list_entry(el, JSFinRecEntry, link);
        if (js_same_value(ctx, fre->token, token)) {
            list_del(&fre->link);
            delete_finrec_weakref(ctx->rt, fre);
            js_finrec_free(ctx->rt, fre);   /* can free `el1` */
            removed = true;
        }
    }
}
```

`js_finrec_free()` frees `held_val`:

```c
static void js_finrec_free(JSRuntime *rt, JSFinRecEntry *fre)
{
    JS_FreeValueRT(rt, fre->held_val);   /* <- may drop the last ref */
    JS_FreeValueRT(rt, fre->token);
    JS_FreeValueRT(rt, fre->cb);
    JS_FreeContext(fre->ctx);
    js_free_rt(rt, fre);
}
```

If `fre->held_val` is the last strong reference to object `T`, freeing it
runs `free_object(T)` -> `reset_weak_ref(T)`. A second FinalizationRegistry
entry `E2` whose **target is T** is unlinked and freed inside that reset
(`quickjs.c:63446..63512`), even though `E2` is the `el1` saved by the
`unregister` loop. The loop then uses the freed node.

Two consequences:

* `el1 = el->next` reads the freed `JSFinRecEntry`; `list_del` in
  `reset_weak_ref` has set its `link.prev/next` to NULL, so the next loop
  step dereferences NULL (`member access within null pointer of type 'struct
  list_head'`, UBSan).
* If the freed entry were reclaimed with controlled bytes before the loop
  update, `js_same_value(fre->token, token)` and `list_del(&fre->link)` would
  operate on fake `prev/next` pointers. No such reclaim allocation exists in
  the gap here, so this remains a write-what-where hypothesis.

The entry is `sizeof(JSFinRecEntry) == 88` bytes, arena class 96. It is freed
with `js_free_rt`, so in the app's arena allocator it can be recycled by a
later 96-byte allocation, but not before the stale iteration.

## 3. PoC

`lab/qjs_novel_audit/poc/finalization_registry_unregister_uaf.js` (plain JS,
no host APIs):

```js
var T = {};
var tok = {};
var k1 = {};
var reg = new FinalizationRegistry(function(){});
reg.register(k1, T, tok);   // E1: target k1, held T (strong), token tok
reg.register(T, 2);         // E2: target T (weak)
T = null;                   // only E1's held value keeps T alive
reg.unregister(tok);        // frees E1 -> frees T -> reset_weak_ref frees E2
```

Reproduced with the generic runner `harness/runjs.c`:

```bash
clang -g -O0 -DNDEBUG -D__SANITIZE_ADDRESS__=1 -fsanitize=address \
  -I<quickjs-src> harness/runjs.c <quickjs-objects> -lm -lpthread -o runjs_asan
ASAN_OPTIONS=detect_leaks=0 ./runjs_asan poc/finalization_registry_unregister_uaf.js
```

ASan (`logs/asan_finrec_uaf.txt`):

```
ERROR: AddressSanitizer: heap-use-after-free
READ of size 8 in js_finrec_unregister quickjs.c:63369
freed by:
  js_finrec_free quickjs.c:63250
  reset_weak_ref   quickjs.c:63511
  free_object
  js_free_value_rt
  JS_FreeValueRT
  js_finrec_free   quickjs.c:63246   (held value T)
  js_finrec_unregister quickjs.c:63374
```

The freed region is a 96-byte allocation (88-byte `JSFinRecEntry` + arena
header). UBSan on the Debug build reports the same null `list_head` access at
`quickjs.c:63369`; a build linked against 7a23d8e reports the equivalent at
`quickjs.c:63295` (`logs/ubsan_finrec_appera.txt`).

A second variant, `poc/finalization_registry_unregister_null_write.js`,
registers E2 with the same token so the stale `js_same_value` branch is
taken; the stale `list_del(&fre->link)` then has NULL `prev/next` (the
`reset_weak_ref` `list_del` cleared them), i.e. a NULL write rather than only
a NULL read (`logs/asan_finrec_null_write.txt`).

## 4. Why this is not (yet) RCE

The stale node is used in two places:

1. `js_same_value(ctx, fre->token, token)` — a read. If the freed entry's
   token still equals the argument (e.g. register E2 with the same token),
   the branch is taken.
2. `list_del(&fre->link)` — `prev->next = next; next->prev = prev`.

`reset_weak_ref` calls `list_del(&fre->link)` before freeing E2, so
`fre->link.prev/next` are NULL. A taken branch therefore writes to NULL, not
to an attacker address. To turn this into a controlled write, the freed
96-byte block would need to be reallocated with attacker-controlled
`link.prev/next` and a matching `token` before the loop update. I found no
allocation between the free and the update:

Ordering, exactly:

1. `js_finrec_unregister(E1)` -> `list_del(E1)` -> `delete_finrec_weakref(E1)`
   (only `js_free_rt(wr)`).
2. `js_finrec_free(E1)` -> `JS_FreeValueRT(E1->held_val)` -> `free_object(T)`
   -> `reset_weak_ref(T)`:
   - pass 1 unlinks all weak refs, including `list_del(E2)`;
   - pass 2, FINREC: `JS_EnqueueJob(fre->ctx, js_finrec_job, 2, args)` allocates
     `sizeof(JSJobEntry) + 2 * sizeof(JSValue)` = 72 bytes (measured
     `sizeof(JSJobEntry) == 40`) -> arena class 80,
     then `js_finrec_free(E2)` frees E2 (class 96);
   - other weak-ref kinds only unlink/free records or values.
3. Back in `js_finrec_free(E1)`: free E1 token, callback, context, then E1
   (class 96).
4. Return to `list_for_each_safe`: `el = el1` (E2), `el1 = el->next` reads
   the freed E2 link (NULL).

There is no JS execution in this interval. The only allocation is the
class-80 job. The free paths that can run (Array, Map, Set, Proxy,
ArrayBuffer/TypedArray, String/Rope, BigInt, Promise, Generator,
FinalizationRegistry, WeakRef, DisposableStack) only free and enqueue at
most the same class-80 FinalizationRegistry job; none allocates class 96 or
calls back into JS. `register()` cannot run until `unregister()` returns.
Reentrant `unregister` from a getter/`Symbol.toPrimitive`/Proxy trap is
impossible here: the token expression is evaluated before the C function
enters, and the loop itself performs no user-code call. A 96-byte
`JSFinRecEntry` can be allocated by `reg.register()` only after the crash.
Therefore the present finding is a deterministic **DoS / memory-safety UAF**,
not a demonstrated RCE. If a future/other primitive can allocate 96 bytes of
controlled data at this point, the stale `list_del` becomes a two-pointer
write.

## 5. Novelty check

GitHub API searches on 2026-11-02, repo `quickjs-ng/quickjs`:

* `FinalizationRegistry` -> 22 issues/PRs; reviewed #1318, #1352, #1366, #432,
  #494, #656: all are different lifetime/cycle bugs (callback cycles,
  `fre->obj` raw reference in `reset_weak_ref`, finalizer ordering).
* `unregister` in title/body -> 0 results.
* `js_finrec_unregister`, `freed entry`, `list_for_each_safe entries` -> no
  matching report.
* `origin/master` at the time was still `d7215b0`.

## 6. Other hot spots audited (negative)

* **ArrayBuffer/typed arrays**: resize/transfer/slice/subarray/set/with/
  toSorted/fill/copyWithin/detach revalidation; no new OOB. The `resize`/
  `maxByteLength` issues #1858/#1859 are spec-conversion only; allocation
  length always matches the stored length.
* **Map/Set**: hash resize, delete/clear/forEach/iterators, weak-map symbol
  keys; no new UAF beyond the known #1835 (fixed by #1844). Set algebra
  methods copy/lock correctly. I also tested a WeakMap with a symbol key and
  a cyclic value through `JS_RunGC`; the value survives (its record's strong
  ref keeps it alive), so the suspected symbol-key mark gap is not a UAF.
* **FinalizationRegistry/WeakRef family**: besides the unregister UAF, the
  finalizer, reset, WeakRef finalizer, registration and callback-job paths
  were re-read; no second controllable write. `JS_AddBrand` appears to leak
  one symbol reference per brand use (`js_symbol_to_atom` is borrowed while
  the local `brand` JSValue is not freed), but this is a leak, not memory
  corruption, and is not claimed here.
* **BigInt**: limb arithmetic, shifts, `asUintN/asIntN`, parsing. Targeted
  ASan runs over decimal/hex/octal/binary length sweeps and mixed-limb
  arithmetic found no OOB (`lab/qjs_novel_audit` does not include these
  negative logs; they were run against the same ASan build).
* **Proxy**: trap reentrancy/revoke, ownKeys list, descriptor invariants; no
  new UAF found.
* **Promises/async/generators**: reaction list, thenable job, async generator
  queue, async-from-sync iterator; no new defect beyond known #1865/#1570.
* **Strings/ropes/JSON**: string builder/rope lifetime, repeat/pad numeric
  conversion, JSON stringify/parse source records; no new memory bug.
* **BigInt**: limb arithmetic, shifts, `asUintN/asIntN`, parsing; no new
  memory bug.
* **Parser**: the previously reported N1 (`push_scope`) and #1782 are the
  parser-OOM findings; I did not re-report them. A code-reading hypothesis
  remains around `emit_op`/`fd->last_opcode_pos` after a failed `dbuf_putc`
  (one-byte fixed-opcode write past the bytecode buffer), but it is
  parser-OOM-adjacent and was not verified here.

## 7. Artifacts

```
lab/qjs_novel_audit/
  poc/finalization_registry_unregister_uaf.js
  poc/finalization_registry_unregister_null_write.js
  harness/runjs.c
  logs/asan_finrec_uaf.txt
  logs/asan_finrec_null_write.txt
  logs/ubsan_finrec_uaf.txt
  logs/ubsan_finrec_appera.txt
```

No RCE, arbitrary read/write, or address leak is claimed.
