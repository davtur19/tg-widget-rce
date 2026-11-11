# armv7 quickjs-ng layout — `lib/armeabi-v7a/libtmessages.49.so` (Telegram 13.2.0 beta 72789)

Target : `/tmp/opencode/libtmessages_armv7.so` (ELF32 ARM, soft-float ABI, NDK r27c, stripped)
md5 `e950232092fba8452eddb36349bc25ef`, BuildID `406a1befe8f723798888235a759969174c13f95e`, 22,874,080 B
IDB    : `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_armv7_widget_annotated.i64`
         (working copy `/tmp/opencode/libtmessages_armv7.so.i64`; annotations saved in both)
Scope  : static analysis only, no device/emulator.

Every offset below is an **ELF-base-relative vaddr** (ET_DYN, first `PT_LOAD` at vaddr 0).

---

## 0. Engine fingerprint

Atom blob @ `0x34EB50` (`"null\0false\0true\0if\0…"`). Atom values are **identical to the
arm64 build**: `Object`=157, `Array`=158, `BigInt`=187, `Map`=190, `Set`=191,
`WeakMap`=192, `WeakSet`=193, `Iterator`=194, `DisposableStack`=222, `lastIndex`=93,
`exec`=143, `constructor`=64, `flags`=116.

⇒ same engine snapshot as the arm64 binary (master between 2026-10-08 and the #1844 merge,
per the arm64 analysis §2/§12), i.e. `js_def_free`-style allocator hooks, `var_ref_count`
u16 semantics, and the #1865-era generator frame code.

Class table `js_std_class_def` @ **`0x156C3D0`**, **12-byte** entries `{JSAtom atom; fn; fn}`
(32-bit): class 1 `Object`, 2 `Array` (fin `0x136B76C`), 19 `RegExp`, 20 `ArrayBuffer`,
22 `Uint8ClampedArray`, 23 `Int8Array`, **24 `Uint8Array`** (fin `0x136BF6C`),
25..33 other typed arrays, 34 `DataView`, **36 `Map`** (fin `0x136BFEC`), 37 `Set`,
38 `WeakMap`, 39 `WeakSet`, 40 `Iterator`.

---

## 1. Allocator endpoint (`js_def_free` → `free@plt` → GOT)

| item | value | evidence |
|---|---|---|
| `js_def_free` | **`0x136D1B0`** | `MOV R0,R1 ; B free` (8 B, Thumb) |
| `js_def_calloc` / `js_def_malloc` / `js_def_realloc` / `js_def_malloc_usable_size` | `0x136D19C` / `0x136D1A8` / `0x136D1B8` / `0x136D1C4` | same 20-byte block |
| `def_malloc_funcs` (JSMallocFunctions) | **`0x156C680`** | 5 dwords `{calloc, malloc, free, realloc, usable_size}` |
| `JS_NewRuntime` | **`0x136CB20`** | `calloc(1,0x328)`; copies the 5 dwords to `rt+0..0x10` |
| `.free` PLT stub | `0x150D9A0` | `ADRL R12,#0x15769A8 ; LDR PC,[R12,#0x9EC]!` → GOT `0x1577394` |
| **`free@GOT`** | **`0x1577394`** | `R_ARM_JUMP_SLOT`, sym `free` (`.rel.plt`, file off `0x1573394`) |
| `malloc@GOT` | `0x15773A0` | `R_ARM_JUMP_SLOT`, sym `malloc` |
| `free` GLOB_DAT (alt.) | `0x15720B8` | `R_ARM_GLOB_DAT` in `.rel.dyn` (address-taken uses) |
| `js_free_rt` | **`0x1326984`** | string `"js_free_rt: malloc_size underflow…"` @ `0x1B1AFE` |

**`JSMallocFunctions` (32-bit) = 5 pointers = 20 bytes**, copied by value to `rt+0`:

```
rt+0x00  js_malloc_calloc        (js_def_calloc)
rt+0x04  js_malloc               (js_def_malloc)
rt+0x08  js_free                 (js_def_free)      <-- arm64 was rt+0x10
rt+0x0C  js_realloc              (js_def_realloc)
rt+0x10  js_malloc_usable_size   (js_def_malloc_usable_size)
rt+0x14  malloc_state.malloc_count
rt+0x18  malloc_state.malloc_size
rt+0x1C  malloc_state.malloc_limit
rt+0x20  malloc_state.opaque     <-- arm64 was rt+0x40 (this is the arg0 passed to js_free)
```

`js_free_rt` proof (large-block path): `sub_1326984(rt, ptr)` ends with
`(*(int(**)(int,int))(rt + 8))(*(u32*)(rt + 0x20), ptr-8)` — callee from **`rt+8`**,
first argument from **`rt+0x20`**. `sizeof(JSRuntime)` = **0x328**
(`calloc(1,0x328)`); arena zero-block at `rt+0x228` (checked against `rt+552` in the same
function).

**ELF hardening**: `DT_FLAGS=0xa` (`DF_SYMBOLIC|DF_BIND_NOW`), `DT_FLAGS_1=0x1` (`DF_1_NOW`)
⇒ the JUMP_SLOTs are resolved at load time (slot holds the real libc `free`); `PT_GNU_RELRO`
= `0x1513100 + 0x6486c` = `0x1513100..0x157796C`, which covers `.got` (`0x1571FE8`) and
`.got.plt` (`0x1573324..0x157796C`) ⇒ read-only after relocation. No `.note.gnu.property`
section in the program headers, soft-float ABI (`e_flags=0x5000200`, `EF_ARM_ABI_FLOAT_SOFT`).

---

## 2. `JSValue` — **NaN-boxed 64-bit, 8 bytes**

`quickjs.h`: `#if INTPTR_MAX < INT64_MAX → JS_NAN_BOXING 1` — 32-bit builds are NaN-boxed.
Binary confirmation (`js_array_finalizer` @ `0x136B76C`, array elements):

```c
v7 = *(DWORD *)(p + 0x1C);          // u.array.values
v8 = *(DWORD *)(v7 + i*8);          // values[i].ptr  (low word)
if (*(DWORD *)(v7 + i*8 + 4) >= 0xFFFFFFF7) ...   // values[i].tag (high word)
stride = 8
```

Layout: `JSValue` = `uint64_t`; **low 32 bits = ptr/int**, **high 32 bits = tag**
(`JS_VALUE_GET_TAG(v) = (int)(v >> 32)`). In soft-float AAPCS a JSValue is passed in
**R0:R1** (R0 = low, R1 = tag).

Tags: `BIG_INT=-9, SYMBOL=-8, STRING=-7, STRING_ROPE=-6, MODULE=-3,
FUNCTION_BYTECODE=-2, OBJECT=-1, INT=0, BOOL=1, NULL=2, UNDEFINED=3, UNINITIALIZED=4,
CATCH_OFFSET=5, EXCEPTION=6, SHORT_BIG_INT=7, FLOAT64=8` (floats are offset-encoded
NaN boxes; any tag > 8 is a float).

---

## 3. `JSObject` — verified

`JSGCObjectHeader` = 8 bytes (`{prev,next}`), so flags/class_id sit at +8/+0x0A.

| off | field | verified in |
|---:|---|---|
| `+0x00` | GC header `{prev,next}` (8 B) | implied by +0x08/+0x0A |
| `+0x08` | flags u16: bit0 is_prototype, bit1 extensible(0x02), bit2 free_mark, bit3 is_exotic(0x08), **bit4 fast_array (0x10)**, bit5 is_constructor, bit6 uncatchable, bit7 tmp_mark, (+0x09) is_HTMLDDA | `js_array_push` `0x138DD64`: `v11 = *(_WORD*)(p+8) & 0x12; v11 == 18` |
| **`+0x0A`** | **class_id u16** | `js_array_push` `*(u16*)(p+10)==2`; `js_map_set 0x136219C` `*(u16*)(p+10)==magic+36` |
| `+0x0C` | `shape` | `js_array_push` (`shape->proto` at `shape+36`) |
| `+0x10` | `prop` | `js_array_push` (`prop[0].u.value` = array length) |
| `+0x14` | `first_weak_ref` | implied (u follows) |
| **`+0x18`** | **union `u`** | `js_map_set` `p->u.map_state = *(u32*)(p+0x18)` |
| `u.array.u1` (size / typed_array) | `+0x18` | `js_array_push` (`length > *(u32*)(p+0x18)`) |
| **`u.array.values` / `u.array.u.ptr`** | **`+0x1C`** | `js_array_push`, `js_array_finalizer` |
| **`u.array.count`** | **`+0x20`** | `js_array_push` (`*(u32*)(p+0x20) == length`) |
| `u.func.function_bytecode` | `+0x18` | first member of `u.func` |
| `u.func.var_refs` | `+0x1C` | second member |
| `u.func.home_object` | `+0x20` | third member |

`sizeof(JSObject)` = **0x24** (union `u.func` = 3 pointers = 12 B).

### Typed-array / ArrayBuffer chain (armv7)

```
JSObject (class 24, Uint8Array)
  +0x18  u.array.u1.typed_array ──► JSTypedArray
  +0x1C  u.array.u.uint8_ptr        (view-adjusted data pointer)
  +0x20  u.array.count              (element count == byte length)

JSTypedArray (0x1C):  +0x00 link.prev  +0x04 link.next  +0x08 obj (back ptr)
                      +0x0C buffer (JSObject* ArrayBuffer)  +0x10 offset  +0x14 length
                      +0x18 track_rab

JSObject (class 20, ArrayBuffer)
  +0x18  u.array_buffer ──► JSArrayBuffer

JSArrayBuffer (0x20): +0x00 byte_length (int)   +0x04 max_byte_length (-1 = fixed)
                      +0x08 detached  +0x09 immutable  +0x0A shared
                      +0x0C data (u8*)          +0x10/+0x14 array_list
                      +0x18 opaque              +0x1C realloc_func
```

Scan predicate (same as arm64 but with 32-bit offsets):
`*(u16*)(p+0x0A)==24 && (*(u16*)(p+0x08) & 0x10) && *(u32*)(p+0x20)==N && *(u32*)(p+0x1C)!=0`.
Validation: `*(u32*)(*(u32*)(p+0x18) + 8) == p` (`JSTypedArray.obj`).

---

## 4. `JSString` — verified (32-bit header 0x10)

| off | field |
|---:|---|
| `+0x00` | `len:31 | is_wide_char:1` |
| `+0x04` | `hash:28 | kind:2` (`kind 0` inline, `1` slice, `2` indirect) |
| `+0x08` | `atom_type:2 | hash_next:30` |
| `+0x0C` | `first_weak_ref` |
| `+0x10` | data (inline: `p+0x10`; slice/indirect: `*(u32*)(p+0x10) + *(u32*)(p+0x14)`) |

Evidence: `JS_RegExpDelete` `0x139DC04` — `len = *(u32*)str & 0x7FFFFFFF` (line 144 of the
pseudo-code), indirect data `*(u32*)(str+0x10) + *(u32*)(str+0x14)` (lines 127/133),
`string_buffer_concat(str, …, len)` (line 237).

`JSStringRope` (kind value used by ropes): `{u32 len; u8 is_wide_char; u8 depth; JSValue left; JSValue right}`.

---

## 5. `JSFunctionBytecode` (derived from the 0.18.0 struct, 32-bit arithmetic)

| off | field | arm64 equivalent |
|---:|---|---|
| `+0x00` | GC header (8) | +0x00 (16) |
| `+0x08` | bitfields (`is_strict_mode`…`backtrace_barrier`, 2 B) | +0x10 |
| `+0x0C` | `byte_code_buf` | +0x18 |
| `+0x10` | `byte_code_len` (int) | +0x20 |
| `+0x14` | `func_name` (JSAtom) | +0x24 |
| `+0x18` | `vardefs` (`JSVarDef*`) | +0x28 |
| `+0x1C` | `closure_var` (`JSClosureVar*`) | +0x30 |
| `+0x20` | `arg_count` u16 | +0x38 |
| `+0x22` | `var_count` u16 | +0x3A |
| `+0x24` | `defined_arg_count` u16 | +0x3C |
| `+0x26` | `stack_size` u16 | +0x3E |
| **`+0x28`** | **`var_ref_count` u16** | +0x40 |
| `+0x2A` | `closure_var_count` u16 | +0x42 |
| `+0x2C` | `cpool_count` int | +0x44 |
| **`+0x30`** | **`realm` (JSContext*)** | **+0x48** ← the "bytecode+0x48" anchor |
| `+0x34` | `cpool` (JSValue*) | +0x50 |
| `+0x38` | `filename` JSAtom | +0x58 |
| `+0x3C` / `+0x40` / `+0x44` / `+0x48` | line_num / col_num / source_len / pc2line_len | +0x60… |
| `+0x4C` / `+0x50` | `pc2line_buf` / `source` | |
| size | **0x54** | 0x68 |

`JSVarDef` (0x14 on 32-bit): `var_name +0x00, scope_level +0x04, scope_next +0x08,
bitfield byte +0x0C, var_ref_idx u16 +0x0E, func_pool_idx +0x10`.
`JSClosureVar` (0x08): `{u8 flags; u8 pad; u16 var_idx; u32 var_name}` → 8 bytes.

---

## 6. `JSVarRef` and `JSStackFrame` (derived, 32-bit)

`JSVarRef` — **0x18 bytes**:

| off | field |
|---:|---|
| `+0x00` | GC header `{prev,next}` (8 B) |
| `+0x08` | `is_detached` (u8) |
| `+0x09` | `is_lexical` |
| `+0x0A` | `is_const` |
| `+0x0B` | `is_coro` |
| **`+0x0C`** | **`JSValue *pvalue`** (points at the stack slot or at `+0x10`) |
| `+0x10` | union: `JSValue value` **or** `{u16 var_ref_idx; JSStackFrame *stack_frame}` → **`stack_frame` at `+0x14`** |

`pvalue` is a `JSValue*` to an **8-byte NaN-boxed** slot.

`JSStackFrame` — **0x2C bytes**:

| off | field | arm64 |
|---:|---|---|
| `+0x00` | `prev_frame` | +0x00 |
| **`+0x04`** | **`cur_func` ptr** | **+0x08** ← the "sf+8" anchor |
| `+0x08` | `cur_func` tag | +0x10 |
| `+0x0C` | `arg_buf` (JSValue*) | +0x18 |
| `+0x10` | `var_buf` (JSValue*) | +0x20 |
| **`+0x14`** | **`var_refs` (`JSVarRef**`)** | +0x28 |
| `+0x18` | `cur_pc` | +0x30 |
| **`+0x1C`** | **`var_ref_count` u16** | +0x38 |
| `+0x1E` | `arg_count` u16 | +0x3A |
| `+0x20` | `is_strict_mode` | +0x3C |
| `+0x21` | `is_constructor` | +0x3D |
| `+0x24` | `cur_sp` | +0x40 |
| `+0x28` | `cur_gc_obj` | +0x48 |

---

## 7. Other structures the exploit may touch

* `JSBigInt`: `{u32 len; u32 tab[];}` → **limb = 32 bits**, `len` at `+0x00`, limbs at
  `+0x04`, little-endian two's complement, `len >= 1`. `JS_TAG_BIG_INT = -9`;
  short bigints live inline in the JSValue (`JS_TAG_SHORT_BIG_INT = 7`, payload in the low
  32 bits, signed).
* `JSRegExp` (by value in `u`): `pattern +0x00`, `bytecode +0x04` (so
  `p->u.regexp.bytecode` = `*(u32*)(obj + 0x1C)`).
* `JSMallocBlockHeader` (8 bytes before every allocation): `u16 block_idx (+0)`,
  `u8 block_size_idx (+2)`, `u8 gc_type:7|mark:1 (+3)`, `int ref_count (+4)`,
  `user_data` at **+8**. `block_idx == 0xFFFF` ⇒ large block.
  ⇒ every quickjs object pointer is `allocation + 8`, and `ref_count` lives at `p-4`.
* `JSMapState` (32-bit): `is_weak +0x00`, `records +0x04/+0x08`, `record_count +0x0C`,
  `hash_table +0x10`, `hash_size +0x14`, `threshold +0x18`;
  `JSMapRecord`: `ref_count +0x00, empty +0x04, map +0x08, link +0x0C/+0x10,
  hash_link +0x14/+0x18, key +0x20 (8 B), value +0x28 (8 B)`, size 0x30.

---

## 8. arm64 → armv7 anchor mapping for the exploit

| arm64 expression | arm64 | armv7 | notes |
|---|---:|---:|---|
| `rt->mf.js_free` | `rt+0x10` | **`rt+0x08`** | `def_malloc_funcs[2]`, js_def_free = `0x136D1B0` |
| `rt->malloc_state.opaque` | `rt+0x40` | **`rt+0x20`** | arg0 of `js_free` |
| `ctx->rt` | `ctx+0x10` | **`ctx+0x08`** | 215 call sites `LDR R0,[ctx,#8]; BL js_free_rt` |
| `b->realm` | `bytecode+0x48` | **`bytecode+0x30`** | `JSFunctionBytecode.realm` |
| `sf->cur_func.ptr` | `sf+0x08` | **`sf+0x04`** | `JSStackFrame.cur_func` |
| `p->u.func.function_bytecode` | `curfunc+0x30` | **`curfunc+0x18`** | union `u` at +0x18 |

So the armv7 chain is
`sf+0x04 → curfunc+0x18 → bytecode+0x30 (realm) → ctx+0x08 (rt) → rt+0x08 (js_def_free)`,
and the write primitive is `rt+0x08 = system`, `rt+0x20 = command`.

---

## 9. Frame / OOB geometry (65,534 params + eval + 5 locals)

* `JSValue` = **8 B**; `var_refs[]` entries are **4-byte `JSVarRef*`**.
* `arg_count`, `var_count`, `stack_size`, `var_ref_count`, `closure_var_count` are all
  **u16** in `JSFunctionBytecode` (+0x20, +0x22, +0x26, +0x28, +0x2A) and in
  `JSStackFrame` (+0x1C `var_ref_count`, +0x1E `arg_count`).
* Frame buffers in the (generator/coroutine) frame:
  `arg_buf = 8 * arg_count`, `var_buf = 8 * var_count`, `stack_buf = 8 * stack_size`,
  `var_refs = 4 * var_ref_count`.
  With 65,534 params: `arg_buf` = **524,272 B**; with 5 locals `var_buf` = 40 B.
* **Truncation**: `var_ref_count` is stored as u16. 65,534 params + 5 locals = 65,539
  captured slots ⇒ stored value = `65539 & 0xFFFF` = **3**. The array is allocated with
  **3 entries = 12 bytes**, while `var_refs[idx]` is still indexed with the *untruncated*
  index (u16 `JSVarDef.var_ref_idx`, so max 65,535).
* **OOB slot**: `var_refs + 4*idx`; for `idx = 65535` that is `var_refs + 262,140`,
  i.e. **262,128 bytes past the 12-byte allocation** (≈256 KiB). Slot distance formula:
  `Δ = 4 * (idx - stored_var_ref_count)`.
* Every `var_refs[i]` is a `JSVarRef*`; a `JSVarRef` is 0x18 B with `pvalue` at **+0x0C**,
  so an OOB slot that is later used as a var_ref pointer gives a controlled dereference at
  `+0x0C` (read/write of an 8-byte NaN-boxed JSValue).
* "P / padding" equivalent: on arm64 the padding was the byte distance between the
  allocation and the target slot; on armv7 it is the same
  `P = 4*(idx_real − var_ref_count_u16)`, with `idx_real ≤ 65,535`. `P` can be dialled in
  4-byte steps up to 262,128 B, i.e. much coarser granularity (4 B) than arm64 (8 B).

> Caveat: the exact number of captured slots depends on the compiler marking each
> parameter/local as captured (`is_captured` ⇒ `var_ref_idx`). With `eval` in the body all
> enclosing vars become captured, but the precise count must be confirmed from the emitted
> `JSFunctionBytecode` (fields +0x20/+0x22/+0x28) at runtime.

---

## 10. What is verified vs derived

**Verified in this binary** (addresses above): allocator endpoint (`js_def_free`,
`def_malloc_funcs`, PLT/GOT/relocations/BIND_NOW/RELRO), `JSMallocFunctions` layout /
`rt+0..0x20`, `sizeof(JSRuntime)=0x328`, `js_free_rt` callee/opaque slots, `ctx+0x08 = rt`,
`JSValue` = 8-byte NaN box (stride/tag in `js_array_finalizer`), `JSObject`
flags/class_id/shape/prop/u/array fields, `JSString` header 0x10 + data at +0x10,
class table and class IDs, `js_map_set`/`js_array_push`/`JS_RegExpDelete`.

**Derived** from the v0.18.0 struct definitions using the verified primitives (4-byte
pointers, 8-byte GC header, 8-byte JSValue, natural 32-bit alignment):
`JSFunctionBytecode`, `JSVarRef`, `JSStackFrame`, `JSBigInt`, `JSArrayBuffer`,
`JSTypedArray`, `JSVarDef`, `JSClosureVar`, `JSMapRecord`. These are structurally
unambiguous (no bitfield straddling) but were not each disassembled; validate the two that
matter most for the chain (`bytecode+0x30` realm, `sf+0x04` cur_func) on the first device
run by reading a known function's bytecode object.

**Not available**: an **armv7 Android libc**. `/tmp/opencode/device_libc/*.so` are all
AArch64 (ELF class 2, machine 183); there is no `armeabi-v7a` libc or emulator image in
this workspace, so `free`→`system` (the arm64 `+0x26df0`) **cannot be derived here**. It
must come from the target device's `/system/lib/libc.so` (or from `dlsym`/a leak) on-device.

---

## 11. IDB

`<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_armv7_widget_annotated.i64`
(273 MB, saved; working copy `/tmp/opencode/libtmessages_armv7.so.i64`).

Renamed: `js_def_calloc/malloc/free/realloc/malloc_usable_size`, `def_malloc_funcs`,
`JS_NewRuntime`, `js_free_rt`, `js_array_finalizer`, `js_array_push`, `js_map_set`,
`js_map_finalizer`, `js_std_class_def`, `JS_RegExpDelete`, `free_GOT`, `malloc_GOT`;
comments on `js_def_free`, `JS_NewRuntime`, `js_free_rt` documenting the `rt` layout.
