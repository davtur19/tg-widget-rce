# Universal chain architecture — 0day candidates for MTE-on Android + iOS

Date: 2026-11-08. **Host-only** (no device, Frida, bot or network). Scope: turn the
existing primitives (v7/#1827 endgame, N1, C2, F1, parser route 2, OOM getter) into
a chain map, design concrete full-RCE chains, and name the single missing primitive
that blocks a universal (MTE-on Android + iOS, ideally same payload) 0day.

This note does **not** modify the shared inventory/notes; it is additive. Evidence
and reproducers are under `lab/universal_chain/`.

---

## 0. Verdict (short)

1. **No chain exists today that is a universal MTE-on-Android + iOS 0day RCE.**
   The only cross-platform (same-engine) primitives are (a) the parser
   `ARG_SCOPE_END` 0day — a non-OOM, same-tag, host-proven OOB read/write whose
   device geometry and iOS endgame are unproven — and (b) F1, a same-tag UAF
   **read** only. Everything else is Android-only (N1 needs an OOM; the getter
   bypass that makes it survivable is Android-proven and **iOS-unverified** —
   the only iOS N1 run predates the getter) or an n-day (v7).
2. **The endgame bar is much lower than the v7 payload suggested.** A new host
   proof (`lab/universal_chain/run/poc_count_rce.js`) shows that a **single
   4-byte small-value write to a typed-array `JSObject+64` (`u.array.count`)**
   boots the whole v7 same-view chain to `system()`: scan → re-pivotable BigInt
   reader → `ctx`/`rt` → ELF `system` resolver → `rt->mf.js_free` hook. No 2 GB
   `byte_length` corruption is needed. A count of **64** is enough when the view
   object is in the same class-112 page as its data (measured delta 112/224 B);
   1,024 covers the common burst layouts; 8,192 the worst seen (6.9 KB).
   **Therefore the missing primitive is not "a v7-class bug"; it is any
   non-OOM 4-byte write of a value ≥ ~64 into a typed-array count (or another
   length field) with a controllable target.**
3. The closest existing fit is **N1** (0day, same-tag, value = parsed var count
   ≤ 65535, exact 4-byte store): with the v7 endgame it becomes an MTE-on
   Android full RCE. Its blocker is the same one as before — the write target's
   per-state/per-device layout — plus the OOM gate (getter: Android-proven,
   iOS unverified).
4. The only **non-OOM** 0day write is the **parser route 2** (arena `b` + arena
   target). Its blocker is not a memory primitive but **layout portability**
   (slab contiguity/slot/phase) and the iOS endgame/PAC; it is the only path
   that can plausibly be same-payload across both platforms.
5. The **fork's RegExp cache changes the v7 technique's preconditions**: the
   #1827 stale-bytecode free is *not* unconditional. The shipped v7 payload
   works because `"abcdefghij"×12` and `"x"` collide in cache slot 0
   deterministically (reproduced: both slot 0 with flags=1). The fork hash is
   reproducible in JS, so eviction can be forced for any carrier (F1 currently
   evicts probabilistically with 24 patterns; it can be made deterministic).

**Single most promising missing primitive:** a **portable, non-OOM 4-byte
length/count write in the tag-0 arena** — concretely, complete the parser
route-2 stage so its `b + 1,310,828` target is *self-locating* (or find a second
non-OOM stale-pointer store in the RegExp/string engine). Second: make the N1
count write layout-robust on Android (same-class-page groom + a bounded, safe
calibration).

---

## 1. Primitive / chain map

Legend — **tag**: `arena` = QuickJS `JS_ARENA_SLABS` 64 KiB `mmap`, `PROT_READ|WRITE`,
tag 0, never MTE-checked; `scudo-P` = Scudo primary, `MAP_MTE` under MTE-on,
random chunk tag; `scudo-S` = secondary user data, tag 0 on the measured Android 17
smaps; `C++` = native heap.
**OOM**: the trigger needs a refused allocation (fatal unless the getter bypass is
installed — Android-proven, iOS unverified). **zlib9** = measured unless marked est.

| id | primitive | gives | tag domain | OOM? | Android | iOS | zlib9 | 0day? |
|---|---|---|---|---|---|---|---|---|
| **v7/#1827** | freed RegExp bytecode reclaimed by `Uint8Array` (class 480/512) → fake `REOP_set_i32` → victim AB `byte_length` (class 64) → BigInt same-view `u.ptr` re-pivot | **full arbitrary 64-bit RW** + `system()` | arena everywhere; `rt`/`ctx` read/written with full tags | no | **MTE-on proven** (Pixel 9, C2 uid 10290) | primitive proven (open/read/write exfil); full RCE blocked by PAC | 3,056 | **n-day** (`3d5cb14`/`2b62af1` missing in app snapshot) |
| **N1** | failed `push_scope` realloc → fake `JSVarScope` parent chain → 4-byte store of `var_idx` at `scopes+20L+4` | **4-byte small-value write** (≤ var count, ≤65535), 20-byte target grid, value tunable by source | arena (class 128 scopes + target) | **yes** (refused `realloc`) | host 5/5 full chain; device gate/getter/job proven; layout not portable | **unverified** (one run without the getter crashed on the fake-chain/OOM path) | gate 1,270; AB stage 3,094; full 6,618 | **0day** (unreported) |
| **C2** | `update_var_htab` uses requested mask after failed grow → 4-byte store `k` at class-288 neighbour+48/188/192 | 4-byte store, value ≤106, same-slab | arena | yes (realloc) | no endgame | no | ~2.3–2.5 KB | 0day |
| **F1** | subclass `RegExp` + failed `lastIndex` define; post-`lre_exec` prototype setter recompiles → `lre_get_groupnames` reads freed bytecode | **forward C-string read / heap leak** (6-byte pointers to first NUL), atom in `m.groups`; no write | arena (class 480/512) | no | host `groups=[F1]` | engine-shared, not run | small | **0day** (upstream still snapshots before the setter) |
| **Parser P0** | `ARG_SCOPE_END`: `b->vardefs[argc+65534]` → +1,310,700 OOB read of a fake `JSVarDef`, then closure-var writes to a class-64 AB struct | **large length write** (327,744) → 327 KB window; controlled 8-byte closure-var stores | route 2: arena class 352 `b` + arena class-512 target, tag 0; shipped form: Scudo cross-tag | **no** | host 5/5; Sony 72929 5/5 (shipped, MTE-off) | same bug present in 0.17.0 upstream; iOS build/geometry unverified | 4,001 / 4,079 | **0day** (upstream) |
| **OOM getter** | `InternalError.prototype.name` getter makes the engine log instead of kill | policy bypass: the aborted script's sibling/job still runs | n/a | n/a | **proven on Sony** | **unverified** (iOS reads name/message through the same shape per `widget_memory_limits` §7; no getter run yet) | 247 | tool |
| **FR / MB-01 / MB-02** | finalizer/WeakMap record UAF (class 96) | DoS crash; no class-96 allocation in the free→read gap | arena | no | no | no | small | 0day/n-day |
| **C1** | `cpool_add` failure → 16-byte write at `cpool-16` | chunk-header write (tag 0 through a tagged pointer) | scudo-P → header | yes | MTE fault | no | — | 0day |
| **LT** | litehtml `rowspan/colspan` negative index | C++ vector underflow (data-56) | C++ | no | MTE fault (cross-tag) | no | — | 0day |

Notes that matter for chaining:

* **The v7 endgame is a technique, not the bug.** It needs (i) a view over a
  controlled/data block `D`, (ii) the ability to read/write the view's
  `JSObject+56` (`u.ptr`) and `+64` (`count`) at least once, (iii) the view
  objects within the forward window (`k < 8*count` for BigInt64 views).
* `JSObject` layout is identical on host x86-64 and arm64 LP64 (measured):
  `class_id +18` (2 B inside the word at +16), `shape +24`, `prop +32`,
  `u.array.u.ptr +56`, `u.array.count +64`, size 72. A typed-array JSObject with
  2 inline props is **class 112** (same class as `ArrayBuffer(72)` data blocks,
  which is why the v7 forward scan finds the views).
* The **fast element paths do not re-check `typed_array_is_oob`**: they check
  `idx < count` only (`js_get_fast_array_element`, `js_put_fast_typed_array_element`).
  A corrupted `count` therefore yields OOB RW even though
  `typed_array_is_oob()` would flag the view (confirmed by the working PoC).
* The fork's `JS_REGEXP_CACHE_SIZE 16` holds strong refs to the last 16
  (pattern, flags) bytecodes. `JS_RegExpDelete`/`js_regexp_exec` only see a
  freed bytecode after the victim's slot is evicted. Eviction is fully
  controllable: the slot is
  `(h * 0x9e3779b1) >>> 28`, `h = flags; h = h*263 + char; h ^= len*0x61c88647`
  (all 32-bit), reproduced in `lab/universal_chain/run/cache_slot.js` and
  matched to the engine trace for the v7 pattern pair (both slot 0).

---

## 2. The missing link (exact)

A **non-OOM, same-tag (arena), portable 4-byte write** whose value can be made
≥ ~64 and whose target can be a typed-array count (`JSObject+64`), or any
equivalent length field that yields an 8–64 KB forward window. It may also be a
4-byte write at an arbitrary address if a leak/calibration is available.

Why this is the right bar:

* The v7 endgame is host-proven to work from **one** count corruption of 1,024
  (and the tight geometry needs only ~64): no pointer write, no 64-bit value,
  no fake object.
* The store value only has to exceed the byte distance to the view object
  divided by 8. In the measured tight groom the view is +112/+224 B from `D`
  → value ≥ 28/29; a value of 64 covers 512 B.
* The store must not be cross-tag: the target (class-112 page) and the store
  base (whatever the bug uses) should both be tag 0. N1's base is the class-128
  scopes block (arena) → same tag. The parser's base is `b` (arena class 352
  under route 2) → same tag.
* The write should be reachable **without a refused allocation** to be
  portable: a non-OOM write never touches the iOS OOM policy (unverified with
  the getter) and needs no getter on Android.

Current inventory against the bar:

| candidate | value | target reach | OOM-free | portable | verdict |
|---|---|---|---|---|---|
| N1 | ≤65535 ✔ | 20-byte grid from scopes; **layout per state/device** ✘ | ✘ | ✘ | closest Android carrier |
| C2 | ≤106 ✔ (enough for the tight groom) | class-288 neighbour **+48/188/192 ≠ +64** ✘ | ✘ | ✘ | dead end |
| Parser P0 | 327,744 ✔ | fixed +1,310,828; route 2 puts both sides in arena, geometry host-only ✘ | ✔ | ✘ (currently) | only non-OOM write, long shot |
| F1 | — (read) | — | ✔ | ✔ (engine-shared) | leak only |
| new/second stale-pointer store | ? | ? | ? | ? | **the hunt target** |

---

## 3. Chain A — N1 small write → typed-array count → v7 same-view endgame

**Status: endgame host-proven (today); write placement and gate tuning open;
Android MTE-on (iOS reopenable only if the getter takes — §3.2).**

### 3.1 Trigger and geometry

1. Groom a 64 KiB arena slab with two pages:
   * class-112 page: 31 × `new ArrayBuffer(72)`; the victim data block is the
     last one; then `new BigInt64Array(victim)` and `new BigUint64Array(victim)`
     (their JSObjects are also class 112; in the n1_fork trace the victim data
     is block 31 and the views blocks 32/33, i.e. +112/+224 B from `D`).
   * class-128 page (same slab): pre-fill with `('q'+i+':').padEnd(95,'P')`
     strings, then the FK string and the parser's `scopes` array.
2. Gate: the self-calibrating class-48 fill + `InternalError.prototype.name`
   getter + a pre-compiled job `J2` (existing artifacts). `J2` does `TAKE(F)`,
   creates/keeps the victim views, allocates the FK (`String.fromCharCode(...)`
   with the parent chain), then `eval(SRC)` where `SRC` has ~1024 vars.
3. The 6→9 `push_scope` realloc is refused; the parser walks the fake
   `JSVarScope` chain (`scopes[-1].parent = -2 … [-4] = L`) and
   `add_scope_var` stores `idx` (= var count, 1024) at `scopes + 20L + 4`.
4. Choose `L` so the store lands on the victim view's `count` (+64):
   `20L = (ar2-ar1) + 112·i2 − 128·i1 + 60`, with `i1` = scopes block index,
   `i2` = view block index, `ar1`/`ar2` = the two 4 KiB page bases. For two
   pages in the same slab, `ar2-ar1 = 4096·Δs` (`Δs = s2−s1`, view slot minus
   scopes slot); integrality requires `i1 + i2 ≡ 2·Δs (mod 5)`. Measured
   example (n1_fork trace): slot1=8, slot2=7 (`Δs=−1`), i1=9, i2=32 →
   not integral; with i1=11 → **L = −93**, target = view+64, all inside the
   same 64 KiB slab (mapped, tag 0).
5. The eval aborts (uncatchable OOM); the getter keeps the engine alive. A
   sibling script frees the fill (`Q.A=null`, ~3 MB) and then runs the endgame
   with `R`/`W` (count now 1024).
6. Endgame (host-proven, see §7): scan `R[0..1024)` for the view JSObject
   (`class_id` in the word at +16, `count` at +64), read `D` from `u.ptr`,
   compute `shape/proto/ctor/ctx/rt/js_free`, resolve `system` through the ELF
   GNU hash, write `rt+16=system`, `rt+64=D` (command), drop `TRIG` →
   `system(cmd)`.

Tag domain: scopes, FK, view data, view JSObjects, command buffer → all arena
tag 0. Endgame `rt`/`ctx` accesses are full 64-bit (tag-preserving, the v7
rule). MTE-on safe by construction, assuming the layout is right.

### 3.2 Why this is a 0day and why it is not universal

* The bug is N1 (`push_scope` OOM), unreported, same-tag — a 0day. The v7
  endgame is the proven technique.
* The gate is a **refused allocation**. On Android the getter bypass makes it
  survivable (device-proven). The iOS status is **unverified, not closed**: the
  only iOS N1 run (`n1_ios_s1safe_nothrow.html`, crash
  `Telegram-2026-11-07-220651.ips`) predates the getter and died on a wild
  fake-chain address (`far=0x10371036103510d4`, `pc` in the engine), not on a
  clean "Memory limit exceeded" policy kill. The iOS widget engine reads the
  exception description through the same `qjs_take_exception_description`
  shape (per `widget_memory_limits` §7), so **installing the getter on iOS is
  the single highest-value device experiment**: if it takes the log branch,
  N1 becomes a cross-platform carrier and the Chain A payload only differs in
  engine-build constants (P/Δ), not in the primitive. This does not change the
  conservative verdict (no proven iOS carrier), but it is the cheapest unlock
  in the whole matrix and should be run before writing iOS off.
* The target geometry is per-state: the same-slab placement is achievable
  (measured: view page slot 7, scopes page slot 8, same slab) but the block
  indices move with the startup/groom state (the Sony J2-FK probe crashed at
  `scopes−896` because the scopes block was ≲6). A blind `L` sweep is unsafe
  because grid points hit arena **block headers** (7% of points), which can
  corrupt the free list.
* Payload: gate 1,270 zlib + runtime-built AB stage ≈1.8 KB (measured builder
  723 + harness ≈1.1 KB) + endgame ≈1.5–2.0 KB (the unminified PoC is 2,203
  zlib) → ≈3.3–3.9 KB estimated, likely inside 4,096 but not measured. The
  text AB stage (3,094) does not fit with the endgame.

### 3.3 Host experiment that validates the missing link

**First PoC (next): a *bounded, header-safe* layout calibration.** The safe
probe idea from `widget_memory_limits_20261108` §10.3 can be extended:
1. Fill the class-112 page with alternating `ArrayBuffer(72)` + `BigInt64Array`
   views, all live, and likewise the class-128 page (canary strings).
2. Run the 4→6 grow in a throwaway eval (no OOM) to learn the *scopes page*
   (`n1_dump_slot` host-only; on device, the level −1/−2 read-back probe from
   §10.3/§11 identifies the block before the scopes safely).
3. The only unsafe dimension left is the slot difference to the class-112 page.
   Test whether a `L` computed for the *wrong* slot can be made harmless by
   ensuring the 4-byte store always lands in *user data*: align the class-112
   page so that the candidate targets for all 16 slot differences are in data
   blocks (the grid condition `i1+i2 ≡ 2Δs mod 5` leaves one residue per
   slot; a 16-point sweep can be pre-filtered by checking the target mod 112
   against the 8-byte header window in JS — the payload knows `i2` but not the
   slot, so this is the open question).
4. If a header-safe sweep exists, the payload is device-portable; if not, the
   chain is per-device (Sony/Pixel) and must be tuned like the leak gate.

The lab harness (`lab/universal_chain/harness/uc.c`, `run/uc`) already has
`__corrupt`, `__voff`, `__dptr`, `__sym`, and runs the full endgame. Adding
`__n1write(L,value)` on top of the n1_fork trace build (which exports
`n1_dump_slot` and the `N1SCOPES` address) closes the loop: write at the exact
`scopes+20L+4`, observe the canary view's `.length`, run `poc_count_rce.js`.

---

## 4. Chain B — parser route 2 + self-locating stage (the only non-OOM 0day write)

**Status: host-proven primitive and full chain (5/5 at 8 MiB, 5/5 under a 3 MB
preload); device geometry and iOS unproven; 4,001/4,079 zlib.**

### 4.1 What it gives

* `b` = runtime-created anonymous function expression with `argc=1 varc=6 cvc=0`
  → `JSFunctionBytecode` fsize 313 → arena class 352 (tag 0).
* The OOB read at `b->vardefs + 1,310,828` lands in a sprayed class-512
  `ArrayBuffer` data block 20 slabs above `b` (host: `1310720 = 20×65536`,
  same slot index, offset 50020, phase 868), reading a fake `JSVarDef` pair
  (`var_name=4`, `scope_level=5`, `scope_next=4/65535`, `flags=4`).
* The parser then writes the closure vars into the class-64 page next to the
  closure array, setting `T[599].byte_length = 327,744` → a 327 KB
  `Uint8Array` window; the c2560s endgame (tag-preserving `endG9s` variant)
  consumes it: full chain + 162-byte proof.
* Non-OOM: the spray is ~4.3 MB charged (no symbols) or 5.86 MB
  (symbol-safe); 300 ms quota not exceeded (host 9.5 ms primitive, 51–75 ms
  full chain).

Tag domain: `b` (class 352) and the target (class-512 data) are arena tag 0;
the closure/victim class-64 page is arena; the only tagged accesses are
`realm`/`rt` in the endgame, done with full high words (`endG9s`). Same-tag
under both readings of MTE.

### 4.2 Why it is the only cross-platform candidate

The bug is in quickjs-ng 0.17.0 (present in upstream `e22ce4d`), not a Telegram
fork patch: the Pixel release 72801, beta 72889/72929 and the iOS engine are the
same generation. One payload/bug could therefore serve both platforms, unlike
N1 (OOM) and v7 (n-day). The endgame differs per platform: Android
`rt->mf.js_free`, iOS the v7-style ROP/PAC problem (the iOS #1827 chain already
proves the primitive and exfil; full stock RCE is PAC-blocked).

### 4.3 Missing link and host experiment

The missing link is **geometry portability**, not a memory primitive:
1. 20 contiguous 64 KiB slabs above `b` (host mmap burst; device unmeasured).
2. The target page must be our class-512 data (same slot as `b`'s page); the
   host N2 sweep hits for N2 = 385/400/405/415/425 and misses/crashes for
   380/390/395/410/420/430. A per-device N2 cannot be in a 4,096-zlib payload
   with 17 bytes of margin.
3. Phase `t = 164 + 352k (mod 20)`; 5-phase sweep covers multiples of 4; a
   crossing case (k=4) needs another N2.

Host experiment to validate a universal stage: make the target **self-locating**
and *slot-agnostic*:
* spray enough class-512 pages that **every slot of every slab in the +20
  window is class-512 data** (16 pages/slab × 7 blocks × 488 B ≈ 55 KB per
  slab; a few hundred KB covers tens of slabs);
* make the fake record valid for all 20-byte phases (or keep the 5-phase sweep
  but only inside the same eval);
* test the *same* payload across a sweep of N2 values (the host build can
  sweep N2 without changing the payload) and across an allocation-order
  perturbation that simulates a different device baseline;
* measure zlib of the resulting stage (must stay ≤ ~2.2 KB to leave room for
  the endgame) and the charged heap at 6 MiB (must be < 6 MiB with the app
  baseline).
If the same stage hits for all N2 in the sweep, the geometry link is closed on
the host; the device run is then the orchestrator's call (the parser is
non-destructive on a miss only if the symbol-safe variant is used).

iOS-specific check (host-only, from the binary if available): confirm the iOS
Telegram build contains `JS_ARENA_SLABS` (fork commit 27787d3, 2026-10-12). If
the iOS build predates it, route 2 cannot exist there; the shipped c2560s
(Scudo) is MTE-cross-tag and iOS page size 16 KiB changes the slot math.

---

## 5. Chain C — F1 read as a leak/calibration primitive (no endgame)

F1 (`js_regexp_exec` snapshots `re->bytecode`, the `lastIndex` prototype setter
recompiles, `lre_get_groupnames` then reads the freed buffer) is a genuine
**upstream 0day**, same-tag, non-OOM, and engine-shared. It gives:

* a forward C-string read from a reclaimed class-480/512 arena block, atomized
  into `m.groups` keys; the read starts at `bc + 8 + fake_bytecode_len`
  (`flags & NAMED_GROUPS`), so it can be aimed anywhere forward in the arena;
* pointer leaks up to the first NUL: a 48-bit heap pointer yields 6 bytes
  (measured `groups=[xV4…]`, `klen=6`); enough to reconstruct a canonical VA
  on Android/arm64 (byte 6 is 0; the MTE tag is byte 7 and is not needed for
  the low 48 bits).

It is **read-only**: the stale use after the setter is only
`lre_get_groupnames`/`JS_NewAtom`; `lre_exec` runs on the real bytecode before
the callback. There is no write and no length corruption. Its value is as a
*calibration/leak* for a write chain: pointer leaks, slab-base recovery, and
eviction control (the fork cache hash is reproducible in JS, so the victim's
slot can be evicted deterministically instead of the current 24-pattern
probabilistic sweep).

Measured today: F1's reclaim requires the cache eviction; the eviction is
controllable, and the v7 pattern pair collides deterministically (slot 0).

Host experiment to make F1 useful: place the reclaim block so the leaked
forward region contains a `JSObject` of a known allocation; verify the 6-byte
pointer reconstruction against the instrumented address; then use the leaked
slab base to compute a N1 `L` (Chain A) without the same-slab groom. This is
the "leak + small write" combination the task asked to consider; the write
still has to come from N1 (Android) or the parser (both), so F1 alone does not
change the platform verdict.

The specific "F1 leak + C2 store + a length target" combination is closed:
C2's store lands at a class-288 neighbour **+48/188/192**, while a typed-array
count is at `JSObject+64` in a class-112 block; the class cannot match, and the
second-order `fd->vars` index is a few JSValue slots past a frame, not an
address (§2). The "N1 + a leak/64-bit write for iOS" combination is also not
the unlock: N1 on iOS is blocked by the OOM gate (getter unverified), not by a
missing leak; a leak would only remove the layout guess, and the layout is not
what kills the iOS run (the fake-chain read does).

---

## 6. n-day vs 0day accounting

| item | status | why |
|---|---|---|
| v7 / #1827 | **n-day** | fixed upstream `3d5cb14` / cherry-pick `2b62af1`, missing in app snapshot `2dfeee3e` |
| N1 | **0day** | unreported; device gate/getter/job proven; no full carrier |
| F1 | **0day** | unreported; upstream `js_regexp_exec` still has the order (verified in `origin/master`) |
| Parser `ARG_SCOPE_END` | **0day** | upstream 0.17.0; route 2 host-proven |
| C1/C2/MB-01/MB-02/FR/LT | 0day (DoS/no endgame) | per inventory |
| v7 endgame technique (same-view BigInt, ELF resolver, tag-preserving writes) | technique | usable on top of any qualifying 0day |

The user's requirement is a **0day bug**; the v7 payload is the technique
reference and the MTE-on proof, not the bug. Chain A's bug is N1 (0day) with
the v7 technique; Chain B's bug is the parser (0day).

---

## 7. Evidence produced today (host-only)

All under `lab/universal_chain/`:

1. **Endgame from a single count corruption** — `run/poc_count_rce.js`,
   `evidence/count_endgame_8m.log`, `evidence/proof_count_endgame.txt`:
   ```
   PIVOT j=864 cls=29 D=0x7f...4768
   RT=0x5636...e2a0 JSFREE=0x5636...9b00
   LIBCFREE=0x7f9b...dfc0 RESOLVED_SYSTEM=0x7f9b...e090 EXPECT=0x7f9b...e090
   HOOKED
   AFTER
   rc=0
   ```
   and the proof file contains the `id` output. The count was set by the lab
   helper `__corrupt(view, 8192)` (the N1-shaped 4-byte store at `JSObject+64`);
   everything after (`scan → pivot → ctx/rt → ELF resolver → rt hook → system`)
   is the production v7 code path.
   A second run with the exact **N1 AB-stage value 1,024** also reaches
   `system()` — `run/poc_count_rce_1024.js`, `evidence/count_endgame_1024.log`,
   `evidence/proof_count_endgame_1024.txt`: `PIVOT j=928 cls=29`,
   `RESOLVED=EXPECT`, `HOOKED`, `AFTER`, proof = `id` output. This is the
   Chain A value; the window needed is `k/8 = 928` elements (7.4 KB).
2. **Same-slab layout** — `run/layout_scopes3.js`,
   `evidence/layout_same_slab.log`: a class-112 page (victim data idx 31, view
   JSObjects idx 32/33) and the parser's class-128 `scopes` page (idx 9) land in
   the **same 64 KiB slab** (slots 7 and 8), with the grow page in the same
   slab. This is the measured basis for the `L` arithmetic (`L=-93` for
   i1=11,i2=32, slot difference 1). Reproduced twice (independent runs).
3. **Cache-slot collision** — `run/cache_slot.js` vs the engine trace
   `evidence/cache_slot_trace.log`: the v7 old pattern and `"x"` both hash to
   slot 0 with flags=1; the trace shows `COMPILE slot=0`, `COMPILE slot=0`,
   `CACHE_EVICT`, `BYTECODE_STRING_FREE`. The JS hash reproduces the engine
   (`flags`, `h*263+char`, `^len*0x61c88647`, `*0x9e3779b1>>>28`).
4. **Harness** — `harness/uc.c` + `run/uc` (fork 2dfeee3e, 6/8 MiB,
   `__corrupt`/`__dptr`/`__voff`/`__cls`/`__sym`); `harness/slots.c` + `run/slots`
   (n1_fork trace build, `slot(obj)`/`abdata(ab)`).

No device, Frida, bot or network was used. No shared note or inventory file was
edited.

---

## 8. Ranking and recommendation

| rank | chain | platform | 0day | works today? | blocker |
|---:|---|---|---|---|---|
| 1 | **A: N1 count → v7 endgame** | Android MTE-on (Pixel/Sony); **iOS reopenable** if the getter takes | **yes** (N1) | endgame proven; write/gate tuning open | same-class-page layout + safe `L`; OOM getter (Android-proven, iOS unverified) |
| 2 | **B: parser route 2 + self-locating stage** | Android + iOS (same bug) | **yes** (parser) | primitive/full chain host-proven; same-payload not | slab contiguity/slot/phase; iOS endgame/PAC; 4,096 margin |
| 3 | C: F1 leak + A/B | Android (+ leak shared) | yes (F1) | read primitive only | needs the write from A/B; no endgame of its own |
| — | v7 as shipped | Android MTE-on + iOS primitive | **no** (n-day) | yes | n-day; not countable |

**Cheapest cross-platform unlock:** re-run the iOS N1 safe probe **with the
getter** (`InternalError.prototype.name` + a refused allocation) before any
more N1 work. The existing iOS crash predates the getter and is a wild
fake-chain fault, not a clean policy kill; the iOS engine reads the exception
description through the same shape as Android. If the getter logs instead of
killing, Chain A is same-*bug* cross-platform (payload differs only in P/Δ),
and the user's requirement is met at the primitive/RCE level on both platforms
(the iOS endgame remains the v7/PAC problem, i.e. arbitrary RW + exfil, full
code execution only if a PAC bypass exists). This experiment is non-destructive
if it uses the existing safe probe body (no fake chain, no write) — the getter
only changes the post-script decision.

**Single most promising missing primitive:** a **portable non-OOM 4-byte
length/count write in the tag-0 arena**. The cheapest route is to finish the
parser route-2 stage's self-locating target (non-OOM, same bug on iOS); the
cheapest *new* bug would be any second non-OOM stale-pointer store in the
RegExp/string/typed-array engine (the fork's cache and the `js_regexp_exec`
snapshot order show this family is still fertile — F1 is the read half of a
potential write sibling).

**First host PoC to build next:** the N1 `__n1write(L,value)` calibration on
the n1_fork trace build described in §3.3 (bounded/header-safe `L` sweep over
the same-slab class-112/class-128 pages, canary views, then
`poc_count_rce.js`). Success criterion: `canary.length === 1024` and a proof
file, with no write into a block header, at 6 and 8 MiB with one payload.

Then, in parallel: the parser route-2 N2-invariance test (§4.3) — the only
route that can satisfy the "same payload on iOS" requirement.

---

## 9. Honest negatives / limits

* Chain A's **write has not been produced by N1** in this lab; the endgame was
  driven by a lab helper that performs exactly the N1-shaped store. The gate
  and getter are device-proven for the leak source, not for the AB source; the
  AB host gate crashed at ~6.19 MB before the gate in the earlier campaign and
  is still untuned.
* The same-slab layout is **state-dependent**: the n1_fork trace shows the
  desired slots, but the `uc` build's class-112 free-list state puts the views
  at −3.2 MB or +127 KB for different burst sizes. A payload must control the
  class-112 free list, not just allocate a burst. This is the same class of
  problem as the Sony J2-FK crash and is not solved.
* The parser route 2 is **host-only**: no device run, no proof that the 20-slab
  contiguity holds on Android 17, no iOS binary verification of
  `JS_ARENA_SLABS`, and the 4,079-zlib symbol-safe variant has 17 bytes of
  margin.
* F1 is read-only; the leaked pointer bytes stop at the first NUL (6 bytes on
  arm64), and the atomization is a C-string walk (a long leak can cross into an
  unmapped page and crash the widget; the read is not bounded by the engine).
* The v7 cache-collision fact cuts both ways: it explains why the n-day works
  on the shipped fork, and it means any new carrier built on the same stale
  bytecode must either collide or evict; a "port the v7 endgame" claim that
  ignores the cache is incomplete.
* MTE-on for Chain A is a **design argument** (all touched pages tag 0; the
  endgame preserves tags) plus the v7 Pixel proof; it is not a new device
  measurement.

---

## 10. Files

```
notes/universal_chain_20261108.md                     this note
notes/LEMMALOG_FACTS_universal_chain_20261108.txt     facts for the orchestrator
lab/universal_chain/src/                              fork 2dfeee3e + UC_* lab helpers
lab/universal_chain/harness/uc.c                      endgame harness (6/8 MiB)
lab/universal_chain/harness/slots.c                   n1_fork slot probe
lab/universal_chain/run/poc_count_rce.js              count corruption -> system() proof
lab/universal_chain/run/poc_count_probe.js            scan/pivot/ctx probe
lab/universal_chain/run/cache_slot.js                 JS reimplementation of the cache hash
lab/universal_chain/run/layout_scopes3.js             same-slab class-112/class-128 trace
lab/universal_chain/run/groom_slots2.js               page/slot groom probe
lab/universal_chain/evidence/                         logs + proof
```
