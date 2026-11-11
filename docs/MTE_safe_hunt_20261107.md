# MTE-safe hunt — v7, iOS 27, Android MTE evidence and the 18-bug matrix

Date: 2026-11-07 (host-only; no device, no bot, no network).
Scope: resolve whether the old **#1827 class-64 v7** widget payload ever ran
with MTE/MIE enforced for its process, extract its real memory-tag profile, and
use the result to rank the lab's 0day for MTE-on targets (Samsung S24/S25,
Pixel with forced MTE, iPhone 17 with MIE).

All file references are relative to `telegramandroidwidget/` unless absolute.

---

## 0. Verdict (short)

1. **v7 MTE-on = proven.** The Pixel 9 had **MTE enabled from Developer
   Options** (device-wide, independent of `android:memtagMode`). The v7 full
   C2 session **`tg-10290-Pixel_9` (uid 10290, `org.telegram.messenger`,
   2026-11-05)** ran under that configuration and **did not crash**. This is
   the reference datum: a widget RCE that is MTE-safe. The earlier
   `mte_test_20261101` "MTE remains untested" is **superseded for v7**.
   The 2026-11-02 debug-package v3 run (44 `mt` mappings) is corroborating.
2. **The v7 pattern is same-view / same-allocation-slot.** The freed regexp
   bytecode is reclaimed in the same QuickJS arena class (480/512); the fake
   bytecode writes the victim `JSArrayBuffer` structs; and the BigInt view
   writes its **own** `u.ptr` slot at the fixed positive offset
   `W[(k+56)/8]` — a same-view write with no cross-allocation pointer
   arithmetic and no tag change. Tagged `rt`/`ctx` are read/written as full
   64-bit pointers (tags preserved). That is the MTE-safe model proven on the
   Pixel 9 and to be ported to the new 0day.
3. **The regexp engine reads the freed buffer with a stale pointer**
   (`JS_RegExpDelete`, quickjs.c:50775; snapshot :50798, coercion :50803,
   exec :50822). This is part of the proven pattern: the freed/reclaimed
   buffer is an arena block (measured: bytecode len 384, capacity 480,
   usable 472, class 480, slab=1), tag 0, so the stale read is not
   tag-checked. The same property is what makes N1 tag-safe.
4. **The parser 0day (`ARG_SCOPE_END`) is the one RCE-capable 0day that is not
   MTE-safe**: `b->vardefs` is a tagged Scudo primary pointer and the access
   is a 1.31 MB linear cross-allocation read/write. Do not conflate it with
   v7 or with N1.
5. **N1 is the new-0day candidate with the v7 profile.** Its fake
   `JSVarScope` is in a controlled arena buffer, and the `add_scope_var` write
   targets a **real** `JSArrayBuffer` struct in the same tag domain (arena,
   tag 0). Strictly, the write is cross-*block* but never cross-*tag*. A
   fake-ABUF-inside-the-buffer variant with a JSValue pointing at it is **not
   reachable with N1's 32-bit small-int write** (see §7.2): it needs a 64-bit
   pointer write or a heap leak + pointer write, i.e. a different primitive.
6. **iOS 27 is the cross-platform reference for the primitive/pattern.** The
   #1827/v7 same-view BigInt primitive was proven on stock Telegram 13.2
   (36535); the full stock RCE (shell/C2) remained blocked by PAC (the JSC
   `mov sp,x0;ret` gadget is absent; only `retab`), and the 47 MB DB was
   pulled via CoreDevice. The pattern to port is the same-view one. MIE-on is
   not claimed for iOS 27 (the stock binary has no
   `com.apple.security.cs.checked_allocations`).

---

## 1. Method and evidence inventory

Inputs read (all on disk):

| evidence | what it shows |
|---|---|
| `poc/loader_v7_plain_text_cec.html` (SHA-256 `22c96d824e814f1b7de8…`) | v7 payload, 7,460 raw / 3,056 zlib9 |
| `notes/v7_plain_text_batch.md` | v7 reduction history, proofs 5467-5494 |
| `notes/v7_plain_nokeypad.md` | v7 on Sony, C2 `tg-10357-XQ-BT52`, proof 5460 |
| `notes/v7_auto_plain_release.md` | v7-release variant, not device-tested in that exact form |
| `notes/1865_72879_c2.md` | #1865 C2 reference (different bug; not v7) |
| `notes/pixel_android17_botapi_c2_20261105.md` | Pixel 9 release C2 `tg-10290-Pixel_9`, v7 cec |
| `evidence/c2_pixel_android17_proof.log` | C2 session, uid 10290, `org.telegram.messenger` paths, **no MTE data** |
| `notes/pixel_debug_build.md` | `.dbg` package + `setprop persist.arm64.memtag.app.org.telegram.messenger.beta.dbg on` |
| `evidence/evidence_20261102/pixel_mte/` | MTE-on run: `app_smaps_mte.txt`, `mte_mapping_analysis.txt`, proof, payloads |
| `evidence/evidence_20261102/pixel_mte/pixel_payload.html` | **v3 universal** (JS_DEF_FREE `0x173e36c`, FREE_GOT `0x1964cc0`, SYSTEM_DELTA `0x41fe0`, `.dbg` proof path) |
| `<HOME>/ailocal/Telegram/notes/ios27_iphone17_test.md` | iOS 27 primitive proven, 2026-11-05 |
| `<HOME>/ailocal/Telegram/notes/ios27_exploit_status_20261106.md` | iOS 27 `open/read/write` exfil success, 2026-11-06 |
| `lab/ios27_20261106/c2_console.log`, `exfil_*.bin` | 3,039-byte file exfil (lockState + SQLite header), hashes |
| `lab/ios27_20261106/ios17_rw3.html` | iOS 27 payload (same #1827 class-64 primitive) |
| `ios_sideload/Telegram_13.2.0_decrypted.ipa` | original App Store entitlements (no MIE keys) |
| `Android_Beta_13.2.0_(72789).apk`, `apks/Android_Beta_13.2.1_(72889).apk` | manifests: `memtagMode` 0 occurrences |
| `lab/qjs_fork_audit/n1_hookfree/src` (app snapshot `2dfeee3e`) | allocator/parser source used for the host measurements |

Host measurements performed for this note (new):

* instrumented `2dfeee3e` (`/tmp/opencode/mte_lab`) with
  `n1_in_slab(rt, p)` (walks `rt->arena_state.slab_list`) and prints in
  `push_scope`/`pop_scope`/`add_scope_var` and in `js_compile_regexp`;
* measured the v7 regexp bytecode allocation and the N1 scopes/stores.

---

## 2. What MTE actually checks (the model used below)

### 2.1 Android / Scudo

From the AOSP Scudo MTE design (public) and the measurements here:

* Scudo tags **primary** chunks (size < 0x10000 = 64 KiB). Secondary chunks
  (≥ 64 KiB, mmap) are a separate path: historically untagged, but on the
  Android 17 smaps here **11 of 106 `[anon:scudo:secondary]` mappings carry
  `mt`** (each an 8 KiB `PROT_MTE` prefix followed by the untagged data
  mapping). Do not assume "≥ 64 KiB ⇒ untagged" without checking the device.
* A fresh chunk gets a random tag; a freed chunk is **retagged with a
  different tag** on free (UAF detection), then keeps its tag when reused.
* `M_MEMTAG_TUNING_BUFFER_OVERFLOW` (the default on Android) enables
  **odd/even tags**: adjacent chunks differ in tag parity, so a linear
  overflow is caught with high probability (not certainty — 4-bit tags).
* **Chunk headers are tag 0** (Scudo metadata is not tagged) and act as a
  red zone between chunks.
* Tag checks are per 16-byte granule; an access inside the allocation (or in
  memory that was never `PROT_MTE`) is not checked.

Consequence: an access is safe iff (a) it stays inside the same tagged
allocation, or (b) the target mapping is not `PROT_MTE` **and** the pointer's
tag is 0. A tagged pointer into an untagged granule faults just like the
reverse. **Correction 2026-11-08:** the last sentence is too strong; tag
checks are performed only on `PROT_MTE` pages (see the status section at the
end of this note). The safe condition is: target not `PROT_MTE` (any tag is
ignored by TBI), or target `PROT_MTE` with the matching allocation tag. The
c2560s failure is the second case with a different Scudo chunk tag.

### 2.2 Apple / MIE

Apple's published model: MIE = secure typed allocators + **EMTE in synchronous
mode** + tag-confidentiality. Default-on for the kernel, 70+ system daemons
and Safari/WebKit. **Third-party apps opt in** via Enhanced Security
("Hardware Memory Tagging"), which adds
`com.apple.security.cs.checked_allocations` (plus `enhanced_security`,
`hardened_process`, `hardened_heap`). A non-opted-in app gets the normal
allocator, no tag checks.

### 2.3 QuickJS arena (the important part, both platforms)

The Telegram QuickJS fork (`2dfeee3e`) allocates **all blocks ≤ 512 B**
(`total_size = size + 8` header) from **64 KiB slabs obtained with a direct
`mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, …)`**
(`JS_ARENA_SLABS`, `arena_slab_take`, quickjs.c:1881). That mapping is not
`PROT_MTE` and is not Scudo-managed: **tag 0, never checked**. This covers,
among others:

* `JSObject`, `JSString` (≤ ~487 B), `JSArrayBuffer` struct (~64 B),
  `ArrayBuffer` data ≤ 512 B, `JSVarScope` arrays ≤ 512 B (120/180 B in N1),
  typed-array views, RegExp bytecode ≤ ~504 B, capture arrays, JSVarRef arrays
  for small functions.

Blocks > 512 B go to `js_malloc` → Scudo primary (tagged, < 64 KiB) or
secondary (untagged, ≥ 64 KiB). This is why `JSFunctionBytecode` (2.5-4 KiB),
`JSFunctionDef`, `cpool`, big `vars` arrays and large regexp bytecode are
tagged, while the exploit's fake objects are not.

### 2.4 Measured MTE coverage on the Pixel 9 debug run

`evidence/evidence_20261102/pixel_mte/app_smaps_mte.txt` (4,534 mappings):

* 44 mappings carry `mt` (`PROT_MTE`): **33 `[anon:scudo:primary]` +
  11 `[anon:scudo:secondary]`**.
* 66 `[anon:scudo:primary]` mappings total, i.e. **33 tagged / 33 untagged**;
  each size-class region has one tagged ~256 KiB mapping and one larger
  **untagged** growth mapping (`primary` 262,144 + a bigger sibling).
* `mte_mapping_analysis.txt` resolves the exploit's own addresses:

```
D(arena)  0x718a990538 rw-p  mt=False
shape     0x718e8879f8 rw-p  mt=False
proto     0x718f74a268 rw-p  mt=False
ctx       0x6fca5b7c78 [anon:scudo:primary] mt=False
rt        0x6fea5b8180 [anon:scudo:primary] mt=False
js_free   0x6e4207636c r-xp  mt=False
system    0x71b16e76e0 r-xp  mt=False
```

i.e. **MTE was enabled for the process, but every address the chain touched
was in a non-`PROT_MTE` mapping**. That is the whole explanation of "it worked
with MTE on".

---

## 3. v7 primitive — exact mechanics and MTE profile

### 3.1 Allocation path of the freed object

`JS_RegExpDelete` (quickjs.c:50775) does, in this order:

```c
re_bytecode = str8(re->bytecode);      /* snapshot of the raw bytecode buffer */
re_flags   = lre_get_flags(re_bytecode);
...
val = JS_GetProperty(ctx, this_val, JS_ATOM_lastIndex);   /* attacker valueOf */
JS_ToLengthFree(ctx, &last_index, val);                   /* re.compile() here */
...
ret = lre_exec(capture, re_bytecode, ...);                /* STALE pointer */
```

`re->bytecode` is a `JSString` of kind `JS_STRING_KIND_INDIRECT`
(`js_compile_regexp`, quickjs.c:50135-50140): a small wrapper whose data is an
8-byte pointer to the raw `lre_compile()` buffer, allocated through
`lre_realloc → js_realloc_rt`. On recompile, `JS_FreeValue(re->bytecode)`
frees **the raw buffer** (`js_free_string0`, `JS_STRING_KIND_INDIRECT` →
`js_free_rt(rt, strv(str))`) and the wrapper.

The stale read is therefore of the **raw bytecode buffer**, and the v7
reclaims it with `new Uint8Array(454)` / `new Uint8Array(480)` (data buffers
allocated by `js_mallocz`).

### 3.2 Measured size/class (new host measurement, app snapshot)

Pattern: `"abcdefghij".repeat(12)` (120 chars), flags `g`:

```
RE_BYTECODE len=384 buf=0x7f205786b218 slab=1 usable=472 patlen=120
```

* raw bytecode length: **384 B**; the `lre_compile` DynBuf **capacity is 480**
  (arena block usable **472** → **class 480**);
* the freed `js_realloc_rt` block is that class-480 arena block;
* **`slab=1`** → inside a 64 KiB QuickJS arena `mmap` (tag 0, no `PROT_MTE`).

The two reclaim buffers cover the two possible capacities:
`454 + 8 = 462` → class 480 (matches the measured usable 472);
`480 + 8 = 488` → class 512 (covers the alternate capacity).
Both are arena blocks, i.e. **the UAF read and the reclaim are tag-0 → tag-0**.

### 3.3 The fake bytecode and the class-64 write

`mkbuf()` builds `[cc=2][rc=3]` followed by `REOP_set_i32` instructions:
`pc[0] = 8j-4`, value `0x7A000000 + 8*74565 + 8j` (~2 GB). `REOP_set_i32`
writes at `capture + 8*(2*cc + pc[0]) = capture + 64j`, i.e. into the
`ArrayBuffer(72)` **structs** (class 64 arena blocks) that follow the capture
array. `byte_length` becomes ~2 GB; `new Uint8Array(victim)` / BigInt views
give a huge forward window.

* Domain: capture array (class 64), victim structs (class 64), victim data
  (72 B) → all arena, tag 0.
* The write is cross-block inside the same 4 KiB arena page/slab; it does not
  cross a tag boundary because no block has a tag.

### 3.4 The BigInt view / "same-view" write

Two views over the same victim: `R` (BigInt64Array, class 29) and `W`
(BigUint64Array, class 30), both with data pointer `D` (the victim's 72-byte
data block). The primitive:

```js
setR(A) { W[(k+56)/8] = A }              /* rewrite R's own u.ptr */
rd64(A) { if (D <= A and aligned) W[(A-D)/8]; else setR(A); R[0] }
wr64(A,v) { ... same ... }
```

* `k` is the offset where `R`'s JSObject was found in the 2 GB window;
  `(k+56)/8` is a **small positive index**, always the same slot.
* The store writes `A` (a full 64-bit value) into `R`'s JSObject `u.ptr`.
  It is **same-view**, not same-allocation: `R`'s JSObject is in a different
  arena block than `D` (same 64 KiB slab or another one). It is safe because
  both are tag 0.
* `rd64` returns `BigInt.asUintN(64, …)`: **tag bits are preserved** in
  `D`, `shape`, `proto`, `ctx`, `rt`. The tagged structures (`ctx`/`rt`,
  Scudo primary) are therefore accessed with their own tags.
* The only deliberate tag strip is `cmdAddr = D & 0x00ff_ffff_ffff_ffff`
  before writing `rt->malloc_state.opaque`. `D` is the **arena** data block
  (tag 0), so the mask loses nothing; `system(cmdAddr)` receives a tag-0
  pointer to tag-0 memory.

### 3.5 MTE profile / what would break it

| step | memory | tag check? |
|---|---|---|
| freed regexp bytecode (len 384, capacity 480) + reclaim (454/480) | arena slab | **no (tag 0)** |
| fake `set_i32` into victim AB structs | arena (class 64) | no |
| forward scan/read through the 2 GB view (LIM 8192) | arena slabs | no (unmapped gaps → plain SEGV, not MTE) |
| `W[(k+56)/8] = A` re-point | arena (JSObject in a different block) | no |
| `rd64`/`wr64` of `ctx`/`rt` | Scudo primary (tagged or not) | **yes, but the pointer tag is preserved** |
| `rt+16 = system`, `rt+64 = cmd` | Scudo primary / arena pointer | tag preserved / tag 0 |
| `system(cmd)` | text + arena | no |

Failure modes under a *fully* tagged heap:

1. If the freed bytecode buffer were > ~504 B usable, it would be a Scudo
   primary chunk (tagged); the free retags it; the stale `lre_exec` read
   faults (`SEGV_MTESERR` sync / `SEGV_MTEAERR` async). **The 120-char
   pattern is deliberately (or luckily) below this threshold.**
2. If a gadget stripped the tag of `rt`/`ctx` and then dereferenced it, the
   access would fault. v7 does not.
3. If `cmdAddr` pointed to tagged memory, the masked pointer would fault.
   It points to the arena.

So: **v7 is MTE-compatible for this engine, but its safety is inherited from
the QuickJS arena being outside the tagged allocator.** It is not a
"same-allocation" proof and it does not generalize to a bug whose corrupted
buffer is a Scudo primary allocation.

---

## 4. Android — the v7 MTE-on reference (authoritative)

The Pixel 9 had **MTE enabled from Developer Options**. That setting is
device-wide and applies to every app process, independent of the app's
`android:memtagMode`. It is the configuration of the reference run.

### 4.1 v7 on the Pixel 9 release app (2026-11-05) — MTE-on, full C2

* Session `tg-10290-Pixel_9`, `uid=10290(u0_a290)` =
  `org.telegram.messenger` (release), paths
  `/data/user/0/org.telegram.messenger/…`
  (`evidence/c2_pixel_android17_proof.log`).
* Payload: `poc/loader_v7_plain_text_cec.html`, SHA-256
  `22c96d824e814f1b…`, 3,056 B zlib9, delivered by Bot API `sendWidget`
  (message 5511); proofs 5512/5513; `[exec rc=0 1.59s]`.
* MTE state: **on**, from Developer Options. The absence of
  `android:memtagMode` in the manifest (0 occurrences in 72789/72889) is
  **not** the controlling factor: the Developer Options setting forces MTE
  for the process.
* **Result: full C2, no crash ⇒ v7 is MTE-safe, proven on device.**

### 4.2 Corroborating MTE-on run (2026-11-02, `.dbg` package)

* `org.telegram.messenger.beta.dbg` (debug rebuild of 72799, UID 10178),
  `setprop persist.arm64.memtag.app.org.telegram.messenger.beta.dbg on`;
  smaps shows **44 `mt` mappings** (33 primary + 11 secondary).
* Payload: **v3 universal** (`JS_DEF_FREE 0x173e36c`, `FREE_GOT 0x1964cc0`,
  `SYSTEM_DELTA 0x41fe0`, `.dbg` proof path) — the direct ancestor of v7.
* Proof `uid=10178(u0_a178) …`, `rce_date.txt` = 2026-11-02 13:42:51 UTC.
* Per-address analysis: every touched mapping `mt=False` (§2.4). This is
  consistent with the v7 proof: the chain is tag-safe because its data domain
  (the QuickJS arena) is untagged, not because the allocator was off.

### 4.3 Non-MTE baselines (context only)

* Sony XQ-BT52: Snapdragon 695 / Cortex-A78+A55, **ARMv8.2, no MTE**; the
  `0x174d9ac` crash is `SEGV_ACCERR` on a `PROT_NONE` page, not
  `SEGV_MTESERR/MTEAERR`. The Sony proofs validate the chain shape, not MTE.
* `mte_test_20261101` (QEMU user-mode) is invalid as an emulation datum, and
  its "MTE remains untested" conclusion is **superseded for v7** by the
  Pixel 9 Developer Options run.

---

## 5. iOS 27 — resolved

### 5.1 What actually ran

* Device: iPhone 17 (`iPhone18,5`), iOS 27.0 build 24A437, stock Telegram
  13.2 (36535), `ph.telegra.Telegraph`, account <CHAT_ID>.
* 2026-11-05 (`ios27_iphone17_test.md`): widget delivery + `#1827` primitive
  proven on the stock app (`R_OK F=0x1934fc49c S=0x13115e6f0 U=0x12bdf7808`,
  RAB layout, rt layout). The allocator-hook `opendir` exfil failed; the JSC
  `mov sp,x0;ret` pivot is absent (only `retab`) — so the 6s chain could not
  be reused.
* 2026-11-06 (`ios27_exploit_status_20261106.md`, `lab/ios27_20261106/`):
  the ROP was re-armed with app/libc code and the payload **`ios17_rw3.html`
  (9,201 B) executes `open/read/write/connect`**; the C2 listener received
  **3,039-byte file contents**, including
  `lockState.json` (sha256 `641ebc34…`) and the SQLite header of
  `accounts-metadata/db/db_sqlite` (sha256 `72a90d91…`).
  `lab/ios27_20261106/c2_console.log` shows 24 CONN, the last three with
  3,039 bytes each.
* The **full 47,534,080-byte DB** was pulled via the **CoreDevice file
  service** from the *sideload* app (`ios17_session_c2.md`), not by the
  widget. So: "full DB = CoreDevice" is true; "the widget did nothing" is
  false — it performed a real open/read/write exfil on the stock app.

### 5.2 MIE status on iOS 27

* Apple policy: MIE default-on for kernel/70+ system processes/Safari;
  third-party apps must opt in (Enhanced Security → Hardware Memory Tagging)
  and get `com.apple.security.cs.checked_allocations`.
* Entitlements of the decrypted stock Telegram 13.2 binary
  (`ios_sideload/Telegram_13.2.0_decrypted.ipa`, `Payload/Telegram.app/Telegram`):
  `application-identifier`, `aps-environment`, iCloud/CarPlay/Siri/etc.
  **No `com.apple.security.cs.checked_allocations`, no
  `com.apple.security.enhanced_security`, no `hardened_process`,
  no `hardened_heap`.**
* No MIE/MTE fault artifact exists: the only iOS 27 crash on record is
  `Telegram-2026-11-06-005952.ips` = `EXC_CRASH/SIGSYS` at `sendfile+8`
  (sandbox denial, ESR `0x56000080`), not `EXC_GUARD/GUARD_EXC_MTE_SYNC_FAULT`.
  A repository-wide grep for `mteState`, `GUARD_EXC_MTE`, `MTE_SYNC_FAULT`
  returns **zero files**.
* The iPhone 6s `.ips` files in `/tmp/opencode/` (tg_crash_*.ips,
  `Telegram-2026-11-07-201751.ips`) are iPhone8,1/iOS 15.8.8 — irrelevant to
  MIE.

**Conclusion:** the stock Telegram app has no MIE entitlement, so MIE-on is
not claimed for iOS 27. The iOS 27 value is the **cross-platform same-view
primitive/pattern** (§7), not an MIE-on datum. The full stock RCE (shell/C2)
was blocked by PAC; the same-view pattern is what to port. (The QuickJS arena
is untagged on iOS as well; the tagged `rt`/`ctx` accesses preserve their
tags. That makes MIE compatibility plausible, but it is not claimed as
measured.)

---

## 6. The 18-bug MTE matrix

The lab's dedup inventory (`notes/bug_inventory_20261105.md`) has **14 root
causes**; four later unreported findings (N2, FinalizationRegistry-unregister,
the parser `ARG_SCOPE_END` 0day, litehtml table span) bring the count to
**18**. Known n-days (#1827, #1865, #1792, #1835, #1855, #1852) are not
counted.

Legend, in the MTE-on frame used for the new hunt:

* **same-tag (v7-like)** = the whole read/write domain stays in one tag
  domain: the QuickJS arena (tag 0, the v7-proven property) or a single
  allocation. No tag check can fire.
* **cross-tag** = a tagged pointer crosses a granule with a different tag
  (another allocation's tag, or a tag-0 chunk header).
* **same-tag read-only / DoS** = same tag domain but no write-RCE primitive.
* **N/A** = no memory violation (leak/DoS/policy) or unreachable.

| # | id | primitive | memory domain | MTE class | verdict |
|---:|---|---|---|---|---|
| 1 | **N1** | `push_scope` OOM → fake `JSVarScope` chain → `add_scope_var` 32-bit write at `scopes+20*level+4` | `scopes` 120/180 B, FK string 120 B, victim `JSArrayBuffer` 64 B → **all arena slabs** (host-measured `s=rs=ss=1`) | **same-tag (v7-like)** | MTE-safe by tag domain with the **real** ABUF; the fake-object variant is not reachable with the 32-bit write alone, but a class-confusion + leak extension is possible (§7.2). Blockers: 6→9 gate, FK adjacency, 20-byte grid. |
| 2 | C1 | `cpool_add` failure → 16-byte write at `cpool-16` | `cpool` 2.8 KB → Scudo primary (tagged); `cpool-16` is the **chunk header (tag 0)** | **cross-tag** | Tagged pointer → tag-0 header: sync fault. (Same root cause as round-8 cpool.) |
| 3 | C2 | `update_var_htab` mask after failed grow → 4-byte OOB write / second-order `fd->vars[*p]` | htab 256 B → arena (same-tag for the 4-byte store); `vars` for 27 vars = 548 B → Scudo (tagged) for the second-order read | **cross-tag (partial)** | The clean 4-byte store is in-slab; the useful second-order index is tag-checked. No RCE either way. |
| 4 | N2 | `get_closure_var` -1 → `var_refs[65535]` read/write at +0x7fff8 | fixed +512 KiB from a small arena array | **cross-tag** | Wild cross-slab/unmapped. |
| 5 | S1 | same `-1` in `resolve_scope_var` (compile-time) | fixed OOB read | **cross-tag** | Crash/DoS. |
| 6 | F1 | `lre_get_groupnames` UAF read | group-name buffer → arena | **same-tag (read-only)** | Heap-forward ASCII leak only; no write. |
| 7 | F2 | OOM error object → `JS_NULL` | none | **N/A** | Policy/tuning. |
| 8 | T1 | slice-string atom leaks parent | none (leak) | **N/A** | Heap exhaustion. |
| 9 | T2 | stale typed-array length (C API) | embedder read past a small AB | **cross-tag (unreachable)** | Not JS-reachable from the widget. |
| 10 | T3 | `Atomics` writes immutable AB | none | **N/A** | Semantics only. |
| 11 | F-A | `flatMap` `return()` after done | none | **N/A** | Policy/DoS. |
| 12 | V1 | `resize_properties` list_del before fallible realloc | fixed NULL write at 0x8 | **N/A** | NULL/DoS. |
| 13 | V2 | `js_function_bind` NULL finalizer read | fixed NULL | **N/A** | NULL/DoS. |
| 14 | R1 | `re_need_check_adv_and_capture_init` 2-byte OOB read | DynBuf slack inside the same arena block | **same-tag (read-only)** | In-block; no write. |
| 15 | R2 | `is_duplicate_group_name` 1-byte OOB read | same | **same-tag (read-only)** | In-block; no write. |
| 16 | FR | FinalizationRegistry `unregister` UAF | 88 B entry → arena | **same-tag (DoS)** | Deterministic crash; stale `list_del` is a NULL write; no reclaim shown. |
| 17 | **P0** | parser `ARG_SCOPE_END` → `b->vardefs[arg+65534]` (+1,310,700) | `b` (JSFunctionBytecode 2.5-4 KB) → **Scudo primary (tagged)**; target 1.31 MB away | **cross-tag** | **The only RCE-capable 0day that is not MTE-safe.** Sync fault at the first `vd->scope_level`; async `SEGV_MTEAERR`. The >64 KiB `b` lead is weak and unverified (§7.3). |
| 18 | LT | litehtml table `rowspan/colspan` negative index | `std::vector` data (C++ heap) → Scudo primary; `data-56` is the previous chunk | **cross-tag** | Tagged pointer → previous chunk: fault. Controlled increment, but MTE-blocked. |

**Reference (not counted among the 18):** #1827/v7 class-64 — **same-tag,
MTE-safe proven** on Pixel 9 with Developer Options MTE (full C2, uid 10290).
The 2026-11-02 v3 `.dbg` run (44 `mt` mappings, all touched addresses
`mt=False`) corroborates. v7 is the *pattern reference*, not a candidate (it
is an n-day).

Reading of the matrix:

* **N1 is the 0day carrier with the v7 profile**: its whole domain is the
  untagged arena, so it is same-tag; no fake object is required for MTE
  safety. The fake-object variant would need a pointer write/leak (§7.2).
* **The parser 0day is the only RCE-capable 0day that is cross-tag**; it is
  structurally MTE-unsafe, independently of stage-A tuning.
* C1/C2/N2/S1/LT end in a tagged access; they are not RCE-capable.
* F1/R1/R2/FR are same-tag but read-only or DoS.

---

## 7. MTE-safe pattern and the next 0day target

### 7.1 The proven v7 pattern (port this to the new 0day)

**P1 — same-view / same-allocation slot.** The BigInt view writes its own
`u.ptr` at the fixed positive offset `W[(k+56)/8]`; no cross-view pointer
arithmetic and no pointer taken from a foreign allocation.

**P2 — reclaim in the same arena class.** The freed regexp bytecode
(len 384, capacity 480, class 480) is reclaimed by `Uint8Array(454)`
(462 → class 480); `Uint8Array(480)` (488 → class 512) covers the alternate.
Both are arena blocks (tag 0).

**P3 — fake objects in the arena.** The fake bytecode writes the victim
`JSArrayBuffer` structs (class 64) and the capture array; all arena.

**P4 — tag-preserving tagged accesses.** `rt`/`ctx` are read/written as full
64-bit values (`BigInt.asUintN(64, …)`); only the command pointer is masked,
and it points into the arena (tag 0).

**P5 — no linear cross-allocation OOB.** v7 never performs a cross-allocation
read/write from a tagged pointer.

### 7.2 N1 — what is MTE-safe and what is missing for the fake-object variant

**What the hook-assisted chain does today.** The fake `JSVarScope` chain is
in the controlled FK string (arena); `add_scope_var` writes
`fd->scopes[level].first = idx` into the **real** `JSArrayBuffer` struct
(`byte_length` at +0). That is cross-*block* (scopes block → AB block) but
**same-tag**: both are in 64 KiB arena slabs (tag 0). The host measurement
shows `scopes/read/store` in-slab (`s=rs=ss=1`). The subsequent
`new Uint8Array(AB)` view is also arena (tag 0). **N1 is therefore MTE-safe
in the v7 sense (same tag domain), with no fake object needed.**

**Can it write a fake ABUF inside the buffer, with a JSValue referencing it?**
Not with the current write:

* `add_scope_var` writes a **32-bit small integer** (`idx` = variable index,
  ≤ ~65535) at `scopes + 20*level + 4`. It cannot write the 8-byte
  `JSObject.u.array_buffer` pointer (offset +48) or a `JSValue` payload
  (8 bytes) to point at a buffer.
* A half-write of `u.array_buffer` would produce
  `(old_high32 << 32) | idx` or `(idx << 32) | old_low32`, both outside the
  controlled arena; the fake struct would not be reachable.
* The union at +48 means a class-id confusion (`class_id` at +18) makes
  `u.array_buffer` alias `u1.typed_array` — a real `JSTypedArray*`, not the
  controlled data buffer. The fake struct's `data` field (+16) would still
  need a 64-bit pointer to the buffer, which we do not have without a leak.

**A possible extension (0.4, not the current chain).** Use the same 32-bit
write to set a `Uint8Array` object's `class_id` (+18) to `JS_CLASS_ARRAY`
(=2; `idx` is tunable). The fast-array view then reads `u.array.values` (+56)
= the typed array's data pointer (the controlled buffer) and `u.array.count`
(+64) = its element count. A JS read `arr[i]` interprets the buffer bytes as
`JSValue`s, so a crafted 16-byte slot can fabricate a JSValue with tag
`JS_TAG_OBJECT` and a payload pointing at a fake `JSObject` inside the same
buffer. Putting a fake `JSArrayBuffer` struct in the buffer as well gives the
"fake ABUF inside the buffer + JSValue referencing it" shape. It still needs
the **buffer address** (the N1 leak stage gives a read primitive, so a
groomed leak can supply it), a valid `shape` pointer for the fake object, and
GC-safe lifetime. It is a research extension for the new hunt, not a proven
chain.

**The exact gap / modification needed.** For a strict
fake-object-in-buffer + JSValue chain, add one of:

1. a **64-bit arbitrary write** to a `JSValue` payload or
   `JSObject.u.array_buffer` (different bug);
2. a **heap-address leak** of the controlled buffer, then a write that can
   place that pointer into the fake struct's `data` field (the N1 leak stage
   gives a read primitive, not a pointer write; a second stage would be
   needed);
3. a **type confusion** that makes the engine interpret buffer bytes as a
   `JSObject` (not present in the current inventory).

Without one of these, the N1 delivery is the **real-ABUF same-tag** chain —
exactly the v7 profile and MTE-safe on MTE-on targets.

**Practical recommendation for the new hunt:** port the v7 pattern to N1's
real-ABUF primitive (no fake object), and only pursue the fake-object variant
if the new hunt independently finds a pointer write/leak. The parser 0day is
**not** a candidate for MTE-on.

### 7.3 Parser 0day — an untested MTE-on lead

`b->vardefs` is tagged because `b` (2.5-4 KB) is a Scudo primary chunk. If
`b` were forced **> 64 KiB**, it would move to the secondary path; *if* that
path is untagged on the target (see §2.1: Android 17 shows 8 KiB `mt` prefixes
on some secondary mappings, so this is not guaranteed), `b->vardefs` would be
tag 0 and the 1.31 MB OOB read/write would be unchecked, provided the landing
region is also untagged. The fake `JSVarDef` grid would have to sit at
`(1,310,700 mod 65,536) = 65,516` in every sprayed chunk.
This is a **weak hypothesis** (0.2): it needs (a) a source shape that makes
`sizeof(JSFunctionBytecode)` > 64 KiB within the 6 MiB/300 ms envelope,
(b) proof that Android 17 secondary data chunks are untagged (`stg` absent —
the smaps `mt` flag alone is not proof), (c) a >1.31 MB spray with the right
phase, (d) the existing `chain_off`-style calibration. No PoC exists; do not
count it as a route until (b) is measured.

### 7.4 Rejected as MTE-on carriers

* C1 / round-8 cpool (chunk-header write; the header is tag 0 while the
  pointer is tagged).
* C2 second-order `fd->vars` (tagged `vars`).
* N2/S1 (`var_refs` + 0x7fff8).
* Parser `ARG_SCOPE_END` as-is (tagged `b`, 1.31 MB).
* Litehtml span (C++ heap, previous chunk).
* R1/R2/F1/FR (read-only or DoS).

---

## 8. Test plan for the orchestrator (when a device is available)

### 8.1 Android MTE-on (Samsung S24/S25, Pixel with forced MTE)

1. Mode:
   `getprop ro.arm64.memtag.bootctl_supported`, `getprop arm64.memtag.bootctl`,
   `getprop persist.arm64.memtag.app_default`,
   `getprop | grep -i memtag`.
   Per package: `dumpsys package <pkg> | grep -i -E "memtag|MTE"`;
   `am compat enable NATIVE_MEMTAG_SYNC <pkg>` (or `_ASYNC`) for the forced
   case; restart the process.
2. Coverage (authoritative): `grep -c " mt " /proc/<pid>/smaps` and
   `grep -c "anon:scudo:primary" /proc/<pid>/smaps`; then resolve the
   addresses the payload reports (`D`, `shape`, `proto`, `ctx`, `rt`,
   `js_free`, `system`) and check `mt` on each. Expect the QuickJS arena
   (`D`/`shape`/`proto`) to be `mt=False` on every device.
3. Run order: **v7 cec first** (the proven MTE-on reference: expect no
   fault and a C2 session); then a v3-style debug payload with the address
   log; then an **N1 stage-A probe** with the address log (on device use the
   6→9 sweep; the host forced-gate build is not shipped). The parser 0day is
   **not** to be run on an MTE-on device.
4. Fault signature: `SEGV_MTESERR` (sync) / `SEGV_MTEAERR` (async) in the
   tombstone; an address with the pointer tag in the top byte. A plain
   `SEGV_ACCERR`/`MAPERR` is a mapping problem, not MTE (the Sony case).

### 8.2 iOS 17 (MIE)

1. `codesign -d --entitlements - <app>` → look for
   `com.apple.security.cs.checked_allocations` (MIE), `enhanced_security`.
   Without it, the app is not MIE-enabled regardless of the device.
2. Crash logs: `mteState` + `GUARD_EXC_MTE_SYNC_FAULT` are the definitive
   MIE-fault fields; their absence means no tag fault was recorded.
3. The v7-style chain is expected to be MIE-compatible in principle (arena +
   tag-preserving `rt`/`ctx` access), but this is **unproven**; the first
   test must be the primitive with an address log, not a full C2.

### 8.3 Limits

* No device was touched for this note; all new evidence is host-side source
  instrumentation plus the existing device artifacts.
* The Scudo tag algorithm (random per chunk, odd/even parity, retag on free,
  header tag 0, primary < 64 KiB) is from the public design and matches the
  measured smaps; the AOSP source was not read in-tree.
* v7 MTE-on is **proven by the Pixel 9 Developer Options run** (full C2,
  uid 10290) and corroborated by the 2026-11-02 v3 `.dbg` run (44 `mt`
  mappings, all touched addresses `mt=False`).
* The N1 fake-object variant is **not** MTE-safe-proven because it does not
  exist yet; the proven N1 property is the real-ABUF same-tag chain.
* The iOS MIE-on hypothesis (v7 survives MIE) is a design argument, not a
  measurement.

---

## 9. Artifacts / repro

New host artifacts (this note):

```
/tmp/opencode/mte_lab/src/quickjs.c       app snapshot + n1_in_slab() + prints
/tmp/opencode/mte_lab/app6                gcc -O2 -DNDEBUG -DN1_TRACE
/tmp/opencode/mte_lab/re.js               120-char regexp test
/tmp/opencode/mte_lab/leak_stage.js       N1 leak stage
```

Repro:

```bash
cd /tmp/opencode/mte_lab
N1_TRACE=1 ./app6 re.js
# RE_BYTECODE len=384 buf=... slab=1 usable=472 patlen=120
N1_TRACE=1 N1_FAIL_GROW=1 QJS_HEAP_LIMIT=6291456 ./app6 leak_stage.js
# N1POP_READ ... s=1 ... rs=1 ; N1ADD_STORE ... ss=1
```

Evidence reused:

```
evidence/evidence_20261102/pixel_mte/app_smaps_mte.txt
evidence/evidence_20261102/pixel_mte/mte_mapping_analysis.txt
evidence/evidence_20261102/pixel_mte/{pixel_payload.html,rce_proof.txt,rce_date.txt}
evidence/c2_pixel_android17_proof.log
lab/ios27_20261106/{ios17_rw3.html,c2_console.log,exfil_*.bin}
ios_sideload/Telegram_13.2.0_decrypted.ipa  (entitlements)
```

Lemmalog: facts asserted under `mte_*`, `v7_*`, `ios27_*`, `n1_*`,
`scudo_*`, `mte_verdict` in the Telegram project snapshot
`Telegram-27f28aacca55073e33c1`. Updated 2026-11-07: v7 MTE-on = proven
(Pixel 9 Developer Options, full C2 uid 10290); N1 = same-tag real-ABUF
candidate; the fake-ABUF-in-buffer variant is blocked by the 32-bit write.

## Status update 2026-11-07 late — N1 carrier closed on the widget engine

The N1 real-ABUF primitive is same-tag (v7 profile), but its trigger is a
**refused allocation** (`js_realloc(scopes, 180)` at the memory cap). The
Telegram widget engine treats any refused allocation as fatal:

* device (Sony 72929): `widget … stopped (2): Memory limit exceeded (8 MB)`;
  the next `<script>` never runs; the last render stays frozen;
* canonical tests (`lab/qjs_fork_audit/widget-sandbox/tests/attacks.spec.ts`):
  "out-of-memory is uncatchable … stopped like one that does not"; "one 256 MB
  allocation is refused outright and stops the widget".

Device matrix (`device/logs/device_parser_rce/script_matrix/`): siblings run
(`M1 B`), a 3 MB live allocation is fine (`M2 B3M`), a 6.2 MB allocation stops
the widget (`Memory limit exceeded`), a catchable throw continues (`M4 B`).
Therefore the fork-native gate, same-slab TD2, compact 4 KB and v7 endgame are
all downstream of a dead engine; **N1 is not an MTE-on RCE carrier**.

iOS: the safe probe was delivered (Frida 17.17 host/server on 27043); the
throw variant was stopped with the last render frozen, the no-throw variant
crashed the app in `message-widget.0` (`SIGSEGV 0x10371036103510d4`, crash log
in `lab/qjs_postsnapshot/ios_n1/evidence/`). No N1 iOS claim.

The second MTE-on 0day must be **same-tag without an allocation-failure or
near-cap trigger**. The parser c2560s remains MTE-off; v7 remains the proven
MTE-on RCE.

## Status update 2026-11-07 (second same-tag hunt): matrix unchanged

The follow-up hunt for a **same-tag, non-OOM** primitive (§12 of
`new_0day_mte_specs_20261107.md`) is a **negative for a memory-corruption
primitive**; the 18-bug matrix above is unchanged.

* `js_free_shape` zombie shapes, inline property arrays, the arena slab
  allocator (`arena_slab_take`/`give_back`, slot/page reuse), `JSVarRef`
  detach with reentrant coroutine teardown, and the
  `JSArrayBuffer.array_list` finalizer order were all exercised with an
  instrumented arena build (shape-refcount, zombie-list, and slab
  double-free invariants), ASan+UBSan, and ~55k GC-stress libFuzzer execs:
  no violation, no UAF.
* The reentrant `free_var_ref → js_release_coro → async_func_free` path is
  real and was reproduced; it is safe because the frame slot is cleared
  before the release and every other open var_ref holds a counted coroutine
  reference.
* New same-tag lifetime issues found are **leaks only**: an async-function
  frame leak (~1.37 KB per abandoned call, also present in upstream
  `e22ce4d`) and a teardown-time context leak with symbol-targeted
  `FinalizationRegistry` entries (also upstream). Both are DoS at the 6 MiB
  cap, not carriers.
* The unreported `FinalizationRegistry.unregister` UAF remains DoS-only:
  the only allocation in its free→read gap is a class-64 `JSJobEntry`, which
  cannot reclaim the class-96 entry that would be needed for a
  write-what-where.

Ranked shortlist, exact triggers, host repros and the honest negative are in
`new_0day_mte_specs_20261107.md` §12; artifacts in
`lab/qjs_fork_audit/sametag_hunt_20261107/`.

## Status update 2026-11-08 — parser c2560s MTE route 2 (arena `b`) and the same-payload verdict

**Deliverable:** `notes/parser_mte_route2_samepayload_20261108.md`; artifacts
in `lab/qjs_fork_audit/mte_route2_20261108/`.

### Positive MTE answer (host)

The parser `ARG_SCOPE_END` OOB can be made **tag 0 → tag 0** without replacing
the bug:

* the vulnerable function is created at runtime (anonymous function
  expression via indirect eval) with `argc=1 varc=6 cvc=0`; its
  `JSFunctionBytecode` is **fsize 313 / arena class 352** (not Scudo), so
  `b->vardefs` is tag 0;
* the target `b + 1,310,828` is exactly **20 × 65,536** above `b`, in a
  sprayed arena class-512 `ArrayBuffer` data block; the arena slabs are
  plain `PROT_READ|WRITE` `mmap`s (no `PROT_MTE`, tag 0), so the cross-
  allocation read is unchecked;
* the closure array/victim `T[599]` class-64 geometry is the original
  c2560s one;
* host: `ABLEN[599]=327744` **15/15** at 6/8 MiB, full chain + proof **5/5**
  isolated and **5/5** under a 3 MB preload; trigger charge 4.31 MB (no symbols) / 5.86 MB (symbol-safe); the latter
  is above the c2560s stage A's 5.20 MB, so it is tight with the app baseline;
* the c2560s endgame is **not** MTE-safe as shipped: its `p48`/`a48F` strip
  the tag on `realm`/`rt`. A minimal tag-preserving variant (`endG9s.js`,
  full hi word written for `realm`/`rt` and `rt+16/64`) is host-validated
  (`HF OK` 3/3).

### Model correction (§2.1)

Tag checks apply **only to `PROT_MTE` pages** (Linux arm64 MTE doc; the
allocation tag is 0 when such a page is first mapped). Non-`PROT_MTE` memory
ignores the top byte (TBI). The c2560s is unsafe because `b` and the target
are both in Scudo primary class regions that Scudo maps `MAP_MTE`, with
different chunk tags — not because a tag-0 target would fault. Route 2 is
safe under either reading because both sides are tag 0.

### Same-payload verdict (Sony 72929 beta vs Pixel release 72801)

The new campaign requires one payload, no per-build/per-device hardcodes,
≤ 4,096 zlib9 on both the Sony 72929 beta (MTE off, 6 MiB) and the Pixel 9
release 13.2.0 / 72801 (MTE on, 8 MB). Result:

* the shipped c2560s is **not same-payload**: stage A is Scudo-class-specific
  (2560/4096), the CMD is the beta package path, it has no Pixel run, and
  the audit already declared it non-universal for MTE/OS/device;
* route 2 removes the Scudo class ladder and the MTE cross-tag blocker; the
  Pixel release lib (72801) carries the same **QuickJS-ng 0.17.0** strings
  as the 72929 beta lib, so the bug/ABI generation matches;
* but the route-2 device geometry (20 contiguous arena slabs, target slot
  class, phase) is **host-only**; the release's `JS_ARENA_SLABS`/fork
  snapshot is inferred, not verified; the CMD is per-package; and the
  symbol-safe payload is **4,079 zlib9** (17 bytes under the limit) and 5.86 MB charged, with
  per-device N2/phase tuning that does not fit;
* **verdict: deprioritize the parser vs N1.** The MTE route is a host-proven
  long shot, not a same-payload delivery candidate. The v7 n-day remains the
  proven cross-build/MTE-on C2 reference.

No device, Frida, bot or network payload delivery was used; no file was
deleted.
