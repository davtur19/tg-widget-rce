# Scudo containment analysis for the parser-0day +1.31 MB target

Date: 2026-11-08. Host-only. Worker: `hunt_parser`. No device access; the
orchestrator runs the next probe.

Inputs: device result `probe_881safe` (survives, `SAFE881 AB=-1 CHG=0
DIR=direct E1=function eval()… E2=1`), `A_univ881big` 3,200×AB(881)
(`NOCORR`, alive, no proof), and the two Sony tombstones
`universal/logs/tombstone_sony_probe_08.txt` / `tombstone_sony_a1980_09.txt`.
The 881 class is tag-compatible; the remaining failure is containment.

## 1. Correct class: 0x450 (1,104 B), not 0x830

AOSP `platform/external/scudo`, `android13-release`, `AndroidSizeClassMap`
(64-bit, `SizeDelta=16`):

```
0x20,0x30,0x40,0x50,0x60,0x70,0x90,0xb0,0xc0,0xe0,0x120,0x160,0x1c0,0x250,
0x320,0x450,0x670,0x830,0xa10,0xc30,0x1010,…
```

* b's `JSFunctionBytecode` request 889 → **0x450 = 1,104 B**.
* `ArrayBuffer(881)` → **0x450** (same class, same MTE tag).
* `ArrayBuffer(1,096)` / `(1,104)` → **0x450** (same class; max chunk size).
* `ArrayBuffer(1,980)` → **0x830 = 2,096 B**, a *different* class/region.

Therefore `n1_hookfree/universal/poc/A_univ1980.js` (800×AB(1,980)) and the
old Frida "889 b / 1988 filler" calibration are **not applicable to this
target**: a 0x830 allocation cannot contain a 0x450 chunk. Do not run the
1,980 variant. The 881/1,096/1,104 family is the right one.

`PrimaryRegionSizeLog=28` → a 256 MiB reservation per class;
`PrimaryMapSizeIncrement=1<<18` (256 KiB); `PrimaryEnableRandomOffset=true`
(the region base is shifted by a random page-aligned offset; the chunk phase
relative to b is still fixed by b's address, see §2).

## 2. Target geometry from the tombstones

Probe (1,800×881) and A1980 maps give the same 0x450 region layout:

```
0x6e0e618000-0x6e0e717fff rw- [scudo:primary]   1 MiB
0x6e0e718000-0x6e0f097fff rw- [scudo:primary]   9.5 MiB   <- b is here
0x6e0f098000-0x6e1e61efff --- (PROT_NONE)       245.5 MiB
```

* b = `0x6e0effae78`, vardefs = `0x6e0effb0d8`, target =
  `b + 1,311,308` = `0x6e0f13b0c4`.
* The committed region ends at `0x6e0f098000`; the target is **667 KiB past
  the end**, in the uncommitted PROT_NONE part at 1,800×881 → SIGSEGV at
  `add_closure_variables` (the `vd->scope_level` load).
* Chunk math (C=1,104): b mod C = 472; target delta = 1,311,308 =
  **1,188 chunks + 228 B**. The chunk containing the target starts at
  `0x6e0f13afe8`; the target byte is 228 into the chunk. The 881-byte AB
  data covers it (881 > 228). **The miss is chunk allocation, not the
  within-chunk phase or the 881-vs-1,104 data size.**
* The same math holds for both tombstones (b mod 1,104 = 472 in both); the
  region base random offset cancels because b's chunk and the target chunk
  share the same grid.

## 3. Fit of the two device points

Let F = number of free 0x450 chunks already on the class free list before
the spray (from the engine/bundle heap; they are in other regions and are
consumed first). The spray maps new 256 KiB increments contiguously after
`0x6e0f098000`; each increment holds `0x40000/1104 = 237` chunks. The target
is 2 increments + 143,556 B past the committed end; inside the target
increment the target chunk is 130 chunks from the bottom / 106 from the top.

* `map_need` (first chunk of the target increment) = `2*237 + 1 = 475`.
* `cover_need` (pop the target chunk itself, LIFO from the top) =
  `2*237 + 106 + 1 = 581`; FIFO = `2*237 + 130 + 1 = 605`.

Device observations:

| spray | observation | constraint |
|---:|---|---|
| 1,800×881 | target page PROT_NONE (crash) | 1800 < F + 475 |
| 3,200×881 | target page mapped, NOCORR | F + 475 ≤ 3200 < F + 581 |

Both hold for **F ∈ (2,595, 2,725]**, best fit **F ≈ 2,700**. Then
`map_total = 3,175` (so 3,200 maps the target page) and
`cover_total = 3,281 (LIFO) / 3,305 (FIFO)` (so 3,200 misses the target
chunk by ~81-105 chunks). This is exactly the observed `NOCORR`: the page is
committed, but the target chunk has not been popped from the free list.

The model is `device/scudo_model.py` (`--fit` reproduces the table;
`--maps <maps> --b <addr> --spray N --prefree F` for a live run).

## 4. Recommended next probe: 3,400×881 paired canary

Threshold: **≥ 3,281 (LIFO) / 3,305 (FIFO)**: use **3,400×881** for margin.
The widget is built and host-validated with the *same* stage-A order/sizes as
`A_univ881big` (keep=3,000 symbols, PB/UV fill, 3,400×AB(881), D=3,000,
T=600) plus a paired class-64 canary array C (1,200; free evens):

```
device/widget/canary_n1c_probe_3400_72889.html   7,815 raw / 1,062 zlib9
device/widget/canary_n1c_final_3400_72889.html   7,815 raw / 3,215 zlib9
device/widget/canary_n1c_debug_3400_72889.html
```

Stage A is identical in probe/final/debug (A=2,322; B padded to the endgame
length 4,957; C padded to 408), so the pre-A heap is the same. The probe's
stage B is a no-op; stage C renders
`PRB H=<hit> N=<attempts> S=881 T=- C=<canary>`.
The final's stage B is the patched `endG3_dev.min.js` (multi-candidate pivot
loop), which accepts a canary-forged AB; host twin 3/3 `HF OK` + proof.

Interpretation on the Sony:

| probe marker | meaning | next |
|---|---|---|
| `PRB H=CANARY[i]=327744` | target chunk is in the filled spray **and** the paired adjacency works; containment solved | run `canary_n1c_final_3400_72889.html`; expect `HF OK` + n1 proof |
| `PRB H=NOCORR N=10` | containment still short (F > 2,725) or the fake chain did not add F=2 | try 3,600/3,800; if OOM, use the drain-keep-tail variant (§5) |
| crash at stage A | target page PROT_NONE (F > 2,725 and 3,400 did not map it) | try 3,600+; if OOM, drain first |
| `PRB H=ABLEN[599]` | T[599] adjacency also works | run the final |

`probe_881safe` (all-4 pattern) cannot detect containment: with F=1 the
single OOB entry lands on the victim block's *header*, not `byteLength`
(`CHG=0` is expected). The JUMP/TERM paired-canary is the positive signal.

## 5. Memory and alternatives

Memory is the binding constraint: the 3,200 device run fits; 3,600+C with a
3.1 MiB bundle OOMs in the host model; the atom table (65,600 symbols peak,
kept 3,000) and the spray peak are separate phases (the slice frees before
the spray). 3,400 is the smallest margin-safe spray.

If 3,400 is still short (F > 2,725):

1. **3,600-4,000, but reduce overhead**: drop the D drain (D is not needed
   with the paired canary; saves ~0.3 MB), keep C=1,200, keep=3,000. The
   N1 `A_univC4800` uses D=2,500 and no C; a 4,800+C is likely OOM at a
   3.2 MiB bundle but may fit at ~2 MiB.
2. **Drain-keep-tail**: allocate the full 3,400 (peak unchanged), then free
   the first 2,700 references (`A[i]=null, i<2700`) and keep the last ~700
   (the newly mapped increments near the target). The peak is the same, but
   the post-stage-A live set drops by ~2.4 MB, leaving room for the endgame.
   The target is in the kept tail only if the allocation order matches the
   model (F then contiguous increments); the canary verifies.
3. **Prefill/drain before b** does *not* reduce the total: b is compiled
   after the prefill, and the target is 1,188 chunks after b; a 2,700-chunk
   prefill still leaves a ~1,188-chunk post-b spray (total ~3,900). The
   single 3,400 spray is better.
4. **Class-size insurance**: AB(1,096) or AB(1,104) is still class 0x450
   (tag-compatible) and covers every within-chunk phase. The observed phase
   is 228, so 881 is sufficient today; switch to 1,096 only if the maps show
   a phase >881 (it costs ~0.7 MB at 3,400).
5. **Do not use AB(1,980)** (class 0x830): wrong region, cannot contain the
   target. The old 1,980 calibration should be retired.

## 6. What to collect on the next device run (rooted orchestrator)

After the 3,400 probe (alive or crashed), collect the live maps and a b
address to refine F:

```bash
PID=$(pidof org.telegram.messenger.beta)
adb -s <SERIAL> shell "su -c 'cat /proc/$PID/maps'" > /tmp/sony_maps_3400.txt
```

and a b leak: dump a window of the qjs heap or use the N1 leak; b is a
`JSFunctionBytecode` with `byte_code_len=133, argc=1, var_count=6,
closure_var_count=0, cpool_count=30` at offsets 0x20/0x38/0x3a/0x42/0x44
(host f). With b, `scudo_model.py --maps … --b … --spray 3400` prints the
exact target chunk/phase and the required spray count. The live maps also
show which `anon:scudo:primary` region is the 0x450 one (the 256 MiB
reservation containing b) and whether the target page is `rw-`, `---`, or a
different class.

## 7. Files

```
device/scudo_model.py                         class/region/increment/free-list model
device/gen_n1_canary.py                       N1-layout stage A + paired canary
device/widget/canary_n1c_{probe,final,debug}_3400_72889.html
device/widget/canary_n1c_{probe,final,debug}_3600_72889.html
device/widget/canary_n1c_*_host.html          host twins
```

No N1 artifact was modified. The N1 worker's 4,800/refill direction is
compatible with the fit; the fit says 3,281-3,305 is the minimum, so 4,800
is sufficient but not necessary, and 3,400 is the memory-safer first try.
