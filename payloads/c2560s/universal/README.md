# Universal stage-A class ladder

Generated 2026-11-07 by the `zeroday_hunt_parser` group; updated after the
first live-device ladder run. The orchestrator owns every device operation.

## 0. Device status (read this first)

| class | device result (Sony XQ-BT52, Android 13, 72929, uid 10346) | status |
|---|---|---|
| **2560** | probe `SAFE2560C`, final `ABLEN[599]=327744 VLEN=327744` / `HF OK` / `n1` | **device-proven** (72889 + 72929) |
| **4096** | forge probes base/legacyB4957/nab900: **`ABLEN[599]=327744`**; final (B endgame): `NOCORR END=HF ERR NOV` | **stage-A forge proven; final pending** |
| **3840** | forge probe: **SIGSEGV `0x1fff9`** | **unsafe; excluded** |

The all-4 probe is a **fault/safety probe**: it only proves that the target
page is mapped and tag-compatible. It never checks the forge. `SAFE4096C` +
`NOCORR` is a consistent pair. **Use the forge probe**
(`c<C>_forgeprobe_ladder_72929.html`) to select a class: it is the final
stage A (RT/RJ fake vardefs) with a no-op B and reports
`S1 ABLEN[599]=327744 VLEN=327744 END=-` or `S1 NOCORR END=-` without
running the endgame.

c4096 is **not a class failure**: the same A with a no-op B forges on the
device. The c4096 **final** fails because the 7,182-byte endgame B changes
the pre-stage-A string layout (real-bundle harness: same
`malloc_size=3,315,848`, `used` +3,635 = `2,549,861` vs `2,546,226`). B
length (legacyB4957) and nab (nab900) are not the variable. The fix is the
runtime heap re-alignment family in `fix4096/`; no final is declared until a
run writes `n1`.

The host matrix (below) forged every class, including c4096, and therefore
did **not** predict the device result. Host/probe results are not device
coverage.

## 1. What is here

| path | meaning |
|---|---|
| `c<C>_forgeprobe_ladder_72929.html` | **forge probe / class selector** (device) |
| `c<C>_forgeprobe_ladder_host.html` | host twin of the forge probe |
| `c<C>_final_ladder_72929.html` | device final (CMD `id>.../files/n1`, CALIGN=4) |
| `c<C>_probe_ladder_72929.html` | all-4 safety probe, marker `SAFE<C>C` (not a forge predictor) |
| `c<C>_final_ladder_host.html`, `c<C>_probe_ladder_host.html` | host twins |
| `stageA/c<C>_{final,probe}.js` | raw stage-A scripts for the Scudo harness |
| `c3072max_*` | map-robust 3072 variant (nfloat max); unmeasured |
| `c4096_forgeprobe_legacyB4957_72929.html` | 4096 B-length diagnostic (device ABLEN) |
| `c4096_forgeprobe_nab900_72929.html` | 4096 coverage diagnostic (device ABLEN) |
| `fix4096/` | c4096 final layout-calibration family (29 finals + MANIFEST/README) |
| `MANIFEST.json` | parameters, per-file raw/zlib9/SHA-256, `device_evidence` |
| `NEXT_DEVICE_RUN.md` | forge-probe order (historical; superseded by fix4096/README) |
| `harness/scudo_ladder_sim.c` | Scudo-primary containment model (`-m 4k\|alt\|dense`) |
| `harness/lab_bundle_heap.c` | real-bundle pre-A heap probe (quickjs-ng + bundle) |
| `harness/run_matrix.sh` | rebuild + full host matrix, logs in `harness/logs/` |
| `c3840_*` | dense 4096-slot artifact, **UNSAFE on device (SIGSEGV 0x1fff9)**, evidence only |

Base ladder: 2048, 2304, 2560, 3072, 3584, 4096, 4608, 5120 (map `4k`);
alt 2080, 3104 (map `alt`, AOSP `AndroidSizeClassMap` hypothesis);
`c3072max` under 4k; `c3840` evidence only (unsafe).
`c2560_final_ladder_72929.html` is **byte-identical** to the device-proven
`../c2560_final_c2560s_72929.html` (SHA-256 `992a5126...`), likewise the
probe (`b9104fae...`).

## 2. Class rule

QuickJS allocates a large block with `mf.js_calloc(1, 8 + size)` (the 8-byte
`JSMallocBlockHeader`). With `class(x)` = smallest ladder value `>= x`:

    class(8 + BSIZE) == class(8 + fs) == C
    BSIZE = round_up_16(19*nfloat + 311)          (measured, cpool shift)
    fs    = C - 8                                  (ladder default)
    nab   = round(2.86e6 / fs / 100) * 100

The shipped 2560/4096 packages use `fs = C - 16` (8 bytes of extra slack);
they are reproduced with those pinned parameters. Every other class uses
`fs = C - 8`. `nfloat` is the midpoint of `{n : class(BSIZE+8) == C}`.

Same-class under three candidate tables (device-proven classifier rule):

| artifact | req_b / req_ab | 4k | dense | android | robust |
|---|---|---|---|---|---|
| 2048 | 1928 / 2048 | 2048/2048 | 2048/2048 | 2080/2080 | yes |
| 2304 | 2184 / 2304 | 2304/2304 | 2304/2304 | 2560/2560 | yes |
| **2560** | 2424 / 2552 | 2560/2560 | 2560/2560 | 2560/2560 | **proven** |
| 3072 (mid) | 2808 / 3072 | 3072/3072 | **2816/3072** | 3104/3104 | **no** |
| **c3072max** | 3064 / 3072 | 3072/3072 | 3072/3072 | 3104/3104 | yes |
| 3584 | 3336 / 3584 | 3584/3584 | 3584/3584 | 4096/4096 | yes |
| **4096** | 3752 / 4088 | 4096/4096 | **3840/4096** | 4096/4096 | **no** |
| **c3840** | 3704 / 3840 | 4096/4096 | 3840/3840 | 4096/4096 | yes |
| 4608 | 4360 / 4608 | 4608/4608 | 4608/4608 | 4608/4608 | yes |
| 5120 | 4872 / 5120 | 5120/5120 | 5120/5120 | 7104/7104 | yes |

The **dense** table is the 1.25×/256-step hypothesis from
`REPORT_scudo_classmap.md` §2 (`... 2816, 3072, 3328, 3584, 3840, 4096,
4352 ...`); it is the only known table that splits c4096. The **android**
column is the `AndroidSizeClassMap` usable ladder. c4096 is not a simple map
mismatch on the 4k/android tables; the 72889→72929 difference (same stage A,
B 4,957→7,182) points to heap/B-length layout. The diagnostics and c3840
settle it on the device.

## 3. Selection (forge probe, not all-4)

| target | order |
|---|---|
| Sony / Android 13, 4K | **2560 forge** (control) → **4096 forge** (class proven) → **fix4096 final family** (§3.1) → 3584 → 4608 → 5120 → 2048 → 2304 → **c3072max** |
| Android 14/15/16, 4K, unknown revision | **2560 forge** → **4096 forge** (class proven; final layout pending) → 3584 → 4608 → 5120 → 2048 → 2304 → c3072max |
| Android 15/16, 16K pages | same order; if all 4K forge probes fail, alt **3104 → 2080 → 4608** |
| MTE-enabled build | **do not run** (hard limit) |

**c3840 must not be run** (SIGSEGV `0x1fff9`); it is evidence only.
`c4096_final_ladder_72929.html` must not be redeployed (NOCORR).

For each class: send the forge probe; on `ABLEN[599]=327744` send the matching
final; on `NOCORR` skip the final; on a crash move to the next class. One
class per message. The C2 loader can sequence the probes (do not modify the
active C2 files; wrap a chosen final with
`device/gen_c2_widget.py --src <final> --out <tmp>`).

A single widget carrying two stage A scripts fits the zlib budget (4072/4096
for two finals, 1076 for two probes) but is not useful: the first fault kills
the second, and the second A overwrites the global `V/VAB/T/A/UV`.

### 3.1 Exact next run: c4096 final layout calibration

The class is proven; the endgame B is the variable. Family in
`fix4096/` (29 finals, full SHAs in `fix4096/MANIFEST.json`, priority in
`fix4096/README.md`). One message per widget; stop at the first
`S1 ABLEN[599]=327744 VLEN=327744 END=HF OK` and check `n1`.

Minimal first batch:

```
1. fix4096/c4096_final_fe0_72929.html          function-expression A, no preamble
2. fix4096/c4096_final_fe_free1_72929.html     1x class-4096 alloc/free before b
3. fix4096/c4096_final_fe_free2_72929.html     2x
4. fix4096/c4096_final_fe_free4_72929.html     4x
5. fix4096/c4096_final_fe_8192_free1_72929.html 1x class-8192 (B string class)
6. fix4096/c4096_final_fe_8192_free2_72929.html 2x
7. fix4096/c4096_final_fe_mix_free1_72929.html  4096+8192
8. fix4096/c4096_final_pad256_72929.html        B pre-A length shift
```

If a run reports `ABLEN` + `END=HF ERR ...` (NOANCHOR/NOBASE/NO*), the
stage-A forge is fixed; stop and report the exact `END=` string (the anchor
is the next blocker). If `NOCORR`, continue. Do not declare the final until a
run writes `n1`.

## 4. Host matrix (summary only)

Rebuilt from `../../../../src`, not the stale `build/run_scudo` (its 32-byte
header/table classifies the c2560 AB as 3072 and always returns NOCORR).

* same-map stage A: 8/8 4K finals FORGE, 8/8 probes SAFE; 3/3 alt; c3072max
  forges under 4k+dense; c3840 host-forges but the **device SIGSEGVs**
  (unsafe);
* cross-map: alt 2080/3104 under 4k fault in `add_closure_variables` (real
  class mismatch); the 4k 3072 run under alt also faults but is a fake-chain
  crash, not used as a discrimination proof;
* glibc: 10/10 probes safe, 10/10 finals forge; endgame `HF OK` 7/10, `HF
  ERR` 3/10; all 12 forge probes report ABLEN; the 29 fix4096 host twins
  forge and run `HF OK`.

**This matrix did not predict the c4096 device NOCORR.** It validates class
arithmetic and script plumbing only. The real-bundle pre-A heap probe
(`harness/lab_bundle_heap.c`) is the model that explains the final failure:
same `malloc_size`, `used` +3,635 for the endgame B.

## 5. Regenerate / verify

```sh
python3 device/gen_stageA_ladder.py --check     # byte-identity vs shipped 2560/4096
python3 device/gen_stageA_ladder.py --all       # ladder + forge probes + diag
python3 device/widget/universal/gen_c4096_layout.py  # fix4096 family
device/widget/universal/harness/run_matrix.sh   # full host matrix
```

`--pos min|mid|max` controls the nfloat choice; `--fs/--nfloat/--nab`
override the geometry. The generator never writes outside this directory
(or `--outdir`) and never touches `device/endG8s.js`, `gen_c2560s.py`, the
shipped finals or the C2 variants.

## 6. Limits

* **Stage-A forge proven**: 2560 (dual build) and 4096 (base/legacyB4957/
  nab900 probes). **c4096 final pending**: the endgame-B pre-A heap breaks
  the forge; `fix4096` is the calibration. **c3840 unsafe** (SIGSEGV
  `0x1fff9`).
* The **all-4 probe is not a forge predictor** (proven on c4096/72929).
* Scudo class table is the in-tree measured ladder; a new revision can
  rename/shift classes. Probe forge-first.
* 16K pages: class map assumed unchanged; the alt set covers the
  AndroidSizeClassMap hypothesis; the phase changes, so a forge probe per
  device is mandatory.
* MTE: hard limit (parser OOB read crosses allocation tags).
* 52-bit VA: `ok48` rejects >= 2^48 -> safe NOANCHOR; `MASK=2^52` is an
  unvalidated one-line change.
* Host model only: device proof remains the orchestrator's job.
