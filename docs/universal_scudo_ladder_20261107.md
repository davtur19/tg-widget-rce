# Universal Scudo class ladder for the parser-0day stage A

Date: 2026-11-07. **Host-only** (no device, no bot, no network, no deletion).
Worker: parser-ladder subagent. Scope: `device/widget/universal/`,
`device/gen_stageA_ladder.py`, this note. The active finals
`c2560_final_c2560s_72929.html`/`c4096s` and the C2 variants were only read;
`device/endG8s.js`, `device/gen_c2560s.py` and the RUNBOOK were not modified.

Companion artifacts: `device/widget/universal/README.md`, `MANIFEST.json`,
`harness/` (model + matrix logs). Evidence base:
`notes/audit_universality_20261107.md` §1.2/§2/§4,
`REPORT_parser_hunt.md` §17–§19, `device/C4096_FIX_AND_C2560.md`,
`device/LOCALVAR_CLASS_ANALYSIS.md`,
`lab/qjs_fork_audit/n1_hookfree/universal/REPORT_scudo_classmap.md`.

---

## DEVICE UPDATE (2026-11-07, Sony XQ-BT52, Android 13, build 72929, uid 10346)

The orchestrator ran the first ladder class on the live device. **This
section overrides the host-only selection of the first version of this
note.**

| widget | device result | meaning |
|---|---|---|
| `c2560_forgeprobe_ladder_72929.html` | `S1 ABLEN[599]=327744 VLEN=327744 END=-` | control: forge-probe plumbing OK |
| `c4096_forgeprobe_ladder_72929.html` (B no-op 7,182) | `S1 ABLEN[599]=327744 VLEN=327744 END=-` | **class 4096 forges** |
| `c4096_forgeprobe_legacyB4957_72929.html` | `S1 ABLEN[599]=327744 VLEN=327744 END=-` | B length is not the variable |
| `c4096_forgeprobe_nab900_72929.html` | `S1 ABLEN[599]=327744 VLEN=327744 END=-` | nab is not the variable |
| `c4096_probe_ladder_72929.html` (all-4) | `S1 SAFE4096C END=-` | fault probe only |
| `c4096_final_ladder_72929.html` (B endgame 7,182) | `S1 NOCORR END=HF ERR NOV`, no `n1`, app alive | **the endgame B changes the pre-stage-A heap; the stage A then does not forge** |
| `c3840_forgeprobe_ladder_72929.html` | SIGSEGV `0x1fff9` (app died) | **c3840/dense is unsafe; excluded** |

Consequences:

1. **Class 4096 is valid**; the earlier `NOCORR` was not a class failure. The
   all-4 probe is still only a fault probe (it does not predict the forge),
   and the forge probe is the class selector.
2. **The final failure is the endgame-B pre-A layout.** The same A with a
   no-op B forges; with the 7,182 endgame B it does not. The 72889/72929
   history and the real-bundle harness (`harness/lab_bundle_heap.c`) agree:
   the B code string is 7,182 chars in both, but the endgame content changes
   the pre-A string layout (+3,635 used at boot, same malloc_size). Carrier
   variants (endgame in C/T/eval/comment/encoding) increase that delta to
   30 KB and are dead ends.
3. **c3840 is refuted/unsafe**: the dense-3840 slot gave SIGSEGV `0x1fff9`.
   Remove it from the safe selection; the class table is 2560/4096 stage-A
   forge, 3840 unsafe, the rest unmeasured.
4. **Do not declare a c4096 final until it writes `n1`.** The fix is a
   runtime heap re-alignment; the calibration family is in
   `device/widget/universal/fix4096/` (see §5.1).

---

## 0. TL;DR

* `device/gen_stageA_ladder.py` reproduces the shipped **stage A byte-for-byte**
  for C=2560 (2,228 B) and C=4096 (2,503 B), and the full c2560 final/probe
  byte-for-byte (`992a5126…` / `b9104fae…`).
* It generated **10 base variants** (8 classes of the 4K ladder, 2 classes of
  the provisional alt/16K ladder) plus **forge probes** for every class, the
  `c3072max` variant, two **4096 diagnostics** (legacy B=4,957, nab=900), and
  the **c4096 layout-calibration family** in
  `device/widget/universal/fix4096/` (29 finals). Worst size: **14,317 raw /
  4,094 zlib9** — inside 32,768 / 4,096.
* **Device truth (72929)**: c2560 forge probe `ABLEN`; **c4096 forge probes
  `ABLEN` with the base no-op B, legacyB4957 and nab900** → the class is
  valid. The c4096 **final** (B = 7,182 endgame) is `NOCORR`: the endgame B
  changes the pre-stage-A heap. The all-4 probe is only a fault probe; the
  forge probe is the selector. `c3840` is **SIGSEGV `0x1fff9` (unsafe)**.
* The c4096 failure is **B/pre-A layout**, not the class map: `req_b=3752`
  and `req_ab=4088` are the same class under the device-proven rule on the
  4k and AndroidSizeClassMap ladders; the endgame B string changes the
  pre-A string layout (+3,635 used at boot, same malloc_size in the real
  bundle harness). The fix is runtime heap re-alignment (fix4096 family),
  not another carrier: endgame-in-C/T/eval/comment/encoding makes the pre-A
  delta ~30 KB and is a dead end.
* **MTE is a hard limit** for this design: the parser OOB read itself crosses
  allocations with different tags, before any JS runs. 16K pages: class map
  assumed unchanged; an alt probe set covers the other AOSP map hypothesis.
  52-bit VA: safe-fail (NOANCHOR).

No device claim beyond the stage-A forge of 2560/4096: a c4096 **final** is
not declared until it writes `n1`. The orchestrator owns the next run.

---

## 1. Class map used, and its provenance

Base map (map `4k`; values are **usable** sizes, the ladder the shipped
packages were derived against):

```
16,32,48,64,80,96,112,128,144,160,176,192,208,224,240,256,288,320,352,384,
416,448,480,512,576,640,704,768,896,1024,1152,1280,1536,1792,2048,2304,
2560,3072,3584,4096,4608,5120,6144,7168,8192,9216,10240,12288,14336,16384,…
```

Provenance, in order of strength:

1. **Device-measured**: `REPORT_parser_hunt.md` §17 — Frida usables
   889/1988 map to 896/2048; the 1,980 filler is class 2048; cpool 110/180
   land in 2560/4096, and the class-matched sprays contain the target
   (`c2560s` 5/5 on 72929, `c4096c` 5/5 on 72889).
2. **In-tree class-map note**: `REPORT_scudo_classmap.md` §2 records the
   1.25× measured ladder above 1 KB and the +8 headroom rule.
3. **AOSP**: this task is host-only/no-network and no Scudo source is
   vendored in-tree. The `4k` table above is identical to the AOSP
   `DefaultSizeClassMap` values as known from the in-tree analysis; it was
   **not** re-read from the android-15/16 tree. The `alt` table is derived
   from `AndroidSizeClassMap` chunk sizes `0x20…0x10010` minus the 16-byte
   chunk header (source list quoted in
   `lab/sony_webp_chain/harness/scudo_map.py`):
   `16,32,48,64,80,96,128,160,176,208,272,336,432,576,784,1040,1648,2080,
   2560,3104,4096,4608,7104,8704,11648,14208,16384,18432,23040,29440,
   33280,65536`.
   The alt set is a **probe hypothesis**, not a certified map.

The class rule (proved by `C4096_FIX_AND_C2560.md`, re-verified here):

```
ArrayBuffer(size) -> js_mallocz(size) -> arena_calloc_large ->
      mf.js_calloc(opaque, 1, 8 + size)          (8-byte JSMallocBlockHeader)
class_of(x) = smallest ladder value >= x
invariant:  class_of(8 + BSIZE) == class_of(8 + fs) == C
```

where `BSIZE = round_up_16(fsize)` is the QuickJS large-block request and `fs`
is the `ArrayBuffer(fs)` filler length.

### 1.1 c4096: the class forges, the endgame-B heap does not (device 72929)

The all-4 probe and the final execute **the same allocator sequence** (same A
length, same `fs`, `nab`, drain, T); only the fill bytes differ. Therefore
the class regions, the committed ranges and the target address are identical
between `SAFE4096C` and `NOCORR`. `SAFE` means the OOB read path did not
fault (the target page is mapped and tag-compatible); it says **nothing**
about whether the target lies in our sprayed AB data. `NOCORR` is the first
real signal: the target bytes did not form a long-enough fake vardef chain.

The class rule that the device itself proved is the request-only rule
`class(x) = smallest map value >= x` (this is what makes c2560's
`req_b=2424` and `req_ab=2552` the same class). Under that rule:

| artifact | req_b | req_ab | 4k b/ab | dense b/ab | android b/ab | robust |
|---|---:|---:|---|---|---|---|
| 2048 | 1928 | 2048 | 2048 / 2048 | 2048 / 2048 | 2080 / 2080 | yes |
| 2304 | 2184 | 2304 | 2304 / 2304 | 2304 / 2304 | 2560 / 2560 | yes |
| **2560** | 2424 | 2552 | 2560 / 2560 | 2560 / 2560 | 2560 / 2560 | **yes (proven)** |
| 3072 (mid) | 2808 | 3072 | 3072 / 3072 | **2816 / 3072** | 3104 / 3104 | **NO (dense)** |
| `c3072max` | 3064 | 3072 | 3072 / 3072 | 3072 / 3072 | 3104 / 3104 | yes |
| 3584 | 3336 | 3584 | 3584 / 3584 | 3584 / 3584 | 4096 / 4096 | yes |
| **4096** | 3752 | 4088 | 4096 / 4096 | **3840 / 4096** | 4096 / 4096 | **NO (dense)** |
| `c3840` | 3704 | 3840 | 4096 / 4096 | 3840 / 3840 | 4096 / 4096 | yes |
| 4608 | 4360 | 4608 | 4608 / 4608 | 4608 / 4608 | 4608 / 4608 | yes |
| 5120 | 4872 | 5120 | 5120 / 5120 | 5120 / 5120 | 7104 / 7104 | yes |
| alt 2080 | 1864 | 2080 | **2048 / 2304** | **2048 / 2304** | 2080 / 2080 | alt-only |
| alt 3104 | 2840 | 3104 | **3072 / 3584** | **3072 / 3328** | 3104 / 3104 | alt-only |

Columns: `4k` = the measured/default ladder used by the shipped packages;
`dense` = the 1.25×/256-step ladder in `REPORT_scudo_classmap.md` §2
(`,…,2816,3072,3328,3584,3840,4096,4352,…`); `android` = the
`AndroidSizeClassMap` usable values (`0x1010=4112` chunk / 4096 usable, …).

What this says about c4096 (updated after the forge-probe device runs):

* **The class is proven.** The same stage A with the no-op B forges on the
  device in three independent probes: base (B 7,182), legacyB4957 (B 4,957)
  and nab900 (A nab=900). `req_b=3752` and `req_ab=4088` are the same class
  under the device-proven rule on the 4k ladder **and** under
  AndroidSizeClassMap; the earlier `NOCORR` was not a class failure.
* **The final's B content is the failure.** The final uses the same A and C
  but B = the 7,182-byte endgame; the pre-stage-A heap differs. The real
  bundle harness (`harness/lab_bundle_heap.c`, 72889 `sandbox-bundle.js`)
  measures the boot state before A:
  `malloc_size=3,315,848` for both, but `used=2,546,226` (probe) vs
  `2,549,861` (final), `str=78,933` vs `82,568`. The B code string is 7,182
  chars in both; the endgame content changes the string layout by **+3,635
  bytes**. On the device that shift moves b out of the forge state.
* **The dense 3840 candidate is refuted**: `c3840_forgeprobe` is SIGSEGV
  `0x1fff9` (unsafe). It is removed from the safe selection; the dense map
  hypothesis is not a usable fallback here.
* **The phase/pattern is not the cause**: the chunk-relative target phases
  are 1,868 (c2560) and 2,988 (c4096), both 28 mod 40. The AB data starts at
  chunk+24 (Scudo 16-byte header + QuickJS 8-byte block header), so the
  fill-relative offsets are 1,844 and 2,964, both **4 mod 40**. The stage A's
  `ph=4` pass writes a record starting exactly there; the RT/RJ record has
  `scope_level=5>0` and `scope_next=4` (or 65535), the same valid fake
  vardef that c2560 uses. A c4096 target **inside our AB data forges** — the
  forge probes prove it. The final's problem is that the pre-A shift changes
  where b/the spray land, not the pattern.
* **Carrier variants are dead ends**: putting the endgame in C, in a
  `type="text/plain"` node, or encoding it raises the pre-A delta to ~30 KB
  (measured with the bundle harness); the probe-B layout is the only exact
  one. The fix is runtime heap re-alignment (the `fix4096` family, §5.1).

**Class status on the Sony, from the device + table:**

* **Stage-A forge proven**: **2560** (dual build) and **4096** (base,
  legacyB4957, nab900 probes on 72929).
* **Unsafe**: **3840** (SIGSEGV `0x1fff9`); excluded.
* **Unmeasured** (pair-robust but no device forge): 2048, 2304, 3584, 4608,
  5120; `c3072max` is the robust 3072 variant.
* **Map-specific**: the alt 2080/3104 artifacts only make sense if the Sony
  uses AndroidSizeClassMap; under 4k/dense their pairs split. They are
  frozen as an AOSP-alternative probe family, not as Sony candidates.

The old c4096 crash tombstone (`tombstone_c4096_10.txt`) is historical: the
target `vd_base+1,310,700` fell in the b class region's `PROT_NONE` tail at
0x6e5e85f000; that was the old `ArrayBuffer(4096)` class mismatch
(AB -> 4352). The current stage A is a different layout and the class
forges; the final's NOCORR is the B/pre-A shift, not a fault.

### 1.2 Forge probe vs safety probe

| probe | stage A fill | hit test | what it proves |
|---|---|---|---|
| all-4 (`probe`) | `PB[i]=4` | `TCHG` only | the target page is mapped/tag-compatible (no crash); **not** a forge |
| forge (`forgeprobe`) | RT/RJ fake vardefs | `ABLEN[...]=327744` | the target lies in our AB data and the fake chain forges the victim AB |
| final | RT/RJ + endgame | `ABLEN` + endgame | forge + exploit; endgame can add its own failure (`NOV`/`NOANCHOR`) |

The forge probe uses the **final stage A** with a no-op stage B of the same
7,182-B length and the same 408-B stage C; it reports
`S1 ABLEN[599]=327744 VLEN=327744 END=-` or `S1 NOCORR END=-` and never runs
the endgame. It is at least as safe as the final on a class whose final is
safe (c4096 is the proof: the final returned NOCORR without a crash).

**Layout caveat:** the probe keeps the B *length* but replaces the endgame
*content* with a no-op. If the engine compiles B before evaluating A, the
pre-A heap could differ from the final's; the final remains the ground
truth. The c4096 run tests this directly: if the forge probe returns
NOCORR, it reproduces the final's stage A; if it returns ABLEN, the B content
matters and the final's NOCORR was a layout artifact of the endgame B.

---

## 2. Generator and formula

`device/gen_stageA_ladder.py`:

```
fs     = C - 8                     (ladder default; max data for class C)
nfloat = midpoint{n : class(round_up_16(19*n+311) + 8) == C}
BSIZE  = round_up_16(19*nfloat + 311)
nab    = round(2.86e6 / fs / 100) * 100
drain  = 3000, T = 600 (T[598]=null), SY = 65600, keep = 3000
```

`19*nfloat + 311` is the **measured** `fsize` relation of the cpool shift
(110→2401, 180→3731); `nfloat` is searched, not assumed. The midpoint (not
min/max) hedges a small class-map revision: it keeps `req_b` away from both
class boundaries. Any n in the valid interval works on the measured map
(e.g. 2560: 105..117; 4096: 172..198).

`--all` now emits, besides the final/probe pair: the **forge probe** for
every class (final stage A + no-op B=7,182 + stage C), `c3072max` (nfloat
max), the dense `c3840` artifact (kept for evidence only: device SIGSEGV
`0x1fff9`, unsafe), and the two **4096 diagnostics** (legacy B=4,957,
nab=900).

Reference reproductions use the pinned shipped parameters
(`fs=C-16`: 2544/110/1100 and 4080/180/700) so the two device-proven stage A
scripts stay byte-identical. For the ladder classes there is no pinned
artifact, so `fs=C-8` is used as specified; the 8-byte difference is 0.2–0.4 %
of a chunk and does not change the class. If the literal `fs=C-8` geometry is
wanted for the two pinned classes too, it is one command (measured in the
`--no-write` table): `--classes 2560,4096 --pos max` gives fs 2552/4088,
nfloat 117/198, zlib9 4,022/4,024; those variants are not shipped because
the pinned ones are the device-proven artifacts.

### 2.1 Byte-identity validation (executed)

```
$ python3 device/gen_stageA_ladder.py --check
REF C=2560  stageA final IDENTICAL (2228 B)  probe IDENTICAL (2228 B)
REF C=4096  stageA final IDENTICAL (2503 B)  probe IDENTICAL (2503 B)
REF full c2560_final_c2560s_72929.html      IDENTICAL
REF full c2560_probe_c2560s_72929.html      IDENTICAL
```

The full `c4096s` widget is **not** byte-identical to the shipped one, for a
non-stage-A reason: the shipped `c4096s` package used the older B=6,917
endgame, while the ladder assembles the current B=7,182 endgame (the one
that is device-proven with c2560s). Its stage A is identical; the ladder
c4096 final is the old A with the new B, not a regression of the old artifact.

The assembler duplicates `gen_c2560s.py`'s stage-B pipeline (read
`endG8s.js`, substitute DBG/CALIGN/CMD, `terser -c passes=2 -m`, pad to
7,182) and the fixed 408-B stage C. It does not import or modify the
canonical builder.

---

## 3. Generated family

All files in `device/widget/universal/`; full parameters/SHAs in
`MANIFEST.json`. Device finals/probes below; host twins differ only in the
stage-B CMD/CALIGN (same A/C, same sizes).

| class | map | fs | nfloat | nab | BSIZE | req b | req AB | A | final raw/zlib | final SHA-256 | probe raw/zlib | probe SHA-256 |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|
| 2048 | 4k | 2040 | 84 | 1400 | 1920 | 1928 | 2048 | 2124 | 9842 / 4025 | `1f88570bd7b02e7be209ff2d36b99781be47153eca5501ba8c8461e5bcb4dbc2` | 9842 / 960 | `316213077951271264e2935e858156b9fd5c8fbc9e76271fccaf075ebea1ddc5` |
| 2304 | 4k | 2296 | 98 | 1200 | 2176 | 2184 | 2304 | 2180 | 9898 / 4025 | `5252cbca2baeafce216178dbfa0e50e80d2e41e94b39257855e5a77cbca98814` | 9898 / 961 | `e1bca7be0bfbf209b7402d6d42a25f56590dab78d19d7b59bc9e3c2ab45e1ab8` |
| 2560 | 4k | 2544 | 110 | 1100 | 2416 | 2424 | 2552 | 2228 | 9946 / 4023 | `992a51267a385c57635f5aed835aa29a1006ca8c584ca3843b265cd2c71318b4` | 9946 / 959 | `b9104faef8be5e06fc451fc11c62aea546b8e995d56585a13c53b897cdeae41f` |
| 3072 | 4k | 3064 | 131 | 900 | 2800 | 2808 | 3072 | 2307 | 10025 / 4024 | `f9f533b31c0a33e3b06e72b7fb72cc63ab71be592b609f54f7fde07a80296e50` | 10025 / 957 | `b10ed6dc02ca6d336cfe85bfd67f64323be4df39431a72bdc4a259f92760b6a6` |
| 3584 | 4k | 3576 | 158 | 800 | 3328 | 3336 | 3584 | 2415 | 10133 / 4026 | `06ff6789ed332d6b318ca04ec4e167dd9c5220161e2c2ac74850b51e40cac296` | 10133 / 962 | `aa3a4b2a9a76a5f9215072e0d0f4bd6b53cd67ec7ed95da36585ac8ab4211113` |
| 4096 | 4k | 4080 | 180 | 700 | 3744 | 3752 | 4088 | 2503 | 10221 / 4023 | `fe3b41ae7c469d2e8a4cc6900ccb92c3c3d31823c5fa9349435a00e426dadc1f` | 10221 / 963 | `f89262067f9b9e848459cc4ca97c8d8288e70e678b87f1eecaa1c16876c4ab55` |
| 4608 | 4k | 4600 | 212 | 600 | 4352 | 4360 | 4608 | 2631 | 10349 / 4021 | `d4ef019d3eb399842818e09bdd79b1f5ba776b7c6ebe9b2104355795946cebd8` | 10349 / 957 | `144d98032ce5b7159e59775a069426e251390b0d3a51c3f353aa1baf2c0908f8` |
| 5120 | 4k | 5112 | 239 | 600 | 4864 | 4872 | 5120 | 2739 | 10457 / 4021 | `536ffccf59a84ea9103863594798a24fa9b22b7da4c021ad391bdde7a1ac22b0` | 10457 / 958 | `00eb33164131e86d25fbe105aede988636e40b89372022853899d447da38c85d` |
| 2080 | alt | 2072 | 81 | 1400 | 1856 | 1864 | 2080 | 2112 | 9830 / 4024 | `1e2027d1ae28d8b2f0a266dfb272c2a4acac931f9bf6cc07f9d90f698db38176` | 9830 / 961 | `1cbf00e74051da6fece29fde3dcf5b04786bf5c91e2723740fa984e38cfb48b1` |
| 3104 | alt | 3096 | 132 | 900 | 2832 | 2840 | 3104 | 2311 | 10029 / 4024 | `5d5fa092c5ba127c0135c1c3aa5a2c1da2c9ea3d484aa38503f11f6a14ed7292` | 10029 / 959 | `333f3e30df5fbfc9cd55523e3df08f83262e5d556647107d388f83a642d9238e` |

Probe convention: same length as the final A, marker `SAFE<C>C`, all-4
filler (`PB[i2]=4`, 4-byte stride), hit condition only `TCHG[i]=...`
(the final uses RT/RJ fake-vardef patterns and `ABLEN[i]=...`).

Budget: **raw max 10,457 / 32,768** (5120), **zlib9 max 4,026 / 4,096**
(3584, vs 4,023 for the shipped c2560s). Headroom is only 70 bytes of
zlib9. If a future endgame grows, the finals can exceed: trim `nfloat` to
the interval minimum (`--pos min`, saves ~40–60 B raw), or ship a C2/loader
that carries the stage A and B in separate messages. Probes are unaffected
(their B is a 7,182-B pad that compresses to ~30 B).

### 3.1 Forge probes (the new device selector)

`c<C>_forgeprobe_ladder_{72929,host}.html`: final stage A + no-op B
(7,182 B) + stage C. Raw size equals the final's (same A/B/C lengths);
zlib9 ≈ 1.0 KB because the B is a pad. Reports
`S1 ABLEN[599]=327744 VLEN=327744 END=-` on a working class and
`S1 NOCORR END=-` otherwise; no endgame.

| artifact | forgeprobe raw / zlib | forgeprobe SHA-256 |
|---|---:|---|
| 2048 | 9842 / 1013 | `508c3b290a3b9b199d3ce69f387140dbddaac10713e938dada9986749b964756` |
| 2304 | 9898 / 1013 | `71b60e35ffa41a4e0a35fda95bbb307f0a0ae4422cde8aaaeb021c90501c2645` |
| **2560** | 9946 / 1011 | `382b4ea307425ddd1ff014071cd3f62ee7d50c0c97afb6c696375f60d2b3571c` |
| 3072 | 10025 / 1010 | `0829a6f7a41bd0a5453002c4d04ed56fb985c79e5bab268fd8af589bfc50138b` |
| 3584 | 10133 / 1015 | `a42738cd6e66c724ed946e4d7c75189ea38f185b7613fb5db0760197fbce68b1` |
| **4096** | 10221 / 1014 | `d8e249ac5f203b059ce083192fddd7eedfc09fc71a5c21f4402e122a2a40804a` |
| 4608 | 10349 / 1011 | `76e126e2102bb729e09e0a63109839ad289c927097297218380e297778fb7526` |
| 5120 | 10457 / 1011 | `9856cd528b444cedb1557e238fc46ccf27ae015b5de10e3c919b99de57712683` |
| 2080 (alt) | 9830 / 1013 | `8f1fc7d161f2a0598cb040d72e3580cad9d49b6b2ef4ea3a729f048b93d6dd19` |
| 3104 (alt) | 10029 / 1013 | `13ccd417c18c07505c4ef182dfb356eace38e0aa28aec4b723ca8c37a182f2fe` |
| **c3840** (dense 4096 slot) | 10213 / 1014 | `84782ffea269b3a9f7cd7ead184119b75581f9b55b44e5b9ffb13d55e630474f` — **device SIGSEGV `0x1fff9`, UNSAFE** |
| **c3072max** (robust 3072 slot) | 10077 / 1013 | `9ab210dc556f09f0b3ec01c03edf24a39efe4858f8e9509fc75cec6613ae1530` |
| 4096 diag legacyB4957 | 7996 / 1004 | `1439aa4059b617971ce063ec0cfd3a62b76784bd458276d5dc266c511f2de554` |
| 4096 diag nab900 | 10221 / 1014 | `8cdda536995923ccfda0f65e799a89fea7717a908a782fff1ade2cd71ca1ae42` |

The **map-robust** variants:

* `c3840` = dense-map class 3840: `fs=3832`, `nfloat=178`, `nab=700`,
  `req_b=3704`, `req_ab=3840`. Host-forges under 4k/dense, but the **device
  crashed with SIGSEGV `0x1fff9`**; the dense slot is **refuted/unsafe** and
  removed from the safe selection. The artifact is kept for evidence only.
* `c3072max` = 3072 with `nfloat=144` (interval max), `fs=3064`,
  `req_b=3064` (above the dense 2816 boundary). Same class under all three
  tables; unmeasured on device.

Diagnostics for the 72929 c4096 negative (all three forge probes returned
ABLEN on the device; they isolate the final-B layout, not the class):

* `c4096_forgeprobe_legacyB4957_72929.html`: same A, no-op B **4,957 B**
  (the 72889 c4096c B length). Device: **ABLEN** → B length is not the
  variable.
* `c4096_forgeprobe_nab900_72929.html`: same A text length, `nab=900`
  (3.69 MB spray instead of 2.87 MB). Device: **ABLEN** → nab is not the
  variable.

### 3.2 c4096 final layout-calibration family (`fix4096/`)

Because the class forges and the endgame-B content is the only failing
variable, the family keeps the **same endgame B (7,182) and stage C** and
changes only the way b/the spray are reached:

| priority | family | lever |
|---:|---|---|
| 1 | `c4096_final_fe0_72929.html` | `function f` -> `var f=function` (same fsize=3731/class 4096); isolates the A form |
| 2-6 | `fe_free{1,2,4,8,16}` | K class-4096 chunks allocated and **freed** before b; reorders the b/spray free list, spray reuses them |
| 7-10 | `fe_8192_free{1,2,4,8}` | K class-8192 chunks (the B string class) allocated/freed before b |
| 11 | `fe_8192_keep{1,2,4}` | class-8192 live chunks (lower priority) |
| 12-14 | `fe_mix_free{1,2,4}` | both classes |
| 15-18 | `fe_keep{1,2,4,8}` | K class-4096 live chunks (lower priority: may occupy the target path) |
| 19-23 | `pad{256,512,1024,2048,4096}` | endgame B padded with a comment (pre-A length shift) |
| 24-27 | `split{2,3,4,6}` | endgame source split into N string scripts, eval in B2 (changes the pre-A string class) |

All files: `fsize=3731` (class 4096), max **14,317 raw / 4,094 zlib9**.
Host: 29/29 host twins forge and run `HF OK`; the Scudo model forges every
preamble A. **Host is not device coverage** (c4096 final is the proof). See
`fix4096/README.md` for the exact order; the next device run is in §5.1.
No final is declared until one writes `n1`.

---

## 4. Host Scudo matrix

### 4.1 Harness

`device/widget/universal/harness/scudo_ladder_sim.c` — QuickJS (fork `src`)
with a Scudo-primary model:

* `class_of(request)` = smallest class `>= request`, request includes the
  8-byte JS header (matches the device-proven c2560/c4096 geometry);
* one 256 MiB PROT_NONE reservation per class, committed in 256 KiB
  increments, chunks bumped upward in the class region, per-class LIFO
  free list;
* `malloc_usable_size` returns the class size;
* `-m 4k|alt|dense` selects the table (dense = the 1.25×/256-step
  hypothesis of §1.1).

The existing `build/run_scudo` is **not usable** for this: its table is
`0x10…0x2000` and it adds a 32-byte header, so the c2560 AB request
(8+2544=2552, +32 = 2584) maps to 3072 while b (2424+32=2456) maps to 2560;
it returns `RESULT NOCORR` for the device-proven stage A. That is why the
model was rebuilt from the in-tree Scudo notes rather than reused.

### 4.2 Same-map results (`harness/logs/matrix.tsv`)

| map | class | final | probe |
|---|---:|---|---|
| 4k | 2048, 2304, 2560, 3072, 3584, 4096, 4608, 5120 | **8/8 FORGE** `RESULT ABLEN[599]=327744 VLEN=327744` | **8/8 SAFE** `RESULT SAFE<C>C` |
| alt | 2080, 3104, 4608 | **3/3 FORGE** | **3/3 SAFE** |
| dense / 4k | 3840 (dense + 4k) | **2/2 FORGE (host only)** | — |
| 4k / dense | 3072max (4k + dense) | **2/2 FORGE** | — |

**The host matrix is not device coverage.** Every same-map final, including
c4096, forges under the model; the device returned NOCORR for c4096 (and
SIGSEGV for c3840). The model validates the class arithmetic and the script,
not the target's residence or the pre-A heap.

### 4.3 Cross-map controls (model discrimination)

Same artifacts under the *other* map: 4k 2048/2304/2560/3584/4096/4608/5120
forge under alt (the requests coalesce into alt classes
2080/2560/4096/4608), while **alt 2080/3104 under 4k** fault with SIGSEGV
inside `add_closure_variables` (`vd->scope_level`) — the expected class
mismatch. 4k 3072 under alt also faults, but that run lands in alt class
3104 for both b and AB; the fault is a fake-chain walk, not a class
mismatch, so it is not used as a discrimination proof.

### 4.4 Full widgets on glibc (`run_sib_plain -l 8`)

10/10 probes: `VDOM=S1 SAFE<C>C END=-`.
10/10 finals: stage A `ABLEN[599]=327744 VLEN=327744`; endgame `HF OK`
(proof 162 B) for 2048/2304/2560/3072/4096/2080/3104, safe `HF ERR`
(NOANCHOR) for 3584/4608/5120. The stage-A forge is glibc-lucky; the endgame
anchor is layout-sensitive on glibc and is **not** the device path.

Forge probes (`glibc_forgeprobes.tsv`): all 12 standard/robust classes and
both 4096 diagnostics report `VDOM=S1 ABLEN[599]=327744 VLEN=327744 END=-`
on the host. This checks the marker/no-op-B plumbing only; the c4096 device
counterexample (host forge, device NOCORR) shows it cannot be used as a
device predictor.

Bonus: feeding the three extracted scripts (A, B, C) of the host 2560 and
3072 finals to the Scudo model with the host CMD writes the 162-B
`/tmp/hf_proof`; the endgame is class-agnostic and runs on top of the
ladder-A forge.

---

## 5. Selection (corrected after the 72929 device run)

There is no JS-visible device/allocator signal (the widget UA/platform are
fixed; no Android version, no page size, no MTE flag). **The all-4 probe is
only a safety/fault probe and must not be used to select a class.** The
selector is the **forge probe**:

* forge probe reports `S1 ABLEN[599]=327744 VLEN=327744 END=-` → the class
  works on this device/build; send the matching final;
* forge probe reports `S1 NOCORR END=-` → the class does not forge (target
  outside our spray or a bad fake chain); do not send the final; move on;
* forge probe faults → the class target page is not safe; move on (collect
  the tombstone if the orchestrator wants the map geometry).

Recommended order (updated after the forge-probe runs):

| target | order |
|---|---|
| Sony / Android 13, 4K (this device) | **2560 forge** (control) → **4096 forge** (class proven) → **c4096 final fix4096 family** (see §5.1) → 3584 → 4608 → 5120 → 2048 → 2304 → `c3072max` |
| Android 14/15/16, 4K, unknown Scudo revision | **2560 forge** first (the only dual-build class) → **4096 forge** (class proven, final layout pending) → 3584 → 4608 → 5120 → 2048 → 2304 → c3072max |
| Android 15/16, 16K pages | the same forge-probe order first; if every 4K probe fails, the alt family **3104 → 2080 → 4608** |
| MTE-enabled build | do not deploy (hard limit, §6) |

Rationale:

* 2560 is the **only** class with a device-proven forge on both builds and a
  device-proven final. It is also the forge-probe control.
* **4096 stage A is device-proven**: base, legacyB4957 and nab900 all return
  `ABLEN`. The final's `NOCORR` is the endgame-B pre-A layout, not the class.
  The fix is the `fix4096` family; do not deploy the old
  `c4096_final_ladder_72929.html` again.
* **c3840 is unsafe** (SIGSEGV `0x1fff9`); removed from the safe selection.
* `c3072max` is the map-robust 3072 variant; unmeasured.
* 2048, 2304, 3584, 4608, 5120 are pair-robust but **unproven**; the forge
  probe decides.
* No final is declared until it writes `n1`; the ladder remains host-matrix
  plus the proven stage-A classes (2560, 4096).

Cross-map note for the alt hypothesis: under AndroidSizeClassMap the 4K
**2048** artifact lands in the alt 2080 class and the 4K **3072** artifact in
the alt 3104 class (both b and AB coalesce), so 2080/3104 are not new
physical classes there; they are shipped as separate phase/layout probes.
Under 4k/dense, the alt 2080/3104 artifacts split and are not Sony
candidates (table §1.1).

### 5.1 Next device run: c4096 final layout calibration

The class is proven; the B endgame is the only variable. The family is in
`device/widget/universal/fix4096/` (29 finals, `MANIFEST.json` with full
SHAs, `README.md` with the mechanism). One message per widget; stop at the
first `S1 ABLEN[599]=327744 VLEN=327744 END=HF OK` and check the `n1` proof.

Minimal first batch (highest information):

1. `fix4096/c4096_final_fe0_72929.html` — function-expression A, no
   preamble. If it forges, the A form alone re-aligns the layout.
2. `fix4096/c4096_final_fe_free1_72929.html`
3. `fix4096/c4096_final_fe_free2_72929.html`
4. `fix4096/c4096_final_fe_free4_72929.html`
5. `fix4096/c4096_final_fe_8192_free1_72929.html`
6. `fix4096/c4096_final_fe_8192_free2_72929.html`
7. `fix4096/c4096_final_fe_mix_free1_72929.html`
8. `fix4096/c4096_final_pad256_72929.html`

If a run reports `ABLEN` but `END=HF ERR ...` (NOANCHOR/NOBASE/NO*), the
stage-A forge is fixed and the remaining blocker is the endgame anchor; stop
and report the exact `END=` string. If `NOCORR`, continue. `c3840` must not
be run (SIGSEGV `0x1fff9`). The full priority order (free → 8192 → mix →
keep → pad → split) is in `fix4096/README.md`.

The `fe*` variants keep B exactly 7,182 bytes, so the existing SAFE probe at
B=7,182 applies. The `pad*`/`split*` variants change B; the B=7,182 SAFE
probe does not cover them, so their stage-A mark is the first signal and a
matching B-length probe is needed before treating one as a final.

Do not declare the final until a run writes `n1`. If all 29 variants return
NOCORR, the blocker is the pre-A heap itself and the next lever is a
two-stage delivery (endgame fetched after A via a data channel) — not
another in-widget carrier.

### 5.2 Can one widget try two classes?

Measured: two finals in one widget = 12,162–12,462 raw / **4,071–4,073
zlib9** (fits 4,096); two probes = **1,076 zlib9**. But it is not useful:

1. the scripts are evaluated in order and the engine stops that widget on a
   sandbox fault; if A1's class is wrong the target read faults before A2;
2. A2 overwrites the global `A/UV/T/V/VAB`, freeing A1's spray and
   discarding A1's forged `V`, so the shared stage B only sees the last
   class;
3. a modified endgame that keeps `V1`/`V2` would be a new endgame (owned by
   the canonical builder), not this ladder.

Therefore: **one class per widget**, probe then final; sequence the probes
with the bot/C2 loader. The active C2 files were not touched; to test a
chosen final through C2, wrap it read-only:
`python3 device/gen_c2_widget.py --src <final> --out /tmp/opencode/c2_<C>.html`.

---

## 6. MTE: hard limit, tag-preserving analysis

What the current endgame does (`device/endG8s.js`):

* `p48` (line 27) = `(hi % 65536)*2^32 + lo` → keeps bits 0–47, **drops the
  top byte** (the TBI/MTE tag);
* `wrV`/`wrD` (32, 66) write back `hi = floor(v/2^32)`, i.e. tag = 0;
* `setF` (68–77) re-points the forged AB's `u.array.u.ptr` to an arbitrary
  address `A` and reads it through `VAB`/`FAR`.

Under TBI (Sony) the tag byte is ignored; under MTE the access checks the
pointer tag against the memory tag of the granule and faults on mismatch.

A tag-preserving variant is possible **only for the in-allocation re-points**:

1. read the full 64-bit pointer (`r64`), split `addr = ptr & 0x00FF_FFFF_FFFF_FFFF`
   and `tag = ptr >> 56`;
2. keep `tag` alongside every pointer (e.g. `setF(A, tagA)`), write
   `tagA<<56 | addr` back;
3. for the V/VAB self-view and the re-point to `VBase` (same allocation),
   the original tag is valid, so the anchor scan and the in-V writes can be
   made tag-clean.

But it does **not** save the design:

* The **parser OOB read is performed by QuickJS itself**, before any JS: the
  outer function's `vardefs` pointer carries the bytecode allocation's tag
  and the target is 1.31 MB away in an AB-spray allocation with a different
  MTE tag. `add_closure_variables` faults at `vd->scope_level` under MTE,
  no matter what the endgame does. (Same for the far reads of `rt`, libc and
  the app `.bss`, whose allocation tags are unknown and cannot be guessed:
  a wrong guess is a synchronous SIGSEGV.)
* Scudo assigns MTE tags per allocation; there is no tag oracle from widget
  JS, and brute-forcing 16 tags per address kills the sandbox on the first
  miss (and is not a controlled read anyway).

Conclusion: **MTE = no-go** for this chain, independent of stage A. The
5.1-compatible precondition is MTE off (opt-in on Pixel 8/9; verify from the
orchestrator side before deploying). Async-MTE builds may defer the fault but
still kill the process at the kernel check; do not claim them.

---

## 7. 16K pages

Assumption documented (no AOSP 15/16 Scudo source was read in this host-only,
network-free task):

* the Scudo **class table is compile-time and page-size independent** in the
  Default hypothesis → the same 4K ladder applies at 16K; what changes is the
  primary region/map increment geometry (256 KiB commit, page-aligned random
  region offset), hence the **phase** `(b + 1,310,700) mod C`, which is not
  predictable from JS. A probe per device is mandatory.
* if the 16K/Android-15+ build selects `AndroidSizeClassMap` instead, the
  usable ladder is the `alt` table: the classes that matter are
  **2560, 3104, 4096, 4608** (and 2080 for the smaller end). Under that map
  the 4K **2048** artifact coalesces into alt 2080 and the 4K **3072**
  artifact into alt 3104 (both b and AB), so the alt artifacts are
  phase/layout probes, not new physical classes.
* the endgame's page constants are engine-internal: the QuickJS arena slab
  is still 64 KiB with a 16-bit 4 KiB-page bitmap (`PG[81]`, `q>>12`,
  `q&0xfff`), independent of the OS page; the ELF scan steps 4 KiB and a
  16K-aligned base is also 4K-aligned. No 16K change is needed in B/C, but
  the `VBase`/arena guards remain 4K-based and are worth re-checking if the
  fork changes its arena size.

Derived ladder points for the alt hypothesis: 2080, 2560, 3104, 4096, 4608.
All are generated; in addition, the 4K 2048/3072 artifacts coalesce into
alt 2080/3104 under that map (same b/AB class), so they are equivalent
probes with a different phase.

---

## 8. 52-bit VA (LVA)

`ok48/okp/hok` require `x < 2^48 - 1`; `p48` masks to 48 bits. On an LVA
device whose heap pointers exceed 2^48, the forged view pointer/anchors are
rejected → `HF ERR NOANCHOR` (safe, no read past the guard). The stage A
itself still forges (it uses no pointer arithmetic); only the endgame stops.

A 52-bit variant is a contained change (not shipped, unvalidated):

```
MASK = 2^52
p52(o)  = (hi % 1048576)*2^32 + lo        // keep bits 0..51
ok52(x) = x > 65536 && x < MASK-1 && (x % 8) === 0
```

Keep `codeok` at 2^48 unless code mappings are also above 2^48 on the target
(LVA normally affects app data, not the executable). This must be re-tested
against a real LVA device; it is listed as a future lever, not a claim.

---

## 9. Honest limits

* **Device stage-A forge**: 2560 (dual build) and 4096 (base/legacyB4957/
  nab900 probes) are proven. **c4096 final is not achieved**: the endgame-B
  pre-A heap breaks the forge. The `fix4096` family is the calibration; no
  final until `n1`.
* **c3840 is unsafe**: device SIGSEGV `0x1fff9`; the dense-3840 slot is
  excluded. Do not run it.
* **The all-4 probe is a fault probe, not a forge probe.** It proves only
  that the target page is mapped/tag-compatible; `SAFE` + `NOCORR` is a
  valid pair. Selection must use `c<C>_forgeprobe_*`.
* **The c4096 class is not the problem**: `3752` and `4088` are the same
  class under the device-proven rule on the 4k and AndroidSizeClassMap
  ladders; the forge probes confirm it. The failure is the **B endgame
  content changing the pre-A string layout** (+3,635 used at boot in the
  real bundle harness; same malloc_size). Carrier variants (endgame in
  C/T/eval/comment/encoding) make the delta ~30 KB and are dead ends.
* **Class map**: the in-tree measured 4K ladder, not a freshly read AOSP
  source. A Scudo revision can rename/shift classes; the forge probe covers
  it, but the dense/alt tables are hypotheses, not certified maps.
* **Engine update**: `19*nfloat + 311` and the leak (`scope_idx=65534`,
  count=7) are fork-specific. A `libtmessages` update invalidates the
  formula and the leak; re-derive with `src_diag` (`FSIZE`/`ACV BSIZE`) and
  re-run the forge probe before the final.
* **Endgame on glibc**: 3/10 safe NOANCHOR; the device endgame is unchanged
  and its class-24/page-derived path is device-proven for 2560 only. If a
  fix4096 variant reports `ABLEN` + `HF ERR NOANCHOR`, the stage-A forge is
  fixed and the anchor is the next blocker.
* **Memory/CPU**: spray cost is ~2.87 MB constant per class (`nab*C`), same
  as the device-proven c2560 budget; fills are ~2.9 MB per phase, bounded by
  the same 20-phase loop. The larger classes (4608/5120) have fewer, larger
  chunks; `nab900` for 4096 is 3.69 MB and stays under the 8 MB baseline in
  the host model (device budget to be confirmed).
* **Zlib headroom**: the fix4096 max is 4,094/4,096 (split6); do not add
  more text. Any B growth needs a trim (`--pos min`) or a loader split.
* **C2**: untouched. The active finals and C2 variants were not modified.

---

## 10. Files and commands

```
device/gen_stageA_ladder.py                 generator (--check / --all / --class)
device/widget/universal/MANIFEST.json       params + raw/zlib9/SHA-256 + device_evidence
device/widget/universal/README.md           operator summary
device/widget/universal/NEXT_DEVICE_RUN.md  exact forge-probe order + SHAs + expected
device/widget/universal/harness/scudo_ladder_sim.c
device/widget/universal/harness/run_matrix.sh
device/widget/universal/harness/logs/       matrix.tsv, sim_*.txt, glibc_widgets.tsv,
                                            glibc_forgeprobes.tsv
device/widget/universal/stageA/             raw A scripts for the harness
```

New device-facing files (this update):

```
c<C>_forgeprobe_ladder_72929.html           forge probe (selector; no endgame)
c<C>_forgeprobe_ladder_host.html            host twin
c3072max_{final,probe,forgeprobe}_ladder_*  map-robust 3072 slot (unmeasured)
c4096_forgeprobe_legacyB4957_72929.html     4096 B-length diagnostic (device ABLEN)
c4096_forgeprobe_nab900_72929.html          4096 coverage diagnostic (device ABLEN)
fix4096/                                    c4096 final layout-calibration family
  gen_c4096_layout.py                       family generator
  MANIFEST.json                             family params + SHA-256
  README.md                                 mechanism + priority
  c4096_final_fe* / fe_free* / fe_8192* /
  fe_mix* / fe_keep* / pad* / split*        device/host finals
  (c3840 final/probe kept for evidence only: device SIGSEGV 0x1fff9)
```

```sh
# verify the two shipped stage A references
python3 device/gen_stageA_ladder.py --check
# regenerate the whole family (writes only under device/widget/universal/)
python3 device/gen_stageA_ladder.py --all
# regenerate the c4096 layout-calibration family
python3 device/widget/universal/gen_c4096_layout.py
# host matrix (rebuilds the model if needed)
device/widget/universal/harness/run_matrix.sh
```

Next device step (orchestrator): the `fix4096` family, starting with
`fix4096/c4096_final_fe0_72929.html` then `fe_free1/2/4`,
`fe_8192_free1/2`, `fe_mix_free1`, `pad256` (full order in
`fix4096/README.md` and §5.1). The forge probe/`c3840` phase is over:
2560 and 4096 stage-A forge are proven; **c3840 is unsafe** and must not be
run. Do **not** redeploy `c4096_final_ladder_72929.html` (NOCORR). No final
is declared until a run writes `n1`. On a 16K/MTE Pixel: check MTE first; if
off, run the same 2560/4096 forge probes then the alt 3104 forge probe.
Nothing here authorises a device operation by this worker.
