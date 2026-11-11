# Next device run — c4096 final layout calibration

Status: the **forge-probe phase is complete** on the Sony 72929 (uid 10346):
2560 and 4096 stage-A forge are proven; `c3840` is SIGSEGV `0x1fff9`
(unsafe, do not run). The remaining blocker is the **c4096 final**: the
7,182-byte endgame B changes the pre-stage-A heap, so the same stage A that
forges with the no-op B returns NOCORR with the endgame B.

The class is not the variable; the family changes only the way b/the spray
are reached. **One message per widget; stop at the first**
`S1 ABLEN[599]=327744 VLEN=327744 END=HF OK` and check the `n1` proof. If a
run reports `ABLEN` but `END=HF ERR ...` (NOANCHOR/NOBASE/NO*), the stage-A
forge is fixed; stop and report the exact `END=` string. If `NOCORR`,
continue.

## Minimal first batch (highest information)

| # | file (in `fix4096/`) | SHA-256 | raw / zlib |
|---:|---|---|---|
| 1 | `c4096_final_fe0_72929.html` | `995e8cc8e79e82b7850d3f1d3c737b43b21b1a098ee9f489b4d076866a061f49` | 10226 / 4026 |
| 2 | `c4096_final_fe_free1_72929.html` | `d9e4269d643c7ba18dd11013100491cac79eaf3f36cf0b90084d6fa2a30436d3` | 10323 / 4052 |
| 3 | `c4096_final_fe_free2_72929.html` | `b369d8a0d3976f38d45f3acc8d74ec599e1fd8dc8e9ebbe12985483ea6518cb0` | 10323 / 4052 |
| 4 | `c4096_final_fe_free4_72929.html` | `c7579b00ad4629ecb844f246ff16f44f71c908061f271b21b44e75fc63745a7a` | 10323 / 4054 |
| 5 | `c4096_final_fe_8192_free1_72929.html` | `8bae479b07e2c06074cad7756cc4915c38da58d1ff21972cd5f4cdea4239651b` | 10323 / 4057 |
| 6 | `c4096_final_fe_8192_free2_72929.html` | `b34e6b30a6a59de70867353be0bc8aee496b3d9a1d5183b83ed20027c8b54c92` | 10323 / 4058 |
| 7 | `c4096_final_fe_mix_free1_72929.html` | `e2ac43fa0e83ab904a42266457d48ab911c47384bda075a314d480ae5425673c` | 10420 / 4062 |
| 8 | `c4096_final_pad256_72929.html` | `a5e7bec1b15ef64b632222f2e3f75b65b8d6e7cc8d17f3e80da07ceb8dccd9af` | 10477 / 4028 |

`fe0` is the cheapest: if the function-expression A form alone re-aligns the
layout, no preamble is needed. The free preambles reorder the class-4096
free list (the spray reuses the freed chunks); the 8192/mix preambles change
the region created by the B string class; `pad256` shifts the pre-A length.

## Full priority order

The complete 29-variant order (free -> 8192 -> mix -> keep -> pad -> split)
with SHAs and host results is in `fix4096/MANIFEST.json` and
`fix4096/README.md`. After the minimal batch, continue in that order.

## Do not run

* `c4096_final_ladder_72929.html` (the old baseline): already NOCORR.
* `c3840_forgeprobe/final_ladder_72929.html`: device SIGSEGV `0x1fff9`.
* `c4096_probe_ladder_72929.html` as a selector: all-4 fault probe only
  (it returned SAFE4096C on the class that then failed).

## Host verification of the family

All 29 host twins report `ABLEN[599]=327744 VLEN=327744` and `END=HF OK`
under `run_sib_plain -l 8`; the Scudo model forges every preamble A. This is
**not** device coverage (the c4096 final is the counterexample). Sizes:
max 14,317 raw / 4,094 zlib9.
