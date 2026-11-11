# HANDOFF — iOS 27 reliability + cross-platform frame (docs owner: merge into repo docs)

Source: `notes/ios27_reliability_20261108.md` (full analysis),
`tg-rce/payloads/ios27_rel/` (payloads + MANIFEST), facts
`notes/LEMMALOG_FACTS_ios27_reliability_20261108.txt`.
This file is short on purpose: it lists only the deltas the repo docs need.

Hash note: every SHA-256 in this handoff is pre-redaction. Current sizes and
hashes are in `docs/PAYLOAD_HASHES.json`. For the proven iOS 27 page the
current values are 8,647 raw / 3,658 zlib9 / `8b6706e5…`; the older
`bf31f2f6…` / 3,680 pair is the pre-redaction artifact. The `zlib9` values
also depend on the zlib build; this host uses 1.3.1.

Status note: the 5725 run is the proof. The stage-A marker of that message was
below the fold and is unknown. The 16:22 marker belongs to another message.
The gated 9,139 B twin and the two-phase detector/final are host-only.

Apply to: `tg-rce/docs/ios17e_instrument_20261108.md` (or `docs/ios_0day_chain_20261108.md`),
`docs/two_phase_universal_20261108.md`, `README.md` (payload index).

---

## 1. Corrections (existing text is wrong or imprecise)

### 1.1 The 5725 stage-A marker (`ios17e_instrument_20261108.md` §9.13)

Current text says the run reported
`RESULT SS2 C=34 SZ=957 N=2600 R=4 M=768 HIT=545 LEN=327744 PH=12 VK=598 NT=106`.

Evidence: `x8_0.png` / `_proof_alive.png` / `_final_state.png` show that widget above
the **16:22** message timestamp, and `w8_0.png`/`v6_0.png` show
`S:EXC ReferenceError: src is not defined` on the message below it. The 16:27 message is
the one below and its `#v` was never captured.

Replace with:

> The 16:22 message (pre-`src`-fix payload, `MS=[384,512,640,256,768,…]` order) forged at
> `R=4 M=768 HIT=545 LEN=327744 PH=12 VK=598 NT=106`. The **RCE-proven 16:27 message**
> (`ss8_final.html`, 8,647 raw / 3,680 zlib9, sha256 `bf31f2f6…`) rendered at 16:27:39 and
> wrote `rce.txt`; its own stage-A marker was below the fold and is **unknown**.

### 1.2 Marker field `M` vs file

`M=768` at `R=4` is only consistent with the ss5-family `MS=[384,512,640,256,768,…]`
(`MS[4]=768`), not with `ss8_final.html`'s `[512,640,768,896,1024,…]` (`MS[4]=1024`).
Both orders have device hits: OCR of `v6_0`/`v7_0` shows the 16:25/16:26 messages forging
at `R=0 M=512` and `R=1 M=640` with `HIT=545 PH=12`.

### 1.3 Stage-A `N=` field is a literal

`RESULT … N=2600` is hardcoded; the `p3/p4` variants (N=3000) still print `N=2600`.
Do not infer the executed N from the marker.

## 2. New measured facts (add to the 17e section)

* App console 14:19:48–16:08:07: **45 widget renders, 11 `js_free_rt: malloc_size
  underflow` aborts**, all in 14:53–15:25 (`freeing 5.1–6.0e9 but only 16.77e6 tracked`,
  sizes `0x13xxxxxxf8`). Window rate: **11/22 = 50 %** forge-and-abort per render.
* The underflow abort is a **stage-A forge that did not reach `pthread_exit`**; on the 17e
  a stage-A-only probe is fatal. The 6s does not show this (0 aborts in the 6s logs).
* launch → first render: **median 20 s** (45 samples, `--console`); send→render <1 s;
  `rce.txt` backup read-back ≈ 23 s.
* Forge is reproducible **within a process**: the 16:22 message re-forged at 16:27:06 and
  16:28:57; a fresh launch re-rolls the geometry.
* Forged victim index is stable across platforms: `T[545]` (modal) / `T[585]`, `VK=598`.

## 3. New artifact set (add to the payload index)

`tg-rce/payloads/ios27_rel/` — invariant family derived from the RCE-proven page
(all: raw 8,647, script 8,524, S2 6,099):

| file | N | MS order (first 5) | zlib9 | sha256 |
|---|---:|---|---:|---|
| `p0_proven.html` | 2600 | 512,640,768,896,1024 | 3658 | `8b6706e5f2dcdba25d87f548ad0818b66882809805241a4a0015459a5bcc6b10` |
| `p1_pad768.html` | 2600 | 768,512,640,896,1024 | 3659 | `92ba67f2ddbf342e6f9d4652d04573299ec80fc6e41a978f123df3e1001e2e3d` |
| `p2_pad384.html` | 2600 | 384,512,640,768,896 | 3659 | `031ea2c5e28be3df6378f6d65db81127d81cf9a971e553aa61a41a539f755761` |
| `p3_n3000.html` | 3000 | 512,640,768,896,1024 | 3661 | `f1294c0e79e7cb7b7b04df9590ccc101200146ed42bd5bdfa583a21ea5913f73` |
| `p4_n3000_pad768.html` | 3000 | 768,512,640,896,1024 | 3662 | `46d3510d84e5e7483a126b89c422c728b3ed4122d58d95e53e725b1a16c9d379` |
| `srop_v5_min.js` (S2) | – | – | – | `2ba2f47fff08805fd0874b7b703ffaf384b9c61ea3bb21786d486e7e5853951e` |

These are the post-redaction values. The older `bf31f2f6…` / 3,680 pair is the
pre-redaction p0.

## 4. Pin drift (fix in `docs/two_phase_universal_20261108.md` §1)

Generator output, reproduced byte-exactly this session:

| file | doc says | actual (generator = shipped) |
|---|---|---|
| `bot/detector.html` (P2 ungated) | 1,487 zlib9, `0d66ce83…` | **1,489 zlib9**, `35f8698e…` |
| `bot/final_inline.html` (P2 ungated) | 3,988, `7aae63e7…` | 3,988, `7aae63e7…` |
| `bot/final_fallback.html` (P2 ungated) | (unpinned) | 2,151 raw / 1,024 zlib9, `245f4dc4…` |
| `payloads/two_phase/detector.html` (P3 gated) | 1,546 zlib9 in the reviewed version | **1,641 zlib9**, `ba063822…` |
| `payloads/two_phase/final_inline.html` (P3 gated) | 3,988 in the reviewed version | **4,068 zlib9**, `f8bba658…` |
| `payloads/two_phase/final_fallback.html` (P3 gated) | 2,151 in the reviewed version | **2,620 raw / 1,261 zlib9**, `f30cacb2…` |

The P2 and P3 pairs are different packages. The table in §1 of
`docs/two_phase_universal_20261108.md` mixed them; the header there now says
which pair each number belongs to.

Also: `scripts/two_phase/gen_two_phase.py` resolves inputs at
`../pixel72801_route2/oob/*`; those files are only under
`telegramandroidwidget/lab/pixel72801_route2/oob/`. Copy or symlink them next to the
script so repo-only regeneration works.

## 5. Cross-platform section to add (one table)

| | iOS 27 17e | iOS 15 6s | Sony 72929 | Pixel 72801 |
|---|---|---|---|---|
| `b` locus | tiny 976, compiled before spray | tiny 976, **in-spray hole** | Scudo 2560 | arena 352 (64 KiB slab) |
| OOB | `b+1,311,372` | `b+1,311,372` | `b+1,310,828` | `b+1,310,828` |
| spray | 2,600×957 (+pads) | 3,000×957 + hole H | 1,100×AB(2544) | two-sided 1800/415/2400 |
| safe probe | **no** (forge → teardown abort) | yes | yes (`SAFE…C`) | yes (`NOCORR`) |
| split | final-only + retry | probe H400 → final | detector → final | detector → final/fallback |
| proven | RCE_OK (1×) | RCE_OK | 5/5 forge + C2 | forge; endgame out-of-band |

## 6. Where the detail lives

* Geometry and knob semantics: `notes/ios27_reliability_20261108.md` §1.
* Crash-mode table (6 states, `.ips` presence, avoidability): §2.
* Device protocol + decision tree + accounting table: §4.
* Host validation log (13 runs + negative controls + Android pins): §7.
