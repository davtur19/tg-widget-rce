# PLAN — two-phase universal 0day (detector → host → pre-calibrated final)

Status: **host-validated 2026-11-08 17:xx** (P3); device runs pending
(Sony → Pixel → Samsung Tue; 17e and 6s on the iOS track). Full design,
numbers and failure modes: `docs/two_phase_universal_20261108.md`.
Payloads: `payloads/two_phase/`; server/generator: `scripts/two_phase/`.
Handoff: `docs/HANDOFF_ios27_two_phase_20261108.md`.

Post-run corrections: the gated P3 Android pair is 9,185 B (detector 1,641
zlib9, final 4,068), not 9,176/1,546/3,988. The 9,176/1,489/3,988 numbers are
the P2/ungated pair in `bot/`. The iOS 27 safe detector is 1,581 raw / 804
zlib9. The 8,647/3,680/`bf31f2f6…` pin is pre-redaction; current is
3,658/`8b6706e5…`. The Android beta final is a 9,190/4,071 rebuild with the
beta package path and hit `HF ERR NA` on the Sony; it is not an RCE. On beta
**72979** the widget runs in isolated UID 99017 (`u:r:isolated_app:s0`): the
v3/c2560s stage A still hits (`ABLEN[599]=327744 ATT=1`) but the endgame stops
at `HF ERR NOANCHOR VNC=0 VO=-1`, and the app-data write and C2 are blocked.
The current beta **72989** keeps the same model at UID **99024**; PING works,
detector `el=55ms`, v3 final 9,190 / 4,081 zlib9, same `HF ERR NOANCHOR`, no
`n1`/C2. App-level proof needs 72929/72889 or an isolated-process escape. See
`docs/CRITIQUE_20261108.md`.

## Objective

One open of a chat → **2–3 s** → code execution, with **one report format and
one host mapping** across Android and iOS, per-platform final payloads. The
direct one-message final is the hot path; the detector is the universality /
fallback layer. Reliability first: a miss is a safe `HIT=-1`/`NOCORR`, never a
self-inflicted crash from our own record.

## Phases

1. **Detector** (per-platform page, one P3 report):
   * Android route2: forging detector, 9,185 B / 1,641 zlib9 (safe teardown
     on Android); 2-attempt H sweep, GC re-arm. The 9,176 / 1,489 page is the
     P2/ungated reference in `bot/`.
   * iOS 27: **safe handshake**, 1,581 / 804; 256 x `Uint8Array(957)` sample +
     compile `f` **without calling it**, P3 echo of the calibrated 5725
     geometry; no forge (a forge aborts at teardown).
   * iOS 15: device-proven `at_probe_h400.html` (6,801 / 1,050), marker relayed
     to P3 by `relay_ios15.py`.
   The report is `"P3"+62 hex` = 31 bytes = **64 chars** (request-data limit):
   platform/chain/flags, hit/att/sel/n/hd/cb, DPR/screen/lang/tz, elapsed,
   padM, N, SZ, UBn, UBsz, `t_rep`. Legacy P2 still parses.
2. **Host** (`bot_two_phase.py`): parse P3/P2 → `devices.json[uid]` platform /
   `last_m` / `prefer` → ACK `K` → `sendWidget` height 50, allow_queries,
   background_query, 3 s cooldown.
   * platform 1: hit → `final_inline.html`; miss → `final_fallback.html`
     (`E0..E7`, background ~37 s / taps ~5–7 s).
   * platform 2: hit → `ios15/at_final_h<sel>.html`; miss → next H probe
     (400 → 200 → 64 → 500).
   * platform 3: safe/hit/miss → `final_ios27[_m<last_m|padM>].html`; a safe
     miss re-sends the final after 3 s.
3. **Final** (pre-calibrated):
   * Android: the gated 9,185-B page, 4,068 zlib9, inline endgame. The beta
     package rebuild is 9,190 / 4,071; the repo page writes the release path.
   * iOS 27: canonical `final_ios27.html` = the msg-5725 `ss8_final`
     (**8,647 / 3,680**, sha `bf31f2f6…`; pre-redaction), compile-first self-sweep over 15
     pads, inline 6,099-char srop; 15 pad-first variants (8,647 each,
     3,680–3,684 zlib9). The self-sweep is the stale-geometry fallback.
   * iOS 15: `at_final_h<H>.html` (6,801 / 2,528; attribute variant,
     host-validated/device-pending); fallback `srop.js` (6,011 / 2,596) +
     `ls_final_h200_2036.html` via the DB-rewrite path.

## Invariants

* Android: detector and final are page-equal (9,176 B) and share the
  byte-identical stage A; only stage C differs. Host experiment: a same-length
  dummy stage C forges exactly like the endgame.
* iOS 27: the detector is **not** page-equal and does not certify the hit.
  This is deliberate: a forging detector cannot survive teardown. The final's
  pad self-sweep is the measurement; `last_m` only chooses a pad-first variant.
* The JS fingerprint is thin (screen/DPR/locale/tz); UA/platform are constant,
  so `devices.json` is the authoritative platform table.

## Device sequence and acceptance

| device | payloads | acceptance |
|---|---|---|
| Sony XQ-BT52 beta 72929 (first) | `--pkg beta` detector/final, `chunks_beta/` | `DET HIT … R=P3…` then `S1 ABLEN… \| HF OK T1=…`, `T1_final − T0_detector ≤ 3 s`; first route2-on-Sony datum |
| Pixel 9 release 72801 | release detector/final, `chunks/` | same markers; route2 device-proven here |
| Samsung (Tue) | same bytes; `--pkg` only if the proof path differs | first-open universal run; report DPI/screen/anchor |
| iPhone 17e 27.0 24A437 | `ios27/detector_ios27.html` → `ios27/final_ios27_m768.html` (or canonical) | `DET SAFE P3…` then `RESULT … HIT=545 LEN=327744 PH=12 VK=598`; `rce.txt` = 7 B `RCE_OK\n` sha `704984d9…`; app alive; timed run for `T0_final − t_rep` |
| iPhone 6s 15.8.8 | `ios15/at_probe_h400.html` → relay P3 → `ios15/at_final_h400.html` | `HIT=545 LEN=327744 PH=36 VK=598` then `RCE_OK`; fallback `srop.js`; H order 400→200→64→500 |

For a known 17e chat, sending the canonical final directly is the 2–3 s hot
path; the detector handshake adds one Telegram delivery. If the final misses
(safe `HIT=-1`), re-send after 3 s or try another `_m<M>` variant; the old
univA probe is diagnostic only.

## Open items

1. First device datum for the 9.2-KB Android inline page shape (the gate for
   the 2–3 s path; `s2s9`/`s2s10` were safe `NOCORR` on the Pixel with the
   older stage A).
2. 17e two-phase device run + timed final (`T0_final − t_rep`, `T1−T0`); the
   RCE itself is proven (msg 5725).
3. 6s attribute `at_final_h400` device run; the `srop.js` path remains the
   proven fallback.
4. A ≤1,024 B (or two-answer) Android endgame would remove the inline page;
   the count-primitive chain (~2–2.5 KB minified) is the route.
