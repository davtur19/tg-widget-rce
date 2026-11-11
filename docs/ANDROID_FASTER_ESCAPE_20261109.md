# Android faster escape — corrected model and v3 (2026-11-09)

Status: **2.2 min model falsified; v3 targeted-hold design ready; device Phase 0
running.** No stock marker yet.

## Why 2.2 min was wrong

The earlier model treated the injector's 13,659 involuntary-preemption
rate as continuous. On device it is a **windowed** rate: the injector is
active ~529 µs per 48 ms cycle (~1.1 % duty), so the time-averaged rate is
~178 wakes/s per injector. Worse, the 50 µs hold cannot span the 0.5–2 ms
grower delay, so a window hit resumes the peer into the still-live array and
the gradient ctor overwrites it: `P_hold ≈ 0`.

| run | wall | cycles | cycles/s | iwakes | iwakes/s | hits |
|---|---:|---:|---:|---:|---:|---:|
| control | 371.4 s | 7,800 | 21.0 | 0 | 0 | 0 |
| force | 506.5 s | 10,525 | 20.8 | 539,725 | 1,066 (windowed; 178/s avg) | **0** |

Corrected useful fraction `f = P(align)·P(hold)` ≈ 0.003–0.08 →
**30 min–15 h**, consistent with the 0-hit 506 s run.

## v3: one aimed hold per peer CPU

- Arm at the measured C=1 offset: `arm = t_release + δ_p50 − wake_late`.
- One **continuous busy hold** at nice −20 from the C=1 window until after
  the grower's draw (`gdelay + T_grow + margin`; v3 extends to
  `grower_done`, cap +5 ms). No H/P pulsing.
- Priority ladder: peer client −10 (app thread inherits −10), injector −20,
  grower −20 on CPU 7. 4.19 source verified: 6 ms latency, 0.75 ms minimum
  granularity, 1 ms wakeup gran, 3 ms sleeper credit.
- Peers on A55 in-order CPUs 0–3 (the 11-instruction window is real there);
  CPUs 4–5 are OoO bonus candidates; N=4 for calibration.
- `P = 0.4·w/σ`, `w = 4.1 ns` (A55), σ = per-CPU store-time sd:
  - σ = 5 µs → **~38 s**;
  - σ = 2 µs → **~15 s**;
  - a coherence-widened 50 ns window → **~3 s**.
- The 240 records/s gate is **per `WidgetSandboxBackend`**; K=2–4 widget
  sessions multiply the candidate rate (start K=2 with a `cycle/2` phase
  offset).
- The 1 ms injector idle-poll keeps peer CPUs out of deep idle; force-run
  peer-last lateness p50 was 34 µs vs 200 µs in the control.

The decisive unknown is **σ**, measured in Phase 0. If σ ≈ 100 µs (the v2
six-thread jitter), the wall moves back to send/dispatch; next levers:
persistent worker pool, record-entry split, Binder funnel.

## Test-only deterministic (not stock)

`runner/w2_det_hold.js` marks the kamikaze binder thread at
`growForVerb.onLeave` (between the `fArray` load and the caller's store) and
sleeps 5 ms there; the grower runs during the sleep and the store lands on
the gradient. This proves undercount → reclaim → fake-object `system()` in one
cycle, but requires Frida in the app.

## Harness fixes

- Frida 17.17 removed the bundled Java bridge; any plain `Java.perform` script
  dies. The v3 runner applies `frida_legacy_compat.auto_patch()`.
- `iwakes` is a windowed count, not a continuous rate.

## Live test

`LIVE_TEST_v3.md`: Phase 0 calibration (inj off, 2–5 min; per-CPU σ/p50),
Phase 1 targeted hold 30 min, Phase 2 aim sweep, Phase 3 K sessions, Phase 4
deterministic endgame. Pass/fail per σ.

## Artifacts

`lab/artifacts_20261108/speed_force/faster_escape/`:
`REPORT_faster_escape.md`, `LIVE_TEST_v3.md`, `src/w2_driver_cmodule_v3.c`,
`host/v3_sim.c` (9/9), `runner/w2_runner_v3.py`,
`runner/w2_app_hooks_v3.js`, `runner/w2_det_hold.js`,
`tools/analyze_c1.py`, `calc/model.py`.

## Device force3 — 73029 (2026-11-09)

The v3 targeted hold ran 303.7 s on the updated beta 73029:

```
4,973 cycles (16.38/s) · 24,865 trans (5.0/cycle) · 159,136 sprays · err 0
C=1 51,565 (169.8/s) · growths 4,411 · growTotal 600,444
ctorGrad 9,946 · gradFree 6,580 · dtorGrad 8,083
reclaim 1,911 · unrefOnFreed 363 · systemCalls 0 · marker 0
c1_delta p50 ≈1.17 ms · p90 5–12 ms
```

**The 15–38 s model failed**: the measured store/send jitter is ms-scale,
not µs. The run produced no `system`/marker. `unrefOnFreed 363` suggests the
C=1/free path is occurring, but the endgame does not land; v4 must diagnose
the real free/cleaner timing and either synchronize the spray or state the
wall.

## Claim boundary

No stock `41414141`/`system` marker. The corrected mean is σ-dependent
(seconds to hours); Phase 0 decides. The deterministic hold is Frida-only.
