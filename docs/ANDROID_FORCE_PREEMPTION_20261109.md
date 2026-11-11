# Android force/preemption — Binder nice inheritance (2026-11-09)

Status: **host-validated; device Phase 0 failed its σ gate (0.83–5.5 ms vs
≤10 µs); Phase 1 negative (0 markers in 25.2 min on 72989; 73029 partial
cancelled by the owner)**. No stock marker yet. The 2.2 min model below is
falsified — see ANDROID_FASTER_ESCAPE_20261109.md.

## The lever

A **synchronous** Binder transaction copies the caller's scheduler nice into
the receiving app thread for the duration of the call:

- `drivers/android/binder.c:3203` copies policy/nice for `!oneway`;
- `binder_proc_transaction` → `binder_transaction_priority` →
  `binder_set_priority` → `binder_do_set_priority` applies it with
  `set_user_nice` (line 1190), clamped by the **receiver's** `RLIMIT_NICE`;
- it is restored when the thread sends the reply (line 3520).

One-way transactions do not inherit. RT/SCHED_FIFO needs `inherit_rt`, which
a Java `Binder` does not set. Inheritance needs an idle pool thread at
dispatch; a saturated pool silently runs at nice 0.

The isolated process can set its own nice (subject to its `RLIMIT_NICE`) and
make the app's `record` thread run at that nice. A high-priority injector
thread can then preempt it inside the 11/14-instruction window.

## Measured on host (Linux 6.12 EEVDF, Ryzen 7600)

One pinned injector at `clock_nanosleep` with `PR_SET_TIMERSLACK=1`:

- 78,944 wakes/s at 12.7 µs; 10.5k/s with default 50 µs slack.
- As a wakee against a same-CPU target: **38,701 involuntary preemptions/s**
  at 20 µs; 35,453/s at 10 µs; 18,638/s at 40 µs. Target alone: 4/s.
- Implied cadence equals `1/period` within 3%: every wakeup preempts.

The 4.19 CFS condition is `wakeup_gran = calc_delta_fair(1 ms, wakee)`;
preemption requires the vruntime gap to exceed it. Same cgroup, peer nice 0 /
injector −20 → 11.5 µs gap; different cgroups → group entities, ~1–2 ms.

## Rate model

`P = r · w`, `w` = 11 instructions ≈ 3.5 ns; n capped by the 240 records/s
gate at 137–174/s:

| case | mean |
|---|---|
| ambient today (r=250–1000/s) | 35 min–2.3 h |
| injector, same cgroup (r=8.9k–16k/s) | **1.9–3.4 min** |
| injector, same cgroup, long period | 9 min |
| injector, different cgroups (r≈600/s) | ~50 min |

Two design constraints:
1. the preemption must hold until the gradient ctor (~30–100 µs), so the
   grower must be higher priority than the injector (grower −20, injector −10
   on another CPU, peers 0);
2. placement is steerable: `wake_affine_idle` (`fair.c:5879`) puts a
   sync-woken receiver on the sender's CPU when that CPU has only the sender.

Fallback if cgroups differ: the **Binder hammer** — app binder threads as the
preemptor, same cgroup by construction.

## Device result (Phase 0/1)

Measured on the Sony:

- Isolated: `2:cpu:/`, cpuset/schedtune `/top-app`, `uid_99084/pid_13833`.
- App: `2:cpu:/`, cpuset/schedtune `/top-app`, `uid_10346/pid_13721`.
- **CPU cgroup matches**; both `RLIMIT_NICE 40`; `setpriority(PRIO_PROCESS, tid, -20)`
  returns 0 in both; `Cpus_allowed 0-7`.
- Injector A/B (target CPU 0 nice 0; injector CPU 0 nice −20,
  `PR_SET_TIMERSLACK=1`, H=50 µs, P=12 µs):
  - off 2 s: `nonvoluntary=0`;
  - on 2 s: **27,318 nonvoluntary / 13,659 per second**, every wakeup
    preempts.
- Model (superseded): r=13.66k/s, n=160/s at N=6, w=3.5 ns → mean
  **130.7 s ≈ 2.2 min** treated the windowed injector rate as continuous;
  falsified (windowed ≈178 wakes/s per injector; `P_hold≈0`). Measured
  Phase 0 wall instead: per-CPU store σ = 0.83–5.5 ms; analyzer rates
  ≈1/7,247 s (background) and ≈1/40,289 s (foreground) at w = 4.1 ns
  (`device_results/v3/WALL_v3_72989_20261109.md`).

Phase 2 is not reached yet: the grower-mix + defineImage run died at cycle
100 (7.3 s) with a **late-peer double-realloc** in
`SkPathRef::growForVerb+412` (`Scudo ERROR: race on chunk header`), not the
RT pathref UAF. The 1–4 µs grower delay is below app-side Binder/JSON jitter.
Fix in progress: **0.5–2 ms grower delay**, sends synchronized to the
injector's sleep window, client off the injector CPU, N=6. No dispatcher
marker or `system(cmd)` yet.

## Phase 2 timing fix — PASS

With the grower delay at **0.5/1/2 ms** (not 1–4 µs), N=6, kamikaze peers,
`dl_rt_grower_mix.bin`, live 32/cycle defineImage spray:

```
239 cycles / 18.054 s = 13.2 cycles/s; trans=7/cycle; err=0
app + isolated alive
no growForVerb Scudo abort, no RT pathref UAF, no app crash
```

The late-peer double-realloc is removed. The force injector itself is proven
on-device (13,659 preemptions/s). Integration is the remaining harness issue:
the sleep-window flags are not observed by the peers, and the Frida CLI 25 s
script-load timeout unloads the CModule while injector threads run, killing
the isolated/app. Next: poll `sleep_flag[0..5]`, use ≤8 s chunks or a
persistent Frida session, keep the CModule pinned, then run Phase 2 for
30–60 min. The 2.2 min mean is falsified (see above); the expected time is
σ-dependent per ANDROID_FASTER_ESCAPE_20261109.md.

## Device-state note (2026-11-09)

The integrated injector run was blocked by the unobserved sleep flags and the
Frida CLI 25 s load timeout; the timeout-unload left the 72989 app not
starting (`pm path`/`dumpsys` empty, no `:widgets`), and the Sony then wedged
at `adb shell echo ok`/package-manager level. The USB path is clean (pyusb
`dev.reset()` succeeds), but adbd went `offline`; the known Sony Wi-Fi IP
`<LAN_IP>` was unreachable and ports 5555/5037 were closed. The phone
was **not powered off**: the owner unplugged and replugged the USB cable with
the screen locked (no PIN); that restored adbd. No power-cycle and no unlock
were needed. After adbd returned: install 72929 (`pm install -r -d`),
verify versionCode 72929/UID 10346/login, run **session-impact Phase A**,
reinstall 72989, run the load-safe harness v2 (control 5 min, force 30–60
min). No stock 72989 marker or `system` yet.

## Harness v2 (2026-11-09)

Load-safe force-integration harness in
`lab/artifacts_20261108/speed_force/harness_v2/`:

- **Synchronization:** peers + grower meet one `pthread_barrier_t` after
  pinning CPU/nice/timerslack + JNI attach + Parcel build; the coordinator
  publishes `t_release = now + 2 ms`. Peers send at `t_release`, grower at
  `t_release + gdelay` (0.5/1/2 ms). Injectors absolute-sleep to
  `t_release + gdelay − 50 µs` and run only around the grower; peers never
  wait on them. `sleep_flag[]`/`inj_state[]` are volatile observability only.
- **Runner:** persistent Frida sessions for app + isolated; one cycle per
  `setTimeout` (~60–80 ms), no long RPC and no CLI 25 s unload. `stop()` joins
  injectors; safe SIGTERM; JS self-stops if the host disappears.
- **Native driver:** `native/w2_native_driver.c` + `w2_native.h` implement the
  same cycle in C/JNI/Binder (`w2_native_start`), no adb/root/Frida at runtime.
- **Host evidence:** `host/run_all.sh` passes; `w2_sync_sim` 60 cycles,
  peers-first 25/25 at 0.5/2 ms, grower latency p50 10–30 µs, injector p95
  <3 ms; `test_cmodule.py` 40 cycles/280 transacts/0 errors; native driver
  `gcc -fsyntax-only` OK.
- **Device request:** control 5 min + force 30–60 min with
  `--stop-on-marker`; Ctrl-C/SIGTERM only, never `kill -9`. Queued after the
  72929 session Phase A (final `-r -d` run; downgrades are now forbidden) and
  72989 reinstall. Expected mean is σ-dependent; Phase 0 decides.

## Free speedup

Current run: 67 useful candidates/s (N=4, 16.7 cycles/s). The measured N=6
one-grower cycle (27.7 cycles/s, 9 records, the 35.2 s `og_meas_n6` run)
gives 166 useful/s = **2.4×** with the same payloads (the integrated force
run measures 20.8 cycles/s — different harness load). Use N=6 for the
instrumented run.

## Live test

`LIVE_TEST_force.md`:
- **Phase 0**: isolated and app `/proc/self/cgroup`, `/proc/self/limits`
  (`RLIMIT_NICE`), CPU set; `nonvoluntary_ctxt_switches` A/B.
- **Phase 1**: injector A/B with `PR_SET_TIMERSLACK=1`,
  `setpriority(PRIO_PROCESS, tid, -20)`, H=50–100 µs, P=12–200 µs; peers
  nice 0 pinned per CPU; grower −20.
- **Phase 1b**: Binder hammer if cgroups differ.
- **Phase 2**: W2 one-grower + grower mix + defineImage spray with the force,
  N=6, ≤60 min; expected marker/`system`.

The final chain can call `setpriority` from the isolated native payload; it
is stock (no adb/root/Frida). Phase 0 decides whether the isolated process has
the needed `RLIMIT_NICE` and whether it shares the app cgroup.

## Wall

The preemption must **start** between `libhwui+0x35c314` and
`+0x352168`/`+0x35173c`/`+0x352778` (11/14 instructions, 3–4 ns) and hold
~30–100 µs. No payload/op widens it; the only lever is the preemption-start
rate. Without the device-side priority lever the rate is 250–1000/s and the
mean is hours; with it, minutes if cgroups match, ~1 h if not.

## Claim boundary

Host measurements are Linux 6.12/EEVDF; the device is Android 4.19/CFS. The
Binder mechanism is source-verified for the device family, but Phase 0/1 on
the Sony is the arbiter. No stock marker, no reliability number, no session
read is claimed yet.
