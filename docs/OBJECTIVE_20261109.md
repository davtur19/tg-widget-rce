# Objective 2026-11-09 — stock Android/iOS RCE with session impact

## Target

**Primary target: the latest Telegram builds** — Android beta **73029**
(updated from 72989 on 2026-11-09 16:27) with the isolated `:widgets`
process, and iOS 27 stock 13.2. The older 72929/72889
app-level builds are **baseline/control and session-impact evidence only**;
they are not the deliverable. Users update, so the isolated second stage is
the real universal problem.

A real, unreported 0day chain that works from a normal Telegram widget on
stock Android and iOS, with no adb/root/Frida/downgrade in the final path:

- code execution in the Telegram app process (Android UID 10346 / iOS app);
- read the user's Telegram session (account/postbox/authKey) and exfiltrate it;
- fast (target 2–3 s), reliable (target ≥90%, measured), and portable across
  Android/iOS Telegram 13.x builds;
- no Android/system/other-app escape, no kernel/Android CVE, no known
  Telegram CVE.

**2026-11-10 owner rule (final):** the chain must be Telegram bug on
Telegram bug — the parser/CALA RCE in the widget engine, then Telegram's
own canvas Binder/UAF into the app. Android Binder is transport, not an
Android OS bug. No downgrade, no reboot, no Frida/adb/DB patch/root in the
final path; Frida is debug-only for lab observation. The session is read by
the app-side Telegram RCE, never by adb or a DB patch.

## Current ground truth (not a claim of completion)

- Parser 0day `ARG_SCOPE_END` (QuickJS-ng 0.17.0) is universal across
  Telegram 13.x Android/iOS; it is the entry.
- Android <=72929: parser RCE in the app process is device-proven
  (c2560s, 5/5 + 1/1, UID 10346, C2).
- Android 72989/73029: widget runs in the isolated `:widgets` process. The W2
  shared-`SkPath` chain has:
  - one-grower + kamikaze peers;
  - `dl_rt_grower_mix.bin` (RT pathref UAF structural fix);
  - byte-exact code-4 `defineImage` class-0x120 spray;
  - **app-process M3 marker on 73029 (2026-11-09 18:30, app survived):**
    `W2_DEFINEIMAGE_OK`, `system` as UID 10346, 477.3 s / 3,313 cycles /
    159,040 sprays / 0 errors; `reclaim 5,341/6,603 (81 %)`, `systemCalls 1`;
    config `inj-count 7` (CPU7 injector-free), arm CPU6, `gdelay 6.731 ms`,
    `win 7.5 ms`, single-reused-Parcel spray. **The trigger is harness-driven
    (Frida CModule in `:widgets`); a stock page cannot express it (no
    record/transact API, no threads/affinity, no truncated DLs, no raw image
    bytes, per-boot code pointers). The stock-page fallback is a closed
    negative.** Session stealer **0/2 dedicated runs**. New native paths:
    C1 shader, C3 cached `SkBlurMaskFilterImpl`, fast W2 2–13 s/double-unref
    steal, leak2 raw-premultiplied canvas (`ANDROID_ISOLATION_PATHS_20261109.md`).
    The deterministic app-process escape is still 0.
- Force/speed 2026-11-09: **Binder nice inheritance** is a real stock lever
  (synchronous transaction copies caller nice into the app record thread).
  Host-measured 38.7k involuntary preemptions/s, but the 1.9–3.4 min
  same-cgroup estimate is falsified (windowed, not continuous, injector
  rate; see ANDROID_FASTER_ESCAPE_20261109.md). Device Phase 0 measured
  per-CPU store σ = 0.83–5.5 ms (gate ≤10 µs); measured undercount rates
  ≈2.0 h (background) / ≈11 h (foreground) at w=4.1 ns. Phase 1: 0 markers
  in 25.2 min on 72989 (reclaim-order tombstone); 73029 partial cancelled
  by the owner. N=6 gives a 2.4× candidate-rate gain over N=4.
- Session impact **live-proven on 72929** (2026-11-09): `HELLO uid=10346`;
  `tgnet.dat` (5,176 B, `a5aa8871…`), `userconfing.xml` (5,550 B,
  `04719231…`), `cache4.db` (10,199,040 B, `9b87711a…`); DC1/2/5
  `authKeyPerm`; app alive; no root/Frida in the exploit path (adb only for
  the lab install). Rotation pending; raw files not committed. 72989/73029
  still requires the app-process escape; the 73029 APK
  (`lab/artifacts_20261108/escape_host/tg73029.apk`) is kept for harness
  verification — no reinstall (a 72989 reinstall would be a forbidden
  downgrade).
- Portable endgame 2026-11-09: **no deterministic stock chain**. The cubic
  write is a 24-byte one-object write whose Scudo header corruption prevents
  reclaim; `fIntervals` is finite-float clamped; no depth-2 pointer-chain
  gadget. Host-verified **invoker gadget** `libhwui+0x714928` executes
  `system(fake+0x10)` from a 24-byte fake object (slots `+0x50`/`+0x38`);
  byproduct 48-byte `SkDashImpl` spray removes the 248-byte premultiplied
  bitmap. Still preemption-bound; T1/T2/T3 queued.
- Alt-escape audit 2026-11-09: **no new isolated→app read/write/RCE**. New
  material: wallet pre-consent native address/BOC parsing (safe Rust,
  panic-at-worst), the Q0 16 MiB chunk envelope, and Binder
  `DUMP_TRANSACTION` OOM (DoS); `signal(5)` gate is real; canvas dims are
  64-bit. The wall is unchanged: the W2 host race is still the only path.
- iOS 17e: parser RCE proven once (msg 5725, `RCE_OK`). App version is still
  **13.2 (36535)**, so no app patch explains the failures. The chat was clean;
  v0 fails 0/3 and v10 0/20 (10+10 across both bots; 9/20 parse-time
  deaths). Root cause: v0 paints only the post-`b` spray
  (asc/desc free-list direction), while v10's 7.65 MB peak crosses the 8 MiB
  widget heap and its 5-round stage A approaches the 500 ms CPU slice.
  **v14** (`out/v14_stage_a.html`, varying pads
  `[2560,3072,2304,2816,2048,2560]`, 6.71 MB, 31–34 ms, model 40/40 at pre
  0/2000/4000 and 36/40 at 6000, 0 faults; 28/28 on the original matrix) is
  host-validated, but the live block failed: the K3p probe died at stage A
  and K3 v14 was 0/10 (6 parser deaths) — K4 certification (gated on K3
  10/10) was not run. v15: stage A executes 8/8, forges 0/8. v16: 16
  probes, 9 deaths, 7 SAFE, 0 `HIT>=0`. **v17's "page-side placement exhausted"
  is retracted:** its string pads (`repeat(960)` = 993 B) were in class 1008,
  not 976, so the drain was inert and the sweep only covered the view
  spray/hole position. The 8 MiB cap is per widget runtime, not per process;
  the 5725 forge had live holder bubbles above the payload. **v18** fixes the
  pad to `repeat(936)` = 969 B and warms up with 3–5 `v18_hold6600` bubbles;
  host model: 2+ holders → `HIT=545 LEN=327744`. **Controlled device forge
  2026-11-09 17:37 (17e, app alive):** six holders + prior h400 boots →
  `probe-h400` `HIT=545 LEN=327744 PH=12 VK=598 NT=6`; `final-h400` →
  `IOS_N1_OK base=0x106184000 printf=0x10b6ffc20 rt=0x134b94700
  D=0x135403c10 leak=FORGED`. The v18 h93 probes were 0/4 SAFE; the h400
  geometry is the page. **The 17:37 forge was confounded**: the chat still
  held the other operator's payload widgets (owner observation). The clean
  17e-only six-holder T=4 retest is **SAFE** (`HIT=-1`, measured 5936, 6s
  off), and the cold-relaunch block was 0/10. The six-holder-only design
  does not reproduce the forge; the winning state needs live payload
  bubbles or the incremental history (the app launched into a chat already
  holding them, holders in three waves, two prior h400 boots, crashes).
  No 100%/90% claim; no session time.
- iOS deterministic parser 0day 2026-11-09: `for (await using x of …)` in a
  class static block (non-async frame) → open `JSVarRef` into a dead
  `JS_CallInternal` alloca → deterministic cross-frame JSValue read/write
  (`RESULT HIT N=16 slot=9 before=1009 after=PWN9`, 10/10 host-proven, ASan
  stack-oob) + OOB NULL write. Shipped 13.2/36535; upstream issue #1902
  describes the missing check but has no PoC/primitive. **Device-proven
  2026-11-09 19:13, msg 5979** (controls `SAFE diag=num:24301`, app alive).
  Calibration: **CAL2/CALA1/CALA2B/CALA3 PASS** (M=22 slot + 64-bit payload;
  self-anchored; A−4 refcount; writers+pvalue); CALA4 died at `f()` (pvalue
  write geometry, recalibrating). The F4 generator chain gives device-proven
  full R/W (`F4W restored VLEN=24`); the stock net page read the live
  `login-tokens` (msg 6061) and the **full DB/auth-key window** (msg 17128,
  1,052,672 B; SQLite `header_ok`; 3 verified auth keys; `t1` partial
  2,470/6,599 B, overflow page 5,365 at 21,970,944; single-run `dt_accept`
  0.250 s / `dt_done` 0.288 s). **Full-chain N=10 (current page): chain
  execution 10/10, strict 3-key 5/10 (95% lower 0.2224); mean `dt_accept`
  0.268 s / `dt_done` 0.312 s**; the 5 strict failures are 2-key partial
  `t1`, not transport. **DB2 same-engine after the first window: 10/10
  official selectors/keys, strict complete-t1 2/3 (offset drift after
  relaunch)**; **stealth first-window N=10: 10/10, 95% lower 0.741; mean
  `dt_accept` 0.5603/0.5639 s, `dt_done` 0.6016/0.6026 s; crashes 0;
  visibility 0. The single-page multi-window full 3-key is live 1/1:
  2,101,248 B, `t1` complete, 10/10 official keys; offset drift (current
  18,182,144).** The file `spdb`/`sptk` path is the debug fallback.
  tdesktop/macOS QuickJS is in-process (tdesktop #2 best new deterministic);
  Web K is wasm-sandboxed (no session path). **iOS full chain is live; no
  Android stock completion claim.**
- Android G1 2026-11-09/10: F4/typed-array arbitrary R/W + native shapes
  (`js_free`/`syslog`/`abort`/`cfunc`) host 10/10; stock pages S0–G1b ready.
  The **live F4 front is a device negative**: the correct chat is
  **@<BOT_USERNAME> <BOT_ID> "test"** (chat_id <CHAT_ID> = @<TG_USERNAME>),
  not @<BOT_USERNAME>; S0/S1/S2 executed but `g1_front` died with **SIGSYS (31)**,
  no marker, widget chat **FLAG_SECURE** (bubble unreadable), and the app
  crashed on a RecyclerView stable-ID collision. **No-G1 and C5/C6 are
  closed negatives.** **Maps P1/endgame (Frida-forced) prove the app-side
  `~Bitmap` arbitrary read (64 KiB scan) and a clean `Execute`/`system`
  with the app alive (live `MAPS_PC_OK` + session files with hashes)**,
  but the stock trigger and 64-bit app leak are missing; the **Binder
  vehicle is
  host-proven** (`c` proxy/parcel,
  `mf.js_realloc` transact-shaped call, `dl_iterate_phdr` provenance,
  `BpBinder::transact` with no baked offsets; `s5_oracle`/`s5_scan`;
  **`clone(220)` host-proven but W1-unschedulable; the fork tree bypasses
  W1/W2 (children survive/transact); the 64-bit disclosure is the one fatal
  gate**), but the G1 front negative blocks the s5 device run.
  The **`g1_diag` F4 page is a live negative**: the engine dies SIGSYS
  before the text-limit validator (fresh mid; patching an existing mid reuses
  the cached page). The parser-only leak is a live negative (all
  294913/294912, no chunk); the **CALA Android port is host 5/5**
  (raw+native); the **arm64 leak-S is found** (`S=bits+0x3F0`; CALA
  anchor-complete in one session; `leak_s` pages 11/11); **leak-S live all
  chunks (high 0x74, low varies; self-compute); cleanup done; current
  @<BOT_USERNAME>→<TG_USERNAME> user id <CHAT_ID>**; combined page next; rt follow-on;
  the F4 front is **closed** (Scudo 1 MiB reuse memory-safety, not
  stack/seccomp); G-B is **closed by the real-object route** (direct/probe
  pages); the stock fork-tree trigger/endgame is host-ready
  (page 14,285/2,467), missing G-A/G-C/G-D/W2; the final stealth page
  host-ready/inert (1,700/678; G1–G7); the stock integrator host-ready
  (S0–S8; 8,687/3,756 + 7,540/3,339); then the Binder records.
- iOS session impact 2026-11-09: host-validated 4/4. Net/file payloads read
  `login-tokens` and the plaintext `postbox/db/db_sqlite` (auth keys in
  `t1.persistent`); v10/v0 payload hashes in
  `docs/IOS27_SESSION_IMPACT_20261109.md`. The F4 net page delivered the live
  full DB/auth-key chain (msg 17128); the complete `t1` overflow window and
  the full-chain rate campaign are pending.
  Correction: p0 hardcodes the all-zero AppGroup UUID, so the 5725 `rce.txt`
  proves the current-UUID payload family, not p0's S2; v14 session payload
  uses the current group/account.
- Leak hunt closed; no app heap/pointer leak. Deterministic leads: cubic
  neighbour vptr, RT UAF `List` pointer; portable endgame search running.

## Workstreams

| stream | owner | deliverable |
|---|---|---|
| iOS stage-A fix/reliability | v10fix agent | page that reaches stage A on device; host model + live matrix |
| iOS clean-chat v0 control | P1 operator | valid v0 control, then v10 attempts |
| iOS session impact | new agent | stock ROP/payload reads account/postbox/authKey and exfiltrates |
| Android W2 force/leak/speed | speed agent | force the C=1 write, new leak/oracle, or faster deterministic trigger |
| Android alternative escape | alt-escape agent | new host surface → app read/write/RCE or session read |
| Android deterministic endgame | portable-endgame agent | known-address endgame for cubic/RT UAF |
| Android session impact | new agent | app-level session stealer on 72929/72889 and post-escape 72989 |
| review/critic | after candidates | independent verification, claim-vs-evidence, fixes |

## Acceptance

- Final payload is a stock widget; adb/root/Frida are lab-only.
- Session proof: read a session file/authKey and exfiltrate it; include hash/
  contents, not just a command echo.
- Reliability: point estimate + 95% lower bound (one-sided Clopper-Pearson:
  30/30 → 0.905, 60/60 → 0.951; the iOS certification docs quote two-sided
  bounds: 30/30 → 0.884, 36/36 → 0.903 — state the convention wherever a
  bound is quoted); no >95% claim without the run count.
- Speed: measured from widget render to proof.
- **Both platforms:** after the session read, report the **success rate %** and
  **execution time** with the run count. Android: fresh-app/engine attempts,
  `sendWidget`→session capture; iOS: fresh-app/engine attempts,
  widget-send→LAN capture. Include the 95% one-sided lower bound and the
  mean/median; no session claim without the table. **Success is counted only
  when the session is captured, the app is alive with no crash/tombstone,
  and the exploit is not blatantly visible (no F4SF/debug text; benign
  widget body; screenshot check). Debug-page rates are not the final
  metric.** **Chain first:** the table is the last step; no rate/time work
  until the full chain produces the session on the current build (Android
  73029 / iOS 13.2/36535).
- Portability: document per-build offsets/limits; test at least the Sony,
  Pixel and a second Android/iOS target where available.

## Rules

- **No downgrades.** Never install an older Telegram version on a device
  again (`adb install -d` and older APKs are forbidden). The 72929/72889
  session proof is archived evidence (the 2026-11-09 09:43 session Phase A
  was the final `-r -d` run; it predates this rule); the device stays on
  the latest build (currently 73029). If a test would require an older
  build, do not run it.
- **No reboots.** Rebooting the iPhone invalidates the host pairing and shows
  a Trust dialog that blocks the tunnel and ignores synthetic HID. For link
  problems use the USB cable replug / `dev.reset()` recovery only; a fresh
  state is app relaunch + chat cleanup, never `diagnostics restart`.
- **No app uninstall/reinstall without explicit owner approval.** The owner
  vetoed the fresh-AppGroup reinstall (2026-11-09). Destructive device
  actions (uninstall, data wipe) are forbidden unless the owner says to do
  them.

- No fake results, no counting contaminated or instrumentation-assisted runs
  as stock evidence.
- Clean the chat/messages before every attempt; record ids.
- Keep the repo updated with current status, tools and exact artifacts.
- The review/critic gate runs before any “done” claim; it must verify every
  link and fix the problems it finds.
