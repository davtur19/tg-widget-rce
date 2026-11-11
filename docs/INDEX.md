# Documentation index

This tree has two kinds of pages: current runbooks and dated research notes.
Start with the first group. The dated notes are evidence; they are not
maintained as current status.

**Status note:** the findings in the dated notes were live on the tested pins.
The current Telegram builds include the fixes; the bugs are now n-days. The
"no fix" and "unreported" wording in the dated notes describes the state at
the time of the research, not the current state.

## Current

| Page | What |
|---|---|
| [`PAYLOAD_CHAIN.md`](PAYLOAD_CHAIN.md) | End-to-end chain, delivery, evidence and verification checklist. |
| [`CRITIQUE_20261108.md`](CRITIQUE_20261108.md) | Prioritized audit, claims vs evidence, residual risks. |
| [`ARTIFACTS_20261108.md`](ARTIFACTS_20261108.md) | Persistent lab artifacts manifest, token location, current status. |
| [`HOST_BINDER_ESCAPE_20261108.md`](HOST_BINDER_ESCAPE_20261108.md) | Isolated-process host Binder results: boundary, races, DoS, no app-level escape. |
| [`IOS27_V13_20261109.md`](IOS27_V13_20261109.md) | iOS 27 17e stage-A root cause, v13 page, K0–K4 certification matrix. |
| [`IOS27_V14_20261109.md`](IOS27_V14_20261109.md) | v14 varying-pad stage-A page, probe, and certification matrix. |
| [`IOS27_V15_20261109.md`](IOS27_V15_20261109.md) | v15 hole-reuse stage-A page, scattered-free-list diagnosis, W0–W9 matrix. |
| [`IOS27_V17_20261109.md`](IOS27_V17_20261109.md) | v17 placement wall: no two page-owned blocks 1,343 apart; fingerprints. |
| [`IOS27_V18_20261109.md`](IOS27_V18_20261109.md) | v18: the v15/v16/v17 string pad is class 1008 (inert); 8 MiB cap is per widget runtime; multi-bubble holder warm-up + hole-reuse payload. |
| [`IOS27_PARSER_0DAY_20261109.md`](IOS27_PARSER_0DAY_20261109.md) | Deterministic parser 0day: `await using` in a class static block → cross-frame JSVarRef R/W + OOB NULL write; device-proven; CAL2/CALA1/CALA2B/CALA3 PASS, CALA4 recalibrating. |
| [`IOS27_F4_HEAP_20261109.md`](IOS27_F4_HEAP_20261109.md) | F4 generator OOB: device-proven full R/W, frontstop, live `login-tokens` (msg 6061) and DB/auth-key window (msg 17128); **first-window stealth N=10 10/10 (95% lower 0.741; mean 0.5603/0.5639 accept, 0.6016/0.6026 done; crashes 0; visibility 0)**; **single-page multi-window live 1/1 (2,101,248 B, `t1` complete, 10/10 keys; offset drift)**. |
| [`IOS27_WEB_WIDGET_20261109.md`](IOS27_WEB_WIDGET_20261109.md) | Web K widget isolation: QuickJS-WASM worker, shadow root, wasm sandbox; no session path. |
| [`TDESK_MAC_ISOLATION_20261109.md`](TDESK_MAC_ISOLATION_20261109.md) | tdesktop/macOS widget QuickJS in-process; exact-source verification; ranking. |
| [`ANDROID_PORTABLE_ENDGAME_20261109.md`](ANDROID_PORTABLE_ENDGAME_20261109.md) | Deterministic-endgame verdict, invoker gadget, dash spray variant, T1–T3. |
| [`ANDROID_FASTER_ESCAPE_20261109.md`](ANDROID_FASTER_ESCAPE_20261109.md) | Corrected force model, v3 aimed-hold design, σ gate, live test. |
| [`ANDROID_M3_STOCK_20261109.md`](ANDROID_M3_STOCK_20261109.md) | 73029 app-process M3 `system` marker (Frida CModule in `:widgets`); stock-page fallback closed negative; G1 needed. |
| [`ANDROID_ISOLATION_PATHS_20261109.md`](ANDROID_ISOLATION_PATHS_20261109.md) | C1/C3/C4/fast W2/leak2/maps; **maps P1/endgame (Frida-forced app-side arbitrary read + clean Execute/system; live MAPS_PC_OK/session files — debug only)**; **F4 front closed (Scudo 1 MiB reuse memory-safety, not stack/seccomp)**; no-G1/C5 closed; **Binder vehicle host-proven, clone 220 W1-unschedulable, fork tree bypasses W1/W2; G-B closed by the real-object route (direct/probe pages)**; **parser-only direct-call host 10/10; CALA port host 5/5; arm64 leak-S found (S=bits+0x3F0; CALA anchor-complete; leak_s 11/11); leak-S live all chunks (high 0x74, low varies; self-compute); cleanup done; current <BOT_USERNAME>→<TG_USERNAME> user id <CHAT_ID>; combined page next; rt follow-on; stock fork-tree trigger/endgame host-ready (page 14,285/2,467), missing G-A/G-C/G-D/W2; final stealth page host-ready/inert (1,700/678; G1–G7); stock integrator host-ready (S0–S8; 8,687/3,756 + 7,540/3,339)**; **G-A disclosure page host 5/5 (base/rt/alloc); live msg 17220 SIGSYS31 at frame exit, GA line unobservable (console.log not forwarded), DOM-text fix pending; selfcala page 1,973 zlib9 held; walls: 8-byte write, callable rd/wr, size 5,282 zlib9, libbinder base**; lab chat clean. |
| [`ANDROID_STOCK_CONCURRENCY_20261110.md`](ANDROID_STOCK_CONCURRENCY_20261110.md) | Stock page cannot create the app-side second transact for C3/W2/leak2/maps: one recorder, two-way callbacks, per-session z0. Static negative + 27-check verifier. |
| [`ANDROID_73039_20261110.md`](ANDROID_73039_20261110.md) | New beta 13.2.2/73039: parser 0day patched in **both** layers (async-bit check + uncatchable "suspending opcode in a normal function"), 7,713/7,735 engine functions identical, JNI arbiter/filterPixels moved to libtmessages, app-side file/parser/WebView/normal-API UAF all closed; no stock entry. Sony restored to 73029. |
| [`ANDROID_FREETAIL_PIVOT_20261110.md`](ANDROID_FREETAIL_PIVOT_20261110.md) | 73029 free-tail pivot: `C[8]` heap-block leak (no `free@plt`, block stays allocated), 0x4000 block-resident ctx patched by the page's 8-byte store, live `FT_A9`/`FTR1 17`, stack-gap wall (2,808 B vs 4,072 B) and 13,408 B fix; oneway `TF_ONE_WAY` transacts; in-block `lb`/`bp` oracle (`gProcess=lb+0xbeb48`); transact page next. |
| [`production_widget_forward_inline_20261110.md`](production_widget_forward_inline_20261110.md) | Production forward/copy/inline results: `sendWidget` protected, all forward/copy methods 400, inline widget `INPUT_MEDIA_WIDGET_NOT_ALLOWED`, `sendSharedWidget` cross-chat protected. App 73029 widget chats FLAG_SECURE. |
| [`ANDROID_DECODER_HUNT_20261109.md`](ANDROID_DECODER_HUNT_20261109.md) | Decoder topology: widget decode in `:widgets`; libwebp/PNG DoS; no app-process escape. |
| [`OBJECTIVE_20261109.md`](OBJECTIVE_20261109.md) | 2026-11-09 objective, ground truth, acceptance, campaign rules. |
| [`ANDROID_SESSION_IMPACT_20261109.md`](ANDROID_SESSION_IMPACT_20261109.md) | Android session stealer; 72929 live Phase A proof; 72989/73029 precondition; bot-return stealth variant documented. |
| [`ANDROID_FORCE_PREEMPTION_20261109.md`](ANDROID_FORCE_PREEMPTION_20261109.md) | Binder nice-inheritance force; host/device preemption measurements. |
| [`ANDROID_BUILD_PROCESS_DETECTION_20261109.md`](ANDROID_BUILD_PROCESS_DETECTION_20261109.md) | Runtime app-level vs isolated build detection after parser RCE. |
| [`ANDROID_ISOLATED_PERSISTENCE_20261109.md`](ANDROID_ISOLATED_PERSISTENCE_20261109.md) | 72989 isolated-process persistence measurements; Frida CLI runner note. |
| [`IOS27_SESSION_IMPACT_20261109.md`](IOS27_SESSION_IMPACT_20261109.md) | iOS session ROP, paths, payloads, host validation; live F4 DB/auth-key chain; stealth multi-window; bot-return stealth idea documented. |
| [`SECOND_STAGE_AUDITS_20261108.md`](SECOND_STAGE_AUDITS_20261108.md) | Source and UI/WebView/service audits: negative app-process escape; wallet BOC DoS; blind signing. |
| [`KERNEL_CVE_COVERAGE.md`](KERNEL_CVE_COVERAGE.md) | Kernel/Binder CVE matrix, measured lab results, negative 0day search. |
| [`PAYLOAD_HASHES.json`](PAYLOAD_HASHES.json) | Current post-redaction sizes and SHA-256 pins. |
| [`STATE_20261108.md`](STATE_20261108.md) | Campaign state at 2026-11-08. |
| [`common/00-index.md`](common/00-index.md) | Engine, delivery, answer channel, devices, markers, glossary. |
| [`two_phase_universal_20261108.md`](two_phase_universal_20261108.md) | Two-phase design. Section 15 is the withdrawn desktop gate. |
| [`PLAN_two_phase_20261108.md`](PLAN_two_phase_20261108.md) | Two-phase plan and corrections. |
| [`HANDOFF_desktop_gate_20261108.md`](HANDOFF_desktop_gate_20261108.md) | Desktop gate withdrawal. |
| [`HANDOFF_ios27_two_phase_20261108.md`](HANDOFF_ios27_two_phase_20261108.md) | 17e two-phase handoff. |
| [`HANDOFF_ios27_reliability_20261108.md`](HANDOFF_ios27_reliability_20261108.md) | 17e reliability and hash-provenance note. |

## Per-ID

| Page | What |
|---|---|
| [`../VULNS.md`](../VULNS.md) | Master RCE index. |
| [`../vulns/0day-2-RCE-PARSER-SCOPE/README.md`](../vulns/0day-2-RCE-PARSER-SCOPE/README.md) | Parser 0day, routes. |
| [`../vulns/nday-1-RCE-V7-RGX-1827/README.md`](../vulns/nday-1-RCE-V7-RGX-1827/README.md) | v7 / #1827 n-day. |
| [`../vulns/nday-2-RCE-VARREF-1865/README.md`](../vulns/nday-2-RCE-VARREF-1865/README.md) | #1865 n-day. |

## Delivery and tools

| Page | What |
|---|---|
| [`../bot/README.md`](../bot/README.md) | `sendWidget`, `sendSharedWidget`, answer servers, chunks. |
| [`common/02-widget-delivery.md`](common/02-widget-delivery.md) | Delivery channels, standard/beta bases, sharing. |
| [`common/03-the-answer-channel.md`](common/03-the-answer-channel.md) | `answerWidgetQuery`, `data`, limits. |
| [`common/tools/README.md`](common/tools/README.md) | DB rewrite, Postbox, harness tools. |
| [`instrumentation/ios17e/`](instrumentation/ios17e/) | 17e USB, DDI, navigation, OCR, sweep. |
| [`instrumentation/ios17e/RUNBOOK_20261109.md`](instrumentation/ios17e/RUNBOOK_20261109.md) | 17e USB recovery, instrumentation, chat-scroll limitation, P1 run sheet. |
| [`instrumentation/ios6s/`](instrumentation/ios6s/) | 6s Frida, Wi-Fi, screenshots. |
| [`c2/`](c2/) | c2560s server, implant and runbooks. |

## Dated research notes

The remaining `docs/*.md` files are dated engineering notes. They are kept for
provenance: audit logs, negative results, loader and startup research, media
parser work, and non-RCE findings. Read them with their date. If a dated note
contradicts a current page, the current page wins.

Non-RCE findings are indexed in [`../NON_RCE.md`](../NON_RCE.md). Their
fixtures are in [`../non-rce/`](../non-rce/).
