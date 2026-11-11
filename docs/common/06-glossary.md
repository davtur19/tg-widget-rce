# Glossary and name mapping

The engineering logs used short internal names. The user-facing files use
descriptive names. This page maps one to the other.

## Terms

| Term | Meaning |
|---|---|
| **widget** | A Telegram message that carries HTML/JavaScript and is rendered by litehtml + QuickJS-ng. |
| **0day** | A bug that is not publicly reported and has no public fix. Here: the parser `ARG_SCOPE_END` bug. |
| **n-day** | A bug with a public report or fix. Here: QuickJS-ng PR #1827. |
| **QuickJS-ng** | The JavaScript engine Telegram uses for widgets. Version 0.17.0-era in the tested builds. |
| **litehtml / twidget** | Telegram's HTML/CSS renderer for widgets. |
| **AB** | `ArrayBuffer`. |
| **UB** | A `Uint8Array` buffer used to hold ROP data. The name comes from “user buffer” in the stage-B code. |
| **TRIG** | The typed array whose finalizer triggers the fake `js_free` call in the endgame. |
| **D** | The data pointer of the forged `ArrayBuffer` view. |
| **V / VAB** | The huge `Uint8Array` view and its backing `ArrayBuffer` after stage A. |
| **ctx** | `JSContext`. |
| **rt** | `JSRuntime`. |
| **js_free** | The runtime's free function pointer (`rt->mf.js_free`). Redirecting it to `system` or `printf` is the endgame. |
| **GOT / PLT** | The ELF tables used to resolve imported libc functions at runtime. |
| **arena** | QuickJS's internal allocator. On Android it uses 64 KiB `mmap` slabs; on iOS, 4 KiB blocks. Arena memory is not MTE-tagged. |
| **Scudo** | Android's native allocator. Under MTE, its primary chunks are tagged. |
| **class-N** | A size class. `class 64` means a 64-byte allocation. `c2560` means a 2,560-byte spray class. |
| **MTE** | ARM Memory Tagging Extension. Checks pointer tags on `PROT_MTE` pages. |
| **MIE** | Apple Memory Integrity Enforcement. The iOS equivalent; the app must opt in. |
| **PAC** | ARM Pointer Authentication. Not relevant to the arm64 app code used here. |
| **TBI** | Top Byte Ignore. On non-MTE memory, the top byte of a pointer is ignored. |
| **OOM** | Out of memory. The engine has a fatal OOM policy unless a getter bypass is installed. |
| **stage A** | The part of the payload that triggers the bug and forges the oversized `ArrayBuffer`. |
| **stage B** | The part that turns the oversized view into arbitrary read/write and resolves `ctx`/`rt`. |
| **stage C** | The marker/reporter stage. |
| **endgame** | The final step: redirect `js_free`, call `system`, `printf`, or a ROP chain. |
| **inline endgame** | The endgame is in the same HTML page as stage A. |
| **out-of-band endgame** | The endgame is fetched through `TelegramWidget.request` after stage A. |
| **H** | The hole index in the iOS spray (which of the freed blocks the vulnerable bytecode reuses). |
| **HN** | The number of consecutive holes freed. |
| **PH** | The phase of the victim sweep in stage A (0, 4, 8, …). |
| **VK** | The victim index that hit. |
| **NT** | The number of phase/victim attempts before the hit. |
| **C=34** | The number of float terms in the iOS trigger function; it fixes the bytecode size to 957 bytes and the Apple tiny class to 976. |
| **SZ=957** | The requested size of the sprayed iOS blocks. |
| **N=3000** | The number of iOS spray blocks. |
| **ABLEN** | `ArrayBuffer.byteLength`, the forged length. The expected value is 327,744. |
| **VLEN** | The length of the `Uint8Array` view over the forged buffer. It equals `ABLEN` when the forge worked. |
| **HF** | Literal prefix of the Android endgame markers (`HF READY`, `HF OK`, `HF HF OK`). It is not an abbreviation used in the code; treat it as an opaque marker. |
| **S1** | Literal prefix of the stage-A marker. |
| **t7 / t4** | Postbox table names. `t7` holds message objects; `t4` holds history rows. |
| **Postbox** | Telegram's iOS storage layer. |
| **AppGroup** | The shared iOS container that holds `telegram-data`. |
| **DDI** | Apple Developer Disk Image, needed for developer services on iOS 17+. |
| **DVT** | Apple's Developer Tools service (used by `pymobiledevice3` for screenshots/launch). |
| **AFC** | Apple File Conduit, the file service used over USB. |
| **C2** | Command and control (the server/implant), unless written “C2 (bug)”, which is the separate `update_var_htab` parser finding. It is not an RCE; see `NON_RCE.md`. |
| **N1** | `0day-1-SCOPE-OOM`: an older OOM-gated QuickJS parser bug (`push_scope`). Not used as the carrier; it is iOS-fatal and layout-fragile. |
| **C1 (bug)** | `cpool_add` OOM → 16-byte write before the constant pool. Not used. |
| **F1 / FR / LT / N2** | Other QuickJS/litehtml findings. Negative or DoS-only. See `NON_RCE.md`. |
| **v7 / #1827** | `nday-1-RCE-V7-RGX-1827`: the public RegExp bytecode n-day. |
| **v3** | A stage-A revision used by `0day-2-RCE-PARSER-SCOPE/STAG` (Scudo-string GC priming, tagged-int record). |
| **c2560s / c4096s** | `0day-2-RCE-PARSER-SCOPE/XTAG` widget families. The number is the spray class (2,560 or 4,096 bytes). |
| **c2560q / c2560r** | Earlier 72889-specific bridge revisions. Historical; not shipped. |
| **route 2** | `0day-2-RCE-PARSER-SCOPE/STAG`: arena bytecode + arena class-512 spray. |
| **hole-reuse** | `0day-2-RCE-PARSER-SCOPE/TINY`: free a run of same-size blocks, compile the trigger into a hole, spray around it. |

## File name mapping

### Android cross-tag (`vulns/0day-2-RCE-PARSER-SCOPE/XTAG/payloads/`)

| Original name | New name |
|---|---|
| `c2560_final_c2560s_72929.html` | `final-sony-beta-72929.html` |
| `c2560_probe_c2560s_72929.html` | `probe-sony-beta-72929.html` |
| `c2560_debug_c2560s_72929.html` | `debug-sony-beta-72929.html` |
| `c2560_final_c2560s_c2_72929.html` | `c2-final-sony-beta-72929.html` |
| `c2560_final_c2560s_host.html` | `final-host-twin.html` |
| `c2560_probe_c2560s_host.html` | `probe-host-twin.html` |
| `c2560_debug_c2560s_host.html` | `debug-host-twin.html` |
| `c2560_final_c2560s_c2_host.html` | `c2-final-host-twin.html` |
| `c4096_final_c4096s_72929.html` | `fallback-4096/final-sony-beta-72929.html` |
| `c4096_probe_c4096s_72929.html` | `fallback-4096/probe-sony-beta-72929.html` |
| `c4096_debug_c4096s_72929.html` | `fallback-4096/debug-sony-beta-72929.html` |
| `endG8s.js` | `src/endgame-stage-b.js` |
| `gen_c2560s.py` | `builders/0day-2/xtag/original/gen_c2560s.py`; runnable: `builders/0day-2/xtag/build_widgets.py` |
| `gen_c2_widget.py` | `builders/0day-2/xtag/original/gen_c2_widget.py`; runnable: `builders/0day-2/xtag/build_c2_widget.py` |

### Android same-tag (`vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/route2/`)

| Original name | New name |
|---|---|
| `s2s3_probe_72801.html` | `stage-a-probe-72801.html` |
| `s2s3_stageA_dev.js` | `src/stage-a-device-72801.js` |
| `gen_s2s3.py` | `tools/build-stage-a-probe.py` |
| `s2v3_device_72801.html` | `inline-endgame-72801.html` |
| `s2v3_full_host.html` | `inline-endgame-host.html` |
| `s2v3` stage A | `src/stage-a-v3.js` |
| `s2oob_device_72801.html` | `out-of-band-72801.html` |
| `s2oob_burst_device_72801.html` | `out-of-band-burst-72801.html` |
| `s2oob_mock_host.html` | `out-of-band-host-mock.html` |
| `bot_server.py` | `bot/answer_server.py` |
| `endgame_72801.js` | `endgame-72801.js` |
| `endgame_host.js` | `endgame-host.js` |
| `driver.js` | `driver-out-of-band.js` |
| `driver_burst.js` | `driver-out-of-band-burst.js` |
| `s2probe_limits_72801.html` | `limits-probe-72801.html` |
| `verify_72801.py` | `tools/verify-72801.py` |
| `s2s9`, `s2s10`, `s2b`, `s2s` variants | Not shipped. They are superseded revisions; see `vulns/0day-2-RCE-PARSER-SCOPE/STAG/evidence/pixel-route2-engineering-log.md`. |

### iOS hole-reuse (`vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/`)

| Original name | New name |
|---|---|
| `hole_stageA_probe_h400.html` | `probe-h400.html` |
| `hole_stageA_final_h400.html` | `final-h400.html` |
| `hole_stageA_probe_h200.html` | `probe-h200.html` |
| `hole_stageA_final_h200.html` | `final-h200.html` |
| `ls_final_h400_2036.html` | `stage-a-2036-h400.html` |
| `ls_seed.html` | `seed-stage-b.html` |
| `ls_seed_inline_4600_ub.html` | `seed-inline-rop.html` |
| `ls_final_inline_h200_ios_4600_ub.html` | `inline-rop-h200.html` |
| `ls_final_inline_h150_ios_4600_ub.html` | `inline-rop-h150.html` |
| `ls_final_inline_h250_ios_4600_ub.html` | `inline-rop-h250.html` |
| `ls_final_inline_h400_ios_4600_ub.html` | `inline-rop-h400.html` |
| `at_rop_final_h200_ios.html` | `attribute-rop-h200.html` |
| `stage2_host_twin_fixed.js` | `tools/stage2-host-twin.js` |
| `gen_hole_stageA.py` | `builders/0day-2/tiny/gen_hole_stage_a.py` |
| `build_ios_way.py` | `builders/0day-2/tiny/build_ios_way.py` |
| `make_inline_set_4600.py` | `tools/make_inline_set_4600.py` |
| `make_inline_ub_pair.py` | `tools/make_inline_ub_pair.py` |
| `postbox_rewrite_widget.py` | `docs/common/tools/postbox_rewrite_widget.py` |

### Parallel fan-out (`vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/universal/parallel/`)

| Original name | New name |
|---|---|
| `w_v0.html` … `w_v3.html` | `device-widget-a.html` … `device-widget-d.html` |
| `m_v0.html` … `m_v3.html` | `host-mock-a.html` … `host-mock-d.html` |
| `stageA_v0.js` … `stageA_v3.js` | `stage-a-a.js` … `stage-a-d.js` |
| `m_ra.html` | `host-mock-rearm.html` |
| `stageA_ra.js` | `stage-a-rearm.js` |
| `m_stop.html` | `host-mock-stop.html` |
| `gen_parallel.py` | `builders/0day-2/stag/gen_parallel.py` |
| `bot_first_only.py` | `bot/answer_server_first_wins.py` |
| `send_batch.json` | `send-batch.json` |

### iPhone 17e (`vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/`)

The 17e files keep descriptive names. The main groups are:

| Original / lab name | New name |
|---|---|
| `hole_stageA_probe_h*.html` | `probes/probe-h*.html` |
| `hole_stageA_final_h*.html` | `finals/final-h*.html` |
| `at_probe_h*` / `at_final_h*` | `attribute/probe-h*.html` / `attribute/final-h*.html` |
| `ls_seed.html` / `ls_seed_real.html` | `storage/seed-stage-b.html` / `seed-stage-b-real.html` |
| `ls_final_inline_h200_ios_4300_ub.html` | `storage/inline-rop-h200.html` |
| `ls_final_inline_h150_ios_4300_ub.html` | `storage/inline-rop-h150.html` |
| `ls_seed_inline_4300_ub.html` | `storage/seed-inline-rop.html` |
| `at_rop_final_h*_ios_17e.html` | `rop/at_rop_final_h*_ios_17e.html` |
| `srop_17e.js` | `rop/srop-ios27.js` |
| `srop_wide.js` / `srop_earlyub.js` / `srop_multibuf.js` | `rop/srop-ios27-{wide,earlyub,multibuf}.js` |
| `probe_CF_C34.html` | `compile-first/probe-c34.html` |
| `inline_cf_p*.html` | `compile-first/inline-p*.html` |
| `ss2_rop_wide.html` | `compile-first/rop-compile-first-wide.html` |

The 17e is **device-proven once (msg 5725); the gated twin is host-only**.

### Common scripts (`docs/common/tools/`)

| Original name | New name |
|---|---|
| `send_poc.py` (minimal PoC) | `send_widget.py` |
| `send_widget.py` (MTProto) | `send_widget_mtproto.py` |
| `widget_tool.py` | `patch_android_widget_db.py` |
| `build_db.py` | `build_android_widget_db.py` |
| `postbox_rewrite_widget.py` | `postbox_rewrite_widget.py` |
| `iosdb.py` | `list_ios_postbox_rows.py` |
| `deliver_n1_6s.py` | `docs/instrumentation/ios6s/deliver_widget_frida_usb.py` |
| `deliver_n1_wifi.py` | `docs/instrumentation/ios6s/deliver_widget_frida_wifi.py` |
| `run_js.py` | `docs/instrumentation/ios6s/run_frida_script.py` |
| `shot_h100.js` | `docs/instrumentation/ios6s/shot_screen.js` |
| `run6m.c` | `quickjs-widget-harness.c` |
