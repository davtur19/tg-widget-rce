# HISTORY.md: old names and paths

This repository was rebuilt several times. This page maps the old campaign
names to the current IDs and paths. The technical facts are unchanged.

## Vulnerability IDs

| Old name | Current ID / path |
|---|---|
| parser `ARG_SCOPE_END`, "0day" | `0day-2-RCE-PARSER-SCOPE`; `vulns/0day-2-RCE-PARSER-SCOPE/` |
| `c2560s` | `0day-2-RCE-PARSER-SCOPE/XTAG`; `vulns/0day-2-RCE-PARSER-SCOPE/XTAG/` |
| `c4096s` | `0day-2-RCE-PARSER-SCOPE/XTAG` fallback; `.../XTAG/payloads/fallback-4096/` |
| `c2560q`, `c2560r` | historical XTAG revisions; not shipped (see `XTAG/evidence/`) |
| `route2`, `route 2` | `0day-2-RCE-PARSER-SCOPE/STAG`; `vulns/0day-2-RCE-PARSER-SCOPE/STAG/` |
| `universal`, `v3`, parallel fan-out | `0day-2-RCE-PARSER-SCOPE/STAG` universal; `.../STAG/payloads/universal/` |
| `hole-reuse`, `ls_*`, `N1IOS` | `0day-2-RCE-PARSER-SCOPE/TINY`; `vulns/0day-2-RCE-PARSER-SCOPE/TINY/` |
| `ios17e`, `iPhone 17e`, `iOS 27` | `0day-2-RCE-PARSER-SCOPE/IOS27`; `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/` |
| `v7`, `v7-class-64`, `#1827` | `nday-1-RCE-V7-RGX-1827`; `vulns/nday-1-RCE-V7-RGX-1827/` |
| `#1865`, `var_ref_count` | `nday-2-RCE-VARREF-1865`; `vulns/nday-2-RCE-VARREF-1865/` |
| `N1`, "N1 same-tag fake-scope" | `0day-1-SCOPE-OOM`; `vulns/0day-1-SCOPE-OOM/` |
| `MB-01`, `#1835`, `#1844` | `WEAKMAP-1835`; DoS/possible chaining entrypoint, one line in `NON_RCE.md` |
| DoS/read-only/negatives | one line each in `NON_RCE.md` |

## Stage-A and payload aliases

| Old name | Current name / status |
|---|---|
| `s2s3_probe_72801.html` | `stage-a-probe-72801.html` (STAG) |
| `s2s3_stageA_dev.js` | `src/stage-a-device-72801.js` (STAG) |
| `s2s3_device_72801.html`, `s2s4_device_72801.html` | superseded; 16723-16726 device series |
| `s2s7`, `s2s8`, `s2s9`, `s2s10` | superseded stage-A revisions; `s2s9`/`s2s10` are payload aliases only |
| `s2b`, `s2b_*` | superseded two-sided spray series |
| `s2v3_device_72801.html` | `inline-endgame-72801.html` (STAG) |
| `s2v3_full_host.html` | `inline-endgame-host.html` (STAG) |
| `s2oob_device_72801.html` | `out-of-band-72801.html` (STAG) |
| `s2oob_burst_device_72801.html` | `out-of-band-burst-72801.html` (STAG) |
| `s2oob_mock_host.html` | `out-of-band-host-mock.html` (STAG) |
| `s2probe_limits_72801.html` | `limits-probe-72801.html` (STAG) |
| `bot_server.py` | `bot/answer_server.py` |
| `bot_first_only.py` | `bot/answer_server_first_wins.py` |
| `w_v0.html` … `w_v3.html` | `device-widget-a.html` … `device-widget-d.html` (STAG universal) |
| `m_v0.html` … `m_v3.html` | `host-mock-a.html` … `host-mock-d.html` (STAG universal) |
| `stageA_v0.js` … `stageA_v3.js` | `stage-a-a.js` … `stage-a-d.js` |
| `m_ra.html` | `host-mock-rearm.html` |
| `m_stop.html` | `host-mock-stop.html` |
| `gen_parallel.py` | `build_parallel.py` |
| `gen_c2560s.py` | `build_widgets.py` (XTAG scripts) |
| `gen_c2_widget.py` | `build_c2_widget.py` (XTAG scripts) |
| `endG8s.js` | `endgame-stage-b.js` (XTAG scripts) |

## Directory moves

| Old path | Current path |
|---|---|
| `0day/payloads/c2560s/` | `vulns/0day-2-RCE-PARSER-SCOPE/XTAG/payloads/` |
| `0day/payloads/route2/` | `vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/route2/` |
| `0day/payloads/universal/` | `vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/universal/` |
| `0day/payloads/ios-hole-reuse/` | `vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/` |
| `0day/payloads/ios-17e/` | `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/` |
| `0day/evidence/c2560s/` | `vulns/0day-2-RCE-PARSER-SCOPE/XTAG/evidence/` |
| `0day/evidence/route2/` + `universal/` | `vulns/0day-2-RCE-PARSER-SCOPE/STAG/evidence/` |
| `0day/evidence/ios-hole-reuse/` | `vulns/0day-2-RCE-PARSER-SCOPE/TINY/evidence/` |
| `0day/scripts/ios-17e/` | `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/scripts/` (builders) and `docs/instrumentation/ios17e/` (device tools) |
| `docs/0day/ios-17e/` | `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/README.md` + `evidence/instrumentation-plan.md` |
| `docs/0day/00-overview.md` + `01-the-bug.md` | `vulns/0day-2-RCE-PARSER-SCOPE/README.md` |
| `docs/0day/02-android-cross-tag-c2560s.md` | `vulns/0day-2-RCE-PARSER-SCOPE/XTAG/README.md` |
| `docs/0day/03-android-same-tag-route2.md` + `05-universal-and-parallel.md` | `vulns/0day-2-RCE-PARSER-SCOPE/STAG/README.md` |
| `docs/0day/04-ios-hole-reuse.md` | `vulns/0day-2-RCE-PARSER-SCOPE/TINY/README.md` |
| `nday/v7-1827/` | `vulns/nday-1-RCE-V7-RGX-1827/` |
| `docs/nday/01-v7-1827.md` | `vulns/nday-1-RCE-V7-RGX-1827/README.md` |
| `nday/1865/` | `vulns/nday-2-RCE-VARREF-1865/` |
| `docs/nday/02-1865.md` | `vulns/nday-2-RCE-VARREF-1865/README.md` |
| `nday/mb-01-weakmap/` | one line in `NON_RCE.md` (`WEAKMAP-1835`) |
| `nday/historical/`, `docs/dos/`, `docs/readonly/`, `docs/negatives/`, `dos/`, `readonly/`, `negatives/` | one line each in `NON_RCE.md` |
| `docs/reference/` | per-ID `evidence/` logs and the two `docs/instrumentation/` notes |
| `scripts/common/` | `docs/common/tools/` |
| `scripts/bot/` | `bot/` |
| `scripts/c2/` | `docs/c2/` |
| `scripts/instrumentation/` | `docs/instrumentation/` |

## Notes

- `v3`, `v7`, `c2560s`, `route2`, `N1`, `s2s9`, `w_v0` are **old identifiers**.
  They are kept here and inside the per-ID READMEs for traceability. The
  user-facing names are the IDs above.
- `c2560q`/`c2560r` were 72889-specific bridge revisions; they are historical,
  not shipped. The universal XTAG widget is 5/5 on 72929 and 1/1 on 72889.
- `s2s9`, `s2s10`, `s2b` are superseded stage-A revisions; they are aliases
  in the engineering logs, not current payload names.

## Lab artifact mapping

The lab artifacts are copied with their original names. Use these patterns to
find a file that was moved from the lab.

| Lab source | Repository target |
|---|---|
| `lab/qjs_n1/widget/` | `vulns/0day-1-SCOPE-OOM/payloads/variants/` |
| `lab/qjs_n1/device_run_sony_*/` | `vulns/0day-1-SCOPE-OOM/evidence/variants/` |
| `lab/ios_way/payload/` | `vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/variants/` and `.../IOS27/payloads/variants/` |
| `lab/ios_way/tools/` | `.../TINY/scripts/variants/` and `.../IOS27/scripts/variants/` |
| `lab/ios_way/evidence/` | `.../TINY/evidence/variants/` and `.../IOS27/evidence/variants/` |
| `lab/qjs_postsnapshot/ios_n1/` | `.../TINY/payloads/variants/` (delivery and safe probes) |
| `lab/pixel72801_route2/` | `.../STAG/payloads/variants/route2/`, `.../STAG/scripts/variants/route2/`, `.../STAG/evidence/variants/route2/` |
| `lab/parallel_univ_20261108/` | `.../STAG/payloads/variants/parallel/` |
| `lab/qjs_fork_audit/zeroday_hunt_parser/device/widget/` | `.../XTAG/payloads/variants/widget/` |
| `lab/qjs_fork_audit/zeroday_hunt_parser/device/gen_c2560s.py` | `.../XTAG/scripts/variants/` |
| `lab/qjs_fork_audit/zeroday_hunt_parser/device/logs/device_parser_rce/` | `.../XTAG/evidence/variants/device_parser_rce/` |
| `lab/ios27_20261106/` | `vulns/nday-1-RCE-V7-RGX-1827/payloads/variants/`, `scripts/variants/`, `evidence/variants/` |
| `lab/ios_port/` | `vulns/nday-1-RCE-V7-RGX-1827/payloads/variants/ios_port/` |
| `/tmp/opencode/ios17e/` | `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/variants/` and `evidence/` |
| `lab/ios_uiframework_hunt/`, `lab/widget_surface_hunt/`, `lab/lib_hunt_*` | `non-rce/` (only the single fixtures named in `NON_RCE.md`) |

## Tool mapping

| Lab tool | Repository target |
|---|---|
| `pixel72801_route2/oob/bot_server.py` | `bot/bot_server.py` and `bot/answer_server.py` |
| `parallel_univ_20261108/bot_first_only.py` | `bot/bot_first_only.py` and `bot/answer_server_first_wins.py` |
| `pixel72801_route2/oob/probe_answers.py` | `bot/probe_answers.py` |
| `pixel72801_route2/oob/chunks/` | `bot/chunks/route2/` and `STAG/payloads/route2/chunks/` |
| `parallel_univ_20261108/chunks/` | `bot/chunks/parallel/` and `STAG/payloads/universal/parallel/chunks/` |
| `ios_wifi_tools/` | `docs/instrumentation/ios6s/wifi_tools/` |
| `/tmp/opencode/deliver_n1_wifi.py` | `docs/instrumentation/ios6s/deliver_n1_wifi.py` |
| `ios_way/tools/postbox_rewrite_widget.py` | `docs/common/tools/postbox_rewrite_widget.py` |
| `ios_way/tools/make_inline_rop.py` | `builders/0day-2/tiny/make_inline_rop.py` |
| `ios_way/tools/make_inline_ub_pair.py` | `builders/0day-2/tiny/make_inline_ub_pair.py` |
| `ios_way/tools/pad_inline_z.py` | `builders/0day-2/tiny/pad_inline_z.py` |
| `ios_way/tools/gen_hole_stageA.py` | `builders/0day-2/tiny/gen_hole_stage_a.py` |
| `ios_way/tools/build_ios_way.py` | `builders/0day-2/tiny/build_ios_way.py` |
| `zeroday_hunt_parser/device/gen_c2560s.py` | `builders/0day-2/xtag/original/gen_c2560s.py` |
| `parallel_univ_20261108/gen_parallel.py` | `builders/0day-2/stag/gen_parallel.py` |
| `two_phase_20261108/gen_two_phase.py` | `builders/two_phase/gen_two_phase.py` |
| `two_phase_20261108/bot_two_phase.py` | `bot/bot_two_phase.py` |
| `c2/` | `docs/c2/c2560s/` |
