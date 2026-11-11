# Result schema (`i17e-runner/attempt/1`)

Each attempt writes `<out>/attempts/<label>_<n>_<stamp>.json` and a matching
`.md`. Artifacts are redacted by default. A compact example:

```json
{
  "schema": "i17e-runner/attempt/1",
  "tool": {"name": "i17e_runner", "version": "1.0.0"},
  "attempt": {
    "label": "K3",
    "index": 1,
    "started_at": "2026-11-09T03:56:07+00:00",
    "ended_at": "2026-11-09T03:56:32+00:00",
    "duration_s": 25.1
  },
  "verdict": {"status": "pass", "reason": "marker", "success": true},
  "device": {
    "model": "iPhone18,5",
    "os_version": "27.0",
    "build": "24A437",
    "udid": "<UDID>",
    "bundle_id": "ph.telegra.Telegraph",
    "app_version": "13.2",
    "app_build": "36535",
    "app_checked": true
  },
  "payload": {
    "path": "…/v14_stage_a.html",
    "raw": 8647,
    "zlib9": 3660,
    "sha256": "4906d6f9…101a",
    "limits": {"raw": 32768, "zlib9": 4096},
    "raw_ok": true,
    "zlib_ok": true,
    "message_id": 5002
  },
  "chat": {
    "id": "<CHAT_ID>",
    "clean_before_send": true,
    "deleted_ids": [5001],
    "last_message_ok": true,
    "previous_max_message_id": 5001,
    "clean_after": true,
    "deleted_after": [5002]
  },
  "timeline": {
    "t_start": "…",
    "t_device_ok": "…",
    "t_clean_ok": "…",
    "t_launch": "…",
    "t_pre_send_ok": "…",
    "t_send": "…",
    "t_first_shot": "…",
    "t_marker_observed": "…",
    "t_proof_done": "…",
    "t_end": "…",
    "durations": {"total_s": 25.1, "launch_wait_s": 3.5, "shot_count": 14}
  },
  "logs": {
    "path": "…/logs/K3_01_console.log",
    "offset_before": 0,
    "offset_send": 1234,
    "new_bytes": 5678,
    "launch_tail": "…",
    "tail": "…",
    "marker_lines": ["RESULT SS2 … HIT=545/585 LEN=327744"]
  },
  "screenshots": [
    {"index": 1, "t_rel_s": 0.6, "path": "…/shots/K3_01_s01.png",
     "ok": true, "size": 123456, "markers": [], "ocr": null}
  ],
  "ocr": {"available": false, "error": "rapidocr_onnxruntime is not installed"},
  "marker": {
    "found": true,
    "text": "RESULT SS2 … HIT=545/585 LEN=327744",
    "fields": {"hit": "545/585", "len": "327744", "r": "0", "m": "0",
               "ph": "12", "nt": "0"},
    "tokens": ["result"],
    "lines": ["RESULT SS2 … HIT=545/585 LEN=327744"],
    "first": "RESULT SS2 … HIT=545/585 LEN=327744",
    "guard": null
  },
  "app": {"state": "alive", "evidence": "console process is still attached",
          "exit_code": null, "bubble": "marker"},
  "proof": {
    "attempted": true,
    "regex": "<APPGROUP>.*rce.txt|.*spdb",
    "found": true,
    "proof_ok": true,
    "rce_ok": true,
    "spdb_ok": true,
    "matches": [
      {"kind": "rce", "relative_path": "…/rce.txt", "size": 7,
       "sha256": "704984d9…", "rce_ok": true, "spdb_ok": false}
    ],
    "retries": 0,
    "error": null
  },
  "cleanup": {},
  "processes": {
    "frida_before": [],
    "console_stop": {"pid": 1234, "terminated": true, "killed": false,
                     "returncode": 0},
    "console_pids_after": [],
    "frida_after": []
  },
  "errors": [],
  "extras": {"artifacts": {"json": "…", "markdown": "…",
                           "results_jsonl": "…"}}
}
```

## Field notes

| field | meaning |
|---|---|
| `verdict.status` | `pass`, `fail`, `invalid`, `error`, `plan`, `manual` |
| `verdict.reason` | `marker`, `proof`, `app_dead_no_marker`, `endgame_guard`, `wrong_device`, `chat_dirty`, `launch_failed`, `send_failed`, `usb_unavailable`, `proof_missing`, `dry_run`, … |
| `device.udid` | real value locally, `<UDID>` when redacted |
| `payload.message_id` | id returned by `sendWidget`; the ledger records it as the last payload |
| `chat.last_message_ok` | `message_id` is greater than the ledger's previous maximum |
| `logs.offset_send` | byte offset captured immediately before `sendWidget`; the marker tail is read from here |
| `marker.guard` | first endgame guard token (`U_NF`, `NO_RT`, `NO_BASE`, `LEN_*`) |
| `app.state` | `alive` if the `--console` process is still attached when checked, `dead` if it exited, `unknown` in `--no-launch` mode |
| `proof` | only populated when `--backup` or `require_proof` is set |
| `processes` | confirms the console was terminated and records leftover PIDs |

`results.jsonl` appends the same object (one line per attempt) and
`matrix_summary.json` / `SUMMARY.md` aggregate the block, including a
one-sided 95 % Clopper-Pearson lower bound over valid attempts.
