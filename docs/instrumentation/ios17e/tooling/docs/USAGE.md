# Usage sheet — iPhone 17e runner

One device operation at a time. The operator keeps the bot chat open at the
bottom; `--tap`/`--drag` can send a simple post-launch tap, but scrolling and
chat-state judgement remain operator-assisted. Use a clean chat and one payload
per open.

## 0. Setup (once per shell)

```sh
cd lab/ios17e/tooling
export BOT_TOKEN='<bot token>'          # never commit
export I17E_UDID='<UDID>'
export I17E_CHAT_ID='<chat id>'
export I17E_APPGROUP='<AppGroup UUID>'  # only for proof backup
export I17E_ACCOUNT_ID='<account dir>'  # optional; also auto-redacted from logs
```

`python3 -m i17e_runner doctor --udid "$I17E_UDID"` must print
`iPhone18,5 27.0 ... 24A437` and `13.2 (36535)`. Otherwise stop: the runner
will refuse to send.

## 1. Clean the chat

```sh
# ids from the local ledger plus ids copied from an older run note
python3 -m i17e_runner clean --chat-id "$I17E_CHAT_ID" \
  --payload-id 1001 --anchor-id 1002 --verify-screenshot
```

The command prints the JSON result. `clean=false` means the run must not
continue; delete the reported ids manually or stop.

## 2. One attempt

```sh
python3 -m i17e_runner run --label K3 \
  --html lab/ios17e/reliability_20261109/fix_v10/out/v14_stage_a.html \
  --payload-root "$PWD/../../.." \
  --chat-id "$I17E_CHAT_ID" --udid "$I17E_UDID" \
  --success-marker 'HIT=' --success-marker 'RESULT SS2' \
  --out runs/v14_k3
```

The runner:
1. re-checks the device and app version;
2. re-cleans the ledger ids (and `--delete-id` values);
3. launches with `--console --userspace`, records the log offset, then runs
   any `--tap X,Y` / `--drag X1,Y1,X2,Y2` input (e.g. to open the chat after a
   cold relaunch; coordinates are 1170×2532 screenshot pixels);
4. sends the payload (checked raw/zlib9) as the last message;
5. captures screenshots and the console tail, OCR if available;
6. records app state and optional proof;
7. deletes the payload and terminates the console attachment;
8. writes JSON/Markdown under `runs/v14_k3`.

## 3. Matrix blocks

```sh
# K3p + K3 x10 + gated K4 x6
python3 -m i17e_runner matrix --spec examples/v14_k3_k4.json \
  --payload-root "$PWD/../../.." --chat-id "$I17E_CHAT_ID" \
  --udid "$I17E_UDID" --out runs/v14_k3_k4

# P1 v10 x10 + v0 control
python3 -m i17e_runner matrix --spec examples/p1_v10.json \
  --payload-root "$PWD/../../.." --chat-id "$I17E_CHAT_ID" \
  --udid "$I17E_UDID" --out runs/p1_v10

# session file (proof required) then net (external receiver)
python3 lab/ios17e/session_impact/tools/c2_recv.py --port 4453 \
  --out /tmp/opencode/sess_cap.bin --parse &
python3 -m i17e_runner matrix --spec examples/session_v14.json \
  --payload-root "$PWD/../../.." --chat-id "$I17E_CHAT_ID" \
  --udid "$I17E_UDID" --appgroup "$I17E_APPGROUP" \
  --out runs/session_v14
```

## 4. Read the result

```sh
jq '{verdict, marker: .marker.fields, app: .app.state, proof: .proof.rce_ok,
     ids: {deleted: .chat.deleted_ids, after: .chat.deleted_after}}' \
  runs/v14_k3/attempts/*.json
cat runs/v14_k3/SUMMARY.md
```

Failure classes are recorded in `verdict.reason` and the Markdown:

| reason | action |
|---|---|
| `no_marker` / `app_dead_no_marker` | per matrix rules; relaunch or stop |
| `endgame_guard` | stop; the geometry works, the endgame is the defect |
| `chat_dirty` | do not count; clean again |
| `wrong_device` | fix UDID/model; never use the 6s/another phone |
| `usb_unavailable` | wake/unlock/Trust, replug, rerun `recover` |
| `proof_missing` | proof file absent; check `--appgroup` and `backup2` |

## 5. Warm app / no relaunch

If the app is already running with a console attached:

```sh
python3 -m i17e_runner run --label warm --no-launch \
  --console-log /tmp/opencode/console.log \
  --html <payload> --chat-id "$I17E_CHAT_ID" --udid "$I17E_UDID"
```

Warm mode does not own the console process and will not kill it.

## 6. Dry run and tests

```sh
python3 -m i17e_runner run --dry-run --label plan --html <payload> \
  --chat-id '<CHAT_ID>' --out /tmp/i17e-plan
python3 -m unittest discover -s tests -t . -v
```
