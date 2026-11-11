# Universal parallel fan-out payloads

Docs: `vulns/0day-2-RCE-PARSER-SCOPE/STAG/README.md`. First-wins server:
`bot/answer_server_first_wins.py`.

## Files

| File | What |
|---|---|
| `device-widget-a.html` … `device-widget-d.html` | The four device widgets (stage A with two attempts + answer-channel driver). |
| `host-mock-a.html` … `host-mock-d.html` | Host mocks with a mock `TelegramWidget` and the host endgame. |
| `host-mock-rearm.html` | Forced-miss twin (`ATT=1`). |
| `host-mock-stop.html` | Mock returning STOP (`X`). |
| `stage-a-a.js` … `stage-a-d.js` | The four stage-A sources. |
| `stage-a-rearm.js` | The re-arm twin. |
| `build_parallel.py` | Rebuilds the widgets, mocks, chunks, and `send-batch.json`. |
| `send-batch.json` | The four `sendWidget` bodies. Set `chat_id`. |
| `run_host.sh` | The host matrix. |
| `chunks/` | 8 × 1,000 B, release proof path. |
| `chunks_beta/` | Same, Sony beta proof path. |
| `design.md` | Original design notes (lab paths). |

## Host validation

```sh
cd vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/universal/parallel
python3 build_parallel.py
./run_host.sh
```

Expected in `logs/host_matrix.txt`: 12/12 `ABLEN[599]=327744 … | HF HF OK`,
re-arm 3/3, 6 MiB profile, STOP, and the safe host `NOANCHOR`.

## Device use

Send the four widgets to the same chat, keep the chat open, and run the
first-wins server. The first widget that forges asks for `E0`; the server
answers it and sends `X` to the others.

## Status

Host 12/12. Device pending (Pixel and Samsung).
