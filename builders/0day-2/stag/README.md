# STAG builders (`route2`)

Build the Android same-tag payloads. Output directory:
`vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/`. Override with
`STAG_PAYLOAD_DIR`.

## Files

| File | What |
|---|---|
| `build_probe.py` | Builds the 72801 stage-A probe byte-identically. |
| `gen_parallel.py` | Builds the four parallel widgets, host mocks, chunks, and `send-batch.json`. |
| `build_stage_a_device_page.py` | Builds the 9,064-byte stage A + stage B device page. |
| `split_endgame.py` | Splits the 7,469-byte endgame into 950-byte answer chunks. |
| `check_parallel.sh` | Rebuilds the parallel package and compares the SHA-256 pins. |

## Checks

Probe:

```sh
cd builders/0day-2/stag
python3 build_probe.py --check
```

Expected: `raw=1566 zlib9=686` and SHA-256
`a534a8725b8a1a07efacf7a5c8108ab5c31488d4b0e2e1bc7558d548a7f39412`,
`RESULT: PASS`.

Parallel:

```sh
./check_parallel.sh
```

Expected: `PARALLEL CHECK PASS`.

Chunks:

```sh
python3 split_endgame.py \
  vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/route2/endgame-72801.js \
  --outdir /tmp/opencode/chunks --check
```

Expected: `RESULT: PASS`.

## Build

```sh
python3 gen_parallel.py
python3 build_probe.py --out vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/route2/stage-a-probe-72801.html
python3 build_stage_a_device_page.py /tmp/opencode/route2-device.html
```

`gen_parallel.py` rewrites the canonical parallel files. It prints raw and
zlib9 sizes. `check_parallel.sh` verifies the hashes.

## Pins

| File | Raw | zlib9 | SHA-256 |
|---|---:|---:|---|
| `stage-a-probe-72801.html` | 1,566 | 686 | `a534a8725b8a1a07efacf7a5c8108ab5c31488d4b0e2e1bc7558d548a7f39412` |
| `device-widget-a.html` | 2,764 | 1,270 | `cc1881ca32d23321d37a2620df01099c164d375cdcb53aa8d92c461c3352ca39` |
| `device-widget-b.html` | 2,764 | 1,273 | `f77c198079b4b54b3856d5899b7a4322ac79282a0ca006f54f5be46c95a8ef63` |
| `device-widget-c.html` | 2,764 | 1,274 | `4fa7621eb214abef80ef16d7f1c196e47d9f8cbd2f1c37e07c0c660efa5dc0ae` |
| `device-widget-d.html` | 2,764 | 1,271 | `25a5fb54a28af04e954c1d4530707b5cbf88a2ca8141e0473b525d93aefb693c` |

## Inputs

- Stage-A source: `STAG/payloads/route2/src/stage-a-device-72801.js`.
- Endgame: `STAG/payloads/route2/endgame-72801.js`.
- Host endgame: `STAG/payloads/route2/endgame-host.js`.
- Driver: `STAG/payloads/route2/driver-out-of-band.js`.
- Fallback page: `STAG/payloads/route2/out-of-band-72801.html`.
