> **Historical engineering note.** Paths inside this file refer to the
> original lab tree (`lab/...`, `/tmp/opencode/...`). They are kept for
> provenance. The current paths and the clean commands are in the directory
> `README.md` and in `docs/`. No token file is included in this repository.

# Parallel universal package: implementation notes

Host-only implementation of `notes/universal_parallel_20261108.md`. No device,
bot or network action was taken here.

## Inventory

| file | what |
|---|---|
| `gen_parallel.py` | builds everything below; `--pkg beta` regenerates `chunks_beta/` with the beta proof path |
| `stageA_v0..v3.js` | the four stage-A instances (2-attempt H sweep, GC re-arm, class-512 string spray, tagged-int record) |
| `stageA_ra.js` | forced-miss twin: attempt 0 skips the trigger, attempt 1 hits (`ATT=1`) |
| `w_v0..v3.html` | device widgets: stage A + answer-channel driver; 2,764 raw / 1,270-1,274 zlib9 |
| `m_v0..v3.html`, `m_ra.html` | host mocks: same stage A + mock `TelegramWidget` (1,000-B chunks of the host endgame) + driver |
| `m_stop.html` | mock returning the STOP sentinel `X` |
| `m_dev_v0.html` | mock serving the **device** endgame (`oob/endgame_72801.js`); stops at safe `HF ERR NOANCHOR` on the host |
| `chunks/` | device endgame, 8 × 1,000 B, manifest with per-chunk sha256 (release proof path) |
| `chunks_beta/` | same, `org.telegram.messenger.beta` proof path (Sony) |
| `bot_first_only.py` | first-wins answer server; `--parallel-self-test` |
| `send_batch.json` | the 4 `sendWidget` bodies (height 50, allow_queries, background_query) |
| `run_host.sh` | the validation matrix; output in `logs/host_matrix.txt` |

## Design in one paragraph

The page is the device-proven stage A (no endgame text) plus a fetch driver.
The stage A sprays 479-char class-512 strings with the `RJ/RT` record lattice
at data 228, evals the 9-float victim function between the pre- and post-spray,
and triggers the parser `ARG_SCOPE_END` OOB; the target offset is the same for
every block index, so the only unknown is placement. Two attempts per widget
(with a GC re-arm between them) times four fixed variants (NP/NQ table) give up
to eight placement trials per open, in separate sandboxes running on the
process's `widget.sandbox` pool. The first forger calls
`TelegramWidget.request("E0")` immediately; the first-wins server answers its
8 × ≤1,000 B chunks in order (client pacing 5 s) and sends `X` to any other
widget that asks, which stops those drivers.

## Validation

```
cd lab/parallel_univ_20261108 && ./run_host.sh
```

See `logs/host_matrix.txt`: 12/12 variant runs `ABLEN[599]=327744 … | HF HF OK`
at 8 MiB; the re-arm twin 3/3 `ATT=1` + `HF OK`; 6 MiB forge + `HF OK`; STOP
path; device-endgame path safe `NOANCHOR` on the host; first-wins self-test
PASS.

## Honest boundary

The single ≤1,024 B answer endgame is not reachable with the parser chain
(7,469 B; section sizes in the note §6). The answer channel buys placement
independence and universality, not 1 s latency: ~110-145 ms to the first
answer, ~37 s to `HF OK` at the client's 5 s background pacing. The parallel
fan-out shortens the path to the first *forge*, not the chunk pipeline.
