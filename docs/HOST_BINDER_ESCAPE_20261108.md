# Android isolated widget process: host Binder results

Dated research note, 2026-11-08. Target: Android beta 72989, app UID 10346,
widget engine in `WidgetEngineService` (isolated UID 990xx, SELinux
`u:r:isolated_app:s0`). The parser stage A works in that process. This note
tracks Telegram-owned host bugs only; Android kernel/SELinux bugs are out of
scope.

Full report, scripts and tombstones:
`<LAB>/artifacts_20261108/escape_host/REPORT_ipc_host_escape.md`,
`TELEGRAM_BUG_path_race.md`, `HANDOFF.md`,
`tombstone_27_filterpixels.txt`, `tombstone_28_race.txt`,
`tombstone_29_canvasread_abort.txt`,
`tombstone_30_scudo_pathrace.txt`,
`tombstone_31_pathrace_5000.txt`,
`tombstone_02_16thread_scudo.txt`,
`tombstone_03_path60000.txt`,
`frida_jni_16race_run.js`, `dl_path60000.bin`,
`HEAP_SHAPING_ATTEMPT.md`, `Pregrow_analysis.md`, `LEAK_SEARCH.md`,
`ALT_HOST_AUDIT_20261108.md`, `reverse_binder_72989/REPORT_reverse_binder_72989.md`,
`FINAL_WALL.md`.

## Boundary

The isolated process can reach only two Telegram Binder objects:
`IWidgetEngine` (codes 1 to 14) and `IWidgetEngineCallback` (codes 1 to 12).
Of 251 `servicemanager` names only five pass (`activity`, `package`,
`permissionmgr`, `display`, `webviewupdate`). All Telegram services,
receivers and providers are blocked by `ActivityManagerService`
(`enforceNotIsolatedCaller`). Filesystem reads and writes to the app data and
shared storage fail; only APK assets are readable. The seccomp filter traps
`execve`, `execveat`, `ptrace`, `process_vm_readv/writev`, `bpf`,
`perf_event_open`, io_uring, keyring, module/kexec, namespace/mount and
swap/reboot. Threads, Binder, futex and `mmap` remain allowed.

The host validates the callback data: 64-bit canvas dimensions and products,
array and display-list bounds, JSON limits, font and image budgets, a 16 MiB
chunk cap. The suspected `canvasRun` and `canvasRead` integer overflows were
refuted in the bytecode.

## The Telegram bug: shared SkPath race

`WidgetSandboxBackend.record` and its painter `z0.d` use one `z0` per session
with shared `Path`, `Paint`, `Matrix` and float fields, and no synchronization.
Every record does `path.rewind()` / `addRect` / `addPath` and
`Canvas.clipPath(path)` on the same `Path`. The 240-slot `recordTimes`
structure is a burst gate, not a mutex.

With a path display list (5k to 20k point polylines; `dl_path5000.bin`,
`dl_path20k.bin`) and two concurrent `record` calls, direct host calls
produce:

- SIGSEGV in `Canvas.clipPath` at `0x0058000041900118`; x8 is SkPoint
  coordinate data from the generated path (tombstone 31).
- A Scudo `race on chunk header` native heap write corruption (tombstone 30).
  A 4000-Bitmap `0x41414141` spray still produced the Scudo chunk race.

The earlier rect/clip variant produced only the null deref in
`SkPathPriv::IsRectContour` (tombstone 28). The crash site is Skia/libhwui,
but the unsynchronized object belongs to Telegram. This is a Telegram-owned
native memory-corruption bug, not an Android bug.

End-to-end from the isolated process is now reproduced: 16 native pthreads,
each JNI-attached, synchronous `transact(6, pathDL)` loops (50 iterations,
5000-point path) broke the 240-slot gate and Binder dispatch jitter. The host
died with a Scudo `race on chunk header` in
`SkPathRef::growForVerb -> sk_realloc_throw` (tombstone 02). A 60k-point path
gives an 8-byte UAF write in `SkPath::lineTo` at page-aligned `0x6c8685b000`
(SEGV_ACCERR, tombstone 03) from `z0.i -> record`. The real c2560s payload can
spawn the 16 threads and call Binder directly; no network/C2.

The remaining wall: small paths abort in Scudo's header-race check before a
controllable primitive; large paths give a UAF write to the stale points
array, not a chosen object; `clipPath`'s wild pointer is a read with no exfil.

A first heap-shaping attempt used 20k/50k-point paths with distinctive
coordinates and up to 500 live 200x200 Bitmaps matching the 20k points array,
inspected with `getPixels`/`Arrays.hashCode` for the SkPoint bits. No HIT. The
stale points array is a large Skia `realloc` allocation (Scudo
secondary/unmapped on free); the write goes to the stale address; reclaiming
the small `SkPathRef` needs a same-size small allocation plus a heap address
leak; Scudo `reportHeaderRace` aborts the small-path variant before shaping.
Next: pre-grow the `Path` to force a write-only race (no `growForVerb`
realloc), spray small same-size objects for `SkPathRef`, aim the stale
`fPoints` at a fake array, or force allocator reuse with the 60k path plus
Bitmap/canvas churn, then bypass/live with Scudo and find an observable leak.

Pre-growing the shared `Path` to >=N is source-proven to remove the
corruption: `SkPathRef::Rewind` clears or resets the shared ref to the old
point/verb counts, so concurrent `lineTo` writes land in a live reserved
buffer. A pre-grow record plus two 5000-loop record threads ran without a host
crash. Pre-grow cannot be weaponized; it confirms the corruption is the
points/verbs `realloc`/`free`, not the concurrent point writes.

All remaining concrete options are negative. 3000 small Bitmaps (4-12 px,
64-576 B, matching `SkPathRef` size classes) filled with 0x41414141, followed
by the two-thread path race, gave no reclaim and no controlled fault; 500 live
200x200 Bitmaps with distinctive SkPoint bits gave no HIT; the 60k points
array is Scudo-secondary/quarantined, so the stale write hits an
unmapped/quarantined block; no observable leak was found (`canvasRead` reads
the canvases map, not the corrupted Path/points; rendered pixels are not
exposed to the isolated process; diagnostics/crash metadata are root-only).

A focused leak search audited the callback replies (code 1 `float[6]`, code 2
`float`, code 11 `byte[]` pixels; no pointer, long, address or allocation
size), exception strings (fixed; Java OOM Java-heap counts; Skia asserts
abort), Binder reply Parcels (scalars/arrays; no addresses), validator/JNI (no
return data), `signal`/query/wallet (relay attacker bytes; no host address),
host-to-service data (widget/theme/scalars), rendered output (the record path
affects the `a0` RenderNode; `canvasRead` reads the separate canvases map; no
op draws the record RenderNode into a readable canvas; the bubble/WebView does
not expose pixels), and crash metadata (root-only). The answer relay is a
valid 1-64 B request / 1-1024 B answer exfil, but there is no leak to send. A
104 x 200x200 canvas churn hit a Frida type error before reading, so it is not
evidence either way; no completed spray run had a HIT.

Final wall: a controlled primitive requires a host heap address leak, a
reliable same-size `SkPathRef` reclaim with a fake absolute `fPoints` pointer,
or an observable output; none exists. The end-to-end trigger is a host
DoS/native heap corruption, not an escape. Pre-grow removes the bug.

## Other host-fuzz results

- `i1.b` RenderNode discard/sync race: not reproduced and statically unlikely.
  `i1.b` discards pending `I` under `synchronized(i1.s)`; the UI `b1` moves
  `I` to `H` and nulls `I` under the same lock; the UI draws `H`; every record
  creates a new `a0`. 165 HTML pages, 52k mutated TWDL lists and 30k mutated
  `canvasRun` streams produced no crash. No path where the discarded node is
  the drawn node.
- `layers()` int overflow: the `record_probe.js` corpus with `±1e38`,
  `INT_MIN`/`INT_MAX` and 4294967295 layer bounds completed on the Sony API 33
  with no crash. The software `ImageReader(w,h)` fallback is not reached on the
  hardware path; a direct software-canvas test was blocked by Frida timeouts.
- `canvasRead`/`canvasRelease`: end-to-end stock-user-space host SIGABRT in
  `Bitmap_getPixels` (`Error, cannot access an invalid/free'd bitmap here!`,
  tombstone 29). DoS only; the JNI aborts before copying pixels, no leak.
- `filterPixels`: zero calls on API 33 across shadow/blur/backdrop pages. On
  API <=30 the software branch has a one-row read-only OOB; no practical leak
  on the 4.19/API-33 target.
- `recordLayer`/`canvasRun`: the only stock-reachable host race, on
  `WidgetSandboxBackend.pendingLayers` (plain `HashMap`, one writer and a
  keyed get/clear on the other thread). Dropped layer updates, no native memory
  effect found.
- `signal(13)`: the isolated callback can invoke
  `ClipboardManager.setPrimaryClip` through the host (`SETCLIP
  text=CLIP-FROM-ISOLATED`). A host-only API call with a live debug view, not
  an app-data read. `createVirtualDisplay` from the isolated process is denied
  (`packageName must match the calling uid`).
- Validator, JNI strings, Parcel handling: 52k mutated TWDL, 27k systematic
  extreme words and 30k mutated `canvasRun` streams produced no
  SIGSEGV/SIGABRT/tombstone. The Java layer is memory-safe; the native
  `filterPixels` OOB is the only parser-adjacent issue found.

## Alternate host audit

A second pass over the remaining host surfaces is negative.

- `filterPixels` is unreachable on 72989: `a0.a()` is a hardware
  `RecordingCanvas` (measured `isHardwareAccelerated()==true`), the software
  `b0` path is selected only for SDK < 29, and backdrop/image-filter render
  nodes are hardware. Extreme layer/backdrop/filter bounds (`±1e38`,
  `INT_MIN`/`INT_MAX`, `0xFFFFFFFF`) are clean.
- Shared `Paint`/`Shader` lifetime race: a pre-grown 50k clip path plus one
  gradient-record thread and eight fill-record threads (9 x 2000 calls) did
  not crash. A true `SkPaint`/`SkShader` ownership race remains unproven.
- Correction to the pre-grow result: pre-growing removes the `growForVerb`
  realloc/free and the Scudo chunk-header UAF, but **not** the `SkPath`
  null-read race. A pre-grown path still crashed in
  `SkPathPriv::IsRectContour` (`tombstone_05_pregrow_grad`).
- Cross-canvas `h.c` op-5 / `g.canvasBitmap` race: 20,000 source-canvas
  resizes while drawing into another canvas did not abort; bounded by the
  invalid-bitmap abort class.
- Bitmap-lifetime races cannot leak. libhwui `Bitmap_getPixels` refs the
  `android::Bitmap` before the pixel access; a 2048x2048 `canvasRead` raced
  against `canvasRelease` at 0-2 ms (copy 96 ms) returned intact red pixels
  every time; an earlier release gives only a Java recycled-bitmap
  exception/abort. No host-memory read channel.
- Bitmap parcel accepts invalid `SkAlphaType` (4/5/6/7/0x7fffffff/-1);
  ARGB_8888 is blocked by the Java non-premultiplied check, while RGB_565,
  ALPHA_8 and RGBA_F16 invalid-alpha bitmaps draw natively and safely. A
  framework hardening note, not a primitive.
- Re-checked negative: `canvasRun`/`canvasRead` dimension products are 64-bit
  in the bytecode; `i.b` header/table/blob bounds are complete; `z0`
  gradient/filter/path counts are pre-checked; a fresh `canvasRead` is all
  zero.

Host DoS only: `Q0` 16 MiB chunk accumulator lets `signal`/`selectableText`/
`defineFont` parse unbounded JSON/feature strings (OOM/StackOverflow/CPU);
`h.g`/`h.f` advance the canvas word cursor by `ncmd+nfl`, so negative counts
can hold/reverse it and turn `canvasRun` into a monitor-holding loop
(source-derived, not device-run); `n0.m` decompression has no output cap
(pre-existing F4).

Exact wall: replies expose only `float[6]` metrics, one `float`, and the
`canvasRead` pixels we supplied. Bitmap UAFs are ref-protected before pixel
access (abort/exception only); `filterPixels` is unreachable; the SkPath
corruption has no observable output. A controlled primitive still requires a
host heap leak, a reclaim giving an absolute-pointer read/write without a
leak, or a host OOB read folded into `canvasRead`; none exists on this build.

## Reverse IWidgetEngine direction

The host client to isolated service direction is negative. `IWidgetEngine` has
12 oneway methods and two two-way methods: create (code 1) returns
`[exception-int][long]`; conformance (code 14) returns `[exception-int]`. The
host proxy reads only `readException()` and `readLong()`; every other call uses
`transact(code, parcel, null, 1)`. The only service-derived value is the
code-1 long; it is stored in `o0.d` and used only in calls back to the same
isolated service. No host API, map key, pointer, allocation, classloader or
native call consumes it. A mutated create reply (`0x123456789abcdef`) was
stored; the live service token was echoed in `visible`/`tick`.

The host reads no `Parcelable`, `Bundle`, `IBinder`, fd, array or string from
replies. Injecting 20 fds and 5 strong binders into code-14 replies left the
host fd count unchanged (176 to 176); empty, truncated, negative-length, 1 MB
exception-string, 200 KB-extra and 400 random replies caused only Java
exceptions; host and isolate stayed alive. A foreign `onBind` binder is
blocked: the client always writes the
`org.telegram.utils.twidget.IWidgetEngine` token; feeding the
`activity`/`package`/`display`/`webviewupdate`/`permissionmgr` binders and the
host `o0` callback binder to `q0.onServiceConnected` produced
`SecurityException: Binder invocation to an incorrect interface` for all six.

The only robustness gap is that `a.t` does not validate the reply length/long:
an empty reply yields session id 0 and the host calls the service with 0. It is
reachable only by a compromised service that already has isolated code
execution; it degrades the widget session, not a host primitive.

## Second-stage audits (72989)

The second-stage source audit and the host UI/WebView/service audit are
complete and negative; full detail in
[`SECOND_STAGE_AUDITS_20261108.md`](SECOND_STAGE_AUDITS_20261108.md).

- Public `DrKLO/Telegram` 13.2.1 is older than beta 72989. The 72929 → 72989
  diff adds 29 `twidget` classes and `WidgetEngineService`
  (`exported=false`, `process=":widgets"`, `isolatedProcess=true`) and no new
  host file/component surface; widget assets are byte-identical.
- The only new host-native parser reachable from a stock widget is the Wallet
  BOC engine. `WalletEngine2.isValidCellBoc` reaches Rust `ton_core 0.1.4`,
  where `raw_boc.rs:170` indexes `cells[cells_len - 1 - root_index]` without a
  `root_index < cells_cnt` check. A 20-byte BOC indexes
  `18446744073709551361`; the public crate panics. If the panic crosses JNI
  the host aborts (DoS), otherwise the call returns false. Not RCE.
- Wallet `signData` shows only attacker `payload.text` but signs the real
  payload (blind signing); `Browser` appends `autologin_token` to
  server-listed hosts (latent, no leak demonstrated); cross-session callbacks
  are an isolated-process amplifier only.
- UI/WebView/service: RenderNode discard (`i1.b:173`) only touches the pending
  node; `layers`/filter state is per call and the filter cap is 64-bit;
  the SDK WebView renderer is absent and `openLink` is user-confirmed; service
  create/destroy/rebind is lock-consistent. H-1 (browser proxy origin check
  skipped when `G0 == null`), H-2 (frame gate stalls on a null `h1()`) and
  H-3 (destroyed-session backend drivable) are host-only, no primitive.

## Real-chain requirements

A native payload in the isolated process can spawn 16 pthreads, attach each
to the JVM, build Parcels and call `IBinder::transact(6, ...)` on the callback
binder. The c2560s final is the device-proven native route; the parser stage A
works but its endgame is `NOANCHOR`. The next payload is a c2560s-style stage
B that spawns the threads and calls `transact(6, ...)` instead of the C2
socket; no network is used. `execve` is trapped, so there is no shell after a
successful escape.

## Status

No stock widget-only Telegram RCE was reproduced, and the app-process escape
is not achieved. The shared SkPath race is a genuine Telegram native
memory-corruption bug: the end-to-end isolated trigger is achieved (16
pthreads, Scudo chunk-header race, 8-byte UAF write); all heap/leak options,
the alternate host surfaces and the reverse IWidgetEngine direction are
negative. The source and UI/WebView/service audits found no second primitive
and no app-data read; the Wallet BOC panic is a new host DoS candidate pending
a live test. The remaining wall is a host heap leak, a reliable SkPathRef
reclaim with a fake absolute fPoints pointer, or a host OOB read folded into
canvasRead. The end-to-end effect is a host DoS/native heap corruption, not an
escape. Root and Frida were used only for instrumentation; the direct host
reproduction is not the final chain.
