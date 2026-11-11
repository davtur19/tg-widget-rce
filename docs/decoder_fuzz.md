# Bot-delivered media decoders in Telegram Android 72799 — fuzz/audit report

Date: 2026-11-02. Host-only (no phone, no emulator, no VM). Lab:
`lab/decoder_fuzz/`. This note does not modify the main report.

## 0. Verdict

**One memory-safety bug was reproduced in a host model of the app-bundled
TGS path**: a race-dependent **heap-use-after-free** in the `RLottieNative`
check-then-free lifecycle around tlottie (`Budget::transform`, ASan). The
Android Java timing itself was not run; the model proves the guard pattern is
unsafe, not that an end-to-end app crash is deterministic. The realistic
impact is a remote crash/DoS; RCE is speculative (no heap-reuse/write
primitive was demonstrated). No other memory-corruption bug was found in the
bot-reachable app-bundled decoders (GIF/FFmpeg, VP9/WebM, tlottie parser).

What *was* found is a **bot-deliverable resource-exhaustion DoS** in the GIF
path:

- A **43-byte GIF** with a 16000×16000 logical screen makes the bundled
  FFmpeg 8.1.3 GIF decoder allocate and fill a **~1.04 GiB** canvas during
  `avformat_find_stream_info()`, before Telegram's 3840 px check runs.
  Host measurement: peak VmRSS 1,088,240 KiB, ~3.9 s; under a 512 MB RSS
  budget the process is killed. On a phone this is an OOM/ANR risk, not
  memory corruption.
- A lower-severity TGS gzip-expansion issue exists (the JNI loop has no
  decompressed-size cap), but the platform gzip is system `libz.so` and the
  Telegram sticker cap is 64 KiB compressed, so the practical ceiling is
  tens of MiB, not a reliable crash.

The rlottie C++ premise does **not** apply to 72799: the TGS parser is
statically linked Rust **tlottie**; the known rlottie CVE family is absent.
WebP is **not** parsed by `libtmessages` at all; static WebP stickers go to
Android `BitmapFactory`/Skia. Therefore the only app-bundled bot-media
parsers are FFmpeg (GIF, video stickers/WebM, videos/audio) and tlottie.

The custom-emoji TGS path is stronger than “chat open”: the **chat list
itself draws custom-emoji TGS documents on cold start**, without opening the
chat. A bot that owns a custom-emoji sticker set can place such an emoji in
the last message text/caption, so a cached TGS is parsed/rendered while the
dialog list is drawn. This is the update-surviving startup trigger analyzed
in §1.2 and §5.2. The tlottie parser itself was negative (safe Rust; no
panic in 300k mutations), but the Android JNI lifecycle's check-then-free
race is reproduced as a host UAF (§5.2.1). Resource exhaustion (§3/§4) is a
separate, deterministic DoS.

TGS-specific summary: the parser is safe Rust **tlottie 31f1b54** (shared
with iOS); 81 real TGS files and 300k mutated JSON inputs produced no panic,
and the audited `unsafe` blocks are bounds-checked. The TGS **DoS** surface
is the JNI's unbounded gzip inflation (system `libz.so`; ~60 MiB from a
64 KiB sticker; multiplied by multiple custom emoji at chat-list startup).
The TGS memory-safety finding is the race-dependent `RLottieNative`
check-then-free UAF reproduced in §5.2.1; it needs a concurrent
render/destroy, which the chat-list startup path makes plausible but does not
prove end-to-end.


Everything below is crash/DoS unless explicitly called memory-safety.

## 1. Target and exact versions

| | |
|---|---|
| App | `org.telegram.messenger.beta` 13.2.0 beta (72799), arm64 |
| Native lib | `lib/arm64-v8a/libtmessages.49.so`, 27,016,000 B, md5 `2c0caa68a07fc26f79d13519af6c3526`, BuildId `645cce3998197329915f6cbfcc9ffd7f124d9f86` |
| FFmpeg | tag **n8.1.3**, commit `1041abdc962f4cc4f394aa8de9dc5236c0c3b9e7`; `Lavc62.28.103`, `Lavf62.12.103` |
| libvpx | **1.17.0**, commit `6df3ec34557879fff673706f4a1d9fbd0f3a6f0e`; app build config has `--size-limit=4096x4096` |
| tlottie | **31f1b542f88e7b4be9a01e749920d857535fc715** (2026-09-11), statically linked Rust; pinned by both `Android/.gitmodules` (tree 13.1.1) and `iOS/.gitmodules` |
| zlib | **platform** `libz.so` (`gzopen`/`gzread`/`inflate` are undefined imports; `readelf -d` shows `NEEDED libz.so`) |

Evidence anchors:

- FFmpeg version strings in the binary: `Lavc62.28.103` @`0x28a5d5`,
  `Lavf62.12.103` @`0x246ca1` (also `notes/ida_media_parsers_72799.md`).
- libvpx configure blob: `--size-limit=4096x4096` at file offset `0x21bc66`
  (`strings -a -t x libtmessages.49.so`).
- TGS JNI functions are `Java_..._RLottieNative_nCreate` @`0x74F710`,
  `rlottie_jni_create_impl` @`0x74F924`, `nGetFrame` @`0x750228` in the
  72799 IDB. The actual wrapper source is
  `Android/TMessagesProj/jni/lottie.cpp` (tree 13.1.1, which pins the same
  tlottie commit); its `nCreate`/`nGetFrame`/`nDestroy` match the 72799
  decompile. The parser behind them is Rust tlottie: the binary contains
  Rust panic machinery (`panicked at`, `/rust/deps/miniz_oxide-0.8.9/...`)
  and no rlottie C++ RTTI/source paths; see `notes/db_native_parsers.md` §1.
- `libwebp`/`libjpeg`/`libpng` are absent: no `VP8L`, `RIFF`, `WebPDecode*`,
  `jpeg_*`, `FT_*` symbols/strings; `Utilities.loadWebpImage` is not
  exported by the 72799 `.so` (`nm -D`).
- The app-bundled FFmpeg build is the trimmed set in
  `build_ffmpeg.sh`: demuxers `mov,gif,ogg,matroska,mp3,aac`; decoders
  `h264,hevc,mpeg4,mjpeg,gif,alac,mp3,aac,flac,libdav1d,libvpx_vp9`;
  `--disable-zlib`. Our host build matches this set.

### 1.1 The provided 9.7.6 source is not the 72799 source

`/tmp/opencode/telegram_src` is public **9.7.6 (3721)**, Aug 2023, with
rlottie C++ and bundled libwebp/mozjpeg in `jni/`. The target APK is
**13.2.0 (72799)**, Oct 2026. The binary proves the newer tree: Rust tlottie,
no libwebp/mozjpeg JNI, FFmpeg 8.1.3. All native conclusions here use the
72799 binary/IDB plus upstream sources at the pinned versions; the 9.7.6
tree is only a historical reference.

A newer Android tree is available at `<HOME>/ailocal/Telegram/Android`
(**13.1.1 / 7237**, commit `3de37c8cfb039452be7398909461da6288babf15`,
2026-10-25). It pins `TMessagesProj/jni/tlottie` to the
same `31f1b54` commit and contains the real `lottie.cpp` and `gifvideo.cpp`.
The 72799 binary is a later build, but its decompiled `nCreate`/`nGetFrame`/
`nCreateDecoder`/`writeFrameToBitmap` match this source. The 13.1.1 tree is
used as the source reference below; version-specific 72799 differences are
noted where visible.

### 1.2 Chat-list custom-emoji TGS reachability (cold start)

The user-provided widget-cache subagent found the startup path; it is
confirmed in the 72799 smali:

```
vi.smali:3691/3726        TL_messageEntityCustomEmoji -> new o5(document)
v2.smali:30712            DialogCell.onDraw -> o5.drawAnimatedEmojis(...)
f5.smali:916              ImageReceiver.B() -> ci0 (RLottieDrawable)
ci0.smali:789/1350/1426   RLottieNative.a(...) / b(...) -> JNI nCreate
RLottieNative.smali:511-520  native nCreate/nCreateWithJson/nGetFrame/nDestroy
```

A custom-emoji entity in the **last message text or caption** is turned into
an `AnimatedEmojiSpan` (`o5`) when the dialog cell lays out its message. The
cell's `onDraw` calls `o5.drawAnimatedEmojis`, which starts the emoji
drawable (`f5`), gets its `ci0` renderer, and calls `RLottieNative` to create
and render the TGS. The chat list is drawn at cold start, before any chat is
opened, so a TGS already in the cache is parsed and rendered at startup.

Delivery: a bot can create a **custom-emoji sticker set** (`createNewStickerSet`
with the custom-emoji type) and send a message containing the custom emoji.
The document is small and is auto-downloaded/cached like other stickers; the
message and cache file persist in the chat DB/cache. No file planting, root,
QuickJS, or prior RCE is involved.

The same TGS parser is shared with iOS: the iOS tree pins
`submodules/tlottie/tlottie` to the identical
`31f1b542f88e7b4be9a01e749920d857535fc715` commit and `TLottieAnimation.mm`
calls the same `tlottie_new_with_options`/`tlottie_render` C API. macOS uses
`submodules/rlottie` (C++), not tlottie. So a tlottie parser bug is
Android+iOS; the Android JNI/gzip wrapper and the `RLottieNative` lifecycle
are Android-specific.

| Platform | TGS/custom-emoji parser |
|---|---|
| Android 72799 | tlottie `31f1b54` (Rust static lib) + Android JNI `RLottieNative` |
| iOS | tlottie `31f1b54` via `TLottieAnimation.mm` (same C API) |
| macOS | rlottie C++ (`submodules/rlottie`), different parser |



## 2. Method

- Built FFmpeg **n8.1.3** from the exact tag on x86_64 with
  `-fsanitize=fuzzer-no-link,address,undefined` and the app's component set
  (`lab/decoder_fuzz/src/build_ffmpeg_asan.sh`).
- Harness `fuzz_decoder.c`: memory AVIO with `usetoc=1` and
  `AVFMT_FLAG_FAST_SEEK`, `avformat_open_input` → `find_stream_info` →
  best video stream → `avcodec_send_packet`/`receive_frame`, 24 frames,
  2 MiB input cap. This mirrors `AnimatedFileNative.nCreateDecoder`
  (`avformat_open_input` + `avformat_find_stream_info` +
  `avcodec_*`; see 0x74DC98 / 0x74D084 / 0x74F458 / 0x74F30C).
- Replayed public OSS-Fuzz corpora with FFmpeg's own pinned targets
  (`target_dem_fuzzer.c`, `target_dec_fuzzer.c`) so the fuzz inputs' 2048-byte
  control block is interpreted correctly.
- Built libvpx 1.17.0 with the app's `--size-limit=4096x4096` for the WebM
  video-sticker path.
- Built tlottie at the app's `31f1b54` and ran a parse+render panic scanner
  (`panic_scan`) and a 300k-iteration mutation loop (`panic_fuzz`) with
  `catch_unwind`.
- All logs and commands are under `lab/decoder_fuzz/logs/`.

## 3. Finding F1 — bot GIF canvas bomb (crash/DoS, not memory-safety)

### 3.1 What happens

A GIF's logical screen width/height are 16-bit fields. FFmpeg's GIF decoder
accepts them up to the generic image-size limit
(`av_image_check_size2`: for RGB32, roughly <268M pixels) and allocates a
full canvas. On the first keyframe it calls `gif_fill()`, which writes every
pixel:

- `libavcodec/gifdec.c:76` `gif_fill()` loops `h × w` and stores 4 bytes per
  pixel.
- `libavcodec/gifdec.c:186` `gif_read_image()` clips the *image descriptor*
  to the screen but the frame buffer is already the full screen size.
- `libavcodec/gifdec.c:430` `gif_decode_frame()` calls
  `ff_set_dimensions(avctx, screen_width, screen_height)` and
  `ff_reget_buffer()`.

`AnimatedFileNative.nCreateDecoder` calls `avformat_find_stream_info()` at
0x74DC98, which opens the GIF decoder and decodes the first frame. Telegram's
only dimension guard is in Java, **after** `AnimatedFileNative.a(...)`
returns:

- `smali_classes3/org/telegram/ui/Components/s5.smali:616` creates the
  native decoder.
- `s5.smali:638-652` checks `data[0] > 0xf00 || data[1] > 0xf00`
  (0xf00 = 3840) and only then calls `AnimatedFileNative.f()` to destroy it.

So the 1 GiB allocation/fill happens before the cap.

### 3.2 Reproduction and measurements

PoC: `lab/decoder_fuzz/pocs/gif_16000.gif` — **43 bytes**:

```
47 49 46 38 37 61   GIF87a
80 3e 80 3e         screen 16000 x 16000
81 00 00            GCT flag, 2 colors
00 00 00 00 00 00   global color table
2c 00 00 00 00      image descriptor, left/top 0
01 00 01 00         image 1 x 1
00                  flags
08                  LZW min code size
04 00 01 04 04 00   LZW data + terminator
3b                  trailer
```

Host run (`build/fuzz_decoder_vpx`, FFmpeg n8.1.3 + ASan/UBSan):

```
./build/fuzz_decoder_vpx -runs=1 pocs/gif_16000.gif
# exit 0; sampled VmRSS peak 1,088,240 KiB (~1.04 GiB); real 3.855 s
```

With a 512 MB app-like budget:

```
ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:hard_rss_limit_mb=512 \
  ./build/fuzz_decoder_vpx -runs=1 pocs/gif_16000.gif
# ==...==AddressSanitizer: hard rss limit exhausted (512Mb vs 567Mb) -> abort
```

A 51-byte variant with GCE disposal=3 (`pocs/gif_16000_restore.gif`) was also
tested; it allocates the canvas and the restore buffer (peak measured
1,088,088 KiB in this build; the restore buffer is allocated lazily).
46300×46300 is rejected by FFmpeg's size check; 16000×16000 is accepted.

### 3.3 Reachability from a bot message

- A bot can send a GIF/animation (Telegram's GIF/animation path permits files
  up to 2 MB; the PoC is 43 bytes). The message and its file persist in the
  chat DB/cache; no user file-planting, root, or prior RCE is used.
- When the chat containing the GIF is opened (the media is bound/visible), `s5` (AnimatedFileDrawable) creates
  `AnimatedFileNative.a(path, data, ...)`; the native decoder opens the
  cached file and runs `avformat_find_stream_info`.
- The GIF is decoded by the **app-bundled** `libtmessages.49.so`; it is not a
  platform/Skia path.
- This is a **crash/DoS**: OOM kill or multi-second background decode
  stall/ANR risk, not an out-of-bounds access, so no control-flow primitive. Repeated
  oversized GIFs in one chat amplify the memory pressure; a single PoC is
  already ~1 GiB transient on the host.

### 3.4 Update survival

`libtmessages.49.so` and its FFmpeg are shipped inside the APK; the decode
path and the Java-side late cap are app code. An app update that does not add
a pre-open dimension cap (or a lower FFmpeg `max_pixels`) keeps the issue.
It is not an OS-decoder bug and does not depend on the device patch level.
The current 72799 build is affected.

## 4. Finding F2 — TGS gzip expansion (low-severity DoS)

`Java_..._RLottieNative_nCreate` @0x74F710 does:

```
gzopen(path); while ((n = gzread(gz, stackbuf, 0x4000)) > 0)
    append(&string, stackbuf, n);   // sub_16A57AC, no decompressed cap
```

The decompressed bytes are then passed to tlottie. There is no 2 MiB
uncompressed cap in this JNI (iOS/Desktop rlottie loaders historically had
one). With Telegram's 64 KiB compressed sticker cap, deflate's maximum ratio
caps the practical expansion at roughly 60–66 MiB for one member; a 64 KiB
gzip of zeros is ~66 MiB of `std::string`, then tlottie rejects it. This is a
memory/CPU spike, not memory corruption. A 64 KiB multi-member gzip does not
change the ratio ceiling materially.

Host evidence: 60 MB of zeros compresses to 61,173 bytes with gzip -9; the loop
allocates that 60 MB before parsing. The gzip implementation is the platform
`libz.so`, so a zlib-level bug would be an OS issue, not app-bundled.

**Startup amplification via custom emoji (chat list).** Because the chat
list draws custom-emoji TGS documents at cold start (§1.2), a bot can put
several custom emoji in the last-message text. Each unique TGS is
decompressed independently before tlottie's 16 MiB `max_input_bytes` check;
with the 64 KiB compressed sticker cap each can expand to roughly 60–66 MiB
(a single-member deflate ratio ceiling). Ten distinct emoji are already
~600 MiB of transient allocation while the dialog list is being drawn; the
parser then rejects the non-JSON payload. This is a startup OOM/ANR **DoS**,
not memory corruption, and it depends on the Telegram server accepting the
gzipped sticker without validating the decompressed payload. It is listed as
a low/medium-severity follow-up, not a proven crash.

A **valid-Lottie** variant is `pocs/tgs_min_pad_16m.tgs`: a 594-byte valid
512×512 Lottie padded with JSON whitespace to 16,776,192 bytes, gzip -9 to
**16,573 bytes** (inside the 64 KiB sticker cap). tlottie parses it (host
`panic_scan`: 18 ms); the Android JNI allocates the full 16 MiB string before
the parser's `max_input_bytes` check. A bot custom-emoji set can contain many
such documents; a last-message line with 10–50 custom emoji multiplies the
transient allocation. Server-side uncompressed-size validation is the
gating unknown.



## 5. Fuzzing/audit results (parser negatives; JNI race)

### 5.1 GIF demuxer + decoder

- OSS-Fuzz `ffmpeg_dem_GIF_fuzzer` corpus: **1,761/1,761** inputs replayed
  through `build/dem_gif`; no ASan/UBSan memory error
  (`logs/replay_gif_demux_cov.log`).
- OSS-Fuzz `ffmpeg_AV_CODEC_ID_GIF_fuzzer` corpus: **1,035/1,035** inputs
  replayed through `build/dec_gif`; no ASan/UBSan memory error
  (`logs/replay_gif_dec_corpus.log`).
- Coverage-guided fuzzing of both targets was run (logs `fuzz_gif_*.log`);
  no crash artifacts. The decoder was audited against
  `libavcodec/gifdec.c`: clipping of `left/top/width/height` to the screen,
  `pw`, `gce_*`, `stored_img`, interleaved pointer math, and palette indexing
  are internally consistent. Palette indices above a short local palette read
  uninitialized color entries (within the 256-entry array), not OOB.
- No post-n8.1.3 GIF memory-safety fix exists upstream; the only recent GIF
  commit is `ae9e69781b` (“don't return AVERROR_EOF”, Sep 17 2026), already
  in n8.1.3.

### 5.2 TGS / tlottie

- 81 real Telegram `.tgs` assets (from the iOS resources and
  `TMessagesProj/src/main/res/raw`) decompressed and parsed/rendered at
  256×256, 1×1, and 2000×2000, four frames each: **0 panics**
  (`logs/tlottie_panic_scan.log`).
- 300,000 mutated JSON inputs (byte flips, inserts/deletes, huge numbers,
  NaN/Inf, truncation, token duplication): **0 panics**
  (`logs/tlottie_mutation_300k.log`).
- tlottie is safe Rust outside a few audited `unsafe` blocks:
  `mapped_accumulator.rs` and `mapped_surface.rs` check `checked_mul`,
  `mmap` failure (`(isize)-1`), and use `get_mut(range)`; the C API checks
  `out_len >= width*height` with `checked_mul` before constructing the output
  slice (`bindings/c_api.rs`). The parser enforces canvas/geometry limits.
- rlottie C++ (and its CVE-2021-31320/31323 family) is not in the 72799
  binary. The premise in the task (“check the 9.7.6 source for rlottie”)
  applies to the stale 9.7.6 tree, not 13.2.0.
- Cross-platform: iOS pins `submodules/tlottie/tlottie` to the same
  `31f1b542...` commit and uses `tlottie_new_with_options`/`tlottie_render`
  in `TLottieAnimation.mm`; macOS uses `submodules/rlottie` (C++). A tlottie
  parser bug is therefore Android+iOS, not macOS. The gzip decompression and
  the `RLottieNative` lifecycle are Android-specific.

#### 5.2.1 `RLottieNative` check-then-free race — reproduced in a host model

**Class: race-dependent heap-use-after-free (memory-safety); crash at
minimum; RCE speculative. App-level Java timing not reproduced; the native
consequence is reproduced under ASan. This is a code-level finding in
Telegram's JNI wrapper, not a known upstream tlottie CVE.**

The Android source (`Android/TMessagesProj/jni/lottie.cpp`, tree 13.1.1,
same tlottie pin as 72799) is small enough to audit directly:

```c
JNIEXPORT void nDestroy(JNIEnv*, jclass, jlong ptr) {
    tlottie_drop(reinterpret_cast<TLottieInstance *>(ptr));
}
JNIEXPORT jint nGetFrame(JNIEnv *env, jclass, jlong ptr, ...) {
    if (ptr == 0 || bitmap == nullptr) return 0;
    auto *instance = reinterpret_cast<TLottieInstance *>(ptr);
    ...
    tlottie_render_with_options(instance, ...);   // no refcount/lock
}
```

`tlottie_drop` frees the instance (`Box::from_raw`); `tlottie_render_*` only
takes a raw pointer. The Java wrapper tries to guard this with an
`AtomicBoolean`, but the guard is a check-then-act:

```
c(I, Bitmap, Z):                    d():
  if (destroyed.get()) throw          if (destroyed.compareAndSet(false, true))
  ptr = b;                               b = 0; nDestroy(ptr);
  nGetFrame(ptr, ...)                 // tlottie_drop(ptr)
```

There is no lock, refcount, or in-flight counter. Concrete cross-thread path
in `ci0`:

- `ci0.B(Bitmap,Z)` (render path, `ExecutorService R0`/`S0`,
  `ci0.smali:2063/2500/2657` and `:3422/3430`) loads `m0` and calls
  `RLottieNative.c(...)`.
- `ci0.D(Z)` nulls `m0` and posts `eb0(oldM0)`; the runnable calls
  `RLottieNative.d()` (`eb0.smali:848`) on the UI/handler thread. `D(Z)` is
  reached from `ci0.C(Z)`/`ci0.p()` when the drawable is stopped/recycled
  (`ci0.smali:2732/6025`). There is no `Future`/`shutdown`/`awaitTermination`
  wait for the render task.

So a destroy can overlap a render on the old object. A TGS that makes a
frame render long (many shapes, large geometry, 512–2000 px output) widens
the window.

Host reproduction: `src/uaf_guard_model.cpp` models the Java check-then-act
with a 1 ms window and calls the same `tlottie_new`/`tlottie_render`/
`tlottie_drop` C API. ASan result (`logs/uaf_guard_model_asan.log`):

```
==...==ERROR: AddressSanitizer: heap-use-after-free ... thread T1
READ of size 8 at ... in <tlottie::renderer::frame::budget::Budget>::transform
  /tmp/opencode/tlottie-31f1b54/src/renderer/frame/budget.rs:331:10
SUMMARY: AddressSanitizer: heap-use-after-free ... Budget::transform
```

The model is not the app: the Android Java threading was not run, and the
1 ms sleep is a proxy for the check-to-call/slow-render window. It does
prove that the wrapper's guard pattern is insufficient and that the tlottie
C API is not safe against concurrent drop. Exploitability is race-dependent;
at minimum this is a remote crash, and a heap-reuse could in principle become
a write primitive (ASan stops at the first read; no write primitive was
demonstrated).

Update survival: `lottie.cpp`/`RLottieNative` are app-bundled and the
tlottie pin is shared with iOS; an app update that adds a mutex or a
refcount/in-flight guard fixes it. Until then it is present in the 72799
lineage. The chat-list custom-emoji startup path (§1.2) makes the trigger
reachable without opening a chat. iOS uses the same raw C API in
`TLottieAnimation.mm` but a different wrapper/lifecycle; it was not analyzed
for this race.

### 5.3 WebP

- `libtmessages.49.so` has **no WebP decoder**: no `VP8L`/`RIFF`/`WebP`
  decode tables or `WebPDecode*`/`loadWebpImage` exports; the only “webp”
  strings are MIME/type names. `libwebp`, `libjpeg`, and `libpng` are not
  linked.
- Static WebP stickers are decoded by Android `BitmapFactory`/Skia in the
  app process. That is an OS/platform decoder; CVE-2023-4863-class bugs there
  depend on the device security patch, are outside `libtmessages`, and are
  not fixed by app updates. They are not app-bundled findings.
- Consequence for this task: a WebP sticker does not reach an app-bundled
  memory-unsafe parser in 72799.

### 5.4 Video stickers (.webm / VP9)

- libvpx **1.17.0** with the app's `--size-limit=4096x4096`:
  - OSS-Fuzz `ffmpeg_AV_CODEC_ID_VP9_fuzzer` corpus: **14,917/14,917**
    inputs replayed through `build/dec_vp9`; no ASan crash
    (`logs/replay_vp9_dec_corpus3.log`).
  - WebM containers extracted from the Matroska corpus: **4,278** replayed
    through the full demux+decode harness; no ASan crash
    (`logs/replay_webm_media2.log.gz`).
  - Coverage-guided Matroska demux fuzz: 33,072 execs, peak 1.1 GiB, no ASan
    crash (`logs/fuzz_mkv_dem.log`). One UBSan signed-overflow report at
    `libavformat/demux.c:943` (duration arithmetic) — UB/DoS class, not a
    memory-safety bug and not reproduced as a crash without UBSan.
- A 23-byte raw VP9 frame that makes libvpx request 2.3 GB in
  `vp9_dec_alloc_mi` was found in the VP9 corpus. With the app's
  `--size-limit=4096x4096`, the same input is rejected in 0 ms, so it is not
  a 72799 finding. This is an important fidelity check: an un-size-limited
  libvpx build produces a false OOM.
- No post-1.17.0 VP9 decoder memory-safety fix is known; the app ships the
  current release.

### 5.5 Other app-bundled media parsers

- FFmpeg `mov`/`matroska` demuxers and H.264/HEVC/MPEG-4/MJPEG decoders are
  reachable from bot-sent videos, not from GIF/TGS/WebP stickers. They were
  not the refinement target. A 297-byte OSS-Fuzz MOV input did expose an
  edit-list OOM/timeout in n8.1.3 (`mov_fix_index`, fixed after n8.1.3 by
  `10b634950382`, “bound the edit list rebuilt sample index”); it is a DoS,
  not memory-safety, and needs an MP4/video path rather than an animated
  sticker. Recorded here only as an adjacent observation.

## 6. Crash vs RCE assessment

| Finding | Class | Why |
|---|---|---|
| F1 GIF canvas bomb | **Crash/DoS** | Resource exhaustion (1 GiB fill, multi-second decode); all writes stay inside the allocated frame; no OOB/UAF, no attacker-controlled pointer or length. |
| F2 TGS gzip expansion (chat-list startup amplification) | **Crash/DoS (low/medium)** | Unbounded decompressed string allocation; bounded by the 64 KiB sticker cap to tens of MiB per emoji; multiple custom emoji multiply it at cold start; no memory corruption. Server-side validation caveat. |
| §5.2.1 RLottieNative check-then-free | **Race-dependent UAF; crash/DoS confirmed in model; RCE speculative** | AtomicBoolean guard is check-then-act; `nDestroy` can free the tlottie animation while `nGetFrame` renders. Host guard model reproduces ASan heap-use-after-free in `Budget::transform`; Android Java race not run end-to-end and no write primitive demonstrated. |
| GIF/VP9/tlottie fuzz negatives | — | No ASan/UBSan memory error, no panic in the tested corpora/mutations. |
| WebP | **Out of app scope** | Platform `BitmapFactory`/Skia; not in `libtmessages`; device-patch dependent. |

No confirmed write primitive or deterministic code execution was
demonstrated. The §5.2.1 UAF is the only candidate memory-corruption path;
its exploitation was not attempted, and the realistic impact is a crash/DoS.

## 7. Reproduction artifacts

All under `lab/decoder_fuzz/`:

- `src/fuzz_decoder.c`, `src/build_ffmpeg_asan.sh`
- `pocs/gif_16000.gif`, `pocs/gif_16000_restore.gif`,
  `pocs/gif_huge_screen.gif`
- `pocs/tgs_min_pad_16m.tgs` (16,573 B; decompresses to 16,776,192 B valid
  Lottie)
- `pocs/tgs_slow_2000.tgs` (24,951 B; valid 2000-layer Lottie, used to widen
  the render window)
- `src/uaf_guard_model.cpp` (Java check-then-free guard model; ASan UAF),
  `seeds/tgs_sample.json`
- `logs/uaf_guard_model_asan.log`, `logs/uaf_guard_model_lab_run.log`,
  `logs/uaf_guard_model_summary.txt`
- `src/uaf_race_model.c` (raw render/drop timing probe; no ASan report)
- `logs/poc_gif_16000_rss.txt`, `logs/gif_16000_rss512.log`
- `logs/replay_gif_demux_cov.log`, `logs/replay_gif_dec_corpus.log`
- `logs/replay_vp9_dec_corpus3.log`, `logs/replay_webm_media2.log.gz`
- `logs/fuzz_gif_dec.log`, `logs/fuzz_gif_dem.log`, `logs/fuzz_mkv_dem.log`
- `logs/tlottie_panic_scan.log`, `logs/tlottie_mutation_300k.log`
- `logs/versions.txt`, `logs/host_env.txt`
- `README.md` (build and exact commands)

Host: Debian 13, x86_64, clang 19.1.7, 8 cores. No device or emulator was
used. Host measurements are indicative of the allocation/decode cost, not a
device OOM certificate; the device's per-app memory limit and the Telegram
server's GIF/sticker validation were not tested.

## 8. Limits

- The Telegram server may reject or re-encode pathological GIFs before
  delivery; the PoC assumes the bot can deliver a GIF animation (Telegram's
  documented GIF/animation limit is 2 MB, and the PoC is 43 bytes).
- The app's actual decoder may stop after the first frame/probe differently
  from the host harness; the host `avformat_find_stream_info` path is the
  same FFmpeg n8.1.3 code and the JNI calls it identically.
- tlottie version is inferred from the app submodule (`31f1b54`) plus the
  Rust/tlottie strings; v1.0.5/v1.0.6 are later commits. If 72799 actually
  ships v1.0.6, the panic results are still negative; the parser is the same
  safe-Rust lineage.
- WebP platform bugs were not tested on a device; the conclusion is only
  that WebP is not an app-bundled parser.
