# JNI media boundary audit — integer/length bug → controlled write?

Target: `libtmessages.49.so` (Telegram Android **13.2.0**, versionCode **72799**, arm64)
MD5 `2c0caa68a07fc26f79d13519af6c3526`
IDB: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_media_annotated.i64`
(annotated + saved; functions below renamed from `sub_*`)
Lab: `lab/jni_media_bounds/` (host model, crafted GIFs, decompilation dumps)

**Verdict (TL;DR): no integer/length bug leading to a controlled write was found in the
requested JNI media boundary.** Every width/height/stride that reaches a native write is
either (a) taken from the Java `Bitmap` itself and therefore bounds the write, or (b) gated
by an equality check against the `AVFrame`, or (c) capped by Java at **3840 px per side**
before the frame path is ever used. The single 32-bit size product in the component
(`FFALIGN(bitmapWidth*4,16) * bitmapHeight`) needs a live **≥ 4 GiB** Bitmap before it can
wrap, and the wrapped branch hands `sws_scale` a multi-GiB write into a tiny allocation —
an immediate fault, not a controllable primitive. Details, evidence and a device test plan
for the residual DoS at most.

---

## 0. Method and source correspondence

* Hex-Rays on the arm64 IDB; JNI/Java side from the APK (`jadx72799_full`, baksmali dumps in `/tmp/opencode/dex72799`).
* The public Telegram 12.9.2 tree uses FFmpeg 8.0.x; the **72799 binary**
  carries `Lavc62.28.103`/`Lavf62.12.103`, which matches **FFmpeg 8.1.3**
  (confirmed by the media audit's n8.1.3 build; see
  `notes/local_message_media_ace.md` §4). The `AVCodecParameters` layout
  (`coded_side_data@32 / nb@40 / format@44 / bit_rate@48 / width@72 /
  height@76`) is used for the bounds proof and is version-independent here.
* `gifvideo.cpp` in the binary is a faithful match of public `DrKLO/Telegram` **12.9.2**
  (`TMessagesProj/jni/gifvideo.cpp` @ `b7561f0c64`, saved as
  `lab/jni_media_bounds/decompiled/gifvideo_12.9.2_reference.cpp`). All string references
  recovered from the native component match that file 1:1, including
  `gifvideo.cpp new stream`, `gifvideo.cpp stream`, `can't seek file %s`, `usetoc`,
  `refcounted_frames`, `getWaveform: op_read failed: %d`, etc. This makes the public source a
  valid model for line-level reasoning; every claim below was re-checked against the binary.

## 1. Function map (binary addresses)

`AnimatedFileNative` (TMessagesProj/jni/gifvideo.cpp):

| addr | function |
|---|---|
| `0x74dc98` | `nCreateDecoder` |
| `0x74d6ac` | `nGetVideoInfo` |
| `0x74eaf0` | `nGetVideoFrame` |
| `0x74e53c` | `nGetFrameAtTime` |
| `0x74e30c` | `nPrepareToSeek` (sets `info->seeking=1`) |
| `0x74e3fc` | `nSeekToMs` |
| `0x74e2fc` | `nStopDecoder` (sets `info->stopped=1`) |
| `0x74e224` | `nDestroyDecoder` (`delete VideoInfo`) |
| `0x74e6b0` | `writeFrameToBitmap` (the only AVFrame→Bitmap writer) |
| `0x74e31c` | `push_time` (`data[3]=ts*1000`) |
| `0x74e3ac` | `push_single_frame` (`data[7]=1`, **no length check**) |
| `0x74d084` | `open_codec_context` |
| `0x74f230` | `VideoFrameReader::ctor` |
| `0x74f30c` | `VideoFrameReader::getNextFrame` (0=Ok 1=Eof 2=Aborted 3=Error) |
| `0x74f458` | `VideoFrameReader::feedNextPacket` |
| `0x74f2b4` | `VideoFrameReader::seek` = `av_seek_frame(fmt, idx, pts, flags)` |
| `0x74f4e4` | `SwsContextHolder::get` → `sws_getContext` |
| `0x74f078` | `VideoInfo::~VideoInfo` |
| `0x74d3d0` / `0x74d520` | `readCallback` / `seekCallback` (custom AVIO for streamed files) |
| `0x74d240` | `requestFd` (resolves finished path from Java stream) |

`MediaController` / `AudioRecorderNative` (TMessagesProj/jni/audio.c):

| addr | function |
|---|---|
| `0x16f19a4` | `MediaController_getWaveform` |
| `0x16f1764` | `MediaController_getWaveform2` |
| `0x16f1658` | `MediaController_isOpusFile` |
| `0x16f234c` | `MediaController_cropOpusFile` |
| `0x16f2658` | `MediaController_joinOpusFiles` |
| `0x16f3888` | `AudioRecorderNative_nCropOpusFile` (same opus path, new recorder) |
| `0x16f3bc8` | `AudioRecorderNative_nGetWaveform` (thunk → `MediaController_getWaveform`) |
| `0x16f2260` | static `append_stream` (join helper) |

## 2. Data flow: file → AVFrame → Bitmap

1. `nCreateDecoder(path, data[8], account, streamFileSize, stream, preview)`
   * copies the Java UTF-8 path into a `new char[len+1]`;
   * `streamFileSize == 0` (local file) → `avformat_open_input(&fmt, path, NULL, NULL)` — **format is
     sniffed by content**, the extension is irrelevant; a `…gif` cache file can contain MP4/WebM/AV1/HEVC;
   * `avformat_find_stream_info` → `open_codec_context(VIDEO)` → `avcodec_alloc_context3` +
     `avcodec_parameters_to_context` + `avcodec_open2`;
   * allocates `VideoFrameReader(fmt, dec, idx)`;
   * writes the Java `int[8]`: `data[0]=dec_ctx->width`, `data[1]=dec_ctx->height`,
     `data[2]=rotation`, `data[4]=fmt->duration/1000`, `data[5]=fps`
     (arm64 stores confirmed as `STR W` at offsets 0/4/8/0x10/0x14 in `0x74dc98`).
2. `nGetVideoFrame(ptr, bitmap, data, preview, start_time, end_time, loop)`
   * `stopped`/`seeking` early-out; `getNextFrame()`;
   * `pastEnd = end_time>0 && frameTime(frame) > end_time`; loop→`seek(startPts)`+`getNextFrame()`;
   * `if (bitmap) writeFrameToBitmap(env, info, frame, data, bitmap);`
   * `push_time(env, info, frame, data)` → `data[3]`.
3. `nGetFrameAtTime(ptr, ms, bitmap, data)` — seek + decode until `frameTime >= ms/1000`,
   falls back to an `av_frame_ref`'d held frame at Eof, then the same `writeFrameToBitmap`.
4. `writeFrameToBitmap(env, info, frame, data, bitmap)` is the **only** place where file-derived
   geometry meets a writable buffer. Decompilation: `decompiled/writeFrameToBitmap.c`.

## 3. Every native write that consumes file geometry

### 3.1 `writeFrameToBitmap` (0x74e6b0)

Pseudocode (from the binary; `a2`=VideoInfo, `a3`=AVFrame):

```
if (IsSameObject(bitmap,NULL)) { push_time(...); return; }
dataArr = GetIntArrayElements(data,0);
AndroidBitmap_getInfo(env, bitmap, &info);          // return value NOT checked
w = info.width; h = info.height; stride = info.stride;
if (dataArr) { wantedW=dataArr[0]; wantedH=dataArr[1];
               dataArr[3]=1000*ts*q2d(tb);
               if (GetArrayLength(data) > 6) dataArr[6]=isOpaque; release; }
else { wantedW=w; wantedH=h; }
if (!((wantedW==frame->w && wantedH==frame->h) ||
      (wantedW==frame->h && wantedH==frame->w))) return;      // (A)
if (AndroidBitmap_lockPixels(env,bitmap,&pixels)) return;
sws = SwsContextHolder_get(info+64, frame->w, frame->h, frame->format, w, h, AV_PIX_FMT_RGBA);
if (sws && ((uintptr_t)pixels & 15)==0) {
    dst[0]=pixels; dstStride[0]=stride;
    sws_scale(sws, frame->data, frame->linesize, 0, frame->height, dst, dstStride);
    unlock; return;                                           // (B) bounded by Bitmap
}
if (frame->w != w || frame->h != h) {
    if (!sws && ...) {}
    else if (pixels unaligned) {                              // (C) fallback
        int32_t alignedStride = FFALIGN(w*4,16);
        int32_t bufSize = alignedStride * h;                  // 32-bit product
        buf = av_malloc((int)bufSize);
        sws_scale(sws, frame->data, frame->linesize, 0, frame->height,
                  {buf}, {alignedStride});
        if (alignedStride == stride) memcpy(pixels, buf, bufSize);
        else for (i<h) memcpy(dst, src, w*4), src+=alignedStride, dst+=stride;
        av_free(buf);
    }
    unlock; return;
}
/* (D) libyuv, only when frame->w==w && frame->h==h */
switch (frame->format) {
  YUV444P(5)   : H444ToARGB(src..., pixels, stride, w, h);
  YUV420P(0)/YUVJ420P(12): H420ToARGB or I420ToARGB (BT709), pixels, stride, w, h;
  BGRA(28)     : ABGRToARGB(frame->data[0], frame->linesize[0], pixels, stride, w, h);
  YUVA420P(33) : I420AlphaToARGBMatrix(..., pixels, stride, &kYvuI601Constants, w, h, 1);
}
unlock;
```

Bounds reasoning:

* (A) guarantees the decoded frame's geometry equals the values Java used to size the Bitmap
  **before** any conversion. MediaInfo array is written once by `nCreateDecoder` and never
  refreshed, so a mid-stream resolution change simply fails the check (no draw).
* (B) `sws_scale` destination is `(w,h)` = `AndroidBitmapInfo` with `dst_stride = stride`; Skia
  guarantees `stride >= w*4`, and the pixel buffer is exactly `stride*h`. Safe for every format.
* (D) is only reachable when `frame->w==bitmapW && frame->h==bitmapH`, and uses
  `stride`/`w`/`h` of the Bitmap for the destination. Safe (a smaller frame than the Bitmap is
  impossible here; a *larger* frame is rejected by (A)/(C)).
* (C) is the only 32-bit arithmetic: `FFALIGN(w*4,16)*h`. It is self-consistent on the allocation
  and the final `memcpy`, and `sws_scale` writes exactly `alignedStride*h` into that buffer.
  It can only misbehave when the **Bitmap itself** is ≥ 2 GiB (negative → `av_malloc` fails) or
  ≥ 4 GiB (wrap → short allocation, then a multi-GiB `sws_scale` → immediate fault).
  Model + numbers: `lab/jni_media_bounds/wftb_model.c` / `.out`
  (smallest square that wraps: 32768×32768 = **4.00 GiB** of pixels).

### 3.2 The Java layer caps the geometry at 3840 px **before** the frame path

`org/telegram/ui/Components/s5.<init>` allocates `this.d = new int[8]` (smali `0x53d69e`:
`const/16 v3, #8; new-array v4, v3, [I; iput-object v4, …s5.d`).
In the "prepare decoder" runnable (`q5.run`, case at `0x53c836`) the app right after
`AnimatedFileNative.a(path, this.d, …)` performs (`0x53c89a`):

```
53c8a2  iget-object v0, v1, s5.d:[I
53c8a6  aget v5, v0, 0            // d[0] = dec_ctx->width
53c8aa  const/16 v6, #int 3840
53c8ae  if-gt v5, v6, 0099        // width > 3840 -> destroy
53c8b2  aget v0, v0, 1            // d[1] = dec_ctx->height
53c8b6  if-le v0, v6, 00a1        // height <= 3840 -> keep
53c8ba  … AnimatedFileNative.f()  // destroy decoder, d0 = null
```

So any container/bitstream that advertises width or height > 3840 (GIF logical screen is 16-bit
→ up to 65535; MP4 tkhd is 16.16 → up to 65535; Matroska PixelWidth is 32-bit) results in the
decoder being destroyed immediately after the first parse. No Bitmap, no `sws_scale`, no libyuv.

For a decoder that survives the cap, `w,h ≤ 3840` and the (C) product is at most
`FFALIGN(3840*4,16)*3840 = 58,982,400` — four orders of magnitude below `2^31`.

`org/telegram/messenger/video/VideoFramesRewinder` (the second/only other caller of the
frame natives) allocates its `meta` as `new int[8]` (smali `0x665d7a`) and creates its bitmaps
with `w = min(viewW/4, meta[0])`, `h = min(viewH/4, meta[1])`, further scaled so that
`max(w,h) <= maxFrameSide = 480` (`0x666138..0x66615c`). Its (C) product is ≤ 1.7 MB.

### 3.3 Java array-length contracts (all call sites verified)

`nCreateDecoder` writes 6 ints (0,1,2,4,5; `[4]` is an 8-byte store covering `[4],[5]`).
`push_single_frame` writes `data[7]` with **no** `GetArrayLength` check; `writeFrameToBitmap`
guards `data[6]` with `GetArrayLength(data) > 6`.
Call sites (smali):

| caller | array | writes OK? |
|---|---|---|
| `s5.<init>` `0x53d69e` | `int[8]` | yes (0..7) |
| `VideoFramesRewinder.<init>` `0x665d7a` | `int[8]` | yes (0..7) |
| `n5.s` `0x8a3988` (thumbnails) | `int[11]` | yes |
| `mr0` `0x8a3994` (PhotoViewer video info) | `int[11]` | yes |
| `v50` `0x7e9fd6` | `int[11]` | yes |
| `rh/l5` (`[[I` created by `n5.s`) | `int[11]` | yes |

`nGetVideoInfo` writes indices 0,1,2,3,4,7,8,9,10 (confirmed from the arm64 `STR W` stores in
`0x74d6ac`; no 8-byte stores, the Hex-Rays “qword” view was the source field's width).
`nGetVideoFrame`/`nGetFrameAtTime` read `data[0..1]` and write `data[3]` (+`data[7]` on Eof).

### 3.4 Opus / waveform path (audio.c)

* `getWaveform`: global PCM buffer `malloc(0x20000)`, `op_read(file, buf, 0x10000, NULL)`.
  In the bundled libopusfile `_buf_size` is **total values** (not bytes), so
  `0x10000 * 2 = 0x20000` bytes → exact fit (`opusfile.c: nsamples*nchannels > _buf_size →
  nsamples = _buf_size/nchannels`, `memcpy(sizeof(*pcm)*nchannels*nsamples)`).
  Peaks go to `calloc(100,2)` with `if (idx <= 99) buf[idx++] = peak`;
  packed 5-bit stream into `calloc(0x43)` writing at most bytes 61..62; then
  `SetByteArrayRegion(env, NewByteArray(63), 0, 63, buf)` — sizes match.
* `getWaveform2(short[] s, int length)`: `length` comes from `array-length` at the only call
  site (`dump.txt 0x564066`), writes into the same 200-byte peak buffer with `idx<=99` guard,
  reads `s[0..length-1]` in-bounds.
* `cropOpusFile` / `AudioRecorderNative_nCropOpusFile`: `buf = malloc(1920*channels)` bytes;
  `max_frames = min(960, remaining/channels)`, then `op_read(file, buf, channels*max_frames)`
  (values) → at most `960*channels` values = `1920*channels` bytes. The channel count comes
  from `OpusHead` (0..255) and is the same value used for both the allocation and the read size.
* `joinOpusFiles` / `append_stream`: `channels = MIN(ch1, ch2)`, buffer `1920*channels`,
  `op_read(of, buf, 960)` (values) → ≤ 1920 bytes ≤ buffer. The `writeFrame(..., samples*channels*2)`
  byte count is ≤ what op_read wrote for that file.
* `isOpusFile`: `fopen` + `op_open_callbacks` with the bundled `FILE*` callbacks; on failure the
  object is cleaned (`sub_17D59E4` = op_free's guts) and `free()`d exactly once — the
  `cleanup; free()` pattern is correct for this build (op_free does not free the struct itself).

No length arithmetic derived from the file is used for a native write in this group.

## 4. Reachability from app data (unchanged by the negative result)

For completeness, the path a first-stage RCE would use:

1. Drop the crafted file at the path `FileLoader.getPathToAttach(document)` resolves to
   (`<app data>/cache/...`, account subdir; exact name is derived from the document's
   `id`/`access_hash`/`file_reference`), and
2. insert/update the message + document row so ImageLoader builds an `AnimatedFileDrawable`
   (`s5`) for it: image location type `"g"` (GIF) is rendered at chat list/chat open;
   a video-sticker document (`video` attribute, MP4/WebM) is rendered at chat open.
   `nCreateDecoder` is called from `s5`'s `q5` runnable on a worker
   (`Utilities.e`/`i0.g3`), the drawable is cached per document.
3. `avformat_open_input` sniffs content, so the file extension/content pair does not matter.

This is sufficient to reach **parsing and codec open** — but per §3, not a write.

## 5. Why “huge/odd-dimension GIF/MP4” does not reach the arithmetic

* FFmpeg’s GIF demuxer copies the 16-bit logical screen into `codecpar->width/height`
  (`libavformat/gifdec.c:127-133,227-228`, `width==0||height==0` rejected); the GIF decoder
  clamps each image descriptor to the screen (`libavcodec/gifdec.c:186-214`).
* `nCreateDecoder` propagates those values into `data[0..1]`.
* `s5` destroys the decoder when either value > 3840 (smali `0x53c89a`), i.e. before
  `Bitmap.createBitmap` for the animated drawable and before any frame decode.
* If the bitstream resolution differs from the container values, `wanted == frame` (A) fails
  and `writeFrameToBitmap` returns without touching the bitmap; a *smaller* frame is impossible
  because the Bitmap was created from the same numbers.
* `VideoFramesRewinder` never trusts the file size for its Bitmap: `min(view/4, dims)` then
  `maxFrameSide=480`.

Residual effect: a crafted file can still make the app waste time in FFmpeg parsing/decoding
and can make the Java layer construct a large-but-legal Bitmap; worst observed class is
`OutOfMemoryError`/`IllegalArgumentException` from `Bitmap.createBitmap` for dimensions that
slip through other call sites (e.g. `n5` thumbnail `int[11]` path → `Math.max(1, …)` sizes).
That is a **DoS**, not a controlled write.

## 6. Other findings in the component (not the requested bug)

* **UAF race (real, but a race):** `nDestroyDecoder` does `delete VideoInfo` while a decoding
  thread may be inside `nGetVideoFrame`/`VideoFrameReader`. `s5.f()` only does an
  `AtomicBoolean.compareAndSet` on the Java object and calls `nDestroyDecoder`; nothing
  serialises against the worker that calls `nGetVideoFrame`. Same for `sws_ctx_holder`
  (not thread-safe). This is the more promising Telegram-specific native lead (heap UAF), but
  it is a timing bug, not an integer/length bug, and it needs a re-allocation to become a
  write. Flagged, not claimed.
* `push_time`/`push_single_frame` dereference `GetIntArrayElements` without a NULL check
  (OOM → null deref). `push_single_frame` also writes `data[7]` unchecked — safe today because
  both callers pass `int[8]`, but a future caller with `int[6]` would corrupt the Java heap.
* `AndroidBitmap_getInfo` return value unchecked in `writeFrameToBitmap`; if it ever failed the
  dimensions/stride would be stack garbage. Not reachable from Java with a real `Bitmap`
  (`getInfo` only fails for non-Bitmap/null, and `IsSameObject(bitmap,NULL)` is checked first).
* `gifvideo` stream path (`readCallback`): `buf_size` is clamped to `file_size - last_seek_p`
  and `read(fd, buf, n)` runs on a 64 KiB AVIO buffer. The only way to exceed the buffer would
  be Java `AnimatedFileDrawableStream.read` returning > requested or < 0; the Java
  implementation clamps to the requested size and returns 0 on cancel/error
  (`AnimatedFileDrawableStream.read`, smali `0x47e0xx`; `m7.h` clamps with `Math.min`).
  No negative/oversized return path found.
* The `isOpusFile`/crop/join `cleanup + free` pairs are correct for this libopusfile build.

## 7. Verdict

* **No controlled write, no ACE claim.** The audited boundary is bounds-consistent and, on top
  of that, the Java layer refuses > 3840 px geometry before the frame path.
* The 32-bit `FFALIGN(w*4,16)*h` product is the only integer-size hazard; it is unreachable in
  a useful way (needs a ≥ 4 GiB live Bitmap; the wrapped write is an immediate fault).
* No PoC file is provided for a write because there is none. The crafted GIFs in
  `lab/jni_media_bounds/odd_dim_gifs/` are for parser/dimension reachability checks only.

### Recommended next leads for a *second local ACE*

1. `nDestroyDecoder`/`nGetVideoFrame` **UAF race** (heap UAF → need a reallocation primitive;
   `VideoInfo`, its `AVFormatContext`, and `SwsContextHolder` are all freed while reachable).
2. FFmpeg 8.0 decoder/demuxer surface reachable through the same `avformat_open_input(path)`
   (GIF, VP9, AV1, HEVC, H.264, Matroska) — content-sniffed, local file, no Telegram code needed.
3. Other Telegram-specific parsers that were out of scope here: `image.cpp`/`libwebp` (WebP
   photo documents), `rlottie` (TGS), `secureid_ocr`, `fast-edge` — each takes a document from
   the same DB and parses it natively at cold start.

## 8. Artifacts

* `lab/jni_media_bounds/decompiled/` — Hex-Rays dumps of every function listed in §1
  plus the matching public source (`gifvideo_12.9.2_reference.cpp`).
* `lab/jni_media_bounds/wftb_model.c` / `.out` — host model of the 32-bit product, proof of
  the ≥4 GiB threshold.
* `lab/jni_media_bounds/gen_odd_dim_gif.py` + `odd_dim_gifs/` — hand-built GIFs with
  3840/4000/65535/0 logical-screen and frame sizes (35 bytes each) to probe dimension
  propagation if ever needed.
* `lab/jni_media_bounds/test_plan.md` — optional device procedure (DoS-only expectation).

## 9. Follow-up: the `nDestroyDecoder` / frame-worker UAF — crashable, not (no-leak) PC control

This closes the strongest residual lead from §7.1. Full evidence, dumps and
tooling: `lab/jni_media_bounds/uaf/` (README, `classes.py`, malloc-tracing
probe, TGS reclaim generator, device plan). Summary:

**9.1 Lifetime.** `nDestroyDecoder` (`0x74e224`) calls `VideoInfo_dtor(info)`
(`0x74f078`) then `operator delete`. Free order: `VideoFrameReader` (96 B) +
`AVPacket` + `AVFrame` → `AVCodecContext` (864 B) → `AVFormatContext` (600 B) →
`src` → `ioContext` → `SwsContext` (53 KB) → `VideoInfo` (160 B) last. There is
**no join**: `nStopDecoder` only sets `stopped`, `nPrepareToSeek` only sets
`seeking`, and `s5.u()` (`0x53e190`) does an `AtomicBoolean` CAS then calls
`AnimatedFileNative.f()` (`0x53eafc`) → `nDestroyDecoder` directly, with no wait.

**9.2 The race is on the normal animation path.** Frame decode runs on
background threads: `s5.x(Z)` (`0x53e3e0`) posts the decode runnable (q5 case 7,
which calls `AnimatedFileNative.c` → `nGetVideoFrame` at `0x53cbba`) to
`DispatchQueue("decodeQueue"+this)` / `t5.a` / the static 8-thread
`ScheduledThreadPoolExecutor W0`; and q5 case 7 starts the frame-cache
generator (`rf.e.g()` → E0 → case 5 sets `s5.e = null` then posts `q5(9)` to
`DispatchQueue("cache generator queue")` → `rf.e.b()` → `s5.a()` →
`nGetVideoFrame` at `0x53d520`). `s5.u()` (`0x53e190`, UI thread) destroys only
when `e == null`, but case 5 has already cleared `e`, and
`cancelRunnable(D0)` cannot stop a generator that is already running. Hence the
UI thread can free the decoder **while a frame worker is inside
`nGetVideoFrame`**. The Java null check only protects between calls. A second,
narrower variant: the decode runnable's completion runnable F0 (q5 case 6)
clears `s5.e = null` unconditionally (`0x53cca6`), so a newer H0 queued by
`s5.x()` can be in flight while `u()` sees `e == null` and frees.

**9.3 Post-free call sites.** `shouldAbort` indirect call (reader+0x20),
`av_frame_unref` → `AVBufferRef->free` (frame+0x108), `avcodec_receive_frame` →
`avctx->codec->receive_frame`, `av_read_frame` → `iformat->read_packet` /
`pb->read_packet` (AVIOContext+0x30), `sws_scale` function pointers.

**9.4 Reclaim.** tlottie's `owned_string()` (`json.rs:127`, `parse.rs:2277`) is
an **exact-length, content-controlled, persistent** allocation for each JSON
`"id"`/`"refId"`: `malloc(len)+memcpy(len)`, no NUL, raw bytes (valid UTF-8,
no `"`/`\`; 0x00 and ASCII pointers are representable). Measured with the
pinned tlottie staticlib (`alloc_id_probe`): an 82-byte payload gives exactly 8
allocations of 82 B (Scudo class **0x60** = `VideoFrameReader`), a 152-byte
payload gives 8 allocations of 152 B (class **0xa0** = `VideoInfo`); a freed
same-class victim is hit by one of them on the glibc host build (host Scudo with
the documented quarantine needed more than 250). The parser
accepts up to ~260 assets per sticker, i.e. ~260 same-class chunks per TGS.

**9.5 Partial low-16 overwrite: ruled out.** A same-class string of length `L`
writes `[0,L)` and preserves the tail only from `L`; a pointer at offset `X`
can keep its high 6 bytes only if `X` is inside the last
`class_size - prev_class_size` bytes. `classes.py` shows that window contains a
pointer only for `VideoFrameReader.m_frame` (+0x50, L=0x52) — and that same
string necessarily overwrites `m_dec` (+0x38), `m_fmt` (+0x30) and `m_pkt`
(+0x48) with attacker bytes, while the worker calls `avcodec_receive_frame`
with `m_dec` right after the first `av_frame_unref`. No `VideoInfo` pointer,
no `AVFrame`/`AVCodecContext`/`AVFormatContext`/`AVIOContext`/`AVPacket`
pointer, and no vtable lies in the respective windows. Data-pointer partial
overwrites (`data[]`, `buf[]`, sws src/dst) fail for the same offset reason.

**9.6 Verdict.** The UAF is real, reachable without user interaction (rendering
an animated GIF / video sticker), and crash-capable. **It is not a controlled
write or PC control without an address disclosure**: every fake pointer in the
reclaim must reference attacker-influenced memory whose address is unknown.
With a leak, the clean chain is: reclaim the 0x60 reader with `m_pkt != 0`,
`shouldAbort = 0`, `m_frame` → fake `AVFrame` in controlled memory →
`av_frame_unref` → `frame->buf[0]->free(buf, data)` (controlled RDI/RSI) plus an
arbitrary free. Do not claim ACE without that leak.

**9.7 Cold-start reachability of the "GIF destroy → TGS parse" ordering.** The
GIF side is confirmed (dialog cells and chat cells use `s5`; background decode,
UI-thread destroy). The TGS side (`nCreate`/`nCreateWithJson` from
`ci0.<init>`/`ci0.B`) is confirmed for custom-emoji message cells in an open
chat; I found no evidence that the dialog-list subtitle instantiates a TGS
parser on 13.2.0, so the suggested "cold start on the chat list, same refresh
parses the TGS" sequence is **unconfirmed**. The confirmed co-location is
scroll/rebind in an open chat (GIF cell recycled, custom-emoji cell bound right
after). `uaf/test_plan.md` has the `am force-stop`/`am start` procedure; no
reboot.

**9.8 Device reachability test (Sony XQ-BT52, Android 13, 2026-11-03; no reboot).**
Full log: `lab/jni_media_bounds/uaf/device/README.md`.
`cache4.db` + `-wal` + `-shm` were backed up with md5/sha256 before any change
(`96112714…`, `df8a038c…`, `5e0480d8…`) and restored byte-identical afterwards;
`files/.base.art.orig` (md5 `7be328aa…`) was not touched. The test used a copy
of the DB in which the cached video-sticker message `mid=78508`
(doc `2_5379985277462781945`, VP9 495x512, sticker attribute) was cloned as the
dialog's last message with a 9.5 MB 1920x1080 MPEG-4 file at its cached path
(the document `size` field patched accordingly). The sticker rendered and
played (screenshot in `uaf/device/shots/`), i.e. `nCreateDecoder` /
`nGetVideoFrame` ran with a 1080p decode.

Result: **no crash** over ~20 open/scroll/recycle cycles (delays 0.3–4 s, plus
in-session scroll cycles and a 12 s settle run). SIGQUIT traces
(`/data/anr/trace_NN`, saved in `uaf/device/traces/`) show the real threading:
`pool-21-thread-1/4` inside `AnimatedFileNative.nGetVideoFrame` ← `q5.run`
(the guarded H0 decode), and `"cache generator queue"` busy in
`RLottieNative.nGetFrame` ← `ci0.a` ← `rf.e.b` ← `bi0.run` (TGS caching). No
`rf.e.b → s5.a → nGetVideoFrame` stack and no `<media>_*.pcache2` for the s5
sticker were ever observed: the shared cache-generator queue was occupied by
TGS jobs and the s5 generator task either never started or was cancelled by
`s5.u()` before it did. The guarded H0 path cannot race because `s5.e` is only
cleared on the UI thread after H0 has returned.

So on this build/state the **unguarded cache-generator path did not engage**,
and the device test did not produce the crash. This does not change the
code-level finding (the `e == null` guard genuinely misses the generator), but
it means the crash must be reproduced by first forcing the s5 generator to run
and observing its stack (next steps in `uaf/device/README.md` §7). Also seen
and unrelated: the pre-existing `messages_v2` b-tree inconsistency
(`integrity_check` error reproduced on the untouched backup), `NPE: src == null`
in `TL_chatPhoto.readParams`, and `can't do request without login` network
errors. The device was left with the restored DB/media and the app running.

**9.9 Loaded/local retry (second device pass).** Re-applied the same setup and
re-opened the chat in the same session. First open: `create load operation ...
stream=AnimatedFileDrawableStream` then `finished downloading ... size=9,1 MB`.
Second open: no new load, but no s5 `<media>_*.pcache2` and no
`rf.e.b → s5.a → nGetVideoFrame` stack (cache queue idle); the sticker still
plays through the guarded H0 path. Forcing the document `size=0` made the app
resolve `<dc>_<id>.temp` and fail to open it, proving a DB-only clone never
reaches the FileLoader "finished/local" state. Blocker: a real MTProto
FileLoader-completed video sticker is needed to get `stream == null` /
`isFinishedLoadingFile == true`; the device's account/network state
(`can't do request without login`, mock TL parse errors) cannot produce one.
No crash; DB/media restored byte-identically; ART untouched. Details in
`lab/jni_media_bounds/uaf/device/README.md` §8.
