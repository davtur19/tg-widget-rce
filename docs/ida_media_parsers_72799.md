# Bundled third-party media parsers — libtmessages.49.so, arm64, beta 72799

Survey date: 2026-11-02. Host-only (no phone / no emulator).

> **Correction 2026-11-03 (libvpx deep dive).** The libvpx row below is
> correct: the bundle is **libvpx 1.17.0**, not 1.5.4 (the `1.5.4-0-g54706fc6`
> string is **dav1d 1.5.4**). The media3 `ExperimentalFfmpegVideoDecoder`
> row is **wrong for 72799**: that renderer is dead code because
> `DefaultRenderersFactory` is constructed with extension mode OFF
> (`i2.j` ctor `c = 0`, only iput in all four dex). The local libvpx path is
> `AnimatedFileDrawable`/`AnimatedFileNative` (video stickers, custom emoji),
> chat-open; ordinary video messages use MediaCodec. Details:
> `notes/libvpx_deep.md` and `lab/libvpx_deep/`.

| | |
|---|---|
| Target | `/tmp/opencode/tg49_72799.so` (= `lib/arm64-v8a/libtmessages.49.so` of APK 72799) |
| Size / md5 | 27,016,000 B / `2c0caa68a07fc26f79d13519af6c3526` |
| BuildId | `645cce3998197329915f6cbfcc9ffd7f124d9f86` |
| Format | ELF64 AArch64, stripped, NDK r27c (12479018), clang 18.0.3 `+pgo,+lto` |
| Layout | `.rodata` 0x1F5000–0x46B338, `.text` 0x733C80–0x18B13AC, `.data.rel.ro` 0x18B6D70–0x19594B8 |
| IDA database | `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_media_annotated.i64` (278 MB, annotated; in-place DB `/tmp/opencode/tg49_72799.so.i64`) |

All addresses below are **image-base-relative (base 0)** for this exact build, taken from the IDA
database above (`ida_domain`, 80,520 functions, auto-analysis complete). File offset == VA for
`.text`/`.rodata` in this ELF, so offsets can be re-checked with any hex editor.

> Method note: another agent's `libtmessages_armv7.so` IDB became the MCP *default* target
> mid-session. Every address in this report was re-derived afterwards against the explicit instance
> id of the 72799 arm64 database (`f1356e871fde`), so no ARMv7 address leaked into the tables.

---

## 1. Version inventory (evidence-grade)

| Library | Version | Evidence (address → reference) |
|---|---|---|
| **FFmpeg** | libavcodec **62.28.103**, libavformat **62.12.103** → FFmpeg **8.x, git snapshot newer than 8.0.3** | `"Lavc62.28.103"` @0x28A5D5 → `sub_753B18` (`ffmpegGetVersion` thunk: `NewStringUTF(env, "Lavc62.28.103")`); `"Lavf62.12.103"` @0x246CA1 → mux/`matroskaenc`/`movenc` (`LIBAVFORMAT_IDENT`). FFmpeg 8.0.3 (2026-06-18) ships lavc 62.**11**.103 / lavf 62.**3**.103, so this build is *newer* than the newest 8.0.x point release. Corroborated by sources only present in 7.1+/8.x: `src/libavformat/iamf_{parse,reader}.c`, `src/libavformat/vvc.c`, `src/libavcodec/aac/aacdec_usac.c`, `src/libavcodec/vvc/`. |
| **libvpx** | **1.17.0** | `"WebM Project VP9 Decoder v1.17.0"` @0x1FD5EE, `"WebM Project VP8 Decoder v1.17.0"` @0x22622B, `"... VP9 Encoder v1.17.0"` @0x221642. Build config blob @0x21C4AD: `--target=arm64-android-gcc --prefix=/jni/prebuild/build/libvpx ... --enable-vp8 --enable-vp9 --enable-vp8-decoder ... --disable-neon-asm --size-limit=4096x4096` (Telegram-internal build, same static lib used by WebRTC **and** by FFmpeg's `libvpx`/`libvpx-vp9` decoders). |
| **libdav1d** | **1.5.4** (tag, `1.5.4-0-g54706fc6`) | `"1.5.4-0-g54706fc6"` @0x289425 → `dav1d_version()` @0x137AF94. Log sink `"libdav1d %s\n"` @0x207A2A → 0x1234600 (FFmpeg `libavcodec/libdav1d.c` wrapper). |
| **libopus** | unknown (no configure) | `"libopus unknown-fixed"` @0x211D27 → `opus_get_version_string()` @0x14131C0. Built through ndk-build without autoconf, so the version macro is the placeholder string. Only the *decoder* is relevant (FFmpeg `libopus`, MediaController opus helpers). |
| **rlottie** | no version string (Telegram fork of Samsung rlottie; upstream last release **v0.2**, 2020) | JNI `Java_org_telegram_ui_Components_RLottieNative_{nCreate,nCreateWithJson,nGetFrame,nDestroy}` @0x74F710 / 0x750140 / 0x750228 / 0x750220; core code 0x1030304–0x10A5080 (531 functions, zero string literals — the fork compiles `strcmp` key checks into immediates, so key names like `masksProperties` are **not** findable as strings). |
| zlib, libyuv, litehtml, BoringSSL, WebRTC/tgcalls, QuickJS | present | `gzopen/gzread/gzclose` in the .tgs loader; `nLibyuvARGBSaleBitmap`; `_a_, _abbr_, _acronym_ …` litehtml tag table; `WebRTC-*` field trials. |

### Definitively **absent** (important negatives)

| Library | Proof |
|---|---|
| **libwebp** (any version) | No `RIFF`, `WEBP`, `VP8L`, `VP8X`, `ALPH`, `ANIM`, `ANMF` byte patterns anywhere in the 27 MB image (raw `re.finditer` over the file, 0 hits); no `vp8_dec` code-to-plane table `18 07 17 19 28 06 27 29 16 1a`; no VP8L code-length-order table `11 12 00 01 02 03 …`; no `WebP*` symbols/strings. |
| **libjpeg-turbo** | No `libjpeg`, `jdhuff`, `jmemmgr`, `Bogus Huffman table definition`, `Invalid progressive parameters`. The single `jpeg_natural_order`-like table @0x336424 and `"Intel(R) JPEG Library, version 1"` @0x29CCD2 are FFmpeg `mjpegdec.c`. |
| **libpng** | No `\x89PNG`, no `IHDR/IDAT/IEND`, no `libpng` strings. |
| **FreeType** | No `FreeType`/`FT_Init_FreeType`/`FT_Face` strings. |
| libheif / libavif / libjxl | none (only FFmpeg `mov` brand strings `heic`, `avif`, `image/jxl` descriptors — descriptors are always compiled, the decoders are not). |

**Consequence:** the classic *"crafted .webp static sticker"* idea does **not** hit app-bundled code in
Telegram Android 13.2.0. `BitmapFactory`/Skia decode WebP/JPEG/PNG inside the OS image
(`libhwui`/`libandroid_runtime`), i.e. CVE-2023-4863-class bugs there are an **Android platform**
issue, not reachable through `libtmessages.49.so` and not patchable by Telegram.

---

## 2. FFmpeg is a *trimmed* build — exact compiled surface

The binary carries a full `codec_desc` table (≈1000 descriptors, .data.rel.ro 0x1908D18…) which is
misleading, plus three real registry arrays. These are the authoritative lists:

**Demuxers — 6 (0x1901658 -> 0x1901698)**
```
aac | gif | matroska,webm | mov,mp4,m4a,3gp,3g2,mj2 | mp3 | ogg
```

**Decoders — 14 (0x19080C0 -> 0x1908128)**
```
gif  h263  h264  hevc  mjpeg  mpeg4        (video)
aac  alac  flac  mp3                        (audio)
libdav1d (AV1)  libopus  libvpx (VP8)  libvpx-vp9 (VP9)
```

**Bitstream filters — 4 (0x1908B08)**
```
aac_adtstoasc | pgs_frame_merge | vp9_raw_reorder | vp9_superframe
```

Notes:
* No native `vp8`/`vp9` decoders — VP8/VP9 always go through **libvpx 1.17.0**.
* No `av1` native decoder — AV1 always goes through **dav1d 1.5.4**.
* No `webp`, no image2, no avi/flv/mpegts/rtsp/http demuxer, no `h264_mp4toannexb`.
* `mov.c` still parses `avif/heic/heif` brands (name string @0x29C346) but no image decoder exists for them.

FFmpeg API anchors. The binary is stripped, so these names are *reconstructed* from call-site semantics
(argument shapes, return-code constants such as `AVERROR_EOF` = -541478725, the gifvideo call sequence
and the FFmpeg 8.x source layout), not from symbols. Where LTO/ICF merged a thunk, the address is the
merged block, so treat them as ±1 function. They are also applied as names in the saved IDB.

| Address | Function |
|---|---|
| 0x1481F44 | `av_malloc` |
| 0x110E520 | `avio_alloc_context` |
| 0x110E594 | `avio_context_free` |
| 0x1145EF4 | `avformat_alloc_context` |
| 0x1110248 | `avformat_open_input` |
| 0x1111F48 | `avformat_find_stream_info` |
| 0x110D28C | `av_find_best_stream` |
| 0x12589F4 | `avcodec_alloc_context3` |
| 0x1164CF0 | `avcodec_parameters_to_context` |
| 0x1161168 | `avcodec_open2` |
| 0x1165714 | `avcodec_send_packet` (returns `AVERROR_EOF` = -541478725, `AVERROR(EINVAL)` = -22) |
| 0x116221C | `avcodec_receive_frame` |
| 0x1258CB8 | `av_packet_alloc` |
| 0x147972C / 0x1479AE0 | `av_dict_set` / `av_dict_free` |

Demuxer source anchors (for bug-site orientation): `matroskadec.c` @0x111CEC8, `mov.c` @0x113994C /
@0x1139BC0, `demux.c` @0x1115978, `oggdec.c` @0x11416FC.

---

## 3. Reachability from message data

### 3.1 FFmpeg ← `gifvideo.cpp` ← `AnimatedFileDrawable` ← **any animated message**
This is the main finding: chat "GIF", video-sticker (`.webm`), and video-message playback are
demuxed **and decoded** by the bundled FFmpeg, not by MediaCodec.

```
Java  org.telegram.ui.Components.AnimatedFileNative.a(path[, stream])
      (AnimatedFileDrawable / s5.java:331,611, q5.java:139, VideoFramesRewinder.java:307)
  ->  JNI Java_..._AnimatedFileNative_nCreateDecoder    0x74DC98
        "gifvideo.cpp new stream"   @0x2227CA
        "http://localhost/file"     @0x2802BE   (dummy filename for avformat_open_input)
        av_malloc(0x10000)                         0x1481F44
        avio_alloc_context(buf,0x10000,pb=ctx,cbs) 0x110E520   [read=0x74D3D0, seek=0x74D520]
        avformat_alloc_context()                   0x1145EF4
        av_dict_set(&o,"usetoc","1",0)             0x147972C
        avformat_open_input(&ctx,"http://localhost/file",0,&o)  0x1110248
        avformat_find_stream_info()                0x1111F48
        av_find_best_stream() -> avcodec_alloc_context3() -> avcodec_parameters_to_context()
        avcodec_open2()                            0x1161168
  ->  per frame: av_packet_alloc -> avcodec_send_packet(0x1165714) -> avcodec_receive_frame(0x116221C)
```
Because the input is a *callback-driven* AVIO (0x74D3D0 / 0x74D520, backed by
`AnimatedFileDrawableStream`), a partially downloaded / streamed file is parsed too; seek requests
are answered from the Java stream, so the parser can be steered through arbitrary offsets.

`AnimatedFileNative.nGetVideoInfo` **0x74D6AC** runs the same demux path and is called by
`Utilities.getVideoInfo` (`qz.n`) and by **PhotoViewer** (`nr0.java:36`, `w50.java:489`,
`rh/l5.java:627`) — i.e. simply opening a received video demuxes it.

### 3.2 FFmpeg ← other JNI entry points
| Entry | Address | Use |
|---|---|---|
| `Java_..._FfmpegAudioWaveformLoader_init` | 0x16F1C88 | avformat demux of an audio file to build a story waveform (23 calls into FFmpeg) |
| `Java_..._MediaController_getWaveform` | 0x16F19A4 | avformat demux (audio) for waveform |
| `Java_..._MediaController_{crop,join}OpusFile` | 0x16F234C / 0x16F2658 | opus/ogg handling |
| `Java_..._WebmEncoder_{createEncoder,writeFrame,stop}` | 0x16F3E20 / 0x16F422C / 0x16F43E8 | *encoder* side (attacker is the author; lower value) |
| `Java_androidx_media3_decoder_ffmpeg_ExperimentalFfmpegVideoDecoder_*` | 0x754CB8 / 0x754E04 / 0x754FA0 / 0x75547C | media3 `FfmpegLibrary`-style **avcodec-only** path (send_packet/receive_frame/ANativeWindow render). Class name only appears in `classes.dex`, so this is a fallback decoder in the ExoPlayer stack (AV1/HEVC when MediaCodec is absent). |

### 3.3 rlottie ← `.tgs` / Lottie JSON ← animated stickers & premium emoji
```
Java org.telegram.ui.Components.RLottieNative.nCreate(byte[][] data, key, w, h)
  -> JNI 0x74F710 : gzopen()/gzread() (".tgs" is gzip'ed JSON) -> std::string
  -> sub_74F924 (rlottie_jni_create_impl)  -> rlottie_Animation_loadFromData  0x1094A7C
  -> cache insert sub_750088 ; refcount sub_1094884
nGetFrame 0x750228 : AndroidBitmap_lockPixels -> rlottie_Animation_render 0x1094E44
                     -> frame count 0x10954E0
nCreateWithJson 0x750140 (raw JSON path)
```
Core: **0x1030304 – 0x10A5080**, 531 functions, largest 0x106DC60 (0x47D0 B). Both the JSON parser
and the software rasteriser (`vdrawhelper`, gradients, RLE) live in this block; there are no symbol
strings, so the fork's vintage cannot be read out of the binary — upstream rlottie has been frozen at
v0.2 since 2020 and Telegram's fork carries the 2020-vintage parser plus their own renderer changes.

---

## 4. CVE cross-check

| Component | Bundled | Known CVEs | Verdict for 72799 |
|---|---|---|---|
| **libwebp** | **not bundled** | CVE-2023-4863 (lossless Huffman `BuildHuffmanTable`), CVE-2023-5129, older `VP8LDecodeImage`/`VP8DecodeMB` issues | **N/A to app code.** WebP files reach the OS decoder via `BitmapFactory`; the bug site would be the device's `libwebp`/Skia, not `libtmessages.49.so`. |
| **FFmpeg** lavc 62.28.103 | trimmed | All published FFmpeg CVEs target ≤ 7.x / 8.0.x (e.g. CVE-2023-50007/50008/50009/50010, CVE-2023-51793/51794/51798, CVE-2024-31578/31585, CVE-2023-49502). 8.0.3 (lavc 62.11.103, 2026-06) is the newest 8.0.x; this build is **later**. | **Not vulnerable to any known CVE.** Residual risk is 0-day class only: `matroskadec.c` EBML parser, `mov.c` atom/box parser, `h264dec.c`, `hevc/hevcdec.c`, `mjpegdec.c`, and the `libvpx`/`dav1d` wrappers. |
| **libvpx** 1.17.0 | yes | CVE-2023-5217 (VP8 *encoder* heap overflow, fixed 1.13.1), CVE-2023-44488 (VP9, fixed 1.13.1), CVE-2020-0034 (VP9 decode OOB, fixed 1.8.2) | **Not vulnerable.** 1.17.0 ≫ all fixes. Decoder path is reachable (VP8/VP9 from `.webm`). |
| **dav1d** 1.5.4 | yes | CVE-2021-30474 / CVE-2021-30475 (dav1d ≤ 0.8.x), plus continuous OSS-Fuzz fixes through 1.x | **Not vulnerable.** Reachable via AV1 in `.mp4`/`.webm`. |
| **libopus** unknown | yes | CVE-2017-0381 (`celt` decoder, fixed 1.1.4) and little else | **No known applicable CVE**; version cannot be printed by the binary. |
| **rlottie** (Telegram fork) | yes | **CVE-2021-31320** heap OOB **write** in `VGradientCache::generateGradientColorTable`; **CVE-2021-31323** heap OOB **read** in `LottieParserImpl::parseDashProperty` (+11 more found by Shielder: type confusion, int overflow, stack OOB). Fixed in Telegram **7.1.0 (2090)**, Sept 2020. | **Those specific bugs are fixed** (build is 13.2.0). But the parser/renderer is the same 2020-era code lineage, has no version pin, no hardening, and is exactly the class of code that produced 13 remote bugs when last audited. |
| libyuv / litehtml / zlib / BoringSSL | yes | — | out of scope for media; litehtml is only reachable through Instant-View HTML, not message media. |

---

## 5. Ranked candidates for a crafted file in the app DB

**#1 — crafted `.webm` / `.mp4` "video sticker" or animated GIF → FFmpeg via gifvideo.cpp.**
*Reachability:* automatic. Video stickers and GIFs animate inline as soon as the chat is opened;
no tap needed. `AnimatedFileNative.a()` is unconditional (`s5.java:331`, `b()` override) — there is
no MediaCodec fallback for this path.
*Surface:* `avformat_open_input` **0x1110248** (matroska/mov/gif/ogg demuxers) →
`avcodec_open2` **0x1161168** → decode loop **0x1165714 / 0x116221C**.
*Why promising:* largest C attack surface in the app, attacker fully controls container + bitstream,
custom AVIO lets the parser be driven across arbitrary offsets, and the code is a **git snapshot**
(not an audited release) whose exact commit cannot be pinned from the binary.
*Best sub-targets:* `matroskadec.c` (0x111CEC8 region) and `mov.c` (0x113994C/0x1139BC0) for the
container; `libvpx-vp9` (1.17.0) and `dav1d` (1.5.4) for the codec. Note VP9/AV1 in WebM is the
shortest path to a decoder that Telegram never exercises through MediaCodec on older devices.

**#2 — crafted `.tgs` (gzip'ed Lottie JSON) → rlottie parser.**
*Reachability:* automatic for stickers / premium emoji once the chat or the sticker tab is rendered;
`.tgs` is gunzipped in JNI (0x74F710) and handed to `rlottie_Animation_loadFromData` **0x1094A7C**.
*Why promising:* hand-written JSON parser + vector rasteriser, 2020 fork, no version pin, no bounds
hardening, and a documented history of 13 remotely triggerable memory bugs (CVE-2021-31320/31323 among
them). Nothing in the binary suggests the parser was rewritten.
*Caveat:* Telegram's server validates/filters animated stickers and requires them to belong to a
sticker set (a bot can create such a set), so delivery needs a sticker-set wrapper.

**#3 — crafted video opened in PhotoViewer → `nGetVideoInfo` 0x74D6AC.**
Same FFmpeg demux path but **before** any decoding, i.e. pure `mov.c`/`matroskadec.c` parsing; needs
the victim to open the video (or the video to be preloaded for the viewer).

**#4 — media3 `ExperimentalFfmpegVideoDecoder` (0x754CB8 / 0x754E04 / 0x754FA0).**
avcodec-only (no demuxer), so the payload must be a codec-level bitstream delivered through
ExoPlayer's own extractors. Lowest priority: hard to confirm it is actually selected on this build.

**Ruled out / not useful**
* `.webp` static stickers, photos (JPEG), PNG: decoded by the **Android platform**, not by this `.so`
  (no libwebp/libjpeg/libpng/FreeType linked).
* HEIF/AVIF: `mov.c` parses the brands but no image decoder exists in the build.
* WebRTC `LibvpxVp8/Vp9Decoder` (0xa3fe44 / 0xa3ff30): only fed by the peer's RTP stream, not by
  stored media.

---

## 6. Artifacts

* Annotated IDB: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_media_annotated.i64`
  (in-place working copy `/tmp/opencode/tg49_72799.so.i64`).
* Named in the IDB: `rlottie_jni_create_impl`, `rlottie_Animation_loadFromData`, `rlottie_Animation_render`,
  `avformat_open_input`, `avformat_find_stream_info`, `av_find_best_stream`, `avcodec_open2`,
  `avcodec_send_packet`, `avcodec_receive_frame`, `av_packet_alloc`, `av_dict_set`, `av_malloc`,
  `gifvideo_avio_read_cb`, `gifvideo_avio_seek_cb`, `ffmpeg_demuxer_list`, `ffmpeg_codec_list`,
  `ffmpeg_bsf_list`, `dav1d_version`, `opus_get_version_string`.
* Raw string dump used for the negative tests: `/tmp/opencode/tg_strings.txt`.
