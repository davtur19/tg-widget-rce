# libvpx in Telegram Android 72799 — local WebM decode path, version truth, CVE matrix, ACE verdict

Date: 2026-11-03. Target: `org.telegram.messenger.beta` 13.2.0 beta,
versionCode **72799**, arm64 (`lib/arm64-v8a/libtmessages.49.so`), Sony
XQ-BT52 (Xperia 10 III), Android 13, build `62.2.A.0.533`, UID 10357.

Method: IDA Pro 9.4 on the stripped `.so` (image-base-relative addresses,
base 0), full `dexdump -d` of all four dex, the public Telegram source tree at
8.9.0 as a structural reference (`/tmp/opencode/telegram_src`; every 72799
claim below is re-checked against the 72799 dex), host ASan builds of libvpx
v1.17.0 and v1.5.0, and one read-only device identity check (`pm path`,
APK/lib md5). No device exploit was run; the device plan is
`lab/libvpx_deep/device/test_plan.md`.

Companion artifacts: `lab/libvpx_deep/` (builds, harness, seeds, logs,
evidence), `lab/decoder_fuzz/` (existing app-like FFmpeg 8.1.3 + libvpx
1.17.0 fuzz lab), `notes/ida_media_parsers_72799.md` (component inventory),
`notes/db_native_parsers.md` (cache4.db schema).

---

## 0. Verdict

**The local WebM path is real, but the "libvpx 1.5.4" premise is false.**

1. **Reachability: confirmed.** A local `.webm` **video sticker** (or
   `TL_documentAttributeCustomEmoji` document) rendered in a chat goes
   `ChatMessageCell` → `ImageReceiver` filter `"g"` → `ImageLoader`
   (`IMAGE_TYPE_ANIMATION`) → `AnimatedFileDrawable` (`s5`) →
   `AnimatedFileNative` JNI → FFmpeg matroska demuxer → FFmpeg
   `libvpx-vp9` → `vpx_codec_dec_init_ver(vpx_codec_vp9_dx())` →
   `vpx_codec_decode` → VP9 decoder core. **Chat open**, not chat list.
2. **Version: 1.17.0, not 1.5.4.** All four ABIs carry
   `WebM Project VP8/VP9 Decoder/Encoder v1.17.0` and a build config with
   `--size-limit=4096x4096`. The only `1.5.4` string in the binary
   (`1.5.4-0-g54706fc6`) is **dav1d 1.5.4**: it is returned by
   `dav1d_version()` and consumed by FFmpeg's `libdav1d` wrapper. Upstream
   libvpx never published a `v1.5.4` tag (v1.5.0 → v1.6.0). The device runs
   the exact analysed binary (installed APK md5 `04317a9f…`, lib md5
   `2c0caa68…`).
3. **CVE matrix: no known decoder ACE applies.** Every 2023–2026 CVE in the
   task list is **encoder-side** or API-only, and all are fixed well below
   1.17.0. The 2015 decoder bugs were fixed before v1.5.0; the 2016 decoder
   bug confirmed against a hypothetical v1.5.0 is CVE-2016-3881, an **OOB
   read/DoS** in `decoder_peek_si_internal` (reproduced here with a 9-byte
   input; null-call SEGV), not a write/UAF (the 2017–2020 Android decoder
   issues are also OOB reads/DoS). Even the premise's version does not give a
   known local ACE.
4. **Empirical:** ASan libvpx v1.5.0 and v1.17.0 with an FFmpeg-`libvpxdec`-
   shaped harness: 4.15 M VP9 + 1.61 M VP8 executions on 1.17.0, 1.65 M +
   9.5 k on 1.5.0, plus 1.28 M / 0.83 M 8-thread VP9 runs — no ASan/UBSan
   report in the mutation campaigns. The OSS-Fuzz VP9 corpus replay produced
   one **1.5.0 DoS artifact** (9-byte input, null-call SEGV in
   `decoder_peek_si_internal`) and **zero 1.17.0 artifacts** (§5.1). The
   combined AnimatedFileNative path (FFmpeg n8.1.3 matroska + libvpx-vp9
   wrapper + libvpx 1.17.0, all ASan+coverage) ran **1,001,048 executions**
   in the final 20-minute fork campaign, plus ~0.5 M earlier, with **no ASan
   memory corruption** (§5.2). These are negative campaigns, not proof of
   safety.

**Consequence.** The libvpx lead is closed for *known* CVEs. A local ACE from
a DB/media file now requires a **0-day** in libvpx 1.17.0's VP9 decoder (or
in FFmpeg's matroska/libvpx wrapper). The trigger would be a chat open with a
video-sticker/custom-emoji document; the first RCE writes the file and the
`cache4.db` rows. Do not present any encoder CVE as local decode ACE.

Correction to the earlier note `notes/ida_media_parsers_72799.md`: its
libvpx row already says 1.17.0 (correct); the "1.5.4" in the task premise is
dav1d. Its media3 `ExperimentalFfmpegVideoDecoder` row is wrong for 72799 —
that renderer is dead code (§2.4).

---

## 1. Version evidence (decisive)

Binary: 27,016,000 B, md5 `2c0caa68a07fc26f79d13519af6c3526`, BuildId
`645cce3998197329915f6cbfcc9ffd7f124d9f86`.

### 1.1 libvpx 1.17.0 in all four ABIs

```
$ strings -a lib/arm64-v8a/libtmessages.49.so | grep 'WebM Project'
0x1FD5EE  WebM Project VP9 Decoder v1.17.0
0x22622B  WebM Project VP8 Decoder v1.17.0
0x221642  WebM Project VP9 Encoder v1.17.0
0x26EE85  WebM Project VP8 Encoder v1.17.0
```

Identical strings exist in `armeabi-v7a`, `x86_64`, and `x86`. There is only
one `libtmessages.49.so` per ABI in the APK and no separate `libvpx.so`; the
`libtmessages.49loc.so` fallback in app data is a 2,704-byte stub.

The codec-interface structs confirm these strings are live decoder/encoder
interfaces, not dead literals:

| iface | address | name (offset 0) | getter |
|---|---|---|---|
| VP9 decoder | `0x191C260` | `"WebM Project VP9 Decoder v1.17.0"` | `sub_13681F4` (`vpx_codec_vp9_dx`) |
| VP8 decoder | `0x191B658` | `"WebM Project VP8 Decoder v1.17.0"` | `sub_12CC2A4` (`vpx_codec_vp8_dx`) |
| VP9 encoder | `0x191B7A8` | `"WebM Project VP9 Encoder v1.17.0"` | `sub_12D94A8` (`vpx_codec_vp9_cx`) |

The build config blob at `0x21C4AD` is:

```
--target=arm64-android-gcc --prefix=/jni/prebuild/build/libvpx/install/arm64-v8a
--disable-shared --enable-static --enable-pic --enable-optimizations
--enable-multithread --disable-examples --disable-tools --disable-docs
--disable-unit-tests --disable-install-bins --disable-install-docs --disable-debug
--enable-vp8 --enable-vp9 --enable-vp8-decoder --enable-vp8-encoder
--enable-vp9-decoder --enable-vp9-encoder --disable-runtime-cpu-detect
--enable-realtime-only --enable-small --enable-better-hw-compatibility
--disable-webm-io --disable-neon-asm --disable-neon-dotprod --disable-neon-i8mm
--disable-sve --disable-sve2 --size-limit=4096x4096 --extra-cflags=-O3 ...
```

Notable: `--disable-tools` (no `vpxdec`/`vpxenc`), `--disable-webm-io` (no
libwebm container parser inside libvpx), no `--enable-vp9-postproc`, no
`--enable-error-concealment`, 8-bit only (no `--enable-vp9-highbitdepth`),
`--size-limit=4096x4096`, multithreaded.

### 1.2 The `1.5.4-0-g54706fc6` string is dav1d

```
0x289425  "1.5.4-0-g54706fc6"
  xref -> 0x137AF94  dav1d_version()          (IDA name, from the media IDB)
             <- 0x123461C  sub_1234600       (FFmpeg libdav1d wrapper)
  sub_1234600 also uses 0x207A2A "libdav1d %s\n"  (FFmpeg libavcodec/libdav1d.c)
```

Three independent reasons:

1. The string is the return value of `dav1d_version()`, and the same function
   is called only from the FFmpeg `libdav1d` wrapper that logs
   `"libdav1d %s"`. dav1d's version macro is generated as
   `<tag>-<commits>-g<hash>` by meson, exactly this shape.
2. Upstream libvpx has no `v1.5.4` tag. The 1.5 line is `v1.5.0`
   (2015-11-10); the next tag is `v1.6.0` (2016-07-21). libvpx's version
   string is `"v1.17.0"`/`"1.17.0"` (no `-0-g` suffix).
3. Every libvpx codec name in the binary says `v1.17.0` (§1.1). A second,
   hidden 1.5.4 libvpx would have to duplicate the iface names and codec
   structs; there is exactly one `"WebM Project VP9 Decoder"` string and one
   xref to it.

`v1.17.0` was released **2026-08-07** ("Yellowbilled Duck", tag
`6df3ec34557879fff673706f4a1d9fbd0f3a6f0e`), i.e. the app bundle is the
newest upstream release, not a 2015 build.

### 1.3 Device identity

```
adb shell dumpsys package org.telegram.messenger.beta  -> versionCode=72799
adb pull .../base.apk ; md5sum                         -> 04317a9fae026fb41b1c741e8946b77e
unzip -p base.apk lib/arm64-v8a/libtmessages.49.so | md5sum
                                                       -> 2c0caa68a07fc26f79d13519af6c3526
```

The installed APK is byte-identical to the analysed `/tmp/opencode/base72799.apk`,
and the installed `.so` is byte-identical to the analysed `/tmp/opencode/tg49_72799.so`.
There is no device-specific libvpx.

---

## 2. The local decode path (exact)

### 2.1 Java side: video stickers are decoded, not sent to MediaCodec

Source reference (Telegram 8.9.0, structurally identical to 72799; the 72799
dex call sites were checked separately):

* `MessageObject.isVideoStickerDocument(document)` = has
  `TL_documentAttributeSticker` **or** `TL_documentAttributeCustomEmoji`
  **and** `mime_type == "video/webm"` (`MessageObject.java:6316`).
* `ChatMessageCell.setMessageObject`:
  `if (messageObject.isVideoSticker()) { … photoImage.setImage(
  ImageLocation.getForDocument(document), ImageLoader.AUTOPLAY_FILTER, …) }`
  (`ChatMessageCell.java:6762-6766`); `AUTOPLAY_FILTER = "g"`
  (`ImageLoader.java:151`).
* `ImageLoader` sets `img.imageType = IMAGE_TYPE_ANIMATION` when
  `MessageObject.isVideoSticker(imageLocation.document)` (or GIF/round video)
  (`ImageLoader.java:3103-3104`), and in the animation branch constructs
  `new AnimatedFileDrawable(cacheImage.finalFilePath, createDecoder, …)` and
  calls `setIsWebmSticker(MessageObject.isWebM(document) ||
  MessageObject.isVideoSticker(document) || isAnimatedAvatar(filter))`
  (`ImageLoader.java:1094-1114`).
* `AnimatedFileDrawable` constructor with `createDecoder == true` calls the
  native `createDecoder(...)` (`AnimatedFileDrawable.java:496/506`), i.e.
  `AnimatedFileNative.a(...)` → `nCreateDecoder`.
* The autoplay branch constructs with `createDecoder = fistFrame` (false for
  a normal sticker), but the drawable is not decoder-less: `start()` runs
  `loadFrameRunnable`, and its `if (!decoderCreated && nativePtr == 0)` block
  calls the native `createDecoder` (`AnimatedFileDrawable.java:360-367`).
  In 72799 this is `s5.b()` → `AnimatedFileNative.a` → `nCreateDecoder`.
  So a chat-open video sticker always reaches the native decoder.

72799 dex confirmation (obfuscated names, same structure):

| what | 72799 class.method | address |
|---|---|---|
| `isVideoStickerDocument` | `org.telegram.messenger.kj.O4(Document)Z` | `0x5331B0` |
| `isVideoSticker()` (no-arg) | `kj.M4()Z` | — |
| ChatMessageCell bind | `org.telegram.ui.Cells.q1.r3` | `0x3BF02C` |
| `isVideoSticker()` call sites in the bind | `M4` | `0x3CAF8E`, `0x3CAFB6` |
| `const-string "g"` | — | `0x3CAF30` |
| `ImageReceiver.u0(..., "g", ...)` | — | `0x3CAF38` |
| ImageLoader cache-image task | `org.telegram.messenger.xb` (`d()` called from `run()`) | `0x4DCA74` |
| autoplay filter `"g"` / `"gl"` check in `xb.d` | — | `0x4DD1D8`, `0x4DD1F0` |
| animation branch checks `"video/webm"` | — | `0x4DD310` |
| `MessageObject.isVideoSticker` (`kj.N4`) | — | `0x4DD32E` |
| `new AnimatedFileDrawable` (autoplay/decoder branches) | — | `0x4DD2FE`, `0x4DD482` |
| ImageLoader class string | `"Image Loader image is empty = "` | `0x4DE40A` |

`q1` is the 72799 `ChatMessageCell` (it contains the message-bind method with
the `isVideoSticker()`/`"g"` setImage sequence, `ImageReceiver` fields, and the
message-view logic; the class name is obfuscated). `kj` is `MessageObject`.
`xb` is the ImageLoader cache-image task: it also contains
`"Image Loader image is empty = "`, the `WallPaper` helper `a(Bitmap,
WallPaper)`, and the three `new s5` sites of the loader.

### 2.2 Native side: AnimatedFileNative → FFmpeg → libvpx

| step | address | evidence |
|---|---|---|
| JNI `nCreateDecoder` | `0x74DC98` | name preserved in `.dynsym` |
| `avformat_open_input("http://localhost/file", custom AVIO)` | `0x1110248` | string `"http://localhost/file"` @0x2802BE; AVIO read/seek `0x74D3D0` / `0x74D520` |
| `avformat_find_stream_info` | `0x1111F48` | call in `0x74DC98` |
| open video decoder | `sub_74D084` @`0x74D084` | `av_find_best_stream(ic, AVMEDIA_TYPE_VIDEO, …)` @`0x110D28C` → `avcodec_find_decoder(codec_id)` (`sub_114B3FC` → `sub_114B370`) → `avcodec_alloc_context3` → `avcodec_parameters_to_context` → `avcodec_open2` @`0x1161168` |
| per-frame send | `sub_74F458` @`0x74F458` | `avcodec_send_packet` @`0x1165714` |
| per-frame receive | `sub_74F30C` @`0x74F30C` | `avcodec_receive_frame` @`0x116221C` |
| JNI `nGetVideoFrame` | `0x74EAF0` | calls `sub_74F30C`; the only decoder loop (`nGetFrameAtTime` @`0x74E53C`, `nSeekToMs` @`0x74E3FC` use the same loop) |

The surrounding FFmpeg is tag **n8.1.3** (libavcodec 62.28.103, libavformat
62.12.103), per `lab/decoder_fuzz` and the media IDB. The FFmpeg decoder
registry (`0x19080C0`, 14 entries) contains **no native VP8/VP9 decoder**:

```
i  name          AVCodecID
12 libvpx        139 (AV_CODEC_ID_VP8 struct @0x1911758)
13 libvpx-vp9    167 (AV_CODEC_ID_VP9 struct @0x19117C8)
```

The demuxer registry (`0x1901658`) contains `matroska,webm`. Therefore a
`.webm` VP9 stream opened by `avformat_open_input` / `av_find_best_stream`
resolves to `libvpx-vp9` and nothing else.

The FFmpeg `libvpxdec` wrapper then does:

```
sub_1235CAC (ff_libvpx_vp9_decoder.init)
  -> sub_13681F4  (vpx_codec_vp9_dx)
  -> sub_1235F40  (ctx->iface = iface)
  -> sub_1235CCC  (libvpx_init: threads, vpx_codec_dec_init_ver, caps, frame-buffer callbacks)
       vpx_codec_dec_init_ver = sub_1280168   (checks ver==12, iface ABI version==5)
       vpx_codec_set_frame_buffer_functions = sub_1280330 (if caps & 0x40)
sub_1235740 (ff_libvpx_vp9_decoder.decode)
  -> sub_1274988  (libvpx decode entry; public vpx_codec_decode path)
sub_1235C78  (close)
```

VP8 is the same with `sub_1235720` (init) and the `libvpx` iface. The VP8/VP9
**encoders** are also linked (`vpx_codec_vp8_cx`/`vp9_cx`) and are used by
WebRTC and FFmpeg's `WebmEncoder`; they are not on the local decode path.

### 2.3 Which local documents reach it

* **Video sticker message** (`mime_type="video/webm"`, sticker attribute):
  ChatMessageCell autoplay bind, chat open.
* **Custom emoji** (`TL_documentAttributeCustomEmoji`, `video/webm`): message
  text entities resolve the document by id and
  `AnimatedEmojiDrawable.i(boolean)` (`f5.i` @`0x539AE0`) checks
  `"video/webm"` @`0x539CF8` and constructs `s5` @`0x539F06`; chat open.
* **Sticker set cell** (`kt.s`, class `org.telegram.ui.kt`) checks
  `isVideoSticker` and binds the same ImageLocation; sticker panel open.
* **Animated wallpaper** — the same ImageLoader task `xb` has a wallpaper
  helper `a(Bitmap, WallPaper)` and creates `s5` in `d()`; a local animated
  wallpaper is another WebM input to the same native path, not message-driven.
* **Thumbnail / first-frame generators** (`mg.c0.run`, `rz.s`) create an
  `s5`, call `p()`/`q()` to extract one frame, then release it; these are
  one-frame decodes, still through the same native path, but not the
  animation loop. They can run for a plain local WebM video document too
  (`rz.s(str, t, params, true)`), so the VP9 decoder can be reached with a
  single packet even when the document is not a sticker.
* **`AnimatedFileNative.nGetVideoInfo`** (`Utilities.getVideoInfo`,
  PhotoViewer/pre-send) demuxes a local video to read duration/size. This is
  the FFmpeg matroska path without decoding; it is a container attack surface,
  not a libvpx one.

### 2.4 Chat list vs chat open (critical)

**Chat open.** The autoplay decode is bound by the message cell. `q1.r3`
(ChatMessageCell) is the only 72799 class that calls `kj.M4` (no-arg
`isVideoSticker`) and it sets the image with filter `"g"`; the 8.9.0 source
matches (`ChatMessageCell.java:6762`). The ImageLoader task `xb.d` then
takes the `"g"`/`"gl"` branch at `0x4DD1D8`/`0x4DD1F0` and constructs the
drawable at `0x4DD2FE`; the decoder-enabled branch follows the
`"video/webm"`/`isVideoSticker` checks (`0x4DD310`, `0x4DD32E`) and
constructs at `0x4DD482`. The decode runs on the drawable's frame thread
(`loadFrameRunnable` → native `createDecoder` → per-frame `nGetVideoFrame`)
and repeats for the visible sticker.

**Chat list.** The dialog cell (72799 `org.telegram.ui.Cells.k6`) has **no**
`kj.M4`/`kj.O4` call and **no** `"g"`, `"webp"`, or `"video/webm"` constant;
it uses `ImageReceiver` only for the last-message thumbnail. A thumbnail can
still be produced by `rz.s`/`mg.c0.run` (one frame), but the animated decode
loop is not started. So the trigger is **chat open**, not app start/chat list.
(The `notes/db_native_parsers.md` §4.4 statement "chat open … not the chat
list" is correct; its media3 sentence is superseded by §2.5.)

### 2.5 Media3/FFmpeg renderer is dead code (negative control)

72799 bundles `androidx.media3.decoder.ffmpeg.{ExperimentalFfmpegVideoDecoder,
ExperimentalFfmpegVideoRenderer,FfmpegLibrary,FfmpegAudioRenderer}` but they
are never used:

* `ExperimentalFfmpegVideoRenderer`/`Decoder`/`FfmpegLibrary` occur **only in
  `classes.dex`** (class definitions and self-references); no occurrence in
  `classes2/3/4.dex`, and no app-class constructor call or field use.
* The renderer factory is `i2.j` (obfuscated `DefaultRenderersFactory`); its
  constructor sets the extension-mode field `c = 0`
  (`EXTENSION_RENDERER_MODE_OFF`) at `0x3976C0`, and this is the **only**
  `iput` of that field in all four dex. `i2.j.b(...)` builds the MediaCodec
  video renderer `a3.n` first and branches on `c`; at `c == 0` it skips the
  FFmpeg/VP9/AV1 extension block (the block with
  `"androidx.media3.decoder.vp9.LibvpxVideoRenderer"` and
  `"Loaded LibvpxVideoRenderer."` strings).
* The only construction of `i2.j` is in the component factory `c2.c.get()`
  at `0x25EAC0`; nothing sets the mode to ON/PREFER.

So ordinary video messages/round videos use **MediaCodec** (system decoder),
not Media3 FFmpeg and not libvpx. Only the `AnimatedFileDrawable` path
(video stickers, custom emoji, GIFs, wallpapers) uses FFmpeg/libvpx locally.

---

## 3. Local trigger: file and DB fields

The media bytes are not in `cache4.db`; the DB stores metadata plus a path
computed by `FileLoader`. For a document:

```
FileLoader.getPathToAttach(document)
  dir = MEDIA_DIR_DOCUMENT or MEDIA_DIR_VIDEO or MEDIA_DIR_CACHE
  name = <document.dc_id> + "_" + <document.id> + ext
  ext  = extension from document.file_name, else getExtensionByMimeType(mime)
         -- "video/webm" is not in that switch, so ext == "" (no .webm suffix)
```

A sticker normally maps to `MEDIA_DIR_DOCUMENT` (`isVideoDocument()` is false
when the animated attribute is present); if the document also carries a
non-animated video attribute it maps to `MEDIA_DIR_VIDEO`. For autoplay `"g"`
with a missing file it falls back to `MEDIA_DIR_CACHE/<dc_id>_<id>.temp`
(`ImageLoader.java:3163-3165`). The first RCE can discover the real
directories (`find /data/user/0/<pkg> -type d`) and write all candidates.

Minimal `cache4.db` surface (schema in `notes/db_native_parsers.md`):

```
messages_v2(mid, uid, read_state, send_state, date, data BLOB, media, ...)
  data = SerializedData(TL_message)
         media = TL_messageMediaDocument
           document = TL_document {
             id, access_hash, dc_id, mime_type="video/webm", size,
             file_reference, thumbs,
             attributes = [TL_documentAttributeSticker]
                        or [TL_documentAttributeCustomEmoji] }
dialogs(did, ..., last_mid, data BLOB, ...)   -- did=chat, last_mid=new mid
media_v4(...)                                 -- optional cache
```

The local path does not require a server round trip if the file exists at the
computed path: `ImageLoader`/`AnimatedFileDrawable` open it directly, and
`gifvideo.cpp` demuxes/decodes it. `document.file_reference`/`access_hash`
matter for downloads, not for reading an existing local file. The message must
still be bound by the chat (chat open). This minimal row set is a hypothesis
for the device test; it is not verified on device.

The first RCE (existing widget QuickJS → `system()`, UID 10357) is the
assumed writer: it can place the file and edit the SQLite DB with a bundled
`sqlite3` (Android has no `sqlite3` CLI by default; ship a static one) or with
a small helper. Back up `cache4.db` first (§device plan). The injected row is
local-only: a server history sync can overwrite/remove it, so the trigger
window is the local state before the next sync (the widget-message seed has
the same property; it survives because it is also a real server message).

---

## 4. CVE matrix — decoder vs encoder, 1.5.x vs 1.17.0

"1.5.x" means the real v1.5.0 (there is no v1.5.4). "Fixed" is the first
upstream release containing the fix. "PoC" means a public, weaponisable PoC
was found; "private/OSS-Fuzz" means a testcase may exist but is not a public
exploit.

### 4.1 Decoder-side issues

| CVE | Component / function | Type | Fixed | v1.5.0 | 1.17.0 | Public PoC found | Local ACE? |
|---|---|---|---|---|---|---|---|
| CVE-2015-4485 | VP9 decode, `resize_context_buffers` | heap OOB **write** | ≤1.4.0-4 (Debian) | no | no | no | no |
| CVE-2015-4486 | VP9 decode, `decrease_ref_count` | OOB **read** | ≤1.4.0-4 | no | no | no | no |
| CVE-2015-4506 | VP9 decode, `vp9_init_context_buffers` (dup CVE-2015-1258) | buffer overflow | ≤1.4.0-4 | no | no | no | no |
| **CVE-2016-3881** | VP9 `vp9_dx_iface.c`, `decoder_peek_si_internal` | buffer **over-read** → hang/reboot (null-call SEGV in our build) | 1.6.1 (Debian; "probably fixed earlier") | **confirmed** (`pocs/vp9_9byte_peek_si_segv_1.5.0.bin`) | no (1.17.0 has the `data_sz < 10` guard) | public 9-byte crash input (DoS) | no (DoS only) |
| CVE-2016-2464 | `libwebm`/`mkvparser.cpp` (Android mediaserver container) | memory corruption | 1.6.1 | n/a | no | no | no (libwebm not built: `--disable-webm-io --disable-tools`) |
| CVE-2016-1621 | `libwebm`/`mkvparser.cpp` | memory corruption | 1.6.1 | n/a | no | no | no (tools only) |
| CVE-2017-13194, CVE-2019-9232/9325/9371/9433, CVE-2020-0034 | Android libvpx decoder (odd dimensions, OOB reads, resource exhaustion) | mostly OOB read/DoS | 1.8.2 / 1.9.0 | yes (some) | no | no | no (no write) |
| 1.17.0 changelog decoder fixes | `vp9_dec_alloc_row_mt_mem` (row-mt decode coeffs), `vp9_postproc`, VP9 invalid-ref-index crash, VP8 flush/MT/partition fixes | heap OOB **write** (row-mt), crashes | **1.17.0** | n/a | **fixed** (app has the fix) | no | would be a candidate only on ≤1.16.0 |

Notes:

* The 2015 bugs were fixed **before** v1.5.0; a v1.5.0 decoder is already
  patched for them. The 2016 `decoder_peek_si_internal` over-read (DoS) and
  the 2017–2020 Android decoder issues (mostly OOB reads/DoS) are the only
  older decoder items that could touch a v1.5.0 build; none is a proven
  write/UAF ACE.
* The `libwebm` CVEs are container-parser bugs in `vpxdec`/`vpxenc` and
  libvpx's optional WebM I/O. The app is built with `--disable-tools
  --disable-webm-io`, and the container is parsed by FFmpeg, so those CVEs
  are unreachable even if the libvpx version were old.
* The 1.17.0 changelog is the interesting delta: it fixes a **VP9 decoder
  row-mt heap overflow** (`vp9_dec_alloc_row_mt_mem`) and several decoder
  crashes. The app disables VP9 postproc, so the `vp9_postproc` item is not
  built; the row-mt item is reachable on multi-core phones (the app's
  `libvpx_init` uses `av_cpu_count()`, capped at 64, and the decoder is
  `AV_CODEC_CAP_OTHER_THREADS`). Telegram 72799 ships 1.17.0, i.e. the fixed
  side. A downgrade to ≤1.16.0 would open a real decoder issue; a downgrade
  to 1.5.x would open the 2016 OOB read.
* No public weaponised PoC was found for any listed decoder item; absence of
  a public PoC is not proof that none exists privately (OSS-Fuzz testcases are
  usually private for 90 days).

### 4.2 Encoder-side issues (not local decode ACE)

| CVE | Component / function | Fixed | 1.17.0 | Why not local ACE |
|---|---|---|---|---|
| CVE-2023-5217 | VP8 **encode** heap overflow | 1.13.1 | no | attacker is the decoder of a received file; encode input is app camera/frames |
| CVE-2023-44488 | VP9 **encode** width crash | 1.13.1 | no | same |
| CVE-2023-6349 | VP9 **encode** heap overflow (frame > configured) | 1.13.1 | no | same |
| CVE-2025-5283 | libvpx **encoder** double-free (WebRTC) | 1.15.2 | no | same; WebRTC encode, not local file |
| CVE-2026-1861 | VP9 **encoder** heap overflow (`vpx_enc_fuzzer_vp9`, Chrome 144) | 1.17.0-rc1 / 1.17.0 (commit `d5f35ac8`) | no | encoder settings `lag_in_frames≥25 + error_resilient + realtime`; not a decoder path |
| CVE-2026-2447 | VP9 **encoder** heap overflow (Firefox 147.0.4; same class) | 1.17.0-rc1 / 1.17.0 | no | same |
| CVE-2024-5197 | `vpx_img_alloc`/`vpx_img_wrap` integer overflow (API) | 1.14.1 | no | the FFmpeg **decoder** wrapper never calls these; FFmpeg's **encoder** does, with app-controlled dimensions |

The app does link the VP8/VP9 encoders (WebRTC and FFmpeg `WebmEncoder` for
round videos/video stickers), so encoder bugs are reachable in the *encoding*
direction, but the attacker of a local DB file is not the one supplying
encoder frames. An encoder CVE is not a local decode ACE.

### 4.3 `--size-limit=4096x4096` impact

The app's libvpx is built with `CONFIG_SIZE_LIMIT=1`,
`DECODE_WIDTH_LIMIT=4096`, `DECODE_HEIGHT_LIMIT=4096`. On the first frame,
`resize_context_buffers` (`vp9/decoder/vp9_decodeframe.c:1481`) rejects a
coded size above 4096 in either dimension with
`VPX_CODEC_CORRUPT_FRAME` ("Dimensions of WxH beyond allowed size"), before
the context buffers are resized. Consequences:

* It caps the allocation size for a crafted frame; the huge-dimension
  integer-overflow class (CVE-2024-5197 is API-level, but similar
  dimension-driven allocator bugs) is bounded.
* A >4096 VP9 stream is a clean on-device discriminator: libvpx will refuse
  it, while MediaCodec/system may not (§device plan T3).
* It does **not** protect the tile/partition/coefficient decoders inside a
  4096×4096 frame; those are the remaining 0-day surface.

---

## 5. Lab: builds, harness, runs

Full detail in `lab/libvpx_deep/RESULTS.md`.

* Built libvpx **v1.17.0** (`6df3ec34…`, the app's exact tag) and **v1.5.0**
  (`cbecf57f…`, the nearest real 1.5.x) with clang + ASan and the app's
  `--size-limit=4096x4096`.
* Harness `harness/vpx_decode_fuzz.c` mirrors FFmpeg's `libvpxdec`: per-packet
  `vpx_codec_decode`, `vpx_codec_get_frame` loop, IVF-aware, optional
  `VPX_THREADS` (the app uses `av_cpu_count()` capped at 64).
* Results (fresh, 2026-11-03; no ASan/UBSan report for these mutation runs;
  the corpus-replay artifact is in §5.1):

| target | runs | time |
|---|---|---|
| VP9 1.17.0, 1 thread | 4,151,995 | 180 s |
| VP9 1.5.0, 1 thread | 1,645,022 | 180 s |
| VP8 1.17.0, 1 thread | 1,608,951 | 180 s |
| VP8 1.5.0, 1 thread | 9,474 | 180 s (throughput collapse, not a crash) |
| VP9 1.17.0, 8 threads | 1,277,844 | 120 s |
| VP9 1.5.0, 8 threads | 833,078 | 120 s |

* A coverage-instrumented libvpx build (`src/vpx-1.17.0-cov`, same tag)
  linked into `build/fuzz_vp9_cov` added a **coverage-guided raw VP9**
  campaign: 422,159 executions in 306 s (6 forks), 2,191 libvpx edges /
  11,212 features, 0 crash, 0 artifact (`logs/campaign_vp9_cov_300s.log`).
* Existing app-like lab (`lab/decoder_fuzz`): FFmpeg **n8.1.3** (the app's
  exact tag, libavcodec 62.28.103) + libvpx **1.17.0** with the app's
  `--size-limit`, memory AVIO (same shape as `gifvideo.cpp`):
  14,917 VP9 decoder-corpus inputs and 4,278 WebM demux+decode samples, no
  fatal crash; 33,072 Matroska demuxer execs, no memory error.
  **Caveat:** that libvpx build is *not* ASan-instrumented
  (`--extra-cflags="-g -O1 -fno-omit-frame-pointer"`), so it only detects
  libvpx faults, not all heap OOB writes. The ASan libvpx campaigns in
  `lab/libvpx_deep` (both versions, single- and multi-threaded) are the
  authoritative decoder memory-safety check here; the app-like lab mainly
  covers FFmpeg's container/wrapper side.

### 5.1 A real v1.5.0 decoder crash (DoS, not ACE) — and the 1.17.0 guard

Replaying the public OSS-Fuzz `ffmpeg_AV_CODEC_ID_VP9_fuzzer` corpus (14,881
media prefixes) through the **ASan** harness produced one 1.5.0 artifact and
zero 1.17.0 artifacts:

```
pocs/vp9_9byte_peek_si_segv_1.5.0.bin
  b1 a4 c1 a1 00 00 00 12 19          (9 bytes)
  original OSS-Fuzz corpus id: 6510249808a337d07a1fb7d9275aa754871e4f5b

1.5.0:
  AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x0)
  #1 vp9_read_frame_size
  #2 decoder_peek_si_internal  vp9_dx_iface.c
  #3 decode_one
  #4 decoder_decode
  #5 vpx_codec_decode
1.17.0:
  executed cleanly (rc 0)
```

Mechanism: in 1.5.0 `decoder_peek_si_internal` only rejects `data_sz <= 8`;
a 9-byte keyframe passes that check, then `vp9_read_frame_size` reads 32 bits
past the end of the 9-byte buffer. `vpx_rb_read_bit` falls into its
out-of-range branch and calls `rb->error_handler`, which is `NULL` in this
call path → null function-pointer call. This is the `decoder_peek_si_internal`
area of **CVE-2016-3881** (buffer over-read → hang/reboot), here visible as a
null-call SEGV in our build. 1.17.0 has the CVE-2016-3881-era guard
`if (data_sz < 10) return VPX_CODEC_UNSUP_BITSTREAM;` (and `< 11` for the
colorspace case) before the reads; 1.5.0 only has the weaker `data_sz <= 8`
check, so the 9-byte input is rejected cleanly by 1.17.0.

This is a **DoS**, not a write/UAF and not an ACE: it kills the decoder
process/thread. It is only reachable if the app ships a pre-1.6.1 libvpx; 72799
ships 1.17.0. It is still useful as a version discriminator and as a positive
control that the harness finds real 1.5.0 bugs.

### 5.2 Combined AnimatedFileNative path — FFmpeg n8.1.3 + libvpx 1.17.0

This is the exact local path: **matroska/webm demuxer + FFmpeg `libvpx-vp9`
wrapper + libvpx 1.17.0 decoder**, all ASan-instrumented and coverage-guided.

Build (reproducible with `lab/libvpx_deep/build_combined_asan.sh`):

* FFmpeg **n8.1.3** (`1041abdc962f…`, the app tag), ASan+UBSan+fuzzer
  coverage, `matroska` demuxer, **native VP9 disabled**
  (`CONFIG_VP9_DECODER 0`), `libvpx_vp9` enabled; exact configure line saved
  in `lab/libvpx_deep/build/ffmpeg_configure_cmd.txt`.
* libvpx **v1.17.0** (`6df3ec34…`) rebuilt with ASan+fuzzer coverage and the
  app flags: `--size-limit=4096x4096 --enable-small --enable-realtime-only
  --enable-better-hw-compatibility --disable-runtime-cpu-detect
  --disable-webm-io --enable-multithread` plus VP8/VP9 decoders
  (`src/vpx-1.17.0-cov`).
* Harness `harness/fuzz_webm_combined.c` mirrors `AnimatedFileNative`:
  64 KiB memory AVIO (`read`/`seek` like `gifvideo_avio_read_cb`/`_seek_cb`),
  `avformat_open_input("http://localhost/file")`, `usetoc=1`,
  `AVFMT_FLAG_FAST_SEEK`, `avformat_find_stream_info`,
  `av_find_best_stream(AVMEDIA_TYPE_VIDEO)`, `avcodec_alloc_context3` /
  `parameters_to_context` / `avcodec_open2(refcounted_frames=1)`, then
  `av_read_frame` → `avcodec_send_packet`/`receive_frame` (32 frames max,
  frame data touched). Verified on a valid seed: the verbose build prints
  `VERBOSE dec=libvpx-vp9 frames=8` for the 320×240 WebM
  (`logs/verbose_seed_320x240.log`).
* Fuzzer-only caps (not in the app; they keep DoS/other-codec noise out):
  `ctx->max_pixels = 4096²`, `probesize=1 MiB`, `max_analyze_duration=1 s`,
  `max_streams=16`, `video_codec_id=VP9` (also models a container that
  claims `V_VP9` while carrying arbitrary bytes).
* Seeds: valid VP9 WebM at 64×64 / 128×96 / 320×240 (`vpxenc` +
  `harness/ivf2webm.py`), four OSS-Fuzz VP9 WebM, and 600 OSS-Fuzz VP9
  frame payloads wrapped as single-frame WebM. The campaign evolved
  `corpus/webm_clean` to 8,205 units; it was minimized to
  `corpus/webm_final_min` (3,653 coverage-unique units, 56 MB) for reuse.

Campaigns (all ASan; `VPX_THREADS=2` so libvpx runs multi-threaded, as the
app does with `av_cpu_count()`):

| run | configuration | executions | coverage | result |
|---|---|---|---|---|
| final, 2026-11-03 | `-fork=6 -max_total_time=1200 -max_len=65536 -use_value_profile=1` | **1,001,048** in 1,205 s | 21,345 edges / 135,229 features / 6,895 units | **0 OOM, 0 timeout, 0 crash, 0 ASan artifacts** |
| earlier fork | `-fork=6`, 1,215 s, mixed WebM corpus | 323,950 | 49,675 edges | 6 OOM (dav1d probing), 0 ASan |
| earlier jobs | `-jobs=5`, 1,200 s | 82,373 | — | 5 OOM, 0 ASan |
| earlier jobs | `-jobs=4`, 1,200 s | 115,859 | — | 4 OOM + timeouts, 0 ASan |

Combined-path total ≈ **1.52 M executions**; the VP9 decoder core was also
run **~5.8 M executions** in the standalone ASan harnesses (5.4 M mutation +
0.42 M coverage-guided, §5). **No ASan
heap/stack/global overflow, use-after-free, double-free or SEGV was found on
the target path.** This is a negative campaign, not proof of safety. No
memory-corruption input exists to minimize or escalate; if one is found later,
the reachability and first-RCE write path are already fixed in §3 and the
device plan (chat open, `FileLoader.getPathToAttach(document)`, `messages_v2`/
`dialogs`, `OpenChatReceiver`).

Non-findings (not counted as ACE):

* **OOM/DoS in a different decoder.** A 3.5 KiB WebM with an AV1 track made
  `avformat_find_stream_info` → `dav1d_parse_obus` request >512 MiB
  (`posix_memalign`); with `allocator_may_return_null=0` ASan reports
  `allocation-size-too-big`. This is a dav1d/container DoS, not the libvpx
  path; after forcing `video_codec_id=VP9` and capping probe/pixels the final
  campaign had zero OOMs.
* **Timeouts / slow units** — matroska/decoder DoS, not memory corruption.
* **UBSan `float-cast-overflow`** at `matroskadec.c:2740:46`,
  `3267:37`, `4165:49` (NaN/±inf duration/timebase converted to integer).
  Undefined behavior in the demuxer, not a memory-safety violation; a
  production build without UBSan does not trap. No ASan report.

**Caveats.** The combined campaign is ~1.5 M executions; a negative result
cannot exclude a 0-day. Fuzzer-only caps (`max_pixels`, probe/time caps,
`video_codec_id=VP9`) remove some app-default behavior (mostly DoS surface).
The host libvpx uses x86 SSE/AVX asm; the app's arm64 build disables NEON
asm, so the shared C decoder core is what this campaign validates — an
x86-asm-only finding would need arm64 triage. The harness does not model the
Java/ImageLoader lifetime (reuse/recycle of `AnimatedFileDrawable`/
`AnimatedFileNative`), which is a separate UAF surface worth auditing
independently of libvpx. The final corpus is retained for continuation; a
longer run should use `-fork` with the same build.

---

## 6. Device plan (summary)

Full runnable plan: `lab/libvpx_deep/device/test_plan.md`.

1. **T0 baseline** — `am force-stop` / `am start`, open a chat with a known
   video sticker, capture `logcat`. `tmessages_native` logs only failures.
2. **T1 write** — first RCE writes the crafted WebM to
   `<MEDIA_DIR_DOCUMENT>/<dc_id>_<id>` (and the `.temp` cache fallback) and
   inserts the `messages_v2`/`dialogs` rows. Back up `cache4.db`.
3. **T2 chat open** — `am force-stop` then
   `am start -n …/OpenChatReceiver -a com.tmessages.openchat… --el chatId …`;
   wait for the ImageLoader thread; capture `logcat` (`tmessages_native`,
   `DEBUG`, `libc`) and dropbox tombstones.
4. **T3 discriminator** — a valid 4097-px VP9 keyframe: libvpx's
   `--size-limit` rejects it; if the app renders it, the decode was not this
   libvpx path.
5. **T4 crash** — only with a real PoC; none exists for 1.17.0. A positive
   would be `Fatal signal 11/6` with `vpx*` frames in
   `libtmessages.49.so`.
6. **T5 controls** — chat list only (expect thumbnail, no decode loop),
   ordinary `.mp4` (MediaCodec), `.tgs` (rlottie/tlottie).

Identity is already verified: the installed APK/lib are the analysed 72799
binary with libvpx 1.17.0.

---

## 7. Verdict detail and residual risk

1. **The local path is genuine but the version premise is wrong.** A video
   sticker/custom-emoji WebM in the local DB and file cache is decoded by
   libvpx **1.17.0** on chat open. `1.5.4` is dav1d.
2. **No known CVE gives a local ACE.** The recent CVEs are encoder-only
   (2023-5217/44488/6349, 2025-5283, 2026-1861/2447) or API-only
   (2024-5197); the old decoder bugs are fixed by 1.6.1, and the 1.5.x decoder
   items are OOB reads/DoS, not a known write/UAF. The app's 1.17.0 also
   contains the 1.17.0 decoder fixes (`vp9_dec_alloc_row_mt_mem` heap
   overflow, invalid-ref-index crash).
3. **A local ACE now needs a 0-day** in libvpx 1.17.0 (VP9 decoder core:
   tile/partition/coefficient decode, loop filter, row-mt) or in FFmpeg's
   matroska/libvpx wrapper. The combined ASan campaign (~1.5 M executions)
   found no memory corruption; the 0-day remains unproven and is a research
   target, not a CVE replay.
4. **Ranking if a 0-day is found:** (a) VP9 decoder core via a video-sticker
   WebM — chat open, highest value; (b) FFmpeg matroska EBML/`matroskadec.c`
   — same trigger, container-level; (c) FFmpeg `libvpxdec.c` dimension/thread
   handling — smaller; (d) encoder-side bugs — not local ACE, do not rank
   them as such.
5. **What would change the verdict:**
   * a public decoder PoC for a CVE not fixed in 1.17.0 (none found);
   * proof that the app ships a different libvpx (it does not; all ABIs and
     the installed APK match);
   * a downgrade to ≤1.16.0 (1.17.0 decoder fixes become relevant) or a
     hypothetical 1.5.x build (CVE-2016-3881 becomes a DoS candidate);
   * a working 0-day, which would make the chain: first RCE → write WebM +
     DB rows → chat open → decoder ACE.

---

## 8. Artifacts

```
lab/libvpx_deep/
├── RESULTS.md                       # builds, harnesses, run tables, caveats
├── harness/vpx_decode_fuzz.c        # raw libvpx decoder harness
├── harness/fuzz_webm_combined.c     # combined FFmpeg matroska + libvpx-vp9 path
├── harness/ivf2webm.py              # IVF/raw VP9 -> WebM seed muxer
├── build_combined_asan.sh           # reproduce the combined ASan target
├── build/ffmpeg_configure_cmd.txt   # exact FFmpeg n8.1.3 configure line
├── src/vpx-1.17.0/                  # tag 6df3ec34… (ASan build)
├── src/vpx-1.17.0-cov/              # same tag, ASan+coverage, app flags
├── src/vpx-1.5.0/                   # tag cbecf57f… (ASan build)
├── build/fuzz_vp{8,9}_{1.17.0,1.5.0}
├── build/fuzz_vp9_cov              # coverage-guided raw VP9 harness
├── build/fuzz_webm_combined         # combined harness binary
├── build/fuzz_webm_verbose          # same + frame-count proof
├── seeds/seed_vp{8,9}_64.ivf, seeds/webm/  # valid WebM/IVF seeds
├── corpus/webm_final_min/           # 3,653 coverage-unique WebM units
├── corpus/                          # raw VP9 corpora + ossfuzz_vp9_media
├── pocs/vp9_9byte_peek_si_segv_1.5.0.bin   # 1.5.0 DoS, 1.17.0 clean
├── logs/fuzz_*.log, logs/replay_oss_*.log, logs/campaign_final_1200s.log
├── artifacts/webm/                  # DoS/OOM artifacts (no ASan memory corruption)
├── evidence/version_strings_all_abis.txt
├── evidence/ida_iface_registry_callgraph.txt
└── device/test_plan.md              # T0–T5
```

Key tool outputs are reproducible from the binary with
`strings -a -t x` and the offsets in §1; IDA addresses are image-base-relative
(base 0), file offset == VA for `.text`/`.rodata`.
