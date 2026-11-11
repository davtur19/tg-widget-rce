# Cold-start `AnimatedFileNative`: MOV/AV1 (dav1d 1.5.4) deep fuzz + reachability

Date: 2026-11-03. Target: `org.telegram.messenger.beta` 13.2.0 beta
(versionCode 72799), arm64 `lib/arm64-v8a/libtmessages.49.so`
(md5 `2c0caa68a07fc26f79d13519af6c3526`, BuildId
`645cce3998197329915f6cbfcc9ffd7f124d9f86`), installed on the Sony XQ-BT52
(Xperia 10 III, Android 13, `62.2.A.0.533`, rooted with Magisk, UID 10357).

Companion lab: `lab/dav1d_coldstart_fuzz/`. This note does not modify
`REPORT_20261102.md`; it extends `notes/local_message_media_ace.md` §2.4/§7
and `notes/libvpx_deep.md`.

---

## 1. Verdict

**No write/UAF/overflow was found in the exact decode path.** The campaigns
in §7 executed **1,080,418** inputs of FFmpeg n8.1.3 + dav1d 1.5.4
(ASan+UBSan, coverage-guided, multi-threaded), including a **2-hour**
`-fork=4` run and a parallel 2-hour container-decided run, with **0
ASan/UBSan memory reports, 0 crashes**. The only non-clean artifacts are 4
OOM saves (2 non-reproducing at 1–2 ms, 2 Matroska/AV1 frame-size DoS cases);
they are DoS-class and are not counted. That is a negative result, not a
proof of safety.

The reachability premise is **refuted for the chat-list thumbnail**:

* **APK bytecode (72799).** `ImageLocation` is obfuscated as
  `Lorg/telegram/messenger/jc;` (`classes.dex`). Its
  `c(Lorg/telegram/tgnet/TLRPC$PhotoSize;Lorg/telegram/tgnet/TLRPC$Document;)`
  (the `getForDocument(PhotoSize, Document)` used by `DialogCell.setThumb`)
  calls the private `jc.h(FileLocation, int, Photo, Document, InputPeer, …)`
  and returns the result directly. It never writes field `i`, the
  `ImageLocation.document` field. Consequence: `imageLocation.document` is
  **null** for document thumbnails built from a `PhotoSize`; `ImageLoader`'s
  `isGifDocument(imageLocation.document)` / `isRoundVideoDocument(...)` checks
  are false, `img.imageType` stays non-animation, and the cell decodes the
  thumb with BitmapFactory. The animation branch in
  `ImageLoader.createLoadOperationForImageReceiver` is not taken.
  (The 13.1.1 Java source agrees: `getForDocument(PhotoSize, Document)` →
  `getForPhoto(...)`, which sets `documentId` but not `document`.)
* **Device trace (inotify).** During a cold start with the forged new-GIF row
  as the first pinned dialog, `inotifyd` recorded the exact `openat` of the
  thumb file (`…/cache/-5213150876327219931_1109.jpg` and
  `…/-5913236580004267342_1115.jpg`) and the close events. But:
  an audio-only MP4 at the thumb path produced **no** `tmessages_native` /
  `can't find video stream` line; a valid **AV1 MP4** thumb produced **no
  rendered image** (BitmapFactory cannot decode AV1); a GIF thumb rendered
  (BitmapFactory can). A `video/webm` custom-emoji document (doc
  5848141329816620378) also produced only its **static thumb**
  (`-5848141329816620378_1109.jpg`) open, never the document file.
* **Plain video last message (tested last, 11:02).** A real plain video
  (`video/mp4`, `TL_documentAttributeVideo` 720×1280, **no** animated attr,
  mid 1282905, doc 6001211881186926846) was made the first pinned dialog; its
  `m` thumb path was replaced with a valid AV1 MP4 and the document paths with
  audio-only MP4s. Cold start: the `m` thumb
  (`cache/-6001211881186926846_1109.jpg`) was opened and closed twice, the
  document file was never opened, no `tmessages_native`/FFmpeg line appeared,
  and the AV1 thumb rendered nothing (the cell showed the generic "Video"
  icon). Same constructor path: `DialogCell` = `Lorg/telegram/ui/Cells/v2;`,
  `updateMessageThumbs` = `j0()V`, `setThumb` = `g0(ILkj;)V`; both call
  `Lorg/telegram/messenger/jc;.f(PhotoSize, TLObject)` (`0x3f8d12`,
  `0x3f8d1a`, `0x3f926e`, `0x3f93ce`), which dispatches a `Document` to
  `jc.c` (`0x4e43e6`) and returns without writing field `i`
  (`ImageLocation.document`). `isVideo()` only sets `drawPlay` in the cell.
* **All cold-start candidates are now refuted:** new-GIF, round video (same
  thumb branch), `image/gif` (not a trigger), animated wallpaper (wallpaper
  agent), and plain video (this test). The cold-start FFmpeg line is closed.
  The remaining `AnimatedFileNative` surfaces are chat-open/autoplay
  (`AUTOPLAY_FILTER` on the document media file), PhotoViewer /
  `VideoSeekPreviewImage`, and explicit `AnimatedFileDrawable` users.
* Therefore the 297-byte MOV `mov_fix_index` artifact is **not** a cold-start
  DoS through the dialog cell; that classification in
  `notes/local_message_media_ace.md` §2.4/§7.4 is retracted. It remains a
  MOV demuxer hang in the host harness and may be reachable on other
  (chat-open/media-viewer) surfaces.
* The real `AnimatedFileNative` surfaces are the **chat-open/autoplay**
  `AUTOPLAY_FILTER` path (`ImageLoader` branch that sets
  `IMAGE_TYPE_ANIMATION` from a real document location), PhotoViewer /
  `VideoSeekPreviewImage`, and a few other `AnimatedFileDrawable` users — not
  the dialog-cell last-message thumbnail. No cold-start FFmpeg decode was
  demonstrated.

No ACE is claimed. The rest of the note is the evidence, the harness, the
campaign numbers, and the (failed) cold-start plan.

---

## 2. Exact call path (72799)

### 2.1 Java → JNI

```
DialogCell.updateMessageThumbs()                              DialogCell.java:5690
  if (message.isPhoto() || message.isNewGif() || message.isVideo()
      || message.isRoundVideo() || message.isStoryMedia())
      setThumb(0, message)                                    DialogCell.java:5720
  setThumb: selectedThumb = bigThumb ('m' PhotoSize) unless
      !canDownloadMedia(...), then the stripped 'i' size;
      thumbImage.setImage(ImageLocation.getForObject(
          selectedThumb, document), "20_20", ...)             DialogCell.java:5760-5776
ImageLoader.createLoadOperationForImageReceiver()
  isGifDocument(document) || isRoundVideoDocument(document) …
      -> img.imageType = IMAGE_TYPE_ANIMATION                 ImageLoader.java:3128-3135
ImageLoader.CacheOutTask
  imageType == IMAGE_TYPE_ANIMATION, filter "20_20"
  new AnimatedFileDrawable(cacheFile, /*createDecoder=*/false,
      /*streamSize=*/0, …, document, …)                       ImageLoader.java:1129-1145
AnimatedFileDrawable.loadFrameRunnableImpl()
  mDecoder = AnimatedFileNative.createDecoderFrom(path.getAbsolutePath(),
      metaData, account, streamFileSize, stream, false)       AnimatedFileDrawable.java:318-334
```

`stream` is created only when `streamSize != 0` (`AnimatedFileDrawable.java`
constructor). `ImageLoader` passes `0` for the cached thumbnail, so the
**direct-file** native branch is used at chat-list cold start. The 64 KiB
memory-AVIO + `usetoc=1` branch is the progressive/stream branch.

### 2.2 Native `nCreateDecoder` (IDA, image-relative)

`Java_..._AnimatedFileNative_nCreateDecoder` = **0x74DC98**. Decompiled:

* `a6 == NULL` (no stream):
  `avformat_open_input(&fmt, src, NULL, NULL)`; on success goes straight to
  `avformat_find_stream_info`.
* `a6 != NULL` (stream): `open(src)`, `av_malloc(0x10000)`,
  `avio_alloc_context(..., 0x10000, readCallback, seekCallback)`,
  `av_dict_set(&opts, "usetoc", "1", 0)`,
  `avformat_open_input(&fmt, "http://localhost/file", NULL, &opts)`, then
  `fmt->flags |= 0x80000` (`AVFMT_FLAG_FAST_SEEK`) and `|= 0x40`
  (`AVFMT_FLAG_NOBUFFER`) when `preview != 0`.
* Both: `avformat_find_stream_info(fmt, NULL)`, then
  `open_codec_context(&stream_index, &codec_ctx, fmt, 0)`.

`open_codec_context` = **0x74D084**:
`av_find_best_stream(fmt, AVMEDIA_TYPE_VIDEO /*0*/, -1, -1, NULL, 0)`,
`avcodec_alloc_context3(dec)`, `avcodec_parameters_to_context()`,
`av_dict_set(&opts, "refcounted_frames", "1", 0)`, `avcodec_open2()`.

The frame loop is `VideoFrameReader_ctor` **0x74F230**,
`VideoFrameReader_getNextFrame` **0x74F30C**,
`VideoFrameReader_feedNextPacket` **0x74F458** (`av_read_frame` →
`avcodec_send_packet`/`avcodec_receive_frame`).

### 2.3 DB fields and file name

The message comes from `messages_v2.data` (TL `Message`) and must be the
dialog's last message (`dialogs.last_mid`):

* `TL_messageMediaDocument#52d8ccd9` → `TL_document#8fd4c4d8`
  (`id:int64`, `access_hash:int64`, `file_reference:bytes`, `date:int`,
  `mime_type:string`, `size:int64`, `thumbs:Vector<PhotoSize>` (flags bit 0),
  `dc_id:int`, `attributes:Vector<DocumentAttribute>`).
* Cold-start predicates: `mime_type = "video/mp4"`; attributes must include
  `TL_documentAttributeAnimated` (0x11b58939) and
  `TL_documentAttributeVideo` (0x43c57c48) with width/height ≤ 1280
  (`MessageObject.isNewGifDocument`), or `TL_documentAttributeVideo.round`.
* `PhotoSize` 'm' (type `"m"`, `w`, `h`, `size`) serialized as
  `TL_photoSize#75c78e60` **without** a location on the wire. The Java
  deserializer synthesizes it: `volume_id = -document_id`,
  `local_id = 1000 + type.charAt(0)` (`TLRPC.java:44176-44193`).
* `FileLoader.getPathToAttach(PhotoSize)` =
  `<volume_id>_<local_id>.jpg` = `-<document_id>_1109.jpg`, in
  `MEDIA_DIR_CACHE` = `AndroidUtilities.getCacheDir()` =
  `context.getExternalCacheDirs()[0]` (`AndroidUtilities.java:2635-2660`),
  i.e. on the device
  `/storage/emulated/0/Android/data/org.telegram.messenger.beta/cache/`.
* The *message media* file path (`Telegram Video/...`) is not opened by the
  dialog-cell thumbnail path. Only the thumb cache file is.

The first RCE (UID 10357) can write both the DB and the cache file, so the
whole trigger is local; no server validation applies. A normal in-place APK
update preserves `/data/data/...` and external files; the native library is
replaced, so a future Telegram/FFmpeg/dav1d version can change the path.

### 2.4 72799 static mapping (DialogCell, all four last-message kinds)

Bytecode from the 72799 APK (`classes3.dex` / `classes.dex`), consistent with
the 13.1.1 source:

* `DialogCell` = `Lorg/telegram/ui/Cells/v2;`.
* `updateMessageThumbs` = `v2.j0:()V` (code 0x3f917c); `setThumb(index,
  MessageObject)` = `v2.g0:(ILorg/telegram/messenger/kj;)V` (0x3f8ba4).
* The `updateMessageThumbs` condition chain calls, in order:
  `kj.m5()` (0x3f94ce, `needDrawBluredPreview`), `kj.S3(Message)` (0x3f94de,
  `isPhoto`), `kj.L3()` (0x3f94ea, `isNewGif`), `kj.L4(Message)` (0x3f94fa,
  `isVideo`), `kj.h4()` (0x3f9506, `isRoundVideo`; also used for the round
  radius at 0x3f8d3e), `kj.y4()` (0x3f9512, `isStoryMedia`; the body checks
  `TL_messageMediaStory`). `isGifDocument` is not in this chain.
* `setThumb` builds the thumb with
  `jc.f:(PhotoSize, TLObject)` (`ImageLocation.getForObject`) at 0x3f8d12 /
  0x3f8d1a (`g0`) and 0x3f926e / 0x3f93ce (`j0`). `jc.f` (0x4e43b4)
  dispatches a `Document` to `jc.c:(PhotoSize, Document)` (0x4e43e6).
  `jc.c` (0x4e4298) calls `jc.h(FileLocation, …, Document, …)` and returns;
  it never writes field `i` (`ImageLocation.document`). The constructor that
  does set `.document` is `jc.b:(Document)` (0x4e4270), used by
  `ImageLocation.getForDocument(Document)` (autoplay/chat-open), not by
  `DialogCell`.
* Consequence: for `isPhoto` the object is a `Photo` (photo path), for
  `isNewGif`/`isVideo`/`isRoundVideo` it is a **Document**, but the selected
  thumb is a `PhotoSize` and `jc.c` leaves `.document == null`. `ImageLoader`'s
  animation check at `ImageLoader.java:3132` (`isGifDocument(imageLocation.
  document) || isRoundVideoDocument(...) || isVideoSticker(...)`) is false and
  `IMAGE_TYPE_ANIMATION` is not set; `CacheOutTask` uses BitmapFactory.
  `MediaMetadataRetriever` is only at `ImageLoader.java:1087` for a filter
  containing `pframe`; the dialog filter is `"20_20"`. `document.video_thumbs`
  (`VideoSize`) is not passed to `setThumb` (it uses `message.photoThumbs`,
  i.e. `document.thumbs` `PhotoSize`). `isVideo()` only sets `drawPlay`.
* The same branch is therefore shared by new-GIF, round video and plain video;
  all three are refuted at chat-list cold start. `image/gif` does not even
  pass the condition (no `isGif` in `updateMessageThumbs`).

---

## 3. Versions and why this path was still interesting

From the analysed `.so`:

* FFmpeg **n8.1.3**, commit `1041abdc962f4cc4f394aa8de9dc5236c0c3b9e7`
  (libavcodec 62.28.103, libavformat 62.12.103), with mov, matroska, gif,
  ogg, mp3, aac demuxers; h264, hevc, mpeg4, mjpeg, gif, libdav1d,
  libvpx_vp8/vp9, opus decoders.
* **dav1d 1.5.4-0-g54706fc6** (exact tag commit), arm64 asm.
* libvpx 1.17.0 (`--size-limit=4096x4096`, `--disable-neon-asm`), libopus
  1.6.1.

Prior labs covered:

* `lab/local_message_media_ace`: MOV **demux** corpus (22,649 files, 7,643
  execs) and MP4/MKV **decode** of VP9/H.264/MPEG-4/MJPEG samples (6,335
  execs); no AV1/dav1d decode, no MOV+AV1 container path.
* `lab/libvpx_deep`: WebM/VP9 demux+decode with ASan libvpx (1.52 M combined
  execs). The only dav1d contact was an incidental OOM while probing an AV1
  WebM (`artifacts/webm/…`); it was not fuzzed.

Upstream delta since the app versions (checked 2026-11-03):

* dav1d `1.5.4..master` = 45 commits, mostly optimizations. The only
  memory-safety-adjacent fixes are **OOM-path** only:
  `9143ecb decode.c: Reset tile state count when reallocation fails` and
  `e5fd231 obu: fix assert or memory leak after itut-t35 metadata malloc
  fails`; the others are x86 AVX-512 and RISC-V fixes (`d7a83f6`, `e91a97f`)
  that cannot affect the app's arm64 build.
* FFmpeg `n8.1.3..master` for `libavformat/mov.c` + `libavcodec/libdav1d.c`
  = 6 commits: a `tfra` box infinite-loop DoS (`332df18e67`, same class as
  the prior `mov_fix_index` hang), an OOM leak (`4b1149c8eb`), Exif/stream
  group features. No non-OOM memory-corruption fix in these files.

So the app does not miss a *published* non-OOM memory-safety fix in this
path; the campaign is a true 0-day hunt.

---

## 4. Harness

`lab/dav1d_coldstart_fuzz/harness/fuzz_animated_decode.c` mirrors the exact
order above:

1. `avio_alloc_context` with a 64 KiB buffer over the fuzz input (or
   `APP_FILE_MODE=1` to drop `usetoc`/`FAST_SEEK` and model the direct-file
   cold-start branch).
2. `avformat_open_input("http://localhost/file")`, `find_stream_info`.
3. optional `codecpar->codec_id` forcing (models a container that announces
   the codec; `fuzz_mov_av1` forces `AV_CODEC_ID_AV1`, `fuzz_mov_hevc` HEVC).
4. `av_find_best_stream(VIDEO)`, `avcodec_alloc_context3`,
   `avcodec_parameters_to_context`, `refcounted_frames=1`, `avcodec_open2`.
5. decode loop up to 64 frames / 512 packets, `send_packet` +
   `receive_frame`, touching the first and last byte of every plane (an OOB
   read that the app would turn into a bitmap copy is made observable).

Fuzzer-only caps (deliberate, documented): `max_pixels = 4096²`,
`probesize = 1 MiB`, `max_analyze_duration = 1 s`, `max_streams = 16`,
`thread_count = 2` (the app uses `av_cpu_count()`; dav1d
`AV_CODEC_CAP_OTHER_THREADS` → `n_threads = min(cpu, DAV1D_MAX_THREADS)`).
dav1d film grain is applied (the wrapper default `apply_grain=1`), so the
grain synthesis path runs.

Three binaries are built from the same source:

| binary | codec | open branch |
|---|---|---|
| `fuzz_mov_av1` | AV1 forced | direct file (`APP_FILE_MODE=1`) |
| `fuzz_anim_any` | container decides | stream (`usetoc=1`, `FAST_SEEK`) |
| `fuzz_anim_file` | container decides | direct file (`APP_FILE_MODE=1`) |
| `fuzz_mov_hevc` | HEVC forced | direct file |
| `fuzz_mov_av1_t8` | AV1 forced, 8 threads | direct file |

The `FORCE_CODEC_ID` default must stay undefined for the container-decided
targets; the original `#ifndef FORCE_CODEC_ID #define … 0` made the later
`#ifdef` block zero every video stream's codec id (see §7).

The verbose build (`-DVERBOSE_DECODE`) prints the decoder, dimensions,
thread count and frame count; `seeds/av1_64x64_crf20.mp4` prints
`VERBOSE dec=libdav1d 64x64 threads=2 … VERBOSE frames=10 packets=10`.

## 5. Build

* FFmpeg: existing ASan+UBSan+coverage build of tag n8.1.3
  (`--enable-libdav1d`, demuxers `mov,gif,ogg,matroska,mp3,aac`, decoders
  `h264,hevc,mpeg4,mjpeg,gif,…,libdav1d,libvpx_vp8/vp9`),
  `/tmp/opencode/ffmpeg-8.1.3-local-asan-build`.
* dav1d 1.5.4 **ASan+UBSan+coverage**, built here:
  `CC=clang CXX=clang++ meson setup build-cov-fuzz --buildtype=debugoptimized
   -Db_sanitize=address,undefined
   -Dc_args="-fsanitize=fuzzer-no-link -fno-omit-frame-pointer"
   -Ddefault_library=static -Denable_asm=true -Denable_tools=false
   -Denable_tests=false -Denable_examples=false`,
  `ninja -C build-cov-fuzz src/libdav1d.a`.
  `nm … | grep -c __sanitizer_cov_8bit_counters_init` = 50 objects.
  (The older `build-asan-static` had ASan but no coverage; this lab adds it.)
* libvpx 1.17.0 app-flags coverage build from `lab/libvpx_deep`; libopus
  1.6.1 ASan.
* `bash lab/dav1d_coldstart_fuzz/build_targets.sh` links the three fuzzers
  with `-fsanitize=fuzzer,address,undefined`.

## 6. Corpus

* 45 generated seeds from the first pass, plus 14 long-run seeds from
  `gen_seeds_extra.sh`: AV1 10-bit 4:2:0/4:4:4, 10-bit film grain, 4:4:4
  Matroska, fragmented AV1 MP4, H.264 High-10, H.264/HEVC MOV, HEVC Main-10,
  HEVC Rext 4:4:4 10-bit, fragmented HEVC and multi-track AV1/H.264 MP4.
  All decode through the fixed `fuzz_anim_file_verbose` (H.264/HEVC/dav1d).
* 2,982 AV1-classified files ≤64 KiB from the OSS-Fuzz
  `ffmpeg_dem_MOV_fuzzer` (389) and `ffmpeg_dem_MATROSKA_fuzzer` (2,593)
  corpora (`ffprobe -select_streams v:0` = av1), 3,027 initial inputs with
  the first-pass seeds.
* Long-run corpora (2 h): `corpus/long_av1` = 9,357 inputs (all seeds + the
  evolved `av1_mov`/`av1_4k` corpora); `corpus/long_mixed` = 5,071 inputs
  (all seeds + `mixed` + `hevc_mixed`).
* Mixed corpus: seeds + the prior Telegram video samples (VP9/H.264/
  MPEG-4/MJPEG) + 250 AV1 containers.
* The 2,307 OSS-Fuzz raw AV1 `ffmpeg_AV_CODEC_ID_AV1_fuzzer` inputs could
  not be remuxed (they are decoder-fuzzer payloads without a sequence
  header; `ffmpeg -f av1/-f obu` fails), so they are not used as container
  seeds.

## 7. Campaigns and results

Host: 8 cores, ASan+UBSan, `-fork=N`, `-max_len=65536`,
`-use_value_profile=1`, `-rss_limit_mb=1200`, `-malloc_limit_mb=512`,
`-timeout=15`.

| campaign | binary | config | execs | coverage | result |
|---|---|---|---|---|---|
| smoke | fuzz_mov_av1 | fork=2, 120 s | 17,143 | 77,717 edges / 363,522 ft | 0 crash, 0 OOM, 0 timeout |
| A (MOV/AV1) | fuzz_mov_av1 | fork=4, 1800 s | **224,756** (1,836 s wall) | 83,509 edges / 454,533 ft / 7,114 units | 0 ASan, 0 crash, 4 **sporadic** timeouts |
| B (mixed) | fuzz_anim_any | fork=3, 1500 s | **132,501** (1,512 s) | 79,070 edges / 347,843 ft / 3,764 units | 0 ASan, 0 crash, 4 sporadic timeouts + 1 slow-unit |
| C (4K/8-thread) | fuzz_mov_av1_t8 | fork=2, 600 s | **30,373** (614 s) | 68,252 edges / 336,485 ft / 1,996 units | 0 ASan, 0 crash |
| D (HEVC) | fuzz_mov_hevc | fork=1, 600 s | **16,137** (625 s) | 66,086 edges / 247,171 ft / 1,207 units | 0 ASan, 0 crash |
| **long_av1** (2 h) | fuzz_mov_av1 | fork=4, 7200 s, direct file | **501,482** (7,232 s) | 94,380 edges / 523,390 ft / 9,937 units | 0 ASan, 0 crash, 4 non-reproducing/DoS OOM |
| **long_mixed** (2 h) | fuzz_anim_file | fork=2, 7200 s, direct file, container-decided | **158,026** (7,251 s) | 124,915 edges / 650,551 ft / 7,169 units | 0 ASan, 0 crash, 0 artifacts |

**Total: 1,080,418 libFuzzer executions, 0 memory-safety reports, 0
crashes.** The two 2-hour runs alone are 659,508 execs in ~2 h wall time
(parallel, 6 workers, RSS caps).

Artifacts: `artifacts/campA_av1/` (8 `timeout-*`), `artifacts/campB_mixed/`
(4 `timeout-*`, 1 `slow-unit-*`), `artifacts/long_av1/` (4 `oom-*`),
`artifacts/long_mixed/` (empty). The campaign A/B `timeout-*` and the long
`oom-*` files replay individually in 1–767 ms with a higher RSS limit; the
Matroska/AV1 ones hit the harness's 16M-pixel `max_pixels` limit
(`Frame size 30327x3791 exceeds limit 16777216`, dav1d/Matroska allocation
DoS), not a memory error. Any real OOM/timeout is a DoS and is not counted as
a memory-corruption finding.

**Harness bug found and fixed during the long run (important for the old
numbers).** The original harness had
`#ifndef FORCE_CODEC_ID / #define FORCE_CODEC_ID 0 / #endif`. Because the
later block is `#ifdef FORCE_CODEC_ID`, that default made **every**
container-decided target execute `codecpar->codec_id = 0` on each video
stream. `fuzz_anim_any` (old campaign B) and the initial
`fuzz_anim_file` therefore never opened a video decoder; old campaign B is a
**demux/parser/probe** campaign, not a decode campaign. The forced targets
(`fuzz_mov_av1`, `fuzz_mov_av1_t8`, `fuzz_mov_hevc`) were unaffected because
the command-line `-DFORCE_CODEC_ID=…` overrides the default. The default was
removed at 07:25; `build/fuzz_anim_file_verbose` now proves H.264 (incl.
High 10), HEVC (Main 10 and Rext 4:4:4 10-bit) and libdav1d (10-bit 4:4:4,
film grain, Matroska) decode. The long `long_mixed` campaign below uses the
fixed binary.

## 8. Reachability: what is and is not reachable

Preconditions: the first exploit (UID 10357) can write
`/data/data/org.telegram.messenger.beta/files/cache4.db`, the external media
tree and `shared_prefs`. No root/ADB/Frida/overlay is needed at trigger time.

**Not reachable at chat-list cold start (refuted):** a forged new-GIF or
**plain video** last message and its thumbnail cache file
(`<external cache>/-<doc_id>_<1000+type>.jpg`). The bytecode and the device
traces in §1/§9 show the thumb is opened and decoded by BitmapFactory, not by
`AnimatedFileNative`. `DialogCell` uses
`ImageLocation.getForObject(PhotoSize, TLObject)` (`jc.f`) → `jc.c` for a
document, which does not set `ImageLocation.document`; `isVideo()` only adds
the play icon. `MediaMetadataRetriever` is only used for a `pframe` filter
(`ImageLoader.java:1087`), not the dialog `"20_20"` filter; `video_thumbs`
(`VideoSize`) are not passed to `setThumb` (only `document.thumbs` PhotoSize).
Do not use this as a cold-start trigger.

**Reachable on chat open (candidate, not cold start):** a document that
`ImageLoader` classifies as `IMAGE_TYPE_ANIMATION` through a real document
location:

* `video/webm`/`video/mp4` **video sticker**, **GIF** or **round video**
  message opened in `ChatMessageCell` with the autoplay filter
  (`AUTOPLAY_FILTER` "g") — `ImageLoader` creates `AnimatedFileDrawable`
  with the document location and size, so `nCreateDecoder` runs on the
  document media file.
* `PhotoViewer`/`VideoSeekPreviewImage` / `AnimatedEmojiDrawable` paths that
  construct `AnimatedFileDrawable` directly.

For a chat-open PoC the file is the document media file
(`Telegram Video|Documents/<dc>_<id>`, or the cache `.temp` fallback), not
the thumb. The first RCE can write the message row, the document blob and
the file; the trigger is a chat open (a tap/notification/deep link, not the
chat list). A normal in-place APK update preserves `/data/data/...` and the
external files.

**Discriminators (no crash needed):**

* An audio-only MP4 at the decoded path makes `nCreateDecoder` log
  `can't find video stream in the input, aborting <path>` (tag
  `tmessages_native`), proving FFmpeg reached the file. A valid AV1 MP4
  reaching the same path produces no error; its decode is visible as a
  rendered/animated frame (BitmapFactory cannot decode AV1).
* `inotifyd`/`fdtrace` (`device/`) record the exact `openat` and fd position;
  a static `aarch64-linux-gnu` `fdtrace` binary and `inotifyd` are used
  because the device has no `strace` and tracefs has no syscall events.

## 9. Device check (2026-11-03, Sony XQ-BT52)

Tools: the device has no `strace`, and tracefs exposes no syscall events
(`available_events` has only `raw_syscalls:`). Two tracers were used instead:

* `inotifyd - <dir>:ar0` on the external cache / `Telegram Video` /
  `Telegram Documents` directories (records `r` open, `a` access, `0` close
  with the file name);
* `fdtrace`, a 775 KB statically linked aarch64 helper built for this lab
  (`device/`), polling `/proc/<pid>/fd` every 20 ms and logging the resolved
  path plus `fdinfo` position.

The DB was pulled with WAL/SHM after `am force-stop` and always restored
afterwards. Only `dialogs.last_mid/date/pinned` were edited; the message rows
were copied **verbatim** (no document-blob edits in the successful runs).

**Test 1 — new-GIF last-message rows (refuted).** Three real new-GIF rows
were used as the first pinned dialog: mid 34600 (chat -<CHAT_ID>), mid <CHAT_ID>
(deleted user 932145014, single `s` thumb) and mid 401 (archived chat; later
excluded because `folder_id=1`). Probes at the exact thumb paths
(`-5213150876327219931_1109.jpg`, `-5913236580004267342_1115.jpg`) were an
audio-only MP4, a valid AV1 MP4 and a valid GIF in successive cold starts
(`am force-stop` → `am start … LaunchActivity`, `LaunchState: COLD`).

The inotify trace shows the exact files being opened and closed at cold
start (`device/logcat_*`, `device/reach_*.png`):

```
r  .../cache  -5213150876327219931_1109.jpg
0  .../cache  -5213150876327219931_1109.jpg
r  .../cache  -5913236580004267342_1115.jpg
0  .../cache  -5913236580004267342_1115.jpg
```

But the audio-only MP4 produced **no** `tmessages_native` line (the native
`nCreateDecoder` error log is therefore not reached); the AV1 MP4 thumb
produced **no rendered image**, while the GIF thumb rendered a static first
frame. BitmapFactory cannot decode AV1 but can decode GIF, so the opener is
the image loader's static path, not `AnimatedFileNative`.

**Test 2 — video/webm custom emoji document (also refuted at cold start).**
`animated_emoji` contains 8 `video/webm` custom-emoji documents (100×100,
`TL_documentAttributeVideo`, dc 4). Message 1282838 (chat -<CHAT_ID>)
contains a custom-emoji entity for doc `5848141329816620378`; the message was
made the last message of a pinned dialog, verbatim. An audio-only MP4 was
written to every plausible document path
(`Telegram Video/4_5848141329816620378`, `Telegram Documents/…`, and the
`cache/….temp` fallbacks). At cold start only
`cache/-5848141329816620378_1109.jpg` (the static thumb) was opened; the
document file was never opened and no `tmessages_native` line appeared.

**Test 3 — plain video last message (also refuted).** From the fresh DB a
real plain video was chosen: mid 1282905, chat -<CHAT_ID>,
`mime_type=video/mp4`, `TL_documentAttributeVideo` 720×1280, **no**
`TL_documentAttributeAnimated` (so `isVideoDocument()` is true and
`isNewGif()` is false), `document.thumbs` = `i` (stripped) + `m` (6372 B),
doc 6001211881186926846, dc 4. Only `dialogs.last_mid=1282905`,
`dialogs.pinned=7` and `dialogs.date` were edited; the message row stayed
verbatim. The `m` thumb path
`…/cache/-6001211881186926846_1109.jpg` was replaced with a valid **AV1 MP4**
(18,384 B); audio-only MP4 probes were written to
`…/files/Telegram/Telegram Video/4_6001211881186926846{,.mp4}`,
`…/Telegram Documents/…` and the `cache/….temp` fallbacks. Cold start
(`LaunchState: COLD`, no tap): `inotifyd` recorded the `m` thumb open/close
twice; the **document files were never opened**; no `tmessages_native` /
`avformat`/FFmpeg line appeared; the AV1 thumb rendered **no frame** — the
row showed the generic "Video" icon (`device/video_plain.png`,
`device/logcat_video_plain.log`, `device/ino_video.log`). The original thumb
(6372 B) and the pre-test DB/WAL/SHM were restored afterwards.

**Why (APK bytecode).** In 72799 `ImageLocation` is
`Lorg/telegram/messenger/jc;`. `jc.c(PhotoSize, Document)` (the
`getForDocument(PhotoSize, Document)` used by `DialogCell.setThumb`) calls
`jc.h(...)` and returns; it never writes field `i`
(`ImageLocation.document`). `imageLocation.document` is therefore null, so
`ImageLoader` does not set `IMAGE_TYPE_ANIMATION`; the thumb goes through
BitmapFactory. This matches the 13.1.1 Java source and the device result.

**Restore.** After each run the original `cache4.db` + WAL + SHM were pushed
back, probe files removed, Wi-Fi/data re-enabled, the app restarted and the
pid/`versionCode=72799` verified. No reboot, no data wipe. The audio-only,
AV1 and GIF probe files and the raw logcat/screenshot captures are in
`lab/dav1d_coldstart_fuzz/device/`.

**Verdict of the device runs: the chat-list cold-start FFmpeg decode is
refuted.** The generated row is accepted and rendered, and its thumb path is
opened, but `nCreateDecoder` is not called for it. A chat-open PoC (autoplay
filter on the document media file) remains the viable local trigger; a
cold-start PoC on this surface does not exist. Do not cite §2.4 of
`local_message_media_ace.md` as a cold-start FFmpeg/DoS path.

## 10. Limits

* Host is x86_64; the device is arm64. dav1d/FFmpeg C paths are shared, but
  arm64 asm and the app's 8-thread configuration are not executed on the
  host. The ASan build uses the C/asm x86 paths; arm64-only asm bugs would
  not be found.
* The app's exact `thread_count` is `av_cpu_count()` (8 on the phone);
  fuzzing used 2 for determinism. A dedicated `APP_THREADS=8` campaign is
  the next step if a threading bug is suspected.
* `max_pixels`/`probesize`/`max_analyze_duration` caps are fuzzer-only; the
  app has no `max_pixels` cap before the Java 3840 check, so huge-dimension
  OOM/DoS is under-modelled (but OOM is not ACE).
* A 0-finding campaign of this size cannot exclude a 0-day. It does exclude
  the previously reported DoS classes and shows the harness reaches
  `libdav1d` decode.

## Reproduce

```sh
B=$PWD/lab/dav1d_coldstart_fuzz
bash $B/build_targets.sh
"$B/build/fuzz_mov_av1" -fork=4 -max_total_time=1800 -max_len=65536 \
  -use_value_profile=1 -rss_limit_mb=1200 -timeout=15 \
  -artifact_prefix=$B/artifacts/campA_av1/ $B/corpus/av1_mov
"$B/build/fuzz_anim_any" -fork=3 -max_total_time=1500 -max_len=65536 \
  -use_value_profile=1 -rss_limit_mb=1200 -timeout=15 \
  -artifact_prefix=$B/artifacts/campB_mixed/ $B/corpus/mixed
```
