# Local-message media → native parser audit (Telegram Android 72799)

Date: 2026-11-02/03. Target: `org.telegram.messenger.beta` 13.2.0 beta
(versionCode 72799), arm64, `lib/arm64-v8a/libtmessages.49.so`
(md5 `2c0caa68a07fc26f79d13519af6c3526`, BuildId
`645cce3998197329915f6cbfcc9ffd7f124d9f86`). Device used for the
non-destructive reachability check: Sony XQ-BT52 (Xperia 10 III), Android 13,
build `62.2.A.0.533`, security patch **2023-07-01**.

This note does **not** modify `REPORT_20261102.md`. It extends, and in one
place corrects, `notes/db_native_parsers.md`, `notes/ida_media_parsers_72799.md`
and `notes/decoder_fuzz.md`.

Lab: `lab/local_message_media_ace/` (sources, scripts, corpora, logs,
artifacts, device backup).

---

## 0. Threat model and scope

The starting point is the first exploit: an **app-UID shell**. The attacker can
therefore rewrite:

* `files/cache4.db` (and its WAL), i.e. the TL-serialized `messages_v2.data`,
  `media_v4`, `dialogs`, `users`, `chats` blobs;
* every file under the app's media cache / external `Android/data/.../files`;
* `files/`, `shared_prefs/`, `cache/`.

The Java TL deserializer is memory-safe and is not the target. The target is a
**native parser** that consumes attacker-chosen bytes from a local message and
can plausibly give code execution or a clean memory-corruption primitive. A
crash, OOM, ANR or NULL dereference is not ACE and is labelled as such below.

The important difference from bot-delivered media is **server validation is
gone**. A local `TL_document` may carry any `mime_type`, `size`, `attributes`
and `thumbs`; a `TL_photo` may carry any `id`/`type`/dimensions; the file at
the derived cache path may be any bytes. This makes parser *selection* and
resource limits attacker-controlled, but it does not change the parser code.

All app addresses below are image-base-relative for this exact build. The
bundled-version and registry facts were re-derived from the IDA database
`<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_media_annotated.i64`
and from `nm -D` on the exact `.so`.

---

## 1. Verdict

**No app-bundled media/document parser at 72799 has a demonstrated
memory-corruption or ACE primitive reachable from a local DB message.**

What is reachable and what it is worth:

| Rank | Path | Kind | Verdict |
|---|---|---|---|
| 1 | System Skia/libwebp via a cached avatar/photo (**CVE-2023-4863**) | heap OOB **write** in the platform decoder | **Vulnerable code confirmed** in Sony `libhwui` (pre-fix 1.2.4 `ReadHuffmanCodes` fixed block), and the avatar path is proven decoded at cold start (red-WebP control). PoC WebPs produced **no crash/tombstone** (silent OOB on non-ASan Scudo). Reachable platform bug, but no demonstrated ACE/controlled primitive. |
| 2 | FFmpeg 8.1.3 (MOV/MKV/OGG/GIF + H.264/HEVC/MPEG-4/MJPEG/VP8/VP9/AV1/Opus) | large C attack surface, app-bundled | Fuzzed: see §7. **No ASan memory error found** in this pass (only non-memory UBSan UB). All 2026 FFmpeg CVEs are either patched in 8.1.3 or in decoders/demuxers that are **not compiled** (§4). Cold-start reachable through the last-message **new-GIF/round-video thumbnail** (§2.4); a 297-byte MOV causes a reproducible `mov_fix_index` hang (DoS, not corruption). |
| 3 | `opusfile` v0.12 + libopus 1.6.1 via `getWaveform` | app-bundled, chat-open | The known CVE-2022-47021 is a **NULL deref only when `ogg_sync_buffer` allocation fails**, i.e. OOM-triggered, not a crafted-file bug. Fuzzing found no ASan error. |
| 4 | tlottie (TGS) | Rust, safe parser | Covered separately; the only memory-safety issue is the JNI check-then-free **race UAF** in the prior `decoder_fuzz` model, not a parser bug. |
| 5 | GIF canvas / TGS gzip expansion | resource exhaustion | Deterministic **DoS**, not corruption. |
| 6 | SQLite 3.39.3 (`cache4.db`) / `tgnet.dat` | startup native | Prior audits: OOB **reads** / UAF / OOM, no write primitive. |

The only *known, public, ACE-class* bug in the reachable set is the platform
libwebp CVE-2023-4863. It is outside the app `.so` and the app cannot patch it.
The Sony `libhwui` code is **pre-fix 1.2.4** and the avatar path is
**confirmed decoded at cold start** (red-WebP control), so the vulnerable code
is reachable. The three public PoCs did **not** crash the handset; an OOB write
on a non-ASan Scudo heap can be silent. This report does **not** claim an
end-to-end RCE or a controlled primitive from that bug.

---

## 2. How a local message reaches a parser

### 2.1 DB fields and file paths

`messages_v2.data` is a TL `Message`. The relevant media objects:

* `messageMediaDocument#52d8ccd9` → `document#8fd4c4d8`
  (`id:int64`, `access_hash:int64`, `file_reference:bytes`, `mime_type:string`,
  `size:int64`, `thumbs:Vector<PhotoSize>`, `dc_id:int32`,
  `attributes:Vector<DocumentAttribute>`);
* `messageMediaPhoto#e216eb63` → `photo#fb197a65`
  (`id:int64`, `dc_id:int32`, `sizes:Vector<PhotoSize>`);
* `messageMediaWebPage` → `webpage.photo` / `webpage.document`;
* `messageMediaStory` → `storyItem.media`.
* `users.data` / `chats.data` contain `photo_small` (`UserProfilePhoto` /
  `ChatPhoto`), which is **not** a message but is decoded at chat-list/widget
  cold start (§6.2).

`MessageObject`/`FileLoader` derive the cache path from those fields:

* document: `FileLoader.getAttachFileName()` = `<dc_id>_<id><ext>`
  (`FileLoader.java:1652-1670`). The directory is
  `MEDIA_DIR_AUDIO` for `isVoiceDocument`, `MEDIA_DIR_VIDEO` for
  `isVideoDocument`, otherwise `MEDIA_DIR_DOCUMENT`
  (`FileLoader.java:1347-1425`). On Android 13 the external dirs are
  `Android/data/org.telegram.messenger.beta/files/Telegram/Telegram {Audio,Video,Documents}`.
* photo: `TLRPC.PhotoSize.TLdeserialize()` sets
  `volume_id = -photo_id`, `local_id = type.charAt(0)`;
  `getAttachFileName()` yields `<volume_id>_<local_id>.jpg`
  (`TLRPC.java:44176-44192`, `FileLoader.java:1680-1685`), under
  `Telegram Images/`. The extension is irrelevant: `BitmapFactory` sniffs the
  content.
* `messageOwner.attachPath` is only read by `readAttachPath()` for
  outgoing/self/legacy messages (`TLRPC.java:58920-58980`); it is **not** a
  general received-message path override. `Document.localPath` is a
  Java-only field (`TLRPC.java:28894`) and is not deserialized from the DB.

So the attacker can place **arbitrary bytes at a predictable path** for any
message, but cannot make a received message point outside the app's media
directories through TL fields alone.

### 2.2 Parser selection predicates

`MessageObject` decides which native path a document takes:

| Predicate | Condition | Native consumer |
|---|---|---|
| `isVoiceDocument` | any `TL_documentAttributeAudio` with `voice=true` | `MediaController.getWaveform` (opusfile/FFmpeg) on cell draw; playback is system MediaPlayer |
| `isVideoDocument` | `TL_documentAttributeVideo`, not round, file extension not in `isV()` blacklist | `AnimatedFileDrawable`/`VideoFramesRewinder`/PhotoViewer → FFmpeg |
| `isGifDocument` | `image/gif`, or `video/mp4` + `attributeAnimated` + w/h ≤ 1280 | `AnimatedFileDrawable` → FFmpeg |
| `isVideoStickerDocument` | `video/webm` + `attributeSticker`/`attributeCustomEmoji` | `AnimatedFileDrawable` → FFmpeg |
| `isAnimatedStickerDocument(...,true)` | `application/x-tgsticker` (with thumbs) or `application/x-tgsdice` | `RLottieNative` → tlottie |
| `isStickerDocument` | `attributeSticker` and mime `image/webp` or `video/webm` | static WebP: BitmapFactory; video: FFmpeg |
| `canPreviewDocument` | image/png, image/jpg, image/jpeg, image/heic + image-size < 6000 + thumb | BitmapFactory |
| `isNewGif` / `isGif` | as above | FFmpeg |

Key source refs: `MessageObject.java:6908-6980`, `10270-10360`,
`11160-11340`, `10422-10460`; `ImageLoader.java:1116-1138`;
`DialogCell.java:5733-5830`.

### 2.3 Trigger timing

| Trigger | What is parsed | Evidence |
|---|---|---|
| **Cold start / chat list** | **dialogs’ user/chat avatars** via `ImageLoader`/`BitmapFactory`; custom-emoji TGS in the last message text/caption (`AnimatedEmojiSpan.drawAnimatedEmojis`); last-message **photo** thumbnail via `DialogCell.setThumb` → `ImageLoader` → BitmapFactory; **new-GIF / round-video thumbnail** via `AnimatedFileDrawable` → FFmpeg (see §2.4) | `DialogCell.java:4250-4275`, `5733-5830`; `ImageLoader.java:1040-1140`; prior TGS startup analysis |
| **Notification** | avatar bitmap via BitmapFactory; notification sound via system MediaPlayer. A DB-only message does **not** produce a push notification, so this is not a message-triggered native parser path. | `NotificationsController` uses `MediaPlayer`/`Ringtone` |
| **Chat open** | static WebP sticker → BitmapFactory; TGS sticker/custom emoji → tlottie; GIF/video sticker/round video/autoplay video → `AnimatedFileDrawable` → FFmpeg; **voice waveform generation** → opusfile/FFmpeg; document thumbs → BitmapFactory/MediaMetadataRetriever | `ChatMessageCell.updateWaveform` 12652; `MessageObject.getWaveform` 12567; `audio.c:639` |
| **Tap video / PhotoViewer** | `nGetVideoInfo` demux (`gifvideo.cpp:376`), `VideoFramesRewinder` decode; media3/ExoPlayer playback | `PhotoViewer.java:21699`, `VideoFramesRewinder.java:72` |
| **Open PDF** | system `libpdfium` via `PdfRenderer` | user tap only |
| **Instant View / WebPage** | WebView/Chromium (remote HTML); not a local-file parser | user tap / network |
| **Theme / wallpaper** | `.attheme` Java parser; wallpaper BitmapFactory; animated wallpaper FFmpeg | user-applied; not message-automatic |

### 2.4 `AnimatedFileNative` at chat-list cold start (important correction)

**CORRECTION 2026-11-03 (APK bytecode + device trace).** The chain below is
**not** taken for document thumbnails. In 72799
`ImageLocation.getForDocument(PhotoSize, Document)` (obfuscated
`Lorg/telegram/messenger/jc;.c`) does not set the `ImageLocation.document`
field, so `ImageLoader`'s `isGifDocument(imageLocation.document)` is false and
the dialog cell uses BitmapFactory. A device cold-start trace with
`inotifyd` sees the thumb cache file being opened, but no
`tmessages_native`/FFmpeg decode: an audio-only MP4 thumb logs nothing, an
AV1 MP4 thumb renders no image, and a GIF thumb renders via BitmapFactory.
A `video/webm` custom-emoji document also opens only its static thumb. A
**plain video** last message (`video/mp4`, video attr 720x1280, no animated
attr, mid 1282905) behaves identically: the `m` thumb
`-6001211881186926846_1109.jpg` is opened twice by BitmapFactory, the
document file is never opened, no `tmessages_native` line appears, and an
AV1 thumb renders no frame. The 72799 `DialogCell` (`Lorg/telegram/ui/Cells/
v2;`) `updateMessageThumbs` (`j0()V`) / `setThumb` (`g0(ILkj;)V`) call
`jc.f(PhotoSize, TLObject)` -> `jc.c` for a document; `isVideo()` only sets
`drawPlay`. `MediaMetadataRetriever` is used only for a `pframe` filter, not
the dialog `"20_20"` filter, and `video_thumbs` (`VideoSize`) are not passed
to `setThumb`.
The `mov_fix_index` 297-byte hang below is therefore **not** a cold-start DoS
via the dialog cell; treat that classification as retracted. The real
`AnimatedFileNative` triggers are chat-open/autoplay paths
(`AUTOPLAY_FILTER`) and other explicit `AnimatedFileDrawable` users. See
`notes/dav1d_coldstart_fuzz.md` §1/§8/§9.

`AnimatedFileNative` is normally described as a **chat-open** parser. The
chat list does not decode the *full* GIF/video, but it can still reach
`AnimatedFileNative` at cold start through the **last-message thumbnail** of
two media types:

* a **new GIF**: `video/mp4` + `TL_documentAttributeAnimated` +
  `TL_documentAttributeVideo` (w/h ≤ 1280) — `MessageObject.isNewGif()`;
* a **round video**: `video/mp4` + `attributeVideo.round_message=true`
  (w/h ≤ 1280) — `MessageObject.isRoundVideo()`.

Exact chain (source 13.1.1, matching the 72799 smali call graph):

```
DialogCell.updateMessageThumbs()
  -> setThumb(index, message)                       DialogCell.java:5733
     selectedThumb = a non-stripped PhotoSize       DialogCell.java:5760-5776
     thumbImage[index].setImage(
        ImageLocation.getForObject(selectedThumb, photoThumbsObject),
        "20_20", ...)                               DialogCell.java:5772
  -> ImageLocation.getForDocument(photoSize, document)
       imageLocation.document = document            ImageLocation.java:337-343
  -> ImageLoader.createLoadOperationForImageReceiver()
       if (isGifDocument(imageLocation.document) ||
           isRoundVideoDocument(imageLocation.document) ...)
           img.imageType = IMAGE_TYPE_ANIMATION     ImageLoader.java:3130-3135
       cacheFile = path from photoSize.location     ImageLoader.java:3190-3205
  -> ImageLoader.CacheOutTask
       imageType == IMAGE_TYPE_ANIMATION            ImageLoader.java:1040
       fistFrame = false (filter "20_20")
       new AnimatedFileDrawable(cacheFile, false, 0, ..., document, ...)
                                                    ImageLoader.java:1137
  -> ImageReceiver.setImageBitmap(...)
       allowStartAnimation default true             ImageReceiver.java:296
       fileDrawable.checkRepeat()                   ImageReceiver.java:937/3000
  -> AnimatedFileDrawable.start() -> loadFrameRunnableImpl()
       AnimatedFileNative.createDecoderFrom(path, ...)  AnimatedFileDrawable.java:318-334
  -> Java_..._AnimatedFileNative_nCreateDecoder 0x74DC98
       avformat_open_input / avformat_find_stream_info / avcodec_*
                                                    gifvideo.cpp:526-640
```

The file consumed is the **thumbnail cache file**, not the message media:
for a document thumb, `PhotoSize.TLdeserialize(document_id, ...)` sets
`volume_id = -document_id`, `local_id = 1000 + type.charAt(0)`
(`TLRPC.java:44176-44192`), so the path is

```
cache/-<document_id>_<1000+typechar>.jpg (MEDIA_DIR_CACHE; DialogCell passes size=0, so ImageLoader takes the cache branch)
```

The extension `.jpg` is irrelevant; FFmpeg sniffs the content. A local DB
message can therefore place **any container bytes** (WebM, MP4, GIF, MOV,
Matroska) at that path and have `AnimatedFileNative` parse them at cold start.
This is a genuine **startup FFmpeg surface**, but note the limits:

* it applies only to **new GIF / round video** last messages; ordinary video
  and video stickers are not in `DialogCell.updateMessageThumbs()`;
* the parse is of the **thumb** file, so the file can be small (the DB
  `size`/`w`/`h` are not used to validate the thumb bytes);
* `AnimatedFileDrawable` checks `metaData[0] > 3840 || metaData[1] > 3840`
  **after** `nCreateDecoder` returns (`AnimatedFileDrawable.java:486-494`), so
  a GIF canvas bomb / parser hang is already inside FFmpeg before the guard;
* `ImageReceiver` uses `allowStartAnimation=true` by default; `DialogCell`
  does not disable it (`grep setAllowStartAnimation` only in
  `ImageReceiver`).
* to make the non-stripped thumb the selected one, omit the inline stripped
  `i` size or keep its advertised `size` small enough for
  `DownloadController.canDownloadMedia`; a stripped `i` selected instead has
  no file location and never reaches `AnimatedFileNative`.

The 297-byte MOV/Mp4 hang found by the `dem_mov` campaign (`pocs/mov_tfra_hang.bin`)
is an example of a **cold-start thumbnail DoS** under this model: no memory
corruption, but `mov_fix_index()` loops/reallocs (`mov.c:4460`) from
`mov_read_trak`/`mov_build_index` (`mov.c:5014/5257`), so the animation decode
thread burns CPU/memory. It is not an ACE primitive.

72799 smali anchors for the JNI surface (obfuscated names are the 72799
mapping):

| Smali | Java/native |
|---|---|
| `smali_classes3/org/telegram/ui/Components/AnimatedFileNative.smali:167` | `native nCreateDecoder(String,[IIJ,Object,Z)J` |
| `...AnimatedFileNative.smali:170` | `native nDestroyDecoder(J)V` |
| `...AnimatedFileNative.smali:173` | `native nGetFrameAtTime(JJ,Bitmap,[I)I` |
| `...AnimatedFileNative.smali:176` | `native nGetVideoFrame(J,Bitmap,[IZFFZ)I` |
| `...AnimatedFileNative.smali:179` | `native nGetVideoInfo(String,[IJ)V` |
| `...AnimatedFileNative.smali:182/185/188` | `nPrepareToSeek` / `nSeekToMs` / `nStopDecoder` |
| `smali_classes3/org/telegram/ui/Components/s5.smali:616` | `AnimatedFileNative.a(...)` = `nCreateDecoder` from `AnimatedFileDrawable` |
| `s5.smali:1561` | `nGetVideoFrame` |
| `s5.smali:4690` | `nGetFrameAtTime` |
| `s5.smali:4649` | `nSeekToMs` |
| `s5.smali:6103` | `nPrepareToSeek` |
| `smali/org/telegram/messenger/rz.smali:14076` | `AnimatedFileNative.d(String,[IJ)` = `nGetVideoInfo` (`PhotoViewer`/`ImageLoader`) |

The `s5.smali:616` call passes exactly the JNI shape
`(src, int[11], account, streamFileSize, AnimatedFileDrawableStream, preview)`;
the `int[11]` is `PARAM_NUM_*` (supported codec, w, h, bitrate, duration,
audio frame size, video frame size, framerate, rotation, supported audio,
has audio). `nGetVideoInfo` uses `int[11]` too and only fills the demux
metadata (`gifvideo.cpp:376-515`).

For **animated stickers (TGS)** in the last message, `DialogCell` does not
show a sticker thumbnail at all (not in `isPhoto/isNewGif/isVideo/
isRoundVideo/isStoryMedia`); the only startup TGS path is a custom-emoji span
in the message text (`AnimatedEmojiSpan.drawAnimatedEmojis`), which goes to
tlottie, not `AnimatedFileNative`.

### 2.5 Update survival of the local-message delivery

The first exploit gives app-UID write to:
`/data/data/org.telegram.messenger.beta/files/cache4.db` and the external
`Android/data/.../files/Telegram/...` media tree. An `adb install -r` /
PackageInstaller update replaces the APK but **does not clear app data**;
therefore:

* the crafted DB row and the cached GIF/WebM/MOV thumbnail persist across a
  normal in-place update;
* `libtmessages.49.so` and its FFmpeg version are replaced by the new APK
  (`lib/arm64-v8a/libtmessages.49.so`); 72799 is 8.1.3. A newer build may
  change the parser or the `AnimatedFileNative` wrapper, so the same bytes may
  no longer hit the same code path;
* Telegram's own updater also preserves data, but the app may run DB
  migrations (`user_version`) and server sync. A cold start renders the chat
  list **before** sync, so a forged DB message/thumbnail can still be parsed
  at startup even if the server later removes it;
* a forged server `mid` that does not exist remotely may be dropped on the
  next difference sync, so the delivery is strongest for the first cold start
  after writing the DB (and for offline starts).

This is the same persistence model as the prior widget/Ace work; no new
update-trigger bypass is claimed here.

---

## 3. Parser inventory (app-bundled)

Versions were re-checked against the exact `.so`; registry addresses are in
`.data.rel.ro`.

| Surface | Library / version | Entry point | DB field / media path | Reachability | Known CVE status |
|---|---|---|---|---|---|
| TGS / custom emoji | **tlottie** Rust `31f1b542…` (2026-09-11), not rlottie | `RLottieNative.nCreate` 0x74F710, `nGetFrame` 0x750228 | document mime `application/x-tgsticker`/`x-tgsdice`; `<dc>_<id>.tgs` | cold start (custom emoji in last message) / chat open | rlottie CVE family absent (different parser); prior JNI race UAF model |
| GIF | **FFmpeg n8.1.3** (`Lavc62.28.103`/`Lavf62.12.103`) gif demux+gif decoder | `AnimatedFileNative.nCreateDecoder` 0x74DC98; `avformat_open_input` 0x1110248, `avformat_find_stream_info` 0x1111F48, `avcodec_*` 0x1165714/0x116221C | document mime `image/gif` or `video/mp4` + animated; `Telegram Documents/…` or `Telegram Video/…` | chat open autoplay | no known in-range CVE; canvas bomb DoS (prior) |
| Video sticker / WebM | FFmpeg matroska demux + **libvpx 1.17.0** VP9 (`--size-limit=4096x4096`) | same `nCreateDecoder` path | `video/webm` + sticker/custom-emoji attr; `Telegram Documents/<dc>_<id>.webm` | chat open autoplay | libvpx 1.17.0 contains the 2026 fixes |
| Video / MP4 | FFmpeg mov demux + h264/hevc/mpeg4/mjpeg/libvpx/dav1d; `nGetVideoInfo`; `VideoFramesRewinder` | 0x74DC98, 0x74D6AC, 0x74EAF0 | `TL_messageMediaDocument`/`video`; `Telegram Video/<dc>_<id>.mp4` | chat open inline autoplay, tap/PhotoViewer | no known in-range CVE; see §4 |
| Voice / audio waveform | **opusfile v0.12** (`a55c164…`) + **libopus 1.6.1** (`22244de…`); FFmpeg fallback | `MediaController.getWaveform` 0x16F19A4; `FfmpegAudioWaveformLoader.init` 0x16F1C88 | voice document (`TL_documentAttributeAudio.voice=true`) with empty `waveform`; `Telegram Audio/<dc>_<id>.ogg` | **chat open** (cell `updateWaveform`) | CVE-2022-47021 is OOM-only NULL deref; no RCE CVE |
| Voice playback | system `libcodec2_soft_opusdec.so` + APEX `libopus.so` (MediaPlayer) | MediaCodec `c2.android.opus.decoder` (alias `OMX.google.opus.decoder`) | same OGG file | tap play | no known RCE; version string `libopus unknown-fixed` |
| Static sticker/photo/thumb/avatar | **system Skia/libwebp 1.2.4 (pre-fix)**/libjpeg/libpng/libheif; no libwebp in `libtmessages` | `BitmapFactory.decodeFile` (`ImageLoader.java`); widget `h4.smali:866`/`k5.smali:871` | avatar `cache/-<photo_id>_97.jpg` (chat list) / `Telegram Images/-<photo_id>_97.jpg` (widget); photo cache `<vol>_<loc>.jpg` | **avatar cold start / chat list**; chat open | **CVE-2023-4863 confirmed in `libhwui`**; PoC no crash, no controlled primitive |
| Video/document thumb | system `MediaMetadataRetriever` / BitmapFactory | `SendMessagesHelper.createVideoThumbnail` | video/document | chat open / quality thumb | system |
| Theme / wallpaper | `.attheme` Java parser; wallpaper BitmapFactory; animated wallpaper `AnimatedFileNative` | `BitmapFactory` / `AnimatedFileNative` | theme document / wallpaper prefs | user-applied (not message-automatic) | no app-bundled theme parser RCE |
| PDF | system `libpdfium.so` via `PdfRenderer` | `PdfRenderer` | document mime `application/pdf` | user tap | not audited here |
| Documents / archives | Java `ZipFile`/external handler or system viewer; no app-bundled archive decoder in `libtmessages` | — | `TL_messageMediaDocument` generic | user tap / external app | out of scope (not automatic) |
| WebPage / Instant View | WebView/Chromium, `litehtml` not on this path | `ArticleViewer`/WebView | webpage URL/document | user tap/network | out of scope |
| SQLite | **3.39.3** | `SQLiteDatabase_opendb` 0x74C8F0 | `cache4.db` | **startup** | OOB read/UAF (CVE-2025-7458/6965/2024-0232); no write |
| `tgnet.dat` | Telegram `tgnet` native | `ConnectionsManager.native_*` | `files/tgnet.dat` | **startup** | prior audit: OOB reads / OOM only |
| Code blocks (adjacent) | `libprisma` native | `PrismaHighlighter.nativeHighlight` 0x99D7AC | message text, language | chat open | not media; not fuzzed here |

**Registry evidence (authoritative, IDA):**

* demuxers @ `0x1901658`: `aac`, `gif`, `matroska,webm`,
  `mov,mp4,m4a,3gp,3g2,mj2`, `mp3`, `ogg`; sentinel at `0x1901688`.
* decoders @ `0x19080B0`: `libvpx`, `libvpx-vp9`, `gif`, `h263`, `h264`,
  `hevc`, `mjpeg`, `mpeg4`, `aac`, `alac`, `flac`, `mp3`, `libdav1d`,
  `libopus` (14 entries).
* BSFs @ `0x1908B08`: `aac_adtstoasc`, `pgs_frame_merge`,
  `vp9_raw_reorder`, `vp9_superframe`.

Consequences:

* **No TIFF, RASC, RSCC, MagicYUV, LCL, AVI, WebP, PNG, JPEG-2000, HEIF/AVIF
  decoder is compiled into `libtmessages`.**
* TIFF would go to `BitmapFactory` (system), not FFmpeg.
* AVI is not a demuxer; RASC/RSCC/MagicYUV/LCL cannot be selected.
* `--disable-zlib` is real (`CONFIG_ZLIB=no` in the host model); Matroska
  zlib-compressed frames are not decoded by the app's build.

---

## 4. FFmpeg CVE matrix (corrected)

The app really is **n8.1.3** (`1041abdc962f4cc4f394aa8de9dc5236c0c3b9e7`,
2026-09-20), newer than 8.1.2. Machine-readable matrix:
`lab/local_message_media_ace/ffmpeg_cve_matrix.tsv`. The host model was built from that tag with the exact
registry plus libvpx 1.17.0, dav1d 1.5.4 and libopus 1.6.1.

| CVE | Component / bug | Fixed in | In 8.1.3? | Compiled in 72799? | Reachable? | Impact |
|---|---|---|---|---|---|---|
| **CVE-2026-8461** | MagicYUV decoder heap OOB **write** | 8.1.2 (three commits, `pr/23159`) | **yes** | **no** (`magicyuv` absent) | no | RCE-capable class, but irrelevant here |
| **CVE-2026-12706** | RASC `decode_move()` heap OOB/UAF **read**, crafted AVI | 9.0 (`2f60af4`); 8.1 delta has the RASC DLTA row check (`cf148db`) | RASC row check yes; exact move fix not needed | **no** | no (no RASC decoder, no AVI demuxer) | info leak/DoS |
| **CVE-2026-70629** | RSCC uninitialised heap **read** on short input | 9.0 (`a5fe21a`/`cd1f545`); 8.1.3 delta contains `57e01be` “do not leave uninitialized data…” | **yes** (source check present) | **no** | no | info leak/DoS |
| **CVE-2026-70631** | TIFF uninitialised heap **read** (inflate shorter than strip) | 9.0 (`3c287af`/`2f234ea`); 8.1.3 delta contains `24d0c11` “reject inflate output shorter than the strip” | **yes** (source check present) | **no** (`tiff` absent; images go to BitmapFactory) | no | info leak/DoS |
| **CVE-2026-66038** | LCL/ZLIB heap info leak | 9.0 (`7c0b8c8`/`e7cbfd1`); 8.1.3 delta contains `25867a1`/`2addf44` lcldec zeroing | **yes** (source checks present) | **no** (`lcldec` absent) | no | info leak |
| **CVE-2026-30997/30998/30999** | tooling/resource issues (30998 is `tools/zmqsend` FILE leak) | 8.1.2 / 9.0 | 30999 in 8.1.2; 30998 is a host tool | **no** (tools not shipped in `libtmessages`) | no | DoS/tool |
| **CVE-2026-30754** | RTP | 8.1 branch | yes | **no** (`--disable-network`) | no | n/a |

The critical point: **“8.1.3 is affected by a 9.0 CVE” is not a lead unless the
decoder/demuxer is in the registry**. The CVE-2026-8461 class (MagicYUV) is a
heap OOB write, but the decoder does not exist in the Telegram build. The
RASC/RSCC/TIFF/LCL CVEs are info leaks/DoS and their decoders are absent. The
reachable FFmpeg registry remains the 6 demuxers / 14 decoders in §3.

Also: an earlier draft saying “CVE-2026-70629/70631 affect 8.1.3” is not
accurate for this tree. The n8.1.2→n8.1.3 delta already contains the
`rscc`/`tiff`/`lcldec`/`rasc` fixes (commits dated 2026-06-28 to 2026-08-12,
in `cmp813.json`), and `libavcodec/tiff.c:549` / `rscc.c:317` /
`lcldec.c:159,292` contain the corresponding checks. Even if one were
incomplete, none of those decoders can be selected by 72799.

**Conclusion:** no FFmpeg 8.1.3 CVE is a reachable ACE lead. The remaining risk
is 0-day class in the 6 demuxers and 14 decoders; that is what the fuzz
campaigns in §7 target.

---

## 5. Opus / opusfile

### 5.1 Exact versions

* libopus: submodule `TMessagesProj/jni/third_party/xiph/opus`
  = `22244de5a79bd1d6d623c32e72bf1954b56235be` (2026-01-13), tag **v1.6.1**;
  binary `opus_get_version_string()` returns the built-in placeholder
  `libopus unknown-fixed`.
* opusfile: submodule
  `TMessagesProj/jni/third_party/xiph/opusfile`
  = `a55c164e9891a9326188b7d4d216ec9a88373739` (2020-06-26), tag **v0.12**.
  The sources are compiled directly by
  `TMessagesProj/jni/CMakeLists.txt:256-260`; `libopus.a` is the prebuilt
  static library. The app therefore has **opusfile 0.12 + libopus 1.6.1**.

### 5.2 Reachability (important, and better than the bot path)

`MessageObject.getWaveform()` (`MessageObject.java:12567`) returns
`TL_documentAttributeAudio.waveform`; if it is null/empty it calls
`MediaController.generateWaveform(this)` (`MediaController.java:5330`).
That runs on `Utilities.globalQueue` and calls the native
`getWaveform(path)` (`MediaController.java:5340`).

`Java_..._MediaController_getWaveform` (`audio.c:639`) does:

1. `op_open_file(path, &error)` — **opusfile 0.12 parser**;
2. if that succeeds, `op_pcm_total`, `op_read` loop — **libopus decoder**;
3. if `op_open_file` fails, it falls back to
   `avformat_open_input` + `avformat_find_stream_info` + audio decoder
   (`audio.c:745-926`) — the FFmpeg OGG/Opus path.

`ChatMessageCell.updateWaveform()` (`ChatMessageCell.java:12652`) calls
`getWaveform()` for `DOCUMENT_ATTACH_TYPE_AUDIO`/`ROUND` when the cell is
bound. Therefore a **local voice document with `voice=true` and an empty
`waveform`** causes native opusfile parsing at **chat open**, before the user
presses play. The file is at `Telegram Audio/<dc>_<id>.ogg` (or the document
cache dir, depending on `isVoiceDocument`).

This is an app-bundled, local-message-triggered parser path. It is not
startup/chat-list: `DialogCell` does not call `getWaveform`.

### 5.3 CVEs

* **CVE-2022-47021** (opusfile 0.9–0.12): NULL pointer dereference in
  `op_get_data`/`op_open1` when `ogg_sync_buffer()` returns NULL. The fix
  commit `0a4cd796` only adds `if (buffer == NULL) return OP_EFAULT;`.
  **This is an allocation-failure/OOM bug, not a crafted-file bug.** A normal
  OGG cannot force `ogg_sync_buffer` to fail except by exhausting memory.
  It is a DoS at most; it is **not** an ACE lead.
* **CVE-2017-0381**: old Android libopus; the app ships 1.6.1, and the system
  decoder is a different copy. Not applicable to the app build.
* **CVE-2026-40614 / CVE-2025-65102**: PJSIP Opus decode overflow. Telegram
  uses WebRTC/tgcalls and its own libopus, **not PJSIP**; excluded.
* No recent libopus RCE CVE is known for 1.6.1.

The opusfile tag is old, but the post-0.12 commits are mostly OOM handling
(`e9f3486`, `cc04a82`, `e9fa83a`) and a 2026 one-line picture-buffer fix
(`0e61551`) that only affects the intermediate post-`cc04a82` code, not the
v0.12 code. No crafted-file memory-corruption fix is being missed by the
v0.12 pin in the audited code.

### 5.4 Fuzzing

Harnesses:

* `src/opusfile_fuzzer.c` — `op_open_memory` + `op_pcm_total`/`op_head`/
  `op_tags` + 64 `op_read` calls; opusfile v0.12 + libopus 1.6.1, ASan/UBSan,
  coverage build.
* `src/opus_packet_fuzzer.c` — direct `opus_packet_parse` +
  `opus_decode` (PLC/FEC included), libopus 1.6.1 coverage build.

Results: see §7.3/§7.5. Full second pass: opusfile **71,006 exec / 601 s**,
direct libopus **77,816 exec / 601 s**, no ASan/UBSan memory error. Two
first-pass libFuzzer timeouts did not reproduce on replay (one 5-byte
`SIpOs`, one 200 KB Matroska-header blob, both execute in milliseconds);
they are scheduler artifacts, not parser findings.

**Conclusion:** opusfile/Opus is a genuine chat-open native parser, but the
known CVE is OOM-only and the fuzz campaigns are negative. Do not call this
ACE.

---

## 6. Image / thumbnail path: the platform libwebp

Telegram 72799 has **no libwebp/libjpeg/libpng/FreeType** in
`libtmessages.49.so` (no `RIFF`, `WEBP`, `VP8L`, `VP8X`, `WebPDecode*`,
`jpeg_*`, `FT_*` strings/symbols; `nm -D` has no `loadWebpImage`). Cached
photos, avatars, static WebP stickers and document image thumbs go through
`android.graphics.BitmapFactory` → `libhwui.so` → Skia → the platform
libwebp/libjpeg/libpng/libheif.

On the test Sony:

```
ro.build.version.security_patch = 2023-07-01
ro.build.fingerprint = Sony/XQ-BT52_EEA/XQ-BT52:13/62.2.A.0.533/...
/system/lib64/libhwui.so   8,899,480 B, build 2023-08-22
  strings: image/webp, WEBPVP8L, VP8L
/system/lib64/libwebp.so   absent (static in libhwui)
/system/lib64/libheif.so, libpdfium.so present
```

### 6.1 The Sony decoder is the pre-fix 1.2.4 code (exact evidence)

The patch-level date alone was not enough. IDA on the pulled
`/system/lib64/libhwui.so` resolves the libwebp functions and shows the
**pre-fix** implementation:

| Evidence | Value |
|---|---|
| `libhwui.so` SHA-256 | `1df543f0a43487a99f58081930a2e06ee6c6435669c42b270302162a7fe4036f` |
| Build ID | `056e592fad8f6c3d4d7473d4d511e078` |
| Size / build date | 8,899,480 B / 2023-08-22 |
| Security patch | 2023-07-01 |
| Location | `/system/lib64/libhwui.so` (not an APEX/Mainline module) |
| WebView | `com.google.android.webview` 153.0.8010.36 (2026-09-23) — separate process/decoder, not `BitmapFactory` |

IDA `ida_hexrays.decompile` of `DecodeImageStream` at `0x6c575c` shows the
vulnerable single fixed huffman-table allocation:

```c
v76 = WebPSafeCalloc(v76, 4);        // code_lengths
v78 = v52 * v74;                     // num_htree_groups * table_size
v162 = WebPSafeMalloc(v78, 4);       // <-- fixed huffman_tables block
v80 = WebPSafeMalloc(v52, 568);      // htree_groups
...
ReadHuffmanCode(..., v82);           // v82 walks the fixed block
```

This matches libwebp 1.2.4 `ReadHuffmanCodes()`:

```c
huffman_tables = (HuffmanCode*)WebPSafeMalloc(num_htree_groups * table_size,
                                              sizeof(*huffman_tables));
```

and `ReadHuffmanCode` at `0x6c8040` calls the 4-argument
`VP8LBuildHuffmanTable` at `0x6e4d28` (`BuildHuffmanTable` at `0x6e4e30`);
there is **no** `VP8LHuffmanTablesAllocate` symbol in the binary. There is no
`HuffmanTables*`/`HuffmanTablesSegment`/`VP8LHuffmanTablesAllocate` path.
libwebp **1.3.2** (the CVE-2023-4863 fix) replaced this with
`HuffmanTables*` and per-segment allocation:

```c
int VP8LBuildHuffmanTable(HuffmanTables* const root_table, ...)
...
if (root_table->curr_segment->curr_table + total_size >= ...)
    ... WebPSafeMalloc(... HuffmanTablesSegment ...)
```

Therefore **Sony's `libhwui` contains the vulnerable 1.2.4 code**, not the
patched segment allocator. This is exact static patch evidence, independent
of the security-patch string. Host control: `libwebp 1.2.4` ASan crashes on
`bad`/`maxdrift`/`nso`; `libwebp 1.3.2` (same harness, `decode-asan-1.3.2`)
returns `nil`/rejects them without an ASan report:

```
ASAN_OPTIONS=detect_leaks=0 ./build_webp_decode_1.2.4 webp_poc/bad.webp whole
  ERROR: AddressSanitizer: heap-buffer-overflow ... ReplicateValue
ASAN_OPTIONS=detect_leaks=0 ./build_webp_decode_1.3.2 webp_poc/bad.webp whole
  [harness] whole done: rgba=(nil) 1x1        # no ASan report
```

### 6.2 Avatar path: exact DB/cache mapping and device control

`ChatsWidgetProvider` (`smali/org/telegram/messenger/h4.smali:866`) and
`ContactsWidgetProvider` (`.../k5.smali:871`) call
`BitmapFactory.decodeFile` on `UserProfilePhoto.photo_small` /
`ChatPhoto.photo_small` (via `FileLoader.getPathToAttach`, `b8.K`). For a
user/chat photo:

```java
photo_small.volume_id = -photo_id;
photo_small.local_id  = 'a';       // 97
```

(`TLRPC.java:32067-32084` for user, `:698-718` for chat). The resulting file
names are:

| Consumer | Directory | File |
|---|---|---|
| widget (`b8.K`, FileLocation branch) | `Telegram Images` | `-<photo_id>_97.jpg` |
| `DialogCell` avatar (`ImageLoader`, cache branch, size=0) | app `cache/` | `-<photo_id>_97.jpg` |

On the test Sony the visible "User" user (`uid <CHAT_ID>`, photo id
`108965549847546626`) had
`/sdcard/Android/data/org.telegram.messenger.beta/cache/-108965549847546626_97.jpg`.
The control test:

1. Backed up that 10,923-byte JPEG.
2. Wrote a valid **red 160×160 lossy WebP** (`pocs/avatar_red.webp`) to the
   same path; `am force-stop` + start (no reboot). The chat list showed a red
   avatar (`evidence/avatar_red_control.png`) — proving the path is decoded by
   `BitmapFactory` at cold start.
   Then wrote a valid **blue 160×160 lossless VP8L WebP**
   (`pocs/avatar_blue_lossless.webp`): the avatar turned blue
   (`evidence/avatar_blue_lossless_control.png`), proving the **VP8L lossless**
   decode path itself, which is the path the CVE PoCs use.
3. Replaced it with `bad.webp`, then `maxdrift.webp`, then `nso.webp`; each
   time `am force-stop` + start. The app stayed alive (pids 17159/17394/17617),
   no app tombstone, avatar rendered blank/grey
   (`evidence/avatar_badwebp_result.png`).
4. Restored the original JPEG.

The positive control makes the negative meaningful: the avatar file is
decoded at startup. The PoC results show **no crash**, but a non-ASan heap
OOB write need not crash; `maxdrift.webp` writes ~12 KB past the allocation
under ASan and is silent on a normal Scudo heap. The static evidence above
proves the vulnerable code is present, so this is **not** a patched-device
negative. It is a **reachable vulnerable platform decoder with no demonstrated
crash/controlled primitive** on this handset. Do not call it ACE.

The Telegram widget providers are registered (`dumpsys appwidget` entries 44
and 45), but no Telegram widget instance was on the launcher, so the
`Telegram Images` widget path was not separately triggered. It uses the same
`BitmapFactory`/libwebp code as the chat-list control; the only difference is
the directory.

The earlier photo-thumbnail/GIF-thumbnail/sticker attempts were inconclusive
for their own paths; they are not needed for the avatar verdict. Details and
backup hashes: `lab/local_message_media_ace/device/DEVICE_TEST.md`.

The `tombstone_03` found afterwards is an unrelated ART
`<pre-initialized>` process (pid 8078, uid 10282, `Signal Catcher` SIGSEGV),
not `org.telegram.messenger.beta`; do not attribute it to libwebp.

## 7. Host harnesses and fuzz results

All harnesses are in `lab/local_message_media_ace/`; builds are ASan+UBSan
with `-fsanitize=fuzzer-no-link` coverage where noted. The host is x86_64;
the target is arm64, so these are parser models, not device reproductions.

### 7.1 FFmpeg app-model build

`scripts/build_ffmpeg_local_asan.sh` builds FFmpeg **n8.1.3** with:

* demuxers `mov,gif,ogg,matroska,mp3,aac`;
* decoders `h264,hevc,mpeg4,mjpeg,gif,alac,mp3,aac,flac,libdav1d,libopus,libvpx_vp8,libvpx_vp9`;
* parsers `h264,hevc,mpeg4video,mpegaudio,aac,opus,av1,gif`;
* libvpx 1.17.0, dav1d 1.5.4, libopus 1.6.1 from the pinned sources;
* `--disable-zlib`, `--disable-network`;
* ASan/UBSan + coverage.

`src/ffmpeg_local_fuzzer.c` mirrors `AnimatedFileNative.nCreateDecoder`:
memory AVIO (64 KiB, `usetoc=1`, `AVFMT_FLAG_FAST_SEEK`),
`avformat_open_input("http://localhost/file")`, `find_stream_info`, best
video decoder, 24 frames (or audio-only/demux-only modes). This is closer to
the app than a raw decoder fuzzer.

`build_dem_{mov,matroska,ogg,gif}` and `build_dec_{VP9,OPUS,H264,HEVC,GIF}`
are FFmpeg's own pinned targets, built against the same libraries; they
consume the OSS-Fuzz 2048-byte control-block corpora.

### 7.2 Corpora

* MOV: 22,649 OSS-Fuzz `ffmpeg_dem_MOV_fuzzer` files (416 MB).
* Matroska: 21,351 files (162 MB).
* VP9: 14,916 `ffmpeg_AV_CODEC_ID_VP9_fuzzer` files (217 MB).
* GIF: 1,760 demux + 1,035 decoder files.
* OGG/Opus: real `voice_note.ogg`, `mono.opus`, `stereo.opus`,
  `joinedMono.opus`; 438 extracted raw Opus packets.
* Video: real Telegram H.264/MPEG-4/MJPEG/VP9/Matroska samples in
  `corpus_video/`.
* WebP: public CVE-2023-4863 `bad.webp`/`maxdrift.webp` plus system-image
  seeds.

### 7.3 Results

| Campaign | Binary | Inputs / execs | Coverage | Result |
|---|---|---|---|---|
| MOV demux | `build_dem_mov` | 22,649-corpus; 7,643 exec | 12,386 edges @4096 | **one reproducible 297-byte hang** (`pocs/mov_tfra_hang.bin`, `mov_fix_index`/`mov.c:4460`); no ASan memory error; UBSan `mov.c:2812` float→int |
| Matroska demux | `build_dem_matroska` | 21,351-corpus; **122,584 exec / 601 s** | 64,810 | no ASan memory error; UBSan `demux.c:943`, `libdav1d.c:135` |
| FFmpeg audio/OGG | `build_ffmpeg_local_audio` | raw OGG/Opus/MP4 corpus; **34,028 exec** | ~32k | no ASan memory error; one 225 KB WebM hard-RSS OOM; one timeout |
| VP9 decode | `build_dec_VP9` | 14,916-corpus; **71,520 exec / 601 s** | 16,173 | no ASan memory error |
| GIF decode | `build_dec_GIF` | 1,035-corpus; **26,119 exec / 601 s** | 4,414 | no ASan memory error |
| Opus packet | `build_opus_packet_fuzzer_cov` | 438 seeds; **77,816 exec / 601 s** | 9,154 | no ASan memory error |
| opusfile | `build_opusfile_fuzzer_cov` | 4 OGG/Opus + mutations; **71,006 exec / 601 s** | 9,956 | no ASan memory error |
| MP4/MKV video decode (`build_ffmpeg_local_video`) | real H.264/MPEG-4/MJPEG/VP9 samples | **6,335 exec / 302 s** | 1,075 MB | no ASan memory error |
| WebP | `build_webp_fuzzer` | 3 PoCs | — | ASan heap OOB **known CVE-2023-4863** |

The table uses the second pass where it completed a full 601 s; the first
pass stopped earlier on a single slow unit. The first-pass logs are
`logs/fuzz_*.log`, the full runs `logs/*2.log`; both show no ASan memory
error. The MOV hang is the only reproducible
new failure; it is a DoS, not a memory-corruption primitive. The audio
campaign also hit a **hard-RSS limit** on a 225 KB WebM
(`artifacts/ffmpeg/oom-f2ab8d…`, WebM header): that is decoder allocation
exhaustion, not corruption, and is not an ACE lead.

### 7.4 Interpreting the logs

* `ERROR: AddressSanitizer: heap-buffer-overflow` / `heap-use-after-free` =
  memory corruption; save the artifact and reproduce with `-runs=1`.
* `SUMMARY: UndefinedBehaviorSanitizer` = UB, not necessarily a security bug.
  Known UBSan noise in this pass:
  `libavformat/demux.c:943` signed overflow (Matroska duration),
  `libavformat/mov.c:2812` float→int cast,
  `libavcodec/libdav1d.c:135` left shift of negative. None is a write.
* `ERROR: libFuzzer: timeout` / `hard rss limit` / `out-of-memory` = DoS, not
  ACE. The GIF 16000×16000 canvas bomb from the prior lab is the canonical
  example (1.04 GiB in `avformat_find_stream_info`).
* The MOV artifact `pocs/mov_tfra_hang.bin` (297 B) is a **new reproducible
  demuxer hang**. GDB stack:
  `mov_fix_index()` at `libavformat/mov.c:4460` (repeated
  `av_realloc(frame_duration_buffer, num_discarded_begin * 8)`), called from
  `mov_build_index()` `mov.c:5014` and `mov_read_trak()` `mov.c:5257`;
  `avformat_open_input` never returns. This is an ANR/CPU/memory DoS; there
  is no out-of-bounds write and no controlled primitive. It can be delivered
  as the §2.4 chat-list **thumbnail** (e.g. a new-GIF/round-video last
  message), so it is a cold-start DoS, not just a host fuzzer artifact.
* `SEGV` in `memcpy`/`ReplicateValue` etc. must be checked for a controlled
  write; a NULL deref in `op_get_data` is not ACE.

### 7.5 Opus-specific results

See §5.4. No memory error. The only artifacts are non-reproducing scheduler
timeouts; they are retained but not findings.

---

## 8. Device plan (repeatable)

### 8.1 Facts to record first

```
getprop ro.build.version.security_patch
getprop ro.build.fingerprint
md5sum /data/app/.../lib/arm64/libtmessages.49.so
ls -l /system/lib64/libhwui.so /system/lib64/libheif.so /system/lib64/libpdfium.so
ls -l /apex/com.android.media.swcodec/lib64/{libopus.so,libvpx.so}
strings /apex/com.android.media.swcodec/lib64/libvpx.so | grep 'WebM Project'
```

On the test Sony: patch `2023-07-01`; `libvpx` reports
`v1.16.0-1737-g19a3dbd6c`; `libopus` reports the placeholder
`libopus unknown-fixed`; `libhwui` contains `WEBPVP8L`; no `libwebp.so`.

### 8.2 Avatar first (preferred; proven path)

1. Pick a visible user/chat with a `photo_small`; `UserProfilePhoto.photo_small`
   is `volume_id=-photo_id`, `local_id='a'` (97).
2. Chat-list file: `Android/data/.../cache/-<photo_id>_97.jpg`;
   widget file: `Telegram Images/-<photo_id>_97.jpg`.
3. Replace the file with a valid red/blue WebP control, `am force-stop` +
   start, screenshot to prove the path; then use the PoC WebP.
4. Restore the original file. The exact 2026-11-03 run and hashes are in
   `lab/local_message_media_ace/device/DEVICE_TEST.md` §8.

### 8.2b WebP / photo thumbnail (platform CVE-2023-4863)

1. Back up `cache4.db`, `-wal`, `-shm` and the target image.
2. Use `scripts/tl_photo_paths.py <db>` to list photo messages and the
   derived `Telegram Images/<vol>_<loc>.jpg` paths.
3. Make a photo the last message of a visible dialog:
   `UPDATE dialogs SET last_mid=<mid>, date=<msg.date> WHERE did=<uid>;`
   (the message `uid` is the dialog `did` for user chats).
4. Put `bad.webp` at the path for the **big** size (`type` `m`/`x`/`y`/`w`,
   not the stripped `i`). Use the largest non-stripped size to avoid
   `DownloadController`/stripped-thumb gating.
5. Force-stop, disable Wi-Fi/data, start, stay on the chat list; then open
   the chat and scroll to the photo so `ChatMessageCell` loads the full file.
6. Check `logcat -b crash`, `/data/tombstones`, and the fault library. A
   tombstone in `libhwui.so` with `BuildHuffmanTable`/`ReplicateValue` proves
   the platform bug; a clean app means either the file was not decoded or
   Sony backported the fix.
7. Restore DB/WAL/image; re-enable network; verify pid.

Do **not** use a weaponised heap groom on a daily driver; this is an app-only
crash test.

### 8.3 FFmpeg (video sticker / GIF / video)

1. Pick a local message with a cached video sticker/GIF/video, or create one.
2. Compute the path from the document:
   `Telegram Documents/<dc>_<id><ext>` for stickers/animated GIF,
   `Telegram Video/<dc>_<id>.mp4` for videos; use
   `scripts/tl_document_paths.py`.
3. Replace the file with a host-fuzzer artifact (or a benign malformed file
   first) and open the chat. A malformed file that makes
   `gifvideo.cpp` log `can't open source`/`failed to find codec` proves the
   path without a crash.
4. For a crash, use only an artifact that reproduces under ASan with a
   **write** (not OOM/timeout). Check the tombstone is in
   `libtmessages.49.so` and the fault is in `libavformat`/`libavcodec`/
   `libvpx`/`dav1d`, not a Java OOM.
5. Restore the file.

### 8.3a `AnimatedFileNative` from the **chat list** (cold start)

This is the §2.4 path. It does **not** need opening the chat.

1. Find a last-message **new GIF** (`video/mp4` + `attributeAnimated`) or
   **round video** (`attributeVideo.round_message=true`). `MessageObject`
   predicates are in §2.2.
2. Use `scripts/tl_document_paths.py <db>` to get the document id and thumb
   type. For a document thumb the path is
   `cache/-<document_id>_<1000+typechar>.jpg` (MEDIA_DIR_CACHE).
3. Replace that thumb file with a crafted WebM/GIF/MOV (the extension is
   ignored by FFmpeg) and make the message the **last message** of a visible
   dialog: `UPDATE dialogs SET last_mid=<mid>, date=<msg.date> WHERE did=<uid>`.
4. Cold start with network off (to prevent a server refresh of `dialogs`);
   `DialogCell` -> `ImageLoader` -> `AnimatedFileDrawable` ->
   `AnimatedFileNative.nCreateDecoder` should parse the thumb. Confirm with
   `logcat` (`gifvideo.cpp` errors / FFmpeg log lines) before using a crash
   artifact.
5. For a DoS check, use `pocs/mov_tfra_hang.bin`: it hangs `mov_fix_index`
   in `dem_mov` (297 bytes, reproducible). It should produce an ANR/CPU spin
   in the app's decode thread, not a tombstone. This is **not** an ACE test.
6. Restore the thumb and DB.

Ordinary videos and video stickers are not in `DialogCell.updateMessageThumbs()`;
do not expect a cold-start FFmpeg decode for them. TGS last-message stickers
are likewise not drawn by `DialogCell`; only custom-emoji spans in text reach
tlottie at cold start.

### 8.4 Opus / opusfile (chat open)

1. Find a voice message (`TL_documentAttributeAudio.voice=true`) or create one
   in Saved Messages.
2. Ensure `waveform` is absent/empty (either in the TL blob or by clearing the
   `attributeAudio.waveform` bytes; a zero-length waveform is enough).
3. Place a crafted OGG/Opus at `Telegram Audio/<dc>_<id>.ogg`.
4. Open the chat. `ChatMessageCell.updateWaveform` → `getWaveform` runs
   without pressing play. A crash in `libtmessages` at
   `op_open_file`/`op_read` is the opusfile path; an FFmpeg log line is the
   fallback path.
5. CVE-2022-47021 needs allocation failure, so do not report a normal OGG
   NULL deref as that CVE unless the allocation actually failed.

### 8.5 MediaCodec/system decoders

The received-video path may use `OMX.qcom.video.decoder.vp9` (hardware) or
`c2.android.vp9.decoder` (software, APEX libvpx 1.16.0-1737). The received
voice path uses `c2.android.opus.decoder` (APEX libopus). Force the software
decoder only if testing the APEX copy; the app-bundled libvpx 1.17.0 is the
patched one. Check `media_codecs_vendor.xml`/`media_codecs_google_c2_video.xml`
and `dumpsys media.codec` before attributing a crash to libvpx/opus.

---

## 9. What would change the verdict

1. A **write** ASan/UBSan artifact in the MOV/Matroska/GIF/OGG/VP9/Opus
   campaigns, reproducible with `-runs=1`, with a controlled offset/size.
2. A device tombstone or controlled heap effect in `libhwui.so` from the
   avatar/full-photo PoC. The vulnerable code and decode path are already
   proven; what is missing is a crash/controlled primitive (heap grooming on
   Scudo), not reachability.
3. A new opusfile/opus bug that is not the OOM NULL deref.
4. A parser path not in this inventory that consumes a local file with a
   memory-unsafe native decoder (e.g. a new Telegram media type).

Until one of those exists, the honest verdict is **no local-message-media ACE
in the app-bundled parsers at 72799**.

### 9.1 Limits of this pass

* The host is x86_64; the app is arm64. ASan/coverage results are parser
  models, not an arm64 reproduction.
* Fuzz campaigns were short and several stopped on one slow unit
  (`-timeout`), so the exec counts in §7.3 are not long-run coverage. A
  negative result means "no crash in these campaigns", not "bug-free".
* The `AnimatedFileNative` chat-list path (§2.4) is derived from the 13.1.1
  source and the 72799 smali call graph; it was not demonstrated on the test
  phone (Attempt B in `device/DEVICE_TEST.md`: first try invalidated by a
  DB/WAL copy race, second try inconclusive because the row/thumb was not
  confirmed drawn).
* System libwebp is now identified from the `libhwui` code itself, not just
  the patch level: IDA shows the pre-fix fixed-allocation `ReadHuffmanCodes` block
  and the 4-argument `VP8LBuildHuffmanTable` (no segment allocator). The
  remaining uncertainty is only whether the PoC reaches the vulnerable write
  and whether it can be turned into a controlled primitive on Scudo; the
  avatar decode path is proven by the red-WebP control.
* `libopus` reports `unknown-fixed`; the 1.6.1 pin comes from the submodule
  commit `22244de…`, not from the binary.
* The exact 72799 prebuilt FFmpeg flags are inferred from the public
  `build_ffmpeg.sh` plus the binary registry. The registry (6 demuxers /
  14 decoders / 4 BSFs) is authoritative for what is callable; minor flags
  could differ.
* `Prisma`, `libpdfium`, WebView/Chromium and the Wallet/TON parser were not
  fuzzed; they are outside the media scope and listed only as adjacent
  surfaces.

---

## 10. Artifacts

```
lab/local_message_media_ace/
  src/ffmpeg_local_fuzzer.c        app-model demux+decode target
  src/opusfile_fuzzer.c            opusfile v0.12 target
  src/opus_packet_fuzzer.c         libopus 1.6.1 packet target
  src/webp_fuzzer.c                system libwebp 1.2.4 target
  src/webp_decode.c                1.2.4/1.3.2 whole/inc decode control
  build_webp_decode_{1.2.4,1.3.2}  patched/unpatched host controls
  scripts/build_ffmpeg_local_asan.sh
  scripts/build_webp_controls.sh
  scripts/pkgconfig/{vpx,opus,dav1d}.pc
  scripts/tl_photo_paths.py        TL photo → cache path mapper
  scripts/tl_document_paths.py     TL document → file/thumb path mapper
  ffmpeg_cve_matrix.tsv            CVE/component/fix/reachability matrix
  pocs/                            MOV hang, GIF canvas bomb, TGS DoS aids
  corpus/, corpus_video/, corpus_opuspacket/
  webp_poc/{bad,maxdrift,nso}.webp
  pocs/avatar_red.webp            benign lossy WebP avatar control
  pocs/avatar_blue_lossless.webp  benign lossless VP8L avatar control
  logs/                            build, campaign, replay logs
  artifacts/                       timeouts/known WebP crashes
  device/DEVICE_TEST.md             device attempts + avatar CVE test + restore checklist
  device/backup_20261102/          pre-test DB + original image backup
  evidence/                        device screenshots, libhwui.so, IDA patch excerpt,
                                   unrelated tombstone
```

Related prior artifacts: `lab/decoder_fuzz/` (TGS UAF model, GIF canvas bomb,
VP9/WebM corpora), `lab/sony_webp_chain/` (libwebp ASan/CVE work),
`notes/db_native_parsers.md`, `notes/ida_media_parsers_72799.md`,
`notes/decoder_fuzz.md`.

---

## 11. Bottom line for the main report

* Add the **local-message media surface** as covered: FFmpeg (GIF, WebM/VP9,
  MOV/H.264/HEVC/MPEG-4/MJPEG/AV1), opusfile v0.12/libopus 1.6.1 (voice
  waveform at chat open), tlottie (TGS), and platform BitmapFactory/Skia.
* Replace the earlier “FFmpeg 8.1.3 may be affected by 9.0 CVEs” line with
  §4: the components are absent or the fixes are already in 8.1.3.
* Do **not** promote CVE-2022-47021 to an ACE finding; it is an OOM NULL
  deref.
* The only ACE-class candidate remains **platform CVE-2023-4863**. Sony
  `/system/lib64/libhwui.so` is confirmed pre-fix 1.2.4 (IDA), and the avatar
  path is confirmed decoded at cold start (red-WebP control). The public PoCs
  did not crash the handset; no controlled primitive/ACE was demonstrated.
  Do not report a device RCE from this test.

---

## 12. Addendum 2026-11-03 — MOV/AV1 cold-start deep fuzz

`notes/dav1d_coldstart_fuzz.md` and `lab/dav1d_coldstart_fuzz/` close the
MOV/AV1/H.264/HEVC **decode** gap left in §7 (the earlier MOV campaign was
demux-only, and `lab/libvpx_deep` fuzzed WebM/VP9). The new lab links FFmpeg
n8.1.3 against dav1d 1.5.4 with ASan+UBSan+coverage and runs the exact
`AnimatedFileNative` order (`avformat_open_input` → `find_stream_info` →
`av_find_best_stream(VIDEO)` → `avcodec_open2` → send/receive), both the
cold-start direct-file branch (`nCreateDecoder` with `stream == NULL`) and
the 64 KiB `usetoc=1`/`FAST_SEEK` stream branch.

One correction to §2.4: an `image/gif` document is **not** a chat-list
cold-start trigger. `isNewGif()` requires `mime_type = "video/mp4"` plus
`TL_documentAttributeAnimated` plus `TL_documentAttributeVideo(w,h<=1280)`
(or a round video). `image/gif` only reaches `AnimatedFileNative` on chat
open. What is decoded at cold start is the document's **thumbnail cache
file** `-<document_id>_<1000+type>.jpg` under
`/storage/emulated/0/Android/data/org.telegram.messenger.beta/cache/`, and
FFmpeg probes it by content, so the bytes can be an MP4/MOV/Matroska
container regardless of the `.jpg` name.

Result (details in the new note): **1,080,418 executions** in total, including
a 2-hour `-fork=4` AV1 run (**501,482** execs, 94,380 edges) and a parallel
2-hour container-decided run (**158,026** execs, 124,915 edges), with **0
ASan/UBSan memory reports and 0 crashes**. The only artifacts are 4 OOM saves
(2 replay in 1–2 ms, 2 are Matroska/AV1 frame-size DoS cases); DoS is not
ACE. A harness default (`FORCE_CODEC_ID 0`) had zeroed codec ids in the first
container-decided campaign (demux/parser only); it is fixed, and
`fuzz_anim_file` now decodes H.264/HEVC/dav1d (verified). The device trace
**refuted** the chat-list cold-start premise above: the thumb file is opened,
but the cell uses BitmapFactory; an audio-only MP4 thumb produced no
`tmessages_native` log and an AV1 MP4 thumb produced no image, while a GIF
thumb rendered. The 297-byte `mov_fix_index` hang is therefore not a
cold-start DoS via the dialog cell; the viable `AnimatedFileNative` trigger is
chat open/autoplay (document media file, not the thumb).
