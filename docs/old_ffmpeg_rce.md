# FFmpeg in Telegram 72799 — "old FFmpeg" premise disproved; reachable surface is FFmpeg 8.1.3 (host-only assessment)

Status: **negative result for the proposed thesis, with positive identification of the real
FFmpeg**. Host-only; no device was touched. Supersedes the WebP/Skia question (dropped by
decision: the Sony decoder is treated as patched). Historical WebP lab artifacts remain in
`lab/sony_webp_chain/` and are not part of this assessment.

Target under test: `/tmp/opencode/tg49_apk.so`, md5 `2c0caa68a07fc26f79d13519af6c3526`,
which is byte-identical to `lib/arm64-v8a/libtmessages.49.so` inside
`/tmp/opencode/base72799.apk` (md5 `04317a9fae026fb41b1c741e8946b77e`). IDA database
`/tmp/opencode/tg49_72799.so.i64` holds the same input (md5/size verified).

---

## 1. Headline findings

1. **There is no old FFmpeg in this APK.** `libtmessages.49.so` contains exactly one
   FFmpeg: **FFmpeg 8.1.3**, libavformat **62.12.103**, libavcodec **62.28.103**,
   statically linked. The only version strings in the library are
   `Lavf62.12.103` and `Lavc62.28.103`; those macros match the local FFmpeg 8.1.3
   source exactly (`LIBAVFORMAT_VERSION_MINOR 12 / MICRO 103`,
   `LIBAVCODEC_VERSION_MINOR 28 / MICRO 103`). The same two strings appear in the
   armv7 artifact. No `Lavf57.x.y`, no `Lavc57.x.y`, no `Lavu55..60.x.y` exist
   anywhere in either library.

2. **`Lavf57.%d.%d` is not a version marker.** It is a *format string inside FFmpeg
   8.1.3's own Matroska demuxer*: `libavformat/matroskadec.c:2210`,
   `mkv_field_order()` parses a file's `muxingapp` tag to work around a bug of the
   old 57.x Matroska muxer (`bttb = (minor >= 36 && minor <= 51 && micro >= 100)`).
   The IDA xref lands in the Matroska demuxer code (`sub_1119048`, which is
   `mkv_field_order`). `Lavc%d.%d.%d` is likewise `libavcodec/mpeg4videodec.c`'s
   `Lavc` metadata parser. Both are parser inputs, not build identification.

3. **Two FFmpeg surfaces are wired up**, not one:
   (a) Telegram's own stories audio-waveform loader (`avformat` + audio decode on a
   local path, editor-side, proven), and (b) the Media3 FFmpeg decoders, whose JNI
   is **registered at `JNI_OnLoad`** (`sub_755ABC`: `FindClass
   androidx/media3/decoder/ffmpeg/FfmpegAudioDecoder` → `RegisterNatives(…, 6)`;
   same for `FfmpegLibrary`; the six `ExperimentalFfmpegVideoDecoder_*` entry
   points are exported). So the Media3 FFmpeg audio/video decoders *can* be used
   by the player — whether the app actually selects them is the remaining
   question (§4). This corrects an earlier reading that the missing
   `libffmpegJNI.so` made them unusable.

4. **No known CVE applies to FFmpeg 8.1.3 in that path.** 8.1.3 (released
   2026-09-21) is the current 8.1-branch release; the CVEs fixed by it include
   CVE-2026-8461 (MagicYUV heap OOB write, CVSS 8.8), CVE-2026-30999,
   CVE-2025-12343, CVE-2025-67306, CVE-2025-69693 and CVE-2026-30754. The
   post-8.1.3 CVEs on ffmpeg.org/security.html are in RSCC, RASC, LCL/ZLIB, NVDEC,
   RTP, HLS and swscale — none of them is exercised by `avformat_open_input()` on a
   local audio file plus an audio decoder. **There is no concrete CVE + PoC to
   build for the reachable path; consequently there is no crash, and certainly no
   RCE claim.**

---

## 2. Version identification (measured)

Evidence file: `lab/old_ffmpeg_rce/logs/ffmpeg_version_evidence.txt`.

| Probe | Result |
|---|---|
| `strings libtmessages.49.so \| grep -E 'Lav[cfu][0-9]'` | `Lavc62.28.103`, `Lavf62.12.103`, `Lavf57.%d.%d` only |
| armv7 `libtmessages_armv7.so` | identical three strings |
| `Lavc57.`` / `Lavu55..60.`` | 0 occurrences |
| local `ffmpeg-8.1.3/libavformat/version.h` | minor 12, micro 103 |
| local `ffmpeg-8.1.3/libavcodec/version.h` | minor 28, micro 103 |
| `ffmpeg-8.1.3/Changelog` | `version 8.1.3:` … (matches the string set) |
| `matroska,webm` in .so | exactly 1 data instance (one libavformat demuxer registry) |
| `mov,mp4,m4a,3gp,3g2,mj2` | 2 instances = demuxer `name` + `extensions` of the same 8.x mov demuxer |

Cross-check with sources: a string-literal diff of FFmpeg 3.4.13 vs 8.1.3 produced
5,467 "3.4-only" literals; only 20 of them occur in the library, and every one that
was checked by hand exists in **8.1.3** under a different extraction path
(`3x3 displaymatrix` → `libavutil/side_data.c`; `mp2,mp3,m2a,mpa` →
`libavformat/mp3dec.c`; `Unsupported DTS audio channel layout` →
`libavformat/mov.c`; `Mixing of superframe syntax and naked VP9 frames not
supported` → `libavcodec/bsf/vp9_superframe.c`; …). The reverse direction is
decisive: 266 FFmpeg-8-only literals (`AAC USAC …`, `AVIAMF…`, `AES-128 IV for
Audible AAXC files`, …) are present. There is one FFmpeg and it is 8.x.

Build shape (from strings): full-ish lavf/lavc with mov/mp4/m4a/3gp, matroska/webm,
ogg, mp3, aac, flac, wav; decoders h264, hevc, av1, vp9, mpeg4, mjpeg, aac, mp3,
opus, vorbis, flac, alac; BSF set. This matches a normal Media3 + Telegram build,
not a minimal waveform-only build.

---

## 3. What the JNI actually calls (the proven path)

`Java_org_telegram_ui_Stories_recorder_FfmpegAudioWaveformLoader_init` at
**0x16f1c88** (exported; symbol present in `.dynsym`). Decompiled call graph:

```
0x16f1ce0  avformat_alloc_context
0x16f1cfc  avformat_open_input(&ctx, path, NULL, NULL)      ; attacker-sized input file
0x16f1d84  avformat_find_stream_info
0x16f1da8  av_find_best_stream(AVMEDIA_TYPE_AUDIO)
0x16f1dbc  avcodec_alloc_context3
0x16f1dd8  avcodec_parameters_to_context
0x16f1df4  avcodec_open2
0x16f1ef0  avcodec_send_packet
0x16f1f18  avcodec_receive_frame
```

Error path logs `avformat_open_input error %s` to `tmessages_native`. The function
then computes peaks and returns a `short[]` to Java (100 buckets).

Java side (dex, classes3.dex):

* `org.telegram.ui.Stories.recorder.FfmpegAudioWaveformLoader` — methods
  `init(String,int)` (mid 38226), `<init>(String,int,k20)`, `receiveChunk(short[],int)`,
  `destroy()`, plus synthetic lambdas.
* The view that owns it is `Lvh/s8;` — constructed at `Lvh/z8;->p()` (`b3452a`:
  `new-instance v0, Lvh/s8;` → `<init>(Lvh/z8, String, int)`), taking the path from
  the field **`Lvh/z8;->O:Ljava/lang/String;`**.
* `Lvh/k4;->q(Lvh/n5;Z)` sets it: `b0712c` compares `z8.O` with
  `Lvh/n5;->y:Ljava/lang/String;` (`TextUtils.equals`), then `b07152`
  `iput-object v6, z8.O` and `b07156` calls `z8.p()` (start waveform).
* `Lvh/z8;->setCollage(...)` builds per-clip waveform objects `Lvh/u8;` from
  `Lvh/n5;->L:Ljava/io/File;` (`b33fda: File.getAbsolutePath()` → `Lvh/u8;->d:Ljava/lang/String;`).
* `Lvh/k4` contains the literal `"vthumb://"` (`b06140`) and story theme keys
  (`themeconfig`, `lastDayTheme`, `lastDarkTheme`) — i.e. the **story recorder /
  video editor**.

So: the FFmpeg demuxer+decoder surface is reached when the *editor* needs a
waveform for a local file (recorded clip, or the music track picked for a story).

## 4. What is NOT reached (and why this matters for delivery)

* **Received voice messages**: `Java_org_telegram_messenger_MediaController_getWaveform`
  (0x16f19a4) does **not** use FFmpeg. Its callees are `sub_17D6F38` /
  `sub_17D6FC8` / `sub_17D8558` and it logs `getWaveform: op_read failed`, i.e. it
  is **libopusfile** (`op_open_file`, `op_pcm_total`, `op_read`). The
  `AudioRecorderNative_nGetWaveform` JNI at 0x16f3bc8 is a thunk to the same
  function.
* **Received photos/videos/audio playback**: goes through MediaPlayer/ExoPlayer and
  platform codecs, not through the waveform loader. Merely opening a chat does not
  invoke `avformat_open_input`.
* **Media3 FFmpeg is present and registered.** `JNI_OnLoad` (0x16efa34) calls
  `sub_755ABC`, which does `FindClass("androidx/media3/decoder/ffmpeg/FfmpegAudioDecoder")`,
  looks up `growOutputBuffer`, then `RegisterNatives(..., 6)`; it then registers
  `androidx/media3/decoder/ffmpeg/FfmpegLibrary` and logs
  `JNI_OnLoad: RegisterNatives failed for …` on error (tag `ffmpeg_jni`). The six
  `Java_androidx_media3_decoder_ffmpeg_ExperimentalFfmpegVideoDecoder_*` entry
  points are exported in `.dynsym`. Therefore the Media3 FFmpeg audio and video
  decoders are **functionally available** in this APK (no `libffmpegJNI.so` needed,
  because the natives are registered from `libtmessages.49.so`).
  What is *not* proven: that the app's renderer factory actually adds
  `FfmpegAudioRenderer` / `ExperimentalFfmpegVideoRenderer`. The dex references the
  classes (`ExperimentalFfmpegVideoRenderer` 2×, `FfmpegAudioRenderer` 3×,
  `DefaultRenderersFactory` 1×) but contains no `setExtensionRendererMode`
  literal — Media3's default is EXTENSION_RENDERER_MODE_OFF, so either the app
  builds its own renderer list or the extension is dormant. This single point
  decides whether received-media playback reaches FFmpeg; it needs a runtime check.

## 5. Delivery model (bot/contact -> editor) — where it stands

The pivot's premise (bot-sent media, no server re-encode, chat/story opened by the
victim, persists across app updates) is correct *in general* for documents/audio:
Telegram re-encodes photos and generates photo thumbnails server-side, but audio
documents and story music files are stored and delivered as uploaded bytes.

For **this** FFmpeg path the delivery has an extra hop that is not yet established:
the file must be opened by the *story/video editor* (`vh/k4`/`vh/z8`), not by the
viewer/player. Candidate route: a received story/message carrying music or audio
whose file is then used as the editor's audio track (e.g. "add to story"/repost
flows), at which point `vh/n5.y` is the downloaded cache path and the loader runs
`avformat_open_input()` on attacker bytes. That route is **plausible but unproven**:
the call sites that were resolved feed the loader from the composer's own objects.
Proving it requires one runtime trace on a device (log the path passed to
`FfmpegAudioWaveformLoader.init`, then open a bot-sent story with music in the
editor). Until then, treat the delivered-media reachability of this FFmpeg as
**unconfirmed**.

## 6. CVE status of 8.1.3 (why there is no PoC to build here)

* 8.1.3 was released **2026-09-21**; it contains 268 commits since 8.1.2, a large
  share of them memory-safety fixes (mov atom bounds, mpegts PES payload bounds,
  oggdec overflow, vorbis/flac, h264_direct, hevc WPP range, av1 uvlc, jpegls/tiff/
  png bounds, …). Full list: `git compare n8.1.2...n8.1.3`.
* CVEs explicitly fixed in 8.1.3 (ffmpeg.org/security.html): **CVE-2026-8461**
  (MagicYUV heap OOB write, "PixelSmash", CVSS 8.8), CVE-2026-30999,
  CVE-2025-12343, CVE-2025-67306, CVE-2025-69693, CVE-2026-30754, CVE-2026-66038
  (LCL/ZLIB disclosure, "through 8.1.2", fix present in the 8.1.3 Changelog).
* CVEs still listed only for master after 8.1.3 (as of 2026-11-02) are in RSCC,
  RASC, NVDEC, RTP/HLS, CAF/AVI/DASH demuxers and swscale — **none** touches the
  proven path (local-file avformat demux of mov/mp3/ogg/flac/wav + audio decode).
  The DepthFirst 21-zero-day batch (June 2026, incl. CVE-2026-39210..39218) was
  fixed before 8.1.3; the mpegts/av1 entries are visible in the 8.1.3 Changelog.
* The "old FFmpeg" CVE families (FFmpeg 3.x: CVE-2023-49501…, CVE-2024-7055,
  CVE-2025-1594, …) are irrelevant: those versions are not in the APK. Chasing them
  in this build was a false lead caused by the `Lavf57.%d.%d` format string.

**Conclusion: no known-vulnerable component is reachable through the proven FFmpeg
path in this APK.** What remains is 0-day risk in FFmpeg 8.1.3's audio demuxers/
decoders or in the (unproven) Media3 video decoder. That is research, not a CVE
chain.

## 7. Exploitability, if a bug were found (honest bounds)

* The process is the app UID, 64-bit, Scudo, MTE off (the app does not declare
  `android:memtagMode`; Android 13 does not enable MTE for apps). No PAC involvement
  in FFmpeg data flows.
* A demuxer/decoder heap overflow in this code would still need: a leak or a
  deterministic same-class neighbor, control of the allocation pattern from a file
  that is only opened by an editor flow, and a way past Scudo's 16-byte chunk header
  + checksum. None of that is demonstrated here.
* **Crash is not RCE.** Even a reproduced SIGSEGV in `wf_harness` would only prove a
  DoS. No crash was produced in this work because no applicable bug was identified.
* Update survival is the opposite of the original hope: because this FFmpeg is
  *bundled in libtmessages.49.so*, it is fixed by **app updates** (8.1.3 is current
  and carries the 2026 fixes). It is not a system-Skia-like "only an OTA can fix it"
  surface. A message/story persists server-side and re-triggers on open, but the
  vulnerable code ships in the APK, so the patch vehicle is the APK.

## 8. Artifacts and reproduction

`lab/old_ffmpeg_rce/`

```
harness/wf_harness.c        exact model of FfmpegAudioWaveformLoader_init():
                            avformat_open_input -> find_stream_info ->
                            av_find_best_stream(AUDIO) -> avcodec_open2 ->
                            send_packet/receive_frame
harness/dex_callsites.py    payload-aware call-site finder (dextool disassembler)
harness/dex_newinstance.py  constructor-site finder
harness/dex_xref.py         raw xref scan (kept for reference)
logs/ffmpeg_version_evidence.txt   identity evidence (§2)
logs/harness_smoke.txt      harness results on wav/mp3/m4a
build/ffmpeg-8.1.3-install  local FFmpeg 8.1.3 static build (demuxers mov/mp3/ogg/
                            flac/wav/matroska/aac, decoders aac/mp3/opus/vorbis/
                            flac/pcm, file protocol, --disable-x86asm)
poc/silence.wav             smoke input
```

Build/run:

```
cd lab/old_ffmpeg_rce
gcc -O1 -g -I build/ffmpeg-8.1.3-install/include -o build/wf_harness \
    harness/wf_harness.c build/ffmpeg-8.1.3-install/lib/libavformat.a \
    build/ffmpeg-8.1.3-install/lib/libavcodec.a \
    build/ffmpeg-8.1.3-install/lib/libswresample.a \
    build/ffmpeg-8.1.3-install/lib/libavutil.a -lm -lpthread -lz
./build/wf_harness <file>
```

Smoke results (logs/harness_smoke.txt):

```
silence.wav  format=wav  decoder=pcm_s16le  8000 Hz  1 ch  16 frames
sound_a.mp3  format=mp3  decoder=mp3float  44100 Hz  2 ch  78 frames
opening.m4a  format=mov,mp4,m4a,3gp,3g2,mj2  decoder=aac  44100 Hz  2 ch  296 frames
```

## 9. What would change this conclusion

1. **Runtime trace on a device**: log the argument of
   `FfmpegAudioWaveformLoader.init` and the callers of `vh/k4.q` / `vh/z8.p` while
   opening a bot-sent story with music; if a downloaded cache path appears, the
   attacker-controlled path is real (still 8.1.3 code, so only 0-day risk).
2. **Confirm/deny Media3 FFmpeg renderer selection** (the JNI registration is
   already proven): find the renderer factory in the obfuscated player code and
   check whether `FfmpegAudioRenderer` / `ExperimentalFfmpegVideoRenderer` are
   instantiated, or trace `FfmpegLibrary.isAvailable()` at runtime. If they are
   selected, received audio/video packets reach lavc 62.28.103 (aac/mp3/opus/
   vorbis/flac/h264/hevc/av1/vp9) during normal playback — a much wider surface
   than the waveform loader, though still current 8.1.3 code.
3. If a specific post-8.1.3 FFmpeg CVE appears in an audio demuxer/decoder, port the
   upstream PoC into `wf_harness` and measure; then, and only then, discuss
   exploitation under Scudo.

## 10. Limitations

* I did not run on the Sony/Pixel (host-only, per instructions); the reachability
  hop in §5 is inferred from static call sites, not observed.
* IDA function names such as `avformat_open_input` are symbols/annotations in the
  provided IDB; the version claim does not rest on them but on the version strings,
  the demuxer behaviour (`mkv_field_order` source match) and the FFmpeg 8.1.3 source
  macros. The Media3 JNI-registration finding (`sub_755ABC`) does rest on the
  decompiled `FindClass`/`RegisterNatives` calls and their log strings, which are
  explicit in the binary.
* No fuzzing was performed: with a current 8.1.3 build and no applicable CVE the
  expected yield is low, and the brief asked for a concrete CVE + PoC over generic
  fuzzing.
