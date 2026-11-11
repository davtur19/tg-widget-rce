# Images / data-URI decoder hunt — widget `<img>` & background path

Date: 2026-11-08. **Host-only** (no device, no Frida, no bot, no network payload
delivery; public-source/CVE research via websearch is used and cited). Scope:
the widget litehtml `<img>` / CSS `background-image` / `data:` URI path and the
image decoders statically linked in `libtmessages.49.so` (Android 72889/72929)
and in iOS `TelegramUIFramework` (13.2 / 36535). SVG, CSS, fonts and Lottie are
out of scope per the task split and were not touched.

Lab: `lab/lib_hunt_images/` (build, harnesses, seeds, logs, corpus).
This note adds rows to the existing memory-bug ledger; it does not modify any
earlier note.

---

## 0. Verdict (honest)

**No unreported memory corruption was found in the widget data-URI image path.**
The task premise — "the data URI is decoded by libjpeg-turbo / libwebp / PNG /
GIF / FFmpeg decoders statically linked in `libtmessages.49.so`" — does **not**
hold for Android. The only data-URI handler in the widget backend is Java
`WidgetSandboxBackend.loadImage(I,[B)[F`, and it calls
`android.graphics.BitmapFactory.decodeByteArray` — the **platform Skia**
decoder, not an app-bundled one. This is proven from the shipped 72889 DEX
(§2.2) and from the 72889/72929 binary (no libwebp/libjpeg/libpng code; the
FFmpeg image decoders are not built, §2.3).

For iOS the widget runtime (`wr`, C++ DOM on QuickJS + twidget litehtml fork)
delegates image decoding to a host callback that yields
`std::optional<wr::DecodedImage>`; the host is the app's image stack and the
generic data-URI decode is ImageIO (`CGImageSourceCreateWithData`), i.e. also a
platform decoder. `libwebp 1.3.2` and `mozjpeg 4.1.4` **are** linked into
`TelegramUIFramework`, but the data-URI path does **not** use the Telegram WebP
binding: the ObjC call-site count for `+[WebP convertFromWebP:]` in the 13.2
binary is **exactly 5**, i.e. the five pre-existing Swift callers
(`FetchCachedRepresentations`, `LottieAnimationCache`, `VideoStickerFrameSource`,
`ReactionImageComponent`, `PhotoResources`) and **no widget caller**; the
`convertToWebP:quality:error:` count is **4**, also exactly the 13.1.1 source
set. Method and caveats in §3.1. So both platforms decode a widget data URI
with a **platform** decoder (Android Skia, iOS ImageIO), and no app-bundled
codec is on the path.

What the campaign did produce:

| id | finding | class | reachable from a widget data URI? | memory corruption? |
|---|---|---|---|---|
| **IMG-01** | Java PNG pre-scan in `WidgetSandboxBackend.loadImage` inflates IDAT chunks with `java.util.zip.Inflater` into an uncapped `ByteArrayOutputStream` | resource exhaustion / OOM inside a JNI callback | **yes** (`data:image/png;base64,…` with a deflate bomb) | **no** (DoS) |
| **IMG-02** | Any Java exception thrown by `loadImage` (e.g. `OutOfMemoryError`, `IllegalArgumentException` from `Bitmap.createBitmap`) returns to native with a pending exception; the native caller was not shown to call `ExceptionCheck` | JNI pending-exception abort | yes (same input class) | **no** (DoS) |
| **IMG-03** | iOS `UIImage+WebP.m` failure path leaks `targetMemory`/`CGContext` and does not pop `UIGraphics` context (no bounds bug; padding loop is dead for `w > 1`) | resource leak | only if the WebP binding is used | **no** |
| **IMG-04** | iOS `MozjpegBinding decompressImage` ignores the `tjDecompress2` return; a failed decode leaves the buffer uninitialised and still builds a `CGImage` | uninitialised read (info) | only on the direct-media path, not data URI | **no** |
| **IMG-05** | Small ASAN fuzz of iOS-pin **libwebp 1.3.2** through the exact `WebPBinding` call geometry: 232,130 execs / 181 s, coverage 1,462 edges, **no ASan report** | — | — | negative |

Platform n-days that a data URI can reach on old devices (CVE-2023-4863-class in
`libhwui`/Skia, and libpng/ImageIO n-days) are **OS-level**, not app-bundled;
the Pixel 9 / Android 17 and iOS 13.2 device patch levels are outside this
host-only pass and are listed in §5 for completeness. The already-reported Sony
`libhwui` 1.2.4 finding is unchanged and is not re-counted here.

---

## 1. Targets and identity

| target | file | size | hash |
|---|---|---|---|
| Android 13.2.1 beta 72889 | `apks/Android_Beta_13.2.1_(72889).apk`, `lib/arm64-v8a/libtmessages.49.so` | 27,069,808 B | sha256 `f12c3cb8b5e0345f51b543887b923001c8a8e04cda5cd38aed513d2d365f5f13` |
| Android 72929 (device update dir) | `lab/qjs_fork_audit/…/updates/72929/lib/libtmessages.49.so` | 27,070,032 B | md5 `f832021b2b3d6312e059602f4ecfdcc9` |
| iOS 13.2 (36535) | `ios_sideload/Telegram_13.2.0_decrypted.ipa` → `Payload/Telegram.app/Frameworks/TelegramUIFramework.framework/TelegramUIFramework` | 122,824,000 B | sha256 `577d3c7e1b1edec3350264f2bb66340933950686d4c1543ac52f75d5c3059f74` |
| iOS 13.1.1 source (reference) | `<HOME>/ailocal/Telegram/iOS` @ `fb0e62ba8` (`release-13.1.1`) | — | — |

The 13.1.1 source tree is used only for build configuration and the
`WebPBinding` / `MozjpegBinding` wrappers; the shipped widget engine (`wr`,
`twlite`) is not in that tree and was analysed from the 13.2 framework binary.

---

## 2. Android: where a data URI actually goes

### 2.1 Native side (libtmessages)

The widget engine is `twidget::WidgetHost` + `twlite::Renderer` (litehtml +
gumbo) + QuickJS sandbox. The renderer hands images to the Java backend through
JNI; the relevant strings in the 72889 lib are:

```
0x2957b2  "loadImage"                 (JNI method name)
0x24a257  "(I[B)[F"                   (loadImage signature: int id, byte[] url -> float[2])
0x2819f2  "(Landroid/graphics/Bitmap;[BF)V"   (filterPixels signature)
imports:  AndroidBitmap_getInfo / AndroidBitmap_lockPixels / AndroidBitmap_unlockPixels
```

`libtmessages.49.so` imports `libjnigraphics.so`; the only pixel access in the
widget engine is `filterPixels` (CSS filter) and the Java canvas path — both out
of this subtask's scope. The `<img>` draw itself is executed by Java
(`Canvas.drawBitmap`), so no native pixel consumer sits between the decoder and
the screen.

### 2.2 Java side: `WidgetSandboxBackend.loadImage` (the only data-URI handler)

Disassembly of `Lorg/telegram/utils/twidget/WidgetSandboxBackend;->loadImage(I [B)[F`
(classes4.dex, log `lab/lib_hunt_images/logs/loadImage_disasm.txt`) shows:

1. `new String(bytes, UTF-8)`, `indexOf(',')`, `startsWith("data:")`.
2. If `String.length() > 0x200000` (2 MiB) → return `null`.
3. Media type = `substring(5, comma)`; if it contains `"svg"` → return `null`.
4. `";base64"` → `android.util.Base64.decode(payload, 0)`; otherwise
   `URLDecoder.decode(payload,"UTF-8").getBytes(ISO_8859_1)`.
5. `BitmapFactory.Options{inJustDecodeBounds=true}` +
   `BitmapFactory.decodeByteArray(data,0,len,opts)`.
6. Reject if `outWidth<=0 || outHeight<=0 || (long)w*h > 0x400000`
   (4,194,304 px) or `imageBytes + w*h*4 > 0x2000000` (32 MiB budget).
7. **PNG special case** (when the signature matches and the IHDR bit
   depth/colour type selects it): walk IHDR/IDAT/IEND, verify chunk bounds and
   CRC32, inflate IDAT with `java.util.zip.Inflater`, scan the filter byte of
   each row (`>4` ⇒ invalid), then rebuild a PNG (`Deflater` + CRC) with an
   adjusted IHDR, decode it with `BitmapFactory.decodeByteArray`, and draw it
   onto `Bitmap.createBitmap(ihdr_w, ihdr_h, ARGB_8888)`.
8. `images.put(id, bitmap)`, `imageBytes += bitmap.getAllocationByteCount()`,
   return `float[]{bitmap.getWidth(), bitmap.getHeight()}`.

**There is no call to any Telegram-native decoder.** The full method contains
exactly three `BitmapFactory.decodeByteArray` invocations and no other decode
entry point. A scan of **all four** 72889 DEX files for the exact constant
`"data:"` finds it only in `WidgetSandboxBackend`; the only other data-URI
literals in the app are `data:application/x-mpegurl;base64,` (HLS, in `Lwf/d;`
and `Lorg/telegram/ui/Components/n51;`) and a `";base64"` helper in `Lj2/f;`.
`Utilities.loadWebpImage` does not exist in this lib (the only
`Java_org_telegram_messenger_Utilities_*` exports are `blurBitmap`,
`stackBlurBitmap`, `averageBitmapColor`, `copyBitmaps`,
`nLibyuvARGBSaleBitmap`, `setupNativeCrashesListener`), and `ImageLoader` (the
Java class) is not referenced by any `twidget` class (`xref_twidget.py` over
classes4.dex: the only image-related call in the package is the
`BitmapFactory` found above).

Consequence: `<img src="data:image/webp;base64,…">`, `data:image/png`,
`data:image/jpeg`, `data:image/gif` are all decoded by the **platform**
decoder of the device (Skia on Android), in the app process but in system
code.

### 2.3 The app-bundled decoders are not built (binary proof)

The 13.1.1 `TMessagesProj/jni/prebuild/build_ffmpeg.sh` configures FFmpeg with
`--disable-everything` and only:

* decoders: `h264, hevc, mpeg4, mjpeg, gif, alac, libopus, mp3, aac, flac, libdav1d, libvpx_vp9` (+`libvpx_vp8`, `--disable-zlib`)
* demuxers: `mov, gif, ogg, matroska, mp3, aac`
* parsers: `h264, hevc, mpeg4video, mpegaudio, aac, opus, av1, gif`

The same enabled set is confirmed **in the 72889 and 72929 binaries** (both
libs show identical results):

| probe | 72889 | meaning |
|---|---|---|
| `"mjpeg_decode_dc: bad vlc"` (mjpegdec.c) | present | FFmpeg MJPEG decoder **compiled** |
| `"gif decoder"` (gifdec.c `.class_name`) | present | FFmpeg GIF decoder **compiled** |
| `"GIF demuxer"` | present | GIF demuxer compiled |
| `"Multiple IHDR"`, `"Invalid image size"`, `"Invalid compression method"`, `"IHDR after IDAT"`, `"pHYs after IDAT"` (pngdec.c) | **absent** | FFmpeg PNG decoder **not compiled** |
| `"WebP"`, `"VP8L"`, `"RIFF"`, `"VP8X"`, `"entropy coded image"` (webp.c) | **absent** | FFmpeg WebP decoder **not compiled** |
| libwebp VP8L code-length table `11 12 00 01 02 03 04 05 10 06 07 08 09 0a 0b 0c 0d 0e 0f` | **absent** | no libwebp in the app |
| libjpeg-turbo / libpng symbol strings (`tjDecompress`, `jpeg_read_header`, `png_read_row`) | absent | not linked |
| `"Independent JPEG Group"`, `"JPEG parameter"`, `"Corrupt JPEG"`, `"libpng"`, `"png_"` | absent | no libjpeg / libpng in the app |
| `"IHDR"` (literal chunk type) | absent | no PNG chunk parser in native code (the Java scanner compares the 8 signature bytes via `q.a[8]`, not the `IHDR` literal) |

(The strings `jpeg2000`, `jpegxl`, `jpegls`, `JPEGInterchangeFormat`,
`image/png`, `image/jpeg`, `image/webp`, `image/svg+xml` that motivated the
original hypothesis are **codec-descriptor / JS-token / litehtml string-pool**
entries. `codec_desc.c` lists every codec name and MIME type regardless of
`CONFIG_*`; `mjpegdec.c` even contains the literal
`"JPEG-LS support not enabled."` because the MJPEG decoder is built without
JPEG-LS. None of those strings implies a decoder is compiled.)

The FFmpeg demuxer set is also the only route into `mjpeg`/`gif`; the
`image2`/`image2pipe` demuxers are not registered (`"image2 demuxer"` absent;
the bare `image2` literal lives in `libavformat/demux.c`/`format.c`, which are
always compiled). The widget engine never calls avformat/avcodec at all
(`twidget_native_audit.md` §7: no file I/O, no `open`, no `dlopen` in the
twidget range).

---

## 3. iOS: where a data URI actually goes

The iOS 13.2 framework contains the same widget engine, but in a C++ form:

```
_TtC22MessageWidgetRendering18WidgetTreeRenderer          (Swift render driver)
"WidgetRuntime: a C++ DOM on QuickJS (quickjs-ng fork), laid out by
 twidget's litehtml fork, drawn by CoreGraphics"
N2wr10RenderTreeE / N2wr10RenderHostE / N2wr3ios18CoreTextRenderHostE
N2wr16HTMLImageElementE ; ZN2wr8imageSourceChangedEP9JSContextRNS_16HTMLImageElementE...
NSt3__110__function6__funcIZN2wr10RenderTreeC1EP9JSContextRNS2_10RenderHostENS2_13RenderOptionsEE3$_0FNS_8optionalINS2_12DecodedImageEEEyEEE
N2wr3ios12IOSHostImageE
ZN2wr3ios12_GLOBAL__N_19paintWithERKNS2_9LayerTreeEP9CGContextPKNS2_9PaintItemEiP13LHEffectStoreE3$_0FP7CGImagePKv6CGRectddbE
imports: _CGImageSourceCreateWithData, _CGImageSourceCreateImageAtIndex, …
```

Interpretation (from the RTTI/vtable names, no decompilation needed):

* `wr::RenderTree(JSContext*, wr::RenderHost&, wr::RenderOptions)` is constructed
  with a `std::function<std::optional<wr::DecodedImage>(uint64_t)>` — i.e. the
  DOM/render tree **asks the host to decode an image handle**; it does not
  decode bytes itself.
* `wr::HTMLImageElement` / `wr::imageSourceChanged` perform the async image
  load; the result is an `IOSHostImage` and the layer painter obtains a
  `CGImage*` (`paintWith` lambda).
* The framework imports ImageIO (`CGImageSourceCreateWithData` etc.), which is
  the generic image decoder for data / file bytes on iOS.

The app **does** link two app-bundled decoders into this framework:

| library | version (pin) | evidence |
|---|---|---|
| libwebp | **1.3.2**, commit `c1ffd9ac7593894c40a1de99d03f0b7af8af2577` | `iOS/third-party/webp/BUILD` comment; `configure.ac` `AC_INIT([libwebp],[1.3.2])`; VP8L code-length table present in the framework at file offset `0x5905cca` (2 occurrences) |
| mozjpeg | **4.1.4** (build 10000), libjpeg-turbo 2.1.5.1/2.1.6 lineage, `WITH_JPEG8=1`, `PNG_SUPPORTED=FALSE` | string `"mozjpeg version 4.1.4 (build 10000)"`; `iOS/third-party/mozjpeg/change.log` "2.1.6 relative to 2.1.5.1"; `build-mozjpeg-bazel.sh` |

Their wrappers:

* `submodules/WebPBinding/Sources/UIImage+WebP.m` — `+[WebP convertFromWebP:]`
  does `WebPGetInfo` → `malloc(((4w+31)&~31) * h)` → `WebPDecodeBGRAInto`.
* `submodules/MozjpegBinding/Sources/MozjpegBinding.mm` — `decompressImage:`
  does `tjDecompressHeader2` → `malloc((3w+31)&~31 * h)` → `tjDecompress2(...,
  TJPF_RGB, TJFLAG_FASTDCT|FASTUPSAMPLE)` (decode), and `compressImage:`.

**Reachability of libwebp from a widget data URI: resolved negative (high
confidence).** The framework is stripped (`llvm-nm --defined-only` → 0
symbols), but the ObjC dispatch surface is fully recoverable, so the call graph
was measured instead of decompiled (§3.1). Result: `+[WebP convertFromWebP:]`
has **exactly 5 call sites** in the 13.2 binary (0x4527bc, 0x3038490,
0x3272b70, 0x34dddfc, 0x34fe6ac) and `convertToWebP:quality:error:` has **4**
(0x41c208, 0x2009648, 0x221d734, 0x221d870). The 13.1.1 UI source contains
exactly 5 `WebP.convert(fromWebP:)` call sites (`FetchCachedRepresentations:295`,
`LottieAnimationCache:65`, `VideoStickerFrameSource:326`,
`ReactionImageComponent:169`, `PhotoResources:2532`) and 4
`WebP.convert(toWebP:)` sites. The counts are unchanged in 13.2, so the new
widget runtime added **no** WebP-binding caller; a widget `data:image/webp`
therefore goes to the generic host/ImageIO path, like PNG/JPEG/GIF.

Caveat: this is call-graph counting, not symbol attribution; it cannot rule out
a refactor that removed one old caller and added a widget one. Given that all
five old call sites are photo-cache/sticker code that still exists in 13.2,
this is unlikely. The decisive confirmation would be a device experiment: a
WebP variant that only libwebp (not ImageIO) accepts should **not** render in a
widget, while the same file renders as a photo/sticker (which uses
`WebP.convert`). That is a 1-file test for the next iPhone run; no device was
touched here.

### 3.1 How the iOS call-site count was obtained (and why it is reliable)

The framework is a stripped arm64 Mach-O with chained fixups
(`LC_DYLD_CHAINED_FIXUPS`), so pointers are 36-bit rebase offsets, not plain
addresses. Procedure (scripts in `lab/lib_hunt_images/ios_scan_*.py`):

1. Parse `LC_SEGMENT_64`; take `__TEXT,__text` (0x24000, 0x5546bb0),
   `__TEXT,__objc_methname`, `__objc_selrefs`, `__objc_stubs`.
2. Look up the exact selector string in `__objc_methname` and find the single
   `__objc_selrefs` entry whose chained pointer (masked to 36 bits) targets it.
3. Scan `__objc_stubs` for the `adrp x1, page; ldr x1, [x1, #off]` pair whose
   effective address is that selref: that stub is the `objc_msgSend$selector`
   thunk.
4. Vector-scan `__text` with NumPy for `bl` (top 6 bits `100101`) and compute
   each target from its PC (`pc + sign_extend(imm26)*4`); count the branches to
   the stub.

Validation: the same method on a control selector (`initWithFrame:`-prefixed
long selector) finds its one real load, and the two WebP API counts match the
13.1.1 source exactly (5/4), which a broken scanner would not reproduce.

Distribution of decode duties that *is* established:

| input | Android 72889/72929 | iOS 13.2/36535 (established) |
|---|---|---|
| `data:image/png` | Java PNG pre-scan + BitmapFactory (Skia) | ImageIO (via host callback; wr returns DecodedImage) |
| `data:image/jpeg` | BitmapFactory (Skia) | ImageIO |
| `data:image/gif` | BitmapFactory (Skia) | ImageIO |
| `data:image/webp` | BitmapFactory (Skia, platform libwebp) | ImageIO (iOS ≥14 supports WebP); Telegram WebP binding excluded by the call-site count in §3.1 |
| `data:image/svg+xml` | Java rejects (`contains("svg")` → null) | not investigated (out of scope; the litehtml MIME list does name `image/svg+xml`) |
| `tw-canvas:` | Java canvas Bitmap (no decoder) | IOSCanvasBitmap (no decoder) |

---

## 4. Decoder inventory and version map (what a data URI can reach)

| platform | decoder that processes the bytes | version | app-bundled? |
|---|---|---|---|
| Android 72889/72929 | Skia codecs via `BitmapFactory` | device platform (Pixel 9 / Android 17: current; older devices: patch-level dependent) | **no** |
| Android (media, not widget) | FFmpeg n8.1.3: mjpeg, gif (+ mov/gif/ogg/matroska/mp3/aac demuxers) | n8.1.3 | yes, but not wired to widget images |
| iOS 13.2 | ImageIO (`CGImageSourceCreateWithData`) | OS (iOS 13.2) | no |
| iOS 13.2 (explicit paths only) | libwebp 1.3.2 / mozjpeg 4.1.4 | as above | yes |

---

## 5. CVE / advisory survey mapped to this scope

Method: CVE/NVD/advisory search plus the repo's own CVE notes
(`notes/old_ffmpeg_rce.md`, `notes/local_message_media_ace.md`,
`notes/universal_scudo_ladder_20261107.md`), then a reachability filter against
§2–§4.

### libwebp

| item | affects | in the app? | reachable from widget data URI? |
|---|---|---|---|
| **CVE-2023-4863** (BuildHuffmanTable heap OOB write, lossless) | libwebp < 1.3.2 | iOS: **1.3.2 → fixed**; Android: platform Skia/libwebp (patched on Android 17; Sony `libhwui` 1.2.4 was already reported in `local_message_media_ace.md` §8.2b) | platform only on Android; iOS fixed; the iOS binding is **not** on the widget data-URI path (§3.1) |
| post-1.3.2 hardening commits (2025–2026 main): `2d16e4a` ptrdiff overflow (YUVA/crop), `5755839` cap Huffman RAM (DoS), `5c8c69e` error/bounds paths, `5f22193` stride validation (mostly encoder), `a53957a` paletted-alpha window w/ crop_top, `efaaa24` scratch-row cast (no-op), `21c53c1` group-mapping regression (introduced 2026), `315e817` CheckNonOpaque, `0ff181e` truncated Huffman streams, `36f3445` Huffman alloc | main-branch fixes after the 1.3.2/1.6.0 line | iOS ships **1.3.2** (all missing) | none shown to affect `WebPDecodeBGRAInto` on a still RGBA image: `2d16e4a` is YUVA/crop only, `a53957a` needs `crop_top≠0`, `5f22193`/`5c8c69e` are encoder/incremental/quant-levels paths, `21c53c1` is a regression newer than 1.3.2. Only the DoS items (`5755839`, `0ff181e`) plausibly apply to 1.3.2 |

### libjpeg-turbo / mozjpeg

| item | affects | in the app? | reachable? |
|---|---|---|---|
| CVE-2023-2804 merged-upsample OOB (12-bit lossless) | libjpeg-turbo 2.1.5/3.0.0 fixed | mozjpeg 4.1.4 is an **8-bit** build (`WITH_JPEG8=1`), CVE requires 12-bit precision | **no** |
| CVE-2026-75466 PNG loader div-by-zero (DoS) | libjpeg-turbo 3.2.0 `tj3LoadImage*` | app builds `PNG_SUPPORTED=FALSE` | no |
| CVE-2020-35538 NULL deref `jcopy_sample_rows` | 2.0.5+ lineage, fixed later | status in the 2.1.5.1-based mozjpeg not verified; NULL-deref DoS only, not on the `tjDecompress2` default path | low |
| CVE-2026-112403 Pillow JPEG draft overflow | Pillow's `draft()` + 8-bit lossless SOF3 | not Pillow | no |

### libpng

| item | note |
|---|---|
| CVE-2025-64505/64506/64507/64508 (1.6.51 fixes: `png_do_quantize` OOB read etc.) | no libpng in the app; Android = Skia's own PNG (platform), iOS = ImageIO |
| CVE-2026-22695 (simplified API OOB read, 1.6.51–1.6.53) | simplified API (`png_image_finish_read`) is not used by ImageIO/Skia paths |
| CVE-2026-25646 (`png_set_quantize` heap overflow) | low-level API with dithering; not reached by decode-only callers |

### FFmpeg image/video decoders

| item | built here? | reachable from widget? |
|---|---|---|
| CVE-2025-9951 jpeg2000dec heap OOB write | **no** (jpeg2000 decoder not built, §2.3) | no |
| CVE-2026-8461 MagicYUV heap OOB write | no (not built) | no |
| CVE-2026-66040 PNG encoder eXIf heap OOB | no (png encoder/decoder not built; `--disable-zlib`) | no |
| CVE-2026-64832/64833/64834/64835 (AISLE FFmpeg set) | codec-specific; not in the enabled set | no |
| image2 demuxer issues | demuxer not registered | no |

### Browser / platform image pipelines (knowledge transfer)

Chrome/Skia `CVE-2025-32318`, `CVE-2026-6298`, `CVE-2026-3931`,
`CVE-2026-121086`; Samsung `libimagecodec.quram` `CVE-2026-21096`; WebKit image
CVEs — all are vendor/platform decoders. They confirm the bug classes to look
for (Huffman table growth, stride/dimension arithmetic, palette/alpha unfilter
windows) but are not app-bundled findings here. On Android, a widget data URI
does reach exactly this layer (`BitmapFactory`), so a device-specific Skia
n-day would be triggered by a widget — but it is an OS bug on that device, not
a Telegram bug, and the Pixel 9/Android 17 image stack was not fuzzed here.

### 5.1 Research methods used (and what to use next)

What was actually used here, in the order that found the reachability answer:

1. **String-presence triage with false-positive control.** The initial premise
   came from bare strings (`image/jpeg`, `image/webp`, `JPEGInterchangeFormat`,
   `jpeg2000`…). Two checks kill that class of false positive: (a) FFmpeg's
   `codec_desc.c` names/MIME types are compiled for **all** codecs regardless
   of `CONFIG_*`, so a name string proves nothing; (b) per-decoder
   implementation strings are decisive (`mjpegdec.c`'s
   `"mjpeg_decode_dc: bad vlc"`, `pngdec.c`'s `"Multiple IHDR"`,
   `webp.c`'s `"entropy coded image"`). Use error/log format strings unique to
   the `.c` file, not codec names.
2. **Library fingerprinting in stripped binaries.** Search for fixed data
   tables (libwebp's VP8L code-length order
   `11 12 00 01 02 03 04 05 10 06 07 08 09 0a 0b 0c 0d 0e 0f`, 2 occurrences in
   the iOS framework, 0 in `libtmessages`) and for copyright/version banners
   (`"mozjpeg version 4.1.4 (build 10000)"`, `"Copyright (C) 1991-2023 The
   libjpeg-turbo Project"`). This is how the iOS decoder inventory was built
   without symbols.
3. **Call-path proof from DEX, not from class names.** `androguard` gave the
   exact `loadImage` bytecode and the constant pool; scanning all four DEX
   files for the exact `const-string "data:"` proved there is no second
   data-URI handler. String-table `grep` alone is not enough (it matches
   substrings such as `metadata:`).
4. **Patch mining / diffing.** `libwebp`'s public `ChangeLog` + GitHub commit
   history (`src/dec/vp8l_dec.c`) was mined for every fix after the pin; each
   patch was read to decide whether it touches the still-RGBA decode path
   (`WebPDecodeBGRAInto`) or only encoder/incremental/YUVA/crop paths. This is
   the highest-yield method for an app that pins an old codec: **the fix
   commits are the bug list**, and each patch's hunk tells you the required
   input conditions.
5. **OSS-Fuzz corpora / replay.** libwebp, FFmpeg, libjpeg-turbo corpora are
   the natural next input; prior campaigns in this repo already replayed the
   FFmpeg GIF/VP9/Matroska/MOV corpora.
6. **Differential fuzzing across versions** (method note; the image queue was
   dropped, §8): build the pinned version and a fixed/newer version with the
   same harness; only crashes that reproduce on the pinned build and not on the
   fixed one are candidates.
7. **Crash dedup against advisories.** Before claiming a 0day, match the crash
   site against the CVE fix commits (e.g. `BuildHuffmanTable` → CVE-2023-4863;
   `h2v2_merged_upsample_internal` → CVE-2023-2804; `png_image_read_direct_scaled`
   → CVE-2026-22695). The repo's `notes/old_ffmpeg_rce.md` and
   `local_message_media_ace.md` already hold the FFmpeg-side matrix.
8. **Bug trackers / writeups** for bug-class priors: Cloudflare/JFrog/Huntress
   on libwebp, the libjpeg-turbo issue tracker (`#675`), libpng `pngnews`,
   Chromium/WebKit security releases, and the OSS-Fuzz issue tracker for
   fuzzer-found regressions.

---

## 6. Bug log (every memory bug found, 0day and n-day)

### IMG-01 — Java PNG IDAT inflate has no output cap (DoS, not corruption)

| field | value |
|---|---|
| where | `WidgetSandboxBackend.loadImage` PNG branch (`Inflate` → `ByteArrayOutputStream`, classes4.dex) |
| class | resource exhaustion (Java heap OOM), delivered through a JNI callback |
| trigger | `data:image/png;base64,<small deflate bomb>` with a PNG signature + IHDR selecting the branch; the URI is capped at 2 MiB (⇒ ≤ ~1.5 MiB decoded), but deflate expands up to ~1032:1, so a few hundred KiB can expand to hundreds of MiB before the row-scan/height bound is consulted |
| bounds present | URI 2 MiB, 4M px, 32 MiB image budget (all checked **after**/around the inflate; the inflater itself is unbounded) |
| memory corruption | **no** — Java arrays/streams are bounds-checked |
| impact | `OutOfMemoryError` inside the native→Java callback; combined with IMG-02 this is a plausible app abort/ANR, i.e. remote DoS from a widget message |
| novelty | unreported (DoS only) |
| status | code-level proof; not executed on a device (no device use in this pass) |

### IMG-02 — pending Java exception across the JNI boundary (DoS risk)

| field | value |
|---|---|
| where | native `twidget`/`twlite` caller of `loadImage` (JNI `CallObjectMethod` on `WidgetSandboxBackend`) |
| class | JNI pending-exception abort (ART `JNI DETECTED ERROR IN APPLICATION`) if the native caller makes another JNI call without `ExceptionCheck`/`ExceptionClear` |
| trigger | any exception from `loadImage` (IMG-01 OOM, `IllegalArgumentException` from `Bitmap.createBitmap` on odd IHDR dimensions, `ArrayIndexOutOfBoundsException` if a truncated PNG reaches a helper) |
| memory corruption | **no** |
| status | **not confirmed; evidence suggests it is handled.** Java side: the PNG pre-scan has 4 try ranges and the inflate block's handler calls `Inflater.end()` and then `throw` (rethrow), so exceptions do reach the native caller. Native side: the twidget range (0x770000–0x9a0000) contains **28 `ExceptionCheck` call sites** (JNIEnv table offset 0x720, verified with capstone), including the `GetMethodID` block that caches `loadImage` at 0x98d790–0x98d7ac, so the JNI layer is exception-aware. The exact `CallObjectMethod` site for `loadImage` (methodID at backend+0x58) was not pinned; treat IMG-02 as an unproven risk, not a crash claim. |

### IMG-03 — iOS WebPBinding failure path leaks (no corruption)

`UIImage+WebP.m` `+convertFromWebP:`: on `WebPDecodeBGRAInto` failure it
returns `nil` without freeing `targetMemory`, releasing `colorSpace`, popping
the pushed `UIGraphics` context, or releasing the `targetContext` — a leak per
malformed image. The padding loop is arithmetic-dead for `w >= 2`
(`i` starts at `y*stride + 4w` but is bounded by `stride >> 2`; for `w = 1`
only offsets 4..7 of the first ≥32-byte row are touched), so it is not a write
primitive. No memory corruption.

### IMG-04 — iOS mozjpeg `decompressImage` ignores `tjDecompress2` failure

On decode failure the RGB buffer stays uninitialised and is converted and
published as a `CGImage` — an uninitialised-read/info-disclosure class at most;
buffer sizes and strides are consistent (`3w+31`/`4w+31`). No OOB. Path:
`DirectMediaImageCache` (direct media), not widget data URIs.

### IMG-05 — libwebp 1.3.2 fuzz (negative)

See §7.

### Memory corruption in scope: **none**

No OOB read/write, UAF, double free or type confusion was found in the widget
data-URI image path. The only app code on the path is the Java PNG pre-scan,
which is memory-safe by construction (Java arrays), and the platform decoders,
which are outside the app.

---

## 7. Fuzzing performed in this session (small, bounded)

Target: **libwebp 1.3.2 at the exact iOS pin** (`iOS/third-party/webp/libwebp`,
commit `c1ffd9ac…`), compiled with `-fsanitize=address,fuzzer-no-link -O1 -g`.

Harness `src/webp_binding_fuzz.c` mirrors `UIImage+WebP.m` exactly:
`WebPGetInfo` → `malloc(((4w+31)&~31) * h)` → `WebPDecodeBGRAInto(data, len,
mem, stride*h, stride)`. Fuzz-only deviation: buffers > 256 MiB are skipped so
libFuzzer stays inside its RSS budget (documented in the source).

Command (log `logs/fuzz_webp_binding_180s.log`):

```
ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 \
./build/webp_binding_fuzz -max_total_time=180 -rss_limit_mb=1024 \
  -malloc_limit_mb=256 -max_len=262144 -timeout=10 \
  -artifact_prefix=artifacts_webp/ seeds_webp_fuzz
```

Result:

```
Done 232130 runs in 181 second(s)
stat::number_of_executed_units: 232130
stat::average_exec_per_sec:     1282
stat::new_units_added:          1814
stat::peak_rss_mb:              309
```

* **0 ASan reports, 0 artifacts (UBSan was not enabled in this build)** (`artifacts_webp/` empty).
* Coverage at end: 1,462 edges / 6,420 features.
* Corpus: 140 generated seeds (`seeds_webp/`: lossy q=0/50/100, lossless,
  alpha, palette, animation, dimensions 1×1…16383×1, plus hand-built truncated
  RIFF) + the evolved 898-unit corpus (`seeds_webp_fuzz/`).
* The known CVE-2023-4863 PoCs (`bad.webp`, `maxdrift.webp`, `nso.webp`) are
  **rejected** by 1.3.2 (`decode fail` in `webp_binding_run`), confirming the
  pin is past that CVE.

This is a short campaign, not a verdict on libwebp; it is consistent with
1.3.2 being fixed for the well-known still-image bugs.

---

## 8. Fuzz queue — dropped (per orchestrator directive)

**Status: no image fuzzing is queued or running, and no workers are requested.**
The earlier plan (P1 libwebp differential, P2 mozjpeg, P3 FFmpeg) was **dropped**
by the orchestrator on 2026-11-08: those are famous, freshly-updated libraries,
and the widget data-URI path does not reach them (Android = platform Skia;
iOS = ImageIO, §3.1). The global worker budget (2–3) is fully used by the
litehtml (2) and CSS (1) campaigns.

What remains, if a slot ever frees, is at most the already-built **small**
libwebp 1.3.2 harness (`build/webp_binding_fuzz`, §7): it is 1 worker, 309 MB,
and it targets the only app-bundled codec the app still uses (remote photo /
sticker paths, **not** widget data URIs). It is not queued.

The Android platform Skia path cannot be fuzzed on the host (system code at the
device patch level); the only faithful test is a device, which is out of scope
(Pixel crash-log-only, Sony untouched). iOS ImageIO is closed source.

---

## 9. Tag domain, MTE and iOS applicability

* **Android, app-bundled native code**: none on this path. The QuickJS arena
  (tag 0) is not involved in image decode.
* **Android, platform decoder (Skia/BitmapFactory)**: runs in the app process.
  Native pixel buffers are normal C++ heap allocations (Scudo); under MTE they
  carry the allocating thread's random tag. A decoder OOB that crosses a
  16-byte granule on a tagged allocation faults as `SEGV_ACCERR` with a tag
  mismatch (`ESR.TFSR` set) — the same detector class as the C2 Pixel 9 runs,
  but the allocation is in system code, so the tag is whatever tag the decoding
  thread has, not the arena tag 0. The widget render/decode runs on the widget
  thread (`widget.sandbox` in the 72801 tombstone), so a data-URI decode is
  synchronous on that thread and inherits its tag.
* **Java bitmaps**: the pixel buffer is a native (Skia) allocation too;
  `Bitmap.createBitmap`/`BitmapFactory` both end in `SkBitmap` allocations.
  The Java object itself is ART-heap.
* **iOS**: user apps do **not** get MTE (Apple does not expose it; PAC protects
  control data only). A libwebp/ImageIO heap overflow in `TelegramUIFramework`
  is a plain in-process heap corruption, no MTE backstop, no PAC mitigation for
  data; exploitation is the classic iOS malloc/ASLR problem.
* **Applicability**: a bug in the *platform* decoder applies to every app on
  the device (OS patch level); a bug in iOS libwebp 1.3.2 applies to Telegram
  only, in the app process, and would survive Telegram app updates until the
  pin is bumped.

---

## 10. Host PoC / minimal trigger / payload & endgame plan

**Minimal HTML (Android and iOS widget):**

```html
<img src="data:image/png;base64,AAAA...">
<!-- or -->
<div style="background-image:url(data:image/webp;base64,AAAA...)"></div>
```

**Size math (important for any future decoder bug):**

* Java hard cap: the whole `data:` string must be ≤ 2,097,152 chars
  (`0x200000`), and `w*h ≤ 4,194,304`, `imageBytes + 4*w*h ≤ 33,554,432`.
* The widget document itself is delivered as a gzip/deflate
  `messageMediaWidget.payload`; the server-side size cap applies to the
  compressed payload, and base64 of high-entropy image bytes does not compress.
  Any image-borne PoC therefore has to be small (tens of KiB) unless the widget
  payload cap is larger than the sticker-style 64 KiB. Verify the actual server
  cap before planning a delivery.
* The document is materialised by the native litehtml+gumbo engine (the exact
  ingest call is gap G5 in `twidget_native_audit.md`), so an image-only widget
  document should be enough; the renderer JS is not required for `<img>`.

**Endgame if a decoder bug existed:**

1. Minimal widget document with one `<img>` data URI (no JS, no CSS filter).
2. Delivery as `messageMediaWidget` (needs a whitelisted bot/account per the
   project's server-gating note).
3. Trigger: opening the chat (or the widget cache/prewarm) decodes the image on
   the render thread.
4. Android: the fault is in platform code; MTE-on would report a tag mismatch
   if the OOB leaves the allocation, otherwise a silent OOB (Scudo may or may
   not notice at free). No app-level primitive without a platform bug.
5. iOS: if (and only if) the WebP binding is on the widget path, a libwebp OOB
   write is a normal in-process heap overflow in `TelegramUIFramework`; the
   endgame would follow the project's existing iOS chain work (no MTE), with
   the constraint that the input must survive ImageIO/Telegram's pre-checks if
   any run before the binding.

**Host PoC status**: none for memory corruption (none found). IMG-01 has a
host-side arithmetic proof only; no device execution was attempted.

---

## 11. Negative results and open questions

**Negative (checked, no bug):**

1. No app-bundled decoder is invoked for any widget `<img>`/background/data URI
   on Android (exact DEX method + binary inventory in §2).
2. The Java PNG pre-scan is bounds-checked: IHDR length ≥ 33, `q.a/q.c` reads
   are guarded by the chunk-length checks, IDAT/IEND handling validates
   `chunkLen ≤ len - off - 12`, CRC32 is recomputed (no attribute trust).
3. The Java image budget accounting is consistent (`imageBytes` add/subtract
   uses `getAllocationByteCount`), and the returned `float[2]` comes from the
   stored bitmap, so native width/height cannot disagree with the bitmap.
4. libwebp 1.3.2 rejects the known 2023 PoCs; 232k-exec ASAN fuzz found
   nothing on the BGRA still path.
5. The FFmpeg MJPEG/GIF decoders are built but have no widget call site (no
   avformat/avcodec in the twidget range), and PNG/WebP/JPEG2000/JXL/JLS
   decoders are not built at all.

**Open questions:**

1. ~~**iOS WebP routing**~~ — **resolved negative** by the ObjC call-site count
   in §3.1: 5 `convertFromWebP:` sites = the five pre-existing Swift callers,
   no widget caller. Confidence high; the residual caveat is that a refactor
   of one old caller into the widget path cannot be excluded from counts alone.
   A 1-file device experiment (WebP variant accepted only by libwebp should
   *not* render in a widget) would close it; no device was touched.
2. **IMG-02:** the exact `CallObjectMethod` site for `loadImage` (methodID at
   backend+0x58) was not pinned. The twidget range has 28 `ExceptionCheck`
   sites and the Java side rethrows after `Inflater.end()`, so this is a
   residual, unproven risk, not a crash claim.
3. **Server cap** on `messageMediaWidget.payload` (compressed) — determines the
   largest embeddable data URI.
4. **Pixel 9 Skia version** — the platform decoder is the only Android decoder
   on this path; a device patch-level diff would show whether any unpatched
   Skia/libwebp n-day is present (out of host scope; crash-log-only device).
5. `image(int)` JNI signature not found in `.rodata` (the native↔Java binding
   builds some signatures dynamically); only `loadImage` and `filterPixels`
   signatures are literal. Not a bug, but it limits static xrefs.

---

## 12. Files

```
notes/lib_hunt_images_20261108.md                 this note
notes/LEMMALOG_FACTS_images_20261108.txt          facts for the orchestrator
lab/lib_hunt_images/README.md                     artifact index
lab/lib_hunt_images/build/                         libwebp 1.3.2 ASAN build (cmake)
lab/lib_hunt_images/src/webp_binding_fuzz.c       exact WebPBinding-geometry fuzzer
lab/lib_hunt_images/src/webp_binding_run.c        single-file runner
lab/lib_hunt_images/seeds_webp/                   140 generated WebP seeds
lab/lib_hunt_images/seeds_webp_fuzz/              evolved corpus (898 units, 10.5 MB)
lab/lib_hunt_images/logs/loadImage_disasm.txt     Java loadImage disassembly
lab/lib_hunt_images/logs/fuzz_webp_binding_180s.log  232,130-exec ASAN run
lab/lib_hunt_images/logs/ios_selref_counts.txt    ObjC call-site counts (§3.1)
lab/lib_hunt_images/logs/cmake_webp1342.log, build_webp132.log
lab/lib_hunt_images/dex/classes*.dex              extracted 72889 DEX
lab/lib_hunt_images/ios_scan_selrefs.py           Mach-O chained-fixup selref/stub/bl counter
lab/lib_hunt_images/find_adrp_refs.py             arm64 ELF adrp+add xref finder
lab/lib_hunt_images/dump_twidget.py, disasm.py, xref_twidget.py, scan_plt.py, find_calls.py, find_calls2.py
```

No device, Frida, bot or network payload delivery was used. No existing note or
evidence was modified or deleted.
