# Startup theme/wallpaper path — bounds audit (Telegram beta 13.2.0 / 72799, arm64)

Date: 2026-11-03
Target: `org.telegram.messenger.beta` 13.2.0 (versionCode **72799**), arm64,
`libtmessages.49.so` 72,799 bytes symbol naming, md5 `2c0caa68a07fc26f79d13519af6c3526`.
Device: Sony XQ-BT52 (Xperia 10 III), Android 13 build 62.2.A.0.533, UID 10357,
rooted (Magisk), app **not** debuggable. Screen 1080x2394, app
`memoryClass=256`, `dalvik.vm.heapsize=512m`.
IDB: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_media_annotated.i64`
(saved; backup copy
`<HOME>/ailocal/voda/.opencode/idbs/libtmessages_49_arm64_startup_wallpaper_annotated.i64`).
Lab: `../../lab/startup_wallpaper_bounds/` (native pseudocode, arithmetic model,
PoC input generator, device procedure).
Follow-up (2026-11-03): §10 answers the animated/video-wallpaper question — it is **not** a launch FFmpeg surface in 72799.

Prior notes deliberately not duplicated: `../../notes/startup_appdata_full_audit_20261102.md`
(SQLite/libwebp/tgnet), `../../notes/startup_appdata_persistence.md`.

---

## 0. Verdict

**No controlled native write was found on the app-launch theme/wallpaper path.
This is not an ACE primitive; do not claim ACE from it.**

What the audit *did* find is a family of **launch-time DoS** outcomes reachable
from app data without a tap: a crafted theme mask makes the wallpaper drawable
allocate `w*h*4` ARGB (`jb0.e()`), and a crafted pattern document makes the
in-app SVG renderer allocate screen-sized bitmaps and parse unbounded path
data. A runtime-applied `.wp` wallpaper can additionally reach
`Theme.j`'s `createBitmap(0,24)` (that branch needs the in-app apply, see
§1.3). All of these raise `IllegalArgumentException` / `OutOfMemoryError`,
killing the process on every cold start while the crafted theme remains
installed.

The reason there is no write is structural, not luck:

1. Every native sink that combines two bitmaps (`copyBitmaps`,
   `applySoftLight`, `applyAlphaInvert`, `expandAlphaToBlack`,
   `extractAlpha`, `generateQrBackdrop`) **enforces equal width/height** (and,
   where it matters, equal/expected format) before it touches memory.
2. Every sink that writes into one bitmap derives `width/height/stride` from
   `AndroidBitmapInfo` of that same bitmap. The app cannot forge a `Bitmap`:
   the dimensions and row bytes come from Skia, so `stride*height` is the real
   allocation and `stride >= bpp*width` holds.
3. The remaining arithmetic (`w*h`, `4*width`, `(4w+15)*h`) is 32-bit, but a
   wrap needs **>= 2^29 pixels** (2 GiB ARGB / 512 MiB ALPHA_8) — 4x the whole
   `largeHeap` limit of this device (`heapsize=512m`, measured
   `memoryClass=256`). `blurBitmap` additionally rejects `w*h > 22500` and
   `stackBlurBitmap` requires `RGBA_8888`.
4. The animated/video wallpaper does **not** add a launch FFmpeg surface:
   `Theme.J` never creates an `AnimatedFileDrawable`/`ImageReceiver`; the
   video-capable wallpaper drawable (`org.telegram.ui.xn`) is only built by
   the ChatActivity provider (`sn`) and story replies, so a video document in
   the global theme is ignored/parsed as a pattern at launch. See §10.
5. The one sink that *does* accept mismatched source/destination dimensions
   (`Utilities.nLibyuvARGBSaleBitmap` -> libyuv `ARGBScale`) is not on the
   theme/wallpaper path (its only caller is story-photo scaling,
   `vh/n5.java:570`).

Model output (`../../lab/startup_wallpaper_bounds/model.py`): 131,960 feasible
bitmap/sink combinations, **0** write-bound violations.

---

## 1. Java reachability and cold-start order

### 1.1 The trigger

`LaunchActivity.onCreate` calls:

```java
// jadx: org/telegram/ui/LaunchActivity.java:2902
org.telegram.ui.ActionBar.t6.o1(true);
A();
Q0();
```

`t6` is `org.telegram.ui.ActionBar.Theme` (fields `t6.I` = current `s6`
ThemeInfo, `t6.im` = colors, `t6.e0` = wallpaper drawable). In smali the same
call is `classes3/org/telegram/ui/LaunchActivity.smali:59900`
(`invoke-static {v12}, Lorg/telegram/ui/ActionBar/t6;->o1(Z)V`).

Immediately afterwards, still in `onCreate`, the dialogs fragment is created:

```java
// jadx LaunchActivity.java:2933-2938
if (this.f33377q0.getFragmentStack().isEmpty() && ...) {
    if (org.telegram.messenger.d20.i(this.O).p()) {
        this.f33377q0.c(-1, new pf0());      // chat list (DialogsActivity)
    } else {
        this.f33377q0.c(-1, P());
    }
```

So the wallpaper job is **queued before the chat-list fragment is
instantiated**, on every cold start, with no user action. The public-source
line `LaunchActivity:556` quoted in the task corresponds to this call in the
13.x source; in the 72799 build it is decompiled line 2902 / smali 59900.

### 1.2 `Theme.o1(true)` is asynchronous — and uncaught

`o1` (smali `t6.smali:57466`) reads `t6.I` and `t6.I.i0` (the current
wallpaper settings), then, because the argument is `true`:

```smali
# t6.smali (o1, force branch)
sget-object p0, Lorg/telegram/messenger/Utilities;->i:Lorg/telegram/messenger/r5;
new-instance v3, Lorg/telegram/messenger/sh;   # captures (m6, File, intensity,
                                              #  blur, document, flag)
invoke-direct/range {v3 .. v9}, Lorg/telegram/messenger/sh;-><init>(...)V
sput-object v3, Lorg/telegram/ui/ActionBar/t6;->d:Lorg/telegram/messenger/sh;
invoke-virtual {p0, v3}, Lorg/telegram/messenger/r5;->c(Ljava/lang/Runnable;)V
```

`Utilities.i` is the `"themeQueue"` pool (`Utilities.java:60`,
`d/e/f/g/h/i` = stage/global/cacheClear/search/phoneBook/**theme**). The
runnable `sh.run()` (`classes/org/telegram/messenger/sh.smali:103`,
`pswitch_1e`) calls `Theme.p1(m6, file, intensity, blur, document, flag)`
**without a try/catch**:

```smali
:pswitch_1e
  ...
  invoke-static/range {v1 .. v6}, Lorg/telegram/ui/ActionBar/t6;->p1(...)Landroid/graphics/drawable/Drawable;
  move-result-object v0
  new-instance v1, Llg/s;  const/16 v2, 0x1d
  invoke-static {v1}, Lorg/telegram/messenger/i0;->g3(Ljava/lang/Runnable;)V
```

`p1` = `Theme.p1` (jadx 5534, smali 58075) calls
`Theme.J(...)` (jadx 2961, smali 22407) and then `P()`. The returned drawable is
handed to `lg/s`, which runs on the UI thread and calls
`Theme.j(drawable)` + `Theme.h(drawable)` (`lg/s.smali:136,141`,
`t6.smali:46864`).

Consequence: an `Error`/`RuntimeException` thrown inside `p1`/`J` on the theme
queue, or inside `Theme.j` on the UI thread, reaches Android's default
`UncaughtExceptionHandler` and kills the process. That is the DoS primitive
(§6), not a memory-corruption primitive.

### 1.3 The app-data inputs

All of the following are writable by UID 10357 and read during that cold-start
sequence:

| input | where | used as |
|---|---|---|
| `shared_prefs/themeconfig.xml` | `accents_<theme>.attheme` = Base64 `SerializedData` of `s6` (ThemeInfo), `accent_current_*`, `themes2` JSON | current theme + current `m6` wallpaper settings (`s6.i0` = `r6.y`), colors, `pIntensity`, `wBlur`, `wMotion`, wallpaper slug |
| `files/<theme>_<accent>_<wpId>_v5.jpg` (or `_v8_debug.jpg`) | `r6.e()` (`r6.java:167`) | theme-embedded wallpaper; `Theme.J` path 1, decoded as **ALPHA_8** mask (`BitmapFactory.decodeFile`, `J` smali ~22580-22650) |
| `files/MD5(url).wp` | `Theme.b1(m6)` builds `https://attheme.org?slug=...`; `J` uses `files/<MD5(url)>.wp` | wallpaper image; `Theme.J` path 3 (only when `Be == 0` **and** the runtime static `h0` is set by an in-app apply), `n1` -> `BitmapDrawable` |
| `files/<theme>.attheme` at `wallpaperFileOffset` | theme blob + `hm` key `wallpaperFileOffset` | `Theme.J` path 4 (`s6.b` + runtime static `g0`), `n1(FileInputStream, offset)` -> `BitmapDrawable` |
| pattern document (`application/x-tgwallpattern`, `.tgv`) | theme `TL_theme.settings[0].wallpaper.document` | `J` path 2: `b8.K(document)` -> `e00.f(file, minScreen, maxScreen, 2)` -> in-app SVG renderer `b00` |
| `files/cache4.db` `wallpapers2.data` | theme/wallpaper list | TL wallpapers (document ids, settings); not directly a bitmap sink |
| `files/*.attheme` | theme picker/load | same `s6`/`m6` fields, incl. embedded wallpaper offset |

`Theme.J` chooses in this order (smali 22407+):

1. `file != null && file.exists()` and `Be`/`Ce`/`De` (chat wallpaper gradient
   colors) are all non-zero -> `jb0` + `BitmapFactory.decodeFile(...,
   inPreferredConfig=ALPHA_8)`; if the decode config is not ALPHA_8,
   `bitmap.copy(ALPHA_8, false)`.
2. `Be` non-zero (gradient color 1 present): if `Ce`/`De` are also non-zero,
   `jb0` + pattern bitmap from `e00.f(document)` when a pattern document is
   supplied, else the built-in pattern `e00.c(1.0f, R.raw.<style>, min, max,
   -1, 2)`; otherwise a `GradientDrawable` / `ColorDrawable`. This branch
   **skips** the `.wp` path.
3. `Be == 0` and `p4` (the wallpaper URL string, `t6.b1(m6)`) non-empty ->
   `files/<MD5(p4)>.wp` -> `n1` -> `BitmapDrawable`.
4. `Be == 0`, `p4` empty, intensity > 0 and `s6.b`/`s6.d` set -> `n1` on that
   file -> `BitmapDrawable`.
5. otherwise `ColorDrawable`.

The current device theme (`lastDarkTheme=Dark Blue`) has `Be` set, the
`*_v5.jpg` file for accent 0 is present but 0 bytes (decode fails), and the
`themeconfig` carries `application/x-tgwallpattern` documents, so the running
background is the built-in/pattern branch (2).

**Cold-start caveat for branches 3 and 4:** `o1(true)` passes `p4 = t6.h0`
(the wallpaper URL) and `offset = t6.g0`; both are runtime statics that are
only written by an in-app wallpaper apply (`bi/n4.java:155,166`) and are reset
to `null`/`0` at process start (the only `sput` sites are the theme reset paths,
`t6.smali:62481/62619`, `ActionBarLayout.smali:15114`). On a plain cold start
`h0 == null` and `g0 == 0`, so branches 3 and 4 do **not** run from app data
alone; they are reached after the user applies a wallpaper in the running
process. The cold-start-reachable branches are **1** (theme mask file) and
**2** (pattern document / built-in pattern). This is the conservative
no-tap model used below.

### 1.4 Name mapping vs. the public source

The task names public-source symbols. In 72799 they are R8-renamed; the
strings `loadWallpaper`, `loadWallpaperInternal`, `createBackgroundDrawable`,
`createWallpaperForAccent`, `PatternsLoader`, `SvgHelper` are **not present**
in any of the four dex string pools (checked), so the mapping below is by
behaviour and call graph:

| public source | 72799 | evidence |
|---|---|---|
| `Theme.loadWallpaper(boolean)` | `Theme.o1(Z)` | only caller from `LaunchActivity.onCreate`; schedules `sh` -> `p1` -> `J` |
| `Theme.loadWallpaperInternal(...)` | `Theme.n1(FileInputStream,int)` | decodes at a file offset, computes `min2 = min/max` sample and `createScaledBitmap(w*max2, h*max2)`; used for the `.wp` image and by `o6.java:125` |
| `Theme.createBackgroundDrawable` / `createWallpaperForAccent` | `Theme.J(...)` (factory returning `bh.d`) + `jb0` / `nb0` drawable | `J` builds `jb0`/`BitmapDrawable`/`ColorDrawable`; `jb0` owns the 60x80 gradient + mask + `applyAlphaInvert`/`copyBitmaps`/`expandAlphaToBlack` |
| `PatternsLoader` / `SvgHelper` | `e00` (`f`/`c`), `b00` (SAX handler/renderer), `d00` (path collector) | `e00.f` parses a document file, `e00.c` parses a raw resource, both install `b00` as `ContentHandler`; `d00` is only used for `GiftPatterns` (message gifts, not theme) |

---

## 2. Native sinks: exact symbols, checks, verdict

All addresses are from the annotated IDB (file offsets == RVA for this .so).
`Java_...` names are the JNI exports. Decompiled bodies are in
`../../lab/startup_wallpaper_bounds/native/`.

| sink | address | key checks | writes | verdict |
|---|---|---|---|---|
| `Utilities.copyBitmaps` | `0x74AB74` | `IsSameObject`; `AndroidBitmap_getInfo` both; equal `width/height`; equal `format`; format in `{1,4,7,8,9,10}` (`0x3C9`); `bpp(fmt)*w <= stride` of **both**; `w,h != 0` | `memcpy(dst,src,bpp*w*h)` only if `bpp*w == both strides`, else row `memcpy` of `bpp*w` per row | safe (size_t size, stride-checked) |
| `Utilities.applySoftLight` | `0x74AD80` | `IsSameObject`; equal `w/h`; both `format==RGBA_8888`; `stride >= 4*w` both | 1 px (4 B) per pixel at `dst.stride*row` | safe |
| `Utilities.applyAlphaInvert` | `0x74B294` | equal `w/h`; src `RGBA_8888` or `ALPHA_8`; dst `RGBA_8888`; `src.stride >= (fmt==1 ? 4w : w)`; `dst.stride >= 4w` | 4 B per src pixel | safe |
| `Utilities.expandAlphaToBlack` | `0x74B920` | equal `w/h`; src `ALPHA_8`, dst `RGBA_8888`; `src.stride >= w`; `dst.stride >= 4w` | 4 B per pixel | safe |
| `Utilities.extractAlpha` | `0x74BAC0` | equal `w/h`; src `RGBA_8888`, dst `ALPHA_8`; `src.stride >= 4w`; `dst.stride >= w` | 1 B per pixel | safe |
| `Utilities.blurBitmap` | `0x7476E4` | `w,h,stride != 0`; branch `stride == 2*w` (RGB_565) or `4*w <= stride` (ARGB); radius `<= 15`; `2r+1 < w,h`; **`h*w > 22500` rejected** | 2 B or 4 B per pixel; temp `8*area` | safe (area cap) |
| `Utilities.stackBlurBitmap` | `0x74933C` | radius `>= 1`; **`format == RGBA_8888`**; no explicit `stride >= 4w` (Android invariant); area `h*w` int | 4 B/px; 4 work buffers `4*area` | safe for feasible bitmaps; `h*w >= 2^31` (8 GiB ARGB) to wrap |
| `Utilities.generateGradient` | `0x749DCC` | `RGBA_8888`; `w,h != 0`; writes `stride*row + 4*col` | 4 B/px | safe (wallpaper call is 60x80/80x80) |
| `Utilities.drawDitheredGradient` | `0x7499C8` | `RGBA_8888`; temp `16*h*stride`; rect args only feed floats | 4 B/px | safe |
| `Utilities.generateQrBackdrop` | `0x74A334` | `RGBA_8888`; array lengths; if a background bitmap is supplied it must have **equal w/h**; both strides from `AndroidBitmapInfo` | 4 B/px | safe (QR login path, not theme) |
| `Utilities.averageBitmapColor` | `0x74B770` | rect `a4..a6/a5..a7` inside `w/h`, non-negative; `RGBA_8888`; `stride >= 4w` | reads only | safe |
| `Utilities.nLibyuvARGBSaleBitmap` | `0x74B5BC` | both `RGBA_8888`; `w < 2^29`, `h,stride >= 0`; `stride >= 4w`; filter `<= 3`; **dims may differ** (scale) | libyuv `ARGBScale` into dst | designed for mismatch; not on wallpaper path |
| `AnimatedFileNative.nGetVideoFrame` / `writeFrameToBitmap` | `0x74EAF0` / `0x74E6B0` | dest dims always read from the passed Bitmap; sws/converters use those dims; temp alloc `((4w+15)&~15)*h` (32-bit product) | frame into bitmap | safe for feasible bitmaps; temp overflow needs `w*h >= 2^29` |
| `AnimatedFileNative.nCreateDecoder` | `0x74DC98` | writes Java `int[0..5]`; `s5.d` is `int[8]` (`s5.smali:318`) | metadata | safe |
| `AnimatedFileNative.nGetVideoInfo` | `0x74D6AC` | writes `int[0..10]` (incl. 8-byte stores at `[3]`/`[4]`) | metadata | safe: all callers pass `int[11]` (`qz.java:1715`, `w50.java:488`, `nr0.java:35`) |

### 2.1 The checks that matter (quoted)

Data flow for every sink: Java `Bitmap` -> `AndroidBitmap_getInfo` fills
`{width, height, stride, format, flags}` from the SkBitmap (`stride` is the
real `rowBytes`, `lockPixels` returns the allocation base) -> the native loop
writes at `base + stride*row + bytecol`, so `row < height` and
`bytecol < rowbytes` imply `offset < stride*height == allocation`. The only
way to break this is to use a width/height that does not belong to the bitmap
(the paired-bitmap sinks check it) or to overflow the byte count (needs a
bitmap bigger than the heap).

`copyBitmaps` (native/copyBitmaps.c:26-48):

```c
if ( (info.flags & 0x80000000) == 0 && (v14.flags & 0x80000000) == 0 ) {
  if ( info.width != v14.width || info.height != v14.height ) return 0;
  ...
  v8 = info.format - 1;
  if ( (unsigned int)(info.format - 1) > 9 || ((0x3C9u >> v8) & 1) == 0 ) return 0;
  v9 = qword_2A63F0[v8] * info.width;          /* bpp * width, 64-bit */
  if ( v9 <= info.stride && v9 <= v14.stride ) {
    ...
    if ( v9 == info.stride && v9 == v14.stride )
      memcpy(dest, addrPtr, v9 * info.height); /* size_t */
    else { do { memcpy(v10, v11, v9); ... } while (v12 < info.height); }
```

The bpp table `0x2A63F0` is `{4,1,1,2,1,1,2,1,8,4}` for formats 1..10, i.e.
RGBA_8888=4, RGB_565=2, RGBA_4444=2, A8=1, F16=8, 1010102=4.

`applySoftLight` (native/applySoftLight.c:54-61):

```c
if ( AndroidBitmap_getInfo(a1, a3, &info) == 0
  && AndroidBitmap_getInfo(a1, a4, &v42) == 0
  && info.width == v42.width ) {
  if ( info.height == 0 || info.width == 0 || info.height != v42.height
    || info.format != 1 || v42.format != 1 ) return 0;
  if ( info.stride >= 4 * info.width && v42.stride >= 4 * info.width ) { ... }
```

`blurBitmap` area guard (native/blurBitmap.c:415 / 958-963):

```c
if ( v178 >= (int)width || v178 >= (int)height || (int)height * (int)width > 22500 )
    return AndroidBitmap_unlockPixels(...);
...
if ( v97 >= (int)width || v97 >= (int)height
  || (int)height * (int)width > 22500
  || 4 * (int)width < stride ) return ...;
```

`stackBlurBitmap` format gate (native/stackBlurBitmap.c:151-158):

```c
if ( AndroidBitmap_getInfo(result, jbitmap, &v141) == 0 && v141.format == 1 ) {
  width = v141.width; height = (int)v141.height; stride = (int)v141.stride;
```

---

## 3. The hypotheses, tested one by one

### 3.1 Source/destination dimension mismatch

* `copyBitmaps`, `applySoftLight`, `applyAlphaInvert`, `expandAlphaToBlack`,
  `extractAlpha`, `generateQrBackdrop` all reject `w/h` mismatch (and format
  mismatch where it matters). The model confirms the rejection for
  `1080x2394` vs `1079x2394`.
* `nLibyuvARGBSaleBitmap` is the only mismatch-tolerant sink. It is not
  reachable from the theme path: the only caller is
  `Utilities.y(Bitmap,Bitmap)` (`Utilities.java:420`) from `vh/n5.java:570`
  (story photo scaling); the Java side there computes the destination from the
  view dimensions, not from theme data.
* Consequence: the task's "crafted wallpaper that reaches copyBitmaps /
  applySoftLight / blur with mismatched dimensions" cannot happen — the
  mismatch is rejected before any pointer is taken.

### 3.2 `w*h*4` / `stride*h` 32-bit overflow

The 32-bit products and the smallest bitmap that wraps them:

| expression | sink | wrap needs | minimum ARGB allocation |
|---|---|---|---|
| `h*w` (`v12`) | `stackBlurBitmap` buffers | `w*h >= 2^31` | 8 GiB |
| `2*w*h` (`v16`) | `stackBlurBitmap` weight table | `w*h >= 2^30` | 4 GiB |
| `((4w+15)&~15)*h` | `writeFrameToBitmap` temp | `w*h >= 2^29` | 2 GiB |
| `w << 2` | `applyAlphaInvert` stride check | `w >= 2^30` | 4 GiB |
| `4*w` | `expandAlphaToBlack` stride check | `w >= 2^30` | 4 GiB |

The device's `largeHeap` ceiling is `dalvik.vm.heapsize=512m` and the app
reports `memoryClass=256` at cold start, so none of these bitmaps can exist.
`blurBitmap` never gets there because it rejects `h*w > 22500`; the theme
call is `blurBitmap(createBitmap, 3)` on a bitmap that is 24 px high and at
most a few hundred px wide.

### 3.3 Unchecked `memcpy` / `copyPixelsToBuffer`

* `copyBitmaps` memcpy sizes are `size_t` (`v9 * info.height`, `v9` per row)
  and `v9` is bounded by both strides.
* `expandAlphaToBlack`, `applyAlphaInvert`, `applySoftLight`, `extractAlpha`
  use byte loops bounded by `w` (not `stride`).
* `writeFrameToBitmap` memcpy uses the destination bitmap's
  `stride`/`height` (`native/writeFrameToBitmap.c:119-145`).
* No `copyPixelsToBuffer` on this path (that is `Bitmap.copyPixelsToBuffer`,
  Java-side, and not used by `jb0`/`Theme`).

### 3.4 ALPHA_8 / RGB_565 vs ARGB assumptions

Each sink checks the format it assumes:

* `blurBitmap` selects the row size from the stride relation and rejects
  anything that is neither `stride == 2w` nor `stride >= 4w`; an `ALPHA_8`
  bitmap (`stride == w`) is a no-op.
* `stackBlurBitmap` requires `format == 1` (RGBA_8888).
* `applyAlphaInvert`/`expandAlphaToBlack`/`extractAlpha` explicitly support the
  A8<->RGBA combination with matching dimensions.
* The `jb0` mask path decodes the theme image as `ALPHA_8`
  (`inPreferredConfig`), then `jb0.e()` allocates an `ARGB_8888` copy of the
  **same** dimensions and calls `expandAlphaToBlack` or `copyBitmaps`
  (`jb0.smali:4209/4234`, `jb0.java:412-443`). Both are equal-dimension sinks.

### 3.5 1xN / huge / mismatched wallpaper

What actually happens (host model + Java arithmetic). The cold-start branches
are 1 (mask) and 2 (pattern); branches 3/4 are runtime-apply only (§1.3).

* **Theme mask (path 1, cold start).** The file is decoded as `ALPHA_8`
  (`BitmapFactory.decodeFile`); a huge but decodable mask (e.g.
  `12000x12000` = 144 MB) then makes `jb0.e()` allocate `w*h*4` = 576 MB ARGB.
  The allocation failure is raised inside `draw()` with no catch, so it kills
  the process (IAE or OOM depending on the allocation path). The mask itself
  is never passed to a native writer with mismatched dimensions: `jb0.e()`
  creates the ARGB copy at the same `w/h` and calls `expandAlphaToBlack` /
  `copyBitmaps`, both of which re-check equality.
* **Pattern document (path 2, cold start).** `e00.f` -> `b00` (see §4);
  the bitmap is screen-sized by construction, and the attacker-controlled
  point/element counts only consume time and Java heap (DoS).
* **`.wp` / embedded-offset wallpaper (paths 3/4, runtime apply only).**
  `Theme.n1` decodes, and if a dimension is below the screen computes
  `max2 = max(1080.0f/w, 2394.0f/h)` (float division, smali `t6` n1) and calls
  `Bitmap.createScaledBitmap(w*max2, h*max2)`. `n1` wraps the block in
  `catch (Exception)`, so an `IllegalArgumentException` is survivable (theme
  falls back); an `Error` (OOM) would escape. If the scaled bitmap succeeds
  with an aspect ratio `< 1/24` (e.g. 100x2500 -> 1080x27000 = 116 MB, which
  fits the heap), `Theme.j` then computes `intrinsicWidth = 0` and calls
  `Bitmap.createBitmap(0,24,ARGB_8888)` (`t6.java:4668`,
  `t6.smali:47247-47260`, float division confirmed by `div-float`) on the UI
  thread, with no catch in `lg/s` -> process death. This is a *user-action*
  path, not a no-tap path.

All of these are DoS. None writes outside a buffer.

---

## 4. SVG / pattern (`e00.f` -> `b00`)

`Theme.J` path 2 calls `e00.f(File, p1=min(screen), p2=max(screen), 2)`.
`e00.f` (`classes/org/telegram/messenger/e00.smali:5835`) feeds the file to a
SAX parser whose handler is `b00` (`b00.smali:2394`, `startElement`).

Dimension handling in `b00` (`startElement`, case `"svg"`):

```java
// jadx_c1/sources/org/telegram/messenger/b00.java:517-560
Float k17 = e00.k("width", attributes);
Float k18 = e00.k("height", attributes);
... viewBox fallback ...
int i12 = this.e;  int i13 = this.d;          // target max/min screen dims
if (k17 == null || k18 == null) { k17 = i13; k18 = i12; }
int ceil = (int) Math.ceil(k17.floatValue());
int ceil2 = (int) Math.ceil(k18.floatValue());
if (ceil != 0 && ceil2 != 0) {
  if (i13 == 0 || i12 == 0) { i13 = ceil; i12 = ceil2; }
  else {
    if (this.f9874x == 2) this.f9869f = i13 / ceil;
    else this.f9869f = Math.min(i13 / ceil, i12 / ceil2);
    i13 = (int)(ceil * this.f9869f);
    i12 = (int)(ceil2 * this.f9869f);
  }
}
...
Bitmap.createBitmap(i13, i12, this.E ? ALPHA_8 : ARGB_8888);
```

* `ceil`/`ceil2` come from the file, but `i13/i12` are recomputed from the
  positive screen target; `ceil == 0` skips the block. NaN width -> `(int)NaN
  == 0` -> skipped. One negative and one positive dimension -> negative
  `i12` -> `createBitmap` throws `IllegalArgumentException` (caught by
  `e00.f`'s `catch (Exception)`; `J` falls back to `ColorDrawable`).
  Both negative -> positive bitmap with a mirrored canvas scale; harmless.
* `rect`/`circle`/`polygon`/`path` only build `RectF`/`Path` and draw them to
  a `Canvas` clipped to the screen-sized bitmap; coordinates are floats.
* `polygon` points are parsed into `ArrayList<Float>` and indexed
  `i11`/`i11+1`; an odd count throws `IndexOutOfBoundsException` (Java), not a
  native write (`b00.java:466-509`).
* The only attacker-controlled size is the number of points/elements
  (`pattern_big.tgv` in the lab is 2.2 MB of points) -> parse time / Java heap
  -> ANR/OOM (DoS).

XXE was not re-tested (given blocked in the task context); this section only
examines memory safety of the renderer.

---

## 5. `.pcache2` frame cache (animated wallpaper / sticker)

`rf.e` is the Java frame cache for `AnimatedFileDrawable` (`s5` implements the
`rf.c` interface; `s5` constructs `rf.e` at `s5.smali:777`). The file name is
built from the media file name + dimensions:

```java
// rf/e.java:110-127 (jadx_c1 numbering)
File file3 = new File(file2 /* files/acache */,
    name + "_" + i10 + "_" + i11 + (z10 ? "_nolimit" : " ") +
    (i12 != 0 ? "_fitz" : "") + ".pcache2");
```

Parser (constructor and `f()`):

```java
// rf/e.java:154-158
this.f15940q = randomAccessFile.readBoolean();
if (this.f15940q && arrayList.isEmpty()) {
  randomAccessFile.seek(randomAccessFile.readInt());      // offset: arbitrary
  int readInt = randomAccessFile.readInt();              // count
  d(randomAccessFile, readInt > 10000 ? 0 : readInt);    // capped at 10000
}

// rf/e.java:432-445
public final void d(RandomAccessFile raf, int i10) {
  if (i10 == 0) return;
  byte[] bArr = new byte[i10 * 8];       // <= 80000 bytes
  raf.read(bArr);
  ByteBuffer wrap = ByteBuffer.wrap(bArr);
  for (...) { dVar.f15919c = wrap.getInt();   // offset
              dVar.f15918b = wrap.getInt(); } // length
}

// rf/e.java:512-540
randomAccessFile.seek(dVar.f15919c);
byte[] e = e(dVar);                       // new byte[(int)(len*1.3f)]
randomAccessFile.readFully(e, 0, dVar.f15918b);
...
BitmapFactory.decodeByteArray(e, 0, dVar.f15918b, options); // inBitmap = s5.M0
if (ALPHA_8 target) Utilities.extractAlpha(this.f15944u, bitmap);
```

Bounds analysis:

* `count` is capped at 10000 before `new byte[count*8]`; the multiplication is
  safe (`<= 80000`).
* `seek(offset)` with a negative/out-of-range offset throws `IOException`,
  caught by the surrounding `catch (Throwable)` in `f()`/constructor.
* `length` is used for `new byte[(int)(len*1.3f)]` (negative -> Java
  `NegativeArraySizeException`; huge -> OOM, both caught) and as the
  `readFully` length; `e()` guarantees `buffer.length >= len` for every
  non-negative `len` because it allocates `1.3*len` (float->int saturates
  upward for `len > ~1.65e9`).
* Decoding uses the existing `Bitmap` as `inBitmap`; Android/Skia rejects an
  image larger than the allocation, and a smaller image is written with its
  own row bytes (<= the allocation's stride). The only native sink here is
  `extractAlpha`, which enforces equal dimensions and
  `stride >= 4w`/`>= w` (native/extractAlpha.c:31-44).
* The write path into the bitmap is the `AnimatedFileNative` decoder
  (§2), which uses the bitmap's own `AndroidBitmapInfo`.

Reachability: the cache is only consulted when an `AnimatedFileDrawable`
(`s5`) is created for a media file with exactly matching
`name_w_h[_nolimit| ][_fitz].pcache2`. For a **motion wallpaper** that means
the theme/wallpaper document must survive as a playable media file in the
app cache; a first RCE that writes both the file and the cache can reach the
parser. The parser itself is a Java-only length/offset consumer; the model and
the constructor cap show no native write. Worst case is `IOException`/
`NegativeArraySizeException`/OOM, i.e. DoS.

---

## 6. Launch DoS findings (real, but not ACE)

These are the memory-safety-relevant outcomes found on this path. Items 1 and
2 are no-tap cold start; item 3 needs one in-app wallpaper apply (branches
3/4); item 4 is not reached from launch (§10); item 5 is the mechanism behind
item 3.

1. **`jb0.e()` ARGB expansion** (`jb0.java:412-445`) — **cold start, path 1**.
   A large but valid `ALPHA_8` theme mask (`12000x12000` = 144 MB, compressed
   PNG a few hundred KB) makes `Bitmap.createBitmap(w,h,ARGB_8888)` request
   576 MB; the allocation failure happens inside `draw()` with no catch ->
   process death (OOM/IAE) on every launch.
2. **Pattern renderer `b00`** (`e00.f`, §4) — **cold start, path 2**. A
   document `.tgv` with `width="1e30"`, a degenerate viewBox and hundreds of
   thousands of path/polygon points makes the renderer parse and draw
   unbounded data at startup (Java heap / CPU -> OOM/ANR). Screen-sized bitmap
   is allocated by construction; the growth vector is element count.
3. **`Theme.j` 24-px thumbnail** (`t6.java:4668`): `createBitmap(0,24)` for a
   cover-scaled `BitmapDrawable` wallpaper with `w/h < 1/24`. This needs the
   `.wp`/offset branches (3/4), i.e. an in-app wallpaper apply in the running
   process, so it is **not** a no-tap cold-start primitive on its own; it is
   listed because the analysis found it and it is one in-app action away.
4. **Video metadata** (`nGetVideoInfo`): a malformed MP4 with a large declared
   frame size becomes the Java bitmap size in `s5.a(Bitmap)` -> allocation
   failure. This is **not** reached from the launch wallpaper path (§10); it
   needs an `s5` created by ImageLoader (media cell / opened chat).
5. **`Theme.n1` upscale** (`t6.java:5237-5281`, call at 5275): an image with a
   dimension below the screen is cover-scaled; the failure itself is caught by
   `n1` (`catch (Exception)`), and a successful degenerate result feeds item 3.

The first RCE can install items 1 and 2 by writing the theme blob / the
corresponding file, and the app will crash on each launch until the file is
removed. That is persistent **DoS**, not code execution. It does not give a
controlled write, does not bypass SELinux/UID isolation, and does not run
attacker code.

---

## 7. Host model and PoCs

`../../lab/startup_wallpaper_bounds/model.py`:

```
selftest: tight bounds ok, synthetic short stride detected
blur area>22500 rejected: rejected: area/radius guard
stackBlur on ALPHA_8 rejected: rejected: format != RGBA_8888

bitmap/sink combinations checked: 131960
write-bound violations: 0

paired-bitmap sinks reject dimension/format mismatch: True | expandAlphaToBlack: rejected: dims

32-bit overflow thresholds vs heap:
  stackBlurBitmap area               needs >=  2,147,483,648 px =     8.00 GiB ARGB /   2048.0 MiB ALPHA_8
  generateGradient 2*area            needs >=  1,073,741,824 px =     4.00 GiB ARGB /   1024.0 MiB ALPHA_8
  writeFrameToBitmap temp            needs >=    536,870,912 px =     2.00 GiB ARGB /    512.0 MiB ALPHA_8
  applyAlphaInvert w<<2              needs >=  1,073,741,824 px =     4.00 GiB ARGB /   1024.0 MiB ALPHA_8
  expandAlphaToBlack 4*w             needs >=  1,073,741,824 px =     4.00 GiB ARGB /   1024.0 MiB ALPHA_8
  device large-heap ceiling (observed memoryClass=256 MB): 512 MiB
```

`poc_files.py` generates:

* `mask_1x4096.png`, `mask_4096x1.png`, `mask_1x60000.png`,
  `mask_60000x1.png`, `mask_12000x12000.png` (theme mask path);
* `wp_100x2500.png`, `wp_1x3000.png`, `wp_1080x2400.png` + `wp_names.txt`
  (MD5 naming for `files/<md5>.wp`);
* `pattern_big.tgv`, `pattern_negative.tgv`, `pattern_zero.tgv` (SVG path);
* `pcache2_oob_seek.bin`, `pcache2_negative_len.bin`,
  `pcache2_huge_len.bin`, `pcache2_count_10001.bin`.

These are reproducers, not exploits. Expected device results are listed in
`../../lab/startup_wallpaper_bounds/README.md`.

---

## 8. Device status and procedure

Executed (non-destructive):

```
adb logcat -c
adb shell am force-stop org.telegram.messenger.beta
adb shell am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity
# pidof -> 14395, no FATAL/AndroidRuntime in logcat
# screenshot: chat list rendered (1080x2394), theme background (jb0) applied
```

Cold-start logcat confirms the environment used in this note:
`memoryClass = 256`, screen `1080 2394`, build `v13.2.0 (72799) universal
arm64-v8a`, `loaded normal lib`.

Not executed: the destructive PoCs. They would crash the user's logged-in
client for the seconds before `restore` and only demonstrate the DoS in §6.
Procedure (root required, app not debuggable) is in
`../../lab/startup_wallpaper_bounds/device_plan.sh`:

1. `backup` — copies `shared_prefs/themeconfig.xml`, `mainconfig*.xml`,
   `files/cache4.db*`, `files/*.attheme`, `files/*.wp`,
   `files/*_v5.jpg`, `files/*_v8_debug.jpg`, `files/acache/` to
   `/data/local/tmp/wp_audit_backup_<stamp>`.
2. `reach` — replace the active accent's `*_v5.jpg` (the 0-byte placeholder
   is fine) with a 4x4 PNG, `am force-stop` + `am start`, screenshot, restore,
   restart. Confirms the theme mask is read from app data at cold start.
3. `dos-oom` — same file with `mask_12000x12000.png`; expected `FATAL
   EXCEPTION` / allocation failure in the `jb0` draw path; restore + restart.
4. `wp-dos <md5>.wp` — `.wp` URL-cache path; expected
   `OutOfMemoryError`/`IllegalArgumentException` in `n1`/`Theme.j`. This path
   needs an in-app wallpaper apply (runtime statics `h0`/`g0`), so it does not
   model a no-tap cold start.
5. `pcache <name>` — drop a crafted `acache/<name>.pcache2` for an animated
   wallpaper; expected caught Java exceptions / no write.

No test in this lab can produce a controlled write because the code has no
such sink on this path.

---

## 9. Why this is not ACE, and what would be needed

For ACE we would need a sink where an attacker-controlled **length or
destination geometry** is independent of the real `Bitmap` allocation. On the
audited path:

* destination geometry is always `AndroidBitmapInfo` of the bitmap being
  written (Skia-owned, not forgeable from app data);
* the paired-bitmap APIs reject mismatched dimensions/formats;
* the 32-bit products that could desynchronise size and loop bounds require a
  bitmap 4x larger than the whole heap;
* the SVG and `.pcache2` parsers are Java-side and throw before any native
  pointer arithmetic.

A future version would need re-auditing if (a) `copyBitmaps` loses the
`width/height/format` checks, (b) a new JNI function takes separate
source/destination dimensions without validating them, or (c) a wallpaper
path starts passing `Canvas`/`Path` coordinates to native code that computes
buffer sizes from them. None of that is present in 72799.

Limitations of this audit: the sink checks were read from Hex-Rays output and
modelled on the host, not re-executed under a JNI harness on the device; the
platform image decoders (Skia/libwebp/libjpeg/libpng) are system components
and only touched as "decode to a Bitmap" (their own bugs, e.g.
CVE-2023-4863, are covered by the separate note); the crash PoCs in the lab
were not executed against the user's logged-in client.

---

## 10. Follow-up (2026-11-03): animated/video wallpaper — *not* a launch FFmpeg surface

Question: does `Theme.loadWallpaper` at chat-list launch instantiate
`AnimatedFileDrawable` (`s5`) -> `AnimatedFileNative.nCreateDecoder` ->
`avformat_open_input` for a video/motion wallpaper, i.e. a launch FFmpeg
surface for a first RCE that writes theme data + a video file?

**Answer: no, for 72799.** The earlier cold-start FFmpeg refutation is not
limited to dialog-cell thumbnails here: the wallpaper path never creates a
decoder at all. The evidence is the same call chain the task names.

### 10.1 `Theme.J` never consumes a WallPaper/video document

`Theme.p1` -> `Theme.J` (smali `t6.smali:22407-23635`, 982 insns; called from
`o1`/`sh.run` as in §1). A full-method grep of the J range finds:

* no `Lorg/telegram/ui/xn;` (the video-capable wallpaper drawable),
* no `Lorg/telegram/messenger/ImageReceiver;`,
* no `Lorg/telegram/ui/Components/s5;` / `AnimatedFileNative`,
* no read of `m6.f20604t` (`TLRPC.WallPaper`) or `r6.f20745s`
  (`r6.java:167` / `J` args),
* only `jb0` (gradient/mask/pattern drawable), `e00.f`/`e00.c` (SVG/built-in
  pattern), `Theme.n1(FileInputStream,offset)` -> `BitmapDrawable`,
  `BitmapFactory`, `f9`/`GradientDrawable`, `ColorDrawable`.

So a video document placed in the global theme reaches `J` path 2:
`b8.K(document)` -> `e00.f(file, min, max, 2)` (SAX/SVG, §4). The video file
fails the SVG parse (Exception caught), `J` falls back to the built-in
pattern (`e00.c`) or a gradient. No FFmpeg is involved.

### 10.2 The video drawable is only created by ChatActivity / stories

`org.telegram.ui.xn` is the drawable that wraps an `ImageReceiver`:

```java
// org/telegram/ui/xn.java:44-95
public xn(TLRPC.WallPaper wallPaper, boolean z10, boolean z11) {
    ...
    ag.c2 c2Var = new ag.c2(this, 2);          // ImageReceiver
    ...
    TLRPC.Document document = wallPaper.document;
    if (document != null) {
        c2Var.q0(ic.b(document), sb3, b10, null, wallPaper, 1);
    } else {
        c2Var.w0(b10);
    }
```

Construction sites of `xn` / assignment of `jb0.imageReceiver`:

| site | context | at launch? |
|---|---|---|
| `sn.java:508` -> `xn.d(drawable, wallPaper, z10)` | `sn` is the resource provider built by `un` (ChatActivity) `un.smali:367397` and `rh/i.java:563` (settings fragment); `wallPaper` comes from the chat/theme settings | no (chat/settings opened) |
| `sn.java:525` -> `jb0Var2.f27300y = new ImageReceiver(...)`, `q0(ic.b(document), "80_80", ...)` | same provider, 80x80 wallpaper preview | no |
| `vh/k4` (`vh/k4.smali:1436`) | story/reply view | no |
| `org/telegram/ui/Components/f11` | story reply drawing | no |

`jb0.f27300y` is assigned **only** at `sn.java:525` (verified over all smali:
one `iput-object ... jb0;->y:` site). The `jb0` created by `Theme.J` leaves
the receiver null.

### 10.3 What LaunchActivity actually sets as the background

`LaunchActivity.onCreate` creates the drawer container `w8(this, null)`
(jadx `LaunchActivity.java:775`); the constructor sets `f42897f0 = 5`
(`w8.java:26-29`). `w8.getNewDrawable()` case 5 only handles the power-save
flag `tz.H0` and otherwise delegates to `uu0.getNewDrawable()`
(`w8.java:110-132`), which returns `t6.t0()` (`uu0.java:367-369`).
`t6.t0()` returns `f20960f0` or `f20942e0` (`t6.java:5812-5815`); both are
only ever set from `Theme.J`/`p1` results (`t6.java:5543`, `t6.smali:64307`
copies `e0`; `u1` resets them, no `xn`).

`uu0.U(drawable)` does support `xn`/`jb0` backgrounds (`uu0.java:258-292`),
but the drawable passed at launch is `t6.s0()`, i.e. the J result — a `jb0` or
`BitmapDrawable`, never an `xn`.

### 10.4 Prefs/files an app-UID writer controls (and why they don't help)

For completeness, the state a writer would set for a *chat-wallpaper* video
(not launch). Note: there is **no** `wallpaper` / `wallpaperFile` /
`wallpaperDocument` / `currentTheme` key in 72799; those public-source names
map to the nested fields below, and the global wallpaper is not a standalone
preference.

* `shared_prefs/themeconfig.xml`
  * `accents_<themeKey>` — Base64 of `SerializedData` v9: `int 9`,
    `int count`, then per accent (`t6.java:6315-6345`):
    `id, accent, outbox, color0..color3, bool animated, 4×int64,
    int intensity, int64 0, double intensity, bool blur, string wallpaperId,
    bool hasTheme, int themeSize, TL_theme.serializeToStream`;
    the nested `TL_theme.settings[0].wallpaper` is the `TL_wallPaper`
    (optionally with a `document`).
  * `accent_current_<themeKey>` (int), `lastDarkTheme` (string),
    `themes2` (JSON with `info` = hex `TL_theme`).
* `shared_prefs/chatthemeconfig_emoji.xml`
  * `chatWallpaper_<account>_<dialogId>` = hex `TL_wallPaper`
    (`g4.java:519-535`), used only when that chat is opened.
* `files/<themeName>_<accentId>_<wallpaperId>_v5.jpg` (mask),
  `files/<MD5(Theme.b1(m6))>.wp`, `.attheme` at `wallpaperFileOffset` — all
  app-writable, all decoded as `Bitmap`/SVG by `J`.
* The video file itself: FileLoader attach path from `b8.K(document)`
  (app-writable); it is only opened by `xn`/`s5`, i.e. after the chat (or
  story) that uses it is opened.

A global theme video document is not rendered by any launch component, so
writing these keys cannot produce a launch `nCreateDecoder`.

### 10.5 Device check

Cold start with `atrace` (category `view`, 14 s; app sections are captured —
17,034 section-begin records incl. `Choreographer#doFrame`, Skia ops):

```
adb shell am force-stop org.telegram.messenger.beta
adb shell "nohup atrace -t 14 -a org.telegram.messenger.beta view > /data/local/tmp/wp_trace.txt 2>&1 &"
sleep 1; adb shell am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity
# grep AnimatedFileNative / avformat / createDecoder -> 0 hits
```

The current install has pattern/static wallpapers (themeconfig accents carry
`application/x-tgwallpattern`; `wallpapers2` is empty), so this trace alone
does not exercise a video wallpaper; the static result above does. The trace
is reproducible with `../../lab/startup_wallpaper_bounds/trace_launch.sh`.

Read-only backups taken: `themeconfig.xml`, `cache4.db`, `cache4.db-wal`,
`cache4.db-shm` (no device writes; nothing to restore).

### 10.6 Decoder path (for the media agent, not reachable via wallpaper)

If the media agent pursues a startup video surface, the wallpaper is the wrong
entry. The actual path is:

```
ImageReceiver / ImageLoader -> s5 (AnimatedFileDrawable)
  -> AnimatedFileNative.nCreateDecoder        (0x74DC98)
  -> avformat_open_input (direct file when the stream arg is null,
     custom AVIO when streaming from AnimatedFileDrawableStream)
  -> VideoFrameReader -> FFmpeg 8.1.3 / dav1d 1.5.4 decoder
```

The remaining launch candidate is the dialog-cell last-message **video
document** (`ImageLocation.document != null`), which is outside this subtask;
the wallpaper contributes no decoder at launch.

**Verdict: the animated/video wallpaper is not a launch FFmpeg surface in
72799. It does not give the first RCE a startup decoder; no ACE/DoS
escalation beyond §6.**

---

## Appendix — exact symbols

```
Java_org_telegram_messenger_Utilities_blurBitmap              0x7476E4
Java_org_telegram_messenger_Utilities_stackBlurBitmap         0x74933C
Java_org_telegram_messenger_Utilities_drawDitheredGradient    0x7499C8
Java_org_telegram_messenger_Utilities_generateGradient        0x749DCC
Java_org_telegram_messenger_Utilities_generateQrBackdrop      0x74A334
Java_org_telegram_messenger_Utilities_copyBitmaps             0x74AB74
Java_org_telegram_messenger_Utilities_applySoftLight          0x74AD80
Java_org_telegram_messenger_Utilities_applyAlphaInvert        0x74B294
Java_org_telegram_messenger_Utilities_averageBitmapColor      0x74B770
Java_org_telegram_messenger_Utilities_expandAlphaToBlack      0x74B920
Java_org_telegram_messenger_Utilities_extractAlpha            0x74BAC0
Java_org_telegram_messenger_Utilities_nLibyuvARGBSaleBitmap   0x74B5BC
Java_org_telegram_ui_Components_AnimatedFileNative_nGetVideoInfo 0x74D6AC
Java_org_telegram_ui_Components_AnimatedFileNative_nCreateDecoder 0x74DC98
Java_org_telegram_ui_Components_AnimatedFileNative_nGetVideoFrame 0x74EAF0
writeFrameToBitmap                                            0x74E6B0
```

IDB function comments for all of the above were added in this session
(`save_database` in place; backup copy under
`<HOME>/ailocal/voda/.opencode/idbs/`).
