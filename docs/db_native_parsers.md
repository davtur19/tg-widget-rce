# DB/media → native code: parser audit for Telegram Android 13.2.0 beta (72799)

Date: 2026-11-02. Target: `org.telegram.messenger.beta` 13.2.0 (72799), arm64
(`libtmessages.49.so`, BuildId `645cce39…`). Host-only: no phone, no emulator.

Question: given arbitrary write to `cache4.db` and app data, which
**native parser** consumes those bytes, on **startup / chat-list render** if
possible, and is there a known memory-corruption bug in the bundled version?

---

## 0. Verdict (short)

- **No bundled media parser has a known, reachable memory-corruption CVE at the
  installed versions.** The media parsers are current (Aug–Sep 2026) and the
  Lottie engine was rewritten in Rust.
- **tlottie (Rust) replaced rlottie.** The whole rlottie CVE family
  (CVE-2021-31319/31323, CVE-2025-0634 UAF, CVE-2025-53075, the 2026
  `Gradient::populate` issues) **does not apply**. The parser code is safe Rust
  with depth limits; worst case is a `panic=abort` DoS.
- **FFmpeg is 8.1.3**, built with a minimal `--disable-everything` set. The
  recent FFmpeg CVEs either hit components that are **not compiled**
  (jpeg2000, WTV, filters, HLS/RTSP/TLS) or are **already fixed in 8.1.3**
  (`mov_read_ispe` bounds check is present). The only reachable known issues are
  post-release **DoS** (MOV `tfra` infinite loop, Matroska duration cast).
- **libvpx 1.17.0** (Aug 2026) contains the CVE-2026-2447/1861 fixes;
  **dav1d 1.5.4** and **opus 1.6.1** are current.
- The only **old** native parser reachable from app data is **SQLite 3.39.3**
  (`cache4.db`), reached **at startup**. Its in-range CVEs are **OOB read / UAF
  (info leak, DoS)**, not writes: CVE-2025-7458, CVE-2025-6965, CVE-2024-0232.
  They require arbitrary SQL, which a **malicious schema (VIEW named
  `messages_v2`)** does provide — but there is no write primitive.
- **Images (WebP/JPEG/PNG) are not parsed by libtmessages at all.** They go to
  Android's `BitmapFactory` (system libwebp/libjpeg-turbo/Skia). The one known
  RCE-grade path in this area is **CVE-2023-4863 (libwebp heap overflow)** via a
  cached avatar/photo file during chat-list render — **outside** libtmessages and
  **device-patch dependent**.

Best *practical* prototype: the framework WebP path (§6/§8) **if** the phone's
`ro.build.version.security_patch` is older than 2023-09-01. Best
*libtmessages-only* research target: FFmpeg `mov`/`matroska` demuxers + the
h264/hevc/av1/vp9 decoders (§7).

---

## 1. Parser inventory (inside `libtmessages.49.so`)

| Parser | Version / build | Evidence | Reachable from | Trigger |
|---|---|---|---|---|
| **tlottie** (Lottie/TGS, Rust) | submodule `31f1b54` (2026-09-11); crate 1.0.x | `jni/lottie.cpp` calls `tlottie_new_with_options`; parser error strings at `0x313646/0x31377c` match `tlottie/src/composition/parse.rs`; **no rlottie C++/RTTI/source-path strings** (the `Java_…RLottieNative_*` names are only the retained Java class name); `rlottie`-style messages are replicated in Rust | document mime `application/x-tgsticker` / `x-tgsdice`; TGS file | sticker / animated emoji / emoji-status render |
| **FFmpeg** | **8.1.3** (`Lavc62.28.103`, `Lavf62.12.103`) | strings at `0x28a5d5`, `0x246ca1`; `jni/prebuild/build_ffmpeg.sh` (configure list) | mov/mp4/m4a/3gp/heic/heif/avif, matroska/webm, ogg, gif, mp3, aac; decoders h264/hevc/mpeg4/mjpeg/gif/alac/libopus/mp3/aac/flac/libdav1d/libvpx_vp8/vp9 | GIF / video sticker / video / voice playback |
| **libvpx** | **1.17.0** | `0x22622b` "WebM Project VP8 Decoder v1.17.0" (VP9 Encoder/Decoder likewise) | VP8/VP9 via FFmpeg libvpx wrappers; WebRTC | video sticker (.webm), calls |
| **dav1d** | **1.5.4** | submodule `54706fc` (2026-07-14); `NEWS` headed "1.5.4 'Sonic'" | AV1 via FFmpeg `libdav1d` | AV1 video |
| **opus** | **1.6.1** (submodule `22244de`, 2026-01-13) | `xiph/opus` submodule = tag `v1.6.1`; `WebRtcOpus_*` strings | OGG/Opus voice messages; WebRTC | voice playback |
| **SQLite** | **3.39.3** (2022-09-05) | `0x4668ea` "3.39.3"; source id `2022-09-05 11:02:23 4635f4a6…`; `jni/sqlite/sqlite3.c` | `cache4.db` (open + schema + queries) | **app startup** |
| WebRTC / tgcalls / openh264 | vendor snapshots 2026 | `/voip/webrtc`, `CWelsH264SVCEncoder` strings | network call media | calls only |
| libyuv | vendor | `libyuv` symbols | pixel conversion | any video |

**Not in libtmessages:** libwebp, libjpeg-turbo, libpng, FreeType. No `RIFF`,
`WEBP`, `VP8X`, `VP8_STATUS` strings exist; no `WebPDecode*`/`jpeg_*`/`FT_*`
symbols. Image decode is `android.graphics.BitmapFactory` in Java
(`BitmapFactory.decodeFile` 28 sites, `decodeByteArray` in the emoji-pack reader
`n6.java:96`; stripped thumbs in `hc.java:252`).

---

## 2. Version evidence (raw)

```
Lavc62.28.103                    0x28a5d5   FFmpeg 8.1.3 libavcodec
Lavf62.12.103                    0x246ca1   FFmpeg 8.1.3 libavformat
WebM Project VP8 Decoder v1.17.0 0x22622b   libvpx 1.17.0
3.39.3                           0x4668ea   SQLite 3.39.3
2022-09-05 11:02:23 4635f4a6…              SQLite source id
mov,mp4,m4a,3gp,3g2,mj2,psp,m4b,ism,ismv,isma,f4v,avif,heic,heif   mov demuxer
```

`build_ffmpeg.sh` (public, same submodule generation) pins the media surface:

```
--disable-everything --enable-protocol=file
--enable-decoder=h264,hevc,mpeg4,mjpeg,gif,alac,libopus,mp3,aac,flac
--enable-decoder=libdav1d,libvpx_vp9 (+libvpx_vp8 when enabled)
--enable-demuxer=mov,gif,ogg,matroska,mp3,aac
--enable-parser=h264,hevc,mpeg4video,mpegaudio,aac,opus,av1,gif
--enable-muxer=matroska --enable-bsf=vp9_superframe,vp9_raw_reorder
--disable-network --disable-zlib
```

Corroborated by the binary (mov/ogg/gif/matroska/mp3/aac demuxer names; no
jpeg2000/png/webp/avi decoders compiled).

---

## 3. CVE match

| Component | Bundled | Relevant CVEs | In range? | Reachable? | Impact |
|---|---|---|---|---|---|
| rlottie CVEs | — | CVE-2021-31319, CVE-2021-31323, CVE-2025-0634 (UAF), CVE-2025-53075 (path trav.), 2026 `Gradient::populate` (CVE-2026-49510 family) | **No** | n/a | code is **not present** (tlottie is a Rust rewrite) |
| tlottie | 1.0.x | none published (repo created 2026-07) | — | yes (sticker) | safe Rust; `panic=abort` ⇒ DoS only |
| FFmpeg | 8.1.3 | CVE-2026-96611 (`mov_read_ispe` int overflow) | **fixed** (bounds check present at `mov.c:9409`) | — | n/a |
| | | CVE-2026-52295/52296/52297 (extradata padding OOB read) | **fixed** (`ff_alloc_extradata`/`AV_INPUT_BUFFER_PADDING_SIZE` in `mov.c` 8.1.3, e.g. iacb at `mov.c:935`) | — | n/a |
| | | CVE-2026-66036 (`vf_hqdn3d`), CVE-2026-70628 (WTV), CVE-2026-107660/675/676/677/695/696, CVE-2026-30754 (RTP), CVE-2026-90815/90816 (filters/HLS) | not compiled (no filter/avdevice/network) | **No** | n/a |
| | | `mov tfra` size-0 infinite loop (fix 2026-10-27) | **present** in 8.1.3 | yes (MP4) | **DoS** (hang in `avformat_open_input`) |
| | | Matroska duration float-cast (fix 2026-09-29) | present | yes (MKV) | UB / DoS |
| libvpx | 1.17.0 | CVE-2026-2447 / CVE-2026-1861 heap overflow (fix `d5f35ac`, 2026-01-22) | **fixed** (1.17.0 > fix; Debian marks 1.17.0-1 fixed) | — | n/a |
| dav1d | 1.5.4 | none in NEWS; no in-range CVE found | — | yes (AV1) | no known issue |
| opus | 1.6.1 | no in-range memory-safety CVE found | — | yes (voice) | no known issue |
| SQLite | **3.39.3** | CVE-2025-7458 (`sqlite3KeyInfoFromExprList` int overflow; fixed 3.42.0) | **YES** (3.39.2–3.41.1) | via crafted schema/SQL (startup) | OOB **read** (info leak / DoS) |
| | | CVE-2025-6965 (aggregate terms; fixed 3.50.2) | **YES** (< 3.50.2) | same | OOB **read** |
| | | CVE-2024-0232 (JSON1 UAF; fixed 3.43.2) | **YES** | same (JSON1 compiled) | UAF, SQLite calls it DoS |
| | | CVE-2025-7709 / CVE-2026-11822/11824 (FTS5) | no | — | FTS5 **not compiled** |
| **framework libwebp** | system (Android 13) | **CVE-2023-4863** heap buffer overflow | depends on device patch level | **yes, chat-list avatar** (see §6) | **RCE-capable** (public exploit) |

Note: SQLite's own CVE page classifies all of the above as requiring arbitrary
SQL, with "denial of service" as the realistic outcome. That matches the
analysis below.

---

## 4. Reachability: which bytes reach which parser, and when

### 4.1 What the DB stores, and what the app does with it

`cache4.db` is a plain SQLite DB (`jni/sqlite/sqlite3.c` compiled in;
`org.telegram.SQLite`). Relevant tables (`hs.java:167-177`):

```
users(uid INTEGER PRIMARY KEY, name TEXT, status INTEGER, data BLOB)
chats(uid INTEGER PRIMARY KEY, name TEXT, data BLOB)
dialogs(did INTEGER PRIMARY KEY, ..., last_mid INTEGER, data BLOB, ...)
messages_v2(mid, uid, read_state, send_state, date, data BLOB, media, ...)
media_v4(mid, uid, date, type, data BLOB, ...)
```

`data` is a TL-serialized object, parsed by **Java** (`SerializedData`), not
native. The **media bytes themselves are not in the DB**: only metadata plus
small inline thumbs. The real file is on disk under the app cache.

### 4.2 Photo / avatar path (framework decode — the startup path)

- `hc.java:629-631` builds the photo cache path:
  `<cacheDir>/<photoSize.location.volume_id>_<photoSize.location.local_id>.jpg`
  (`b8.z(0)` = cache dir).
- `hc.java:604` and the `ImageLoader` path call `BitmapFactory.decodeFile(...)`.
- Inline "stripped" thumbs (`photoSize.bytes`, `chat.photo.stripped_thumb`) are
  **wrapped in a hard-coded 623-byte JPEG header** by `hc.F()` (`js.java:22`
  `f16431c` = JPEG SOI/DQT/DHT/SOF0; `hc.java:252`), so those bytes can only be
  JPEG, not WebP. The **cache file** is the free-format input.
- **Chat-list trigger:** `Cells/k6.z(...)` (dialog cell) binds the peer avatar
  from `user.photo` / `chat.photo`; the avatar `ImageReceiver` loads
  `photo_small` from the cache path above at **app start / list render**, with no
  chat opened.

### 4.3 TGS / sticker / emoji-status path (tlottie)

- mime gate: `jj.java:967` (`application/x-tgsticker`, `application/x-tgsdice`).
- `RLottieNative.nCreate(path, json, …)` → `jni/lottie.cpp` →
  `tlottie_new_with_options` (§1).
- Drawable stack: `f5`/`bi0` (`RLottieNative.a(...)` in `bi0.java:320/371/733`).
- **Chat-list trigger:** emoji status is rendered by the dialog cell
  (`Cells/k6.java:238-252` → `d5.j(docId)` → `f5.m(account, docId)`; `f5` is the
  `AnimatedEmojiDrawable`, which draws through an `ag.c2` `ImageReceiver` bound to
  the status document). The TGS decode itself goes through `RLottieNative`
  (`bi0`/`zh0`); `RLottieNative.a(File,…)` is reached from `bi0.B()` and
  `RLottieNative.b(json,…)` from `zh0`/`Cells/q1`. Opening the app is enough
  **if** the peer has an emoji status and the TGS file is in cache. (Sticker
  messages need a chat open; the emoji-status case does not.)
- tlottie is memory-safe Rust; this is a **DoS-only** surface.

### 4.4 GIF / video-sticker / video (FFmpeg)

- `AnimatedFileNative` (`jni/gifvideo.cpp`, `VideoFrameReader`) → ffmpeg
  `avformat_open_input` + decoders. `s5.java` is the drawable; created when a
  GIF / `.webm` sticker / video is bound.
- `media3` `ExperimentalFfmpegVideoDecoder` (`jni/ffmpeg_jni.cc`) is the video
  player path (`PhotoViewer`, `nr0.java:36`, `w50.java:489`).
- Trigger: **chat open** (autoplay GIF/video sticker) or media viewer. Not the
  chat list.

### 4.5 Voice/audio (opus/ffmpeg)

- Playback only. No startup path.

### 4.6 DB (SQLite) — the only native parser at startup

- `org.telegram.SQLite.SQLiteDatabase_opendb` → `sqlite3_open` on
  `cache4.db`; the app then runs its schema statements and its queries
  (`hs.java:160-192`, `SELECT data FROM users/chats/...`).
- A malicious DB is parsed natively **before any UI exists**.

---

## 5. SQLite 3.39.3 — malicious schema runs SQL at startup (host-tested)

SQLite semantics allow a **VIEW** to occupy the name of a table the app thinks
it owns:

```sql
-- crafted cache4.db (set PRAGMA user_version to the app's current value)
CREATE VIEW messages_v2 AS
  SELECT json_valid('<crafted JSON>') AS mid, ... ;   -- 20 columns as expected
```

`CREATE TABLE IF NOT EXISTS messages_v2(...)` issued by the app is a no-op when
the name already exists (verified on the host with sqlite3 3.46.1: create view,
then `CREATE TABLE IF NOT EXISTS` → no error; `SELECT ... FROM messages_v2` →
the view's expression executes). So the app's own `SELECT` prepares/executes
attacker SQL at startup.

In-range SQLite bugs reachable that way:

- **CVE-2025-7458** — integer overflow in `sqlite3KeyInfoFromExprList` with a
  huge `ORDER BY` expression list → read past the array (info leak / DoS).
  Affects 3.39.2–3.41.1 (fixed 3.42.0). **3.39.3 is vulnerable.**
- **CVE-2025-6965** — aggregate-term vs column count truncation → read past
  array (info leak / DoS). Fixed 3.50.2.
- **CVE-2024-0232** — JSON1 `jsonParseAddNodeArray` UAF → crash (DoS). Fixed
  3.43.2.

**Honest assessment:** this is a genuine *native, startup, DB-content* path, but
the known bugs are **OOB reads / UAF**, not write primitives. Useful as an info
leak (e.g., heap bytes returned as message text) or a crash; **not a ready
RCE**. It also requires the app to tolerate a VIEW in place of `messages_v2`
(schema-version migrations must be disabled by setting `user_version`
correctly). A crafted `sqlite_master` alone (schema text) is parsed at open even
before queries; no CVE is known in that parser for 3.39.3.

---

## 6. Framework image decoder — the WebP path (outside libtmessages)

- Telegram has **no WebP decoder**; `BitmapFactory.decodeFile` is used for
  cached photos/avatars (`hc.java:604`, `ImageLoader`).
- Cache path is DB-controlled: `<volume_id>_<local_id>.jpg` (§4.2). The
  extension is irrelevant — `BitmapFactory` sniffs RIFF/WEBP.
- Trigger: **chat-list avatar at startup**, no chat open.
- **CVE-2023-4863** (libwebp VP8L Huffman table heap buffer overflow, exploited
  in the wild; fixed in Android 2023-09-01 bulletin) would give a controlled
  heap write in the app process. Whether it applies depends on the phone's
  `ro.build.version.security_patch` (Sony XQ-BT52, Android 13 — likely last
  patched in 2023, i.e. **probably vulnerable**; must be checked on-device).
- This is the only **known RCE-grade** path found, but it is the **platform**
  decoder, not a libtmessages parser.

---

## 7. Ranked shortlist

1. **Framework libwebp via cached avatar/photo (CVE-2023-4863)** — startup /
   chat list; known write primitive; **device-patch dependent**; outside
   libtmessages. Best practical candidate.
2. **SQLite 3.39.3 malicious schema** — startup, native, DB-content-only; known
   in-range CVEs are **info-leak/DoS** (CVE-2025-7458, CVE-2025-6965,
   CVE-2024-0232); no write primitive. Best *startup-native* candidate; good
   info-leak primitive.
3. **FFmpeg 8.1.3 (mov/matroska + h264/hevc/av1/vp9)** — no known RCE; the only
   reachable known bugs are DoS (`tfra` hang, Matroska duration cast). Biggest
   **unknown-bug** surface; needs chat/media view (or an autoplaying sticker).
4. **tlottie** — memory-safe Rust; no memory corruption; `panic=abort` DoS at
   most. The rlottie CVE family does not apply.
5. **libvpx 1.17.0 / dav1d 1.5.4 / opus 1.6.1** — current; no known in-range CVE;
   only reachable from video/voice playback.
6. **openH264 / WebRTC / tgcalls** — call media only, not file parsers.

---

## 8. Best candidate to prototype first

**Framework WebP avatar (CVE-2023-4863)** if the device patch level permits;
otherwise **FFmpeg mov/matroska fuzzing** as the best libtmessages-only target
(no known bug — this is research, not an exploit).

Prototype plan for the WebP path (needs the next on-device agent):

1. `getprop ro.build.version.security_patch` (and `ro.build.fingerprint`). If
   `< 2023-09-01`, system libwebp is CVE-2023-4863-vulnerable.
2. Pick a dialog peer (self / Saved Messages user row, or a group chat row).
   Decode `users.data` / `chats.data` TL blob, locate `photo.photo_small`
   (`PhotoSize` with `location.volume_id`, `location.local_id`; set `dc_id`,
   `file_reference` as needed), set `volume_id=V`, `local_id=L`, re-serialize.
   Keep `stripped_thumb` valid (or absent) so the placeholder path still works.
3. Write the PoC WebP to
   `/data/user/0/org.telegram.messenger.beta/cache/<V>_<L>.jpg` as UID 10357.
4. Restart the app (cold start) and stay on the chat list. The avatar
   `ImageReceiver` decodes the file → system libwebp.
5. First test with a **non-weaponised** malformed WebP that crashes libwebp;
   confirm a tombstone in the app process with the fault in `libwebp.so`
   (`BuildHuffmanTable`/`VP8LDecodeImage`). That proves reachability and the
   vulnerable build. Only then attempt control-flow work.

Why this fits the constraints: no root, no widget UAF, no chat opened; the
bytes are in app data + DB only.

Fallback if the patch level is recent: the SQLite schema route (startup, native)
for an **info leak**, and FFmpeg demuxer fuzzing for a new bug.

---

## 9. Host-only test plan (what can be done without the phone)

- **SQLite view semantics** — done on host: `CREATE VIEW messages_v2`, then
  `CREATE TABLE IF NOT EXISTS messages_v2(...)` → no error; view SQL executes on
  `SELECT`. Reproduce with a 3.39.3 build (`sqlite3.c` from the APK's
  `jni/sqlite/sqlite3.c`) to confirm the CVE-2025-7458 OOB read with a crafted
  view (`ORDER BY` with a large expression list) under ASan.
- **FFmpeg `tfra` DoS** — craft a minimal MP4 (`ftyp` + `moov`/`mfra` with a
  `tfra` box of size 0); `ffmpeg 8.1.3` host build hangs in
  `avformat_open_input` (same code as bundled). DoS only.
- **tlottie** — build `dkaraush/tlottie` at `31f1b54` and fuzz
  `src/composition/parse.rs` (cargo-fuzz); the crate already has `src/tests/dos.rs`
  and depth limits, so expect panics/aborts, not memory corruption.
- **WebP** — prepare the CVE-2023-4863 PoC and the DB patch script; execution
  needs the device.

---

## 10. Limits of this report

- Host-only; the phone was not touched. The device patch level and the actual
  `cache4.db` layout at 72799 are **not** verified here.
- FFmpeg build flags are from the public `build_ffmpeg.sh` at the same submodule
  generation; the binary's demuxer names and version strings corroborate, but
  the exact 72799 prebuilt set could differ in a minor flag.
- tlottie version is inferred from the submodule commit plus the parser strings;
  it is a few commits around 1.0.6.
- "No known CVE" is not "no bug": FFmpeg 8.1.3 and the framework codecs remain
  the largest unproven surfaces.
