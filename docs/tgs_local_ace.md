# TGS / tlottie as a *local* ACE: cold-start paths, the corrected race, and leak-vs-no-leak

Date: 2026-11-03. Host-only pass (no phone, no emulator used for this note);
device steps are marked **DEVICE-PENDING**. Lab: `lab/tgs_local_ace/`.
Companion to (and correction of) `notes/tgs_uaf_weaponization.md`,
`notes/loader_tgs_native.md`, `notes/tlottie_gzip_audit.md`.
This note does not modify the main report.

Target: `org.telegram.messenger.beta` 13.2.0 beta **72799**, arm64,
`lib/arm64-v8a/libtmessages.49.so` 27,016,000 B, md5
`2c0caa68a07fc26f79d13519af6c3526` (verified: the apktool/dex tree used below
is `base_dec` of that APK). Pinned tlottie `31f1b54`
(`Android/TMessagesProj/jni/lottie.cpp`, 13.1.1 tree = same file for this pass).
Assumed attacker: app-UID shell (UID 10357) + arbitrary writes to `files/`,
`cache/`, `shared_prefs`, and the SQLite DBs; **no ptrace**, no `/proc/<pid>`
of the app (dumpable=0), no in-process JS unless a widget is rendered.

Conventions: `S/` = `/tmp/opencode/dbgbuild/smali72799` (72799 apktool),
`J/` = `/tmp/opencode/jadx72799_full/sources` (72799 jadx, same build),
`N/` = `Android/TMessagesProj/jni`; `L/` = `lab/tgs_local_ace`.
Class names are the 72799 R8 names; the readable identity is given once and the
identification evidence is in §1.1.

---

## 0. Verdict (short)

| Question | Answer |
|---|---|
| Is there a TGS path reachable from a **local DB row with no widget and no user tap** at cold start? | **Yes.** The dialog list draws custom-emoji spans from the last message's entities and from a custom-emoji reaction prefix. No other startup component runs the TGS parser (notification service and the app widget are static). |
| Is a crafted `cache4.db` + one `.tgs` file sufficient? | **Yes**, plus (for the file path) writing `cache/<dc>_<id>.tgs` (or a `file_to_path.db` row) — all inside app data. `animated_emoji` supplies the `TLRPC.Document`; the entity only carries `document_id`. |
| Does the earlier "81 % hit rate" model apply to 72799? | **No — it overstates it.** The 72799 `RLottieDrawable` (`ci0`) has an in-flight guard (`P`) and a deferred-destroy flag (`V`): while any `ImageReceiver` is attached, `C()`/`p()` defer `D()`. The exploitable interleaving is narrower: the **last receiver detached** (`v()==false`) **and** a frame still in flight **and** a `C(false)` (cache eviction / `clearImage`) arriving in that ≤ one-render window. `n()` only clears `P` when `v()==false`, which is exactly how the guard is bypassed. |
| Can a huge/slow TGS widen the *victim's* JNI prologue deterministically? | **No.** `nCreate` can be made slow (measured 0.05–0.2 ms @4.5 KB, 0.3–0.9 ms @1 MB, 2.5–15 ms @8 MB on host, load-dependent), but that is the *creating* thread; `tlottie` has **no global lock**, so it neither blocks nor extends the victim's `nGetFrame`. The victim's window is the render call itself, bounded by `Limits::max_render_work` (14 ms @96 px measured previously; ~19 ms @144 px). |
| Does the startup burst itself produce the free-during-render? | **Allocation: yes; free: no (deferred).** N emoji in one message create N `TLottieInstance`s in a burst (a real, self-contained 0x670 groom), and the 10 MB drawable cache starts evicting at ~284 ARGB 96×96 drawables. But the evicted drawables are still *attached*, so `C()` sets `V` and the destroy is deferred to the next frame completion. The free only lands inside a render for a **detached** drawable. |
| Any content-driven synchronous destroy? | **No.** A 1-frame TGS *disables* the race (`w()` blocks `I()`); a 0-frame or fps>60 document is rejected in `writeMetadata` → `nCreate` returns 0 and the app deletes the file; the animation-end callback runs *after* the last render; the colour-rebuild `old.d()` runs on the executor thread. |
| Does a `/proc/self/maps` leak (SVG XXE) turn the UAF into ACE? | **Not by itself.** With known bases the fake instance's `comp`/walker/`rasters` pointers become valid addresses, giving (a) an atomic **+1** at a chosen address (paired with a drop → net 0 unless the process dies inside `render`), (b) reads through chosen pointers, (c) a **104-byte** `Vec::push` write at `ptr + len*104` whose content is a `Rasterizer`, not attacker bytes, (d) `free(chosen_ptr)`. There is **no executable target** (W^X), GOT/RELRO is read-only, and the Rust object has **no vtable**. It is a heap-corruption primitive, not control flow. |
| Single-threaded parser/rasterizer fuzz: any non-race write/UAF? | **None found** in the pinned `tlottie 31f1b54` with ASan+UBSan: 73.5M executions (768-seed corpus, structure-aware mutator, 4+3 workers) plus 73 limit-boundary documents (§11). The unsafe surface is small and every kernel/mapping is length-clamped (§11.4). |
| Any deterministic, non-race impact from a crafted TGS at cold start? | **Yes, DoS only: unbounded read → OOM/abort.** A gzip TGS is decompressed into a Java `String` with no size cap; a plain TGS is read by `lottie.cpp readFile()` into a `std::string` with no cap. One DB row + one file kills the process at every cold start (§12). This is a kill switch, not ACE. |
| End-to-end local ACE? | **No.** Best defensible claim: *cold-start, no-interaction, race-dependent memory corruption → crash/DoS* (reliable enough for a kill switch / crash loop), plus a **constructed attacker-bytes reclaim payload** for the 0x670 block (§4, `pocs/marker.json`, DEVICE-PENDING) that becomes a *conditional* data-only primitive with a leak. No controlled write to a code pointer was found. |

---

## 1. Every TGS path from local data (exact refs)

### 1.1 Class identification (so the refs can be trusted)

| 72799 class | Identity | Evidence |
|---|---|---|
| `RLottieNative` (`S/smali_classes3/org/telegram/ui/Components/RLottieNative.smali`) | JNI wrapper | `nCreate` :511, `nCreateWithJson` :514, `nDestroy` :517, `nGetFrame` :520, `c(...)` :525, `d()` :606, `finalize` :693 |
| `ci0` | `RLottieDrawable` | extends `BitmapDrawable` + `Animatable`; 4-thread `R0` / 2-thread `S0` pools; 7182 smali lines; `C/Z` :2680, `D/Z` :2807, `I()` :3242, `draw` :4886, `finalize` :4917, `l` :5556, `n` :5797, `p` :5981, `start` :6712, `stop` :6819, `v()` :6919 |
| `bi0` | frame-task `Runnable` switch | `run()` :40; case 5 = `f(ci0)` (worker), 1 = `P=null; p()`, 2 = `h()`, 4 = `d(ci0)`, default 6 = `m()` |
| `eb0` | posted destroy wrapper | `eb0(ptr, 15)` → `RLottieNative.d()` at :848 |
| `f5` | `AnimatedEmojiDrawable` | 5149 smali lines; `m(IJLjava/lang/String;I)` make :493, `l(I,I,Document)` :338, `i(Z)` build :1646, `draw` :1476, `u()` attach-state :4423, `r(IZ)` :702 |
| `b5` | `AnimatedEmojiDrawable.EmojiDocumentFetcher` | `b(J,Lc5;)` fetch :108; DB in `y4` :283 (`SELECT data FROM animated_emoji WHERE document_id IN (`) |
| `o5` | `AnimatedEmojiSpan` | ctors :69/161/172/186; `drawAnimatedEmojis` :?; `update(...)` called from cells |
| `q1` | `DialogCell` | extends `Cells.z`; 263,838 smali lines; 5× `o5.drawAnimatedEmojis`, 7× `o5.update`; `k5` emoji stacks; theme keys `drawableMsgSticker*` |
| `lc` | `ImageLoader` drawable-cache entry (`entryRemoved`) | `a()` :68, `ci0.C(false)` at :205 |
| `lb` | `ImageLoader.DrawableCache` (LruCache) | `ic.e` = `new lb(ic)` → limit `0xa00000` (10 MB), `sizeOf` = w*h*4 for `ci0` |
| `b8` | `FileLoader` | `z(int)` = `getDirectory`, media dirs |

### 1.2 Document → drawable → `nCreate` (the single common tail)

All DB-driven TGS paths funnel through the same code, which is why the race and
the heap object are identical for emoji, stickers and reactions:

1. `ImageReceiver.setImage(ImageLocation.getForDocument(document), filter, …, document, 1)`
   (`S/smali/org/telegram/messenger/ImageReceiver.smali`, `Y()`/`S(...)`).
2. `ImageLoader` (`ic`) marks the location `IMAGE_TYPE_LOTTIE` when
   `document.mime_type == "application/x-tgsticker"` or `"application/x-tgsdice"`.
3. The `CacheOutTask` (`xb`, `run()` at :8951) reads the cache file; when it
   starts with the gzip magic it gunzips to a Java `String` (`decompressGzip`,
   no size cap) and constructs
   `new ci0(file, json, w, h, cacheOptions, limitFps, colorReplacement, fitz)`
   (`xb` :2409 with json, :2451 with `null`).
4. The `ci0` ctor calls `RLottieNative.a(path, json, …)` → JNI `nCreate`
   (`N/lottie.cpp:134`): `std::string input` ← `GetStringUTFChars` copy, then
   `tlottie_new_with_options(input.data(), input.size(), …)`.
5. `tlottie_new_with_options` = parse + `Box<TLottieInstance>`; the instance
   request is **1320 B** on arm64 (`0x528`) → Scudo class **0x670** (1648).
6. `ImageReceiver`'s setter (`J/…/ImageReceiver.java:1928`) registers itself in
   `ci0.I0` when attached and calls `ci0.start()` + `ci0.J(true)` → the first
   `nGetFrame` is posted **immediately**, before the first draw. So a bound
   `DialogCell` starts the animation without the cell being visible.

Media path (default, no SD card): `ImageLoader.createMediaPaths()` only fills
`MEDIA_DIR_CACHE`; `FileLoader.getDirectory(MEDIA_DIR_DOCUMENT)` falls back to
it, so the file is

```
/data/user/0/<pkg>/cache/<dc_id>_<id><ext>
```

with `ext` from `TL_documentAttributeFilename` (e.g. `poc0.tgs`) or empty
(`getExtensionByMimeType()` returns `""` for `x-tgsticker`).
`FileLoader.getPathToAttach()` first asks `file_to_path.db`
(`files/file_to_path.db`, `paths(document_id, dc_id, type, path, flags)`); a
row there redirects the path arbitrarily (attacker-controlled).
No size check applies to `ungzip` documents (`FileLoadOperation` skips
`totalBytesCount != length` when `ungzip`), so any file content is accepted.
`lottie.cpp:readFile` uses `gzopen`, which accepts **gzip or plain JSON**;
the Java `decompressGzip` path passes the JSON string only for gzip files.

### 1.3 The paths

| # | Path | Local source (exact) | Cold start? | Notes |
|---|---|---|---|---|
| **P1** | custom emoji in the **dialog-list last-message text/caption** | `messages_v2.data` (TL-message with `entities` = `TL_messageEntityCustomEmoji` 0xc8cf05f8, `document_id`) + `animated_emoji(document_id, data=TL_document)`. `q1` (`DialogCell`) `o5.update(...)` → `f5.m/l` → `b5.b` → DB → `f5.i(Z)` → ImageReceiver → `ci0` | **Yes** — chat list is the default start screen; drawables are created at bind (`setText`), not at first draw | Needs `animate emoji` not disabled by the user (`SharedConfig`) — attacker can set the pref in `shared_prefs`; also premium emoji render for non-premium only as far as the span exists, which the DB controls |
| **P2** | custom-emoji **reaction prefix** in the dialog cell | `messages_v2.data` `reactions.recent_reactions[0].reaction = TL_reactionCustomEmoji(document_id)` + `animated_emoji` row; span built in `MessageObject`/`kj` (:10 `o5.<init>(J…)` sites) | **Yes** (same cell/layout as P1) | 13.1.1 source `DialogCell.java:1714` sets `new AnimatedEmojiSpan(visibleReaction.documentId, …)`; 72799 keeps the same shape |
| **P3** | custom emoji in a **message bubble** (chat open) | same as P1, entities of any message | No (opens the chat; may be the restored screen) | same tail, bigger render size → longer window |
| **P4** | **TGS sticker** message (chat open) | `messages_v2.data` media.document (`mime=application/x-tgsticker`) + media file | No | `DialogCell` has **no** sticker preview (no `isSticker` branch in 13.1.1 `DialogCell`), so a sticker as *last message* does **not** run the parser in the list |
| **P5** | **reactions** UI (chips/effects, chat open) | `ReactionsUtils.java:185/188/201` → `AnimatedEmojiDrawable.make(..., document_id)` → `animated_emoji` | No | same tail |
| **P6** | sticker keyboard / set covers / featured stickers | `sticker_sets`-derived documents; `f5`/`ci0` | No (panel opened) | same tail |
| **P7** | notifications | `NotificationsController` builds the large icon from a document **thumb** (`PhotoSize`) | **No Lottie at all** (verified: no `RLottieDrawable`/`AnimatedEmojiDrawable`/`AnimatedFileDrawable` in the class) | — |
| **P8** | app widget (`ChatsWidgetProvider`) | static `RemoteViews` + avatar bitmaps | **No Lottie** (verified: no Lottie references in provider/service) | — |
| **P9** | dice (`x-tgsdice`), premium emoji status, QR/avatar previews | bundled resource ids / server objects | n/a | not DB-steerable |

**Conclusion for the startup question:** the only no-interaction, DB-only TGS
surfaces are **P1** and **P2**, both in `DialogCell`. They share the exact same
native object and race as the chat-open paths; the wrapper/locking is identical
(there is no per-path lock).

---

## 2. The 72799 lifecycle, corrected

### 2.1 The JNI wrapper (unchanged from the earlier note)

```
RLottieNative.c(frame,bmp,clear)            RLottieNative.d()
  if (recycled.get()) throw ISE               if (CAS(false,true)) {
  ptr = b;              // read after check   ptr = b; b = 0;
  nGetFrame(ptr,...)    // render             nDestroy(ptr);  // tlottie_drop
                                              }
```

`c()` :525-604 and `d()` :606-690 in `S/…/RLottieNative.smali`; `nDestroy` is
`MOV X0,X2; B tlottie_drop` (8 bytes, `libtmessages.49.so` `0x750220`),
`tlottie_drop` at `0x1094884` in the 72799 binary (prior note §1.1/§4.1).

The race condition is therefore *not* "a destroy during the 14 ms render is
enough": the pointer read must happen **before** `d()` stores 0, and any
`d()` after that point frees an instance the executor is still inside. In
practice `c()` reads `b` a few instructions after the check, so `d()` starting
any time after the frame task enters `nGetFrame` is a hit.

### 2.2 `ci0` does have a guard — and where it leaks

Fields (72799): `P` = in-flight frame `Runnable`, `O` = cache-gen task,
`V` = destroy pending, `k0` = isRunning, `l0` = dead, `I0` = receivers.

```
C(z):  k0=false; l0=true; l(); n();
       if (P!=null || O!=null || x0) { V=true; return; }
       D(z);
D(z):  r=m0; m0=null; post eb0(r,15) to main (z) or Utilities.e (background)
p():   if (V) { n(); if (P==null && O==null && m0!=null) D(true); }
       ...
       if (!v()) stop();          // stop() = k0=false + l() (ticker, not destroy)
       if (k0) I();               // post the next frame
n():   cancel O; if (v() || R==null || P==null) return; P=null; R=null;
v():   !I0.isEmpty() || view != null || getCallback() != null
```

`n()` clearing `P` when `v()==false` is the guard's hole: `C()` then sees
`P==null` and calls `D()`. Everything else is consistent.

**Destroy call sites (72799):**

| site | thread | condition |
|---|---|---|
| `lc.a()` :205 (`ImageLoader.DrawableCache.entryRemoved`) | whichever thread puts/trims the cache (ImageLoader threads) | drawable cache eviction over the **10 MB** limit (`lb` limit `0xa00000`, `sizeOf` = w*h*4 → ~284 ARGB 96×96 drawables (more at the 57–78 px emoji sizes)) |
| `ImageReceiver.S(int,String)` :3661 (`f()`/`clearImage`) | UI | last reference and the key is no longer in the drawable cache |
| `ci0.finalize()` :4917 → `C(false)` | finalizer | object unreachable (the queued frame task keeps it reachable, so this is mostly a no-op) |
| `ci0.D()` from `p()` | UI | only when `V` and no task in flight |
| `ci0.B()` colour rebuild (`m0.d()` at :353) | executor | same thread as the render — no cross-thread race |

### 2.3 What this changes relative to `tgs_uaf_weaponization.md`

* The earlier model called `RLottieNative.d()` at a uniform time during
  playback; with the real guard that destroy is **deferred** whenever the
  drawable is attached. The 81 % figure is a property of the model, not of the
  app.
* The real trigger is: **last `ImageReceiver` detaches** (cell recycled /
  `f5.u()` → `ImageReceiver.R()` → `B.F(this)`), **one render still in
  flight**, and a **cache eviction** (`lc.a`) in that ≤ one-render window.
* `stop()` is not a destroy path (it calls `l()` = the 60 fps ticker `m()`),
  contrary to a literal reading of the Java names.

---

## 3. Angle 1 — can a huge/slow TGS widen the window?

Measured with the pinned tlottie staticlib, host x86_64
(`L/build_alloc_probe`, `src/alloc_probe.cpp`, `R3`):

| JSON size | `tlottie_new_with_options` |
|---|---|
| 4.5 KB | 0.19–0.21 ms |
| 100 KB | 0.11 ms |
| 1 MB | 0.85–0.87 ms |
| 8 MB (≈ the 13 MB `max_parse_bytes` region) | **2.5–14.7 ms** |

`Limits::default()` (`src/composition/limits.rs:106-143`): `max_layers 2304`,
`max_parse_bytes 13 031 466`, `max_render_points 1 048 576`,
`max_render_work 4 194 304`. There is **no global mutex**
(`grep Mutex/RwLock src/bindings/c_api.rs` → none), so:

* A slow `nCreate` only slows the *creating* thread. It cannot extend the
  victim's `nGetFrame`, and it does not serialise against `tlottie_drop`.
* What a slow create *does* buy: a longer **allocation stream** (the JSON
  string + the new instance + parse Vecs) during which a freed 0x670 block can
  be reclaimed (§4), and more time for the UI thread to reach a `C()`.
* The Java side adds two more copies for the same document: `decompressGzip`
  (whole file → Java `String`, no cap) and `GetStringUTFChars` +
  `input.assign` (two native copies). For an 8 MB gzip the Java side alone is
  tens of ms and a 8–16 MB native allocation — but again on the loader thread.
* The *render* window stays bounded by `max_render_work`. Prior measurements:
  14.1 ms at 96×96, 18.75 ms at 144×144 for the 60-layer payload; a larger
  canvas hits the work limit instead of running longer.

**Negative result:** a big TGS cannot make the destroy synchronous with the
render. It can only make the *groom* denser.

---

## 4. Angle 2 — the self-contained startup groom (and what it can reclaim)

### 4.1 The groom is real and attacker-shaped

One last message can carry N `TL_messageEntityCustomEmoji` entities, each with
its own `document_id` → N `animated_emoji` rows → N `f5` drawables → N
`ImageLoader` tasks → **N `nCreate` calls**, on the ImageLoader threads, right
after the dialog cell binds. With 4 emoji per dialog and ~10 bound dialogs the
startup burst is ~40 instances; with 30 emoji in one message it is 30 for a
single cell. Every drawable also **starts animating immediately**
(`ImageReceiver` setter calls `start()` + `J(true)`), so the burst is
concurrent with rendering.

`L/src/make_poc_db.py` builds exactly this DB (`poc4.db`: 4 entities, 4
documents, 4 media files; verified by re-parsing the TL-lite blobs).

Measured with real Scudo on the host (`build_alloc_probe_scudo`, R1/R4/R5):

* inside one `nCreate`, the `TLottieInstance` is allocated after the JSON
  buffer; the host build's instance request is 1152 B (arm64 72799: 1320 B) —
  both in class 0x670;
* the freed block is sometimes reclaimed by the very next `nCreate` (trace
  seq 83/124 = the next create's instance) and sometimes not within 300
  creates; the reuse depends on the allocator state (per-thread cache vs
  central list) and is **not** something the attacker can time;
* with the Android-doc quarantine
  (`quarantine_size_kb=256:thread_local_quarantine_size_kb=64:quarantine_max_chunk_size=2048`)
  the block did not reappear within 300 `nCreate` calls (≥600 same-class
  allocations) in this harness, i.e. the quarantine delays the reclaim far
  beyond a single 14 ms window. This is *stricter* than the earlier "217
  allocations" figure and should be re-measured on the device;
* the host tracer cannot see the JSON `std::string` itself (libstdc++
  allocates through the shared library, outside `-Wl,--wrap`), so the
  string-vs-instance ordering in the app is inferred from `lottie.cpp`
  (`input.assign` happens before `tlottie_new`), not measured here.

### 4.2 What the reclaim gives

Two distinct reclaimers, with different value:

1. **A new `TLottieInstance`** (another emoji's `nCreate`) — a *valid*
   `CPURenderer` lands on the freed block. The stale render of the victim then
   operates on a live object of the same type: a data race on
   `rasters`/`surfaces`/`walker`, double-free of raster buffers, Scudo abort.
   **This is a crash primitive** (prior lab: 1/20 with Scudo, 8–9/20 with
   ASan/plain).
2. **The attacker's JSON string** (1089–1632 B) — attacker bytes land on the
   freed block. `CPURenderer::render` reads `model_validated` at `+0x50B`
   (nonzero in JSON text → `validate_model` skipped), `comp` at `+0x4F0`, then
   `mem::take(walker)` at `+0x000`. A JSON text can carry `AAAAAAAA` at those
   offsets while remaining a legal Lottie document; `L/src/gen_payloads.py`
   builds `pocs/marker.json` (1574 B, class 0x670, `AAAAAAAA` at `0x4F0`,
   byte `0x50B` = 0x22) verified to parse and render on the host. If such a
   string is the reclaimer, the renderer dereferences
   `0x4141414141414141` → a tombstone whose fault address is
   `0x4141414141414199` proves attacker bytes became the `CPURenderer`.
   Its lifetime, however, is only the `tlottie_new` call (µs for a 1.5 KB
   JSON), so it must land in the narrow slot between the free and the
   renderer's first read of the object.

   **Host limitation:** the x86_64 build's `TLottieInstance` is 1152 B, so
   offsets `≥ 0x480` are *outside* the block on the host and the marker cannot
   be validated there (the arm64 72799 object is 1320 B and the offsets come
   from its disassembly). `pocs/marker.json` is therefore a **device** payload;
   the host check is only "it is a legal Lottie document in the right class".

### 4.3 The startup burst does *not* free during a render

The drawable cache (10 MB, `sizeOf` = w*h*4) starts evicting after ~284 ARGB
96×96 drawables — reachable in a startup burst. But the evicted drawables are
still **attached** (`I0` non-empty), so `C()` sets `V` and the destroy waits
for the frame completion; the free is *deferred*. The parser cannot be made to
free its own instance while rendering it from inside a single message.

**So the startup groom supplies allocations, not the free.** The free still
needs a detach: scroll/rebind, cell recycle, or leaving the list.

---

## 5. Angle 3 — sticker/reaction paths: same object, same timing

* The chat list does **not** render a TGS sticker as the last message (no
  `isSticker` branch in `DialogCell`); it shows a text/emoji placeholder. The
  reaction prefix (P2) *is* rendered as an `AnimatedEmojiSpan` and therefore
  runs the TGS parser at startup.
* All paths share `ImageReceiver` → `ImageLoader` → `ci0` → `RLottieNative`;
  there is no alternative wrapper, no per-path lock, no per-path thread. The
  only difference is the target bitmap size: a sticker in a bubble is much
  larger than a 19/20/26 dp emoji, so `nGetFrame` is longer (more work per
  frame) — the *window* is bigger, the *race* is identical.
* Reactions in the message bubble draw through the same `AnimatedEmojiDrawable`
  cache (`CACHE_TYPE_SAVED_REACTION`), so an emoji document shared between a
  reaction and a message reuses the same `f5`/`ci0` (one instance, several
  `ImageReceiver`s), which *reduces* the detach window (the shared drawable
  stays attached while any user is attached).

---

## 6. Angle 4 — can a crafted TGS force a synchronous destroy?

Checked all content-driven paths:

| candidate | result |
|---|---|
| **1-frame animation** | `ci0.w()` (`Q!=null && e[0]==1`) makes `I()` return false → no frame task at all → **race disabled** |
| **0 frames / fps 0 / fps>60 / frames>600** | `lottie.cpp:writeMetadata` returns false → `nCreate` returns 0 → `ci0` logs `nativePtr == 0 … remove file` and **deletes the cache file** (a useful reachability marker, §8) |
| **animation end** | `i()` sets `N=true` and runs the end callback; the destroy (if any) is posted *after* the render returns |
| **render error (`-3` LimitExceeded)** | `f(ci0)` posts the retry runnable (`v0`) on the UI thread; no destroy |
| **colour replacement** (`setColor`/layer replacement) | `B()` re-creates and calls `old.d()` **on the executor thread** — same thread as the render, not a cross-thread free |
| **`limitFps` / `S0` 2-thread pool** | changes the pool, not the guard |
| **`clearImage`/`setImage` on the same receiver** | `S()` → `C(false)` while the receiver is still in `I0` → `V` → deferred |

**Negative result:** no TGS content can make `nDestroy` run during the same
instance's `nGetFrame`. The destroy is always framework-driven.

---

## 7. Leak vs no leak (SVG XXE `/proc/self/maps`)

Assumption for this section: another primitive (SVG `SvgHelper`/AndroidSVG 1.2.2
XXE, being verified by the SVG agent) leaks `/proc/self/maps` of the **same
process**, before the TGS instance is created. The attacker can then rewrite the
`.tgs` file from its shell (the file is read only when the drawable is created,
and the emoji is only created when its cell binds).

### 7.1 What the leak unlocks

With real addresses, the marker in §4.2 is replaced by a **valid fake
`CPURenderer`**:

| field | meaning with a leak |
|---|---|
| `+0x50B` `model_validated` | `1` → `validate_model` skipped |
| `+0x4F0` `comp: Arc<Composition>` | any mapped address; `render` does `LDRB [comp+0x58]` then `*(u64*)comp += 1` (LDXR/STXR) |
| `+0x000…` `walker: FrameWalker` | Vec/HashMap pointers used by `render_validated` → attacker-chosen reads |
| `+0x2B0…` `RenderScratch` | `Vec<Rasterizer>` header; `put_raster` does `push()` → writes 104 bytes at `ptr + len*104` |
| end of `render` | `self.walker = walker` writes 0x260 bytes back; `Vec::drop` frees attacker pointers |

### 7.2 Why this is still not a control-flow primitive

1. **No executable target.** Android is W^X for the app process; the heap is
   `rw-`. Writing a heap pointer somewhere and jumping to it needs a `PROT_EXEC`
   region; `libtmessages` is mapped `r-xp` (not writable), and RELRO makes the
   GOT read-only (verify per-device with `readelf -lW`; the app links
   `-z now`).
2. **The 104-byte write content is not attacker data.** `Vec::push` writes a
   `Rasterizer` (`{ptr, len, w, h, …}`) whose pointer is a *renderer-owned*
   pool buffer; the geometry fields are attacker-influenced only in a limited
   numeric range. There is no way to place a chosen 8-byte value.
3. **Stride/alignment.** The write address is `ptr + len*104`; the attacker
   controls `ptr` (8 bytes, aligned to the Vec header) and `len` (≤ cap), so it
   is a *coarse* 104-byte-aligned write — it cannot hit an arbitrary function
   pointer inside an object without also smashing 104 bytes around it.
4. **`+1` is paired.** `Arc::clone` +1 is undone by the drop at the end of the
   same `render`; it survives only if the process dies inside `render` (i.e. it
   is a post-mortem increment, as the earlier note measured).
5. **No vtable in the object.** `CPURenderer` is a concrete Rust struct with
   static dispatch; there is no function pointer in the 0x510 bytes to
   overwrite. PAC is irrelevant until a data-only corruption is turned into an
   indirect call.
6. **The same race + reclaim is still required**, and the *attacker-bytes*
   reclaimer lives only for the `tlottie_new` call (§4.2).

The realistic use of a leak is therefore: a *reliable heap-corruption primitive*
(arbitrary free / arbitrary 104-byte data write / +1), which is a stepping
stone for a second bug (e.g. overlapping allocations into a C++ object with a
vtable, such as `twidget::WidgetHost` or `tgcalls`), **not** ACE on its own.
The SVG leak itself is read-only; it does not add a write.

### 7.3 What the TGS side needs from the SVG leak (coordination interface)

For the SVG agent's leak to be usable here, the maps dump must contain:

* `libc.so` and `libtmessages.49.so` mapping bases (any line of
  `/proc/self/maps` is enough to derive them), and at least one writable
  mapping whose address is stable for the lifetime of the process (the app
  heap / `[anon:scudo:*]` ranges are fine — the fake instance only needs an
  address to point `comp` at);
* a *hand-off*: the leaked file must be readable by the app-UID shell while the
  process is still alive, and the TGS document must not have been created yet
  (reserve one dialog/emoji for the exploit, leak from another);
* if the leak can only happen *after* the TGS draw has been created, the chain
  needs a second create: change the DB? no — instead use a *different*
  document that is created later (scroll), or force the drawable cache to drop
  the first one (eviction) so a later bind re-creates it from the rewritten
  file.

Everything in §7.2 stays true with such a leak.

### 7.4 Same-process feasibility

The leak and the TGS parse must be in the same process:

* P1/P2 run in the chat list at cold start; the SVG path (wallpaper or
  document) also runs in the same process if it is parsed at startup. Sequence:
  cold start → SVG XXE writes `/proc/self/maps` (to a file the shell reads, or
  to the C2) → the shell rewrites `cache/<dc>_<id>.tgs` with the fake instance
  → the emoji is created when its cell binds / when the user scrolls →
  reclaim + render.
* The rewrite must beat the `ci0` creation of that document (the file is read
  once). With many dialogs, the attacker can reserve a *later* dialog for the
  exploit and leak from an *earlier* one — no user action needed if the list
  binds both; otherwise a scroll is needed.
* After a restart the maps change: the SVG must re-leak and the TGS file must
  be rewritten again. This is a per-process chain, not a persistent implant.

---

## 8. Device test plan

Two devices, different purposes (both already provisioned by earlier work):

* **Sony XQ-BT52**, Android 13, rooted (`notes/device_loader_proof_20261102.md`,
  UID 10357, `ro.debuggable=0`). Root is used only for *observation*
  (`/proc/<pid>/maps`, tombstone text, gdb attach) — the attacker path itself
  runs as UID 10357.
* **Pixel 9**, Android 17, debuggable second package
  `org.telegram.messenger.beta.dbg` (UID 10178) with the Sony account cloned
  (`notes/pixel_debug_build.md`). `run-as` works; **check MTE** (the app does
  not declare `memtagMode`; if the device has MTE-always-on for debuggable
  apps, the UAF becomes a deterministic tag check → useful as a *detector*,
  fatal for the exploit).

### 8.1 Reachability marker (no crash, proves the cold-start path)

1. Build a PoC DB with `make_poc_db.py` pointing at **garbage** `.tgs`
   content (e.g. `printf 'nope'`).
2. Push DB + file, delete `cache4.db-wal/-shm`, `am force-stop`, start, wait
   10 s, `adb logcat -d`.
3. Expected: `RLottieDrawable nativePtr == 0 … remove file` and the cache file
   **deleted** → the dialog list created a `ci0` for our document at cold
   start (P1 executed) with no tap.

### 8.2 No-interaction crash test (heavy TGS)

1. `make_poc_db.py --count 4 --tgs pocs/heavy.tgs` (or 30 emoji in one
   message), push to `cache/`.
2. Cold start ×20, no touch. Count `Fatal signal` in logcat and tombstones in
   `/data/tombstones` (root).
3. Expected: **0 crashes** (guard defers; startup evictions are attached).
   Any crash here would itself be a finding — capture the full tombstone.

### 8.3 Detach + eviction churn (the real trigger)

1. N dialogs, each with a *distinct* heavy emoji (so each cell has its own
   instance and detaching the cell makes `v()` false immediately).
2. Cold start; then `adb shell input swipe` to scroll down and up repeatedly
   (10–20 swipes), 20 runs.
3. Watch for: `Fatal signal 11` in `libtmessages.49.so`, backtrace frames in
   `Rasterizer::draw_line`, `fill_contours_translated`, `CPURenderer::draw`,
   `RenderScratch::put_raster`; Scudo `invalid chunk state when deallocating`
   / `double free`.
4. Record the per-run crash rate and the payload/size that maximises it. This
   is the number the earlier note's 81 % should be replaced with.

### 8.4 Determinism (root, lab-only)

With root, make the race deterministic to *validate* the model (not as an
attacker path): attach gdb to the app, break in
`tlottie_render_with_options` (or `nGetFrame`), continue only the UI thread to
`tlottie_drop` while the executor is stopped inside the render, then release.
This yields a 100 % UAF and a clean ASan-style backtrace for the note.

### 8.5 Reclaim and fake-instance proof

1. Quarantine check on the device: root `grep -i scudo /proc/<pid>/smaps` and
   the runtime behaviour of §4.1 (how many `nCreate`s are needed before a
   freed instance address is reused). If the block is reused immediately, the
   device runs with the quarantine disabled and §4.1's "quarantine off" row
   applies.
2. Attacker-bytes reclaim: marker JSON (§4.2) as one of the documents, heavy
   TGS as the victim, scroll. Expected tombstone `signal 11 … fault addr
   0x41414141414141xx` (or, with a leak, `0x<leaked page>+0x58`). A marker
   fault is the proof that the JSON bytes became the `CPURenderer`.
3. If an SVG `/proc/self/maps` leak is confirmed by the SVG agent, repeat 2
   with `comp` = a mapped read-only page from the leaked map: the fault must be
   `SEGV_ACCERR` at exactly that page → control of `comp` demonstrated.

### 8.6 Deterministic OOM/abort (the §12 finding)

1. Build a P1 document whose media is `pocs/bomb_1024m.tgs` (1 MB gzip →
   ~1 GiB Java `String`; the app sets `android:largeHeap="true"`, so the heap
   limit is the large-heap one and a 64 MiB bomb may survive) or a sparse plain
   file (`pocs/sparse_4g.tgs`, 0 disk blocks → native `std::string`), push,
   cold start, no tap.
2. Expected: process death with `OutOfMemoryError` in the ImageLoader thread
   (gzip) or `Fatal signal 6 (SIGABRT)` / `Aborted` from Rust
   `handle_alloc_error` (plain), and/or an LMK kill. Repeat 3×: it must be
   deterministic, unlike the race.
3. This is a DoS. Do not report it as ACE.

### 8.7 Startup cycle with the first RCE (persistence question)

Write DB + media with the app-UID shell, `am force-stop`, reboot, cold start
and re-check 8.1–8.5. The trigger survives (DB + media are app data); the
*leak* does not (maps change), so the leak-dependent variant must re-leak each
process. Record whether the app crash-loops (a DoS kill switch) or survives.

---

## 9. Reproduction

```
lab/tgs_local_ace/
  src/tl72799.py          TL-lite (72799) message/document serializer+parser
  src/make_poc_db.py      build/verify the startup PoC cache4.db + media
  src/gen_payloads.py     small/heavy/huge/marker TGS (gzip + plain)
  src/alloc_probe.cpp     nCreate cost, allocation order, reclaim distance
  src/marker_uaf.cpp      free-during-render + JSON-string reclaim harness
  build_*                 host builds (clang 19, pinned libtlottie.a)
  pocs/                   payloads, base_v2.db, poc1.db, poc4.db, media/
  device/                 adb scripts (plan §8)
  logs/                   captured output (see §3, §4)
```

Host builds (x86_64; `$SRC=/tmp/opencode/tlottie-uaf`):

```
clang++ -O1 -g -fsanitize=scudo -std=c++17 -I$SRC/include \
  src/alloc_probe.cpp $SRC/target/release-nostd/libtlottie.a \
  -lz -lm -lpthread -ldl -Wl,--wrap=malloc -Wl,--wrap=free \
  -Wl,--wrap=calloc -Wl,--wrap=realloc -o build_alloc_probe_scudo
./build_alloc_probe_scudo pocs/small.json pocs/heavy.json pocs/pad.json
python3 src/gen_payloads.py && python3 src/make_poc_db.py make pocs/base_v2.db pocs/poc4.db \
  --tgs pocs/heavy.tgs --media-dir pocs/media4 --count 4
```

The host is x86_64 with the *host* `CPURenderer` layout; field offsets quoted
for arm64 (`+0x4F0`, `+0x50B`) come from the 72799 binary and must be
re-verified on the device (the marker offset sweep in 8.5).

---

## 10. Limits / open items

* No device run in this pass: the crash rate of §8.3, the Scudo configuration
  of the device, and the marker offsets are **DEVICE-PENDING**.
* The TL-lite message/document serializer was validated by parsing 121 real
  `messages_v2` text rows and round-tripping the crafted rows; the app-side
  acceptance of the crafted row (P1 actually drawing the emoji) is
  **DEVICE-PENDING** (8.1 is the check).
* The scalar "the JSON string is in the same class as the instance" holds for
  the pinned tlottie and the AOSP arm64 Scudo table
  (`0x450, 0x670, 0x830`; `SizeDelta 16`), but was only measured with the host
  Scudo build.
* The SVG XXE leak is being verified by another agent; §7 is conditional on
  it and deliberately claims no ACE either way.
* The `0x2001` tail word that every `messages_v2` blob carries is reproduced
  verbatim; its meaning was not recovered from the binary (the reader ignores
  it or consumes it after `TLdeserialize`).


---

## 11. Single-threaded fuzz campaign (2026-11-03)

Goal: a **non-race** memory-safety bug in the TGS JSON/gzip → tlottie path that
`RLottieNative.nCreate` / `nGetFrame` runs at cold start. Everything here is
single-threaded, so the known `d()`/`c()` race cannot be the cause of any
report.

### 11.1 Harness

`L/fuzz/tgs_fuzz.cpp` (+ `tgs_mutator.cpp`), built against the pinned
`tlottie 31f1b54` with the app's `c-api` feature and the **ASan-instrumented
staticlib**, linked with `-fsanitize=fuzzer,address,undefined`:

```
input bytes --(gzip? zlib inflate 15+16 : plain)--> JSON
  -> tlottie_new_with_options(json, len, fitz=0, no colors)
  -> JNI writeMetadata() gate: fps in (0,60], frameCount <= 600
  -> 6 render probes: frames {0, 0.5, 1, last/2, last, last+0.75}
     RGBA8 (antialias 1, curve tolerance 0.125, clear alternating)
     + ALPHA_8 at frames 0 and last
  -> tlottie_drop
```

A second binary (`-DTGS_BIG_CANVAS`) renders 512×512 and 1024×1024 for cheap
documents, which takes `Surface`/`Accumulator` over the 1 MiB mmap threshold
(`mapped_surface.rs`, `mapped_accumulator.rs`) and the AVX2/AVX-512 span
kernels (`simd.rs`).

Corpus: 768 seeds / 52 MB — 722 unique real Telegram animations (decompressed),
the 55 hostile documents from `notes/tlottie_gzip_audit.md`, and the lab
payloads. Mutator: structure-aware (duplicate layer/shape objects, extreme
numbers, injected fields, 4 KiB strings, deletion, byte flips); gzip seeds are
inflated before mutation so the parser sees JSON.

### 11.2 Campaign

| run | binary | workers | wall | executions | reports |
|---|---|---|---|---|---|
| A | `tgs_fuzzer` (16–48 px) | 4 (`-fork=4`) | 2416 s | **55,667,569** | **0** |
| B | `tgs_fuzzer_big` (512/1024 px) | 3 (`-fork=3`) | 1821 s | **17,814,554** | **0** |

Total **73,482,123 single-threaded executions**. The per-job `oom/timeout/crash`
counter stayed `0/0/0` in all 136 (A) and 102 (B) fork restarts, and both
`artifacts/` and `artifacts_big/` are empty.

Flags: `-keep_seed=1 -cross_over_uniform_dist=1 -rss_limit_mb=1536
-timeout=20/25 -artifact_prefix=artifacts*/`. Logs in `L/fuzz/logs/`; crash
artifacts in `L/fuzz/artifacts*/` (empty).

Targeted companion: 73 limit-boundary documents (`L/src/gen_stress.py`) —
dash/trim degeneracies, 1024-stop and focal gradients, 64×64 repeaters,
16 masks with 128-point paths, matte chains, cyclic/self precomps, 128-deep
parent chains, ±140000 coordinates / 1e6 scales / NaN / inf, 2048 keyframes,
zero/negative/8192-px canvases, 128-point stars, hostile UTF-8 names. Both
binaries executed all 73 with **no ASan/UBSan report**.

### 11.3 Limitation that matters for interpreting the numbers

rustc 1.98 removed `-Zsanitizer-coverage` (`unknown unstable option`), so the
Rust staticlib is **not** libFuzzer-instrumented: the `cov:` counter in the
logs is the C++ harness only. Guidance is therefore weaker than a normal
libFuzzer run; it is compensated by `-keep_seed=1` (all 768 seeds stay
mutable), `-cross_over_uniform_dist=1`, the structural mutator, and the
targeted stress set. A future campaign should use a nightly toolchain with
`-Zsanitizer-coverage=trace-pc-guard` (or cargo-fuzz) for real coverage.

### 11.4 Why the absence of reports is credible (audit of the unsafe surface)

The crate is hardened: `panic`/`unwrap`/`expect`/`indexing_slicing` are denied by
lint, the JSON reader is iterative with `max_nesting_depth = 128`
(`composition/json.rs`), the C API checks `width*height` overflow and
`out_len < w*h` (`bindings/c_api.rs:225-232`, `backend.rs:40-52`), and the
remaining `unsafe` is confined to four files:

| file | construction | verdict |
|---|---|---|
| `renderer/cpu/simd.rs` | every kernel clamps to `dst.len().min(src.len())` (etc.), splits at `n - n%8/16`, tails go to the scalar oracle | lengths equal by construction |
| `renderer/cpu/mapped_surface.rs` | `mmap(capacity)`; `Deref` uses the logical `len <= capacity`; `resize_zeroed` only fills when `len > old_len` | no underflow, no stale length |
| `renderer/cpu/mapped_accumulator.rs` | `get_mut(range)` → `from_raw_parts_mut(ptr, len).get_mut(range)` | bounds-checked |
| `renderer/cpu/backend.rs` | `bitmap.as_mut()` only while `with_bitmap` holds the caller slice; cleared by `BitmapReset` | borrow-scoped |

The 0x670 `TLottieInstance` is allocated by the `HostAlloc` shim
(`src/no_std_runtime.rs`), which forwards to `malloc` and over-aligns by
storing the raw pointer below the aligned address — the `malloc(0x528)` +
`free(*(instance-8))` pair from the earlier note.

### 11.5 Verdict

No non-race write/UAF/overflow was found in the pinned parser/rasterizer in
this campaign. The TGS surface remains: (a) the known race (crash, §2), and
(b) the deterministic OOM/abort below. Neither is ACE.

---

## 12. Deterministic non-race finding: unbounded TGS read → startup OOM/abort

This is reachable from the **same P1/P2 row** at cold start, with no race and
no user action, and it is deterministic.

### 12.1 The two encodings take two unbounded paths

`ImageLoader.CacheOutTask` decides whether the cache file is gzip by reading
its first two bytes (`xb.smali` :2050-2090: `0x1f 0x8b` → `compressed`), then:

* **gzip** → `new ci0(file, decompressGzip(file), …)` (`xb` :2409). `ic.o(File)`
  (`decompressGzip`) is `GZIPInputStream` + `BufferedReader.readLine()` into a
  `StringBuilder`, **no size cap** (`xb` :2389, `ic.o` :7409). OOM is an
  `OutOfMemoryError` (an `Error`), and the surrounding handler is
  `catch (Exception)` — it does not catch it.
* **plain** → `new ci0(file, null, …)` (`xb` :2451) → `RLottieNative.nCreate`
  with `json == null` → `lottie.cpp readFile()` = `gzopen` + `gzread` into a
  `std::string` (16 KiB chunks, **no cap**, `lottie.cpp:95-108`). Rust
  allocation failure calls `handle_alloc_error` → abort.

Nothing checks the file size: `FileLoadOperation` explicitly skips the
`totalBytesCount != length` check for `ungzip` (sticker) documents, and
`document.size` is attacker-written in `animated_emoji` and unused for the
local file.

### 12.2 Measurements

| payload | compressed | decompressed | note |
|---|---|---|---|
| `pocs/bomb_64m.tgs` | 65,250 B | 64 MiB | ratio 1028.5:1 |
| `pocs/bomb_256m.tgs` | 260,934 B | 256 MiB | ratio 1028.7:1 |
| `pocs/bomb_1024m.tgs` | 1,043,656 B | 1 GiB | ratio 1028.8:1 |
| `pocs/sparse_4g.tgs` | 4 GiB apparent | — | **0 disk blocks**, plain |

`L/src/bomb_probe.cpp` is `readFile()` verbatim (gzopen/gzread/std::string),
and `L/src/java/Bomb.java` is `ImageLoader.decompressGzip()` verbatim (GZIPInputStream
+ `readLine()` into a `StringBuilder`, `catch (Exception)`):

* plain sparse 4 GiB under `ulimit -v 1.5 GiB` → grows 256 → 512 MiB and dies
  with `terminate called after throwing an instance of 'std::bad_alloc'`
  (exit 134). `logs/bomb_native_sparse4g.txt`.
* 1 GiB gzip bomb under `ulimit -v 600 MiB` → same abort after 256 MiB.
  `logs/bomb_native_gzip1024m.txt`.
* Java replica on the 64 MiB bomb with `-Xmx96m` → `Exception in thread "main"
  java.lang.OutOfMemoryError: Java heap space`, thrown out of
  `decompressGzip` **past the `catch (Exception)`** (the harness prints
  `ESCAPED: java.lang.OutOfMemoryError`). `logs/bomb_java_64m.txt`.

On the device the same read is bounded only by the app's memory budget: the
Java string hits the ART heap limit first for gzip (fast, deterministic
`OutOfMemoryError`), the native string hits the kernel/LMK budget for plain
files (abort or LMK kill one or two seconds later).

### 12.3 Impact and limits

* **Impact:** deterministic process death at every cold start that binds the
  dialog (a kill switch / crash loop). One row + one file; no tap, no race.
  Telegram's only default uncaught handler (`BuildVars`, installed when
  `logsEnabled`) chains to the previous (system) handler, so it does not
  swallow the `Error`.
* **Not ACE:** no memory corruption, no controlled write, no leak. Explicitly
  below the bar the campaign was aiming at.
* The 64 KiB *sticker upload* cap is server-side and irrelevant here: the file
  is written locally by the app-UID shell.
* The read happens at **drawable creation** (`o5.update` → `f5.i` →
  `ImageReceiver` → `CacheOutTask`), not at draw time, so disabling animated
  emoji or the animation does not avoid it — binding the cell is enough.
* The Java side is 13.1.1 source (`ImageLoader.decompressGzip`); the 72799
  call site is `xb:2389` and the method is `ic.o` (same GZIPInputStream code).
  Device confirmation is §8.6.

### 12.4 What would turn this into more than DoS

Nothing in this path: it is an unbounded copy into a growing buffer, not a
length confusion. A memory-corruption variant would need the parser to trust a
length that the buffer does not have — the parser is fed `(ptr, len)` from the
same string, so the only way is a bug in the parser itself (§11 found none).
