# TGS / tlottie loader + gzip path in Telegram Android 72799 — audit

Date: 2026-11-02. Host-only (no phone, no emulator, no VM). Lab:
`lab/tlottie_gzip_audit/`. This note does not modify the main report and does
not repeat `notes/decoder_fuzz.md`; it refines it where the earlier note was
imprecise and adds the binary-level ground truth.

Scope: the Telegram-specific TGS loader — `RLottieNative.nCreate` /
`nCreateWithJson` / `nGetFrame` / `nDestroy`, the `readFile()` gzip loop, the
`zlib` inflate path behind it, the JNI-side size/length handling, the tlottie C
API contract, the frame-buffer arithmetic, and the lifecycle/ownership rules.
Reachability: a bot-owned custom-emoji TGS parsed at cold start in the chat
list.

## 0. Verdict

**No new memory-corruption bug. The loader is a crash/DoS surface, not an RCE
surface.**

| Question | Result |
|---|---|
| Unbounded gzip decompression in `nCreate` | **Confirmed** (no cap, allocation happens before the parser's 16 MiB check) |
| Exact worst case inside Telegram's 64 KiB `.tgs` cap | **65,536 B → 67,404,116 B** decompressed (ratio 1028.5:1), measured |
| Bounded by tlottie's 16 MiB `max_input_bytes` | Only *after* the whole string is allocated: peak **135 MB** RSS per file, **~180 ms** |
| Failure mode under memory pressure | **Deterministic abort**: uncaught `std::bad_alloc` escapes the JNI frame → `std::terminate` → SIGABRT (measured, §3.3). Otherwise OOM-kill/ANR. |
| Wrong buffer length in `nGetFrame` (delegated hypothesis) | **Negative** — buffer length is `width*height` u32 elements, stride temporaries are exact; verified in asm and under ASan (§2.4) |
| Double-free / stale pointer without a race | **Negative** — `nDestroy` is a tail call to `tlottie_drop`; the Java side guards the *sequential* path with a CAS'd `AtomicBoolean` (§5) |
| Concurrent render/destroy | Still a UAF, as previously reported; the 72799 binary has no lock/refcount in the wrapper (§5.1) |
| tlottie parser/renderer memory safety (hostile corpus, ASan-instrumented) | **330 runs, 0 memory errors, 0 aborts**; every structured attack is rejected by a clean `LimitExceeded` (§4) |
| RCE | **Not plausible from this surface** — no attacker-controlled pointer/length reaches a write; the only memory-safety issue is race-dependent and was not turned into a primitive |

The single most useful new result is the *failure mode*: for a 64 KiB file the
process performs a ~135 MB transient allocation and, if that allocation fails,
aborts with `std::bad_alloc` instead of failing gracefully. The prior note
classified this as "a memory/CPU spike, not a reliable crash"; with an
allocation that can actually fail (a 64 MiB expansion from a 64 KiB sticker
cap), the code path has no error handling at all, so the honest classification
is **remote crash/DoS (SIGABRT or OOM-kill), gated only by server-side TGS
validation**.

## 1. Ground truth: which code is in 72799

App: `org.telegram.messenger.beta` 13.2.0 beta (72799), arm64.
Native lib: `lib/arm64-v8a/libtmessages.49.so`, 27,016,000 B,
md5 `2c0caa68a07fc26f79d13519af6c3526` (verified against the IDB's
`retrieve_input_file_md5`).

Exported JNI entries and boundaries (readelf + IDA):

| Address | Size | Symbol |
|---|---|---|
| `0x74F710` | 532 B | `Java_org_telegram_ui_Components_RLottieNative_nCreate` |
| `0x750140` | 224 B | `..._nCreateWithJson` |
| `0x750220` | **8 B** | `..._nDestroy` (`MOV X0,X2; B tlottie_drop`) |
| `0x750228` | 752 B | `..._nGetFrame` |
| `0x74F924` | 1,892 B | `createInstance` (analyst label `rlottie_jni_create_impl`) |
| `0x750088` | 184 B | `writeMetadata` (analyst label `rlottie_cache_insert`) |
| `0x1094884` | 420 B | `tlottie_drop` (analyst label `rlottie_animation_unref`) |
| `0x1094A7C` | — | `tlottie_new_with_options` (label `rlottie_Animation_loadFromData`) |
| `0x10954E0` | — | `tlottie_render_with_options` (label `rlottie_Animation_frameCount`) |

Two corrections to `notes/decoder_fuzz.md` §5.2.1:

1. The `rlottie_*` names in the annotated IDB are **analyst labels, not the real
   ABI**. There is no animation cache and no explicit refcount in the wrapper:
   `rlottie_cache_insert` is `writeMetadata` (it calls
   `tlottie_frame_count`/`tlottie_frame_rate`, checks `fps∈[1,60]` and
   `frameCount≤600`, and writes three ints with `SetIntArrayRegion`), and
   `rlottie_animation_unref` is `tlottie_drop`. A reader of the IDB could
   wrongly conclude that 72799 has a handle cache that changes the lifecycle
   analysis; it does not.
2. `nCreate` **does** take and use all seven Java arguments. IDA's prototype for
   `createInstance` has two parameters, so the decompiler prints a two-argument
   call; the actual instruction sequence at `0x74F87C..0x74F898` sets
   `x1=json bytes, x2=len, x3=layerNames, x4=layerColors (stack arg), x5=colorReplacement, w6=fitz`.
   The 72799 `nCreate` is therefore the same function as
   `Android/TMessagesProj/jni/lottie.cpp` (13.1.1 tree) — the prior note's
   conclusion that "the 13.1.1 source matches the 72799 decompile" is right,
   but only after fixing the IDB's prototypes. This matters because the
   13.1.1 source is the only readable copy of the loader logic.

`tlottie_drop` is not a bare free: it atomically decrements a refcount at
`[instance+0x4F0]` (an `Arc<Composition>`; `src/renderer/cpu/renderer.rs:17`),
frees the shared composition when it hits zero (`sub_106D1CC`), then frees the
instance's own vectors/surfaces (`free`/`munmap`). The *instance pointer* is
still freed unconditionally, so the render/destroy race in §5.1 is a real UAF
on the instance.

## 2. The loader, instruction by instruction

### 2.1 `nCreate` (`0x74F710`)

```
0x74F750  if (json != NULL) {                       // jstring json
0x74F760      chars = (*env)->GetStringUTFChars(env, json, 0);
0x74F778      len   = (*env)->GetStringUTFLength(env, json);
0x74F790      std::string::assign(&input, chars, (size_t)(int)len);
0x74F79C      (*env)->ReleaseStringUTFChars(env, json, chars);
0x74F7B4  } else if (src != NULL) {                 // jstring src = cache path
0x74F7C8      path = GetStringUTFChars(env, src, 0);
0x74F7E0      gz = gzopen(path, "rb");
0x74F7F8      while ((n = gzread(gz, stackbuf /*16 KiB @sp+0x20*/, 0x4000)) > 0)
0x74F810          std::string::append(&input, stackbuf, n);     // sub_16A57AC
0x74F838      gzclose(gz);
0x74F840      ReleaseStringUTFChars(env, src, path);
0x74F858  }                     // src==NULL leaves input empty
0x74F858  if (input.size() == 0) return 0;
0x74F870  inst = createInstance(env, input.data(), input.size(), layerNames,
                               layerColors, colorReplacement, fitz);
0x74F8A0  if (!inst) return 0;
0x74F8AC  if (!writeMetadata(env, data, inst)) { tlottie_drop(inst); return 0; }
0x74F8B8  return (jlong)inst;
```

What is *not* there, and matters:

- **No decompressed-size cap of any kind.** No counter, no comparison against
  16 MiB, no comparison against the compressed size. `gzread` is called until
  it returns `<= 0`; `std::string::append` grows geometrically.
- **No error handling.** `gzread` returning `-1` (corrupt/truncated gzip) ends
  the loop and `readFile` returns `ok = (read == 0)` → false, but the caller
  *ignores the return value* and parses whatever prefix was read. A truncated
  TGS whose prefix is a complete JSON value is accepted (§4.3).
- **`gzopen` is transparent**: gzip and raw data both work. Telegram's bundled
  `res/raw/*.tgs` are **uncompressed JSON** (verified: `dartloop.tgs` starts
  with `{"tgs":1,"v":"5.5.2"...`), which is why both the native path and the
  Java resource path work for the same extension.
- The 16 KiB stack buffer is fine (the frame is `0x4020` bytes); the risk is
  the heap string, not the stack.
- `input.assign(chars, GetStringUTFLength(json))` is the *second* place an
  unbounded allocation can happen — the `nCreateWithJson` path (§3.5).

### 2.2 `createInstance` (`0x74F924`) — layer/color replacements

Copies what it needs before the call returns: `LayerColorReplacement` in
tlottie owns a `String` (`src/composition/options.rs`), and
`tlottie_new_with_options` does `prefix.to_owned()`
(`src/bindings/c_api.rs:113-120`). The JNI reserves the two vectors
(`prefixes.reserve(count)`, `values.reserve(count)`) before pushing, so the
`layer_name_prefix` pointers stored in `TLottieLayerColorReplacement` stay
valid for the whole call. No dangling-pointer bug here, and no pointer is kept
by tlottie after the call.

### 2.3 `writeMetadata` (`0x750088`) — the only Telegram-side gate

```c
frameCount = tlottie_frame_count(inst);
fps        = (int32_t)tlottie_frame_rate(inst);
ok = (fps >= 1 && fps <= 60 && frameCount <= 600);
if (data != NULL && GetArrayLength(data) >= 3 && ok) SetIntArrayRegion(data,0,3,{frameCount,fps,0});
return ok;
```

Consequences, verified with payloads (§7, `gates/`):

- `fr = 61` or `999`: tlottie parses it happily (`info` reports 61/999 fps);
  the JNI rejects it. So the 60 fps sticker rule is enforced **only** here.
- `op - ip > 600`: `tlottie_frame_count()` saturates to `u32` and the JNI
  rejects (`gates/frames_huge_anim.tgs` → 4294967295 frames in `info`,
  `nCreate` returns 0).
- **The gate runs after the parse.** All the memory and CPU of
  decompression + parse are spent before this check. For a *huge decompressed
  payload*, the gate is irrelevant: tlottie rejects the input first (16 MiB
  `max_input_bytes`) — but also only after the string exists.

### 2.4 `nGetFrame` (`0x750228`) — buffer arithmetic

The delegated hypothesis ("wrong buffer length") is **negative**. The exact
sequence:

```
0x7502CC  w = info.width; h = info.height;            // LDP W8,W2,[info]
0x7502D4  count = UMULL(w, h)                          // 64-bit w*h
0x7502E0  if (format == A_8) {
0x7502EC      if (stride == w) p = lockPixels_buf;
0x750318      else { vector<uint8_t>::resize(&tmp, count); p = tmp; }
0x750370      rc = tlottie_render_alpha8_with_options(inst, (float)frame, w, h,
                                                      p, count, 1, 0.125f, clear);
0x7503A4      if (rc==0 && tmp used) per-row memmove(width bytes) back
0x7502FC  } else {                                     // RGBA_8888
0x750308      if (stride == w*4) p = lockPixels_buf;
0x7503F0      else { vector<uint32_t>::resize(&tmp, count); p = tmp; }   // count u32s
0x750448      rc = tlottie_render_with_options(inst, float in s0, w, h,
                                               p, count, aa=1, tol=0.125 in s1, clear);
0x75047C      if (rc==0 && tmp used) per-row memmove(4*width bytes) back
0x7504D8  AndroidBitmap_unlockPixels();
0x7504E4  return rc==0 ? frame : -5;
```

- `count` is `w*h` in **elements**, and tlottie's `out_len` is also in
  elements (`tlottie_render_with_options`: `px = (width as usize).checked_mul(height)`,
  `out_len < px → -2`, then `from_raw_parts_mut(out, px)`). Consistent.
- The temporary path allocates exactly `count` elements and copies
  `width`/`4*width` bytes per row; the copy-back uses the bitmap's own stride.
- Only `ANDROID_BITMAP_FORMAT_RGBA_8888 (1)` and `A_8 (8)` are accepted;
  `RGB_565`/`HARDWARE` return 0.
- `Bitmap.createBitmap(w,h)` is Java-side; `w*h` cannot overflow `size_t` on
  arm64, and the Java callers size the bitmap from the *view/text* size
  (`ci0`'s `w`/`h` fields), never from the composition's declared `w`/`h`, so
  an attacker-controlled composition size cannot inflate the render target.
- ASan-instrumented runs over all 6 geometry variations (including forced
  `stride != width`, `stride != 4*width`, and `A_8`) show **no** out-of-bounds
  access (§4).

### 2.5 `nDestroy` (`0x750220`) and the drop path

`MOV X0,X2; B tlottie_drop` — no null check in the wrapper, but `tlottie_drop`
starts with `CBZ X0, ret`. The `TLottieInstance` owns everything; the drop is
idempotent only if not called concurrently. The Java guard is a CAS'd
`AtomicBoolean` (`RLottieNative.d()`), which is a check-then-act relative to
`c()`'s read of `f24122b` — the known race.

## 3. gzip / inflate: compressed vs decompressed caps

### 3.1 The real ceiling inside Telegram's cap

Telegram's own sticker specification (`core.telegram.org/stickers`,
"Animation Requirements") says: canvas 512×512, ≤3 s, 60 fps, and **"final file
size must not exceed 64 KB"**. The payload that Telegram stores and the client
downloads is the `.tgs` (gzip) file, so **65,536 bytes is the compressed cap**.

DEFLATE's maximum ratio is ~1032:1. Binary-searching the largest all-zero
payload whose `gzip -9` output is ≤ 65,536 bytes:

```
decompressed 67,404,116 B  ->  gzip 65,536 B   (ratio 1028.5:1)
```

That is the true worst case for one TGS: **64.28 MiB from a file at the cap**.
(`pocs/bomb_zeros_max.tgs`.)

### 3.2 Allocation happens before the 16 MiB check

tlottie checks `bytes.len() > limits.max_input_bytes (16 << 20)` as the *first*
statement of `parse_composition` (`src/composition/parse.rs:2295`). The JNI has
already materialised the whole string by then. Measured with the 64.28 MiB
payload (plain build, `getrusage` peak + `/proc/self/statm`):

```
file_bytes=65536  decompressed=67404116
ms: read=178.5  create=0.0   (the parser rejected immediately)
rss KiB: start=3740  after_read=71676  after_create=71868  peak=134988
```

Two things to read from this:

- The steady 70 MB is the string itself; the **135 MB peak** is the geometric
  reallocation (`append` doubling: 64 MiB → 128 MiB → final trim).
- `create=0.0 ms` proves the order: the parser's limit check fires after the
  entire decompression.

### 3.3 Failure mode: uncaught `std::bad_alloc` → SIGABRT

`readFile` has no `try`/`catch`, and neither `nCreate` nor any of its callees
does. A `std::string` growth failure therefore throws out of the JNI entry
point. ART calls JNI methods through a C function pointer and has no C++
handler on that path, so the exception reaches `std::terminate` → `abort()`.
Reproduced on the host by capping the address space (the same payload as
above):

```
$ ( ulimit -v 200000; ./build/jni_model --no-render pocs/size/bomb64k_max.tgs )
terminate called after throwing an instance of 'std::bad_alloc'
  what():  std::bad_alloc
Aborted            # exit 134 (SIGABRT)
```

The abort reproduced at every address-space cap tried (200, 120, 90 and
70 MB), because the code needs ~135 MB for this file. On a phone the same
64 KiB file forces either this abort (if the allocator/`cgroup` limit makes
`malloc` fail) or an LMK/OOM kill (if the kernel kills on touch), and the
exception type would be `std::bad_alloc` or `std::length_error`. Either way the
user sees the app die, and it is caused entirely by attacker-controlled content
at the documented maximum sticker size.

Same class, second site: `input.assign(chars, GetStringUTFLength(json))` in the
`nCreateWithJson` path (§3.5). Same absence of a catch.

### 3.4 Concurrency: the multiplier that matters

`nCreate` is called from the image/render workers (`ci0.b()`/`B()` are reached
from `rf.e` and the `R0`/`S0` executor pools) and from the thread that runs the
sticker metadata probe (`vh/n5.u`, §6). Each concurrent call has its own string.
Measured with a `--threads N` barrier so the decompressions overlap:

| concurrent `nCreate` | peak RSS |
|---|---|
| 1 | 135 MB |
| 2 | 242 MB |
| 4 | **496 MB** |
| 8 | 627 MB |

So **four** simultaneous 64 KiB TGS creations are ~0.5 GB of native heap in one
process — enough to trip the LMK on a mid-range device, and enough to make the
`bad_alloc` path of §3.3 likely.

### 3.5 The accepted case is small; the rejected case is the weapon

- Largest **valid** TGS inside the cap: a normal 512×512 Lottie padded with
  trailing JSON whitespace to **16,777,216 B** (exactly 16 MiB; the parser's
  check is a strict `>`), gzip **16,594 B** — 25% of the 64 KiB cap — parses in
  5 ms, renders in 0.2 ms, peak RSS **21 MB**
  (`pocs/size/pad_16m_over.tgs`; `pad_16m_ok.tgs` is the same payload at
  16,777,214 B).
- 16,777,768 B → `InputBytes` (rejected *after* 16 MiB are allocated).
- 15 MiB of *dense* layers → `resource limit exceeded: ParseMemory`
  (`max_parse_bytes` 12.4 MiB) — tlottie's parse-side amplification is bounded;
  `pocs/size/dense_15m.tgs`.
- So the *only* way to get a large allocation is content that the parser
  **rejects** — i.e. the DoS works precisely when the sticker is invalid.

### 3.6 Server-side validation is the only gate — and it may be shallow

The client performs no validation before decompression. The bot uploads the
`.tgs` through `uploadStickerFile`/`createNewStickerSet`; the server enforces
"≤64 KB" (documented) and, presumably, some format check. Two payloads probe
the difference:

- `pocs/size/bomb_valid_then_nul.tgs` — **a fully valid 512×512 / 60 fps /
  ip=0 / op=60 Lottie object**, followed by ~64 MiB of NUL bytes (65,589 B
  gzipped). A validator that reads the leading object and does not reject
  trailing data (many "header scan" checks) accepts it. tlottie itself rejects
  trailing data (`pocs/size/trailing_nul_small.tgs`, 100 KB of NUL after the
  same object → `invalid JSON at byte 101: TrailingData`), but for the 64 MiB
  variant the 16 MiB `InputBytes` check fires first — after the allocation.
- `pocs/size/bomb_header_valid.tgs` — valid field prefix, then zeros
  (65,715 B). Only a full parse can reject it.

This is the one unknown that decides the severity, and it is **not** resolved
here (no device, no bot token, no server). If the server fully parses the TGS
(plausible: it must check 512×512, ≤3 s, 60 fps), then only *valid* TGS reach
clients and the DoS collapses to ~21 MB per animation, i.e. low severity. If
the check is shallow or textual, a 64 KiB sticker yields 135 MB and an abort.

## 4. tlottie FFI / unsafe / parser audit (hostile corpus, ASan)

### 4.1 C API contract

`src/bindings/c_api.rs` is defensive: null JSON/handle checks, `checked_mul`
for `w*h`, `out_len < px → -2`, `from_raw_parts(out, px)` only after the
bounds check, `FitzModifier::from_u32`/`ChannelOrder::from_u32` reject unknown
values, replacement arrays are validated element by element, prefixes are
UTF-8-checked and copied. `tlottie_drop(NULL)` is a no-op. The FFI cannot be
driven to an invalid slice by anything the JNI passes for a real bitmap.

### 4.2 Hostile corpus

`pocs/` contains 55 hand-built payloads in four families (`gates/`, `struct/`,
`size/`, plus the bombs). Each was run through the model at six geometries
(512², 1×1, 2000², forced RGBA stride mismatch, ALPHA_8, forced ALPHA_8 stride
mismatch) with **tlottie itself compiled with Rust ASan**
(`RUSTC_BOOTSTRAP=1 RUSTFLAGS=-Zsanitizer=address`, the same staticlib as
`lab/decoder_fuzz`). Result: **330 runs, 0 ASan reports, 0 aborts, 0
panics**; all rejections are clean error codes (`nCreate` returns 0,
`nGetFrame` returns -3/-5). Raw table: `results/corpus_asan.csv`.

Every structured attack is caught by a limit, not by luck
(`logs/parse_errors.log`):

| payload | result |
|---|---|
| precomp self-reference / pair | `PrecompExpansion` (self), accepted as a normal 60-frame comp (pair) |
| parent cycle / self-parent | `ParentChainDepth` |
| shape-group nesting 32 / 33 | accepted / `NestingDepth` |
| 2048 / 2049 keyframes | accepted / `Keyframes` |
| 2304 / 2305 layers | `ParseMemory` (parse-byte cap fires first) |
| repeater ×1e6 | `RepeaterCopies` |
| polystar 1e6 points | `PolystarPoints` |
| path coords ±1e9 | `PathCoordinate` |
| `w=0`, `w<0`, `w=8193`, `w=1e9` | `CompositionSize` (8192 accepted) |
| `op<=ip`, `op=1e999` | `out point must be greater than in point` / `BadNumber` |
| transform scale 1e9, dash 1e9, 32 masks | accepted, render OK |
| 2000-layer "slow" TGS from `lab/decoder_fuzz` | **rejected** (`ParseMemory`) — so that payload cannot be used to widen the race window on this commit |

### 4.3 Truncation quirk (robustness, not memory safety)

`readFile` parses a partial prefix when `gzread` fails mid-file
(`ok` is ignored by `nCreate`). Consequence: a deliberately truncated TGS whose
prefix is a complete JSON value is *accepted by the client* even though the
server stored a corrupt file. No security impact beyond "malformed input
renders", but it is the reason `readFile`'s boolean is dead code.

### 4.4 `unsafe` in tlottie

Spot-audited, in addition to the prior note: `mapped_surface.rs` and
`mapped_accumulator.rs` (mmap-backed scratch for ≥1 MiB canvases) check
`checked_mul`, `mmap` failure, keep `capacity >= len`, re-zero on grow, and use
`get_mut(range)`; the `Deref` impls only expose `len` elements; `Drop` uses the
recorded capacity for `munmap`. `Budget`-driven rendering is bounded by
`max_render_points`/`max_render_work`/`max_render_bytes`, which the corpus
confirms (`render=-3` instead of a crash at 2000×2000 for the extreme
transforms). Nothing in the unsafe surface is reachable with
attacker-controlled lengths from a TGS.

## 5. JNI lifecycle / ownership

### 5.1 The known race, confirmed against the binary

`RLottieNative.c()` (`smali_classes3/.../RLottieNative.smali:525`) reads
`f24122b` **after** the `AtomicBoolean` check and then calls `nGetFrame`;
`d()` CASes the flag, zeroes `f24122b`, and calls `nDestroy` → `tlottie_drop`
→ `free`. The binary has no lock, no refcount on the handle, and no in-flight
counter. The window is therefore exactly as previously reported: a destroy on
the UI thread can free the instance while a render thread is inside
`tlottie_render_with_options` (`Budget::transform`), i.e. a heap UAF on the
instance and on its `Arc<Composition>`. The 72799 `nDestroy` being an 8-byte
tail call removes any doubt that the wrapper does extra lifetime management.
Impact remains **crash/DoS, RCE speculative** (no write primitive was
demonstrated before or now).

Two additional notes on the Java wrapper, both minor:

- If `d()` wins the race *before* `c()` reads `f24122b`, `c()` calls
  `nGetFrame(0, ...)`, which returns 0 — and callers treat 0 as success
  (`ci0.a(Bitmap)`: only `-5` is an error, then `C0 += 1`). A concurrent
  destroy can therefore silently advance the frame counter and render nothing.
  Logic bug, not memory safety.
- `finalize()` calls `d()`; the CAS makes the sequential double-destroy
  impossible (`finalize` + explicit `d()` is guarded). No double-free without
  the race.

### 5.2 No "wrong length" path

See §2.4. The other candidate, `nCreateWithJson`, does
`input.assign(chars, GetStringUTFLength(json))` — length is the modified-UTF-8
byte length of the same buffer, so it is exact for the buffer
`GetStringUTFChars` returned. (If a Java caller built the String from arbitrary
bytes, U+FFFD expansion makes the UTF-8 copy up to 3× the char count, but the
copy is still consistent — only a memory amplifier, §6.2.)

## 6. Reachability

### 6.1 Custom-emoji TGS at cold start (strongest, update-surviving)

The prior trace stands and was re-verified: `vi` (`MessageObject`) turns a
custom-emoji entity into an `AnimatedEmojiSpan` (`o5`); `DialogCell.onDraw`
calls `o5.drawAnimatedEmojis`; that reaches `AnimatedEmojiDrawable` = `f5`
(`f5.toString()` → `"AnimatedEmojiDrawable{"`), which calls
`ImageReceiver.B()` → the `ci0` (RLottieDrawable) and `start()`s it. The
dialog list is drawn at cold start, before any chat is opened, so a TGS in the
last message's text/caption is parsed and rendered at launch. Delivery: a bot
creates a custom-emoji sticker set and sends a message using the emoji; the
document is auto-downloaded and cached like any sticker.

**The custom-emoji TGS reaches the native gzip path directly**, and the chain
is explicit in the 72799 smali. In `vh/b4` (the custom-emoji drawable helper):

```java
Document d = span.document != null ? span.document : f5.e(account, span.getDocumentId());
FileLoader.getInstance(account);                       // b8.G(account)
File f = FileLoader.getPathToAttach(d, "*", false, false);   // b8.K(...)
String path = f.getAbsolutePath();
boolean ok  = vh.n5.u(d, path);                        // smali_classes3/vh/b4.smali:12017
```

and `vh/n5.u(Document, path)` (`smali_classes3/vh/n5.smali:3260`) checks the
MIME type and calls

```java
RLottieNative.a(path, /*json*/null, /*options*/null, /*colors*/null, /*fitz*/0, /*map*/null)
```

i.e. `nCreate(src=path, json=null, ...)` → `gzopen(path,"rb")` + `gzread` loop
(§2.1) → `tlottie_new_with_options` → `tlottie_frame_count`. `vh` is the
sticker/emoji package, so this is the sticker metadata probe, and it is the
same `nCreate` the drawable uses.

The path is Telegram's document cache path (`FileLoader.getPathToAttach` with
`ext="*"`); the file is the server-stored `.tgs` byte-for-byte (the client does
not re-encode), and the `.tgs` extension/MIME selects the TGS parser. So the
135 MB allocation of §3.2 happens on the **document-cache file of a
bot-supplied custom emoji**, not on a resource or a user file.

### 6.2 The Java-side decompressor (wallpaper path) — worse amplification, weaker trigger

`ic.o(File)` (`smali/org/telegram/messenger/ic.smali:7409`) decompresses with
`GZIPInputStream` + `BufferedReader.readLine()` into a `StringBuilder`, with
**no size limit and no line handling** (newlines are dropped), and returns a
`String`. Its caller `xb` builds `ci0(File, json, ...)`, and `ci0.b()` passes
the String to `nCreateWithJson`. Java therefore holds the text at least twice
(`StringBuilder` growth plus `toString()`, 2 B/char each) and the JNI copies it
twice more (`GetStringUTFChars`, then `input`: 1–3 B/char each). For a 64 KiB
bomb (67 MB decompressed) that is on the order of 400 MB of Java+native heap
for one file. Analytic, not measured here (the trigger is a wallpaper, not a
chat message).

Also in that area: `i0.y2(File,resId)` reads a whole file/resource into a
**ThreadLocal `byte[]` that doubles and is never shrunk** (method at
`smali/org/telegram/messenger/i0.smali:40215`; the grown array is stored back
into the ThreadLocal at `:40360`). A single large read permanently pins the
doubled buffer on that thread. Only reachable with large *uncompressed* JSON
files (resources or the `qh/x0` file), so it is an observation, not a finding.

### 6.3 Server-side TGS validation

Documented: `.tgs` ≤ 64 KB, 512×512, ≤3 s, 60 fps. Unknown: whether the server
parses the JSON at upload time and whether it rejects trailing garbage
(§3.6). No bot token or device was available to test; this is the same gap the
prior note flagged.

## 7. Reproduction

```
lab/tlottie_gzip_audit/
  src/jni_model.cpp       faithful model of nCreate/readFile/createInstance/
                          writeMetadata/nGetFrame (13.1.1 lottie.cpp semantics,
                          same tlottie 31f1b54)
  src/build.sh            ASan build (Rust-instrumented staticlib)
  src/build_plain.sh      plain build for RSS numbers
  src/gen_corpus.py       generates the hostile corpus
  src/run_corpus.py       330-run matrix -> results/corpus_asan.csv
  src/measure.sh          the measurements quoted above -> logs/measurements.log
  pocs/                   payloads (bombs, gates/, struct/, size/)
  evidence/               72799 JNI exports + IDA asm excerpts + tlottie limits
  build/                  jni_model, jni_model_asan
  logs/measurements.log, logs/parse_errors.log, logs/badalloc.trace
  results/corpus_asan.csv
```

```bash
# 1. Rust ASan staticlib of the pinned tlottie (already used by decoder_fuzz)
export PATH=$HOME/.cargo/bin:$PATH
cd /tmp/opencode/tlottie-31f1b54
RUSTC_BOOTSTRAP=1 RUSTFLAGS="-Zsanitizer=address -Cdebuginfo=2" \
  cargo rustc --release --features c-api,std --lib -- --crate-type staticlib
# 2. builds
lab/tlottie_gzip_audit/src/build.sh          # -> build/jni_model_asan
lab/tlottie_gzip_audit/src/build_plain.sh    # -> build/jni_model
# 3. measurements and corpus
lab/tlottie_gzip_audit/src/measure.sh
lab/tlottie_gzip_audit/src/run_corpus.py
```

Host: Debian 13, x86_64, clang 19.1.7, Rust 1.98.0. Host numbers are
allocator/timing measurements, not a device OOM certificate.

## 8. Limits and what would change the verdict

- The Android Java threading was not run; the race stays "reproduced in a
  model", as before.
- The 64 KiB ceiling assumes the documented Telegram TGS limit is enforced for
  custom-emoji stickers as for stickers; the client has no size check either
  way.
- If the server fully validates the decompressed TGS (must reject trailing
  bytes and non-JSON), the gzip issue is a ~21 MB transient per valid
  animation: low severity, not a crash.
- If it does not, a 64 KiB custom emoji produces 135 MB and can abort the
  process, and four concurrent creations produce ~0.5 GB: a remote crash/DoS
  from a bot-owned sticker set, triggered by the chat list at cold start.
- Nothing in this audit produces a pointer or length that the attacker
  controls at a write site; the only memory-safety candidate is the
  race-dependent UAF, which remains RCE-speculative.
