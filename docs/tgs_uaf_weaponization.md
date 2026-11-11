# Telegram Android TGS/RLottie UAF — weaponization study

Date: 2026-11-02. Host-only (no phone, no emulator, no VM). Lab:
`lab/tgs_uaf_weaponization/`. This note does not modify the main report.

Target: `org.telegram.messenger.beta` 13.2.0 beta (72799), arm64,
`lib/arm64-v8a/libtmessages.49.so` 27,016,000 B,
md5 `2c0caa68a07fc26f79d13519af6c3526`, tlottie `31f1b542…`
(`Android/TMessagesProj/jni/lottie.cpp`, 13.1.1 tree, same pin).

Prior work this note builds on (not repeated):
`notes/decoder_fuzz.md` §5.2.1 (the guard model reproduces a UAF),
`notes/tlottie_gzip_audit.md` §2.4/§5.1 (buffer arithmetic, no lock/refcount),
`notes/scudo_bypass_notes.md` (Scudo quarantine facts for this app).

---

## 0. Verdict

| Question | Result |
|---|---|
| Is the `RLottieNative.c()` / `d()` check-then-act race real in 72799? | **Yes.** No lock, no refcount, no in-flight counter; `nDestroy` is an 8-byte tail call to `tlottie_drop`. Confirmed again in the binary and the smali. |
| Can the race be made *reliably* winnable by a bot-supplied TGS? | **Yes, at the model level.** A 10 KB (inside the 64 KiB sticker cap) valid TGS makes one `nGetFrame` last **14.1 ms at 96×96** on the host versus **15.5 µs** for a normal Telegram animation — 900× wider. With a destroy uniform in the playback window the measured destroy-inside-render rate was **81 % (81/100)**, and **every** hit crashed. |
| What kind of memory error is it? | Not a read-only UAF. ASan shows **WRITE of 104 bytes into a freed 416-byte `Rasterizer` buffer** (`RenderScratch::put_raster`) and **READ of 8 bytes at instance+0x458 inside the freed 1296-byte instance** (`CPURenderer::draw`). The glibc runs end in `free(): invalid pointer`, `munmap_chunk(): invalid pointer`, `double free or corruption` — i.e. corrupted heap metadata, not just stale reads. |
| Can the freed instance be reclaimed with attacker data? | **Yes, and the reclaim distance was measured with real Scudo.** Instance = 1296 B object in a **1320 B malloc block** → Android class **0x670 (1648 B)**. With the Scudo quarantine disabled (runtime default) the next same-size allocation gets the block **immediately**. With the documented Android settings (256 KB/64 KB/≤2048) the first reclaim required **217 same-class allocations** after the free. |
| Is there a control primitive after reclaim? | **Yes, demonstrated.** `CPURenderer::render` reads `comp` (Arc pointer) at **instance+0x4F0** from the reclaimed bytes, reads `[comp+0x58]`, then executes `Arc::clone` = **`*(u64*)comp += 1` at an attacker-chosen address**. Measured: `refcount_before=0 after=1 delta=1` on a controlled page. It then attempts to free attacker-derived pointers (Scudo: `misaligned pointer when deallocating`). |
| Is there a no-leak corruption path? | **Yes.** If the block is reclaimed by *another live `TLottieInstance`*, the stale handle aliases a live `CPURenderer` and two threads call `render(&mut self)` concurrently. ASan: heap-use-after-free in `Rasterizer::draw_line`; Scudo: `invalid chunk state when deallocating` (double free); plain: SIGSEGV/`double free or corruption`. Repeated processes: 9/20 plain, 8/20 ASan, 1/20 Scudo crashed at 4 threads × 300 renders. |
| End-to-end RCE? | **No. Not demonstrated, and not reachable from the current evidence.** The chain is gated by (a) winning the race (feasible), (b) reclaiming a specific 1648-byte chunk inside the window (needs ~200 same-class allocations in the window, and the attacker cannot allocate native memory directly — only steer content), and (c) for the pointer-controlled variant, a heap/libc address leak that this surface does not provide. The realistic, defensible classification is **remote race-dependent memory corruption → crash/DoS**, with a *conditional* arbitrary-increment/type-confusion primitive that is one leak + one grooming step short of control. |

Everything below that is not explicitly a binary fact is a **host model**.

---

## 1. Exact lifecycle map (72799 smali + binary)

### 1.1 The Java guard is a check-then-act

`smali_classes3/org/telegram/ui/Components/RLottieNative.smali`

```java
// c(int frame, Bitmap bmp, boolean clear)          // :525
if (!destroyed.get()) {                              // :528 AtomicBoolean
    long p = this.b;                                 // :536  handle read AFTER the check
    Trace.beginSection("RLottieNative#getFrame");
    return nGetFrame(p, frame, bmp, clear);          // :544
}
throw new IllegalStateException("Called method on a recycled RLottie instance");

// d()                                              // :606
if (destroyed.compareAndSet(false, true)) {
    long p = this.b;
    this.b = 0;
    nDestroy(p);                                     // -> tlottie_drop
}
```

* `nDestroy` @`0x750220` is `MOV X0,X2; B tlottie_drop` (8 bytes). `tlottie_drop`
  @`0x1094884` decrements the `Arc<Composition>` refcount at `[instance+0x4F0]`,
  drops the instance's Vecs/surfaces, then `free(*(void**)(instance-8))`
  (the allocator's stored raw pointer). No lock, no refcount on the handle.
* If `d()` wins before `c()` loads `b`, `c()` calls `nGetFrame(0,…)`, which
  returns **0** without throwing. No caller treats 0 as an error:
  `ci0.a(Bitmap)` maps only `-5` to failure (`ci0.smali` :4650), and `B()`
  returns its generic success code for any non-negative result
  (`:cond_c if-gez v6`). A destroy can therefore silently advance the frame
  counter — a logic bug, and proof that the wrapper has no "the handle went
  away" path.

### 1.2 Where the render runs, where the destroy runs

`smali_classes3/org/telegram/ui/Components/ci0.smali` (RLottieDrawable)

| Step | Code | Thread |
|---|---|---|
| animation tick | `ci0.start()` :6712 → `I()` :3242 | caller (UI) |
| queue a frame | `I()` :3406..3435 → `Executor.execute(F0)` | **R0 = `newFixedThreadPool(4)`**, `S0` = 2 threads (`<clinit>` :179-260) |
| frame task | `bi0` type 5 → `ci0.f(ci0)` :1654 | **executor thread** |
| render | `f()` :1800 `Bitmap.createBitmap(b,c)` then `B(bitmap,z)` :2063 | executor |
| native call | `B()` :2500 → `RLottieNative.c()` → `nGetFrame` | executor |
| stop/recycle | `ImageReceiver` :3661 / `ci0.C(Z)` :2680 → `l()`, `n()`, `D(Z)` :2807 | UI |
| destroy post | `D()` :2812 builds `eb0(native, 0xF)`; `Z ? t5.a(r)` (main Handler) `: Utilities.e.c(r)` | UI |
| actual free | `eb0` case 0xF :848 → `RLottieNative.d()` → `nDestroy` | **main/UI thread** |

`f()` also re-posts the next frame (`v0` → `i0.h3(runnable, delay)`) at 60 fps,
so while an animation plays the executor is inside `nGetFrame` for a sizable
fraction of every 16.7 ms period.

**There is no `Future`, no `shutdown()`, no `awaitTermination`, and no join
between `D()` and the in-flight frame task.** That is the bug.

### 1.3 Trigger sequences (all reachable from the chat list)

1. **Cold start / bind**: `DialogCell.onDraw` → `o5.drawAnimatedEmojis` →
   `AnimatedEmojiDrawable` (`f5`) → `ImageReceiver.B()` → `ci0.start()` →
   executor render. (Reachability of the bot-owned custom emoji in the
   last-message text/caption was verified in the two prior notes.)
2. **Scroll / rebind / detach**: the cell's `ImageReceiver` is recycled
   (`ImageReceiver` :3661 `ci0.C(Z)`, `:2557` `stop()`), which posts the
   destroy while the executor may still be rendering the previous frame.
3. **Animation end**: the last frame returns, then `p()`/`D()` runs — this one
   is *after* the render, so it is not the interesting case.
4. **Color-variant rebuild**: `B()` :2342 replaces `m0` and calls `old.d()`
   **on the executor thread** — a destroy on the same thread as the render;
   no cross-thread race, but it shows the same object can be destroyed from
   more than one place.

The window is (executor inside `tlottie_render_with_options`) ∩ (UI thread in
`tlottie_drop`). Because the destroy is *posted*, it lands at an arbitrary
point of the frame loop, i.e. exactly the randomization we model below.

---

## 2. Making the race reliably winnable

The window equals the duration of one `tlottie_render_with_options` call.
It is attacker-influenced through the TGS content and the target bitmap size.

### 2.1 Normal stickers are far too fast on the host

80 real Telegram animations (`iOS/submodules/TelegramUI/Resources/Animations`),
30 frames each, `results/render_time.csv`:

| canvas | p50 (median of p50s) | worst p50 | worst single frame |
|---|---|---|---|
| 48×48 | 9.0 µs | 31 µs | 100 µs |
| 96×96 | 15.5 µs | 53 µs | 181 µs |
| 160×160 | 23.5 µs | 67 µs | 318 µs |

Duty cycle at 60 fps is 0.1–2 %, which is why the host lifecycle model shows
0/40 hits for a normal asset. On a phone these numbers are a few times larger
but still far below 16.7 ms.

### 2.2 A 10 KB valid TGS makes one frame last 14 ms

`src/gen_heavy_tgs.py` builds valid Lottie documents that stay inside every
tlottie limit (`max_layers 2304`, `max_path_points 4096`,
`max_render_points 1 048 576`, `max_render_work 4 194 304`,
`max_parse_bytes 13 031 466`) and gzip far below Telegram's documented
64 KiB sticker cap because the layers are structurally identical and differ
only in transform numbers (so the coverage cache still misses per layer).

Generated payloads (`pocs/`):

| payload | gzip | layers | frames | result at 96×96 (host) |
|---|---|---|---|---|
| `mx_20.tgs` | 6,210 B | 20 | 30 | 17/30 frames OK then `-3`, **5.2 ms/frame** |
| `mx_30.tgs` | 7,211 B | 30 | 30 | 11/30 frames then `-3`, **7.3 ms/frame** |
| `mx_60.tgs` | 10,160 B | 60 | 30 | 6/30 frames then `-3`, **14.1 ms/frame** |

(`-3` is tlottie's clean `LimitExceeded`; the app stops the animation at that
point, but the time is already spent *inside* `nGetFrame`, which is all the
race needs.)

Per-size table (`logs/heavy_render_times.txt`, p50):

| payload | 32 px | 48 px | 64 px | 96 px | 144 px |
|---|---|---|---|---|---|
| mx_20 | 2.25 ms | 3.23 ms | 3.98 ms | 5.21 ms | 6.83 ms |
| mx_30 | 3.50 ms | 4.59 ms | 5.85 ms | 7.32 ms | 9.74 ms |
| mx_60 | 6.14 ms | 8.49 ms | 10.49 ms | 14.14 ms | 18.75 ms |

A custom emoji in a dialog cell is drawn at text size: `AnimatedEmojiDrawable`
uses 19/20/26 dp sizes (`f5.x()` constants `0x13/0x14/0x1a`), i.e. **57–78 px
at 3× density**, so `mx_60` at 64–96 px is a fair model of a "heavy but legal"
custom emoji, and it already occupies **60–85 % of a 60 fps period**. On a slower phone the same payload will exceed the period and the
executor thread will be inside `nGetFrame` essentially continuously during
playback.

### 2.3 Hit-rate measurements (`logs/lifecycle_rates.txt`)

`src/uaf_lifecycle_model.cpp` models the Java objects exactly (AtomicBoolean
CAS in `d()`, handle read after the check in `c()`, `m0` null before the post,
`eb0`-style destroy on a UI thread, 4-thread executor, 60 fps pacing, real
tlottie C API). Each trial runs in a forked child so a crash does not stop the
campaign; a shared page records "the free happened while the executor was
inside `nGetFrame`" *before* the free, so a crash still counts as a hit.

| scenario | destroy time | result |
|---|---|---|
| model validation: normal asset + injected 5 ms inside the native call | uniform 0–100 ms | **32/100 hits (32 %)** — matches the 5/16.7 ms = 30 % duty; 32/32 hit children crashed |
| normal asset, no injection | uniform 0–500 ms | **0/40** |
| `mx_20` @64 px | uniform 0–500 ms | **27/100 (27 %)**; 27/27 crashed (`free(): invalid pointer`) |
| `mx_20` @96 px | uniform 0–500 ms | **17/100**; 16/17 crashed |
| `mx_60` @96 px | uniform 0–500 ms | **15/100**; 15/15 crashed |
| `mx_60` @96 px | uniform 0–100 ms (the 0.5 s playback window) | **81/100**; 81/81 crashed |

Reading the last row: once a heavy emoji is playing, nearly every detach that
happens during playback frees the instance while the executor is rendering it.
The 0–500 ms rows are diluted by the 400 ms after the animation has stopped,
which is irrelevant to the attack: the attacker needs **one** detach during
playback, and scrolling produces detaches continuously.

The important consequence for reliability: a user who scrolls a chat list while
a heavy custom emoji animates wins with probability ≈ (render duty cycle).
That is the deterministic part; the probabilistic part is only *when* the user
scrolls.

---

## 3. What the race actually does to the heap

### 3.1 ASan: write into a freed scratch buffer

`logs/lifecycle_asan_write.log` (`-fsanitize=address` on the Rust staticlib):

```
ERROR: AddressSanitizer: heap-use-after-free ... WRITE of size 104 ... thread T4
 #0 __asan_memcpy
 #1 core::ptr::write::<tlottie::renderer::cpu::raster::Rasterizer>
 #2 <alloc::vec::Vec<Rasterizer>>::push
 #4 <RenderScratch>::put_raster      src/renderer/cpu/executor.rs:172
 #5 <CPURenderer>::draw              src/renderer/cpu/backend.rs:145
 ...
 #16 tlottie_render_with_options     src/bindings/c_api.rs:232
 #17 RlottieNative::c  ... Ci0::frame_task
0x514000000240 is located 0 bytes inside of 416-byte region
freed by thread T5 here:
 #1 alloc::alloc::dealloc_nonnull
 #9 drop_glue::<RenderScratch>        <-- the UI-thread tlottie_drop
```

A 104-byte object (a `Rasterizer`) is written into a freed 416-byte Vec buffer
owned by the renderer's scratch — a controlled-size heap write into freed
memory, from the executor, while the UI thread is inside `tlottie_drop`.

### 3.2 ASan: read inside the freed instance itself

`logs/lifecycle_asan_mx60.log`:

```
ERROR: AddressSanitizer: heap-use-after-free ... READ of size 8 ... thread T2
 #0 Vec<DirtyBox>::as_slice
 #2 <CPURenderer>::draw              src/renderer/cpu/backend.rs:85
 ...
 #14 RlottieNative::c ... Ci0::frame_task
0x51a0000004d8 is located 1112 bytes inside of 1304-byte region
   (the TLottieInstance box, std-feature layout)
freed by thread T5: UiThread::run  -> free()   (the posted d()/nDestroy)
```

### 3.3 The allocator sees corruption

In the plain glibc build, the hits end in
`free(): invalid pointer`, `munmap_chunk(): invalid pointer`,
`tcache_thread_shutdown(): unaligned tcache chunk detected`,
`double free or corruption (out)`. That is not a read-only UAF: the render
reads stale `Vec` headers out of the freed instance/scratch and calls
`realloc`/`free`/`munmap` on them.

---

## 4. Reclaim of the freed `TLottieInstance`

### 4.1 Object geometry (binary facts)

```
0x106D2A4:  malloc(0x528)            ; 1320 bytes
            aligned = (raw + 0x17) & ~0xF
            [aligned - 8] = raw
0x1094DD8:  memcpy(aligned, template, 0x510)   ; object = 1296 bytes
0x1094884:  ... free(*(void**)(instance-8))
```

Binary-derived field map (arm64 72799):

| offset | field | use |
|---|---|---|
| `+0x000` | `walker: FrameWalker` (moved out with `memcpy 0x260`) | its Vec/HashMap pointers are used by the render |
| `+0x2B0` | second drop-in-place region — inferred `RenderScratch`, which contains `Budget` | the earlier `Budget::transform` UAF |
| `+0x4C8..+0x4F0` | `static_bitmap: Option<StaticBitmap>` — inferred from the fast-path reads at `0x4C8/0x4D8/0x4E0/0x4E4/0x4E6/0x4E8/0x4EC` | fast-path reads |
| `+0x4F0` | **`comp: Arc<Composition>`** | dereferenced and incremented |
| `+0x50B` | `model_validated` | if non-zero, `validate_model` is **skipped** |
| `+0x510` | object size | |

On Android the request `1320 + 16` (Scudo `SizeDelta`) maps to class
**`0x670` = 1648 bytes** (`AndroidSizeClassMap`, 64-bit table; the classes
around it are 0x450 and 0x670). It is ≤ 2048, so it is in the documented
quarantine range.

### 4.2 Scudo behaviour, measured with the real allocator

`src/uaf_reclaim.cpp`, built with `-fsanitize=scudo` (same Scudo code as
bionic; host class map differs, quarantine logic identical). Probe size is
computed from the host layout, so it is exactly the instance's allocation.

| Scudo configuration | first probe reclaim | first instance-address reuse |
|---|---|---|
| runtime default (`SCUDO_OPTIONS` unset — quarantine off in this build) | **cycle 0** (immediate) | cycle 2 |
| `quarantine_size_kb=256:thread_local_quarantine_size_kb=64:quarantine_max_chunk_size=2048` (the values source.android.com documents for Android) | not in 300 cycles at 1 probe/cycle | **cycle 7** in the captured run (7–15 across runs) |

The second row is the important one: the quarantine is bounded, and with
1 probe/cycle the *next instance* wins the block before the probe. A held
flood reproduces the counting: after freeing the instance, **217 same-class
allocations** (3 × 64 + 25) were needed before one landed in the freed block.
That number is the quarantine turnover for this class/workload and matches the
320 KB budget ÷ ~1.6 KB ≈ 200 chunks.

AOSP `flags.inc` (A13/A17) declares `quarantine_size_kb`,
`thread_local_quarantine_size_kb` and `quarantine_max_chunk_size` with default
**0**; the documented 256/64/2048 values are the platform configuration. Which
one a given 2026 device runs could not be checked without a device, and it is
the single biggest unknown in exploitability (see §7).

### 4.3 Reclaiming with attacker bytes

The attacker has two realistic fill sources:

1. **The decompressed TGS JSON string.** `nCreate` builds a `std::string` from
   `gzread` (no cap) and frees it when `nCreate` returns. A TGS whose
   decompressed size lands in the instance's class (≈1336–1648 B on Android)
   gives a *fully attacker-controlled* byte buffer of the right size, allocated
   on a `nCreate` thread. Content does not need to be valid JSON: `readFile`
   returns the bytes before `tlottie_new` rejects them, and the string is
   allocated regardless.
2. **Another `TLottieInstance`.** Same class by construction; contents are a
   valid `CPURenderer` (type confusion, §5.3).

Both are "content-steered" allocations: the attacker influences *what the app
parses*, never calls `malloc` directly. In a chat list with many custom-emoji
documents, the ImageLoader creates/destroys drawables in bursts, so a burst
can plausibly supply the ~200 same-class operations, but this was not measured
in the app (host-only) and is the second unknown.

---

## 5. Post-reclaim behaviour and primitives

### 5.1 The renderer trusts the reclaimed bytes

`sub_105D28C` (`CPURenderer::render`) prologue, from the 72799 binary:

```
LDRB  W8,  [X1,#0x50B]      ; model_validated  (attacker byte)
TBNZ  W8,#0 -> skip validate_model
LDR   X8,  [X19,#0x4F0]     ; comp  (attacker pointer)
LDRB  W9,  [X8,#0x58]       ; Composition::is_static (deref of attacker pointer)
...
LDXR  X9,  [X8]             ; Arc::clone
ADD   X10, X9, #1
STXR  W11, X10, [X8]        ;  *(u64*)comp += 1     <-- controlled increment
...
memcpy(dst, X19, 0x260)     ; core::mem::take(&mut self.walker)
memcpy(X19, default, 0x260) ; write Default back into the object
```

So after reclaim the next `nGetFrame` on the stale handle:

1. skips model validation if the attacker byte at `+0x50B` is non-zero;
2. dereferences the attacker 8-byte `comp` pointer (read of `[comp+0x58]`);
3. **increments the 64-bit value at `[comp]` by one** (atomic, loop on
   store-exclusive failure);
4. copies 0x260 attacker bytes out as the `walker` and zeroes that region;
5. runs the renderer with attacker-derived `walker`/`scratch` pointers.

### 5.2 Demonstrated: arbitrary 8-byte increment at an attacker-chosen address

`src/uaf_reclaim.cpp window` (real Scudo build): create A, `tlottie_drop(A)`
(the Java guard already passed), flood 1320-byte buffers filled with
`fake_comp` until one overlaps A's block, then call
`tlottie_render_with_options((TLottieInstance*)A, …)`.

```
-- quarantine disabled --
reclaimed inst=0x7f8ffcc18c10 with probe=0x7f8ffcc18c10 (delta=0)
render crashed after using the reclaimed object (recovered)
fake_comp=0x7fa1fd386000 refcount_before=0 after=1 delta=1

-- Android-doc quarantine (217 allocations needed) --
reclaimed inst=0x7f9931029c10 with probe=0x7f9931029c10 (delta=0)
render crashed after using the reclaimed object (recovered)
fake_comp=0x7fa931720000 refcount_before=0 after=1 delta=1
```

The crash afterwards is Scudo refusing a free of an attacker-derived pointer
(`Scudo ERROR: misaligned pointer when deallocating address 0x…438`) — i.e. the
renderer also performs an **arbitrary-free attempt** from the same reclaimed
bytes, and the 0x260-byte "walker" it copies out is fully attacker data. The
signal handler recovers only to print the counter; in the app the process dies.

This is a genuine control primitive, but it is *one primitive*, not a chain:

* value is **+1** per render (repeatable while the frame loop keeps calling
  the stale handle, but the garbage state usually crashes on the first call);
* target address must be known (ASLR);
* no control-flow target exists inside the object: `CPURenderer` is a concrete
  Rust struct with **no vtable/function pointer** (`FrameRenderer` is a generic,
  statically dispatched), so PAC/arm64e pointer authentication is not even the
  limiting factor — there is nothing to overwrite that would be called.

### 5.3 Type confusion without any address knowledge

If the block is reclaimed by another live instance (plain
`tlottie_new` from a concurrent sticker load), the stale handle aliases a
*valid* `CPURenderer` for animation B. Two threads then call
`render(&mut self)` on the same object. `with_bitmap` rejects most overlaps
(`already has a bound bitmap`) but `state.rasters`, `surfaces`, `walker` and
`cov_cache` are mutated outside that guard:

* ASan (`logs/alias_asan_capture.log`, `logs/alias_asan.log`):
  `heap-use-after-free` in `Rasterizer::draw_line` / `fill_contours_translated`
  and in `RawVecInner::non_null` — one thread renders from a raster buffer
  another thread already returned to the pool.
* Scudo (`logs/alias_scudo_abort.log`):
  `ERROR: invalid chunk state when deallocating address …` (double free
  detected → abort).
* glibc: `double free or corruption (out)` / SIGSEGV.

Crash rate over 20 fresh processes, 4 threads × 300 renders on one instance:
**plain 9/20, ASan 8/20, Scudo 1/20** (`logs/alias_crash_rate.txt`). With two
threads the bitmap guard serialises nearly everything and the run is clean.

No leak and no address is needed for this variant — only the reclaim. On a
device the observable result today is an abort (Scudo detects the double free),
so this is a **crash**, with the usual "if the chunk is reallocated between the
free and the second free, it becomes a real double-free primitive" caveat.

---

## 6. Constraints that stop this short of RCE

| Constraint | Effect |
|---|---|
| **ASLR** | The controlled-`comp` path needs a mapped, known address. The JS/QuickJS surfaces of this app have leaks, but the TGS path returns only pixels and a frame index — no pointer ever crosses back to Java. Without a separate leak the fake composition is a wild-pointer crash. |
| **No function pointers in the object** | Rust `CPURenderer` is a concrete struct; the renderer is generic. There is no vtable to redirect; a pc-control step needs a *data* corruption (e.g. a Vec length) converted later. PAC is irrelevant until such a step exists. |
| **+1 increment only** | `Arc::clone` increments by one. Useful to nudge a refcount/length, not to write an arbitrary value. |
| **Scudo quarantine (if enabled)** | The freed 1648-byte class chunk needs ~200 same-class operations inside the window. Measured 217 in the model. Whether the app's burst rate reaches that in 10–100 ms is unproven. |
| **Scudo double-free detection** | The no-leak aliasing path aborts on the second free unless the chunk is reallocated in between (the same 200-allocation grooming problem). |
| **MTE (device-dependent)** | If the app process runs with MTE (opt-in per app on ARMv8.5+), the first UAF access is a tag check failure → deterministic crash, no reuse. The reference device used in `notes/scudo_bypass_notes.md` (Sony XQ-BT52) has no MTE. |
| **Attacker cannot allocate natively** | Everything is content-steered through TGS documents. There is no primitive that lets a bot request a specific `malloc` at a specific time. |

**Honest classification: remote, race-dependent memory corruption with a
reliable crash (DoS), plus a demonstrated conditional arbitrary-increment /
arbitrary-free primitive and a conditional no-leak type-confusion double free.
No RCE was achieved and the evidence does not support claiming one.**

---

## 7. What would change the verdict

1. **A pointer leak reachable from the same trigger.** Any of: an info leak in
   the sticker/emoji metadata path, a renderer error that returns a pointer,
   or a Java-side log of a native address. With a heap base, §5.2 becomes a
   usable arbitrary increment; with two known addresses it becomes a
   length/refcount corruption step.
2. **A measured in-app allocation burst ≥ ~200 same-class chunks within the
   render window.** The heavy payload gives a 14 ms window on the host
   (probably 50–100 ms on a phone); a chat list with dozens of custom emoji
   scrolled quickly is the natural candidate. A device trace of
   `nCreate`/`nDestroy` rates would settle it.
3. **Confirmation of the device's Scudo configuration.** If a device runs with
   the quarantine disabled (AOSP code default), reclaim is *immediate* and the
   whole analysis shifts from "grooming required" to "reclaim is free"; if it
   runs with the documented 256/64/2048, §4.2 applies.
4. **A non-crashing fake composition.** The host model crashes right after the
   increment because the copied walker/scratch is garbage. A crafted 1320-byte
   payload that also satisfies `FrameWalker`'s invariants would let the frame
   loop keep calling the stale handle and turn the increment into a repeated
   write primitive. Not attempted here.

---

## 8. Survival

* The **message and the cached `.tgs` persist** in the chat DB / document
  cache. Nothing about the trigger is one-shot: every cold start that draws
  the dialog list re-creates and re-renders the emoji, and every scroll past
  the message re-runs the start/destroy cycle.
* The vulnerable code is **app-bundled**: `libtmessages.49.so` (tlottie
  `31f1b54` + `lottie.cpp`) and the Java `RLottieNative` / `ci0` wrapper. It is
  not an OS decoder and does not depend on the device patch level.
* **An app update fixes it** by adding a mutex or an in-flight guard/refcount
  around `nGetFrame`/`nDestroy`, or by making `d()` wait for the executor task.
  Until such an update is installed the behaviour is unchanged; the client has
  no server-side mitigation other than refusing the emoji.
* The same tlottie commit is pinned by iOS (`TLottieAnimation.mm`), but the
  racy lifecycle is the Android JNI/`ci0` wrapper; iOS was not analysed here.

---

## 9. Reproduction

```
lab/tgs_uaf_weaponization/
  src/tgs_common.h              gzip read identical to lottie.cpp readFile()
  src/layout_probe.c            host layout of the pinned staticlib
  src/render_time.cpp           per-frame render cost
  src/gen_heavy_tgs.py          valid heavy TGS generator (limits respected)
  src/uaf_lifecycle_model.cpp   Java-guard + executor/UI model, fork-per-trial
  src/uaf_reclaim.cpp           Scudo reclaim distance + post-reclaim primitive
  src/uaf_alias.cpp             forced type-confusion / double-render model
  run_all.sh                    reproduces every number in this note
  logs/, results/, pocs/, evidence/
```

Build prerequisites (host): clang 19, Rust 1.98, zlib.

```
# Android-faithful tlottie staticlib (same features/profile as build_tlottie.sh)
cd /tmp/opencode/tlottie-uaf
cargo rustc --no-default-features --features cpu,no-std,c-api \
  --profile release-nostd --lib --crate-type staticlib
# ASan staticlib for the UAF reports
RUSTC_BOOTSTRAP=1 RUSTFLAGS="-Zsanitizer=address -Cdebuginfo=2" \
  cargo rustc --release --features c-api,std --lib --crate-type staticlib
# everything
cd lab/tgs_uaf_weaponization && ./run_all.sh
```

Key logs: `logs/lifecycle_rates.txt`, `logs/lifecycle_asan_write.log`,
`logs/lifecycle_asan_mx60.log`, `logs/reclaim_drain.txt`,
`logs/reclaim_primitive.txt`, `logs/alias_results.txt`,
`logs/alias_asan_capture.log`, `logs/alias_scudo_abort.log`,
`logs/alias_crash_rate.txt`, `logs/heavy_render_times.txt`,
`results/render_time.csv`.

---

## 10. Limits

* Host x86_64 measurements; no device and no emulator. Absolute timings differ
  on arm64 phones (the payload is 10 KB, so it is deliverable; the *ratio* to a
  normal sticker is the transferable result).
* The lifecycle model reproduces the Java state machine from the smali, but the
  Android runtime (Handler latency, ART GC, `ExecutorService` scheduling) was
  not run.
* The host Scudo is `scudo_standalone` with a different size-class map than
  Android; class *behaviour* and quarantine logic are the same, the exact
  chunk counts are not.
* Scudo's Android configuration on a given device is not verified; AOSP's code
  default is quarantine 0, the documented platform values are 256/64/2048.
* The heavy payload is a valid Lottie that satisfies the documented sticker
  rules, but the Telegram server's upload validation (does it parse/limit
  layers?) was not tested.
