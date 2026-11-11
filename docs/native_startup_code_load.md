# Native startup code-load audit — Telegram Android 72799 (fresh pass)

Date: 2026-11-02
Target: `org.telegram.messenger.beta` 13.2.0 beta, versionCode **72799**, arm64
(`lib/arm64-v8a/libtmessages.49.so`, 27,016,000 B, md5
`2c0caa68a07fc26f79d13519af6c3526`, BuildId
`645cce3998197329915f6cbfcc9ffd7f124d9f86`; `liblanguage_id_l2c_jni.so`,
1,019,552 B, md5 `96bf0e71fe2033edfd0bc5b26fb8a8f1`).
Host/IDA only — no device and no emulator were used in this pass.

Scope of this note: a **fresh, independent audit of the native side** — every
startup native library, every `JNI_OnLoad` / `INIT_ARRAY` constructor, every JNI
entry point, and every place where native code could turn a file into code.
Goal: a Telegram-specific native loader that consumes **app-data** content at
**app startup** and **executes** it (not merely parses it), surviving reboot —
without the widget/QuickJS path.

Separate from the main report (`REPORT_20261102.md`), which is not modified.
Lab: `lab/native_startup_code_load/` (ranked table, evidence dumps, scripts,
device plan).

---

## 0. Verdict (short)

1. **No native code in this build loads code from app data at startup.**
   The startup native closure — 18 `INIT_ARRAY` constructors + `JNI_OnLoad`,
   **244 functions** of 80,521, computed on the CFG-restricted call graph —
   touches **no** `open`/`fopen`/`mmap`/`mprotect`/`dlopen`/`dlsym`/`exec`.
   Its 43 external calls are `pthread_*`, `getenv`
   (`LH_NO_SVG_GROUP_CACHE`), `__system_property_get("ro.arch")`,
   `getauxval`, `dl_iterate_phdr` (PC→module lookup), `openlog`/`syslog`,
   `newlocale`, libc memory/string/stdio primitives, and exactly one raw
   syscall — `syscall(178 /* gettid */)` inside `__cxa_guard_acquire`
   (`sub_16CEC98`).

2. **No JNI entry point reaches a code loader with attacker-controlled input.**
   483 unique JNI entry functions were tested — the 422 `Java_*`-named functions
   in the IDB (418 of them exported) plus the 84 `JNINativeMethod` table slots,
   23 of which overlap. Direct-call reachability: `dlopen` **0**,
   `sqlite3LoadExtension` **0**, `mprotect` **0**. The 14 `dlsym` hits are
   Rust/OpenSSL infrastructure looking up fixed libc symbols
   (`android_set_abort_message`, `getrandom`). `wasm_runtime_load` is reached
   only through virtual dispatch — Java → `InstanceV2Impl` → `CallCoreHost`
   (`sub_B49274`) → `WamrCoreBackend::load` — and always with the embedded
   module bytes (§4).

3. Two **real code-load engines** exist inside `libtmessages.49.so`, both
   documented below and both **not attacker-fed**:
   * **WAMR** (WebAssembly Micro Runtime, tgcalls `v2wasm`) — fast interpreter
     + **AOT loader that relocates into `mmap`ed text and `mprotect`s it RX/RWX**
     (`0xfefb04` prot=7, `0xfefc7c` prot=5). Its module bytes are the
     **embedded** 83,472-byte wasm blob at `.rodata:0x2C8818`; there is exactly
     one `\0asm` magic in the whole library. No file, no socket, no asset.
   * **SQLite extension loading** — `load_extension()` → `sqlite3LoadExtension`
     (`0x1823b38`) → VFS `xDlOpen` = `sub_181CA18` = `dlopen(path, RTLD_NOW|RTLD_GLOBAL)`.
     This *is* a genuine "app-data `.so` → code" path, but it is gated on
     `db->flags & SQLITE_LoadExtension` (0x10000) and the **only** setter of
     that flag (`sqlite3_enable_load_extension`, which ORs `0x30000`) is not
     present in the binary: no `0x30000` and no `0xFFFCFFFF` immediate exists
     anywhere in `.text`. `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` is not
     exposed by Telegram's JNI wrapper and would in any case only set
     `SQLITE_LoadExtension`, while the SQL function also requires
     `SQLITE_LoadExtFunc` (0x20000).

4. **What is genuinely new** versus the earlier notes (which already said
   "SQLite `load_extension` compiled but disabled"):
   * the **previously missing proof**: the four `sqlite3_vfs` structs
     (`0x19CA300` "unix" …) carry a working `xDlOpen` = `sub_181CA18`
     (`dlopen(path, RTLD_NOW|RTLD_GLOBAL)` at `0x181CA20`), i.e. the whole
     chain exists in this ELF, and the reason it cannot fire is that
     `sqlite3_enable_load_extension` — the only setter of `0x30000` — was
     garbage-collected (no `0x30000` and no `0xFFFCFFFF` immediate anywhere in
     4,519,791 instructions of `.text`);
   * the startup closure is now **computed** (244 functions, CFG-restricted)
     rather than argued, and it contains **no** file/dlopen/mmap/exec API;
   * the WAMR finding is confirmed and sharpened: single embedded `\0asm` blob
     at `.rodata:0x2C8818` (`0x14610` bytes), one constructor call
     (`0xB4A824`), and the AOT module loader's two executable `mprotect`s
     (`0xFEFB04` prot=7, `0xFEFC7C` prot=5) reachable only from that path.
   * the litehtml `getenv` string is **`LH_NO_SVG_GROUP_CACHE`**
     (`0x83D1F0`), not `LH_SVG_LATE_CACHE`.
   * in this build the SQL `load_extension()` refusal text is
     **`"not authorized"`** (`0x24DC59`, xref `0x18209A8`), not
     `"unsafe use of load_extension()"` (that string does not exist in the
     binary); the device expectation in
     `notes/loader_startup_components.md` should be updated when re-tested.

5. **Structural fact that changes the shape of the problem:** the APK ships
   exactly **two** native libraries per ABI — `libtmessages.49.so` and
   `liblanguage_id_l2c_jni.so`. Everything usually listed as a "bundled
   library" (`tgnet`, SQLite 3.39.3, FFmpeg/media3, OpenSSL, WebP, Skia,
   lottie/rlottie, libvpx, opus, lz4, tgcalls/tg_owt, WAMR, Breakpad, Rust std)
   is **statically linked into `libtmessages.49.so`**. Auditing "the bundled
   libraries" therefore means auditing symbols and call sites inside one ELF,
   not separate `.so` files.

---

## 1. Ranked table

Legend — **Code**: actually loads/executes code, not data parsing.
**Startup**: reached before/at `w0.onCreate` (process start / `JNI_OnLoad` /
`INIT_ARRAY` / `native_init`). **App-data**: a UID 10357-writable file is the
input. **Verdict** is what an attacker with app-UID code execution can do with
it *today*.

| # | Surface | Exact entry point | Code | Startup | App-data | Verdict |
|---|---|---|---|---|---|---|
| 1 | WAMR wasm/AOT engine (tgcalls `v2wasm`) | `wasm_runtime_load` `0xFB3DAC`; AOT loader `sub_FED93C` (`mprotect` prot=7 @`0xFEFB04`, prot=5 @`0xFEFC7C`) | **yes** | no (call setup) | **no** — module is embedded `.rodata:0x2C8818`, len `0x14610` | **REAL ENGINE, NOT FED.** No app-data path; would become a loader if the module ever came from a file/asset |
| 2 | SQLite `load_extension()` | SQL fn name @`0x28A420` → `sub_1823B38` → VFS `xDlOpen` `sub_181CA18` (`dlopen` @`0x181CA20`) | **yes** | DB open is startup; extension call is not | **yes** (a `.so` path in SQL) | **LATENT NO-GO.** Enabler absent from binary; DB flag can't be set from Java |
| 3 | `ks` local-lib fallback | `System.load(files/lib/libtmessages.49loc.so)` `ks.smali:1672`, `:2803` | **yes** | only inside `catch(Error)` of `System.loadLibrary("tmessages.49")` | **yes** | **REAL LOADER, DEAD GATE.** No app-data action makes the first `loadLibrary` throw |
| 4 | `JNI_OnLoad` + `INIT_ARRAY` | `0x16EFA34`, 18 ctors `0x19594C8..0x1959550` | no | **yes** (dlopen-time) | no | **NO-GO** — closure of 244 functions has zero file/exec APIs |
| 5 | tgnet config | `native_init` `0x752314` → `sub_1009B74` → `loadConfig` `0x10035D8` → `files/tgnet.dat` | no (binary config parser) | **yes** (ConnectionsManager ctor) | **yes** | **NO-GO** (parse only; fields are ints/strings/DC options) |
| 6 | Media / FFmpeg / opus / rlottie / WebP | `AnimatedFileNative_nCreateDecoder` `0x74DC98`, `MediaController_*` `0x16F1xxx`, `RLottieNative_nGetFrame` `0x750228` | no (decode) | no | yes (media cache) | **NO-GO** (data parsing; covered by decoder audits) |
| 7 | WebRTC `dlopen` | `sub_A45BD0` @`0xA45F5C`/`0xA45FAC` → `dlopen("libnetd_client.so", 2/6)` | **yes** but fixed system lib | no (VoIP call path, virtual dispatch via vtable `0x18CAA20`) | no | **NO-GO** |
| 8 | Breakpad raw `execve` | `svc` #59 @`0x158AEB4` / `0x158B9B0` in syscall shim | **yes** | no | no | **NO-GO** (dead: `setupNativeCrashesListener` has 0 callers) |
| 9 | MLKit `liblanguage_id_l2c_jni.so` | 3 JNI fns; model = `assets/tflite_langid.tflite.jpg` | no (TFLite inference) | ctors: yes, no I/O; model load: on demand | no (APK asset) | **NO-GO** |
| 10 | ART runtime image `cache/oat_primary/arm64/base.art` | ART generic | **yes** | **yes** | **yes** | **out of native scope**; prior audit (`loader_startup_components.md`, `loader_art.md`): update-fragile, crashes in `InitializeClass` |
| 11 | twidget / QuickJS bytecode | `assets/WidgetSandbox/WidgetJS/*.qbc` copied to cache with digest check | **yes** (JS VM) | no (widget view) | cached copy yes, **hash-checked against the asset** | **NO-GO** (excluded by task; integrity-gated anyway) |

CSV: `lab/native_startup_code_load/ranked_table.csv`.

---

## 2. What actually runs at startup (exact)

### 2.1 Load order

`w0.onCreate` (`smali/org/telegram/messenger/w0.smali:2263`) →
`ks.g` (`:2734`) → `System.loadLibrary("tmessages.49")` (`ks.smali:1484`).

Android's `dlopen` then runs:

1. `.init_array` — 18 entries. The file bytes at `0x19594C8..0x1959550` are
   zero; the targets come from `R_AARCH64_RELATIVE` relocations
   (`outputs/init_array_relocs.txt`):

   | slot | ctor | what it does |
   |---|---|---|
   | `0x19594C8` | `0x109A60C` | `getauxval(AT_HWCAP)` + `__system_property_get("ro.arch")` → Exynos-9810 CPU-feature workaround |
   | `0x19594D0` | `0x109A8BC` | same family (hwcap init) |
   | `0x19594D8` | `0x16AE860` | static object + `__cxa_atexit` |
   | `0x19594E0` | `0x742544` | function-local static #1 |
   | `0x19594E8` | `0x7425E4` | function-local static #2 |
   | `0x19594F0` | `0x742684` | function-local static #3 |
   | `0x19594F8` | `0x74738C` | atexit pair (gifvideo) |
   | `0x1959500` | `0x83D1F0` | litehtml `getenv("LH_NO_SVG_GROUP_CACHE")` |
   | `0x1959508` | `0x86E4B8` | litehtml static tables (`aspect-ratio`, `orientation`, …) |
   | `0x1959510` | `0x86F544` | litehtml `render_item_block` RTTI tables |
   | `0x1959518` | `0x8927DC` | litehtml tag/CSS property tables |
   | `0x1959520` | `0x8A920C` | litehtml (2,880 B, no strings) |
   | `0x1959528` | `0x8B68A0` | small static init |
   | `0x1959530` | `0x99A97C` | small static init |
   | `0x1959538` | `0xA6ABD0` | WebRTC/tg_owt static init (4 feature probes + atexit); strings `WebRTC-Manager` |
   | `0x1959540` | `0xA9BD54` | WebRTC static init |
   | `0x1959548` | `0xAB9398` | WebRTC static init |
   | `0x1959550` | `0x147079C` | small static init |

   There is **no `DT_INIT`** (`readelf -d`: only `INIT_ARRAY`/`FINI_ARRAY`).

2. `JNI_OnLoad` `0x16EFA34` — `GetEnv(vm,&env,0x10006)`, then four
   `RegisterNatives` batches (`0x74ECC0` AnimatedFileDrawableStream,
   `0x7529D4` tgnet `NativeByteBuffer`+`ConnectionsManager`,
   `0x755ABC` media3 FFmpeg, `0x987CAC` twidget — failure tolerated),
   `0xA5801C` `GetJavaVM`, `srand(time())`. All class/method names are
   compile-time literals (`outputs/jni_tables.txt`).

3. `w0.onCreate:2740` → `ConnectionsManager.native_setJava(false)` →
   `0x752914` (stores the JavaVM, installs 5 per-DC timer objects). No file.

4. `ConnectionsManager.<init>(I)` → `init(...)` (smali line 1468) →
   `native_init` `0x752314` → `sub_1009B74` → `loadConfig` `0x10035D8`
   → `fopen(<files>/tgnet.dat)` + `fread`.

### 2.2 The startup native closure contains no file API

`scripts/reach.py` builds a call graph from the IDB (80,521 functions,
188,320 edges) and — importantly — restricts each function to the basic blocks
**reachable from its entry** (`qflow_chart_t` + BFS over successors). That
matters: IDA's function ranges include outlined cold chunks, and the naive
"all instructions in range" graph produces a false positive
(`sub_AE69EC → sub_B00490 → libc++ filebuf::open`) that is *not* reachable from
the function entry (`0xAE69EC` is a single `B 0xAEAB28`; only 8 of 954 blocks
are live). Result after the fix:

```
roots = 18 ctors + JNI_OnLoad
union = 244 reachable functions of 80,521
dlopen            NOT reachable      mmap          NOT reachable
dlsym             NOT reachable      mprotect      NOT reachable
open/openat       NOT reachable      read/fread    NOT reachable
fopen             NOT reachable      AAsset*_open  NOT reachable
stat/access/...   NOT reachable      getenv        REACHABLE (0x83D1F0)
dl_iterate_phdr   REACHABLE (unwinder PC->module lookup)
__system_property_get REACHABLE ("ro.arch")
```

Full list: `outputs/startup_reachable.txt`; the import-call-site inventory:
`outputs/sink_inventory.txt`; raw dumps: `outputs/imports_xrefs.json`,
`outputs/import_callers.json`.

The 43 external functions reached are, in full: `.abort`,
`.__android_log_print`, `.android_set_abort_message`, `.closelog`,
`.__cxa_atexit`, `.dl_iterate_phdr`, `.fflush`, `.fprintf`, `.fputc`, `.free`,
`.fwrite`, `.getauxval`, `.getenv`, `.getpid`, `.malloc`, `.memchr`, `.memcmp`,
`.memcpy`, `.memmove`, `.memset`, `.newlocale`, `.openlog`, `.posix_memalign`,
`.pthread_cond_broadcast`, `.pthread_cond_wait`, `.pthread_getspecific`,
`.pthread_mutex_lock`, `.pthread_mutex_unlock`, `.pthread_once`,
`.pthread_rwlock_rdlock`, `.pthread_rwlock_unlock`, `.pthread_rwlock_wrlock`,
`.pthread_setspecific`, `.realloc`, `.srand`, `.strlen`, `.strncmp`, `.syscall`,
`.syslog`, `.__system_property_get`, `.time`, `.vasprintf`, `.vfprintf`.
`.syscall` is `syscall(178)` = `gettid` in `__cxa_guard_acquire`
(`sub_16CEC98`). `.fprintf`/`.fwrite`/`.fputc` write to the `stderr` FILE that
litehtml/WebRTC already hold; no path is opened.

**Consequence:** nothing in `JNI_OnLoad` or in any constructor can read, map or
execute a file. Any startup native code-load has to be a *different* entry
point (a JNI method invoked from Java during startup, or ART itself).

### 2.3 The JNI side: 483 entries, none reaches a loader

`scripts/jni_reach.py` BFS from every `Java_*`-named function in the IDB (422;
418 of them exported) and every `JNINativeMethod` table slot (84, from
`outputs/jni_tables.txt`) over the same graph — 483 unique roots:

| sink | entries that reach it |
|---|---|
| `dlopen` | **0** |
| `dlsym` | 14 (all `WalletEngine2_*`, path: Rust `std` → `dlsym("android_set_abort_message")`) |
| `sqlite3LoadExtension` | **0** |
| `wasm_runtime_load` / `WamrCoreBackend::load` | **0 by direct call** — reached only via virtual dispatch from the call core (`CallCoreHost`), which is itself outside the direct graph; see §4 |
| `mprotect` | **0** |
| `mmap` | 3 (`RLottieNative_nGetFrame`, twidget `create`/`destroy` — anon `PROT_READ|WRITE` allocators) |
| `AAssetManager_open` | 1 (`MrzRecognizer_performRecognition`, fixed asset) |
| `open` | 3 (`WalletEngine2_nativeTonConnectCrypto`, `AnimatedFileNative_nGetVideoInfo`, `…_nCreateDecoder`) |
| `fopen` | 13 (tgnet `native_init`, twidget `create`, WebRTC log sink, VoIP `makeNativeInstance`, `MediaController_*`, `AudioRecorderNative_*`) |

**Limitation, stated explicitly:** a direct-call graph cannot see virtual
dispatch. Three loader-ish targets are reached only indirectly, and each was
analysed by hand:

* `sub_A45BD0` — WebRTC `NetworkBinderInterface::BindSocketToNetwork`, stored
  in a vtable at `0x18CAA20` (no direct callers). It `dlopen`s the *literal*
  `"libnetd_client.so"` twice (`0xA45F5C` flags 2, `0xA45FAC` flags 6) and
  `dlsym`s `android_setsocknetwork` / `setNetworkForSocket`. Reachable only
  while binding a VoIP socket.
* `sub_B761CC` — `WamrCoreBackend::load`, a vtable slot at `0x18D49F0`; its only
  constructor call is `sub_B7601C(ptr, 0x2C8818, 0x14610)` at `0xB4A824`
  (§4).
* the four `sqlite3_vfs` tables (`0x19CA300` "unix", `0x19CA3A8` "unix-none",
  `0x19CA450` "unix-dotfile", `0x19CA4F8` "unix-excl") whose `xDlOpen` slot is
  `sub_181CA18` (§5).

---

## 3. `libtmessages.49.so`: the code-load inventory in full

Every `dlopen`/`dlsym`/`dladdr`/`dl_iterate_phdr`/`mmap`/`mprotect` call site
was resolved from the import GOT slot to the PLT stub to the containing
function, and every GOT-direct reference (the `0x181Cxx`/`0x181Dxx`/`0x181Exx`
sqlite wrappers call libc with `ldr x8,[got]; blr x8`) was added separately.
Full dump: `outputs/sink_inventory.txt`.

| family | sites | where / what |
|---|---|---|
| `dlopen` | 3 | `0xA45F5C`, `0xA45FAC` = `libnetd_client.so` (literal, flags 2/6); `0x181CA20` = sqlite `unixDlOpen` (`RTLD_NOW|RTLD_GLOBAL`) |
| `dlsym` | 5 | `android_setsocknetwork`, `setNetworkForSocket`, `getrandom`, `android_set_abort_message`, sqlite `xDlSym` |
| `dladdr` | 1 | WebRTC stack-trace symbolisation (`sub_A19C00`) |
| `dl_iterate_phdr` | 2 | unwinder `sub_16EBC30`; Rust backtrace `sub_1665DDC` |
| `mmap` | 7 fns | anon `PROT_READ|WRITE` allocators (`0x105E53C`, `0x1092648`, `0x156EDB8`, `0x16FE8AC`), one read-only file map (`sub_1682640`, prot=1), WAMR `os_mmap` (`0xFB2768`), Rust |
| `mprotect` | 1 wrapper, 8 sites | WAMR `os_mprotect` `0xFB2A70` only; prot values 0/1/3 and **5/7 in the AOT relocation path** |
| `execve`/`system`/`popen`/`fork`/`posix_spawn` | **0 imports** | only `__register_atfork` |
| raw `svc` | 119 | all in `0x1589F90..0x1594390` (Breakpad syscall shim); 2 × `#59` (`execve`) at `0x158AEB4`, `0x158B9B0`, dead |

`android_dlopen_ext` is not imported. There is no `mmap` with `PROT_EXEC`
outside WAMR's AOT path, and no self-modifying-code pattern.

---

## 4. WAMR — the only executable-memory producer (`libtmessages.49.so`)

**What it is.** Telegram bundles Intel's WebAssembly Micro Runtime (fast
interpreter + AOT loader + WASI) for `tgcalls` "v2wasm" (tgcalls v2 call core
compiled to wasm). Evidence:

* `CallCoreHost: WAMR core backend (embedded)` (`0x261C77`);
  `WamrCoreBackend: no module bytes`, `… load failed:`, `… instantiate failed:`,
  `… missing required export`, `… runtime init failed`,
  `… core call trapped:`, `… rt_alloc/rt_free trapped:`;
  source path `<HOME>/Documents/Projects/Telegram/Android/TMessagesProj/jni/tgcalls/tgcalls/v2wasm/WamrCoreBackend.cpp`.
* WAMR proper: `WASM module load failed: %s`, `WASM module instantiate failed: %s`,
  `Init wasi environment failed: …`, `wasi_snapshot_preview1`,
  `aot_intrinsic_*`, `cannot apply relocation to text section for aot file
  generated with "--enable-indirect-mode" flag`, `fast interpreter offset overflow`.

**The module is embedded.** Exactly one `\0asm\1\0\0\0` in the whole 27 MB
library, at `.rodata:0x2C8818`; the constructor call is

```
0xb4a804  MOV  W0,#0xA0          ; operator new(0xA0)
0xb4a80c  ADRP X8,#off_195C4D8   ; LDR X8,[X8] -> 0x2DCE28
0xb4a814  LDR  X2,[X8]           ; X2 = 0x14610  (83,472 = module length)
0xb4a818  ADRP X1,#off_195C4D0
0xb4a820  LDR  X1,[X1]           ; X1 = 0x2C8818 (module bytes)
0xb4a824  BL   sub_B7601C        ; WamrCoreBackend(bytes,len) -> memcpy into heap vector
```

`sub_B7601C` copies the bytes into a heap vector (`+0x40/+0x48/+0x50`);
`sub_B761CC` then does `wasm_runtime_load` (`0xFB3DAC`), `open("/dev/null",2)`
(WASI fd), `wasm_runtime_instantiate` (`0xFB3E88`), `exec_env` (`0xFB3F24`),
and `wasm_runtime_lookup_function` for `core_init`, `core_on_event`,
`rt_alloc`, `rt_free`.

**Executable memory.** The AOT module loader `sub_FED93C` (it references
`"AOT module load failed: %s"`, `"invalid aot section type"` and
`"cannot apply relocation to text section ..."`) maps RW, relocates, then
`mprotect`s to RX/RWX:

```
0xfefaf0  BL  sub_FB2768        ; mmap(..., prot=3, MAP_PRIVATE|MAP_ANON, fd=-1)
0xfefb04  BL  sub_FB2A70        ; mprotect(..., prot=7)   <- RWX
0xfefc7c  BL  sub_FB2A70        ; mprotect(..., prot=5)   <- R|X
0xfefca8  BL  sub_FB2A70        ; mprotect(..., prot=1)
```

**Why it is not a candidate.** No path is opened anywhere in the WAMR core
(`0xFB0000–0xFF4000`); the only `open()` in the v2wasm code is
`open("/dev/null", 2)` in `WamrCoreBackend::load` (`0xB761CC`, for the WASI fd
table). The only module source is the `.rodata` buffer; the module is a *wasm*
binary (magic `\0asm`), so even the AOT relocator is not exercised unless
someone supplies `\0aot`-magic bytes. Also **not startup**: the backend is
constructed by the call core (`CallCoreHost`, `sub_B49274`) when a call is set
up.

**Why it still matters.** This is the only place in the app where a
memory buffer becomes executable, with a full AOT relocation engine (it will
patch a text section). If a future build ever takes the module from
`files/`/`assets/`/the network — or if a bug lets the "embedded" buffer be
replaced — that is instant app-data code execution, with no `dlopen` involved
and therefore none of the usual loader gates. Keep it on the watch list.

---

## 5. SQLite extension loading — compiled in, unreachable

This is the most interesting *native* finding of this pass, because it is a
complete "app-data `.so` → code" chain that exists in the binary.

**The chain (all verified in this IDB):**

```
SQL  load_extension('...')              name string @0x28A420 (sqlite builtin-name table,
                                        referenced from .data 0x19C88B8 / 0x19C8900)
  -> loadExt()                          checks db->flags & SQLITE_LoadExtFunc (0x20000)
                                        else sqlite3_result_error("not authorized")
                                        ("not authorized" @0x24DC59, xref 0x1823B98)
  -> sqlite3LoadExtension               sub_1823B38; first check: (db[0x32] & 1) == 0
                                        -> "not authorized"          [SQLITE_LoadExtension]
  -> xDlOpen = sub_181CA18              dlopen(path, RTLD_NOW|RTLD_GLOBAL)  @0x181CA20
  -> xDlSym  = sub_181CA88              dlsym(h, "sqlite3_extension_init")
  -> call   sqlite3_extension_init(db, ...)
```

**Wiring.** The four `sqlite3_vfs` structs in `.data` all carry that `xDlOpen`:

| vfs | base | `xDlOpen` slot |
|---|---|---|
| `unix` | `0x19CA300` | `0x19CA348` → `0x181CA18` |
| `unix-none` | `0x19CA3A8` | `0x19CA3F0` → `0x181CA18` |
| `unix-dotfile` | `0x19CA450` | `0x19CA498` → `0x181CA18` |
| `unix-excl` | `0x19CA4F8` | `0x19CA540` → `0x181CA18` |

(struct layout: `iVersion/szOsFile` @0, `mxPathname` @8, `pNext` @0x10,
`zName` @0x18, `pAppData` @0x20, `xOpen` @0x28 = `sub_181C13C`, `xDelete` @0x30,
`xAccess` @0x38, `xFullPathname` @0x40, `xDlOpen` @0x48, …)

**Why it cannot fire in this build.**

1. The flag `SQLITE_LoadExtension` (0x10000) is never set. The only API that
   sets it *together with* `SQLITE_LoadExtFunc` is
   `sqlite3_enable_load_extension` (`flags |= 0x30000`, `flags &= ~0x30000`).
   A full `.text` scan (4,519,791 instructions) finds **no** `0x30000` and
   **no** `0xFFFCFFFF` immediate (the only `0x30000` immediates are at
   `0xD9F4E4`, `0xD9F510`, `0xD9F554`, `0x105E76C`, `0x11DF904`, `0x1250D58`,
   `0x148F6C4`, `0x148FCF8`, `0x1494D80`, `0x14953B4`, `0x1633260`, `0x1638BDC`
   — none in the SQLite range `0x17A0000–0x18B13AC`). The function was
   garbage-collected as unused.
2. `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` (the `sqlite3_db_config` op) sets
   only `SQLITE_LoadExtension` (0x10000) — which enables the *C API*
   `sqlite3_load_extension()` but **not** the SQL function, because `loadExt()`
   checks `SQLITE_LoadExtFunc` (0x20000). Telegram's JNI wrapper does not
   expose `db_config` at all (23 `Java_org_telegram_SQLite_*` methods:
   `opendb`, `closedb`, `beginTransaction`, `commitTransaction`, `prepare`,
   `bind*`, `step`, `reset`, `finalize`, `column*`).
3. `Java_org_telegram_SQLite_SQLiteDatabase_opendb` (`0x74C8F0`) calls only
   `sqlite3_open` (`sub_182533C`), then `strcmp` on the path; no flag call.
4. No JNI entry reaches `sqlite3LoadExtension` (§2.3).

So a `cache4.db` trigger/view that calls `load_extension('/data/…/x.so')`
gets **`not authorized`** (`0x24DC59`, raised by `sub_1820960` at `0x18209A8`).
**But** the code is one `sqlite3_enable_load_extension` call away from being a
startup code-load: `cache4.db` is opened during startup, and triggers run on the
first statement touching their table. Anyone who finds a way to call that API
(or a future Telegram build that does) turns the DB file into a loader. Record
this as **latent**, not as a no-go-by-design.

Note on the refusal text: sqlite 3.39.3 says `not authorized` here; the string
`unsafe use of load_extension()` does **not** exist in this ELF. If a device
test observes the latter, it is not this code path.

---

## 6. Everything else, one line each

* **tgnet** — `native_init` `0x752314` converts 11 Java strings
  (`(IIIILjava/lang/String;×11…)`) and calls the tgnet
  `ConnectionsManager` ctor `sub_1009B74`, which calls `loadConfig`
  `sub_10035D8`: `fopen(<dir>/tgnet.dat)` (`sub_102F180`) then a versioned
  binary parse (`sub_102A0CC` = `readInt32` → config version; fields: DC id,
  time difference, push flag, DC option list, …). Save path `sub_1004078` →
  `sub_102F304`. Fixed file name, fixed directory; parsed values are integers,
  strings and DC addresses — no function pointer, no path that reaches
  `dlopen`. Per-JNI reachability: `native_init` reaches `fopen` and `fread`
  only.
* **FFmpeg / media3 / opus / rlottie / WebP / Skia / libvpx / lz4** — decoders.
  `AnimatedFileNative_nCreateDecoder` (`0x74DC98`) and `MediaController_*`
  `open`/`fopen` media files from the media cache; the RLottie JNI entry
  (`RLottieNative_nGetFrame` `0x750228`) reaches only `mmap` with an anonymous
  `PROT_READ|PROT_WRITE` allocator, no file API. WebP/JPEG/AV1 are not exposed
  as JNI in this library (framework `BitmapFactory` / FFmpeg internals), and no
  codec has a `load_extension`-like plugin API.
* **OpenSSL (static)** — no `ENGINE`/`DSO`/provider loading:
  `OPENSSL_memory_alloc/free/get_size` are the only custom hooks in the import
  list; no `OPENSSL_CONF`, `OPENSSL_MODULES`, `providers/`, `engines/` strings;
  `dlopen` has no OpenSSL caller. The only crypto-related dynamic lookup is
  `dlsym(RTLD_DEFAULT,"getrandom")` (`sub_162B714`).
* **BoringSSL/WebRTC (tg_owt)** — the only `dlopen` is `libnetd_client.so`
  (§3); `JNI_OnLoad` registers nothing that takes a path.
* **Rust std** — `dl_iterate_phdr` + `/proc/self/maps` (backtrace),
  `dlsym("android_set_abort_message")`; no `dlopen`, no `mmap(PROT_EXEC)`.
* **Breakpad** — syscall shim at `0x1589F90..0x1594390` with 119 raw `svc`,
  including 2 `execve`; `Java_…_Utilities_setupNativeCrashesListener` has no
  caller in any dex. Dead.
* **`liblanguage_id_l2c_jni.so`** — statically linked TFLite + MLKit
  language-id. 6 `INIT_ARRAY` ctors (`0xE9FA4`, `0xEA5D8`, `0xD53D4`,
  `0xA210C`, `0xBCF54`, `0xBD9BC`): a capstone closure of the reachable code
  from those roots hits only libc/TFLite infra (`getauxval`,
  `__system_property_get`, `pthread_*`, `malloc/free`, `memcpy`, `snprintf`,
  `newlocale`, `log2f`, `android_set_abort_message`, abseil leak-check) — **no
  `open`, `fopen`, `dlopen`, `mmap`, `AAsset*`**. Two `dlopen`s exist in the
  library but are fixed literals (`libandroid.so` at `0xB15A8`, `libdvm.so` at
  `0xB97E4`). The model comes from the APK:
  `ThickLanguageIdentifier.smali:266` `getAssets().openFd("tflite_langid.tflite.jpg")`
  → `nativeInitFromBuffer(MappedByteBuffer,long)`. Not startup, not app data.
* **APK layout** — only two `.so` per ABI (arm64, armv7, x86, x86_64); no
  split APK, no downloaded native component.

---

## 7. Corrections and cross-checks against the earlier notes

| Earlier claim | This pass |
|---|---|
| `loader_startup_components.md` §1/§6: SQLite `load_extension` "compiled, disabled at runtime", device error `unsafe use of load_extension()` | **verdict confirmed, mechanism now exact**: four working `xDlOpen`s + `unixDlOpen`; the enabler is *absent from the binary* (GC'd), not merely never called. In 3.39.3 the refusal string is **`not authorized`** (`0x24DC59`) — `unsafe use of load_extension()` is **not** in this ELF, so the earlier device expectation needs rechecking. |
| `native_appdata_audit/README.md`: "transitive closure … reaches no file API … the only external read is `getenv("LH_SVG_LATE_CACHE")`" | String is **`LH_NO_SVG_GROUP_CACHE`** (`0x83D1F0`). Closure result confirmed and reproduced independently (244 functions, CFG-restricted), plus the full 43-entry external-call list. |
| `code_load_sinks.md`: 13 `mmap` sites, 11 via PLT + 2 via GOT; 1 `mprotect` | consistent; this pass additionally enumerates the **8 `mprotect` call sites** and their prot values, showing prot=7/prot=5 only in WAMR `sub_FED93C`. |
| `code_load_sinks.md`: `dlsym` 5 xrefs incl. `0x181ca90` | confirmed (`sub_181CA88` = sqlite `xDlSym`). |
| prior: "no app-data `dlopen`" | confirmed — but with the precise distinction: the sqlite `dlopen` **can** take an app-data path; it is unreachable because of the flag, not because of the path. |
| prior: `Utilities.setupNativeCrashesListener` never called | confirmed in this pass: 0 `invoke` sites in all four dex; the 2 raw `execve` `svc`s sit in a syscall shim (`0x1589F90..0x1594390`) with no non-crash-handler caller. |

---

## 8. Device test plan

No host-side candidate is worth a device exploitation run (there is no
attacker-controlled input). The plan is therefore **verification of the
negative results** plus **tripwires** that would catch a build where one of the
latent paths becomes live. All commands assume the existing root/`run-as`
access used by the earlier passes; nothing here needs Frida in the final state.

### 8.1 Verify "startup ctors touch no file" (5 min)

```bash
adb shell "am force-stop org.telegram.messenger.beta"
adb logcat -c
adb shell "am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity"
# wait 3 s, then look for any open of app-data files by the main thread before native_setJava
adb shell "cat /proc/<pid>/maps" > /tmp/maps_startup.txt
grep -E "/data/(data|user)/.*\.(so|wasm|qbc|dex|odex|vdex|art)$" /tmp/maps_startup.txt
```
Expected: only `/data/app/~~*/…/lib/arm64/libtmessages.49.so` (r-xp) and
`liblanguage_id_l2c_jni.so` if already loaded; **no** mapping from
`/data/data/…` or `/data/user/0/…`.

### 8.2 Verify SQLite extension loading is refused (10 min)

```bash
adb shell "run-as org.telegram.messenger.beta sh -c \
  'sqlite3 files/cache4.db \"select load_extension(\\\"x\\\");\"'"   # if sqlite3 is on device
```
Without a device `sqlite3`, use the app's own DB via a Java/`app_process`
harness, or simply re-check statically: the flag byte `db+0x32` is 0 because
`sqlite3_enable_load_extension` does not exist in the ELF (`nm`/IDA scan for
`0x30000`/`0xFFFCFFFF`). Expected: `not authorized`.

Tripwire for a future build: repeat the `0x30000`/`0xFFFCFFFF` `.text` scan on
each new `libtmessages.*.so`. If it appears, the DB becomes a startup code
path and gets top priority.

### 8.3 Verify the WAMR module is the embedded one (10 min)

* Static: one `\0asm` magic at `.rodata:0x2C8818`, length `0x14610` from the
  pointer table; `CallCoreHost: WAMR core backend (embedded)`.
* Device (only if a call is placed): map the process during a call and confirm
  the RWX/RX region is anonymous and its content matches the embedded blob
  (`dd if=… skip=$((0x2C8818)) count=$((0x14610))` vs `/proc/pid/mem`), and that
  no file in `files/`/`cache/` contains a `\0asm` or `\0aot` magic at startup:
  ```bash
  adb shell "run-as org.telegram.messenger.beta sh -c \
    'for f in \$(find files cache -type f -size +1k); do \
       head -c4 \$f | od -An -tx1 | grep -q \"00 61 73 6d\" && echo \$f; done'"
  ```

### 8.4 Verify the `ks` gate cannot be triggered from app data (5 min)

```bash
# with app-UID shell:
adb shell "run-as org.telegram.messenger.beta ls -l files/lib"
```
Expected: only `libtmessages.49loc.so` if a past fallback ran; deleting or
corrupting it does **not** matter, because the fallback only runs after
`System.loadLibrary("tmessages.49")` throws. Confirm by checking the order in
`ks.smali:1484` (`loadLibrary` inside `try`) and `:1611` (`catch Error` →
`files/lib/...`).

### 8.5 Tripwires to keep on every new build

1. `INIT_ARRAY` count/size and `DT_INIT` presence (`readelf -d`).
2. Startup closure sink reachability (`scripts/reach.py` on a fresh IDB): must
   stay at 0 file/exec APIs.
3. `0x30000` / `0xFFFCFFFF` scan (SQLite enabler).
4. `\0asm` / `\0aot` magic count and location (WAMR module source).
5. `dlopen` caller count (must stay ≤ 3) and their string arguments.
6. `Java_*` / `JNINativeMethod` delta (new JNI entry that takes a path/byte
   array is the natural place for a future loader).

---

## 9. Files

```
lab/native_startup_code_load/
  README.md                     what/how to reproduce
  ranked_table.md / .csv        the table from §1
  evidence_refs.md              every address/string used above
  no_go.md                      the negative results, one line each
  device_plan.md                §8 expanded with exact commands
  outputs/
    init_array_relocs.txt       18 R_AARCH64_RELATIVE ctor targets
    startup_reachable.txt       244 functions in the startup closure
    sink_inventory.txt          every dlopen/dlsym/mmap/mprotect/exec site
    jni_tables.txt              84 JNINativeMethod entries
    jni_entry_matrix.txt        483 JNI entries × loader sinks
    sqlite_enable_scan.txt      .text immediate scan for the SQLite enabler
    imports_xrefs.json          raw import→xref dump
    import_callers.json         import→PLT stub→callers
    callgraph_cfg.json          CFG-restricted call graph (80,521 fns)
    funcnames.json              address→name map
    ctors_and_jnionload.c       Hex-Rays of the 18 ctors + JNI_OnLoad
    suspicious_callers.c        Hex-Rays of the dl/mmap/exec call sites
    tgnet_native_init.c         native_init / native_setJava / helpers
    tgnet_config_files.c        loadConfig / saveConfig / conf.dat
    wamr_core_backend.c         WamrCoreBackend::load
    mmap_mprotect_sites.c       WAMR os_mmap/os_mprotect + callers
  scripts/
    reach.py                    startup closure vs sinks
    jni_reach.py                JNI-entry matrix
    verify.sh                   re-runs everything from the dumps
```

IDB used: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_media_annotated.i64`
(input md5 verified `2c0caa68a07fc26f79d13519af6c3526`, 80,520 functions at
open; 80,521 after the flow-chart pass created one chunk).

The database was annotated in this pass with the names used above
(`sqlite_unixDlOpen`, `sqlite3LoadExtension`, `wasm_runtime_load`,
`WamrCoreBackend_load`, `wamr_aot_load_module`, `tgnet_loadConfig`,
`webrtc_BindSocketToNetwork`, …) plus 14 comments, saved in place and backed up as a packed, self-contained
`libtmessages_49_arm64_native_startup_annotated.i64` (286,300,139 B). Reopened
after save with `recovery: none`: input md5 identical and all sampled
names/comments present.
