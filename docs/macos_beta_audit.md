# macOS Telegram beta 13.1.0 (283434) — build map, quickjs widget sandbox, TGS/Lottie

Date: 2026-11-02. Host-only (no device, no VM, no macOS). Lab:
`lab/macos_beta/` (extracted app + arm64 slices + evidence). This note does not
modify the main report and does not repeat the Android findings; it only maps the
macOS beta against them.

Question asked: **does the macOS beta carry (a) the quickjs widget sandbox that the
Android widget bug (#1827/#1865) attacks, and (b) the `tlottie`/`RLottie` TGS
parser that carries the Android check-then-free UAF?**

---

## 0. Verdict

| Question | Result |
|---|---|
| Is the app native AppKit/Swift (not Catalyst/Electron)? | **Native Swift/ObjC++**, universal x86_64+arm64, `ru.keepcoder.Telegram`, Developer ID `TELEGRAM MESSENGER LLP (6N38VWS5BX)`, hardened runtime, **not** App-Sandboxed. |
| Does it embed quickjs-ng? | **Yes.** `quickjs.c`/`libunicode.c` strings, `JS_EvalThis2`, `__JS_EvalInternal`, `JSEvalOptions` version check; runtime `BC_VERSION = 29`. |
| Does it embed the Android widget sandbox? | **Yes, a newer port of it.** Swift module `WidgetSandbox` (`SandboxEngine`, `QuickJSContext`, `ValidatorPool`, `EnginePool`, `RendererPool`, `WidgetFeed`, `WidgetBubble`), shipping the *same* `WidgetJS/{sandbox,validator,renderer}-bundle.js` (+`.qbc`) as the Android APK. Sandbox JS header: `widget-sandbox version=0.6.0 protocol=1 profile=1 sdk=1`. |
| Is untrusted widget JS evaluated in quickjs on macOS? | **Yes** — same split as Android: `sandbox-bundle.qbc` is evaluated by the quickjs engine (`sandbox bundle eval %.0f ms`), the DOM layer compiles inline handlers with `new Function`, refuses `<script src>` at runtime (`external script not available:`), and only *rendering* happens in `RendererWKWebView` (`renderer-bundle.js`). |
| Is the message path reachable? | **Yes.** TL `MessageMedia.messageMediaWidget` / `Cons_messageMediaWidget`, `TelegramCore19TelegramMediaWidget`, `isWidgetMessage`, `MessageWidgetDataChange`, `LocalWidgetMessages.swift`, `WidgetQueries.swift`, UI `WidgetBubble`/`WidgetContainerView`/`WidgetShellPool`. |
| Is the Android #1827 bug class present in the macOS engine? | **Yes, in code.** The macOS `JS_RegExpDelete` is the **pre-fix** order, identical to the Android binary: `re->bytecode` snapshot at `0x10314aac4`, flags test `&0x21` at `0x10314aaf8`, `lastIndex` getter only inside that branch at `0x10314ab10`, `lre_exec` at `0x10314aeb0` with the saved pointer. Upstream PR #1827 is unmerged as of 2026-11-02, so this is expected for any upstream-pinned quickjs-ng. |
| Does the Android TGS `tlottie` UAF apply? | **Not as a race.** The **same Rust `tlottie`** *is* present — in the main binary *and* in `TelegramShare.appex` (11 exported `_tlottie_*` C functions; `TLottieBridge` ObjC++ wrapper). But the macOS wrapper holds a **`std::mutex`** and locks around both `tlottie_render` and the `tlottie_drop` path; the Android bug is the *absence* of any lock/refcount in the Java `RLottieNative` wrapper. |
| Does macOS use C++ `rlottie`? | **No.** No `rlottie` namespace symbols, no `lottiemodel`/`vdrawable`/`LottieParser` strings, zero lottie `.cpp` sources; the front-end is Swift (`TelegramMedia/LottiePlayer.swift`, `LottieAnimation`, `LottieRenderer`, `MetalRenderer`) over the Rust `tlottie` C API. |
| Is a stored widget message evaluated at app launch (chat list / dialog preview)? | **No.** No `ChatList*` type carries any widget/HTML/sandbox state; the dialog row is text + static image/video preview. The widget is instantiated only by the chat view (`ChatHTMLRowItem` → `HTMLBubbleView` → `WidgetSandbox`). No widget extension, no notification extension, no restorable-state implementation, no login item. See §12. |
| Bottom line | **The quickjs widget class of bug is present and architecturally the same as Android, with the same un-fixed RegExp primitive in the shipped engine. The TGS bug is not: the same Rust renderer is used, but behind a mutex-protected wrapper, so the Android check-then-free does not reproduce.** The macOS widget is a **chat-open trigger**, not a reboot-surviving app-loaded payload. No exploit is claimed; see §9 for what is *not* proven. |

---

## 1. Artifact and build identity

| item | value |
|---|---|
| DMG | `<HOME>/ailocal/Telegram/macosbeta/Telegram.dmg`, 165,482,588 B, md5 `8e7077c4333475e0c8327b59e09080e9` |
| Extraction | `7z x Telegram.dmg -oextract` → `extract/Telegram/Telegram.app` (HFS+, 377 MB) |
| Bundle id | `ru.keepcoder.Telegram` |
| Version / build | **13.1.0 (283434)**, `SOURCE = BETA` |
| Published | Sparkle feed `https://mac-updates.telegram.org/beta/versions.xml` lists build 283434 with `pubDate 2026-02-11 18:19:19`; the feed uses **dd-mm-yyyy** (other entries read `2026-31-10`), i.e. **2026-11-02**, the same day as this audit. |
| Minimum OS | `LSMinimumSystemVersion 10.13` |
| Toolchain | `DTSDKName macosx26.2`, `DTXcode 2620`, `DTXcodeBuild 17C52`, `DTPlatformBuild 25C57`, `BuildMachineOSBuild 25C56` |
| Signing | `Developer ID Application: TELEGRAM MESSENGER LLP (6N38VWS5BX)`, `flags=0x10000` (**hardened runtime**), CMS timestamped; no `CSSLOT_TICKET` (0x10002) blob in the executable (DMG-level stapling not assessable after 7z extraction) |
| Entitlements | `com.apple.security.app-sandbox = **false**`; app groups `6N38VWS5BX.ru.keepcoder.Telegram[.TelegramShare]`; `device.audio-input`, `device.camera`, `personal-information.location` |
| Arch | universal: x86_64 slice 140,839,408 B @0x4000; **arm64 slice 122,868,768 B** @140,869,632 |
| Main binary | `Contents/MacOS/Telegram`, 263,738,400 B, md5 `8aa2ed46aff8014d7176439e6e07c24a` |
| Share appex | `Contents/PlugIns/TelegramShare.appex/Contents/MacOS/TelegramShare`, 85,160,160 B (arm64 slice 40,055,008 B), `ru.keepcoder.Telegram.TelegramShare` |
| Frameworks | only the Swift runtime dylibs + `Sparkle.framework` (1.21.0). No third-party Lottie/quickjs dylib. |
| Symbol state | main binary stripped (5,294 symtab entries, 189 defined); **share appex not stripped (206,555 defined symbols)** |

Not sandboxed is relevant: a memory-corruption primitive in the main process would
land in a normal user-level process with full file access, as on Android (app UID).

---

## 2. What is in the binary (build map)

Source paths embedded in the main binary (`<HOME>/build-Beta/...`) show the build:

| root | what it is |
|---|---|
| `telegrammacos/Telegram-Mac` | the new Swift macOS app (AppKit + SwiftUI) |
| `telegrammacos/submodules/telegram-ios` | shared iOS code (TelegramCore, TelegramUI, …), incl. `TelegramCore/Sources/TelegramEngine/Messages/LocalWidgetMessages.swift`, `WidgetQueries.swift`, `State/AvailableReactions.swift` |
| `telegrammacos/packages/*` | Swift packages: `TelegramMedia`, `TelegramMediaUtils`, `ChatUI`, `WidgetUI`, `HTMLBubbles`, `HTMLSandbox`, `HTMLScript`, `TwidgetRenderer`, `StarsUI`, … |
| `telegrammacos/core-xprojects/webrtc` | WebRTC C++ (absl/webrtc symbols present) |
| `telegrammacos/submodules/tgcalls` | calls |
| Rust (`vendor/ton`, `ton_core`, `uniffi_core 0.32.0`, `flate2/miniz_oxide`, `curve25519-dalek`, …) | TON wallet only — **no lottie crate** |

C++ present: webrtc/absl, `litehtml`, boost::regex, `td::` (TDLib). No `rlottie`.

Resource bundles of interest: `WidgetSandbox_WidgetSandbox.bundle`, `twidget_Twidget3D.bundle`
(`twidget3d.js`, `three.js`), `HTMLBubbles_HTMLBubbles.bundle`.

---

## 3. quickjs-ng: present, version, build config

| evidence | where |
|---|---|
| `quickjs.c`, `libunicode.c`, `js_calloc_rt`, `JS_EnqueueJob`, `js_free_rt: malloc_size underflow: freeing %zu but only %zu tracked` | main binary strings |
| `JS_EvalThis2`, `bad JSEvalOptions version`, `__JS_EvalInternal` | quickjs-ng API (Bellard's quickjs has no `JSEvalOptions`) |
| **runtime `BC_VERSION = 29`** | `0x103116cf4: mov w9, #0x1d` (vararg for `"invalid version (%d expected=%d)"` at `0x10565d1e2`, xref `0x103116cfc`) — the version check inside `JS_ReadObjectAtoms`; same function computes the bytecode checksum |
| `.qbc` header `TWQB` v1 + quickjs bytecode starting with `0x1d` (29) | `WidgetJS/sandbox-bundle.qbc`, `validator-bundle.qbc` |
| BC_VERSION 29 introduced upstream on **2026-10-09** (`c359cac`, "Fix template literal substitution (#1811)") | local quickjs-ng git |

So the shipped engine is quickjs-ng master/0.18.0-era (0.18.0 was tagged 2026-11-01;
build 283434 is 2026-11-02). `BC_VERSION 29` is also what the Android 72789 `.qbc`
uses, so both clients are on the same bytecode generation.

**Build-config difference:** the macOS binary keeps quickjs `assert()` condition
strings (`js_class_has_bytecode(p->class_id)`, `list_empty(&rt->gc_obj_list)`,
`stack_len < POP_STACK_LEN_MAX`), i.e. `NDEBUG` is **not** defined. The Android
`libtmessages.49.so` has none of them (and no `JS_EvalThis2`/`quickjs.c`, consistent
with `-DNDEBUG` + `--gc-sections` + bytecode-only evaluation). Consequence: on macOS
many corruptions will trip a quickjs invariant and abort instead of continuing —
this lowers exploitability, it does not remove the memory-safety bug.

---

## 4. The widget sandbox on macOS

Same architecture as Android, ported to Swift and split in two runtimes:

```
bot message  messageMediaWidget (TL)  →  TelegramCore TelegramMediaWidget
   → WidgetSandbox.WidgetFeed / WidgetExecutor / WidgetBubble
   → SandboxEngine ── quickjs ── sandbox-bundle.qbc   (untrusted widget JS + DOM)
   → RendererWKWebView ── WKWebView ── renderer-bundle.js (paint only)
   → TrustedValidator ── quickjs ── validator-bundle.qbc (sanitizer/measure)
```

| component | evidence |
|---|---|
| engine classes | `_TtC13WidgetSandbox14QuickJSContext`, `…13SandboxEngine`, `…16SandboxResources`, `…13ValidatorPool`, `…10EnginePool`, `…12RendererPool`, `…8JSThread`, `…9MainPacer` |
| renderer | `…15RendererWebView`, `…17RendererWKWebView`, `…21RendererSchemeHandler`, `…19SharedSchemeHandler`; CSP `script-src 'nonce-…'`, `connect-src 'none'`, content-rule-list blocking `http/https/ws/wss/ftp` |
| resources | `WidgetSandbox_WidgetSandbox.bundle/Contents/Resources/WidgetJS/{sandbox,validator,renderer}-bundle.js` + `.qbc` (identical file names to Android `assets/WidgetSandbox/WidgetJS/`) |
| engine runs untrusted JS | `sandbox bundle eval %.0f ms (%@%@)`, `sandbox bundle failed to load`, `bytecode: compiled from a different source (stale .qbc?)`, `…falling back to source` |
| DOM in the sandbox | the 597 KB `sandbox-bundle.js` implements `document`, `createElement`, `querySelector`, `addEventListener`, `requestAnimationFrame`, `localStorage`, and compiles inline handlers with `new Function("event", "with(this)…")` |
| script policy at runtime | `external script not available: ` (a widget `<script src>` is refused at execution time, i.e. inline scripts do run) |
| caps (same family as Android) | `memoryLimitBytes`, `Memory limit exceeded (`, `cpuQuotaWindowMs`, `CPU limit exceeded`, `maxTimerDelay`, `timer-limit-enforced`, `haptics over 5 per burst…` |
| action gating | same wording as Android: “it needs a tap on the visible widget, one request per tap”, “a preview (an inline result not sent yet) takes no actions”, “the server allows no requests for this message (no can_query…)”. |
| pacing (new vs Android) | `WidgetFeed` (`visible`, `isPrepared`, `delay`, `followUpInterval`, `lastExamined`), `MainPacer` (`mainBudget`, `currentSliceMs`, `preempt`) — boot may be deferred until visible |

Sandbox JS version: macOS bundle header `/* widget-sandbox version=0.6.0 protocol=1 profile=1 sdk=1 */`.
Android's asset has no header comment and differs (`sandbox-bundle.js` 596,053 B vs
596,965 B; `validator` 269,440 vs 272,918; `renderer` 34,542 vs 46,751) — a newer
build of the same sandbox, not a different design.

**Conclusion:** on macOS a bot-supplied widget is parsed and its `<script>` runs in
quickjs-ng, exactly as on Android; the WKWebView only paints the ops the sandbox
produces. Reachability is the same class: a widget message in any chat.

---

## 5. The Android #1827 primitive in the macOS binary

The Android widget RCE uses quickjs-ng PR #1827 (`JS_RegExpDelete` snapshots
`re->bytecode` before coercing `lastIndex`, then uses the stale pointer). `#1827`
was opened 2026-10-15 and is still unmerged (also not in v0.18.0), so upstream
quickjs-ng builds remain affected. The macOS binary matches the **un-fixed** order:

```
0x10314aa28  JS_RegExpDelete prologue
0x10314aa68    ldrh w8,[x1,#0x12] ; cmp w8,#0x13      ; JS_CLASS_REGEXP == 19
0x10314aac4    ldr  x8,[x22,#0x38]                    ; re_bytecode = str8(re->bytecode)  <-- snapshot
0x10314aaf0    bl   lre_get_flags
0x10314aaf8    mov  w8,#0x21                          ; LRE_FLAG_GLOBAL|STICKY
0x10314aafc    ands w24,w0,w8
0x10314ab00    b.eq 0x10314abec                       ; no getter unless g/y
0x10314ab10    mov  w3,#0x5d                          ; JS_ATOM_lastIndex == 93
0x10314ab20    bl   <property get, atom 0x5d>         ; attacker getter runs AFTER the snapshot
0x10314ab28    cmp  w26,#0x6 ; b.eq …                ; exception check on the getter result
0x10314ab34..  cmn w26,#0x9 …                        ; ToLength coercion of lastIndex
…
0x10314ae9c    mov  x0,x23 ; ldr x1,[sp,#0x20]        ; saved bytecode from the snapshot (0x10314aea0)
0x10314aeb0    bl   lre_exec                           ; uses the (possibly dangling) bytecode
0x10314b004    mov  w3,#0x5d …                        ; lastIndex write-back (atom 93)
```

Cross-check: the only load of `[x22,#0x38]` in the function is at `0x10314aac4`
(nothing re-reads `re->bytecode` after the getter), and the same function contains
the `"out of memory in regexp execution"` (`0x10314b064`) and
`"corrupted bytecode in regexp execution"` (`0x10314b070`) error paths, i.e. it is
the same `JS_RegExpDelete` analysed in the Android note, compiled with the same
pre-fix ordering.

`RegExp.prototype.compile` is available to sandbox JS: the sandbox bundle only strips
network/worker globals (`fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`,
`RTCPeerConnection`, `Worker`, `SharedWorker`, `importScripts`, `open`); it does not
freeze or delete `RegExp`. So the #1827 trigger shape
(`"ccc".replace(re, "")` with `re.lastIndex = { valueOf() { re.compile("b","g") } }`)
is expressible from a widget script.

---

## 6. TGS / Lottie: which implementation is on macOS

Both implementations are present, and they are *not* what the Android note assumed:

| item | main binary `Telegram` | `TelegramShare.appex` |
|---|---|---|
| Rust `tlottie` C API | **yes** — `TLOTTIE_COV_BUDGET_KB`, `CPU renderer already has a bound bitmap`, `fresh fill requires dense rasterizer`, `render size out of range`, `TLottieInstance` | **yes** — 11 exported `T` symbols: `_tlottie_new`, `_tlottie_new_with_options`, `_tlottie_render`, `_tlottie_render_with_options`, `_tlottie_render_alpha8[_with_options]`, `_tlottie_frame_count/_frame_rate/_width/_height`, `_tlottie_drop` |
| ObjC++ bridge | `TLottieBridge` class, ivars: `_mutex` (**std::mutex**), `_json`, `_colors`, `_colorsChanged`, `_instance` (`TLottieInstance*`), `_scratch`, `_width/_height/_frameCount/_fps` | identical 10 ivars / 10 methods |
| Swift front-end | `TelegramMedia/LottiePlayer.swift`: `LottieAnimation`, `LottieAnimationKey`, `LottieRenderer` (private), `RendererState`, `MetalRenderer`, `MetalContext`, `LottiePlayerView`, `LottieSoundEffect`, `TRLotData`, `RenderedLottieFrame`; hooks `TelegramMediaUtils/LottieRenderHooks.swift` (`install must be called before lottie rendering is used`), protocol `LottieRendererBridge` / `LottieFrameRenderer`, `makeLottieRenderer` | `SE_LottieAnimation`, `SE_LottieRenderer`, `SE_LottieRunLoop`, `LottieColor`, `LottieAnimationKey` |
| C++ `rlottie` | **absent** (no namespace/typeinfo, no lottie `.cpp`, no `lottiemodel`/`vdrawable`) | absent |
| Rust lottie crate | absent from cargo paths (only TON wallet crates) | — |

### 6.1 Why the Android race does not reproduce

The Android UAF is not a tlottie-internal bug: it is the Java wrapper
(`RLottieNative.c()` tests `destroyed.get()` then reads the handle; `d()` posts
`nDestroy` → `tlottie_drop` on the UI thread) racing a render on a 4-thread pool,
with **no lock and no refcount** in the C API.

On macOS the wrapper is `TLottieBridge` and it carries a `std::mutex`:

* render path (appex `imp 0x1016ca3a8`): validates `width≥1`, `height≥1`,
  `width*4 ≤ buffer_length`, then `std::mutex::lock` (stub `0x1019a0a7c`) →
  `tlottie_render` (`0x1016ca4b0`) → `std::mutex::unlock`;
* destroy path (appex `imp 0x1016c9660`): `std::mutex::lock` → `tlottie_drop`
  (`0x1016c9678`) → unlock;
* main binary `TLottieBridge` methods call the same `std::mutex::lock/unlock`
  (e.g. imps at file offsets `0x45c2d8c`, `0x45c2e04`, `0x45c3ac4`), with the same
  ivar layout.

So a render and a destroy of the same `TLottieInstance` cannot overlap; the
`_instance` pointer is only touched under the lock. **Verdict: the Android
check-then-free UAF class is absent in the macOS wrapper** (it is a different
wrapper around the *same* renderer).

### 6.2 What is still shared with Android

* The same Rust parser/renderer code (same error strings, same C API). The macOS
  build includes the `std`-gated coverage-budget code (`TLOTTIE_COV_BUDGET_KB`)
  that the Android `no_std` build drops — a feature-set difference, not a fork.
* Unbounded-decompression risk before parsing: the shared `MTGzip` wrapper does
  carry a cap (`[MTGzip refusing to inflate beyond %lu bytes]`, libz 1.2.12), so
  the Android "64 KiB → 67 MB" amplification has a different shape here; not
  measured in this audit.

---

## 7. Second quickjs surface: HTML messages with scripts

Independent of widgets, the app ships an HTML message pipeline with two runtimes:

`_TtC10HTMLScript16HTMLScriptEngine`, `…15HTMLScriptClock`, `…16JSCScriptRuntime`,
`…14QuickJSContext`, `…20QuickJSScriptRuntime`, `…20QuickJSScriptContext`,
`_TtC11HTMLSandbox8JSThread`, plus `<script>` regexes
(`<script\b[^>]*>([\s\S]*?)</script\s*>`, `src="app:…"`), `lc-script-error` UI and
a `chat:restart-script` link. Both a JavaScriptCore and a quickjs implementation are
linked; which one is selected per message/policy is not resolved statically. This is
a second quickjs exposure to hostile script text and should be included in any
follow-up test plan.

---

## 8. Differences from Android (honest list)

| aspect | Android 72789 | macOS 283434 |
|---|---|---|
| quickjs presence | yes (widget sandbox + validator) | yes (widget sandbox + validator + HTML scripts) |
| quickjs build | `NDEBUG`, bytecode-only (`JS_EvalThis2` GC'd) | asserts **on**, both source and bytecode |
| `.qbc` BC version | 29 | 29 |
| widget JS bundle | older, no version header | `0.6.0 protocol=1 profile=1 sdk=1` |
| widget script execution | at bind time, no interaction | sandbox runs scripts; `WidgetFeed`/`MainPacer` may defer boot until visible |
| #1827 regexp order | pre-fix | pre-fix (same code sequence) |
| TGS renderer | Rust `tlottie` (`no_std`) | Rust `tlottie` (`std`) behind **mutex-protected** `TLottieBridge` |
| TGS wrapper race | yes (Java check-then-act, no lock) | no (std::mutex around render and drop) |
| app sandbox | Android app UID | **not** App-Sandboxed (hardened runtime only) |

---

## 9. What this audit does **not** prove

1. **No dynamic execution.** Nothing was run: no macOS host, no lldb, no crafted
   widget message. “Same bug class” is a static/code-level statement, not a repro.
2. The #1827 sequence was verified by disassembly shape (class check, bytecode
   snapshot, flags test, `lastIndex` getter, saved pointer into `lre_exec`), not by
   tracing a live `compile()`-driven free. The exact reachability of a freed
   `re->bytecode` depends on quickjs object lifetime at runtime.
3. Widget script execution *without interaction* on macOS is inferred from the
   architecture (sandbox bundle + DOM + `external script not available`) and the
   shared preview/action strings; the `WidgetFeed` pacing means the trigger may
   require the widget to be on-screen.
4. The main-binary `TLottieBridge` locking was shown via `std::mutex::lock/unlock`
   calls in its methods; the drop call itself could not be resolved by name in the
   stripped main binary (it is resolved in the appex, which has symbols and the same
   class/layout).
5. No fuzzing of the macOS `tlottie` or quickjs builds; build-config differences
   (asserts) change crash behaviour.

---

## 10. Next tests (ordered, all host-side where possible)

1. **Engine repro on the host:** build quickjs-ng at `BC_VERSION 29` (0.18.0),
   run the #1827 shape in `qjs`, then repeat with `-DNDEBUG` off/on to see the
   macOS crash mode (assert vs UAF).
2. **Widget path, no Apple hardware:** unpack the macOS `sandbox-bundle.qbc`
   (`TWQB` header 24 B + quickjs bytecode) and load it in the same 0.18.0 engine to
   confirm the bundle's own boot path and the DOM/`new Function` layer run as
   expected.
3. **On a macOS host/VM (not available here):** send a bot widget message whose
   `<script>` sets `lastIndex` to a `valueOf` that calls `compile()`, with
   `MallocScribble`/`MallocGuardEdges` or ASan; confirm whether the app aborts on an
   assert before any primitive.
4. **Widget boot timing:** instrument the “sandbox bundle eval” / “external script
   not available” log lines to establish whether script execution happens before
   any tap and before the widget is visible.
5. **TGS:** confirm by disassembly of the main binary’s `TLottieBridge` dealloc that
   the drop is under the same mutex (or by building `tlottie` + the bridge source and
   running a render/destroy race — the Android model predicted 81 % hit rate with no
   lock; a locked wrapper should show 0).
6. **HTML messages:** determine which runtime (`JSCScriptRuntime` vs
   `QuickJSScriptRuntime`) is chosen for a received HTML message and whether it is
   reachable from a bot.

---

## 11. Reproduction

See `lab/macos_beta/README.md` for the exact commands. Evidence files:

| file | content |
|---|---|
| `lab/macos_beta/evidence/info_plist.txt` | full Info.plist dump |
| `lab/macos_beta/evidence/codesign.txt` | code directories, Team ID, flags, entitlements (both slices) |
| `lab/macos_beta/evidence/hashes.txt` | DMG / main binary / arm64 slice / appex hashes |
| `lab/macos_beta/evidence/quickjs_bc29.txt` | `mov w9,#0x1d` → “invalid version” disassembly |
| `lab/macos_beta/evidence/jsregexpdelete.txt` | pre-fix `JS_RegExpDelete` sequence |
| `lab/macos_beta/work/strings_arm64.txt` | 401,825 strings from the arm64 slice |
| `lab/macos_beta/work/strings_share.txt` | appex strings (tlottie, SE_Lottie, Rust paths) |
| `lab/macos_beta/work/machoxref.py`, `stub.py`, `objcdump.py`, `parse_cs.py`, `bctest.c` | tooling used |
| `lab/macos_beta/work/swiftmeta.py` | Swift nominal-type / field-descriptor dumper (§12) |
| `lab/macos_beta/evidence/chatlist_vs_bubble.txt` | field dumps for chat-list vs bubble vs sandbox types (§12) |
| `lab/macos_beta/evidence/startup_paths.txt` | extensions, restoration, login-item, Spotlight probes (§12) |

Key bytecode check used to date the engine (`.qbc` payload starts at offset 0x18:
`1d` = BC_VERSION 29, then u32 checksum, then the atom table):
`/tmp/opencode/bctest.c` linked against quickjs-ng 0.17.0 answers
`SyntaxError: invalid version (29 expected=28)` at 0x18 — i.e. the bundle was
produced by a BC-29 engine, and the macOS binary itself expects 29.

---

## 12. Startup reachability — is a stored widget evaluated at launch? (follow-up, 2026-11-02)

Question: a bot widget message sits in the local DB. Does the macOS app render/evaluate it
in the chat list / dialog preview at launch (before the user opens the chat), which would
make the quickjs payload load on every app start? Static only, no execution.

### 12.1 Method

The main binary is stripped, so the UI object graph was recovered from Swift metadata:
`__TEXT,__swift5_types` (nominal type descriptors) → `__swift5_fieldmd` (field descriptors)
→ `__swift5_reflstr` (field names). Tool: `lab/macos_beta/work/swiftmeta.py`
(14,669 nominal types parsed). Field **names** are reliable; cross-module field **types**
are stored as Swift symbolic references and were not decoded (see caveat 12.6). The
unstripped `TelegramShare.appex` (206,555 symbols) is used as a cross-check.

### 12.2 Where the widget actually lives: the message bubble

```
DB message  MessageMedia.messageMediaWidget (TL) / TelegramCore.TelegramMediaWidget
            {width,height,payload,isCopy,canQuery,backgroundQuery,chatData,publicData,
             publicDataHash,widgetId,invertMedia,peerIds}
   → ChatUI.ChatHTMLRowItem            (message row; fields: state, widget, twidgetObserver, renderWidth…)
   → HTMLBubbles.HTMLBubbleState       (isWidget, isWidgetMessage, widgetRequestHandler, widgetVisible,
                                        widgetPreview, currentWidgetData, attachedWidgetContext,
                                        twidgetBubble, twidgetLayout(s), twidgetRenderer, twidgetLiveKey,
                                        twidgetHasHost, twidgetSnapshot…)
   → HTMLBubbles.HTMLBubbleView        (state, twidgetView, twidgetSnapshotLayer, shownTwidgetSnapshot,
                                        $__lazy_storage_$_twidgetContainer)
   → WidgetSandbox.WidgetBubble        (slot, html, options, width, theme, host, height, feed, rendererFactory…)
   → WidgetSandbox.WidgetFeed          (policy, delay, spaces, live, visible, snapshots, paused, pressureSource…)
   → WidgetSandbox.SandboxEngine       (html, config, resources, js, prewarmed, bundleEval, timers,
                                        memoryLimitBytes, cpuQuotaWindowMs…)
   → quickjs-ng
```

The message HTML is carried by the bubble (`WidgetBubble.html` → `SandboxEngine.html`);
the engine is a per-bubble object. Full field dumps:
`lab/macos_beta/evidence/chatlist_vs_bubble.txt`.

### 12.3 The chat list has no widget path

| type (ChatListUI) | fields relevant to rendering |
|---|---|
| `ChatListRowItem` (93 fields) | `messages`, `peer`, `displayLayout`, `dateLayout`, `messageLayout`, `messageSelectedLayout`, `chatNameLayout`, `topicsLayout`, `photo(s)`, `contentImageSize`, `contentImageSpecs`, `badgeNode`, `story`, `draft`, `mentionsCount`, `reactionsCount`, `pollVotesCount`, … — text layouts + thumbnail geometry only |
| `ChatListRowView` (50 fields) | `chatNameText`, `dateTextView`, `messageText`, `storyReplyImageView`, `forumTopicTextView`, `topicsView`, `photoVideoView`, `photoVideoPlayer`, `animatedView`, `pollVotesView`, `reactionsView`, `badgeView`, `mentionsView`, … — CoreText layers + image/video views |
| `ChatListTextLayer` | `drawLayer` (CoreText) |
| `ChatListMediaPreviewView` | `context`, `message`, `media`, `imageView`, `playIcon`, `disposable`, `shimmer`, `inkView` — static image / video thumbnail |
| `ChatListMessageRowItem` | 0 stored fields |

Automated negative: **no type whose name starts with `ChatList` has any field matching
`html|bubble|sandbox|twidget|widget`** (script output in
`evidence/chatlist_vs_bubble.txt`). The dialog row is a CoreText compositor plus an
optional static/video image; there is no bubble, no HTML state and no sandbox handle in
the chat-list data model.

The only ChatListUI HTML artifact is an **app-internal demo**: `HTMLDemoChatListRowItem`,
`UIChatListEntryId.htmlDemo`, `ChatCustomContentsKind.htmlDemo`,
`PeersListController.htmlDemoContents: HTMLDemoChatCache`, driven by
`HTMLDemoPreset` cases `allWidgets` / `voxelClash`, bundled `voxel-clash.html` and the fixed
remote origin `https://voxel-clash-production.up.railway.app`. Its content is bundled or
fixed-origin app content, not the bot message from the DB.

### 12.4 Startup-path inventory

| startup path | present in the bundle? | evaluates a stored widget? |
|---|---|---|
| chat list / dialog preview | yes: `PeersListController`, `ChatListRowItem/View`, `ChatListMediaPreviewView` | **no** (12.3) |
| window / state restoration | no `setRestorable:` / `isRestorable` in the binary; the `application:willEncodeRestorableState:`-style strings are the wholesale `NSApplicationDelegate` protocol list in `__objc_methname`, not evidence of implementation | no; launch state is the empty pane (`"EmptyPeer.Description" = "Select a chat to start messaging"`) |
| notification service extension | **none** (`UNNotificationServiceExtension` = 0, `com.apple.notification-service` = 0) | no |
| macOS widget extension (WidgetKit) | **none** (`WidgetKit` = 0; only `TelegramShare.appex` in `Contents/PlugIns`) | no |
| share extension | `TelegramShare.appex`: **0** `WidgetSandbox` symbols and **0** `HTMLBubble` symbols in 206,555 defined symbols | cannot evaluate widget JS at all |
| Spotlight / CoreSpotlight | `SpotlightItem`, `SpotlightContext`, `CSSearchableItem` — text indexing | no rendering |
| NSUserActivity / Handoff / Spotlight launch | opens a chat only on user action | no |
| login item / launch at boot | no `SMAppService`, no `LaunchAgent` | app does not register itself to start at login |
| sandbox prewarm | `SandboxEngine.prewarmed` / `prewarmRequested` | evaluates only the **signed** bundle; the message HTML is assigned per bubble (`SandboxEngine.html`) |

Probe output: `lab/macos_beta/evidence/startup_paths.txt`.

### 12.5 Attacker-controlled vs signed content

* **Signed, fixed:** `Contents/Resources/WidgetSandbox_WidgetSandbox.bundle/.../WidgetJS/
  {sandbox,validator,renderer}-bundle.js` and `.qbc` (inside the Developer ID signature /
  CodeResources).
* **Attacker-controlled:** only the message fields `TelegramMediaWidget.payload`,
  `chatData`, `publicData`, `widgetId` — they reach `SandboxEngine.html` when, and only
  when, a bubble is built for that message.

So a payload must be a message that obtains a bubble. Nothing in the launch path reads
that field.

### 12.6 Verdict

**No startup path on macOS 13.1.0 (283434) renders or evaluates a stored widget message.**
At launch the app shows the chat list (CoreText rows + static previews) with no chat
selected; the quickjs sandbox is instantiated by the chat view
(`ChatHTMLRowItem` → `HTMLBubbleView` → `WidgetBubble` → `SandboxEngine`). The stored
widget message is therefore a **chat-open trigger** on macOS, not a reboot-surviving
app-loaded payload. (The app also does not register a login item, so it is not started by
the OS at boot unless the user configured that manually.)

Caveats:

* Field names are reliable; cross-module field *types* are Swift symbolic references that
  this audit did not decode. A code path that builds a bubble without storing it in a
  field cannot be excluded from metadata alone — but the chat-list row/view/preview types
  hold no widget, HTML or sandbox state, and the row view is a text/image compositor.
* The demo row can host HTML in the chat list, but only app/bundled content
  (`HTMLDemoPreset`, `voxel-clash.html`).
* Nothing was executed on macOS; this is a static structure argument.

### 12.7 Next tests

1. On a macOS host: store a widget message (last message of a chat), quit, relaunch, and
   look for `sandbox bundle eval` / widget log lines *before* any chat is opened. Expected:
   none.
2. Check `ChatPreviewModalController` (hover/“Preview” context action) — if it builds a
   message list it can render the widget on hover; that is still user-initiated.
3. Confirm the `htmlDemo` entry is gated (test mode / `HTMLWidgetTestMode`) and not created
   for normal accounts.
4. If a launch-time payload is required on macOS, the surfaces that *do* run at launch are
   the chat-list avatars/photos, story preload and notification attachments (image
   decoders), not quickjs.
