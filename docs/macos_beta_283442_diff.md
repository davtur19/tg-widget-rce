# macOS Telegram beta 13.1.0 (283442) — diff vs 283434

Date: 2026-11-03. Host-only static diff; no macOS host, no device.

## Artifact

| item | 283434 (previous audit) | 283442 (new) |
|---|---|---|
| version / build | 13.1.0 / 283434 | 13.1.0 / **283442** |
| beta feed pubDate | 2026-02-11 18:19:19 (dd-mm-yyyy = 2026-11-02) | 2026-03-11 20:12:33 (dd-mm-yyyy = 2026-11-03) |
| artifact | `macosbeta/Telegram.dmg`, 165,482,588 B, md5 `8e7077c4333475e0c8327b59e09080e9` | `Telegram-13.1.0.283442.app.zip`, 166,020,469 B feed length, md5 `f2ab8d162b8ebf509c19453e92a23ee3` |
| source | Sparkle beta feed `https://mac-updates.telegram.org/beta/versions.xml` | same feed |

The feed description for 283442 is only **"Bug fixes, minor improvements, and more."**
No detailed public changelog; the beta channel is private.

## Binary diff

| slice | 283434 | 283442 | delta |
|---|---:|---:|---:|
| main `Telegram` arm64 | 122,868,768 B | 123,315,408 B | **+446,640** |
| `TelegramShare` appex arm64 | 40,055,008 B | 40,046,560 B | **-8,448** |
| main arm64 sha256 | `6adf3c74b5444e9f87e5dc70cf8bc57e5ea9135fb6d8cfc19c91020497a56bba` | `5f93d018d19caea71ea549cd1daa2279b749acd464fe4bbb8e8af025aed2f8c5` | |
| appex arm64 sha256 | `bb5b75195d5eea5816ae758f781a1233cffe78845247b0c5fb05aeabff0518c2` | `1f1e551ea040558040ab457807bf102771cd549290486dc8766b0d8c6ec90f4b` | |

- `Info.plist`: only `CFBundleVersion` changed (`283434` -> `283442`); bundle id, minimum OS 10.13, Xcode 2620/17C52, SDK macosx26.2 unchanged.
- Code signature/entitlements unchanged: not App-Sandboxed; same app groups, audio/camera/location entitlements; hardened-runtime flags and Team ID unchanged.
- Sparkle framework unchanged: 1.21.0 (90-gfce013f).
- Resources: **587 files, same names and sizes** in both builds; no resource changes.

## Widget sandbox / quickjs — unchanged, #1827 still present

The five `WidgetSandbox_WidgetSandbox.bundle/.../WidgetJS` files are **byte-identical**
between 283434 and 283442:

```
27f90b22b0f2e0878e605555d9b1ccbcaa1f5a16288ac447f6aa1ff0bbf6e14e  renderer-bundle.js
282dcf4bf8152c34aeff86fb32561bb461a4b72263d369e26d6e4e5faadad470  sandbox-bundle.js
ce1250cc53a8e08a6c9c540d34dea84beec72cd7edc6775495bac3306bf34270  sandbox-bundle.qbc
87be4493ccb87e6dcfcaff3370b4a8e9c65cbc96d0a74970ea950c3ebc9693a2  validator-bundle.js
d4dadd20bf1d426a972119f43a7238dd97514875cf30562764c23f67838e760a  validator-bundle.qbc
```

The widget sandbox header is still `widget-sandbox version=0.6.0 protocol=1 profile=1 sdk=1`.
quickjs runtime `BC_VERSION` is still **29** (`mov w9, #0x1d` at `0x10317bf5c`).

The full client path is also still present, with identical string counts in
283434/283442: `MessageMedia.messageMediaWidget` 3/3,
`Cons_messageMediaWidget` 1/1, `isWidgetMessage` 2/2, `WidgetBubble` 2/2,
`WidgetContainerView` 2/2, `WidgetFeed` 11/11, `ChatHTMLRowItem` 4/4,
`HTMLBubbleView` 6/6, `WidgetSandbox` 88/88, `LocalWidgetMessages` 1/1,
`WidgetQueries` 1/1. Both resource bundles are still shipped:
`WidgetSandbox_WidgetSandbox.bundle` and `twidget_Twidget3D.bundle`.
Nothing was removed in 283442; the rumor is not true for this beta build.

`JS_RegExpDelete` in 283442 still has the **pre-fix** order (the Android
#1827 primitive):

```
283442 function start 0x1031afc90
0x1031afd2c  ldr x8, [x22, #0x38]   ; re->bytecode snapshot
0x1031afd60  mov w8, #0x21          ; GLOBAL|STICKY
0x1031afd78  mov w3, #0x5d          ; JS_ATOM_lastIndex
0x1031afd88  bl  getter             ; attacker getter runs AFTER the snapshot
0x1031affdc  bl  lre_exec           ; x0 = sp+0x38, saved bytecode
```

The relative offsets of the snapshot and getter are identical to 283434
(`+0x9c` and `+0xe8` from function start). The new build still uses the
saved `re->bytecode` after the `lastIndex` getter. **The macOS widget
RegExp/quickjs primitive is not fixed in 283442.**

## TGS / tlottie

- Both builds export the same 11 `_tlottie_*` functions (drop, frame_count,
  frame_rate, height, new, new_with_options, render, render_alpha8,
  render_alpha8_with_options, render_with_options, width).
- `TLottieBridge` still has 10 methods and the same 10 ivars, including
  `_mutex` (`{mutex="__m_"{_opaque_pthread_mutex_t=...}}`).
- The mutex-protected render/drop wrapper is structurally unchanged; the
  Android check-then-free TGS race remains absent in this build.

## What changed

- Main binary grew by 446,640 B; appex shrank by 8,448 B; resources,
  Info.plist (except build), Sparkle, and entitlements are unchanged.
- New Swift type strings appear in the main binary (e.g.
  `BroadcastAudio*`/`BroadcastPlayback*`, `ChatHistoryModel`,
  `ChatInputAccessoryPanel*`, `ChatLoadingStoryRowItem`), and old type
  strings disappear. This is incremental feature/bug-fix work; the public
  feed does not describe it.
- No widget-sandbox, quickjs, TGS wrapper, entitlement, or updater change
  was found.

## Verdict

283442 is an incremental 13.1.0 beta. It does **not** fix the macOS widget
quickjs #1827 primitive (same bundles, same BC 29, same pre-fix
`JS_RegExpDelete`), and it does not introduce a TGS/tlottie race. The
official changelog is only "Bug fixes, minor improvements, and more."
