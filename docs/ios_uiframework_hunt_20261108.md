# iOS `TelegramUIFramework` 36535 — native widget engine hunt (2026-11-08)

Subagent scope (host-only, no device/Frida/bot/network): the **iOS widget
engine in `TelegramUIFramework` 13.2 (36535)** — the native C++ implementation
behind the `tgwidget` rich-message feature — beyond the 18 known QuickJS bugs:
its LiteHTML integration, the native DOM/bridge, the renderer callbacks, the
render-tree mirror/patch layer, and its interaction with quickjs-ng v0.17.0.

Deliverables:

* this note;
* `lab/ios_uiframework_hunt/` — extracted sources, binding-table dump, xref DB,
  decompiler tooling and the decompiled evidence quoted below;
* `notes/LEMMALOG_FACTS_ios_uiframework_20261108.txt`.

Constraints honoured: host-only; iPhone/Sony untouched; Pixel untouched (no
crash logs read in this session); no shared notes edited; no payload sent
anywhere.

---

## 0. Verdict (short, honest)

**No unreported memory-corruption bug was proven in this pass.** What the pass
did establish is a complete, previously undocumented map of the shipped iOS
engine and a set of concrete, code-level results that change the attack-surface
model for the whole widget programme:

1. **The iOS 13.2 widget engine is not the JS `widget-sandbox` design.** It is a
   brand-new (first shipped in 13.2.0) native C++ DOM in namespace `wr::` with
   its own HTML/CSS/DOM/canvas/animation implementation, plus litehtml for
   layout and CoreText/CoreGraphics for paint, exposed to QuickJS v0.17.0
   through hand-written native bindings. The older framework in
   `Telegram_decrypted.ipa` (111,086,800 B) contains **none** of it
   (`N2wr` RTTI count 0; 36535 has the `wr::` RTTI set and 154 binding tables), so there is
   no older iOS build to diff.
2. Several surfaces that look promising from the JS side are **inert stubs** in
   this build: `getImageData` returns a blank `ImageData` (no pixel copy),
   `putImageData` only validates its arguments (records nothing),
   `HTMLCanvasElement.toDataURL` returns `"data:,"`. This closes the
   canvas→pixel-leak route for other agents.
3. Every binding audited in depth is **bounds-checked with 64-bit arithmetic**
   (list in §5), including the ones where a 32-bit overflow would have been the
   obvious bug (`createImageData`, canvas command/pixel budgets, `encodeInto`,
   `btoa`, `substringData`, `insertBefore` next-sibling).
4. **`ton_core 0.1.4` is linked into the iOS framework** (Rust panic strings and
   `.../wallet_engine_crates__ton_core-0.1.4/src/cell/boc/raw_boc.rs`), i.e. the
   already-reported Android WC-1 malformed-BoC panic exists on iOS too, in the
   widget wallet API. It is an n-day DoS (process abort), not memory
   corruption; logged here because it is the only *proven-present* native bug
   in the widget path on iOS (§6.1).
5. The Android litehtml `font-weight: bolder|lighter` null-parent crash
   (``lib_hunt_css_20261108.md``) is also present in the iOS litehtml build in
   principle; the iOS widget path additionally normalises `font-weight` in the
   wr CSS layer, so reachability needs the one-line device test in §6.2. Logged
   as IOS-LT1 (n-day, crash only).
6. Three concrete memory-safety hypotheses remain open and are reduced to
   device tests (§7): mirror `.at()` out_of_range escaping a widget task, GC
   lifetime of child wrappers, and native stack exhaustion in deep-tree
   recursion. None has a host reproducer yet; none is claimed as a 0day.
7. **Second pass (§10) closed H2 and narrowed H1/H3.** A host build of the
   vendored quickjs-ng v0.17.0 proves that C-held `JS_DupValue`d values are
   refcount roots (no GC free; under-marking leaks, it does not UAF), and the
   engine dups on every audited store path — H2's naive UAF is refuted. The
   mirror's refusal exceptions are real tagged `wr` exceptions
   (typeinfo `0x67d4e30`, four LSDA catches); the only catch pads inside the
   mirror are OOM pads around `__push_back_slow_path` that set an inert flag
   (`mirror+0xf1`, whose only reader is unreferenced code that would throw
   `std::bad_alloc`). Where a refusal lands (binding/host) and whether the
   half-applied mirror is reused afterwards is the remaining open route; the
   six `.at()` sites are guarded by the same consistency checker and have no
   statically constructible missing-key path on the single-threaded main
   thread.

The honest position: this engine is new and large (`wr::` + quickjs occupy
roughly 0x3c0a000-0x3f10000, about 3 MB of `__text`, in a 122 MB framework), and it is written defensively; a memory-corruption 0day was
not demonstrated in the time available. The rest of this note is the evidence
so the next pass does not have to re-derive the map.

---

## 1. Target facts (verified in this pass)

| item | value |
|---|---|
| app | Telegram 13.2 (36535), `ph.telegra.Telegraph` |
| framework | `TelegramUIFramework`, arm64, stripped, **122,824,000 B**, sha256 `577d3c7e1b1edec3350264f2bb66340933950686d4c1543ac52f75d5c3059f74`, md5 `8f669ebbae2b7501cb83f719789aee3c` |
| iOS engine | native C++ namespace `wr::` (RTTI names), QuickJS **v0.17.0** statically linked, litehtml (layout), gumbo (markup parse), CoreText/CoreGraphics/ImageIO, TON `ton_core 0.1.4` (Rust) |
| older build | `Telegram_decrypted.ipa` framework **111,086,800 B**, sha256 `7a370303d9b369aa1e3dc5cc49ec20616e25f680670b16b7ab4ee56e6a71d23d`: **0** `N2wr` RTTI names, no `litehtml`/`twidget`/`MessageWidget` strings → widget engine introduced in 13.2.0 |
| Mach-O layout | dylib base 0; `__text` 0x24000..0x556abb0; `__const` 0x5654000; `__cstring` 0x5a349a0; `__gcc_except_tab` 0x625000c (0xcaf0c B); `__objc_const` 0x6910000; `__data` 0x6e6c620. **File offset == VM address** across all sections (verified with `llvm-readobj --sections`) |
| symbol table | 2,999 symbols (29 exported + 2,969 undefined imports); 1,541 stub→import names recovered (`out/imports.json`) |
| JS heap | 8 MiB widget heap (prior note); native DOM objects are `js_malloc`'d and counted against it |

Interface names present (RTTI), i.e. the implemented web surface: `Node`,
`Element`, `CharacterData`, `Text`, `Comment`, `Document`, `DocumentFragment`,
`DocumentType`, `Attr`, `NamedNodeMap`, `DOMTokenList`, `DOMStringMap`,
`HTMLCollection`, `NodeList`, `CSSStyleDeclaration`, `HTMLElement` + 20
element subclasses (incl. `HTMLCanvasElement`, `HTMLTemplateElement`,
`HTMLScriptElement`), `SVGElement`/`SVGGraphicsElement`/`SVGGeometryElement`/
`SVGTextContentElement`, `Event`+`CustomEvent`/`ErrorEvent`/`MouseEvent`/
`PointerEvent`/`TouchEvent`/`AnimationEvent`/`TransitionEvent`,
`ResizeObserver`, `IntersectionObserver`, `MediaQueryList`, `Performance`,
`Storage`, `Crypto`, `TextEncoder`, `TextDecoder`, `URL`, `URLSearchParams`,
`AbortController`/`AbortSignal`, `Blob`, `Path2D`, `CanvasGradient`,
`CanvasPattern`, `CanvasRenderingContext2D`, `ImageData`, WAAPI
(`AnimationEffect`, `DocumentTimeline`, `KeyframeEffect`, `CSSAnimation`,
`CSSTransition`), `Window`, `Location`, `Navigator`, `Clipboard`,
`TelegramWidget`, `HapticFeedback`, `XMLHttpRequest`/`WebSocket`/`EventSource`/
`RTCPeerConnection`/`Worker`/`SharedWorker`/`BroadcastChannel` (refusing
stubs), `LayerMirror`, `RenderHost`, `ios::CoreTextRenderHost`,
`ios::IOSHostFont`, `ios::IOSHostImage`, `ios::IOSCanvasBitmap`,
`canvas::CanvasHost`, `canvas::CanvasState`, `_GLOBAL__N_1::RefusingHost`,
`_GLOBAL__N_1::Refused`, `Thrown`, `ErrorEvent`, `RangeError`.

---

## 2. Architecture recovered from the binary (new)

### 2.1 Objects and bindings

* Every DOM interface has a **property table** in `__data` (0x67d8xxx-0x67f4xxx):
  0x40-byte entries `{name, flags, method|getter, setter, ...}`; 154 groups
  recovered with their implementations (`out/tables.txt`). Example: `Node`
  group at 0x67d8ff8 (44 entries), `EventTarget` at 0x67d8bf8,
  `CanvasRenderingContext2D` at 0x67f2d10 (73 entries), `Path2D` at 0x67f43d0.
* The **interface descriptor table** (0x67d5cc8, stride 0x48) holds
  `{name, flags, prototype-table, entry-count, init-fn}` per interface and is
  iterated at start-up to build prototypes.
* JS method calls go through a common shape: `get_this(ctx, this_val, class_id,
  name)` → `JS_GetOpaque2`-equivalent (throws `Illegal invocation (<name>)` when
  the class id differs), then argument conversions (`JS_ToString`, `JS_ToNumber`,
  `to_node`, `to_uint32` …), then a C++ implementation. Class ids observed:
  Node=3, Document=4, Element=7, Text=10, Comment=10? (character data),
  HTMLCanvasElement=86, CanvasRenderingContext2D=87, Path2D=91, ImageData=92.
* Native objects are **separate `js_malloc` blocks** referenced by the JS object
  as opaque: base Node **296 B** (`sub_3d1a0ac`), HTML element **336 B**
  (`sub_3d1938c`), all zero-filled on creation. Each has a vtable in
  `__const` (e.g. base at 0x67cb558, HTML element at 0x67cbab0) whose slots are
  `[0]` destructor, `[1]` deleting destructor, `[2]` **mark(rt, mark_func)**
  (`JS_MarkValue` calls), `[3]` **clear/free owned JSValues**, then virtual DOM
  operations at +0x20…+0x90.
* Node layout (from decompiled accessors): `+0x08` self JSValue (16 B),
  `+0x30` parent node, `+0x48` parent JSValue (dup'd), `+0x50` parent-ref JSValue,
  `+0x60/+0x68` `std::vector<JSValue>` **children** (16-byte elements),
  `+0x80` index in parent (u32), `+0xc8/+0xd0` observer vector (0x40-byte
  entries, callback JSValue at +0x20), `+0x130/+0x140` additional JSValues
  (HTML element), `+0xb8/+0xc0` text data pointer/length (CharacterData).
* GC/ownership: children, parent links and listener callbacks are `JS_DupValue`d
  into C memory (so they are strong references as far as QuickJS refcounting is
  concerned); `gc_mark` callbacks additionally mark listener callbacks and the
  element's two JSValues so the cycle collector can see them. The children
  vector is **not** marked by the element mark function; under QuickJS
  refcounting a C-held dup is still a root, so this is probably safe, but it is
  the invariant to test on device (§7, H2).
* Markup parsing: `innerHTML`/`insertAdjacentHTML`/`outerHTML` cap the markup at
  **1 MiB** (`The markup is too long to parse.`) and require an HTML document
  (`Markup can be parsed only for an element of an HTML document: there is no
  XML parser.`); parse uses the statically linked **gumbo** (code at 0x413xxxx),
  then a fragment→DOM builder (`sub_3d2bd20`, 205 blocks) with a depth guard and
  checked string growth.

### 2.2 Render tree and mirror

The DOM is mirrored into a litehtml document that is built once and then
**patched incrementally** from a structural journal. The patch layer lives at
0x3e201d8 (13,952 B, 1,132 blocks) with `can_*` guards
(`can_insert_subtree`, `can_remove_subtree`, `can_replace_text`,
`can_set_element_attributes`, `can_set_pseudo_classes`, `can_replace_root`,
node/text-piece caps) and refusal diagnostics. The **`LayerMirror`**
(0x3df3xxx-0x3e01xxx, ~130 KB) turns render items into the native layer tree and
has its own diagnostics (`a publish without a render tree it observed`,
`a recaptured item is gone`, `a clip cannot be applied again`, …). It uses
`std::unordered_map::at` at six inlined sites (0x3df8894, 0x3df91f8, 0x3df9208,
0x3dfa1c8, 0x3dfafb4, 0x3dfafc4); the "not found" path calls
`std::__throw_out_of_range("unordered_map::at: key not found")` and would only
be caught by a `catch (std::out_of_range)`/`catch (...)` — the framework imports
`__ZTISt12out_of_range`, which is consistent with such a catch existing
somewhere, but the catch site was not proven (§7, H1).

---

## 3. Tooling built in this pass (reusable)

All in `lab/ios_uiframework_hunt/tools/`; nothing needs IDA (IDAlib 9.4
segfaults on this dylib before analysis; angr's decompiler fails on the few
14 KB functions, but works on normal ones):

| tool | what |
|---|---|
| `macho_xref.py` | numpy ADRP+ADD scanner over 88 MB `__text`; builds `out/xrefs.json` (26k string targets, 1 s) |
| `addrxref.py` | same scanner for arbitrary data targets (descriptor/property tables) |
| `callscan.py` | numpy BL scanner: call sites of any function/import in ~2 s |
| `tables.py` | recovers all 154 binding tables (name/flags/method/getter/setter) into `out/tables.txt` |
| `imports.py` | maps 1,541 `__stubs` entries to imported symbol names (`out/imports.json`) |
| `decomp.py` | angr per-function decompiler over the linear image (file offset == VMA) |
| `funcs.py` | CFGFast on a region: function starts/sizes when decompilation is not needed |
| `dumpstr.py` | string window dumper |

Regenerate:

```bash
cd lab/ios_uiframework_hunt
python3 tools/macho_xref.py $FW --build out/xrefs.json
python3 tools/imports.py $FW
python3 tools/tables.py > out/tables.txt
python3 tools/decomp.py $FW 0x3cf4b54 0x3cf5a00 | less
```

---

## 4. Method

1. **Source-first**: the iOS 13.2 feature has an open design + implementation
   plan in the Telegram iOS tree (`docs/superpowers/specs/2026-10-13-message-widgets-design.md`,
   `docs/superpowers/plans/2026-10-13-message-widgets.md`, 4,675 lines) and the
   vendored `widget-sandbox` repo (commit `862eec8`) contains the JS shim,
   validator and litehtml core the plan derived from. Reading those first
   avoided auditing the wrong engine: the **shipped** 36535 binary does not
   match them (no `twlite`, no `mwc_`, no `WidgetJS` assets), it is the `wr::`
   native engine.
2. **Binary archaeology**: RTTI names → interface list; property tables →
   complete binding map; `js_malloc`/vtable/mark analysis → object model;
   string xrefs → diagnostics and subsystem boundaries; error-message clusters →
   the guards each subsystem relies on.
3. **Targeted decompilation** of every binding in the categories where a
   controllable primitive is plausible: CharacterData indices, tree mutation,
   fragment insertion, `innerHTML`, clone/normalize, canvas/image data,
   TextEncoder/TextDecoder, btoa/atob, the canvas budget, the mirror.
4. **Negative-space checks**: which APIs are stubs (because a stub cannot be a
   carrier), and where the engine's own caps make an overflow impossible.

---

## 5. Audited bindings and results (all host-static, addresses exact)

| # | surface | implementation | result |
|---|---|---|---|
| 1 | `CharacterData.substringData(offset,count)` | 0x3d0e77c | offset > len → `IndexSizeError`; end = min(offset+count, len) in 64-bit; no overflow |
| 2 | `CharacterData.appendData/insertData/deleteData/replaceData` | 0x3e74b00…0x3e74fbc (bindings) | same JS-string based pattern; indices converted with range check (`is not a finite long.`) |
| 3 | `Node.insertBefore/appendChild` | 0x3d258a4 → 0x3d25930 | `ref == node` next-sibling uses `(u32)index+1` vs `(end-begin)>>4` with unsigned `>=`; in-bounds; fragment insertion copies children to a worklist first |
| 4 | `Node.removeChild` | 0x3d265fc | parent identity check then detach; `NotFoundError` otherwise |
| 5 | `Node.cloneNode(deep)` | 0x3d26b38 | explicit worklist vector (pop tail, push children); no iterator invalidation |
| 6 | `Node.normalize()` | 0x3d29f04 | gathers text nodes into a vector first, then merges; no erase-while-iterating pattern found |
| 7 | `Node.firstChild`/`childNodes`/`textContent`/`nodeValue` | 0x3e5ab..0x3e5b.. | children vector of dup'd JSValues; getters dup the stored JSValue |
| 8 | `Document.createElement` | 0x3d137a8 → 0x3d18e18 | tag-name validation (`InvalidCharacterError`), class-id factory, `js_malloc` of the native object |
| 9 | `Element.innerHTML` setter | 0x3d21b3c → 0x3d2640c | 1 MiB markup cap, gumbo fragment parse, single-text fast path, then remove+insert |
| 10 | `CanvasRenderingContext2D.createImageData` | 0x3cf498c → 0x3d03d1c | **64-bit** `umull` cap check (`3500001 <= w*h`) and 64-bit `w*h*4`; negatives abs()'d; 0 side → `IndexSizeError` |
| 11 | `getImageData(sx,sy,sw,sh)` | 0x3cf4b3c | tail-calls the allocator with `|sw|,|sh|`; **no pixel copy at all** (blank ImageData) |
| 12 | `putImageData` | 0x3cf4b54 | validates gate + `ImageData` class (92) + 3/7 args; **no command recorded** |
| 13 | `drawImage` | 0x3cf4614 | validates 3/5/9 args then records; rasterizer not reached in this pass |
| 14 | `HTMLCanvasElement.toDataURL` | 0x3cf6dd4 | returns `"data:,"` (stub); `toBlob` likewise empty |
| 15 | canvas command budget | 0x3cf00c0 | per-task counter vs limit, throws `Canvas limit exceeded: more than N commands for one canvas in one task (max N)` |
| 16 | canvas pixel budget (prior pass) | 0x3d04e44 | side 1..16384, 64-bit `umull` w*h, 4,194,304 px/widget |
| 17 | `TextEncoder.encode` / `encodeInto` | 0x3d607f0 | per-char `written+n <= capacity` check, surrogate pair handling; capacity from the destination Uint8Array |
| 18 | `TextDecoder.decode` | 0x3d61674 + 0x3d61128 | state machine with min/max continuation checks (overlong/range enforced), checked output vector growth, BOM strip `memmove(begin, begin+2, len-2)` (in-bounds) |
| 19 | `btoa` | 0x3d50d20 | capacity `4*ceil(len/3)` via magic multiply, per-write capacity check; `>0xFF` rejected |
| 20 | `atob` | 0x3d511c0 | whitespace mask `0x100003600`; padding strip; output capacity `(stripped>>2)*3+2`; every write checked/grown; `=` mid-string rejected (§9 item 4) |
| 21 | `structuredClone` | 0x3db8024 | (not fully read — next pass) |
| 22 | `Element.setAttribute/height` conversions | e.g. 0x3efb9cc | this-pointer obtained before argument `ToString`; see H3 |

UBSan/ASan-style host testing of the real engine is impossible (closed binary,
iOS frameworks), so the evidence here is disassembly + the engine's own error
paths. Where the code is not quoted in this note it is in
`out/*.c`/`out/tables.txt`.

---

## 6. Found and logged bugs

### 6.1 IOS-WC1: `ton_core 0.1.4` malformed-BoC panic present on iOS (n-day DoS)

`TelegramUIFramework` contains the Rust strings of the Android wallet engine:
`ton_core::cell::boc::raw_boc`, `Invalid BoC: ref to parent cell detected`,
two `panicked at` strings and the source path
`external/rules_rust++crate+wallet_engine_crates__ton_core-0.1.4/src/cell/boc/raw_boc.rs`.
This is the same crate and the same missing bounds check as Android **WC-1**
(`notes/lib_hunt_static_20261108.md` §…; `te6ccgEBAQEAAgUAAA==` → root index
`5` with 1 cell → `raw_boc.rs:170`), now linked into the iOS widget stack and
reachable from `TelegramWidget.wallet.sendTransaction` / `signData` (the same
TON-Connect validation strings are in the binary at 0x5ab29f0/0x5ab2ac8).

Class: process abort (Rust panic; `panic=abort`-style kill) → widget/app DoS.
Not memory corruption. Platform: new (iOS), root cause: already reported
(Android). Device test: needs wallet-enabled build + a real tap, orchestrator
owned; not run.

### 6.2 IOS-LT1: litehtml `font-weight: bolder|lighter` null-parent path (n-day, unverified on iOS)

The Android CSS hunt (`notes/lib_hunt_css_20261108.md`) found that
`css_properties::compute_font` reads the parent element's computed font-weight
without a null check for `bolder`/`lighter`, so a **root element** carrying the
keyword crashes the document build (host ASan SEGV; Android 72889 `0x7d053c`,
72929 `0x7d90cc`).

The iOS framework ships litehtml (347 `litehtml` strings; litehtml code at
0x3f6xxxx-0x414xxxx, e.g. the `t_strcasecmp(family,"monospace")` site at
0x404354c inside the style/font code). The wr engine has its **own**
`font-weight` parser that recognises the keywords (`bolder` at 0x5aace1f →
0x3d081d8, `lighter` at 0x5aac975 → 0x3d0820c, both inside the 6 KB CSS
declaration parser at 0x3d07a9c; the parser stores keyword flag `4` together
with numeric weights 700/100). Whether the serializer passes the keyword
through to litehtml or rewrites it to a number was not resolved, so iOS
reachability is **unverified**. Trigger to test (1 line of HTML, no JS):

```html
<style>html{font-weight:bolder}</style><body>x</body>
```
(the `<style>` sheet is the strongest variant: its text goes to litehtml's CSS
parser without passing through the wr style-attribute parser), the attribute
variant `<html style="font-weight:bolder"><body>x</body></html>`, or via JS:
`document.documentElement.style.fontWeight='bolder'`.
A SIGSEGV in the document build with PC inside litehtml confirms IOS-LT1.
Class: null-pointer dereference (near-null read at parent+0x335) → crash, not
memory corruption. Same root cause as the Android n-day.

### 6.3 IOS-CAN-STUB: canvas read-back is a stub (surface closure, not a bug)

`getImageData` performs no copy and `putImageData` records nothing; `toDataURL`
returns `"data:,"`. Any hypothesis that needs canvas pixel read-back on iOS
36535 is dead. Logged so it is not re-spent.

### 6.4 IOS-MIRROR-AT (hypothesis, unproven): `unordered_map::at` in the mirror

Six `.at()` sites in the mirror (addresses §2.2). If a widget can reach one with
a missing key and the exception is not caught, the result is an uncaught
`std::out_of_range` → `std::terminate`. The framework imports
`__ZTISt12out_of_range`, so a handler probably exists; not proven either way.
Test in §7 H1.

---

## 7. Open memory-safety hypotheses and the device tests that decide them

All tests are widgets (HTML + JS) to be delivered by the orchestrator to the
6s (iOS 15.8.8, jailbroken) and, if the user authorises, the 17e (iOS 27);
harness rules of the project apply (one live test at a time, orchestrator owns
the device). **Second-pass status: H1/H3 are bounded to a widget-local fatal
exception (§10.2), H2 is refuted by a host proof (§10.3); the widgets for all
four tests are in `lab/ios_uiframework_hunt/payloads/`.**


**H1 — mirror `.at()` out_of_range escapes.**
Widget: build a moderate tree, then in one task do a sequence that changes
structure and style repeatedly (`innerHTML` swap, `removeChild` of a styled
subtree, re-append, `class` toggles, width change via `document.body.style`),
then force a layout read (`offsetHeight`). Watch for a crash whose top frame is
in the mirror region (0x3df3xxx-0x3e01xxx) or in
`__cxa_throw`/`std::__throw_out_of_range`. A crash there is a new native
crash (DoS). If a crash is found, narrow to the exact op sequence; then check
whether the exception object/terminate can be turned into a controlled
unwind (unlikely, but a crash is the entry point).

**H2 — child-wrapper lifetime under forced GC.**
Widget:
```js
var d = document.createElement('div');
for (var i = 0; i < 2000; i++) d.appendChild(document.createElement('span'));
document.body.appendChild(d);
d = null;                       // parent wrapper only reachable from body
for (var k = 0; k < 2000; k++) { var junk = new Array(512).fill(k); }  // force GC
document.body.textContent;      // walk children
document.body.innerHTML = '<b>x</b>';  // remove subtree
```
If child wrappers are collected while the parent's native children vector still
holds them, the walk/removal is a UAF (tag domain: QuickJS arena, same-chunk if
the freed block is in an arena class; otherwise Apple malloc). A crash in
`sub_3d25f74`/`sub_3d25930`/`sub_3d16020` (node free) confirms it. Add a
variant that keeps one child referenced and removes the parent.

**H3 — native stack exhaustion / re-entrancy.**
(a) Depth: nested `<div>` × 20000 built with JS `appendChild`, then
`document.body.innerHTML`, `outerHTML`, `cloneNode(true)`, `normalize()`,
`textContent` — measure whether the widget thread hits the guard page
(SIGSEGV) before any JS/C++ limit. (b) Re-entrancy: `setAttribute('x', obj)`
where `obj.toString` removes/creates nodes on the same element; `style.width =
obj`; `classList.add(obj)`; `appendChild` of a fragment whose children are
mutated by a getter. A crash inside a binding after `JS_ToString` is the
signal.

**H4 — wallet BoC panic (IOS-WC1).** Reproduce the Android WC-1 payload through
the iOS wallet API; expected SIGABRT. Confirms §6.1 on iOS.

Success criteria: any crash/ASAN-style report with a native frame outside
`libc++abi`'s OOM path, reproducible from a ≤32 KiB raw / ≤4 KiB zlib-9 widget.
If H1-H4 are all negative, the next pass should fuzz the fragment builder and
the mirror with a grammar mutator (needs an orchestrator slot; the engine
cannot be built on the host, so this means device crash triage, not ASAN).

---

## 8. Limitations

* No device run in this session (host-only by instruction); all device claims
  are test plans, not results.
* The `wr::` source is not available; the model in §2 is reconstructed from
  RTTI, vtables, binding tables and decompilation, and may be incomplete in
  class hierarchy details.
* angr refuses to decompile the largest mirror/patch functions; the `.at()`
  reachability question (H1) needs either a better decompiler (IDA fails to
  load this dylib in this environment) or device testing.
* `structuredClone`, `URL`, `CSSStyleDeclaration`, the WAAPI and the observers'
  disconnect path were mapped but not fully audited; they are the next static
  targets (`atob` was audited in the second pass).
* The framework's typeinfo/catch coverage for `std::out_of_range` was not
  resolved (import present, catch site not located).

---

## 9. Queue for the next pass (highest value first)

1. **`textContent`/`innerHTML` single-text fast path** (`sub_3d2640c` fast branch,
   0x3d26534-0x3d265a4): it moves two bookkeeping fields (+0x88, +0xc8) from the
   freshly parsed text node into the receiver, then inserts the parsed node and
   zeroes the source. The ownership transfer is deliberate but is the one place
   in the audited set where a pointer is copied out of a temporary node; prove
   the zeroing is complete (including the exception path) or find the missing
   field.
2. **CSS declaration parser** (`sub_3d07a9c` region, ~6 KB, ~200 properties;
   entry points at the `bolder`/`lighter` sites 0x3d081d8/0x3d0820c). Look for
   fixed-index component-value access without a count check, and for
   gradient/transform/filter lists with a single element.
3. **Mirror `.at()` reachability** (H1) — needs a decompiler that handles
   0x3df81d8/0x3e201d8 (IDA fails on this dylib in this environment; try Ghidra
   headless with `-noanalysis` + a raw-binary import of the linear image).
4. `structuredClone` (0x3db8024), `URL`/`URLSearchParams` (0x3d50xxx/0x3d51xxx),
   `CSSStyleDeclaration` (`setProperty`/`cssText`), WAAPI
   (`KeyframeEffect`/`commitStyles`, 0x3e7xxxx?), observers
   (`ResizeObserver`/`IntersectionObserver` callback re-entrancy — registration
   and the global registry are mapped in §10.4, disconnect-during-delivery is
   open). `atob` (0x3d511c0) was checked in the second pass: whitespace mask
   `0x100003600`, padding strip for count%4==0, output capacity
   `(stripped>>2)*3 + 2`, every write capacity-checked or grown, `=` in the
   middle rejected — safe.
5. Device tests H1-H4 (§7) — the cheapest signal is H4 (wallet) and IOS-LT1
   (one line of HTML); then H2 (GC lifetime) and H1 (mirror crash).

---

## 10. Second pass (same day, continued): H1/H2/H3 mechanism proof

The first pass left H1 (mirror `unordered_map::at`), H2 (child-wrapper GC
lifetime) and the mirror state machine unproven. This pass closed H2 with a host
proof, identified the exact H1/H3 failure mechanism and bounded it, audited all
six `.at()` sites with a decompiler that finally handled the 4–14 KB functions,
and produced the device widgets. **No controllable memory corruption was found
in this pass either**; the new results are mechanism-level.

### 10.1 Tooling: Ghidra headless on the raw linear image

IDAlib 9.4 loads this dylib but needs ~16 min per range and can segfault when
run concurrently; angr fails on the 4–14 KB mirror functions. Ghidra 12.1
headless works and decompiles a 10 KB function in seconds:

```bash
GHIDRA_HEADLESS_MAXMEM=4G /opt/ghidra/support/analyzeHeadless \
  lab/ios_uiframework_hunt/ghidra_proj tguifw \
  -import <framework> -noanalysis -processor AARCH64:LE:64:v8A \
  -loader BinaryLoader -loader-baseAddr 0x0 \
  -scriptPath tools/ghidra -postScript DecompFuncs.java <out.c> <addr…>
```

Script: `lab/ios_uiframework_hunt/tools/ghidra/DecompFuncs.java` (imports only
the addresses asked for; no global analysis). Outputs used below are in
`lab/ios_uiframework_hunt/out/ghidra/`.

### 10.2 H1/H3 — the mirror is fail-stop, not state-reusing

Recovered control flow (all addresses exact):

1. **Refusals are exceptions, not log lines.** `sub_3DF5E2C` (0x3df5e2c) is
   `__cxa_allocate_exception(0x10)` + construct + `__cxa_throw` with a wr
   exception type (`0x67d4e30`, GOT `0x690f718`); the call sites are followed by
   `brk #1` (noreturn). Messages include "a replaced text piece has nodes of its
   own", "a piece added outside a text run", "a restyled item is gone", "content
   cannot move out of a group", "a new group's clips cannot be chained", "a clip
   cannot be applied again", "a host context the mirror does not know", "a
   clipper the mirror does not know", "a re-placement's walk is lost".
2. **Eight live mirror vtable methods contain allocation-failure catch pads.**
   The mirror's vtable at `0x67d4db0` (slots `0x3df34fc`/`0x3df3500` are its
   destructor / deleting destructor) has eight methods (`0x3df4124, 0x3df41e0,
   0x3df4254, 0x3df42dc, 0x3df4364, 0x3df43d8, 0x3df4878, 0x3df4974`; a ninth
   `0x3df4650` sits in the same cluster). Each body pushes one or more
   `shared_ptr` pairs into vectors and, on the vector-grow slow path, has a
   landing pad that runs `__cxa_begin_catch` → `strb w8(=1), [x19, #0xf1]` →
   `__cxa_end_catch` and returns without rethrow. These are **OOM pads around
   `__push_back_slow_path`**, not refusal handlers: the flag marks "a mirror
   bookkeeping allocation failed".
3. **The OOM flag has no live reader in 36535.** The only read of `mirror+0xf1`
   in the whole mirror region is inside `FUN_03df1e10` (0x3df1e10), which throws
   `std::bad_alloc` (chained-import[6496] = `__ZTISt9bad_alloc`) when the flag is
   set. But `FUN_03df1e10` has **no static code or data reference**: no `b`/`bl`
   targets it, no 8-byte chained fixup, no 4-byte absolute or relative pointer,
   no `movz/movk` construction, and it is not a slot of the mirror vtable. Its
   callee, the update body `FUN_03df1fb8` (0x3df1fb8, which calls the checker
   `FUN_03df53b8` and the publish `FUN_03df696c`), has BL callers only inside
   that unreferenced function. Statically, the OOM flag and the update body are
   not reachable in this build. The checker `FUN_03df53b8` is called only from
   the update body, and the publish `FUN_03df696c` only from two sites inside
   it, so the whole incremental patch machinery has no live caller in 36535.
   The eight live vtable methods call through `blr` into host callbacks; the
   refusal type is caught in four LSDA entries elsewhere (mapping them needs
   LSDA-aware tooling). Reading the static evidence literally, **the incremental
   mirror patch path ships disabled/unreferenced in this build**, which would
   make H1/H3 unreachable here; the alternative reading is a runtime-resolved
   callback that no static reference reveals.
4. **Consequence for H1.** The exact landing place of a checker/publish refusal
   is therefore not resolved: it is a `wr`-typed exception (typeinfo `0x67d4e30`,
   caught by 4 LSDA entries; the base `wr::Thrown` has 10), and the mirror
   vtable's own pads are OOM pads that do not intercept it. If the refusal is
   caught at the JS binding boundary, the widget can see a JS exception and keep
   running while the mirror is half-applied; if it is caught by the host, the
   widget is stopped; if it escapes, the process dies. The first case is the
   "exception crosses into a reused object" scenario the task asked about and
   remains **open**. Whether the half-applied state is later reused in a
   corrupting way depends on the checker `FUN_03df53b8` catching the resulting
   inconsistency at the start of the next update: it inspects text pieces,
   groups, contexts, clippers and their parents and throws on the cases it
   knows. Its coverage cannot be settled from the stripped binary in this pass.

The six `unordered_map::at` sites (0x3df8894, 0x3df91f8, 0x3df9208 in the 10 KB
publish `FUN_03df6988`; 0x3dfa1c8 in `FUN_03df9cb0`; 0x3dfafb4/0x3dfafc4 in
`FUN_03dfa274`) are ordinary libc++ `at()` inlined hash lookups. Each is reached
only after the mirror's consistency checker `FUN_03df53b8` has accepted the
render tree; the code immediately before each throw performs the same lookup and
branches to a normal exit on a miss, so the throw is only reachable if the map
changes between two reads, which the single-threaded main-thread model forbids.
A miss would throw `std::out_of_range` (uncaught by the wr handlers), i.e. at
worst another fatal crash, never a memory write.

**H1/H3 verdict so far: no corruption demonstrated. The mirror's refusal
exceptions are real (tagged `wr` typeinfo `0x67d4e30`); the only in-mirror catch
pads are OOM pads that set an inert flag; the `std::bad_alloc` bomb that would
consume that flag and the checker/publish machinery it guards have no live
caller found by static analysis (no BL/B, no chained/absolute/relative pointer,
no vtable slot), so the incremental patch path appears **disabled in 36535**.
If that reading is right, H1/H3 are unreachable on this build and the device
widget should simply complete; a crash or a visibly wrong incremental render
would falsify the reachability conclusion and reopen the half-applied-mirror
hypothesis. Device test below.** The payload to drive it is
`lab/ios_uiframework_hunt/payloads/h1_mirror_refusal_hunter.html` (3,870 B raw,
1,524 B zlib-9): text-piece replace, stacking-context group create/destroy/move,
clip radius/overflow churn, fixed-position host context, re-placement, layout
read after every mutation. If it crashes, the `.ips` top frames should be
`FUN_03df1e10`/`FUN_03df53b8`/`FUN_03df6988` → `__cxa_throw`.

### 10.3 H2 — QuickJS v0.17.0 GC semantics: dups are roots, so no UAF

Host test against the exact vendored quickjs-ng v0.17.0 source
(`lab/ios_uiframework_hunt/qjs_host/`, built with ASan):

| test | model | result |
|---|---|---|
| A | native holds a **dup'd** child JSValue + a dup'd parent ref, all JS refs dropped, `JS_RunGC` | `finalized=0`: neither wrapper is collected — a C-held dup is a refcount root, the cycle leaks |
| B | same, then explicit teardown frees the children vector | child freed by refcount (`freed4=1`) — explicit teardown collects |
| C | children stored **without** a dup (counterfactual), child freed, slot reused by the next node | deterministic: the stale stored JSValue resolves to the **new** node (`JS_GetOpaque(stale)==id 100`) — identity/type confusion |
| D | same as C, `JS_DupValue(stale)` under ASan | UAF read in `js_dup`; note the arena may cache the block, so C is the reliable oracle |

Evidence: `evidence/test_ownership.c`, `evidence/out_A.log`, `out_B.log`,
`out_C.log`.

Binary evidence that the engine does store with dups:

* children insert `FUN_03d28b7c` (0x3d28b7c): copies the child's self JSValue
  into the parent's children vector and calls `JS_DupValue` (0x3f1d2f4); the
  removal path `FUN_03d28fc0` `JS_FreeValue`s every entry.
* child→parent refs `FUN_03d291cc` (0x3d291cc): `JS_DupValue(parent.self)`,
  old value freed with `JS_FreeValueRT`.
* event handlers `FUN_03d45980` (0x3d45980, behind every `on*` setter):
  `JS_DupValue(handler)` before replacing, old value freed.
* cached per-node JS objects (`+0xe8`, `+0xf8`, `+0x108`, `+0x118`) are created
  fresh (refcount 1) and owned by the node; the clear function
  `FUN_03d16020` frees them.

Marking gaps (e.g. the base node `gc_mark` 0x3d15f78 marks only the observer
callbacks and four slots, not the children vector) therefore cause **leaks**
(bounded per widget, freed by explicit teardown), not use-after-free.

**H2 verdict: refuted in the naive form.** The residual is a bounded leak; a
missing dup somewhere would have to be found path-by-path. All central paths
audited here dup. The probe widget `payloads/h2_gc_lifetime.html` (1,740 B raw)
should pass; a crash would falsify this model.

### 10.4 Observers / WAAPI / style / URL / structuredClone

* `ResizeObserver.observe` (`FUN_03d2d81c`) and `IntersectionObserver.observe`
  (`FUN_03d20160`) push a record containing a `JS_DupValue` of the target into
  the observer's vector and, when the vector was empty, register the observer in
  a global per-runtime registry (`FUN_03db8d70`, list at `state+0x98`). Delivery
  is therefore outside the DOM insert path (registry-driven), which removes the
  obvious "callback re-enters the vector being iterated" shape; the remaining
  question (disconnect during delivery) needs the device test
  `payloads/h4_observer_waapi.html` (2,319 B raw).
* `disconnect` (`FUN_03d2da9c` region) clears the observer's target list and
  unregisters it; the decompilation is dominated by inlined `JS_FreeValue`
  internals and did not reveal a stale node pointer, but is not fully proven.
* `cssText`/`setProperty`, `URL`/`URLSearchParams`, `structuredClone` were
  exercised by the H4 widget but not audited line-by-line; they remain the best
  untouched static targets (see §9 queue). `atob` was audited (safe: capacity
  `(stripped>>2)*3 + 2` with checked growth, padding/whitespace handled).

### 10.5 Second-pass deliverables

* `lab/ios_uiframework_hunt/tools/ghidra/DecompFuncs.java` + `ghidra_proj/`
* `lab/ios_uiframework_hunt/out/ghidra/` — decompiled mirror core
  (`mirror_core.c` 4,859 lines), update/entry, ownership paths, observer paths
* `lab/ios_uiframework_hunt/qjs_host/` + `evidence/` — the GC/ownership host
  proof (real quickjs-ng v0.17.0, ASan)
* `lab/ios_uiframework_hunt/payloads/` — the four device widgets and README
* facts appended to `notes/LEMMALOG_FACTS_ios_uiframework_20261108.txt`
