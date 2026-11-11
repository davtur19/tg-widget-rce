# lib_hunt_dom — DOM / bridge / JNI memory-safety audit

Date: 2026-11-08. Scope: Telegram Android bot-widget **DOM, events, bridge/host calls, JNI
strings/objects, renderer callbacks** (canvas, CSS/litehtml layout, SVG, images, fonts,
Lottie explicitly excluded; those belong to the other agents).
Host-only: no device, no Frida, no bot, no network. Pixel/Sony/iPhone untouched.

Targets:
- `libtmessages.49.so` 72889 (13.2.1 beta, build id `21ec5d5d81f69a9722cf60824e4c296e373bd87b`)
  and 72929 (next beta, build id `f0a1d2f382fc7c7b69241c1715785e28227d665b`).
- `assets/WidgetSandbox/WidgetJS/{sandbox,validator}-bundle.{js,qbc}` from the 72889 APK.
- **The matching TwidgetCore C++ source** (renderer + validator + profile + JNI bridge), see §1.
- iOS `TelegramUIFramework` 36535 (checked for applicability only).

---

## 0. Verdict

**No memory corruption reachable from widget HTML/JS through the DOM/bridge/JNI was found in
the shipped Android profile.** The layer is built as sandbox ops → a separate validator JS
context → a *shadow DOM* (`twlite::Renderer::Node`) → serialized HTML → litehtml, and both the
validator and the native model enforce node/attribute/cycle invariants independently.

Two **unreported memory-safety defects in the native core** were found and reproduced on the
host against the real C++ renderer:

| id | class | reachable from a widget? | status |
|---|---|---|---|
| **D-1** | use-after-free (dangling `Node::parent` after `textarea.value`) | **No** in the shipped profile (form controls are dropped by the validator). Latent for any embedder/profile that allows form controls. | **new** (ASan-confirmed on the real core) |
| **D-2** | stack exhaustion, recursive `forget()`/`serialize_node()` over a deep shadow tree | **Conditionally** (validator allows 50 000 nodes, no depth cap; renderer-thread stack size decides; needs a device check) | **new** (ASan-confirmed on host; DoS only) |

The interesting negatives (§4) close several tempting primitives: `data-twid` duplicate
attribute poisoning, DOM cycles, id reuse after `rm`, `patch_log_` raw pointers, and the
`Object.prototype.toJSON` forged-ops path. Host PoC, ASan logs and the exact op streams are in
`lab/lib_hunt_dom/` (§6).

---

## 1. Source and method (why the source is authoritative)

`/tmp/opencode/twidget_intel/drklo/TMessagesProj/jni/twidget/` contains the Twidget source tree
that the shipped library is built from:

- `twidget/Sources/TwidgetCore/src/renderer.cpp` (5856 lines) — the shadow DOM, ops, serializer,
  `data-twid` map, patch log.
- `twidget/Sources/LiteHTML/litehtml/` — the litehtml + gumbo fork (`max_build_depth` 256,
  `max_build_elements` 20 000), duplicate-attribute drop in `src/gumbo/tokenizer.c:780`.
- `widget-sandbox/packages/core/src/host/validator.ts` + `profile.json` — the validator policy.
- `widget-sandbox/packages/core/src/sandbox/{dom,forms,...}.ts` — the JS DOM source of the bundle.
- `twidget-bridge.cpp` — the JNI surface (`bytes()`, `canvas_run`, `canvas_read`, fonts, intl).

Correspondence with the binary was verified at several points (both 72889 and 72929):

- `AndroidRenderer` constructor `sub_9989A0` stores vtable `off_18D46E0`, builds the twlite
  renderer at `+128`; the shipped string set (`data-twid`, `[data-twid]`, `" data-twid=\""`,
  `data-tw-frozen`, `tw-canvas:`, `widget-record`, `noAttrFast`, `noCanvasRect`,
  `webAnimations`) is exactly this tree.
- The `prop value` textarea code in the binary is `sub_8D5148` and matches `renderer.cpp`:
  `Node` parent at `+120`, `children.begin/end` at `+128/+136`,
  `*(v548+136) = *(v548+128)` for `children.clear()`, `v6[118]=0` for `patch_log_.valid=false`.
- `Renderer::attached()` compiles to the `do { v = *(v+120); } while (v && v != html)` walk seen
  at `sub_8D5148` — the same offset used by the UAF in D-1.
- 72889 → 72929 `.text` diff: instruction-address sequences are **identical for all
  4 594 699 instructions**; 72929 only appends 57 cold-path instructions at `0x18be2a8` and
  shifts `.data.rel.ro` by +0xE0. No functional change in the renderer/DOM code between the
  two builds (so D-1/D-2 are present in both).

Source-level evidence was then compiled **as the real C++ core** and driven with the exact op
protocol (`lab/lib_hunt_dom/build_tw`, ASan). This avoids guessing from decompiler output.

---

## 2. The pipeline (as audited)

```
widget HTML/JS
  │  sandbox-bundle.js builds ops ({op:"el"/"text"/"ins"/"rm"/"attr"/...})
  │  JSON.stringify(te)  (Object.prototype.toJSON CAN forge this text — see §4.6)
  ▼
__host("ops", json)  (native C callback sub_77F89C; only __host and __hostBinary exist)
  │
  ▼
WidgetHost::onOps → Validator (separate QuickJS context, validator-bundle.js)
  │   tag/attr/url/CSS allowlists (profile.json), node model, cycle check, id checks,
  │   caps: 50 000 nodes, 10 000 ops/batch, 32 KiB text, 32 KiB attr
  ▼  clean ops JSON  (the renderer never sees a rejected op)
toRenderer({"type":"ops","ops":[clean]})  →  twlite::Renderer::receive
  │
  ▼
Renderer::apply_ops/apply_op: shadow Node tree (nodes_, aliases_, fixed html/head/body)
  │   ins: detach + explicit ancestor cycle check; rm: detach + forget(subtree)
  ▼
Renderer::serialize(): shadow tree → HTML with data-twid="<id>" per element
  │
  ▼
litehtml/gumbo parse + layout + paint; data-twid → elements_ map (id → litehtml element)
  │   events/hit-testing resolve ids through this map; every lookup is a shared_ptr
  ▼
platform backend (JNI canvas/font/image/intl callbacks)
```

Key gate: **the validator is a second runtime with its own DOM model**. The sandbox cannot
bypass it; the native renderer trusts its output for tag/attr/prop/url policy and re-checks
structure itself.

---

## 3. Findings

### D-1 — Use-after-free via `textarea.value` + remove + re-insert (latent; blocked by profile)

**Root cause.** In `Renderer::apply_op`, the `prop value` op for a `<textarea>` truncates the
shadow node's child list without deleting the children or clearing their `parent`:

```cpp
// renderer.cpp:2849-2858
if (n->tag == "textarea") {
    if (!n->children.empty()) patch_log_.valid = false;
    else if (attached(n)) patch_log_.texts.insert(n);
    n->data = v;
    n->children.clear();          // dropped pointers; child keeps parent = n
}
```

`forget()` only walks `n->children`, so after the textarea itself is removed the orphaned text
child stays in `nodes_` with a **dangling `Node* parent`**:

```cpp
// renderer.cpp:2960-2969
void Renderer::forget(Node* n) {
    forget_canvas(n->id); resize_watch_.erase(n->id);
    for (Node* c : n->children) { c->parent = nullptr; forget(c); }
    n->children.clear();
    nodes_.erase(n->id);          // deletes n; the cleared children were missed
}
```

Re-inserting that text node emits `text` (ignored: the id still exists in `nodes_`) followed by
`ins`; `apply_op` then dereferences the freed parent:

```cpp
// renderer.cpp:2793-2799 (ins)
note_children(n->parent, n);      // attached(n->parent) walks parent->parent (freed)
detach(n);                        // n->parent->children.erase(...) on freed memory
```

**ASan proof on the real core** (`poc/poc_textarea.cpp`, `logs/poc_textarea_asan.log`):

```
== batch 2: prop value ...   out messages: 0
== batch 3: rm textarea ...  out messages: 1
== batch 4: re-insert orphan -> use-after-free
==1260504==ERROR: AddressSanitizer: heap-use-after-free ... READ of size 8
  #0 twlite::Renderer::attached(...)          renderer.cpp:3206
  #1 twlite::Renderer::note_children(...)     renderer.cpp:3222
  #2 twlite::Renderer::apply_op(...)          renderer.cpp:2796
  #3 twlite::Renderer::apply_ops(...)         renderer.cpp:2683
  #4 twlite::Renderer::receive(...)           renderer.cpp:2511
freed by ... Renderer::forget(...)            renderer.cpp:2968
allocated by ... Renderer::apply_op(...)      renderer.cpp:2728
```

**The op stream is what the shipped bundle emits.** Reproduced from the real
`sandbox-bundle.js` in quickjs-ng 0.17 (`harness/combined.js ta_steps 4`,
`logs/bundle_ta_steps4.log`), three consecutive flushes:

```json
[{"op":"prop","id":5,"name":"value","value":"x"}]
[{"op":"rm","id":5}]
[{"op":"text","id":6,"data":"hello"},{"op":"ins","parent":4,"id":6,"before":null}]
```

The two-tick split is natural: `prop`/`call` ops are flushed from the `En` queue *after* the
dirty-node ops of the same tick (`HN`/`Yb`), so `value=` and `remove()` in the same script give
`rm … ins … prop` (prop last, no UAF). Two `<script>` tags (separate tasks/ticks) give the order
above. Minimal document for any client that does not drop form controls:

```html
<textarea id=t>hello</textarea>
<script>window.__c = document.getElementById('t').firstChild;
        document.getElementById('t').value = "x";</script>
<script>const el = document.getElementById('t');
        el.remove(); document.body.appendChild(__c);</script>
```

**Why it is not reachable in the shipped Android build.** The validator's profile drops form
controls *with their subtree*:

`widget-sandbox/packages/core/profile.json:137` → `"textarea": "drop"` (input/select/option/
optgroup/textarea/datalist/fieldset/progress/meter likewise, `SECURITY_DROPPED_TAGS`/`DROPPED_TAGS`).
Verified against the **shipped 72889 `validator-bundle.js`** (`harness/valtest2.js`,
`logs/validator_textarea_drop.log`): feeding the exact op stream above, the validator emits no
`el` for the textarea and no `prop`:

```
### initial   [el 2 html, el 3 head, el 4 body, text 6]
### value     []
### rm        [rm 6]
### ins-orphan[text 6, ins parent 4 id 6]
```

So native never creates a textarea node; `rm`/`prop` for id 5 are dropped by the validator before
the renderer. The bug requires a profile that keeps form controls (the upstream unit tests and
any host that drives `twlite::Renderer` without the validator, or a future profile change). It is
a genuine defect in shipped code, not a live widget 0day.

**Primitive / endgame (if the gate is ever removed).**
- Freed object is `Renderer::Node`: 168 B in the libstdc++ host build (ASan region), 152 B in
  the libc++/Android build → Scudo class 160.
- **MTE-on**: `attached()` dereferences the stale `parent` (tag mismatch after free) → synchronous
  fault at the first read; reliable crash, not corruption. Same for the `detach()` read of
  `parent->children`.
- **MTE-off / same-tag reuse**: the widget controls allocations in the same batch. After `rm`,
  an `attr` op with a ~150–160-byte value (or a text node of that size) can reclaim the freed
  Node's class-160 chunk with attacker bytes. `Node::parent` sits at offset 120 and
  `children` (begin/end/cap) at 128/136/144, so a reclaimed string supplies a chosen 64-bit
  `parent` and chosen vector iterators. `attached()` then walks an arbitrary pointer chain, and
  `detach()` runs `std::remove`/`erase` over attacker-chosen `begin/end` → wild read and a
  memmove-style write of Node* values. ASLR requires a heap/lib leak (the project has other
  info-leak work); without one this is a controlled crash.
- No OOM/interrupt needed; no JS memory bug; the trigger is two ordinary DOM operations.

**Tag domain:** 160-byte Scudo class; state is per-`Renderer` (widget instance); the freed chunk
stays in the process heap, so a second widget in the same process could in principle be the
reclaimer, but the dangling node is only reachable through its own renderer's `nodes_`.

### D-2 — Stack exhaustion in recursive shadow-tree walks (conditional DoS)

`Renderer::forget()` (renderer.cpp:2965) and `serialize_node()` (renderer.cpp:2973) recurse per
DOM depth. The validator caps node **count** (50 000) and ops/batch (10 000) but has **no depth
cap**; a chain of allowed `<div>`s is legal:

```js
for (let i=0;i<30000;i++){ const d=document.createElement('div'); (i?prev:document.body).appendChild(d); prev=d; }
// or 2 ops per level, 5 000 levels per 10 000-op batch, over a few ticks
```

Host measurement with the real core (`poc/poc_deep.cpp`):

| build | depth 20 k | 30 k | 40 k | 49 k |
|---|---|---|---|---|
| ASan, 8 MB stack | OK | OK | **stack-overflow in `forget()`** | — |
| Release, 8 MB stack | OK | OK | OK | OK |

ASan log `logs/poc_deep_40000.log`: thousands of `twlite::Renderer::forget` frames
(renderer.cpp:2965), then overflow. On Android the renderer is driven from the widget host
thread; bionic's default pthread stack is 1 MB (main thread 8 MB). If the host thread is a
default 1 MB pthread, the release threshold is roughly 6–10 k depth — inside the 50 k node
budget, i.e. a repeatable widget-only crash. **Not verified on device in this pass** (host-only
rule); a crash-log-only Pixel run of a deep-div widget would settle it. Caveat: the validator's
`opInsert` cycle check walks the parent chain for every insert, so *building* depth D costs
O(D²) validator work; the validator CPU quota may stop the widget before the stack threshold.
The host PoC drives the renderer directly (no validator), so it measures the renderer's limit,
not the end-to-end one. This is stack exhaustion, not a controllable write.

---

## 4. Negatives (each checked, with evidence)

### 4.1 `data-twid` attribute poisoning — closed
`serialize_node` writes the real id first (`renderer.cpp:2984`), then echoes the node's attrs,
including a widget-set `data-twid` (`renderer.cpp:3000-3007`). Host output for
`{"op":"el","id":10,"tag":"div","attrs":[["data-twid","2"]]}`:
`<div data-twid="10" data-twid="2"></div>`. Gumbo's tokenizer drops duplicate attribute names
(`src/gumbo/tokenizer.c:780-803`, “Identical attribute; bail”, first wins), and
`document::create_node` builds the attribute map from gumbo's list, so the parsed element keeps
id 10. `elements_` (id → litehtml element) is therefore not poisonable this way. Even if it
were, its values are `shared_ptr` and every lookup copies one.

### 4.2 DOM cycles — closed twice
The validator rejects an `ins` whose parent is a descendant of the inserted node
(`validator.ts opInsert`: walks `parent` to the root and compares with the node). The native
model repeats the check (`renderer.cpp` ins: `for (Node* a=p; a; a=a->parent) if (a==n) return;`).
A cycle is not reachable even with forged ops, because the validator re-serialises every op.

### 4.3 Id reuse after `rm` — safe
The bundle reuses a node's sticky id after removal (`harness/combined.js rmreadd` emits
`rm 6`, `el 6`, `text 7`, `ins 7→6`, `ins 6→5`). Native `el`/`text` ignore an id that is still
in `nodes_`; `rm` removes it via `forget`; the validator deletes removed ids from its model and
rejects later references. No stale lookup, no double `forget`; `forget`’s children vector cannot
be a DAG because `ins` always detaches first and roots are blocked.

### 4.4 `patch_log_` raw `Node*` keys — guarded
`PatchLog.attributes/texts` hold `const Node*` and `patch_document()` dereferences `n->id`.
Every deletion (rm) first calls `note_children(n->parent, n)`, which sets `valid=false` for any
non-text child; `ins` (move) does the same; `forget` is only reached after that. Logged nodes are
only accepted while `attached(n)` (chain to `html_node_`). No path deletes a logged node with
`valid` still true was found. `forget` also ignores `aliases_`, but roots (`html/head/body`) are
blocked from `rm`/`ins` by `is_root`, so no alias is ever freed.

### 4.5 JNI marshalling — bounds checked
`twidget-bridge.cpp`:
- `bytes(JNIEnv*, jbyteArray)`: `std::string(GetArrayLength, '\0')` + `GetByteArrayRegion`
  exactly the string's size; null array → empty.
- `canvas_read`: `w > 0 && h > 0` then `size == size_t(w)*size_t(h)*4` before resizing and
  copying; a mismatched array is rejected.
- `canvas_run`: `NewIntArray(size)` / `SetIntArrayRegion(size)` from the same vector.
- `intl`/`signal`: `DeleteLocalRef` on every path, `check()` clears Java exceptions.
No length, truncation or local-ref bug found.

### 4.6 `Object.prototype.toJSON` forged ops — gate holds
The sandbox serialises the op array with `JSON.stringify`, so a widget can make every op object
serialise as arbitrary JSON (`Object.prototype.toJSON`), reaching `__host("ops", …)` with
attacker-chosen text. That text is parsed by the validator, which re-validates each op and
re-serialises it; tag policy (`textarea`/`input`/… dropped), attribute policy (`data-*` allowed,
`data-tg-*` dropped), URL policy, prop/method tables and the cycle check all apply to forged
ops too. Forging cannot re-enable a form control or skip the cycle check. The validator’s own
model is only mutated by accepted ops, so the ops that reach native stay internally consistent.

### 4.7 Bridge globals / feature gates
Only `__host` and `__hostBinary` are registered (`sub_78213C`; the literal `__hostBinary` at
`0x214008`; `__host` built in-place). `__hostOps` and `__hostCanvas` are absent from the
library and the JS guards leave `If`/`Jo` null, so the binary-ops and canvas-words branches are
dead. The feature builder (`sub_78D044`) keeps only `webAnimations`, `noAttrFast`,
`noInPlaceText`, `noCanvasRect`; `binaryOps`, `canvasWords`, `morphUpdates` are not emitted.

### 4.8 Event path
Hit-testing resolves ids with `widget_id()` (strtoll of `data-twid`) and sends `targetId` to JS;
`Qr(targetId)` returns null for ids the JS DOM no longer has, and the sandbox drops the event.
No node type confusion or stale dereference found in the event/renderer callbacks that a widget
can steer (touch/hover come from the platform, not from JS).

---

## 5. iOS applicability

The iOS renderer in this tree is the Swift `Sources/TwidgetRenderer/WidgetDOM.swift`, not
TwidgetCore: a textarea’s value is stored in `node.formValue`
(`WidgetDOM.swift:781`/`827`) and **children are not cleared**, so D-1’s orphan cannot occur
there. D-2 is a C++-core issue; the Swift DOM has its own recursion but was not built/run in
this pass. The shipped iOS `TelegramUIFramework` 36535 contains `wr::`/litehtml code and
`WidgetDOM`-style handling, and the shared profile drops form controls anyway. No iOS-specific
DOM/bridge memory bug was identified. (iPhone untouched.)

---

## 6. Lab artifacts / reproduction

`lab/lib_hunt_dom/`:

```
assets/…/sandbox-bundle.js|qbc, validator-bundle.js|qbc   (from the 72889 APK)
src/sandbox-bundle.pretty.js, validator-bundle.pretty.js  (beautified)
harness/combined.js        sandbox bundle + mock __host; scenarios in prologue.js
harness/valtest2.js        validator bundle + glue; feeds the exact op stream
poc/poc_textarea.cpp       D-1 PoC against the real TwidgetCore (ASan)
poc/poc_deep.cpp           D-2 depth PoC (ASan and release)
poc/poc_twiddup.cpp        data-twid duplicate serialisation check
build_tw/                  TwidgetCore + litehtml, ASan (-O1)
build_tw_rel/              TwidgetCore + litehtml, release
logs/poc_textarea_asan.log         heap-use-after-free (D-1)
logs/poc_deep_40000.log            stack-overflow (D-2, ASan)
logs/poc_deep_rel_49000.log        release 49 k depth survives (8 MB stack)
logs/validator_textarea_drop.log   shipped validator drops textarea (reachability gate)
logs/bundle_ta_steps4.log          real bundle’s three flush batches for D-1
logs/texdiff_72889_72929.log       (see also domain_align.py output)
```

Build/repro (host):

```
cmake -S <twidget-src>/twidget -B build_tw -DTWIDGET_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"
make -C build_tw -j8 twidget_core
c++ -std=c++20 -fsanitize=address -g -O1 <includes> poc/poc_textarea.cpp \
  build_tw/libtwidget_core.a build_tw/liblitehtml.a -lpthread -lm -o poc/poc_textarea
ASAN_OPTIONS=detect_leaks=0 ./poc/poc_textarea
```

The sandbox bundle runs in upstream quickjs-ng 0.17 (`/tmp/opencode/qjs017/build_clean/qjs`);
`harness/combined.js <scenario>` prints the host calls (`@@ ops: [...]`).

---

## 7. Next steps (for the orchestrator)

1. **D-1 is not a shipped-profile 0day.** If a later build/profile enables form controls
   (`profile.json` `textarea/input` no longer `drop`), it becomes a one-message UAF; ask the
   profile owners before treating it as a live bug. A device test would need such a build (not
   available, and the Pixel is crash-log-only).
2. **D-2** needs one crash-log-only Pixel run with a deep-div widget (e.g. 12 000 nested divs
   built over three scripts) to measure the renderer-thread stack. Not run here.
3. If the project wants an MTE-on primitive from this layer, D-1 under a form-allowing profile is
   the candidate: stale `Node*` deref → tag fault (crash) with MTE on; deterministic crash, no
   corruption.
4. The forged-ops path (§4.6) is worth a dedicated differential fuzzer (sandbox op stream vs
   validator output vs renderer model) — a small/quick fuzz campaign, not started here because
   the task’s heavy-fuzzing budget was not approved.

---

## 8. Prior art consulted and fuzzing plan (not started)

**Pattern research (public).** Browser DOM UAFs of the last two years are overwhelmingly
*raw pointers cached across a DOM mutation that the mutation path forgets to update*:
Firefox `HTMLFieldSetElement::InsertChildBefore` kept `mFirstLegend` after a failed insertion
(Bugzilla 2024651, dup of 2024437); the Oct-2026 Firefox HTML-parser UAFs
(CVE-2026-117883, CVE-2026-117920) and Chrome DOM UAFs (CVE-2026-119267,
CVE-2026-113187) are the same shape; WebKit `HTMLSelectElement::m_listItems`
(Project Zero 42451489) caches dummy `<option>` raw pointers across `surroundContents`.
D-1 is exactly this shape (`Node::parent` cached across `children.clear()`), which is why it
was worth chasing even though the profile currently blocks the tag. litehtml itself has no
security advisories in the public databases; its `appendChild` has no cycle check (upstream
source), but the validator + native model supply one, matching how browsers add
HierarchyRequestError precisely because insertion algorithms assume a tree.

**Methods used.** Source↔binary correlation (vtable `off_18D46E0`, `data-twid` strings,
`Node` offsets `+120/+128/+136`); a host build of the *real* TwidgetCore with ASan; an op-stream
harness running the shipped sandbox bundle in quickjs-ng 0.17 against a mock `__host`; the
shipped validator bundle driven through `__twValidator`; an 72889→72929 instruction-address
diff to rule out a fix between builds.

**Heavy fuzzing plan (needs orchestrator approval; not started).**
- Target: `twlite::Renderer` built as in `build_tw`, ASan, `-O1`, with the stub backend.
- Harness: a libFuzzer/AFL++ driver taking a byte string → a sequence of validator-legal op
  batches (grammar-aware mutator over `{el,text,attr,rattr,data,ins,rm,style,css,prop,call}`,
  ids from a small pool, tags from `profile.json`, attrs from the allowlist + `data-*`).
  Every generated batch is optionally run through the shipped validator bundle in quickjs to
  keep only the ops a widget can actually deliver (differential mode), and through a
  "raw" mode (no validator) to find latent core bugs like D-1.
- Corpus: the op streams from the real widget apps in `evidence/chat_widgets/` (POCKET INFERNO,
  World Clock, Box Breathing) + the harness' initial trees.
- Duration/size: 24 h wall, 8 workers, ~4 GB RSS total, 10 k exec/s target; stop on the first
  ASan report, save the reproducer. No device involvement.
- Secondary: a DOM-mutation fuzzer for the sandbox bundle itself (domato-style sequences of
  create/insert/remove/value/innerHTML) diffing the sandbox's emitted ops against the
  validator's accepted ops, flagging divergences (sandbox-only state) for native analysis.
