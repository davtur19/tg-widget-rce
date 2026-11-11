# T2 / T3 reachability through the Telegram widget host bridge

Date: 2026-11-05. Host-only (IDA + quickjs-ng lab build). No phone, no bot, no device
operations.

Target: `apks/13.2.0 (7287).apk` → `lib/arm64-v8a/libtmessages.49.so`
(sha256 `e83e517a77bec68e565b96218969cb1fad1007f160a1450dc6c7fd9344d90984`).
IDB: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_72879_f2_annotated.i64`
(opened, annotated, saved in place — see §8).

Artifacts: `lab/bridge_t2/` (`ida/` Hex-Rays exports, `poc/`, `evidence/`).

Inputs: `notes/audit_types.md` (T2 = stale `ta->length` in `JS_GetTypedArrayBuffer` /
`JS_GetUint8Array`; T3 = `Atomics` writes through immutable ArrayBuffers),
`notes/widget_js_api_audit.md`, `notes/twidget_native_audit.md`.

---

## 0. Verdict

**T2 is not reachable from widget JavaScript in build 72879. T3 has no app-level
impact either.** Both are embedder-only defects, and this embedder is not the kind
of embedder they need.

The single decisive fact: **the widget's JS→native ABI is
`HostReturn(const std::vector<std::string>&)`.** Every argument of every host call is
marshalled to a `std::string` before any native code sees it. A `Uint8Array`,
`ArrayBuffer`, `DataView`, resizable-buffer view, detached view, Proxy or any other
object is converted to the **empty string** — no pointer, no length, and no user
getter is ever evaluated. There is no native function in the sandbox that receives a
`JSValue`.

Consequences:

* T2's trigger object (a length-tracking view over a shrunk RAB) can be *built* freely
  by widget JS but cannot be *delivered* to a consumer that trusts `ta->length`.
* The quickjs C API functions that expose the stale length are not called from the
  widget module at all: a call-graph audit of every quickjs entry point reachable from
  the widget/validator code (101 direct callees, 468 functions in the 3-level closure)
  finds no array-buffer/typed-array accessor among the direct callees; the only
  array-buffer function anywhere in the closure is `js_array_buffer_constructor3`,
  used to *create* the `__hostBinary` return value.
* T3's premise — "some native bridge assumes a JS ArrayBuffer is read-only" — has no
  subject: no JS buffer crosses the boundary.

The only *latent* route (documented in §4) needs three independent things to change at
once; in this build the first one already fails.

---

## 1. Complete map of the widget native surface

### 1.1 JS-visible native functions

The sandbox is a quickjs-ng runtime created by `tw_sandbox_create` (0x78013C,
`JS_NewRuntime` with a 6 MiB limit — the documented 6 MiB JS heap). That function
registers **exactly two** native globals and then schedules the boot jobs:

| global | registered at | native handler | JS→native ABI |
|---|---|---|---|
| `__host(method, arg)` | 0x78013C → `tw_host_register` (0x77C85C) | `tw_host_op` (0x78AD5C) → `tw_host_dispatch` (0x784528) | `vector<string>{method, arg}` |
| `__hostBinary()` | 0x78013C → `tw_host_register` | `tw_hostBinary_op` (0x78AF30) | **arguments ignored**; returns a staged byte blob |

`__hostCanvas`, `__hostOps` and `__twDispatch` are *not* native. `__twDispatch` is
defined by `sandbox-bundle.js` itself (`Object.defineProperty(Oe,"__twDispatch",…)`,
a JS dispatch table for `boot/nextScript/scriptDone/loaded/endTick/event/timer/frame/
viewport/resize/theme/safeArea/bridge/morph/visibility`). `__hostCanvas` and
`__hostOps` do not exist anywhere in the `.so` — the only occurrence of those byte
strings in the whole 27 MB library is inside the `hide-host.js` literal (§1.5).

`tw_host_register` (0x77C85C) is the **only** "define a native JS function" primitive
in the widget module. It has exactly three call sites in the binary: two in
`tw_sandbox_create` (`__host`, `__hostBinary`) and one in `tw_validator_create`
(`__diag`). It registers a `std::function<HostReturn(const std::vector<std::string>&)>`
and hands the JS side one generic C function (0x77D89C) with the handler index as
magic.

The validator runtime (`tw_validator_create`, 0x7A6150) is a **separate JSRuntime**
holding `__diag` and calling the validator glue entry `__v_create` (a JS function from
`validator-bundle.js`; the call helper `sub_77D230` only resolves a global by name,
checks `JS_IsFunction`, and passes strings). The widget cannot reach that runtime
(separate context, no shared objects, and the widget only ever talks to it through
native code that passes strings).

### 1.2 `__host` method table (all 16 methods, from `tw_host_dispatch`)

`tw_host_dispatch(engine, method: string, arg: string) → HostReturn`. Argument is
always a string; the JSON-shaped ones are parsed with the app's own parser
(`sub_792048`, depth 128). Return kinds: 0/1 = undefined, 2 = string, 3 = double,
4 = external ArrayBuffer (only `__hostBinary` uses 4).

| method | argument | notes |
|---|---|---|
| `ops` | JSON array of render ops | inline compare `op`/`s`; scans for `"cmd":`/`"cmds":[` to charge CPU |
| `now` | – | returns double (ms) |
| `query` | JSON | layout query → JSON string |
| `timer` | JSON | schedules a timer (maxTimers/timer-limit enforcement) |
| `clearTimer` | decimal id string | |
| `raf` | – | requestAnimationFrame |
| `log` | JSON | length-capped diagnostics |
| `diag` | `code:message` | length-capped diagnostics |
| `listen` | – | |
| `pd` | JSON | preventDefault id set |
| `anim` | JSON | |
| `bridge` | JSON `[method, args]` | `TelegramWidget.*` actions (`openLink`, `openTelegramLink`, `copyText`, `request`, `wallet.*`, `ready`, …); tap-gated, preview-gated, URL/type re-validated natively |
| `storage` | JSON `{local?, session?}` | ≤4096 B per value, ≤0x18041 B total |
| `intl` | JSON | |
| `random` | decimal length string | `arc4random_buf`, capped at 0x10000, returned as `[1,2,…]` |
| `stat` | JSON | cache counters |

`TelegramWidget` itself is pure JS defined by the bundle (`F.TelegramWidget=t`); every
method funnels into `vr = (t,...e) => me("bridge", JSON.stringify([t,e]))`.

### 1.3 The one generic trampoline (0x77D89C) — the whole ABI in 20 lines

```
engine = sub_17AE878();                    // engine from JSContext opaque
if (magic >= handler_count) return undefined;     // magic = handler index
for each (argv[i]):
    if  (tag + 7) < 2        -> JS_ToCStringLen2()  then copy into std::string   // sub_17BF348
    elif (tag & ~8) == 0     -> JS_ToFloat64(), "%lld" or "%.17g"                // sub_17BF358
    else                     -> push empty string                                // <-- every object
call handler(std::vector<std::string>)
box HostReturn: 0/1 undefined, 2 JS_NewStringLen(copy), 3 double, 4 js_array_buffer_constructor3(external)
```

* `js_tag_is_string` = `(unsigned)(tag + 7) < 2` → tags −7/−6 (string/symbol).
* `js_tag_is_number` = `(tag & ~8) == 0` → tags 0 (int) and 8 (float64).
* Objects (`JS_TAG_OBJECT = −1`), arrays, typed arrays, ArrayBuffer, DataView,
  Proxy, null and undefined all fall into the `else` branch: **the empty string,
  with no property access and no coercion**. `toString`/`Symbol.toPrimitive` are
  never called (harness proof: 0 getter executions).

### 1.4 Java/JNI surface (for completeness; not reachable from widget JS)

`org.telegram.utils.twidget.WidgetSandboxNative` (jadx,
`.scratch_beta1320/jadx4b/.../WidgetSandboxNative.java`) takes `byte[]`/`long`/`float`
from Java: `create(byte[],byte[],byte[],f,f,i,byte[],byte[],byte[],byte[],z,Backend)`,
`data(long,byte[])`, `answerRequest(long,long,int,byte[])`, `theme/safeArea/limits`,
`filterPixels(Bitmap,byte[],f)`, arbiter/touch/hover/… All buffers here originate in
**Java** (public data, chat data, theme JSON, qbc bundle, widget source), never in
widget JS. The widget's data reaches Java as JSON strings through
`__host("bridge", …)`.

### 1.5 Boot-time scrubbing

`tw_sandbox_boot` (0x78B044) evaluates `sandbox-bundle.js`, requires the global
`__twDispatch` to exist, then runs `hide-host.js`:

```js
(function(g){for(const n of ['__host','__hostBinary','__hostCanvas','__hostOps','__twDispatch'])
  if(!delete g[n])throw new Error(n);})(globalThis);
```

The bundle captures `wf=__host`, `u5=__hostBinary`, `Jo=typeof __hostCanvas=="function"
?__hostCanvas:null`, `If=typeof __hostOps=="function"?__hostOps:null` **before** the
delete. In 7287 the two `typeof` guards evaluate to `undefined` because the globals do
not exist, so `Jo===null` and `If===null`.

---

## 2. Why T2 cannot be reached — six independent proofs

**P1 — The ABI is string-only.** `tw_host_trampoline` (0x77D89C) is the only place
where widget-supplied JS values enter native code. Its argument loop converts to
`std::string` and copies. Even a hypothetical handler bug cannot see a pointer/length
pair from JS.

**P2 — There is no second entry point.** The only JS-function factory in the module is
`tw_host_register`; it has 2 sandbox call sites (`__host`, `__hostBinary`) and 1
validator call site (`__diag`). `__hostCanvas`/`__hostOps` do not exist as byte strings
in the library (verified with a raw `grep -a` over the `.so`: the only hits are inside
the `hide-host.js` literal). Therefore the bundle's two buffer-consuming hooks are
`null`.

**P3 — The quickjs C API used by the widget never touches typed arrays.** I enumerated
every call edge from `libtmessages` widget/validator code (`0x770000–0x7B0000`) into
the quickjs core (`0x1600000–0x1800000`): **101 distinct direct callees**. None of the
101 mentions `array_buffer`, `typed_array`, `immutable` or `class_id` in its body — the
widget never calls a typed-array accessor. Walking the closure further (3 levels,
468 functions) turns up exactly one array-buffer-related function anywhere in it:
`sub_173D5D4` (`js_array_buffer_constructor3`), reached only from `sub_17BF420`, i.e.
the `__hostBinary` return boxing. `JS_GetTypedArrayBuffer`, `JS_GetUint8Array`,
`JS_GetArrayBuffer` and `JS_GetDataView` are not called anywhere in the widget code.

**P4 — `__hostBinary` is dead in the bundle.** `u5 = __hostBinary` is referenced
exactly once — its own declaration. `u5(` has 0 occurrences in
`lab/qjs_async_app/assets/7287/sandbox-bundle.js`. Its native implementation
(`tw_hostBinary_op`, 0x78AF30) ignores its arguments entirely and returns the staged
`answerRequest` bytes (engine+912) as an external, **non-resizable** ArrayBuffer.

**P5 — No quickjs-libc.** The string `could not load module filename` and the `std.*`
API are absent from the `.so`, so the `JS_IMPORT_TYPE_BYTES` path (the only upstream
user of `JS_GetTypedArrayBuffer` inside quickjs itself) is not linked.

**P6 — There is exactly one JS callback in the library.** `sub_17AE878` (fetch the
engine pointer from a `JSContext`) has a single call site in the whole 27 MB binary:
`tw_host_trampoline`. `tw_host_trampoline` itself has a single reference, from
`tw_host_register`. So every registered host function funnels through that one
string-only callback; there is no second, `JSValue`-taking native entry point to audit.
The other JSValue→string helper (`sub_77CB3C`) is used only by the eval/call wrappers
(`sub_77CA60`, `sub_77CD1C`, `sub_77D230`).

Corollary: the claim in `notes/audit_types.md` that "the only native call that receives
a typed array is `__hostCanvas` with an engine-created fixed `Float64Array.subarray`"
is **wrong for 7287**. In this build the `Float64Array` canvas encoder is disabled at
its gate (`pE = t && Jo !== null`, `Jo === null`), and canvas commands travel as JSON
through `__host("ops", …)`. Correction recorded in §8.

---

## 3. Could a view be *passed* despite all this?

Yes, syntactically — the widget can pass anything as an argument — but it is turned
into `""` before native code runs:

```
__host("test", new Uint8Array([1,2,3]))         -> arg ""        (Uint8Array)
__host("test", trackViewAfterShrink)            -> arg ""        (length-tracking RAB view)
__host("test", new ArrayBuffer(1024,{maxByteLength:4096})) -> ""
__host("test", new DataView(buf))               -> ""
__host("test", new Proxy({},{}))                -> ""
__host("test", detachedView)                    -> ""
__host("test", {toString(){...}})               -> ""            (toString never runs)
```

and no getter/resize re-entrancy can occur during conversion, because conversion never
calls back into JS.

The stale length itself is still there in this exact build (same engine family):

```
JS byteLength=16   JS_GetTypedArrayBuffer pbyte_length=1024
```

— it simply has no consumer.

---

## 4. The latent near-miss (what would make T2 reachable)

The bundle *does* contain a code path that hands a `Float64Array` to a host function:

```js
var wf=__host, u5=__hostBinary, Jo=typeof __hostCanvas=="function"?__hostCanvas:null, …
function Db(t,e){return fu.push({words:t,strings:e})-1}
function Rf(){if(!fu.length||!Jo)return; let t=fu; fu=[]; for(...) Jo(e,t[e].words,t[e].strings)}
…
Db(r.f.subarray(0,r.n), r.joined)      // r.f = new Float64Array(512) inside encoder Vf
```

and the encoder is enabled only by a widget feature flag in the boot config
(`config.features`, supplied with the widget by the server):

```js
bE(Array.isArray(r.features)&&r.features.includes("canvasWords"))   // pE = t && Jo!==null
```

Three gates would have to open for a widget-controlled RAB view to reach a native
consumer:

1. **A `__hostCanvas` must exist natively.** Not in 7287 (no such string; `Jo === null`).
2. **It must take a `JSValue`, not a `string`.** If it were registered through
   `tw_host_register` like `__host`/`__hostBinary`, the generic trampoline (P1) would
   stringify the `Float64Array` to `""` anyway.
3. **The bundle must hand it a length-tracking view.** It hands
   `Float64Array.prototype.subarray(0,n)` on a *fixed* 512-element buffer. A widget
   could hijack that via prototype pollution (`Object.prototype`/`Float64Array.prototype`
   are not frozen — `notes/widget_js_api_audit.md` §6.4), e.g.
   `Float64Array.prototype.subarray = () => rabTrackingView`. That is the only way a
   widget-controlled RAB view could enter `fu[]`.

So the realistic T2 weaponization path for a *future* client is:

```js
// only meaningful on a build that has a JSValue-taking __hostCanvas + canvasWords
const b = new ArrayBuffer(1024,{maxByteLength:4096});
const v = new Uint8Array(b);      // length-tracking
b.resize(16);                     // ta->length stays 1024, byteLength becomes 16
Float64Array.prototype.subarray = function(){ return v; };
// next canvas flush: Rf() -> __hostCanvas(idx, v, strings)
// native embedder reads pbyte_length=1024 from a 16-byte allocation -> OOB read
```

If such a host existed and *wrote* back through `pbyte_length`, it would be an OOB
write; if it only read, an info leak (adjacent quickjs heap → engine pointers).
Neither applies to 72879.

A cheap future check (72879 baseline in comments):

```bash
grep -a -o '__hostCanvas' libtmessages.49.so | wc -l   # 72879: 1 (inside hide-host.js only)
grep -a -o '__hostOps'    libtmessages.49.so | wc -l   # 72879: 1 (inside hide-host.js only)
grep -a -o 'u5('          sandbox-bundle.js  | wc -l   # 72879: 0 (__hostBinary dead)
```

plus: confirm `tw_host_register` has ≤3 call sites and that any new one uses the same
`vector<string>` functor type.

---

## 5. T3 — Atomics through immutable ArrayBuffers

The T3 defect (Atomics bypassing `abuf->immutable`) needs a native consumer that
treats an ArrayBuffer as trusted read-only storage. In 72879:

* No ArrayBuffer, typed array or DataView is ever passed from JS to native (P1–P3).
* The only native-created ArrayBuffer is the `__hostBinary` return
  (`js_array_buffer_constructor3`, non-resizable, not marked immutable); it is dead
  code (P4).
* No app code tests an `immutable` flag: there is no call edge from the
  widget/validator modules to `JS_SetImmutableArrayBuffer` (only quickjs-libc would use
  it, and libquickjs-libc is not linked).
* `transferToImmutable()` buffers therefore live and die inside the JS heap; `Atomics`
  writing them is a spec deviation observable only to JS.

Conclusion: T3 remains a pure engine/semantics bug with no app-level
memory-safety or policy consequence in this build.

---

## 6. Evidence

| artifact | content |
|---|---|
| `lab/bridge_t2/ida/sub_78013C_sandbox_create.c` | runtime + `__host`/`__hostBinary` registration |
| `lab/bridge_t2/ida/sub_77C85C_register_host_fn.c` | the only host-function factory |
| `lab/bridge_t2/ida/sub_77D89C_generic_trampoline.c` | the JS→native boundary (string marshalling) |
| `lab/bridge_t2/ida/sub_78AD5C_host_operator.c` | `__host` operator() → dispatcher |
| `lab/bridge_t2/ida/sub_78AF30_hostbinary_operator.c` | `__hostBinary` operator() (args ignored, staged bytes) |
| `lab/bridge_t2/ida/sub_784528_method_dispatch.c` | 16-method dispatcher |
| `lab/bridge_t2/ida/sub_7893EC_twdispatch_call.c` | native→JS `__twDispatch` call (strings) |
| `lab/bridge_t2/ida/sub_7A6150_validator_create.c` | separate validator runtime |
| `lab/bridge_t2/ida/sub_78B044_sandbox_boot.c` | bundle eval + hide-host |
| `lab/bridge_t2/ida/sub_17BF348_is_stringlike.c`, `sub_17BF358_is_number.c` | the tag predicates |
| `lab/bridge_t2/poc/host_abi_repro.c` | faithful reimplementation of the marshalling |
| `lab/bridge_t2/evidence/host_abi_repro.txt` | its output: all non-string/number args → `""`, 0 getters, stale length 1024 vs 16 |
| `lab/bridge_t2/poc/t2_widget_probe.js` | widget-side probe for future builds |
| `lab/bridge_t2/evidence/libhash.txt` | `.so` sha256 |

`host_abi_repro.c` was linked against quickjs-ng `e22ce4d` (`lab/qjs_types_audit/src`,
the same tree used by `notes/audit_types.md`); the app's engine is `7a23d8e`, whose
typed-array C API is unchanged between the two commits (audit_types §0).

Reproduce:

```bash
cd lab/qjs_types_audit
cmake -S src -B builds/plain -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-O1 -g"
make -C builds/plain -j"$(nproc)" qjs_exe
cc -O1 -g -I src ../bridge_t2/poc/host_abi_repro.c builds/plain/libqjs.a -lm -lpthread \
   -o ../bridge_t2/poc/host_abi_repro
../bridge_t2/poc/host_abi_repro
```

IDA side (target IDB already annotated):

```
tw_sandbox_create 0x78013C   tw_host_register 0x77C85C   tw_host_trampoline 0x77D89C
tw_host_op 0x78AD5C          tw_hostBinary_op 0x78AF30    tw_host_dispatch 0x784528
tw_dispatch_to_js 0x7893EC   tw_validator_create 0x7A6150 tw_sandbox_boot 0x78B044
js_tag_is_string 0x17BF348   js_tag_is_number 0x17BF358
```

---

## 7. Dedup

T2/T3 are not in the quickjs-ng tracker (audit_types §1/§8). This note adds no new
engine bug: its value is the **negative reachability result** and the exact host-API
map, which closes the "verify `__hostBinary`'s native implementation before assigning
app impact" item left open in `notes/audit_types.md` §4.

Corrections to prior notes:

* `notes/audit_types.md` §4 (and the T2 blocker row): `__hostCanvas` does not exist in
  this build and no typed array reaches native code at all; the float canvas encoder is
  gated off (`Jo === null`).
* `notes/widget_js_api_audit.md` §6.1 uses `Ko = __hostCanvas`; in the 7287 bundle
  `Ko` is the HTML fragment parser and `Jo` is the `__hostCanvas` slot. The conclusion
  (captured but unusable) is unchanged; `Z8` is `u5` in this build.

## 8. IDB persistence

* Opened `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_72879_f2_annotated.i64`.
* Renamed the 11 functions above, added comments documenting the ABI and the T2
  conclusion, `save_database` in place; names/comments verified by re-query.
* IDB path (standard backup dir):
  `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_72879_f2_annotated.i64`
