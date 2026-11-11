# Update-surviving media cache: does Telegram auto-render a cached media message? (72799)

Scope: host/source only. No device tests were run for this note; all claims are
either code citations from the 72799 APK/smali tree or device logs already in the
project. The widget cache is kept as a **fallback** section: the primary question
is whether a DB-cached **native** media message (bot photo/document/sticker/etc.)
is rendered or opened automatically after an app update.

## 0. Verdict

**No for regular `MessageMedia` (photo, video, document, sticker, voice, …):
a DB-cached media message is not decoded or opened automatically after an
update. There is one important exception: animated custom emoji (TGS) in the
last-message text *is* drawn in the chat list, which reaches Telegram's native
`RLottieNative` parser without opening the chat.**

Concretely, for 72799:

1. **Chat list preview does not render regular message media.**
   `DialogCell` (`org/telegram/ui/Cells/v2`) builds a text preview from
   `MessageObject.v` and loads only the dialog/sender avatar. It has **zero**
   references to the widget engine, `RichTextLayout` (`wv`) or `hl0`; it does not
   call `MessageObject.E0()`. A photo/document/sticker therefore shows a text
   label, not a decoded thumbnail. The one `TL_messageMedia` exception found is
   **paid media** (`TL_messageMediaPaidMedia`): `DialogCell.j0()` builds up to
   three thumbnail `ImageReceiver`s via `g0()`. That is a real chat-list
   image-load path, but it is a special media type and its decoder is the
   ordinary image loader, not the message's full native parser. See §3.4.

2. **Exception: animated custom emoji in the last-message text is rendered in
   the chat list.** `MessageObject.v` keeps the `TL_messageEntityCustomEmoji`
   spans (`o5` ReplacementSpan); `DialogCell.onDraw` calls
   `o5.drawAnimatedEmojis` for its preview layouts, and `o5`/`f5`/`ci0` reach
   `RLottieNative` (JNI) for the TGS document. A bot/user message whose last
   message contains a custom emoji can therefore parse a native TGS **without
   opening the chat**. This is a message-entity document, not a
   `TL_messageMedia`; the message/entity persists in `cache4.db`, while the TGS
   bytes are a cached file. See §3.6.

3. **Chat view does render ordinary media, but only when the chat is opened.**
   `ChatMessageCell` (`org/telegram/ui/Cells/q1`, `r3(...)`) binds media cells and
   builds rich layouts when the chat view is laid out. Opening the chat is a
   user/external action; it is not part of app startup. (Widget-only caveat: a
   text/user update on an already-live `MessageObject` can build the rich layout
   through `n0()`, §4.4; that is an in-process path, not a cold-start path.)

4. **There is no last-chat restore after an update.**
   The package update kills the process with `installPackageLI` and removes the
   task with `proc died without state saved` (device log §6). `LaunchActivity`
   restores fragments only from `savedInstanceState`; there is no “last chat”
   preference. A normal launcher start goes to the chat list (`folderId = 0`),
   and no chat/media is opened automatically.

5. **Boot and package-replaced paths do not open a chat.**
   `AppStartReceiver` is registered only for `BOOT_COMPLETED`/`org.telegram.start`
   and runs the push-service startup; the manifest has no
   `MY_PACKAGE_REPLACED` receiver. `OpenChatReceiver` is exported and can open a
   chat from an explicit `com.tmessages.openchat` intent, but nothing sends that
   intent automatically after an update.

6. **The widget message is an update-surviving payload, not an automatic
   trigger.** It persists in `cache4.db` (verified post-update) and executes when
   its chat is rendered, but the chat must be opened. It is a fallback
   re-infection seed, not an independent update trigger.

At a glance:

| Question | 72799 answer |
|---|---|
| Chat list preview renders a regular photo/video/document/sticker? | **No**; text + dialog avatar only. |
| Chat list preview renders a custom-emoji/TGS document in the message text/caption? | **Yes**, through `o5`/`f5`/`ci0` -> `RLottieNative`; conditional on delivery/cache/settings (§3.6). |
| Chat list preview renders paid-media thumbnails? | Yes, up to 3 `ImageReceiver`s (`TL_messageMediaPaidMedia`); ordinary image loader (§3.4). |
| Chat view renders media/widget? | **Yes**, but only after the chat is opened/rendered. |
| Last-chat restore after an app update? | **No**; task removed with no saved state (§5.1). |
| Boot or `MY_PACKAGE_REPLACED` opens a chat? | **No**; boot starts push only; no package-replaced receiver (§5.3-5.4). |
| Widget message auto-runs after update? | **No**; it needs the chat view (§4.2). |

**Practical consequence for a native (non-JS) app-level RCE:**

* If the candidate is in Telegram's **TGS/RLottie** native parser, a
  **bot-delivered custom-emoji message** is the best update-surviving native
  trigger found: the chat list draws it at startup, the document is stored in
  the message/DB, and the parser is `RLottieNative`. Deliverability and
  server-side TGS validation still need testing (§3.6, T12).
* If the candidate is in a **regular media** parser (photo/document/video/etc.),
  the DB-cached message is a **dormant payload**: it survives the update but
  needs an external trigger (an explicit `OpenChatReceiver` intent, a
  notification tap, or a separate startup stage such as the forged ART app
  image) to get its media rendered. New-message notification and auto-download
  paths can decode some images without opening the chat, but they are
  message-arrival driven and decoder-specific; they are not an “after update”
  trigger by themselves (§5).

The rest of this note proves these statements and ends with a device test plan
and a hybrid-persistence design.

---

## 1. Sources and notation

* Smali tree: `/tmp/opencode/dbgbuild/smali72799/` (72799 beta, debug build;
  package `org.telegram.messenger.beta`). Paths below are relative to that root.
* Manifest: `aapt2 dump xmltree` of
  `/tmp/opencode/dbgbuild/telegram_beta_72799_dbg2.apk`; the decoded snippets
  are in `lab/update_widget_cache/manifest_slices.txt`.
* Device logs: `/tmp/opencode/evidence_20261101/campaign_72799/nb_v2_run1.log`
  (72799 campaign) and the project evidence under
  `telegramandroidwidget/evidence/evidence_20261101/`. Exact slices are in
  `lab/update_widget_cache/log_slices.txt`.
* DB: `evidence/evidence_20261101/new_beta_72799/v2.db`, md5
  `4979ae5e610d291bc0fa97849a0182d7`; message 79415 is the v2 widget payload
  (10540 B HTML, SHA1 `41380f9a33f87a8797aaae72537bfb374ad50dde`).
* Helper: `lab/update_widget_cache/extract_widget.py` (TL parser) and
  `lab/update_widget_cache/evidence_grep.sh` (reproducible greps).

A note on terminology: “render” below means the point where a view is bound or
measured/drawn and the media is actually loaded/decoded. Constructing a
`MessageObject` from the DB is **not** rendering; it only parses TL metadata.

---

## 2. Why “MessageObject construction” is not enough

A cached message is parsed into `MessageObject` (`org/telegram/messenger/kj`) as
soon as the dialog list or chat loads. That path does **not** render media and
does **not** start the widget engine.

* The main `MessageObject` constructor calls `K5()` (message type/text
  computation) and `G()`, not `E0()`/`wv`:
  `smali/org/telegram/messenger/kj.smali:958`, `:1171` (constructor calls
  `K5()`); `K5()` is at `:43486`.
* `K5()` sets the type to `0x24` for a widget message and sets the preview text
  `v` from `message.message` (or string `0x7f0ffbc6` if empty):
  `kj.smali:44607-44619` (media widget test) and `:45906-45912` (`D = 0x24`);
  preview text at `:67375-67400`.
* The **only** producer of the synthetic rich message for widget media is
  `MessageObject.E0()` (`kj.smali:36044`): it builds a `TL_iv.pageBlockEmbed`
  with `url = "tg-widget:<account>/<dialog>/<msg>/<payloadHash>"` and caches the
  `RichMessage` in `x2` (`kj.smali:36455`, `:36510-36528`). `E0()` has only three
  call sites: the rich-layout path `wv.J` (called from `wv.<init>`;
  `wv.smali:5918,5939`) and `MessageObject.n0(User)` (`kj.smali:78171`,
  text-update path). None is the dialog list.
* Therefore a chat-list `MessageObject` for a widget message has type `0x24` and
  a text preview, but no `RichMessage`, no `wv`, no widget profile, and no
  sandbox. The same logic applies to ordinary media: TL metadata only.

One caveat belongs here: `MessageObject.I()` (the “message text changed” path,
`kj.smali:40657`) calls `n0(null)` at `kj.smali:41129`, and `n0` *can* build
`wv` for a live `D == 0x24` object (`kj.smali:78127-78200`). That is an
in-process path (a user-name/translation/edit update on an object that already
exists in memory), not a cold-start path: the dialog list’s last-message object
is not run through `I()`/`n0` by the paths traced here. It is discussed again in
§4.4; it does not make the widget run after an update on its own.

This distinction is the core of the answer: DB parsing happens on startup; media
rendering does not.

---

## 3. Chat list (`DialogCell`): text + avatar, not message media

### 3.1 The cell

`org/telegram/ui/Cells/v2` is the dialog cell (it has
`setDialogCellDelegate(Lorg/telegram/ui/Cells/r2;)` at `v2.smali:43987`). Its
`z()` bind path (`v2.smali:44664`) calls `j0()` (`v2.smali:48152,50575,50605`),
which updates the preview/avatar.

The following counts are exact and reproducible with
`lab/update_widget_cache/evidence_grep.sh`:

```
twidget: 0
Lorg/telegram/messenger/wv;: 0
hl0: 0
```

in `smali_classes3/org/telegram/ui/Cells/v2.smali`. So the chat list never builds
the rich layout or the widget host.

### 3.2 What the preview actually uses

`DialogCell` builds its preview from `MessageObject.v` (a `CharSequence`), e.g.
`v2.smali:10134`, `:10960`, `:12191`. `v` is computed in `K5()`; for widget media
it is `message.message` or the resource string (`kj.smali:67375-67400`), and for
ordinary media it is the media label/description. There is no `E0()` call in
`v2` (only `wv` and `kj.n0` call it; §2).

The dialog avatar is a separate `ImageReceiver` (`Y1`, constructed at
`v2.smali:728-732`); it is set from `MessageObject.c1()` (the dialog/sender
photo), not from the message media:
`v2.smali:21583` (`ImageReceiver.i0(c1(), ...)`), with `c1()` at
`kj.smali:68279`. This is an image-decode path at startup, but it is the
**profile/dialog photo**, not a cached message media payload. It is a separate
auto-decode surface (a bot/chat profile photo is server-processed, so a crafted
local file is not the same thing); do not conflate it with message media.

### 3.3 Regular media in the last-message preview

There is no `ImageReceiver` bind for a regular `TL_messageMediaPhoto`,
`TL_messageMediaDocument`, etc. in `v2`: the only `ImageReceiver.r0` calls are
inside the paid-media path (§3.4). The preview is text (for a photo: “Photo”,
for a document: its name/type), so a bot photo/document is not decoded merely by
being the last message.

### 3.4 The paid-media exception (real, but special)

`DialogCell.j0()` handles `TL_messageMediaPaidMedia`:
`v2.smali:23424` (method start), `:23509` (`instance-of ...PaidMedia`),
`:23525` (cast). For each extended-media preview it calls
`g0(index, messageObject)` at `v2.smali:24484` and `:24730`.

`g0()` (`v2.smali:14614`) selects a `PhotoSize` from the message, checks
`DownloadController.d(message)` (`b6.d`, `v2.smali:14780`; method at
`b6.smali:2865`), and calls `ImageReceiver.r0(...)` at `v2.smali:15051`. The
receiver is one of the `V1` thumbnails created at `v2.smali:713-914`.

So a paid-media message that is the last message in a dialog **does** cause up to
three thumbnails to be loaded while the chat list is shown, without opening the
chat. This is the only message-media auto-load path found in `DialogCell`.

Caveats, stated explicitly:

* Whether a bot can deliver `messageMediaPaidMedia` is a Telegram API question,
  not established here. The code path is real; deliverability to a bot chat is
  unverified.
* The thumbnail goes through `ImageReceiver`/`ImageLoader`; for ordinary WebP/JPEG
  thumbs that is the platform `BitmapFactory` path, not the Telegram native
  media parser. It is only relevant to a native RCE if the candidate decoder is
  the one used for those thumbnails (and if the bot can deliver the media type).

### 3.5 Home-screen Telegram widget / notifications

`ChatsWidgetProvider` uses `RemoteViews` and a `PendingIntent` template
(`ChatsWidgetProvider.smali:429-571`); it has no `twidget`/`wv`/`hl0` references
and cannot host a message-media decoder. Notification previews are discussed in
§5.

### 3.6 Custom emoji / TGS in the last-message text (the native auto-render exception)

This is separate from `TL_messageMedia`, but it is bot-delivered native media and
it is rendered by the chat list:

The message text (or a media caption; both become `MessageObject.v`) can carry
custom-emoji entities:

* Message text entities of type `TL_messageEntityCustomEmoji` are converted to
  `o5` replacement spans by the text builder:
  `vi.smali:3540` (method), `:3691`/`:3708` (`new-instance o5`), `:3726`
  (`setSpan`). `MessageObject.v` therefore contains `o5` spans for custom emoji
  when the message is parsed.
* `DialogCell` prepares the emoji state for its preview layouts with
  `o5.update(...)` (`v2.smali:25349`, `:25377`, `:25405`, `:25433`) and draws it
  from `onDraw` (`v2.smali:25740`) with `o5.drawAnimatedEmojis(...)` at six sites
  (`v2.smali:30712`, `:31744`, `:32284`, `:32536`, `:34128`, `:34283`). This is
  the chat list's own `onDraw`, not `ChatMessageCell`. The preview builder
  returns a `SpannableStringBuilder` (e.g. `v2.smali:10964`), so the `o5`
  `ReplacementSpan`s are not flattened to a plain `String`.
* `o5` holds `j5.f` (`f5`) for the emoji; `o5.smali:1131-1136` and
  `:1390-1461` use `f5`, its `ImageReceiver` (`f5.k`) and
  `f5.setColorFilter/p(...)`. `f5` is the animated-emoji drawable; it gets the
  native animation from `ImageReceiver.B()` -> `ci0`
  (`f5.smali:916`, `:4200-4224`).
* `ci0` is the RLottie drawable: it holds `RLottieNative`
  (`ci0.smali:55`, `:137`) and creates it at `ci0.smali:789`, `:1350`, `:1426`
  (`RLottieNative.b/a`). `RLottieNative` declares the JNI entry points
  `nCreate`, `nCreateWithJson`, `nDestroy`, `nGetFrame`
  (`RLottieNative.smali:511-520`).

**Consequence:** if the native RCE is in the TGS/RLottie parser, a message whose
last-message text contains a custom emoji can parse the TGS document while the
chat list is drawn, without opening the chat. The message and its
`messageEntityCustomEmoji` document reference are in `messages_v2` and survive
updates/force-stop; the TGS bytes are a cached file. The document file must be
available or downloadable for parsing; a missing/evicted file would show a
placeholder until `ImageReceiver` loads it.

Caveats (must be tested, not assumed):

* Bot API deliverability of arbitrary `messageEntityCustomEmoji` documents is
  not established. A user account or a channel can send custom emoji; a bot may
  be restricted to approved emoji.
* Telegram's server normally validates/re-encodes custom emoji documents; a
  crafted TGS may be rejected or normalized. The local file is still a TGS, but
  its bytes may not be the attacker's original.
* The chat list must actually draw the preview (visible row, screen on). That is
  the normal startup state, but the emoji render may be skipped by a reduced
  animation setting; verify with T12.
* This path reaches `RLottieNative` (TGS/Lottie), not the photo/document media
  parser. It does not help a candidate in the JPEG/WebP/video path.

---

## 4. Chat view: media/widget rendering happens here

### 4.1 Regular media

`ChatMessageCell` (`org/telegram/ui/Cells/q1`) binds media cells in its
`r3(MessageObject, ..., ...)` path (`q1.smali:182215`); callers are the chat
message list (`q1` itself and `ih0`, e.g. `ih0.smali:3933,4028`). The cell
creates/loads `ImageReceiver`s for photos/documents/stickers and starts
autoplay/preview work when the cell is bound/visible. This is the normal chat
render path and requires an open chat.

### 4.2 Widget media (fallback)

For a widget message `K5()` sets `D = 0x24` (above). `ChatMessageCell.r3` checks
`D == 0x24` at `q1.smali:205388` and creates the rich layout `wv` at
`q1.smali:205513-205517` (only if `w2` is null).

`wv`'s constructor (`wv.smali:294`) runs `J()` (`wv.smali:5612`), which iterates
the synthetic rich-message blocks and calls `j()` (`wv.smali:13526`). For a
`pageBlockEmbed` whose `url` passes `p.n(url)` (the `tg-widget:` test), `j()`
constructs `hl0` at `wv.smali:17791` and `:17962`.

`hl0`'s constructor obtains the widget profile via
`twidget/p.i(url)` (`hl0.smali:180`) and looks up the cached height via
`twidget/p.k(url, w, width)` (`hl0.smali:220`). If the height is not cached
(`"placeholder"`/`"cache of width"`), it posts a `pb` runnable
(`hl0.smali:289-298`). `pb` selects the profile and calls `p.o()`
(`pb.smali:172`), which is the measurement scheduler (`p.smali:3345`); `p.y()`
(`p.smali:4794`) constructs `k0` (`p.smali:4899`) and submits `k0.e()`
(`p.smali:5143`); `k0.e()` calls
`WidgetSandboxNative.create(...)` (`k0.smali:1263`) — the native sandbox.

The device log’s `widget height 0/<CHAT_ID>/<CHAT_ID>/-809168235: ... on screen ...
running ...` line comes from `hl0.n0` (`hl0.smali:4105`), and the suffix
`-809168235` is `Arrays.hashCode(payload)` (verified by
`lab/update_widget_cache/extract_widget.py`).

So the widget executes through exactly the same “chat view laid out” trigger as
ordinary media. It is not a chat-list/startup path.

### 4.3 Off-screen messages

When the chat is laid out, `wv`/`hl0` may be created for off-screen messages too
(the message window is measured). The log shows off-screen widgets with
`cached heights read ... not running, session 0, scripts held`
(`logcat_survB.txt:14858-14859`), and the on-screen message with `running 0 ms,
session 1` (`nb_v2_run1.log:17407`). For a native media payload, this means a
chat open can bind/decode media in the loaded window even if the bubble is not
currently visible; but it still starts from the chat view, not the chat list.

### 4.4 The `n0()` text-update caveat (widget only)

`MessageObject.I()` (`kj.smali:40657`) is the “message text changed” method; it
calls `n0(null)` at `kj.smali:41129`. `n0(User)` (`kj.smali:78127`) checks
`D == 0x24` and, if so, creates `wv` (`kj.smali:78196`) and calls `wv.L(E0(), ...)`.
That means a text/user update to an **already live** widget `MessageObject` can
build the rich layout and start the widget measurement/sandbox without the chat
cell being newly bound. It does not create a `MessageObject` from the DB and it
does not run on a cold chat list; the dialog list’s last-message object is not
passed through `I()`/`n0` by the update paths traced here. It is a potential
in-process trigger only, and it is widget-specific (ordinary native media has no
`E0()`/`wv` path). It is listed as an unverified remote-edit idea in §10 rather
than part of the update verdict.

---

## 5. Startup, update, notification and auto-download paths

### 5.1 Package update: task removed, no saved state

The 72799 campaign log shows the update path explicitly:

```
[15088] 11-01 19:05:04.042 ... I am_kill : [0,6157,org.telegram.messenger.beta,0,stop ... due to installPackageLI]
[15089] 11-01 19:05:04.043 ... I wm_finish_activity: [... DefaultIcon,proc died without state saved]
[15091] 11-01 19:05:04.057 ... I wm_task_removed: [160,removeChild:...]
```

This is not a force-stop: the reason is `installPackageLI`. Android removed the
activity task and did not save instance state. `LaunchActivity` can restore a
fragment only when it receives a `savedInstanceState` bundle; its restore code
reads `"fragment"`/`"args"` at `LaunchActivity.smali:51404-51445`. With the task
removed and state not saved, there is nothing to restore.

There is no “last chat” preference: searches for `last_chat`, `lastChat`,
`last_chat_id`, `lastChatId`, `last_dialog`, `lastDialog` across the 72799 smali
tree return 0 hits. `LaunchActivity.onCreate` adds the default chat-list fragment
`of0` (`LaunchActivity.smali:51404`) and does not open a chat from prefs.

### 5.2 Normal launch and post-update launch

After the update the app is restarted (installer/launcher) and loads folder 0:

```
[15766] 11-01 19:07:24.104 ... D tmessages: folderId = 0 load cacheOffset = 0 count = 100 cache = true
```

No widget/media render line follows at 19:07:24. The first widget line is at
19:07:33.750/34.274, **after** an input event at 19:07:33.634:

```
[17035] 11-01 19:07:33.634 ... I input_interaction: Interaction with: ... DefaultIcon ...
[17084] 11-01 19:07:33.750 ... D tmessages: widget height 0/<CHAT_ID>/<CHAT_ID>/... away: ... not running ...
[17407] 11-01 19:07:34.274 ... D tmessages: widget height 0/<CHAT_ID>/<CHAT_ID>/... on screen, ... running 0 ms, session 1
```

This is direct evidence that the post-update start was the chat list and the
widget ran only after the chat was opened. It also means the “OTA restart re-ran
the widget” statement in `notes/new_beta_72799_report.md` is overstated unless
the 19:05 proof file has an independent explanation; the available logcat has no
widget line between 19:05:04 (install kill) and 19:07:33.634 (input). Treat that
claim as **unverified**; the verified post-OTA widget run is 19:07:34, after chat
open.

### 5.3 Boot

`AppStartReceiver` (`smali/org/telegram/messenger/AppStartReceiver.smali:30-50`)
handles only `android.intent.action.BOOT_COMPLETED`; it posts `ag/f3(9)`
(`AppStartReceiver.smali:15-23`), whose case 9 calls `uz.t()` and `w0.x()`
(`ag/f3.smali:1339-1352`). `w0.x()` is the push-service startup
(`w0.smali:2046`), not a UI/chat open. The manifest registers
`AppStartReceiver` for `org.telegram.start` and `BOOT_COMPLETED` only
(`manifest_slices.txt`). A reboot starts the process/push service; it does not
render a chat.

### 5.4 Package replaced

The 72799 manifest has **no** `MY_PACKAGE_REPLACED` action/receiver
(`manifest_slices.txt`: count 0). Telegram is not started by a
package-replaced broadcast; the installer/launcher starts it at the chat list.

### 5.5 `OpenChatReceiver` (exported, explicit intent only)

The manifest declares `org.telegram.messenger.OpenChatReceiver` as an
`activity` with `exported=true` and no intent filter
(`manifest_slices.txt`, aapt2 lines 643-646). Its `onCreate` accepts
`action.startsWith("com.tmessages.openchat")`, reads `chatId`/`userId`/`encId`
(`OpenChatReceiver.smali:79-92`), and forwards the intent to
`LaunchActivity` (`OpenChatReceiver.smali:75-95`). `LaunchActivity` handles the
same action at `LaunchActivity.smali:32519` and opens the chat via
`vh/o8.R(...)` (`LaunchActivity.smali:15067`).

This is a real external trigger that survives Telegram updates: any app (or
`adb`) that can start an activity with
`-n org.telegram.messenger.beta/org.telegram.messenger.OpenChatReceiver -a com.tmessages.openchat --el chatId <id>`
will open the chat; the cached media (or widget) is then rendered. It is **not**
automatic: Android background-activity-launch rules apply, and a normal
package-update/boot flow does not send this intent. It is the only non-user
trigger surface found; see the design in §8.

### 5.6 Notifications and new-message media

Notifications are built by `NotificationsController` (`pt`) when messages arrive
(`pt.K` = `processNewMessages`, `pt.smali:10507`; called from the update path,
e.g. `wp.smali:43591`). The notification builder `pt.X` (`pt.smali:13058`) can
decode a notification image with `BitmapFactory.decodeFile`
(`pt.smali:14930`/`:17531`/`:23745`). This happens for a **new message** while
the app is running/started by push, even if the chat is closed. It is not
re-executed by an update: the in-memory notification lists (`pt.a`, `pt.D`) are
empty on a fresh process, and `pt.p()` clears notifications; no startup restore
of old notifications was found.

Important limitation: this generic notification-image path is used for the
notification large icon (sender avatar and/or an attached preview), and the code
shown uses the platform `BitmapFactory` (or `ImageLoader` for cached objects).
The code inspection did **not** establish that a photo/document message's full
native parser is reached here. Treat it as a **system-codec / thumbnail**
surface; only relevant if the native RCE candidate is the decoder used for that
image.

### 5.7 Auto-download

`DownloadController` (`b6`) exposes `canDownloadMedia` (`b6.d`,
`b6.smali:2865`) and `startDownload` (`b6.a`, `b6.smali:1776`). `b6.a` callers
are UI/media cells (e.g. `q1.smali:31990`, `w.smali:1359`,
`org/telegram/ui/v2.smali:1457`, `bh/e1`, `av`, `pu`, `dv`, `ku`, etc.), not
`w0`/`MessagesController` startup.
`b6.d` is used for checks in cells (`v2.smali:14780`, `q1` media paths). No
startup call that downloads/parses the last message media was found in
`w0`/`wp`. Auto-download may fetch a new message's file, but the full parser
still normally runs when the media is rendered (or when a thumbnail/metadata
helper is invoked); this is candidate-specific and not established as an
“after update” trigger.

### 5.8 Media viewer / user actions

Full-screen photo/video/audio viewing, “Play”, “Open”, etc. are user actions and
are out of scope for an automatic update trigger.

---

## 6. Device evidence: the update and the first render

`lab/update_widget_cache/log_slices.txt` contains the full slices. The key
sequence from `nb_v2_run1.log`:

| time | event |
|---|---|
| 19:05:00.682 | package installer `InstallStart` for the 72799 APK |
| 19:05:04.042 | `am_kill ... due to installPackageLI` |
| 19:05:04.043 | `wm_finish_activity ... proc died without state saved` |
| 19:05:04.057 | `wm_task_removed` |
| 19:07:23.6 | new app process `am_proc_start` |
| 19:07:24.104 | `folderId = 0 ...` (chat list) |
| 19:07:33.634 | input interaction |
| 19:07:33.750 / 34.274 | first widget lines (`79414 ... off screen`; `79415 ... on screen ... running`) |

The message 79415 payload is still in the post-update DB:
`v2.db` (md5 `4979ae5e610d291bc0fa97849a0182d7`) extracts to 4146 B zlib /
10540 B HTML, SHA1 `41380f9a...`. This proves **payload survival**, not automatic
execution.

A second, independent log (`persistence_bundle_device/logcat_probe.txt`) shows
`processLoadedMessages` for chat <CHAT_ID> at 01:18:36.848 and the first widget
line at 01:18:37.310 after the chat is on screen. Again: DB load ≠ render.

---

## 7. Trigger matrix

“Auto after update” means: with the app not running and the user doing nothing
after the update, does the media/widget execute?

| Path | What it does | Auto after update? | Evidence |
|---|---|---|---|
| `DialogCell` preview (regular media) | text + dialog avatar; no message-media decode | **No** | `v2.smali` has 0 `twidget`/`wv`/`hl0`; `v`/`c1()`; §3 |
| `DialogCell` paid-media thumbnails | loads up to 3 `ImageReceiver`s for `TL_messageMediaPaidMedia` | **Yes**, when the chat list is drawn (special media type; deliverability unverified) | `v2.j0` 23424, `g0` 14614, `r0` 15051; §3.4 |
| `DialogCell` custom emoji / TGS in preview text | draws `o5` spans; `f5`/`ci0` -> `RLottieNative` | **Yes, if the message is the last message and its emoji file is available** | `vi` 3691/3708, `v2.onDraw` 30712, `f5` 916/4200, `ci0` 789/1350, `RLottieNative` 511-520; §3.6 |
| Chat view (`ChatMessageCell`) | binds media / builds `wv`+`hl0` | **No** (requires opening the chat) | `q1.r3` 182215, 205388/205513; §4 |
| Last-chat restore | fragment restore from `savedInstanceState` | **No** (update removes task, no state) | `LaunchActivity` 51404-51445; log 15088-15092 |
| Boot receiver | starts push service | **No** | `AppStartReceiver` 30-50; `ag/f3` 1339 |
| `MY_PACKAGE_REPLACED` | none registered | **No** | manifest count 0 |
| `OpenChatReceiver` | explicitly opens a chat | **No**, but externally triggerable | manifest 643-646; `OpenChatReceiver` 79-95 |
| New-message notification | may decode a large icon (avatar/preview; message-media parser unverified) | **No**, but a new bot message can trigger while app runs | `pt.K` 10507, `pt.X` 13058, `BitmapFactory` 14930 |
| Auto-download | may fetch a new media file | **No** (UI-driven; candidate-specific) | `b6.a` 1776, `b6.d` 2865; §5.7 |
| Chat-list avatar | decodes dialog/profile photo | **No** message-media path; avatar only | `v2.Y1`, `c1()` 68279; §3.2 |
| Widget message | executes JS when chat view is built | **No**; payload survives | §4.2, §6 |

The only “automatic” things at startup are: the process starts, the chat list
loads, avatars (and paid-media thumbnails, if present) may be decoded, and
**custom emoji/TGS in the last-message preview text may be parsed by
`RLottieNative`** (§3.6). A regular `TL_messageMedia` message or widget message
is not touched.

---

## 8. Hybrid persistence design (native RCE; widget fallback)

Given the above, a DB-cached media message cannot be the sole update-surviving
trigger. Design it as a **durable payload** plus a separate **trigger bridge**.

### 8.1 Layers

1. **Durable payload (proven to survive):**
   * **TGS/RLottie candidate:** a bot/user text message whose **last message**
     contains a custom emoji entity (`TL_messageEntityCustomEmoji`). The message,
     its entity and the document reference are in `messages_v2`; the TGS bytes
     live in the document cache/file system (not inside the DB row). The chat
     list draws it and reaches `RLottieNative` at startup (§3.6), so this layer
     can also be the trigger for that decoder. Keep it as the last message so its
     preview is the visible row.
   * **Regular media candidate:** a bot-delivered photo/document/sticker message
     in a chat, stored in `messages_v2`. Keep it as the **last message** and,
     when the chat is opened, make sure the chat opens at the bottom so the
     bubble is in the visible/measured window. (For the widget, the same: keep it
     last or ensure the scroll position lands on it.)
   * The message also re-syncs from the server if the local DB is cleared; the
     server is the second copy.
   * For regular media, this layer is a seed, not a trigger.

2. **Trigger bridge (choose one):**
   * **TGS/RLottie payload:** no bridge is needed if §3.6 holds on the target
     build — the chat list draw is the trigger. Verify with T12; if the emoji is
     not drawn (animation setting, file missing), fall back to the bridges below.
   * **External explicit intent (strongest non-user path found for regular
     media):** `org.telegram.messenger.OpenChatReceiver` with
     `action=com.tmessages.openchat` and `chatId=<dialog>`. Any companion app or
     host automation that can start an activity can use it; Telegram updates do
     not remove the component. Android background-activity restrictions apply;
     a foreground companion or a user tap on its notification is the realistic
     delivery. This opens the chat and renders the cached media/widget.
   * **Notification tap (user-assisted, reliable):** after the update, send a new
     message to the payload chat from another account/bot; tap the notification.
     The chat opens and the media/widget runs. This is the simplest real-world
     re-infection after an update.
   * **New-message notification/auto-download (candidate-specific):** if the
     native parser is reachable from notification large-icon/thumbnail decoding
     or from an auto-download thumbnail, a new bot message can trigger it
     without opening the chat. Verify the decoder path first; do not assume it.
   * **Startup stage (autonomous, not yet working):** the forged ART app image
     (`cache/oat_primary/arm64/base.art`) runs at process start, including the
     `AppStartReceiver` boot start. It is the only self-contained “after update,
     no UI” mechanism in the project, but the 72799 device test currently
     crashes in `InitializeClass` and app updates may regenerate the image. See
     `notes/persistence_local_existing_rce.md` §7. Use it only once fixed and
     re-deploy it after each update.

3. **Native stage / re-arm:**
   * On successful media/widget execution, write the next-stage payload (for
     example a corrected `base.art`, a C2 configuration, or a detached process
     if the platform permits). Remember the earlier result: an app-UID detached
     watcher survives a crash but **not** `am force-stop`/UID cleanup; do not
     treat it as update persistence.
   * After an update that regenerates `base.art`, the widget/media seed plus a
     trigger bridge is the re-infection path; after the re-infection, re-deploy
     the startup stage.

### 8.2 What not to rely on

* Chat-list preview of a regular photo/document/sticker: it is text/avatar only.
* “Last chat” auto-restore: no such preference; update removes the task.
* Boot receiver: starts push, not a chat.
* `MY_PACKAGE_REPLACED`: not registered.
* Old notifications: the in-memory notification lists are empty on a fresh
  process; no startup restore was found.
* Auto-download alone: downloading a file is not parsing it; verify the parser.

### 8.3 Widget fallback

Keep the widget message as a secondary JS re-infection channel only:

* It survives updates in `cache4.db` and re-syncs from the server.
* It runs when the chat is rendered (same `ChatMessageCell` → `wv` → `hl0`
  path), not from the chat list or startup.
* Its only advantage over a native media seed is that the payload is a
  self-contained HTML/JS blob with no external file/parser dependency; its
  disadvantage is that the current 1865 bug is a JS engine issue and the task is
  to move away from it.

---

## 9. Device test plan (run on the Sony/Pixel; host-only here)

Preconditions: 72799 debug build (`widget height` logs available), the widget
chat <CHAT_ID> with messages 79411-79415, a bot chat for native-media tests, and
`adb`. Use `adb logcat -c` before each step and keep the full log. Do not clear
app data unless a step says so. For T3/T4 use an APK signed with the **same key**
as the installed build; a different key requires uninstall (data clear) and
defeats the test.

### T0 — Baseline DB/payload

```bash
cd telegramandroidwidget
python3 lab/update_widget_cache/extract_widget.py \
  evidence/evidence_20261101/new_beta_72799/v2.db 79415
```

Expect `payload_java_hash = -809168235`, `html_sha1 =
41380f9a33f87a8797aaae72537bfb374ad50dde`.

### T1 — Cold start on the chat list

```bash
adb shell am force-stop org.telegram.messenger.beta
adb logcat -c
adb shell am start -n org.telegram.messenger.beta/org.telegram.ui.LaunchActivity
sleep 20
adb logcat -d -v threadtime > /tmp/t1.log
grep -E "widget height|ImageLoader|BitmapFactory|native" /tmp/t1.log | head
adb exec-out screencap -p > /tmp/t1.png
```

Expected: `folderId = 0` / chat list; **no** `widget height ... 79415` and no
message-media decode line. If the widget line appears without opening the chat,
the finding is refuted; record the activity/fragment state.

### T2 — Open the widget chat

Tap the widget chat (or use T8’s intent), wait 2 s, grep again. Expected:
`widget height 0/<CHAT_ID>/<CHAT_ID>/... on screen ... running ...` and, if the
payload is the proof build, a fresh `cache/rce_proof`. This confirms the chat
view is the trigger.

### T3 — Update with the chat closed

* Force-stop; ensure the launcher shows the chat list.
* Install the next APK (`adb install -r <apk>` or the in-app updater); do not
  open a chat.
* `adb logcat -c`; start the app; wait 20 s; grep widget/media.

Expected: chat list (`folderId = 0`), no widget/media decode. Check the system
log for `am_kill ... installPackageLI`, `proc died without state saved`,
`wm_task_removed`.

### T4 — Update with the chat open

* Open the widget chat; leave it foreground.
* Install the update; after the process restarts, do **not** touch the screen.
* Screenshot + grep for `mResumedActivity`/`widget height`.

Expected: task removed with no saved state; app restarts at chat list; no widget.
If the chat reopens automatically, capture the `savedInstanceState`/task log; that
would be a real exception to the rule and must be verified with a force-stop
control.

### T5 — Process death without update (control)

* Open the chat; press Home; `adb shell am kill org.telegram.messenger.beta` (or
  use a low-memory kill); reopen from Recents.
* Observe whether ChatActivity is restored from `savedInstanceState`.

Expected: possible fragment restore on this path (Android may save state), unlike
the update path. Do not generalize this to updates.

### T6 — Notification path

* From another account, send a photo/sticker/document to the bot chat while the
  app is in the background (chat closed).
* Do not tap; grep for `NotificationsController processNewMessages`, notification
  build, `BitmapFactory`/`ImageLoader` decode.
* Then tap the notification and grep for chat/media render.

Expected: notification build may decode a thumbnail (system/ImageLoader) without
chat open; the full media parser runs only after the chat is opened. Record the
decoder tag.

### T7 — Auto-download

* Enable auto-download for photos/videos/documents in Data and Storage.
* Send a media message from the bot while the chat is closed.
* Grep for `DownloadController`, `FileLoader`, `MediaController`, decoder tags;
  check whether the file is saved and whether any parser runs before chat open.

Expected: download may start; full parser normally waits for render. If a parser
runs on download, that is a new non-chat path; verify with the candidate’s
marker.

### T8 — External `OpenChatReceiver` trigger

```bash
adb shell am start -n org.telegram.messenger.beta/org.telegram.messenger.OpenChatReceiver \
  -a com.tmessages.openchat --el chatId <CHAT_ID>
sleep 2
adb logcat -d -v threadtime | grep -E "widget height|ImageLoader|native" | tail
```

Expected: chat opens; widget/media renders. Repeat with the app force-stopped and
with `chatId` of the bot chat. Note the Android background-activity-launch
result; `adb` is exempt from the user-app restriction, so also test from a
foreground companion app if that is the delivery plan.

### T9 — Paid-media chat-list thumbnail (special case)

If a channel/bot can deliver `TL_messageMediaPaidMedia` (verify API
deliverability first), put it as the last message in a dialog, force-stop, cold
start, and grep for `ImageLoader`/`BitmapFactory` and `g0`-related load. Expected:
the chat list may load up to 3 thumbnails without opening the chat; confirm
whether the candidate decoder is the one used for those thumbnails.

### T10 — Boot

Reboot; wait for `BOOT_COMPLETED`; grep for `AppStartReceiver`, `am_proc_start`,
`loaded normal lib`, and any media/widget line. Expected: push service/process
start only; no chat render.

### T11 — Native-media payload in the chat list (regular `MessageMedia`)

Place a bot photo/document as the **last** message in a dialog; force-stop; cold
start; wait; grep for the candidate’s parser marker. Expected: no parser run; the
preview is text. Then open the chat and confirm the marker. This is the direct
test of the answer for regular media.

### T12 — Custom emoji / TGS in the last-message preview

* From a user account (or a bot, if its API allows custom emoji), send a message
  that ends with a custom emoji as the **last** message of a dialog. Make sure
  the emoji document has been downloaded once (open the chat once, let the emoji
  animate, then close).
* Force-stop; cold start to the chat list; wait 20 s.
* Grep for `RLottieNative`, `ci0`, `RLottie`, `tmessages` parser markers, and
  capture a screenshot. Expected if the candidate is in RLottie/TGS: the native
  parser runs from `DialogCell.onDraw` with no chat open. Then open the chat and
  compare.
* Repeat with animations disabled in Telegram settings to see whether the chat
  list still draws the emoji; if it does not, this path is settings-dependent.

This test distinguishes the regular-media answer (no auto) from the custom-emoji
exception (auto chat-list parse).

All tests are read-only except the APK update; no root and no data clear are
required.

---

## 10. Confidence and open items

**High confidence (code + device log):**

* `DialogCell` does not render regular message media; no `twidget`/`wv`/`hl0`
  references; preview is `MessageObject.v`; avatar is the dialog photo.
* `DialogCell.onDraw` *does* draw custom-emoji `o5` spans in the preview text;
  `o5` -> `f5` -> `ci0` -> `RLottieNative` is a complete code path to the native
  TGS parser, without opening the chat (§3.6).
* `ChatMessageCell.r3` is the media/widget render path; `D=0x24` → `wv` → `hl0`
  → native sandbox for widget.
* Update kills the process with `installPackageLI`, removes the task, and saves
  no state; normal start lands on `folderId = 0`; first widget line follows an
  input event.
* No `last_chat` preference; no `MY_PACKAGE_REPLACED`; boot starts push only.
* `OpenChatReceiver` is exported and forwards `com.tmessages.openchat` to
  `LaunchActivity`, which opens the chat.

**Medium / unverified:**

* Custom-emoji chat-list (TGS/RLottie) path: the Java/native code chain is
  complete and `RLottieNative` is a JNI entry point. Not yet proven on device:
  whether a bot can deliver an arbitrary custom-emoji document, whether the
  server re-encodes/validates it, whether the emoji file is cached at startup,
  and whether the animation is drawn with the user's animation settings.
* Paid-media chat-list thumbnails: the code path is real (`j0`/`g0`/
  `ImageReceiver.r0`), but bot deliverability and the exact decoder are not
  established.
* Remote edit/text update of an **already live** widget `MessageObject` can
  trigger `I()` -> `n0()` -> `wv` (§4.4). It was not observed on device and is
  not a cold-start/update path because the dialog list does not run that object
  through `I()`/`n0()`; keep it as an untested in-process idea.
* Notification/auto-download parser reachability: notification large icons use
  `BitmapFactory`/`ImageLoader`; whether the candidate native parser is invoked
  is decoder-specific and untested here.
* The `notes/new_beta_72799_report.md` “19:05 OTA restart re-ran the widget”
  claim: the available logcat’s first post-update widget line is 19:07:34 after
  an input; the 19:05 proof timestamp needs independent evidence. Do not use it
  as proof of an automatic update trigger.
* ART app image: accepted by the device but crashes in `InitializeClass`
  (`notes/persistence_local_existing_rce.md` §7.3); not a working trigger yet.

**What would refute the verdict:** a device run where, after `installPackageLI`
and a cold start with no input/tap, a **regular** `MessageMedia` parser runs or
the chat view opens (log `widget height ... on screen` or the candidate marker)
before any input event. T1/T3/T4/T11 are designed to catch exactly that.

For T12, the opposite is true: if the custom-emoji/TGS parser does **not** run
from the chat-list draw, that refutes the custom-emoji exception (not the
regular-media verdict); the reason would be deliverability/validation, animation
settings, or the file not being cached.
