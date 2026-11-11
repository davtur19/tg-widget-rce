# Production widget forwarding/copying and inline — live results (2026-11-10)

Bot: `@<BOT_USERNAME>` id <BOT_ID> (token from `/tmp/opencode/tgbot/token.env`, not stored here).
Bases: standard `https://api.telegram.org/bot<TOKEN>/` and beta `/beta/bot<TOKEN>/`.
Target chat: **<CHAT_ID>** (`<TG_USERNAME>`). Second chat: **<CHAT_ID>** (`<TG_USERNAME>`).
Widget: one benign dummy page, 358 B raw / 250 B zlib-9, visible marker
`PROD FWD TEST`, no network calls, no exploit code.

## sendWidget (standard and beta)

| Base | message_id | http | has_protected_content | widget |
|---|---|---|---|---|
| standard | 17212 | 200 | **true** | `{html, width:360, height:180}` |
| standard `is_shared:true` | 17213 | 200 | **true** | `{html, width, height, id:6021440571560691941}` |
| beta | 17216 | 200 | **true** | `{html, width:360, height:180}` |
| beta `is_shared:true` | 17217 | 200 | **true** | `{html, width, height, id:6021787321450366529}` |

## Forward / copy — exact responses

All four methods were tried on the standard and the beta base, cross-chat
(A→B) and same-chat (A→A), for a default widget and for an `is_shared`
widget. Every attempt returned HTTP 400:

| Method | Exact `description` | std | beta |
|---|---|---|---|
| `forwardMessage` | `Bad Request: the message can't be forwarded` | 400 | 400 |
| `copyMessage` | `Bad Request: the message can't be copied` | 400 | 400 |
| `forwardMessages` | `Bad Request: messages can't be forwarded` | 400 | 400 |
| `copyMessages` | `Bad Request: messages can't be forwarded` | 400 | 400 |

Notes:
- `copyMessages` returns the **forward** wording ("can't be forwarded"), not
  "can't be copied". This is the measured server string.
- Same result for the `is_shared` widgets (17213, 17217) and for a message
  placed in chat B with `sendSharedWidget` (17215, HTTP 200,
  `has_protected_content: true`, same `widget.id`). Forwarding or copying that
  shared-sent message from B→A was also refused with the same two errors.
- `protect_content` was not re-probed this run; the previous matrix showed it
  is accepted and ignored. All widget messages here are protected anyway.

## sendSharedWidget (production, cross-chat)

`POST /sendSharedWidget {"chat_id":<CHAT_ID>,"widget_id":"6021440571560691941"}`
→ HTTP 200, message 17215, `has_protected_content: true`, `widget.id`
preserved. Deleted afterwards (delete ok, second delete "not found").
So cross-chat placement of a shared widget object still works in production;
forwarding/copying does not.

## Inline mode

Bot capability: `getMe` → `supports_inline_queries: true` on both bases.
The bot has answered real inline queries before (Nov 7 logs), so inline mode
is enabled for @<BOT_USERNAME>.

API surface (official Bot API, fetched 2026-11-10):
- Bot API **10.4, November 9, 2026** added `InputWidgetMessageContent` and
  `InputSharedWidgetMessageContent` — widget content for `inline_query`
  results — with the explicit note: *"Currently, widgets can't be sent in
  response to inline queries in the production environment."*
- There is **no** `InlineQueryResultWidget` type. Widget content travels as
  `input_message_content` inside a normal `InlineQueryResultArticle` (fields
  `html`/`width`/`height`/... or `widget_id`/`chat_data`).
- The same 10.4 changelog states: *"Widget messages can't be copied using the
  methods copyMessage and copyMessages."* and, on `sendWidget`/`sendSharedWidget`,
  *"sent widgets automatically have protected content and therefore can't be
  forwarded."*

Live measurements:
- `answerInlineQuery` with a deliberately invalid query id returns
  `Bad Request: query is too old and response timeout expired or query ID is
  invalid` for both a text article and a widget `input_message_content`; the
  query-id check runs before the input-content check, so this probe cannot
  distinguish the widget gate.
- An unknown result type gives
  `Bad Request: can't parse InlineQueryResult: type "zzz-not-a-type" is
  unsupported...`, i.e. result types are parsed before the query id.
- `savePreparedInlineMessage` (validates content, no live query needed; with
  `allow_user_chats: true`) on the **standard** base:
  - control text article → HTTP 200, prepared id `wlKL2466k6kS5hvV`
  - `{"html":...}` → **400 `Bad Request: INPUT_MEDIA_WIDGET_NOT_ALLOWED`**
  - `{"widget_id":"6021440571560691941"}` → **400 `INPUT_MEDIA_WIDGET_NOT_ALLOWED`**
  Same two refusals on the **beta** base.
- Bot beta log from 2026-11-07 with **real** inline query ids: 13 widget
  shapes (`html`, `+allow_queries`, `+is_shared`, `+width/height`,
  `+chat_data/public_data`, and `widget_id` references to a shared object that
  `sendWidget` had just created) all returned `400 INPUT_MEDIA_WIDGET_NOT_ALLOWED`;
  a text article was accepted.

Conclusion (production): inline widgets are blocked server-side with
`INPUT_MEDIA_WIDGET_NOT_ALLOWED`. The blocker is the production gate, not bot
configuration (`supports_inline_queries: true`) and not a missing API type
(the types exist since 10.4). The empty/default inline result list plus a text
fallback is the only thing a bot can return for a widget query in production.

A live end-to-end `inline_query` capture (real query id) requires the user to
type `@<BOT_USERNAME> <text>` in any chat on the account; the restarted bot logs the
query and answers each widget variant, then falls back to a text article.

## App 73029

- Installed app: `org.telegram.messenger.beta`, versionName 13.2.2,
  **versionCode 73029**, device XQ-BT52.
- Widget messages are rendered by the isolated `:widgets` process
  (`WidgetEngineService`); logcat shows `WidgetEngine: create ...` sessions.
- A direct screenshot of a widget chat is not obtainable: widget chats are
  FLAG_SECURE and `adb exec-out screencap -p` returns 0 bytes there (observed
  while the bot chat was open; the same command works on the profile screen).
- The dummy widget bubble was visible in the chat and the user removed it
  from the app. No inline widget can be rendered in production because no
  widget inline result can be produced.

## Cleanup (all verified with a second deleteMessage → "not found")

| chat | message_id | what |
|---|---|---|
| <CHAT_ID> | 17212 | standard dummy widget |
| <CHAT_ID> | 17213 | standard shared widget |
| <CHAT_ID> | 17216 | beta dummy widget |
| <CHAT_ID> | 17217 | beta shared widget |
| <CHAT_ID> | 17215 | sendSharedWidget placement |
| <CHAT_ID> | 17208 | send_widget.py dummy send (earlier in the run) |

Prepared inline messages: only the control text prepared message was created
(id `wlKL2466k6kS5hvV`, expiration 1794276914); the widget prepared messages
were refused and created nothing. No chat message, no exploit page, no DB
patch.

## Delta vs the 2026-11-08/09 findings

- **Forwarding/copying: unchanged.** All four Bot API methods still refuse
  every bot-created widget message, on standard and beta, including
  `is_shared` objects and a message placed by `sendSharedWidget`.
  `has_protected_content` remains `true`. New detail: `copyMessages` reports
  "messages can't be forwarded".
- **Inline: the API surface changed, the production gate did not.** Bot API
  10.4 now documents `InputWidgetMessageContent` /
  `InputSharedWidgetMessageContent` for inline results, so "inline is
  test-server only" is now too coarse: the *types* are public, but the
  production server still refuses them (`INPUT_MEDIA_WIDGET_NOT_ALLOWED`,
  measured on standard and beta). The official docs state the production
  restriction explicitly.
- **Sharing is still the only cross-chat path**: `sendSharedWidget` places the
  same widget object in another chat (200), but the delivered message is
  protected and cannot be forwarded or copied.

## Delivery implications

- Do not use forwarding/copying as a widget delivery primitive in production;
  the refusal is server-side and independent of flags.
- Inline mode is not a delivery primitive in production; no widget inline
  result can be answered. It remains a test-server feature.
- The working production paths remain: `sendWidget` in the private chat with
  the bot (protected, not forwardable), `sendSharedWidget` for a known shared
  object into a chat the bot can post to, and, for lab work, the local
  Postbox/`cache4.db`/Frida inserts.
- The answer channel (`answerWidgetQuery`) is unaffected; it still works only
  for the original private-chat widget.

## Bot restart

`/tmp/opencode/tgbot/bot.py` was restarted at 2026-11-10 02:17:46 (pid
3822646, beta base, polling from offset 78276482). It answers inline queries
with the widget variants, logs the refusal, and falls back to a text article;
`/send`, `/sendN`, `/sendto` still send `sendWidget` messages.
