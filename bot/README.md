# Bot tools and runbook

Code for the Bot API methods used by the widgets: `sendWidget`,
`sendSharedWidget` and `answerWidgetQuery`. Standard library only. The token
comes from the environment. No token is stored in the repository.

Official references (fetched 2026-11-09):
[`sendWidget`](https://core.telegram.org/bots/api#sendwidget),
[`sendSharedWidget`](https://core.telegram.org/bots/api#sendsharedwidget),
[`answerWidgetQuery`](https://core.telegram.org/bots/api#answerwidgetquery),
[Telegram Widgets guide](https://core.telegram.org/bots/widgets).

## Files

| File | Use |
|---|---|
| `send_widget.py` | Bot API `sendWidget` / `sendSharedWidget` sender (beta or standard base). |
| `send_widget_mtproto.py` | MTProto `inputMediaWidget` sender. Needs `telethon`. |
| `bot_server.py` | Route-2 out-of-band answer server. Original name. |
| `answer_server.py` | Same server, descriptive name. |
| `bot_first_only.py` | First-wins answer server. Original name. |
| `answer_server_first_wins.py` | Same server, descriptive name. |
| `probe_answers.py` | Answer-limit probe server (P0..P8). |
| `bot_two_phase.py` | P2 report parser and sender for the ungated `bot/` pages. |
| `platforms.json` | P2 platform table for the `bot/` pages. |
| `chunks/` | P2 chunks at the root; `route2/` and `parallel/` subdirs. |
| `config.example.json` | Config shape. All values are placeholders. |

The P3/gated pair lives in `payloads/two_phase/` and is driven by
`scripts/two_phase/bot_two_phase.py`. The two packages are deliberately
separate: `bot/bot_two_phase.py` parses the older 23-byte P2 report and points
at the ungated pages in `bot/`; the P3 server parses 31-byte P3 and points at
the gated pages in `payloads/two_phase/`. Do not mix a P2 server with a P3
detector.

## Limits

Official values with lab measurements marked (Bot API reference and Telegram
Widgets guide, fetched 2026-11-09):

| Item | Official | Lab measurement |
|---|---|---|
| Widget HTML | 1..32,768 bytes; ≤ 4,096 bytes after zlib at the maximum compression level (server compresses). NUL byte → `INPUT_MEDIA_WIDGET_HTML_INVALID`; over the limits → `INPUT_MEDIA_WIDGET_TOO_LARGE` | 32,768 accepted / 32,769 rejected; zlib-9 4,096 accepted / 4,097 rejected |
| `public_data`, `chat_data` | 0..1,024 bytes each | not probed |
| Caption | 0..1,024 characters | not probed |
| Request `data` | 1..64 UTF-8 bytes | matches |
| Answer `data` | 0..1,024 bytes | 1,024 bytes accepted; NUL byte rejected (lab) |
| Background pacing | one request when the widget appears, then at most one per 5 s while visible; original in the private chat with the bot only (server-decided; no `background_query` parameter officially) | `background_query` flag observed on beta (lab) |
| Server flood | 5 requests per 5 s per user and bot, background included | matches |
| Answer window | 15 s | matches |
| Query id lifetime | 15 s | matches |

The answer field is **`data`**, not `result`. `result` is ignored by the beta
endpoint.

## 1. Send a widget

```sh
export BOT_TOKEN='...'
python3 bot/send_widget.py \
  --html vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/route2/out-of-band-72801.html \
  --chat-id <CHAT_ID> \
  --allow-queries --background-query
```

`--dry-run` prints the sizes and the call. It does not connect. The default
base is `beta`; `--api standard` uses the standard base. `--background-query`
sends the lab-observed `background_query` flag (not an official parameter).

Both bases serve `sendWidget` natively as of 2026-11-08 (lab observation; the
official docs document only the standard base). The standard base is no longer
a 404. A whitelisted bot is still required (lab observation; the official docs
do not mention a whitelist).

### 1.0 Official request and response shape

`sendWidget` (only `chat_id` and `html` are required): `chat_id`,
`message_thread_id`, `html` (1-32,768 bytes, ≤ 4,096 bytes zlib-9),
`width` (clamped 200...bubble max), `height` (clamped 50-600), `public_data`
(0-1,024 bytes), `chat_data` (0-1,024 bytes), `caption` (0-1,024 characters),
`parse_mode`, `caption_entities`, `show_caption_above_media`, `allow_queries`,
`is_shared`, `disable_notification`, `protect_content`,
`allow_paid_broadcast`, `message_effect_id`, `reply_parameters`,
`reply_markup`.

`sendSharedWidget` (only `chat_id` and `widget_id` are required):
`message_thread_id`, `chat_data`, the caption fields, `disable_notification`,
`protect_content`, `allow_paid_broadcast`, `message_effect_id`,
`reply_parameters`, `reply_markup`. `allow_queries`/`is_shared` are fixed on
the shared widget.

Response: the sent `Message`, whose `widget` object has `id` (shared widgets
only), `width`, `height`, `html`, `public_data`, `chat_data`.

`background_query` and `fwd_allow_queries` are **not** official parameters;
they are lab-observed on the beta endpoint.

### 1.1 Shared widgets and forwarding

```sh
# send a shared object and print widget.id
python3 bot/send_widget.py --api standard --is-shared \
  --html <widget.html> --chat-id <CHAT_ID>

# place the same widget in another chat
python3 bot/send_widget.py --api standard \
  --share-chat-id <OTHER_CHAT_ID> --share-widget-id <WIDGET_ID>
```

**Current status (official, fetched 2026-11-09): widgets are in production but
not yet forwardable.** The official docs state:

- *"Currently, in the production environment, widgets can be sent only to
  private chats, and sent widgets automatically have protected content and
  therefore can't be forwarded."* (`sendWidget`, `sendSharedWidget`)
- *"In the production environment, a bot sends widgets only to private chats
  with users, and users cannot forward its widget messages."*
- *"Widgets cannot be copied: `copyMessage` and `copyMessages` refuse them.
  A widget sent with `protect_content` cannot be forwarded."*
- Availability: widgets in the private chat with the bot — production Yes;
  forwarding widget messages — production No (test server Yes); groups and
  inline mode — production No (test server Yes).

Lab measurements (2026-11-08, `forward_test/` matrix plus one live update;
marked lab, not official):

- `is_shared: true` returns `widget.id`; `sendSharedWidget` placed the widget
  in another chat (A to B).
- Bot-created widget messages stay `has_protected_content: true`.
  `forwardMessage` and `copyMessage` are refused, including `is_shared`,
  same-chat, and `fwd_allow_queries:true` variants (`fwd_allow_queries` is a
  lab-observed flag).
- A user/third-party widget copy is different (lab, observed once outside the
  `forward_test/` matrix): the update has
  `forward_origin: {type: "hidden_user"}` and `widget: {html, is_copy: true}`,
  with no protected-content flag. `forwardMessage` of that copy works;
  `copyMessage` still fails. The forwarded copy is static HTML, with no
  `widget.id` or live query handle. This was observed once; the official docs
  say production widget messages are always protected and user forwarding is
  test-server only, so re-test before relying on it.
- Forwardability is a property of the source copy, not of the method alone.

Each `sendWidget` creates a new message id. A storage seed and its exploit that
must share a widget id still use the Postbox `t7` rewrite. Cross-chat sharing
preserves the widget object id; a same-chat seed/exploit swap has not been
tested.

### 1.2 P2 vs P3 packages

- `bot/detector.html`, `bot/final_inline.html`, `bot/final_fallback.html` and
  `bot/bot_two_phase.py` are the P2/ungated reference package. The detector
  and final are 9,176 B; the report is 48 chars.
- `payloads/two_phase/` and `scripts/two_phase/bot_two_phase.py` are the
  P3/gated package. The detector and final are 9,185 B; the report is 64
  chars. The server self-test now runs from the repo (`SELF-TEST PASS`).

## 2. Start the answer server

Route 2 out-of-band chunks:

```sh
export BOT_TOKEN='...'
python3 bot/bot_server.py \
  --uid <your user id> \
  --chunks vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/route2/chunks \
  --state-dir /tmp/opencode/oob-state \
  --method answerWidgetQuery
```

First-wins parallel server:

```sh
python3 bot/bot_first_only.py --parallel-self-test \
  --chunks vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/universal/parallel/chunks
python3 bot/bot_first_only.py \
  --uid <your user id> \
  --chunks vulns/0day-2-RCE-PARSER-SCOPE/STAG/payloads/universal/parallel/chunks
```

Answer-limit probe:

```sh
python3 bot/probe_answers.py --self-test
```

## 3. Two-phase flow

```sh
export BOT_TOKEN='...'
python3 bot/bot_two_phase.py --self-test
python3 bot/bot_two_phase.py --simulate
python3 bot/bot_two_phase.py --uid <your user id> --chunks bot/chunks
```

Flow:

1. Send `bot/detector.html` with `sendWidget`.
2. The detector sends a `P2` + 46-hex report (48 chars) through the answer
   channel.
3. `bot_two_phase.py` parses the report and answers `K`.
4. On a hit it sends `bot/final_inline.html`.
5. On a miss it sends `bot/final_fallback.html` and serves `E0`..`E7`.

The P3 package uses `scripts/two_phase/bot_two_phase.py`, a 64-character
`P3` report, and the pages in `payloads/two_phase/`. Self-test both servers
after any edit:

```sh
python3 bot/bot_two_phase.py --self-test
python3 scripts/two_phase/bot_two_phase.py --self-test
```

## 4. One poller per token

Only one process may call `getUpdates` for a token. A second process gets
`409 Conflict: terminated by other getUpdates request`. Stop other pollers
before starting a server.

## 5. Config

Copy `config.example.json` and set the chat id and uid. Keep the token in
`BOT_TOKEN`. Do not write it to a file.

## 6. Safety

- Use only on devices and accounts you own.
- Bind the C2 to loopback or a private LAN.
- Do not expose a loader port to the internet.
- Do not commit a token or a session file.
