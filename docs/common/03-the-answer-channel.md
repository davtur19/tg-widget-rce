# The answer channel

A widget can ask the bot a question and receive a text answer without leaving
the chat. The JavaScript API is (official):

```js
TelegramWidget.request("E0").then(function (answer) {
  // answer is { result: string | null }
});
```

Current status (official, 2026-11-09): widgets are in production but work only
in the private chat with the bot and are not yet forwardable; groups, inline
mode and forwards are test-server only.

The bot receives a `widget_query` update from an original message, or a
`shared_widget_query` update from a forward of a shared widget (official).
`widget_query` fields: `id`, `from`, `data`, `chat`/`message_id` (or
`inline_message_id`), `chat_instance`, `chat_type` (inline messages only),
`type`, `widget_id` (shared widgets only). `shared_widget_query` has only
`id`, `from`, `type`, `data`, `widget_id`. It answers with the Bot API method
[`answerWidgetQuery`](https://core.telegram.org/bots/api#answerwidgetquery):

```
POST https://api.telegram.org/bot<TOKEN>/answerWidgetQuery      (documented)
POST https://api.telegram.org/beta/bot<TOKEN>/answerWidgetQuery (lab-observed base)
Content-Type: application/json

{"widget_query_id": "<id>", "data": "<text>"}
```

Official: the query must be answered within 15 seconds, `data` is 0-1,024
bytes, and on success `True` is returned. The parameter that carries the text
is **`data`**, not `result`. `result` is ignored by the beta endpoint: the API
returns `ok=true` and the widget receives an empty answer. This was measured
on the Pixel route (`F0` failure) and fixed by switching to `data`.

## Limits (official, with lab measurements marked)

| Item | Official | Lab measurement (Telegram 13.x; marked lab) |
|---|---|---|
| Answer text (`data`) | **0-1,024 bytes** | 1,024 bytes accepted; NUL byte rejected (lab); beta error strings `WIDGET_RESULT_TOO_LARGE` / `INVALID_ANSWER` (lab) |
| Request `data` | 1-64 UTF-8 bytes | matches; `WIDGET_QUERY_DATA_INVALID` (lab) |
| Background pacing | one request when the widget appears, then at most one per 5 s while visible; original in the private chat with the bot only | one per 5,000 ms gate; `background_query` flag observed (lab, not an official parameter) |
| Requests per appearance | one immediate background request | Client gate (`show` resets the timer) |
| Server flood | 5 requests / 5 s per user and bot, background included | matches; `FLOOD_WAIT_<n>` (lab) |
| Answer window | 15 s (must answer within 15 s) | matches; `WIDGET_RESPONSE_TIMEOUT` (lab) |
| Query id lifetime | 15 s (unanswered queries reject with `TIMEOUT`) | matches; `QUERY_ID_INVALID` (lab) |
| Widget storage | 4,096 bytes per area (`local`, `session`) | matches; `QuotaExceededError` |

Official widget-visible request error codes: `NOT_ALLOWED`, `BUSY`,
`RATE_LIMITED`, `TIMEOUT`, `FAILED`, `INVALID_ANSWER`.

The answer is text, not binary. A NUL byte is rejected (lab measurement; the
official docs give only the 0-1,024-byte limit for answer `data`). Other
control bytes are valid UTF-8 and pass, but the transport re-encodes through
Java `String.getBytes(UTF_8)`, so keep the payload ASCII when possible.

The 1,024-byte cap is per answer (official). There is no total cap: a chain of
N answers moves N × 1,024 bytes. The 4 KiB storage cap is a different channel
and does not apply.

## What the channel is good for

The answer channel is not a way to bypass the 4 KiB widget HTML limit for a
single page. It is a way to:

- deliver an endgame that is too large for the page, after stage A has already
  forged the primitive;
- deliver several independent chunks with pacing;
- coordinate parallel widgets (the first one that forges asks for work; the
  others are told to stop).

Examples in this repository:

- **Pixel route 2 out-of-band endgame.** The page contains only stage A and a
  driver. The 7,469-byte endgame is split into 8 answers of 950 bytes plus 819
  bytes. The driver requests `E0`…`E7`, joins them, checks the length, and
  evaluates the result in the same runtime. At 5.2 s background pacing this is
  about 40 s; a burst schedule (five requests in the first 5 s window, one
  5.2 s wait, three more) is about 6 s.
- **Parallel fan-out.** Four widgets run in one chat open. Each runs stage A
  with two placement attempts. The first one to forge calls
  `TelegramWidget.request("E0")`. The server answers that widget with the
  endgame chunks and answers the others with `X` (stop). This turns “which
  heap layout will this device have?” into “which of four sandboxes wins?”.

## Exact server behavior

The server in `bot/answer_server.py`:

- long-polls `getUpdates` on the beta endpoint;
- accepts only updates from the configured user id;
- reads the `data` field of `widget_query` (the request key);
- answers with `answerWidgetQuery` and the `data` field;
- logs the API round-trip time and the answer length;
- has `--self-test`, `--simulate`, `--dry-run`, and `--probe` modes.

Only one process may consume `getUpdates` for a token. A second poller gets
`409 Conflict: terminated by other getUpdates request`.

## Timing

Official: background requests are allowed only for the original in the private
chat with the bot and only while visible — one request when the widget appears
on screen, then at most one every 5 seconds while it stays visible. Groups,
inline messages and forwards may ask on a tap only.

The client gate (lab):

- a background request is allowed when `now - last >= 5000 ms`;
- a tap or a foreground request is allowed immediately;
- re-showing the widget (`visible(false)` → `visible(true)`) clears the
  background timer and grants one immediate request;
- while the widget is hidden, requests are held, not refused.

The server flood limit (5 requests / 5 s per user and bot, background included
— official) is independent of the client gate. A burst of five is allowed; a
sixth within the same 5 s window gets a flood error.

## Storage is not the answer channel

`localStorage` and `sessionStorage` are per widget id and capped at 4,096
bytes per area. They are used on iOS to seed a stage B that must survive
between two renders of the same widget. The answer channel does not touch
storage, so it can move more than 4 KiB. But it requires a live bot and the
widget to stay visible.

## Failure tokens

The route payloads print short tokens so a device run is diagnosable:

| Token | Meaning |
|---|---|
| `NOAPI` | `TelegramWidget` or `request` is missing (channel not enabled) |
| `PROMISE` | `request()` did not return a promise |
| `F0` | the answer object had no text (`{result:null}` or empty) |
| `X3` | the promise rejected |
| `F2` | empty answer |
| `LEN <n>` | the joined chunks had the wrong length |
| `EV <error>` | the joined endgame threw |
| `HF HF OK` | the endgame ran to its final marker |

These tokens are literal strings in the payloads and in the evidence logs.
