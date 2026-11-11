# Plaintext text-only loaders, 4 KB (2026-11-05)

No keypad, no encryption, no canvas. The widget is a normal "Ok" text message;
the payload is evaluated synchronously at load and the widget is kept alive
with a small interval so the C2 shell can finish.

## Finalists

| loader | zlib-9 | paths | proof |
|---|---:|---|---|
| `poc/loader_v7_plain_text_4k.html` | **4,050** | arena + ctx fallback | **5463, 5464** |
| `poc/loader_v7_plain_text_ctxonly.html` | **3,594** | ctx only | **5465, 5466** |

Both are under the 4,096 B bot limit. The 4K loader has 46 B margin; the
ctx-only has 502 B.

## What the tests showed

- **Arena only**: marker `ENT`, stop. `rtArena` was 0; without the ctx path the
  payload cannot get `rt`.
- **Ctx only**: works, two consecutive C2 runs. On 72879 the prototype-chain
  context is the path that actually finds the runtime.
- **Arena + ctx**: works, two consecutive C2 runs. It prefers arena and falls
  back to ctx; it is the layout-independent/universal choice.

## Trade-off

- `loader_v7_plain_text_ctxonly.html` is the smallest and is reliable on this
  target, but it depends on the quickjs JSObject/shape offsets; it is less
  portable across future Telegram/quickjs layouts.
- `loader_v7_plain_text_4k.html` keeps the arena path for other layouts and
  still fits 4 KB; use it when "universal" matters more than the extra margin.

Payload artifacts:

- `lab/regexp1827_class64/device_payload_v7_4k.min.js`
- `lab/regexp1827_class64/device_payload_v7_ctxonly.min.js`

## Update 2026-11-05: ctx layout treated as fixed

The ctx offsets (`shape+48`, `proto+32`, `ctor+48`, `ctx+16`) are the same on
72799 and 72879. The app constants changed; the allocator/arena did not survive
on 72879. Decision: use the ctx chain as a fixed arm64 layout for the tested
Telegram versions; keep runtime-universal only the app PLT/GOT and the libc ELF
resolver. See `notes/quickjs_ctx_layout_stability.md`.

Minimal loader: `poc/loader_v7_plain_text_ctxonly.html`, 3,594 B zlib,
proofs 5465/5466. The 4,050 B arena+ctx loader remains as an optional fallback
for builds where the arena layout is known.
