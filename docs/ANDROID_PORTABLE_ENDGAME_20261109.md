# Android portable endgame — verdict and invoker gadget (2026-11-09)

Status: **host-verified; no deterministic stock chain**. T1/T2/T3 device tests
queued. No stock marker, no reliability claim.

## Verdict

No deterministic stock chain closes on 72989. The wall is three layers:

1. **The cubic write is a 24-byte, one-object write.** It always lands on the
   neighbour's packed Scudo header + padding + `user[0]`. The header
   corruption means the neighbour cannot be freed/reclaimed afterwards
   (CRC-keyed header, abort on later Scudo use). The only possible endgame is a
   **direct virtual dispatch on the live neighbour**, with only its first 8
   bytes controlled. Multi-verb fills are dead: every append is a Java
   `Path.lineTo/cubicTo/quadTo` JNI call, and the stale fast-path window is one
   `growForVerb` call — only that verb's 24 bytes are deterministic.
2. **The only attacker pointer reachable through that dispatch is
   `SkDashImpl::fIntervals`**, confined to non-negative finite floats by the
   widget's `Math.max(0.0f, x)` clamp and Skia's `SkDashPath::ValidDashPath`.
   libc/libart addresses are representable; every libhwui address is not
   (low32 `0xda…`/`0xdc…` → negative float32 → clamped to `+0.0`).
3. **The gadget space is empty for the needed shape.** 10,201 text-pointing
   RELR slots / 5,511 targets / 14,486 functions were scanned; no function at
   any vtable/data slot does `P=[x0+0x10]; T=[P+k]; x0=P+c; blr T`. The
   depth-3 “virtual call on fIntervals” gadgets need `[fIntervals]` to be a
   code-pointer table pointer (libc/libart); libhwui is unrepresentable.
   libart (`base 0x7b11600000`, low32 encodable) is the remaining lead.

RT `~List`: both calls take `x0 = listener`, a qword read from known memory;
no known-address qword yields attacker bytes without a heap address. The
`ldadd -1` at `[listener+8]` is a 4-byte decrement at a known address, not a
redirect.

## New invoker gadget (host-verified)

- Gadget `libhwui + 0x714928` at data slot `B+0x81c050`:
  `add x8,x0,#0x10; ldr s0,[x1]; ldr x16,[x0,#8]; mov x0,x8; br x16`.
- With `V=B+0x81c000` (shader `+0x50`) or `V=B+0x81c018` (filterPath
  `+0x38`), a **24-byte** fake object gives:
  `[+8] = &system`, command at `+0x10` → `system(fake+0x10)`.
- No heap address; shared libhwui/libc bases are known.
- **Byproduct:** a smaller W2-dash variant (48-byte `defineImage` ALPHA_8
  16×3 spray, byte-exact, `vptr=B+0x81c018`) — still preemption-bound, but
  removes the 248-byte premultiplied-bitmap problem.

This is an endgame/invoker improvement, not a deterministic trigger.

## Portability

The bug/trigger is Telegram widget-engine code; the clamp, `ValidDashPath`,
reserve heuristic and Scudo classes are source-stable. Per-build re-derivation:
libhwui base + gadget table slot/offsets, `SkDashImpl` vtable/slots,
`filterPath`/unref sites, Scudo class table/TSD, reserve boundary table,
`growForVerb` offsets, `SkPaint` `fPathEffect`. The isolated process can
self-derive libhwui/libc bases and `&system`; a future build with a depth-2
gadget or a libart dispatcher completes the chain.

## Live tests (queued)

- **T1** deterministic cubic neighbour-vptr marker (corrected reserve
  geometry; old payloads were invalid), 10 min.
- **T2** invoker-gadget validation on the M3 harness (debug-only);
  `system(fake+0x10)`.
- **T3** RT marker with a known-address listener (diagnostic).

## Claim boundary

No deterministic stock chain, no stock marker, no session read. The Binder
nice-force path and the W2 undercount remain the live route; the invoker is a
fallback endgame and a smaller spray variant.
