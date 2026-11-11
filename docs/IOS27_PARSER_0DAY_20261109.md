# iOS 27 17e — deterministic parser 0day: `await using` in a class static block (2026-11-09)

Status: **new deterministic 0day, host-proven 10/10 and device-proven
(2026-11-09 19:13, msg 5979): `RESULT HIT N=16 slot=9 before=1009
after=PWN9`; controls `SAFE diag=num:24301`; app alive.** Calibration:
**CAL2, CALA1, CALA2B and CALA3 PASS on device**; CALA4 died at `f()` with
no marker (the `A->pvalue` deref-write geometry) and is being recalibrated.
No session/RCE claim yet.

## Bug

`for (await using x of …)` is accepted inside a **class static block** — a
normal, non-async `JS_FUNC_NORMAL` frame.

- `js_parse_for_in_of()`'s `TOK_AWAIT` branch has no async check
  (`quickjs.c:29328`).
- `update_token_ident()` makes `await` a keyword inside `CLASS_STATIC_INIT`
  (`quickjs.c:23231`).
- At runtime `OP_dispose_scope` emits `OP_using_dispose_async` + `OP_await`
  (`quickjs.c:35629–35632`); `OP_await` is an unconditional
  `goto done_generator` (`quickjs.c:21072`), skipping `close_var_refs()` and
  the local free even for a plain frame (`quickjs.c:21175–21189`).

Any closure escaping the block keeps an open `JSVarRef` whose `pvalue` points
into the dead `JS_CallInternal` `alloca` frame. A second static block, called
from the same class-fields-init site, deterministically overlaps that address
(parser-derived alloca geometry; **no heap, no ASLR, no race**).

## Primitive

- **Read** a live interpreter frame slot:
  `RESULT HIT N=16 slot=9 before=1009`.
- **Write** a chosen JSValue into it: `after=PWN9`.
- Return invalid-tag JSValues from raw stack words (`typeof` = `"unknown"`,
  `String` = `"[unsupported type]"`).
- OOB `NULL` write at `dead_sf->var_refs[var_ref_idx]` on var_ref free
  (`quickjs.c:18051`).

## Evidence (host/static)

- **10/10 deterministic** on the device-shaped `clang -O2 -DNDEBUG` build
  (8 MiB heap, 500 ms, strict-mode script); 10/10 `-O1`; gcc `-O2` also hits.
- ASan: `dynamic-stack-buffer-overflow READ of size 8, JS_CallInternal
  quickjs.c:19229` (`val = *var_refs[idx]->pvalue`).
- Controls (`for (using …)`, legal `async function`) → `SAFE diag=num:24301`
  (`0x5EED`), isolating the bug to the non-async static-block frame.
- Present unchanged in upstream v0.18.0 and master `147d01c`; shipped
  13.2/36535 predates any fix. A public upstream code-reading audit
  (issue #1902, finding 3, posted 2026-11-09 13:11 UTC) describes the missing
  check but has **no PoC or primitive**; this is the first working trigger and
  primitive.

## Live result (17e, 2026-11-09 19:13, msg 5979)

- `awu_probe.html` (7,654 B, sha256 `7e7e22fe…`, manifest match) sent into a
  clean app (fresh PID 1079, no holders, no other widget).
- Marker in all eight burst screenshots: **`RESULT HIT N=16 slot=9
  before=1009 after=PWN9`**; app alive at 19:13:48 and 19:15:12; chat clean.
- Controls in the same session: `awu_ctrl_async.html` (5980) and
  `awu_ctrl_using.html` (5981) → **`RESULT SAFE diag=num:24301`** (0x5EED),
  app alive.
- Console delta 0 (widget `console.log` is not forwarded to app stdout on
  this build); the DOM/screenshot is the channel.
- R3 tier_a (ImageIO corpus) ran in the same clean session: **23/23 pages
  alive, 0 crashes**; `P05`/`J07` did not reproduce the pixel-cap bypass
  (`ERR`), so the decoder path is weak.

## Live request (repro)

- Send `lab/ios17e/reliability_20261109/parser_hunt/out/awu_probe.html` as the
  last message, open the bubble.
- Expected: `RESULT HIT N=16 slot=9 before=1009 after=PWN9` (slot 10 equally
  valid); controls `SAFE diag=num:24301`.
- Independent of the holder warm-up; a clean app is fine.

## Calibration chain (device, 17e)

| stage | result |
|---|---|
| CAL2 | PASS `RESULT CAL2 OK 0x1122334455667788` — M=22 slot + 64-bit BigInt payload round-trip |
| CALA1 | PASS `LEAK … amod 8 pmod 0 v2 1 s0 1 sp 1`; the `sub sp,#0x10` call-site fix: `callee.x19 = caller.local_buf − 0x3C0` (the old −0x3B0 was 0x10 off; it cancels in the phase-1 leak) |
| CALA2 | `q0 0`: the refcount is at **A−4** (allocator header offset 4), not A−8; the fake A was accepted and the app survived |
| CALA2B | PASS `vf 1 q0 1` — fake A placement + A−4 increment device-proven |
| CALA3 | PASS `s0 1 q2 1` — writer slots + `A->pvalue = P` |
| CALA4 | **death at `f()`**, no marker; the self-gate passed, so the failure is the `A->pvalue` deref-write geometry; app PID 1176; recalibrating |

After CALA4 OK the saved-return/ROP page needs its own calibration: the old
`B+0x3A0` used the uncorrected 0x3B0 JS→JS constant; with `sub sp,#0x10` the
class-block anchor is `S = B − 0x3F0`, and the saved `x29/x30` slot must be
recomputed per frame before any write.

## Wall / next

The cross-frame write is a **JSValue** write, type-safe at the JS level. The
natural fake-`JSVarRef*`/tag-zeroing upgrade needs two targets 8 bytes apart;
the measured two-static-block targets are 16 bytes apart, so the tag word
lands on the next `var_refs` slot and `close_var_refs()` would deref
`0xFFFF…`. The most promising next surface is a probe whose `alloca` is tuned
onto the live `JSStackFrame` (`var_ref_count`/`cur_pc`) with a BigInt payload
for a raw 64-bit write, then the existing stage-B/ROP/session payload.

Artifacts: `parser_hunt/REPORT.md`, `LIVE_REQUEST.md`, `out/`,
`src/poc_deliver.js`, harness/ASan logs. Host-proven only; live device proof
and the raw-write upgrade are the next gates.
