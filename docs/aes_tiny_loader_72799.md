# AES tiny loader for the official widget bot — 7,682 B (2026-11-01)

Goal: get a PIN-gated AES loader under the widget-builder size limit
(`INPUT_MEDIA_WIDGET_TOO_LARGE`; the 13.2 KB and 9,970 B loaders were both
rejected). The new file is **7,682 B raw / 4,758 B gzip**.

## File

`lab/qjs_postsnapshot/loaders/widget_loader_aes_72799_pin19111998.html`

- md5 `addf3b472f46dced61a3ccd7f855236a`
- 7,682 B; gzip -9 4,758 B; payload JS 4,777 B -> raw deflate 1,968 B ->
  AES-128-CTR 1,972 B -> base64 2,632 B
- PIN `19111998` (filename only; the PIN is not in the HTML)
- AES-128-CTR (key = PIN UTF-8, padded/truncated to 16 B), raw deflate,
  `atob`, minimal canvas keypad (12 keys), indirect `(0,eval)`.
- Regenerate: `python3 tools/make_loader_aes.py <payload.js> --password '<PIN>'
  --template lab/qjs_postsnapshot/widget_loader_aes_tiny_min.html -o loader.html`

Templates: `lab/qjs_postsnapshot/widget_loader_aes_tiny.html` (readable) and
`_tiny_min.html` (terser output + shell). Generator: `tools/make_loader_aes.py`.

## Payload: compact 72799 chain (NOT the universal v2)

`v2_72799.js` (4,777 B) is derived from `widget_poc_1865_universal_v2.html`
with the universal libc resolver replaced by fixed device constants:

```
js_def_free  = 0x173e36c   (72799)
free@GOT     = 0x1964cc0   (72799; verified .rela.plt R_AARCH64_JUMP_SLOT "free")
system-free  = 0x26df0     (libc md5 44e776da3389c375113928c22b5b9399, Android 13)
fallback pair (72789): 0x1739aec / 0x1960430, same libc delta
```

The payload checks `rd32(base)==0x464c457f` after each pair; a wrong build
throws `build` instead of crashing. Dropped vs v2: `E_S2` frame-reuse wide
fallback, PLT/GOT disassembler, `findLibc`/`resolveSystem` (dynsym), multi-path
proof command. Command: `id>/data/user/0/org.telegram.messenger.beta/cache/rce_proof`.

Trade-off: this compact loader is tied to the 72799/72789 beta **and this
Android 13 libc** (`system-free 0x26df0`). It is not universal across Android
11..15; the universal v2 (9,478 B JS) does not fit under the builder limit.
New device/libc => recompute `system-free` from that device's libc and
regenerate.

## Device verification (<SERIAL>, 72799, Android 13)

Manual PIN entry via adb taps on the widget keypad (the exact uploaded file):

```
S0 | S1a V=0x76d7f52540 off=511880 | S2 pv=0xb4000076b4b63e78
F=0xb4000076b4a63ea8 off=1048528 hl=520 | S3 ctx=0xb4000078c98ef078
rt=0xb4000078d94ec9e0 jsf=0x7736e1536c | S3 free=0x7af2db7f70
sys=0x7af2dded60 | S4 writer ok | S5 rt16=0x7af2dded60 rt64=... | S6
```

- `jsf - 0x173e36c = 0x77356d7000` (page-aligned), so `base` passed the
  `0x464c457f` check; `free = *(base+0x1964cc0) = 0x7af2db7f70`,
  `sys = free + 0x26df0 = 0x7af2dded60` = `rt+0x10` readback.
- proof `/data/user/0/org.telegram.messenger.beta/cache/rce_proof`
  203 B, **22:34:53**, `uid=10357(u0_a357) ... context=u:r:untrusted_app:s0:c101,...`
- evidence: `evidence/evidence_20261101/aes_tiny_loader/` (proof, screenshot
  `markers_manual_pin_2235.png`, loader copy + md5)
- app healthy afterwards; message 79415 restored to `<div id="t">restored</div>`

## Re-entry crash (fixed)

The first 7,666 B build crashed the sandbox thread on the OK tap
(`tombstone_21`, 22:33:55, pc `0x1714b3c`, fault `0x890`, x2/`len=0xfffd`) when
the widget canvas received `pointerdown` + a **late** synthesized `mousedown`:
the OK handler ran the ~seconds-long exploit synchronously, so the mousedown
arrived after the 400 ms de-dup window and `u()` ran a second time with the
first run's pinned globals, corrupting the var_ref/frame state.

Fix in the final file: `Q` running flag (`if(Q)return;Q=1;` at the top of
`u()`), still also ignoring `mousedown` within 400 ms of `pointerdown`.
Verified: 8 digits -> 8 stars, OK -> single run, markers + proof, no crash.

---

## Update: 4 KiB-zlib loader (23:02, device-tested)

The bot's `INPUT_MEDIA_WIDGET_TOO_LARGE` is enforced on **`zlib.compress(html, 9)`**
(header `0x78da`), not raw and not gzip. Real-bot probes: zlib **4,088 accepted**,
zlib **4,188 rejected**; the limit is **4,096**.

New device-tested loader:

- `lab/qjs_postsnapshot/loaders/widget_loader_aes_72799_4096_pin19111998.html`
- 5,641 B raw, **zlib -9 = 3,735 B** (361 B margin), gzip 3,747, md5
  `b8c33f3eb1db99f97aef411282f41cbb`
- AES-128-CTR + LZSS (230 B decoder, `LZ` magic) + `atob` + canvas PIN 19111998
- payload: `size_variants/payloads/conservative_min.js` (3,632 B) = the proven
  `v2_72799` chain with **only** marker/logging deleted (26-line diff; every
  `dv.set*` incl. the 0x100-0x11F zero writes, rd/rdq/rd32, `globalThis` pins,
  constants and generator string untouched)
- device proof: PIN entered by hand on the widget keypad at **23:02:50**,
  `rce_proof` 203 B `uid=10357(u0_a357) … untrusted_app`, app alive
- also validated: `safe_inflate_proven.html` (zlib 4,042, proof 23:02:14)

Important: the earlier marker-free "p2/p5" payloads (byte-wise rb/rdq/rd32,
removed zero-writes) **crash** the sandbox (tombstone_22); the conservative
marker-only strip is the device-safe one.

Evidence: `evidence/evidence_20261101/bot_size_limit/` (`rce_proof_2302.txt`,
`device_safe_lzss_2302.png`, loader copy) and
`lab/qjs_postsnapshot/loaders/size_variants/` (variants, validation).
