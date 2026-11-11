# v7 plaintext loader, no keypad (2026-11-05)

Encryption and the PIN keypad are removed: the loader is a plaintext payload
plus a synchronous eval. The keypad had no security value with autoplay and a
hardcoded password.

## Current loader

`poc/loader_v7_plain_nokeypad.html`:

```html
<canvas id=c ...></canvas>
<script type="text/plain" id=p>PAYLOAD</script>
<script>
var c=...,g=...; g.fillRect(...);
var s=document.getElementById('p').textContent;
(0,eval)(s);
setInterval(function(){},1000);
</script>
```

No ciphertext, no ChaCha/LZSS, no password, no PIN.

## Verification

- C2 session `tg-10357-XQ-BT52`, uid 10357,
  `exec rc=0 4.81s`, bot proof **5460**, app alive.
- The plaintext unminified payload reaches the `TRIG` marker; the minified
  payload fails at `NO_V` (victim scan), so the unminified structure/bytecode
  is currently required.

## Size

- 20,654 B raw / **6,980 B zlib-9** (over the 4,096 B bot limit; DB-only).
- The minified release payload is ~3.2-3.5 KB zlib but fails the victim scan;
  the 4 KB target still needs the heap/bytecode issue solved.
