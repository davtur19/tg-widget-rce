# Password-protected widget loader (2026-11-01)

Purpose: send the widget through the official/beta widget bot **without**
embedding the exploit plaintext. The bot sees only a small loader plus an
RC4/base64 ciphertext; the user enters the PIN on the phone and the loader
evals the decrypted JS.

## Files

| File | Role |
|---|---|
| `lab/qjs_postsnapshot/widget_loader_pin.html` | canvas keypad + RC4 + indirect eval template |
| `tools/make_loader.py` | encrypts the exploit JS and fills the template |
| `lab/qjs_postsnapshot/loaders/widget_loader_v2_pin123456.html` | official-style loader (no auto-run), PIN `123456` |
| `lab/qjs_postsnapshot/loaders/widget_loader_v2_testpin123456.html` | lab-only auto-run with the PIN embedded |
| `lab/qjs_postsnapshot/loaders/widget_loader_benign_testpin123456.html` | loader smoke test (`LOADED`) |

Build:

```bash
python3 tools/make_loader.py exploit.html --password '<PIN>' -o loader.html
# lab only: --test-pin '<PIN>' embeds the PIN and auto-runs
```

## Test result

The test-pin v2 loader (rc4 123456) was installed in message 79415 on the
arm64 72799 phone and ran end-to-end:

```
proof /data/user/0/org.telegram.messenger.beta/cache/rce_proof
203 B, 22:02, uid=10357(u0_a357), untrusted_app
```

The first attempt failed with `ERR Duplicate parameter name not allowed in this
context`: the loader used a direct `eval` inside `'use strict'`, so the
sloppy-mode 65,533-duplicate-parameter generator was rejected. Fixed by
removing `'use strict'` and using **indirect eval** `(0,eval)(src)`, which runs
the decrypted code in global sloppy mode. The loader now runs the full exploit.

## Why the canvas keypad

The widget DOM is litehtml + a canvas-ish sandbox: reference widgets use
`document.querySelector('canvas')`, `getContext('2d')` and
`pointerdown`/`mousedown`. There is **no reliable textarea/IME or clipboard
paste** in the sandbox (clipboard is write-only `copyText`), so the loader uses
a canvas numeric keypad. The PIN is never in the HTML; the ciphertext is.

## Delivery through the official widget bot

1. Choose a **strong PIN** (the test PIN `123456` is weak and RC4 is not
   authenticated). Rename the file so the PIN is not in the filename.
2. Upload the loader HTML to the official/beta widget bot; it sees only the
   loader + ciphertext.
3. Open the resulting widget on the phone; tap the PIN; press OK; the loader
   decrypts and evals the exploit.
4. If the bot/builder enforces a size limit, the ciphertext (~10.4 KB for v2)
   dominates; the loader is ~17 KB raw.

## Caveats

- RC4 is used for obfuscation, not strong confidentiality; a short PIN can be
  brute-forced by anyone who obtains the loader. Use a long PIN and treat the
  ciphertext as sensitive.
- The official bot may reject `eval`-heavy HTML or the size; the loader is
  otherwise benign and does not auto-run without the PIN.
- The loader evals the **script content** extracted from the exploit HTML; it
  needs a `#w` element for the exploit’s markers. The loader provides it.
- The test-pin variant is lab-only; do not deliver it.
