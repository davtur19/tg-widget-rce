# HANDOFF: desktop gate status (withdrawn 2026-11-08)

**Status: the desktop-gate claim is withdrawn.** The earlier handoff said
"every payload is a no-op on Telegram Desktop" and was marked merge-ready.
That is false for the real desktop client. The host matrix tested simulated
environments; the live client is not one of them.

## What was claimed

The old gate was:

```js
var GD=1;
if (U.length<40 && U.indexOf('TelegramWidget')>=0
    && typeof __twReceive=='undefined' && typeof __hostOps=='undefined'
    && typeof webkit=='undefined' && S<=800
    && ((C.bottom||0)+(C.cornerLeft||0)+(C.cornerRight||0)>0
        || (devicePixelRatio||1)>=2)) GD=0;
```

The claim was that a desktop client fails the UA/adapter/DPR test and stops
before stage A. The 12-case host matrix passed because all desktop cases had a
non-mobile UA, adapter globals, or DPR < 2.

## What was measured

A benign environment probe was opened in real Telegram Desktop (Windows) and
on the Sony XQ-BT52 widget sandbox. Both reported:

| Field | Telegram Desktop (Windows) | Sony widget sandbox |
|---|---|---|
| `navigator.maxTouchPoints` | `0` | `0` |
| pointer / `matchMedia('(pointer: coarse)')` | fine / no coarse pointer | fine / no coarse pointer |
| `navigator.userAgent` | the shared `TelegramWidget` UA | the same shared UA |
| `navigator.platform` | the same shared platform | the same shared platform |
| `devicePixelRatio` | `2.0` in the desktop test | `2.6` on the Sony |
| screen | `430x300` in the desktop report | `389x300` in the Sony report |
| safe-area insets | not the deciding term; the DPR term already passed | not the deciding term |

The desktop P3 report from the old-gated detector was:

```
REPORT platform=9 ... dpr=2.0 scr=430x300 ... -> skip
```

The detector reached the desktop branch because the old gate's `DPR >= 2`
term is true on that desktop. A final page with the same prefix would also
pass. The server correctly skipped the final, but that is a host policy, not a
payload guard. If the final is opened directly, the payload is not gated.

The alternative `maxTouchPoints > 0` gatefix was then measured:

| Environment | `maxTouchPoints` | `MT>0` gate |
|---|---:|---|
| Telegram Desktop (Windows) | 0 | blocks |
| Sony XQ-BT52 (the target) | 0 | **blocks the target too** |
| iPhone 6s / 17e | not the differentiator | not a discriminator |

Result: **the `MT>0` gatefix blocks both desktop and mobile.** There is no
JS-visible field in this set that separates the real desktop client from the
Sony sandbox. The two environments expose the same UA, platform, pointer and
`maxTouchPoints`; DPR and screen size overlap.

## Why a JS gate cannot be the fix

The widget runs the same `sandbox-bundle.js` on every platform. The bundle
installs a constant `navigator`/`screen` shim. The JS layer cannot see the OS,
the binary, the engine build, the process, or the account. A gate built from
the shimmed fields is a heuristic, not an isolation boundary. The only reliable
boundary is **account isolation**: send the payload only to the test account
and do not open that chat in Telegram Desktop.

## What remains valid

- The host gate matrix still tests the gate code's logic against simulated
  environments. It is a unit test, not a desktop proof.
- The `platforms.json` row 9 (`do_not_send_final`) is a useful operator guard:
  if a desktop report arrives, the server does not send a final. It does not
  stop a payload that is already in the chat.
- The gated Android and iOS files are host-only. Their page lengths differ
  from the device-proven pages. They need a device re-test after any gate
  change.
- The Android final is 4,068 zlib9 (28 B under the limit); the beta rebuild is
  4,071 (25 B under). Any edit near the gate must re-measure.

## Corrective action in this commit

- `docs/two_phase_universal_20261108.md` §15 is marked withdrawn.
- `README.md`, `docs/STATE_20261108.md`, and the two-phase docs no longer
  claim desktop safety.
- The payload bytes are unchanged. A device re-test is required before any
  gated page is called device-proven.
- If a desktop-safe path is required, use account isolation. Do not add
  another JS heuristic and call it a boundary.

See [`CRITIQUE_20261108.md`](CRITIQUE_20261108.md) P0-03 and
[`PAYLOAD_CHAIN.md`](PAYLOAD_CHAIN.md) §5.5.
