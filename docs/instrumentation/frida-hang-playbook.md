# Frida hang / crash playbook: iOS 27 (17e) and 6s

## Device matrix

| device | jailbreak | Frida |
|---|---|---|
| iPhone 17e, iOS 27.0, UDID `<UDID>` | **no; stock** | only Frida's jailed LLDB injector, or manual LLDB |
| iPhone 6s (<LAN_IP>) | yes; Dopamine 15.6 | `frida-server` 17.18 on port 27042 |

The 6s is a **separate lab device, not a fix for the 17**. The 17 is stock:
there is no `frida-server`, no root, and no page-plan servicer outside
Frida's LLDB injector.

## Decision table

| symptom | most likely cause | first action |
|---|---|---|
| App dies at launch with `EXC_BREAKPOINT`/`brk #0x1337`, `FridaGadget.dylib 0x5f690` | iOS 26/27 page-plan has no servicer in a pre-injected gadget | **Do not reinstall the IPA.** Use Frida's jailed injector or manual LLDB **on the 17**: the 6s is a separate device |
| `frida -f ...` prints `Spawning ...` and hangs | USB link / debugproxy / app already running | USB recovery, kill app, DDI check, then manual LLDB pre-attach |
| `Failed to spawn: bad device` or `No devices found` | iOS 27 usbmuxd link bug (stale forward/idund) | USB recovery (below) |
| `Need Gadget to attach on jailed iOS` | `--aux gadget` path missing/wrong | use `--aux 'gadget=(string)/path/to/gadget.dylib'` |
| `Failed to spawn: incomplete pair record` | Frida Idun pair store stale | move `~/.config/idun` aside, use Frida 17.25.2 (pair migration) |
| `frida-ps -H 127.0.0.1:27042` → `connection closed` | gadget crashed/never listened, or stale port forward | check for `0x5f690` crash; kill stale `pymobiledevice3 usbmux forward` |
| 6s `frida-ps -H <LAN_IP>:27042` times out | frida-server not running / version mismatch | restart frida-server; match host/gadget versions |
| App crashes when opening a chat (no Frida) | stock Telegram widget payload in the chat (`js_free_rt`) | clean the chat/Postbox DB; not a Frida issue |

## 1. Pre-injected gadget on stock iOS 27: unfixable as-is

A gadget loaded by dyld has no LLDB session to service the page-plan
hypercall (`brk #0x1337`), so `gum_init` dies at `FridaGadget.dylib 0x5f690`.
No config, signing, or gadget version fixes this. The 19,985,696 B old gadget
is Frida 16.7.19 (pre-page-plan), which then dies with `CODESIGNING Invalid
Page`. 17.25.1 and 17.25.2 both contain `1a5698f`; their crash-site code is
byte-identical, so the raw 17.25.2 asset does not fix it.

On the 17 (stock, no JB) the only options are:

- **Frida jailed injector** (below); Frida owns the LLDB servicer.
- **LLDB/debugserver** on the 17 (the main session's `pre_attach_proxy.py`).

The jailbroken 6s is a separate device for analysis; it is **not** a fix for
the 17.

## 2. Frida jailed injector

Requirements:

- app signed with `get-task-allow` (free-provisioned sideload build);
- no pre-injected gadget in the IPA (use the no-gadget IPA);
- DDI mounted: `pymobiledevice3 mounter auto-mount --userspace`;
- Frida host 17.25.2.

```sh
cd <HOME>/ailocal/Telegram/ios_sideload
./sideload_tg.sh <no-gadget.ipa>
./venv/bin/frida -D <UDID> \
  -f com.user.tg72799.B472R2D493 \
  --aux 'gadget=(string)/tmp/opencode/frida_fix_history/gadget-17.25.2-arm64.dylib' \
  -l script.js
```

Rules:

- use `-f` (spawn). `-n`/`-p` does **not** create the page-plan servicer;
- `--stream` kills the app when the stream times out/detaches; use plain
  `dvt launch` or the CLI without `--stream` for normal use;
- if the CLI hangs at `Spawning ...`, the iOS 27 debugproxy needs the
  pre-attach `vAttach;<pid>`; use the manual LLDB proxy (section 3).

## 3. Manual LLDB fallback (when the Frida injector hangs)

```sh
cd <HOME>/ailocal/Telegram/ios_sideload
./venv/bin/pymobiledevice3 mounter auto-mount --userspace
./venv/bin/pymobiledevice3 developer debugserver start-server --userspace --local-port 23456
# launch the app suspended (DVT returns the PID)
./venv/bin/pymobiledevice3 developer dvt launch <bundle> --suspended
# pre-attach on the same debugproxy connection:
python <HOME>/ailocal/ios/research/09_pipeline/lab/pre_attach_proxy.py 23462 23456 <PID>
```

LLDB:

```
settings set target.memory-module-load-level minimal
settings set target.preload-symbols false
platform select remote-ios
target create <local-arm64-mach-o>
process connect connect://127.0.0.1:23462
```

The proxy sends `vAttach;<pid>` and rewrites `$k` to `$D` so quitting LLDB
does not kill Telegram. Expression JIT is broken on iOS 27; use register
writes / `thread return` and function calls by address (see
`ios/research/09_pipeline/lab/lldb_coregraphics.md`).

## 4. USB link recovery (iOS 27)

`lsusb` shows `05ac:12a8` but `pymobiledevice3 usbmux list` is empty;
isideload says `bad device` / `No devices found`.

Cause: a stale `pymobiledevice3 usbmux forward ... --daemonize` (observed PID
1550650) or Frida `idund`/`frida -f` left the Apple USB Multiplexor
configuration busy.

```sh
pkill -f 'pymobiledevice3 usbmux forward' || true
pkill -f '/idund' || true
sudo systemctl stop usbmuxd
# pyusb reset (venv has pyusb):
<HOME>/ailocal/Telegram/ios_sideload/venv/bin/python - <<'PY'
import usb.core
usb.core.find(idVendor=0x05ac, idProduct=0x12a8).reset()
PY
sudo systemctl start usbmuxd
pymobiledevice3 usbmux list   # UDID must appear before sideload_tg.sh
```

If `reset()` fails: `dev.set_configuration(3)` with retries, re-finding the
device each time; then start usbmuxd. Retry up to 3 times; keep the phone
unlocked and awake. Details: `notes/usb_link_bug_20261106.md`.

## 5. Separate lab device: jailbroken 6s (not the 17)

The 17 is stock; this path cannot be used on it. It is listed only as a
separate analysis device.

```sh
sshpass -p 'rosso19' ssh mobile@<LAN_IP>
echo rosso19 | sudo -S sh -c \
  'nohup /var/jb/usr/sbin/frida-server -l 0.0.0.0:27042 >/tmp/frida.log 2>&1 &'
```

From the host:

```sh
./venv/bin/frida-ps -H <LAN_IP>:27042
./venv/bin/frida -H <LAN_IP>:27042 -n Telegram --runtime=v8 -q -l script.js
```

Match the host client to the device server (17.18 on the 6s; the venv is
17.25.x and usually connects). The Python `create_script` in 17.25 does not
expose `ObjC`; use the CLI for ObjC hooks.

## 6. What not to do

- Do not reinstall or repack a pre-injected gadget hoping the `0x5f690`
  crash disappears.
- Do not suggest jailbreaking the 17: it is stock and has no JB. Use the
  jailed LLDB injector or manual LLDB on the 17.
- Do not run `frida -f` while another `frida`/`idund`/`pymobiledevice3`
  session holds the 17; it causes the USB bug.
- Do not leave `pymobiledevice3 usbmux forward ... --daemonize` running
  after a test.
- Do not use `dvt launch --stream` for a long-running app; the stream timeout
  kills it and looks like a crash.
