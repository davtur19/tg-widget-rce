# Instrumentation

Two devices need host instrumentation:

- `ios17e/`; iPhone 17e, iOS 27.0, stock app. USB recovery, DDI, CoreDevice
  screenshots, OCR, HID chat navigation, bot delivery. The full procedure is
  `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/README.md`.
- `ios6s/`; iPhone 6s, iOS 15.8.8, jailbroken. Frida delivery, printf hook,
  screenshots, Postbox listing. The payloads are in
  `vulns/0day-2-RCE-PARSER-SCOPE/TINY/payloads/`.

Nothing here installs, launches, or pulls by itself unless you run it. The
scripts are host-side tools with explicit arguments.

## iPhone 17e

| Tool | What |
|---|---|
| `usb_recover.py` | Stops usbmuxd, resets the USB device, restarts usbmuxd, checks the UDID. |
| `navigate_chat.py` | CoreDevice HID + OCR navigation to a bot chat. |
| `ocr_screenshot.py` | OCR a CoreDevice screenshot and print the `#v` marker. |
| `run_sweep.py` | Runs a list of payloads, reads the marker, records the result. |

Common commands:

```sh
VENV=<HOME>/ailocal/Telegram/ios_sideload/venv/bin
$VENV/pymobiledevice3 usbmux list
$VENV/pymobiledevice3 lockdown info
$VENV/pymobiledevice3 mounter auto-mount --userspace
$VENV/pymobiledevice3 developer core-device screen-capture screenshot shot.png --userspace
```

The stock app cannot be attached with Frida. The Postbox `t7` rewrite is not
available because `appGroupDataContainer` fails for the stock group. Delivery
is the beta Bot API. See `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/README.md` (status section).

## iPhone 6s

| Tool | What |
|---|---|
| `deliver_widget_frida_wifi.py` | Insert a local widget message over Wi-Fi Frida. |
| `deliver_widget_frida_usb.py` | Same over USB Frida. |
| `run_frida_script.py` | Attach to a process and run a Frida JS file. |
| `shot_screen.js` | Frida screenshot helper (UIKit). |
| `deliver_n1_wifi.py` | The original Wi-Fi delivery script. |
| `wifi_tools/` | `run_js.py`, `shot_*.js`, `iosdb.py`, `hook_printf.js`, `cycle.sh`, and the other 6s Wi-Fi helpers. |
| `postbox_rewrite_widget.py` | In `docs/common/tools/`; rewrite a `t7` row, preserving the key and lengths. |

The 6s is jailbroken. Frida 17.17 on `0.0.0.0:27043`; the app PID changes on
relaunch. The 6s tools require the phone to be reachable and the app running.

## Safety

- The 17e scripts do not inject code into the stock app.
- The 6s scripts attach to the app process; use only on your own device.
- Do not leave a Frida server exposed on a public interface.
