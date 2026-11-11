# iPhone 17e: device tools

Docs: `vulns/0day-2-RCE-PARSER-SCOPE/IOS27/README.md`. The 17e parser chain is
**device-proven once (msg 5725)**; the gated twin and the two-phase path are
host-only.

| Tool | What |
|---|---|
| `usb_recover.py` | Stops usbmuxd, resets the USB device, restarts usbmuxd, checks the UDID. |
| `navigate_chat.py` | CoreDevice HID + OCR navigation to a bot chat. |
| `ocr_screenshot.py` | OCR a CoreDevice screenshot and print the `#v` marker. |
| `run_sweep.py` | Run a list of payloads and record markers. |
| `tooling/` | Generic `i17e-runner`: USB recovery, clean-chat gate, exact-device check, payload-last send, console/screenshots, `backup2` proof, matrices/statistics. 84 host tests; no device required. |

Frida delivery, screenshots and Postbox rewrite are in `../ios6s/` (the 6s is
jailbroken; the stock 17e cannot be attached). The shared Postbox tool is in
`../../common/tools/`.

The stock 17e delivery is the Bot API `sendWidget` (beta or standard base); the Postbox `t7`
rewrite is unavailable because `appGroupDataContainer` fails for the stock
group. See the IOS27 README.

Current operational notes, including the USB recovery and the chat
scroll/render limitation: [`RUNBOOK_20261109.md`](RUNBOOK_20261109.md).
