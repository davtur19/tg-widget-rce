# iOS 27 USB link bug: usbmuxd loses the iPhone 17e

Date: 2026-11-06
Device: iPhone 17e (iPhone18,5), iOS 27.0 24A437, UDID
`<UDID>`.

## Symptom

- `lsusb` still shows `05ac:12a8 Apple, Inc. iPhone ...`
- `systemctl status usbmuxd` says **active (running)**
- `pymobiledevice3 usbmux list` returns `[]`
- `pymobiledevice3` commands say `Device is not connected`
- `isideload` / `sideload_tg.sh` fails with:

  ```
  bad device
  No devices found
  ```

  sometimes after the Apple ID login, sometimes at the install step.

## Trigger

The link goes stale after a **Frida / usbmux forward was left open**:

- A daemonized `pymobiledevice3 usbmux forward 27042 27042 --daemonize`
  (observed PID 1550650, started Nov 5 and still alive on Nov 6) kept the
  device's Apple USB Multiplexor configuration busy.
- Frida's jailed-iOS `idund` daemon and abandoned `frida -f` attempts can do
  the same.
- Once the owner is gone, the iPhone is still visible on the USB bus but
  usbmuxd no longer enumerates it; a plain replug does not always recover it.

## Recovery (verified)

1. Kill stale forwarders/daemons:
   ```sh
   pkill -f 'pymobiledevice3 usbmux forward' || true
   pkill -f '/idund' || true
   ```
2. Stop usbmuxd:
   ```sh
   sudo systemctl stop usbmuxd
   ```
3. USB-reset the iPhone with pyusb (run as the desktop user; `plugdev`):
   ```sh
   <HOME>/ailocal/Telegram/ios_sideload/venv/bin/python - <<'PY'
   import usb.core
   dev = usb.core.find(idVendor=0x05ac, idProduct=0x12a8)
   dev.reset()
   PY
   ```
   If `reset()` fails with busy/pipe, use the AGENTS.md fallback:
   `dev.set_configuration(3)` with retries (re-find the device each try).
4. Start usbmuxd:
   ```sh
   sudo systemctl start usbmuxd
   ```
5. Verify:
   ```sh
   pymobiledevice3 usbmux list
   ```
   The UDID must be present before invoking `sideload_tg.sh`.

The `dev.reset()` recovery worked on 2026-11-06: reset returned OK and the 17
re-enumerated in `usbmux list` immediately after `systemctl start usbmuxd`.

If the list is still empty, repeat steps 2-4 or physically replug the cable
while the phone is unlocked and awake.

## Prevention

- Never leave `pymobiledevice3 usbmux forward ... --daemonize` running after a
  gadget test; kill it explicitly.
- Kill `idund`/abandoned `frida -f` sessions before installing or pulling
  crash logs.
- Do the USB recovery **before** `sideload_tg.sh`; a `usbmux list` check is
  part of the install preflight.
- Keep the phone unlocked during the install; a lock/sleep can drop the link
  mid-transfer.

## Automation

`recover_usb_and_install.sh` in this directory performs the sequence above and
retries the install up to three times once the UDID reappears.
