# iOS 6s: orchestrator command sheet

Host-only notes for the iPhone 6s (iOS 15.6, Dopamine, root SSH).  The static
agent does **not** run these; the orchestrator owns all live device operations.

## 0. Transport

The 6s is visible in `lsusb` (`05ac:12a8`) but not in the current
`pymobiledevice3 usbmux list`.  Two independent paths:

1. **SSH over Wi-Fi (known working)**: prior notes: `root@<LAN_IP>`
   (or `mobile@<LAN_IP>` + `sudo`), root shell available.  Use this for
   filesystem/container/DB work and for `frida-server`.
2. **usbmux/AFC/DVT**: needed for `pymobiledevice3 apps`, `developer dvt`,
   `crash`, `syslog`.  Recover the USB link before those commands:

```sh
lsusb | grep -i 05ac:12a8
pymobiledevice3 doctor
sudo systemctl restart usbmuxd        # or: sudo pkill usbmuxd; sudo usbmuxd -f -v
pymobiledevice3 usbmux list
```

If it still does not appear: unlock the phone, replug, accept "Trust This
Computer", and check `pymobiledevice3 lockdown pair`.  Wi-Fi lockdown requires
that the host was paired before; `pymobiledevice3 bonjour mobdev2` lists
Wi-Fi-reachable devices.

## 1. Pair / verify

```sh
V=/tmp/opencode/iosvenv/bin/pymobiledevice3
$V lockdown pair            # tap Trust on the device
$V lockdown info            # iOS version, build, UDID, device name
$V usbmux list
```

For iOS 15.x all services are classic lockdown; no RSD tunnel is needed.
`developer dvt` needs the DeveloperDiskImage mounted:

```sh
$V mounter auto-mount
```

Developer Mode is not required for a jailbroken iOS 15 device in the same way
as iOS 16+, but `dvt launch` still needs the DDI.

## 2. Fingerprint the installed Telegram

```sh
$V apps list | grep -i telegra
$V apps query ph.telegra.Telegraph
```

Over SSH (bypasses usbmux):

```sh
ssh root@<LAN_IP> '
  for p in /var/containers/Bundle/Application/*/Telegram.app; do
    echo "== $p"
    /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$p/Info.plist"
    /usr/libexec/PlistBuddy -c "Print :CFBundleVersion"            "$p/Info.plist"
    /usr/libexec/PlistBuddy -c "Print :MinimumOSVersion"           "$p/Info.plist"
  done'
```

Record: `CFBundleShortVersionString`, `CFBundleVersion` (expect 13.2.x, build
~357xx), `MinimumOSVersion` (must be ≤ 15.6 for the 6s).

## 3. Update to 13.2.0 and decrypt

The App Store page on 2026-11-05 shows **13.2** (released a few hours earlier),
minimum iOS 15.0; the 6s is supported.  Update from the App Store, then decrypt
on-device with TrollDecrypt (already used for 13.1.2) or an equivalent
jailbreak-side dumper.

Fallback: the official Telegram Messenger TestFlight public link is
`https://testflight.apple.com/join/u6iogfd0` (beta **35726** already had
widgets).  Use it only if the stable 13.2 build does not expose the widget
gate; TestFlight slots/expiry are outside our control.

```sh
# on the 6s (TrollStore/TrollDecrypt UI): decrypt the installed Telegram
# then, from the host:
scp root@<LAN_IP>:/var/mobile/Documents/Telegram_decrypted.ipa \
    <HOME>/ailocal/Telegram/ios_sideload/Telegram_13.2.0_decrypted.ipa
```

If TrollDecrypt writes to a different path, find it:

```sh
ssh root@<LAN_IP> 'find /var/mobile /tmp -maxdepth 4 -iname "Telegram*.ipa" 2>/dev/null'
```

Sanity check the pulled IPA on the host:

```sh
unzip -p Telegram_13.2.0_decrypted.ipa Payload/Telegram.app/Info.plist > /tmp/tg.plist
python3 - <<'PY'
import plistlib
p=plistlib.load(open('/tmp/tg.plist','rb'))
print(p['CFBundleShortVersionString'], p['CFBundleVersion'], p['MinimumOSVersion'])
PY
```

## 4. Launch / stream stdout (needed for the printf proof)

```sh
V=/tmp/opencode/iosvenv/bin/pymobiledevice3
$V developer dvt launch 'ph.telegra.Telegraph' --kill-existing --stream
```

`--stream` keeps stdout/stderr attached; the widget's `printf(marker)` proof
appears there.  If `dvt launch` is unavailable, fall back to the on-screen
`#iosout` div (the payload mirrors `setres()` there).

Screenshot / logs:

```sh
$V developer dvt screenshot /tmp/opencode/tg.png
$V syslog live --process Telegram
$V crash pull /tmp/opencode/tg_crashes --match 'Telegram'
```

## 5. Container / app-group access

AFC only vends app containers, not app groups:

```sh
$V apps afc ph.telegra.Telegraph            # whole data container
$V apps afc ph.telegra.Telegraph --documents
$V apps pull ph.telegra.Telegraph Documents/ios_proof.txt /tmp/opencode/
```

For the app group and the Postbox DB, use root SSH:

```sh
ssh root@<LAN_IP> '
  find /var/mobile/Containers/Shared/AppGroup -maxdepth 2 -name telegram-data -type d'
```

The 13.1.2 layout (from `ios_sideload/IOS_PROCEDURE.md`):

```
telegram-data/accounts-metadata/atomic-state
telegram-data/accounts-metadata/login-tokens
telegram-data/account-<id>/postbox/db/db_sqlite{,-wal,-shm}
telegram-data/account-<id>/notificationsKey
telegram-data/widgetPresentationData.json
telegram-data/notificationsPresentationData.json
```

13.2 may add widget tables/fields; re-inventory before patching.

## 6. Frida ground truth (root, 6s)

```sh
ssh root@<LAN_IP> 'nohup /var/jb/usr/sbin/frida-server -l 0.0.0.0:27042 \
  >/tmp/frida.log 2>&1 &'
# from the host:
frida -H <LAN_IP>:27042 -f ph.telegra.Telegraph \
  -l lab/ios_port/host/frida_probe.js --no-pause
```

The probe prints `free`, `system`, `dlopen`, `posix_spawn`, stub/module bases,
and whether `/bin/sh` exists.  This is the value to compare with the widget
payload's `RESULT` markers.

## 7. What not to do

- Do not send a widget payload to a third-party bot or chat.  Use Saved
  Messages, your own test account, or a self-hosted bot only.
- Do not use public tunnels (localhost.run, lhr.life, ngrok, cloudflared quick
  tunnels, serveo, pinggy).  LAN only, or a host you control.
- Do not patch the App Store bundle in place; decrypt a copy and keep the
  original for version fingerprints.
