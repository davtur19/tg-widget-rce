# Pixel 9 (Android 17) — debuggable second-package build + account clone

Date: 2026-11-02. Goal: run the #1827 class-64 payload on the Pixel 9
(Android 17/SDK 37, arm64, MTE-capable) without root and without a Telegram
login. Login on the Pixel was failing with Telegram's app-id / Play-Integrity
flood checks; the account state was cloned from the Sony instead.

## 1. Rebuild 72799 as a debuggable second package

Input: `/tmp/opencode/base72799.apk` (md5 `04317a9fae026fb41b1c741e8946b77e`,
the exact APK installed on the Pixel).

```bash
mkdir -p /tmp/opencode/dbgbuild && cd /tmp/opencode/dbgbuild
curl -sSL -o apktool.jar \
  https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar
java -Xmx4g -jar apktool.jar d -s -f -o base_dec /tmp/opencode/base72799.apk
```

`-s` keeps `classes*.dex` raw (verified byte-identical after the rebuild).
Patch `base_dec/AndroidManifest.xml`:

- `<application ...>` add `android:debuggable="true"`; set
  `android:label="Telegram DBG"`.
- `package="org.telegram.messenger.beta"` → `...beta.dbg`.
- replace **all** 13 `org.telegram.messenger.beta` occurrences (permission and
  provider authorities, `androidx-startup`, firebase/mlkit providers, voip
  providers, ...) with `org.telegram.messenger.beta.dbg` so the second package
  does not collide with the installed beta.
- app id rename keeps `org.telegram.messenger.*` Java classes unchanged; the
  dex `BuildConfig.APPLICATION_ID` string is not used for startup decisions.

```bash
java -Xmx4g -jar apktool.jar b -f -o patched_unsigned.apk base_dec
BT=<HOME>/ailocal/old/Android/Sdk/build-tools/35.0.0
keytool -genkeypair -keystore debug.keystore -storepass android -keypass android \
  -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Android Debug,O=Android,C=US"
$BT/zipalign -f -p 4 patched_unsigned.apk patched_aligned.apk
$BT/apksigner sign --ks debug.keystore --ks-key-alias androiddebugkey \
  --ks-pass pass:android --key-pass pass:android \
  --out telegram_beta_72799_dbg2.apk patched_aligned.apk
adb install -r -g telegram_beta_72799_dbg2.apk
```

Result: `org.telegram.messenger.beta.dbg`, UID 10178, `DEBUGGABLE`,
v1+v2+v3 signatures, `run-as` works. Installed **alongside**
`org.telegram.messenger.beta` (and `org.telegram.messenger`), no data touched
in the original.

## 2. Clone the Sony account into the debug package (no login)

Sony XQ-BT52 (`<SERIAL>`, root) has the tested account:
`files/cache4.db`, `files/tgnet.dat` (plain serialized native config, no
device binding), `files/dc2conf.dat`, `shared_prefs/userconfing.xml`
(`userconfing` — the app's account-0 prefs, holds the serialized TL_user under
key `user`).

```bash
P=<LAN_IP>:44297 ; PKG=org.telegram.messenger.beta.dbg
adb -s $P shell am force-stop $PKG
adb -s $P shell "run-as $PKG sh -c 'cat > files/cache4.db'" \
  < /tmp/opencode/sony_cache4_backup.db
adb -s $P shell "run-as $PKG sh -c 'cat > files/tgnet.dat'"  < sony_tgnet.dat
adb -s $P shell "run-as $PKG sh -c 'cat > files/dc2conf.dat'" < sony_dc2conf.dat
adb -s $P shell "run-as $PKG sh -c 'cat > shared_prefs/userconfing.xml'" \
  < sony_userconfing.xml
```

Without `tgnet.dat` the app connects with a fresh key, gets
`401 AUTH_KEY_UNREGISTERED`, and clears config/DB; with the Sony `tgnet.dat`
the account is authorized and syncs. The Sony session stayed healthy
(Telegram accepts concurrent connections for the same auth key). No SMS, no
SafetyNet/Play-Integrity, no root.

## 3. Widget delivery and MTE test

- Patch the widget message in the cloned `cache4.db` (mid 79468 in Saved
  Messages / the "User" dialog) with
  `tools/widget_tool.py <db> 79468 --html <payload.html>`, push it back with
  `run-as`, force-stop/start, open the dialog; the widget log is visible in
  the message bubble.
- Pixel `SYSTEM_DELTA` (libc `free`→`system`) = **0x41fe0**
  (`free=0x5d700`, `system=0x9f6e0` in
  `/apex/com.android.runtime/lib64/bionic/libc.so`; Sony is `0x26df0`).
- MTE: `setprop persist.arm64.memtag.app.org.telegram.messenger.beta.dbg on`
  (persists), then restart the app. Verify with
  `run-as $PKG sh -c 'grep -c mt /proc/<pid>/smaps'` (44-56
  `[anon:scudo:primary]` mappings) and `app_smaps_mte.txt`.
- Revert with `setprop ... off` if the device should go back to the MTE-off
  baseline.
