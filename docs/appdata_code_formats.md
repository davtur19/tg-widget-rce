# Telegram app-data formats — which ones are code, and which run at startup?

Date: 2026-11-02. Target: `org.telegram.messenger.beta` 13.2.0 beta,
versionCode **72799**, arm64, Sony XQ-BT52 (Xperia 10 III), Android 13, build
`62.2.A.0.533`, UID **10357**. Scope: **host/source/native only**; no device or
emulator was used for this pass. The first exploit is assumed to give app-UID
code execution and arbitrary app-data write.

Question: is there a **Telegram-owned app-data format** that the app loads or
executes as code **by itself at startup/reboot**, with **no user action**
(no theme tap, no import dialog, no `ACTION_VIEW`, no manual sticker apply)?

Lab artifacts: `lab/appdata_code_formats/` (ranked table, matrix, exact refs,
no-go list, device plan, reproducible scans). The main report
(`telegramandroidwidget/REPORT_20261102.md`) is **not** modified.
Companion prior work is cited but not re-derived: `notes/loader_art.md`,
`notes/native_appdata_audit.md`, `notes/sqlite_trigger_rce.md`,
`notes/tgnet_parser_audit.md`, `notes/tlottie_gzip_audit.md`,
`notes/twidget_native_audit.md`, `notes/update_widget_cache.md`.

---

## 0. Verdict

**No Telegram-owned app-data format is executed as code on the boot path.**
The only two app-data code loads that happen at cold start are:

1. **ART runtime app image** — `cache/oat_primary/arm64/base.art`, mapped by ART
   before `Application.onCreate`; a genuine code load, but not a Telegram
   format, and it is keyed to the absolute `/data/app/~~<hash>/.../base.apk`
   path (update-fragile). Prior audit `notes/loader_art.md`; device proof
   pending.
2. **`ks` local-library fallback** — `files/lib/libtmessages.49loc.so`, loaded
   by `System.load` only inside `catch (Error)` after
   `System.loadLibrary("tmessages.49")` fails. The file is app data and survives
   reboot, but app data cannot force the primary failure; prior audit
   `notes/native_appdata_audit.md`.

The only code-bearing Telegram format in this inventory is the **widget JS bundle**
in `files/widget-sandbox/<hash>/*.js` (QuickJS). It is a real app-data code load
but is only reached by `WidgetSandboxNative.create` on a message-widget render,
i.e. the known widget/QuickJS route; it does **not** run at boot or on a normal
launcher start without opening the widget chat. It is therefore a **no-go for
the startup requirement**, and it is the route the task excludes.

Everything else that is automatically consumed at boot is **parsed data or
config**, not code: `cache4.db` (SQL), `tgnet.dat` (native config),
`shared_prefs/*.xml`, the current language XML (conditional), and — on a
launcher start — `.attheme` and TGS/emoji. The update APK is code but is
user-gated and signature-checked; backup/import/export/Passport/migration are
data and user-gated; WebView/Instant View/bot WebApps need a UI; the `tgcalls`
WASM module is compiled into `.rodata`, not app data.

| Surface | Code? | Automatic at boot? | Verdict |
|---|---|---|---|
| ART `cache/oat_primary/arm64/base.art` | **yes** (OAT/Dalvik) | **yes** | only real startup code load; prior, update-fragile |
| `files/lib/libtmessages.49loc.so` | **yes** (ELF) | **yes** (gated) | prior; not app-data-forcible |
| `files/widget-sandbox/<hash>/*.js` | **yes** (JS) | **no** | real JS loader, widget/QuickJS only |
| `files/cache4.db` | no (SQL) | **yes** (SQL) | SQL triggers/views execute; no code primitive |
| `files/tgnet.dat` | no | **yes** | config redirect only |
| `shared_prefs/*.xml` | no | **yes** | primitives only |
| `files/remote_*.xml` | no | conditional | strings only |
| `files/*.attheme` | no | no (launcher only) | colors only |
| `*.tgs` | no | no (chat-list UI) | native parser |
| update APK | **yes** (APK) | no | user install + signature |
| backup/import/export/Passport/migration | no | no | data/user action |
| WebView / Instant View / bot WebApps | **yes** (JS) | no | UI object required |
| `tgcalls` WASM | **yes** (WASM) | no | embedded `.rodata`, not app data |
| `libtmessages` `dlopen` / fixed `loadLibrary` | **yes** | n/a | fixed system/APK names |

**Critical distinction:** a theme, language pack, sticker or widget HTML that
is *parsed* is not a loader. Only a file whose bytes become executable
instructions (dex/oat, ELF, JS, WASM, SQL that can call a loader) counts. Of
the Telegram formats, only the widget JS bundle qualifies as code; it is not
startup-reachable.

**Follow-up 2026-11-03 (local document/image parsers).** No new app-code
write/RCE. `Rar@` is `.text` bytes, `7z` is unreferenced `.rodata`, and
`Intel(R) JPEG Library` is an FFmpeg MJPEG COM-marker string — none is a live
archive/IPP parser. There is no built-in PDF viewer (external `ACTION_VIEW`);
JPEG/PNG/WebP/HEIC go to system `BitmapFactory`/Skia; JPEG XL/JPEG2000 have no
compiled decoder; SVG is a live Java `SvgHelper` parser, but Android 13's
`ExpatReader` reports `external-general=false` / `external-parameter=false` and
the device probe found no file/HTTP read (only internal-expansion DoS class).
Only an unpatched **system** image decoder is a plausible app-process
memory-corruption surface, and that is an OS issue, not a Telegram app-data
loader. Full sections: §12–§13; lab: `local_media_parsers.md`, `svg_xxe/`.

---

## 1. What “startup” means here

Three different bars are often mixed; they are kept separate:

* **Boot A — no user action.** `BOOT_COMPLETED` → `AppStartReceiver` →
  `SharedConfig.loadConfig` → `startPushService` → `NotificationsService` →
  `ApplicationLoader.postInitApplication` → `ks.g`, DB, tgnet, prefs. This is
  the user's bar (“no tapping anything”).
* **Cold B — normal launcher start, no further interaction.** The user taps the
  Telegram icon; `LaunchActivity` applies the current theme/language and the
  chat list draws custom emoji. This is “startup” in a loose sense, but it
  still needs the launcher tap.
* **UI C — requires opening a chat/dialog/import screen.** Widget message
  rendering, WebView, import dialogs, sticker apply. This is excluded.

The boot path is the only one that satisfies “by itself at startup/reboot with
no user action”. The widget JS bundle is UI C, not Boot A.

### 1.1 Boot path, exact

```
BOOT_COMPLETED
  manifest_72799_full.txt:814-821            AppStartReceiver
  AppStartReceiver.smali:27-40               runOnUIThread(new ag.f3(9))
    ag/f3.smali:1339-1377                    case 9
      uz.t()          :1344                  SharedConfig.loadConfig
      w0.x()          :1372                  startPushService
        NotificationsService.onCreate        NotificationsService.smali:31
          w0.w()        :1365                postInitApplication
            ks.g()      :1405                native lib
            dd.D0()     :1411                LocaleController
            uz.t()      :1710                prefs
            wp.r1()     :1762                MessagesController
              f1.getMessagesStorage() :303
                is.a0()  :2507
                  is.<init> :472 -> openDatabase
            ConnectionsManager.getInstance :1784 -> native_init
            MediaController :1969; i5/b6/u1 :1979/2015/2028
```

`w0.onCreate` also calls `ks.g` at `w0.smali:2734` before
`ConnectionsManager.native_setJava` (`:2740`), so a normal process start
reaches the same native loader gate.

`AppWidgetProvider` (`ChatsWidgetProvider`, manifest `:885-892`) is a second
automatic event after boot. `ChatsWidgetService` is a `RemoteViewsService`; it
reads `cache4.db` dialog rows and builds `RemoteViews`
(`ChatsWidgetService.java:36-396`). It has no `twidget` / `WidgetSandbox` /
WebView reference. The home-screen widget is not the bot-message widget engine.

---

## 2. Ranked candidates

The full table with all columns is `lab/appdata_code_formats/ranked_table.md`.
The short ranking by “could this execute code at boot?” is:

1. **ART app image** — yes, prior.
2. **`ks` local `.so`** — yes, gated, prior.
3. **Widget JS bundle** — code, but UI C (not startup); excluded route.
4. **`cache4.db`** — executable SQL at boot, not code.
5. **`tgnet.dat`** — config at boot, not code.
6. **`shared_prefs`** — data at boot, not code.
7. **Language XML** — data at boot if current locale is remote, not code.
8. **`.attheme`** — data on launcher start, not code.
9. **TGS/emoji** — data on chat-list draw, not code.
10. **Update APK** — code but user/signature.
11. **WebView/QuickJS** — code but UI C.
12. **`tgcalls` WASM** — code but embedded.
13. **Backup/import/export/Passport/migration** — data/user action.
14. **Native `dlopen`/fixed `loadLibrary`** — fixed names, no app path.

### 2.1 Attacker control and app-UID writability

| Candidate | Attacker-controlled source | App-UID code-exec can write? |
|---|---|---|
| ART `base.art` | app-UID file write; payload hand-built | **yes** (`cache/` is app data) |
| `files/lib/libtmessages.49loc.so` | app-UID file write | **yes** (`files/lib`) |
| `files/widget-sandbox/<hash>/*.js` | app-UID file write; bot widget message is the trigger | **yes** (plus `ready` marker bypass) |
| `files/cache4.db` | app-UID DB write; messages/bots populate rows | **yes** (`files/`) |
| `files/tgnet.dat` | app-UID write; server config in normal use | **yes** (`files/`) |
| `shared_prefs/*.xml` | app-UID write; some server-provided values (`appUpdate`, passport) | **yes** (`shared_prefs/`) |
| `files/remote_*.xml` | app-UID write; language pack can come from server/user import | **yes** (`files/`) |
| `files/*.attheme` | app-UID/user theme; remote theme document | **yes** (`files/`) |
| `*.tgs` | bot/user message → cache; app-UID write | **yes** (cache dir) |
| update APK | app-UID write or server update | **yes** (`files/`/cache) |
| backup/import/export/Passport | user/other app; app-UID write | **yes** (prefs/files) |
| WebView `app_webview` | app-UID write; bot page is the trigger | **yes** (`app_webview/`) |
| `tgcalls` WASM | none (embedded `.rodata`) | **no** |
| `libtmessages` `dlopen` | none (fixed names) | **no** |

The key point is not whether the file can be written (all app-data candidates
can), but whether the **consumer runs at boot** and whether the bytes are
**code**. Only the first two rows satisfy both.

---

## 3. The only two boot-time app-data code loads

### 3.1 ART runtime app image (`cache/oat_primary/arm64/base.art`)

**What it is.** ART's runtime app image. The app image directory is
`<app_data_dir>/cache/oat_primary/` (`RuntimeImage::GetRuntimeImageDir()`;
prior `notes/loader_art.md:276-307`, `notes/loader_startup_components.md:126-145`).
On the device the mapped file is
`/data/user/0/org.telegram.messenger.beta/cache/oat_primary/arm64/base.art`
(prior maps/tombstone, `notes/loader_startup_components.md:141-145`).

**Startup reach.** ART opens/relocates the image at process start, before
`Application.onCreate`; the prior forged image was accepted, mapped, and
reached `w0.onCreate` → `ks.<clinit>`, then died in
`ClassLinker::InitializeClass` (`notes/loader_art.md:31-45`). It is a real code
load, not a parser.

**Attacker control / writability.** `cache/` is app data; UID 10357 can write
the file. The payload is a hand-built OAT image + Dalvik `<clinit>`; the prior
generator/validator are in `lab/loader_art/`
(`gen_loader_image.py`, `validate_loader_image.py`,
`sample/base_72799_loader_load.art`).

**Reboot / update.** The file survives reboot on the same install; the runtime
may overwrite it at the end of a start (`notes/loader_art.md:276-307`). It is
**not update-surviving**: the image embeds the absolute
`/data/app/~~<hash>/.../base.apk` path in its DexCaches; an update changes the
hash and `OpenAndSetDexFiles()` rejects the image
(`notes/loader_startup_components.md:229-238`). This is a **candidate for
reboot**, not for update.

**Device status.** Prior host validator passes; the prior device run crashed in
`InitializeClass`; the fixed image’s device run is still pending
(`lab/loader_art/device_test.sh`). No claim of device code execution is made
here.

### 3.2 `ks` local-library fallback (`files/lib/libtmessages.49loc.so`)

**What it is.** `ks.g` first calls `System.loadLibrary("tmessages.49")`
(`ks.smali:1484`). Only in the `catch (Error)` path does it look at
`new File(getFilesDir(), "lib/libtmessages.49loc.so")` (`ks.smali:1593-1611`)
and call `System.load(absolutePath)` (`:1672`). `ks.k` extracts the same
filename from `getApplicationInfo().sourceDir` (`:2622-2692`) into that path and
calls `System.load` again (`:2803`).

**Startup reach.** Both `w0.onCreate:2734` and `w0.w:1405` call `ks.g`, so the
gate is on the boot path.

**Attacker control / writability.** `files/lib` is app data; UID 10357 can
write the `.so`. The path is fixed (no traversal, no attacker-controlled name).
The **gate is the primary `System.loadLibrary` failure**, not file permissions.

**Can app data force the failure?** No. Prior `notes/native_appdata_audit.md`
shows:

* `JNI_OnLoad` returns `0x00010006` unless `GetEnv` or one of three
  `RegisterNatives`/`GetMethodID` batches fails; every class/method/signature is
  a compile-time literal (`notes/native_appdata_audit.md` §3).
* The 18 `.init_array` constructors and `JNI_OnLoad` reach **no file API** at
  depth 5 (only `getenv("LH_SVG_LATE_CACHE")`, not app-controlled)
  (`lab/native_appdata_audit/load_path_closure.txt`).
* The pre-load `w0.onCreate` code reads no app-writable file; the beta log is
  write-only (`f8.k`).
* The native library itself is in `/data/app/.../lib/arm64`, install-owned and
  read-only; a broken ELF/ABI/RegisterNatives failure would require an APK
  mismatch, not app data.

Two latent issues are post-failure and need an extra primitive: `ks.k` returns
`true` after its own `System.load` fails (`ks.smali:2819-2875`), and the
`listFiles()` cleanup follows a symlink at `files/lib`. Neither creates the
initial failure.

**Reboot / update.** The file survives reboot and `pm install -r` (not
uninstall/clear-data). The filename is version-specific
(`libtmessages.49loc.so`; a `.50` build looks for `.50loc.so`), so a payload
must be re-planted after a library-name bump.

**Device status.** Prior positive control: with the install-owned
`libtmessages.49.so` moved aside by root, the app loads the app-data `.so`
(`notes/loader_ks_fallback.md:315-317`; `lab/loader_ks_fallback/evidence/device_fallback.txt`,
2026-11-01). `lab/loader_device_proof` separately proves app-UID
`linker64`/`app_process` loaders, not this fallback. App-data-only cannot arm
it.

**Bottom line for §3.** Both are known, and neither is a Telegram data format.
No Telegram-owned format adds a third boot-time code load.

---

## 4. The code-bearing format: widget JS bundle (not startup)

This is the only **Telegram-owned app-data file that is executed as code** in
the 72799 tree. It is included because the task explicitly lists the widget
bundle, but it fails the no-user-action startup test and is the known
widget/QuickJS route.

### 4.1 What the code does

`b0.a(Context)` (`b0.smali:48`):

* reads `assets/WidgetSandbox/manifest.txt` (`:94`);
* hashes the manifest with SHA-256 and takes the first 12 bytes as the
  directory name (`:183-235`);
* builds `getFilesDir()/widget-sandbox/<hash>` (`:313`);
* if the `ready` marker is a file (`:344`), returns the directory **without
  re-verification**;
* otherwise parses `sha256 path` lines, rejects `..` and absolute paths
  (`:436-452`), copies `assets/WidgetSandbox/WidgetJS/<path>` into the
  directory, verifies each file’s SHA-256 (`:560-695`), and writes `ready`.

`k0.create()` calls `b0.a` (`k0.smali:1031`), converts the absolute path to
bytes (`:1039`, `:1144`), and passes it as the first argument to
`WidgetSandboxNative.create` (`:1263`). The native QuickJS sandbox then loads
and executes the JS from **app data**: native `WidgetSandboxNative.create`
(`0x980858`) calls `sub_77AD10` at `0x982a20` with the bundle directory string,
and `sub_77AD10` resolves `sandbox-bundle.js` / `renderer-bundle.js` /
`validator-bundle.js` from it (`scans/widget_native_xrefs.txt`).

**Correction to `notes/loader_startup_components.md:633`:** that note says the
JS is “read from the APK, not app data”. The initial bytes come from the APK,
but `b0.a` copies them to `files/widget-sandbox/<hash>/` and `k0` passes that
**app-data path** to `WidgetSandboxNative.create`; the JS that QuickJS evaluates
is the app-data copy. The conclusion (not a startup loader) is unchanged; the
path statement needed correction.

### 4.2 Why it is not a startup loader

The call sites of `b0.a` are only `k0` (widget create), `p`/`w`/`e0` (widget
scheduling/backend). There is **no** `b0`/`k0` reference in `w0`, `uz`, `wp`,
`is`, `NotificationsService`, or `AppStartReceiver` (grep in
`scans/widget_bundle.txt`). The bundle is extracted/loaded only when a
`TL_messageMediaWidget` bubble is rendered (the prior chain
`ChatMessageCell.r3` → `wv` → `hl0` → `p` → `k0` → `WidgetSandboxNative.create`,
`notes/post_update_retrigger.md` §1). The home-screen widget is native
`RemoteViews`, not `twidget`.

### 4.3 Security-relevant detail: `ready` skips verification

Because `b0.a` returns immediately when `files/widget-sandbox/<hash>/ready`
exists, an app-UID writer can pre-create the marker and replace
`sandbox-bundle.js` / `renderer-bundle.js`. The JS then executes in QuickJS on
the next widget render. This is a **real app-data JS loader** — but it still
requires opening the widget chat. It is a useful second-stage primitive for a
payload that already has app-UID code execution, not a cold-start loader.

**Attacker-controlled:** app-UID file write; the trigger is a bot/widget
message render. **Not boot:** no service or receiver calls `k0`/`b0`.

---

## 5. Boot-time formats that are parsed, not code

### 5.1 `cache4.db` — SQL executes at boot, but it is not code

**Exact path.** `w0.w:1762` → `wp` constructor `:2213` calls
`getMessagesStorage()` → `f1.smali:303` → `is.a0(account)` (`is.smali:2507`) →
`is.<init>` (`:472`) posts `openDatabase(1)`.

`openDatabase` (`is.smali:51184`): path `files/cache4.db` /
`files/accountN/cache4.db`, `SQLiteDatabase.<init>` (`:51254`), pragmas
`PRAGMA secure_delete/temp_store/journal_mode/journal_size_limit`
(`:51279-51330`), `PRAGMA user_version` (`:51443`), and
`SELECT seq, pts, date, qts, lsv, sg, pbytes FROM params WHERE id = 1`
(`:51523`). The native open is `SqliteWrapper.cpp:142-154` (`sqlite3_open`)
against the bundled SQLite 3.39.3.

**What executes.** An attacker can replace `params` with a **view** or add a
**trigger**; the startup `SELECT`/`UPDATE` then executes attacker SQL. Prior
`notes/sqlite_trigger_rce.md` confirms this is real at boot but finds **no
SQL-reachable code primitive**: `load_extension` is compiled but disabled at
runtime (`not authorized`), no `writefile`/`readfile`, no `ATTACH`/`VACUUM` in
triggers, and the memory-safety issues are reads/UAF reads (DoS), not writes or
controlled calls.

**Attacker control.** App-UID DB write; message/bot content can also populate
rows, but schema/triggers are not normally server-controlled. A DB view/trigger
is attacker **SQL**, not executable code.

**Verdict.** Boot-executed SQL, no code. This is the closest Telegram format to
“executable config”, but it cannot load a dex/ELF/JS.

### 5.2 `tgnet.dat` — native config at boot

**Exact path.** `w0.w:1784` → `ConnectionsManager` constructor → `native_init`
(`ConnectionsManager.smali:7183`, call `:11183`) →
`Config::readConfig` (`ConnectionsManager.cpp:365-446`) on
`new Config(instanceNum, "tgnet.dat")` (`:367`).

**Format.** `[u32 size][TL payload]`, plaintext, no MAC/checksum
(`notes/tgnet_parser_audit.md`). It carries DC id/addresses/ports/auth keys and
a few flags. It can redirect the client to a different DC/address, but it does
not carry code; `jni/tgnet` has no `dlopen`/`dlsym`/`System.load` (grep empty in
`scans/tgnet_dat.txt`). Prior audit found only OOB reads/DoS, no write or code
primitive.

**Attacker control.** App-UID write (and server-driven config updates in normal
use). **Verdict:** config, not code.

### 5.3 `shared_prefs/*.xml` — data at boot

**Exact path.** `SharedConfig.loadConfig` = `uz.t()` (`uz.smali:3744`), called
at `ag/f3:1344` (boot receiver) and `w0.w:1710` (post-init). It reads
`background_activity` (`:3781`), `userconfing` (`:3804`), `mainconfig`
(`SharedConfig.java:596`), `appUpdate` (`uz.smali:4369`), and
`passportConfigJson` (`:4099`). `w0.w` also initializes `webview_bots`
(`w0.smali:1719`).

**What it can do.** `appUpdate` is a base64 `TL_help_appUpdate` deserialized at
boot; it can make `LaunchActivity` show the blocking update view on the next
user launch. It does **not** auto-install: the install is `ACTION_VIEW` +
`FileProvider` + user prompt (`ApplicationLoaderImpl.smali:250-337`), and the
update check in 72799 passes the literal `"null"` URL (`k1.smali:565`).
`language` selects a language key (see §5.4); `debugWebView` only calls
`WebView.setWebContentsDebuggingEnabled` (`uz.smali:1195`), it does not create a
WebView.

**Attacker control.** App-UID prefs write; some values come from the server
(`appUpdate`, `passportConfigJson`). The framework parser reads primitives
only; no `Class.forName`/class loading.

**Verdict.** Data/config; no code. The `appUpdate` TL object is a parser input,
not an installer.

### 5.4 Language XML — conditional boot parse

**Exact path.** `w0.w:1411` → `dd.D0()` (`LocaleController.getInstance`) →
constructor (`dd.smali:739`) reads the `language` pref (`:3226`) and calls
`dd.d` (`:3351`). If the current `LocaleInfo` is remote/unofficial, its
`getPathToFile()` returns `files/remote_<short>.xml` or
`files/unofficial_<short>.xml` (`ad.smali:650-735`), and `dd.G0(File,Z)`
(`dd.smali:18769`) parses it with `XmlPullParser` (`:18850`).

**What it is.** A map of `<string name="...">value</string>` entries. It
controls UI text and format strings; `String.format` is not code. The parser is
`XmlPullParser`, not an XSLT/script engine. A malformed file is copied to
`files/malformed_locales/` and the locale is reloaded.

**Attacker control.** App-UID prefs + file write; a language pack can also come
from a user import/server. **Verdict:** parsed strings; no code.

### 5.5 `.attheme` — launcher-start parse, not boot

`Theme.getThemeFileValues` = `t6.T0` (`t6.smali:32954`; source
`Theme.java:7560`) reads 1 KiB chunks, parses `key=value`,
`Color.parseColor`/`Utilities.parseInt`, and reads `WLS=`/`WPS` wallpaper
metadata. There is **no** `t6` reference in `w0`, `uz`, `NotificationsService`,
or `AppStartReceiver`; the parser is reached from `LaunchActivity`/theme UI
(`Theme.java:5485`, `5655`, `7249`). A `WLS=` URL is passed to wallpaper code,
not executed. **Verdict:** colors only.

### 5.6 TGS / custom emoji — chat-list parse, not boot

`RLottieNative.nCreate` (`RLottieNative.smali:210`, native decl `:511`) and
`nCreateWithJson` (`:434`) feed the native `tlottie` parser. Prior
`notes/tlottie_gzip_audit.md` shows the loader is a parser/renderer with a
crash/DoS surface, not a code loader. The chat list may draw a custom-emoji TGS
on a launcher start (prior `notes/update_widget_cache.md`), but the boot
service does not render the chat list. **Verdict:** native data parser.

---

## 6. Update / install / backup / import

### 6.1 In-app updater and APK install

**Update check is disabled in 72799.** `k1.a` builds the URL as the literal
`"null"` (`k1.smali:565`); `new URL("null")` throws, so `k1.d` cannot be set by
a server response. `ApplicationLoaderImpl.g()` returns `new File(k1.d)` only if
the file exists (`ApplicationLoaderImpl.smali:90-137`).

**Install is user-gated.** `ApplicationLoaderImpl.v` builds
`ACTION_VIEW` + `application/vnd.android.package-archive` + `FileProvider` and
calls `startActivityForResult` (`:250-337`); `i0.t2` has the same shape
(`i0.smali:35900-36138`, `canRequestPackageInstalls` `:35950`). All call sites
are UI (`i0.t2` users; `w0.g()` users are `c61`, `b61`, `bh/f`).

**PackageInstaller / splits.** Telegram has **no** install session:
`PackageInstaller` appears only in the GMS utility `k6/g.smali:1259-1314`
(`getAllSessions`), with no `createSession`/`commit` anywhere. There is no
`SplitInstall`/`SplitCompat`/`split.apk` loader (grep empty). The manifest
requests `REQUEST_INSTALL_PACKAGES` (`manifest_72799_full.txt:155`), but
`INSTALL_PACKAGES` is only a receiver `android:permission` attribute
(`:824`), not a held permission. Even a staged APK is verified by
`PackageManagerService` against the installed signature; a foreign-signed APK
is rejected.

**Attacker control.** App-UID can write `k1.d` or put an APK in `files/`; it
still cannot install without the user prompt and signature. **Verdict:** code,
but user-gated; not a loader.

### 6.2 Backup / restore

`BackupAgent.onCreate` adds `SharedPreferencesBackupHelper` for
`saved_tokens`/`saved_tokens_login` (`BackupAgent.smali:67-95`); there is no
`onRestore` code and no file/dex/so loading. Android Auto Backup restores prefs
at install time, not app startup. **Verdict:** data only.

### 6.3 Import / export / Passport / migration

* `ImportingService` is a progress notification service
  (`ImportingService.java:20-110`); history/sticker import is user-initiated and
  uses `SendMessagesHelper` ZIP/JSON/HTML parsing
  (`SendMessagesHelper.java:149-505`, `9166-9220`). No `DexClassLoader`/
  `System.load`/`exec` on imported content.
* `Telegram Passport` stores `passportConfigJson` in prefs
  (`SharedConfig.java:276, 538, 757-767`); `PassportActivity` parses it on user
  action. Encrypted document values, no code.
* `FilesMigrationService` moves external `Telegram/` files
  (`FilesMigrationService.java:76-160`); `Files.move` only, no exec/load, and it
  is started from the UI (`checkBottomSheet`), not at boot.
* Chat export writes HTML/JSON; it is output, not an import loader.

**Verdict:** data and user action; no code.

---

## 7. WebView / Instant View / bot WebApps

No `Landroid/webkit/WebView;` object is created in `w0`, `uz`, `wp`, `is`,
`NotificationsService`, or `AppStartReceiver`. `uz.smali:1195` only calls
`WebView.setWebContentsDebuggingEnabled` from the `debugWebView` pref.
`addJavascriptInterface`/`evaluateJavascript` sites are all UI classes
(`org/telegram/ui/...`; see `scans/webview_startup.txt`). Instant View is a
Java template interpreter (`org/telegram/ui/iv`), not JS. Bot WebApps open a
WebView on user action.

**Verdict:** code when a UI page is opened, but no boot path. The `app_webview`
cache is not read by a startup WebView because no WebView exists at boot.

---

## 8. Native libraries, WASM, and `exec`

* `libtmessages.49.so` `NEEDED` list is system libs only (`libm`, `libandroid`,
  `liblog`, `libdl`, `libjnigraphics`, `libz`, `libGLESv2`, `libEGL`,
  `libOpenSLES`, `libc`). Undefined imports include `dlopen`/`dlsym`, but the
  four `dlopen` callers are the WebRTC network monitor and PLT thunks; none
  takes an app-data path (`lab/native_appdata_audit/file_api_xrefs.txt:169-174`).
* No `execve`/`system`/`popen`/`posix_spawn` imports. The only `ProcessBuilder`
  is `EmuDetector` running the fixed `/system/bin/netcfg`
  (`o6.smali:1541-1592`, `EmuDetector.java:376`).
* `System.loadLibrary` names are fixed: `tmessages.49` (`ks.smali:1484/1831`),
  `language_id_l2c_jni` (`ThickLanguageIdentifier.smali:234`), and
  `jingle_peerconnection_so` (`PeerConnectionFactory.smali:289`). None resolves
  from app data.
* `tgcalls` v2wasm is real WASM code, but the only `\0asm` magic in
  `libtmessages.49.so` is at file offset **`0x2c8818`** in `.rodata`; there is
  no `.wasm` asset and no app-data path. `WamrCoreBackend.cpp` /
  `CallCoreHost.cpp` strings confirm the module is compiled in. It runs on call
  setup, not boot.
* `GMS Dynamite` (`y6/e`, `y6/h`) loads classes from a path supplied by Google
  Play services, not Telegram app data; UID 10357 cannot write it.

**Verdict:** no app-data native/wasm/exec loader beyond the `ks` fallback.

---

## 9. No-go list (condensed)

Full table in `lab/appdata_code_formats/no_go.md`. The key rejections:

| Format | Why not a loader |
|---|---|
| `cache4.db` | SQL only; `load_extension` disabled; no custom functions/virtual tables; prior no code primitive. |
| `tgnet.dat` | native config; no `dlopen`/`load`; can redirect network only. |
| `shared_prefs` | primitives only; `appUpdate` is a TL parser input, install still user/signature. |
| language XML | `HashMap<String,String>`; `String.format` is not code. |
| `.attheme` | colors/offsets; no boot reference; UI-applied. |
| TGS/emoji | native Lottie parser; prior crash/DoS only. |
| update APK | user `ACTION_VIEW` + signature; no `PackageInstaller` session; no splits. |
| backup/import/export/Passport/migration | data parsers/movers; user action. |
| WebView/Instant View | no boot WebView; UI only. |
| `tgcalls` WASM | embedded `.rodata`; call only. |
| `dlopen`/fixed `loadLibrary` | fixed system/APK names. |
| `GMS Dynamite` | GMS-owned path, not app data. |
| `app_process`/`linker64` | no Telegram call site; only an existing-RCE process, not startup. |
| `code_cache` | profile/JIT metadata; ART image uses `cache/oat_primary`. |

**Do not claim** a theme/language/sticker/DB file is a loader: the app parses
it, and the only code-bearing Telegram format (widget JS) needs a widget
render.

---

## 10. Device plan

`lab/appdata_code_formats/device_plan.md` has T0–T10 with commands and
expected results. Summary:

* **T1 ART** — prior `lab/loader_art/device_test.sh`; marker/tombstone; no claim
  without the marker.
* **T2 `ks`** — app-data `.so` + normal start: expect `loaded normal lib`, no
  `Load local lib`; root-moved primary lib positive control: expect
  `Load local lib` + marker; restore.
* **T3 `cache4.db`** — `params` view/trigger writes a `canary` table; boot;
  query `canary`; expect SQL ran, no code marker; `load_extension` returns
  `not authorized`.
* **T4 `tgnet.dat`** — planted DC address; observe connection; no code.
* **T5 prefs** — `appUpdate`/`debugWebView`; no install session, no WebView.
* **T6 language** — remote locale + canary string; expect UI string, no code.
* **T7 theme/TGS** — canary color/TGS; expect render, no code.
* **T8 widget JS** — `ready` + tampered bundle; open chat: marker; reboot
  without opening chat: no marker. This is the positive control that the JS is
  app-data code **and** the negative proof that it is not a boot loader.
* **T9 update** — APK in `files/`, `k1.d` set; cold boot; no session/prompt;
  foreign signature rejected.
* **T10 backup/import** — prefs/media only.

All tests are planned; **no device result is claimed in this note**.

---

## 11. What would change the conclusion

1. A way to make `System.loadLibrary("tmessages.49")` fail from app data
   (arms the `ks` fallback).
2. A way to keep the ART app image valid across an install-path change
   (makes the ART image update-surviving).
3. A boot/service path that calls `WidgetSandboxNative.create` (turns the
   widget JS bundle into a startup loader).
4. A Telegram-owned parser that transitions from data to `DexClassLoader`,
   `System.load`, `dlopen`, `Runtime.exec`, or `app_process` — none found in
   72799 smali/native.

Until one of those exists, the honest answer is: **no Telegram-owned app-data
format executes code at boot; only the ART image and the gated `ks` local
library do, and both are prior work.**

---

## 12. Follow-up: local document/image parsers (archives, PDF, JPEG/IPP, other images)

Date: 2026-11-03. This pass covers the local document/image formats that were
not in the first matrix. The premise “a local `cache4.db` message can reference
an arbitrary media/document file; the first RCE can write it” is assumed. The
question is which **app-bundled** parser consumes that local file and whether
it gives **write/RCE** (not path traversal or DoS).

**Verdict: no new app-code write/RCE.** Three of the premises are false leads:

* **No RAR/7z parser.** `Rar@` is at offset `0x182ae1f` **inside `.text`**
  (`0x733c80..0x18b13ac`), bytes `52 61 72 40` embedded in AArch64
  instructions, with **no xref**. The `7z` strings (`0x347419`, `0x351011`,
  `0x396f7c`) are `.rodata` bytes in high-entropy tables, no xrefs. The binary
  has **zero** hits for `Rar!\x1a\x07`, `7z\xbc\xaf\x27\x1c`, or `PK\x03\x04`;
  no `unrar`/`libarchive`/`minizip`/`libzip` strings or symbols. Only Java
  `java.util.zip` exists: APK extraction (`NativeLoader.java:61-65`) and
  user-initiated history/theme zip import (`SendMessagesHelper.java:9222-9255`,
  `LaunchActivity.java:3677-3705`), which strips the path to the last
  component. `.rar`/`.7z` documents open externally via `ACTION_VIEW`
  (`AndroidUtilities.java:4190-4265, 4280-4345`). The unrar/7z/minizip CVEs
  (CVE-2026-14191, CVE-2024-11477, CVE-2023-45853) are **not reachable**.
* **No built-in PDF viewer.** `PdfRenderer`, `pdfium`, and `mupdf` are absent
  from all four smali trees and `src/main/java`; `application/pdf` is not a
  Telegram smali string. `.pdf` is only an icon category
  (`AndroidUtilities.java:1472`, `i0.smali:29801`). Documents use
  `ACTION_VIEW` + `FileProvider`; a system/external PDF viewer runs in another
  process, not UID 10357. MuPDF CVE-2026-3308 / PDFium CVE-2026-6361 are
  external-app/OS issues, not app-data code.
* **No Intel IPP JPEG library.** `"Intel(R) JPEG Library, version 1"` at
  `0x29ccd2` has one xref, `0x12401e4` in `sub_123FC44`, which is FFmpeg’s
  **MJPEG comment parser** (`libavcodec/mjpegdec.c:2183`):
  `strncmp(cbuf, "Intel(R) JPEG Library, version 1", 32)` sets
  `s->flipped = 1`. It is a JPEG **COM marker**, not an IPP codec. FFmpeg’s
  `mjpeg` decoder is compiled (`jni/prebuild/build_ffmpeg.sh:303`), but local
  JPEG documents/thumbnails use `BitmapFactory`/Skia
  (`ImageLoader.java:1202, 1264, 1273, 1304, 3899-4100`), not FFmpeg. FFmpeg
  `mjpeg` is reached only if the bytes are an **MJPEG video stream**.
* **JPEG XL/JPEG2000 are descriptors only.** `jpeg2000`
  (`0x220e04`), `V_JPEG2000` (`0x31af48`), `jpegxl` (`0x24c2bc`),
  `jpegxl_anim` (`0x29c80b`), and `image/jxl` (`0x2403ed`) have data-table
  xrefs only (`0x1909d68`, `0x190bd48`, `0x190bfe8`, `0x190f348`), not code
  functions. The compiled registry is only
  `gif h263 h264 hevc mjpeg mpeg4 aac alac flac mp3 libdav1d libopus libvpx
  libvpx-vp9` for decoders and `aac gif matroska mov mp3 ogg` for demuxers
  (`notes/ida_media_parsers_72799.md:57-78`;
  `jni/prebuild/build_ffmpeg.sh:300-323`). No `jpeg2000`/`jpegxl` decoder and
  no `jpegxl_anim` demuxer. CVE-2025-9951 (JPEG2000 OOB write) and
  CVE-2025-70103 (libjxl PNM extras) are not reachable.
* **HEIF/AVIF are system decoders.** The `HEIF` strings are FFmpeg `mov.c`
  container logs (`mov.c:2144, 10438, 10635, 10666`; native
  `sub_11285AC`/`sub_112C750`), not `libheif`. The mov demuxer parses
  `avif/heic/heif` brands (`mov.c:11844`), but a still image is not sent to
  FFmpeg. `MessageObject.canPreviewDocument` allows `image/heic` on SDK ≥ 26
  (`MessageObject.java:6944`); `ImageLoader` uses `BitmapFactory`
  (`ImageLoader.java:1202-1304`), i.e. **platform** libheif/Skia in the app
  process. No app `libheif`/`libavif`/`libjxl` strings/symbols. AVIF is not in
  `canPreviewDocument`; its MIME strings are MimeTypeMap/Exif utilities.
  libheif CVE-2026-84383/CVE-2026-32740 and libavif CVE-2025-48174 are OS
  library issues, not app-data code.
* **SVG is the one live local app-code parser.** `ImageLoader.java:887-903`
  routes `IMAGE_TYPE_SVG` to `SvgHelper.getSvgBitmap`; `:3175-3211` sets it
  for a `.svg` document or `application/x-tgwallpattern`.
  `MessageObject.canPreviewDocument` gates `.svg` document preview on
  `BuildVars.DEBUG_PRIVATE_VERSION` (`MessageObject.java:6947-6951`);
  wallpattern is unconditional. `SvgHelper.java:498-512` uses
  `SAXParserFactory`/`SAXParser`/`XMLReader` with **no** `setFeature`,
  `EntityResolver`, or doctype hardening. The AndroidSVG 1.2.2 XXE advisory
  (GHSA-g556-x5vx-qh59) matches the code pattern, but on Android 13 the
  platform `ExpatReader` blocks external entities; §13 has the device proof.
  The native litehtml SVG renderer is for widget/Instant View HTML, not local
  `.svg` files.

### 12.1 Ranking by write/RCE × local reachability

| Rank | Surface | Local reach | Code location | Write/RCE? | Verdict |
|---|---|---|---|---|---|
| 1 | System HEIF/HEIC via `BitmapFactory` | chat document preview SDK≥26 | platform libheif/Skia in app process | possible **platform** CVE | OS patch test; not app-data code |
| 2 | System JPEG/PNG/WebP via `BitmapFactory` | photo/document/thumbnail | platform Skia | possible **platform** CVE | OS patch test; not app-data code |
| 3 | SVG `SvgHelper` | `.svg` doc (debug-private)/wallpattern | app Java | external entities blocked by ExpatReader; internal DoS only | data parser; no write |
| 4 | FFmpeg MJPEG | MJPEG **video** only | app native | no current write/RCE CVE identified | local JPEG not this path |
| 5 | FFmpeg GIF/WebM/AV1/VP9 | animated media/video | app native | prior fuzz: no write/RCE; DoS | prior no-go |
| 6 | PDF | external app only | not Telegram | external MuPDF/PDFium CVEs | not app-data code |
| 7 | Archives | external app / Java import | no native parser | unrar/7z/minizip CVEs not reachable | no-go |
| 8 | JPEG XL/JPEG2000 | no decoder | descriptors only | CVEs not reachable | no-go |
| 9 | AVIF | not previewed | platform only | platform CVE only | not app-data code |

**No app-code write/RCE.** The only plausible app-process memory corruption is
an **unpatched system image decoder** (HEIF/JPEG/PNG/WebP); that is an OS
issue, not a Telegram format loader.

### 12.2 CVE map (reachability first)

| CVE/advisory | Component | Type | Live in 72799? |
|---|---|---|---|
| CVE-2026-14191 | UnRAR RAR5 recovery volume | heap OOB write → RCE | **no unrar** |
| CVE-2024-11477 | 7-Zip Zstandard | integer underflow → OOB write → RCE | **no 7z** |
| CVE-2025-11001/11002 | 7-Zip ZIP symlink | path traversal (extraction RCE) | **no 7z** |
| CVE-2023-45853 | zlib minizip `zipOpenNewFileInZip4_64` | integer overflow → heap write (ZIP write API) | **no minizip** |
| CVE-2026-3308 | MuPDF `pdf_load_image_imp` | integer overflow → OOB write | **no PDF parser** |
| CVE-2026-6361 / CVE-2026-87585 | PDFium | heap OOB write / double free | **no PDF parser** |
| CVE-2025-9951 | FFmpeg JPEG2000 `cdef` | heap OOB write | decoder **not built**; fixed 8.0 |
| CVE-2026-8461 | FFmpeg MagicYUV | OOB write → RCE | decoder **not built**; fixed 8.1.2 |
| CVE-2026-70628 | FFmpeg DVB subtitle/WTV | OOB write | WTV demuxer **not built** |
| CVE-2025-70103 | libjxl PNM extras | heap OOB write | **no libjxl**; PNM extras not JXL |
| CVE-2026-84383 / CVE-2026-32740 | libheif | heap OOB write | **no app libheif**; OS only |
| CVE-2025-48174 | libavif | integer overflow → buffer overflow | **no app libavif**; OS only |
| GHSA-g556-x5vx-qh59 | AndroidSVG 1.2.2 | XXE / DoS / file read | **local SVG**, but Android 13 ExpatReader blocks external entities; no ACE |

### 12.3 Device tests

Add T11–T17 in `lab/appdata_code_formats/device_plan.md`:

* **T11 archives**: `.rar`/`.7z`/`.zip` document → external `ACTION_VIEW` or
  Java import; no `unrar`/7z/`libarchive` log; no app crash.
* **T12 PDF**: `.pdf` document → external viewer; no `PdfRenderer`/pdfium in
  Telegram; no app crash.
* **T13 JPEG/IPP**: JPEG with Intel COM marker + malformed JPEG → 
  `BitmapFactory`/Skia; no `mjpegdec` in Telegram log.
* **T14 HEIC/AVIF/JP2/JXL** → HEIC system `BitmapFactory`; AVIF not previewed;
  JP2/JXL no preview.
* **T15 SVG**: external entity/entity expansion (wallpattern path) → SvgHelper
  parses; observe file read/DoS; no code marker.
* **T16 MJPEG video** → FFmpeg `mjpeg` only if video path selects it.
* **T17 zip import** → path components stripped; no outside write.

No device was used in this pass; these are planned tests.

### 12.4 Bottom line

`Rar@`, `7z`, and `Intel(R) JPEG Library` are **static-string false leads**
(`.text` bytes / unreferenced `.rodata` / FFmpeg COM marker). There is no
built-in PDF viewer, no app RAR/7z parser, no app JPEG XL/JPEG2000/AVIF
decoder, and no Intel IPP. The only live local app-code image parser is Java
`SvgHelper`; external entities are blocked by `ExpatReader` (internal
expansion DoS only); the only plausible memory corruption
is an unpatched **system** HEIF/JPEG/PNG/WebP decoder, which is an OS issue,
not a Telegram app-data loader.

Full evidence and refs: `lab/appdata_code_formats/local_media_parsers.md`,
`scans/archives.txt`, `scans/pdf.txt`, `scans/jpeg_ipt.txt`,
`scans/other_images.txt`, `scans/svg_java.txt`, `scans/ffmpeg_registry.txt`.

---

## 13. SVG XXE deep dive (GHSA-g556-x5vx-qh59)

Date: 2026-11-03. This section answers whether the local `SvgHelper` parser is
actually XXE-exploitable on the target, and whether a crafted SVG can leak
`/proc/self/maps` or reach a LAN C2 without user action.

### 13.1 Exact parser setup

`SvgHelper.getSvgBitmap(File,...)` and `getBitmap(File,...)` both use:

```java
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser sp = spf.newSAXParser();
XMLReader xr = sp.getXMLReader();
SVGHandler handler = new SVGHandler(...);
xr.setContentHandler(handler);
xr.parse(new InputSource(stream));
```

Source: `SvgHelper.java:480-496` (`getBitmap(File,...)`) and
`:498-512` (`getSvgBitmap(File,...)`). The smali class is
`org.telegram.messenger.e00`; the file/stream parser method is `e00.m(File,IIZ)`
(`e00.smali:3897-3975`) and the `getBitmap` variant is `e00.f(File,III)`
(`:3204`). There is **no** `setFeature`, `setEntityResolver`,
`disallow-doctype-decl`, `external-general-entities=false`, or
`ACCESS_EXTERNAL_DTD` call in `SvgHelper.java` (grep in
`scans/svg_java.txt`).

### 13.2 Is the bundled AndroidSVG code vulnerable?

The code is Telegram's AndroidSVG-derived `SvgHelper`; the upstream advisory
GHSA-g556-x5vx-qh59 names AndroidSVG 1.2.2. The **code pattern** is the one
the advisory describes: an unconfigured `SAXParserFactory`.
On **desktop Java** with a permissive SAX provider this would be XXE. On
**Android 13**, the platform provider is not permissive:

* `SAXParserFactory.newInstance()` returns
  `org.apache.harmony.xml.parsers.SAXParserFactoryImpl`;
* `newSAXParser().getXMLReader()` returns
  `org.apache.harmony.xml.ExpatReader`;
* `ExpatReader.getFeature()` returns **false** for
  `http://xml.org/sax/features/external-general-entities` **and**
  `.../external-parameter-entities`;
* `ExpatReader.setFeature(name, true)` for those features throws
  `SAXNotSupportedException("Cannot enable " + name)`;
* `ExpatParser.handleExternalEntity()` returns immediately when
  `entityResolver == null`; `SvgHelper` never sets one, so it does not open a
  file or URL. The source comment explicitly says it does not download
  external entities because that would be a security risk for untrusted XML.

AOSP references:
`ExpatReader.java` (`getFeature`/`setFeature`), `ExpatParser.java`
(`handleExternalEntity`), `SAXParserFactoryImpl.java`; excerpts in
`lab/appdata_code_formats/scans/svg_parser_aosp.txt`.

**Verdict:** the library is “vulnerable-shaped” but **not XXE-exploitable on
this Android 13 target**; the gate is the platform SAX provider, not a
Telegram fix. Internal entity expansion is a separate DoS class (the parser
does expand internal entities); it is not a file-read/C2 primitive.

### 13.3 Device proof (Sony XQ-BT52, Android 13, 2026-11-03)

The probe uses `app_process` with the app APK on `CLASSPATH`; it calls the
real app class `e00.m` (`SvgHelper.getSvgBitmap`) and a direct
`SAXParserFactory`/`XMLReader` probe. It does not inject into the Telegram
process.

| Probe | Result |
|---|---|
| parser features | `external-general=false`, `external-parameter=false`, `validation=false` |
| `file:///proc/self/maps` in `<text>&xxe;</text>` | `parse=ok chars=7`; `/proc/self/maps` is **13,695 B** → no file content |
| `file:///data/local/tmp/xxe_color` in `fill="&xxe;"` | `ExpatParser$ParseException: reference to external entity in attribute` |
| `http://<LAN_IP>:18080/xxe-lan` in text | `parse=ok chars=7`; host listener log **empty** |
| external DTD `http://<LAN_IP>:18080/evil.dtd` | `parse=ok chars=10`; host listener log **empty** |
| app `SvgHelper` (`e00.m`) on maps text | returns `b00`/bitmap; no maps content; no parser-driven file read |

Raw output: `lab/appdata_code_formats/svg_xxe/results_sony_20261103.txt`;
empty listener logs: `lan_httpd_no_request.log`,
`dtd_httpd_no_request.log`.

**Cleartext/network policy:** `usesCleartextTraffic=true`
(`manifest_72799_full.txt:234`) and there is no `networkSecurityConfig`, so
`http://<LAN_IP>` is permitted at the network layer. A control request from
the device (`<LAN_IP>`) to the host (`<LAN_IP>:18080`) returned
HTTP 404 and appeared in the host log (`svg_xxe/lan_control_20261103.txt`).
Therefore the empty XXE logs are a **parser gate**, not a network gate.

**No `/proc/self/maps` leak, no libc/libtmessages ASLR bases, no C2, no TGS
coordination.** The content never reaches the `SvgHelper` handler; there is no
string to exfiltrate.

### 13.4 App reachability: when is `SvgHelper` actually called?

* **Boot A (no user action): no SVG parse.** `AppStartReceiver` →
  `NotificationsService` → `w0.w` has no `Theme`/`SvgHelper` reference
  (grep in `scans/svg_java.txt`); the boot service does not load wallpapers or
  document previews.
* **Cold B (app launch, no chat/document tap): conditional SVG parse.** If the
  current theme/accent has a wallpaper document with MIME
  `application/x-tgwallpattern`, `LaunchActivity.java:556` calls
  `Theme.loadWallpaper(true)`; `Theme.loadWallpaper` (`Theme.java:9268`) →
  `loadWallpaperInternal` (`:9324`) → `createBackgroundDrawable` (`:9353`) →
  `SvgHelper.getBitmap(f,...)` (`:9452`) when `wallpaperDocument != null`
  (`:9285`). This runs after the launcher starts Telegram, before any chat or
  document preview.
* **Theme/pattern application:** `Theme.createWallpaperForAccent`
  (`Theme.java:423`) parses an SVG pattern when an accent pattern is
  loaded/applied through `PatternsLoader` (`:245-298`).
* **Document preview (UI C):** `ImageLoader.java:887-903` routes
  `IMAGE_TYPE_SVG` to `SvgHelper.getSvgBitmap`; `:3175-3211` sets the type for
  a `.svg` document or `application/x-tgwallpattern`. `MessageObject.java:6944`
  allows `.svg` document preview only under `DEBUG_PRIVATE_VERSION`;
  wallpattern is unconditional.
* **`cache4.db` / `files`:** a crafted `.svg` document in a message is parsed
  only when its document preview/chat is opened. A crafted wallpattern is
  parsed at `LaunchActivity` **only if it is the current theme's wallpaper
  document**; a random file in `files/` is not scanned at boot. Neither is a
  `BOOT_COMPLETED` path.

So the answer to “wallpaper/background/pattern or only document preview?” is:
**not at boot; yes at normal app launch for the current SVG wallpaper pattern;
document `.svg` only on preview/chat.**

### 13.5 If it had worked

It did not; no file content, no C2 request. There is no `/proc/self/maps` leak
and therefore no ASLR base leak to combine with the TGS UAF. Do not coordinate
a leak with the TGS agent on this result.

### 13.6 Exact gate / what would reopen it

The gate is `ExpatReader`’s hard-coded `false` for external general/parameter
entities and `ExpatParser`’s `entityResolver == null` early return. It would
reopen only if:

1. a future Android/OEM `SAXParserFactory`/`XMLReader` provider enables
   external entities by default (not this Sony build);
2. Telegram sets an `EntityResolver` or `setFeature(..., true)` (it does not);
3. a different parser path (not `SvgHelper`) is introduced for local SVG.

Internal entity expansion (Billion Laughs class) remains a possible **DoS**;
it is not a file-read, ASLR leak, or ACE.

Lab: `lab/appdata_code_formats/svg_xxe/` (`README.md`, probes, SVGs, device
results, control logs); device plan T15a–T15e in
`lab/appdata_code_formats/device_plan.md`.

---

## 14. Lab index

* `lab/appdata_code_formats/README.md`
* `lab/appdata_code_formats/ranked_table.md`
* `lab/appdata_code_formats/format_matrix.csv`
* `lab/appdata_code_formats/startup_paths.md`
* `lab/appdata_code_formats/no_go.md`
* `lab/appdata_code_formats/device_plan.md`
* `lab/appdata_code_formats/evidence_refs.md`
* `lab/appdata_code_formats/local_media_parsers.md`
* `lab/appdata_code_formats/svg_xxe/` — SVG XXE probes, device results, LAN control
* `lab/appdata_code_formats/scans/` — `loader_primitives.txt`,
  `startup_boot_path.txt`, `cache4_sqlite.txt`, `tgnet_dat.txt`,
  `shared_prefs.txt`, `language_xml.txt`, `theme_attheme.txt`,
  `tgs_lottie.txt`, `widget_bundle.txt`, `updater_apk.txt`,
  `backup_import.txt`, `native_load_exec.txt`, `wasm_embedded.txt`,
  `webview_startup.txt`, `art_appimage.txt`, `package_installer.txt`,
  `boot_other_reads.txt`, `archives.txt`, `pdf.txt`, `jpeg_ipt.txt`,
  `other_images.txt`, `svg_java.txt`, `ffmpeg_registry.txt`, `ida_media_xrefs.txt`,
  `svg_parser_aosp.txt`
* `lab/appdata_code_formats/scripts/verify.sh` — read-only anchor check.
