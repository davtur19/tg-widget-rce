# Local app-data persistence with the existing class-64 RCE: forged ART app image → startup code execution

Date: 2026-11-02
Target: `org.telegram.messenger.beta` 13.2.0 beta, versionCode **72799**, arm64,
Sony **XQ-BT52** (Xperia 10 III), Android 13, build **62.2.A.0.533**, UID **10357**.
Scope: **host/static originally; DEVICE-PROVEN 2026-11-03.** See
`notes/loader_art.md` §0 for the successful device run (forged
`cache/oat_primary/arm64/base.art` → forged `ks.<clinit>` → `System.load` of
an app-data `.so`; marker on cold start and on the `AppStartReceiver` boot
path; app alive). The widget/QuickJS/qbc/TGS paths are excluded by
instruction. The main report (`telegramandroidwidget/REPORT_20261102.md`) is
updated with the device result.

## 0. Verdict

**Concrete candidate found: replace the app-writable ART app image
`cache/oat_primary/arm64/base.art` with a valid one-class image whose
`org.telegram.messenger.ks` class initializer executes attacker Dalvik
bytecode.** On the next app process start, `w0.onCreate()` calls
`ks.g(Context)` before `ConnectionsManager.native_setJava()`; class
initialization runs the forged `ks.<clinit>`, which executes
`Runtime.getRuntime().exec(...)` as UID 10357, then returns to the real
`ks.g`, which loads `libtmessages.49` and lets normal startup continue.

This is exactly the published “Counterfeit ART” app-image technique
(WOOT’26, CVE-2026-28664): the app image is app-private/app-writable, is
mapped/relocated by ART at every app start, and a crafted image can redirect a
class/method to attacker-controlled code. It is **not** QuickJS, not qbc, not a
widget, not the `.so` fallback, and needs no root.

Status of the PoC:

* **Proven on the host:** the target image is image version **119**; its header
  and object offsets match the live Sony tombstone mappings byte-for-byte; the
  generator produces an image that passes the ART layout checks listed in
  `validate_image.py` (header, uncompressed layout, bitmap size, Class,
  ArtMethod, ArtField overlay, ClassTable hash slot, code item).
* **DEVICE-PROVEN (2026-11-03):** the forged image is accepted, the forged
  `ks.<clinit>` runs, `System.load` of an app-data `.so` succeeds, the marker
  is written on cold start and on the `AppStartReceiver`/`org.telegram.start`
  boot path, and the app continues (`loaded normal lib`, process alive). The
  first run needed the v4 field-layout fix (two dummy `ArtField`s so the
  methods header no longer overwrites `ks.h`/`ks.i`). See
  `notes/loader_art.md` §0. The image is reboot-persistent; `install -r`
  invalidates it (new `/data/app/~~…` code path), and a re-generated image
  from the post-update `base.art` is device-proven.
* The earlier “corrupt base.art” negative is not a refutation: zeroing the
  first 4 KiB invalidates `ImageHeader::IsValid()` (magic/version), so ART
  rejects the image before any of the logic used here. The PoC keeps a valid
  header, boot checksum, DexCaches and OatHeader.

## 1. Why this is a startup trigger, not a generic app-data write

### 1.1 The app image is loaded at process start

The device tombstone for the 72799 app shows the exact image:

```
# telegramandroidwidget/evidence/evidence_20261101/startup_db/tombstone_07:593
00000000'6a000000-00000000'6a4a3fff rw- 0 4a4000
  [anon:dalvik-/data/user/0/org.telegram.messenger.beta/cache/oat_primary/arm64/base.art]

# same file:2485
0000007a'f2c05000-0000007a'f2c10fff r-- 150000 c000
  /data/data/org.telegram.messenger.beta/cache/oat_primary/arm64/base.art

# UID of the process: tombstone_07:9
uid: 10357
```

The anonymous mapping size **0x4a4000** and the file mapping at offset
**0x150000**/size **0xc000** are exactly the target image’s
`image_reservation_size` and image-bitmap section (see §2.2). The image is
therefore not a dormant file: ART maps it and uses it for the app class loader.
The same mappings appear in `new_beta_72799/tombstone_20.txt:386,2926` and the
size-sweep tombstones.

AOSP loading path (ART 17 source, which is the source matching image version
119; see §2.1):

* `runtime/gc/space/image_space.cc:1069` `ImageSpace::Loader::Init` reads and
  validates the header (`:1078-1083`), checks the file size/data/bitmap layout
  (`:1107-1120`), maps/decompresses the image (`:1122-1180`), and creates the
  live bitmap (`:1165-1180`).
* `runtime/class_linker.cc:2096` `ClassLinker::AddImageSpace` handles an app
  image (`app_image = class_loader != nullptr`, `:2103`), validates the image
  roots and runtime-image special root (`:2117-2248`), reads the class table
  (`:2362-2375`), and adds it to the app class loader.
* `runtime/class_linker.cc:6197-6203` `InitializeClass` invokes a class
  initializer directly: `clinit = klass->FindClassInitializer(...)` then
  `clinit->Invoke(...)`. This is the path used by the PoC; it does **not** go
  through the interpreter’s `FindMethodToCall()`/`IsInvokable()` check
  (`runtime/entrypoints/entrypoint_utils-inl.h:598-601`), which would reject an
  abstract method.

The app starts this process at boot too: `AndroidManifest.xml:384-388`
declares `org.telegram.messenger.AppStartReceiver` for
`android.intent.action.BOOT_COMPLETED`; the receiver starts the process, so
`ImageSpace` loading and `ApplicationLoaderImpl.onCreate` run at boot.

### 1.2 The trigger is before native load

The 72799 jadx source (`.scratch_beta1320` / `jadx72799_c1`) shows:

* `org/telegram/messenger/w0.java:414` is `onCreate()`, and `:457` calls
  `ks.g(f13920b)`; `:315` is the same call from `w0.w()` used by receivers.
* `org/telegram/messenger/ks.java:138` is `public static synchronized void g(Context)`.
  Its normal body calls `System.loadLibrary("tmessages.49")` at `:151` (and
  again at `:232`); it catches `Error` and may try `files/lib/libtmessages.49loc.so`
  at `:188,196`. The `ks` class is therefore the NativeLoader class itself.
* `w0.onCreate` calls `ks.g` **before** `ConnectionsManager.native_setJava(false)`
  (`w0.java:459`), so a forged `ks.<clinit>` runs before the normal native
  library load. This is the key difference from the tested
  `mainconfig.xml` OOM negative: that OOM happens after `loaded normal lib`;
  our trigger is earlier.

`ks` is the right class because it is loaded/initialized exactly at this call.
`w0` itself has no `<clinit>`; `ApplicationLoaderImpl` has no static fields; a
forged `w0.onCreate` would require overwriting a critical method and would not
let normal startup continue. `ks.<clinit>` is a direct ART class-initializer
call, and the real `ks.g` remains available afterwards.

The real `ks` class is present in the app image (not only in dex); its data is
used to build the fake class:

| item | value (image offset unless noted) |
|---|---|
| `ks` Class object | `0x190800` (`0x730e8800` runtime address) |
| `ks` DexCache | `0x140` (`0x72f58140`) |
| `ks` methods array | `0x3c2aa0`, 16 entries |
| `ks.<clinit>` ArtMethod | `0x3c2aa8`, dex idx **38721**, access `0x10391008`, entry `0x722b0070` |
| `ks.g` ArtMethod | `0x3c2b88`, dex idx **38728**, access `0x103a0009`, entry `0x722b0050` |
| `ks` fields array | `0x2ff41c`, 9 entries |
| runtime-image special root (`byte[]` OatHeader) | `0x4f8`, length `0xc74` (ends `0x1178`) |

The real `w0.onCreate` method is **interpreted** in the captured image: its
ArtMethod entry is `0x722b0070`, not an AOT entry. That matters: if we replaced
`ks.g` with an abstract method (the artifact’s generic pattern), the
interpreter’s `FindMethodToCall()` would throw `AbstractMethodError` before
calling it (`entrypoint_utils-inl.h:598-601`). The PoC therefore triggers
`ks.<clinit>` instead, which `InitializeClass` calls directly.

### 1.3 The image is app-writable

`cache/oat_primary/arm64/base.art` is in the app’s private data directory; the
process UID is 10357 and the existing class-64 RCE already writes app data and
runs shell commands as that UID. The file is ordinary app data, so no root,
SELinux transition, or package-manager operation is involved. The image is read
at every process start; replacing it persists across app restart and reboot
(until an app/ART update regenerates it; see §6).

### 1.4 The other local app-data surfaces (checked, not code loaders)

The launch-read audit is in `notes/startup_appdata_full_audit_20261102.md`;
the short version relevant to *code execution* is:

| surface | what happens | verdict |
|---|---|---|
| `cache/oat_primary/arm64/base.art` | ART app image; mapped/relocated at every app start; `ClassTable`, `Class`, `ArtMethod` visitors | **only app-data file that is executable metadata; this PoC** |
| `/data/app/.../oat/arm64/base.odex`, `base.vdex` | AOT code; read-only `/data/app`, not app-writable | no write path without root |
| `files/lib/libtmessages.49loc.so` | only loaded after `System.loadLibrary` throws (`ks.java:151,196`) | root-gated fallback; the tested negative |
| `code_cache/oat_primary`, `profileinstaller` | profile/app-image cache bookkeeping; profile file is not code | no code load |
| AndroidX Startup / EmojiCompat / ProfileInstaller / Firebase / MLKit providers | APK code/assets; EmojiCompat uses a system font provider; ProfileInstaller writes a profile | no app-data `.so`/dex load |
| `FileProvider` provider paths | `res/xml/provider_paths` is an APK resource | no app-data code |
| `shared_prefs/*.xml` | theme/language/update paths; `beta` update is user-gated `ACTION_VIEW` install | no automatic code load |
| `files/*.attheme`, theme wallpapers | Java parser + platform `BitmapFactory` | system codec (libwebp CVE is a separate candidate), not app-native code |
| `files/remote_<code>.xml`, `files/malformed_locales/*` | framework `Xml.newPullParser`; values become format strings | Java/framework, DoS only |
| `files/stats2.dat` | `StatsController.java:146` `RandomAccessFile`, fixed 8-byte reads | data only |
| `files/tgnet.dat`, `files/dc<id>conf.dat`, `files/cdnkeys.dat` | native `Config`/`Datacenter` parsers; huge counts are OOM/DoS; `cdnkeys.dat` load path is commented out in `Handshake.cpp:946` | no code execution found |
| `files/cache4.db` | SQLite 3.39.3 schema/triggers/views; `#define SQLITE_OMIT_LOAD_EXTENSION 1` (`sqlite3.c:158`); S1/S2 are crash/DoS | no extension loader, no clean RCE |
| `files/secureid_ocr_nn.dat` | not app data: `secureid_ocr.cpp:581` opens `AAssetManager_open(assets, "secureid_ocr_nn.dat", ...)` | APK asset, not writable |
| `files/voip_*`, `cache/*` | JSON/log/cache data | no code load |

The important result is negative for the alternatives and positive for the app
image: `base.art` is the only *app-writable* file that ART treats as executable
metadata and processes before the app’s own `onCreate`.

## 2. Target image facts

### 2.1 ART image version 119

The captured target image is:

```
$ md5sum base.art
2bbe67262f52c767e639f5a137a76a89  base.art
```

Its `ImageHeader` is magic `art`, `version "119\0"`, pointer size 8,
`image_begin 0x72f58000`, `image_size 0x4a0978`,
`image_reservation_size 0x4a4000`, `image_roots 0x72f58108`,
`boot_image_begin 0x70c0c000`, `boot_image_size 0x234c000`,
`boot_image_component_count 0x26`, `boot_image_checksum 0x7c37c4a0`.
Image version **119** is the ART source version in the `android17-release`
branch: `runtime/oat/image.cc:39`
`const uint8_t ImageHeader::kImageVersion[] = { '1','1','9','\0' };`.
The Android 13 / Android 14 / Android 15 tags are versions 106/108/111, so the
Sony’s Mainline ART module is the version-119 source; using the Android 13
tree’s class layout would be wrong. The layout checks below use the
`android17-release` tree.

### 2.2 Header/file layout matches the live mappings

The image file is LZ4-block-compressed. Header fields (parsed with the WOOT’26
`art.py`):

* `image_reservation_size = 0x4a4000` — matches the anonymous mapping size in
  `tombstone_07:593` / `tombstone_20:386`.
* image-bitmap section `offset 0x150000`, `size 0xb080` — matches the file
  mapping `offset 0x150000`, `size 0xc000` in `tombstone_07:2485` (the extra
  page is the mapping alignment; the section itself is `0xb080`).
* `data_size = 0x14c6ac`, `blocks_offset = 0x14c6ec`, ten LZ4 blocks.
* The runtime-image special root is a `byte[]` at `0x4f8`, length `0xc74`,
  containing an `OatHeader` magic `oat\n` and version `275`; its end is
  `0x1178`. This is why the PoC copies the prefix through `0x1178`, not just
  the 0xF18 bytes used by the generic Chrome template.

The target image has `oat_checksum = 0`, `oat_file_begin/data... = 0`, and
`image_checksum = 0`. `ImageHeader::IsValid()` (`runtime/oat/image.cc:145-171`)
therefore skips all oat field checks, and the loader’s checksum comparison is
against the copied boot image checksum, not a guessed one. The app’s real
`base.odex`/Vdex and real DexCache locations are still used via the copied
DexCache prefix.

### 2.3 classes.dex indices used by the payload

The forged class is `Lorg/telegram/messenger/ks;` in `classes.dex`:

| item | index |
|---|---|
| class_def_idx | 5862 |
| type_idx | 7366 |
| `ks.<clinit>` method_idx | 38721 |
| `ks.g` method_idx | 38728 |
| `[C` type | 15614 |
| `String` type | 5208 |
| `[Ljava/lang/Class;` | 15964 |
| `[Ljava/lang/Object;` | 15971 |
| `Class` type | 5162 |
| `String.<init>([C)V` | 25992 |
| `Runtime.getRuntime()` | 25968 |
| `Object.getClass()` | 25950 |
| `Class.getDeclaredMethod(String,Class[])` | 25760 |
| `Method.invoke(Object,Object[])` | 26213 |

`ks.g` is `(Landroid/content/Context;)V`; the payload is in `ks.<clinit>` (no
arguments), so its code item uses `ins_size=0`. The bytecode only uses
`classes.dex` type/method/string indices; the fake class’s `dex_cache_` points
at the real `classes.dex` DexCache at image offset `0x140`.

## 3. The candidate in detail

### 3.1 Image layout

The generator writes an **uncompressed** image (storage mode 0; `blocks_count=0`),
which ART supports (`ImageHeader::Block::Decompress`, `runtime/oat/image.cc:221-229`;
`ImageSpace::LoadImageFile` handles the uncompressed case). This removes the
LZ4/block-table complexity; the file layout is:

```
0x0000  ImageHeader (0x108 bytes: fields + 13 sections + 9 image methods + tail)
0x0108  object prefix copied from the target (image roots, 4 DexCaches,
        location strings, special-root byte[] OatHeader), through 0x1178
0x1178  fake ks Class (112 bytes + 0x90 bytes class static storage)
0x1208  copied real ks fields array (4 + 9*16 = 148 bytes; ends 0x129c)
0x1288  copied real ks methods array (8 + 16*32 = 520 bytes); it starts
        inside the fields array so method 0's data word aliases the fake field
0x129c  fake ArtField array (length 1 + one 16-byte ArtField); it sits at
        method 0 + 20 and its declaring_class_ is method 0's data word
0x1490  clinit code item (code_item + instruction payload)
0x15b0  one-entry ClassTable HashSet
0x1600  end of image (image_size)
0x2000  image bitmap (0x50 bytes; file end 0x2050)
```

(Values are for the captured image; the generator derives the class/method/
field offsets from the input image and the counts from `classes.dex`, so a
different but same-version `base.art` is handled.)

### 3.2 Fake Class and ClassTable

The fake `Class` is a 112-byte copy of the real ks Class with these changes:

* `dex_cache_` = real classes.dex DexCache (`image+0x140`);
* `dex_type_idx` = **7366** (ks), so `GetDescriptor()` and `DescriptorHash()`
  still name `Lorg/telegram/messenger/ks;`;
* `dex_class_def_idx` = **285** (`Landroid/support/v4/media/a;`), a class
  def with **zero static fields**, 16 direct methods, superclass
  `java.lang.Object` and no interfaces. This is deliberate: `Class::HasStaticFields()`
  reads the class def (`runtime/mirror/class-inl.h:1212-1217`), and
  `InitializeClass` would otherwise eagerly resolve all nine real `ks` static
  fields (`runtime/class_linker.cc:6137-6190`). The fake class’s fields array is
  a copy of the real `ks` fields (so `ks.g` can access `f11757a`/`f11758b`), but
  the class-def substitution skips the eager static-field loop. The class def
  also reports **16 declared methods**, exactly matching the copied methods
  array, so `FindClassInitializer()` scans method 0 (the forged `<clinit>`) and
  `FindDeclaredClassMethodFast()` (`runtime/mirror/class-inl.h:1426-1470`)
  resolves the real `ks.g` by dex index 38728.
* `status_` = `kVerified` (`0xb0000000`), so resolving `ks` does not verify it
  but `InitializeClass` runs `<clinit>`; `class_flags_ = 0x2` (no reference
  fields); `class_size_ = 0x90` covers the copied static field offsets
  (max 140); `fields_` = copied ks fields array; `methods_` = copied ks methods
  array; `iftable_ = 0`, `vtable_ = 0` (no interfaces/vtable needed);
  `access_flags_ = 0x401` (public abstract, same as the real ks class).

The ClassTable is a `HashSet` header + two `TableSlot` buckets
(`runtime/class_table.h`/`class_table-inl.h`):

```
num_elements=1, num_buckets=2, elements_until_expand=4, min=0.4, max=0.7
bucket[hash & 1] = (image_begin + class_off) | (hash & 7)
```

`hash = ComputeModifiedUtf8Hash("Lorg/telegram/messenger/ks;") = 0x46e7b20`
(`runtime/mirror/class.cc:1491-1516`), low bits 0, bucket 0. The image loader
forwards the 32-bit class reference in the slot (`runtime/gc/space/image_space.cc:809-820`;
`ClassTableVisitor::VisitRoot`), so the image base may be relocated.

### 3.3 The clinit method and the ArtField overlay

The copied methods array keeps the real 16 `ks` methods and their original
`data`/entry values. Only method 0 (`ks.<clinit>`) is changed:

* `access_flags_ = real 0x10391008 | 0x400` (`kAccAbstract`);
  `IsClassInitializer()` is `IsConstructor() && IsStatic()`
  (`runtime/art_method.h:217-219`), still true; `HasCodeItem()` is false
  (`runtime/art_method.h:928-936`), so the image loader will not overwrite
  `data_` with a dex code-item pointer;
* `data_` = image address of the code item; `entry_point` = the real clinit
  nterp entry `0x722b0070`;
* `declaring_class_` = fake class address.

Because `HasCodeItem()` is false, the method visitor leaves `data_` alone; the
**ArtField visitor** is used to relocate it. The image’s fields section contains
the copied real `ks` fields array followed by a one-element
`LengthPrefixedArray<ArtField>` at `method+20`: `length=1`, then an ArtField
whose `declaring_class_` field is exactly the method’s 8-byte `data_` word
(`method+24`). The loader patches
`ArtField::DeclaringClassRoot()` (`runtime/gc/space/image_space.cc:721-733`),
i.e. it treats the data word as a compressed reference and adds the image
delta. The field’s access/dex/offset words overlap the method’s entry word, but
the visitor only touches `declaring_class_`; the method entry remains the nterp
pointer.

This is the same relocation primitive described in the WOOT’26 paper
(ArtField-over-ArtMethod overlay); it is what makes the code-item pointer
correct under app-image ASLR without an info leak.

### 3.4 Execution and app continuation

`w0.onCreate` calls `ks.g`:

1. `ClassLinker::FindClass` finds the fake `ks` in the image ClassTable; its
   descriptor still comes from dex type 7366.
2. `EnsureInitialized` → `InitializeClass`; `HasStaticFields()` is false
   (class def 285), `FindClassInitializer()` finds the forged `<clinit>`, and
   `clinit->Invoke` calls the nterp interpreter on the code item.
3. The bytecode constructs the command String from a UTF-16 char array, builds
   `"exec"`, gets `Runtime.getRuntime()`, `getClass()`,
   `getDeclaredMethod("exec", [String.class])`, and invokes it with the command.
   This runs `/system/bin/sh ...` as UID 10357.
4. The clinit returns; `ks` is marked initialized. The app resolves the real
   `ks.g` (method 7, access `0x103a0009`, concrete) and runs its original body:
   `System.loadLibrary("tmessages.49")`, set `f11757a=true`, log. Normal
   `w0.onCreate` then calls `ConnectionsManager.native_setJava(false)` with the
   native library available.

The forged `ks.<clinit>` is therefore a **startup code-execution hook**, not a
crash: it runs before the normal native load and then hands control back to the
real startup path. The payload can be a shell script (proof marker), a reverse
shell, or a stage that `System.load`s an app-data native `.so`; the immediate
primitive is attacker Dalvik bytecode executed by ART’s native runtime.

## 4. Reproducer/harness

All host artifacts are under `lab/persistence_nonquickjs/`:

| path | what |
|---|---|
| `gen_payload_image.py` | generator; reads the current `base.art`, writes the forged image |
| `payload_builder.py` | minimal Dalvik code_item builder |
| `dextool_min.py` | minimal DEX index/class-data extractor used for the constants |
| `validate_image.py` | host validation of every layout invariant above |
| `payload.sh` | proof/persistence script (`id`, `date` to `files/.p_started`) |
| `sample/base_72799_original.art` | target image from the 72799 snapshot (md5 `2bbe67262f52c767e639f5a137a76a89`) |
| `sample/base_72799_fake.art` | generated sample (md5 `aae30a29b328066a96bbbbb2255427da`) |
| `vendor/art.py` | WOOT’26 ART image parser/serializer, GPL-3.0, unmodified |
| `vendor/LICENSE.artow` | GPL-3.0 license/attribution |

Generate/validate:

```bash
python3 -m venv /tmp/art-venv
/tmp/art-venv/bin/pip install pwntools lz4
cd lab/persistence_nonquickjs
/tmp/art-venv/bin/python gen_payload_image.py \
  --base-art sample/base_72799_original.art \
  --out /tmp/base_fake.art \
  --command '/system/bin/sh /data/user/0/org.telegram.messenger.beta/files/.p'
/tmp/art-venv/bin/python validate_image.py /tmp/base_fake.art
```

Observed validator result for the sample:

```
PASS  magic art
PASS  image version 119
PASS  pointer size 8
PASS  uncompressed image (blocks_count 0)
PASS  file size == bitmap offset + bitmap size
PASS  bitmap offset == RoundUp(0x108 + data_size, 0x1000)
PASS  exactly one ks Class object
PASS  fake class uses zero-static-field/16-method class def 285
PASS  ks status kVerified (class initializer will run)
PASS  copied real ks methods/fields counts
PASS  method 0 is ks.<clinit>
PASS  clinit marked abstract (HasCodeItem false)
PASS  clinit still static/constructor
PASS  g remains concrete/invokable
PASS  ArtFields section aliases method data (method+20)
PASS  fake overlay declaring == clinit data low word
PASS  class table slot == ks Class with descriptor hash bits
PASS  code_item registers/ins/outs/tries
PASS  fill-array-data @0x4 -> payload @0x70 size=64
PASS  fill-array-data @0x11 -> payload @0xf8 size=4
RESULT: PASS
```

(The exact print order of the method/field checks is in the script; the
validator exits non-zero on any failure.)

### 4.1 Exact app-data deployment

Via the existing class-64 RCE (UID 10357):

1. `cp cache/oat_primary/arm64/base.art files/.base.art.orig`; pull that file
   to the host. Keep a second host copy.
2. Write `payload.sh` to `files/.p`.
3. Generate `/tmp/base_fake.art` from the **pulled current** original. If the
   app/ART was updated since the sample, regenerate; do not reuse the sample.
4. Push to `files/.base.art.new` (mode 600), then atomically
   `mv files/.base.art.new cache/oat_primary/arm64/base.art` and `chmod 600`.
5. Force-stop the app (not `pm clear`), cold start. The next process start
   loads the forged image and runs the clinit.
6. Check `files/.p_started`; the first lines are `date` and
   `uid=10357(u0_a357)`. Check logcat for `loaded normal lib` (the real
   `ks.g` ran after the payload).
7. Restore by copying `files/.base.art.orig` back over the image and cold
   starting; verify normal chat list.

The forge is ordinary app data: it survives app restart, `am force-stop`,
recents kill, reboot, and package update (unless the update/ART change
regenerates/rejects the image). It does not require the widget sandbox, any
QuickJS bundle, a fake DC, or network.

## 5. Device test plan (not executed here)

Preconditions: device backup of `cache/oat_primary/arm64/base.art` and
`files/cache4.db`; keep the original image off-device; do not clear app data;
airplane mode optional. A failed load is fail-closed, so the restore step is
always available.

| # | Step | Success signal | Failure/diagnostic |
|---|---|---|---|
| 1 | Pull current image; run generator + validator | `RESULT: PASS` | fix/regenerate |
| 2 | Write `files/.p`; push fake image atomically; mode 600 | hash/size match | write error |
| 3 | `am force-stop`; cold start; no tap | `files/.p_started` contains `uid=10357`; logcat `loaded normal lib` | no marker; logcat `Invalid image header`, `Boot image checksum mismatch`, `Could not load runtime generated app image`, `Invalid image version` |
| 4 | Repeat kill/relaunch 3× | marker timestamp updates each start | marker only once / app crash |
| 5 | Reboot; launch app; also check `AppStartReceiver` boot start | marker updates at boot/launch | marker absent if app not started or image rejected |
| 6 | Restore original; force-stop; cold start | normal chat list | — |

If step 3 reports a checksum/version rejection: the image did not load; this is
**not** evidence of RCE or DoS. Capture the current `base.art` header and
regenerate from it. If the marker appears but the app crashes immediately,
capture the tombstone: the startup payload executed; the crash is an
after-execution stability issue (fields 7/8/class-def substitution), not a load
failure.

## 6. Critical assessment and residual risks

**What is real and proven on the host**

* The target image is version 119 and is loaded by ART at app startup; the
  live tombstone mappings match its reservation/bitmap offsets.
* The app image is app-writable and the existing class-64 RCE runs as the same
  UID.
* The generated image’s header, uncompressed file layout, bitmap, Class,
  ArtMethod, ArtField overlay, ClassTable hash slot, and code item pass the
  host validator. The technique is the published WOOT’26 app-image relocation
  attack, which the authors demonstrated for code execution on commercial
  devices.
* The clinit path is correct: `InitializeClass` invokes a class initializer
  directly (`class_linker.cc:6197-6203`), bypassing the `FindMethodToCall`
  `IsInvokable` check that would reject an abstract method. The real `ks.g` is
  concrete (`0x103a0009`) and is retained.

**What is not proven here**

* No device test (per task). The Sony may reject the image for a reason not
  modeled by the host validator; a rejected image is fail-closed.
* **Class-def substitution risk:** `dex_class_def_idx=285` is used to make
  `HasStaticFields()` false. If the target’s ART checks that
  `class_def_idx == dex_type_idx` on a ClassTable hit, the image may be rejected
  or the class resolution may fail. A future build could tighten this.
* **Field overlay risk:** the methods header and fake ArtField intentionally
  overlap fields 7 (`h`) and 8 (`i`/`f11762i`); field 6 (`f11761g`) stays
  intact. `ks.g` uses fields 0/1 only; later `ks` methods that use the
  overlapped fields may fail. This is a startup hook, not a guarantee of full
  post-startup stability.
* **Image version/ART update:** the boot checksum, class layouts and field
  offsets are tied to the current ART module (version 119) and app image. An
  app update, ART update or boot image change invalidates the image; regenerate
  from the new `base.art` or the image is rejected. The image file is ordinary
  cache data and may be regenerated by ART.
* **`System.loadLibrary` caller:** the real `ks.g` uses the fake class as the
  JNI caller. The image loader sets the class loader for classes in the app
  image (`AddImageSpace`), so the app loader should find `libtmessages.49`; if
  not, the payload has already run but `native_setJava` will crash.
* **Undefined scope of class def 285:** its `<clinit>`/methods are irrelevant;
  only its zero static field count/superclass/no-interface properties are
  used. If a target ART validates the class def against the descriptor, this is
  the first thing to revisit.

**Why the previous negatives do not close this path**

* `mainconfig.xml` 256 MB OOM happens after `loaded normal lib` (the normal
  `ks.g` body has already loaded the library); the PoC triggers *inside*
  `ks.<clinit>` before that load.
* Zeroing the first 4 KiB of `base.art` invalidates the magic/version and
  `ImageHeader::IsValid` (`runtime/oat/image.cc:145-171`); ART rejects it and
  falls back. The PoC keeps a valid header, boot checksum, DexCaches and
  OatHeader.
* SQL triggers: this build’s SQLite has `#define SQLITE_OMIT_LOAD_EXTENSION 1`
  (`Android/TMessagesProj/jni/sqlite/sqlite3.c:158`) and no enabled extension
  loading; the S1/S2 startup bugs are DoS/crash, not a write primitive.
* `files/lib/libtmessages.49loc.so` is only loaded after a `System.loadLibrary`
  failure; the PoC does not need that failure.
* `tgnet.dat`/fake-DC is excluded by the task and was only a C2/DoS surface;
  this PoC is local and needs no network.
* QuickJS/qbc/widget JS and TGS/Rust are not involved.

**Explicit DoS-only items (not claimed as RCE)**

* The previous `base.art` 4 KiB corruption: header rejection/fallback.
* SQLite S1/S2: launch crash/DoS.
* `tgnet.dat` huge counts: OOM/DoS.
* Remote XML width/format strings: OOM/DoS.
* Malformed image files that fail `ImageHeader::IsValid`: fail-closed, not
  execution.

## 7. Exact source/evidence references

* Target image and mappings:
  `telegramandroidwidget/evidence/evidence_20261101/startup_db/tombstone_07:9,593,2485`;
  `.../new_beta_72799/tombstone_20.txt:386,2926`;
  `.../new_beta_72799/v4.db`; image file
  `.../cache/oat_primary/arm64/base.art` (snapshot md5
  `2bbe67262f52c767e639f5a137a76a89`).
* App startup/call:
  `jadx72799_c1/sources/org/telegram/messenger/w0.java:414,457,459`;
  `.../ks.java:138,151,188,232`;
  `.scratch_beta1320/manifest.xml:102,384-388`.
* ART 17 image/loader (source tree:
  `git clone --depth 1 --branch android17-release
  https://android.googlesource.com/platform/art art17`):
  `runtime/oat/image.cc:39` (version 119), `:145-171` (`IsValid`),
  `:221-252` (`Block::Decompress`);
  `runtime/gc/space/image_space.cc:1069-1180` (load/map/bitmap),
  `:718-760` (patch fields/methods), `:809-820` (ClassTable forwarding);
  `runtime/class_linker.cc:2096-2248` (`AddImageSpace`, roots/special root),
  `:2362-2375` (class table), `:5897-6204` (`InitializeClass` / clinit invoke);
  `runtime/mirror/class.cc:1058-1066` (`FindClassInitializer`),
  `:1491-1516` (`ComputeDescriptorHash`);
  `runtime/mirror/class-inl.h:1034-1050` (`NumDirectInterfaces`),
  `:1212-1217` (`HasStaticFields`);
  `runtime/art_method.h:217-219` (`IsClassInitializer`),
  `:327-333` (`IsInvokable`), `:928-936` (`HasCodeItem`);
  `runtime/entrypoints/entrypoint_utils-inl.h:598-601`
  (interpreter rejects non-invokable methods);
  `runtime/class_table.h` / `class_table-inl.h:186-233` (TableSlot);
  `runtime/gc/accounting/space_bitmap.cc:38-59` (bitmap size).
* Published technique/artifact:
  WOOT’26 “Exploiting Android Apps with Counterfeit Art”, EPFL,
  `https://hexhive.epfl.ch/publications/files/26WOOT3.pdf` (especially §2.3,
  §3/4: app-image overwrite, block decompression write, ArtField/ArtMethod
  relocation, bytecode injection); artifact
  `https://github.com/HexHive/artow-artifact` (GPL-3.0); CVE-2026-28664.
* Local PoC:
  `lab/persistence_nonquickjs/gen_payload_image.py`,
  `payload_builder.py`, `validate_image.py`, `payload.sh`,
  `sample/base_72799_original.art`,
  `sample/base_72799_fake.art`,
  `vendor/art.py` (GPL-3.0, attribution in `README.md`).

---

## 7. Device test (Sony XQ-BT52, 2026-11-02 15:54-15:02) — image loads, class init crashes

Deployment used root only to place the files (the final path is the app-UID RCE).
The app image was restored to the ART-generated `02be87ce…` at the end.

### 7.1 First attempt: `Invalid image header` (two generator bugs)

The sample `aae30a29…` was rejected; ART logged
`Could not load runtime generated app image: Invalid image header` and
regenerated the image (md5 `02be87cea7b03a91fb0e4639a9e7d9ff`, 1,161,488 B).
Two causes, both fixed in the generator:

1. **Wrong magic.** The real `ImageHeader::kImageMagic` is `{'a','r','t','\n'}`;
   the generator wrote `art\0`. The validator only checked the `art` prefix.
2. **Wrong segment alignment.** `kElfSegmentAlignment = kMaxPageSize = 0x4000`
   on this ART build (16 KiB), so `image_reservation_size` must be 16 KiB
   aligned. The sample used `0x1000` (`reservation=0x2000` → `IsValid` false).
   The real image's `image_reservation_size=0x378000` and bitmap offset
   `0x114000` confirm 16 KiB.

After `magic=b'art\n'` and `bitmap_off = align_up(0x108+data_size, 0x4000)`,
`IsValid` passes on device.

### 7.2 Second attempt: header accepted, crash in the image relocator

`base_fake16b.art` (16,464 B) loaded; the app mapped it at
`0x6a000000-0x6a003fff` and crashed in:

```
#00 ImageSpace::Relocator::PatchObjectVisitor::VisitGcRootDexCacheArray<Class>(…)+4
    fault addr 0x6a377108
```

`0x6a377108 = image_base + 0x377108`, the real image's
`kSectionDexCacheArrays` offset (0xc58 bytes). The minimal image copied the
image roots but not that section, so the relocated root pointed outside the
reservation. Not a code-execution failure — a missing image section.

### 7.3 Third attempt: DexCache arrays added, crash in `InitializeClass`

The generator now extends the image to include `kSectionDexCacheArrays` at its
real offset, preserving the length word and zeroing the 0x315 resolved-class
roots (to avoid dangling app-class references). File 3,637,328 B, bitmap
`0x378000`, reservation `0x378000`; validator PASS.

Device result: image mapped (`0x6a000000-0x6a377fff`), no header error, and
`w0.onCreate` reached the forged `ks` class. Crash:

```
#00 art::ClassLinker::InitializeClass(Thread*, Handle<Class>, bool, bool)+980
    called from org.telegram.messenger.w0.onCreate+478
signal 11, fault addr 0x60, x0=0, x1=0x11d (dex_class_def_idx 285),
x2=0x6a00117c (fake Class)
```

The fake Class is present and relocated (`dex_cache_=0x6a000140`,
`fields_=0x6a001208`, `methods_=0x6a001288`, `dex_class_def_idx=0x11d`,
`dex_type_idx=0x1cc6`), but `InitializeClass` reads a null 32-bit field at
`class+0x24` and dereferences `[0 + 10*8 + 0x10] = 0x60`. This is a
`mirror::Class` layout / class-def-substitution consistency issue on the
device build, not a load rejection.

**Status (historical): the first image was accepted and reached class
initialization but crashed at the fake-Class null vtable (fault 0x60); no
marker, no RCE.** This was fixed in `notes/loader_art.md` (vtable copy + v4
dummy `ArtField`s); the corrected image is **device-proven** on 2026-11-03
(§0 of that note: marker, `System.load`, app alive, boot-receiver path).

### 7.4 Restore

`cache/oat_primary/arm64/base.art` restored from `02be87ce…`; app restarted
(pid 26486), `loaded normal lib`, chat UI normal. `files/.p` and
`.p_started` removed.
