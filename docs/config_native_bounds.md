# Config values that cross into native code — bounds audit (72799)

Date: 2026-11-02. Target: Telegram **13.2.0 beta (versionCode 72799)**, package
`org.telegram.messenger.beta` / debug clone `org.telegram.messenger.beta.dbg`,
arm64 `lib/arm64-v8a/libtmessages.49.so` (md5 `2c0caa68a07fc26f79d13519af6c3526`,
IDB `/tmp/opencode/tg49_tgnet.so.i64`, md5 re-verified in-session).

Question: the first exploit gives app-UID code execution, i.e. arbitrary write to
`shared_prefs/*.xml`, `files/cache4.db` and `files/tgnet.dat`. Does any **config
value** (string/int) reach **native** code with an out-of-bounds write or an
integer overflow that yields code execution (not just DoS)?

Lab: `lab/config_native_bounds/` (config→JNI map, boundary-matrix generator,
690-case ASan run, PoCs, logs).

---

## 0. Verdict

**No.** In this build there is no config value that reaches a native write with
an attacker-controlled size, index or length. Every `SharedPreferences` /
`cache4.db` value that crosses JNI does so as

* a `jstring` converted to `std::string` (proxy address/user/pass/secret,
  language codes, push regId, log/config paths) — copies are length-tracking,
  and the only fixed-size consumer found is clamped (`TLSHello` domain ≤ 253);
* a `jint`/`jlong` used as an enum, id, time or port — and the ports are
  truncated to 16 bits in `TgNetWrapper`/`Connection::connect`, which is a
  functional bug, not memory corruption;
* a cache **directory path** (fixed app/external roots; `storageCacheDir` is only
  a prefix filter), passed to `Utilities.getDirSize()`/`clearDir()`.

Two native functions that *look* like config sinks in Java are empty stubs in the
72799 binary and were verified in IDA: `NativeInstance.setGlobalServerConfig`
(the `voip_server_config` pref) at `0xa5d894` and `NativeInstance.setBufferSize`
at `0xa5d898` (both 4-byte `ret` bodies). Their config values never reach native.

The tgnet config parser remains read/DoS-only (F1–F4 of
`notes/tgnet_parser_audit.md`). A new 690-case integer-boundary matrix over
every integer and length field of `tgnet.dat` and `dc<id>conf.dat` produced
**0 sanitizer reports**, and a further 269,808 libFuzzer executions with the
matrix as seed corpus produced **0 crashes**.

The realistic impact of config write access is therefore: traffic redirection
(proxy/DC), update-prompt redirection (`appUpdate`), cache deletion, and startup
DoS. None of these is code execution.

---

## 1. The JNI boundary

### 1.1 Which classes even call native code

`grep "\.method.* native "` over all four dex trees gives 465 declarations, but
only these are reachable from the config path:

| class | native methods | config-relevant |
|---|---|---|
| `org.telegram.tgnet.ConnectionsManager` | 37 (`native_init`, `native_setProxySettings`, `native_checkProxy`, `native_setRegId`, `native_setLangCode`, …) | yes |
| `org.telegram.tgnet.NativeByteBuffer` | 5 (`native_getFreeBuffer(I)`, …) | indirectly (buffer sizes computed in Java) |
| `org.telegram.SQLite.*` | 16 (`opendb`, `bindByteBuffer`, `columnByteBufferValue`, …) | DB blobs |
| `org.telegram.messenger.Utilities` | 30+ (`getDirSize`, `clearDir`, `getLastUsageFileTime`, `readlink`, `setupNativeCrashesListener`, AES/bitmap) | paths from the cache-dir layer |
| `org.telegram.messenger.MediaController` | 7 (`startRecord`, `writeFrame`, `getWaveform2`, opus helpers) | no (constants + cache paths) |
| `org.telegram.messenger.voip.NativeInstance` | 40+ (`setBufferSize`, `setGlobalServerConfig`, `setNetworkType`, …) | two are dead stubs; the rest are call/session data |
| `Intro`, `MrzRecognizer`, `WebmEncoder`, media3, webrtc | — | not config |

`MessagesController` (`wp`) calls exactly one native method:
`native_isTestBackend(I)` (`wp.smali:3800`). `MessagesStorage` (`is`) calls
**none** (`grep -c native_ is.smali` → 0). So `cache4.db` cannot reach native
through the message/dialog path at all.

### 1.2 Config → JNI map (exact refs)

Smali paths below are relative to `/tmp/opencode/dbgbuild/smali72799/`
(`smali/` unless noted). `uz` is the obfuscated `SharedConfig`
(`q()` returns the `"userconfing"` prefs), `e20` is `UserConfig`
(`"userconfig"`), `wp` is `MessagesController`, `dd` is `LocaleController`.

| # | source | key | Java read | JNI call | native |
|---|---|---|---|---|---|
| S1 | `mainconfig`/`mainconfig<N>` | `proxy_enabled`, `proxy_ip`, `proxy_port`, `proxy_user`, `proxy_pass`, `proxy_secret`, `proxy_type` | `ji/b.c` (`smali_classes4/ji/b.smali:543-668`; port default 1080); `ConnectionsManager.<init>` `ConnectionsManager.smali:10929-11025` | `native_setProxySettings(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V` `ConnectionsManager.smali:11001/11025` (also `:9186/9224` from the proxy UI) | `TgNetWrapper.cpp:233` → `ConnectionsManager::setProxySettings(address, (uint16_t) port, user, pass, secret)` |
| S2 | `mainconfig` | same, for "check proxy" | `ConnectionsManager.checkProxy` `ConnectionsManager.smali:10086` | `native_checkProxy(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lorg/telegram/tgnet/RequestTimeDelegate;)J` | `TgNetWrapper.cpp:290` → `ProxyCheckInfo` + `ConnectionSocket::setOverrideProxy` |
| S3 | — (Build/pkg) | — | `ConnectionsManager.<init>` (jadx `ConnectionsManager.java:726-741`) | `native_init` `ConnectionsManager.smali:11183` | `TgNetWrapper.cpp:463` → `ConnectionsManager::init` (`std::string` members, `loadConfig`) |
| S4 | `mainconfig` | `forceTryIpV6` | `ConnectionsManager.smali:1136/1148` | `native_setIpStrategy(IB)` `:9810` | `ConnectionsManager::setIpStrategy(uint8_t)` |
| S5 | `userconfing` | `storageCacheDir` | `uz.smali:4135` (load) / `7918` (save); `ImageLoader ic.smali:14121` `l()`, checks at `14258/14419/14765/15112` | `Utilities.getDirSize(Ljava/lang/String;IZ)J`, `clearDir(Ljava/lang/String;IJZ)V` | `jni.c listdir()` (binary `sub_16F03E0`) |
| S6 | `userconfing` | `keep_media`, `lastKeepMediaCheckTime` | `uz.smali:5496/5544` | `clearDir(path, int, long, bool)` | `listdir(..., mode=1, time, ...)` → `stat`/`remove` |
| S7 | `userconfing` | `pushString2` | `uz.smali:4044`; `ConnectionsManager.getRegId()` binds `uz.g` | `native_init`; `native_setRegId(ILjava/lang/String;)V` `:9474` | `ConnectionsManager::currentRegId` → `TL_jsonString` in `initConnection` |
| S8 | `userconfig` | `user` (TL_user) → `id` | `e20`; `getUserConfig().e()` in `<init>` | `native_setUserId(IJ)V` `:12192` | `ConnectionsManager::currentUserId` |
| S9 | locale | current/system language code | `dd.I0()`/`dd.P0()`; `setLangCode` `:8938`, `setSystemLangCode` | `native_setLangCode`, `native_setSystemLangCode` | `currentLangCode` / `currentSystemLangCode` `std::string` |
| S10 | `mainconfig` | `appUpdate` (base64 TL blob), `appUpdateBuild` | `uz.smali:4369-4396`; Java `TLRPC$help_AppUpdate.TLdeserialize` | none | Java TL parser only (update prompt) |
| S11 | `mainconfig` | `debugWebView` | `uz.smali:1216/5512` | none | `WebView.setWebContentsDebuggingEnabled` |
| S12 | `mainconfig` | `voip_server_config` | `VoIPService.smali:32512-32528` → `Instance.setGlobalServerConfig` | `NativeInstance.setGlobalServerConfig` | **empty stub** (`0xa5d894`) |
| S13 | system property | `AudioManager.getProperty(...)` | `VoIPService.smali:38690-38710` → `Instance.setBufferSize` | `NativeInstance.setBufferSize(I)` | **empty stub** (`0xa5d898`) |
| S14 | `cache4.db` | `params` (id=1): `seq,pts,date,qts,lsv,sg,pbytes` | `is.smali:1154` (schema), `51523` (SELECT) | none | Java update-state only |
| S15 | `cache4.db` | `keyvalue` | created in migration `n5.smali:1339`; no query in 72799 | none | unused |
| S16 | `cache4.db` | `app_config.data` | `ro.smali:361` | `SQLiteCursor.columnByteBufferValue` (`BuffersStorage::getFreeBuffer(len)` + `memcpy` of exactly `sqlite3_column_bytes`) | Java TL parser afterwards |
| S17 | `cache4.db` write | any blob | `bindByteBuffer` uses `NativeByteBuffer.limit()` | `sqlite3_bind_blob(handle, i, GetDirectBufferAddress(v), length)` | `length == buffer capacity` |
| S18 | push payload (not app data) | `loc=DC_UPDATE`, `dc`, `addr=ip:port` | `PushListenerController.smali:5233-5287` | `native_applyDatacenterAddress(IILjava/lang/String;I)V` `:9658` | `ConnectionsManager::applyDatacenterAddress` → `TcpAddress`, `saveConfig()` |

The remaining `SharedConfig` keys (`uz.t()` reads 113 keys: UI flags, cache
counters, passcode, column counts, hint counters, `saveIncomingPhotos`,
`streamMedia`, `sortContactsByName`, …) are read in Java and consumed in Java.
None appears in a native call site: a scan of every
`Lorg/telegram/tgnet/NativeByteBuffer;-><init>(I)V` site (128 sites) found no
`uz` field within the argument chain, and neither `is` nor `wp` call
`native_getFreeBuffer`/`Utilities` with preference values.

### 1.3 Dead ends verified in the binary

These are the two places where a config string/int would have entered native
parsers, and they are no-ops in 72799 (checked with Hex-Rays on the IDB, not only
in the source tree):

```
Java_..._NativeInstance_setGlobalServerConfig  0xa5d894  size 4  ->  ret
Java_..._NativeInstance_setBufferSize          0xa5d898  size 4  ->  ret
```

Source agreement: `jni/voip/org_telegram_messenger_voip_Instance.cpp:1014-1019`
has the calls commented out. Consequence: `voip_server_config` (a prefs string
the attacker can rewrite) and the audio buffer size never reach tgcalls.

---

## 2. Native sink analysis

### 2.1 Proxy settings / proxy check (S1, S2)

`TgNetWrapper.cpp:233-252` and `:290-323` do `GetStringUTFChars` →
`std::string`, and cast `jint port` to `uint16_t` before
`ConnectionsManager::setProxySettings`/`checkProxy`. Checks:

* **port**: `proxy_port` is an arbitrary 32-bit `getInt`
  (`ji/b.smali:595`). `(uint16_t) 0x7FFFFFFF` = 65535, `-1` = 65535,
  `65536+8080` = 8080. This is passed to `htons(proxyPort)` in
  `ConnectionSocket::openConnection` (`ConnectionSocket.cpp:107`). Functional
  truncation only; no buffer is indexed by the port.
* **secret**: `ConnectionsManager::decodeSecret` (`ConnectionsManager.cpp:3337`)
  either hex-decodes (`new char[size]`, `size = len/2`, indices `2i,2i+1 < len`)
  or base64url-decodes (table lookup bounded by `i < base64.size()`), then
  `std::string`. No fixed buffer.
* **`ee` MTProxy secret**: `size() > 17 && [0] == 0xEE` →
  `currentSecret = substr(1,16)`, `currentSecretDomain = substr(17)`
  (`ConnectionSocket.cpp:101-104`). `TLSHello::writeOp(Type::Domain)` clamps to
  253 (`TLSHello.cpp:... case Type::Domain`), and the whole hello is written
  into a 65 KiB `ByteArray` allocated for exactly this case.
  Host proof with the **shipped** `TLSHello.cpp` (`src/tlshello_poc.cpp`,
  `out/poc_tlshello.log`): domains of 0…1 MiB all produce a 1.7–2.1 KB hello and
  modify 0 bytes past its end.
* **classic secret**: `Connection::encryptKeyWithSecret` (`Connection.cpp:634`)
  uses `size = min(16, len)`, and only for `len >= 17` with prefix `0xDD/0xEE`
  uses `size = 17` (indices 1..16, i.e. requires len ≥ 17 — checked). The HMAC
  reads exactly those bytes.

### 2.2 `native_init` strings (S3, S7, S9)

All 11 strings become `std::string` members in `ConnectionsManager::init`
(`ConnectionsManager.cpp:3682`). The only path-like one (`configPath`) is
`w0.h()` = `getFilesDir()` (+ `account<N>`), i.e. fixed; `logPath` is
`getExternalFilesDir(null)/logs/<date>_net.txt` and only in debug builds; both
are used with `fopen`/`std::string`. `regId` is later copied into a
`TL_jsonString` and serialized by length-aware `NativeByteBuffer::writeString`.

### 2.3 Datacenter address from a push (S18)

`PushListenerController` parses a push JSON `{"loc":"DC_UPDATE","dc":N,
"addr":"ip:port"}` and calls `applyDatacenterAddress(dc, ip, port)`. Native:
`addresses.emplace_back(ipAddress, port, 0, "")`
(`ConnectionsManager.cpp:3548`) → `TcpAddress{std::string, int32 flags, int32
port, std::string secret}`; the IP goes through `inet_pton`/`gethostbyname`, the
port through `(uint16_t)` at connect (`Connection.cpp:348-351`). The address is
then persisted by `saveConfig()` into `tgnet.dat`. No memory-safety issue; this
is a remote-ish *configuration* channel (a push payload) that agrees with the
app-data one (same effect as writing `tgnet.dat`), which is why it is listed but
not counted as an escalation.

### 2.4 `NativeByteBuffer.native_getFreeBuffer(int)` (S16 and Java buffers)

`NativeByteBuffer.<init>(I)` refuses negative sizes in Java
(`if-ltz p1`, else throws "invalid NativeByteBuffer size") and calls
`native_getFreeBuffer(I)`; `TgNetWrapper.cpp:57` casts to `uint32_t`, and
`BuffersStorage::getFreeBuffer` picks a pool size or `new uint8_t[size]`.
Positive huge sizes (up to 2³¹−1) end in `std::bad_alloc`/abort → DoS, never in
an undersized buffer: every write into the buffer is either a Java
`ByteBuffer.put*` (throws `BufferOverflowException`) or a native
`NativeByteBuffer::write*` with an explicit `_position + length > _limit` check.

### 2.5 `Utilities.getDirSize` / `clearDir` / `readlink` (S5, S6)

* `readlink` uses a thread-local `char buf[PATH_MAX + 1]`
  (`utilities.cpp:12-25`; binary `0x74ccb0` reads 0x1000 into the TLS buffer and
  writes `buf[result] = 0`), so the +1 matters and is present.
* `listdir` (`jni.c:199-263`; binary `sub_16F03E0`) has a real CWE-121-looking
  pattern: `char dest[4096]; strncpy(dest, fileName, 4095);
  *(WORD*)&dest[strlen(dest)] = '/'; strncat(dest, entry->d_name, 4095);`.
  It is **not reachable from config** and, more importantly, **not reachable at
  all on Linux/Android**: any directory whose entries exist satisfies
  `strlen(dir) + 1 + strlen(name) ≤ PATH_MAX-1 = 4095`, so the `strncat`
  destination plus its NUL always fits in `dest[4096]`. A directory with a
  4095-byte path can be created, but no entry can be created inside it
  (`ENAMETOOLONG`, errno 36) — and `listdir`'s loop only runs for entries.
  PoC (`src/listdir_poc.c`, `out/poc_listdir.log`): 4095-byte path → entry
  creation fails with errno 36 → `listdir` returns 0 with no ASan report.
  `storageCacheDir` does not help either: it is compared with `startsWith`
  against `getRootDirs()`/`getExternalFilesDirs()` results
  (`ImageLoader.java:2434-2450`) and can only *select* a system-provided root,
  never supply a path.
* `getDirSize`/`clearDir` also take `time` (from `keep_media`), used only in
  `stat` comparisons before `remove()` — cache deletion, not memory.

### 2.6 VoIP and media natives

`MediaController.startRecord(String, int)` gets `path` from
`FileLoader.getDirectory(MEDIA_DIR_CACHE)` + a generated name and a hard-coded
bitrate (`MediaController.smali:810` `0xBB80`); `writeFrame`, `getWaveform2`,
`cropOpusFile`, `joinOpusFiles` consume recording/playback data, not config.
`Instance.setBufferSize` and `setGlobalServerConfig` are empty stubs (§1.3).
`makeNativeInstance`'s `Instance$Config`/`Endpoint` values come from
`TL_phone_call`/server data; `peerTag` is copied 16 bytes with an explicit
`GetArrayLength` check (`org_telegram_messenger_voip_Instance.cpp:975`).

---

## 3. `tgnet.dat` / `dc<id>conf.dat`: integer-boundary matrix

### 3.1 What was generated

`src/matrix.py` rebuilds the canonical files with a writer that records the byte
offset, width and name of every scalar (integer, bool, TL length prefix) it
writes — 38 fields in `tgnet.dat`, 9 in `dc2conf.dat` — then emits one file per
boundary value:

```
0, 1, 2, 3, 0x7F, 0xFF, 0xFD, 0xFE, 0x100, 0xFFFF, 0x10000,
0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF          (u32/i32/len)
0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000,
0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF   (i64)
```

plus file-level `size` prefix values, `size = payload ± {1,0,1,4}`, and a
truncation at every field boundary. Total **690 cases** (`cases/`, 8.2 MB).

Fields covered: tgnet `version`, `testBackend`, `clientBlocked`,
`langcode.len`, `hasConfig`, `currentDatacenterId`, `timeDifference`,
`lastDcUpdateTime`, `pushSessionId`, `registeredForInternalPush`,
`lastServerTime`, `sessions.count`, `datacenters.count`; per datacenter
`version`, `dcId`, `lastInitVersion`, `lastInitMediaVersion`, the four address
counts, address `ip.len/port/flags/secret.len`, `isCdn`, the three auth-key
lengths + ids, `authorized`, both salt counts and each salt
`since/until/value`; dc-conf `version` and the eight port/address counters.

### 3.2 Result

```
python3 src/matrix.py cases      -> 690 cases, 38 + 9 fields
./build.sh && python3 src/run_matrix.py cases
ran 690 cases
  ok               690
```

No ASan report of any kind (no READ, no WRITE, no SEGV, no OOM). The harness is
the same one as `lab/tgnet_parser_audit` (shipped `NativeByteBuffer.cpp`,
`ByteArray.cpp`, `BuffersStorage.cpp`; verbatim parse bodies), with its two
fuzz-only DoS guards (count ≤ 1024, size ≤ 64 MiB) so the matrix cannot be
satisfied by the known allocation DoS instead of the parser. The `size`-field
extremes were checked separately against the guards-off build and reproduce F3
(allocation failure), not a write.

Fuzzing on top of the matrix seeds: 75 s, **269,808 execs**, 0 crashes
(`fuzz_corpus/` seeds are the first 200 matrix cases; the prior audit's 300 s /
2,183,031 execs and 20,433 structured cases already covered the same parser).
Raw logs: `out/matrix_results.tsv`, `out/matrix_summary.log`.

### 3.3 Why there is no write even in theory

The only writes in the parser/serializer are:

1. `NativeByteBuffer` fixed-field writes (`writeInt32/64`, `writeBool`) —
   `_position + N > _limit` check, N constant.
2. `writeBytes`/`writeByteArray` — `_position + length > _limit` check, where
   `length` is either a `ByteArray::length` that was itself allocated after a
   `readBytes` bound check, or a `std::string::length` obtained from a validated
   `readString`.
3. `memcpy` in `readBytes`/`readString` into a fresh allocation of exactly the
   requested length; the requested length is checked against the remaining
   buffer first.
4. `Datacenter.cpp:106-112` hex-secret decoding into `new char[len/2]`, indices
   `2i+1 ≤ len-1`.
5. `saveConfig`'s two-pass `sizeCalculator` + serialization; each write is
   bounds-checked against the buffer built from the first pass.

The single arithmetic hole is the `uint32_t` sum in those checks
(`_position + length` can wrap). It requires `_position + length ≥ 2³²`, i.e. a
buffer close to 4 GiB and a string/byte-array close to 4 GiB. Reaching it needs
a ≈4 GiB `tgnet.dat` (F3's sign truncation allows the size field, but the file
must really contain that many bytes) and a successful ≈4 GiB native allocation;
what follows is a `memcpy` of ~4 GiB from a heap buffer into a small one —
an immediate SIGSEGV/OOM abort, not a controlled write. This is recorded as
theoretical, not as a primitive.

---

## 4. Values that select a code path / loader

| value | selects | consequence |
|---|---|---|
| `proxy_*`, `proxy_list` | proxy host/port/credentials/secret used by every tgnet socket | traffic goes through an attacker-chosen proxy; MTProto encryption stays end-to-end, so no plaintext, but metadata/DoS |
| `forceTryIpV6` / push `DC_UPDATE` | DC address/port (persisted in `tgnet.dat`) | connection redirection; the peer still needs the real DC's auth key |
| `storageCacheDir` | which **system-provided** external root is used for media dirs (prefix match only) | path choice only; no arbitrary path, no loader |
| `appUpdate` / `appUpdateBuild` | base64 `TL_help_appUpdate` shown as an update prompt | user-visible update; no silent install |
| `debugWebView` | `WebView.setWebContentsDebuggingEnabled` | adb-only debug; not reachable from app data alone |
| `voip_server_config` | would be tgcalls JSON config | **dead stub** in 72799 |
| `language_code`, `pushString2`, `user` | request metadata (initConnection) | data only |

No config value selects a **library name or load path**. `ks.g` still loads the
fixed `libtmessages.49` / `files/lib/libtmessages.49loc.so`; `SQLiteDatabase`
opens the fixed `cache4.db` name in the files dir; `Config` builds
`files/…/tgnet.dat` and `dc<N>conf.dat` from fixed strings. The `datacenterId`
used in the `dc<N>conf.dat` name comes from `tgnet.dat`, but `to_string_int32`
emits only digits and `-`, so no traversal.

---

## 5. Honest near-misses (why this is not ACE)

* **`listdir` fixed 4096-byte stack buffer.** Real-looking `strncpy`/`strncat`
  misuse, but bounded by the kernel's `PATH_MAX` invariant: every entry that can
  exist has a full path ≤ 4095 bytes, so `dest[4096]` is never overrun. Host PoC
  (with the verbatim buffer code) confirms the entry cannot even be created.
  Not config-reachable either (`storageCacheDir` is a filter).
* **F1 (`authKey*` length vs 256-byte key)** — still an OOB **read**
  (`SHA256_Update(authKey->bytes+88,32)`, `generateMessageKey`), no write; all
  consumers read.
* **F2 (`isCustomPort` unclamped `defaultPorts[i]`)** — latent OOB **read**,
  still unreachable without a caller that skips `getCurrentPort`; my matrix
  confirms the dc-conf counters do not otherwise reach an index.
* **F3/F4** — 2 GiB allocation from a 4-byte file, unbounded counts; DoS.
* **`Datacenter::datacenterId` uninitialized** when the version check fails
  (`Datacenter.cpp:57-60`), used as map key and file name — CWE-457, no memory
  consequence.
* **`storeCurrentAddressAndPortNum`** writes `currentPortNumIpv4Temp =
  currentAddressNum` in the clamp branch (`Datacenter.cpp:321`) — a logic bug,
  not memory.

A Java exception (the `NativeByteBuffer` negative-size check, a
`BufferOverflowException` from `ByteBuffer.put`) or an OOM is not code
execution; the audit treats them as such.

---

## 6. Device plan (Pixel debug clone + Sony)

Purpose: confirm reachability and the *observable* effect of each surviving
config→native channel; the memory-safety verdict relies on the host ASan harness
(no ASan Telegram build is available).

Environment (from `notes/pixel_debug_build.md`):
`org.telegram.messenger.beta.dbg`, UID 10178, debuggable, installed on the Pixel
9 (Android 17); Sony XQ-BT52 `<SERIAL>` (root) runs
`org.telegram.messenger.beta` with the working account.

1. **Baseline**: `adb shell am force-stop <pkg>`; cold start; `adb logcat -b
   crash -d` and `/data/tombstones` (Sony root) must be clean.
2. **Proxy prefs (S1, truncation + reachability marker)**: stop the app; edit
   `shared_prefs/mainconfig.xml` (Pixel: `run-as ... cat`; Sony:
   `adb shell su -c`), set `proxy_enabled=true`, `proxy_ip=127.0.0.1`,
   `proxy_port=65536+9050` (i.e. 67626), `proxy_type=2`, empty user/pass/secret.
   Start. Telegram writes a **native** log line only when the value crossed JNI:
   `connection(%p) connecting via proxy 127.0.0.1:9050 secret[0]`
   (`ConnectionSocket.cpp:91`) in `files/logs/*_net.txt`. 9050 proves the
   `(uint16_t)` truncation and that the pref reached tgnet. `ss -tnp` on the Sony
   shows the connect to 127.0.0.1:9050. Expected: no crash.
3. **Proxy secret (S2, clamp)**: set `proxy_secret` to a `ee…` 17-byte hex
   string and to a 64 KB base64 string with the same prefix. Expect the same
   native log line with `secret[16]`/`secret[16]` after `decodeSecret` (the
   domain is clamped), no crash.
4. **DC address via push (S18)**: with the app stopped, craft the tgnet
   equivalent instead of a push (`files/tgnet.dat` with a second DC address) —
   or, if a push harness exists, send `{"loc":"DC_UPDATE","dc":2,
   "addr":"127.0.0.1:1234"}` through the push path. After start, `files/
   tgnet.dat` contains the new address and `_net.txt` logs `connecting
   (127.0.0.1:1234)`. Expected: authorization fails (`AUTH_KEY_…`), no crash.
   This confirms persistence and that the address string is consumed by
   `inet_pton`, not by a fixed buffer.
5. **`voip_server_config` (S12, dead stub)**: set `voip_server_config` to a
   1 MB JSON string; place a call (or start `VoIPService` via the debug build).
   Expected: no native crash, no JSON parse in native (stub); the Java
   `ServerConfig` parser either accepts or catches `JSONException`.
6. **tgnet boundary cases on device (subset)**: push `cases/` selections
   (`dc0-version_{0,1,2,14}`, `dc0-authKeyPerm.len_ffffffff`,
   `dc0-addr0-count_ffffffff`, `salts.count_ffffffff`, `conf-port4_ffffffff`)
   as `files/tgnet.dat`/`dc2conf.dat`, cold start each, collect
   `logcat -b crash`, tombstone, and `pidof`. Expected: benign start or
   native abort/OOM for the count/size cases; **no tombstone with a write
   fault in `libtmessages.49.so`**. A Java `OutOfMemoryError` (Java stack,
   `art::` frames) is recorded separately and is not a memory-corruption hit.
7. **Heap instrumentation (Sony, root)**: `setprop libc.debug.malloc.options
   guard` + `libc.debug.malloc.program org.telegram.messenger.beta`, restart,
   repeat steps 2/4/6. This turns small heap overflows into immediate SIGSEGV
   with a guard page, without an ASan build. Remove the property afterwards.
8. **No `run-as` false positive**: do not treat `run-as` failures or
   `SecurityException`s as app behaviour; all file edits are done while the app
   is stopped, and the evidence for "the value reached native" is a native log
   line / socket, not a Java exception. Any crash must be matched to a native
   frame in `libtmessages.49.so` with the fault address/PC reported.

---

## 7. What would change the verdict

1. A future build wiring `setGlobalServerConfig`/`setBufferSize` to real code
   (the source is commented out; a later revision could re-enable it) — then
   `voip_server_config` becomes a 1-string → native JSON parser path, and
   `AudioManager`/`setBufferSize` an int → audio path; both would need a fresh
   audit.
2. Any code that passes `authKey->length` into a fixed 256-byte **destination**
   (today all consumers read).
3. Any caller of `isCustomPort` without the `getCurrentPort` clamp (F2).
4. A config-controlled cache directory (today `storageCacheDir` is only a
   prefix filter); that alone would still hit the `PATH_MAX` invariant.
5. `SharedPreferences` XML itself is parsed by Android's `XmlPullParser` into
   typed values; there is no Telegram native XML parser, so malformed XML gives
   a Java `XmlPullParserException`, not memory corruption.

---

## 8. Reproduction

```sh
cd lab/config_native_bounds
./build.sh                                   # ASan harness (same sources as tgnet_parser_audit)
./build.sh pocs                              # tlshello_poc, listdir_poc (see src/)
python3 src/matrix.py cases                  # 690 cases
python3 src/run_matrix.py cases              # -> out/matrix_results.tsv
ASAN_OPTIONS=detect_leaks=0 ./build/tlshello_poc   # -> out/poc_tlshello.log
ASAN_OPTIONS=detect_leaks=0 ./build/listdir_poc    # -> out/poc_listdir.log
# fuzz with the matrix seeds
../tgnet_parser_audit/build/fuzz_parser -max_total_time=75 fuzz_corpus
```

Key native addresses (image base 0, `tg49_tgnet.so.i64`):
`loadConfig 0x10035D8`, `Config::readConfig 0x102F180`,
`Datacenter ctor 0x101D1F8`, `getCurrentPort 0x101DA6C`,
`isCustomPort 0x101DEC4`, `createRequestsData 0x101F468`,
`Utilities::getDirSize 0x16F07B0` → `listdir sub_16F03E0`,
`Utilities::clearDir 0x16F08B8`, `Utilities::readlink 0x74CCB0`,
`NativeInstance::setGlobalServerConfig 0xA5D894` (empty),
`NativeInstance::setBufferSize 0xA5D898` (empty).

IDB: `/tmp/opencode/tg49_tgnet.so.i64` (md5 `2c0caa68a07fc26f79d13519af6c3526`,
saved in place; no renames were needed).
