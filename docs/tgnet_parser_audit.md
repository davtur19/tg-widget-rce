# tgnet startup parser — `tgnet.dat` / `dc<id>conf.dat` (72799)

Date: 2026-11-02. Scope: **Telegram-specific** startup parser only (`tgnet`
`Config`/`Datacenter`/`ConnectionsManager`). FFmpeg/Skia/ART/QuickJS are out of
scope here. Host-only: no device, no VM; arm64 code was analysed statically and
the parser logic was re-run on x86-64 from the shipped sources.

Targets
* APK 72799 = Telegram **13.2.0 beta**, `lib/arm64-v8a/libtmessages.49.so`
  md5 `2c0caa68a07fc26f79d13519af6c3526` (27,016,000 B, 80,520 functions).
* Sources: `<HOME>/ailocal/Telegram/Android/TMessagesProj/jni/tgnet`
  (**13.1.1**, the tree that matches the APK) cross-checked against
  `/tmp/opencode/telegram_src` (**9.7.6**).
* IDA: private IDB `/tmp/opencode/tg49_tgnet.so.i64` (copy of `tg49_apk.so`,
  verified same md5); the `tg49_72799.so` / `tg49_twidget.so` DBs were not
  touched.
* Lab: `lab/tgnet_parser_audit/` (harness, fuzzer, PoCs, 1,376 synthetic +
  19,057 real-dump structured cases, IDA extracts, logs).

---

## 0. Verdict

**There is no memory-corruption (out-of-bounds write) primitive reachable from
`tgnet.dat` or `dc<id>conf.dat`.** The parser is length-checked at every read;
the only file-controlled values that reach a memory sink are (a) loop counts,
(b) string/byte-array lengths that are always validated against the remaining
buffer, and (c) integers copied into fixed-size fields.

What *is* there:

| # | Defect | Kind | Reachable at startup | Impact |
|---|--------|------|----------------------|--------|
| **F1** | `authKeyPerm`/`authKeyTemp`/`authKeyMediaTemp` are read with an arbitrary length (`readBytes(len)`) but consumed as fixed **256-byte** keys (`authKey->bytes + 88`, `authKey + 0..136`) | **heap OOB read** (up to ~136 B past a short allocation) | **yes** on a logged-in install — first outgoing packet on the parsed DC | ASan-verified. No write; the over-read is only hashed into a message key, so no attacker-visible leak; practical effect = rare crash / corrupt session, not code execution |
| **F2** | `Datacenter::isCustomPort()` indexes `defaultPorts[currentPortNum]` with a **non-range-checked** `uint32` read from `dc<id>conf.dat` (`getCurrentPort()` *does* clamp, and stores the clamp back) | **heap OOB read** (4 B at `defaultPorts + 4*index`, index up to 2³²−1) | **latent** — every path that reaches it first calls `getCurrentPort()` for the same flags, which rewrites the counter to 0 | SEGV only if the index is huge; not reachable in the startup flow as shipped |
| **F3** | `Config::readConfig` compares `(int32_t) size < fileSize` (sign truncation) → `size ∈ [0x80000000,0xFFFFFFFF]` passes | **DoS** (allocation up to 4 GiB, `SXTW`+`CMP` in asm) | yes, 4-byte file | abort/OOM at every start |
| **F4** | Unbounded counts: sessions, datacenters, **addresses**, salts | **DoS** (OOM / multi-minute loop) | yes | 2·10⁶ addresses = 326 MB, 2³² ≈ 730 GB |

Nothing here reaches `dlopen`, `System.loadLibrary`, or the `ks` local-lib
loader: `loadConfig()` runs **after** `libtmessages.49.so` is already loaded and
`JNI_OnLoad` has succeeded, and `tgnet` contains no dynamic loader call at all
(`grep -n "dlopen|dlsym|loadLibrary" *.cpp *.h` → empty).

The prior audit's statement “bounds-checked; only allocation/loop DoS” is
**correct for writes**, but incomplete: F1 and F2 are real out-of-bounds reads
that were not identified, and F1 is reachable from a 1-byte field.

---

## 1. On-disk format (authoritative)

Both files are `[u32 payload_len][payload]` and are plaintext (no MAC, no
checksum, no signature). `Config::writeConfig` writes `u32 size` then the TL
bytes; `readConfig` reads `size` and then exactly `size` bytes.

### 1.1 `files/tgnet.dat` (`files/account<N>/tgnet.dat`)

Written by `ConnectionsManager::saveConfigInternal` (13.1.1:448-477), read by
`loadConfig` (13.1.1:365-446). Version written/expected: `ConnectionsManager::
configVersion = 5` (13.1.1 `ConnectionsManager.h:140`).

| off (base file) | type | field |
|---|---|---|
| 0 | u32 | `size` (payload length, must satisfy `(int32_t)size < fileSize`) |
| 4 | u32 | `version` (≤ 5 to be parsed; 5 = current) |
| 8 | u32 | `testBackend` bool (`0x997275B5`/`0xBC799737`) |
| 12 | u32 | `clientBlocked` bool (v ≥ 3) |
| 16 | string | `lastInitSystemLangcode` (v ≥ 4) |
| … | u32 | `hasConfig` bool — everything below only if true |
| | u32 | `currentDatacenterId` |
| | i32 | `timeDifference` |
| | i32 | `lastDcUpdateTime` |
| | i64 | `pushSessionId` |
| | u32 | `registeredForInternalPush` bool (v ≥ 2) |
| | i32 | `lastServerTime` (v ≥ 5) |
| | u32 `n` + i64·n | `sessionsToDestroy` |
| | u32 `m` + record·m | datacenters (§1.2) |

`string` = TL “bytes” encoding: `len ≤ 253` → 1 length byte, else `0xFE` + 3-byte
LE length; then data; then 0-pad to a 4-byte boundary of `len+header`.

### 1.2 Datacenter record (inside `tgnet.dat`)

Written by `Datacenter::serializeToStream` (13.1.1:538-609), read by
`Datacenter::Datacenter(int32_t, NativeByteBuffer*)` (13.1.1:47-194, parse body from 57).
Version written: `Datacenter::configVersion = 13` (`Datacenter.h:129`); accepted
range **2…13** (`if (currentVersion >= 2 && currentVersion <= configVersion)`).

```
u32 version                ; 2..13
u32 datacenterId
u32 lastInitVersion        ; v>=3
u32 lastInitMediaVersion   ; v>=10
4 × array                  ; 1 array if v<5: [ipv4]
                           ; order: ipv4, ipv6, ipv4-download, ipv6-download
    u32 n ; n × { string address; u32 port; i32 flags; string secret }
                           ; flags only if v>=7 ; secret only if v>=11 (raw)
                           ; v 9..10: secret is a hex string, decoded in place
u32 isCdnDatacenter bool   ; v>=6
u32 keyLen ; key[keyLen]   ; authKeyPerm  (no length check, no padding!)
i64 authKeyPermId          ; v>=4 ; v<4: u32 present + i64
u32 tmpLen ; tmp[tmpLen]   ; authKeyTemp   (v>=8)
i64 authKeyTempId
u32 medLen ; med[medLen]   ; authKeyMediaTemp (v>=12)
i64 authKeyMediaTempId
i32 authorized
u32 nSalts ; nSalts × {i32 valid_since; i32 valid_until; i64 salt}
u32 nMediaSalts ; …        ; v>=13
```

Note the asymmetry that matters for F1: keys are written with
`writeInt32(len) + writeBytes()` (no alignment padding), while addresses/secrets
use the padded `writeString()`. Both are read correctly, but **`len` is not
validated against 256 anywhere**.

### 1.3 `files/dc<id>conf.dat`

Written by `Datacenter::storeCurrentAddressAndPortNum` (13.1.1:468-484), read in
the `Datacenter` ctor (13.1.1:171-194):

```
u32 size
u32 version (>=1 accepted, no upper bound!)
u32 currentPortNumIpv4 ; u32 currentAddressNumIpv4
u32 currentPortNumIpv6 ; u32 currentAddressNumIpv6
u32 currentPortNumIpv4Download ; u32 currentAddressNumIpv4Download
u32 currentPortNumIpv6Download ; u32 currentAddressNumIpv6Download
```

All eight are attacker-chosen `uint32`; only `currentPortNum*` has a consumer
that forgets to clamp (F2).

Annotated baseline (produced by `src/gen_dat.py`, parsed back by the harness):

```
0000  dc 01 00 00 | 05 00 00 00            size=476, version=5
0004  ...                                  testBackend=F, clientBlocked=F
0010  02 65 6e 00                          langcode "en"
0014  b5 75 72 99                          hasConfig=TRUE
0018  02 00 00 00  dcId=2
...
0040  01 00 00 00 | 0d 00 00 00 | 02 00 00 00   nDC=1, dc version=13, dcId=2
0054  02 00 00 00                            nAddr4=2
0058  0e "149.154.167.51" 00 | bb 01 00 00 | 00 00 00 00 | 00 00 00 00
...
00a0  <keyLen=256>
```

---

## 2. When it runs, and what the app does with the file

```
w0.onCreate (72799 w0.smali:2263)
  ├─ const/4 v6, 0x0                                    ; native_setJava(false)
  ├─ ks.g(context)                     w0.smali:2737     ; local-lib loader decision
  ├─ ConnectionsManager.native_setJava(false)  :2740    ; jclass_ByteBuffer stays null
  └─ … later, per account:
       ConnectionsManager.init(...)  (jadx72799_c1 ConnectionsManager.java:1968)
         └─ native_init(account, …, configPath = files[/account<N>], …)
              └─ ConnectionsManager::init      ConnectionsManager.cpp:3682
                   ├─ currentConfigPath = configPath + "/"
                   └─ loadConfig()             :3717  ← synchronous, first file I/O
                        ├─ Config("tgnet.dat") → readConfig() → parse (§1.1/1.2)
                        │    └─ per record: Datacenter ctor → Config("dc<N>conf.dat") → readConfig()
                        └─ may call saveConfig() → writeConfig() (re-serialises what was parsed)
```

Consequences:

* The parse is **after** the library is loaded and after `ks.g` has already
  chosen the library. Nothing in the parse can influence that decision.
* It is **synchronous on the thread that calls `native_init`**, i.e. before the
  network thread exists — a crash here is an immediate startup crash loop.
* `Config::Config` (13.1.1:18-29, binary `sub_102F014`) first looks for
  `<name>.bak`; if present it **deletes `<name>` and renames `.bak` into place**.
  So a write primitive that can only create `tgnet.dat.bak` still controls the
  next parse (and `writeConfig` deletes the `.bak` only after a successful save).
* Files live in `/data/user/0/<pkg>/files[/account<N>]/` → **survive app
  updates** and clear-data only. The parser ships in the APK; the parse code is
  identical in 9.7.6, 13.1.1 and the 13.2.0-beta binary (§4), so an update does
  not change any of F1–F4.

---

## 3. Taint ledger — every file-derived value and its sink

| Value (file) | Sink(s) | Verdict |
|---|---|---|
| `size` (4-byte prefix) | `getFreeBuffer(size)`; `fread` | **F3** (sign truncation → up to 4 GiB) |
| `version` (tgnet) | `<= 5` gate | clean |
| `testBackend`,`clientBlocked`,`registered…`,`hasConfig`,`authorized`,`isCdnDatacenter` | bool fields | clean |
| `lastInitSystemLangcode` | `std::string` | clean (validated read) |
| `currentDatacenterId` | map lookup, log | clean |
| `timeDifference`, `lastDcUpdateTime`, `pushSessionId` | arithmetic / int64 | clean |
| `sessionsToDestroy` count | `push_back(int64)` loop | **F4** |
| datacenter count | `new Datacenter` + `std::map::operator[]` loop | **F4** (+ leak: same dcId replaces without delete) |
| `datacenterId` | map key; `"dc"+id+"conf.dat"` (decimal, no `/`) | clean |
| address count (×4) | `std::vector<TcpAddress>::push_back` | **F4** (measured: 2·10⁶ → 326 MB) |
| `address` string | `getaddrinfo` / inet_pton | clean |
| `port` | `uint16_t` cast, `TcpAddress::port` | clean |
| `flags` | bit tests only | clean |
| `secret` (raw or hex) | `std::string`, proxy HMAC/AES (all `min(16,len)`) | clean, incl. `char2int` (`Defines.h:198`: unknown char → 0, length halved, max index `2·(n/2)−1 < n`) |
| `keyLen` + key bytes | `ByteArray(len)`; consumed as 256-byte key | **F1** (OOB read) |
| `authKey*Id` | int64 sent in packets | clean |
| salt count (×2) | `new TL_future_salt` + vector | **F4** |
| `valid_since/until`, `salt` | int32/int64 sort/compare | clean |
| `dc*conf` counters | `getCurrentAddress`/`getCurrentPort` (clamped) | clean |
| `dc*conf` `currentPortNum*` | `isCustomPort` → `defaultPorts[i]` | **F2** (latent OOB read) |

Checked and clean (the specific items in the task brief):

* `readString` / `readBytes` / `readByteArray` / `readByteBuffer` — `readBytes(len)`
  validates `len ≤ _limit − _position` and the other three validate
  `len + padding ≤ _limit − _position` before touching the buffer
  (`NativeByteBuffer.cpp:529-674`; binary `sub_102A30C`, `sub_102A388`,
  `sub_102A424`, `sub_102A538`, `sub_102A648`). `readBytes(len)` allocates only
  after the check, so a 16 MiB string cannot become a 4 GiB allocation.
* `ByteArray` length vs 256 — **the one genuine miss** (F1).
* secret hex conversion (`char2int`) — cannot index out of range, and the output
  string is `n/2` bytes for an `n`-char input.
* `TcpAddress` vectors — `push_back` only; all later indexing clamps against
  `size()` (`getCurrentAddress` 13.1.1:233-250, `getCurrentPort` :300-336).
* allocation sizes — `BuffersStorage::getFreeBuffer` maps 8/128/1224/4296/16584/
  40000/160000 or `new[size]`, always `capacity ≥ size`, then `limit(size)`.
* `memcpy` — only fixed-size copies (16/32/36/68/256) or copies whose length was
  bounds-checked immediately before.
* integer wraps — `_position + l + addition` and `_position + length` are uint32;
  a wrap needs `_position ≥ ~0xFF000000`, i.e. a ≥4 GiB buffer (only possible via
  F3) *and* a 4 GiB file. Even then the consequence is an over-*read* inside
  `readString`/`readBytes`, never a write. Recorded as residual/theoretical.

---

## 4. Binary ↔ source equivalence (no planted deviation)

Every function on the path was decompiled and compared with the 13.1.1 source
(identical to 9.7.6 for all of these, `diff` clean except comments):

| source | binary | check |
|---|---|---|
| `ConnectionsManager::loadConfig` | `sub_10035D8` | identical, incl. the two unbounded `for (… ; j != 0; --j)` loops (sessions `0x100374C`, datacenters `0x1003778`) |
| `Config::readConfig` | `sub_102F180` | identical; guard at `0x102F29C SXTW X8,W22` / `0x102F2A0 CMP X21,X8` / `0x102F2A4 B.LE` |
| `Config::Config` (.bak rename) | `sub_102F014` | identical |
| `Datacenter::Datacenter(int,NativeByteBuffer*)` | `sub_101D1F8` | identical: `v13<=4 ? 1 : 4` arrays, key/salt reads, `readBytes` calls |
| `Datacenter::getCurrentPort` | `sub_101DA6C` | clamp present (`if (v9 > 3) v9 = 0` + write-back) |
| `Datacenter::isCustomPort` | `sub_101DEC4` | **no clamp**: `0x101DF28 LDR W8,[X9,X8,LSL#2]` |
| `Datacenter::createRequestsData` | `sub_101F468` | `0x101F908 LDR X8,[X19,#8]` + `0x101F90C ADD X1,X8,#0x58` + `W2=#0x20` → `SHA256_Update(authKey->bytes+88,32)` |
| `BuffersStorage::getFreeBuffer` | `sub_FFFD58` | identical pool classes |
| `NativeByteBuffer::NativeByteBuffer(uint32)` | `sub_1029504` | `if (jclass_ByteBuffer)` else `operator new[] (size)`; `jclass_ByteBuffer` is null because `native_setJava(false)` (`w0.smali:2320 const/4 v6,0x0`, `:2740`) |
| `readInt32/readInt64/readBool/readString/readBytes/readByteArray/readByteBuffer` | `sub_102A03C / 102A0D4 / 102A290 / 102A424 / 102A388 / 102A30C / 102A538 / 102A648` | identical bounds logic (see `lab/…/ida/step2.txt`, `step3.txt`) |
| `generateMessageKey` (inline) | inlined into `sub_101F468` | reads `authKey + 0/40/88/…` with no length check |

IDA extracts: `lab/tgnet_parser_audit/ida/step*.txt` (step numbers are the analysis order, not contiguous).

---

## 5. Findings

### F1 — parsed auth key length vs the fixed 256-byte key (OOB read, reachable)

`Datacenter.cpp:122-145` (binary `sub_101D1F8`): `:123` perm, `:136` temp, `:143` media:

```c
uint32_t len = data->readUint32(nullptr);
if (len != 0) authKeyPerm = data->readBytes(len, nullptr);   // any len ≤ remaining
…
if (len != 0) authKeyTemp = data->readBytes(len, nullptr);
```

`readBytes` allocates exactly `len` bytes. Nothing ever compares `length` with
256. The key is then used by `Datacenter::createRequestsData`
(`Datacenter.cpp:1113-1245`, binary `sub_101F468`) and by
`Datacenter::decryptServerResponse` (`:1246-1283`):

```c
SHA256_Update(&sha256Ctx, authKey->bytes + 88, 32);          // :1216
generateMessageKey(instanceNum, authKey->bytes, …, 2);       // :1240 → reads +0..+36, +40..+76
```

Reachability detail that a naive reading gets wrong: `getAuthKey(type, perm=
pfsInit, …)` only returns `authKeyPerm` when `isCdnDatacenter || perm ||
!PFS_ENABLED` (`:1075-1105`). With `PFS_ENABLED=1`, a normal DC therefore uses
**`authKeyTemp`** for its first packets, and `hasAuthKey()` is true as soon as
`authKeyTemp != nullptr` — so **`authKeyTemp = 1 byte` is enough** to get the
over-read on the first outgoing packet, no handshake required. Setting
`isCdnDatacenter` (v ≥ 6 bool) selects `authKeyPerm` instead.

`createRequestsData` is called by `ConnectionsManager::sendMessagesToConnection`
(`ConnectionsManager.cpp:2312`) and `sendPing` (`:1805`) **before**
`Connection::sendData()`/`connect()`, so the over-read happens even when the
(equally attacker-chosen) DC address is unreachable. The one precondition that
does *not* come from the file is `ConnectionsManager::currentUserId != 0` (a
Java-side value), i.e. the scenario is "plant the file on an installation that is
already logged in", not "own a fresh install".

Proof (`lab/…/out/poc_keylen_shorttemp.log`, real `ByteArray`/`NativeByteBuffer`
compiled from the tree, plus the verbatim `generateMessageKey` and the
`authKey->bytes + 88` line):

```
parsed dc2 (cdn=0): authKeyTemp->length = 1 (heap block = 1 bytes)
==ERROR: AddressSanitizer: heap-buffer-overflow … READ of size 36
  0 bytes after 1-byte region
  #1 SHA256_Update
  #2 generateMessageKey(...)  poc_keylen.cpp:28
  #0 operator new[](unsigned long)
  #1 ByteArray::ByteArray(unsigned int) ByteArray.cpp:20
  #2 NativeByteBuffer::readBytes(unsigned int, bool*) NativeByteBuffer.cpp:549
  #3 HDC::readFrom(...)  harness.cpp:143
```

Same for `authKeyPerm` (CDN) and `authKeyMediaTemp`.

**Why this is not code execution.** Every consumer is a *read*. The bytes after
the allocation are fed to SHA-256/SHA-1 to derive the message key; the derived
key is used as an AES-IGE key on the outgoing buffer (`Datacenter.cpp:1241`
`aesIgeEncryption(buffer->bytes()+24, messageKey+32, …)`), so the over-read data
is never transmitted in a recoverable form and is not attacker-visible. The
packet is undecryptable by the peer, so the session just dies. On Android the
over-read stays inside the same scudo arena, so in practice it neither crashes
nor leaks. ASan flags it; a real-device crash would need the 1-byte allocation to
sit at the very end of a mapping.

### F2 — `isCustomPort()` indexes `defaultPorts[]` unclamped (OOB read, latent)

```c
// Datacenter.cpp:445-466 (return at :465)
bool Datacenter::isCustomPort(uint32_t flags) {
    … currentPortNum = currentPortNumIpv4 …;
    return defaultPorts[currentPortNum] != -1;     // :465, no clamp
}
```

`defaultPorts = new int32_t[4]{-1,443,5222,-1}` is a 16-byte heap block. Binary
`sub_101DEC4`:

```
0x101DF20  LDR  W8, [X8]              ; currentPortNum (uint32 from dc<id>conf.dat)
0x101DF24  LDR  X9, [X0,#8]           ; defaultPorts
0x101DF28  LDR  W8, [X9,X8,LSL#2]     ; OOB read, up to +0x3FFFFFFFC
```

By contrast `getCurrentPort` (`sub_101DA6C`, source `:299-335`) clamps:

```c
if (currentPortNum >= 4) { currentPortNum = 0; currentPortNumIpv4 = currentPortNum; … }
```

`isCustomPort` is only called from `Connection::onDisconnectedInternal`
(`Connection.cpp:660`, binary `sub_10170C4` → `BL sub_101DEC4` at `0x101713C`),
i.e. after `reason == 2 && wasConnected`, and `Connection::connect()` has already
called `getCurrentPort(currentAddressFlags)` for the same flag word (which
rewrote the counter to 0). So as shipped the index is always 0.

Proof (`lab/…/out/poc_isport.log`): with `dc2conf.dat` `currentPortNumIpv4 =
0x40000000`, the guarded order prints `currentPortNumIpv4 = 0` → `isCustomPort =
0`; calling it with the raw value instead gives
`AddressSanitizer: SEGV … READ … in isCustomPort`.

Residual: it becomes reachable if any future/other caller invokes `isCustomPort`
without a preceding `getCurrentPort` for the same flags (patching
`Connection.cpp` locally would do it). Recorded as a latent defect, not a live
primitive.

### F3 — size-field sign truncation (DoS, 4-byte file)

```c
// Config.cpp:45  ==  sub_102F180
if (bytesRead > 0 && size > 0 && (int32_t) size < fileSize) {
    buffer = BuffersStorage::getInstance().getFreeBuffer(size);   // up to 4 GiB
    if (fread(buffer->bytes(), 1, size, file) != size) { … }
```

```
0x102F29C  SXTW  X8, W22      ; (int64)(int32)size
0x102F2A0  CMP   X21, X8      ; fileSize > (int32)size ?
0x102F2A4  B.LE  loc_102F2E0
0x102F2AC  MOV   W1, W22
0x102F2B0  BL    sub_FFFD58    ; getFreeBuffer(0x80000000…0xFFFFFFFF)
```

A 4-byte file `00 00 00 80` → `getFreeBuffer(0x80000000)` → `new uint8_t[2 GiB]`
(`jclass_ByteBuffer == null`, see §4). In the real code there is no handler: the
allocation either succeeds (then the `fread` fails and the buffer is recycled) or
`operator new[]` throws/aborts. `out/poc_sizefield.log`:

```
fileSize=4 size=0x80000000 (int32_t)size=-2147483648  guard-taken=YES
-> BuffersStorage::getFreeBuffer(2147483648) would be called -> new uint8_t[2147483648]
```
and with `--alloc` + `RLIMIT_AS`: `ERROR: Failed to mmap`.

Same file/guard for `dc<id>conf.dat` (same `Config` class).

### F4 — unbounded counts (DoS)

All four loops trust a `uint32` from the file and do not advance the buffer when
a read fails (`read*` returns 0 and leaves `_position` alone):

| site | source | binary |
|---|---|---|
| `sessionsToDestroy` | `ConnectionsManager.cpp:399-401` | `sub_10035D8` `for (i = readUint32; ; --i)` |
| datacenters | `:403-411` (`new Datacenter` each iteration) | same |
| addresses (×4) | `Datacenter.cpp:91` | `sub_101D1F8` |
| salts (×2) | `Datacenter.cpp:149`, `:158` | `sub_101D1F8` |

Measured (`out/poc_count_dos.log`; harness with the guard raised to 2·10⁶): a
`tgnet.dat` with `naddr4 = 0xFFFFFFFF` grows to **326 MB in 0.6 s** for 2·10⁶
pushed `TcpAddress` (≈170 B/entry incl. vector doubling) → the full 2³²−1 would
need ≈ **730 GB** (or run for hours with the 16 MiB-prefix paths). The
datacenter loop is worse: one `new Datacenter` (which opens and parses a
`dc<N>conf.dat`!) per iteration, with an uninitialised `datacenterId` when the
reads fail (side defect below), and the previous object is leaked (map
assignment) — a guaranteed boot loop.

These are the already-reported DoS bugs; the new data point is that the
**address** loop is equally unbounded and is the cheapest trigger (one field,
no valid record needed).

Side defect on the same path: `Datacenter::Datacenter(int32_t, NativeByteBuffer*)`
never initialises `datacenterId` before the `version` check (`Datacenter.h:87`
has no initialiser; binary `sub_101D1F8` stores to `+20` only inside the
`if (version >= 2 && version <= 13)` branch). When the buffer is exhausted the
version reads as 0, so `getDatacenterId()` returns **uninitialised stack/heap
memory** which then becomes the `std::map` key and the `"dc<N>conf.dat"` file
name. It is a CWE-457 uninitialised read (no memory-safety consequence: the value
is only used as a key / decimal path component), but it makes the F4 datacenter
loop non-deterministic and leaks the old map entry for repeated keys.

---

## 6. Fuzzing / differential evidence

| run | what | result |
|---|---|---|
| libFuzzer + ASan, 300 s | `fuzz_parser`, seeds = valid synthetic variants **plus two real 72799 device dumps** (`/tmp/opencode/sony_tgnet.dat`, `/tmp/opencode/tgnet.dat`), parse body verbatim, guards only on the DoS counts | **2,183,031 execs, 458 edges, 0 crashes** (`out/fuzz.log`) |
| structured corpus (synthetic) | 1,376 files: every truncation, every byte poisoned with 00/FF, boundary values (0,1,2,3,0xFD,0xFE,0xFF,0x100,0xFFFF,0xFFFFFF,0x7FFFFFFF,0x80000000,0xFFFFFFFE,0xFFFFFFFF) at every length/count field, dc/tgnet version sweeps, size-prefix sweep | **0 failures** (`run_cases.sh cases`) |
| structured corpus (real dump) | 19,057 files: **every** truncation of `sony_tgnet.dat` (6,352 B, 5 DCs) and **every** byte of it replaced by 00 and FF | **0 failures** (`run_cases.sh real_cases`) |
| earlier libFuzzer run (no address-count guard) | same | OOM at `malloc(4831838208)` inside `std::vector<TcpAddress>::push_back` ← F4 reproduced by the fuzzer itself |

Format validation: the harness parses the real 72799 dumps exactly
(`out/parse_real.log`) — `version=5`, `langcode "it-it"`, 5 datacenters, 4
sessions, per-DC `lastInitVersion = 72799` / `lastInitMediaVersion = 72789|72799`
(the app versionCode), 256-byte perm keys, mixed `authorized` flags, salts and
media salts. Nothing in the real files contradicts §1.

The harness compiles `NativeByteBuffer.cpp`, `ByteArray.cpp`, `BuffersStorage.cpp`,
`FileLog.cpp` **unmodified** from the 13.1.1 tree; the parse bodies are verbatim
copies (mechanical `this->` only) and the DoS guards are marked, so the fuzz
result is a statement about the shipped parser, not about a rewrite. The same
harness built against the **9.7.6** tree compiles and parses the real dump
identically (`TGNET_SRC=/tmp/opencode/telegram_src/TMessagesProj/jni/tgnet`),
which is the practical form of the “9.7.6 == 13.1.1 for this code” claim.

Generated case directories (`cases/`, `real_cases/`, ~134 MB) are not stored;
`README.md` has the two commands that recreate them.

---

## 7. Answers to the brief

1. **Simple memory corruption?** No OOB write. Two OOB reads: F1 (reachable,
   proven) and F2 (latent, proven).
2. **Can it give native code execution?** No: the only file→memory effects are
   reads and allocation sizes; no length is ever used as a destination size
   without a bounds check, and no function pointer/index derived from the file is
   used to write.
3. **Can it force the `ks` local-lib loader?** No. `loadConfig()` is called from
   `ConnectionsManager::init` via `native_init`, i.e. strictly after
   `System.loadLibrary("tmessages.49")`/`JNI_OnLoad` succeeded (and after
   `ks.g`). `tgnet` has no `dlopen`/`dlsym`/`loadLibrary`. The parser cannot
   make the loader run, and a crash inside it cannot *cause* the fallback — the
   loader has already finished.
4. **Update survival?** Files persist in app-private storage across updates; the
   parser is unchanged between 9.7.6, 13.1.1 and the 13.2.0-beta binary, so F1–F4
   persist across updates. `tgnet.dat.bak` is consumed and renamed over
   `tgnet.dat` at startup (extra write-target nuance).
5. **Is it a sandbox escape?** No. Reaching these files already requires write
   access to the app's private directory (same UID or root). The realistic use is
   (a) startup DoS, (b) account/DC redirection when the file can be read, (c) a
   heap over-read that is not attacker-observable.

## 8. What would change the verdict

* Any caller that reaches `isCustomPort` (or `defaultPorts`) without the
  `getCurrentPort` clamp → F2 becomes a controllable OOB read/SEGV.
* A consumer that copies `authKey->length` bytes into a fixed 256-byte buffer
  (today all consumers only read) → F1 becomes an overwrite.
* The `_position` uint32 wrap needs a ≥4 GiB config file *and* the F3 allocation
  to succeed; even then it yields an over-read only.

## Appendix — reproduction

```
cd lab/tgnet_parser_audit
./build.sh                      # clang++ -fsanitize=address (harness, fuzzer, 3 PoCs)
python3 src/gen_dat.py corpus   # format writer (also documents the format)
ASAN_OPTIONS=detect_leaks=0 ./build/harness corpus              # round-trip
ASAN_OPTIONS=detect_leaks=0 ./build/poc_keylen corpus/shorttemp # F1
ASAN_OPTIONS=detect_leaks=0 ./build/poc_isport corpus           # F2
ASAN_OPTIONS=detect_leaks=0 ./build/poc_sizefield               # F3
python3 src/cases.py cases && ./run_cases.sh                    # 1,376 structured cases
./run_cases.sh real_cases                                       # 19,057 real-dump cases
./build/fuzz_parser -max_total_time=300 fuzz_corpus             # F3/F4 counts guarded;
                                                                # F1/F2 are in the connection layer (PoCs)
```

Key addresses (image base 0): `loadConfig 0x10035D8`, `Config::readConfig
0x102F180`, `Config ctor 0x102F014`, `Datacenter ctor 0x101D1F8`,
`getCurrentPort 0x101DA6C`, `isCustomPort 0x101DEC4`, `createRequestsData
0x101F468`, `getFreeBuffer 0xFFFD58`, `NativeByteBuffer ctor 0x1029504`,
`readInt32 0x102A03C`, `readInt64 0x102A0D4`, `readBool 0x102A290`,
`readBytes(buf) 0x102A30C`, `readBytes(len) 0x102A388`, `readString 0x102A424`,
`readByteArray 0x102A538`, `readByteBuffer 0x102A648`.
