# BoringSSL vs `tgnet.dat` at boot — does the DC-key config reach the crypto parser?

Date: 2026-11-03
Target: `org.telegram.messenger.beta` 13.2.0 beta, versionCode **72799**, arm64
(`libtmessages.49.so`, md5 `2c0caa68a07fc26f79d13519af6c3526`, BuildId
`645cce3998197329915f6cbfcc9ffd7f124d9f86`), Sony XQ-BT52 (<SERIAL>),
Android 13. Host IDA + device (root, Frida 17.17) pass.

Scope: the hypothesis "`files/tgnet.dat` carries DC public keys/params that
BoringSSL/OpenSSL parse with ASN.1/X.509/RSA/PEM code at app boot, so a
malformed key file can reach a BoringSSL memory-corruption bug and give ACE".

Separate from the main report (`REPORT_20261102.md`), which is not modified.
Lab: `lab/boringssl_tgnet_ace/` (parser map, CVE matrix, corpus, device logs,
Frida probe).

---

## 0. Verdict

**The hypothesis is false for this build. `tgnet.dat` never reaches a
BoringSSL/OpenSSL parser.**

* `Config::readConfig` (`sub_102F180`) and `Datacenter::Datacenter(int,
  NativeByteBuffer*)` (`sub_101D1F8`) are pure length-prefixed
  integer/string/byte-array readers. Their CFG-restricted call closures
  (129 and 205 functions) contain **no** BoringSSL function at all — not
  `PEM_*`, not `d2i_*`, not `ASN1_*`, not `BN_*`, not `EVP_*`, not even the
  SHA/AES primitives (verified by full call-graph closure over the 80,521-function
  IDB, plus a manual call-list review).
* The byte arrays the file does carry — the 256-byte MTProto **auth keys**, the
  16-byte **transport secret**, addresses/ports/salts — are consumed as opaque
  keys by the *transport* layer: `SHA256_Update(authKey+0x58, 0x20)` at
  `0x101F90C` and AES-IGE/AES-CTR in `Connection`. There is no parser on that
  path, only fixed-size reads (and the known F1 over-read when the stored key is
  shorter than 256 bytes — still a **read**).
* BoringSSL's PEM→ASN.1→RSA code **is** statically linked and **is** reachable
  from tgnet, but from exactly **two** callers of
  `PEM_read_bio_RSAPublicKey` (`0x156989C`), neither of them config-driven:
  * `0x102C0F8` in `sub_102B7B8` (handshake), PEM = **compile-time**
    `serverPublicKeys` strings (`0x20182D`, `0x24670A`);
  * `0x102DE98` in `sub_102DDA4` (after `cdnConfig loaded`), PEM = **network**
    `TL_cdnConfig.public_keys[i].public_key`.

  A third PEM site, `Datacenter::decodeSimpleConfig` `sub_10200A8`
  (`0x1020130`), uses the **compile-time** PEM `0x26394F` to decrypt a
  **network** DNS-config blob (`sub_100D334`: "trying to decrypt config %d").
* Device proof: a PEM and a DER RSAPublicKey planted in a datacenter's auth-key
  field are parsed at startup and **written back byte-identically** (opaque
  `ByteArray`), and a Frida probe shows **0 calls** to
  `PEM_read_bio_RSAPublicKey` and **0 calls** to the ASN.1 decoders during
  startup, while a direct `d2i_RSAPublicKey()` control call on the same buffer
  succeeds (parser works, hook works).

**No ACE. The strongest thing reachable from `tgnet.dat` remains the previously
reported F1 heap over-read (≤136 B, hashed, no leak) and the parser
desynchronisation/DoS described below.**

---

## 1. What the file actually contains (and who consumes it)

`files/tgnet.dat` (and `files/account<N>/tgnet.dat`) is the tgnet
`ConnectionsManager` config: `[u32 size][u32 version=5][bool testBackend]
[bool clientBlocked][string langcode][bool hasConfig][currentDc, timeDiff,
lastDcUpdate, pushSessionId, registered, lastServerTime, sessions[],
datacenters[]]`. Each `datacenter` record carries, per `Datacenter::serializeToStream`
(13.1.1:538-609):

| field (file) | binary consumer | what it becomes | crypto? |
|---|---|---|---|
| `version`, `dcId`, `lastInit*` | `sub_101D1F8` | ints / map key | no |
| 4 × address arrays: `ip`, `port`, `flags`, **`secret`** | `sub_101D1F8` + `TcpAddress` | `std::string`/ints; `secret` is the **transport obfuscation secret** (16 B), used by `Connection` (AES-CTR/HMAC via `computeSHA1`) with `min(16,len)` | transport only, key material, not parsed |
| **`authKeyPerm` / `authKeyTemp` / `authKeyMediaTemp`** | `sub_101D1F8` → `Datacenter` | opaque `ByteArray(len)` — MTProto auth keys (normally 256 B) | consumed by SHA-256/AES-IGE in `createRequestsData` (`sub_101F468`), fixed offsets |
| `keyId`, `*Salt`, `authorized` | `sub_101D1F8` | ints | no |
| `langcode` | `sub_102F180` → `std::string` | string | no |

There is **no ASN.1, DER, PEM, X.509, DH or RSA structure anywhere in this
format.** Telegram's DC RSA public keys are not in the file: they are
compile-time PEM constants baked into tgnet (`0x20182D`, `0x24670A`, `0x26394F`)
and, for CDN DCs, delivered inside the encrypted MTProto session
(`help.getCdnConfig`).

Evidence (IDA, 72799):

* `Config::readConfig` `sub_102F180` — calls only `fopen`(`sub_102F748`),
  `fseek`, `ftell`, `fread`, `fclose`, buffer pool (`sub_FFFBBC`/`sub_FFFD58`),
  `NativeByteBuffer` + read helpers (`sub_10297E4`, `sub_102A7A8`).
* `Datacenter::Datacenter(int,NativeByteBuffer*)` `sub_101D1F8` — calls only
  `memset`, address helpers (`sub_1010A18`, `sub_101439C`, `sub_10144F8`,
  `sub_1014574`), read helpers (`sub_102A290`, `sub_10216xx…`), `Config::Config`
  (`sub_102F014`) for the per-DC `dc<N>conf.dat`, and `std::string`/allocator
  helpers (`sub_16A51B0`, `sub_16A53AC`, `sub_16E94A0`, `sub_77B894`,
  `sub_78E52C`).
* Full closure intersection with the 186 BoringSSL functions that reference
  `crypto/...` source paths: **0** for `loadConfig`, `readConfig`,
  `Datacenter::Datacenter`, `ConnectionsManager::init`.
* `*.dat` is plaintext, no MAC, no signature (prior audit §1); the only
  integrity check in the chain is the per-datacenter `authorized` flag and the
  server's rejection of a wrong auth key.

---

## 2. The BoringSSL/OpenSSL code that *is* reachable from tgnet

### 2.1 Fingerprint of the linked BoringSSL

| property | evidence |
|---|---|
| statically linked BoringSSL (not OpenSSL, not a `.so`) | 151 `__FILE__` strings under `/jni/third_party/boringssl/…` (`ssl/`, `crypto/asn1`, `crypto/x509`, `crypto/pem`, `crypto/rsa`, `crypto/fipsmodule/bn`, `crypto/pkcs8`, …); `DT_NEEDED` has **no** `libcrypto`/`libssl` |
| custom allocator hooks | `OPENSSL_memory_alloc/free/get_size` are **WEAK UND** symbols (BoringSSL hook pattern), no definitions needed |
| snapshot era | `X25519MLKEM768` string (`0x2122E6`) → BoringSSL ≥ late 2024 (ML-KEM rename); `ssl/ssl_credential.cc` (`0x21CBC8`) → 2025-era tree; `ssl/encrypted_client_hello.cc` (ECH) |
| toolchain | `.comment`: Android clang 18.0.3 (r522817c), Linker LLD 18.0.3 |
| code range | ASN.1/X.509/RSA/PEM/SSL functions cluster at `0x14B0000–0x1582000`; libc++/unwinder is elsewhere |

There is **no version string** (BoringSSL is unversioned); any "BoringSSL
3.x / OpenSSL CVE" mapping has to be done per CVE via Google's advisory
mapping, which is what §3 does.

### 2.2 The three PEM/ASN.1 sites, with their inputs

| # | function | PEM/ASN.1 call | PEM source | trigger |
|---|---|---|---|---|
| 1 | `sub_102B7B8` (`handshake: …` strings) | `sub_102E418`(`PEM_read_bio_RSAPublicKey`) @ `0x102C0F8`; `d2i_RSAPublicKey` `0x15698C0` via `sub_156BAE4` | **static** `serverPublicKeys` (`0x20182D`, `0x24670A`), selected by handshake type/test backend | network handshake, after connect |
| 2 | `sub_102DDA4` (`cdnConfig loaded begin handshake`) | same wrapper @ `0x102DE98` | **network** `TL_cdnConfig.public_keys[]` (inside the encrypted session) | `help.getCdnConfig` response |
| 3 | `sub_10200A8` (`Datacenter::decodeSimpleConfig`) | `PEM_read_bio_RSAPublicKey` @ `0x1020130`, then `BN_mod_exp`, `AES-CBC`, `EVP_Digest*` | **static** DNS-config key `0x26394F`; data buffer from `sub_100D334` ("trying to decrypt config %d") | DNS-config blob from the network |

`PEM_read_bio_RSAPublicKey` (`0x156989C`) has exactly these two callers in the
binary (`0x1020130`, `0x102E424`); `sub_102E418` is called from `0x102C0F8`
(handshake) and `0x102DE98` (CDN). `d2i_RSAPublicKey` is passed as a **function
pointer** into `PEM_ASN1_read_bio`, which is why a naive call-graph sees no
ASN.1 edge — the callback is `sub_15698C0`, and the ASN.1 template decoder lives
at `0x15323A8 / 0x1532CF8 / 0x1532F10 / 0x153368C / 0x15337EC`
(`crypto/asn1/tasn_dec.cc`).

**None of the three takes its bytes from `tgnet.dat`.** The config parser does
not call any of them, and no file field is ever passed to them.

### 2.3 The crypto that the file *does* reach (transport, fixed sizes)

`Datacenter::createRequestsData` `sub_101F468`:

```
0x101f8f8  BL  sub_1570C54          ; SHA256_Init
0x101f908  LDR X8,[X19,#8]          ; X8 = authKey->bytes
0x101f90c  ADD X1,X8,#0x58          ; authKey + 88
0x101f904  MOV W2,#0x20             ; 32 bytes
0x101f910  BL  sub_1570C6C          ; SHA256_Update  <-- reads 32B regardless of key length (F1)
0x101f918  BL  sub_1021920          ; message key / padding
0x101f924  BL  sub_1570C6C          ; SHA256_Update(..., W22+W23)
```

AES comes from `Connection::` (`aes_set_encrypt_key` hit stack
`0x156EE88 <- 0x10013E4`), i.e. the MTProto transport keyed by the `secret` /
auth key — again fixed-size key material, no parser.

That is the complete list of crypto reachable from the startup config path:
**SHA-256 and AES, with compile-time sizes.**

---

## 3. CVE matrix 2024–2026 (X.509 / ASN.1 / BN / PEM) and reachability

Method: Google publishes a BoringSSL counterpart for every OpenSSL advisory
(`docs/advisories/`). I fetched and read the advisories that cover the
ASN.1/X.509/BN/PEM write CVEs of the window: **2024-10-16, 2025-09-30,
2026-01-27, 2026-03-13, 2026-04-07, 2026-06-09, 2026-08-13, 2026-08-25,
2026-09-29**. Every row marked "verified" below is quoted from those files;
rows marked "not re-fetched" are OpenSSL-side facts whose BoringSSL mapping I
did not load in this pass (they are unreachable here for the same reason as the
verified ones). "Reachable from tgnet.dat" is this audit's column, not the
vendor's.

| CVE | Area | Impact | BoringSSL status (vendor) | Reachable from `tgnet.dat`? |
|---|---|---|---|---|
| CVE-2026-7383 | `ASN1_mbstring_ncopy` signed overflow → heap overflow | **write** (possible RCE) | **Not affected**, independently fixed 2018 (verified, 2026-06-09) | **no** — no ASN.1 string is ever decoded from the file |
| CVE-2026-34180 | ASN.1 content parsing over-read | read | Not affected (capped 2017; verified) | no |
| CVE-2026-35189 | X.509 CRLDP `nameRelativeToCRLIssuer` quadratic alloc | DoS | **Affected** in snapshots before 0.20260929.0 (verified); needs `X509_verify_cert` | no — tgnet never verifies a chain |
| CVE-2026-45447 | `PKCS7_verify` UAF | write-class | Not affected (module removed; verified) | no |
| CVE-2026-63072 | CMS key unwrap heap overflow | write | Not affected (removed; verified) | no |
| CVE-2026-31789 | hex conversion heap overflow | write | Not affected (verified) | no |
| CVE-2026-28386 | AES-CFB OOB read (AVX-512) | read | Not affected (verified) | n/a |
| CVE-2025-15467 | CMS AuthEnvelopedData stack overflow | write/RCE | Not affected (removed; verified 2026-01-27) | no |
| CVE-2025-69419 | `PKCS12_get_friendlyname` OOB write | write | Not affected (removed; verified 2026-01-27) | no |
| CVE-2025-68160 | `BIO_f_linebuffer` heap OOB write | write | Not affected (removed; verified 2026-01-27) | no |
| CVE-2025-11187 | PBMAC1 parameter validation | auth bypass | Not affected (verified 2026-01-27) | no |
| CVE-2024-9143 | GF(2^m) EC/BN OOB write | **write** | Not affected — code removed at fork (verified 2024-10-16) | no |
| CVE-2024-6119 | X.509 name checks OOB/DoS | read/DoS | not re-fetched | no |
| CVE-2024-5535 | `SSL_select_next_proto` over-read | read | not re-fetched | no |
| CVE-2024-4741 | `SSL_free_buffers` UAF | write-class | not re-fetched | no |
| CVE-2024-0727 | PKCS#12 NULL deref | DoS | not re-fetched | no |

**Affected versions / PoCs (as far as they matter here).** BoringSSL is
unversioned; Google tags releases (`0.YYYYMMDD.0`) and lists the fixing commit
per advisory. The only BoringSSL-affected entry above, CVE-2026-35189, is fixed
in `0.20260929.0` (commit `9b639f5b…`) and is a **memory DoS**. The OpenSSL
write CVEs (CVE-2026-7383, 2025-15467, 2025-69419, 2025-68160, 2024-9143, …)
have public write-ups/PoCs for *OpenSSL*, but every one of them is either
removed from BoringSSL at the fork or (CVE-2026-7383) independently fixed in
2018. None has a PoC that takes a `tgnet.dat`-shaped input, because none of them
is reachable from a config file.

**Reading of the matrix (critical):** even the one *write* CVE that a BoringSSL
snapshot of this era could plausibly carry (CVE-2026-7383 class) requires the
process to decode an **ASN.1 string** from attacker bytes. `tgnet.dat` never
produces ASN.1; the only ASN.1 inputs in the app are (a) three compile-time PEM
blobs and (b) certificates/PEMs that arrive **inside the encrypted MTProto
session or the DTLS handshake**. Those are network-trust surfaces, not
app-data-at-boot, and they are outside this brief. The X.509-affected item
(CVE-2026-35189) is a DoS that needs certificate-chain verification, which
tgnet does not perform.

No public PoC is applicable to `tgnet.dat` for any row; a PoC exists only for
the OpenSSL-only CMS/PKCS12 paths that BoringSSL removed.

---

## 4. Device tests (Sony, 72799, root + Frida 17.17)

Corpus built by taking the **real** device `files/tgnet.dat` (5,496 B,
version 5, 5 datacenters, 256-byte keys, round-trip verified byte-identical by
`tools/tgnet_dat.py`) and mutating one field at a time. All files were written
with `cat > …/files/tgnet.dat` so owner/SELinux label are preserved; the app was
force-stopped, started, and logcat captured (`logs/t_*.log`; tgnet debug logging
is enabled in this beta, so the parse is directly observable:
`Config(...) load, size = …` / `config version = 5` / `datacenter(... N loaded`).

| case | file mutation | startup result | crash | key round-trip |
|---|---|---|---|---|
| `t0_control` | original | version 5, 5 DCs loaded | no | — |
| `t_pem_key_dc3` | dc3 auth key = 425-byte **PEM RSA public key** | parsed, 5 DCs + dc3 | no | **verbatim** (`-----BEGIN RSA P…`) |
| `t_der_key_dc3` | dc3 auth key = 270-byte **DER RSAPublicKey** | parsed | no | **verbatim** (`30 82 01 0a 02 82 01 01 …`) |
| `t_der_bad_dc3` | dc3 key = DER with `0x7fffffff` length | parsed | no | not measured |
| `t_short_key_dc3` | dc3 key = 1 byte (F1) | parsed | no (dc3 unused) | — |
| `t_huge_keylen_dc3` | dc3 keyLen = `0xFFFFFFF0` | **desync**: dc3 with empty key, then two phantom `dc 0` records; current DC 4 lost | no | — |
| `t_pem_langcode` | langcode = PEM | parsed | no | — |
| `t_pem_secret_dc3` | dc3 address secret = PEM | parsed | no | — |

Two results matter:

1. **Opaque storage.** After startup the app rewrites `tgnet.dat`; the rewritten
   file still contains the exact PEM/DER bytes in `dc3.key`
   (`dc3.key == input`, byte-identical, 425/270 bytes). Nothing interpreted,
   normalised, rejected or re-encoded them.
2. **Frida probe** (`tools/probe_startup.js`, output
   `evidence/frida_probe_pem_key_dc3.txt`): with the PEM-key file,
   `PEM_read_bio_RSAPublicKey` = **0 hits**, the five `tasn_dec` ASN.1 entries =
   **0 hits** during the whole startup window, while `sha256_init` (90) and
   `aes_set_encrypt_key` (52) do fire from `Connection`/`createRequestsData`
   (transport). Positive control at the end of the same script: a direct
   `d2i_RSAPublicKey(<the same 270-byte DER>, 270)` returns a valid `RSA*`
   (`0xb400…2338`) — the parser and the hook work. The parser is simply not on
   the config path.

### 4.1 Side effect observed (availability, not memory safety)

`t_huge_keylen_dc3` did not abort the parse: `readBytes(0xFFFFFFF0)` fails the
bounds check and yields an empty key, but the reader **continues at the wrong
offset**, so the remaining bytes were decoded as two phantom `datacenter(0)`
records and `dc4`/`dc5` disappeared. The app then reported
`can't do request without login` and rewrote `files/cache4.db` at 00:36.
This is a **config-integrity/availability** bug (a 1-field edit can drop the
current DC), consistent with F3/F4, not a write primitive.

Caveat on the test account: the DB was not copied before the run, so the exact
pre-test login state cannot be reconstructed. What is verifiable *after* the
run: all four `cache4.db` copies have 0 rows in `users`/`dialogs`, the app sits
on the intro screen, and `tgnet.dat` still holds valid 256-byte auth keys for
dc1/2/4/5 with `currentDc = 4`. The 4.8 MB
`files/malformed_database/cache4.db` snapshot (556 users, from an earlier test)
was used once to restore the DB file; the app accepted it (538 users after
startup) but still did not re-activate the account. Consequence: the
authenticated send path (F1) could not be exercised on-device in this pass; the
startup parse — the surface under audit — was.

---

## 5. Why the F1 over-read cannot be upgraded to a write

F1 (short on-disk auth key) is real, but it is bounded and read-only:

* the short `ByteArray` is allocated by `readBytes(len)` with `len` = file value
  (1 … remaining); consumers read **fixed** 32/36/16-byte windows at fixed
  offsets (`authKey+0`, `+8`, `+40`, `+48`, `+64`, `+88`, …), never a
  file-derived length;
* those windows feed `SHA256_Update`/`SHA1`/`AES_ige_encrypt` as **input**; the
  *output* buffers (`sha[68]`, `result[48]`, the packet buffer) are stack/heap
  objects whose size is a compile-time constant, and the copy lengths
  (`memcpy(result, sha, 8/16/…)`) are constants;
* no file value is used as a destination pointer, as an allocation size for a
  write, or as a length for a write into a fixed buffer. The max over-read is
  ~136 B past a short heap allocation, hashed into a message key (no leak to the
  attacker) — crash at worst.

The ASN.1 angle would have been different (BoringSSL decoders *do* write into
allocated structures sized from the input), which is exactly why the reachability
result in §0/§2 matters: the file cannot reach them.

---

## 6. If it *had* been a write: deployment design and update test

Kept for completeness (the premise is false, so this is a design sketch, not a
plan):

1. **Primitive needed**: a memory-corruption write in a BoringSSL parser that is
   fed by a `tgnet.dat` field. None exists here.
2. **Deployment**: write `files/tgnet.dat` (and, if per-account, the active
   `files/account<N>/tgnet.dat`) as the first RCE's app-UID; `am force-stop` the
   package (or reboot); on next start `w0.onCreate → ks.g → native_setJava →
   ConnectionsManager.<init> → native_init → loadConfig` parses the file before
   any UI. No root, no `dlopen`, no widget.
3. **Update test**: `tgnet.dat` is in app data and survives `pm install -r`
   (only uninstall/clear-data removes it); after an update the same parse runs
   with the new `libtmessages.*.so` — so the payload must be re-validated
   against the new BoringSSL snapshot, and the file format version
   (`configVersion`) must still be accepted.
4. **Kill switch**: deleting the file is harmless (app falls back to defaults);
   restoring a good file un-breaks the client.

---

## 7. What would change the verdict

1. A future build that stores **PEM/DER/X.509 blobs** in `tgnet.dat` and feeds
   them to `PEM_read_bio_*`/`d2i_*` (today the keys are compile-time constants
   and the file holds only raw 256-byte auth keys).
2. A new call site from `Config::readConfig`/`Datacenter::Datacenter` into the
   BoringSSL region — re-run the closure check (`lab/…/tools`), it must stay 0.
3. A change that makes the app **verify** a certificate chain (X.509 CVE class
   becomes relevant) — today tgnet does not; DTLS in calls does its own thing
   and is a network surface.
4. Any switch from `PEM_read_bio_RSAPublicKey` to `d2i_*` over a file-backed
   buffer.

---

## 8. Files

```
lab/boringssl_tgnet_ace/
  README.md                 how to reproduce
  parser_map.md             field → function → consumer → crypto, with addresses
  cve_matrix.csv / .md      2024-2026 ASN.1/X.509/BN/PEM CVEs + reachability
  verdict.md                the negative result, one page
  device_plan.md            device tests (executed) + re-run recipe
  corpus/                   real file + 8 mutations (PEM/DER/bad-DER/short/huge/…)
  logs/                     per-case logcat + meta (md5 before/after, crash count)
  evidence/                 Frida probe output, IDA extracts
  tools/tgnet_dat.py        parser/rebuilder (round-trip verified)
  tools/run_case.sh         one device case
  tools/probe_startup.js    Frida hooks + positive control
  outputs/                  IDA decompiles (config parsers, crypto primitives)
```

IDB: `<HOME>/ailocal/Telegram/.opencode/idbs/libtmessages_49_arm64_media_annotated.i64`
(md5 verified), plus the packed backup
`libtmessages_49_arm64_native_startup_annotated.i64`.
