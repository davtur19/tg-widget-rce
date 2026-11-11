# Methodology

The project follows one rule: **a claim is only as good as the run that
produced it.** Everything else is a hypothesis or a host result.

## 1. Host first

Every primitive is reproduced on a host build of QuickJS-ng before it is run on
a phone. The host build is the same source revision as the app, compiled with
the same allocator model:

- `run6m`: a mutable 6 MiB limit, one synchronous `JS_Eval`, no host API.
- `run_sib_plain`: a sibling-script model that evaluates each `<script>` as a
  separate `JS_Eval` and continues after a throw.
- Instrumented variants that print the allocator decisions (`ACV`, `MTE2T`,
  `GCDBG`, arena class logs).

The host is not the device. It is a filter: if a primitive cannot be made to
work on the host, it is not taken to a device.

## 2. One device operation at a time

A device run is expensive and fragile. The orchestrator:

1. Recovers the USB link before every install/launch/pull.
2. Confirms the build, the package, and the widget process UID
   (app UID on 72929 and earlier; isolated UID on 72979/72989).
3. Installs one payload.
4. Opens one chat.
5. Reads the marker and pulls the proof file.
6. Records the exact payload hash, the result, and whether the app survived.

No two agents touch the device at once. A crashed run is not retried blindly;
the tombstone is read first.

## 3. Reproducibility

A payload is “shipped” only when:

- its SHA-256 is recorded;
- it rebuilds byte-for-byte from the generator in the repository;
- the size is under the delivery limit (32,768 raw / 4,096 zlib9);
- the probe is safe on the target build before the final runs.

The `c2560s` builder asserts the shipped SHA-256 of each canonical widget. The
iOS builder records raw/zlib/hash triples in `evidence/`.

## 4. One run is not a measurement

Heap layout depends on the process state. A single success can be luck. The
project therefore reports:

- **5/5**: five cold starts with fresh state.
- **3/3**: three host or device runs.
- **1/1**: one run, explicitly not a reliability number.
- **0/5**, **NOCORR**, **safe miss**: a failure that is part of the record.

The Sony cross-tag result is 5/5 on 72929 and 1/1 on 72889. The 1/1 is a
compatibility check, not a stability claim. The iOS 6s `RCE_OK` is one
successful device run after a long H sweep; the stage B was separately proven
64 times.

## 5. Allocation models

The two platforms differ:

- Android: QuickJS arena slabs are 64 KiB `mmap`s. Blocks ≤ 512 bytes come from
  the slabs; larger blocks come from Scudo. Scudo primary chunks are tagged
  under MTE. The arena is tag 0.
- iOS: QuickJS v0.17.0 uses 4 KiB arena blocks for ≤ 512 bytes and Apple malloc
  for larger blocks. Apple's tiny zone uses 16-byte quanta up to 1,008 bytes.

A payload that works on one model does not automatically work on the other.
The Android same-tag route and the iOS hole-reuse route are the same bug with
different geometry. Do not merge them.

## 6. Markers and negative results

Every payload prints a short marker. A safe miss is designed to be
distinguishable from a crash:

- Android: `NOCORR`, `HF ERR <token>`, `VK=0`, `VG=2`.
- iOS: `HIT=-1`, `PH=-1`, `NT=25`, `NO_TOPS`.

A crash is still evidence. Pull the `.ips`/tombstone, record the fault address
and the PC, and compare it to the expected geometry. The per-ID
`evidence/` logs contain many such negative results; they are kept because
they explain why a later design changed.

## 7. Build pinning

- Android beta 72929: `libtmessages.49.so` engine snapshot `2dfeee3e`.
- Android release 72801: same v0.17.0-era engine strings; the exact fork
  snapshot is inferred from strings, not from source. Treat layout claims for
  72801 as host-inferred until a device run confirms them.
- iOS 13.2 (36535): `TelegramUIFramework` 122,824,000 bytes, arm64, stripped,
  quickjs-ng v0.17.0.

A new Telegram build can change the engine, the heap baseline, or the struct
offsets. Re-run the probe. Do not reuse a final because the version number
looks close.

## 8. Honest negatives

The project keeps a list of things that did not work:

- N1 (`push_scope` OOM) is fatal on iOS and layout-fragile on Android.
- The C1/C2 parser bugs are not weaponizable in the widget model.
- The iOS giant-bytecode same-allocation variant peaks at 10.4 MB and OOMs at
  8 MiB.
- The iOS small-`b` arena variant lands in a foreign class-40 page.
- The litehtml table-span bug is clamped in the shipped builds.
- The `wr::` DOM surface has no concrete bug yet.

These are in the per-ID `evidence/` logs and in the route READMEs. They are not
failures of the project; they are the reasons the final chain looks the way it
does.

## 9. Evidence discipline

- Text logs and proof files are committed. APKs, `.so` files, databases,
  screenshots of the whole phone, and bot session files are not.
- A proof file is stored with its exact bytes and a hash.
- A marker quoted in a document must be copy-pasteable from a log in
  `evidence/` or from a named reference log.
- Timestamps are kept in the device's local time and labelled.

## 10. What is not claimed

- No root, kernel, or bootloader exploit.
- No iOS process creation or shell. The iOS sandbox still blocks `fork` and
  `execve` after native code execution.
- No universal single payload across Android MTE-on and iOS. The parser bug is
  shared; the geometry and endgame are not.
- No reliability number for a route that has not been run 5 times.
