# Parser 0day RCE: device certification 5/5 (hook-free)

> Superseded for cross-build universality by
> `logs/device_parser_rce/universal_dual/UNIVERSAL_2BUILDS.md`: the same
> `c2560s` widget (4,023 zlib9) writes the 185-B proof on both 13.2.1
> (72889) and 13.2.2 (72929), runtime ELF/GNU-hash resolver, no
> `JS_DEF_FREE`/`FREE_GOT`, no fixed VBase window. This 5/5 remains the
> build-72889 `c2560q` evidence.

Date: 2026-11-07
Device: Sony XQ-BT52 (<SERIAL>), Android 13, Telegram beta 13.2.1 (72889), uid 10346
Entrypoint: parser 0day; strict direct-eval `ARG_SCOPE_END` scope-index leak
            -> forged `ArrayBuffer` (byte_length 64 -> 327,744)
Endgame:   class-24 VBase (Uint8Array view object at V+4232)
           -> JSArenaSlab used-page bitmap (PG[81]) + arena/slab `a48`
           -> absolute `probeCtor`: shape -> proto -> prop -> C_FUNCTION
              -> realm -> rt -> malloc_limit
           -> ELF `.dynsym` linear scan -> libc `system`
           -> `system("id>.../files/n1")`

Widget: `device/widget/c2560_final_c2560q_72889.html`
        8,120 B raw / 3,289 B zlib9 (limits: 32,768 raw / 4,096 zlib9)
No Frida attached. A `frida-server` (the N1 hook-assisted setup) was
present during the original 5/5 but had no app mapping/tracer; it was
stopped and the `magisk-frida` module disabled for the clean 5/5 and the
no-root bot run (false alarm, see `AUDIT_no_root_cheat.md`).
No per-device constants. Only Telegram build 72889 offsets and
engine/Scudo rules; VBase, candidate, pages, arena/slab and `rt` are runtime.

## Result: 5/5

Run 1 (debug `c2560_debug_c2560q_72889.html`, 3,004 B zlib9), app alive:

```
S1 ABLEN[599]=327744 VLEN=327744 END=HF READY VNC=1 VO=1360 X=0 XG=0 G=0 GS=115 V=1 VK=1 VG=5
```

- `VK=1`: class-24 VBase found.
- `VG=5`: page window + used-bit guard OK.
- `X=0` / `XG=0`: absolute probe resolved the full chain.

Final runs 1-5 (`c2560_final_c2560q_72889.html`, 3,289 B zlib9), each run
force-stopped/relaunched the app, replaced `cache4.db`, deleted `n1`, opened
message 80345 and executed the final.

| run | proof | size | md5 |
|---|---|---:|---|
| 1 | `/data/user/0/org.telegram.messenger.beta/files/n1` | 185 B | 52258bc776f2f378542d1b2c736840e3 |
| 2 | same | 185 B | 52258bc776f2f378542d1b2c736840e3 |
| 3 | same | 185 B | 52258bc776f2f378542d1b2c736840e3 |
| 4 | same | 185 B | 52258bc776f2f378542d1b2c736840e3 |
| 5 | same | 185 B | 52258bc776f2f378542d1b2c736840e3 |

Proof content (identical in all 5):

```
uid=10346(u0_a346) gid=10346(u0_a346) groups=10346(u0_a346),3002(net_bt),3003(inet),9997(everybody),20346(u0_a346_cache),50346(all_a346) context=u:r:untrusted_app:s0:c90,c257,c512,c768
```

Post-battery checks:

- app alive: pid 28001 (`pidof org.telegram.messenger.beta`);
- `logcat` between 17:57 and 18:01: **0** `Fatal signal` / `SIGSEGV`;
- widget payload zlib 3,289 -> 8,120 bytes per run;
- 5 proof files byte-identical.

Evidence in this directory: `proof_run1..5.txt`, `run2..5.log` (empty: no
crash lines), `debug_ready_run1.png` (READY marker).

## No-root / no-Frida re-verification

After the original 5/5, `frida-server` PID 3999 was found running (installed
for the N1 work, listening on 127.0.0.1:27042). The app had no Frida
mapping, `TracerPid=0`, `CapEff=0` and no Magisk `su` policy, so this was a
false alarm; it was stopped and the module disabled anyway.

- **Clean 5/5 without Frida** (`logs/device_parser_rce/clean_nofrida/`):
  runs at 18:04:58, 18:05:27, 18:05:56, 18:10:56, 18:11:24; each run
  `NO_SU_NO_FRIDA` before/after, app uid 10346, `TracerPid=0`,
  `CapEff=0`, logcat `widget payload: zlib, 3289 -> 8120`, proof 185 B,
  md5 `52258bc776f2f378542d1b2c736840e3`.
- **No-root bot delivery 1/1** (`logs/device_parser_rce/noroot_bot/`):
  beta `sendWidget` to chat <CHAT_ID>, mid <CHAT_ID>, `is_shared=false`; the
  widget engine logged `zlib, 3289 -> 8120`; `n1` 185 B, same md5, owner
  `u0_a346`, context `untrusted_app`; no `su`/`frida` process during
  execution. Root was used only to delete the previous `n1` and read the
  new one, never to execute the payload.

Full audit: `AUDIT_no_root_cheat.md`.

## Note on the marker

The parser proof is the `id` line only; unlike the N1 hook-assisted proof it
does not contain `MEGARCE`. The 50-byte command is bounded by the 64-byte
forged AB data block, so the marker was not appended. The `n1` path,
`uid=10346`, `untrusted_app` SELinux context and the 5 identical runs are the
RCE evidence.

## Chain overview

1. Stage A: parser scope-index leak forges `T[599]` (`ArrayBuffer`) length
   64 -> 327,744 with data pointer D2; `V = new Uint8Array(VAB)`.
2. Stage B/C: heap layout, class 2560 cpool 110 / AB 2544 (A=2,228,
   B=5,356 device, C=408).
3. Endgame: `V[0,0x7000)` class-24 view scan -> VBase; `VBase-8` block header
   -> arena -> `JSArenaSlab` used bitmap (PG[81]); every V read gated.
4. Absolute probe on page-0 candidates (25 seen in c2560p; VO=1360):
   `shape -> proto -> prop -> C_FUNCTION -> realm -> rt -> malloc_limit -> pie`.
5. `rt` -> libc base -> `.dynsym` scan -> `system` -> `system(cmd)` writes
   `/data/user/0/org.telegram.messenger.beta/files/n1`.

## Superseded / not used

- N1 hook-assisted chain: 5/5 with `MEGARCE`, but Frida-dependent; evidence
  only, not the deliverable.
- n-day entrypoints (#1827/#1865 etc.): not used.
- Per-device calibration hooks/offsets: not used.
