# Parser RCE: universal device proof on 13.2.1 (72889) and 13.2.2 (72929)

Date: 2026-11-07
Device: Sony XQ-BT52 (<SERIAL>), Android 13
Same widget: `device/widget/c2560_final_c2560s_72929.html`
- raw 9,946 B / zlib9 4,023 B (limits 32,768 / 4,096)
- SHA-256: `992a51267a385c57635f5aed835aa29a1006ca8c584ca3843b265cd2c71318b4`
- B = 7,182 (stage A/B/C harness length; same on both builds)

## Device results

### 13.2.1 (72889)
- Probe at B=7,182: `S1 SAFE2560C END=-`.
- Final: engine `widget payload: zlib, 4023 -> 9946 bytes`; proof
  `/data/user/0/org.telegram.messenger.beta/files/n1` **185 B**,
  `uid=10346(u0_a346) ... context=u:r:untrusted_app:s0:c90,c257,c512,c768`,
  md5 `52258bc776f2f378542d1b2c736840e3`; app alive (pid 6526), no SIGSEGV.
- Install: downgrade `adb install -r -d base-72889.apk` (same cert).

### 13.2.2 (72929)
- Probe at B=7,182: `S1 SAFE2560C END=-`.
- Final: engine `widget payload: zlib, 4023 -> 9946 bytes`; proof 185 B,
  same uid/SELinux, md5 `52258bc776f2f378542d1b2c736840e3`; app alive
  (pid 5602), no SIGSEGV.
- Installed from channel post 345: `Telegram-Beta-7292.apk`,
  versionCode 72929, same signing cert.

## What is universal

- **No Telegram-build constants** in the final: app base, `.rela.plt`
  `free` JUMP_SLOT, libc base and `system` are resolved at runtime.
- **No fixed VBase window/offset**: class-20 forged-AB page-0 anchor plus
  page-derived class-24 fallback; on 72929 `VK=2/P=4944`, on 72889 the
  runtime anchor resolves as well.
- **GNU-hash libc lookup** replaces the 30k linear `.dynsym` scan.
- **Same widget bytes** on both builds; same proof.

## Remaining fixed values (declared)

- A/B/C = 2,228 / 7,182 / 408: stage-A harness length, not a Telegram
  build value; probe SAFE on both builds.
- QuickJS/fork ABI struct offsets (shape/prop/realm/rt, `u.array`,
  `JSArrayBuffer`, `JSArenaSlab`, `mf.js_free`): engine-level, identical
  72889→72929; an engine-version change would need the source.
- `CALIGN` (4 device) and the proof command path: architecture/proof, not
  build.
- Class-20/class-24, app/lib bases, GOT and symbols: runtime.

## Evidence

- `universal_dual/probe_72889.png`, `final_72889.png`,
  `final_72889.log`, `proof_72889.txt`
- `72929_universal/probe_g_safe_b7182.png`, `final_run1.png`,
  `final_run1.log`, `final_run1.txt`
- Host proof 162 and GNU-hash output: worker report / `endG8s.js`.

## 72929 5/5 (universal final)

Runs at 19:23-19:29, same widget/B, fresh DB each run:

| run | proof | size | md5 |
|---|---|---:|---|
| 1 | `n1` | 185 B | `52258bc776f2f378542d1b2c736840e3` |
| 2 | `n1` | 185 B | `52258bc776f2f378542d1b2c736840e3` |
| 3 | `n1` | 185 B | `52258bc776f2f378542d1b2c736840e3` |
| 4 | `n1` | 185 B | `52258bc776f2f378542d1b2c736840e3` |
| 5 | `n1` | 185 B | `52258bc776f2f378542d1b2c736840e3` |

All runs app-uid `10346`, `untrusted_app`, app alive; no SIGSEGV.
Evidence: `72929_universal/final_run1..5.txt`, `.png`, `.log`.

## Status

- Universal same-widget device proof: **72889 1/1 + 72929 5/5**,
  same widget bytes and same 185-B proof.
- Probe SAFE at B=7,182 on both builds; host proof 162.
- Across future engine versions: not claimed; ABI change would need the
  fork source. Across these two Telegram builds: proven.
- 72889 reliability: the universal final was run 1/1 on 72889; the
  earlier 5/5 there was the 72889-specific c2560q/c2560r bridge, not this
  universal final. If a dual 5/5 is required, downgrade + 4 more runs.
