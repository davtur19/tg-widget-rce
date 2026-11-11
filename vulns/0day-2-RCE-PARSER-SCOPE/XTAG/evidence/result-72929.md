# c2560s universal debug on Telegram 13.2.2 (72929)

Date: 2026-11-07 19:04-19:05
Device: Sony XQ-BT52, Android 13, build 72929
Stage A/B/C: B=6,917 (c2560s)

Probe `c2560_probe_c2560s_72929.html` (9,681 raw / 958 zlib9):
`S1 SAFE2560C END=-`; app alive.

Debug `c2560_debug_c2560s_72929.html` (9,681 raw / 3,007 zlib9):
`S1 ABLEN[599]=327744 VLEN=327744 END=HF READY VNC=1 VO=1360 X=0 XG=0 G=0 GS=115 V=1 VK=2 VG=5 P=4944`

- `VK=2`: the class-20 forged-AB anchor was not found in V page 0; the
  page-derived class-24 fallback carried the chain.
- `P=4944`: runtime offset found by the fallback (no fixed 0x7000/0x37000
  window, no build constant).
- app alive, no SIGSEGV; widget payload log 3007 -> 9681.

The c2560s **final** remains host-unproven (ELF resolver fault), so it was
not run on the device. Evidence: `probe_safe.png`, `debug_ready.png`.

## B=7,182 probe on 72929 (19:20)

`c2560_probe_c2560g_72929.html` (10,458 raw / 961 zlib9):
`S1 SAFE2560C END=-`; stage A/B/C with B=7,182 is safe.

Final `c2560_final_c2560g_72929.html`: 10,458 raw / **4,179 zlib9**
> 4,096. It is not shipped; the final must shrink by at least 83 zlib9
bytes while keeping the GNU-hash resolver and host proof 162.

## Universal final c2560s on 72929 (19:23)

`c2560_final_c2560s_72929.html`; 9,946 raw / **4,023 zlib9** (<=4,096),
B=7,182, same B as the PASSED probe.

Engine log: `widget payload: zlib, 4023 -> 9946 bytes`.
Proof: `/data/user/0/org.telegram.messenger.beta/files/n1`, **185 B**,
`uid=10346(u0_a346) ... context=u:r:untrusted_app:s0:c90,c257,c512,c768`,
md5 `52258bc776f2f378542d1b2c736840e3`. App alive (pid 5602), no SIGSEGV.
Evidence: `final_run1.txt`, `final_run1.png`, `final_run1.log`.
