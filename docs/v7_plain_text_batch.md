# Plaintext batch reductions (2026-11-05)

Starting point: ctx-only + GNU resolver, 3,518 B zlib (proof 5467).

## Batch

- fixed NONCE (corrupted byte_length constant);
- MAGIC: random (safe variant) or fixed (aggressive variant);
- removed legacy BIG/trigger retention from KEEP;
- removed nStale/di/if(0)/0; debug remnants;
- short C2 bootstrap: `nc`/`sleep` from PATH, no `/system/bin/toybox`;
- shorter keepalive: `setTimeout(()=>{},1e4)` instead of the 1 s interval.

## Results

| variant | zlib-9 | proofs | note |
|---|---:|---|---|
| nonce fixed + MAGIC random | **3,384** | 5468, 5469, 5470 | fresh + same-process re-render |
| nonce fixed + MAGIC fixed | **3,317** | 5471, 5472 | fresh + same-process re-render |

The fixed-MAGIC downside (stale view passing the marker check) was **not
observed** in the same-process re-render. It remains a theoretical risk: a
recycled block containing the same fixed marker and the same fixed length
could pass. The random MAGIC costs only 67 B and removes that collision.

## Recommendation

- Safe/minimal: `poc/loader_v7_plain_text_batch.html` (3,384 B, MAGIC random).
- Absolute minimum tested: `poc/loader_v7_plain_text_fixmag.html` (3,317 B,
  MAGIC fixed), with the stale-marker caveat.
- Both are plaintext, no keypad/encryption, "Ok" text, auto-run, C2 loader
  separate (shell).

## Next reduction candidates (not yet in this batch)

- merge `plausible`/`codeok`, inline `u64`/`rd32`, mask table;
- fixed ctx ctor offset instead of the 8-property scan;
- scanner LIM/candidate reduction;
- minimal ctx-only wrapper;
- larger research: gadget `dlsym`/`dladdr`, two-word 64-bit addresses, token
  packer.

## Second reduction round (wrapper / merge / CFG)

| variant | zlib-9 | result |
|---|---:|---|
| minimal wrapper (no style/div, text "Ok") | **3,292** | proofs **5473, 5474** |
| merge `plausible`/`codeok`, inline `u64`, mask `M` | 3,281 | C2 session opened, shell closed, **no proof** |
| inline CFG object, direct constants | 3,156 | C2 session opened, shell closed, **no proof** |
| fixed MAGIC (earlier) | 3,317 | proof 5471/5472; stale risk |

The two aggressive code reductions still reached `system` (the C2 hello/uid
arrived) but the shell died before the command output/proof. The payload
heap/bytecode is extremely sensitive to removing CFG objects/guard functions;
the wrapper/command/debug changes are safe, the payload-structure changes are
not.

Current reliable minimum: `poc/loader_v7_plain_text_minwrap.html` — 3,292 B
zlib, proofs 5473/5474, MAGIC random, fixed nonce, minimal text wrapper.

Remaining untested ideas: padA/padB removal, fixed ctx ctor offset, scanner
LIM/candidates, mkbuf/writeMag compaction, single `us` view, two-word 64-bit,
token packer, gadget `dlsym`, exported quickjs functions, arena fix. Given the
failures above, each must be validated with a full C2 proof, not just size.

## Universal no-delta variant (best reliable)

Removed the fixed `SYSTEM_DELTA` fallback (Sony-only) and the unused CFG
properties `DBG/ARENA/POISON/DRY`. The payload now relies only on the GNU ELF
resolver for `free -> system`, and keeps the ctx layout fixed.

- loader **3,220 B zlib** (876 B margin)
- proofs **5475, 5476, 5477** (fresh process + same-process re-render)
- no keypad/encryption; text "Ok"; auto-run; C2 loader remains shell/server
- config: fixed nonce, random MAGIC, minimal wrapper, short `nc` command,
  10 s keepalive

Artifacts:

- `poc/loader_v7_plain_text_univ.html`
- `lab/regexp1827_class64/device_payload_v7_univ.min.js`

This is the current reliable minimum. The fixed-MAGIC and merge/CFG-inline
variants remain smaller on paper but are either theoretically stale-prone or
observed to kill the C2 shell.

## Full small-reduction sweep (all tested with C2)

| variant | zlib-9 | result |
|---|---:|---|
| LIM 4096 | 3,219 | FAIL, no session |
| LIM 2048 | 3,220 | FAIL, no session |
| padA/padB removed | 3,181 | proof 5478 |
| single `us` view | 3,221 | proof 5479 (no size gain) |
| `ENT = V[0]` | 3,189 | proof 5480 |
| ctor = first candidate | 3,179 | proof 5481 |
| libc base scan 4 MiB | 3,221 | FAIL, no session |
| dead `if(0)` block | 3,211 | proof 5482 |

Conclusions:

- the scanner window must stay at `LIM=8192`; 4096/2048 lose the victim
  candidates and no session is created;
- the libc base scan must keep 16 MiB (`0x1000` pages); 4 MiB is too small;
- padA/padB, `V[0]` selection, first-candidate ctor and the dead block are safe
  individually and in combination.

## Combined best

Combining padA/padB removal + `V[0]` + first-candidate ctor + dead block on the
3,220 universal base:

- loader **3,094 B zlib** (1,002 B margin)
- proofs **5483, 5484, 5485** (first run, fresh process, same-process re-render)
- no fixed delta, GNU resolver, ctx fixed, MAGIC random, fixed nonce, minimal
  "Ok" wrapper, short `nc` command, 10 s keepalive

Artifacts:

- `poc/loader_v7_plain_text_comb.html`
- `lab/regexp1827_class64/device_payload_v7_comb.min.js`

Remaining untested / research: mkbuf-writeMag compaction, resolver error paths,
two-word 64-bit addresses, token packer, gadget `dlsym`, exported quickjs
functions, arena layout fix.

## Further margin: ctxErr/ctor/u64 sweep

Individual and pair tests on top of the 3,094 combined loader:

| variant | zlib-9 | result |
|---|---:|---|
| u64 inline (only) | 3,090 | proof 5486 |
| ctxErr strings -> numbers (only) | 3,066 | proof 5487 |
| direct first ctor (only) | 3,083 | proof 5488 |
| ctxErr + direct ctor | **3,056** | proofs **5489, 5492, 5493** |
| ctxErr + u64 | 3,065 | proof 5490 |
| ctor + u64 | 3,080 | proof 5491 |
| all three | 3,050 | **FAIL**, no session |

The all-three combination breaks the endgame (no session). `u64` works alone
and in either pair, but not together with both `ctxErr` and the direct ctor.
The stable best is `ctxErr + direct ctor`: **3,056 B zlib**, 1,040 B margin,
three proofs including same-process re-render.

Artifacts:

- `poc/loader_v7_plain_text_cec.html`
- `lab/regexp1827_class64/device_payload_v7_cec.min.js`

Remaining small: mkbuf/writeMag compaction, resolver error paths. Remaining
large/research: two-word 64-bit, token packer, gadget dlsym, exported quickjs,
arena layout fix.

## Final small tests + static dlsym check

| variant | zlib-9 | result |
|---|---:|---|
| writeMag via DataView | 3,067 | proof 5494 (works, but larger) |
| mkbuf fill(0) removal | 3,048 | FAIL, no session |
| resolver error-path removal | 2,989 | FAIL, no session |

Best remains `poc/loader_v7_plain_text_cec.html`, 3,056 B, proofs 5489/5492/5493.

Static checks on libtm72879.so:

- no exported `JS_GetRuntime` / `JS_GetContext` / `JS_NewRuntime` / `JS_NewContext` symbols;
- `dlsym`, `dlopen`, `dladdr`, `mprotect` are imported;
- dlsym GOT is `0x19704a0`, PLT candidate `0x18bd080`;
- no simple `mov x0,xzr; b dlsym@plt` gadget in `.text` (257 `mov x0,xzr; b` hits, none targets the PLT).

So the dlsym route is possible in principle but needs a real call-site/gadget
analysis (or a controlled `js_realloc` return capture), not a one-byte patch.
Two-word 64-bit and token packer remain the large source-level rewrites.

## Autonomous sweep: final results

- Token packer (dictionary + base64 + decoder): loader **4,559 B**, worse
  than 3,056; rejected (base64 overhead kills the gain).
- ELF resolver rewritten in Number (addresses as JS Number, BigInt only for
  the 64-bit reads): loader **3,070 B**, C2 **FAIL** (no session); rejected,
  the BigInt() conversions made it larger.
- dlsym: correct PLT **0x18bcfe0**; the only useful wrapper is
  `0x1827988: mov x0,x1; mov x1,x2; b dlsym@plt`; no
  `mov x0,xzr`/`eor`/`movz` + `b dlsym@plt` gadget; the `js_realloc(ptr=0,
  size=name)` trigger is not reachable. Blocked.
- Current reliable minimum: `poc/loader_v7_plain_text_cec.html`,
  **3,056 B zlib**, proofs 5489/5492/5493.

### Complete size/result table

| variant | zlib-9 | result |
|---|---:|---|
| ctx-only GNU | 3,518 | proof 5467 |
| batch + normal wrapper | 3,384 | proofs 5468-5470 |
| batch + minimal wrapper | 3,292 | proofs 5473/5474 |
| fixed MAGIC | 3,317 | proofs 5471/5472 (stale risk) |
| universal no-delta | 3,220 | proofs 5475/5476/5477 |
| combined padA/V0/ctor/dead | 3,094 | proofs 5483/5484/5485 |
| **ctxErr numbers + direct ctor** | **3,056** | **proofs 5489/5492/5493** |
| u64 inline only | 3,090 | proof 5486 |
| ctxErr only | 3,066 | proof 5487 |
| direct ctor only | 3,083 | proof 5488 |
| ctxErr + u64 | 3,065 | proof 5490 |
| ctor + u64 | 3,080 | proof 5491 |
| all three (ctxErr+ctor+u64) | 3,050 | FAIL |
| merge guards/inline/mask | 3,281 | FAIL (shell dies) |
| CFG inline | 3,156 | FAIL (shell dies) |
| LIM 4096/2048 | 3,219/3,220 | FAIL |
| libc base scan 4 MiB | 3,221 | FAIL |
| mkbuf fill removal | 3,048 | FAIL |
| resolver error-path removal | 2,989 | FAIL |
| writeMag DataView | 3,067 | proof 5494 (larger) |
| token packer | 4,559 | worse |
| resolver Number | 3,070 | FAIL |

Remaining untested: full two-word class-64/writer/reader rewrite; it is the
only size lever left, but the resolver Number experiment shows the
BigInt/Number conversion overhead can erase the gain. The arena layout fix is a
universality item, not a size one.
