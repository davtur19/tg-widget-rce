# PR #1827 exec/set probes — lab results and next device step

Probes: `telegramandroidwidget/lab/regexp1827_arena/widget_poc_1827_*.html`
(each has the same rAF marker as `widget_poc_1827_execprobe.html`:
the div shows `globalThis.RESULT`, or keeps its initial text if the script
hangs). Device/DB untouched.

## 1. `EXEC 1` is ambiguous — use the char probe

On the lab the fake program **does execute** in the probes (instrumented
`[re] set_i32 capture=... cc=1 idx=2` for `setprobe_ib`), but the save/match
program yields `RESULT='EXEC 1'`: an empty match at position 0 deletes
nothing, so the replace returns the original `'a'` (length 1). The old real
bytecode also returns `'a'`, so `EXEC 1` cannot distinguish execution.

`widget_poc_1827_execprobe_char.html` fixes that: it consumes the character
between the saves:

```
save_start 0; REOP_char 'a'; save_end 0; match
```

If the fake program executes, `'a'` is deleted → `EXEC 0`. If the old
bytecode runs → `EXEC 1`. If the header is rejected → `ERR ...`.
**Run this probe first on the device.** Lab: `EXEC 0`.

## 2. Lab results

```
execprobe_char          exit=0   RESULT=EXEC 0   (fake executed, 'a' deleted)
execprobe_save_match    exit=0   RESULT=EXEC 1   (empty match; ambiguous)
setprobe_ib             exit=0   RESULT=EXEC 1   (idx 2 in bounds; trace proves exec)
setprobe_pc0_1..8       exit=0   RESULT=EXEC 1   (all return on the lab)
probe_match_only        exit=0   RESULT=ERR RangeError: invalid string length
probe_save_start_only   exit=139 SIGSEGV
probe_save_end_only     exit=124 TIMEOUT (outer loop hang)
probe_cc0               exit=0   RESULT=ERR InternalError: corrupted bytecode
probe_cc4rc1            exit=0   RESULT=EXEC 1
```

Interpretation:

* `save_end_only` (capture[0] unset) **hangs** in `JS_RegExpDelete`'s outer
  loop: `start/end` are computed from a NULL capture, `last_index` stays
  negative, and the break condition never fires. `save_start_only`
  (capture[1] unset) crashes instead; `match_only` (both unset) throws
  `RangeError` in the string builder.
* Therefore **the strfill device hang is consistent with the fake program not
  setting both `capture[0]` and `capture[1]`** — e.g. the bytes at the stale
  pointer are not our program from offset 0 (reclaim/kind mismatch), or the
  program is partially overwritten between the two `lre_exec` calls. It is not
  a `bytecode_len` issue (the app's `lre_exec` has no length argument and does
  not read `bc_buf+4`).
* `probe_cc0` returning the "corrupted bytecode" error shows the
  `save_start`/`save_end` bounds check is active and the header
  `capture_count` is read at `+2`.

## 3. Branch A — minimal probe returns

Run, in order, with rAF markers:

1. `widget_poc_1827_setprobe_ib.html` — `cc=1, rc=1`, one **in-bounds**
   `set_i32 pc0=0` (idx 2 in the 3-entry array) + match.
2. `widget_poc_1827_setprobe_pc0_1.html` … `pc0_8.html` — the same with one
   **OOB** `set_i32` (`pc0=2` as requested is in this sweep; pc0=1 hits the
   next block header, pc0≥2 hits the next block user memory).

The first file that stops updating the marker is the first hanging index.
On the lab all of them return; the device layout decides which one corrupts
the free list or a live object. If `pc0=1` (next block header) hangs, the
failure is arena free-list/header corruption; if the first hang is at a
larger `pc0`, it is live-object corruption.

## 4. Branch B — minimal probe hangs

Run `widget_poc_1827_probe_match_only.html`,
`..._save_start_only.html`, `..._save_end_only.html`, `..._cc0.html`,
`..._cc4rc1.html`. `save_end_only` reproduces the hang signature on the lab;
`save_start_only` crashes; `match_only` errors; `cc0` returns the bytecode
error. This separates a header/capture problem from a set_i32/OOB problem.

## 5. Files

* `widget_poc_1827_execprobe_char.html` (unambiguous execution marker).
* `widget_poc_1827_execprobe_save_match.html` (same as the running execprobe,
  with the rAF marker).
* `widget_poc_1827_setprobe_ib.html`, `..._setprobe_pc0_1..8.html`.
* `widget_poc_1827_probe_match_only.html`, `..._save_start_only.html`,
  `..._save_end_only.html`, `..._cc0.html`, `..._cc4rc1.html`.
* `gen_probes2.py` (regenerates all of the above), `gen_setprobes.py`.
* Lab twins: `*_lab.js` (payload + `print(RESULT)`), results in
  `notes/evidence_regexp1827_arena/setprobe_lab_results.txt`.
* The rAF marker was added to the strfill/nolen/multistring HTMLs; a hang now
  leaves the div at its initial text (`poc1827`), a return shows
  `HOOKED ...` / `AFTER ...` or `EXEC ...`.
