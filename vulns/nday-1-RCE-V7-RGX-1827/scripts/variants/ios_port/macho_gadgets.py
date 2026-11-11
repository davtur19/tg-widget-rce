#!/usr/bin/env python3
"""Find ROP/JOP candidates in an arm64 Mach-O (iOS endgame helper).

The iOS widget endgame needs, at minimum:

  * a stack pivot reachable from the QuickJS allocator hook
    (`js_free(opaque, ptr)` / `js_realloc(opaque, ptr, size)`),
  * a way to load x0..x3 from the controlled stack and branch to a
    function pointer (app `__stubs` are enough; no libsystem offsets),
  * epilogues to keep the chain moving.

This script scans `__text` for the *encodings* of `ret`, `br xN`, `blr xN` and
`mov sp, xN`, then disassembles only a small window around each candidate.
That avoids the capstone crash seen when feeding the whole 80 MB section.
Every address is build-specific: re-run on the 13.2.0 IPA after decryption.

Usage:
  macho_gadgets.py --macho TelegramUIFramework --all
  macho_gadgets.py --macho ... --pivot --call --max 40
  macho_gadgets.py --macho ... --json /tmp/gadgets.json

Requires: lief, capstone.
"""

from __future__ import annotations

import argparse
import array
import json
import re
import sys
from dataclasses import dataclass, field, asdict

try:
    import lief
except Exception as exc:  # pragma: no cover
    sys.stderr.write("error: missing lief (%s)\n" % exc)
    raise SystemExit(2)

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except Exception as exc:  # pragma: no cover
    sys.stderr.write("error: missing capstone (%s)\n" % exc)
    raise SystemExit(2)

LOAD_RE = re.compile(
    r"^(ldr|ldp)\s+([^,]+(?:,\s*[^,]+)?),\s*\[sp(?:,\s*#(-?0x[0-9a-fA-F]+|-?\d+))?\]!?$")
BR_RE = re.compile(r"^(br|blr)\s+(x\d+)$")

RET = 0xD65F03C0
BR = 0xD61F0000
BLR = 0xD63F0000


@dataclass
class Gadget:
    kind: str
    address: int
    text: str
    window: list = field(default_factory=list)
    stack: dict = field(default_factory=dict)


_KEEP = []


def load_arm64(path: str):
    parsed = lief.MachO.parse(path)
    if parsed is None:
        raise SystemExit("not a Mach-O: %s" % path)
    # LIEF slices reference the parent FatBinary; keep it alive for the whole
    # run, otherwise get_section() dereferences freed memory.
    _KEEP.append(parsed)
    for b in parsed:
        if str(b.header.cpu_type) == "CPU_TYPE.ARM64":
            return b
    return parsed.at(0)


def _parse_load(op_str: str):
    m = LOAD_RE.match(op_str.strip())
    if not m:
        return None
    kind, regs_s, disp_s = m.groups()
    regs = [r.strip() for r in regs_s.split(",")]
    disp = int(disp_s, 0) if disp_s else 0
    return kind, regs, disp


def _window_insns(data: bytes, va: int, addr: int, before: int = 32,
                  after: int = 4):
    start = max(0, addr - before)
    end = min(len(data), addr + after)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    return list(md.disasm(data[start:end], va + start))


def gadget_scan(binary, want_pivot=True, want_call=True, want_pop=True):
    sec = binary.get_section("__text")
    if sec is None:
        raise SystemExit("no __text section")
    data = bytes(sec.content)
    va = sec.virtual_address
    try:
        import numpy as np
        words = np.frombuffer(data, dtype="<u4")
    except Exception:
        words = array.array("I")
        words.frombytes(data[:len(data) & ~3])

    out: list[Gadget] = []
    seen = set()

    def add(g: Gadget):
        key = (g.kind, g.address)
        if key in seen:
            return
        seen.add(key)
        out.append(g)

    # ---- pivots: mov sp, xN / add sp, xN, #0 ------------------------------
    if want_pivot:
        for i, w in enumerate(words):
            if (w & 0xFFC003FF) != 0x9100001F:
                continue
            rn = (w >> 5) & 31
            if rn > 3:
                continue
            addr = va + i * 4
            add(Gadget("pivot", addr, "mov sp, x%d" % rn,
                       stack={"src": "x%d" % rn}))

    # ---- pop: ret preceded by ldr/ldp x0..x3,[sp] ------------------------
    if want_pop:
        for i, w in enumerate(words):
            if w != RET:
                continue
            addr = va + i * 4
            insns = _window_insns(data, va, addr, before=24, after=4)
            loads = {}
            text = []
            for ins in insns:
                if ins.address >= addr:
                    break
                if ins.mnemonic in ("ldr", "ldp"):
                    p = _parse_load(ins.op_str)
                    if p:
                        kind, regs, disp = p
                        for j, r in enumerate(regs):
                            if r in ("x0", "x1", "x2", "x3"):
                                loads[r] = disp + (8 * j if kind == "ldp" else 0)
                text.append("%s %s" % (ins.mnemonic, ins.op_str))
            if loads:
                add(Gadget("pop", addr, "; ".join(text[-4:]), stack=loads))

    # ---- call: br/blr xN where xN is loaded from [sp] --------------------
    if want_call:
        for i, w in enumerate(words):
            if (w & 0xFFFFFC1F) == BR:
                kind = "br"
                rn = (w >> 5) & 31
            elif (w & 0xFFFFFC1F) == BLR:
                kind = "blr"
                rn = (w >> 5) & 31
            else:
                continue
            if rn > 15:
                continue
            addr = va + i * 4
            target = "x%d" % rn
            insns = _window_insns(data, va, addr, before=40, after=4)
            loads = {}
            text = []
            for ins in insns:
                if ins.address >= addr:
                    break
                if ins.mnemonic in ("ldr", "ldp"):
                    p = _parse_load(ins.op_str)
                    if p:
                        k, regs, disp = p
                        for j, r in enumerate(regs):
                            loads[r] = disp + (8 * j if k == "ldp" else 0)
                text.append("%s %s" % (ins.mnemonic, ins.op_str))
            if target not in loads:
                continue
            args = {k: v for k, v in loads.items() if k in ("x0", "x1", "x2", "x3")}
            add(Gadget("call", addr, "; ".join(text[-5:]),
                       stack={"target_reg": target,
                              "target_off": loads[target], **args}))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--macho", required=True)
    ap.add_argument("--pivot", action="store_true")
    ap.add_argument("--call", action="store_true")
    ap.add_argument("--pop", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--max", type=int, default=25,
                    help="max entries printed per kind (default 25)")
    ap.add_argument("--json", help="write all candidates as JSON")
    args = ap.parse_args()

    if not any((args.pivot, args.call, args.pop, args.all)):
        args.all = True

    b = load_arm64(args.macho)
    sec = b.get_section("__text")
    print("== %s ==" % args.macho)
    print("  arch=%s base=%#x text=%#x size=%#x"
          % (b.header.cpu_type, b.imagebase, sec.virtual_address, sec.size))
    gs = gadget_scan(b,
                     want_pivot=args.all or args.pivot,
                     want_call=args.all or args.call,
                     want_pop=args.all or args.pop)

    for kind in ("pivot", "pop", "call"):
        items = [g for g in gs if g.kind == kind]
        items.sort(key=lambda g: g.address)
        print("\n  %s: %d candidates" % (kind, len(items)))
        for g in items[:args.max]:
            extra = ""
            if g.stack:
                extra = "  stack=" + ", ".join(
                    "%s@%s" % (k, v if isinstance(v, str) else hex(v))
                    for k, v in g.stack.items())
            print("    %#012x  %s%s" % (g.address, g.text, extra))

    if args.json:
        with open(args.json, "w") as f:
            json.dump([asdict(g) for g in gs], f, indent=2)
        print("\n  JSON: %s" % args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
