#!/usr/bin/env python3
"""Rewrite the HTML payload of an existing Postbox widget message in place,
preserving the t7 key (message id) and all serialization fields except the
zlib length prefix.

Postbox row format observed on Telegram 13.2 (iOS): the t7 value for a local
widget message is a serialized Message object; the widget HTML is a raw zlib
stream (starts 78 da/78 9c) preceded by a 4-byte little-endian compressed
length, followed by a small trailing field.  The t7 key is
peer(8) | ns(4) | timestamp(4) | message_id(4); keeping the key keeps the
message/widget id, which is what the widget localStorage is keyed by.

Usage:
  postbox_rewrite_widget.py --db db_sqlite --message-id 80374 \
      --html ls_final_h400.html --out db_sqlite.new [--expect N1IOS_SEED]
  postbox_rewrite_widget.py --db db_sqlite --message-id 80374 \
      --html ls_final_h400.html --in-place      # makes db_sqlite.bak-<ts>

The input may be a live-copied db_sqlite plus db_sqlite-wal/-shm; copy all
three to the same temp directory before running.  The tool checkpoints the WAL
into the working copy, edits, and leaves a single checkpointed db_sqlite.
Host-only; no device access.
"""
import argparse, os, shutil, sqlite3, struct, sys, time, zlib

ZLIB_MAGIC = (b'\x78\xda', b'\x78\x9c', b'\x78\x01', b'\x78\x5e')

def find_payload(value):
    """Return (comp_off, comp_len, html) or raise."""
    for magic in ZLIB_MAGIC:
        pos = 0
        while True:
            i = value.find(magic, pos)
            if i < 0:
                break
            pos = i + 1
            if i < 4:
                continue
            comp_len = struct.unpack('<I', value[i-4:i])[0]
            if comp_len <= 0 or i + comp_len > len(value):
                continue
            try:
                d = zlib.decompressobj()
                html = d.decompress(value[i:i+comp_len])
                if not d.eof:
                    continue
                if b'<' in html and (b'html' in html[:200].lower() or b'<div' in html[:400].lower()):
                    return i, comp_len, html
            except Exception:
                continue
    raise ValueError('no zlib HTML payload found')


def pad_preserve_length(new_html, target_ulen, target_clen, pad_html=False):
    """Pad new_html with a JS comment so uncompressed=target_ulen and
    zlib.compress(level=9).len=target_clen.  Returns bytes or None."""
    if len(new_html) > target_ulen:
        return None
    if len(new_html) == target_ulen:
        if len(zlib.compress(new_html, 9)) == target_clen:
            return new_html
        return None
    pre, post = (b'\n<!--', b'-->') if pad_html else (b'/*', b'*/')
    pad = target_ulen - len(new_html) - len(pre) - len(post)
    if pad < 0:
        return None
    import random
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    # try increasing amounts of random content followed by 'A' filler
    for r in range(0, pad + 1):
        # skip huge scan: sample around the likely range first
        pass
    candidates = []
    # coarse scan for the random count that brackets target
    step = max(1, pad // 200)
    rng = random.Random(0x5eed)
    for r in list(range(0, pad + 1, step)) + [pad]:
        body = ''.join(rng.choice(alphabet) for _ in range(r)) + 'A' * (pad - r)
        z = zlib.compress(new_html + pre + body.encode() + post, 9)
        candidates.append((abs(len(z) - target_clen), r, len(z)))
    candidates.sort()
    # refine around the best few
    best = None
    for _, r0, _ in candidates[:4]:
        for r in range(max(0, r0 - 2 * step), min(pad, r0 + 2 * step) + 1):
            for seed in range(0, 200):
                rng = random.Random(seed * 1315423911 + r)
                body = ''.join(rng.choice(alphabet) for _ in range(r)) + 'A' * (pad - r)
                cand = new_html + pre + body.encode() + post
                z = zlib.compress(cand, 9)
                if len(z) == target_clen:
                    return cand
                if best is None or abs(len(z) - target_clen) < best[0]:
                    best = (abs(len(z) - target_clen), len(z))
    print('preserve-length: no exact match, closest delta', best)
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', required=True)
    ap.add_argument('--message-id', type=int, default=0)
    ap.add_argument('--ns', type=int, default=0)
    ap.add_argument('--html', default=None)
    ap.add_argument('--out')
    ap.add_argument('--in-place', action='store_true')
    ap.add_argument('--expect', default=None)
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--preserve-length', action='store_true')
    ap.add_argument('--pad-html', action='store_true')
    args = ap.parse_args()
    if not args.list:
        if not args.html:
            ap.error('--html is required')
        if not args.in_place and not args.out:
            ap.error('use --out or --in-place')
    src = args.db
    workdir = os.path.dirname(os.path.abspath(src)) or '.'
    # Work on a copy (db + wal + shm) in a temp dir.
    tmpdir = os.path.join('/tmp/opencode', 'postbox_rewrite_%d' % int(time.time()))
    os.makedirs(tmpdir, exist_ok=True)
    base = os.path.basename(src)
    for suffix in ('', '-wal', '-shm'):
        p = src + suffix
        if os.path.exists(p):
            shutil.copy2(p, os.path.join(tmpdir, base + suffix))
    work = os.path.join(tmpdir, base)
    if args.in_place:
        bak = src + '.bak-' + time.strftime('%Y%m%d-%H%M%S')
        shutil.copy2(src, bak)
        print('backup', bak)
    conn = sqlite3.connect(work)
    conn.text_factory = bytes
    cur = conn.cursor()
    cur.execute('pragma wal_checkpoint(TRUNCATE)')
    print('integrity before:', cur.execute('pragma integrity_check').fetchone()[0])
    if args.list:
        for k, v in cur.execute('select key, value from t7'):
            if not (isinstance(k, bytes) and len(k) == 20):
                continue
            ns = struct.unpack('>I', k[8:12])[0]
            ts = struct.unpack('>I', k[12:16])[0]
            mid = struct.unpack('>I', k[16:20])[0]
            try:
                i, clen, html = find_payload(v)
                print('id=%d ns=%d ts=%08x key=%s value=%d zoff=%d html=%d head=%r' %
                      (mid, ns, ts, k.hex(), len(v), i, len(html), html[:120]))
            except Exception:
                pass
        return 0
    new_html = open(args.html, 'rb').read()
    rows = []
    for k, v in cur.execute('select key, value from t7'):
        if isinstance(k, bytes) and len(k) == 20 and k[8:12] == struct.pack('>I', args.ns) \
                and k[16:20] == struct.pack('>I', args.message_id):
            rows.append((k, v))
    if not rows:
        print('no t7 row for message id', args.message_id); return 2
    chosen = None
    for k, v in rows:
        try:
            i, clen, html = find_payload(v)
        except Exception as e:
            print('candidate', k.hex(), 'no payload:', e); continue
        print('candidate', k.hex(), 'value_len', len(v), 'zoff', i,
              'comp_len', clen, 'html_len', len(html), 'head', html[:60])
        if args.expect is None or args.expect.encode() in html:
            chosen = (k, v, i, clen, html)
            break
    if chosen is None:
        print('no candidate matched --expect'); return 3
    k, v, i, clen, html = chosen
    if args.preserve_length:
        padded = pad_preserve_length(new_html, len(html), clen, args.pad_html)
        if padded is None:
            print('preserve-length failed; re-run without --preserve-length or adjust the HTML')
            return 4
        new_html = padded
    z = zlib.compress(new_html, 9)
    if args.preserve_length and len(z) != clen:
        print('preserve-length mismatch', len(z), clen); return 4
    newv = v[:i-4] + struct.pack('<I', len(z)) + z + v[i+clen:]
    cur.execute('begin immediate')
    cur.execute('update t7 set value=? where key=?', (newv, k))
    conn.commit()
    print('key preserved:', k.hex())
    print('old value_len', len(v), 'new', len(newv),
          'old comp', clen, 'new', len(z), 'old html', len(html), 'new', len(new_html))
    # verify
    (got,) = cur.execute('select value from t7 where key=?', (k,)).fetchone()
    gi, gclen, ghtml = find_payload(got)
    assert got == newv and ghtml == new_html and gclen == len(z)
    print('verify: key unchanged, payload equals new html')
    print('integrity after:', cur.execute('pragma integrity_check').fetchone()[0])
    t4key = k[:12] + k[16:20]
    t4 = cur.execute('select length(value) from t4 where key=?',
                     (t4key,)).fetchone()
    print('t4 value length:', t4[0] if t4 else 'missing')
    conn.close()
    if args.in_place:
        # replace the original db with the edited copy; remove stale wal/shm
        shutil.copy2(work, src)
        for suffix in ('-wal', '-shm'):
            p = src + suffix
            if os.path.exists(p):
                os.rename(p, p + '.bak-' + time.strftime('%Y%m%d-%H%M%S'))
        print('in-place updated', src)
    else:
        shutil.copy2(work, args.out)
        print('wrote', args.out)
    return 0

if __name__ == '__main__':
    sys.exit(main())
