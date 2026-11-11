#!/usr/bin/env python3
"""Patch Telegram Android cache4.db messageMediaWidget payloads.

TL layout inside messages_v2.data (TL_message):
  media object starts with messageMediaWidget#2238f214, then
  flags:int32, width:int32, height:int32, payload:bytes (TL wire bytes:
  <254 -> 1-byte len; else 0xFE + 3-byte LE len; data padded to 4).

We only support patching a widget that is the LAST field of the message
(no TL fields after the media payload), which is the case for the target
messages (flags 0x204: fwd_from + media).
"""
import sqlite3, struct, zlib, sys, gzip

WIDGET_CTOR = 0x2238f214
CTOR_BYTES = struct.pack('<I', WIDGET_CTOR)


def _media_off(blob):
    idx = blob.find(CTOR_BYTES)
    if idx < 0:
        raise SystemExit('messageMediaWidget constructor not found')
    return idx


def _decode_bytes(data, off):
    b0 = data[off]
    if b0 < 254:
        ln = b0
        off += 1
    elif b0 == 0xfe:
        ln = data[off + 1] | (data[off + 2] << 8) | (data[off + 3] << 16)
        off += 4
    else:
        raise SystemExit('unsupported TL bytes length prefix 0x%02x' % b0)
    payload = data[off:off + ln]
    pad = (4 - (ln % 4)) % 4
    end = off + ln + pad
    return payload, off, end


def _encode_bytes(payload):
    n = len(payload)
    if n < 254:
        head = bytes([n])
    else:
        if n >= (1 << 24):
            raise SystemExit('payload too large')
        head = b'\xfe' + n.to_bytes(3, 'little')
    pad = (4 - (n % 4)) % 4
    return head + payload + b'\x00' * pad


def extract(blob):
    """Return (media_off, payload_off, payload_len, payload, end_off)."""
    m = _media_off(blob)
    flags, w, h = struct.unpack_from('<iii', blob, m + 4)
    payload, poff, end = _decode_bytes(blob, m + 16)
    return m, flags, w, h, payload, poff, end


def decompress(payload):
    if payload[:2] == b'\x1f\x8b':
        return gzip.decompress(payload)
    return zlib.decompress(payload)


def get_blob(db, mid):
    r = db.execute('SELECT data FROM messages_v2 WHERE mid=?', (mid,)).fetchone()
    if not r:
        raise SystemExit('message %d not found' % mid)
    return bytes(r[0])


def set_blob(db, mid, blob):
    r = db.execute('SELECT uid FROM messages_v2 WHERE mid=?', (mid,)).fetchone()
    if not r:
        raise SystemExit('message %d not found' % mid)
    db.execute('UPDATE messages_v2 SET data=? WHERE mid=? AND uid=?',
               (sqlite3.Binary(blob), mid, r[0]))
    # drop cached widget height so the bubble is re-measured
    db.execute('DELETE FROM widget_heights WHERE mid=?', (mid,))
    db.commit()


def patch_payload(blob, raw_html, level=9):
    m, flags, w, h, old, poff, end = extract(blob)
    # Everything after the media payload is the message attach-path tail
    # written by TLRPC.Message.writeAttachPath(); it must be preserved
    # verbatim and stays valid because it follows the TL object.
    tail = blob[end:]
    comp = zlib.compress(raw_html, level)
    new = blob[:m + 16] + _encode_bytes(comp) + tail
    return new, comp


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('db')
    ap.add_argument('mid', type=int)
    ap.add_argument('--html', help='raw HTML file to install')
    ap.add_argument('--text', help='inline HTML string')
    ap.add_argument('--dump', action='store_true')
    ap.add_argument('--dump-compressed', metavar='OUT')
    ap.add_argument('--copy-media-from', metavar='SRCDB',
                    help='restore message blob from another db')
    args = ap.parse_args()

    db = sqlite3.connect(args.db)
    if args.copy_media_from:
        src = sqlite3.connect(args.copy_media_from)
        blob = get_blob(src, args.mid)
        set_blob(db, args.mid, blob)
        print('restored mid %d from %s (%d bytes)' % (args.mid, args.copy_media_from, len(blob)))
    if args.dump or args.dump_compressed:
        blob = get_blob(db, args.mid)
        m, flags, w, h, payload, poff, end = extract(blob)
        html = decompress(payload)
        print('mid=%d blob=%d media_off=%d flags=%d w=%d h=%d '
              'payload_off=%d comp=%d html=%d end=%d'
              % (args.mid, len(blob), m, flags, w, h, poff, len(payload), len(html), end))
        if args.dump:
            sys.stdout.buffer.write(html)
        if args.dump_compressed:
            open(args.dump_compressed, 'wb').write(html)
    if args.html or args.text:
        raw = open(args.html, 'rb').read() if args.html else args.text.encode()
        blob = get_blob(db, args.mid)
        new, comp = patch_payload(blob, raw)
        set_blob(db, args.mid, new)
        print('patched mid %d: html=%d comp=%d blob %d -> %d'
              % (args.mid, len(raw), len(comp), len(blob), len(new)))


if __name__ == '__main__':
    main()
