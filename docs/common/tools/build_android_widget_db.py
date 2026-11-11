import sqlite3, struct, zlib, time, sys, os

DB = sys.argv[1] if len(sys.argv) > 1 else 'work.db'
HTML = sys.argv[2] if len(sys.argv) > 2 else '<HOME>/ailocal/Telegram/telegramandroidwidget/lab/qjs_n1/widget/n1v2_scrub_db_72889.html'
MID = 80345
UID = 0

MSG_CTOR = 1979759059
WIDGET_CTOR = 574157332
PEER_USER = 1498486562

def bstr(b):
    n = len(b)
    if n < 254:
        head = bytes([n])
    else:
        head = b'\xfe' + n.to_bytes(3, 'little')
    pad = (4 - (n + len(head)) % 4) % 4
    return head + b + b'\x00' * pad

def peer_user(uid):
    return struct.pack('<Iq', PEER_USER, uid)

raw = open(HTML, 'rb').read()
comp = zlib.compress(raw, 9)
media = (struct.pack('<Iiii', WIDGET_CTOR, 1, 0, 0) + bstr(comp))
now = int(time.time())
blob = b''.join([
    struct.pack('<I', MSG_CTOR),
    struct.pack('<i', 0x300),           # from_id + media
    struct.pack('<i', 0),               # flags2
    struct.pack('<i', MID),
    peer_user(UID),                     # from_id
    peer_user(UID),                     # peer_id
    struct.pack('<i', now),             # date
    bstr(b''),                          # message text
    media,
    bstr(b' '),                         # attach path tail
])
print('raw', len(raw), 'zlib', len(comp), 'blob', len(blob))

con = sqlite3.connect(DB)
args = (MID, UID, 0, 0, now, sqlite3.Binary(blob), 0, 0, -1, None, 0, 0, 0, None, 0, 0, 0, None, None, 0)
con.execute('INSERT INTO messages_v2 (mid,uid,read_state,send_state,date,data,out,ttl,media,replydata,imp,mention,forwards,replies_data,thread_reply_id,is_channel,reply_to_message_id,custom_params,group_id,reply_to_story_id) '
            'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', args)
con.execute('UPDATE dialogs SET last_mid=?, date=?, unread_count=0 WHERE did=?', (MID, now, UID))
con.commit()
con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
con.commit()
print('rows:', con.execute('select mid,uid,length(data) from messages_v2 where mid=?', (MID,)).fetchall())
print('dialog:', con.execute('select did,last_mid,date from dialogs where did=?', (UID,)).fetchall())
con.close()
