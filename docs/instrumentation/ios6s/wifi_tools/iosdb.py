#!/usr/bin/env python3
"""List / delete bot-chat messages in the Telegram Postbox DB (t7=message, t4=history).
usage: iosdb.py list [db] | delete <ns> <id> [db]
Keys: peer(8)=0000000847cdfde3 | ns(4) | ts(4) | id(4)  for t7; peer|ns|id for t4.
"""
import sqlite3, struct, sys, zlib, datetime
PEER = bytes.fromhex('0000000847cdfde3')
def rows(cur):
    out=[]
    for k,v in cur.execute("select key,value from t7"):
        if isinstance(k,bytes) and k.startswith(PEER):
            ns,ts=struct.unpack(">II",k[8:16]); mid=struct.unpack(">I",k[16:20])[0]
            w=None; i=v.find(b'\x78\xda')
            if i>=0:
                try:
                    d=zlib.decompressobj(); out2=d.decompress(v[i:i+400000],200000); w=out2[:32].decode('utf-8','replace')
                except Exception: w='ERR'
            out.append((ts,mid,ns,len(v),w,k))
    out.sort(); return out
def main():
    cmd=sys.argv[1]
    db=sys.argv[-1] if len(sys.argv)>2 else 'db_sqlite'
    c=sqlite3.connect(db); c.text_factory=bytes; cur=c.cursor()
    if cmd=='list':
        for ts,mid,ns,l,w,k in rows(cur):
            print(datetime.datetime.utcfromtimestamp(ts).strftime('%m-%d %H:%M:%S'), f"id={mid:<6d} ns={ns} len={l:<5d}", ("W:"+w.replace('\n',' ')) if w else "")
    elif cmd=='prune':
        keep=set(int(x) for x in sys.argv[2].split(',')) if len(sys.argv)>2 and sys.argv[2] else set()
        victims=[(m,n,k) for ts,m,n,l,w,k in rows(cur) if n==1 and m not in keep]
        print("pruning ns=1 messages:", [(m,n) for m,n,k in victims])
        cur.execute("begin immediate")
        tot7=0; tot4=0
        for m,n,k in victims:
            tot7+=cur.execute("delete from t7 where key=?",(k,)).rowcount
            t4k=PEER+struct.pack(">I",n)+struct.pack(">I",m)
            tot4+=cur.execute("delete from t4 where key=?",(t4k,)).rowcount
        c.commit()
        print(f"deleted t7={tot7} t4={tot4}")
        print("integrity:", cur.execute("pragma integrity_check").fetchone())
    elif cmd=='delete':
        ns=int(sys.argv[2]); mid=int(sys.argv[3])
        t4key=PEER+struct.pack(">I",ns)+struct.pack(">I",mid)
        t7rows=[(k,) for ts,m,n,l,w,k in rows(cur) if m==mid and n==ns]
        print("t7 candidates:", [r[0].hex() for r in t7rows])
        cur.execute("begin immediate")
        n7=sum(cur.execute("delete from t7 where key=?", r).rowcount for r in t7rows)
        n4=cur.execute("delete from t4 where key=?", (t4key,)).rowcount
        c.commit()
        print(f"deleted t7={n7} t4={n4}")
        print("integrity:", cur.execute("pragma integrity_check").fetchone())
    c.close()
main()
