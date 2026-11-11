#!/usr/bin/env python3
"""Split the 72801 endgame into TelegramWidget.request answer chunks.

Wire constraints (notes/widget_js_api_audit.md §7.3, widget_memory_limits §delivery):
  - request data: 1..64 B UTF-8  -> "E0".."E7"
  - answer: <=1024 B             -> CHUNK = 950 B
  - one request in flight, >=5 s between background requests
Usage: python3 split_endgame.py endgame_72801.js [--outdir DIR] [--check]
Writes E<i>.txt and a manifest with sizes/sha256.
"""
import argparse, hashlib, json, os, sys

CHUNK = 950

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("endgame")
    ap.add_argument("--outdir", default="chunks")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    src = open(args.endgame, 'rb').read().decode('utf-8')
    n = (len(src) + CHUNK - 1) // CHUNK
    os.makedirs(args.outdir, exist_ok=True)
    man = {'source': sys.argv[1], 'len': len(src), 'chunk': CHUNK, 'n': n,
           'sha256': hashlib.sha256(src.encode()).hexdigest(), 'chunks': []}
    for i in range(n):
        c = src[i * CHUNK:(i + 1) * CHUNK]
        open(os.path.join(args.outdir, 'E%d.txt' % i), 'w').write(c)
        man['chunks'].append({'i': i, 'len': len(c),
                              'sha256': hashlib.sha256(c.encode()).hexdigest()[:16]})
    json.dump(man, open(os.path.join(args.outdir, 'manifest.json'), 'w'), indent=1)
    print(json.dumps(man, indent=1))
    if args.check:
        pay = os.environ.get('STAG_PAYLOAD_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'vulns', '0day-2-RCE-PARSER-SCOPE', 'STAG', 'payloads'))
        want = os.path.join(pay, 'route2', 'chunks', 'manifest.json')
        print('RESULT:', 'PASS' if os.path.exists(want) and json.load(open(want))['sha256'] == man['sha256'] else 'FAIL')

if __name__ == '__main__':
    main()
