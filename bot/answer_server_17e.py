#!/usr/bin/env python3
"""Widget answer server (<BOT_USERNAME>).

Polls getUpdates and answers widget_query data "E<i>" with chunk i from
--chunks. The Bot API answer field is `data` (MTProto `result`).

Usage: answer_server.py --chunks DIR [--token TOK] [--log FILE] [--duration S]
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

TOK_DEFAULT = os.environ.get('BOT_TOKEN', '')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--chunks', required=True)
    ap.add_argument('--token', default=TOK_DEFAULT)
    ap.add_argument('--log', default='answer_server_17e.log')
    ap.add_argument('--duration', type=float, default=600)
    args = ap.parse_args()
    man = json.load(open(os.path.join(args.chunks, 'manifest.json')))
    n = int(man['n'])
    chunks = [open(os.path.join(args.chunks, 'E%d.txt' % i), encoding='utf-8').read() for i in range(n)]
    api = 'https://api.telegram.org/beta/bot%s/' % args.token
    logf = open(args.log, 'a', encoding='utf-8')

    def log(*a):
        line = ' '.join(str(x) for x in a)
        logf.write(time.strftime('%Y-%m-%d %H:%M:%S ') + line + '\n')
        logf.flush()
        print(line, flush=True)

    def call(method, payload, timeout=40):
        req = urllib.request.Request(api + method, data=json.dumps(payload).encode(),
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())

    log('START chunks=%s n=%d len=%d' % (args.chunks, n, man['len']))
    offset = 0
    deadline = time.time() + args.duration
    answered = 0
    while time.time() < deadline:
        try:
            r = call('getUpdates', {'offset': offset, 'timeout': 25,
                                    'allowed_updates': ['widget_query', 'shared_widget_query']}, timeout=40)
        except Exception as exc:  # noqa: BLE001
            log('POLL_ERR', repr(exc))
            time.sleep(3)
            continue
        for u in r.get('result') or []:
            try:
                offset = max(offset, int(u.get('update_id', 0)) + 1)
            except Exception:
                pass
            q = u.get('widget_query') or u.get('shared_widget_query')
            if not isinstance(q, dict):
                continue
            data = q.get('data') or ''
            qid = q.get('id')
            sender = q.get('from') or {}
            if not qid:
                continue
            idx = None
            if isinstance(data, str) and data.startswith('E') and data[1:].isdigit():
                idx = int(data[1:])
            if idx is not None and 0 <= idx < n:
                try:
                    call('answerWidgetQuery', {'widget_query_id': qid, 'data': chunks[idx]}, timeout=15)
                    answered += 1
                    log('ANSWER q=%s from=%s uid=%s data=%r chunk=%d len=%d ok' % (
                        qid, sender.get('username'), sender.get('id'), data, idx, len(chunks[idx])))
                except Exception as exc:  # noqa: BLE001
                    log('ANSWER_ERR q=%s data=%r %r' % (qid, data, exc))
            else:
                log('SKIP q=%s from=%s uid=%s data=%r' % (qid, sender.get('username'), sender.get('id'), data))
    log('DONE answered=%d' % answered)
    return 0


if __name__ == '__main__':
    sys.exit(main())
