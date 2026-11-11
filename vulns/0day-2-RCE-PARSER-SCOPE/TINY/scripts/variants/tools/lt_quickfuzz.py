#!/usr/bin/env python3
"""Small litehtml-fork (Telegram 13.2 vendor copy) ASan quick fuzz.

Host-only, single worker, a few minutes.  Not a heavy campaign; ask the
orchestrator before scaling.  Seeds: lab/rce_candidates/lt/html + generated
HTML/CSS templates.  Mutations: token/number/attribute/CSS-value fuzz.
"""
import os, random, re, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
LT = os.path.join(ROOT, 'lab', 'rce_candidates', 'lt')
BIN = os.path.join(LT, 'build', 'telegram_asan', 'lt_harness')
SEEDDIR = os.path.join(LT, 'html')
TMP = '/tmp/opencode/lt_fuzz.html'

TAGS = ['div','span','p','a','b','i','u','em','strong','table','tr','td','th','tbody','thead',
        'tfoot','ul','ol','li','dl','dt','dd','h1','h2','h3','h4','h5','h6','pre','code','blockquote',
        'img','canvas','svg','path','g','defs','linearGradient','stop','use','symbol','style','script',
        'form','input','button','select','option','textarea','label','fieldset','legend','details',
        'summary','figure','figcaption','picture','source','video','audio','iframe','object','embed']
ATTRS = ['style','class','id','width','height','colspan','rowspan','align','valign','bgcolor',
         'color','face','size','src','href','title','alt','cellpadding','cellspacing','border',
         'nowrap','span','start','type','value','checked','disabled','selected','multiple','dir','lang',
         'transform','fill','stroke','viewBox','d','x','y','cx','cy','r','rx','ry','points','gradientUnits']
CSSPROPS = ['width','height','min-width','max-width','min-height','max-height','margin','padding',
            'border','border-radius','background','background-color','background-image','background-size',
            'background-position','background-repeat','background-clip','background-origin','color',
            'display','position','top','left','right','bottom','float','clear','overflow','overflow-x',
            'overflow-y','z-index','opacity','transform','transform-origin','translate','rotate','scale',
            'clip-path','box-shadow','text-shadow','filter','backdrop-filter','flex','flex-direction',
            'flex-wrap','justify-content','align-items','align-content','align-self','gap','row-gap',
            'column-gap','grid-template-columns','grid-template-rows','grid-column','grid-row',
            'grid-auto-flow','order','font','font-size','font-family','font-weight','line-height',
            'letter-spacing','word-spacing','text-align','text-decoration','text-transform',
            'white-space','word-break','word-wrap','overflow-wrap','direction','content','counter-reset',
            'counter-increment','list-style','list-style-type','list-style-position','quotes','tab-size',
            'object-fit','object-position','aspect-ratio','contain','will-change','cursor','visibility']
NUMBERS = ['0','1','-1','2','-2','1000','1001','65535','65536','2147483647','-2147483648','4294967295',
           '1e9','-1e9','0.5','-0.5','999999999','3.4e38','1e308','-1e308','nan','inf','0x7fffffff']
UNITS = ['px','%','em','rem','pt','vw','vh','vmin','vmax','ch','ex','cm','mm','in','deg','rad','s','ms','fr']
CSSVALS = ['none','auto','inherit','initial','unset','revert','0','1px','100%','calc(100% - 1px)',
           'var(--x)','url(x)','linear-gradient(red,blue)','radial-gradient(red,blue)',
           'conic-gradient(red,blue)','repeat(3,1fr)','minmax(0,1fr)','fit-content(10px)',
           'blur(2px)','drop-shadow(1px 1px red)','opacity(0.5)','invert(1)','hue-rotate(90deg)',
           'matrix(1,2,3,4,5,6)','translate(1px,2px)','rotate(45deg)','scale(2)','skew(1deg)',
           'polygon(0 0,100% 0,100% 100%)','inset(1px)','circle(50%)','ellipse(10px 20px)',
           'attr(data-x)','counter(c)','counters(c,".")','"x"','""','open-quote','close-quote']

def gen_templates():
    out = []
    # table spans / grid / flex / filters / gradients / svg / nesting
    for span in ['0','-1','-1000','1000','1001','2147483647','-2147483648','65535','999999']:
        out.append(f'<table><tr><td colspan={span}>x</td><td rowspan={span}>y</td></tr><tr><td>z</td></tr></table>')
    out += [
        '<div style="display:grid;grid-template-columns:repeat(1000,1fr)">' + '<div>x</div>'*100 + '</div>',
        '<div style="display:flex">' + '<div style="flex:1 1 0">x</div>'*100 + '</div>',
        '<div style="filter:blur(1000px);background:linear-gradient(red,blue);width:100%;height:100%">x</div>',
        '<div style="clip-path:polygon(0 0,100% 0,100% 100%,0 100%)">x</div>',
        '<svg viewBox="0 0 10 10"><defs><linearGradient id="g"><stop offset="0" stop-color="red"/></linearGradient></defs><rect width="10" height="10" fill="url(#g)"/></svg>',
        '<style>@media (min-width:1px){div{display:grid;grid-template-columns:repeat(auto-fill,minmax(1px,1fr))}}</style><div>x</div>',
        '<style>div{--x:1px;width:calc(var(--x) * 1000000);height:var(--x);content:counter(c);counter-reset:c 1000000}</style><div>x</div>',
        '<table style="table-layout:fixed"><colgroup><col span="1000"><col></colgroup><tr><td>x</td></tr></table>',
        '<div style="position:fixed;top:-1e9px;left:-1e9px;width:1e9px;height:1e9px">x</div>',
        '<div style="background-image:radial-gradient(circle at 1e9px 1e9px,red,blue);background-size:1e9px 1e9px">x</div>',
    ]
    # nested and malformed
    out.append('<div>'*500 + 'x' + '</div>'*500)
    out.append('<table>'*100 + '<tr><td>x</td></tr>'*100 + '</table>'*100)
    out.append('<style>' + 'div{color:red}'*10000 + '</style><div>x</div>')
    out.append('<div ' + ' '.join(f'{a}="{random.choice(NUMBERS)}"' for a in ATTRS) + '>x</div>')
    return out

def mut(data, rng):
    s = data
    op = rng.randrange(10)
    if op == 0:
        s = s.replace('1', rng.choice(NUMBERS), 1)
    elif op == 1:
        s = s.replace('px', rng.choice(UNITS), 1)
    elif op == 2:
        s = s.replace('red', rng.choice(CSSVALS), 1)
    elif op == 3:
        s = s.replace('<div', f'<{rng.choice(TAGS)}', 1)
    elif op == 4:
        s = s.replace('>', f' {rng.choice(ATTRS)}="{rng.choice(NUMBERS)}">', 1)
    elif op == 5:
        pos = rng.randrange(len(s)+1)
        s = s[:pos] + f'<{rng.choice(TAGS)} style="{rng.choice(CSSPROPS)}:{rng.choice(CSSVALS)}">' + s[pos:]
    elif op == 6:
        prop = rng.choice(CSSPROPS)
        val = rng.choice(CSSVALS) if rng.random() < 0.5 else rng.choice(NUMBERS) + rng.choice(UNITS)
        s = s.replace('</style>', f'{prop}:{val}</style>', 1) if '</style>' in s else s + f'<style>*{{{prop}:{val}}}</style>'
    elif op == 7:
        s = s + s[:rng.randrange(min(len(s), 2000))]
    elif op == 8:
        s = s.replace('colspan="1"', f'colspan="{rng.choice(NUMBERS)}"', 1)
    else:
        s = s.replace('width', rng.choice(CSSPROPS), 1)
    return s[:200000]

def main():
    minutes = float(sys.argv[1]) if len(sys.argv) > 1 else 5.0
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    rng = random.Random(seed)
    if not os.path.exists(BIN):
        print('missing', BIN); return 2
    seeds = []
    for fn in sorted(os.listdir(SEEDDIR)):
        if fn.endswith('.html'):
            seeds.append(open(os.path.join(SEEDDIR, fn), 'rb').read().decode('utf-8', 'replace'))
    seeds += gen_templates()
    print(f'seeds={len(seeds)} bin={BIN}')
    os.makedirs('<HOME>/ailocal/Telegram/telegramandroidwidget/lab/ios_way/evidence/lt_fuzz_crashes', exist_ok=True)
    t0 = time.time(); n = 0; crashes = 0
    env = dict(os.environ); env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1:symbolize=1'
    while time.time() - t0 < minutes * 60:
        data = rng.choice(seeds)
        for _ in range(rng.randrange(1, 6)):
            data = mut(data, rng)
        open(TMP, 'w').write(data)
        n += 1
        try:
            p = subprocess.run([BIN, TMP], capture_output=True, timeout=3, env=env)
            err = p.stderr.decode('utf-8', 'replace')
            if p.returncode not in (0,) and ('AddressSanitizer' in err or 'runtime error' in err or 'SEGV' in err or 'SUMMARY' in err):
                crashes += 1
                out = f'<HOME>/ailocal/Telegram/telegramandroidwidget/lab/ios_way/evidence/lt_fuzz_crashes/crash_{crashes}_{n}.html'
                open(out, 'w').write(data)
                open(out + '.log', 'w').write(err)
                print(f'CRASH {crashes} exec={n} rc={p.returncode} -> {out}')
                print(err.split('\n')[0:6])
        except subprocess.TimeoutExpired:
            pass
        if n % 200 == 0:
            print(f'exec={n} crashes={crashes} elapsed={int(time.time()-t0)}s')
    print(f'done exec={n} crashes={crashes}')
    return 0

if __name__ == '__main__':
    sys.exit(main())
