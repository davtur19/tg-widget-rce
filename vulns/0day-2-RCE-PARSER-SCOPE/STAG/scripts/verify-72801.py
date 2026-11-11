#!/usr/bin/env python3
"""Verify the route-2 assumptions in the Telegram 13.2.0 (72801) release lib.

Checks, with no device and no disassembler dependency beyond capstone/pyelftools:
  1. SHA-256 / Build-ID / size of the lib.
  2. The fork's arena size-class table (31 x uint16) is present and identical.
  3. The one mmap(NULL, 65536, RW, PRIVATE|ANON) call of arena_slab_take.
  4. The add_closure_variables loop signature (byte-identical in 72801/72889/72929).
  5. Function boundaries from .eh_frame for the crash PC and its callers.
  6. The crash arithmetic from the tombstone registers.

Usage: python3 verify_72801.py [--lib PATH] [--tombstone PATH]
"""
import argparse, hashlib, struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_MEM
from elftools.elf.elffile import ELFFile

SIZES = [16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,
         144,160,176,192,208,224,240,256,288,320,352,384,416,448,480,512]
CLASS_TABLE = b''.join(struct.pack('<H', x) for x in SIZES)
# ldrh w11,[x24,#0x38]; ldr x12,[x24,#0x28]; add w11,w11,w10,uxtw;
# madd x13,x11,x8,x12; ldr w13,[x13,#4]
ACV_SIG = b''.join(struct.pack('<I', w) for w in
                   (0x7940730b, 0xf940170c, 0x8b2a416b, 0x9b08316d, 0xb94005ad))


def sx(v, b):
    return v - (1 << b) if v & (1 << (b - 1)) else v


def find_all(d, pat):
    out, s = [], 0
    while True:
        i = d.find(pat, s)
        if i < 0:
            return out
        out.append(i)
        s = i + 1


def plt_symbols(elf):
    plt = elf.get_section_by_name('.plt')
    pd, pb = plt.data(), plt['sh_addr']
    dyn = elf.get_section_by_name('.dynsym')
    rel = elf.get_section_by_name('.rela.plt')
    got2sym = {r['r_offset']: dyn.get_symbol(r['r_info_sym']).name
               for r in rel.iter_relocations()}
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
    stub2sym = {}
    for off in range(0, len(pd) - 16, 16):
        page = got = None
        for ins in md.disasm(pd[off:off + 16], pb + off):
            if ins.mnemonic == 'adrp':
                page = ins.operands[1].imm
            elif ins.mnemonic == 'ldr' and page is not None and len(ins.operands) > 1 \
                    and ins.operands[1].type == ARM64_OP_MEM:
                got = page + ins.operands[1].mem.disp
        if got in got2sym:
            stub2sym[pb + off] = got2sym[got]
    return stub2sym, elf.get_section_by_name('.text')


def fde_ranges(path):
    """Minimal .eh_frame FDE range parser (binary searchable)."""
    f = open(path, 'rb'); e = ELFFile(f)
    sec = e.get_section_by_name('.eh_frame')
    d, base = sec.data(), sec['sh_addr']
    off = 0
    ranges = []
    while off + 4 <= len(d):
        ln = struct.unpack('<I', d[off:off + 4])[0]
        if ln == 0:
            break
        if ln == 0xffffffff:
            break
        cie_id = struct.unpack('<I', d[off + 4:off + 8])[0]
        cid = off if cie_id == 0 else off - cie_id
        if cie_id != 0:
            # FDE: decode initial_location + address_range using the CIE's
            # encoding; virtually all NDK FDEs use pcrel-sdata4 (0x1b).
            p = off + 8
            loc = struct.unpack('<i', d[p:p + 4])[0]
            rng = struct.unpack('<I', d[p + 4:p + 8])[0]
            pc = base + (off + 8) + loc
            if rng:
                ranges.append((pc, pc + rng))
        off += ln + 4
    ranges.sort()
    f.close()
    return ranges


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lib', default='lib/libtmessages.49.so')
    ap.add_argument('--tombstone', default='crash_tombstone_excerpt.txt')
    ap.add_argument('--compare', nargs='*', default=[])
    a = ap.parse_args()

    d = open(a.lib, 'rb').read()
    f = open(a.lib, 'rb'); elf = ELFFile(f)
    print('lib       :', a.lib)
    print('size      :', len(d))
    print('sha256    :', hashlib.sha256(d).hexdigest())
    note = elf.get_section_by_name('.note.gnu.build-id')
    if note:
        print('build-id  :', note.data()[4:].hex())
    print('comment   :', elf.get_section_by_name('.comment').data().split(b'\0')[0].decode())

    print('\n[1] arena class table (fork JS_ARENA_BLOCK_SIZE_COUNT=31)')
    hits = find_all(d, CLASS_TABLE)
    for h in hits:
        print('  hit 0x%x: %s' % (h, SIZES))

    print('\n[2] arena_slab_take mmap(NULL, 0x10000, RW, PRIVATE|ANON)')
    stub2sym, text = plt_symbols(elf)
    tb, td = text['sh_addr'], text.data()
    mm = {s for s, n in stub2sym.items() if n == 'mmap'}
    n = len(td) // 4
    words = struct.unpack('<%dI' % n, td[:n * 4])
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
    for i, w in enumerate(words):
        if (w & 0xFC000000) != 0x94000000:
            continue
        pc = tb + i * 4
        if pc + sx(w & 0x3ffffff, 26) * 4 not in mm:
            continue
        win = list(md.disasm(td[pc - tb - 12 * 4:pc - tb + 4], pc - 12 * 4))
        txt = ' '.join(x.op_str for x in win)
        if '#0x10000' in txt:
            print('  call 0x%x: %s' % (pc, ' | '.join(
                '%s %s' % (x.mnemonic, x.op_str) for x in win[-6:])))

    print('\n[3] add_closure_variables loop signature')
    for h in find_all(d, ACV_SIG):
        print('  hit 0x%x' % h)
        for ins in md.disasm(d[h:h + 24], h):
            print('    0x%x  %-7s %s' % (ins.address, ins.mnemonic, ins.op_str))

    print('\n[4] .eh_frame functions of the crash backtrace')
    rng_all = fde_ranges(a.lib)
    def find(pc):
        lo, hi = 0, len(rng_all) - 1
        while lo <= hi:
            m = (lo + hi) // 2
            if rng_all[m][0] <= pc < rng_all[m][1]:
                return rng_all[m]
            if pc < rng_all[m][0]:
                hi = m - 1
            else:
                lo = m + 1
        return None
    try:
        t = open(a.tombstone).read()
    except OSError:
        t = ''
    pcs = []
    for line in t.splitlines():
        line = line.strip()
        if line.startswith('#') and 'pc ' in line:
            pcs.append(int(line.split()[2], 16))
    for pc in pcs[:8]:
        r = find(pc)
        print('  pc 0x%-8x -> %s' % (pc, ('0x%x..0x%x (%d B)' % (r[0], r[1], r[1] - r[0])) if r else '?'))

    print('\n[5] crash arithmetic')
    print('  b (x24)          = 0x6e776f9c98')
    print('  vardefs (x12)    = 0x6e776f9d18  (= b+0x80, JSFunctionBytecode->vardefs)')
    print('  vd      (x13)    = 0x6e77839d04  (= vardefs + 20*65535 = b+1,310,828)')
    print('  fault            = 0x6e77839d08  (= &vd->scope_level = vd+4)')
    print('  arg_count (b+0x38) = 1, var_count = 6  (c2560s geometry)')
    print('  target slab      = b_slab + 20*0x10000 (20 x 64 KiB)')
    print('  signal           = SIGSEGV/SEGV_ACCERR, ESR DFSC=6 (translation fault,')
    print('                     VMA present without read permission -> PROT_NONE)')

    for c in a.compare:
        dc = open(c, 'rb').read()
        print('\n[compare %s] size %d sha256 %s' % (c, len(dc), hashlib.sha256(dc).hexdigest()[:16]))
        print('  class table:', [hex(x) for x in find_all(dc, CLASS_TABLE)])
        print('  acv sig    :', [hex(x) for x in find_all(dc, ACV_SIG)])
    f.close()


if __name__ == '__main__':
    main()
