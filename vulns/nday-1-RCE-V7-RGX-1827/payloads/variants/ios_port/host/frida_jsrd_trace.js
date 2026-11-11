// C-level trace for the #1827 primitive on Telegram iOS 13.2 / 6s.
// base offsets: JS_RegExpDelete 0x3f6dbd4 (snapshot ldr x8,[x21,#0x38] at +0x194)
// js_def_malloc 0x3f4f16c, js_def_free 0x3f4f174
const base = Process.getModuleByName('TelegramUIFramework').base;
send({ t: 'BASE', base: base.toString() });
const RD = base.add(0x3f6dbd4);
const MAL = base.add(0x3f4f16c);
const FRE = base.add(0x3f4f174);

Interceptor.attach(MAL, {
  onEnter(args) {
    this.sz = args[1].toUInt32();
  },
  onLeave(ret) {
    if (this.sz >= 40 && this.sz <= 512) {
      send({ t: 'M', sz: this.sz, p: ret.toString() });
    }
  }
});

Interceptor.attach(FRE, {
  onEnter(args) {
    send({ t: 'F', p: args[1].toString() });
  }
});

Interceptor.attach(RD.add(0x194), {
  onEnter(args) {
    const re = this.context.x21;
    if (re.isNull()) return;
    const bc = re.add(0x38).readPointer();
    let len = -1;
    let data = '-';
    if (!bc.isNull()) {
      len = bc.readU32() & 0x7fffffff;
      data = bc.add(0x18).toString();
    }
    send({ t: 'RD', re: re.toString(), bc: bc.toString(), len: len, data: data });
  }
});
