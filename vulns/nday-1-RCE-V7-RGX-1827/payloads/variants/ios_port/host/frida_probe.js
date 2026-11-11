/*
 * Frida ground truth for the iOS port (run by the orchestrator on the 6s).
 *
 *   frida -U -f ph.telegra.Telegraph -l frida_probe.js --no-pause
 * or attach:
 *   frida -U ph.telegra.Telegraph -l frida_probe.js
 *
 * Prints the values the widget payload must reproduce:
 *   - module bases (Telegram, TelegramUIFramework, libsystem_*),
 *   - libc free/system/dlopen/posix_spawn addresses,
 *   - whether /bin/sh and /var/jb shells exist,
 *   - an optional mprotect(PROT_EXEC) probe (DANGEROUS; off by default).
 *
 * This is a device operation: the orchestrator runs it, not the static agent.
 */

'use strict';

const DO_MPROTECT = false;   // set true only on a throwaway process

function hx(x) { return '0x' + x.toString(16); }

function main() {
  console.log('[iosprobe] arch=' + Process.arch + ' pid=' + Process.id);

  const mods = ['Telegram', 'TelegramUIFramework', 'libsystem_c.dylib',
                'libsystem_malloc.dylib', 'libsystem_darwin.dylib',
                'libsystem_kernel.dylib'];
  for (const m of mods) {
    try {
      const mod = Process.getModuleByName(m);
      console.log('[iosprobe] module ' + m + ' base=' + hx(mod.base) +
                  ' size=' + hx(mod.size) + ' path=' + mod.path);
    } catch (e) {
      console.log('[iosprobe] module ' + m + ' missing');
    }
  }

  for (const sym of ['free', 'malloc', 'realloc', 'malloc_usable_size',
                     'system', 'dlopen', 'dlsym', 'dladdr', 'posix_spawn',
                     'socket', 'connect', 'read', 'write', 'close',
                     'fopen', 'fprintf', 'fflush', 'printf', 'mprotect']) {
    try {
      const p = Module.getExportByName(null, sym);
      console.log('[iosprobe] sym ' + sym + '=' + p);
    } catch (e) {
      console.log('[iosprobe] sym ' + sym + ' missing');
    }
  }

  for (const p of ['/bin/sh', '/var/jb/bin/sh', '/var/jb/usr/bin/sh',
                   '/usr/bin/sh']) {
    try {
      console.log('[iosprobe] exists ' + p + '=' + File.exists(p));
    } catch (e) {
      console.log('[iosprobe] exists ' + p + ' err=' + e);
    }
  }

  if (DO_MPROTECT) {
    try {
      const mmap = new NativeFunction(Module.getExportByName(null, 'mmap'),
                                      'pointer', ['pointer', 'size_t', 'int', 'int', 'int', 'long']);
      const mprotect = new NativeFunction(Module.getExportByName(null, 'mprotect'),
                                          'int', ['pointer', 'size_t', 'int']);
      // MAP_PRIVATE|MAP_ANON = 0x1002, PROT_READ|WRITE = 3
      const p = mmap(ptr(0), 0x4000, 3, 0x1002, -1, 0);
      const r = mprotect(p, 0x4000, 7); // RWX
      console.log('[iosprobe] mprotect_rwx=' + r + ' page=' + p);
    } catch (e) {
      console.log('[iosprobe] mprotect err=' + e);
    }
  }
}

try {
  if (!Process.getModuleByName('TelegramUIFramework') &&
      !Process.getModuleByName('Telegram')) {
    console.log('[iosprobe] Telegram not loaded yet; waiting for module');
    const timer = setInterval(function () {
      if (Process.getModuleByName('Telegram') ||
          Process.getModuleByName('TelegramUIFramework')) {
        clearInterval(timer);
        main();
      }
    }, 200);
  } else {
    main();
  }
} catch (e) {
  console.log('[iosprobe] fatal ' + e);
}
