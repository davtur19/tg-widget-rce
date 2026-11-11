'use strict';
function hook(name) {
  try {
    var p = Module.findGlobalExportByName(name);
    if (!p) { send({stage:'nohook', fn:name}); return; }
    Interceptor.attach(p, {onEnter: function(args) {
      try {
        var s = args[0].readUtf8String();
        if (s) send({stage:'printf', fn:name, s:s});
      } catch (e) {}
    }});
    send({stage:'hook', fn:name, addr:String(p)});
  } catch (e) { send({stage:'err', fn:name, e:String(e)}); }
}
hook('printf');
hook('puts');
hook('NSLog');
send({stage:'ready'});
setInterval(function(){}, 1000);
