// Capture Telegram's own windows in-process and write a PNG into its container.
try {
  var CG = Process.getModuleByName('CoreGraphics');
  var UIKit = Process.getModuleByName('UIKit');
  var CGColorSpaceCreateDeviceRGB = new NativeFunction(
    CG.getExportByName('CGColorSpaceCreateDeviceRGB'), 'pointer', []);
  var CGBitmapContextCreate = new NativeFunction(
    CG.getExportByName('CGBitmapContextCreate'), 'pointer',
    ['pointer', 'ulong', 'ulong', 'ulong', 'ulong', 'pointer', 'uint32']);
  var CGBitmapContextCreateImage = new NativeFunction(
    CG.getExportByName('CGBitmapContextCreateImage'), 'pointer', ['pointer']);
  var CGContextRelease = new NativeFunction(
    CG.getExportByName('CGContextRelease'), 'void', ['pointer']);
  var CGImageRelease = new NativeFunction(
    CG.getExportByName('CGImageRelease'), 'void', ['pointer']);
  var CGContextTranslateCTM = new NativeFunction(
    CG.getExportByName('CGContextTranslateCTM'), 'void',
    ['pointer', 'double', 'double']);
  var CGContextScaleCTM = new NativeFunction(
    CG.getExportByName('CGContextScaleCTM'), 'void',
    ['pointer', 'double', 'double']);
  var UIImagePNGRepresentation = new NativeFunction(
    UIKit.getExportByName('UIImagePNGRepresentation'), 'pointer', ['pointer']);

  var app = ObjC.classes.UIApplication.sharedApplication();
  var wins = app.windows();
  var win = null;
  for (var i = 0; i < wins.count(); i++) {
    var w = wins.objectAtIndex_(i);
    if (w.isKeyWindow()) { win = w; break; }
  }
  if (!win && wins.count() > 0) win = wins.objectAtIndex_(0);
  if (!win) { send({ ok: false, err: 'no window' }); }
  else {
    var b = win.bounds();
    var width = Math.round(b[1][0]);
    var height = Math.round(b[1][1]);
    var cs = CGColorSpaceCreateDeviceRGB();
    var ctx = CGBitmapContextCreate(ptr(0), width, height, 8, width * 4, cs, 1);
    if (ctx.isNull()) { send({ ok: false, err: 'no bitmap context' }); }
    else {
      CGContextTranslateCTM(ctx, 0, height);
      CGContextScaleCTM(ctx, 1, -1);
      for (var j = 0; j < wins.count(); j++) {
        wins.objectAtIndex_(j).layer().renderInContext_(ctx);
      }
      var cg = CGBitmapContextCreateImage(ctx);
      if (cg.isNull()) { send({ ok: false, err: 'no CGImage' }); }
      else {
        var image = ObjC.classes.UIImage.imageWithCGImage_(cg);
        var png = UIImagePNGRepresentation(image);
        if (png.isNull()) { send({ ok: false, err: 'no PNG' }); }
        else {
          var pngData = new ObjC.Object(png);
          var len = pngData.length();
          var home = ObjC.classes.NSProcessInfo.processInfo()
            .environment().objectForKey_('HOME').toString();
          var path = home + '/Documents/frida_screen.png';
          var wrote = pngData.writeToFile_atomically_(path, true);
          send({ ok: !!wrote, len: len, w: width, h: height, path: path });
        }
        CGImageRelease(cg);
      }
      CGContextRelease(ctx);
    }
  }
} catch (e) {
  send({ ok: false, err: String(e), stack: e.stack });
}
