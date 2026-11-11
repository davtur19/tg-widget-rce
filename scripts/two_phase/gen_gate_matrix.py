#!/usr/bin/env python3
"""Desktop-gate matrix: simulated widget environments, host-only.

Each case is a tiny page: <env script> + <gate + marker script>.  The harness
(no navigator/screen by default) evaluates them in order; the marker prints
GATE 0 (mobile, pass) or GATE 1 (desktop/unknown, stop).
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = ("var GD=1;var N=navigator,U=''+N.userAgent,C=(TelegramWidget&&TelegramWidget.contentSafeAreaInset)||{},"
        "S=(screen&&screen.width)||0;if(U.length<40&&U.indexOf('TelegramWidget')>=0&&"
        "typeof __twReceive=='undefined'&&typeof __hostOps=='undefined'&&typeof webkit=='undefined'&&S<=800&&"
        "((C.bottom||0)+(C.cornerLeft||0)+(C.cornerRight||0)>0||(devicePixelRatio||1)>=2))GD=0;")
MOBILE_UA = "Mozilla/5.0 TelegramWidget/1.0"

CASES = {
    # name: (env js, expected GD)
    "android_basic": ("var navigator={userAgent:'%s',platform:'TelegramWidget'};var screen={width:360,height:640};"
                      "var devicePixelRatio=3;var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};" % MOBILE_UA, 0),
    "ios_with_sa": ("var navigator={userAgent:'%s'};var screen={width:390,height:844};var devicePixelRatio=3;"
                    "var TelegramWidget={contentSafeAreaInset:{bottom:34,cornerLeft:0,cornerRight:0}};" % MOBILE_UA, 0),
    "ios6s_dpr2_nosa": ("var navigator={userAgent:'%s'};var screen={width:375,height:667};var devicePixelRatio=2;"
                        "var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};" % MOBILE_UA, 0),
    "phone_dpr25_nosa": ("var navigator={userAgent:'%s'};var screen={width:412,height:915};var devicePixelRatio=2.5;"
                         "var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};" % MOBILE_UA, 0),
    "desktop_webview_ua": ("var navigator={userAgent:'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',platform:'Win32'};"
                          "var screen={width:1920,height:1080};var devicePixelRatio=1;"
                          "var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};", 1),
    "desktop_webview_dpr2": ("var navigator={userAgent:'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',platform:'MacIntel'};"
                            "var screen={width:1440,height:900};var devicePixelRatio=2;"
                            "var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};", 1),
    "native_desktop_dpr15": ("var navigator={userAgent:'%s',platform:'TelegramWidget'};var screen={width:400,height:300};"
                             "var devicePixelRatio=1.5;var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};" % MOBILE_UA, 1),
    "native_desktop_dpr2_RESIDUAL": ("var navigator={userAgent:'%s',platform:'TelegramWidget'};var screen={width:400,height:300};"
                                     "var devicePixelRatio=2.0;var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};" % MOBILE_UA, 0),
    "webview_adapter_globals": ("var navigator={userAgent:'%s'};var screen={width:390,height:844};var devicePixelRatio=3;"
                                "var TelegramWidget={contentSafeAreaInset:{bottom:34,cornerLeft:0,cornerRight:0}};"
                                "globalThis.webkit={};" % MOBILE_UA, 1),
    "unknown_no_env": ("", 1),
    "short_ua_real_screen": ("var navigator={userAgent:'TelegramWidget/1.0'};var screen={width:1920,height:1080};"
                             "var devicePixelRatio=2;var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};", 1),
    "mobile_ua_long_suffix": ("var navigator={userAgent:'%s (X11; Linux x86_64)'};var screen={width:360,height:640};"
                              "var devicePixelRatio=3;var TelegramWidget={contentSafeAreaInset:{bottom:0,cornerLeft:0,cornerRight:0}};" % MOBILE_UA, 1),
}

for name, (env, exp) in CASES.items():
    body = ('<!doctype html><body><div id="v">Ok</div>'
            + ('<script id="env">' + env + '</script>' if env else '')
            + '<script>' + GATE + '</script>'
            + "<script>var d=document.getElementById('v');if(d)d.textContent='GATE '+GD+' EXPECT %d';</script>" % exp)
    open(os.path.join(HERE, "gate_%s.html" % name), "w").write(body)
print("cases:", len(CASES))
