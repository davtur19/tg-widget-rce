#!/usr/bin/env python3
import argparse, json, sys, time
import frida
ap = argparse.ArgumentParser()
ap.add_argument("--pid", type=int, required=True)
ap.add_argument("--js", required=True)
ap.add_argument("--host", default="<LAN_IP>:27043")
ap.add_argument("--timeout", type=float, default=30.0)
ap.add_argument("--settle", type=float, default=0.5)
a = ap.parse_args()
src = open(a.js).read()
dev = frida.get_device_manager().add_remote_device(a.host)
s = dev.attach(a.pid)
state = {"done": False}
def on_msg(m, d):
    if m.get("type") == "send":
        p = m.get("payload")
        print("JS:", json.dumps(p, ensure_ascii=False))
        if isinstance(p, dict) and p.get("stage") in ("done","error","fatal"):
            state["done"] = True
    else:
        print("ERR:", m.get("description"), m.get("stack",""))
        state["done"] = True
sc = s.create_script(src)
sc.on("message", on_msg)
sc.load()
t0=time.time()
while time.time()-t0 < a.timeout and not state["done"]:
    time.sleep(0.1)
if state["done"]:
    time.sleep(a.settle)
sc.unload(); s.detach()
