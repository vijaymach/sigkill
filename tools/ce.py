#!/usr/bin/env python3
"""ce.py - drive the in-process scanner inside an injected APK.

The gadget listens on 127.0.0.1:<port> inside the app. From the PC:

    adb forward tcp:27042 tcp:27042
    python ce.py info
    python ce.py scan i32 500            # first scan
    python ce.py next i32 480            # next scan, value became 480
    python ce.py next i32 --mode changed # or: changed / inc / dec / lt / gt
    python ce.py list 20
    python ce.py write 0x7a1b2c3d i32 99999999
    python ce.py freeze 0x7a1b2c3d i32 99999999
    python ce.py unfreeze 0x7a1b2c3d
    python ce.py reset

types: i8 i16 i32 i64 f32 f64 utf8 utf16
"""
import argparse
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "ce.js"

DEFAULT_PORT = 27042
API_PORT = 27043


def serve_api(session, script, host: str, port: int):
    """Expose the scanner over a line-delimited JSON socket on the PC.

    Why the PC and not the device: frida's JS runs on one thread, so a
    blocking accept() inside the gadget would stall the freeze timers.
    The device app reaches this server through:
        adb reverse tcp:27043 tcp:27043
    so it just dials 127.0.0.1:27043 and needs no frida code at all.
    """
    import json
    import socketserver
    import threading

    ex = script.exports_sync
    lock = threading.Lock()

    def handle(req):
        cmd = (req.get("cmd") or "").lower()
        if cmd == "info":
            m = ex.module(req.get("module"))
            return {"ok": True, "module": m}
        if cmd == "ranges":
            return {"ok": True, "ranges": ex.ranges()}
        if cmd == "scan":
            t = req.get("type", "i32")
            v = req.get("value")
            if not t.startswith("utf") and not isinstance(v, (int, float)):
                v = float(v) if "." in str(v) else int(v)
            return {"ok": True, **ex.scan(t, v, req.get("module"))}
        if cmd == "next":
            return {"ok": True, **ex.next(req.get("mode", "changed"), req.get("value"))}
        if cmd == "list":
            return {"ok": True, **ex.list(int(req.get("n", 30)))}
        if cmd == "read":
            return {"ok": True, **ex.read(req["addr"], req.get("type", "i32"))}
        if cmd == "write":
            return {"ok": True, **ex.write(req["addr"], req.get("type", "i32"), req["value"])}
        if cmd == "freeze":
            return {"ok": True, **ex.freeze(req["addr"], req.get("type", "i32"), req["value"])}
        if cmd == "unfreeze":
            return {"ok": True, **ex.unfreeze(req.get("addr"))}
        if cmd == "clear":
            return {"ok": True, **ex.clear()}
        if cmd == "reset":
            return {"ok": True, **ex.reset()}
        return {"ok": False, "error": f"unknown cmd: {cmd}"}

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b'{"ok":true,"hello":"ce api"}\n')
            self.wfile.flush()
            for raw in self.rfile:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except Exception as e:
                    resp = {"ok": False, "error": f"json: {e}"}
                else:
                    try:
                        with lock:
                            resp = handle(req)
                    except Exception as e:
                        resp = {"ok": False, "error": str(e)}
                self.wfile.write((json.dumps(resp) + "\n").encode())
                self.wfile.flush()

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer((host, port), Handler)
    print(f"  api listening on {host}:{port}")
    print(f"  device app connects after: adb reverse tcp:{port} tcp:{port}")
    print("  ctrl-c to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
    finally:
        srv.server_close()



def connect(port: int, host: str):
    import frida
    mgr = frida.get_device_manager()
    dev = mgr.add_remote_device(f"{host}:{port}")
    last = None
    for attempt in range(15):
        try:
            procs = dev.enumerate_processes()
            name = None
            for p in procs:
                if "gadget" in p.name.lower():
                    name = p.name
                    break
            if name is None and procs:
                name = procs[0].name
            if name is None:
                raise RuntimeError("gadget not loaded yet")
            session = dev.attach(name)
            script = session.create_script(SCRIPT.read_text(encoding="utf-8"))
            errors = []
            script.on("message", lambda m, d: errors.append(m))
            script.load()
            return session, script, errors
        except Exception as e:          # gadget may still be starting
            last = e
            time.sleep(1)
    raise SystemExit(f"[x] cannot attach to gadget on {host}:{port}: {last}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["info", "module", "ranges", "scan", "next",
                                    "list", "write", "read", "freeze", "unfreeze",
                                    "clear", "reset", "serve"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--mode", default=None,
                    help="next-scan filter: eq ne gt lt ge le inc dec changed unchanged")
    a = ap.parse_args()

    session, script, errors = connect(a.port, a.host)
    ex = script.exports_sync

    try:
        if a.cmd == "serve":
            serve_api(session, script, a.host, int(a.args[0]) if a.args else API_PORT)
        elif a.cmd == "info":
            m = ex.module(None)
            print(f"  pid {m['process']}  {m['arch']}  ptr {m['pointer_size']}B  "
                  f"{m['module_count']} modules")
            for row in m["top"]:
                print(f"    {row['size']/1e6:8.2f} MB  {row['base']}  {row['name']}")
        elif a.cmd == "module":
            if not a.args:
                raise SystemExit("usage: module <name>   (e.g. libil2cpp.so)")
            m = ex.module(a.args[0])
            if not m.get("found"):
                print(f"  not loaded: {a.args[0]}")
            else:
                print(f"  {m['name']}\n  base : {m['base']}\n"
                      f"  size : {m['size']/1e6:.2f} MB\n  path : {m['path']}")
        elif a.cmd == "ranges":
            r = ex.ranges()
            print(f"  rw- ranges: {r['count']}  total {r['total_mb']} MB")
            for row in r["rows"]:
                print(f"    {row['base']}  {row['size']/1e6:.2f} MB")
        elif a.cmd == "scan":
            if len(a.args) < 2:
                raise SystemExit("usage: scan <type> <value> [module]")
            typ, val = a.args[0], a.args[1]
            mod = a.args[2] if len(a.args) > 2 else None
            t0 = time.time()
            r = ex.scan(typ, val if typ.startswith("utf") else float(val) if "." in val else int(val), mod)
            print(f"  first scan {typ} = {val}: {r['count']} hits"
                  f" over {r['ranges']} ranges ({time.time()-t0:.1f}s)"
                  + ("  [truncated]" if r["truncated"] else ""))
        elif a.cmd == "next":
            if len(a.args) < 1:
                raise SystemExit("usage: next <type> [value] [--mode eq|changed|inc|...]")
            typ = a.args[0]
            raw = a.args[1] if len(a.args) > 1 else None
            val = None
            if raw is not None:
                val = raw if typ.startswith("utf") else float(raw) if "." in raw else int(raw)
            mode = a.mode or ("eq" if val is not None else "changed")
            r = ex.next(mode, val)
            print(f"  next scan (mode={mode}, type={typ}): {r['count']} remain")
        elif a.cmd == "list":
            n = int(a.args[0]) if a.args else 30
            r = ex.list(n)
            print(f"  {r['total']} addresses, type {r['type']}, showing {r['shown']}")
            for row in r["rows"]:
                print(f"    {row['addr']}  =  {row['value']}")
        elif a.cmd == "read":
            typ = a.args[1] if len(a.args) > 1 else "i32"
            print(ex.read(a.args[0], typ))
        elif a.cmd == "write":
            if len(a.args) < 3:
                raise SystemExit("usage: write <addr> <type> <value>")
            typ, raw = a.args[1], a.args[2]
            val = raw if typ.startswith("utf") else float(raw) if "." in raw else int(raw)
            print(ex.write(a.args[0], typ, val))
        elif a.cmd == "freeze":
            if len(a.args) < 3:
                raise SystemExit("usage: freeze <addr> <type> <value>")
            typ, raw = a.args[1], a.args[2]
            val = float(raw) if "." in raw else int(raw)
            print(ex.freeze(a.args[0], typ, val))
        elif a.cmd == "unfreeze":
            print(ex.unfreeze(a.args[0] if a.args else None))
        elif a.cmd == "clear":
            print(ex.clear())
        elif a.cmd == "reset":
            print(ex.reset())
    finally:
        if errors:
            for e in errors[:5]:
                print(f"  [script] {e}")
        try:
            session.detach()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
