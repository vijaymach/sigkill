#!/usr/bin/env python3
"""inject_gadget.py - give any APK an in-process memory scanner (frida-gadget).

Why this is the only non-root path: SELinux forbids one app reading another
app's memory (no ptrace, no /proc/<pid>/mem). So the scanner has to live
INSIDE the target process. This tool wires that up:

  1. decode the APK with apktool
  2. drop libfrida-gadget.so + libfrida-gadget.config.so into lib/arm64-v8a/
  3. inject System.loadLibrary("frida-gadget") into the launcher activity's
     static initializer
  4. force android:extractNativeLibs="true" so the config is a real file
  5. rebuild, zipalign, sign with your key

After install, the gadget listens on 127.0.0.1:<port> inside the app.
From the PC:

  adb forward tcp:27042 tcp:27042
  python ce.py info

usage:
  python inject_gadget.py <in.apk> <out.apk> [--port 27042] [--no-sign]

requires: tools/apktool.jar, tools/frida/libfrida-gadget.so, build-tools
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APKTOOL = ROOT / "tools" / "apktool.jar"
GADGET = ROOT / "tools" / "frida" / "libfrida-gadget.so"
KEYSTORE = ROOT / "release.keystore"
KS_PASS = "android"
KS_ALIAS = "k"

BT = Path(os.environ.get("ANDROID_BUILD_TOOLS",
          r"C:\Users\VIJAY\AppData\Local\Android\Sdk\build-tools\36.0.0"))
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _java() -> str:
    """java is not on PATH here; JAVA_HOME points at Android Studio's jbr."""
    cands = []
    jh = os.environ.get("JAVA_HOME")
    if jh:
        cands.append(Path(jh) / "bin" / "java.exe")
    cands.append(Path(r"C:\Program Files\Android\Android Studio\jbr\bin\java.exe"))
    for c in cands:
        if c.exists():
            return str(c)
    found = shutil.which("java")
    if found:
        return found
    raise SystemExit("[x] no java found - set JAVA_HOME")


JAVA = _java()
ENV = dict(os.environ)
ENV["PATH"] = str(Path(JAVA).parent) + os.pathsep + ENV.get("PATH", "")

SMALI_CLINIT = """\
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "frida-gadget"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method
"""


def run(cmd, **kw):
    kw.setdefault("env", ENV)
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        print(f"[x] {' '.join(map(str, cmd))}\n{p.stdout}\n{p.stderr}")
        raise SystemExit(1)
    return p.stdout


def launcher_activity(decoded: Path) -> str | None:
    manifest = decoded / "AndroidManifest.xml"
    tree = ET.parse(manifest)
    root = tree.getroot()
    for tag in ("activity", "activity-alias"):
        for act in root.iter(tag):
            for flt in act.iter("intent-filter"):
                actions = {a.get(ANDROID_NS + "name") for a in flt.iter("action")}
                cats = {c.get(ANDROID_NS + "name") for c in flt.iter("category")}
                if ("android.intent.action.MAIN" in actions and
                        "android.intent.category.LAUNCHER" in cats):
                    return act.get(ANDROID_NS + "name")
    app = root.find("application")
    if app is not None and app.get(ANDROID_NS + "name"):
        return app.get(ANDROID_NS + "name")
    return None


def find_smali(decoded: Path, cls: str) -> Path | None:
    rel = cls.lstrip(".").replace(".", "/") + ".smali"
    for d in sorted(decoded.glob("smali*")):
        if not d.is_dir():
            continue
        p = d / rel
        if p.exists():
            return p
    return None


def inject_clinit(path: Path) -> str:
    """Insert System.loadLibrary("frida-gadget") at the top of the static
    initializer. Works whether the method declares .locals or .registers
    (never both - that is a smali syntax error), and v0 is a safe scratch
    at method entry because <clinit> takes no arguments."""
    text = path.read_text(encoding="utf-8")
    if "frida-gadget" in text:
        return "already injected"

    call = ('    const-string v0, "frida-gadget"\n\n'
            '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n')

    m = re.search(r"^\.method\s+(?:public\s+|private\s+|protected\s+|static\s+)*"
                  r"constructor\s+<clinit>\(\)V", text, re.M)
    if m:
        body_start = m.end()
        d = re.compile(r"^[ \t]*\.(locals|registers)[ \t]+(\d+)[ \t]*$", re.M)
        dm = d.search(text, body_start)
        if dm and dm.start() < body_start + 400:
            n = int(dm.group(2))
            if n < 1:
                repl = f".{dm.group(1)} 1"
                text = text[:dm.start()] + repl + text[dm.end():]
                insert_at = dm.start() + len(repl)
            else:
                insert_at = dm.end()
            text = text[:insert_at] + "\n\n" + call + text[insert_at:]
        else:
            text = text[:body_start] + "\n    .locals 1\n\n" + call + text[body_start:]
        path.write_text(text, encoding="utf-8")
        return "patched existing <clinit>"

    idx = text.rstrip().rfind("}")
    if idx < 0:
        raise SystemExit(f"[x] cannot parse {path}")
    text = text[:idx] + "\n" + SMALI_CLINIT + "\n" + text[idx:]
    path.write_text(text, encoding="utf-8")
    return "added <clinit>"


def patch_manifest(decoded: Path) -> str:
    """Text-level edit. An ElementTree round-trip would rewrite the android:
    namespace prefix as ns0:, which apktool then refuses to rebuild."""
    manifest = decoded / "AndroidManifest.xml"
    text = manifest.read_text(encoding="utf-8")
    m = re.search(r"<application\b[^>]*>", text)
    if not m:
        return "no <application> tag"
    tag = m.group(0)
    before = "unset"
    have = re.search(r'android:extractNativeLibs="([^"]*)"', tag)
    if have:
        before = have.group(1)
        new_tag = tag.replace(have.group(0), 'android:extractNativeLibs="true"')
    else:
        new_tag = tag[:-1].rstrip() + ' android:extractNativeLibs="true">'
    text = text[:m.start()] + new_tag + text[m.end():]
    manifest.write_text(text, encoding="utf-8")
    return f"extractNativeLibs {before} -> true"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("out")
    ap.add_argument("--port", default="27042")
    ap.add_argument("--no-sign", action="store_true")
    ap.add_argument("--keep-decoded", action="store_true")
    a = ap.parse_args()

    src = Path(a.apk).resolve()
    out = Path(a.out).resolve()
    for need in (APKTOOL, GADGET):
        if not need.exists():
            raise SystemExit(f"[x] missing {need}")
    if not src.exists():
        raise SystemExit(f"[x] no such apk: {src}")

    work = Path(tempfile.mkdtemp(prefix="inject_", dir=str(ROOT / "work")))
    decoded = work / "decoded"
    print(f"  input : {src}  ({src.stat().st_size/1e6:.2f} MB)")

    print("  [1/6] apktool d")
    run([JAVA, "-jar", str(APKTOOL), "d", "-f", "-q", str(src), "-o", str(decoded)])

    print("  [2/6] gadget payload")
    jni_dirs = sorted(decoded.glob("lib/*"))
    target_lib = decoded / "lib" / "arm64-v8a"
    target_lib.mkdir(parents=True, exist_ok=True)
    shutil.copy2(GADGET, target_lib / "libfrida-gadget.so")
    (target_lib / "libfrida-gadget.config.so").write_text(
        '{\n'
        '  "interaction": {\n'
        '    "type": "listen",\n'
        '    "address": "127.0.0.1",\n'
        f'    "port": {int(a.port)},\n'
        '    "on_port_conflict": "fail",\n'
        '    "on_load": "wait"\n'
        '  }\n'
        '}\n', encoding="utf-8")
    print(f"         lib dirs seen: {[d.name for d in jni_dirs] or 'none'} -> arm64-v8a")

    print("  [3/6] manifest")
    print("         " + patch_manifest(decoded))

    print("  [4/6] smali injection")
    cls = launcher_activity(decoded)
    if not cls:
        raise SystemExit("[x] no launcher activity found")
    smali = find_smali(decoded, cls)
    if not smali:
        raise SystemExit(f"[x] smali for {cls} not found")
    print(f"         {cls}\n         {inject_clinit(smali)}")

    print("  [5/6] apktool b")
    unsigned = work / "unsigned.apk"
    run([JAVA, "-jar", str(APKTOOL), "b", "-q", str(decoded), "-o", str(unsigned)])
    print(f"         {unsigned.stat().st_size/1e6:.2f} MB")

    if a.no_sign:
        shutil.copy2(unsigned, out)
        print(f"  output: {out} (unsigned)")
        return 0

    print("  [6/6] zipalign + apksigner")
    aligned = work / "aligned.apk"
    run([str(BT / "zipalign.exe"), "-P", "16", "-f", "4", str(unsigned), str(aligned)])
    run([str(BT / "apksigner.bat"), "sign",
         "--ks", str(KEYSTORE), "--ks-pass", f"pass:{KS_PASS}",
         "--key-pass", f"pass:{KS_PASS}", "--ks-key-alias", KS_ALIAS,
         "--out", str(out), str(aligned)])

    if not a.keep_decoded:
        shutil.rmtree(work, ignore_errors=True)

    print(f"  output: {out}  ({out.stat().st_size/1e6:.2f} MB)")
    print(f"  gadget listens on 127.0.0.1:{a.port} inside the app process")
    print(f"  next: adb install -r \"{out}\"")
    print(f"        adb forward tcp:{a.port} tcp:{a.port}")
    print("        python tools/ce.py info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
