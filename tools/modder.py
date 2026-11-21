#!/usr/bin/env python3
"""modder.py - generic Unity/IL2CPP APK modding pipeline.

Temple Run was done by hand. This does the same work for any IL2CPP game:
find the files, dump the symbols, read the ARM64, patch it, repack, sign,
install.

  modder.py dump    <apk> [more.apk ...]  [--out DIR]
      Locates libil2cpp.so + global-metadata.dat anywhere in the APK set
      (base + config splits), extracts them, runs Il2CppDumper, reports.

  modder.py find    <dump.cs> <keyword> [more keywords]
      Prints every field and method matching the keyword, with its file
      offset in libil2cpp.so -- the number you feed to patch.

  modder.py code    <lib.so> <offset> [count]
      Disassemble ARM64 at a file offset.

  modder.py patch   <lib.so> <offset> <asm> [--expect <hex>] [--out <lib.so>]
      Assemble any ARM64 instruction and write it. --expect refuses to
      touch the file if the current word does not match.

  modder.py mult    <lib.so> <offset> <shift> [--out <lib.so>]
      Rewrite "add wX, wX, wY" into "add wX, wX, wY, lsl #shift".
      Keeps the sign, so a subtract path still works.

  modder.py repack  <in.apk> <out.apk> [--replace <entry>=<file>] ...
      Swap payload files, drop the old signature, keep compression.

  modder.py sign    <in.apk> <out.apk>
      zipalign -P 16 + apksigner with the project keystore.

  modder.py install <package> <apk> [more.apk ...]
      adb uninstall (irreversible) then adb install-multiple.

Assumes arm64-v8a. For armeabi-v7a the same flow holds with ARM32 in
lib/armeabi-v7a and a 4-byte-aligned ARM encoding.
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DUMPER = ROOT / "tools" / "il2cppdumper" / "Il2CppDumper.exe"
KEYSTORE = ROOT / "release.keystore"
KS_PASS, KS_ALIAS = "android", "k"
BT = Path(os.environ.get("ANDROID_BUILD_TOOLS",
          r"C:\Users\VIJAY\AppData\Local\Android\Sdk\build-tools\36.0.0"))

SIG_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC", ".MF")


def java() -> str:
    jh = os.environ.get("JAVA_HOME")
    for c in ([Path(jh) / "bin" / "java.exe"] if jh else []) + \
              [Path(r"C:\Program Files\Android\Android Studio\jbr\bin\java.exe")]:
        if c.exists():
            return str(c)
    return shutil.which("java") or "java"


def run(cmd, check=True, cwd=None):
    p = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, cwd=cwd)
    if check and p.returncode != 0:
        print(f"[x] {' '.join(map(str, cmd))}\n{p.stdout}\n{p.stderr}")
        raise SystemExit(1)
    return p


# ---------------------------------------------------------------- dump
def find_members(apks):
    so, meta = None, None
    for apk in apks:
        with zipfile.ZipFile(apk) as z:
            for n in z.namelist():
                low = n.lower()
                if low.endswith("libil2cpp.so") and so is None:
                    so = (apk, n)
                elif low.endswith("global-metadata.dat") and meta is None:
                    meta = (apk, n)
    return so, meta


def cmd_dump(argv):
    apks = [Path(a) for a in argv if not a.startswith("--")]
    out = ROOT / "work" / "modder"
    if "--out" in argv:
        out = Path(argv[argv.index("--out") + 1])
    out.mkdir(parents=True, exist_ok=True)

    so, meta = find_members(apks)
    if not so or not meta:
        print(f"  il2cpp lib      : {'found' if so else 'MISSING'}")
        print(f"  global-metadata : {'found' if meta else 'MISSING'}")
        print("  -> not an IL2CPP Unity build (Mono, Unreal, native or Java game)")
        return 1

    for kind, (apk, entry) in (("libil2cpp.so", so), ("global-metadata.dat", meta)):
        with zipfile.ZipFile(apk) as z:
            (out / kind).write_bytes(z.read(entry))
        print(f"  {kind:18s} <- {Path(apk).name}!{entry}")

    print("  running Il2CppDumper")
    p = run([DUMPER, out / "libil2cpp.so", out / "global-metadata.dat"], check=False, cwd=out)
    for line in (p.stdout + p.stderr).splitlines():
        if any(k in line for k in ("Metadata Version", "Il2Cpp Version",
                                   "CodeRegistration", "Done", "ERROR", "WARNING")):
            print("   ", line.strip())
    produced = out / "dump.cs"
    if produced.exists():
        print(f"  symbols -> {produced}  ({produced.stat().st_size/1e6:.2f} MB)")
    else:
        print(f"  [x] no dump.cs produced in {out}")
        return 1
    return 0


# ---------------------------------------------------------------- find
FIELD_RE = re.compile(r"^\s+public\s+(?:readonly\s+)?([\w\.<>\[\],@ ]+?)\s+(\w+);\s*//\s*(0x[0-9A-Fa-f]+)")
METHOD_RE = re.compile(r"^\s*(?:public|private|protected|internal).*?\s(\w+)\s*\([^)]*\)\s*\{\s*\}$")


def cmd_find(argv):
    dump = Path(argv[0])
    keys = [k.lower() for k in argv[1:]]
    if not keys:
        print(__doc__)
        return 1
    text = dump.read_text(encoding="utf-8", errors="replace").splitlines()

    hits = 0
    pending_offset = None
    for i, line in enumerate(text):
        if line.startswith("// RVA:"):
            m = re.search(r"Offset:\s*(0x[0-9A-Fa-f]+)", line)
            pending_offset = m.group(1) if m else None
            continue
        low = line.lower()
        if not any(k in low for k in keys):
            if line.strip() and not line.strip().startswith("//"):
                if pending_offset and not line.startswith("\tpublic const"):
                    pending_offset = None if not line.strip().startswith(("public", "private", "protected", "internal")) else pending_offset
            continue

        f = FIELD_RE.match(line)
        if f:
            hits += 1
            print(f"  field   {f.group(1):22s} {f.group(2):28s} +{f.group(3)}")
            continue
        m = METHOD_RE.match(line)
        if m and pending_offset:
            hits += 1
            print(f"  method  {pending_offset:>12s}   {line.strip()}")
            continue
        if line.strip().startswith(("public ", "private ", "protected ", "internal ")):
            hits += 1
            print(f"  decl    {(pending_offset or '-'):>12s}   {line.strip()[:110]}")
    print(f"  {hits} hit(s) for {keys}")
    return 0


# ---------------------------------------------------------------- code
def cmd_code(argv):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    path, off = Path(argv[0]), int(argv[1], 16)
    count = int(argv[2]) if len(argv) > 2 else 24
    with open(path, "rb") as f:
        f.seek(off)
        blob = f.read(count * 4)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    n = 0
    for ins in md.disasm(blob, off):
        print(f"  0x{ins.address:08X}  {ins.bytes.hex():8s}  {ins.mnemonic:8s} {ins.op_str}")
        n += 1
        if ins.mnemonic == "ret" and n > 3:
            break
    return 0


# ---------------------------------------------------------------- patch
def cmd_patch(argv):
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    path, off, asm = Path(argv[0]), int(argv[1], 16), argv[2]
    expect = None
    out = path
    if "--expect" in argv:
        expect = int(argv[argv.index("--expect") + 1], 16)
    if "--out" in argv:
        out = Path(argv[argv.index("--out") + 1])

    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    enc, _ = ks.asm(asm)
    enc = bytes(enc)
    if len(enc) != 4:
        print(f"[x] expected one 4-byte instruction, got {len(enc)} bytes")
        return 1

    data = bytearray(path.read_bytes())
    cur = struct.unpack_from("<I", data, off)[0]
    if expect is not None and cur != expect:
        print(f"[x] 0x{off:08X} holds 0x{cur:08X}, expected 0x{expect:08X} - aborting")
        return 1
    struct.pack_into("<I", data, off, struct.unpack("<I", enc)[0])
    out.write_bytes(data)
    print(f"  0x{off:08X}  0x{cur:08X} -> {enc.hex()}  {asm}")
    print(f"  written: {out}")
    return 0


def cmd_mult(argv):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    path, off, shift = Path(argv[0]), int(argv[1], 16), int(argv[2])
    out = Path(argv[argv.index("--out") + 1]) if "--out" in argv else path

    data = bytearray(path.read_bytes())
    word = data[off:off + 4]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    ins = next(md.disasm(bytes(word), off), None)
    if ins is None:
        print("[x] not an instruction")
        return 1
    m = re.match(r"^(w\d+), \1, (w\d+|#0x[0-9a-f]+|#\d+)$", ins.op_str)
    if ins.mnemonic != "add" or not m:
        print(f"[x] {off:#x} is '{ins.mnemonic} {ins.op_str}' -- need 'add wX, wX, wY'")
        return 1

    asm = f"add {m.group(1)}, {m.group(1)}, {m.group(2)}, lsl #{shift}"
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    enc, _ = ks.asm(asm)
    enc = bytes(enc)
    if len(enc) != 4:
        print("[x] does not fit in one instruction")
        return 1
    struct.pack_into("<I", data, off, struct.unpack("<I", enc)[0])
    out.write_bytes(data)
    print(f"  0x{off:08X}  {ins.mnemonic} {ins.op_str}")
    print(f"            -> {asm}   ({enc.hex()})")
    print(f"  multiplier now {1 + (1 << shift)}x per unit")
    return 0


# ---------------------------------------------------------------- repack / sign
def cmd_repack(argv):
    src, dst = Path(argv[0]), Path(argv[1])
    replaces = {}
    for i, a in enumerate(argv):
        if a == "--replace":
            entry, _, f = argv[i + 1].partition("=")
            replaces[entry] = Path(f)
    payloads = {k: v.read_bytes() for k, v in replaces.items()}

    swapped = 0
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename.startswith("META-INF/") and item.filename.upper().endswith(SIG_SUFFIXES):
                continue
            data = payloads.get(item.filename, zin.read(item.filename))
            if item.filename in payloads:
                swapped += 1
                print(f"  replaced {item.filename}  ({len(data)/1e6:.2f} MB)")
            zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
            zi.compress_type = item.compress_type
            zi.external_attr = item.external_attr
            zi.internal_attr = item.internal_attr
            zi.create_system = item.create_system
            zout.writestr(zi, data)
    print(f"  {dst.name}  ({dst.stat().st_size/1e6:.2f} MB), {swapped} file(s) swapped")
    return 0


def cmd_sign(argv):
    src, dst = Path(argv[0]), Path(argv[1])
    aligned = dst.with_suffix(".aligned.apk")
    run([BT / "zipalign.exe", "-P", "16", "-f", "4", src, aligned])
    run([BT / "apksigner.bat", "sign", "--ks", KEYSTORE,
         "--ks-pass", f"pass:{KS_PASS}", "--key-pass", f"pass:{KS_PASS}",
         "--ks-key-alias", KS_ALIAS, "--out", dst, aligned], check=False)
    v = run([BT / "apksigner.bat", "verify", "--print-certs", dst], check=False)
    for line in (v.stdout + v.stderr).splitlines():
        if "SHA-256" in line:
            print("  " + line.strip())
    aligned.unlink(missing_ok=True)
    print(f"  signed: {dst}  ({dst.stat().st_size/1e6:.2f} MB)")
    return 0


def cmd_install(argv):
    pkg, apks = argv[0], [Path(a) for a in argv[1:]]
    print(f"  uninstalling {pkg} (its app data goes with it)")
    run(["adb", "uninstall", pkg], check=False)
    r = run(["adb", "install-multiple", *apks], check=False)
    tail = [l for l in (r.stdout + r.stderr).splitlines() if l.strip()][-3:]
    for l in tail:
        print("  " + l.strip())
    return 0


COMMANDS = {"dump": cmd_dump, "find": cmd_find, "code": cmd_code,
            "patch": cmd_patch, "mult": cmd_mult, "repack": cmd_repack,
            "sign": cmd_sign, "install": cmd_install}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        return 1
    return COMMANDS[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
