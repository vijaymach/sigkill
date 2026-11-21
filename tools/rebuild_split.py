#!/usr/bin/env python3
"""rebuild_split.py - swap a .so inside an APK, strip old signature, keep compression.

usage: python rebuild_split.py <in.apk> <new.so> <so_entry_path> <out.apk>

example:
  python rebuild_split.py split_01.apk libil2cpp_patched.so \
      lib/arm64-v8a/libil2cpp.so split_01_rebuilt.apk
"""
import sys
import zipfile
from pathlib import Path

SIG_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC", ".MF")


def is_sig(name: str) -> bool:
    return name.startswith("META-INF/") and name.upper().endswith(SIG_SUFFIXES)


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        return 1
    src, newso, entry, dst = (Path(sys.argv[1]), Path(sys.argv[2]),
                              sys.argv[3], Path(sys.argv[4]))
    if not src.exists() or not newso.exists():
        print("[x] missing input")
        return 1

    payload = newso.read_bytes()
    replaced = 0
    with zipfile.ZipFile(src, "r") as zin, \
         zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if is_sig(item.filename):
                continue
            data = zin.read(item.filename)
            if item.filename == entry:
                data = payload
                replaced += 1
                print(f"  [+] {item.filename}: {len(data)/1e6:.2f} MB (patched)")
            zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
            zi.compress_type = item.compress_type
            zi.external_attr = item.external_attr
            zi.internal_attr = item.internal_attr
            zi.create_system = item.create_system
            zout.writestr(zi, data)

    print(f"  output: {dst}  ({dst.stat().st_size/1e6:.2f} MB)")
    if replaced == 0:
        print(f"  [!] entry not found: {entry}")
        return 1
    print(f"  signature blocks stripped, {replaced} .so replaced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
