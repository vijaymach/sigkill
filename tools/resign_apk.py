#!/usr/bin/env python3
"""resign_apk.py - strip an APK's existing signature block so it can be
re-signed with a different key. Content is preserved byte for byte;
only META-INF signature files are dropped.

Needed when an app bundle's splits have to travel with a re-signed base:
adb install-multiple rejects splits whose signer differs from the base.

usage: python resign_apk.py <in.apk> <out.apk>
"""
import sys
import zipfile
from pathlib import Path

SIG_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC", ".MF")


def is_sig(name: str) -> bool:
    return name.startswith("META-INF/") and name.upper().endswith(SIG_SUFFIXES)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    if not src.exists():
        print(f"[x] no such apk: {src}")
        return 1

    dropped = 0
    with zipfile.ZipFile(src, "r") as zin, \
         zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if is_sig(item.filename):
                dropped += 1
                continue
            zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
            zi.compress_type = item.compress_type
            zi.external_attr = item.external_attr
            zi.internal_attr = item.internal_attr
            zi.create_system = item.create_system
            zout.writestr(zi, zin.read(item.filename))

    print(f"  {src.name} -> {dst.name}  ({dst.stat().st_size/1e6:.2f} MB), "
          f"{dropped} signature file(s) dropped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
