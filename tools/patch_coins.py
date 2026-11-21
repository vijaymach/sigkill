#!/usr/bin/env python3
"""patch_coins.py - Temple Run 1 (com.imangi.templerun) coin multiplier patch.

Two real coin adders exist in libil2cpp.so:

  GameController.AddCoins(int playerId, int coins)   @ file 0x12AF800
      +0x18  add w8, w8, w19      -> ldr/str pair on [x0,#0x38] / [x0,#0x30]
      +0x1C  add w9, w9, w19

  CharacterPlayer.AddCoins(int count)                @ file 0x12BEF20
      +0x14  add w8, w8, w1       -> fields [x0,#0x148] / [x0,#0x14C]
      +0x18  add w9, w9, w1

GameGUI.SetCoins(int) is HUD text only. SetCoinCount(int,int) writes the
absolute total at [obj+0x38] and is left untouched -- it is the load path.

Patch: turn both adds into shifted adds (LSL #8), i.e. count*256 added per
pickup. Sign of count preserved, so any subtract path still behaves.

usage: python patch_coins.py <libil2cpp.so> [-o out.so]
"""
import shutil
import struct
import sys
from pathlib import Path

# (file offset, expected original u32 (LE as stored), patched u32, note)
PATCHES = [
    (0x12B4908, 0x2A0203F3, 0x529FFFF3, "SetCoinCount  w19 = 65535 (balance floor, free shopping)"),
    (0x12AF818, 0x0B130108, 0x0B132108, "GameController.AddCoins  w8 += coins*256  [obj+0x38]"),
    (0x12AF81C, 0x0B130129, 0x0B132129, "GameController.AddCoins  w9 += coins*256  [obj+0x30]"),
    (0x12BEF34, 0x0B010108, 0x0B012108, "CharacterPlayer.AddCoins w8 += count*256  [this+0x148]"),
    (0x12BEF38, 0x0B010129, 0x0B012129, "CharacterPlayer.AddCoins w9 += count*256  [this+0x14C]"),
]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    src = Path(sys.argv[1])
    dst = Path(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[2] == "-o" else src.with_suffix(".patched.so")
    if not src.exists():
        print(f"[x] no such file: {src}")
        return 1

    data = bytearray(src.read_bytes())
    print(f"  input : {src}  ({len(data)/1e6:.2f} MB)")

    bad = 0
    for off, orig, new, note in PATCHES:
        cur = struct.unpack_from("<I", data, off)[0]
        if cur != orig:
            print(f"  [x] 0x{off:08X} expected 0x{orig:08X} got 0x{cur:08X} -- {note}")
            bad += 1
            continue
        struct.pack_into("<I", data, off, new)
        print(f"  [+] 0x{off:08X}  0x{orig:08X} -> 0x{new:08X}  {note}")

    if bad:
        print(f"[x] {bad} patch site(s) did not match. aborting, nothing written.")
        return 1

    dst.write_bytes(data)
    shutil.copy2(src, dst.with_suffix(".orig.so")) if not dst.with_suffix(".orig.so").exists() else None
    print(f"  output: {dst}  ({len(data)/1e6:.2f} MB)")
    print("  all 4 sites patched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
