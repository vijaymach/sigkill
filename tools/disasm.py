#!/usr/bin/env python3
"""disasm.py - disassemble an ARM64 region of a .so by file offset.

usage: python disasm.py <so> <hex_offset> [count]
"""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    path = sys.argv[1]
    off = int(sys.argv[2], 16)
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 48

    with open(path, "rb") as f:
        f.seek(off)
        blob = f.read(count * 4)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    n = 0
    for ins in md.disasm(blob, off):
        print(f"  0x{ins.address:08X}  {ins.bytes.hex():8s}  {ins.mnemonic:8s} {ins.op_str}")
        n += 1
        if ins.mnemonic in ("ret",) and n > 8:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
