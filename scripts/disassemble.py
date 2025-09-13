#!/usr/bin/env python3
"""Disassemble a PE binary's .text section using LIEF and Capstone.

Usage:
    python disassemble.py <binary> <output> [--limit N]
Outputs disassembly lines of the form:
    0xADDRESS: MNEMONIC OPERANDS
"""
import argparse
import sys
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def disassemble(path, out_path, limit=None):
    pe = lief.parse(path)
    text = pe.get_section('.text')
    code = bytes(text.content)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False
    base = pe.imagebase + text.virtual_address

    count = 0
    with open(out_path, 'w') as f:
        for insn in md.disasm(code, base):
            f.write(f"0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}\n")
            count += 1
            if limit and count >= limit:
                break

    return count

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary')
    ap.add_argument('output')
    ap.add_argument('--limit', type=int, default=None, help='limit number of instructions')
    args = ap.parse_args()
    n = disassemble(args.binary, args.output, args.limit)
    print(f"Disassembled {n} instructions from {args.binary} -> {args.output}")

if __name__ == '__main__':
    main()
