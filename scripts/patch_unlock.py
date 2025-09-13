#!/usr/bin/env python3
"""Patch Ascension.exe to restore FrameScript_ExecuteBuffer call."""
import argparse
import lief
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

def patch(input_path, output_path, call_rva, target_addr):
    pe = lief.parse(input_path)
    text = pe.get_section('.text')
    base = pe.imagebase + text.virtual_address
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    rel = target_addr - (base + call_rva + 5)
    encoding, _ = ks.asm(f'call {rel}')
    content = list(text.content)
    for i, b in enumerate(encoding):
        content[call_rva + i] = b
    text.content = content
    pe.write(output_path)
    print(f'Patched binary written to {output_path}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('output')
    ap.add_argument('rva', help='RVA of patched call', type=lambda x: int(x,16))
    ap.add_argument('target', help='Absolute address of FrameScript_ExecuteBuffer', type=lambda x: int(x,16))
    args = ap.parse_args()
    patch(args.input, args.output, args.rva, args.target)

if __name__ == '__main__':
    main()
