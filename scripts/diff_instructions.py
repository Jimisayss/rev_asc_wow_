#!/usr/bin/env python3
"""Compare call instructions between binaries and report changes."""
import argparse
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def map_instructions(pe):
    text = pe.get_section('.text')
    code = bytes(text.content)
    base = pe.imagebase + text.virtual_address
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    mapping = {}
    for insn in md.disasm(code, base):
        mapping[insn.address] = insn
    return mapping

def compare(ref_path, tgt_path, out_path):
    ref = lief.parse(ref_path)
    tgt = lief.parse(tgt_path)
    ref_map = map_instructions(ref)
    tgt_map = map_instructions(tgt)
    with open(out_path, 'w') as f:
        f.write(f"Comparing {ref_path} -> {tgt_path}\n")
        for addr, insn in ref_map.items():
            if insn.mnemonic == 'call':
                other = tgt_map.get(addr)
                if not other or other.mnemonic != 'call':
                    repl = 'missing' if not other else f"replaced by '{other.mnemonic} {other.op_str}'"
                    f.write(f"0x{addr:08X}: call {insn.op_str} -> {repl}\n")
    print(f'Diff written to {out_path}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('ref')
    ap.add_argument('target')
    ap.add_argument('output')
    args = ap.parse_args()
    compare(args.ref, args.target, args.output)

if __name__ == '__main__':
    main()
