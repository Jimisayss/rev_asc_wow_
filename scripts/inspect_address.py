#!/usr/bin/env python3
"""Disassembles a small region of code around a given virtual address."""
import argparse
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def inspect_address(binary_path, address, context_bytes=50):
    """
    Disassembles and prints code around a specific virtual address in a PE file.

    Args:
        binary_path (str): The path to the PE file.
        address (int): The virtual address to inspect.
        context_bytes (int): The number of bytes before and after the address to include.
    """
    try:
        binary = lief.parse(binary_path)
        if not binary:
            print(f"Error: Could not parse {binary_path}")
            return

        # Calculate the start address for disassembly
        start_address = address - context_bytes
        if start_address < binary.imagebase:
            start_address = binary.imagebase

        # Get the code from the calculated start address
        code_bytes = binary.get_content_from_virtual_address(start_address, context_bytes * 2)

        if not code_bytes:
            print(f"Error: Could not read memory at address {hex(start_address)}")
            return

        print(f"--- Disassembly for {binary_path} around {hex(address)} ---")

        # Initialize Capstone
        md = Cs(CS_ARCH_X86, CS_MODE_32)

        # Disassemble and print
        for i in md.disasm(bytes(code_bytes), start_address):
            highlight = "<-- HERE" if i.address == address else ""
            print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str} {highlight}")

    except lief.bad_file as e:
        print(f"Error processing file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Disassemble code at a specific virtual address.")
    parser.add_argument("binary_path", help="Path to the PE binary file.")
    parser.add_argument("address", help="The virtual address to inspect (e.g., 0x40B7D3).")
    args = parser.parse_args()

    try:
        address_int = int(args.address, 16)
    except ValueError:
        print("Error: Invalid address format. Please use hexadecimal (e.g., 0x40B7D3).")
        return

    inspect_address(args.binary_path, address_int)

if __name__ == "__main__":
    main()
