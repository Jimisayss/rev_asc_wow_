import lief
import sys

if len(sys.argv) < 2:
    print("Usage: python scripts/get_imagebase.py <binary_path>")
    sys.exit(1)

binary_path = sys.argv[1]
pe = lief.parse(binary_path)

if not pe:
    print(f"Error: Could not parse {binary_path}")
    sys.exit(1)

print(f"Info for {binary_path}:")
print(f"  Imagebase: {hex(pe.imagebase)}")

text_section = pe.get_section('.text')
if text_section:
    print(f"  .text section RVA: {hex(text_section.virtual_address)}")
    print(f"  .text section Base Address: {hex(pe.imagebase + text_section.virtual_address)}")
else:
    print("  .text section not found.")
