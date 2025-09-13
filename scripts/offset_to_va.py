import lief
import sys

if len(sys.argv) < 3:
    print("Usage: python scripts/offset_to_va.py <binary_path> <offset>")
    sys.exit(1)

binary_path = sys.argv[1]
offset = int(sys.argv[2])

pe = lief.parse(binary_path)
if not pe:
    print(f"Error: Could not parse {binary_path}")
    sys.exit(1)

va = pe.offset_to_virtual_address(offset)
print(f"File offset {offset} (0x{offset:x}) corresponds to VA 0x{va:x}")
