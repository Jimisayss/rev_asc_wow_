#!/usr/bin/env python3
"""Binary comparison and anti-debug/integrity scan for Ascension/WoW executables."""
import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List, Iterable

import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# Known anti-debugging related APIs
ANTI_DEBUG_APIS = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "ZwQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "GetTickCount",
    "QueryPerformanceCounter",
}

# Known integrity check related APIs
INTEGRITY_APIS = {
    "CheckSumMappedFile",
    "MapFileAndCheckSumA",
    "MapFileAndCheckSumW",
    "RtlComputeCrc32",
}


def map_calls(pe: lief.PE.Binary) -> Dict[int, str]:
    """Return mapping of address -> call instruction text for given PE."""
    text = pe.get_section(".text")
    code = bytes(text.content)
    base = pe.imagebase + text.virtual_address
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    mapping: Dict[int, str] = {}
    for insn in md.disasm(code, base):
        if insn.mnemonic == "call":
            mapping[insn.address] = f"{insn.mnemonic} {insn.op_str}"
    return mapping


def detect_imports(pe: lief.PE.Binary, names: Iterable[str]) -> List[str]:
    """Return list of imported API names present in *names*."""
    found = []
    wanted = set(names)
    for lib in pe.imports:
        for func in lib.entries:
            if func.name in wanted:
                found.append(func.name)
    return found


def detect_strings(path: Path, keywords: Iterable[str]) -> List[str]:
    """Extract ASCII strings and filter by *keywords*."""
    with path.open("rb") as f:
        data = f.read()
    strings: List[str] = []
    current: List[str] = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                s = "".join(current)
                strings.append(s)
            current = []
    if len(current) >= 4:
        strings.append("".join(current))
    kws = [k.lower() for k in keywords]
    return [s for s in strings if any(k in s.lower() for k in kws)]


def compare_binaries(asc_path: Path, base_path: Path, patched_path: Path, out_path: Path) -> None:
    """Generate structured diff and anti-debug/integrity report."""
    logging.info("Parsing binaries")
    asc = lief.parse(str(asc_path))
    base = lief.parse(str(base_path))
    patched = lief.parse(str(patched_path))

    logging.info("Mapping call instructions")
    asc_calls = map_calls(asc)
    base_calls = map_calls(base)
    patched_calls = map_calls(patched)

    all_addrs = sorted(set(asc_calls) | set(base_calls) | set(patched_calls))
    diffs = []
    for addr in all_addrs:
        a = asc_calls.get(addr)
        b = base_calls.get(addr)
        c = patched_calls.get(addr)
        values = {v for v in (a, b, c) if v}
        if len(values) > 1:
            diffs.append({
                "address": f"0x{addr:08X}",
                "ascension": a,
                "wow": b,
                "wow_patched": c,
            })

    logging.info("Scanning for anti-debug imports")
    anti = {
        "ascension": detect_imports(asc, ANTI_DEBUG_APIS),
        "wow": detect_imports(base, ANTI_DEBUG_APIS),
        "wow_patched": detect_imports(patched, ANTI_DEBUG_APIS),
    }

    logging.info("Scanning for integrity imports and strings")
    integ = {
        "ascension": detect_imports(asc, INTEGRITY_APIS) + detect_strings(asc_path, ["crc", "checksum"]),
        "wow": detect_imports(base, INTEGRITY_APIS) + detect_strings(base_path, ["crc", "checksum"]),
        "wow_patched": detect_imports(patched, INTEGRITY_APIS) + detect_strings(patched_path, ["crc", "checksum"]),
    }

    report = {
        "diffs": diffs,
        "anti_debug": anti,
        "integrity": integ,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    logging.info("Report written to %s", out_path)


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare binaries and scan for anti-debugging techniques")
    ap.add_argument("ascension")
    ap.add_argument("wow")
    ap.add_argument("wow_patched")
    ap.add_argument("output", help="Path for generated JSON report")
    args = ap.parse_args()

    compare_binaries(Path(args.ascension), Path(args.wow), Path(args.wow_patched), Path(args.output))


if __name__ == "__main__":
    main()
