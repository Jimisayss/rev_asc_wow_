#!/usr/bin/env python3
"""Extract FrameScript and Lua related information from binaries."""
import argparse
import json
import lief

def scan_strings(pe, needles):
    data = pe.get_section('.rdata')
    blob = bytes(data.content)
    results = {}
    for needle in needles:
        idx = blob.find(needle.encode('ascii'))
        if idx != -1:
            va = pe.imagebase + data.virtual_address + idx
            results[needle] = hex(va)
    return results

def get_framescript_addr(pe):
    try:
        return hex(pe.get_function_address('FrameScript_ExecuteBuffer'))
    except Exception:
        return None

def analyze(path):
    pe = lief.parse(path)
    info = {
        'FrameScript_ExecuteBuffer': get_framescript_addr(pe),
        'strings': scan_strings(pe, ['FrameScript', 'Lua', 'Lua is disabled'])
    }
    return info

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('wow')
    ap.add_argument('wow_fixed')
    ap.add_argument('asc')
    ap.add_argument('output')
    args = ap.parse_args()
    result = {
        'Wow.exe': analyze(args.wow),
        'Wow_fixed.exe': analyze(args.wow_fixed),
        'Ascension.exe': analyze(args.asc)
    }
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"Wrote {args.output}")

if __name__ == '__main__':
    main()
