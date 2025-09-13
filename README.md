
# Ascension Lua Unlocker via Binary Diffing

## Overview

This project reverse engineers `Ascension.exe` by comparing it against the original `WoW.exe` (patch 3.3.5.12340) to identify and unlock disabled Lua functionality such as `FrameScript_ExecuteBuffer`. This is achieved using static binary analysis, disassembly, and patch generation via Python tooling.

## ⚙️ Requirements

- Python 3.8+
- `lief` for binary parsing and patching
- `capstone` for disassembly
- `keystone-engine` (optional) for assembling patches
- `hexdump` (optional, for debugging)

Install dependencies:
```bash
pip install lief capstone keystone-engine hexdump
````

## 📁 Folder Structure

```
ascension_lua_unlock/
├── binaries/
│   ├── Ascension.exe          # Target binary (from Ascension Launcher)
│   ├── Wow.exe                # Clean vanilla client (from Mega)
│   └── Wow_fixed.exe          # Slightly patched 3.3.5a client from robinsch
├── scripts/
│   ├── disassemble.py         # Disassembles and outputs instruction listings
│   ├── diff_instructions.py   # Compares two binaries and highlights diffs
│   ├── find_lua_lock.py       # Searches for signs of disabled Lua calls
│   └── patch_unlock.py        # Patches Ascension.exe to re-enable Lua
├── patches/
│   └── generated_patch.txt    # Raw byte patch output
└── README.md
```

---

## 🧪 Step-by-Step Usage

### 1. Place Required Binaries

Copy the following files into the `binaries/` folder:

* `Ascension.exe` (latest game client)
* `Wow.exe` (clean unmodified 3.3.5.12340 client)
* `Wow_fixed.exe` (optional but useful for confirming legitimate fixes)

### 2. Disassemble

Run disassembly on each binary to extract instruction sequences:

```bash
python scripts/disassemble.py binaries/Wow.exe > out/wow_disasm.txt
python scripts/disassemble.py binaries/Ascension.exe > out/asc_disasm.txt
```

### 3. Diff and Analyze

Compare disassemblies and isolate differences:

```bash
python scripts/diff_instructions.py binaries/Wow.exe binaries/Ascension.exe
```

Optional: Use string signature-based scanning to detect patched or blocked Lua functions:

```bash
python scripts/find_lua_lock.py binaries/Ascension.exe
```

### 4. Generate Unlock Patch

Once the patched regions are identified, run:

```bash
python scripts/patch_unlock.py binaries/Ascension.exe --output patched/Ascension_unlocked.exe
```

This will:

* Inject NOPs or restore missing `call FrameScript_ExecuteBuffer`
* Save the patched executable as `Ascension_unlocked.exe`

---

## 🔐 Tips for Analysis

* Use `Wow.exe` to determine original offsets of:

  * `FrameScript_ExecuteBuffer`
  * `SendChatMessage`
  * `lua_call`, `luaL_loadbuffer`, etc.
* Check if `Ascension.exe` jumps over these or returns early
* Use `.rdata` or `.data` sections to locate string references like `"Lua execution is disabled"`

---

## ✅ Notes on the Client

* The `Wow.exe` and `Wow_fixed.exe` are sourced from the `WoWArchive-0.X-3.X` torrent bundle.
* `Wow_fixed.exe` includes safe bug fixes by [robinsch/WoWFix335](https://github.com/robinsch/WoWFix335).
* This project avoids dynamic analysis and Cheat Engine to maintain stealth.

---

## 🚨 Legal Disclaimer

This tool is provided for **educational purposes only**. Modifying game clients may violate Terms of Service. Use at your own risk.

---

## 📜 Credits

* [robinsch/WoWFix335](https://github.com/robinsch/WoWFix335) – for community patches
* [LIEF](https://lief.quarkslab.com/) – parsing and patching
* [Capstone Engine](https://www.capstone-engine.org/) – disassembly
* [Keystone](https://www.keystone-engine.org/) – reassembly

---

