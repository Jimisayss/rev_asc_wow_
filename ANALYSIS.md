# Analysis of Ascension.exe Protections

This document details the reconnaissance phase of the Lua unlocker project, focusing on identifying the lock mechanism and any anti-debugging or anti-tampering defenses in `Ascension.exe`.

## 1. Lua Lock Mechanism

The primary lock on Lua execution was identified by comparing `Wow.exe` with `Ascension.exe`.

### `Wow.exe` (Original)

A `grep` on the disassembly of `Wow.exe` at the suspected address reveals a standard function call:

```
$ grep -C 3 "0x0040B7D3" out/wow_disasm_fresh.txt
0x0040B7D0: push ebp
0x0040B7D1: mov ebp, esp
0x0040B7D3: call 0x406d70
0x0040B7D8: mov edx, dword ptr [0xb311e8]
```

This shows a standard function prologue followed by a `call` to `0x406d70`, which is the address of the `FrameScript_ExecuteBuffer` function.

### `Ascension.exe` (Patched)

The same analysis on `Ascension.exe` reveals that this entire function has been replaced with a single `jmp` instruction:

```
$ grep -C 3 "mov edx, dword ptr \[0xb311e8\]" out/ascension_disasm_fresh.txt
0x0040B7D0: jmp 0x4e5cb0
0x0040B7D5: nop
0x0040B7D6: nop
0x0040B7D7: nop
0x0040B7D8: mov edx, dword ptr [0xb311e8]
```

**Conclusion:** The developers have completely removed the function that calls `FrameScript_ExecuteBuffer` and replaced it with a `jmp` to a different location. The `nop` instructions are used as padding to fill the space of the original, larger function code. The unlock method must therefore call `0x00406D70` directly, bypassing this `jmp`.

## 2. Anti-Debugging & Integrity Checks

Several methods were used to scan for common protections.

### API-Based Checks

Searches for common WinAPI anti-debugging functions yielded no results in the static disassembly.

```bash
grep -i "IsDebuggerPresent" out/ascension_disasm_fresh.txt
grep -i "CheckRemoteDebuggerPresent" out/ascension_disasm_fresh.txt
grep -i "GetTickCount" out/ascension_disasm_fresh.txt
```
*(All the above commands returned no output.)*

This suggests that if these checks are used, they are loaded dynamically at runtime (e.g., via `GetProcAddress`) to evade static detection.

### Timing Checks (RDTSC)

A search for the `rdtsc` instruction, a common method for detecting debugger-induced slowdowns, also yielded no results.

```bash
grep -i "rdtsc" out/ascension_disasm_fresh.txt
```
*(This command returned no output.)*


### `int3` Breakpoint Traps

A search for the `int3` (software breakpoint) instruction revealed a very high count, which is a strong indicator of anti-debugging traps that rely on Structured Exception Handling (SEH).

```bash
$ grep -c "int3" out/ascension_disasm_fresh.txt
1796
```

**Conclusion:** The primary anti-debugging defense identified is a large number of `int3` traps. The shellcode injection method developed avoids these traps because it does not use a debugger.

### Integrity / CRC Checks

No obvious signs of memory integrity checks (e.g., CRC32 constants, suspicious code reading its own sections) were found during this static analysis. The absence of these checks makes both dynamic shellcode injection and static patching more viable.
