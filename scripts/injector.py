#!/usr/bin/env python3
"""Injects and executes shellcode in a running Ascension.exe process to run Lua code."""
import ctypes
import sys
import os
import time
from ctypes import wintypes
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

# --- Existing ctypes definitions from the original script ---
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40
TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD), ('th32ProcessID', wintypes.DWORD),
                ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)), ('th32ModuleID', wintypes.DWORD),
                ('cntThreads', wintypes.DWORD), ('th32ParentProcessID', wintypes.DWORD),
                ('pcPriClassBase', ctypes.c_long), ('dwFlags', wintypes.DWORD),
                ('szExeFile', wintypes.CHAR * wintypes.MAX_PATH)]

# --- Function definitions ---
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
CreateRemoteThread.restype = wintypes.HANDLE

WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
WaitForSingleObject.restype = wintypes.DWORD

VirtualFreeEx = kernel32.VirtualFreeEx
VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Process32First = kernel32.Process32First
Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]

Process32Next = kernel32.Process32Next
Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]

def find_process_id(name: str) -> int:
    """Finds a process ID by its executable name."""
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if not Process32First(snapshot, ctypes.byref(entry)):
        CloseHandle(snapshot)
        return 0
    while True:
        if entry.szExeFile.decode('utf-8', 'ignore').lower() == name.lower():
            pid = entry.th32ProcessID
            CloseHandle(snapshot)
            return pid
        if not Process32Next(snapshot, ctypes.byref(entry)):
            break
    CloseHandle(snapshot)
    return 0

def execute_lua(pid: int, lua_code: str):
    """Injects shellcode to execute a Lua string in the target process."""
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise ctypes.WinError(ctypes.get_last_error())

    # --- Prepare data to be written into the target process ---
    lua_code_bytes = lua_code.encode('ascii') + b'\x00'
    source_name_bytes = b'JulesInjection\x00'

    # --- Allocate memory for shellcode and data ---
    # Total size = shellcode (around 50 bytes) + lua code + source name
    total_size = 100 + len(lua_code_bytes) + len(source_name_bytes)
    mem_addr = VirtualAllocEx(h_process, None, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not mem_addr:
        raise ctypes.WinError(ctypes.get_last_error())

    print(f"Allocated memory at 0x{mem_addr:08X}")

    # --- Write data strings first ---
    addr_lua_code = mem_addr + 100 # Place it after the shellcode area
    addr_source_name = addr_lua_code + len(lua_code_bytes)

    bytes_written = ctypes.c_size_t(0)
    WriteProcessMemory(h_process, addr_lua_code, lua_code_bytes, len(lua_code_bytes), ctypes.byref(bytes_written))
    WriteProcessMemory(h_process, addr_source_name, source_name_bytes, len(source_name_bytes), ctypes.byref(bytes_written))

    # --- Assemble the shellcode ---
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    FRAMESCRIPT_EXECUTE_BUFFER = 0x00406D70

    assembly = f"""
        push 0
        push {addr_source_name}
        push {addr_lua_code}
        call {FRAMESCRIPT_EXECUTE_BUFFER}
        add esp, 12
        ret
    """

    shellcode, _ = ks.asm(assembly)
    shellcode_bytes = bytes(shellcode)

    # --- Write the shellcode ---
    WriteProcessMemory(h_process, mem_addr, shellcode_bytes, len(shellcode_bytes), ctypes.byref(bytes_written))
    print(f"Wrote {len(shellcode_bytes)} bytes of shellcode.")

    # --- Execute the shellcode ---
    h_thread = CreateRemoteThread(h_process, None, 0, mem_addr, None, 0, None)
    if not h_thread:
        raise ctypes.WinError(ctypes.get_last_error())

    print("Executing remote thread...")
    WaitForSingleObject(h_thread, 0xFFFFFFFF) # Wait indefinitely

    # --- Cleanup ---
    VirtualFreeEx(h_process, mem_addr, 0, 0x8000) # MEM_RELEASE
    CloseHandle(h_thread)
    CloseHandle(h_process)
    print("Execution finished and cleaned up.")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <lua_code_or_filepath>")
        print(f"Example (string): {sys.argv[0]} \"print('Hello!')\"")
        print(f"Example (file):   {sys.argv[0]} my_script.lua")
        return

    lua_input = sys.argv[1]
    lua_to_run = ""

    if os.path.isfile(lua_input):
        print(f"Reading Lua code from file: {lua_input}")
        with open(lua_input, 'r') as f:
            lua_to_run = f.read()
    else:
        print("Treating input as a raw Lua string.")
        lua_to_run = lua_input

    print("Searching for Ascension.exe...")
    pid = find_process_id('Ascension.exe')
    if not pid:
        print('Ascension.exe not found. Is it running?')
        return

    print(f'Found Ascension.exe with PID {pid}.')

    try:
        execute_lua(pid, lua_to_run)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()
