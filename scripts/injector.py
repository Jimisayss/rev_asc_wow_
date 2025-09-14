#!/usr/bin/env python3
"""Injects and executes shellcode in a running Ascension.exe process to run Lua code via APC injection."""
import ctypes
import sys
import os
from ctypes import wintypes
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

# --- Ctypes definitions ---
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
THREAD_SET_CONTEXT = 0x0010

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD), ('th32ProcessID', wintypes.DWORD),
                ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)), ('th32ModuleID', wintypes.DWORD),
                ('cntThreads', wintypes.DWORD), ('th32ParentProcessID', wintypes.DWORD),
                ('pcPriClassBase', ctypes.c_long), ('dwFlags', wintypes.DWORD),
                ('szExeFile', wintypes.CHAR * wintypes.MAX_PATH)]

class THREADENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD), ('th32ThreadID', wintypes.DWORD),
                ('th32OwnerProcessID', wintypes.DWORD), ('tpBasePri', wintypes.LONG),
                ('tpDeltaPri', wintypes.LONG), ('dwFlags', wintypes.DWORD)]

# --- WinAPI Function Prototypes ---
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

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

Thread32First = kernel32.Thread32First
Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
Thread32First.restype = wintypes.BOOL

Thread32Next = kernel32.Thread32Next
Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
Thread32Next.restype = wintypes.BOOL

OpenThread = kernel32.OpenThread
OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenThread.restype = wintypes.HANDLE

QueueUserAPC = kernel32.QueueUserAPC
QueueUserAPC.argtypes = [wintypes.LPVOID, wintypes.HANDLE, wintypes.ULONG_PTR]
QueueUserAPC.restype = wintypes.DWORD

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

def apc_inject_and_run_lua(pid: int, lua_code: str):
    """Injects shellcode via APC to execute a Lua string in the target process."""
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise ctypes.WinError(ctypes.get_last_error())

    lua_code_bytes = lua_code.encode('ascii') + b'\x00'
    source_name_bytes = b'JulesAPC\x00'

    total_size = 100 + len(lua_code_bytes) + len(source_name_bytes)
    mem_addr = VirtualAllocEx(h_process, None, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not mem_addr:
        raise ctypes.WinError(ctypes.get_last_error())

    print(f"Allocated memory at 0x{mem_addr:08X}")

    addr_lua_code = mem_addr + 100
    addr_source_name = addr_lua_code + len(lua_code_bytes)

    bytes_written = ctypes.c_size_t(0)
    WriteProcessMemory(h_process, addr_lua_code, lua_code_bytes, len(lua_code_bytes), ctypes.byref(bytes_written))
    WriteProcessMemory(h_process, addr_source_name, source_name_bytes, len(source_name_bytes), ctypes.byref(bytes_written))

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    FRAMESCRIPT_EXECUTE_BUFFER = 0x00406D70

    assembly = f"""
        pushad
        push 0
        push {addr_source_name}
        push {addr_lua_code}
        call {FRAMESCRIPT_EXECUTE_BUFFER}
        add esp, 12
        popad
        ret
    """

    shellcode, _ = ks.asm(assembly)
    shellcode_bytes = bytes(shellcode)

    WriteProcessMemory(h_process, mem_addr, shellcode_bytes, len(shellcode_bytes), ctypes.byref(bytes_written))
    print(f"Wrote {len(shellcode_bytes)} bytes of shellcode.")

    h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(THREADENTRY32)

    if not Thread32First(h_snapshot, ctypes.byref(entry)):
        CloseHandle(h_snapshot)
        raise ctypes.WinError(ctypes.get_last_error())

    queued_count = 0
    while True:
        if entry.th32OwnerProcessID == pid:
            h_thread = OpenThread(THREAD_SET_CONTEXT | 0x0040, False, entry.th32ThreadID) # THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION
            if h_thread:
                ret = QueueUserAPC(mem_addr, h_thread, 0)
                if ret:
                    queued_count += 1
                CloseHandle(h_thread)

        if not Thread32Next(h_snapshot, ctypes.byref(entry)):
            break

    CloseHandle(h_snapshot)

    if queued_count == 0:
        VirtualFreeEx(h_process, mem_addr, 0, 0x8000) # MEM_RELEASE
        CloseHandle(h_process)
        raise RuntimeError("Failed to queue APC to any thread.")

    print(f"Successfully queued APC to {queued_count} threads. Execution should happen shortly.")

    # Memory is intentionally leaked here for this educational example,
    # as we cannot know when the APC has finished executing.
    CloseHandle(h_process)

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
        apc_inject_and_run_lua(pid, lua_to_run)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()
