#!/usr/bin/env python3
"""Inject lua_executor.dll into a running Ascension.exe process and run an optional interactive shell."""
import ctypes
import sys
import os
import time
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF

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

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

GetLastError = kernel32.GetLastError

# Toolhelp for process enumeration
TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wintypes.DWORD),
                ('cntUsage', wintypes.DWORD),
                ('th32ProcessID', wintypes.DWORD),
                ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                ('th32ModuleID', wintypes.DWORD),
                ('cntThreads', wintypes.DWORD),
                ('th32ParentProcessID', wintypes.DWORD),
                ('pcPriClassBase', ctypes.c_long),
                ('dwFlags', wintypes.DWORD),
                ('szExeFile', wintypes.CHAR * wintypes.MAX_PATH)]

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
Process32First = kernel32.Process32First
Process32Next = kernel32.Process32Next

CreateToolhelp32Snapshot.restype = wintypes.HANDLE
Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]


def find_process(name: str) -> int:
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if not Process32First(snapshot, ctypes.byref(entry)):
        return 0
    while True:
        if entry.szExeFile.decode('utf-8').lower() == name.lower():
            return entry.th32ProcessID
        if not Process32Next(snapshot, ctypes.byref(entry)):
            break
    return 0


def inject(pid, dll_path):
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise OSError(f'OpenProcess failed for PID {pid}')

    thread = None
    try:
        dll_bytes = dll_path.encode('utf-8') + b'\x00'
        alloc = VirtualAllocEx(h_process, None, len(dll_bytes), 0x1000 | 0x2000, 0x40)
        if not alloc:
            raise OSError('VirtualAllocEx failed')

        if not WriteProcessMemory(h_process, alloc, dll_bytes, len(dll_bytes), None):
            raise OSError('WriteProcessMemory failed')

        h_kernel32 = kernel32.GetModuleHandleW('kernel32.dll')
        load_library = kernel32.GetProcAddress(h_kernel32, b'LoadLibraryA')

        thread = CreateRemoteThread(h_process, None, 0, load_library, alloc, 0, None)
        if not thread:
            raise OSError('CreateRemoteThread failed')

        # Wait for the thread to finish. This is good practice.
        ctypes.windll.kernel32.WaitForSingleObject(thread, 0xFFFFFFFF) # Wait indefinitely

    finally:
        if thread:
            CloseHandle(thread)
        if h_process:
            CloseHandle(h_process)


def main():
    dll_name = 'dllmain.dll'
    dll_path = os.path.abspath(os.path.join('out', dll_name))

    if not os.path.exists(dll_path):
        print(f"Error: DLL not found at '{dll_path}'")
        print("Please compile the DLL first using a MinGW g++ compiler.")
        print(r"Example: i686-w64-mingw32-g++ -shared -o out\dllmain.dll dll\dllmain.cpp -static-libgcc -static-libstdc++")
        return

    pid = find_process('Ascension.exe')
    if not pid:
        print('Ascension.exe not found. Is the game running?')
        return

    print(f'Found Ascension.exe with PID {pid}.')
    print(f'Injecting "{dll_path}"...')

    try:
        inject(pid, dll_path)
        print('DLL injected successfully.')
        print('You can now use `python scripts/send_lua.py "your_lua_code()"` to execute commands.')
    except OSError as e:
        print(f"Injection failed: {e}")
        print(f"Win32 Error Code: {GetLastError()}")

if __name__ == '__main__':
    main()
