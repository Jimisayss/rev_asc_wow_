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
        raise OSError('OpenProcess failed')
    dll_bytes = dll_path.encode('ascii') + b'\x00'
    alloc = VirtualAllocEx(h_process, None, len(dll_bytes), 0x1000 | 0x2000, 0x40)
    WriteProcessMemory(h_process, alloc, dll_bytes, len(dll_bytes), None)
    h_kernel32 = kernel32.GetModuleHandleW('kernel32.dll')
    load_library = kernel32.GetProcAddress(h_kernel32, b'LoadLibraryA')
    thread = CreateRemoteThread(h_process, None, 0, load_library, alloc, 0, None)
    if not thread:
        raise OSError('CreateRemoteThread failed')
    return thread


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <lua_executor.dll>")
        return
    dll_path = os.path.abspath(sys.argv[1])
    pid = find_process('Ascension.exe')
    if not pid:
        print('Ascension.exe not found')
        return
    print(f'Injecting into PID {pid}')
    inject(pid, dll_path)
    print('DLL injected. You can now call RunLua via another tool.')

if __name__ == '__main__':
    main()
