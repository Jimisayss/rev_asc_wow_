#!/usr/bin/env python3
"""Process injection harness with interactive shell."""
import argparse
import json
import logging
import ctypes
import struct
from ctypes import wintypes
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

# Toolhelp constants
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.CHAR * wintypes.MAX_PATH),
    ]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", wintypes.LPVOID),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.CHAR * 256),
        ("szExePath", wintypes.CHAR * wintypes.MAX_PATH),
    ]


CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
Process32First = kernel32.Process32First
Process32Next = kernel32.Process32Next
Module32First = kernel32.Module32First
Module32Next = kernel32.Module32Next
OpenProcess = kernel32.OpenProcess
VirtualAllocEx = kernel32.VirtualAllocEx
WriteProcessMemory = kernel32.WriteProcessMemory
CreateRemoteThread = kernel32.CreateRemoteThread
GetLastError = kernel32.GetLastError
VirtualFreeEx = kernel32.VirtualFreeEx
WaitForSingleObject = kernel32.WaitForSingleObject
CloseHandle = kernel32.CloseHandle

MEM_RELEASE = 0x8000
INFINITE = 0xFFFFFFFF


def find_process(name: str) -> int:
    """Return PID of process with *name* or 0 if not found."""
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    try:
        if not Process32First(snapshot, ctypes.byref(entry)):
            return 0
        while True:
            if entry.szExeFile.decode("utf-8").lower() == name.lower():
                return entry.th32ProcessID
            if not Process32Next(snapshot, ctypes.byref(entry)):
                break
        return 0
    finally:
        CloseHandle(snapshot)


def get_module_base(pid: int, module: str) -> int:
    """Return base address of *module* loaded in *pid* or 0."""
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    try:
        if not Module32First(snapshot, ctypes.byref(entry)):
            return 0
        while True:
            if entry.szModule.decode("utf-8").lower() == module.lower():
                return entry.modBaseAddr.value
            if not Module32Next(snapshot, ctypes.byref(entry)):
                break
        return 0
    finally:
        CloseHandle(snapshot)


def alloc_write(h_process, data: bytes) -> int:
    """Allocate remote memory and write *data* to it."""
    size = len(data)
    addr = VirtualAllocEx(h_process, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not addr:
        raise OSError("VirtualAllocEx failed")
    if not WriteProcessMemory(h_process, addr, data, size, None):
        raise OSError("WriteProcessMemory failed")
    return addr


def load_config() -> dict:
    """Load configuration from config.json located next to this script."""
    path = Path(__file__).with_name("config.json")
    if not path.exists():
        logging.warning("config.json not found; using command-line defaults")
        return {}
    with path.open("r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            logging.error("Failed to parse config.json: %s", exc)
            return {}


def run_shell(pid: int, base: int, rva: int) -> None:
    """Interactive loop writing user strings and invoking remote function."""
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise OSError("OpenProcess failed")
    target = base + rva
    logging.info("Using target function at 0x%08X", target)
    try:
        while True:
            try:
                line = input("> ")
            except EOFError:
                break
            if line.strip().lower() in {"quit", "exit"}:
                break
            buf = line.encode("ascii") + b"\x00"
            str_addr = alloc_write(h_process, buf)

            # Stub to call the target function with the string pointer and
            # clean up the stack for the cdecl calling convention:
            #   push <str_addr>
            #   mov eax, <target>
            #   call eax
            #   add esp, 4
            #   ret
            stub = (
                b"\x68" + struct.pack("<I", str_addr) +
                b"\xB8" + struct.pack("<I", target) +
                b"\xFF\xD0" +
                b"\x83\xC4\x04" +
                b"\xC3"
            )
            stub_addr = alloc_write(h_process, stub)

            thread = CreateRemoteThread(h_process, None, 0, stub_addr, None, 0, None)
            if not thread:
                err = GetLastError()
                logging.error("CreateRemoteThread failed: %d", err)
                VirtualFreeEx(h_process, stub_addr, 0, MEM_RELEASE)
                VirtualFreeEx(h_process, str_addr, 0, MEM_RELEASE)
                continue
            logging.info("Thread created at 0x%08X", stub_addr)
            WaitForSingleObject(thread, INFINITE)

            if VirtualFreeEx(h_process, stub_addr, 0, MEM_RELEASE):
                logging.info("Freed stub at 0x%08X", stub_addr)
            else:
                err = GetLastError()
                logging.error("VirtualFreeEx failed for stub: %d", err)

            if VirtualFreeEx(h_process, str_addr, 0, MEM_RELEASE):
                logging.info("Freed remote buffer at 0x%08X", str_addr)
            else:
                err = GetLastError()
                logging.error("VirtualFreeEx failed for buffer: %d", err)
            CloseHandle(thread)
    finally:
        kernel32.CloseHandle(h_process)


def main() -> None:
    cfg = load_config()
    ap = argparse.ArgumentParser(description="Interactive remote command runner")
    ap.add_argument("process", nargs="?", default=cfg.get("process"),
                    help="Process name to target, e.g. Ascension.exe")
    ap.add_argument("rva", nargs="?", default=cfg.get("rva"),
                    help="Target function RVA (hex)")
    args = ap.parse_args()

    pid = find_process(args.process)
    if not pid:
        raise SystemExit(f"{args.process} not found")
    base = get_module_base(pid, args.process)
    if not base:
        raise SystemExit("Failed to locate module base")
    run_shell(pid, base, int(str(args.rva), 16))


if __name__ == "__main__":
    main()
