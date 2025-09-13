#!/usr/bin/env python3
"""
Finds the Ascension.exe process, then uses shellcode injection
to call FrameScript_ExecuteBuffer at runtime, enabling Lua execution.

NOTE: This script is designed to run on WINDOWS only. It uses the ctypes
library to call Windows API functions and will not run on Linux.
"""
import ctypes
import sys
# On non-Windows platforms, ctypes.WinDLL will not exist.
# We create a dummy class to allow the script to be parsed for syntax checking,
# but it will not be executable.
if sys.platform != "win32":
    class WinDLL:
        def __init__(self, *args, **kwargs):
            pass
        def __getattr__(self, name):
            raise NotImplementedError(f"This script is for Windows only. Cannot access {name}.")
    ctypes.WinDLL = WinDLL
import sys
from ctypes import wintypes
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

# --- Globals & Constants ---
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT_RESERVE = 0x1000 | 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40
FRAMESCRIPT_EXECUTE_RVA = 0x6D70  # The RVA of FrameScript_ExecuteBuffer from our analysis

# --- WinAPI Definitions ---
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

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wintypes.DWORD),
                ('th32ModuleID', wintypes.DWORD),
                ('th32ProcessID', wintypes.DWORD),
                ('GlblcntUsage', wintypes.DWORD),
                ('ProccntUsage', wintypes.DWORD),
                ('modBaseAddr', ctypes.POINTER(ctypes.c_byte)),
                ('modBaseSize', wintypes.DWORD),
                ('hModule', wintypes.HMODULE),
                ('szModule', ctypes.c_char * 256),
                ('szExePath', ctypes.c_char * 260)]

# --- Function Prototypes for kernel32.dll ---
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Module32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

def find_process_id(process_name):
    """Finds the Process ID (PID) for a given process name."""
    snapshot = kernel32.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if not kernel32.Process32First(snapshot, ctypes.byref(entry)):
        raise RuntimeError("Failed to get first process.")
    while True:
        if entry.szExeFile.decode('utf-8', 'ignore').lower() == process_name.lower():
            return entry.th32ProcessID
        if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
            break
    return None

def get_module_base_address(pid, module_name):
    """Gets the base address of a module loaded in a remote process."""
    snapshot = kernel32.CreateToolhelp32Snapshot(8, pid) # TH32CS_SNAPMODULE
    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    if not kernel32.Module32First(snapshot, ctypes.byref(entry)):
        raise RuntimeError("Failed to get first module.")
    while True:
        if entry.szModule.decode('utf-8', 'ignore').lower() == module_name.lower():
            return ctypes.addressof(entry.modBaseAddr.contents)
        if not kernel32.Module32Next(snapshot, ctypes.byref(entry)):
            break
    return None

def inject_and_run_shellcode(h_process, func_addr, lua_code):
    """Assembles, injects, and runs shellcode to execute a Lua command."""
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    # 1. Allocate memory for strings
    lua_code_bytes = lua_code.encode('utf-8') + b'\x00'
    buffer_name_bytes = b"Jules_Shellcode\x00"

    addr_lua_code = kernel32.VirtualAllocEx(h_process, None, len(lua_code_bytes), MEM_COMMIT_RESERVE, 4)
    addr_buffer_name = kernel32.VirtualAllocEx(h_process, None, len(buffer_name_bytes), MEM_COMMIT_RESERVE, 4)

    kernel32.WriteProcessMemory(h_process, addr_lua_code, lua_code_bytes, len(lua_code_bytes), None)
    kernel32.WriteProcessMemory(h_process, addr_buffer_name, buffer_name_bytes, len(buffer_name_bytes), None)

    # 2. Assemble shellcode
    assembly = f"""
        push 0;
        push {addr_buffer_name};
        push {addr_lua_code};
        mov eax, {func_addr};
        call eax;
        add esp, 12;
        ret;
    """
    shellcode, _ = ks.asm(assembly)
    shellcode_bytes = bytes(shellcode)

    # 3. Allocate memory for shellcode and write it
    addr_shellcode = kernel32.VirtualAllocEx(h_process, None, len(shellcode_bytes), MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    kernel32.WriteProcessMemory(h_process, addr_shellcode, shellcode_bytes, len(shellcode_bytes), None)

    # 4. Create remote thread to execute shellcode
    thread_handle = kernel32.CreateRemoteThread(h_process, None, 0, addr_shellcode, None, 0, None)

    # 5. Wait for completion and clean up
    kernel32.WaitForSingleObject(thread_handle, -1) # Wait indefinitely
    kernel32.VirtualFreeEx(h_process, addr_lua_code, 0, MEM_RELEASE)
    kernel32.VirtualFreeEx(h_process, addr_buffer_name, 0, MEM_RELEASE)
    kernel32.VirtualFreeEx(h_process, addr_shellcode, 0, MEM_RELEASE)
    kernel32.CloseHandle(thread_handle)

def main():
    """Main function to find process, calculate addresses, and start interactive shell."""
    process_name = "Ascension.exe"
    print(f"[*] Searching for process: {process_name}")
    pid = find_process_id(process_name)
    if not pid:
        print(f"[!] Process '{process_name}' not found. Is the game running?")
        sys.exit(1)
    print(f"[+] Found process '{process_name}' with PID: {pid}")

    try:
        base_address = get_module_base_address(pid, process_name)
        if not base_address:
            raise RuntimeError(f"Could not find base address for {process_name}")

        fs_execute_addr = base_address + FRAMESCRIPT_EXECUTE_RVA
        print(f"[+] Game base address: {hex(base_address)}")
        print(f"[+] Calculated 'FrameScript_ExecuteBuffer' address: {hex(fs_execute_addr)}")

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            raise OSError("Failed to open process handle.")

        print("\n[*] Interactive Lua shell started. Type 'exit' to quit.")
        print("----------------------------------------------------")
        while True:
            lua_command = input("lua> ")
            if lua_command.lower() == 'exit':
                break
            if not lua_command:
                continue

            print(f"[*] Injecting: {lua_command}")
            inject_and_run_shellcode(h_process, fs_execute_addr, lua_command)
            print("[+] Executed.")

    except (RuntimeError, OSError) as e:
        print(f"[!] An error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        if 'h_process' in locals() and h_process:
            kernel32.CloseHandle(h_process)
        print("\n[*] Injector shut down.")

if __name__ == "__main__":
    main()
