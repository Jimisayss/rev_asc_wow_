import ctypes
import psutil
import argparse
import time
import re

# --- Constants & Signatures ---
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
VIRTUAL_MEM = MEM_COMMIT | MEM_RESERVE
FILE_MAP_ALL_ACCESS = 0xF001F
SHARED_MEM_NAME = b"JulesSharedMemory"
BUF_SIZE = 2048

SIG_FRAMESCRIPT_EXECUTE = "68 70 EB 5E 00"

# --- IPC Structs ---
class JulesInit(ctypes.Structure):
    _fields_ = [
        ("frameScriptExecuteBufferAddr", ctypes.c_void_p),
    ]

class SharedData(ctypes.Structure):
    _fields_ = [
        ("init", JulesInit),
        ("is_busy", ctypes.c_bool),
        ("lua_code", (ctypes.c_char * (BUF_SIZE - ctypes.sizeof(JulesInit) - 1)))
    ]

# --- Process & Memory Functions ---
def get_process_id_by_name(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']
    return None

def get_module_info(pid, module_name):
    try:
        p = psutil.Process(pid)
        for mod in p.memory_maps(grouped=False):
            if mod.path and mod.path.endswith(module_name):
                return mod.addr, mod.size
    except psutil.NoSuchProcess:
        return None, None
    return None, None

def find_signature(h_process, start_address, size, signature_str):
    kernel32 = ctypes.WinDLL('kernel32')
    signature_bytes = signature_str.replace('??', ' . ').split()
    signature_len = len(signature_bytes)
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    if not kernel32.ReadProcessMemory(h_process, start_address, buffer, size, ctypes.byref(bytes_read)):
        return None
    for i in range(bytes_read.value - signature_len):
        if all(signature_bytes[j] == '.' or int(signature_bytes[j], 16) == buffer[i+j] for j in range(signature_len)):
            return start_address + i
    return None

def inject_dll(pid, dll_path):
    kernel32 = ctypes.WinDLL('kernel32')
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process: return False
    dll_path_addr = kernel32.VirtualAllocEx(h_process, 0, len(dll_path) + 1, VIRTUAL_MEM, PAGE_READWRITE)
    if not dll_path_addr: return False
    kernel32.WriteProcessMemory(h_process, dll_path_addr, dll_path.encode('ascii'), len(dll_path) + 1, None)
    load_library_addr = kernel32.GetProcAddress(kernel32._handle, b'LoadLibraryA')
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, dll_path_addr, 0, None)
    if not h_thread: return False
    kernel32.CloseHandle(h_process)
    return True

# --- Main Controller Logic ---
def main():
    parser = argparse.ArgumentParser(description="Jules Controller for Ascension WoW")
    parser.add_argument('--proc-name', default='Ascension.exe', help="Name of the game process")
    parser.add_argument('--dll-path', default='out/jules_agent.dll', help="Path to the DLL to inject")
    args = parser.parse_args()

    print(f"--- Jules Lua Controller ---")
    print(f"Waiting for process: {args.proc_name}...")
    pid = None
    while not pid:
        pid = get_process_id_by_name(args.proc_name)
        time.sleep(1)
    print(f"Found process {args.proc_name} with PID: {pid}")

    print("\nScanning for function signatures...")
    h_process = ctypes.WinDLL('kernel32').OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    wow_base, wow_size = get_module_info(pid, args.proc_name)

    fs_addr = find_signature(h_process, wow_base, wow_size, SIG_FRAMESCRIPT_EXECUTE)

    print(f"  -> FrameScript_ExecuteBuffer: {hex(fs_addr if fs_addr else 0)}")

    if not fs_addr:
        print("\nError: Could not find FrameScript_ExecuteBuffer signature. Aborting.")
        return

    print("\nCreating shared memory...")
    kernel32 = ctypes.WinDLL('kernel32')
    h_map_file = kernel32.CreateFileMappingA(-1, None, PAGE_READWRITE, 0, BUF_SIZE, SHARED_MEM_NAME)
    if not h_map_file:
        print(f"Error: Could not create file mapping object: {ctypes.get_last_error()}")
        return

    p_buf = kernel32.MapViewOfFile(h_map_file, FILE_MAP_ALL_ACCESS, 0, 0, BUF_SIZE)
    shared_buffer = SharedData.from_address(p_buf)

    print("Writing initialization data...")
    shared_buffer.init = JulesInit(fs_addr)
    shared_buffer.is_busy = False
    shared_buffer.lua_code = b''

    print("\nInjecting DLL...")
    if not inject_dll(pid, args.dll_path):
        print("Injection failed. Aborting.")
        return
    print("Injection successful.")

    print("\n--- Jules is ready. Type Lua code and press Enter. Type 'exit' to quit. ---")
    try:
        while True:
            code = input("lua> ")
            if code.lower() == 'exit':
                break
            if not code:
                continue

            # Wait for agent to be ready
            while shared_buffer.is_busy:
                time.sleep(0.05)

            # Write code to buffer
            shared_buffer.lua_code = code.encode('ascii')

    except KeyboardInterrupt:
        print("\nExiting.")
    finally:
        kernel32.UnmapViewOfFile(p_buf)
        kernel32.CloseHandle(h_map_file)
        print("Controller shut down.")

if __name__ == '__main__':
    main()
